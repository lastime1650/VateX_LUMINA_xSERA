"""Durable admission journal + transactional columnar analytics, single process."""

import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import stat
import tempfile
import threading
import time
import uuid
import weakref
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path

import duckdb

from .locking import ProcessLock
from .query import Query


class CapacityError(RuntimeError):
    pass


class ConflictError(ValueError):
    pass


@dataclass
class Settings:
    data: Path
    max_queue: int = 100_000
    min_free_bytes: int = 1024 * 1024 * 1024
    retention_days: int = 0  # zero means permanent; no age-based deletion
    query_timeout: float = 15
    workers: int = 4
    memory_limit: str = "512MB"
    cluster: Path | None = None
    appliance_setup: bool = False
    indexing_batch: int = 5000
    indexing_budget: float = 0.25
    indexing_idle: float = 0.25
    max_tenant_queue: int = 25_000
    syslog: object | None = None
    oidc: Path | None = None
    federation: Path | None = None
    fts_max_bytes: int = 8 * 1024**3
    qualification_keys: Path | None = None
    simulation_mode: bool = False


def encode(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    )


def _storage_bytes(path):
    """Estimate regular-file bytes without failing on disappearing WAL files."""
    total = 0
    with os.scandir(path) as entries:
        for entry in entries:
            try:
                snapshot = entry.stat(follow_symlinks=False)
            except FileNotFoundError:
                continue
            if stat.S_ISREG(snapshot.st_mode):
                total += snapshot.st_size
    return total


def normalize(event, now=None):
    now = now or time.time()
    if not isinstance(event, dict):
        raise ValueError("Each event must be an object")  # noqa: TRY004 - Invalid JSON event is HTTP 400.
    allowed = {
        "event_id",
        "event_time",
        "source",
        "sourcetype",
        "host",
        "severity",
        "message",
        "raw",
        "index",
    }
    if set(event) - allowed:
        raise ValueError(
            "Unknown event envelope field; put vendor attributes under raw"
        )
    record = dict(event)
    record.setdefault("event_id", str(uuid.uuid4()))
    record.setdefault("event_time", now)
    record.setdefault("source", "http")
    record.setdefault("sourcetype", "json")
    record.setdefault("host", "unknown")
    record.setdefault("severity", "info")
    record.setdefault("message", "")
    record.setdefault("raw", {})
    record.setdefault("index", "main")
    if not isinstance(record["index"], str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{1,64}", record["index"]
    ):
        raise ValueError("Invalid logical index")
    for field in ["event_id", "source", "sourcetype", "host", "severity", "message"]:
        if not isinstance(record[field], str) or len(record[field]) > (
            32768 if field == "message" else 256
        ):
            raise ValueError(f"Invalid {field}")
    if not record["event_id"] or record["severity"] not in {
        "debug",
        "info",
        "low",
        "medium",
        "high",
        "critical",
    }:
        raise ValueError("Invalid event_id or severity")
    if (
        isinstance(record["event_time"], bool)
        or not isinstance(record["event_time"], (float, int))
        or not math.isfinite(record["event_time"])
        or not 0 <= record["event_time"] <= now + 86400
    ):
        raise ValueError(
            "event_time must be epoch seconds, at most one day in the future"
        )
    from .normalization import normalize as security_normalize

    try:
        record = security_normalize(record)
    except RecursionError:
        raise ValueError("Event nesting exceeds supported depth") from None
    if len(encode(record).encode("utf-8")) > 65536:
        raise ValueError("Event exceeds 64 KiB")
    return record


class Store:
    def __init__(self, settings):
        self._wal_anchor = None
        self._wal_anchor_finalizer = None
        try:
            self._initialize(settings)
        except BaseException:
            # Preserve the original initialization error while releasing every
            # resource acquired so far, including failures after module setup.
            with suppress(Exception):
                self._close_wal_anchor()
            for name in ("analytics", "process_lock"):
                resource = getattr(self, name, None)
                if resource is not None:
                    with suppress(Exception):
                        resource.close()
            raise

    def _initialize(self, settings):
        self.settings = settings
        self.path = Path(settings.data).resolve()
        self.path.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            self.path.chmod(0o700)
        from .migrations import guard_file

        guard_file(self.path / "control.sqlite3")
        self.process_lock = ProcessLock(self.path / "service.lock")
        self.write_lock = threading.RLock()
        self.flush_lock = threading.Lock()
        self.query_slots = threading.BoundedSemaphore(settings.workers)
        self._health_cache = {}
        self.operational = self.path / "control.sqlite3"
        with self.control() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY);
                INSERT INTO schema_version SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM schema_version);
                CREATE TABLE IF NOT EXISTS queue(seq INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT NOT NULL,event_id TEXT NOT NULL,payload TEXT NOT NULL,received REAL NOT NULL,UNIQUE(tenant,event_id));
                CREATE TABLE IF NOT EXISTS receipts(tenant TEXT,event_id TEXT,digest TEXT NOT NULL,received REAL NOT NULL,PRIMARY KEY(tenant,event_id));
                CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY,password TEXT NOT NULL,role TEXT NOT NULL,tenant TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions(digest TEXT PRIMARY KEY,name TEXT NOT NULL,expires REAL NOT NULL,csrf TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS tokens(digest TEXT PRIMARY KEY,name TEXT,tenant TEXT,scope TEXT,created REAL);
                CREATE TABLE IF NOT EXISTS rules(id TEXT PRIMARY KEY,tenant TEXT,name TEXT,query TEXT,interval INTEGER,lookback INTEGER,threshold INTEGER,enabled INTEGER,next_run REAL,last_end REAL,error TEXT);
                CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY,tenant TEXT,rule_id TEXT,name TEXT,created REAL,status TEXT,owner TEXT,version INTEGER,evidence TEXT);
                CREATE TABLE IF NOT EXISTS policies(tenant TEXT PRIMARY KEY,days INTEGER NOT NULL,hold INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,at REAL,tenant TEXT,actor TEXT,action TEXT,detail TEXT,previous TEXT,digest TEXT);
                CREATE INDEX IF NOT EXISTS queue_time ON queue(received);
                CREATE INDEX IF NOT EXISTS findings_tenant ON findings(tenant,created);
                CREATE TABLE IF NOT EXISTS retention_intents(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,cutoff REAL NOT NULL,payload TEXT NOT NULL,created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS retention_applied(id TEXT PRIMARY KEY,applied REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS retention_intents_tenant ON retention_intents(tenant,id);
                CREATE TABLE IF NOT EXISTS log_retained_identities(tenant TEXT NOT NULL,event_id TEXT NOT NULL,received REAL NOT NULL,PRIMARY KEY(tenant,event_id)) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS log_retention_identity_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS log_retention_pending_keys(tenant TEXT NOT NULL,event_id TEXT NOT NULL,intent_id TEXT NOT NULL,PRIMARY KEY(tenant,event_id,intent_id)) WITHOUT ROWID;
                CREATE INDEX IF NOT EXISTS log_retention_pending_intent ON log_retention_pending_keys(intent_id);
                CREATE TRIGGER IF NOT EXISTS log_retention_intent_insert AFTER INSERT ON retention_intents BEGIN
                  INSERT OR IGNORE INTO log_retention_pending_keys SELECT NEW.tenant,CAST(value AS TEXT),NEW.id FROM json_each(NEW.payload) WHERE NOT EXISTS(SELECT 1 FROM retention_applied WHERE id=NEW.id);
                END;
                CREATE TRIGGER IF NOT EXISTS log_retention_intent_delete AFTER DELETE ON retention_intents BEGIN
                  DELETE FROM log_retention_pending_keys WHERE intent_id=OLD.id;
                END;
                CREATE TRIGGER IF NOT EXISTS log_retention_intent_update AFTER UPDATE ON retention_intents BEGIN
                  DELETE FROM log_retention_pending_keys WHERE intent_id=OLD.id;
                  INSERT OR IGNORE INTO log_retention_pending_keys SELECT NEW.tenant,CAST(value AS TEXT),NEW.id FROM json_each(NEW.payload) WHERE NOT EXISTS(SELECT 1 FROM retention_applied WHERE id=NEW.id);
                END;
                CREATE TRIGGER IF NOT EXISTS log_retention_applied_insert AFTER INSERT ON retention_applied BEGIN
                  DELETE FROM log_retention_pending_keys WHERE intent_id=NEW.id;
                END;
                CREATE TRIGGER IF NOT EXISTS log_retention_applied_delete AFTER DELETE ON retention_applied BEGIN
                  INSERT OR IGNORE INTO log_retention_pending_keys SELECT i.tenant,CAST(j.value AS TEXT),i.id FROM retention_intents i,json_each(i.payload) j WHERE i.id=OLD.id;
                END;
                CREATE TRIGGER IF NOT EXISTS log_retention_applied_update AFTER UPDATE OF id ON retention_applied BEGIN
                  DELETE FROM log_retention_pending_keys WHERE intent_id=NEW.id;
                  INSERT OR IGNORE INTO log_retention_pending_keys SELECT i.tenant,CAST(j.value AS TEXT),i.id FROM retention_intents i,json_each(i.payload) j WHERE i.id=OLD.id AND NOT EXISTS(SELECT 1 FROM retention_applied a WHERE a.id=i.id);
                END;
            """)
            user_columns = {r[1] for r in db.execute("PRAGMA table_info(users)")}
            for name, definition in {
                "disabled": "INTEGER NOT NULL DEFAULT 0",
                "must_change": "INTEGER NOT NULL DEFAULT 0",
                "password_changed": "REAL NOT NULL DEFAULT 0",
                "mfa_secret": "TEXT",
                "mfa_pending": "TEXT",
                "mfa_pending_until": "REAL",
                "mfa_counter": "INTEGER NOT NULL DEFAULT -1",
            }.items():
                if name not in user_columns:
                    db.execute(
                        "ALTER TABLE users ADD COLUMN " + name + " " + definition
                    )
            token_columns = {r[1] for r in db.execute("PRAGMA table_info(tokens)")}
            if "expires" not in token_columns:
                db.execute("ALTER TABLE tokens ADD COLUMN expires REAL")
            db.execute(
                "DELETE FROM schema_version WHERE version=1 AND EXISTS(SELECT 1 FROM schema_version WHERE version=2)"
            )
            db.execute("UPDATE schema_version SET version=2 WHERE version=1")
        self._open_wal_anchor()
        from .log_segments import SegmentGate, SegmentManager

        self.segment_lock = SegmentGate()
        segment_root = self.path / "log-segments"
        segment_root.mkdir(exist_ok=True)
        self.analytics = duckdb.connect(
            str(self.path / "events.duckdb"),
            config={
                "memory_limit": settings.memory_limit,
                "threads": str(settings.workers),
            },
        )
        # DuckDB requires allowlists to be set before external access is disabled.
        # No untrusted SQL runs during this private connection initialization.
        self.analytics.execute(
            "SET allowed_directories = ?", [[segment_root.as_posix() + "/"]]
        )
        self.analytics.execute("SET enable_external_access=false")
        self.analytics.execute(
            """CREATE TABLE IF NOT EXISTS events(tenant VARCHAR,event_id VARCHAR,event_time DOUBLE,received DOUBLE,source VARCHAR,sourcetype VARCHAR,host VARCHAR,severity VARCHAR,message VARCHAR,raw VARCHAR,PRIMARY KEY(tenant,event_id))"""
        )
        existing_columns = {
            r[1]
            for r in self.analytics.execute("PRAGMA table_info('events')").fetchall()
        }
        if "index_name" not in existing_columns:
            self.analytics.execute(
                "ALTER TABLE events ADD COLUMN index_name VARCHAR DEFAULT 'main'"
            )
        self.analytics.execute(
            "CREATE INDEX IF NOT EXISTS events_time ON events(tenant,event_time)"
        )
        self.closed = False
        self.replica = None
        try:
            self.segments = SegmentManager(self)
            from . import log_search

            log_search.initialize(self)
            self._initialize_retention_identities()
        except Exception:
            self.analytics.close()
            self.process_lock.close()
            raise
        from .jobs import initialize

        initialize(self)
        from .dashboards import initialize as initialize_dashboards

        initialize_dashboards(self)
        from .membership import initialize as initialize_membership

        initialize_membership(self)
        from .access import initialize as initialize_access
        from .detections import initialize as initialize_detections

        initialize_access(self)
        initialize_detections(self)
        from .oidc import initialize as initialize_oidc

        initialize_oidc(self)
        from .lookups import initialize as initialize_lookups

        initialize_lookups(self)
        from .federation import initialize as initialize_federation

        initialize_federation(self)
        from .casework import initialize as initialize_casework

        initialize_casework(self)
        from .pipeline import initialize as initialize_pipeline

        initialize_pipeline(self)
        from .source_health import initialize as initialize_source_health

        initialize_source_health(self)
        from . import behavior, content, entities, soar

        for module in (entities, behavior, content, soar):
            module.initialize(self)
        from .agent_distribution import initialize as initialize_agents

        initialize_agents(self)
        from .endpoint_response import initialize as initialize_endpoint_response

        initialize_endpoint_response(self)
        from .endpoint_policies import initialize as initialize_endpoint_policies

        initialize_endpoint_policies(self)
        from . import (
            contribution_verdicts,
            detection_governance,
            file_verdicts,
            pipeline_slo,
            risk_priority,
            temporal_identity,
        )

        for module in (
            contribution_verdicts,
            detection_governance,
            temporal_identity,
            risk_priority,
            pipeline_slo,
            file_verdicts,
        ):
            module.initialize(self)
        from .backend_upgrade import initialize as initialize_upgrade

        initialize_upgrade(self)
        from . import (
            behavior_features,
            case_intelligence,
            cpu_ml,
            cpu_sequence,
            intelligence,
            intelligence_sequence,
            intelligence_shadow,
            ml_datasets,
            shadow_analysis,
        )

        for module in (intelligence, cpu_ml, cpu_sequence, intelligence_sequence, shadow_analysis, intelligence_shadow, case_intelligence, behavior_features, ml_datasets):
            module.initialize(self)
        from . import yara_manager

        yara_manager.initialize(self)
        from . import sequence_event_time
        sequence_event_time.initialize(self)
        from . import (
            advanced_intelligence,
            analysis_engines,
            online_analytics,
            research_behavior,
            sensor_adapters,
            sigma_imports,
        )
        for module in (analysis_engines, research_behavior, sensor_adapters, online_analytics, advanced_intelligence, sigma_imports):
            module.initialize(self)
        from . import ops_qualification, signal_evidence, source_delivery_slo
        for module in (ops_qualification, source_delivery_slo, signal_evidence):
            module.initialize(self)
        if settings.cluster:
            from .cluster import Replica

            self.replica = Replica(self, settings.cluster)

    def _open_wal_anchor(self):
        """Keep WAL attached without a transaction, authority query or pool.

        control() still opens, configures, commits/rolls back and closes a fresh
        connection on every call. This idle handle only avoids repeatedly
        becoming SQLite's last connection and checkpointing/reopening WAL.
        """
        anchor = sqlite3.connect(self.operational, timeout=10, check_same_thread=False)
        try:
            if anchor.execute("PRAGMA journal_mode").fetchall()[0][0] != "wal":
                raise RuntimeError("Control database must retain WAL journaling")
            anchor.execute("PRAGMA synchronous=FULL")
            anchor.execute("SELECT name FROM sqlite_master LIMIT 1").fetchall()
            if anchor.in_transaction or anchor.total_changes:
                raise RuntimeError("Idle WAL anchor must not retain a transaction")
            self._wal_anchor = anchor
            # The bound connection callback captures no Store reference, so
            # abandoned/cyclic Stores can release the handle during GC too.
            self._wal_anchor_finalizer = weakref.finalize(self, anchor.close)
        except BaseException:
            anchor.close()
            raise

    def _close_wal_anchor(self):
        finalizer = getattr(self, "_wal_anchor_finalizer", None)
        if finalizer is not None:
            finalizer()
        self._wal_anchor = None

    @contextmanager
    def control(self, local=False):
        if not local and getattr(self, "replica", None):
            with self.replica.control() as db:
                yield db
            return
        db = sqlite3.connect(self.operational, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=10000")
        try:
            with db:
                yield db
        finally:
            db.close()

    def audit(self, db, tenant, actor, action, detail):
        # A local tamper-evident chain, not an externally anchored immutable ledger.
        previous = db.execute(
            "SELECT digest FROM audit ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        previous = previous[0] if previous else "0" * 64
        at = time.time()
        detail = encode(detail)
        digest = hashlib.sha256(
            encode([at, tenant, actor, action, detail, previous]).encode()
        ).hexdigest()
        db.execute(
            "INSERT INTO audit(at,tenant,actor,action,detail,previous,digest) VALUES(?,?,?,?,?,?,?)",
            (at, tenant, actor, action, detail, previous, digest),
        )

    def _initialize_retention_identities(self):
        """One-time bounded-memory reconciliation of old held originals.

        Only identities/receipt times are recoverable; no digest is invented.
        Catalog and completion marker publish together before admission starts.
        """
        with (
            self.flush_lock,
            self.segment_lock.read(),
            self.write_lock,
            self.control(local=True) as db,
        ):
            state = db.execute(
                "SELECT version FROM log_retention_identity_state WHERE singleton=1"
            ).fetchone()
            if state:
                if state[0] != 1:
                    raise RuntimeError("Unsupported local retention identity catalog")
                return
            self.segments.ensure_readable()
            self._retention_identity_reserve()
            db.execute("PRAGMA temp_store=FILE")
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM log_retention_pending_keys")
            db.execute(
                "INSERT OR IGNORE INTO log_retention_pending_keys SELECT i.tenant,CAST(j.value AS TEXT),i.id FROM retention_intents i,json_each(i.payload) j LEFT JOIN retention_applied a ON a.id=i.id WHERE a.id IS NULL"
            )
            db.execute(
                "CREATE TEMP TABLE retained_candidates(tenant TEXT,event_id TEXT,cutoff REAL,PRIMARY KEY(tenant,event_id)) WITHOUT ROWID"
            )
            cursor = db.execute("SELECT tenant,cutoff,payload FROM retention_intents")
            while intents := cursor.fetchmany(8):
                for intent in intents:
                    values = json.loads(intent["payload"])
                    self._retention_identity_reserve(
                        sum(
                            (len(intent["tenant"].encode()) + len(ident.encode()) + 128)
                            * 4
                            for ident in values
                        )
                    )
                    db.executemany(
                        "INSERT INTO retained_candidates VALUES(?,?,?) ON CONFLICT(tenant,event_id) DO UPDATE SET cutoff=max(cutoff,excluded.cutoff)",
                        [
                            (intent["tenant"], ident, intent["cutoff"])
                            for ident in values
                        ],
                    )
            db.execute("DELETE FROM log_retained_identities")
            if db.execute("SELECT 1 FROM retained_candidates LIMIT 1").fetchone():
                sealed = db.execute(
                    "SELECT k.tenant,k.event_id,k.received FROM log_sealed_keys k JOIN retained_candidates c USING(tenant,event_id) WHERE k.received<c.cutoff"
                )
                while keys := sealed.fetchmany(4000):
                    self._retention_identity_reserve(
                        sum(
                            (len(key[0].encode()) + len(key[1].encode()) + 128) * 4
                            for key in keys
                        )
                    )
                    db.executemany(
                        "INSERT INTO log_retained_identities VALUES(?,?,?)",
                        [tuple(key) for key in keys],
                    )
                con = self.analytics.cursor()
                try:
                    con.execute("SELECT tenant,event_id,received FROM events")
                    while keys := con.fetchmany(400):
                        wanted = ",".join("(?,?,?)" for _ in keys)
                        found = db.execute(
                            "WITH wanted(tenant,event_id,received) AS (VALUES "
                            + wanted
                            + ") SELECT w.tenant,w.event_id,w.received FROM wanted w CROSS JOIN retained_candidates c WHERE c.tenant=w.tenant AND c.event_id=w.event_id AND w.received<c.cutoff",
                            [value for key in keys for value in key],
                        ).fetchall()
                        self._retention_identity_reserve(
                            sum(
                                (len(key[0].encode()) + len(key[1].encode()) + 128) * 4
                                for key in found
                            )
                        )
                        db.executemany(
                            "INSERT OR REPLACE INTO log_retained_identities VALUES(?,?,?)",
                            [tuple(row) for row in found],
                        )
                finally:
                    con.close()
            self._retention_identity_reserve()
            db.execute("INSERT INTO log_retention_identity_state VALUES(1,1)")

    def _retention_identity_reserve(self, extra=0):
        # Candidate B-trees are temporary disk files; protect both volumes.
        for path in (self.path, Path(tempfile.gettempdir())):
            if (
                shutil.disk_usage(path).free
                < self.settings.min_free_bytes + extra + 65536
            ):
                raise CapacityError("Retention identity migration disk reserve reached")

    def ingest(
        self,
        tenant,
        events,
        actor="collector",
        allowed_indexes=None,
        authorization=None,
    ):
        if not isinstance(events, list) or not 1 <= len(events) <= 1000:
            raise ValueError("Batch size must be 1..1000")
        records = [normalize(event) for event in events]
        now = time.time()
        accepted, duplicate = 0, 0
        with self.write_lock, self.control() as db:
            db.execute("BEGIN IMMEDIATE")
            from .query import index_predicate

            index_predicate(allowed_indexes)
            if authorization is not None:
                if not callable(authorization):
                    raise ValueError(
                        "Internal ingestion authorization must be callable"
                    )
                current_scope = authorization(db)
                index_predicate(current_scope)
                if current_scope is None:
                    raise PermissionError(
                        "Authenticated ingestion scope must be explicit"
                    )
                if allowed_indexes is None or allowed_indexes == ["*"]:
                    allowed_indexes = current_scope
                elif current_scope != ["*"]:
                    allowed_indexes = [
                        name for name in allowed_indexes if name in current_scope
                    ]

            def authorize_index(name):
                if (
                    allowed_indexes is not None
                    and allowed_indexes != ["*"]
                    and name not in allowed_indexes
                ):
                    raise PermissionError(
                        "Event index is outside the current ingestion scope"
                    )

            for record in records:
                authorize_index(record["index"])
            incoming_ids = encode([record["event_id"] for record in records])
            retiring = db.execute(
                "SELECT 1 FROM json_each(?) incoming CROSS JOIN log_retention_pending_keys p WHERE p.tenant=? AND p.event_id=incoming.value LIMIT 1",
                (incoming_ids, tenant),
            ).fetchone()
            if retiring:
                raise ConflictError(
                    "Retention of an event identity is pending; retry after recovery completes"
                )
            retained = db.execute(
                "SELECT 1 FROM json_each(?) incoming CROSS JOIN log_retained_identities k WHERE k.tenant=? AND k.event_id=incoming.value AND NOT EXISTS(SELECT 1 FROM receipts r WHERE r.tenant=k.tenant AND r.event_id=k.event_id) LIMIT 1",
                (incoming_ids, tenant),
            ).fetchone()
            if retained:
                raise ConflictError(
                    "Event identity remains retained without its admission receipt; reuse is unavailable"
                )
            pending = db.execute("SELECT count(*) FROM queue").fetchone()[0]
            from . import pipeline

            policies = pipeline.for_ingest(db, tenant)
            new_records, quarantined = [], []
            for original, record in zip(events, records):
                payload = encode(record)
                fingerprint = dict(record)
                # Derived schema enrichment is versioned independently of the
                # collector's content. Preserve pre-upgrade retry fingerprints.
                fingerprint["raw"] = original.get("raw", {})
                # Omitted source timestamp must not change idempotency on retry.
                if "event_time" not in original:
                    fingerprint.pop("event_time")
                if "index" not in original:
                    fingerprint.pop("index")
                digest = hashlib.sha256(encode(fingerprint).encode()).hexdigest()
                old = db.execute(
                    "SELECT digest FROM receipts WHERE tenant=? AND event_id=?",
                    (tenant, record["event_id"]),
                ).fetchone()
                if old:
                    if old[0] != digest:
                        raise ConflictError(
                            "event_id already exists with different content"
                        )
                    duplicate += 1
                    continue
                db.execute(
                    "INSERT INTO receipts VALUES(?,?,?,?)",
                    (tenant, record["event_id"], digest, now),
                )
                policy = policies.get(record["source"])
                record, errors = pipeline.apply(record, policy)
                authorize_index(record["index"])
                payload = encode(record)
                if errors:
                    quarantined.append(
                        (
                            tenant,
                            record["event_id"],
                            record["index"],
                            record["source"],
                            payload,
                            now,
                            policy["name"],
                            policy["version"],
                            "; ".join(errors),
                        )
                    )
                else:
                    new_records.append((tenant, record["event_id"], payload, now))
            if pending + len(new_records) > self.settings.max_queue:
                raise CapacityError(
                    "Admission journal full; retry without changing event_id"
                )
            tenant_pending = db.execute(
                "SELECT count(*) FROM queue WHERE tenant=?", (tenant,)
            ).fetchone()[0]
            if tenant_pending + len(new_records) > self.settings.max_tenant_queue:
                raise CapacityError(
                    "Tenant admission quota reached; retry stable event IDs"
                )
            durable_records = new_records + [
                (r[0], r[1], r[4], r[5]) for r in quarantined
            ]
            if durable_records:
                from .pressure_retention import reserve_bytes

                disk = shutil.disk_usage(self.path)
                # The admission transaction sees the current replicated policy,
                # even before a peer's background worker refreshes its cache.
                saved_policy = db.execute("SELECT definition FROM record_management_policy WHERE singleton=1").fetchone()
                capacity_policy = json.loads(saved_policy[0]) if saved_policy else None
                if disk.free <= reserve_bytes(self, disk,capacity_policy) + sum(len(x[2].encode()) * 3 for x in durable_records):
                    wake = getattr(self, "capacity_wake", None)
                    if wake is not None:
                        wake.set()
                    raise CapacityError("Storage volume reserve reached; cleanup requested; retry stable event IDs")
            admitted_hook = getattr(authorization, "on_admitted", None)
            if admitted_hook is not None:
                if not callable(admitted_hook):
                    raise ValueError("Admission provenance hook must be callable")
                admitted_hook(
                    db, durable_records, [record["event_id"] for record in records], now
                )
            db.executemany(
                "INSERT INTO queue(tenant,event_id,payload,received) VALUES(?,?,?,?)",
                new_records,
            )
            pipeline.admit_quarantine(db, quarantined)
            accepted = len(durable_records)
            self.audit(
                db,
                tenant,
                actor,
                "ingest",
                {
                    "accepted": accepted,
                    "duplicate": duplicate,
                    "quarantined": len(quarantined),
                },
            )
        from .pipeline_dispatch import notify
        notify(self, "index")
        result = {
            "accepted": accepted,
            "duplicate": duplicate,
            "durable": True,
            "searchable": False,
        }
        if quarantined:
            result["quarantined"] = len(quarantined)
        return result

    def _sealed_replay_conflicts(self, values, sealed):
        """Verify replay bodies only in the segments containing incoming keys."""
        if not sealed:
            return False
        from .log_segments import COLUMNS, SegmentError, sql_path

        expected = {
            (value[0], value[1]): value
            for value in values
            if (value[0], value[1]) in sealed
        }
        if any(value[3] != sealed[key]["received"] for key, value in expected.items()):
            return True
        segments = sorted({value["segment_id"] for value in sealed.values()})
        with self.control(local=True) as db:
            rows = db.execute(
                "SELECT id,path FROM log_segments WHERE state='ready' AND id IN (SELECT value FROM json_each(?))",
                (encode(segments),),
            ).fetchall()
        if len(rows) != len(segments):
            raise SegmentError("Sealed replay identity has no ready segment")
        paths = ",".join(sql_path(self.segments._path(row["path"])) for row in rows)
        fields = ",".join("e." + name for name in COLUMNS.split(","))
        wanted = "SELECT value->>0 AS tenant,value->>1 AS event_id FROM json_each(?)"
        cursor = self.analytics.cursor()
        try:
            actual = cursor.execute(
                "SELECT "
                + fields
                + " FROM read_parquet(["
                + paths
                + "]) e JOIN ("
                + wanted
                + ") wanted USING(tenant,event_id)",
                [encode(list(expected))],
            ).fetchall()
        finally:
            cursor.close()
        return len(actual) != len(expected) or any(
            tuple(row) != expected[(row[0], row[1])] for row in actual
        )

    def flush(self, batch=1000, after_commit=None):
        with self.flush_lock:
            self._apply_retention_locked()
            with self.control() as db:
                rows = db.execute(
                    "SELECT * FROM queue ORDER BY seq LIMIT ?", (batch,)
                ).fetchall()
            if not rows:
                return 0
            # flush_lock excludes lifecycle publication and file deletion.
            # Check the committed manifest before consulting sealed identities.
            self.segments.ensure_readable()
            sealed = (
                self.segments.sealed_keys(
                    [(row["tenant"], row["event_id"]) for row in rows]
                )
                if self.segments.view_manifest
                else {}
            )
            from . import log_search

            with self.write_lock, self.control(local=True) as db:
                pending_handoffs = {
                    row[0]
                    for row in db.execute(
                        "SELECT seq FROM log_fts_inflight WHERE seq IN (SELECT CAST(value AS INTEGER) FROM json_each(?))",
                        (encode([row["seq"] for row in rows]),),
                    )
                }
                cost_exempt = set(sealed) - {
                    (row["tenant"], row["event_id"])
                    for row in rows
                    if row["seq"] in pending_handoffs
                }
                # A large configured batch must not strand a smaller available
                # journal window. Select only an ordered queue prefix; sealed
                # replays consume no new journal space only when no earlier
                # source commit is awaiting its FTS handoff. This is not a
                # reservation: preflight and final append remain authoritative.
                prefix = log_search.journal_prefix(
                    self, db, rows, sealed_keys=cost_exempt
                )
            rows = rows[:prefix]
            selected_keys = {(row["tenant"], row["event_id"]) for row in rows}
            sealed = {key: sealed[key] for key in selected_keys if key in sealed}
            values = []
            for row in rows:
                r = json.loads(row["payload"])
                if r["event_id"] != row["event_id"]:
                    raise ConflictError(
                        "Queued event identity mismatch; queue preserved"
                    )
                values.append(
                    (
                        row["tenant"],
                        r["event_id"],
                        r["event_time"],
                        row["received"],
                        r["source"],
                        r["sourcetype"],
                        r["host"],
                        r["severity"],
                        r["message"],
                        encode(r["raw"]),
                        r.get("index", "main"),
                    )
                )
            sealed_conflict = self._sealed_replay_conflicts(values, sealed)
            indexed_rows = [
                row
                for row in rows
                if (row["tenant"], row["event_id"]) not in sealed
                or row["seq"] in pending_handoffs
            ]
            values = [value for value in values if (value[0], value[1]) not in sealed]

            with self.write_lock, self.control(local=True) as db:
                # A committed source batch must never appear FTS-ready in the
                # crash window before its derivative journal/queue ACK commits.
                if not sealed_conflict:
                    log_search.journal_preflight(self, db, indexed_rows)
                log_search.journal_begin(self, db, rows)
            if sealed_conflict:
                raise ConflictError(
                    "Incoming event conflicts with a retained original; queue preserved"
                )
            con = self.analytics.cursor()
            try:
                con.execute("BEGIN TRANSACTION")
                names = [
                    "tenant",
                    "event_id",
                    "event_time",
                    "received",
                    "source",
                    "sourcetype",
                    "host",
                    "severity",
                    "message",
                    "raw",
                    "index_name",
                ]
                structs = [dict(zip(names, value)) for value in values]
                # Vectorized ingestion avoids one Python/SQL round trip per event.
                incoming = """SELECT value->>'tenant' AS tenant,value->>'event_id' AS event_id,
                    CAST(value->>'event_time' AS DOUBLE) AS event_time,CAST(value->>'received' AS DOUBLE) AS received,
                    value->>'source' AS source,value->>'sourcetype' AS sourcetype,value->>'host' AS host,
                    value->>'severity' AS severity,value->>'message' AS message,value->>'raw' AS raw,
                    value->>'index_name' AS index_name FROM json_each(?)"""
                insert = "INSERT INTO events(tenant,event_id,event_time,received,source,sourcetype,host,severity,message,raw,index_name) "
                # Only actual PK conflicts compare immutable bodies. This avoids
                # a full hot scan while preserving legitimate commit/ACK replay.
                same = " AND ".join(
                    "events." + name + " IS NOT DISTINCT FROM excluded." + name
                    for name in names[2:]
                )
                statement = (
                    insert
                    + incoming
                    + " ON CONFLICT DO UPDATE SET received=CASE WHEN events.event_id IS NULL OR ("
                    + same
                    + ") THEN excluded.received ELSE error('retained_identity_conflict:' || events.event_id) END"
                )
                con.execute(statement, [encode(structs)])
                con.execute("COMMIT")
            except Exception as exc:
                con.execute("ROLLBACK")
                if isinstance(
                    exc, duckdb.InvalidInputException
                ) and "retained_identity_conflict" in str(exc):
                    raise ConflictError(
                        "Incoming event conflicts with a retained original; queue preserved"
                    ) from None
                raise
            finally:
                con.close()
            if after_commit:
                after_commit()  # failure-injection seam: queue must remain until analytical commit.
            with self.write_lock, self.control(local=True) as db:
                self.segments.bump(db, content=bool(indexed_rows))
                from . import log_search

                if indexed_rows:
                    log_search.journal_indexed(self, db, indexed_rows)
                    from . import detections

                    detections.journal_indexed(self, db, indexed_rows)
                    from . import pipeline_slo

                    pipeline_slo.journal_indexed(self, db, indexed_rows)
                    from . import event_projections

                    event_projections.journal_indexed(self, db, indexed_rows)
                    from . import intelligence

                    intelligence.journal_indexed(self, db, indexed_rows)
                    from . import research_behavior
                    research_behavior.journal_indexed(self, db, indexed_rows)
                    from . import online_analytics
                    online_analytics.journal_indexed(self, db, indexed_rows)
                log_search.journal_complete(self, db, rows)
                db.executemany(
                    "DELETE FROM queue WHERE seq=?", [(r["seq"],) for r in rows]
                )
            from .pipeline_dispatch import notify
            notify(self, "intelligence", "ml", "research", "online", "fts", "scheduler")
            return len(rows)

    def search(self, tenant, payload, cancel=None, allowed_indexes=None):
        q = Query.parse(payload)
        from .lookups import for_query

        sql, args = q.compile(
            tenant,
            allowed_indexes=allowed_indexes,
            lookup_tables=for_query(self, tenant, payload),
        )
        result = self.analytics_query(sql, args, cancel=cancel, max_rows=q.limit)
        return {**result, "limit": q.limit, "at_limit": result["returned"] == q.limit}

    def analytics_query(self, sql, args, *, cancel=None, max_rows=1000, timeout=None):
        timeout = self.settings.query_timeout if timeout is None else timeout
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("Analytics deadline must be finite and positive")
        deadline = time.monotonic() + min(timeout, self.settings.query_timeout)
        with self.segment_lock.read(deadline=deadline):
            self.segments.ensure_readable(deadline=deadline)
            self._require_retention_applied()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("Segment read deadline exceeded")
            return self._analytics_query(
                sql, args, cancel=cancel, max_rows=max_rows, timeout=remaining
            )

    @property
    def event_generation(self):
        return self.segments.generation

    @property
    def content_generation(self):
        return self.segments.content_generation

    def _require_retention_applied(self):
        with self.control(local=True) as db:
            if db.execute(
                "SELECT 1 FROM retention_intents i LEFT JOIN retention_applied a ON a.id=i.id WHERE a.id IS NULL LIMIT 1"
            ).fetchone():
                raise ConflictError(
                    "Retention deletion is pending; search remains unavailable until recovery completes"
                )

    @property
    def purge_generation(self):
        return self.segments.purge_generation

    def _analytics_query(self, sql, args, *, cancel=None, max_rows=1000, timeout=None):
        """Execute server-generated SQL with shared slots, deadline and output bounds.

        This is an internal analytics primitive. API callers must use the query
        compiler; SQL text must never be accepted from an HTTP request.
        """
        if type(max_rows) is not int or not 1 <= max_rows <= 10000:
            raise ValueError("Analytics result bound must be in 1..10000")
        timeout = self.settings.query_timeout if timeout is None else timeout
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError("Analytics deadline must be finite and positive")
        timeout = min(timeout, self.settings.query_timeout)
        if not self.query_slots.acquire(blocking=False):
            raise CapacityError("Search concurrency exhausted; retry later")
        con = self.analytics.cursor()
        completed = threading.Event()
        interrupted = threading.Event()
        started = time.perf_counter()

        def watch():
            while not completed.wait(0.05):
                try:
                    requested = (
                        cancel()
                        if callable(cancel)
                        else bool(cancel and cancel.is_set())
                    )
                except Exception:  # noqa: BLE001 - A broken cancellation callback must cancel rather than escape its watcher.
                    requested = True
                if requested or time.perf_counter() - started >= timeout:
                    interrupted.set()
                    con.interrupt()
                    return

        timer = threading.Thread(
            target=watch, name="sapientia-query-deadline", daemon=True
        )
        try:
            if cancel and (cancel() if callable(cancel) else cancel.is_set()):
                raise RuntimeError("Search cancelled")
            timer.start()
            con.execute(sql, args)
            columns = [x[0] for x in con.description]
            rows, result_bytes = [], 2
            while chunk := con.fetchmany(min(128, max_rows + 1 - len(rows))):
                for row in chunk:
                    item = dict(zip(columns, row))
                    result_bytes += len(encode(item).encode("utf-8")) + 1
                    if result_bytes > 2 * 1024 * 1024:
                        raise ValueError("Result exceeds 2 MiB; reduce fields or limit")
                    rows.append(item)
                    if len(rows) > max_rows:
                        raise CapacityError(
                            "Analytics row bound exceeded; narrow the request"
                        )
            if interrupted.is_set():
                raise RuntimeError("Search cancelled or deadline exceeded")
            return {
                "columns": columns,
                "rows": rows,
                "returned": len(rows),
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
            }
        finally:
            completed.set()
            if timer.ident is not None:
                timer.join()
            con.close()
            self.query_slots.release()

    def health(self, tenant, allowed_indexes=None):
        from .log_segments import SegmentError

        deadline = time.monotonic() + min(2, self.settings.query_timeout)
        try:
            with self.segment_lock.read(deadline=deadline):
                self.segments.ensure_readable(deadline=deadline)
                try:
                    self._require_retention_applied()
                except ConflictError:
                    self._health_cache.clear()
                    return self._health(
                        tenant, allowed_indexes, deadline, "retention_pending"
                    )
                return self._health(tenant, allowed_indexes, deadline)
        except SegmentError:
            raise  # Never disguise corruption as an ordinary monitoring delay.
        except RuntimeError:
            return self._health(
                tenant, allowed_indexes, deadline, "storage_deadline_exceeded"
            )

    def _health(
        self, tenant, allowed_indexes=None, deadline=None, analytics_error=None
    ):
        from .query import index_predicate

        predicate, grants = index_predicate(allowed_indexes)
        queue_predicate = predicate.replace(
            "index_name", "coalesce(json_extract(payload,'$.index'),'main')"
        )
        with self.control() as db:
            row = db.execute(
                "SELECT count(*),min(received),coalesce(sum(length(CAST(payload AS BLOB))),0) FROM queue WHERE tenant=? AND "
                + queue_predicate,
                [tenant, *grants],
            ).fetchone()
            policy = db.execute(
                "SELECT days,hold FROM policies WHERE tenant=?", (tenant,)
            ).fetchone()
        stats, sources = [None, None, None, None], []
        key = (
            tenant,
            None if allowed_indexes is None else tuple(sorted(set(allowed_indexes))),
        )
        cached = self._health_cache.get(key)
        purges, generation = self.purge_generation, self.content_generation
        if cached and cached["purges"] != purges:
            cached = (
                None  # Expired source information must not survive as stale metrics.
            )
        state, measured_at = "unavailable", None
        if not analytics_error:
            if (
                cached
                and cached["generation"] == generation
                and time.time() - cached["at"] < 5
            ):
                stats, sources, measured_at = (
                    cached["stats"],
                    cached["sources"],
                    cached["at"],
                )
                state = "cached"
            else:
                remaining = (deadline or time.monotonic() + 2) - time.monotonic()
                try:
                    if remaining <= 0:
                        raise RuntimeError("Health analytics deadline exceeded")
                    # Aggregate sources once. Window totals operate on the
                    # source groups, not on every raw event, before top-30.
                    sql = (
                        "WITH grouped AS (SELECT source,count(*) AS events,min(event_time) AS oldest,max(event_time) AS latest,max(received) AS last_seen FROM events_all WHERE tenant=? AND "
                        + predicate
                        + " GROUP BY source) SELECT source,events,last_seen,sum(events) OVER () AS indexed,min(oldest) OVER () AS oldest,max(latest) OVER () AS latest,count(*) OVER () AS source_count FROM grouped ORDER BY events DESC,source ASC LIMIT 30"
                    )
                    result = self._analytics_query(
                        sql, [tenant, *grants], max_rows=30, timeout=remaining
                    )
                    if result["rows"]:
                        first = result["rows"][0]
                        stats = [
                            first["indexed"],
                            first["oldest"],
                            first["latest"],
                            first["source_count"],
                        ]
                        sources = [
                            {
                                name: entry[name]
                                for name in ("source", "events", "last_seen")
                            }
                            for entry in result["rows"]
                        ]
                    else:
                        stats = [0, None, None, 0]
                    measured_at, state = time.time(), "ready"
                    if len(self._health_cache) >= 256:
                        self._health_cache.clear()
                    self._health_cache[key] = {
                        "stats": stats,
                        "sources": sources,
                        "at": measured_at,
                        "purges": purges,
                        "generation": generation,
                    }
                except (
                    CapacityError,
                    RuntimeError,
                    duckdb.InterruptException,
                    duckdb.OutOfMemoryException,
                ) as exc:
                    if isinstance(exc, CapacityError):
                        analytics_error = "capacity_exhausted"
                    elif isinstance(exc, duckdb.OutOfMemoryException):
                        analytics_error = "memory_budget_exhausted"
                    else:
                        analytics_error = "analytics_deadline_exceeded"
        if analytics_error and cached:
            stats, sources, measured_at = (
                cached["stats"],
                cached["sources"],
                cached["at"],
            )
            state = "stale"
        from . import log_footprint

        errors = {
            "retention_pending": "Retention deletion is pending; search remains unavailable until recovery completes",
            "storage_deadline_exceeded": "Health storage deadline exceeded",
            "capacity_exhausted": "Search concurrency exhausted; retry later",
            "memory_budget_exhausted": "Health analytics memory budget exhausted",
            "analytics_deadline_exceeded": "Health analytics deadline exceeded",
        }
        return {
            "indexed": stats[0],
            "source_count": stats[3],
            "oldest": stats[1],
            "latest": stats[2],
            "pending": row[0],
            "pending_bytes": row[2],
            "oldest_pending_seconds": round(time.time() - row[1], 1) if row[1] else 0,
            "disk_free_bytes": shutil.disk_usage(self.path).free,
            "storage_bytes": _storage_bytes(self.path),
            "storage_bytes_scope": "root_regular_files_only",
            "storage_footprint": log_footprint.status(self.path),
            "analytics_status": {
                "state": state,
                "measured_at": measured_at,
                "age_seconds": None
                if measured_at is None
                else round(time.time() - measured_at, 3),
                "error_code": analytics_error,
                "error": errors.get(analytics_error),
                "budget_seconds": min(2, self.settings.query_timeout),
            },
            "retention_days": policy[0] if policy else self.settings.retention_days,
            "legal_hold": bool(policy[1]) if policy else False,
            "sources": sources,
        }

    def _apply_retention_locked(self, after_delete=None, now=None):
        # Permanent means no time expiry; capacity-tagged intents still recover.
        with self.segment_lock.write(), self.write_lock:
            return self._apply_retention_segments_locked(after_delete, now)

    def _apply_retention_segments_locked(self, after_delete=None, now=None):
        with self.control(local=True) as db:
            if getattr(self, "record_policy", {}).get("permanent", True):
                legacy = db.execute("SELECT i.id,i.tenant FROM retention_intents i LEFT JOIN retention_applied a ON a.id=i.id LEFT JOIN capacity_retention_intents c ON c.intent_id=i.id WHERE a.id IS NULL AND c.intent_id IS NULL").fetchall()
                for intent in legacy:
                    db.execute("INSERT OR IGNORE INTO record_retention_cancellations VALUES(?,?,?,?)", (intent["id"],intent["tenant"],"permanent recording enabled",time.time()))
                    db.execute("INSERT OR IGNORE INTO retention_applied VALUES(?,?)",(intent["id"],time.time()))
                    self.audit(db,intent["tenant"],"system","retention.cancelled.permanent",{"intent_id":intent["id"],"originals_reconstructed":False})
                if legacy:
                    db.execute("UPDATE log_fts_state SET bootstrap_required=1 WHERE singleton=1")
            pending = db.execute(
                "SELECT i.*,c.protect_case_evidence AS capacity_protect_case FROM retention_intents i LEFT JOIN retention_applied a ON a.id=i.id LEFT JOIN capacity_retention_intents c ON c.intent_id=i.id WHERE a.id IS NULL AND (?=0 OR c.intent_id IS NOT NULL) ORDER BY i.created LIMIT 100",
                (int(getattr(self, "record_policy", {}).get("permanent", True)),),
            ).fetchall()
        deleted = 0
        con = self.analytics.cursor()
        try:
            for row in pending:
                ids = json.loads(row["payload"])
                if self.replica:
                    # A no-op quorum commit catches up policy/hold changes while
                    # this writer lease and write_lock exclude local mutations.
                    # read_barrier cannot be used: this intent is not applied yet.
                    self.replica.barrier()
                with self.control(local=True) as db:
                    if row["capacity_protect_case"] is not None:
                        from .pressure_retention import protected_ids

                        saved_policy = db.execute("SELECT definition FROM record_management_policy WHERE singleton=1").fetchone()
                        protect_case = json.loads(saved_policy[0]).get("protect_case_evidence",True) if saved_policy else True
                        held = protected_ids(self, db, row["tenant"], ids, now,
                                             protect_case=bool(row["capacity_protect_case"]) or protect_case)
                    else:
                        held = self.segments.held_ids(db, row["tenant"], ids, now)
                    if held:
                        originals = {
                            key[1]: value["received"]
                            for key, value in self.segments.sealed_keys(
                                [(row["tenant"], ident) for ident in held]
                            ).items()
                            if value["received"] < row["cutoff"]
                        }
                        originals.update(
                            con.execute(
                                "SELECT event_id,received FROM events WHERE tenant=? AND received<? AND event_id IN (SELECT json_extract_string(value,'$') FROM json_each(?))",
                                [row["tenant"], row["cutoff"], encode(sorted(held))],
                            ).fetchall()
                        )
                        receipts = {
                            r[0]
                            for r in db.execute(
                                "SELECT event_id FROM receipts WHERE tenant=? AND event_id IN (SELECT value FROM json_each(?))",
                                (row["tenant"], encode(sorted(held))),
                            )
                        }
                        if set(originals) - receipts:
                            # Older intents or a peer may already have retired
                            # the receipt. Keep held originals and the fence;
                            # accepting that identity would discard a new body.
                            raise ConflictError(
                                "Retained original lacks its admission receipt; retention remains pending"
                            )
                        db.executemany(
                            "INSERT INTO log_retained_identities VALUES(?,?,?) ON CONFLICT(tenant,event_id) DO UPDATE SET received=excluded.received",
                            [
                                (row["tenant"], ident, received)
                                for ident, received in originals.items()
                            ],
                        )
                ids = [ident for ident in ids if ident not in held]
                if ids:
                    # This derivative handoff is node-local, not part of the
                    # replicated policy transaction. Pending retention fences
                    # reads until physical deletion and the applied marker.
                    with self.control(local=True) as db:
                        self.segments.bump(db, purge=True, content=True)
                        from . import log_search

                        log_search.journal_purged(self, db, row["tenant"], ids)
                removed = con.execute(
                    "DELETE FROM events WHERE tenant=? AND received<? AND event_id IN (SELECT json_extract_string(value,'$') FROM json_each(?)) RETURNING event_id",
                    [row["tenant"], row["cutoff"], encode(ids)],
                ).fetchall()
                segment_deleted = self.segments.delete_ids(
                    row["tenant"], ids, row["cutoff"]
                )
                removed_count = len(removed) + segment_deleted
                if removed_count:
                    self.segments.bump(purge=True, content=False)
                if after_delete:
                    after_delete()
                if ids:
                    with self.control() as db:
                        db.execute("BEGIN IMMEDIATE")
                        # Quarantined payloads are original logs too. Retire
                        # them under the same fence, cutoff and immutable IDs.
                        removed_count += db.execute(
                            "DELETE FROM ingest_quarantine WHERE tenant=? AND received<? AND event_id IN (SELECT value FROM json_each(?))",
                            (row["tenant"],row["cutoff"],encode(ids)),
                        ).rowcount
                        # Replicate receipt retirement only after this node has
                        # deleted originals. A later hold keeps both original
                        # and immutable receipt; pending peers fence admission.
                        db.executemany(
                            "DELETE FROM receipts WHERE tenant=? AND event_id=? AND received<? AND NOT EXISTS(SELECT 1 FROM queue q WHERE q.tenant=receipts.tenant AND q.event_id=receipts.event_id)",
                            [(row["tenant"], ident, row["cutoff"]) for ident in ids],
                        )
                        from . import event_projections

                        event_projections.retire(db, row["tenant"], ids, row["cutoff"])
                deleted += removed_count
                with self.write_lock, self.control(local=True) as db:
                    db.executemany(
                        "DELETE FROM log_retained_identities WHERE tenant=? AND event_id=? AND received<?",
                        [(row["tenant"], ident, row["cutoff"]) for ident in ids],
                    )
                    db.execute(
                        "INSERT OR IGNORE INTO retention_applied VALUES(?,?)",
                        (row["id"], time.time()),
                    )
        finally:
            con.close()
        return deleted

    def retain(self, now=None, after_delete=None):
        now = now or time.time()
        deleted = 0
        # Logical expiration is committed before the analytical deletion. The
        # signed intent is replayed on every replica; deletion and replay are
        # idempotent even if the process dies before the local applied marker.
        with self.flush_lock, self.segment_lock.write():
            deleted += self._apply_retention_locked(after_delete, now)
            con = self.analytics.cursor()
            try:
                tenants = [
                    tuple(x)
                    for x in con.execute(
                        "SELECT DISTINCT tenant,index_name FROM events_all"
                    ).fetchall()
                ]
                deadline = time.monotonic() + 10
                for tenant, index in tenants:
                    with self.control(local=True) as db:
                        progress = db.execute(
                            "SELECT event_id FROM log_retention_progress WHERE tenant=? AND index_name=?",
                            (tenant, index),
                        ).fetchone()
                        cursor = progress[0] if progress else None
                    while time.monotonic() < deadline:
                        # Lock policy changes during each bounded deletion batch.
                        with self.write_lock, self.control() as db:
                            policy = self.segments.effective_policy(tenant, index, db)
                            days, hold = policy["retention_days"], policy["hold"]
                            if hold or getattr(self, "record_policy", {}).get("permanent", True) or days == 0:
                                break
                            cutoff = now - days * 86400
                            candidates = con.execute(
                                "SELECT event_id FROM events_all WHERE tenant=? AND index_name=? AND received<? AND (? IS NULL OR event_id>?) ORDER BY event_id LIMIT 5000",
                                [tenant, index, cutoff, cursor, cursor],
                            ).fetchall()
                            if candidates:
                                cursor = candidates[-1][0]
                            held = self.segments.held_ids(
                                db, tenant, [r[0] for r in candidates], now
                            )
                            count = [r for r in candidates if r[0] not in held]
                            if count:
                                db.execute(
                                    "INSERT INTO retention_intents VALUES(?,?,?,?,?)",
                                    (
                                        str(uuid.uuid4()),
                                        tenant,
                                        cutoff,
                                        encode([r[0] for r in count]),
                                        now,
                                    ),
                                )
                                # Expiry is logically committed with the intent.
                                # Invalidate derivative copies even if physical
                                # deletion subsequently fails or is held on replay.
                                self.segments.bump(db, purge=True, content=False)
                            # Preserve receipts until physical deletion succeeds;
                            # a hold installed during recovery must retain the
                            # original identity's immutable admission digest.
                            if count:
                                self.audit(
                                    db,
                                    tenant,
                                    "system",
                                    "retention.plan",
                                    {
                                        "expired_ids": len(count),
                                        "receipt_cutoff": cutoff,
                                    },
                                )
                        deleted += self._apply_retention_locked(after_delete, now)
                        # Retain bounded traversal progress locally. A large
                        # prefix of held events must not consume every pass.
                        with self.control(local=True) as db:
                            if len(candidates) < 5000:
                                db.execute(
                                    "DELETE FROM log_retention_progress WHERE tenant=? AND index_name=?",
                                    (tenant, index),
                                )
                            else:
                                db.execute(
                                    "INSERT INTO log_retention_progress VALUES(?,?,?) ON CONFLICT(tenant,index_name) DO UPDATE SET event_id=excluded.event_id",
                                    (tenant, index, cursor),
                                )
                        if len(candidates) < 5000:
                            break
                con.execute("CHECKPOINT")
            finally:
                con.close()
        with self.control(local=True) as db:
            db.execute("DELETE FROM sessions WHERE expires<?", (now,))
            db.execute(
                "DELETE FROM search_jobs WHERE expires<? AND state IN ('done','failed','cancelled')",
                (now,),
            )
        with self.control(local=True) as db:
            db.execute("PRAGMA wal_checkpoint(PASSIVE)")
        self.segments.maintenance(now=now)
        with self.control(local=True) as db:
            snapshots = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='log_snapshots'"
            ).fetchone()
        if snapshots:
            from .log_search import maintenance as maintain_search_copies

            maintain_search_copies(self)
        return deleted

    def close(self):
        if not self.closed:
            try:
                if self.replica:
                    self.replica.close()
            finally:
                try:
                    self.analytics.close()
                finally:
                    try:
                        self._close_wal_anchor()
                    finally:
                        self.process_lock.close()
                        self.closed = True
