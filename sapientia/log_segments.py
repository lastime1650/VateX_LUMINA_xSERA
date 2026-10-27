"""Node-local, verified Parquet partitions with recoverable publication.

The SQLite catalog is authoritative. Files are flushed before catalog publication;
hot rows disappear only after publication. All four tiers remain searchable. This
is a local lifecycle, not a remote object-store, WORM, or distributed shard manager.
"""

import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from .query import index_predicate

TIERS = ("hot", "warm", "cold", "archive")
COLUMNS = "tenant,event_id,event_time,received,source,sourcetype,host,severity,message,raw,index_name"
POLICY_KEYS = {"hot_days", "warm_days", "cold_days", "retention_days", "hold", "version"}
KEY_FORMAT = 1
PARQUET_ROW_GROUP_ROWS = 16384
# DuckDB 1.5.6 accepts an ordered COPY batch within one 2048-row
# vector of its target. Leave that headroom and verify the physical bound.
PARQUET_ROW_GROUP_TARGET = PARQUET_ROW_GROUP_ROWS - 2048


class SegmentError(RuntimeError):
    pass


class SegmentGate:
    """Concurrent readers, one reentrant writer; never upgrade a read lease."""

    def __init__(self):
        self.condition = threading.Condition(threading.RLock())
        self.readers = 0
        self.writer = None
        self.depth = 0
        self.waiting = 0
        self.local = threading.local()

    @contextmanager
    def read(self, deadline=None):
        ident = threading.get_ident()
        with self.condition:
            nested = getattr(self.local, "reads", 0)
            while self.writer not in (None, ident) or (self.waiting and not nested and self.writer != ident):
                remaining = None if deadline is None else deadline - time.monotonic()
                if remaining is not None and remaining <= 0:
                    raise RuntimeError("Segment read deadline exceeded")
                self.condition.wait(remaining)
            if deadline is not None and time.monotonic() >= deadline:
                raise RuntimeError("Segment read deadline exceeded")
            self.readers += 1
            self.local.reads = nested + 1
        try:
            yield
        finally:
            with self.condition:
                self.readers -= 1
                self.local.reads -= 1
                self.condition.notify_all()

    @contextmanager
    def write(self):
        ident = threading.get_ident()
        with self.condition:
            if self.writer == ident:
                self.depth += 1
            else:
                if getattr(self.local, "reads", 0):
                    raise SegmentError("Cannot upgrade a segment read lease")
                self.waiting += 1
                try:
                    while self.writer is not None or self.readers:
                        self.condition.wait()
                    self.writer, self.depth = ident, 1
                finally:
                    self.waiting -= 1
        try:
            yield
        finally:
            with self.condition:
                self.depth -= 1
                if not self.depth:
                    self.writer = None
                    self.condition.notify_all()


def file_hash(path, deadline=None):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            if deadline is not None and time.monotonic() >= deadline:
                raise RuntimeError("Segment read deadline exceeded")
            digest.update(block)
    return digest.hexdigest()


def sql_path(path):
    # Only server-generated, containment-checked paths reach this function.
    return "'" + Path(path).as_posix().replace("'", "''") + "'"


def _sync(path):
    with Path(path).open("r+b") as stream:
        os.fsync(stream.fileno())


def _sync_directory(path):
    if os.name != "nt":
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class SegmentManager:
    def __init__(self, store):
        self.store = store
        self.root = store.path / "log-segments"
        self.root.mkdir(exist_ok=True)
        if self.root.is_symlink() or self.root.resolve() != self.root:
            raise SegmentError("Segment directory must be a local managed directory")
        self.checked = {}
        self.keys_ready = False
        self.clean_manifest = None
        with store.control(local=True) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS log_segments(
                    id TEXT PRIMARY KEY,tenant TEXT NOT NULL,index_name TEXT NOT NULL,
                    day INTEGER NOT NULL,tier TEXT NOT NULL,path TEXT NOT NULL UNIQUE,
                    sha256 TEXT NOT NULL,rows INTEGER NOT NULL,min_time REAL,max_time REAL,
                    min_received REAL,max_received REAL,state TEXT NOT NULL,
                    created REAL NOT NULL,updated REAL NOT NULL,revision INTEGER NOT NULL DEFAULT 1);
                CREATE INDEX IF NOT EXISTS log_segment_scope ON log_segments(tenant,index_name,state);
                CREATE TABLE IF NOT EXISTS log_index_policies(
                    tenant TEXT NOT NULL,index_name TEXT NOT NULL,hot_days INTEGER NOT NULL,
                    warm_days INTEGER NOT NULL,cold_days INTEGER NOT NULL,retention_days INTEGER NOT NULL,
                    hold INTEGER NOT NULL,version INTEGER NOT NULL,updated REAL NOT NULL,
                    PRIMARY KEY(tenant,index_name));
                CREATE TABLE IF NOT EXISTS log_event_generation(
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),value INTEGER NOT NULL,purges INTEGER NOT NULL DEFAULT 0);
                INSERT OR IGNORE INTO log_event_generation(singleton,value) VALUES(1,0);
                CREATE TABLE IF NOT EXISTS log_evidence_holds(
                    tenant TEXT NOT NULL,index_name TEXT NOT NULL,event_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,created REAL NOT NULL,expires REAL,reason TEXT NOT NULL,
                    PRIMARY KEY(tenant,event_id,case_id));
                CREATE TABLE IF NOT EXISTS log_retention_progress(
                    tenant TEXT NOT NULL,index_name TEXT NOT NULL,event_id TEXT NOT NULL,
                    PRIMARY KEY(tenant,index_name));
                CREATE TABLE IF NOT EXISTS log_sealed_keys(
                    tenant TEXT NOT NULL,event_id TEXT NOT NULL,segment_id TEXT NOT NULL,
                    received REAL NOT NULL,PRIMARY KEY(tenant,event_id)) WITHOUT ROWID;
                CREATE INDEX IF NOT EXISTS log_sealed_keys_segment
                    ON log_sealed_keys(segment_id,tenant,event_id,received);
                CREATE TABLE IF NOT EXISTS log_sealed_key_manifests(
                    segment_id TEXT PRIMARY KEY,sha256 TEXT NOT NULL,rows INTEGER NOT NULL,
                    key_digest TEXT NOT NULL,format_version INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS log_sealed_key_state(
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),format_version INTEGER NOT NULL);
            """)
            if "purges" not in {row[1] for row in db.execute("PRAGMA table_info(log_event_generation)")}:
                db.execute("ALTER TABLE log_event_generation ADD COLUMN purges INTEGER NOT NULL DEFAULT 0")
            if "content" not in {row[1] for row in db.execute("PRAGMA table_info(log_event_generation)")}:
                db.execute("ALTER TABLE log_event_generation ADD COLUMN content INTEGER NOT NULL DEFAULT 0")
        with store.segment_lock.write(), store.write_lock:
            self.verify(deep=True)
            self._initialize_keys()
            self._reconcile_hot()
            self._refresh_view()
            self._clean_orphans()
            self.bump(content=False)

    def _rows(self):
        with self.store.control(local=True) as db:
            return [dict(row) for row in db.execute("SELECT * FROM log_segments WHERE state='ready' ORDER BY id")]

    def _path(self, relative):
        if not isinstance(relative, str) or not re.fullmatch(
            r"(?:hot|warm|cold|archive)/[0-9a-f]{32}/[A-Za-z0-9_-]{1,64}/[0-9]{1,8}/[0-9a-f]{32}\.parquet", relative
        ):
            raise SegmentError("Invalid managed segment path")
        candidate = self.root / relative
        if not candidate.resolve().is_relative_to(self.root.resolve()):
            raise SegmentError("Segment path escapes the managed directory")
        if candidate.is_symlink() or any(parent.is_symlink() for parent in candidate.parents if parent != self.root.parent):
            raise SegmentError("Segment symlinks are not supported")
        return candidate

    def _new_path(self, tenant, index, day, tier):
        tenant_id = hashlib.sha256(tenant.encode()).hexdigest()[:32]
        relative = f"{tier}/{tenant_id}/{index}/{day}/{uuid.uuid4().hex}.parquet"
        path = self._path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        return relative, path

    def bump(self, db=None, purge=False, content=True):
        if db is not None:
            db.execute("UPDATE log_event_generation SET value=value+1,purges=purges+?,content=content+? WHERE singleton=1", (int(purge), int(content)))
        else:
            with self.store.control(local=True) as local:
                self.bump(local, purge, content)

    @property
    def generation(self):
        with self.store.control(local=True) as db:
            return db.execute("SELECT value FROM log_event_generation WHERE singleton=1").fetchone()[0]

    @property
    def purge_generation(self):
        with self.store.control(local=True) as db:
            return db.execute("SELECT purges FROM log_event_generation WHERE singleton=1").fetchone()[0]

    @property
    def content_generation(self):
        with self.store.control(local=True) as db:
            return db.execute("SELECT content FROM log_event_generation WHERE singleton=1").fetchone()[0]

    @staticmethod
    def _key_bytes(tenant, event_id, received):
        return (json.dumps([tenant, event_id, float(received)], ensure_ascii=False,
                           separators=(",", ":"), allow_nan=False) + "\n").encode()

    def _catalog_keys(self, db, row, path, replacement=False):
        """Publish one bounded segment's exact keys in its catalog transaction."""
        previous = None
        if replacement:
            previous = {tuple(key) for key in db.execute(
                "SELECT tenant,event_id,received FROM log_sealed_keys WHERE segment_id=?", (row["id"],))}
        db.execute("DELETE FROM log_sealed_keys WHERE segment_id=?", (row["id"],))
        digest, count = hashlib.sha256(), 0
        con = self.store.analytics.cursor()
        try:
            con.execute("SELECT tenant,event_id,received FROM read_parquet(" + sql_path(path) + ") ORDER BY tenant,event_id")
            while keys := con.fetchmany(1000):
                for tenant, event_id, received in keys:
                    if tenant != row["tenant"] or not isinstance(event_id, str) or not isinstance(received, (float, int)) or not math.isfinite(received):
                        raise SegmentError("Segment identity metadata is invalid")
                    if previous is not None and (tenant, event_id, received) not in previous:
                        raise SegmentError("Segment replacement cannot add or change event identities")
                    digest.update(self._key_bytes(tenant, event_id, received))
                try:
                    db.executemany("INSERT INTO log_sealed_keys VALUES(?,?,?,?)",
                                   [(tenant, event_id, row["id"], received) for tenant, event_id, received in keys])
                except sqlite3.IntegrityError as exc:
                    raise SegmentError("Sealed event identity is duplicated; publication refused") from exc
                count += len(keys)
            if count != row["rows"]:
                raise SegmentError("Segment row count disagrees with its identity catalog")
            db.execute("INSERT OR REPLACE INTO log_sealed_key_manifests VALUES(?,?,?,?,?)",
                       (row["id"], row["sha256"], count, digest.hexdigest(), KEY_FORMAT))
        finally:
            con.close()

    def _initialize_keys(self):
        rows = self._rows()
        with self.store.control(local=True) as db:
            state = db.execute("SELECT format_version FROM log_sealed_key_state WHERE singleton=1").fetchone()
            if state is None:
                # One-time old-store migration. The format marker and every key
                # commit together; a crash cannot publish a partial migration.
                db.execute("BEGIN IMMEDIATE")
                db.execute("DELETE FROM log_sealed_keys")
                db.execute("DELETE FROM log_sealed_key_manifests")
                for row in rows:
                    self._catalog_keys(db, row, self._path(row["path"]))
                db.execute("INSERT INTO log_sealed_key_state VALUES(1,?)", (KEY_FORMAT,))
            elif state[0] != KEY_FORMAT:
                raise SegmentError("Unsupported sealed identity catalog format")
        self.keys_ready = True
        self._validate_keys(rows, deep=True)

    def _validate_keys(self, rows, deep=False, deadline=None):
        """Read-verify existing keys at startup/deep verify, never rewrite them."""
        with self.store.control(local=True) as db:
            manifests = {row["segment_id"]: dict(row) for row in db.execute("SELECT * FROM log_sealed_key_manifests")}
            if set(manifests) != {row["id"] for row in rows}:
                raise SegmentError("Sealed identity catalog manifest needs reconciliation")
            for row in rows:
                actual = manifests[row["id"]]
                if (actual["sha256"], actual["rows"], actual["format_version"]) != (row["sha256"], row["rows"], KEY_FORMAT):
                    raise SegmentError("Sealed identity catalog manifest mismatch")
                if deep:
                    digest, count = hashlib.sha256(), 0
                    cursor = db.execute("SELECT tenant,event_id,received FROM log_sealed_keys WHERE segment_id=? ORDER BY tenant,event_id", (row["id"],))
                    while keys := cursor.fetchmany(1000):
                        if deadline is not None and time.monotonic() >= deadline:
                            raise RuntimeError("Segment read deadline exceeded")
                        for tenant, event_id, received in keys:
                            if tenant != row["tenant"]:
                                raise SegmentError("Sealed identity catalog tenant mismatch")
                            digest.update(self._key_bytes(tenant, event_id, received))
                        count += len(keys)
                    if (count, digest.hexdigest()) != (actual["rows"], actual["key_digest"]):
                        raise SegmentError("Sealed identity catalog checksum mismatch")
            if deep and db.execute("SELECT 1 FROM log_sealed_keys k LEFT JOIN log_sealed_key_manifests m ON m.segment_id=k.segment_id WHERE m.segment_id IS NULL LIMIT 1").fetchone():
                raise SegmentError("Sealed identity catalog contains orphan keys")

    def sealed_keys(self, pairs):
        """Bounded incoming-key lookups, never scan the historical key set."""
        result = {}
        with self.store.control(local=True) as db:
            for start in range(0, len(pairs), 400):
                part = pairs[start:start + 400]
                placeholders = ",".join("(?,?)" for _ in part)
                # CROSS JOIN fixes the small VALUES relation as the outer loop;
                # the WITHOUT ROWID composite PK supplies exact point lookups.
                sql = "WITH wanted(tenant,event_id) AS (VALUES " + placeholders + ") SELECT k.tenant,k.event_id,k.received,k.segment_id FROM wanted CROSS JOIN log_sealed_keys k WHERE k.tenant=wanted.tenant AND k.event_id=wanted.event_id"
                for row in db.execute(sql, [item for pair in part for item in pair]):
                    result[(row["tenant"], row["event_id"])] = dict(row)
        return result

    def held_ids(self, db, tenant, ids, now=None):
        if not ids:
            return set()
        now = time.time() if now is None else now
        policy = db.execute("SELECT hold FROM policies WHERE tenant=?", (tenant,)).fetchone()
        if policy and policy[0]:
            return set(ids)
        placeholders = ",".join("?" for _ in ids)
        held = {row[0] for row in db.execute("SELECT event_id FROM log_evidence_holds WHERE tenant=? AND event_id IN (" + placeholders + ") AND (expires IS NULL OR expires>?)", (tenant, *ids, now))}
        indexes = [row[0] for row in db.execute("SELECT index_name FROM log_index_policies WHERE tenant=? AND hold=1", (tenant,))]
        if indexes:
            held.update(row[0] for row in self.store.analytics.execute(
                "SELECT event_id FROM events_all WHERE tenant=? AND index_name IN (SELECT json_extract_string(value,'$') FROM json_each(?)) AND event_id IN (SELECT json_extract_string(value,'$') FROM json_each(?))",
                [tenant, json.dumps(indexes), json.dumps(ids)]).fetchall())
        return held

    def verify(self, deep=False, deadline=None):
        total = 0
        rows = self._rows()
        for row in rows:
            if deadline is not None and time.monotonic() >= deadline:
                raise RuntimeError("Segment read deadline exceeded")
            path = self._path(row["path"])
            try:
                stat = path.stat()
                fingerprint = (stat.st_size, stat.st_mtime_ns, stat.st_ino)
                if deep or self.checked.get(row["id"]) != (row["sha256"], fingerprint):
                    if file_hash(path, deadline) != row["sha256"]:
                        raise SegmentError(f"Segment checksum mismatch: {row['id']}")
                    self.checked[row["id"]] = (row["sha256"], fingerprint)
            except OSError as exc:
                raise SegmentError(f"Segment missing or unreadable: {row['id']}") from exc
            total += 1
        if self.keys_ready:
            self._validate_keys(rows, deep=deep, deadline=deadline)
        return {"valid": True, "segments": total, "mode": "full_sha256" if deep else "sha256_on_stat_change"}

    def ensure_readable(self, deadline=None):
        self.verify(deadline=deadline)
        manifest = [(row["id"], row["path"], row["sha256"]) for row in self._rows()]
        if manifest != self.view_manifest:
            raise SegmentError("Segment publication needs reconciliation; run lifecycle maintenance or restart")

    def backup_files(self, verify=True):
        if verify:
            self.verify(deep=True)
        return [{"path": "log-segments/" + row["path"], "sha256": row["sha256"],
                 "size": self._path(row["path"]).stat().st_size} for row in self._rows()]

    def _refresh_view(self):
        rows = self._rows()
        manifest = [(row["id"], row["path"], row["sha256"]) for row in rows]
        if self.clean_manifest != manifest:
            raise SegmentError("Hot/sealed identity reconciliation is incomplete")
        self._validate_keys(rows)
        if rows:
            paths = ",".join(sql_path(self._path(row["path"])) for row in rows)
            sealed = f"read_parquet([{paths}],union_by_name=true)"
            self.store.analytics.execute("CREATE OR REPLACE VIEW events_sealed_keys AS SELECT tenant,event_id FROM " + sealed)
            self.store.analytics.execute(
                "CREATE OR REPLACE VIEW events_all AS SELECT " + COLUMNS
                + " FROM events UNION ALL SELECT " + COLUMNS + " FROM " + sealed
            )
        else:
            self.store.analytics.execute("CREATE OR REPLACE VIEW events_sealed_keys AS SELECT CAST(NULL AS VARCHAR) AS tenant,CAST(NULL AS VARCHAR) AS event_id WHERE FALSE")
            self.store.analytics.execute("CREATE OR REPLACE VIEW events_all AS SELECT " + COLUMNS + " FROM events")
        self.view_manifest = manifest

    def _remove_hot_keys(self, keys):
        if not keys:
            return
        relation = "SELECT value->>0 AS tenant,value->>1 AS event_id,CAST(value->>2 AS DOUBLE) AS received FROM json_each(?)"
        encoded = json.dumps(keys)
        overlap = self.store.analytics.execute(
            "SELECT e.tenant,e.event_id FROM events e JOIN (" + relation
            + ") k USING(tenant,event_id) WHERE e.received<>k.received LIMIT 1", [encoded]).fetchone()
        if overlap:
            raise SegmentError("Hot/sealed event identity has conflicting receipt times")
        self.store.analytics.execute(
            "DELETE FROM events USING (" + relation + ") k WHERE events.tenant=k.tenant AND events.event_id=k.event_id AND events.received=k.received", [encoded])

    def _reconcile_hot(self, segment_ids=None):
        rows = self._rows()
        if rows and self.store.analytics.execute("SELECT count(*) FROM events").fetchone()[0]:
            if segment_ids is not None:
                with self.store.control(local=True) as db:
                    for ident in segment_ids:
                        cursor = db.execute("SELECT tenant,event_id,received FROM log_sealed_keys WHERE segment_id=?", (ident,))
                        # Seal files contain at most 100k identities. One
                        # bounded derived relation avoids rescanning the hot
                        # table for every small SQLite fetch chunk.
                        while keys := cursor.fetchmany(100000):
                            self._remove_hot_keys([tuple(key) for key in keys])
            else:
                # Startup/interrupted publication: scan hot keys once and point
                # lookup only those keys; historical Parquet is never rescanned.
                cursor = self.store.analytics.cursor()
                try:
                    cursor.execute("SELECT tenant,event_id FROM events")
                    overlaps = []
                    while keys := cursor.fetchmany(1000):
                        found = self.sealed_keys(keys)
                        overlaps.extend((tenant, event_id, value["received"]) for (tenant, event_id), value in found.items())
                        if len(overlaps) >= 100000:
                            self._remove_hot_keys(overlaps[:100000])
                            del overlaps[:100000]
                    self._remove_hot_keys(overlaps)
                finally:
                    cursor.close()
        self.clean_manifest = [(row["id"], row["path"], row["sha256"]) for row in rows]

    def _clean_orphans(self):
        active = {row["path"] for row in self._rows()}
        # The backup service owns .snapshots beneath the allowlisted root.
        # Reconciliation owns only lifecycle tier directories.
        paths = (path for tier in TIERS for path in (self.root / tier).rglob("*"))
        for path in paths:
            if path.is_symlink():
                raise SegmentError("Unexpected symlink in segment directory")
            if path.is_file() and path.suffix == ".parquet" and path.relative_to(self.root).as_posix() not in active:
                # Only the exact application-owned path grammar can be removed.
                managed = self._path(path.relative_to(self.root).as_posix())
                managed.unlink()
            elif path.is_file() and re.fullmatch(r"\.pending-[0-9a-f]{32}", path.name):
                path.unlink()

    def effective_policy(self, tenant, index, db=None):
        if db is None:
            with self.store.control() as local:
                return self.effective_policy(tenant, index, local)
        tenant_row = db.execute("SELECT days,hold FROM policies WHERE tenant=?", (tenant,)).fetchone()
        days, hold = tuple(tenant_row) if tenant_row else (self.store.settings.retention_days, 0)
        row = db.execute("SELECT * FROM log_index_policies WHERE tenant=? AND index_name=?", (tenant, index)).fetchone()
        if row:
            result = dict(row)
            result["hold"] = bool(hold or result["hold"])
            result["retention_days"] = 0
            result["permanent"] = True
            return result
        # Boundaries are cumulative ages since admission; short retention can
        # expire data before it reaches a later tier.
        return {"tenant": tenant, "index_name": index, "hot_days": 1, "warm_days": 7,
                "cold_days": 30, "retention_days": 0, "permanent": True, "hold": bool(hold), "version": 0}

    def policies(self, tenant):
        with self.store.control() as db:
            return [dict(row) | {"hold": bool(row["hold"])} for row in db.execute(
                "SELECT * FROM log_index_policies WHERE tenant=? ORDER BY index_name", (tenant,))]

    def save_policy(self, tenant, index, data, actor="system"):
        index_predicate([index])
        if index == "*" or not isinstance(data, dict) or set(data) != POLICY_KEYS:
            raise ValueError("Exact index and hot_days,warm_days,cold_days,retention_days,hold,version required")
        ages = [data[key] for key in ("hot_days", "warm_days", "cold_days", "retention_days")]
        if any(type(value) is not int for value in ages) or not 1 <= ages[0] < ages[1] < ages[2] or ages[3] != 0:
            raise ValueError("Lifecycle requires 1 <= hot < warm < cold; retention_days=0 for permanent records")
        if type(data["hold"]) is not bool or type(data["version"]) is not int or data["version"] < 0:
            raise ValueError("hold must be boolean and version a nonnegative integer")
        from .storage import ConflictError
        with self.store.write_lock, self.store.control() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT version FROM log_index_policies WHERE tenant=? AND index_name=?", (tenant, index)).fetchone()
            version = old[0] if old else 0
            if version != data["version"]:
                raise ConflictError("Index lifecycle version changed")
            db.execute("INSERT INTO log_index_policies VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant,index_name) DO UPDATE SET hot_days=excluded.hot_days,warm_days=excluded.warm_days,cold_days=excluded.cold_days,retention_days=excluded.retention_days,hold=excluded.hold,version=excluded.version,updated=excluded.updated",
                       (tenant, index, *ages, int(data["hold"]), version + 1, time.time()))
            self.store.audit(db, tenant, actor, "log.lifecycle.save", {"index": index, **data, "version": version + 1})
        return self.effective_policy(tenant, index)

    @staticmethod
    def _tier(age_days, policy):
        if age_days >= policy["cold_days"]:
            return "archive"
        if age_days >= policy["warm_days"]:
            return "cold"
        return "warm"

    def _metrics(self, path):
        row = self.store.analytics.execute(
            "SELECT count(*),min(event_time),max(event_time),min(received),max(received) FROM read_parquet(" + sql_path(path) + ")"
        ).fetchone()
        return tuple(row)

    def _disk_reserve(self, path, extra=0):
        from .storage import CapacityError

        if shutil.disk_usage(path.parent).free < self.store.settings.min_free_bytes + extra:
            raise CapacityError("Segment disk reserve reached; source remains unchanged")

    def _max_row_group_rows(self, path):
        con = self.store.analytics.cursor()
        try:
            return con.execute("SELECT coalesce(max(row_group_num_rows),0) FROM parquet_metadata(?)", [str(path)]).fetchone()[0]
        finally:
            con.close()

    def _copy_query(self, sql, args, path):
        pending = path.parent / (".pending-" + uuid.uuid4().hex)
        try:
            self._disk_reserve(path)
            self.store.analytics.execute("COPY (" + sql + ") TO " + sql_path(pending)
                                         + f" (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE {PARQUET_ROW_GROUP_TARGET})", args)
            self._disk_reserve(path)
            if self._max_row_group_rows(pending) > PARQUET_ROW_GROUP_ROWS:
                raise SegmentError("Segment row-group bound exceeded; publication refused")
            _sync(pending)
            digest = file_hash(pending)
            os.replace(pending, path)
            _sync_directory(path.parent)
            return digest
        finally:
            if pending.exists():
                pending.unlink()

    def _replace(self, row, sql, args, tier=None, refresh=True):
        tier = tier or row["tier"]
        relative, path = self._new_path(row["tenant"], row["index_name"], row["day"], tier)
        digest = self._copy_query(sql, args, path)
        metrics = self._metrics(path)
        with self.store.control(local=True) as db:
            db.execute("BEGIN IMMEDIATE")
            updated = dict(row, path=relative, sha256=digest, rows=metrics[0])
            self._catalog_keys(db, updated, path, replacement=True)
            db.execute("UPDATE log_segments SET path=?,sha256=?,rows=?,min_time=?,max_time=?,min_received=?,max_received=?,tier=?,state=?,updated=?,revision=revision+1 WHERE id=?",
                       (relative, digest, *metrics, tier, "ready" if metrics[0] else "deleted", time.time(), row["id"]))
            if not metrics[0]:
                db.execute("DELETE FROM log_sealed_key_manifests WHERE segment_id=?", (row["id"],))
            self.bump(db, purge=metrics[0] < row["rows"], content=False)
        if refresh:
            self._finish_replacements()
        self._path(row["path"]).unlink(missing_ok=True)
        if not metrics[0]:
            path.unlink()
        return row["rows"] - metrics[0]

    def _finish_replacements(self):
        # Replacement validation proves the new identities are a subset of
        # already-reconciled identities, so no hot overlap can be introduced.
        self.clean_manifest = [(row["id"], row["path"], row["sha256"]) for row in self._rows()]
        self._refresh_view()

    def repack(self, max_files=8, max_seconds=60):
        """Explicitly repair legacy wide row groups at complete-file boundaries.

        Verification and metadata discovery, lock waits, and a running file's
        COPY/fsync/catalog work can exceed the cooperative time budget. Row
        groups bound rows, not compressed bytes, memory use, or I/O latency.
        """
        if type(max_files) is not int or not 1 <= max_files <= 64:
            raise ValueError("Repack max_files must be 1..64")
        if (isinstance(max_seconds, bool) or not isinstance(max_seconds, (int, float))
                or not math.isfinite(max_seconds) or not 0.01 <= max_seconds <= 3600):
            raise ValueError("Repack max_seconds must be finite and in [0.01,3600]")
        began = time.monotonic()
        rewritten, events = 0, 0
        with self.store.flush_lock, self.store.segment_lock.write(), self.store.write_lock:
            self.ensure_readable()
            content, purges = self.content_generation, self.purge_generation
            targets = [row for row in self._rows()
                       if self._max_row_group_rows(self._path(row["path"])) > PARQUET_ROW_GROUP_ROWS]
            for row in targets:
                if rewritten >= max_files or time.monotonic() - began >= max_seconds:
                    break
                source = self._path(row["path"])
                # Existing size is a conservative preflight, never a promise
                # that the replacement will compress equally. The writer also
                # rechecks reserve after writing, before any publication.
                self._disk_reserve(source, extra=source.stat().st_size)
                self._replace(row, "SELECT " + COLUMNS + " FROM read_parquet(" + sql_path(source) + ")", [])
                rewritten += 1
                events += row["rows"]
            if content != self.content_generation or purges != self.purge_generation:
                raise SegmentError("Repacking changed the logical content generation")
            return {"rewritten_segments": rewritten, "rewritten_events": events,
                    "remaining_segments": len(targets) - rewritten, "complete": rewritten == len(targets),
                    "physical_generation": self.generation, "content_generation": content, "purge_generation": purges,
                    "row_group_rows": PARQUET_ROW_GROUP_ROWS,
                    "row_group_target_rows": PARQUET_ROW_GROUP_TARGET,
                    "budget_semantics": "cooperative_per_file_not_hard_io_deadline"}

    def delete_ids(self, tenant, ids, cutoff):
        """Internal: caller holds flush_lock and the segment writer lease."""
        if not ids:
            return 0
        self.ensure_readable()
        deleted = 0
        targets = {value["segment_id"] for value in self.sealed_keys([(tenant, ident) for ident in ids]).values()
                   if value["received"] < cutoff}
        with self.store.control(local=True) as db:
            rows = [dict(db.execute("SELECT * FROM log_segments WHERE id=? AND state='ready'", (ident,)).fetchone()) for ident in targets]
        for row in rows:
            path = sql_path(self._path(row["path"]))
            predicate = "tenant=? AND received<? AND event_id IN (SELECT json_extract_string(value,'$') FROM json_each(?))"
            args = [tenant, cutoff, json.dumps(ids)]
            count = self.store.analytics.execute("SELECT count(*) FROM read_parquet(" + path + ") WHERE " + predicate, args).fetchone()[0]
            if count == row["rows"] and count:
                # A complete file can be unpublished and unlinked without
                # writing an empty replacement on a nearly full filesystem.
                # The writer lease excludes readers. Catalog commit precedes
                # unlink; startup orphan cleanup recovers a crash in between.
                with self.store.control(local=True) as db:
                    db.execute("BEGIN IMMEDIATE")
                    db.execute("UPDATE log_segments SET state='deleted',rows=0,updated=?,revision=revision+1 WHERE id=?", (time.time(),row["id"]))
                    db.execute("DELETE FROM log_sealed_keys WHERE segment_id=?", (row["id"],))
                    db.execute("DELETE FROM log_sealed_key_manifests WHERE segment_id=?", (row["id"],))
                    self.bump(db,purge=True,content=False)
                self._finish_replacements()
                source = self._path(row["path"])
                source.unlink(missing_ok=True)
                _sync_directory(source.parent)
                deleted += count
            elif count:
                # Reserve room for the complete replacement before modifying
                # the source. Failure retains the pending intent for recovery.
                self._disk_reserve(self._path(row["path"]),extra=self._path(row["path"]).stat().st_size)
                deleted += self._replace(row, "SELECT " + COLUMNS + " FROM read_parquet(" + path + ") WHERE NOT (" + predicate + ")", args, refresh=False)
        if deleted:
            self._finish_replacements()
        return deleted

    def seal(self, tenant=None, index=None, now=None, batch=5000, after_publish=None):
        if type(batch) is not int or not 1 <= batch <= 100000:
            raise ValueError("Seal batch must be 1..100000")
        if index is not None:
            index_predicate([index])
            if index == "*":
                raise ValueError("Sealing requires an exact index")
        now = time.time() if now is None else now
        if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now) or now < 0:
            raise ValueError("Lifecycle time must be finite epoch seconds")
        with self.store.flush_lock, self.store.segment_lock.write(), self.store.write_lock:
            self.verify()
            manifest = [(row["id"], row["path"], row["sha256"]) for row in self._rows()]
            if self.clean_manifest != manifest:
                self._reconcile_hot()
            self._refresh_view()
            where, args = [], []
            if tenant is not None:
                where.append("tenant=?")
                args.append(tenant)
            if index is not None:
                where.append("index_name=?")
                args.append(index)
            # Limit eligible partitions, not arbitrary hot groups. Otherwise
            # recent admissions with old event timestamps can indefinitely
            # occupy the first 64 groups ahead of sealable data.
            with self.store.control() as db:
                boundaries = [dict(row) for row in db.execute("SELECT tenant,index_name,hot_days FROM log_index_policies")]
            eligible = "SELECT e.tenant,e.index_name,CAST(floor(e.event_time/86400) AS BIGINT) AS day FROM events e LEFT JOIN (SELECT value->>'tenant' AS tenant,value->>'index_name' AS index_name,CAST(value->>'hot_days' AS BIGINT) AS hot_days FROM json_each(?)) p ON p.tenant=e.tenant AND p.index_name=e.index_name WHERE e.received < ?-coalesce(p.hot_days,1)*86400"
            if where:
                eligible += " AND " + " AND ".join("e." + item for item in where)
            groups = self.store.analytics.execute(eligible + " GROUP BY ALL ORDER BY day LIMIT 64", [json.dumps(boundaries), now, *args]).fetchall()
            sealed = 0
            published = []
            for scope_tenant, scope_index, day in groups:
                policy = self.effective_policy(scope_tenant, scope_index)
                cutoff = now - policy["hot_days"] * 86400
                sql = "SELECT " + COLUMNS + " FROM events WHERE tenant=? AND index_name=? AND event_time>=? AND event_time<? AND received<? ORDER BY received,event_id LIMIT ?"
                query_args = [scope_tenant, scope_index, day * 86400, (day + 1) * 86400, cutoff, batch]
                metrics = self.store.analytics.execute("SELECT count(*),min(event_time),max(event_time),min(received),max(received) FROM (" + sql + ")", query_args).fetchone()
                if not metrics[0]:
                    continue
                tier = self._tier((now - metrics[4]) / 86400, policy)
                relative, path = self._new_path(scope_tenant, scope_index, day, tier)
                digest = self._copy_query(sql, query_args, path)
                ident = uuid.uuid4().hex
                with self.store.control(local=True) as db:
                    db.execute("BEGIN IMMEDIATE")
                    self._catalog_keys(db, {"id": ident, "tenant": scope_tenant, "sha256": digest, "rows": metrics[0]}, path)
                    db.execute("INSERT INTO log_segments VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)",
                               (ident, scope_tenant, scope_index, day, tier, relative, digest, *metrics, "ready", now, now))
                    self.bump(db, content=False)
                # A crash here leaves both copies; startup reconciliation and
                # the reader gate prevent publication of duplicate identities.
                published.append(ident)
                if after_publish:
                    after_publish()
                sealed += metrics[0]
            if published:
                self._reconcile_hot(published)
                self._refresh_view()
            return {"sealed_events": sealed, "searchable_tiers": list(TIERS), "generation": self.generation}

    def maintenance(self, now=None, tenant=None, index=None, batch=5000):
        now = time.time() if now is None else now
        result = self.seal(tenant, index, now, batch)
        moved = 0
        with self.store.flush_lock, self.store.segment_lock.write(), self.store.write_lock:
            self.ensure_readable()
            for row in self._rows():
                if (tenant is not None and row["tenant"] != tenant) or (index is not None and row["index_name"] != index):
                    continue
                policy = self.effective_policy(row["tenant"], row["index_name"])
                target = self._tier((now - row["max_received"]) / 86400, policy)
                # A hold prevents expiry, not safe movement between searchable tiers.
                if TIERS.index(target) > TIERS.index(row["tier"]):
                    self._replace(row, "SELECT " + COLUMNS + " FROM read_parquet(" + sql_path(self._path(row["path"])) + ")", [], target, refresh=False)
                    moved += 1
            if moved:
                self._finish_replacements()
            self._clean_orphans()
        return {**result, "moved_segments": moved, "generation": self.generation}

    def status(self, tenant=None, allowed_indexes=None):
        with self.store.segment_lock.read():
            self.ensure_readable()
            return self._status(tenant, allowed_indexes)

    def _status(self, tenant=None, allowed_indexes=None):
        index_predicate(allowed_indexes)
        rows = [row for row in self._rows() if (tenant is None or row["tenant"] == tenant)
                and (allowed_indexes is None or allowed_indexes == ["*"] or row["index_name"] in allowed_indexes)]
        totals = {tier: {"segments": 0, "events": 0, "bytes": 0} for tier in TIERS}
        totals["hot"]["bytes"] = None
        predicate, args = index_predicate(allowed_indexes)
        if tenant is not None:
            predicate = "tenant=? AND " + predicate
            args.insert(0, tenant)
        totals["hot"]["events"] = self.store.analytics.execute(
            "SELECT count(*) FROM events WHERE " + predicate, args).fetchone()[0]
        for row in rows:
            totals[row["tier"]]["segments"] += 1
            totals[row["tier"]]["events"] += row["rows"]
            totals[row["tier"]]["bytes"] += self._path(row["path"]).stat().st_size
        return {"tiers": totals, "segments": rows, "generation": self.generation,
                "hot_bytes_attribution": "shared_duckdb_not_attributed",
                "searchable_tiers": list(TIERS), "partition": "tenant/index/UTC_event_day",
                "lifecycle_clock": "received", "archive": "local_searchable_parquet",
                "verification": "startup/full explicit SHA256; on search stat-change SHA256"}
