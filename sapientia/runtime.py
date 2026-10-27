"""Durable tenant-fair scheduling and bounded adaptive indexing."""

import hashlib
import json
import logging
import math
import re
import threading
import time
import uuid

from .query import Query
from .storage import CapacityError, encode

LOG = logging.getLogger("sapientia")


def initialize(store):
    # Separate metadata preserves the legacy rules table and its INSERT arity.
    with store.control(local=True) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS rule_execution(
            rule_id TEXT PRIMARY KEY,owner TEXT,failures INTEGER NOT NULL DEFAULT 0,
            retry_at REAL NOT NULL DEFAULT 0,last_attempt REAL,last_success REAL,
            duration_ms REAL,state TEXT NOT NULL DEFAULT 'ready');
        CREATE TABLE IF NOT EXISTS scheduler_cursor(id INTEGER PRIMARY KEY,tenant TEXT);
        CREATE TABLE IF NOT EXISTS rule_detection_options(rule_id TEXT PRIMARY KEY,
          trigger TEXT NOT NULL,case_adapter TEXT);
        CREATE TRIGGER IF NOT EXISTS rule_detection_options_delete AFTER DELETE ON rules
        BEGIN DELETE FROM rule_detection_options WHERE rule_id=OLD.id; END;
        CREATE TRIGGER IF NOT EXISTS rule_execution_delete AFTER DELETE ON rules
        BEGIN DELETE FROM rule_execution WHERE rule_id=OLD.id; END;
        INSERT OR IGNORE INTO scheduler_cursor VALUES(1,'');
        INSERT OR IGNORE INTO rule_execution(rule_id,owner)
        SELECT r.id,(SELECT a.actor FROM audit a
          WHERE a.action='rule.create' AND a.tenant=r.tenant AND json_valid(a.detail)
          AND json_extract(a.detail,'$.id')=r.id ORDER BY a.seq DESC LIMIT 1)
        FROM rules r;
        """)


def owner_indexes(store, owner, tenant):
    """Resolve live permissions; orphan tasks must never become system searches."""
    from .access import get_for_user

    with store.control() as db:
        user = db.execute(
            "SELECT tenant,role,disabled FROM users WHERE name=?", (owner,)
        ).fetchone()
    if (
        not user
        or user["tenant"] != tenant
        or user["disabled"]
        or user["role"] not in {"admin", "analyst", "viewer"}
    ):
        raise PermissionError("Saved search owner is missing, disabled or unauthorized")
    return get_for_user(store, owner, tenant)


def validate_trigger(data, threshold=1):
    if data is None:
        return {"mode": "rows", "value": threshold}
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("mode"), str)
        or data["mode"] not in {"rows", "aggregate"}
    ):
        raise ValueError("Trigger mode must be rows or aggregate")
    if data["mode"] == "rows":
        if (
            set(data) != {"mode", "value"}
            or type(data["value"]) is not int
            or not 1 <= data["value"] <= 1000
        ):
            raise ValueError("Row trigger requires value 1..1000")
        return dict(data)
    if set(data) != {"mode", "field", "op", "value"}:
        raise ValueError("Aggregate trigger requires field/op/value")
    if not isinstance(data["field"], str) or not re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]{0,63}", data["field"]
    ):
        raise ValueError("Aggregate trigger field must be a result column")
    if (
        not isinstance(data["op"], str)
        or data["op"] not in {"gte", "gt", "eq", "lt", "lte"}
        or type(data["value"]) not in (int, float)
        or abs(data["value"]) > 1e100
        or not math.isfinite(data["value"])
    ):
        raise ValueError(
            "Aggregate trigger requires finite numeric value and comparison"
        )
    return dict(data)


def evaluate_trigger(trigger, result):
    rows = result["rows"]
    if trigger["mode"] == "rows":
        return len(rows) >= trigger["value"], {
            "metric": "result_rows",
            "observed": len(rows),
            "value": trigger["value"],
        }
    if result.get("at_limit"):
        raise CapacityError("Aggregate trigger requires complete result groups")
    selected = []
    for row in rows:
        value = row.get(trigger["field"])
        if (
            type(value) not in (int, float)
            or abs(value) > 1e100
            or not math.isfinite(value)
        ):
            raise ValueError("Aggregate trigger field must contain finite numbers")
        op, threshold = trigger["op"], trigger["value"]
        if {
            "gte": value >= threshold,
            "gt": value > threshold,
            "eq": value == threshold,
            "lt": value < threshold,
            "lte": value <= threshold,
        }[op]:
            selected.append(row)
    return bool(selected), {
        "metric": "aggregate",
        "field": trigger["field"],
        "op": trigger["op"],
        "value": trigger["value"],
        "matching_groups": len(selected),
        "observed": [row[trigger["field"]] for row in rows],
    }


def save_rule(store, who, data):
    if set(data) - {
        "name",
        "query",
        "interval",
        "lookback",
        "threshold",
        "enabled",
        "trigger",
        "case_adapter",
        "late_recovery",
    }:
        raise ValueError("Unknown rule property")
    name = data.get("name", "")
    if not isinstance(name, str) or not 1 <= len(name) <= 120:
        raise ValueError("Rule name required")
    query = data.get("query")
    parsed = Query.parse(query)
    if not isinstance(data.get("enabled", True), bool):
        raise ValueError("enabled must be boolean")  # noqa: TRY004 - Invalid JSON rule is HTTP 400.
    interval, lookback, threshold = (
        data.get("interval", 300),
        data.get("lookback", 600),
        data.get("threshold", 1),
    )
    if any(type(x) is not int for x in (interval, lookback, threshold)) or not (
        30 <= interval <= 86400
        and interval <= lookback <= 604800
        and 1 <= threshold <= 1000
    ):
        raise ValueError(
            "interval 30..86400, lookback interval..604800, threshold 1..1000"
        )
    trigger = validate_trigger(data.get("trigger"), threshold)
    horizon = data.get("late_recovery", 900)
    if type(horizon) is not int or not 0 <= horizon <= 86400:
        raise ValueError("late_recovery must be integer0..86400 seconds")
    if trigger["mode"] == "rows" and parsed.limit < trigger["value"]:
        raise ValueError("Query limit must be at least detection threshold")
    allowed = owner_indexes(store, who["name"], who["tenant"])
    # Parsing cannot catch all invalid backend regex/functions. Probe with a deadline.
    now, deadline = time.time(), time.monotonic() + 1
    probe = store.search(
        who["tenant"],
        {**query, "earliest": max(0, now - 1), "latest": now, "limit": 1},
        cancel=lambda: time.monotonic() >= deadline,
        allowed_indexes=allowed,
    )
    rule_id = str(uuid.uuid4())
    with store.write_lock, store.control() as db:
        db.execute("BEGIN IMMEDIATE")
        from . import detection_automation, principal

        actor = principal.current(db, who, ("admin", "analyst"))
        if actor["allowed_indexes"] != allowed:
            raise PermissionError("Saved search permissions changed during validation")
        adapter = detection_automation.validate_case_adapter(data.get("case_adapter"))
        if adapter and trigger["mode"] != "rows":
            raise ValueError(
                "Automatic Case adapter requires original event rows; aggregate triggers remain findings"
            )
        if adapter:
            required = {
                "event_id",
                "event_time",
                "host",
                "source",
                "severity",
                adapter["entity_field"],
            }
            columns = set(probe["columns"])
            if not required <= columns or not columns & {"index_name", "index"}:
                raise ValueError(
                    "Case adapter query must project original identity/time/index/host/source/severity/entity fields"
                )
        db.execute(
            "INSERT INTO rules VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                rule_id,
                who["tenant"],
                name,
                encode(query),
                interval,
                lookback,
                threshold,
                int(data.get("enabled", True)),
                now,
                None,
                None,
            ),
        )
        db.execute(
            "INSERT INTO rule_execution(rule_id,owner) VALUES(?,?)",
            (rule_id, who["name"]),
        )
        db.execute(
            "INSERT INTO rule_detection_options VALUES(?,?,?)",
            (rule_id, encode(trigger), encode(adapter) if adapter else None),
        )
        db.execute("INSERT INTO rule_late_options VALUES(?,?)", (rule_id, horizon))
        store.audit(
            db, who["tenant"], who["name"], "rule.create", {"id": rule_id, "name": name}
        )
    return rule_id


def _cancelled(cancel):
    return bool(cancel and (cancel() if callable(cancel) else cancel.is_set()))


def _retry(store, rule, now, exc=None, duration=0):
    """Retry state is separate from the original scheduled window end."""
    with store.write_lock, store.control() as db:
        db.execute("BEGIN IMMEDIATE")
        current = db.execute(
            "SELECT next_run,enabled FROM rules WHERE id=?", (rule["id"],)
        ).fetchone()
        if (
            not current
            or not current["enabled"]
            or current["next_run"] != rule["next_run"]
        ):
            return
        prior = db.execute(
            "SELECT failures FROM rule_execution WHERE rule_id=?", (rule["id"],)
        ).fetchone()
        failures = min(1000, (prior[0] if prior else 0) + bool(exc))
        delay = min(300, 2 ** min(failures, 9)) if exc else 2
        state = (
            "owner_unavailable"
            if isinstance(exc, PermissionError)
            else "backoff"
            if exc
            else "waiting_index"
        )
        db.execute(
            """INSERT INTO rule_execution(rule_id,owner,failures,retry_at,last_attempt,duration_ms,state)
            VALUES(?,?,?,?,?,?,?) ON CONFLICT(rule_id) DO UPDATE SET failures=excluded.failures,
            retry_at=excluded.retry_at,last_attempt=excluded.last_attempt,
            duration_ms=excluded.duration_ms,state=excluded.state""",
            (rule["id"], rule["owner"], failures, now + delay, now, duration, state),
        )
        if exc:
            db.execute(
                "UPDATE rules SET error=? WHERE id=?",
                (type(exc).__name__ + ": " + str(exc)[:400], rule["id"]),
            )
        db.execute("UPDATE scheduler_cursor SET tenant=? WHERE id=1", (rule["tenant"],))


def run_due(store, now=None, budget=0.5, cancel=None):
    now = time.time() if now is None else now
    deadline = time.monotonic() + max(0.01, budget)
    with store.control() as db:
        cursor = db.execute(
            "SELECT tenant FROM scheduler_cursor WHERE id=1"
        ).fetchone()[0]
        ordinary = [
            dict(row)
            for row in db.execute(
                """WITH candidates AS (
                SELECT r.*,x.owner,ROW_NUMBER() OVER(PARTITION BY r.tenant ORDER BY r.next_run,r.id) AS tenant_rank
                FROM rules r LEFT JOIN rule_execution x ON x.rule_id=r.id
                WHERE r.enabled=1 AND r.next_run<=? AND COALESCE(x.retry_at,0)<=?
            ) SELECT * FROM candidates ORDER BY tenant_rank,
              CASE WHEN tenant>? THEN 0 ELSE 1 END,tenant,next_run,id LIMIT 20""",
                (now, now, cursor),
            ).fetchall()
        ]
        from . import detection_automation

        late = detection_automation.late_work(db, "saved_search", now, 8)
        for row in late:
            owner = db.execute(
                "SELECT owner FROM rule_execution WHERE rule_id=?", (row["id"],)
            ).fetchone()
            row["owner"] = owner[0] if owner else None
        rules = (late + ordinary)[:20]
    count = 0
    for rule in rules:
        if _cancelled(cancel) or time.monotonic() >= deadline:
            break
        started, end = time.monotonic(), rule["next_run"]
        try:
            with store.control() as db:
                pending = db.execute(
                    "SELECT 1 FROM queue WHERE tenant=? AND received<=? LIMIT 1",
                    (rule["tenant"], end),
                ).fetchone()
            if pending:
                if rule.get("_late"):
                    with store.write_lock, store.control() as db:
                        detection_automation.fail_late(
                            db, rule, now, CapacityError("Indexing pending")
                        )
                else:
                    _retry(store, rule, now)
                continue
            query = json.loads(rule["query"])
            query.update(earliest=max(0, end - rule["lookback"]), latest=end)
            allowed = owner_indexes(store, rule["owner"], rule["tenant"])
            input_window = detection_automation.register_input(
                store,
                "saved_search",
                rule,
                max(0, end - rule["lookback"]),
                end,
                allowed,
            )
            result = store.search(
                rule["tenant"],
                query,
                allowed_indexes=allowed,
                cancel=lambda: _cancelled(cancel),
            )
            if owner_indexes(store, rule["owner"], rule["tenant"]) != allowed:
                raise PermissionError(
                    "Saved search permissions changed during execution"
                )
            from . import detection_automation, principal

            with store.control() as db:
                options = db.execute(
                    "SELECT trigger,case_adapter FROM rule_detection_options WHERE rule_id=?",
                    (rule["id"],),
                ).fetchone()
                actor = principal.current(
                    db,
                    {
                        "name": rule["owner"],
                        "tenant": rule["tenant"],
                        "role": "analyst",
                        "allowed_indexes": allowed,
                    },
                    ("admin", "analyst"),
                )
            trigger = (
                json.loads(options["trigger"])
                if options
                else validate_trigger(None, rule["threshold"])
            )
            matched, trigger_result = evaluate_trigger(trigger, result)
            original_rows = (
                detection_automation.prepare_case_rows(
                    store,
                    actor,
                    json.loads(options["case_adapter"]),
                    result["rows"],
                    cancel,
                )
                if matched and options and options["case_adapter"]
                else None
            )
            with store.write_lock, store.control() as db:
                db.execute("BEGIN IMMEDIATE")
                current = db.execute(
                    "SELECT * FROM rules WHERE id=?", (rule["id"],)
                ).fetchone()
                if (
                    not current
                    or not current["enabled"]
                    or (not rule.get("_late") and current["next_run"] != end)
                ):
                    continue
                if detection_automation.late_definition_digest(
                    "saved_search", current
                ) != detection_automation.late_definition_digest("saved_search", rule):
                    raise CapacityError(
                        "Saved search definition changed during evaluation"
                    )
                detection_automation.check_late(db, rule)
                detection_automation.check_input(db, input_window)
                from . import detection_automation, principal

                actor = principal.current(
                    db,
                    {
                        "name": rule["owner"],
                        "tenant": rule["tenant"],
                        "role": "analyst",
                        "allowed_indexes": allowed,
                    },
                    ("admin", "analyst"),
                )
                if actor["allowed_indexes"] != allowed:
                    raise PermissionError(
                        "Saved search owner permissions changed before emission"
                    )
                options = db.execute(
                    "SELECT trigger,case_adapter FROM rule_detection_options WHERE rule_id=?",
                    (rule["id"],),
                ).fetchone()
                trigger = (
                    json.loads(options["trigger"])
                    if options
                    else validate_trigger(None, rule["threshold"])
                )
                matched, trigger_result = evaluate_trigger(trigger, result)
                if matched:
                    finding_id = hashlib.sha256(
                        f"{rule['id']}:{end}".encode()
                    ).hexdigest()
                    db.execute(
                        "INSERT OR IGNORE INTO findings(id,tenant,rule_id,name,created,status,owner,version,evidence) VALUES(?,?,?,?,?,?,?,?,?)",
                        (
                            finding_id,
                            rule["tenant"],
                            rule["id"],
                            rule["name"],
                            now,
                            "new",
                            "",
                            1,
                            encode(
                                {
                                    "earliest": query["earliest"],
                                    "latest": end,
                                    "matched_at_least": len(result["rows"]),
                                    "sample": result["rows"][:10],
                                    "access_scope": allowed,
                                    "trigger": trigger_result,
                                }
                            ),
                        ),
                    )
                    if options and options["case_adapter"]:
                        detection_automation.emit_rows(
                            db,
                            store,
                            actor,
                            "finding:" + rule["id"],
                            json.loads(options["case_adapter"]),
                            original_rows,
                            end,
                            "saved_finding",
                            basis_indexes=allowed,
                        )
                detection_automation.check_input(db, input_window, finish=True)
                if rule.get("_late"):
                    detection_automation.finish_late(db, rule, rule["interval"])
                else:
                    db.execute(
                        "UPDATE rules SET next_run=?,last_end=?,error=NULL WHERE id=?",
                        (end + rule["interval"], end, rule["id"]),
                    )
                db.execute(
                    "UPDATE rule_execution SET failures=0,retry_at=0,last_attempt=?,last_success=?,duration_ms=?,state='ready' WHERE rule_id=?",
                    (now, now, (time.monotonic() - started) * 1000, rule["id"]),
                )
                db.execute(
                    "UPDATE scheduler_cursor SET tenant=? WHERE id=1", (rule["tenant"],)
                )
                store.audit(
                    db,
                    rule["tenant"],
                    "scheduler",
                    "rule.run",
                    {"id": rule["id"], "end": end, "matches": len(result["rows"])},
                )
            count += 1
        except Exception as exc:  # noqa: BLE001 - Isolate a rule failure and retain its persisted window for retry.
            if _cancelled(cancel):
                break
            if rule.get("_late"):
                with store.write_lock, store.control() as db:
                    detection_automation.fail_late(db, rule, now, exc)
            else:
                _retry(store, rule, now, exc, (time.monotonic() - started) * 1000)
            LOG.warning(
                "Scheduled rule %s deferred: %s", rule["id"], type(exc).__name__
            )
    return count


def rule_health(store, tenant):
    with store.control() as db:
        rows = db.execute(
            """SELECT r.id,r.name,r.enabled,r.next_run,r.last_end,r.error,x.owner,
            COALESCE(x.failures,0) AS failures,COALESCE(x.retry_at,0) AS retry_at,
            x.last_attempt,x.last_success,x.duration_ms,COALESCE(x.state,'owner_unavailable') AS state
            FROM rules r LEFT JOIN rule_execution x ON x.rule_id=r.id
            WHERE r.tenant=? ORDER BY r.next_run,r.id""",
            (tenant,),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            options = db.execute(
                "SELECT * FROM rule_detection_options WHERE rule_id=?", (row["id"],)
            ).fetchone()
            item["trigger"] = (
                json.loads(options["trigger"])
                if options
                else {"mode": "rows", "value": None, "legacy": True}
            )
            item["case_adapter"] = (
                json.loads(options["case_adapter"])
                if options and options["case_adapter"]
                else None
            )
            result.append(item)
    return result


def scheduler_health(store, tenant=None):
    now = time.time()
    with store.control() as db:
        row = db.execute(
            """SELECT count(*),COALESCE(sum(r.enabled=1 AND r.next_run<=?),0),
            COALESCE(sum(r.enabled=1 AND x.retry_at>?),0),
            COALESCE(sum(r.enabled=1 AND COALESCE(x.failures,0)>0),0),max(x.last_success)
            FROM rules r LEFT JOIN rule_execution x ON x.rule_id=r.id
            WHERE (? IS NULL OR r.tenant=?)""",
            (now, now, tenant, tenant),
        ).fetchone()
    return dict(
        zip(
            ("rules", "due_windows", "deferred_rules", "failing_rules", "last_success"),
            row,
        )
    )


class Runtime:
    def __init__(self, store):
        self.store = store
        from .pipeline_dispatch import Dispatch
        self.dispatch = store.pipeline_dispatch = Dispatch()
        self.stop = threading.Event()
        self.thread = self.scheduler = self.fts_thread = None
        self.capacity_thread = None
        self.intelligence_thread = None
        self.ml_thread = None
        self.yara_thread = None
        self.yara_worker_error = None
        self.analysis_engine_thread = self.research_thread = self.online_thread = None
        self.analysis_engine_error = self.research_error = self.online_error = None
        self.analysis_engine_tick = self.research_tick = self.online_tick = None
        self.research_result = self.online_result = {}
        self.ml_tick = self.ml_worker_error = None
        self.intelligence_error = self.intelligence_tick = None
        self.intelligence_result = {}
        self.capacity_error = self.capacity_tick = None
        self.fts_error = None
        self.fts_error_code = None
        self.fts_deferred = None
        self._fts_log = (None, 0)
        self._capacity_log = (None, 0)
        self.last_error = self.last_tick = self.scheduler_error = (
            self.scheduler_tick
        ) = None
        self.detection_error = None
        self.enterprise_errors = {}
        self.syslog = None
        self.indexed_total = self.indexed_eps = self.indexing_lag = 0
        self.indexing_active_eps = 0
        self._metrics_at = time.monotonic()
        self.last_indexed = self.last_batches = 0
        from .jobs import JobManager

        self.jobs = JobManager(store)

    def start(self):
        if self.store.replica:
            self.store.replica.start()
        self.jobs.start()
        self.thread = threading.Thread(
            target=self.loop, name="sapientia-indexer", daemon=True
        )
        self.scheduler = threading.Thread(
            target=self.schedule_loop, name="sapientia-scheduler", daemon=True
        )
        self.fts_thread = threading.Thread(
            target=self.fts_loop, name="sapientia-fulltext-indexer", daemon=True
        )
        self.capacity_thread = threading.Thread(
            target=self.capacity_loop, name="sapientia-capacity-retention", daemon=True
        )
        self.thread.start()
        self.scheduler.start()
        self.fts_thread.start()
        self.capacity_thread.start()
        self.intelligence_thread = threading.Thread(
            target=self.intelligence_loop, name="xsera-intelligence", daemon=True
        )
        self.intelligence_thread.start()
        self.ml_thread = threading.Thread(target=self.ml_loop,name="xsera-cpu-ml",daemon=True)
        self.ml_thread.start()
        self.yara_thread = threading.Thread(target=self.yara_loop, name="xsera-yara", daemon=True)
        self.yara_thread.start()
        for attribute,target,name in (
            ('analysis_engine_thread',self.analysis_engine_loop,'xsera-file-analysis'),
            ('research_thread',self.research_loop,'xsera-research-cpu'),
            ('online_thread',self.online_loop,'xsera-online-drift'),
        ):
            thread=threading.Thread(target=target,name=name,daemon=True)
            setattr(self,attribute,thread);thread.start()
        config = getattr(self.store.settings, "syslog", None)
        if config:
            from .syslog_input import SyslogReceiver, SyslogSettings

            try:
                self.syslog = SyslogReceiver(
                    self.store,
                    SyslogSettings(**config) if isinstance(config, dict) else config,
                )
                self.syslog.start()
            except Exception:
                self.close()
                raise

    def capacity_loop(self):
        from .pressure_retention import record_error, step

        while not self.stop.is_set():
            self.store.capacity_wake.clear()
            try:
                result = step(self.store, cancel=self.stop)
                self.capacity_tick = time.time()
                self.capacity_error = self.store.capacity_worker_error = None
                delay = 0.25 if result.get("state") in {"reclaiming","recovering","busy"} else self.store.record_policy["capacity_check_seconds"]
            except Exception as exc:
                self.capacity_error = self.store.capacity_worker_error = type(exc).__name__
                try:
                    record_error(self.store,exc)
                except Exception:
                    # Memory health remains visible even when a full filesystem
                    # cannot append the durable error/audit record.
                    pass
                LOG.exception("Capacity retention failed; pending intent retained")
                delay = self.store.record_policy["capacity_check_seconds"]
            self.store.capacity_wake.wait(delay)

    def intelligence_loop(self):
        from . import intelligence

        while not self.stop.is_set():
            token = self.dispatch.token("intelligence")
            try:
                self.intelligence_result = intelligence.run_due(
                    self.store, cancel=self.stop, budget=0.25, max_runs=2, include_ml=False,
                    original_budget=1.0,
                )
                self.intelligence_error = None
                self.intelligence_tick = time.time()
            except Exception as exc:
                self.intelligence_error = type(exc).__name__
                LOG.exception("Intelligence worker deferred; durable input cursor retained")
            if self.intelligence_result.get("originals"):
                self.dispatch.notify("ml", "research", "scheduler")
            self.dispatch.wait("intelligence", token, 0.01 if self.intelligence_result.get("originals") else 0.5)

    def yara_loop(self):
        from . import yara_manager
        while not self.stop.is_set():
            try:
                yara_manager.run_due(self.store, cancel=self.stop)
                self.yara_worker_error = None
            except Exception as exc:
                self.yara_worker_error = type(exc).__name__
                LOG.exception("YARA worker deferred; collection and job evidence retained")
            self.stop.wait(1)

    def ml_loop(self):
        from . import intelligence, intelligence_sequence, cpu_sequence, ml_datasets
        while not self.stop.is_set():
            token = self.dispatch.token("ml")
            try:
                intelligence._ml_due(self.store,cancel=self.stop,maximum=32,coalesce=True)
                self.sequence_result = intelligence_sequence.run_due(
                    self.store, cancel=self.stop, budget=.25, max_runs=32
                )
                cpu_sequence.run_due(self.store, cancel=self.stop, budget=.1, max_runs=2)
                ml_datasets.run_due(self.store, cancel=self.stop, budget=.1, max_runs=32)
                self.ml_worker_error=None
                self.ml_tick=time.time()
            except Exception as exc:
                self.ml_worker_error=type(exc).__name__
                LOG.exception("CPU ML deferred; durable jobs retained")
            self.dispatch.notify("intelligence") if getattr(self, "sequence_result", {}).get("processed") else None
            self.dispatch.wait("ml", token, .5)

    def analysis_engine_loop(self):
        from . import analysis_engines
        while not self.stop.is_set():
            try:
                analysis_engines.run_due(self.store,cancel=self.stop)
                self.analysis_engine_tick=time.time();self.analysis_engine_error=None
            except Exception as exc:
                self.analysis_engine_error=type(exc).__name__
                LOG.exception('File analysis deferred; durable evidence retained')
            self.stop.wait(1)

    def research_loop(self):
        from . import research_behavior,advanced_intelligence
        while not self.stop.is_set():
            token = self.dispatch.token("research")
            try:
                result=research_behavior.run_due(self.store,cancel=self.stop.is_set,budget=.5,max_runs=4)
                published=advanced_intelligence.run_due(self.store,cancel=self.stop)
                self.research_result={'processed':result.get('processed',0),'status':result.get('status'),'published':published['published']}
                self.research_tick=time.time();self.research_error=None
            except Exception as exc:
                self.research_error=type(exc).__name__
                LOG.exception('Research analysis deferred; immutable runs retained')
            if self.research_result.get('published'):
                self.dispatch.notify("intelligence")
            self.dispatch.wait("research", token, .01 if self.research_result.get('processed') else .5)

    def online_loop(self):
        from . import online_analytics
        while not self.stop.is_set():
            token = self.dispatch.token("online")
            try:
                result=online_analytics.run_due(self.store,cancel=self.stop)
                self.online_result={'processed':result.get('processed',0)}
                self.online_tick=time.time();self.online_error=None
            except Exception as exc:
                self.online_error=type(exc).__name__
                LOG.exception('Online drift observer deferred; input cursor retained')
            self.dispatch.wait("online", token, .5)

    def fts_loop(self):
        from .log_search import drain, error_code

        while not self.stop.is_set():
            token = self.dispatch.token("fts")
            try:
                result = drain(
                    self.store,
                    budget=0.25,
                    max_documents=5000,
                    cancel=self.stop,
                    defer_lock=True,
                )
                self.fts_deferred = result.get("deferred")
                if not self.fts_deferred:
                    self.fts_error = None
                    self.fts_error_code = None
                self.dispatch.wait("fts", token, 0.01 if result.get("processed") else 0.25)
            except Exception as exc:
                self.fts_deferred = None
                self.fts_error = type(exc).__name__
                self.fts_error_code = error_code(exc)
                now = time.monotonic()
                if (
                    self._fts_log[0] != self.fts_error_code
                    or now - self._fts_log[1] >= 60
                ):
                    LOG.exception(
                        "Full-text indexing failed; journal retained (%s)",
                        self.fts_error_code,
                    )
                    self._fts_log = (self.fts_error_code, now)
                self.stop.wait(1)

    def schedule_loop(self):
        while not self.stop.is_set():
            token = self.dispatch.token("scheduler")
            try:
                run_due(self.store, cancel=self.stop)
                self.scheduler_error = None
                self.scheduler_tick = time.time()
            except Exception as exc:
                self.scheduler_error = type(exc).__name__
                LOG.exception(
                    "Scheduler iteration failed; persisted windows remain pending"
                )
            if not self.stop.is_set():
                try:
                    from . import detections

                    detections.run_due(self.store, cancel=self.stop)
                    self.detection_error = None
                except ImportError:
                    pass
                except Exception as exc:
                    self.detection_error = type(exc).__name__
                    LOG.exception("Correlation detector iteration failed")
            for name in ("source_health", "soar", "detection_automation", "correlation_runtime", "record_governance", "case_intelligence", "behavior_features"):
                if self.stop.is_set():
                    break
                try:
                    from importlib import import_module

                    module = import_module("." + name, __package__)
                    module.run_due(
                        self.store, cancel=self.stop, budget=0.25, max_runs=2
                    )
                    self.enterprise_errors.pop(name, None)
                except Exception as exc:
                    self.enterprise_errors[name] = type(exc).__name__
                    LOG.exception("Enterprise worker iteration failed: %s", name)
            self.dispatch.wait("scheduler", token, 0.25)

    def drain(self):
        """Consume consecutive batches until idle, cancelled or work budget exhausted."""
        settings = self.store.settings
        batch = max(1, min(100000, int(getattr(settings, "indexing_batch", 5000))))
        budget = max(0.01, min(5, float(getattr(settings, "indexing_budget", 0.25))))
        start, total, batches, backlog = time.monotonic(), 0, 0, False
        while not self.stop.is_set() and batches < 128:
            size = self.store.flush(batch=batch)
            total += size
            batches += 1
            backlog = size == batch
            if not backlog or time.monotonic() - start >= budget:
                break
        duration = max(0.000001, time.monotonic() - start)
        self.indexed_total += total
        finished = time.monotonic()
        self.indexed_eps = round(total / max(0.000001, finished - self._metrics_at), 2)
        self.indexing_active_eps = round(total / duration, 2)
        self._metrics_at = finished
        self.last_indexed, self.last_batches = total, batches
        with self.store.control(local=True) as db:
            oldest = db.execute("SELECT min(received) FROM queue").fetchone()[0]
        self.indexing_lag = max(0, time.time() - oldest) if oldest is not None else 0
        self.last_tick = time.time()
        return oldest is not None

    def health(self):
        return {
            "dispatch": self.dispatch.snapshot(),
            "last_tick": self.last_tick,
            "error": self.last_error,
            "fulltext_error": self.fts_error,
            "fulltext_error_code": self.fts_error_code,
            "fulltext_deferred": self.fts_deferred,
            "fulltext_worker_running": bool(
                self.fts_thread and self.fts_thread.is_alive()
            ),
            "indexed_total": self.indexed_total,
            "indexed_eps": self.indexed_eps,
            "indexing_active_eps": self.indexing_active_eps,
            "last_indexed": self.last_indexed,
            "last_batches": self.last_batches,
            "oldest_pending_seconds": round(self.indexing_lag, 3),
            "scheduler_tick": self.scheduler_tick,
            "scheduler_error": self.scheduler_error,
            "detection_error": self.detection_error,
            "enterprise_errors": dict(self.enterprise_errors),
            "capacity_worker_error": self.capacity_error,
            "capacity_worker_tick": self.capacity_tick,
            "capacity_worker_running": bool(self.capacity_thread and self.capacity_thread.is_alive()),
            "intelligence_worker_running": bool(self.intelligence_thread and self.intelligence_thread.is_alive()),
            "intelligence_worker_error": self.intelligence_error,
            "intelligence_worker_tick": self.intelligence_tick,
            "intelligence_worker_last_result": dict(self.intelligence_result),
            "intelligence_ml_error": getattr(self.store, "intelligence_ml_error", None),
            "intelligence_ml_status":getattr(self.store,"intelligence_ml_status",None),
            "ml_worker_running":bool(self.ml_thread and self.ml_thread.is_alive()),
            "ml_worker_error":self.ml_worker_error,
            "ml_worker_tick":self.ml_tick,
            "sequence_worker_last_result":dict(getattr(self,"sequence_result",{})),
            'analysis_engine_worker_running':bool(self.analysis_engine_thread and self.analysis_engine_thread.is_alive()),
            'analysis_engine_worker_error':self.analysis_engine_error,'analysis_engine_worker_tick':self.analysis_engine_tick,
            'research_worker_running':bool(self.research_thread and self.research_thread.is_alive()),
            'research_worker_error':self.research_error,'research_worker_tick':self.research_tick,
            'research_worker_last_result':dict(self.research_result),
            'online_worker_running':bool(self.online_thread and self.online_thread.is_alive()),
            'online_worker_error':self.online_error,'online_worker_tick':self.online_tick,
            'online_worker_last_result':dict(self.online_result),
            "syslog": self.syslog.health() if self.syslog else None,
        }

    def loop(self):
        last_retention = time.monotonic() - 3600
        last_search_cleanup = time.monotonic()
        while not self.stop.is_set():
            token = self.dispatch.token("index")
            backlog = False
            try:
                backlog = self.drain()
                if not self.stop.is_set() and time.monotonic() - last_retention >= 3600:
                    self.store.retain()
                    last_retention = time.monotonic()
                if (
                    not self.stop.is_set()
                    and time.monotonic() - last_search_cleanup >= 30
                ):
                    from .log_search import maintenance

                    maintenance(self.store, deadline=time.monotonic() + 2)
                    last_search_cleanup = time.monotonic()
                self.last_error = None
            except CapacityError as exc:
                from .log_search import error_code

                self.last_error = type(exc).__name__
                code, now = error_code(exc), time.monotonic()
                if self._capacity_log[0] != code or now - self._capacity_log[1] >= 30:
                    LOG.warning(
                        "Background indexing deferred; journal retained (%s)", code
                    )
                    self._capacity_log = (code, now)
            except Exception as exc:
                self.last_error = type(exc).__name__
                LOG.exception("Background indexing failed; journal retained")
            idle = max(
                0.01, min(5, float(getattr(self.store.settings, "indexing_idle", 0.25)))
            )
            self.dispatch.wait("index", token, min(idle, 0.01) if backlog else idle)

    def close(self):
        if self.syslog:
            self.syslog.close()
            self.syslog = None
        self.stop.set()
        self.dispatch.close()
        self.store.capacity_wake.set()
        self.jobs.close()
        for thread, name in (
            (self.thread, "Worker"),
            (self.scheduler, "Scheduler"),
            (self.fts_thread, "Full-text worker"),
            (self.capacity_thread, "Capacity retention worker"),
            (self.intelligence_thread, "Intelligence worker"),
            (self.ml_thread,"CPU ML worker"),
            (self.yara_thread,"YARA worker"),
            (self.analysis_engine_thread,'File analysis worker'),
            (self.research_thread,'Research CPU worker'),
            (self.online_thread,'Online drift worker'),
        ):
            if thread:
                thread.join(timeout=30)
                if thread.is_alive():
                    raise RuntimeError(
                        name + " still running; database must remain open"
                    )
