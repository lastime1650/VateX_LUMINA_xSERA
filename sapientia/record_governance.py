"""Unlimited Case/control history, capacity-based log retention and full export.

Page size is a transfer unit, never a lifetime record quota. Current tenant/index
authority is rechecked per chunk. Exports end with an explicit completeness marker.
"""

import base64
import hashlib
import json
import shutil
import threading
import time

from . import migrations, principal
from .storage import ConflictError, encode

DEFAULT = {"permanent": True, "record_count_limit": None, "page_size": 1000,
           "warning_free_percent": 25, "critical_free_percent": 5,
           "capacity_cleanup_enabled": True, "min_free_percent": 20,
           "cleanup_hysteresis_percent": 5, "capacity_check_seconds": 60,
           "cleanup_batch_rows": 5000, "protect_case_evidence": True}
RESOURCES = {
    "cases": ("incidents", "case"), "findings": ("findings", "index"),
    "contributions": ("risk_contributions", "case"), "case_notes": ("case_notes", "case"),
    "case_tasks": ("case_tasks", "case"), "case_feedback": ("incident_feedback", "case"),
    "case_bookmarks": ("case_bookmarks", "case"), "case_movements": ("case_movement_history", "movement"),
    "audit": ("audit", "admin"), "quarantine": ("ingest_quarantine", "index"),
    "source_proofs": ("source_event_receipts", "index"), "projections": ("event_projections", "index"),
    "effects": ("effect_receipts", "effect"), "analysis_runs": ("analysis_schedule_runs", "indexes"),
    "behavior_runs": ("behavior_runs", "indexes"), "source_monitor_runs": ("source_monitor_runs", "monitor"),
    "response_history": ("endpoint_responses", "index"), "file_verdicts": ("file_verdict_runs", "case"),
    "sandbox_jobs": ("file_sandbox_jobs", "case"), "playbook_runs": ("soar_runs", "case"),
    "identity_history": ("temporal_identity_history", "identity"),
    "pipeline_clocks": ("pipeline_event_clocks", "index"), "pipeline_case_clocks": ("pipeline_case_clocks", "case"),
    "governance_decisions": ("detection_governance_decisions", "indexes"), "source_registry": ("source_registry", "index"),
    "artifact_metadata": ("endpoint_artifacts", "case"), "capacity_alerts": ("record_capacity_alerts", "admin"),
    "capacity_cleanup_history": ("record_capacity_cleanup_history", "admin"),
    "detector_diagnostics": ("detector_diagnostics", "indexes"),
    "detectors": ("detector_registry", "indexes"),
    "yara_runs": ("yara_runs", "case"),
    "yara_rules": ("yara_rules", "yara_definition"),
    "yara_rule_history": ("yara_rule_history", "yara_definition"),
    'analysis_engine_runs': ('analysis_engine_runs','case'),
    'analysis_engine_approvals': ('analysis_engine_approvals','case'),
    'research_models': ('research_behavior_models','indexes'),
    'research_runs': ('research_behavior_runs','indexes'),
    'online_models': ('online_analytics_models','indexes'),
    'online_runs': ('online_analytics_runs','indexes'),
    'sequence_event_time_profiles': ('sequence_event_time_config','indexes'),
    'sigma_imports': ('sigma_imports','indexes'),
    'sigma_import_history': ('sigma_import_history','admin'),
    'operational_plans': ('ops_qualification_plans','indexes'),
    'operational_runs': ('ops_qualification_runs','indexes'),
    'signal_evidence_manifests': ('signal_evidence_manifests','indexes'),
    'research_evaluation_datasets': ('research_evaluation_datasets','indexes'),
    'research_evaluation_runs': ('research_evaluation_runs','indexes'),
    'research_evaluation_dataset_archives': ('research_evaluation_dataset_archives','admin'),
    'research_evaluation_run_archives': ('research_evaluation_run_archives','admin'),
    'research_rebaseline_candidates': ('research_rebaseline_candidates','indexes'),
    'research_rebaseline_audit': ('research_rebaseline_audit','admin'),
    'research_horizon_snapshots': ('research_horizon_snapshots','indexes'),
    'sigma_import_deployments': ('sigma_import_deployments','admin'),
}


def initialize(store):
    migrations.apply_store(store, "record_governance", [
        "CREATE TABLE IF NOT EXISTS record_management_policy(singleton INTEGER PRIMARY KEY CHECK(singleton=1),definition TEXT NOT NULL,version INTEGER NOT NULL,updated REAL NOT NULL)",
        "CREATE TABLE IF NOT EXISTS record_retention_cancellations(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,reason TEXT NOT NULL,created REAL NOT NULL)",
        "CREATE TABLE IF NOT EXISTS record_capacity_alerts(id INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT NOT NULL,state TEXT NOT NULL,free_bytes INTEGER NOT NULL,free_percent REAL NOT NULL,at REAL NOT NULL)"])
    from . import pressure_retention

    pressure_retention.initialize(store)
    store.capacity_wake = threading.Event()
    store.capacity_worker_lock = threading.Lock()
    with store.segment_lock.write(), store.write_lock, store.control(local=True) as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("INSERT OR IGNORE INTO record_management_policy VALUES(1,?,1,?)", (encode(DEFAULT), time.time()))
        saved = db.execute("SELECT definition FROM record_management_policy WHERE singleton=1").fetchone()
        store.record_policy = {**DEFAULT, **json.loads(saved[0]), "permanent": True, "record_count_limit": None}
        if json.loads(saved[0]) != store.record_policy:
            db.execute("UPDATE record_management_policy SET definition=?,version=version+1,updated=? WHERE singleton=1", (encode(store.record_policy), time.time()))
        # Cancel old automatic expiry intents, preserving their original audit
        # record and immutable receipts. Already deleted originals need backup
        # recovery; this change cannot fabricate them from a receipt.
        pending = db.execute("SELECT i.id,i.tenant FROM retention_intents i LEFT JOIN retention_applied a ON a.id=i.id LEFT JOIN capacity_retention_intents c ON c.intent_id=i.id WHERE a.id IS NULL AND c.intent_id IS NULL").fetchall()
        for row in pending:
            db.execute("INSERT OR IGNORE INTO record_retention_cancellations VALUES(?,?,?,?)", (row["id"], row["tenant"], "permanent recording enabled", time.time()))
            db.execute("INSERT OR IGNORE INTO retention_applied VALUES(?,?)", (row["id"], time.time()))
            store.audit(db, row["tenant"], "system", "retention.cancelled.permanent", {"intent_id": row["id"], "originals_reconstructed": False})
        if pending:
            # Prior purge journals may have removed a derivative before physical
            # deletion. Structured originals remain authoritative; FTS needs an
            # explicit rebuild rather than publishing an incomplete cache.
            db.execute("UPDATE log_fts_state SET bootstrap_required=1 WHERE singleton=1")


def configure(store, who, data):
    if not isinstance(data, dict) or "version" not in data or set(data)-({"version"}|set(DEFAULT)) or type(data["version"]) is not int:
        raise ValueError("A typed version and supported policy fields are required")
    # Publish the in-memory policy after commit while still holding write_lock.
    with store.write_lock:
        with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
            if actor["tenant"] != "default" or actor["allowed_indexes"] != ["*"]:
                raise PermissionError("Global record policy requires an unrestricted default-tenant administrator")
            row = db.execute("SELECT version,definition FROM record_management_policy WHERE singleton=1").fetchone()
            old = row["version"]
            if old != data["version"]:
                raise ConflictError("Record management revision changed")
            definition = {**DEFAULT, **json.loads(row["definition"]), **{k:v for k,v in data.items() if k != "version"}}
            if definition["permanent"] is not True or definition["record_count_limit"] is not None:
                raise ValueError("No age expiry or lifetime record count limit is permitted")
            for key, low, high in (("page_size",1,10000),("min_free_percent",1,95),
                                   ("cleanup_hysteresis_percent",1,20),("capacity_check_seconds",1,3600),
                                   ("cleanup_batch_rows",1,10000),("warning_free_percent",1,100),("critical_free_percent",0,99)):
                if type(definition[key]) is not int or not low <= definition[key] <= high:
                    raise ValueError("Invalid capacity/transfer setting: "+key)
            if definition["min_free_percent"]+definition["cleanup_hysteresis_percent"] >= 100 or definition["critical_free_percent"] >= definition["warning_free_percent"]:
                raise ValueError("Ordered capacity thresholds and a recovery target below 100% are required")
            if any(type(definition[k]) is not bool for k in ("capacity_cleanup_enabled","protect_case_evidence")):
                raise ValueError("Typed cleanup and Case evidence switches are required")
            db.execute("UPDATE record_management_policy SET definition=?,version=?,updated=? WHERE singleton=1", (encode(definition), old+1, time.time()))
            store.audit(db, actor["tenant"], actor["name"], "record.management.configure", definition)
        store.record_policy = definition
    store.capacity_wake.set()
    return {**definition, "version": old+1}


def status(store, who):
    with principal.transaction(store, who, ("admin",)) as (db, actor):
        row = db.execute("SELECT * FROM record_management_policy WHERE singleton=1").fetchone()
        policy = {**DEFAULT, **json.loads(row["definition"]), "permanent": True, "record_count_limit": None, "version": row["version"]}
        counters = {}
        if actor["allowed_indexes"] == ["*"]:
            for name,(table,_) in RESOURCES.items():
                if db.execute("SELECT 1 FROM sqlite_master WHERE name=? AND type='table'", (table,)).fetchone():
                    counters[name] = db.execute("SELECT count(*) FROM "+table+" WHERE tenant=?", (actor["tenant"],)).fetchone()[0]
        cleanup = None
        if actor["tenant"] == "default" and actor["allowed_indexes"] == ["*"]:
            saved = db.execute("SELECT definition FROM record_capacity_cleanup_state WHERE singleton=1").fetchone()
            cleanup = json.loads(saved[0]) if saved else {"state":"idle"}
    disk = shutil.disk_usage(store.path)
    free = 100*disk.free/disk.total if disk.total else 0
    state = "critical" if free <= policy["critical_free_percent"] else "pressure" if free <= policy["min_free_percent"] else "warning" if free <= policy["warning_free_percent"] else "ready"
    return {"policy": policy, "tenant_record_counts": counters, "counts_scope": "entire tenant only for unrestricted administrator",
            "disk": {"total":disk.total,"used":disk.used,"free":disk.free,"free_percent":free,"state":state},
            "storage": "SQLite control history plus DuckDB/verified Parquet originals and existing backup/archive adapters",
            "automatic_record_deletion": policy["capacity_cleanup_enabled"],
            "capacity_action": "oldest received original/quarantine logs; preserve Case/history and holds; verify physical free bytes",
            "capacity_cleanup": cleanup, "capacity_worker_error": getattr(store,"capacity_worker_error",None),
            "start_used_percent": 100-policy["min_free_percent"],
            "stop_used_percent": 100-policy["min_free_percent"]-policy["cleanup_hysteresis_percent"],
            "absolute_reserve_bytes": store.settings.min_free_bytes,
            "retention_semantics": "no time expiry; capacity-triggered deletion of unprotected log originals; Case/control history retained",
            "export_resources": [*RESOURCES, "logs"], "lifetime_record_limit": None}


def authorized(db, actor, table, mode, row):
    declared_scope = row.get("indexes", row.get("scope"))
    if declared_scope and not principal.contains(actor["allowed_indexes"], json.loads(declared_scope)):
        return False
    if mode == "admin":
        return actor["role"] == "admin" and actor["allowed_indexes"] == ["*"]
    if mode == "yara_definition":
        definition = json.loads(row.get("definition", row.get("body", "{}")))
        return principal.contains(actor["allowed_indexes"], definition.get("indexes", ["*"]))
    if mode == "case":
        identifier = row.get("incident_id", row.get("id") if table == "incidents" else None)
        if not identifier:
            return False
        try:
            principal.incident(db, actor, identifier)
            return True
        except (KeyError, PermissionError):
            return False
    if mode == "effect":
        from . import effect_receipts
        try:
            effect_receipts.visible(db, actor, row["id"])
            return True
        except (KeyError, PermissionError):
            return False
    if mode == "movement":
        try:
            principal.incident(db, actor, row["source_incident"])
            principal.incident(db, actor, row["target_incident"])
            return True
        except (KeyError, PermissionError):
            return False
    if mode == "monitor":
        definition = db.execute("SELECT definition FROM source_monitors WHERE tenant=? AND id=?", (actor["tenant"], row["monitor_id"])).fetchone()
        if not definition:
            return False
        return principal.contains(actor["allowed_indexes"], json.loads(definition[0]).get("indexes", ["*"]))
    if mode == "identity":
        binding = db.execute("SELECT indexes FROM temporal_identity_bindings WHERE tenant=? AND id=?", (actor["tenant"], row["id"])).fetchone()
        return bool(binding and principal.contains(actor["allowed_indexes"], json.loads(binding[0])))
    if mode == "indexes":
        indexes = row.get("indexes", row.get("scope"))
        if not indexes:
            return actor["allowed_indexes"] == ["*"]
        return principal.contains(actor["allowed_indexes"], json.loads(indexes))
    index = row.get("index_name")
    if not index:
        # Legacy records without explicit scope cannot be granted to a narrower
        # reader merely because they belong to the same tenant.
        return actor["allowed_indexes"] == ["*"]
    return principal.contains(actor["allowed_indexes"], [index])


def page(store, who, resource, cursor=None, count=None):
    if resource not in RESOURCES:
        raise ValueError("Unsupported durable record resource")
    size = store.record_policy["page_size"] if count is None else count
    if type(size) is not int or not 1 <= size <= 10000:
        raise ValueError("Transfer page size must be 1..10000; total records have no limit")
    table, mode = RESOURCES[resource]
    with principal.transaction(store, who) as (db, actor):
        if not db.execute("SELECT 1 FROM sqlite_master WHERE name=? AND type='table'", (table,)).fetchone():
            raise KeyError("Record resource is unavailable")
        after = 0
        frontier = db.execute("SELECT coalesce(max(rowid),0) FROM "+table+" WHERE tenant=?", (actor["tenant"],)).fetchone()[0]
        if cursor:
            try:
                state = json.loads(base64.urlsafe_b64decode(cursor.encode("ascii")))
                if state["tenant"] != actor["tenant"] or state["resource"] != resource or state["name"] != actor["name"] or state["scope"] != actor["allowed_indexes"] or type(state["after"]) is not int or type(state["frontier"]) is not int or not 0 <= state["after"] <= state["frontier"]:
                    raise ValueError
                after, frontier = state["after"], min(frontier, state["frontier"])
            except (ValueError, KeyError, UnicodeError, TypeError):
                raise ValueError("Record cursor differs from current authority") from None
        rows = db.execute("SELECT rowid AS __record_rowid,* FROM "+table+" WHERE tenant=? AND rowid>? AND rowid<=? ORDER BY rowid LIMIT ?", (actor["tenant"],after,frontier,size)).fetchall()
        items = []
        for row in rows:
            candidate = dict(row)
            after = candidate.pop("__record_rowid")
            if authorized(db,actor,table,mode,candidate):
                items.append(candidate)
        more = bool(rows and after < frontier and db.execute("SELECT 1 FROM "+table+" WHERE tenant=? AND rowid>? AND rowid<=? LIMIT 1", (actor["tenant"],after,frontier)).fetchone())
        token = base64.urlsafe_b64encode(encode({"resource":resource,"tenant":actor["tenant"],"name":actor["name"],"scope":actor["allowed_indexes"],"after":after,"frontier":frontier}).encode()).decode() if more else None
        return {"records":items,"next_cursor":token,"complete":not more,"record_count_limit":None,"snapshot":"rowid high-water; current content and current ACL"}


def run_due(store, now=None, cancel=None, budget=.25, max_runs=2):
    """Monitor volume capacity and wake the dedicated cleanup worker."""
    if cancel is not None and cancel.is_set():
        return 0
    clock = time.monotonic()
    if clock-getattr(store,"_record_capacity_checked",0) < store.record_policy["capacity_check_seconds"]:
        return 0
    store._record_capacity_checked=clock
    disk=shutil.disk_usage(store.path)
    free=100*disk.free/disk.total if disk.total else 0
    policy=store.record_policy
    if policy["capacity_cleanup_enabled"] and free <= policy["min_free_percent"]:
        store.capacity_wake.set()
    state="critical" if free<=policy["critical_free_percent"] else "pressure" if free<=policy["min_free_percent"] else "warning" if free<=policy["warning_free_percent"] else "ready"
    if state==getattr(store,"_record_capacity_state",None):
        return 0
    with store.write_lock,store.control() as db:
        db.execute("INSERT INTO record_capacity_alerts(tenant,state,free_bytes,free_percent,at) VALUES('default',?,?,?,?)",(state,disk.free,free,time.time() if now is None else now))
        store.audit(db,"default","system","record.capacity."+state,{"free_bytes":disk.free,"free_percent":free,"automatic_deletion":policy["capacity_cleanup_enabled"]})
    store._record_capacity_state=state
    return 1


def export(store, who, resource):
    if resource == "logs":
        yield from export_logs(store,who)
        return
    cursor, total, digest = None, 0, hashlib.sha256()
    yield encode({"kind":"begin","resource":resource,"record_count_limit":None})+"\n"
    while True:
        result = page(store,who,resource,cursor)
        for row in result["records"]:
            body=encode({"kind":"record","record":row})+"\n"
            digest.update(body.encode())
            total+=1
            yield body
        cursor=result["next_cursor"]
        if cursor is None:
            break
    yield encode({"kind":"end","complete":True,"records":total,"sha256":digest.hexdigest()})+"\n"


def export_logs(store, who):
    from .query import index_predicate
    with principal.transaction(store,who) as (_,actor):
        pass
    predicate,grants=index_predicate(actor["allowed_indexes"])
    total,digest=0,hashlib.sha256()
    with store.segment_lock.read(deadline=time.monotonic()+3):
        store._require_retention_applied()
        con=store.analytics.cursor()
        try:
            con.execute("BEGIN TRANSACTION")
            con.execute("SELECT * FROM events_all WHERE tenant=? AND ("+predicate+") ORDER BY index_name,event_id",[actor["tenant"],*grants])
            columns=[c[0] for c in con.description]
            yield encode({"kind":"begin","resource":"logs","scope":"indexed original events at analytical transaction snapshot","record_count_limit":None})+"\n"
            while True:
                rows=con.fetchmany(store.record_policy["page_size"])
                if not rows:
                    break
                principal.recheck(store,actor)
                for row in rows:
                    body=encode({"kind":"record","record":dict(zip(columns,row))})+"\n"
                    digest.update(body.encode())
                    total+=1
                    yield body
            yield encode({"kind":"end","complete":True,"records":total,"sha256":digest.hexdigest()})+"\n"
        finally:
            try:
                con.execute("ROLLBACK")
            finally:
                con.close()
