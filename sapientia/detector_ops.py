"""Common detector authority, scoped decision history and analysis retention."""
import json
import time

from . import migrations, principal
from .storage import ConflictError, encode


def initialize(store):
    migrations.apply_store(store,"detector_ops",[
        "CREATE TABLE IF NOT EXISTS detector_registry(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,kind TEXT NOT NULL,indexes TEXT NOT NULL,definition TEXT NOT NULL,version INTEGER NOT NULL,updated REAL NOT NULL)",
        "CREATE TABLE IF NOT EXISTS detector_diagnostics(id INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT NOT NULL,detector_id TEXT NOT NULL,version INTEGER NOT NULL,indexes TEXT NOT NULL,event_id TEXT,reason TEXT NOT NULL,detail TEXT NOT NULL,at REAL NOT NULL)",
        "CREATE INDEX IF NOT EXISTS detector_diagnostic_scope ON detector_diagnostics(tenant,detector_id,at,id)"])
    # Upgrade existing declarations even when every old match is deduplicated.
    # Registration is derived from stored authority, never a reconstructed log.
    with store.control(local=True) as db:
        db.execute("BEGIN IMMEDIATE")
        for row in db.execute("SELECT * FROM correlation_plans").fetchall():
            plan=json.loads(row["definition"])
            register(db,{"id":"v2:"+row["id"]+":"+str(row["version"]),"tenant":row["tenant"],"version":row["version"]},
                     {**plan["case_adapter"],"steps":[],"evaluation_delay":0},
                     {"name":row["owner"],"tenant":row["tenant"],"allowed_indexes":json.loads(row["indexes"])},"v2-positive-flow")
        for row in db.execute("SELECT * FROM analysis_schedules").fetchall():
            register_schedule(db,row)


def register_schedule(db,row):
    plan=json.loads(row["definition"])
    if plan.get("case_adapter") is not None:
        register(db,{"id":"analysis:"+row["id"],"tenant":row["tenant"],"version":row["version"]},
                 {**plan["case_adapter"],"evaluation_delay":0},
                 {"name":row["owner"],"tenant":row["tenant"],"allowed_indexes":plan["indexes"]},row["kind"])


def register(db, policy, definition, actor, kind):
    if policy["tenant"] != actor["tenant"]:
        raise PermissionError("Detector tenant differs")
    packed=encode(definition)
    old=db.execute("SELECT * FROM detector_registry WHERE id=?",(policy["id"],)).fetchone()
    if old and (old["tenant"]!=actor["tenant"] or old["owner"]!=actor["name"] or old["version"]>policy["version"]):
        raise ConflictError("Detector authority changed")
    if old and old["version"]==policy["version"] and old["definition"]!=packed:
        raise ConflictError("Detector definition changed without a revision")
    indexes=old["indexes"] if old and old["version"]==policy["version"] else encode(actor["allowed_indexes"])
    db.execute("INSERT INTO detector_registry VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET definition=excluded.definition,indexes=excluded.indexes,version=excluded.version,updated=excluded.updated",
               (policy["id"],actor["tenant"],actor["name"],kind,indexes,packed,policy["version"],time.time()))


def policy(db, actor, identifier):
    row=db.execute("SELECT * FROM correlation_policies WHERE tenant=? AND id=?",(actor["tenant"],identifier)).fetchone()
    if row:
        return dict(row)
    row=db.execute("SELECT * FROM detector_registry WHERE tenant=? AND id=?",(actor["tenant"],identifier)).fetchone()
    if not row or not principal.contains(actor["allowed_indexes"],json.loads(row["indexes"])):
        raise KeyError("Detection policy not found")
    result=dict(row)
    if row["kind"]=="v2-positive-flow":
        parts=identifier.split(":")
        plan=db.execute("SELECT version,enabled FROM correlation_plans WHERE tenant=? AND id=?",(actor["tenant"],parts[1])).fetchone()
        if not plan or plan["version"]!=row["version"] or not plan["enabled"]:
            raise ConflictError("Detector plan is disabled or superseded")
    if identifier.startswith("analysis:"):
        current=db.execute("SELECT version,enabled FROM analysis_schedules WHERE tenant=? AND id=?",(actor["tenant"],identifier.split(":",1)[1])).fetchone()
        if current and (current["version"]!=row["version"] or not current["enabled"]):
            raise ConflictError("Analysis detector is disabled or its revision changed")
    return result


def diagnostic(db, actor, identifier, version, event_id, reason, detail=None):
    db.execute("INSERT INTO detector_diagnostics(tenant,detector_id,version,indexes,event_id,reason,detail,at) VALUES(?,?,?,?,?,?,?,?)",
               (actor["tenant"],identifier,version,encode(actor["allowed_indexes"]),event_id,reason,encode(detail or {}),time.time()))


def protected_ids(db, tenant, ids, now=None, store=None):
    """No consumer acknowledgement implies no permission to remove its window.

    Conservatively protect the declared lookback/recovery interval and any
    frozen unfinished window. An absent watermark never means successful work.
    """
    if not ids:
        return set()
    now=time.time() if now is None else now
    windows=[]
    for row in db.execute("SELECT definition,frozen_end,snapshot_seq FROM correlation_plans WHERE tenant=? AND enabled=1",(tenant,)):
        plan=json.loads(row["definition"])
        end=row["frozen_end"] if row["snapshot_seq"] else now
        windows.append((max(0,min(end,now)-plan["window"]),None))
    for row in db.execute("SELECT definition,next_run FROM correlation_policies WHERE tenant=? AND enabled=1",(tenant,)):
        plan=json.loads(row["definition"])
        windows.append((max(0,min(now,row["next_run"])-plan["window"]-plan.get("late_recovery",900)-plan.get("evaluation_delay",0)),None))
    for row in db.execute("SELECT definition,next_run FROM analysis_schedules WHERE tenant=? AND enabled=1",(tenant,)):
        plan=json.loads(row["definition"])
        windows.append((max(0,min(now,row["next_run"])-plan["lookback"]-plan.get("late_recovery",900)),None))
    for row in db.execute("SELECT r.lookback,r.next_run,coalesce(o.horizon,900) AS horizon FROM rules r LEFT JOIN rule_late_options o ON o.rule_id=r.id WHERE r.tenant=? AND r.enabled=1",(tenant,)):
        windows.append((max(0,min(now,row["next_run"])-row["lookback"]-row["horizon"]),None))
    # Persisted recovery work can be older than today's configured horizon.
    # Its cursor, rather than wall time, defines the earliest live input.
    for row in db.execute("SELECT l.cursor,p.definition FROM log_correlation_late_ranges l JOIN correlation_policies p ON p.id=l.policy_id AND p.version=l.version AND p.tenant=l.tenant WHERE l.tenant=? AND p.enabled=1",(tenant,)):
        windows.append((max(0,row["cursor"]-json.loads(row["definition"])["window"]),None))
    for row in db.execute("SELECT l.cursor,s.definition FROM analysis_late_ranges l JOIN analysis_schedules s ON l.kind='schedule' AND s.id=l.source_id AND s.tenant=l.tenant WHERE l.tenant=? AND s.enabled=1",(tenant,)):
        windows.append((max(0,row["cursor"]-json.loads(row["definition"])["lookback"]),None))
    for row in db.execute("SELECT l.cursor,r.lookback FROM analysis_late_ranges l JOIN rules r ON l.kind='saved_search' AND r.id=l.source_id AND r.tenant=l.tenant WHERE l.tenant=? AND r.enabled=1",(tenant,)):
        windows.append((max(0,row["cursor"]-row["lookback"]),None))
    for row in db.execute("SELECT w.window_start FROM analysis_window_inputs w WHERE w.tenant=? AND (EXISTS(SELECT 1 FROM analysis_schedules s WHERE w.kind='schedule' AND s.id=w.source_id AND s.tenant=w.tenant AND s.enabled=1) OR EXISTS(SELECT 1 FROM rules r WHERE w.kind='saved_search' AND r.id=w.source_id AND r.tenant=w.tenant AND r.enabled=1))",(tenant,)):
        windows.append((max(0,row["window_start"]),None))
    if not windows:
        return set()
    cutoff=min(w[0] for w in windows)
    # Clocks cover indexed native/generic paths; projections cover registered
    # sources, including old records whose provider clock metadata was absent.
    protected={r[0] for r in db.execute(
        "SELECT event_id FROM event_projections WHERE tenant=? AND event_time>=? AND event_id IN (SELECT value FROM json_each(?)) UNION SELECT event_id FROM pipeline_event_clocks WHERE tenant=? AND provider_time>=? AND event_id IN (SELECT value FROM json_each(?))",
        (tenant,cutoff,encode(ids),tenant,cutoff,encode(ids)))}
    if store is not None:
        con=store.analytics.cursor()
        try:
            protected.update(r[0] for r in con.execute("SELECT event_id FROM events_all WHERE tenant=? AND event_time>=? AND event_id IN (SELECT json_extract_string(value,'$') FROM json_each(?))",[tenant,cutoff,encode(ids)]).fetchall())
        finally:
            con.close()
    return protected
