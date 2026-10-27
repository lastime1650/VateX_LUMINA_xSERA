"""Evidence-bound analyst verdicts and audited, nonduplicating Case regrouping.

Classification is an analyst judgement, never a machine malicious probability.
Stale verdict snapshots do not suppress changed evidence. Moving contributions
keeps their original IDs and verdicts; tasks, notes, holds and response receipts
stay on their original Case and remain accessible through an archived scope.
"""

import hashlib
import json
import re
import time
import uuid

from . import evidence_scope as evidence
from . import principal
from .storage import CapacityError, ConflictError, encode

CLASSIFICATIONS = {"true_positive", "expected_activity", "false_positive", "unknown"}
EDIT = ("admin", "analyst")
MAX_CASE_EVIDENCE = 10000


def initialize(store):
    with store.control(local=True) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS contribution_verdicts(
          tenant TEXT NOT NULL,contribution_id TEXT NOT NULL,classification TEXT NOT NULL,
          reason TEXT NOT NULL,actor TEXT NOT NULL,at REAL NOT NULL,version INTEGER NOT NULL,
          evidence_snapshot TEXT NOT NULL,origin TEXT NOT NULL,
          PRIMARY KEY(tenant,contribution_id));
        CREATE TABLE IF NOT EXISTS contribution_verdict_history(
          tenant TEXT NOT NULL,contribution_id TEXT NOT NULL,version INTEGER NOT NULL,
          record TEXT NOT NULL,PRIMARY KEY(tenant,contribution_id,version));
        CREATE TABLE IF NOT EXISTS case_movement_history(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,kind TEXT NOT NULL,
          source_incident TEXT NOT NULL,target_incident TEXT NOT NULL,
          actor TEXT NOT NULL,at REAL NOT NULL,indexes TEXT NOT NULL,record TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS case_movement_target ON
          case_movement_history(tenant,target_incident,kind);
        CREATE TABLE IF NOT EXISTS archived_case_scopes(
          tenant TEXT NOT NULL,incident_id TEXT NOT NULL,indexes TEXT NOT NULL,
          movement_id TEXT NOT NULL,PRIMARY KEY(tenant,incident_id));
        """)
    # Also initialize when this module is used independently by an upgrade or
    # a recovery tool; aliases are part of the atomic regrouping contract.
    from . import case_intelligence

    case_intelligence.initialize(store)


def active_predicate(alias="r"):
    """Fixed server-owned SQL only; caller values never become identifiers."""
    if not isinstance(alias, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", alias):
        raise ValueError("Invalid internal contribution alias")
    return (
        "NOT EXISTS(SELECT 1 FROM contribution_verdicts cv WHERE cv.tenant="
        + alias + ".tenant AND cv.contribution_id=" + alias + ".id AND cv.evidence_snapshot="
        + alias + ".evidence AND cv.classification IN ('false_positive','expected_activity'))"
    )


def classification(db, row):
    verdict = db.execute(
        "SELECT * FROM contribution_verdicts WHERE tenant=? AND contribution_id=?",
        (row["tenant"], row["id"]),
    ).fetchone()
    if not verdict:
        return {"classification": "unknown", "version": 0, "active": True, "stale": False}
    stale = verdict["evidence_snapshot"] != row["evidence"]
    label = "unknown" if stale else verdict["classification"]
    return {
        "classification": label,
        "version": verdict["version"],
        "active": label not in {"false_positive", "expected_activity"},
        "stale": stale,
        "actor": verdict["actor"],
        "at": verdict["at"],
        "reason": verdict["reason"],
        "origin": verdict["origin"],
        "meaning": "Analyst adjudication, not calibrated malicious probability",
    }


def _record(db, actor, row, label, reason, origin="analyst"):
    if len(row["evidence"].encode()) > 2 * 1024 * 1024:
        raise CapacityError("Contribution evidence snapshot exceeds 2 MiB")
    old = db.execute(
        "SELECT version FROM contribution_verdicts WHERE tenant=? AND contribution_id=?",
        (actor["tenant"], row["id"]),
    ).fetchone()
    version = (old[0] if old else 0) + 1
    now = time.time()
    db.execute(
        "INSERT INTO contribution_verdicts VALUES(?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(tenant,contribution_id) DO UPDATE SET classification=excluded.classification,"
        "reason=excluded.reason,actor=excluded.actor,at=excluded.at,version=excluded.version,"
        "evidence_snapshot=excluded.evidence_snapshot,origin=excluded.origin",
        (actor["tenant"], row["id"], label, reason, actor["name"], now, version, row["evidence"], origin),
    )
    result = {
        "contribution_id": row["id"], "incident_id": row["incident_id"],
        "classification": label, "reason": reason, "actor": actor["name"],
        "at": now, "version": version, "origin": origin,
        "evidence_sha256": hashlib.sha256(row["evidence"].encode()).hexdigest(),
    }
    db.execute("INSERT INTO contribution_verdict_history VALUES(?,?,?,?)",
               (actor["tenant"], row["id"], version, encode(result)))
    return result


def adjudicate(store, who, incident_id, contribution_id, data):
    if not isinstance(data, dict) or set(data) != {"classification", "reason", "version"}:
        raise ValueError("classification, reason and version are required")
    label = evidence.choice(data["classification"], CLASSIFICATIONS, "classification")
    reason = evidence.text(data["reason"], "adjudication reason", 2000)
    version = evidence.integer(data["version"], "version", 0, 2**31 - 1)
    with principal.transaction(store, who, EDIT, write=True) as (db, actor):
        incident = principal.incident(db, actor, incident_id)
        row = db.execute(
            "SELECT * FROM risk_contributions WHERE tenant=? AND incident_id=? AND id=?",
            (actor["tenant"], incident_id, contribution_id),
        ).fetchone()
        if not row:
            raise KeyError("Contribution not found in this Case")
        old = db.execute("SELECT version FROM contribution_verdicts WHERE tenant=? AND contribution_id=?",
                         (actor["tenant"], contribution_id)).fetchone()
        if (old[0] if old else 0) != version:
            raise ConflictError("Contribution verdict version changed")
        result = _record(db, actor, row, label, reason)
        # A malicious/unreviewed observation cannot remain hidden by a whole-Case FP.
        status = "triage" if incident["status"] == "false_positive" and label in {"true_positive", "unknown"} else incident["status"]
        db.execute("UPDATE incidents SET status=?,updated=?,version=version+1 WHERE tenant=? AND id=?",
                   (status, time.time(), actor["tenant"], incident_id))
        store.audit(db, actor["tenant"], actor["name"], "case.contribution.adjudicate", result)
        return {**result, "incident_status": status, "active": label not in {"false_positive", "expected_activity"}}


def require_case_adjudication(db, actor, incident_id, status):
    """Same transaction hook for legacy bulk FP and safe mixed-Case handling."""
    if status == "false_positive":
        rows = db.execute("SELECT * FROM risk_contributions WHERE tenant=? AND incident_id=? LIMIT ?",
                          (actor["tenant"], incident_id, MAX_CASE_EVIDENCE + 1)).fetchall()
        if len(rows) > MAX_CASE_EVIDENCE:
            raise CapacityError("Classify large Case evidence in bounded pages")
        labels = [classification(db, row) for row in rows]
        if any(v["classification"] == "true_positive" for v in labels):
            raise ConflictError("Mixed Case contains true-positive evidence; classify or split individual contributions")
        explicit = any(v.get("origin") == "analyst" for v in labels)
        if explicit and any(v["classification"] == "unknown" for v in labels):
            raise ConflictError("Classify remaining unknown evidence before dismissing the whole mixed Case")
        for row, verdict in zip(rows, labels):
            if verdict["classification"] == "unknown":
                _record(db, actor, row, "false_positive", "Explicit legacy whole-Case false-positive adjudication", "case_status")
    elif status in {"new", "triage"}:
        rows = db.execute(
            "SELECT r.* FROM risk_contributions r JOIN contribution_verdicts v ON v.tenant=r.tenant "
            "AND v.contribution_id=r.id WHERE r.tenant=? AND r.incident_id=? AND v.origin='case_status' LIMIT ?",
            (actor["tenant"], incident_id, MAX_CASE_EVIDENCE + 1),
        ).fetchall()
        if len(rows) > MAX_CASE_EVIDENCE:
            raise CapacityError("Reopen large Case evidence in bounded pages")
        for row in rows:
            _record(db, actor, row, "unknown", "Whole-Case dismissal reopened; independent analyst labels retained", "case_status")


def list_verdicts(store, who, incident_id, after="", count=100):
    evidence.integer(count, "count", 1, 200)
    if not isinstance(after, str) or len(after) > 256:
        raise ValueError("Invalid contribution cursor")
    with principal.transaction(store, who) as (db, actor):
        principal.incident(db, actor, incident_id)
        rows = db.execute("SELECT * FROM risk_contributions WHERE tenant=? AND incident_id=? AND id>? ORDER BY id LIMIT ?",
                          (actor["tenant"], incident_id, after, count + 1)).fetchall()
        return {"items": [{"contribution_id":r["id"],"policy_id":r["policy_id"],**classification(db,r)} for r in rows[:count]],
                "next_cursor": rows[count-1]["id"] if len(rows)>count else None}


def authorize_archived_scope(db, actor, incident_id):
    row = db.execute("SELECT indexes FROM archived_case_scopes WHERE tenant=? AND incident_id=?",
                     (actor["tenant"], incident_id)).fetchone()
    if not row or not principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
        raise KeyError("Incident not found")
    return True


def _scope(db, actor, identifier):
    indexes = {value for row in db.execute("SELECT indexes FROM risk_contributions WHERE tenant=? AND incident_id=?",
               (actor["tenant"], identifier)) for value in json.loads(row[0])}
    indexes.update(row[0] for row in db.execute("SELECT index_name FROM case_bookmarks WHERE tenant=? AND incident_id=?",
                   (actor["tenant"], identifier)))
    archived = db.execute("SELECT indexes FROM archived_case_scopes WHERE tenant=? AND incident_id=?",
                          (actor["tenant"], identifier)).fetchone()
    if archived:
        indexes.update(json.loads(archived[0]))
    return sorted(indexes)


def _ancestors(db, tenant, identifier):
    rows = db.execute("""WITH RECURSIVE origins(id) AS (
      SELECT ? UNION SELECT h.source_incident FROM case_movement_history h JOIN origins o
      ON h.target_incident=o.id WHERE h.tenant=? AND h.kind='merge')
      SELECT id FROM origins LIMIT 130""", (identifier, tenant)).fetchall()
    if len(rows)>129:
        raise CapacityError("Merged Case lineage exceeds 128 sources")
    return [r[0] for r in rows]


def require_resolution(db, actor, incident_id):
    origins = _ancestors(db, actor["tenant"], incident_id)
    if db.execute("SELECT 1 FROM case_tasks WHERE tenant=? AND incident_id IN ("+
                  ",".join("?" for _ in origins)+") AND mandatory=1 AND status!='done' LIMIT 1",
                  [actor["tenant"], *origins]).fetchone():
        raise ConflictError("Complete required tasks on this Case and merged source Cases before resolving")


def regroup(store, who, incident_id, kind, data, *, _after=None):
    required = {"version", "reason", "contribution_ids"} if kind == "split" else {"version", "reason", "target_id", "target_version"}
    if kind not in {"split", "merge"} or not isinstance(data,dict) or set(data)!=required:
        raise ValueError("Typed split or merge fields are required")
    reason=evidence.text(data["reason"],"regroup reason",2000)
    version=evidence.integer(data["version"],"version",1,2**31-1)
    with principal.transaction(store,who,EDIT,write=True) as (db,actor):
        source=principal.incident(db,actor,incident_id)
        if source["version"]!=version:
            raise ConflictError("Source Case version changed")
        rows=db.execute("SELECT * FROM risk_contributions WHERE tenant=? AND incident_id=? ORDER BY id LIMIT ?",
                        (actor["tenant"],incident_id,MAX_CASE_EVIDENCE+1)).fetchall()
        if not rows or len(rows)>MAX_CASE_EVIDENCE:
            raise CapacityError("Source Case needs 1..10000 contributions for atomic regrouping")
        source_scope=_scope(db,actor,incident_id)
        now=time.time()
        if kind=="split":
            selected=data["contribution_ids"]
            if (not isinstance(selected,list) or not selected or any(not isinstance(x,str) for x in selected)
                or len(set(selected))!=len(selected) or not set(selected)<{r["id"] for r in rows}):
                raise ValueError("Split selects a nonempty proper subset of exact source contribution IDs")
            target_id=str(uuid.uuid4())
            db.execute("INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?)",
                       (target_id,actor["tenant"],source["entity"],source["entity_field"],
                        ("Split: "+source["name"])[:120],now,now,"triage",source["owner"],1))
            target_scope=[]
        else:
            target_id=evidence.text(data["target_id"],"target_id")
            if target_id==incident_id:
                raise ValueError("A Case cannot merge into itself")
            target=principal.incident(db,actor,target_id)
            if target["version"]!=evidence.integer(data["target_version"],"target_version",1,2**31-1):
                raise ConflictError("Target Case version changed")
            if target["status"] not in {"new","triage"}:
                raise ConflictError("Reopen the target Case before merging")
            if target_id in _ancestors(db,actor["tenant"],incident_id):
                raise ConflictError("Case merge would create a lineage cycle")
            selected=[r["id"] for r in rows]
            target_scope=_scope(db,actor,target_id)
            if len(_ancestors(db,actor["tenant"],target_id))+len(_ancestors(db,actor["tenant"],incident_id))>129:
                raise CapacityError("Merged Case lineage exceeds 128 sources")
        indexes=sorted(set(source_scope+target_scope))
        if not principal.contains(actor["allowed_indexes"],indexes):
            raise KeyError("Case regroup requires complete source and target evidence scope")
        from . import case_intelligence

        case_intelligence.assert_mutation_allowed(db, actor, incident_id, target_id)
        for identifier in selected:
            db.execute("UPDATE risk_contributions SET incident_id=? WHERE tenant=? AND incident_id=? AND id=?",
                       (target_id,actor["tenant"],incident_id,identifier))
        db.execute("UPDATE incidents SET updated=?,version=version+1,status=? WHERE tenant=? AND id=?",
                   (now,"resolved" if kind=="merge" else source["status"],actor["tenant"],incident_id))
        if kind=="merge":
            db.execute("UPDATE incidents SET updated=?,version=version+1 WHERE tenant=? AND id=?",
                       (now,actor["tenant"],target_id))
        movement_id=str(uuid.uuid4())
        result={"id":movement_id,"kind":kind,"source_id":incident_id,"target_id":target_id,
                "contribution_ids":selected,"reason":reason,"actor":actor["name"],"at":now,
                "indexes":indexes,"duplicate_evidence_created":False,
                "original_notes_tasks_holds_and_response_receipts_retained":True}
        db.execute("INSERT INTO case_movement_history VALUES(?,?,?,?,?,?,?,?,?)",
                   (movement_id,actor["tenant"],kind,incident_id,target_id,actor["name"],now,encode(indexes),encode(result)))
        case_intelligence.record_movement(
            db, actor, incident_id, target_id, kind, movement_id, rows, selected
        )
        if kind=="merge":
            db.execute("INSERT INTO archived_case_scopes VALUES(?,?,?,?) ON CONFLICT(tenant,incident_id) "
                       "DO UPDATE SET indexes=excluded.indexes,movement_id=excluded.movement_id",
                       (actor["tenant"],incident_id,encode(source_scope),movement_id))
        store.audit(db,actor["tenant"],actor["name"],"case."+kind,result)
        if _after is not None:
            _after(db, actor, result)
        return result


def movement_history(store,who,incident_id):
    with principal.transaction(store,who) as (db,actor):
        principal.incident(db,actor,incident_id)
        rows=db.execute("SELECT * FROM case_movement_history WHERE tenant=? AND "
                        "(source_incident=? OR target_incident=?) ORDER BY at,id",
                        (actor["tenant"],incident_id,incident_id)).fetchall()
        visible=[json.loads(r["record"]) for r in rows
                 if principal.contains(actor["allowed_indexes"],json.loads(r["indexes"]))]
        return {"items":visible,"truncated":False,
                "meaning":"Evidence IDs moved; original investigation material and mandatory tasks remain on source Cases"}
