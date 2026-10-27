"""Compact routine research payloads while retaining permanent hash history.

Case, legal-hold, live anomaly, pending queue and active model training evidence
are not released. Compaction never physically deletes an original telemetry row.
"""

import json
import time

from . import evidence_scope, migrations, principal
from .research_behavior_graph import digest
from .storage import ConflictError, encode

NORMAL_SECONDS = 86400
NORMAL_DETAILS_PER_MODEL = 128

# CASE is deliberately lazy: runs that are not yet due do not need the JSON,
# legal-hold or Case-reference candidate checks. Archival rechecks protections
# and payload integrity in its own current-principal write transaction.
_DUE_RUNS_SQL = """
SELECT r.* FROM research_behavior_runs r
WHERE NOT EXISTS(SELECT 1 FROM research_behavior_archives a WHERE a.id=r.id)
AND CASE
    WHEN (r.created<=? OR (
        SELECT count(*) FROM research_behavior_runs n
        WHERE n.tenant=r.tenant AND n.model_id IS r.model_id AND n.created>r.created
        AND NOT EXISTS(SELECT 1 FROM research_behavior_archives a WHERE a.id=n.id)
    )>=?)
    THEN (
        NOT(r.mode='live' AND json_extract(r.body,'$.decision.anomaly')=1)
        AND NOT EXISTS(SELECT 1 FROM policies p WHERE p.tenant=r.tenant AND p.hold=1)
        AND NOT EXISTS(
            SELECT 1 FROM record_case_evidence_refs e
            WHERE e.tenant=r.tenant AND e.kind IN ('bookmark','contribution')
            AND e.event_id IN (SELECT value FROM json_each(r.body,'$.event_ids'))
        )
    )
    ELSE 0
END
ORDER BY r.created LIMIT ?
"""


def initialize(store):
    migrations.apply_store(store,"research_behavior",[
        "CREATE TABLE IF NOT EXISTS research_behavior_archives(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,indexes TEXT NOT NULL,model_id TEXT,created REAL NOT NULL,input_digest TEXT NOT NULL,summary TEXT NOT NULL,archived REAL NOT NULL)",
        "CREATE INDEX IF NOT EXISTS research_behavior_archive_scope ON research_behavior_archives(tenant,created)",
        "CREATE TABLE IF NOT EXISTS research_behavior_retired_models(model_id TEXT PRIMARY KEY,tenant TEXT NOT NULL,reviewer TEXT NOT NULL,at REAL NOT NULL,digest TEXT NOT NULL,summary TEXT NOT NULL)",
    ],version=2)


def _archive(store,db,actor,identifier,reason):
    row=db.execute("SELECT * FROM research_behavior_runs WHERE id=? AND tenant=?",(identifier,actor["tenant"])).fetchone()
    if not row or not principal.contains(actor["allowed_indexes"],json.loads(row["indexes"])):
        raise KeyError("Research archive requires complete current run scope")
    old=db.execute("SELECT summary FROM research_behavior_archives WHERE id=? AND tenant=?",(identifier,actor["tenant"])).fetchone()
    if old:return json.loads(old["summary"])
    run=json.loads(row["body"])
    if digest(run)!=row["digest"]:
        raise ConflictError("Research payload changed before archival")
    ids=run["event_ids"]
    hold=db.execute("SELECT hold FROM policies WHERE tenant=?",(actor["tenant"],)).fetchone()
    protected = bool(hold and hold["hold"])
    if db.execute("SELECT 1 FROM record_case_evidence_refs WHERE tenant=? AND event_id IN (SELECT value FROM json_each(?)) AND kind IN ('bookmark','contribution') LIMIT 1",(actor["tenant"],encode(ids))).fetchone():
        protected=True
    if run["mode"]=="live" and run["decision"]["anomaly"]:
        protected=True
    if protected:
        return {"run_id":identifier,"state":"protected","reason":"Live anomaly, Case evidence or legal hold; full details retained"}
    now=time.time()
    summary={"run_id":identifier,"model_id":row["model_id"],"state":"archived","at":now,
        "original_payload_digest":row["digest"],"original_graph_digest":digest(run["graph"]),
        "original_event_count":len(ids),"original_set_digest":digest(sorted(ids)),
        "original_metadata_digest":digest(run["originals"]),"original_decision":run["decision"],
        "original_graph_counts":{"nodes":len(run["graph"].get("nodes",[])),"edges":len(run["graph"].get("edges",[])),"paths":len(run["graph"].get("summary_paths",[]))},
        "permanent_hash_metadata_retained":True,"originals_physically_deleted":False,
        "case_model_anomaly_queue_refs_modified":False,"reason":reason}
    # Preserve original IDs, admission hashes and numeric decisions. Semantic
    # features and detailed graphs can be replayed only while originals remain.
    run["results"]=[{key:value for key,value in item.items() if key not in {"features","missing_features","provenance"}} for item in run["results"]]
    run["graph"]={"archived":True,"original_graph_digest":summary["original_graph_digest"],"counts":summary["original_graph_counts"]}
    run["archive"]=summary
    run["status"]="archived"
    db.execute("INSERT INTO research_behavior_archives VALUES(?,?,?,?,?,?,?,?,?)",(identifier,actor["tenant"],row["owner"],row["indexes"],row["model_id"],row["created"],row["digest"],encode(summary),now))
    db.execute("UPDATE research_behavior_runs SET body=?,digest=? WHERE id=? AND tenant=?",(encode(run),digest(run),identifier,actor["tenant"]))
    db.execute("DELETE FROM record_case_evidence_refs WHERE tenant=? AND kind='research_behavior_run' AND record_id=?",(actor["tenant"],identifier))
    store.audit(db,actor["tenant"],actor["name"],"research.run.archive",summary)
    return summary


def archive_runs(store,who,run_ids,reason):
    from .research_behavior import _ids
    ids=_ids(run_ids,64)
    reason=evidence_scope.text(reason,"archive reason",2000)
    with principal.transaction(store,who,("admin","analyst"),write=True) as (db,actor):
        return {"items":[_archive(store,db,actor,identifier,reason) for identifier in ids]}


def retire(store,who,identifier,reason):
    from . import research_behavior as research
    reason=evidence_scope.text(reason,"retirement reason",2000)
    with principal.transaction(store,who,("admin","analyst"),write=True) as (db,actor):
        old=db.execute("SELECT * FROM research_behavior_retired_models WHERE tenant=? AND model_id=?",(actor["tenant"],identifier)).fetchone()
        if old:
            row=db.execute("SELECT indexes FROM research_behavior_models WHERE id=? AND tenant=?",(identifier,actor["tenant"])).fetchone()
            if not row or not principal.contains(actor["allowed_indexes"],json.loads(row["indexes"])):raise KeyError("Retired model not found")
            return json.loads(old["summary"])
        row,snapshot=research._verify_model(db,actor,identifier,authority=False)
        if row["owner"]==actor["name"]:
            raise PermissionError("Model creator cannot approve their own retirement")
        if row["state"]=="active":
            raise ConflictError("Disable the research model before explicit retirement")
        pending=db.execute("SELECT 1 FROM research_behavior_outbox o JOIN research_behavior_state s ON s.model_id=? WHERE o.tenant=? AND o.seq>s.cursor AND o.index_name IN (SELECT value FROM json_each(?)) LIMIT 1",(identifier,actor["tenant"],row["indexes"])).fetchone()
        if pending:
            raise ConflictError("Pending research originals must finish before retirement")
        count=db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE tenant=? AND kind='research_behavior_model' AND record_id=?",(actor["tenant"],identifier)).fetchone()[0]
        summary={"model_id":identifier,"retired":True,"reviewer":actor["name"],"at":time.time(),"model_digest":row["digest"],"revision":row["revision"],
            "training_references_released":count,"training_original_metadata_digest":digest(snapshot["originals"]),
            "model_weights_and_provenance_retained":True,"originals_physically_deleted":False,"case_anomaly_other_model_queue_refs_modified":False,"reason":reason}
        db.execute("INSERT INTO research_behavior_retired_models VALUES(?,?,?,?,?,?)",(identifier,actor["tenant"],actor["name"],summary["at"],row["digest"],encode(summary)))
        db.execute("UPDATE research_behavior_models SET state='retired' WHERE id=?",(identifier,))
        db.execute("DELETE FROM record_case_evidence_refs WHERE tenant=? AND kind='research_behavior_model' AND record_id=?",(actor["tenant"],identifier))
        db.execute("DELETE FROM record_case_evidence_refs WHERE tenant=? AND kind='research_behavior_context' AND record_id=?",(actor["tenant"],identifier))
        from . import research_long_horizon
        research_long_horizon.release_retired_cache(db,actor["tenant"],identifier)
        store.audit(db,actor["tenant"],actor["name"],"research.model.retire",summary)
        return summary


def run_due(store,now=None,cancel=None,maximum=8):
    now=time.time() if now is None else now
    with store.control() as db:
        rows=[dict(r) for r in db.execute(_DUE_RUNS_SQL,(now-NORMAL_SECONDS,NORMAL_DETAILS_PER_MODEL,min(16,maximum)))]
    archived=protected=excluded=0
    for row in rows:
        if cancel and cancel():break
        try:
            result=archive_runs(store,{"tenant":row["tenant"],"name":row["owner"],"role":"analyst"},[row["id"]],"Bounded normal/shadow detail lifecycle; permanent original hashes retained")["items"][0]
            archived+=result["state"]=="archived"
            protected+=result["state"]=="protected"
        except (PermissionError,KeyError,ConflictError):excluded+=1
    # Consumed journal references are redundant after all non-retired model
    # frontiers pass them. Never remove a pending row of a disabled model.
    with store.control() as db:
        db.execute("DELETE FROM research_behavior_outbox WHERE seq IN (SELECT o.seq FROM research_behavior_outbox o WHERE NOT EXISTS(SELECT 1 FROM research_behavior_state s JOIN research_behavior_models m ON m.id=s.model_id AND m.state<>'retired' WHERE s.tenant=o.tenant AND s.cursor<o.seq) ORDER BY o.seq LIMIT 256)")
    return {"archived":archived,"protected":protected,"excluded":excluded,"normal_detail_seconds":NORMAL_SECONDS,
            "normal_details_per_model":NORMAL_DETAILS_PER_MODEL,"permanent_run_hash_history":True}
