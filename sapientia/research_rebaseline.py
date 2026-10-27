"""Drift notices and explicit normal-evidence/review/promotion/rollback workflow."""

import json
import time
import uuid

from . import evidence_scope, migrations, principal
from .research_behavior_graph import digest
from .storage import CapacityError, ConflictError, encode


def initialize(store):
    migrations.apply_store(store,"research_rebaseline",[
        "CREATE TABLE IF NOT EXISTS research_rebaseline_candidates(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,indexes TEXT NOT NULL,created REAL NOT NULL,updated REAL NOT NULL,revision INTEGER NOT NULL,state TEXT NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS research_rebaseline_drift(model_id TEXT PRIMARY KEY,tenant TEXT NOT NULL,state TEXT NOT NULL,digest TEXT NOT NULL,updated REAL NOT NULL)",
        "CREATE TABLE IF NOT EXISTS research_rebaseline_audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT NOT NULL,candidate_id TEXT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,at REAL NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL)",
    ])


def _read(db,actor,identifier):
    row=db.execute("SELECT * FROM research_rebaseline_candidates WHERE tenant=? AND id=?",(actor["tenant"],identifier)).fetchone()
    if not row:raise KeyError("Rebaseline candidate unavailable")
    if not principal.contains(actor["allowed_indexes"],json.loads(row["indexes"])):raise PermissionError("Full rebaseline scope required")
    body=json.loads(row["body"])
    if digest(body)!=row["digest"] or body["revision"]!=row["revision"] or body["state"]!=row["state"]:raise ConflictError("Rebaseline candidate hash differs")
    return dict(row),body


def _write(db,actor,body,action,*,expected=None):
    now=time.time();body["updated"]=now
    if expected is None:
        if db.execute("SELECT count(*) FROM research_rebaseline_candidates WHERE tenant=? AND state NOT IN ('rolled_back','rejected')",(actor["tenant"],)).fetchone()[0]>=32:raise CapacityError("Rebaseline capacity 32 reached")
        db.execute("INSERT INTO research_rebaseline_candidates VALUES(?,?,?,?,?,?,?,?,?,?)",(body["id"],actor["tenant"],body["owner"],encode(body["indexes"]),body["created"],now,body["revision"],body["state"],encode(body),digest(body)))
    else:
        body["revision"]=expected+1
        changed=db.execute("UPDATE research_rebaseline_candidates SET updated=?,revision=?,state=?,body=?,digest=? WHERE tenant=? AND id=? AND revision=?",(now,body["revision"],body["state"],encode(body),digest(body),actor["tenant"],body["id"],expected)).rowcount
        if changed!=1:raise ConflictError("Rebaseline candidate changed")
    audit={"candidate_digest":digest(body),"revision":body["revision"],"state":body["state"]}
    db.execute("INSERT INTO research_rebaseline_audit(tenant,candidate_id,actor,action,at,body,digest) VALUES(?,?,?,?,?,?,?)",(actor["tenant"],body["id"],actor["name"],action,now,encode(audit),digest(audit)))
    return {**body,"digest":digest(body)}


def create(store,who,data):
    from . import research_behavior as research
    if not isinstance(data,dict) or set(data)!={"model_id","reason"}:raise ValueError("Candidate requires model_id/reason")
    reason=evidence_scope.text(data["reason"],"reason",2000)
    evidence_scope.text(data["model_id"],"model_id")
    with principal.transaction(store,who,research.EDITORS,write=True) as (db,actor):
        row,snapshot=research._verify_model(db,actor,data["model_id"],require_active=True)
        if not research._v2(snapshot):raise ValueError("Rebaseline workflow requires explicit v2 model")
        body={"id":"RBC-"+uuid.uuid4().hex,"schema":"xsera.research-rebaseline.v1","tenant":actor["tenant"],"owner":actor["name"],"indexes":json.loads(row["indexes"]),"created":time.time(),"revision":1,"state":"needs_normal_evidence","baseline_model_id":row["id"],"baseline_digest":row["digest"],"baseline_reviewed_at":row["reviewed"],"reason":reason,"automatic_learning":False,"automatically_promoted":False}
        return _write(db,actor,body,"create")


def prepare(store,who,identifier,data):
    from . import research_behavior as research
    from . import research_evaluation as evaluation
    if not isinstance(data,dict) or set(data)!={"expected_revision","dataset_id","epochs","seeds","normal_training_confirmed"} or data["normal_training_confirmed"] is not True:raise ValueError("Explicit curated normal evidence and expected_revision/dataset_id/epochs/seeds required")
    evidence_scope.text(data["dataset_id"],"dataset_id");evidence_scope.integer(data["expected_revision"],"expected_revision",1,1000000)
    with principal.transaction(store,who,research.EDITORS) as (db,actor):
        _,body=_read(db,actor,identifier)
        if body["revision"]!=data["expected_revision"] or body["state"]!="needs_normal_evidence":raise ConflictError("Candidate must await normal evidence at exact revision")
        previous,_=research._verify_model(db,actor,body["baseline_model_id"],require_active=True)
        if previous["digest"]!=body["baseline_digest"] or previous["reviewed"]!=body["baseline_reviewed_at"]:raise ConflictError("Baseline epoch changed")
    dataset=evaluation.dataset(store,actor,data["dataset_id"])
    if dataset.get("archived"):raise ConflictError("Archived dataset cannot prepare a new baseline")
    if not set(dataset["indexes"])<=set(body["indexes"]):raise PermissionError("Candidate dataset exceeds baseline scope")
    train_ids=[e for s in dataset["scenarios"] if s["split"]=="training" for e in s["event_ids"]];val_ids=[e for s in dataset["scenarios"] if s["split"]=="validation" for e in s["event_ids"]]
    model=research.train(store,actor,{"name":previous["name"],"indexes":body["indexes"],"training_ids":train_ids,"validation_ids":val_ids,"epochs":data["epochs"],"seeds":data["seeds"],"normal_training_confirmed":True,"gate_version":"v2"})
    if model.get("status")=="unavailable":return model
    result=evaluation.evaluate(store,actor,{"dataset_id":dataset["id"],"model_id":model["id"]})
    if result.get("status")=="unavailable":return result
    with principal.transaction(store,actor,research.EDITORS,write=True) as (db,_):
        evaluation.require_retained(db,actor,"datasets",dataset["id"])
        evaluation.require_retained(db,actor,"runs",result["id"])
        _,latest=_read(db,actor,identifier)
        if latest["revision"]!=data["expected_revision"] or latest["state"]!="needs_normal_evidence":raise ConflictError("Candidate changed during CPU preparation; unapproved model remains pending")
        latest.update(state="pending_review",dataset_id=dataset["id"],dataset_digest=dataset["digest"],candidate_model_id=model["id"],candidate_model_digest=model["digest"],evaluation_id=result["id"],evaluation_digest=result["digest"],prepared_by=actor["name"],evaluation_metrics=result["metrics"],origin=result["origin"])
        return _write(db,actor,latest,"prepare",expected=data["expected_revision"])


def _prepare_evidence(store,who,identifier,revision,state):
    """Read large immutable raw cohorts before acquiring the atomic write lock."""
    from . import research_behavior as research
    from . import research_evaluation as evaluation
    with principal.transaction(store,who,research.EDITORS) as (db,actor):
        _,body=_read(db,actor,identifier)
        if body["revision"]!=revision or body["state"]!=state:raise ConflictError("Exact rebaseline state/revision required")
        research._verify_model(db,actor,body["candidate_model_id"])
    manifest,records=evaluation.dataset(store,actor,body["dataset_id"],with_records=True)
    result=evaluation.get_run(store,actor,body["evaluation_id"])
    if result.get("archived"):raise ConflictError("Archived evaluation cannot approve a replacement")
    if manifest["digest"]!=body["dataset_digest"] or result["digest"]!=body["evaluation_digest"]:raise ConflictError("Reviewed dataset/evaluation epoch differs")
    return {"actor":actor,"candidate_digest":digest(body),"manifest":manifest,"records":records,"result":result}


def _evidence(db,actor,body,prepared):
    from . import research_behavior as research
    from . import research_evaluation as evaluation
    evaluation.require_retained(db,actor,"datasets",body["dataset_id"])
    evaluation.require_retained(db,actor,"runs",body["evaluation_id"])
    baseline,_=research._verify_model(db,actor,body["baseline_model_id"])
    candidate,snapshot=research._verify_model(db,actor,body["candidate_model_id"])
    if baseline["digest"]!=body["baseline_digest"] or candidate["digest"]!=body["candidate_model_digest"]:raise ConflictError("Rebaseline model hash differs")
    if prepared["actor"]!=actor or prepared["candidate_digest"]!=digest(body):raise ConflictError("Candidate/actor changed during raw evidence preparation")
    manifest=prepared["manifest"];records=prepared["records"];result=prepared["result"]
    current_dataset=db.execute("SELECT digest FROM research_evaluation_datasets WHERE tenant=? AND id=?",(actor["tenant"],manifest["id"])).fetchone()
    current_result=db.execute("SELECT digest FROM research_evaluation_runs WHERE tenant=? AND id=?",(actor["tenant"],result["id"])).fetchone()
    if not current_dataset or not current_result or current_dataset[0]!=manifest["digest"] or current_result[0]!=result["digest"]:raise ConflictError("Evaluation dataset/run changed during preparation")
    if manifest["digest"]!=body["dataset_digest"] or result["digest"]!=body["evaluation_digest"] or result["model_digest"]!=candidate["digest"]:raise ConflictError("Reviewed dataset/evaluation epoch differs")
    evidence_scope.recheck(db,actor,records);research._verify_sources(db,actor,manifest["originals"],required=True)
    research._verify_sources(db,actor,snapshot["originals"],required=True)
    return baseline,candidate,snapshot,result


def review(store,who,identifier,data):
    from . import research_behavior as research
    if not isinstance(data,dict) or set(data)!={"expected_revision","approve","reason","mode","minimum_precision","minimum_recall","maximum_false_positive_rate"} or type(data["approve"]) is not bool:raise ValueError("Independent review requires exact revision/decision/mode/reason and explicit evaluation acceptance thresholds")
    reason=evidence_scope.text(data["reason"],"reason",2000);mode=evidence_scope.choice(data["mode"],{"shadow","live"},"mode")
    for key in ("minimum_precision","minimum_recall","maximum_false_positive_rate"):
        if type(data[key]) not in (int,float) or not 0<=data[key]<=1:raise ValueError("Finite 0..1 acceptance thresholds required")
    evidence_scope.integer(data["expected_revision"],"expected_revision",1,1000000)
    prepared=_prepare_evidence(store,who,identifier,data["expected_revision"],"pending_review")
    with principal.transaction(store,who,research.EDITORS,write=True) as (db,actor):
        _,body=_read(db,actor,identifier)
        if body["revision"]!=data["expected_revision"] or body["state"]!="pending_review":raise ConflictError("Exact pending review candidate required")
        baseline,candidate,_,result=_evidence(db,actor,body,prepared)
        if actor["name"] in {body["owner"],body["prepared_by"],candidate["owner"],baseline["owner"],prepared["manifest"]["owner"],result["owner"]}:raise PermissionError("Independent reviewer must differ from baseline/candidate/dataset creators and preparer")
        metrics=result["metrics"];p=metrics["precision"]["estimate"];r=metrics["recall"]["estimate"];f=metrics["false_positive_rate"]["estimate"]
        if data["approve"] and (p is None or r is None or f is None or p<data["minimum_precision"] or r<data["minimum_recall"] or f>data["maximum_false_positive_rate"]):raise ValueError("Independent holdout does not meet explicit reviewer acceptance thresholds")
        body.update(state="approved" if data["approve"] else "rejected",reviewer=actor["name"],reviewed_at=time.time(),review_reason=reason,mode=mode,acceptance={k:data[k] for k in ("minimum_precision","minimum_recall","maximum_false_positive_rate")})
        return _write(db,actor,body,"review",expected=data["expected_revision"])


def promote(store,who,identifier,data):
    from . import research_behavior as research
    if not isinstance(data,dict) or set(data)!={"expected_revision","reason"}:raise ValueError("Atomic promotion requires expected_revision/reason")
    reason=evidence_scope.text(data["reason"],"reason",2000)
    evidence_scope.integer(data["expected_revision"],"expected_revision",1,1000000)
    prepared=_prepare_evidence(store,who,identifier,data["expected_revision"],"approved")
    with principal.transaction(store,who,research.EDITORS,write=True) as (db,actor):
        _,body=_read(db,actor,identifier)
        if body["revision"]!=data["expected_revision"] or body["state"]!="approved":raise ConflictError("Approved exact candidate revision required")
        baseline,candidate,snapshot,_=_evidence(db,actor,body,prepared)
        reviewer=principal.current(db,{"name":body["reviewer"],"tenant":actor["tenant"],"role":"analyst"},research.EDITORS)
        if not principal.contains(reviewer["allowed_indexes"],body["indexes"]):raise PermissionError("Reviewer scope changed")
        if baseline["state"]!="active" or baseline["reviewed"]!=body["baseline_reviewed_at"] or candidate["state"]!="pending":raise ConflictError("Active baseline or pending candidate epoch changed")
        now=time.time();mode=body["mode"]
        db.execute("UPDATE research_behavior_models SET state='disabled' WHERE id=?",(baseline["id"],))
        db.execute("UPDATE research_behavior_models SET state='active',reviewer=?,review_mode=?,review_reason=?,reviewed=? WHERE id=?",(reviewer["name"],mode,reason,now,candidate["id"]))
        db.execute("INSERT INTO research_behavior_reviews(tenant,model_id,reviewer,approve,mode,reason,at,digest) VALUES(?,?,?,?,?,?,?,?)",(actor["tenant"],candidate["id"],reviewer["name"],1,mode,reason,now,candidate["digest"]))
        state={"schema":research._fusion_engine(snapshot).SCHEMA,"recent_ids":[]};cursor=db.execute("SELECT coalesce(max(seq),0) FROM research_behavior_outbox").fetchone()[0]
        db.execute("INSERT INTO research_behavior_state VALUES(?,?,?,?,?,?,NULL)",(candidate["id"],actor["tenant"],cursor,encode(state),digest(state),now))
        body.update(state="promoted",promoted_at=now,promoted_by=actor["name"],promotion_reason=reason,promoted_model_reviewed_at=now)
        return _write(db,actor,body,"promote",expected=data["expected_revision"])


def rollback(store,who,identifier,data):
    from . import research_behavior as research
    if not isinstance(data,dict) or set(data)!={"expected_revision","reason"}:raise ValueError("Rollback requires expected_revision/reason")
    reason=evidence_scope.text(data["reason"],"reason",2000)
    evidence_scope.integer(data["expected_revision"],"expected_revision",1,1000000)
    with principal.transaction(store,who,research.EDITORS,write=True) as (db,actor):
        _,body=_read(db,actor,identifier)
        if body["revision"]!=data["expected_revision"] or body["state"]!="promoted":raise ConflictError("Exact promoted candidate required")
        baseline,snapshot=research._verify_model(db,actor,body["baseline_model_id"])
        candidate,_=research._verify_model(db,actor,body["candidate_model_id"],require_active=True)
        if actor["name"] in {baseline["owner"],candidate["owner"],body["prepared_by"]}:raise PermissionError("Independent reviewer required for rollback")
        if candidate["reviewed"]!=body["promoted_model_reviewed_at"] or baseline["state"]!="disabled" or baseline["digest"]!=body["baseline_digest"]:raise ConflictError("Rollback epoch changed")
        mode=baseline["review_mode"];research._verify_sources(db,actor,snapshot["originals"],required=mode=="live")
        now=time.time();db.execute("UPDATE research_behavior_models SET state='disabled' WHERE id=?",(candidate["id"],))
        db.execute("UPDATE research_behavior_models SET state='active',reviewer=?,review_reason=?,reviewed=? WHERE id=?",(actor["name"],reason,now,baseline["id"]))
        db.execute("INSERT INTO research_behavior_reviews(tenant,model_id,reviewer,approve,mode,reason,at,digest) VALUES(?,?,?,?,?,?,?,?)",(actor["tenant"],baseline["id"],actor["name"],1,mode,reason,now,baseline["digest"]))
        body.update(state="rolled_back",rolled_back_at=now,rollback_reason=reason,rolled_back_by=actor["name"])
        return _write(db,actor,body,"rollback",expected=data["expected_revision"])


def observe(store,actor,run):
    """Score-pressure notice only; no raw input is labelled normal or learned."""
    from . import research_behavior as research
    if run.get("mode")!="live" or not run.get("long_evidence"):return
    with principal.transaction(store,actor,research.EDITORS,write=True) as (db,fresh):
        row,snapshot=research._verify_model(db,fresh,run["model_id"],require_active=True)
        if not research._v2(snapshot) or row["digest"]!=run["model_digest"]:return
        old=db.execute("SELECT * FROM research_rebaseline_drift WHERE model_id=?",(row["id"],)).fetchone()
        state=json.loads(old["state"]) if old else {"schema":"score_pressure.v1","runs":[],"last_candidate":None}
        if old and digest(state)!=old["digest"]:raise ConflictError("Drift notice state differs")
        if any(r["id"]==run["id"] for r in state["runs"]):return
        state["runs"]=(state["runs"]+[{"id":run["id"],"anomaly":run["decision"]["anomaly"],"score":run["decision"]["score"],"at":run["created"]}])[-8:]
        if len(state["runs"])>=5 and sum(r["anomaly"] for r in state["runs"][-5:])>=3 and not state["last_candidate"]:
            body={"id":"RBC-"+uuid.uuid4().hex,"schema":"xsera.research-rebaseline.v1","tenant":fresh["tenant"],"owner":fresh["name"],"indexes":json.loads(row["indexes"]),"created":time.time(),"revision":1,"state":"needs_normal_evidence","baseline_model_id":row["id"],"baseline_digest":row["digest"],"baseline_reviewed_at":row["reviewed"],"reason":"Score-pressure notice: at least 3 anomalies in last 5 live runs; this is neither confirmed benign drift nor an instruction to learn these events","trigger_runs":[r["id"] for r in state["runs"][-5:]],"automatic_learning":False,"automatically_promoted":False}
            _write(db,fresh,body,"score_pressure_notice");state["last_candidate"]=body["id"]
        db.execute("INSERT INTO research_rebaseline_drift VALUES(?,?,?,?,?) ON CONFLICT(model_id) DO UPDATE SET state=excluded.state,digest=excluded.digest,updated=excluded.updated",(row["id"],fresh["tenant"],encode(state),digest(state),time.time()))


def get(store,who,identifier):
    with principal.transaction(store,who) as (db,actor):
        _,body=_read(db,actor,identifier)
        return {**body,"digest":digest(body)}


def listing(store,who):
    with principal.transaction(store,who) as (db,actor):
        return {"items":[{**json.loads(r["body"]),"digest":r["digest"]} for r in db.execute("SELECT * FROM research_rebaseline_candidates WHERE tenant=? ORDER BY updated DESC LIMIT 128",(actor["tenant"],)) if principal.contains(actor["allowed_indexes"],json.loads(r["indexes"]))],"automatic_learning":False}
