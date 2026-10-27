"""Explicit, immutable labelled-original evaluation; never a publication route."""

import collections
import json
import math
import time
import uuid

from . import evidence_scope, migrations, principal
from .research_behavior_graph import digest
from .storage import CapacityError, ConflictError, encode

MAX_SCENARIOS=2048
MAX_EVENTS=16384
MAX_BYTES=64*1024*1024


def initialize(store):
    migrations.apply_store(store,"research_evaluation",[
        "CREATE TABLE IF NOT EXISTS research_evaluation_datasets(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,created REAL NOT NULL,indexes TEXT NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS research_evaluation_runs(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,created REAL NOT NULL,indexes TEXT NOT NULL,dataset_id TEXT NOT NULL,model_id TEXT NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS research_evaluation_scope ON research_evaluation_runs(tenant,created)",
    ])
    migrations.apply_store(store,"research_evaluation",[
        "CREATE TABLE IF NOT EXISTS research_evaluation_dataset_archives(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,actor TEXT NOT NULL,created REAL NOT NULL,original_digest TEXT NOT NULL,summary TEXT NOT NULL,digest TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS research_evaluation_run_archives(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,actor TEXT NOT NULL,created REAL NOT NULL,original_digest TEXT NOT NULL,summary TEXT NOT NULL,digest TEXT NOT NULL)",
    ],version=2)


def _archive_row(db,actor,kind,identifier):
    table="research_evaluation_dataset_archives" if kind=="datasets" else "research_evaluation_run_archives"
    row=db.execute("SELECT * FROM "+table+" WHERE tenant=? AND id=?",(actor["tenant"],identifier)).fetchone()
    if not row:return None
    summary=json.loads(row["summary"])
    if digest(summary)!=row["digest"]:raise ConflictError("Evaluation archive hash differs")
    return summary


def require_retained(db,actor,kind,identifier):
    if _archive_row(db,actor,kind,identifier):raise ConflictError("Archived evaluation evidence cannot be used for new evaluation or promotion")


def _load(store,actor,ids):
    from . import research_behavior as research
    result={};size=0
    for offset in range(0,len(ids),32):
        batch=research._originals(store,actor,ids[offset:offset+32]);size+=sum(len(encode(r).encode()) for r in batch.values())
        if size>MAX_BYTES:raise CapacityError("Evaluation raw cohort exceeds 64 MiB")
        result.update(batch)
    return result


def _quality(scenarios,records):
    from . import research_features_v2 as features
    from . import research_fusion_v2 as fusion
    groups={name:[s for s in scenarios if s["split"]==name] for name in ("training","validation","test")}
    sets={name:{"events":{eid for s in rows for eid in s["event_ids"]},"hosts":{fusion.host_key(records[eid]) for s in rows for eid in s["event_ids"]},"families":{s["family"] for s in rows},"campaigns":{s["campaign"] for s in rows}} for name,rows in groups.items()}
    overlaps=[]
    for left,right in (("training","validation"),("training","test"),("validation","test")):
        overlap={key:len(sets[left][key]&sets[right][key]) for key in sets[left]}
        if any(overlap.values()):raise ValueError("Independent split overlap: "+encode({"left":left,"right":right,**overlap}))
        overlaps.append({"left":left,"right":right,**overlap})
    ranges={name:[min(records[e]["event_time"] for e in sets[name]["events"]),max(records[e]["event_time"] for e in sets[name]["events"])] for name in groups}
    if not ranges["training"][1]<ranges["validation"][0] or not ranges["validation"][1]<ranges["test"][0]:raise ValueError("Strict training < validation < test chronology required")
    signatures={name:[digest([features.features(records[e])["values"],features.features(records[e])["target"]]) for e in sets[name]["events"]] for name in groups}
    return {"strict_split_passed":True,"overlaps":overlaps,"time_ranges":ranges,"scenario_counts":{k:len(v) for k,v in groups.items()},
        "feature_content_overlap":[{"left":left,"right":right,"count":len(set(signatures[left])&set(signatures[right]))} for left,right in (("training","validation"),("training","test"),("validation","test"))],
        "repeated_feature_fraction":{name:1-len(set(values))/len(values) for name,values in signatures.items()},
        "family_names_are_curator_assertions":True,"semantic_family_independence_proven":False,"labels_used_as_model_features":False,
        "warning":"Host/time/family/campaign identifiers are separated. Repeated normal behaviour and semantic feature overlap remain explicitly measured; renamed family identifiers alone do not establish real-world generalization."}


def save_dataset(store,who,data):
    from . import research_behavior as research
    from . import research_fusion_v2 as fusion
    if not isinstance(data,dict) or set(data)!={"name","origin","scenarios","description"}:raise ValueError("Dataset requires name, origin, scenarios, description")
    name=evidence_scope.text(data["name"],"name",120);description=evidence_scope.text(data["description"],"description",4000)
    origin=evidence_scope.choice(data["origin"],{"synthetic","field_import"},"dataset origin")
    scenarios=data["scenarios"]
    if not isinstance(scenarios,list) or not 3<=len(scenarios)<=MAX_SCENARIOS:raise ValueError("3..2048 explicitly labelled scenarios required")
    normalized=[];seen=set();ids=[]
    for scenario in scenarios:
        if not isinstance(scenario,dict) or set(scenario)!={"id","split","family","campaign","label","event_ids","observation_seconds"}:raise ValueError("Exact scenario label/split/family/campaign/event_ids/observation_seconds required")
        sid=evidence_scope.text(scenario["id"],"scenario id",120)
        if sid in seen:raise ValueError("Duplicate scenario ID")
        seen.add(sid);split=evidence_scope.choice(scenario["split"],{"training","validation","test"},"split")
        label=evidence_scope.choice(scenario["label"],{"normal","attack"},"label")
        if split!="test" and label!="normal":raise ValueError("Frozen baseline training and validation must be curated normal")
        event_ids=research._ids(scenario["event_ids"],128)
        duration=scenario["observation_seconds"]
        if type(duration) not in (int,float) or not math.isfinite(duration) or not 1<=duration<=8*86400:raise ValueError("Bounded positive declared observation duration required")
        normalized.append({"id":sid,"split":split,"label":label,"family":evidence_scope.text(scenario["family"],"family",120),"campaign":evidence_scope.text(scenario["campaign"],"campaign",120),"event_ids":event_ids,"observation_seconds":duration})
        ids.extend(event_ids)
    if len(ids)>MAX_EVENTS or len(ids)!=len(set(ids)):raise ValueError("At most 16384 non-reused labelled originals required")
    if any(not any(s["split"]==split for s in normalized) for split in ("training","validation","test")):raise ValueError("All three independent splits required")
    with principal.transaction(store,who,research.EDITORS) as (_,actor):pass
    records=_load(store,actor,ids)
    for scenario in normalized:
        rows=[records[e] for e in scenario["event_ids"]]
        if None in {fusion.host_key(r) for r in rows} or len({fusion.host_key(r) for r in rows})!=1:raise ValueError("Each scenario requires one authenticated stable host identity")
        if max(r["event_time"] for r in rows)-min(r["event_time"] for r in rows)>scenario["observation_seconds"]:raise ValueError("Declared observation interval does not cover scenario originals")
        scenario["observed_host_key"]=fusion.host_key(rows[0]);scenario["observation_start"]=min(r["event_time"] for r in rows)
        scenario["observation_end"]=scenario["observation_start"]+scenario["observation_seconds"]
    quality=_quality(normalized,records);indexes=sorted({r["index_name"] for r in records.values()})
    body={"id":"RED-"+uuid.uuid4().hex,"schema":"xsera.research-evaluation-dataset.v1","name":name,"description":description,"origin":origin,"scenarios":normalized,"indexes":indexes,
        "originals":research._proofs(records),"quality":quality,"created":time.time(),"owner":actor["name"],"tenant":actor["tenant"],
        "field_provenance_externally_verified":False,"source_receipts_verified":True,"publishable":False,"labels_detached_from_detector":True}
    with principal.transaction(store,actor,research.EDITORS,write=True) as (db,fresh):
        if fresh!=actor:raise PermissionError("Dataset creator authority changed")
        evidence_scope.recheck(db,actor,records);research._verify_sources(db,actor,body["originals"],required=True)
        if db.execute("SELECT count(*) FROM research_evaluation_datasets d WHERE tenant=? AND NOT EXISTS(SELECT 1 FROM research_evaluation_dataset_archives a WHERE a.id=d.id)",(actor["tenant"],)).fetchone()[0]>=32:raise CapacityError("Evaluation dataset capacity 32 reached; archive independently reviewed unused datasets")
        db.execute("INSERT INTO research_evaluation_datasets VALUES(?,?,?,?,?,?,?)",(body["id"],actor["tenant"],actor["name"],body["created"],encode(indexes),encode(body),digest(body)))
        db.executemany("INSERT OR IGNORE INTO record_case_evidence_refs VALUES(?,?,?,?)",[(actor["tenant"],eid,"research_evaluation_dataset",body["id"]) for eid in ids])
    return {**body,"digest":digest(body)}


def dataset(store,who,identifier,*,with_records=False):
    from . import research_behavior as research
    with principal.transaction(store,who) as (db,actor):
        row=db.execute("SELECT * FROM research_evaluation_datasets WHERE tenant=? AND id=?",(actor["tenant"],identifier)).fetchone()
        if not row:raise KeyError("Evaluation dataset unavailable")
        if not principal.contains(actor["allowed_indexes"],json.loads(row["indexes"])):raise PermissionError("Full evaluation dataset scope required")
        body=json.loads(row["body"])
        if digest(body)!=row["digest"]:raise ConflictError("Evaluation manifest digest differs")
        archived=_archive_row(db,actor,"datasets",identifier)
        if with_records:require_retained(db,actor,"datasets",identifier)
    if not with_records:return {**body,"digest":row["digest"],"archived":bool(archived),"archive":archived}
    records=_load(store,actor,[p["event_id"] for p in body["originals"]])
    if research._proofs(records)!=body["originals"]:raise ConflictError("Evaluation raw original/source epoch changed")
    with principal.transaction(store,actor) as (db,_):research._verify_sources(db,actor,body["originals"],required=True)
    return {**body,"digest":row["digest"]},records


def wilson(success,total):
    if not total:return {"estimate":None,"lower":None,"upper":None,"denominator":0,"confidence":.95,"method":"Wilson"}
    z=1.959963984540054;p=success/total;den=1+z*z/total;center=(p+z*z/(2*total))/den;half=z*math.sqrt(p*(1-p)/total+z*z/(4*total*total))/den
    return {"estimate":p,"lower":0 if success==0 else max(0,center-half),"upper":1 if success==total else min(1,center+half),"denominator":total,"confidence":.95,"method":"Wilson","assumption":"Scenario trials treated as independent Bernoulli observations; a shared synthetic generator does not prove field independence"}


def _metrics(results,scenarios):
    counts=collections.Counter()
    for result in results:counts[(result["label"]=="attack",result["anomaly"])]+=1
    tp=counts[(True,True)];fp=counts[(False,True)];fn=counts[(True,False)];tn=counts[(False,False)]
    intervals=collections.defaultdict(list)
    for scenario in scenarios:
        if scenario["label"]=="normal":intervals[scenario["observed_host_key"]].append((scenario["observation_start"],scenario["observation_end"]))
    normal_seconds=0
    for values in intervals.values():
        start=end=None
        for left,right in sorted(values):
            if start is None:start,end=left,right
            elif left<=end:end=max(end,right)
            else:normal_seconds+=end-start;start,end=left,right
        if start is not None:normal_seconds+=end-start
    days=normal_seconds/86400
    # Wilson-Hilferty Poisson approximation is explicit; zero upper bound exact.
    low=0 if fp==0 else fp*max(0,1-1/(9*fp)-1.959963984540054/(3*math.sqrt(fp)))**3
    upper=-math.log(.025) if fp==0 else (fp+1)*(1-1/(9*(fp+1))+1.959963984540054/(3*math.sqrt(fp+1)))**3
    return {"tp":tp,"fp":fp,"fn":fn,"tn":tn,"precision":wilson(tp,tp+fp),"recall":wilson(tp,tp+fn),"false_positive_rate":wilson(fp,fp+tn),
        "false_positive_scenarios_per_declared_host_day":{"estimate":fp/days if days else None,"lower":low/days if days else None,"upper":upper/days if days else None,"normal_host_days":days,"confidence":.95,"method":"Poisson count interval, Wilson-Hilferty approximation for positive counts; exact zero upper bound","exposure":"Union of curator-declared intervals per authenticated host identity; completeness not independently attested"}}


def evaluate(store,who,data):
    from . import research_behavior as research
    if not isinstance(data,dict) or set(data)!={"dataset_id","model_id"}:raise ValueError("Evaluation requires exact dataset_id/model_id")
    evidence_scope.text(data["dataset_id"],"dataset_id");evidence_scope.text(data["model_id"],"model_id")
    with principal.transaction(store,who,research.EDITORS) as (db,actor):
        row,snapshot=research._verify_model(db,actor,data["model_id"])
        if not research._v2(snapshot):raise ValueError("Independent scenario evaluation requires explicit v2 model")
        model=dict(row)
    manifest,records=dataset(store,actor,data["dataset_id"],with_records=True)
    training={e for s in manifest["scenarios"] if s["split"]=="training" for e in s["event_ids"]};validation={e for s in manifest["scenarios"] if s["split"]=="validation" for e in s["event_ids"]}
    if training!=set(snapshot["training_ids"]) or validation!=set(snapshot["validation_ids"]):raise ConflictError("Evaluation split must match frozen model training/validation exactly")
    test=[s for s in manifest["scenarios"] if s["split"]=="test"];ids=[e for s in test for e in s["event_ids"]];features={eid:research._features(snapshot,records[eid]) for eid in ids};scores={};cpu_ms=0
    for offset in range(0,len(ids),32):
        batch=ids[offset:offset+32];answer=research._worker({"operation":"research_v2_infer","features":[features[e]["values"] for e in batch],"targets":[features[e]["target"] for e in batch],"ensemble":snapshot["ensemble"]},30)
        if answer.get("status")=="unavailable":return answer
        scores.update(zip(batch,answer["scores"]));cpu_ms+=answer["duration_ms"]
    results=[];engine=research._fusion_engine(snapshot);started=time.perf_counter()
    for scenario in test:
        history=[];values={};ordered=sorted((records[e] for e in scenario["event_ids"]),key=lambda r:(r["event_time"],r["event_id"]))
        for offset in range(0,len(ordered),16):
            batch=ordered[offset:offset+16];history=(history+batch)[-engine.MAX_ORIGINALS:]
            values.update(engine.evaluate(batch,scores,snapshot["fusion"],[r["event_id"] for r in batch],history_rows=history))
        results.append({"scenario_id":scenario["id"],"label":scenario["label"],"family":scenario["family"],"event_count":len(ordered),"anomaly":any(v["anomaly"] for v in values.values()),
            "maximum_score":max(v["score"] for v in values.values()),"threshold":snapshot["fusion"]["threshold"],"relation_only":any(scores[e]>snapshot["threshold"] for e in scenario["event_ids"]),
            "ablation":{k:any(v["ablations"]["without_"+k]["anomaly"] for v in values.values()) for k in engine.COMPONENTS},"reasons":sorted({r for v in values.values() if v["anomaly"] for r in v["reasons"]})})
    metrics=_metrics(results,test);metrics["ablation"]={k:_metrics([{**r,"anomaly":r["ablation"][k]} for r in results],test) for k in engine.COMPONENTS};metrics["relation_only"]=_metrics([{**r,"anomaly":r["relation_only"]} for r in results],test)
    body={"id":"RER-"+uuid.uuid4().hex,"schema":"xsera.research-evaluation-run.v1","tenant":actor["tenant"],"owner":actor["name"],"created":time.time(),"dataset_id":manifest["id"],"dataset_digest":manifest["digest"],"model_id":model["id"],"model_digest":model["digest"],"model_revision":model["revision"],"feature_contract_digest":snapshot["feature_contract_digest"],"fusion_contract_digest":snapshot["fusion"]["contract_digest"],"indexes":manifest["indexes"],"origin":manifest["origin"],"scenario_results":results,"metrics":metrics,"quality":manifest["quality"],"cpu_inference_ms":cpu_ms,"fusion_evaluation_ms":(time.perf_counter()-started)*1000,"ablation_method":"Disable named component without retraining or recalibrating; ablation keys name the omitted component","device":"cpu","publishable":False,"runtime_state_mutated":False,"threshold_tuned_on_test":False,"actual_field_performance_verified":False}
    with principal.transaction(store,actor,research.EDITORS,write=True) as (db,fresh):
        require_retained(db,actor,"datasets",manifest["id"])
        current,_=research._verify_model(db,actor,model["id"])
        if fresh!=actor or current["digest"]!=model["digest"]:raise ConflictError("Evaluation model/actor changed")
        evidence_scope.recheck(db,actor,records);research._verify_sources(db,actor,manifest["originals"],required=True)
        if db.execute("SELECT count(*) FROM research_evaluation_runs r WHERE tenant=? AND NOT EXISTS(SELECT 1 FROM research_evaluation_run_archives a WHERE a.id=r.id)",(actor["tenant"],)).fetchone()[0]>=128:raise CapacityError("Evaluation run capacity 128 reached; archive unused evaluation runs")
        db.execute("INSERT INTO research_evaluation_runs VALUES(?,?,?,?,?,?,?,?,?)",(body["id"],actor["tenant"],actor["name"],body["created"],encode(body["indexes"]),manifest["id"],model["id"],encode(body),digest(body)))
    return {**body,"digest":digest(body)}


def get_run(store,who,identifier):
    with principal.transaction(store,who) as (db,actor):
        row=db.execute("SELECT * FROM research_evaluation_runs WHERE tenant=? AND id=?",(actor["tenant"],identifier)).fetchone()
        if not row:raise KeyError("Evaluation run unavailable")
        if not principal.contains(actor["allowed_indexes"],json.loads(row["indexes"])):raise PermissionError("Evaluation scope denied")
        body=json.loads(row["body"])
        if digest(body)!=row["digest"]:raise ConflictError("Evaluation digest differs")
        archived=_archive_row(db,actor,"runs",identifier)
        return {**body,"digest":row["digest"],"archived":bool(archived),"archive":archived}


def listing(store,who,kind):
    table="research_evaluation_datasets" if kind=="datasets" else "research_evaluation_runs"
    with principal.transaction(store,who) as (db,actor):
        rows=db.execute("SELECT * FROM "+table+" WHERE tenant=? ORDER BY created DESC LIMIT 128",(actor["tenant"],)).fetchall()
        items=[]
        for row in rows:
            if not principal.contains(actor["allowed_indexes"],json.loads(row["indexes"])):continue
            body=json.loads(row["body"])
            item={"id":row["id"],"created":row["created"],"owner":row["owner"],"digest":row["digest"],"indexes":json.loads(row["indexes"]),"origin":body["origin"],"archived":bool(_archive_row(db,actor,kind,row["id"]))}
            if kind=="datasets":item.update(name=body["name"],scenario_count=len(body["scenarios"]))
            else:item.update(model_id=body["model_id"],dataset_id=body["dataset_id"])
            items.append(item)
        return {"items":items,"actual_field_performance_verified":False}


def archive(store,who,kind,identifier,data):
    """Independent explicit reference release; original hash history stays intact."""
    from . import research_behavior as research
    if kind not in {"datasets","runs"} or not isinstance(data,dict) or set(data)!={"reason"}:raise ValueError("Evaluation archive requires exact reason")
    reason=evidence_scope.text(data["reason"],"reason",2000)
    table="research_evaluation_datasets" if kind=="datasets" else "research_evaluation_runs"
    archive_table="research_evaluation_dataset_archives" if kind=="datasets" else "research_evaluation_run_archives"
    with principal.transaction(store,who,research.EDITORS,write=True) as (db,actor):
        row=db.execute("SELECT * FROM "+table+" WHERE tenant=? AND id=?",(actor["tenant"],identifier)).fetchone()
        if not row or not principal.contains(actor["allowed_indexes"],json.loads(row["indexes"])):raise KeyError("Complete evaluation archive scope required")
        prior=_archive_row(db,actor,kind,identifier)
        if prior:return prior
        body=json.loads(row["body"])
        if digest(body)!=row["digest"]:raise ConflictError("Evaluation evidence changed before archive")
        if row["owner"]==actor["name"]:raise PermissionError("Independent reviewer required to archive evaluation evidence")
        if db.execute("SELECT 1 FROM policies WHERE tenant=? AND hold=1",(actor["tenant"],)).fetchone():raise ConflictError("Legal hold protects evaluation evidence")
        key="dataset_id" if kind=="datasets" else "evaluation_id"
        if db.execute("SELECT 1 FROM research_rebaseline_candidates WHERE tenant=? AND state IN ('pending_review','approved','promoted') AND json_extract(body,?)=? LIMIT 1",(actor["tenant"],"$."+key,identifier)).fetchone():raise ConflictError("Live rebaseline candidate still requires evaluation evidence")
        released=0
        if kind=="datasets":
            ids=[p["event_id"] for p in body["originals"]];encoded=encode(ids)
            if db.execute("SELECT 1 FROM record_case_evidence_refs e JOIN research_behavior_models m ON m.id=e.record_id AND m.tenant=e.tenant WHERE e.tenant=? AND e.kind='research_behavior_model' AND m.state IN ('active','pending') AND e.event_id IN (SELECT value FROM json_each(?)) LIMIT 1",(actor["tenant"],encoded)).fetchone():raise ConflictError("Active or pending model still requires dataset originals")
            if db.execute("SELECT 1 FROM record_case_evidence_refs WHERE tenant=? AND kind IN ('bookmark','contribution') AND event_id IN (SELECT value FROM json_each(?)) LIMIT 1",(actor["tenant"],encoded)).fetchone():raise ConflictError("Case or bookmark still requires dataset originals")
            released=db.execute("DELETE FROM record_case_evidence_refs WHERE tenant=? AND kind='research_evaluation_dataset' AND record_id=?",(actor["tenant"],identifier)).rowcount
        summary={"id":identifier,"kind":kind,"tenant":actor["tenant"],"actor":actor["name"],"at":time.time(),"reason":reason,"state":"archived","original_digest":row["digest"],"indexes":json.loads(row["indexes"]),"origin":body["origin"],"raw_references_released":released,"original_hash_proofs_and_history_retained":True,"originals_physically_deleted":False,"other_model_case_references_modified":False}
        if kind=="datasets":summary.update(scenario_count=len(body["scenarios"]),original_count=len(body["originals"]),original_metadata_digest=digest(body["originals"]))
        else:summary.update(model_id=body["model_id"],dataset_id=body["dataset_id"],metrics_digest=digest(body["metrics"]))
        db.execute("INSERT INTO "+archive_table+" VALUES(?,?,?,?,?,?,?)",(identifier,actor["tenant"],actor["name"],summary["at"],row["digest"],encode(summary),digest(summary)))
        store.audit(db,actor["tenant"],actor["name"],"research.evaluation.archive",summary)
        return summary
