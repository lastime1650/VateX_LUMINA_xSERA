"""Frozen pure signal, Story graph, composite and optional CPU model comparison.

Only immutable comparison/replay rows are appended. This module never calls
the operational signal publisher, Story writer, Case adapter or ML run writer.
"""

import copy
import itertools
import json
import math
import platform
import time
import uuid
from collections import defaultdict
from pathlib import Path

from . import entities, evidence_scope, identity_resolver, intelligence, migrations, principal, release_manifest, security_schema, shadow_analysis
from .query import index_predicate
from .storage import CapacityError, ConflictError, encode

SCHEMA = "xsera.intelligence-shadow.v1"
MAX_EVENTS = 5000
MAX_POLICIES = 32
MAX_SIGNALS = 10000
MAX_BYTES = 16 * 1024 * 1024
MAX_COMBINATIONS = 100000


def initialize(store):
    migrations.apply_store(store, "intelligence_shadow", [
        "CREATE TABLE IF NOT EXISTS intelligence_shadow_runs(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,indexes TEXT NOT NULL,created REAL NOT NULL,snapshot_digest TEXT NOT NULL,result_digest TEXT NOT NULL,snapshot TEXT NOT NULL,result TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS intelligence_shadow_scope ON intelligence_shadow_runs(tenant,id)",
        "CREATE TABLE IF NOT EXISTS intelligence_shadow_replays(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,run_id TEXT NOT NULL,created REAL NOT NULL,snapshot_digest TEXT NOT NULL,result_digest TEXT NOT NULL,identical INTEGER NOT NULL)",
    ])


def _engine():
    from . import cpu_ml,cpu_sequence,cpu_sequence_features,cpu_ml_runtime,cpu_model_memo,storage,ml_datasets,native_predicates
    worker_directory=Path(cpu_ml.__file__).parent
    return {**shadow_analysis._engine(), "intelligence": release_manifest.hash_file(intelligence.__file__),
            'native_conditions':release_manifest.hash_file(native_predicates.__file__),
            "intelligence_shadow": release_manifest.hash_file(__file__), "cpu_features": release_manifest.hash_file(cpu_ml.__file__),
            "cpu_worker": release_manifest.hash_file(worker_directory/"cpu_ml_worker.py"),
            "sequence_worker":release_manifest.hash_file(worker_directory/"cpu_sequence_worker.py"),
            "cpu_limits":release_manifest.hash_file(worker_directory/"cpu_ml_limits.py"),
            "sequence_model":release_manifest.hash_file(cpu_sequence.__file__),
            "sequence_features":release_manifest.hash_file(cpu_sequence_features.__file__),
            "cpu_runtime":release_manifest.hash_file(cpu_ml_runtime.__file__),
            "cpu_model_memo":release_manifest.hash_file(cpu_model_memo.__file__),
            "ml_dataset_authority":release_manifest.hash_file(ml_datasets.__file__),
            "canonical_storage":release_manifest.hash_file(storage.__file__),
            "manifest":release_manifest.hash_file(release_manifest.__file__),
            "python_version":platform.python_version(),"python_implementation":platform.python_implementation()}


def _context(db,actor,indexes):
    result=shadow_analysis._context(db,actor,indexes)
    if db.execute("SELECT 1 FROM sqlite_master WHERE name='cpu_sequence_models'").fetchone():
        result["sequence_models"]=[{"id":row["id"],"revision":row["revision"],"digest":row["digest"],"definition_digest":release_manifest.digest(json.loads(row["definition"])),"active":bool(db.execute("SELECT 1 FROM cpu_sequence_active WHERE tenant=? AND model_id=?",(actor["tenant"],row["id"])).fetchone()),"reviews":[dict(r) for r in db.execute("SELECT id,reviewer,at FROM cpu_sequence_reviews WHERE tenant=? AND model_id=? ORDER BY id",(actor["tenant"],row["id"]))]} for row in db.execute("SELECT * FROM cpu_sequence_models WHERE tenant=? ORDER BY id",(actor["tenant"],)) if principal.contains(indexes,json.loads(row["indexes"]))]
    return result


def _policies(db, actor, indexes, supplied, ids=None):
    policies = []
    if supplied is not None:
        if not isinstance(supplied, list) or len(supplied) > MAX_POLICIES:
            raise ValueError("At most 32 frozen intelligence policies per side required")
        for item in supplied:
            if not isinstance(item, dict) or set(item)-{"id", "definition", "revision"} or not {"id", "definition"} <= set(item):
                raise ValueError("Shadow intelligence policies require id/definition and optional revision")
            identifier = evidence_scope.text(item["id"], "policy id", 256)
            definition = intelligence._definition(item["definition"])
            revision = evidence_scope.integer(item.get("revision", 1), "revision", 1, 2147483647)
            if not principal.contains(indexes, definition["indexes"]):
                raise PermissionError("Shadow policy indexes must be inside the complete frozen scope")
            policies.append({"id": identifier, "owner": actor["name"], "revision": revision, "definition": definition})
    else:
        if ids is not None and (not isinstance(ids, list) or len(ids)>MAX_POLICIES or any(not isinstance(i,str) for i in ids) or len(set(ids)) != len(ids)):
            raise ValueError("At most 32 exact unique intelligence policy IDs required")
        rows = db.execute("SELECT * FROM intelligence_policies WHERE tenant=? ORDER BY id", (actor["tenant"],)).fetchall()
        rows = [r for r in rows if r["id"] in ids] if ids is not None else [r for r in rows if r["state"]=="active" and principal.contains(indexes,json.loads(r["indexes"]))]
        if ids is not None and len(rows)!=len(ids):
            raise KeyError("Frozen intelligence policy not found")
        if len(rows)>MAX_POLICIES:
            raise CapacityError("Select at most 32 intelligence policies")
        for row in rows:
            definition = json.loads(row["definition"])
            if not principal.contains(indexes, definition["indexes"]):
                raise PermissionError("Policy is outside the complete frozen scope")
            shadow_analysis._owner(db, actor["tenant"], row["owner"], definition["indexes"])
            policies.append({"id": row["id"], "owner": row["owner"], "revision": row["version"], "definition": definition,"approver":row["approver"]})
    if len({p["id"] for p in policies}) != len(policies):
        raise ValueError("Policy IDs must be unique per comparison side")
    definitions = {p["id"]: p for p in policies}
    ordered, visited = [], set()
    def visit(identifier, path):
        if identifier in path:
            raise ValueError("Frozen composite cycle is forbidden")
        if len(path)>=8:
            raise ValueError("Frozen composite depth exceeds eight")
        if identifier in visited:
            return
        for selector in definitions[identifier]["definition"].get("inputs", []):
            parent=selector.get("rule_id")
            if parent in definitions:
                visit(parent, path | {identifier})
        visited.add(identifier); ordered.append(definitions[identifier])
    for identifier in sorted(definitions):
        visit(identifier,set())
    heights={}
    for rule in ordered:
        parents=[s["rule_id"] for s in rule["definition"].get("inputs",[]) if s.get("rule_id") in definitions]
        heights[rule["id"]]=1+max((heights[p] for p in parents),default=0)
        if heights[rule["id"]]>8:
            raise ValueError("Frozen composite depth exceeds eight")
        if rule["definition"]["kind"]!="composite":
            continue
        expected_pins,expected_models={},{}
        for selector in rule["definition"]["inputs"]:
            parent_id=selector.get("rule_id")
            if parent_id and parent_id.startswith("ml:"):
                model_pin=intelligence._input_model_pin(None,db,actor,parent_id,require_review=supplied is None)
                if not principal.contains(rule["definition"]["indexes"],model_pin["indexes"]):
                    raise PermissionError("Frozen composite requires its input model's complete index scope")
                expected_models[parent_id]=model_pin
            if parent_id in definitions:
                parent=definitions[parent_id]
                expected_pins[parent_id]={"version":parent["revision"],"definition_digest":release_manifest.digest(parent["definition"])}
            elif parent_id:
                parent=db.execute("SELECT * FROM intelligence_policies WHERE tenant=? AND id=?",(actor["tenant"],parent_id)).fetchone()
                if parent:
                    if not principal.contains(indexes,json.loads(parent["indexes"])):
                        raise PermissionError("Frozen parent policy is outside the complete index scope")
                    shadow_analysis._owner(db,actor["tenant"],parent["owner"],json.loads(parent["indexes"]))
                    expected_pins[parent_id]={"version":parent["version"],"definition_digest":release_manifest.digest(json.loads(parent["definition"]))}
        if supplied is not None:
            # Only the validated parent snapshots define pins. The public root
            # validator rejects caller-supplied internal input_revisions.
            rule["definition"]["input_revisions"]=expected_pins
            if expected_models:
                rule["definition"]["input_models"]=expected_models
        else:
            if rule["definition"].get("input_revisions",{})!=expected_pins:
                raise ConflictError("Frozen composite parent revision or definition changed")
            if rule["definition"].get("input_models",{})!=expected_models:
                raise ConflictError("Frozen composite model revision or feature contract changed")
            intelligence._parents_current(db,actor["tenant"],rule["definition"],actor)
    return ordered


def _model(db, actor, indexes, identifier):
    if identifier is None:
        return None
    from . import cpu_ml
    evidence_scope.text(identifier, "model id", 256)
    row, definition, snapshot = cpu_ml._load(db, actor, identifier, False)
    if not principal.contains(indexes, json.loads(row["indexes"])):
        raise PermissionError("Frozen CPU model requires its complete declared index scope")
    return {"id": identifier, "owner": row["owner"], "indexes": json.loads(row["indexes"]), "revision": row["revision"],
            "model_digest": row["digest"], "feature_schema": snapshot["feature_schema"],
            "weights": snapshot["weights"], "weights_digest": release_manifest.digest(snapshot["weights"]),
            "threshold": snapshot["threshold"], "framework_version": definition["framework_version"],
            "definition_digest": release_manifest.digest(definition),"feature_contract_digest":definition["feature_contract_digest"]}


def _sequence_model(db,actor,indexes,identifier):
    if identifier is None:
        return None
    from . import cpu_sequence
    evidence_scope.text(identifier,"sequence model id",256)
    row,definition,snapshot=cpu_sequence._load(db,actor,identifier,require_review=False)
    if not principal.contains(indexes,json.loads(row["indexes"])):
        raise PermissionError("Frozen sequence model requires its complete declared index scope")
    review=db.execute("SELECT r.reviewer FROM cpu_sequence_active a JOIN cpu_sequence_reviews r ON r.id=a.review_id WHERE a.tenant=? AND a.model_id=?",(actor["tenant"],identifier)).fetchone()
    return {"id":identifier,"owner":row["owner"],"indexes":json.loads(row["indexes"]),"revision":row["revision"],"model_digest":row["digest"],"feature_schema":snapshot["feature_schema"],"weights_digest":release_manifest.digest(snapshot["weights"]),"threshold":snapshot["threshold"],"framework_version":definition["framework_version"],"feature_contract_digest":definition["feature_contract_digest"],"definition_digest":release_manifest.digest(definition),"definition":definition,"snapshot":snapshot,"reviewer":review[0] if review else None}


def _freeze(store, who, data):
    fields={"start","end","indexes","policy_ids","baseline_policies","candidate_policies","baseline_model_id","candidate_model_id","baseline_sequence_model_id","candidate_sequence_model_id","sequence_windows","max_events","expected_context_digest"}
    if not isinstance(data,dict) or set(data)-fields or not {"start","end","indexes"}<=set(data):
        raise ValueError("Frozen intelligence window/index fields required")
    start,end=entities.window(data["start"],data["end"])
    if end-start>7*86400:
        raise ValueError("Frozen intelligence windows are bounded to seven days")
    indexes=entities.exact_indexes(data["indexes"])
    maximum=evidence_scope.integer(data.get("max_events",MAX_EVENTS),"max_events",1,MAX_EVENTS)
    with principal.transaction(store,who,("admin","analyst")) as (db,actor):
        if not principal.contains(actor["allowed_indexes"],indexes):
            raise PermissionError("Frozen intelligence scope exceeds current grants")
        baseline=_policies(db,actor,indexes,data.get("baseline_policies"),data.get("policy_ids"))
        candidate=_policies(db,actor,indexes,data["candidate_policies"]) if "candidate_policies" in data else copy.deepcopy(baseline)
        models={"baseline":_model(db,actor,indexes,data.get("baseline_model_id")),"candidate":_model(db,actor,indexes,data.get("candidate_model_id"))}
        sequence_models={"baseline":_sequence_model(db,actor,indexes,data.get("baseline_sequence_model_id")),"candidate":_sequence_model(db,actor,indexes,data.get("candidate_sequence_model_id"))}
        if not baseline and not candidate and not any(models.values()) and not any(sequence_models.values()):
            raise ValueError("At least one frozen policy or model is required")
        context=_context(db,actor,indexes)
    context_digest=release_manifest.digest(context)
    if data.get("expected_context_digest",context_digest)!=context_digest:
        raise ConflictError("Frozen intelligence context changed")
    predicate,args=index_predicate(indexes)
    records=store.analytics_query("SELECT event_id,event_time,received,source,sourcetype,host,severity,message,raw,index_name FROM events_all WHERE tenant=? AND "+predicate+" AND event_time>=? AND event_time<? ORDER BY event_time,event_id LIMIT ?",[actor["tenant"],*args,start,end,maximum+1],max_rows=maximum+1)["rows"]
    if len(records)>maximum:
        raise CapacityError("Frozen intelligence cohort exceeds its bound; no partial success")
    if (any(models.values()) or any(sequence_models.values())) and len(records)>1000:
        raise CapacityError("Frozen model cohort exceeds 1000; narrow this model comparison window")
    snapshot={"schema":SCHEMA,"tenant":actor["tenant"],"owner":actor["name"],"indexes":indexes,"start":start,"end":end,
              "context":context,"context_digest":context_digest,"engine":_engine(),"baseline":baseline,"candidate":candidate,
              "models":models,"sequence_models":sequence_models,"sequence_windows":data.get("sequence_windows"),"events":[],"receipts":{},"projections":{},"sources":{},"projection_seq":{},"events_digest":{}}
    with principal.transaction(store,actor,("admin","analyst")) as (db,fresh):
        if actor!=fresh:
            raise PermissionError("Authority changed during frozen intelligence intake")
        for record in records:
            eid=record["event_id"]
            proof=db.execute("SELECT digest,received FROM receipts WHERE tenant=? AND event_id=?",(actor["tenant"],eid)).fetchone()
            if not proof or proof["received"]!=record["received"]:
                raise ConflictError("Frozen original admission is unavailable")
            event={**record,"raw":json.loads(record["raw"]) if isinstance(record["raw"],str) else record["raw"]}
            snapshot["events"].append(event); snapshot["receipts"][eid]=dict(proof)
            snapshot["events_digest"][eid]=release_manifest.digest(event)
            row=db.execute("SELECT seq,projection,receipt_digest FROM event_projections WHERE tenant=? AND event_id=? ORDER BY seq DESC LIMIT 1",(actor["tenant"],eid)).fetchone()
            if row:
                if row["receipt_digest"]!=proof["digest"]:
                    raise ConflictError("Projection does not match frozen original admission")
                source=db.execute("SELECT source_definition,receipt_digest FROM source_event_receipts WHERE tenant=? AND event_id=?",(actor["tenant"],eid)).fetchone()
                if not source or source["receipt_digest"]!=proof["digest"] or not source["source_definition"]:
                    raise ConflictError("Frozen projection source version is unavailable")
                projected=json.loads(row["projection"])
                authority=json.loads(source["source_definition"])
                if release_manifest.digest({k:v for k,v in projected.items() if k!="projection_digest"})!=projected.get("projection_digest") or projected.get("source_id")!=authority.get("id") or projected.get("source_version")!=authority.get("version"):
                    raise ConflictError("Frozen projection content or authority integrity failed")
                snapshot["projections"][eid]=projected; snapshot["projection_seq"][eid]=row["seq"]
                snapshot["sources"][eid]=authority
    for model in sequence_models.values():
        if model:
            _sequence_windows(snapshot,model)
    if len(encode(snapshot).encode())>MAX_BYTES:
        raise CapacityError("Frozen intelligence snapshot exceeds 16 MiB")
    return actor,snapshot


def _graph(snapshot, candidate, until):
    nodes,edges,identities,processes={}, {}, {}, {}
    by_guid=defaultdict(set)
    def node(identifier,kind,event_id,**attributes):
        if identifier not in nodes:
            nodes[identifier]={"id":identifier,"kind":kind,"event_ids":[],**attributes}
        nodes[identifier]["event_ids"]=sorted(set(nodes[identifier]["event_ids"])|{event_id})
    def edge(a,b,relation,event_ids):
        identifier=release_manifest.digest([a,b,relation,sorted(event_ids)])
        edges[identifier]={"id":identifier,"from":a,"to":b,"relation":relation,"event_ids":sorted(event_ids),"causality_proven":False}
    ordered=sorted(snapshot["events"],key=lambda e:(snapshot["projection_seq"].get(e["event_id"],2**63),e["received"],e["event_time"],e["event_id"]))
    for event in ordered:
        if time.monotonic()>until:
            raise CapacityError("Frozen graph deadline exceeded; no partial success")
        eid=event["event_id"]
        projection=security_schema.project({**event,"index":event["index_name"]},snapshot["sources"][eid]) if candidate and eid in snapshot["sources"] else snapshot["projections"].get(eid)
        process_key=identity_resolver.relation_key(None,None,projection,"process") if projection else None
        root=process_key or release_manifest.digest([snapshot["tenant"],"event",eid])
        parent=None
        scope=(projection.get("realm"),projection.get("source_id"),projection.get("account")) if projection else ()
        parent_guid=(projection or {}).get("process",{}).get("parent_guid")
        if process_key and parent_guid:
            candidates=[processes[k] for k in by_guid[(*scope,parent_guid)] if identity_resolver.parent_link(processes[k]["projection"],projection)]
            if len(candidates)==1:
                parent=candidates[0]; root=parent["root"]
        story="STORY-"+release_manifest.digest([snapshot["tenant"],root])
        event_node="EVENT-"+release_manifest.digest([snapshot["tenant"],eid])
        node(event_node,"event",eid,story_id=story,observed_not_created=(projection or {}).get("event_semantics",{}).get("kind")=="observation")
        if process_key:
            pn="PROCESS-"+release_manifest.digest([snapshot["tenant"],process_key])
            node(pn,"process",eid,story_id=story,identity_key=process_key)
            edge(pn,event_node,"performed_observation",[eid])
            if parent:
                edge(parent["node"],pn,"reported_parent",[eid,*parent["events"]][:32])
            if process_key not in processes:
                processes[process_key]={"projection":projection,"root":root,"node":pn,"events":[]}
                by_guid[(*scope,projection["process"]["guid"])].add(process_key)
            processes[process_key]["events"].append(eid)
        keys={}
        if projection:
            keys={name:identity_resolver.relation_key(None,None,projection,mode) for name,mode in (("process","process"),("flow","flow"),("session","auth_session"))}
            if keys["flow"]:
                fn="FLOW-"+release_manifest.digest([snapshot["tenant"],keys["flow"],story])
                node(fn,"flow",eid,story_id=story,identity_key=keys["flow"],ownership_proven=False)
                edge(event_node,fn,"reported_flow",[eid])
            file=projection.get("file",{})
            if file.get("path"):
                fk=identity_resolver.relation_key(None,None,projection,"file_object")
                fn="FILE-"+release_manifest.digest([snapshot["tenant"],fk or eid])
                node(fn,"file",eid,story_id=story,identity_key=fk,object_version_known=bool(fk))
                edge(event_node,fn,"reported_file_activity",[eid])
        identities[eid]={"record":event,"projection":projection,"story_id":story,"entity_key":process_key or keys.get("flow") or release_manifest.digest([snapshot["tenant"],"event",eid]),"association_keys":keys}
    return {"nodes":sorted(nodes.values(),key=lambda x:x["id"]),"edges":sorted(edges.values(),key=lambda x:x["id"]),
            "causality_proven":False,"automatic_endpoint_authorization":False},identities


def _signal(snapshot,rule,kind,ids,identities,parents=(),features=None,model=None):
    ids=sorted(set(ids))
    if len(ids)>32:
        raise CapacityError("Frozen signal original ancestry exceeds 32; no partial success")
    records={eid:identities[eid]["record"] for eid in ids}
    first=min(ids,key=lambda eid:(records[eid]["event_time"],eid))
    identity=identities[first]
    definition=rule["definition"]
    times=[records[eid]["event_time"] for eid in ids]
    context=release_manifest.digest([snapshot["context_digest"],[(eid,snapshot["sources"].get(eid)) for eid in ids],model and model["model_digest"]])
    parent_ids=sorted(p["id"] for p in parents)
    identifier="SIG-"+release_manifest.digest([snapshot["tenant"],"shadow",kind,rule["id"],rule["revision"],ids,parent_ids,context])
    return {"id":identifier,"kind":kind,"rule_id":rule["id"],"rule_revision":rule["revision"],"definition_digest":release_manifest.digest(definition),
            "event_ids":ids,"parent_signal_ids":parent_ids,"indexes":sorted({records[eid]["index_name"] for eid in ids}),
            "entity_key":identity["entity_key"],"story_id":identity["story_id"],"association_keys":identity["association_keys"],
            "event_window":{"start":min(times),"end":max(times)},"context_digest":context,
            "severity":definition["severity"],"confidence_grade":definition["confidence_grade"],"features":features or {},
            "model_digest":model and model["model_digest"],"evidence_dependency":intelligence._dependencies([p["event_ids"] for p in parents] or [ids]),
            "originals":[{"event_id":eid,"admission_digest":snapshot["receipts"][eid]["digest"],"record_digest":snapshot["events_digest"][eid]} for eid in ids],
            "malicious_probability":None,"automatic_endpoint_authorization":False,"mode":"shadow"}


def _ml(snapshot,model,identities,pinned_job=None):
    if not model:
        return [],{"status":"not_requested","executed":False}
    from . import cpu_ml
    events=[e for e in snapshot["events"] if e["index_name"] in model["indexes"]]
    features=[cpu_ml.extract_features(e) for e in events]
    artifact={"model_id":model["id"],"revision":model["revision"],"model_digest":model["model_digest"],"weights_digest":model["weights_digest"],
              "feature_schema":model["feature_schema"],"feature_digest":release_manifest.digest(features),"event_count":len(events),"device":"cpu"}
    if pinned_job and pinned_job.get("status")=="excluded":
        return [],copy.deepcopy(pinned_job)
    if model.get("feature_contract_digest")!=cpu_ml.FEATURE_CONTRACT_DIGEST:
        if pinned_job and pinned_job.get("status")=="completed":
            raise ConflictError("Pinned CPU feature contract changed; no partial replay")
        return [],{**artifact,"status":"excluded","executed":False,"compatibility":"시스템에서 호환되지 않음","reason":"Frozen CPU feature contract differs from the evaluator"}
    if not events:
        return [],{**artifact,"status":"empty_cohort","executed":False}
    status=cpu_ml.runtime_status(force=True)
    if not status.get("available") or status.get("version")!=model["framework_version"]:
        if pinned_job and pinned_job.get("status")=="completed":
            raise ConflictError("Pinned CPU framework runtime changed; full replay cannot be reproduced")
        return [],{**artifact,"status":"excluded","executed":False,"compatibility":"시스템에서 호환되지 않음","reason":"CPU framework unavailable or differs from frozen model framework"}
    try:
        output=cpu_ml._worker({"operation":"infer","weights":model["weights"],"features":[list(f.values()) for f in features]},timeout=15)
    except CapacityError:
        if pinned_job and pinned_job.get("status")=="completed":
            raise ConflictError("Pinned CPU model exceeded its replay deadline; no partial success") from None
        return [],{**artifact,"status":"excluded","executed":False,"compatibility":"시스템에서 호환되지 않음","reason":"Pinned CPU inference exceeded its execution deadline"}
    if output.get("worker_error"):
        if pinned_job and pinned_job.get("status")=="completed":
            raise ConflictError("Pinned CPU model failed during replay; no partial success")
        return [],{**artifact,"status":"excluded","executed":False,"compatibility":"시스템에서 호환되지 않음","reason":"Pinned CPU inference worker failed"}
    if len(output.get("scores",[]))!=len(events) or len(output.get("feature_errors",[]))!=len(events):
        raise ConflictError("Frozen CPU worker returned an incomplete feature cohort")
    rule={"id":"ml:"+model["id"],"revision":model["revision"],"definition":{"severity":"medium","confidence_grade":"model_distribution_deviation","model_digest":model["model_digest"]}}
    predictions,signals=[],[]
    for event,feature,score,errors in zip(events,features,output["scores"],output["feature_errors"]):
        if type(score) not in (int,float) or not math.isfinite(score) or not isinstance(errors,list) or len(errors)!=7 or any(type(v) not in (int,float) or not math.isfinite(v) for v in errors):
            raise ConflictError("Frozen CPU worker returned invalid numeric results")
        prediction={"event_id":event["event_id"],"score":score,"threshold":model["threshold"],"anomaly":score>model["threshold"],"feature_errors":errors}
        predictions.append(prediction)
        if prediction["anomaly"]:
            signals.append(_signal(snapshot,rule,"ml",[event["event_id"]],identities,features={**feature,"score":score,"threshold":model["threshold"]},model=model))
    return signals,{**artifact,"status":"completed","executed":True,"framework_version":status["version"],"predictions":predictions,"result_digest":release_manifest.digest(predictions)}


def _sequence_windows(snapshot,model):
    """Derive typed windows from frozen originals, never caller feature tensors."""
    from . import cpu_sequence,cpu_sequence_features
    records={event["event_id"]:event for event in snapshot["events"]}
    contexts={context["id"]:context for context in model["definition"]["sources"]}
    keys={}
    for eid,event in records.items():
        if event["index_name"] not in model["indexes"]:
            continue
        authority=snapshot["sources"].get(eid)
        context=contexts.get((authority or {}).get("id"))
        if not context:
            continue
        if any(authority.get(name)!=context[name] for name in ("id","version","account","realm","product")) or context["index_name"]!=event["index_name"]:
            raise ConflictError("Frozen sequence original source context differs from its model")
        data=cpu_sequence_features.get(event["raw"],"xdr.data") or {}
        host,user,container=data.get("host",{}),data.get("user",{}),data.get("container",{})
        if not isinstance(host,dict) or not isinstance(user,dict) or not isinstance(container,dict) or not all(isinstance(host.get(name),str) and host[name] for name in ("id","boot_id")):
            continue
        if any(not identity_resolver.identity_text(host[name]) for name in ("id","boot_id")):
            continue
        for name in ("id","boot_id"):
            evidence_scope.text(host[name],"frozen reported host incarnation")
        session=user.get("session_id")
        if session is None:
            session=cpu_sequence_features.get(data,"authentication.session_id")
        optional=(user.get("id"),session,container.get("id"),container.get("namespace"))
        for value in optional:
            if value is not None and not identity_resolver.identity_text(value):
                raise ValueError("Frozen sequence user/session identity must be reported text")
            if value is not None:
                evidence_scope.text(value,"frozen reported sequence identity")
        keys[eid]=(event["index_name"],context["id"],context["version"],context["account"],context["realm"],host["id"],host["boot_id"],*optional,event["host"])
    supplied=snapshot.get("sequence_windows")
    if supplied is not None:
        if not isinstance(supplied,list) or not 1<=len(supplied)<=32:
            raise ValueError("Frozen comparison requires 1..32 exact sequence windows")
        windows=[]
        for item in supplied:
            if not isinstance(item,dict) or set(item)!={"event_ids"} or not isinstance(item["event_ids"],list) or not 2<=len(item["event_ids"])<=32:
                raise ValueError("Frozen sequence windows accept only 2..32 original IDs")
            ids=item["event_ids"]
            if any(not isinstance(eid,str) or eid not in keys for eid in ids) or len(set(ids))!=len(ids) or len({keys[eid] for eid in ids})!=1:
                raise ValueError("Frozen sequence cannot join unavailable sources, indexes, hosts, boots or sessions")
            windows.append(ids)
    else:
        groups=defaultdict(list)
        for event in sorted(snapshot["events"],key=lambda e:(snapshot["projection_seq"].get(e["event_id"],2**63),e["received"],e["event_time"],e["event_id"])):
            if event["event_id"] in keys:
                groups[keys[event["event_id"]]].append(event["event_id"])
        windows=[]
        for key in sorted(groups,key=encode):
            ids=groups[key]
            windows.extend(ids[pos:pos+12] for pos in range(0,len(ids),12) if len(ids[pos:pos+12])>=3)
        if len(windows)>32:
            raise CapacityError("Frozen sequence comparison exceeds 32 windows; specify a narrower original cohort")
    result=[]
    for ids in windows:
        vector=cpu_sequence.frozen_features([records[eid] for eid in ids])
        key=keys[ids[0]]
        entity=release_manifest.digest([snapshot["tenant"],key[0],key[1],key[3],key[4],key[5],key[6],*key[7:11]])
        result.append({"event_ids":ids,"features":vector,"feature_digest":release_manifest.digest(vector),"source_entity_key":entity,"source_id":key[1],"source_version":key[2],"indexes":[key[0]],"source_identity_digest":release_manifest.digest(key)})
    return result


def _sequence_ml(snapshot,model,identities,pinned_job=None):
    if not model:
        return [],{"status":"not_requested","executed":False}
    from . import cpu_ml,cpu_sequence
    if pinned_job and pinned_job.get("status")=="excluded":
        return [],copy.deepcopy(pinned_job)
    windows=_sequence_windows(snapshot,model)
    evaluated={eid for window in windows for eid in window["event_ids"]}
    artifact={"model_family":"sequence","model_id":model["id"],"revision":model["revision"],"model_digest":model["model_digest"],"weights_digest":model["weights_digest"],"feature_contract_digest":model["feature_contract_digest"],"feature_digest":release_manifest.digest([w["features"] for w in windows]),"windows":len(windows),"originals":sum(len(w["event_ids"]) for w in windows),"device":"cpu","coverage":{"frozen_originals":len(snapshot["events"]),"evaluated_originals":len(evaluated),"unselected_or_unusable_original_ids":sorted(event["event_id"] for event in snapshot["events"] if event["event_id"] not in evaluated),"window_basis":"explicit original IDs or indexed-order source/device/boot/session chunks of 12; final partial requires 3"}}
    def excluded(reason):
        if pinned_job and pinned_job.get("status")=="completed":
            raise ConflictError("Pinned sequence model cannot fully replay: "+reason)
        return [],{**artifact,"status":"excluded","executed":False,"compatibility":"시스템에서 호환되지 않음","reason":reason}
    if model["feature_contract_digest"]!=cpu_sequence.FEATURE_CONTRACT_DIGEST:
        return excluded("Frozen sequence feature contract differs from evaluator")
    if not windows:
        return [],{**artifact,"status":"empty_cohort","executed":False}
    runtime=cpu_ml.runtime_status(force=True)
    if not runtime.get("available") or runtime.get("version")!=model["framework_version"]:
        return excluded("CPU framework unavailable or differs from frozen sequence framework")
    try:
        output=cpu_sequence.frozen_infer(model["definition"],model["snapshot"],model["model_digest"],[w["features"] for w in windows])
    except CapacityError:
        return excluded("Frozen sequence CPU worker unavailable or exceeded deadline")
    if len(output.get("scores",[]))!=len(windows):
        raise ConflictError("Frozen sequence worker returned incomplete windows")
    rule={"id":"ml:sequence:"+model["id"],"revision":model["revision"],"definition":{"severity":"high","confidence_grade":"reviewed_sequence_model_hypothesis"}}
    predictions,signals=[],[]
    for window,score in zip(windows,output["scores"]):
        if type(score) not in (int,float) or not math.isfinite(score) or not 0<=score<=1:
            raise ConflictError("Frozen sequence worker score is invalid")
        prediction={**{key:window[key] for key in ("event_ids","source_entity_key","source_id","source_version","indexes","feature_digest","source_identity_digest")},"score":score,"threshold":model["threshold"],"anomaly":score>=model["threshold"]}
        predictions.append(prediction)
        if prediction["anomaly"]:
            signal=_signal(snapshot,rule,"ml",window["event_ids"],identities,features={"model_family":"sequence","sequence_score":score,"threshold":model["threshold"],"sequence_length":len(window["event_ids"]),"probability_calibrated":False},model=model)
            flow=next((identities[eid]["association_keys"].get("flow") for eid in reversed(window["event_ids"]) if identities[eid]["association_keys"].get("flow")),None)
            signal["entity_key"]=flow or window["source_entity_key"]
            signal["metadata"]={"model_family":"sequence","source_entity_key":window["source_entity_key"],"partial_window":len(window["event_ids"])<12,"native_capture_proven":False}
            signals.append(signal)
    return signals,{**artifact,"status":"completed","executed":True,"predictions":predictions,"output_digest":release_manifest.digest(predictions),"tensor_shape":output["input_tensor_shape"],"padding_masked":True}


def _strict_order(chain,identities):
    for previous,following in zip(chain,chain[1:]):
        before,after=[],[]
        for signal,target,direction in ((previous,before,1),(following,after,-1)):
            for eid in signal["event_ids"]:
                projection=identities[eid]["projection"] or {}
                precision=projection.get("clock_precision")
                if type(precision) not in (int,float) or not math.isfinite(precision) or precision<0:
                    return False
                target.append(identities[eid]["record"]["event_time"]+direction*precision)
        if max(before)>=min(after):
            return False
    return True


def _side(snapshot,policies,candidate,pinned_job=None,pinned_sequence_job=None):
    until=time.monotonic()+20
    graph,identities=_graph(snapshot,candidate,until)
    signals,diagnostics={},[]
    def add(signal):
        signals[signal["id"]]=signal
        if len(signals)>MAX_SIGNALS:
            raise CapacityError("Frozen intelligence signal budget exceeded; no partial success")
    for event in snapshot["events"]:
        if time.monotonic()>until:
            raise CapacityError("Frozen atomic execution deadline exceeded; no partial success")
        for rule in policies:
            definition=rule["definition"]
            if definition["kind"]!="atomic" or event["index_name"] not in definition["indexes"]:
                continue
            if intelligence._atomic_matches({"event":event,"raw":event["raw"],"projection":identities[event["event_id"]]["projection"] or {}},definition):
                add(_signal(snapshot,rule,"atomic",[event["event_id"]],identities))
    model=snapshot["models"]["candidate" if candidate else "baseline"]
    model_signals,job=_ml(snapshot,model,identities,pinned_job)
    for signal in model_signals:
        add(signal)
    sequence_signals,sequence_job=_sequence_ml(snapshot,snapshot.get("sequence_models",{}).get("candidate" if candidate else "baseline"),identities,pinned_sequence_job)
    for signal in sequence_signals:
        add(signal)
    # The CPU worker has its own hard subprocess deadline; restart a bounded
    # core budget after its completed/excluded job, without partial results.
    until=time.monotonic()+20
    combinations=0
    for rule in policies:
        definition=rule["definition"]
        if definition["kind"]!="composite":
            continue
        def pinned(signal):
            pin=definition.get("input_models",{}).get(signal["rule_id"])
            return not pin or signal["rule_revision"]==pin["revision"] and signal.get("model_digest")==pin["digest"]
        pool=sorted([s for s in signals.values() if principal.contains(definition["indexes"],s["indexes"]) and pinned(s)],key=lambda s:(s["event_window"]["start"],s["id"]))
        cohorts=[]
        for selector in definition["inputs"]:
            cohorts.append([s for s in pool if s["rule_id"]!=rule["id"] and all(s.get(k)==v for k,v in selector.items())])
        if any(not c for c in cohorts):
            diagnostics.append({"rule_id":rule["id"],"reason":"missing_input","selectors":[selector for selector,cohort in zip(definition["inputs"],cohorts) if not cohort]})
            continue
        for anchor in cohorts[0]:
            join_key=intelligence._join(anchor,definition["join_on"])
            if not join_key:
                diagnostics.append({"rule_id":rule["id"],"anchor_id":anchor["id"],"reason":"unknown_join_identity"}); continue
            candidates=[]
            for cohort in cohorts[1:]:
                candidates.append([s for s in cohort if s["id"]!=anchor["id"] and intelligence._join(s,definition["join_on"])==join_key and abs(s["event_window"]["end"]-anchor["event_window"]["end"])<=definition["window"]])
            if any(not c for c in candidates):
                continue
            found=False
            for tail in itertools.product(*candidates):
                combinations+=1
                if combinations>MAX_COMBINATIONS or time.monotonic()>until:
                    raise CapacityError("Frozen composite execution budget exceeded; no partial success")
                chain=[anchor,*tail]
                if len({s["id"] for s in chain})!=len(chain):
                    continue
                if definition["ordered"] and any(b["event_window"]["start"]<=a["event_window"]["end"] for a,b in zip(chain,chain[1:])):
                    continue
                if definition["ordered"] and definition.get("clock_policy","reported")=="strict" and not _strict_order(chain,identities):
                    continue
                dependency=intelligence._dependencies([s["event_ids"] for s in chain])
                if dependency["disjoint_original_groups"]<definition["minimum_independent_groups"]:
                    continue
                signal=_signal(snapshot,rule,"composite",[eid for s in chain for eid in s["event_ids"]],identities,parents=chain,features={"disjoint_original_groups":dependency["disjoint_original_groups"]})
                signal["entity_key"]=join_key
                if definition["join_on"]=="story":
                    signal["story_id"]=join_key
                add(signal); found=True
                # One canonical complete qualified chain per anchor, with all
                # alternatives inspected before calling it dependent/missing.
                break
            if not found:
                diagnostics.append({"rule_id":rule["id"],"anchor_id":anchor["id"],"reason":"dependent_or_unordered_evidence"})
    output={"graph":graph,"signals":sorted(signals.values(),key=lambda s:s["id"]),"diagnostics":sorted(diagnostics,key=encode),"ml_job":job,"sequence_job":sequence_job,
            "execution":{"status":"complete","cursor":len(snapshot["events"]),"frozen_events":len(snapshot["events"]),"composite_combinations":combinations,
                         "supported_inputs":["atomic","composite","ml"],"live_effects":False}}
    if len(encode(output).encode())>MAX_BYTES:
        raise CapacityError("Frozen intelligence output exceeds 16 MiB; no partial success")
    return output


def _compare(snapshot,pinned_result=None):
    baseline=_side(snapshot,snapshot["baseline"],False,(pinned_result or {}).get("baseline",{}).get("ml_job"),(pinned_result or {}).get("baseline",{}).get("sequence_job"))
    candidate=_side(snapshot,snapshot["candidate"],True,(pinned_result or {}).get("candidate",{}).get("ml_job"),(pinned_result or {}).get("candidate",{}).get("sequence_job"))
    def key(signal):
        return encode({k:signal[k] for k in ("kind","rule_id","event_ids","entity_key")})
    left={key(s):s for s in baseline["signals"]}; right={key(s):s for s in candidate["signals"]}
    common=set(left)&set(right)
    changed=[{"baseline":left[k],"candidate":right[k]} for k in sorted(common) if left[k]!=right[k]]
    return {"schema":SCHEMA,"status":"complete","mode":"frozen_intelligence_shadow","live_effects":False,
            "window":{"start":snapshot["start"],"end":snapshot["end"],"frozen":True},"engine":snapshot["engine"],
            "context_digest":snapshot["context_digest"],"event_count":len(snapshot["events"]),"baseline":baseline,"candidate":candidate,
            "comparison":{"added":[right[k] for k in sorted(set(right)-set(left))],"removed":[left[k] for k in sorted(set(left)-set(right))],
                          "changed":changed,"unchanged":len(common)-len(changed),"graph_equal":baseline["graph"]==candidate["graph"]},
            "limitations":["pure frozen staged execution; Case/SOAR/OS actions intentionally excluded",
                           "original overlap groups do not prove statistical independence or malicious probability",
                           "legacy/finding/UEBA signals are not synthesized by this original-driven evaluator",
                           "graphs reconstruct the frozen indexing frontier; they do not predict future missing parents"]}


def _authorize(db,actor,snapshot):
    if not principal.contains(actor["allowed_indexes"],snapshot["indexes"]):
        raise PermissionError("Frozen intelligence scope is no longer authorized")
    for rule in snapshot["baseline"]+snapshot["candidate"]:
        shadow_analysis._owner(db,actor["tenant"],rule["owner"],rule["definition"]["indexes"])
        if rule.get("approver"):
            shadow_analysis._owner(db,actor["tenant"],rule["approver"],rule["definition"]["indexes"])
    for model in [*snapshot["models"].values(),*snapshot.get("sequence_models",{}).values()]:
        if model:
            shadow_analysis._owner(db,actor["tenant"],model["owner"],model["indexes"])
            if model.get("reviewer"):
                shadow_analysis._owner(db,actor["tenant"],model["reviewer"],model["indexes"])
            for context in model.get("definition",{}).get("sources",[]):
                shadow_analysis._owner(db,actor["tenant"],context["owner"],[context["index_name"]])


def run_compare(store,who,data):
    actor,snapshot=_freeze(store,who,data)
    result=_compare(snapshot)
    identifier=uuid.uuid4().hex
    snapshot_digest,result_digest=release_manifest.digest(snapshot),release_manifest.digest(result)
    with principal.transaction(store,actor,("admin","analyst"),write=True) as (db,fresh):
        if actor!=fresh or _engine()!=snapshot["engine"] or release_manifest.digest(_context(db,fresh,snapshot["indexes"]))!=snapshot["context_digest"]:
            raise ConflictError("Frozen intelligence context changed before publication")
        _authorize(db,fresh,snapshot)
        for eid,receipt in snapshot["receipts"].items():
            proof=db.execute("SELECT digest,received FROM receipts WHERE tenant=? AND event_id=?",(actor["tenant"],eid)).fetchone()
            if not proof or dict(proof)!=receipt:
                raise ConflictError("Frozen intelligence original changed before publication")
        db.execute("INSERT INTO intelligence_shadow_runs VALUES(?,?,?,?,?,?,?,?,?)",(identifier,actor["tenant"],actor["name"],encode(snapshot["indexes"]),time.time(),snapshot_digest,result_digest,encode(snapshot),encode(result)))
        store.audit(db,actor["tenant"],actor["name"],"intelligence.shadow.compare",{"id":identifier,"snapshot_digest":snapshot_digest,"result_digest":result_digest,"live_effects":False})
    return {"id":identifier,"snapshot_digest":snapshot_digest,"result_digest":result_digest,**result}


def _visible(db,actor,identifier):
    row=db.execute("SELECT * FROM intelligence_shadow_runs WHERE tenant=? AND id=?",(actor["tenant"],identifier)).fetchone()
    if not row or not principal.contains(actor["allowed_indexes"],json.loads(row["indexes"])):
        raise KeyError("Frozen intelligence comparison not found")
    snapshot,result=json.loads(row["snapshot"]),json.loads(row["result"])
    if release_manifest.digest(snapshot)!=row["snapshot_digest"] or release_manifest.digest(result)!=row["result_digest"]:
        raise ConflictError("Frozen intelligence snapshot/result integrity failed")
    _authorize(db,actor,snapshot)
    return row,snapshot,result


def get(store,who,identifier):
    with principal.transaction(store,who) as (db,actor):
        row,_,result=_visible(db,actor,identifier)
        return {"id":identifier,"snapshot_digest":row["snapshot_digest"],"result_digest":row["result_digest"],**result}


def listing(store,who,cursor=None,count=50):
    evidence_scope.integer(count,"count",1,100)
    if cursor is not None:
        evidence_scope.text(cursor,"cursor",128)
    with principal.transaction(store,who) as (db,actor):
        scoped="" if actor["allowed_indexes"]==["*"] else " AND NOT EXISTS(SELECT 1 FROM json_each(indexes) x WHERE x.value NOT IN (SELECT value FROM json_each(?)))"
        args=[actor["tenant"],cursor or ""]+([] if not scoped else [encode(actor["allowed_indexes"])])+[count+1]
        rows=db.execute("SELECT id,indexes,created,snapshot_digest,result_digest FROM intelligence_shadow_runs WHERE tenant=? AND id>?"+scoped+" ORDER BY id LIMIT ?",args).fetchall()
        return {"items":[{**dict(r),"indexes":json.loads(r["indexes"])} for r in rows[:count]],"next_cursor":rows[count-1]["id"] if len(rows)>count else None,"live_effects":False}


def replay(store,who,identifier):
    with principal.transaction(store,who,("admin","analyst")) as (db,actor):
        row,snapshot,pinned_result=_visible(db,actor,identifier)
    if _engine()!=snapshot["engine"]:
        raise ConflictError("Frozen intelligence evaluator changed; create a new comparison")
    result=_compare(snapshot,pinned_result)
    result_digest=release_manifest.digest(result); replay_id=uuid.uuid4().hex
    with principal.transaction(store,actor,("admin","analyst"),write=True) as (db,fresh):
        fresh_row,_,_=_visible(db,fresh,identifier)
        if fresh!=actor or _engine()!=snapshot["engine"] or fresh_row["snapshot_digest"]!=row["snapshot_digest"]:
            raise ConflictError("Frozen intelligence replay authority changed")
        db.execute("INSERT INTO intelligence_shadow_replays VALUES(?,?,?,?,?,?,?,?)",(replay_id,actor["tenant"],actor["name"],identifier,time.time(),row["snapshot_digest"],result_digest,int(result_digest==row["result_digest"])))
    return {"id":identifier,"replay_id":replay_id,"identical":result_digest==row["result_digest"],"snapshot_digest":row["snapshot_digest"],"result_digest":result_digest,"live_effects":False,"status":"complete"}


def register(app,store,runtime,who,body):
    from fastapi import Request
    from starlette.concurrency import run_in_threadpool

    @app.post("/api/v3/shadow/intelligence/compare",status_code=201)
    async def compare(request:Request):
        return await run_in_threadpool(run_compare,store,who(request,("admin","analyst")),await body(request))

    @app.get("/api/v3/shadow/intelligence/runs")
    async def runs(request:Request):
        return await run_in_threadpool(listing,store,who(request),request.query_params.get("cursor"),int(request.query_params.get("count","50")))

    @app.get("/api/v3/shadow/intelligence/runs/{identifier}")
    async def details(identifier:str,request:Request):
        return await run_in_threadpool(get,store,who(request),identifier)

    @app.post("/api/v3/shadow/intelligence/runs/{identifier}/replay")
    async def rerun(identifier:str,request:Request):
        return await run_in_threadpool(replay,store,who(request,("admin","analyst")),identifier)
