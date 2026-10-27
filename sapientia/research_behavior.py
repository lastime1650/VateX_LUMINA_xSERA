"""Reviewed CPU research models and bounded provenance investigations.

An original implementation of selected research ideas, not a reproduction of
any published system. Ingest ACK only journals original references. CPU work
runs later; inference re-reads admitted originals and current source authority.
"""

import json
import time
import uuid
from contextlib import nullcontext
from pathlib import Path

from . import (
    evidence_scope,
    migrations,
    principal,
    research_features_v2,
    research_fusion,
    research_fusion_v2,
    research_long_horizon,
)
from .release_manifest import hash_file
from .research_behavior_graph import (
    ACTIONS,
    FEATURES,
    SCHEMA,
    analyze_graph,
    dataset_quality,
    digest,
    event_features,
    inputs,
)
from .storage import CapacityError, ConflictError, encode

LEGACY_FEATURE_CONTRACT_DIGEST = "c42045a942417634024c5510458a59c9c4292d67883e181e105394d45d619b97"
FEATURE_CONTRACT_DIGEST=digest({"schema":SCHEMA,"features":list(FEATURES),"actions":list(ACTIONS),
    "graph_implementation":hash_file(Path(__file__).with_name("research_behavior_graph.py")),
    "worker_implementation":hash_file(Path(__file__).with_name("research_behavior_worker.py")),
    "fusion_contract":research_fusion.CONTRACT_DIGEST})
V2_FEATURE_CONTRACT_DIGEST=digest({"schema":research_fusion_v2.SCHEMA,"features":list(research_features_v2.FEATURES),
    "fusion_contract":research_fusion_v2.CONTRACT_DIGEST,"long_implementation":hash_file(Path(__file__).with_name("research_long_horizon.py"))})
KNOWN_V2_COMPATIBILITY={
    ("d64bd08de362efad0ab6e8a5aa4b68cba7be7d0287cda5798b0a6c3d661189d3","4916a91f05d0161cbddcf6cfb14eec4a254177d3483365057fd61f0e88797647"),
}


def _v2(snapshot):return bool(snapshot and snapshot.get("fusion",{}).get("schema")==research_fusion_v2.SCHEMA)


def _compatible_snapshot(snapshot):
    if _v2(snapshot):
        pair=(snapshot.get("feature_contract_digest"),snapshot["fusion"].get("contract_digest"))
        return pair==(V2_FEATURE_CONTRACT_DIGEST,research_fusion_v2.CONTRACT_DIGEST) or pair in KNOWN_V2_COMPATIBILITY
    expected=FEATURE_CONTRACT_DIGEST if "fusion" in snapshot else LEGACY_FEATURE_CONTRACT_DIGEST
    return snapshot.get("feature_contract_digest")==expected and ("fusion" not in snapshot or snapshot["fusion"].get("contract_digest")==research_fusion.CONTRACT_DIGEST)


def _fusion_engine(snapshot):return research_fusion_v2 if _v2(snapshot) else research_fusion


def _features(snapshot,row):
    from . import research_compute_cache
    version=V2_FEATURE_CONTRACT_DIGEST if _v2(snapshot) else FEATURE_CONTRACT_DIGEST
    # Both extractors read exclusively through inputs(); include every actual
    # parsed field, rather than unrelated telemetry/evaluation payload bytes.
    return research_compute_cache.compute("features:"+version,inputs(row),lambda:research_features_v2.features(row) if _v2(snapshot) else event_features(row))

EDITORS = ("admin", "analyst")
MAX_MODELS = 64
MAX_AUTO_MODELS = 8
CAPABILITIES = [
    {"id":"research_fusion","name":"정상 보정 관계·시간·장기 스케치 융합 탐지","implemented":True,"paper_url":"https://spg.cs.ubc.ca/publication/2024-sp/","scope":"Frozen normal reference; real relation CE, same-incarnation cadence/transition and 128-bin normal-history distribution jointly gate reviewed signals; own CPU implementation","license_note":"Own calibrated deterministic fusion, not a GNN or published-system reproduction"},
    {"id":"velox_edge","name":"CPU 개별 관계 예측","implemented":True,"paper_url":"https://www.usenix.org/conference/usenixsecurity25/presentation/bilot","scope":"24 features, 7 relation classes, linear/MLP CPU ensemble; original implementation","license_note":"Own code; no upstream code or weights copied; not a paper reproduction"},
    {"id":"orthrus_paths","name":"핵심 인과 경로 축약","implemented":True,"paper_url":"https://www.usenix.org/conference/usenixsecurity25/presentation/jiang-baoxiang","scope":"At most 8 paths, 8 edges/path, reported incarnation identity only","license_note":"Own bounded greedy summarizer; not ORTHRUS model reproduction"},
    {"id":"kairos_temporal","name":"시간 그래프 관계 이상도","implemented":True,"paper_url":"https://spg.cs.ubc.ca/publication/2024-sp/","scope":"Bounded process-incarnation transition rarity and reconstruction; no GNN or CUDA requirement","license_note":"Own CPU adaptation; upstream code not copied"},
    {"id":"unicorn_sketch","name":"장기 고정 크기 그래프 스케치","implemented":True,"paper_url":"https://www.ndss-symposium.org/wp-content/uploads/2020/02/24046-paper.pdf","scope":"128 bins, 24-hour half life, bounded process transition history","license_note":"Own sketch; no GPL component copied; sketch does not replace original evidence"},
    {"id":"windows_prism","name":"Windows EDR 잡음·경로 그룹화","implemented":True,"paper_url":"https://www.ndss-symposium.org/wp-content/uploads/prism2026-12.pdf","scope":"Service IPC candidates and 2-second partitions, normalized paths, read-only leaf groups; explanation only","license_note":"Own conservative variants; never suppress originals or alerts based on a service name"},
    {"id":"holmes_ttp","name":"TTP 연관·공격 단계 요약","implemented":True,"paper_url":"https://www.seclab.cs.sunysb.edu/seclab/pubs/holmes19.pdf","scope":"Reported text hints for 4 ATT&CK techniques plus causal-path summary","license_note":"Own heuristics, not a HOLMES reproduction or confirmed attack attribution"},
    {"id":"nodlink_tree","name":"온라인 유계 경로 축약","implemented":True,"paper_url":"https://www.ndss-symposium.org/ndss-paper/nodlink-an-online-system-for-fine-grained-apt-attack-detection-and-investigation/","scope":"Own bounded greedy ancestor paths; not a Steiner-tree approximation guarantee","license_note":"NodLink Research-Only license: upstream code and data not bundled"},
    {"id":"dataset_quality","name":"분리·누수·반복 배경 평가","implemented":True,"paper_url":"https://sts.cs.illinois.edu/papers/paper/WhatWeTalkAboutWhenW20250512.html","scope":"Event/content/host/campaign overlap, chronology, repeated background, excluded labels","license_note":"Own audit; synthetic scenario count is not a detection-rate claim"},
]


def initialize(store):
    migrations.apply_store(store,"research_behavior",[
        "CREATE TABLE IF NOT EXISTS research_behavior_models(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,name TEXT NOT NULL,revision INTEGER NOT NULL,indexes TEXT NOT NULL,state TEXT NOT NULL,created REAL NOT NULL,snapshot TEXT NOT NULL,digest TEXT NOT NULL,metrics TEXT NOT NULL,quality TEXT NOT NULL,reviewer TEXT,review_mode TEXT NOT NULL,review_reason TEXT,reviewed REAL)",
        "CREATE INDEX IF NOT EXISTS research_behavior_model_scope ON research_behavior_models(tenant,state,name)",
        "CREATE TABLE IF NOT EXISTS research_behavior_reviews(seq INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT NOT NULL,model_id TEXT NOT NULL,reviewer TEXT NOT NULL,approve INTEGER NOT NULL,mode TEXT NOT NULL,reason TEXT NOT NULL,at REAL NOT NULL,digest TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS research_behavior_runs(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,indexes TEXT NOT NULL,model_id TEXT,created REAL NOT NULL,mode TEXT NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS research_behavior_run_scope ON research_behavior_runs(tenant,created)",
        "CREATE TABLE IF NOT EXISTS research_behavior_state(model_id TEXT PRIMARY KEY,tenant TEXT NOT NULL,cursor INTEGER NOT NULL,state TEXT NOT NULL,digest TEXT NOT NULL,updated REAL NOT NULL,error TEXT)",
        "CREATE TABLE IF NOT EXISTS research_behavior_outbox(seq INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT NOT NULL,event_id TEXT NOT NULL,index_name TEXT NOT NULL,received REAL NOT NULL,UNIQUE(tenant,event_id,received))",
        "CREATE INDEX IF NOT EXISTS research_behavior_outbox_scope ON research_behavior_outbox(tenant,index_name,seq)",
    ])
    from . import research_behavior_lifecycle
    research_behavior_lifecycle.initialize(store)
    research_long_horizon.initialize(store)
    from . import research_evaluation, research_rebaseline
    research_evaluation.initialize(store)
    research_rebaseline.initialize(store)


def _worker(payload, timeout=30):
    from .cpu_ml_runtime import request
    result = request(payload, timeout)
    if result.get("worker_error"):
        if result["worker_error"] == "ValueError":
            raise ValueError(result.get("reason","Invalid research worker input"))
        return {"status":"unavailable","available":False,"reason":result.get("reason","CPU framework unavailable"),
                "compatibility":"시스템에서 호환되지 않음","simulation_continues":True}
    return result


def _ids(values, maximum=32, minimum=1):
    if not isinstance(values,list) or not minimum <= len(values) <= maximum:
        raise ValueError(f"{minimum}..{maximum} original event IDs required")
    for value in values:
        evidence_scope.text(value,"event_id")
    if len(set(values)) != len(values):
        raise ValueError("Original event IDs must be unique")
    return values


def _originals(store, actor, ids, *, db=None):
    records = {}
    source_bytes = 0
    for offset in range(0,len(ids),1056):
        batch=evidence_scope.originals_many(store,actor,ids[offset:offset+1056],db=db)
        source_bytes+=sum(len(encode(record).encode()) for record in batch.values())
        if source_bytes>8*1024*1024:
            raise CapacityError("Research original snapshot exceeds 8 MiB; narrow the cohort")
        records.update(batch)
    with store.control() if db is None else nullcontext(db) as connection:
        _source_context(connection,actor,records,project=True)
    return records


def _source_pin(db,actor,record):
    return _source_context(db,actor,{record["event_id"]:record})[record["event_id"]]


def _source_context(db,actor,records,*,project=False):
    """Batch fresh source facts within one invocation; never cache authority."""
    if not records:return {}
    receipts={r["event_id"]:r for r in db.execute("SELECT * FROM source_event_receipts WHERE tenant=? AND event_id IN (SELECT value FROM json_each(?))",(actor["tenant"],encode(list(records))))}
    source_ids=sorted({r["source_id"] for r in receipts.values()})
    sources={r["id"]:r for r in db.execute("SELECT * FROM source_registry WHERE tenant=? AND id IN (SELECT value FROM json_each(?))",(actor["tenant"],encode(source_ids)))} if source_ids else {}
    owners={};verified={};result={}
    for identifier,record in records.items():
        proof=receipts.get(identifier)
        if not proof or not proof["source_definition"]:
            result[identifier]=None
            if project:record.update(projection=None,source_authority=None)
            continue
        if (proof["receipt_digest"]!=record["admission_digest"] or proof["received"]!=record["received"] or proof["index_name"]!=record["index_name"]):
            raise ConflictError("Research source admission receipt differs")
        source=sources.get(proof["source_id"])
        if (not source or source["state"]!="active" or source["version"]!=proof["source_version"] or source["index_name"]!=proof["index_name"]):
            raise PermissionError("Registered research source revoked, changed or rebound")
        key=(source["id"],proof["source_definition"])
        if key not in verified:
            authority=json.loads(proof["source_definition"])
            expected={"id":source["id"],"version":source["version"],**{k:source[k] for k in ("product","account","realm")}}
            if not isinstance(authority,dict) or any(authority.get(k)!=v for k,v in expected.items()):raise ConflictError("Research source definition binding differs")
            if source["owner"] not in owners:
                owners[source["owner"]]=principal.current(db,{"name":source["owner"],"tenant":actor["tenant"],"role":"analyst"},EDITORS)
            if not principal.contains(owners[source["owner"]]["allowed_indexes"],[source["index_name"]]):raise PermissionError("Research source owner index authority changed")
            pin={"source_id":source["id"],"source_version":source["version"],"source_owner":source["owner"],"index":source["index_name"],"source_definition_digest":digest(authority),"registry_definition_digest":digest(json.loads(source["definition"]))}
            verified[key]=(authority,pin)
        authority,source_pin=verified[key]
        pin=dict(source_pin)
        result[identifier]=pin
        if project:
            from . import research_compute_cache, security_schema
            # Current source/owner/admission validation above is mandatory even
            # when deterministic projection work on identical raw bytes is reused.
            context={key:record[key] for key in ("event_id","event_time","source","sourcetype","host","severity","message","index_name","raw","received")}
            projection=research_compute_cache.compute("projection:"+security_schema.PARSER_DIGEST,[context,authority],lambda record=record,authority=authority:security_schema.project({**record,"index":record["index_name"]},authority))
            record.update(projection=projection,source_authority=pin)
    return result


def _verify_sources(db,actor,proofs,required=False):
    if required and (not proofs or any(p.get("source_authority") is None for p in proofs)):
        raise PermissionError("Live research requires authenticated source receipts for every original")
    authenticated={p["event_id"]:p for p in proofs if p.get("source_authority") is not None}
    pins=_source_context(db,actor,authenticated)
    for proof in authenticated.values():
        if pins[proof["event_id"]]!=proof["source_authority"]:
            raise ConflictError("Research source authority snapshot changed")


def _proofs(records):
    return [{**evidence_scope.reference(r),"index":r["index_name"],"receipt_digest":r["admission_digest"],"event_digest":r["record_digest"],"source_authority":r["source_authority"]}
            for r in sorted(records.values(),key=lambda x:x["event_id"])]


def _verify_model(db, actor, identifier, require_active=False, *, authority=True):
    row = db.execute("SELECT * FROM research_behavior_models WHERE id=? AND tenant=?",(identifier,actor["tenant"])).fetchone()
    if not row or not principal.contains(actor["allowed_indexes"],json.loads(row["indexes"])):
        raise KeyError("Research model not found in the authorized scope")
    snapshot = json.loads(row["snapshot"])
    if row["state"] == "retired":
        raise ConflictError("Retired research model cannot be activated or inferred")
    if digest(snapshot) != row["digest"] or snapshot.get("schema") != SCHEMA or (authority and not _compatible_snapshot(snapshot)):
        raise ConflictError("Research model snapshot hash mismatch")
    if authority and "fusion" in snapshot and snapshot["fusion"].get("contract_digest") not in (research_fusion_v2.COMPATIBLE_CONTRACTS if _v2(snapshot) else {research_fusion.CONTRACT_DIGEST}):
        raise ConflictError("Fusion implementation changed; explicit retraining and independent review required")
    if require_active and not authority:
        raise ValueError("Active inference always requires current model authority")
    if authority:
        _verify_sources(db,actor,snapshot["originals"],required=require_active and row["review_mode"]=="live")
        owner = principal.current(db,{"name":row["owner"],"tenant":row["tenant"],"role":"analyst"},EDITORS)
        if not principal.contains(owner["allowed_indexes"],json.loads(row["indexes"])):
            raise PermissionError("Research model owner scope changed")
    if require_active:
        if row["state"] != "active" or not row["reviewer"] or row["reviewer"] == row["owner"]:
            raise PermissionError("Independent active research model review required")
        reviewer = principal.current(db,{"name":row["reviewer"],"tenant":row["tenant"],"role":"analyst"},EDITORS)
        if not principal.contains(reviewer["allowed_indexes"],json.loads(row["indexes"])):
            raise PermissionError("Research model reviewer scope changed")
        approval = db.execute("SELECT * FROM research_behavior_reviews WHERE model_id=? AND tenant=? ORDER BY seq DESC LIMIT 1",(identifier,actor["tenant"])).fetchone()
        if not approval or not approval["approve"] or approval["digest"] != row["digest"] or approval["mode"] != row["review_mode"] or approval["reviewer"] != row["reviewer"]:
            raise ConflictError("Research model review snapshot differs")
    return dict(row),snapshot


def _public(row):
    value = dict(row)
    for name in ("indexes","metrics","quality"):
        value[name] = json.loads(value[name])
    snapshot=json.loads(value.pop("snapshot"))
    fusion=snapshot.get("fusion")
    engine=_fusion_engine(snapshot)
    value["detection_gate"]={"method":engine.METHOD if fusion else "cpu_edge_relation_cross_entropy",
        "version":engine.SCHEMA if fusion else "legacy-0.17-ce",
        "contract_digest":fusion["contract_digest"] if fusion else LEGACY_FEATURE_CONTRACT_DIGEST,
        "threshold":fusion["threshold"] if fusion else snapshot["threshold"],
        "component_calibration":fusion["calibration"] if fusion else {"relation":snapshot["threshold"]},
        "normal_validation":fusion["normal_validation"] if fusion else None,
        "automatic_learning":False,"explicit_retraining_required_for_gate_change":True,
        "implementation_compatible":_compatible_snapshot(snapshot),
        "feature_width":len(snapshot.get("features",[])),"horizons_seconds":list(research_fusion_v2.HORIZONS) if _v2(snapshot) else [],"rolling_context_originals":16}
    return value


def list_models(store, who):
    with principal.transaction(store,who) as (db,actor):
        return {"items":[_public(row) for row in db.execute("SELECT * FROM research_behavior_models WHERE tenant=? ORDER BY CASE state WHEN 'active' THEN 0 WHEN 'pending' THEN 1 WHEN 'disabled' THEN 2 ELSE 3 END,created DESC LIMIT 128",(actor["tenant"],))
                         if principal.contains(actor["allowed_indexes"],json.loads(row["indexes"]))]}


def train(store,who,data):
    allowed = {"name","indexes","training_ids","validation_ids","epochs","seeds","normal_training_confirmed","gate_version"}
    if not isinstance(data,dict) or set(data)-allowed:
        raise ValueError("Unknown research training field")
    version=evidence_scope.choice(data.get("gate_version","v1"),{"v1","v2"},"research gate version")
    new_version=version=="v2"
    engine=research_fusion_v2 if new_version else research_fusion
    feature_fn=research_features_v2.features if new_version else event_features
    operation="research_v2_" if new_version else "research_"
    name = evidence_scope.text(data.get("name"),"name",120)
    indexes = evidence_scope.indexes(data.get("indexes"))
    training = _ids(data.get("training_ids"),1024,16)
    validation = _ids(data.get("validation_ids"),256,8)
    if set(training)&set(validation):
        raise ValueError("Training and validation originals must be disjoint")
    if data.get("normal_training_confirmed") is not True:
        raise ValueError("Normal-training acknowledgement required")
    epochs = evidence_scope.integer(data.get("epochs",60),"epochs",1,120)
    seeds = data.get("seeds",[17,29,43])
    if not isinstance(seeds,list) or not 1 <= len(seeds) <= 3 or any(type(x) is not int or not 0 <= x <= 2**31-1 for x in seeds) or len(set(seeds)) != len(seeds):
        raise ValueError("1..3 unique bounded seeds required")
    with principal.transaction(store,who,EDITORS) as (db,actor):
        if not principal.contains(actor["allowed_indexes"],indexes):
            raise PermissionError("Research training index scope denied")
        if db.execute("SELECT count(*) FROM research_behavior_models WHERE tenant=? AND state<>'retired'",(actor["tenant"],)).fetchone()[0] >= MAX_MODELS:
            raise CapacityError("Research model capacity reached; preserve/export and retire old versions")
    records = _originals(store,actor,training+validation)
    if any(r["index_name"] not in indexes for r in records.values()):
        raise PermissionError("Research training originals exceed declared model scope")
    if max(records[x]["event_time"] for x in training) >= min(records[x]["event_time"] for x in validation):
        raise ValueError("Point-in-time training must precede all validation originals")
    training_rows,validation_rows = [records[x] for x in training],[records[x] for x in validation]
    quality = dataset_quality({"training":training_rows,"validation":validation_rows})
    tf,vf = [feature_fn(x) for x in training_rows],[feature_fn(x) for x in validation_rows]
    answer = _worker({"operation":operation+"train","training":[x["values"] for x in tf],"training_targets":[x["target"] for x in tf],
                      "validation":[x["values"] for x in vf],"validation_targets":[x["target"] for x in vf],"epochs":epochs,"seeds":seeds},60)
    if answer.get("status") == "unavailable":
        return answer
    validation_scores=dict(zip(validation,answer.get("validation_scores",[])))
    for offset in range(0,len(validation),32):
        batch=validation[offset:offset+32]
        if all(eid in validation_scores for eid in batch):continue
        evaluated=_worker({"operation":operation+"infer","features":[feature_fn(records[eid])["values"] for eid in batch],
            "targets":[feature_fn(records[eid])["target"] for eid in batch],"ensemble":answer["ensemble"]},20)
        if evaluated.get("status")=="unavailable":return evaluated
        validation_scores.update(zip(batch,evaluated["scores"]))
    fusion=engine.fit(training_rows,validation_rows,validation_scores,answer["threshold"])
    answer["metrics"]["fusion_normal_validation"]=fusion["normal_validation"]
    snapshot = {"schema":SCHEMA,"feature_contract_digest":V2_FEATURE_CONTRACT_DIGEST if new_version else FEATURE_CONTRACT_DIGEST,"features":list(research_features_v2.FEATURES if new_version else FEATURES),"actions":list(ACTIONS),"ensemble":answer["ensemble"],"threshold":answer["threshold"],
                "originals":_proofs(records),"training_ids":training,"validation_ids":validation,"epochs":epochs,"seeds":seeds,
                "training_end":max(records[x]["event_time"] for x in training),"validation_end":max(records[x]["event_time"] for x in validation),
                "framework":"pytorch","framework_version":answer["framework_version"],"device":"cpu","reproduction_claim":False,
                "fusion":fusion}
    identifier = "RBM-"+uuid.uuid4().hex
    with principal.transaction(store,actor,EDITORS,write=True) as (db,fresh):
        if fresh != actor:
            raise PermissionError("Research training permissions changed")
        if db.execute("SELECT count(*) FROM research_behavior_models WHERE tenant=? AND state<>'retired'",(actor["tenant"],)).fetchone()[0] >= MAX_MODELS:
            raise CapacityError("Research model capacity reached during training")
        evidence_scope.recheck(db,actor,records)
        _verify_sources(db,actor,_proofs(records))
        # Source revocation between the snapshot and publication is terminal.
        # Reproject all originals from fresh receipts/registry/owners in this
        # write TX. Per-record control queries would inspect the same source
        # repeatedly; this keeps every proof check and exact projection value.
        current_records={eid:dict(record) for eid,record in records.items()}
        _source_context(db,actor,current_records,project=True)
        if any(current_records[eid]["projection"]!=record.get("projection") for eid,record in records.items()):
            raise ConflictError("Research projection changed during inference")
        revision = db.execute("SELECT coalesce(max(revision),0)+1 FROM research_behavior_models WHERE tenant=? AND name=?",(actor["tenant"],name)).fetchone()[0]
        db.execute("INSERT INTO research_behavior_models VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (identifier,actor["tenant"],actor["name"],name,revision,encode(indexes),"pending",time.time(),encode(snapshot),digest(snapshot),encode(answer["metrics"]),encode(quality),None,"shadow",None,None))
        db.executemany("INSERT OR IGNORE INTO record_case_evidence_refs VALUES(?,?,?,?)",[(actor["tenant"],eid,"research_behavior_model",identifier) for eid in records])
        row = db.execute("SELECT * FROM research_behavior_models WHERE id=?",(identifier,)).fetchone()
        return {**_public(row),"status":"completed","active":False}


def review(store,who,identifier,data):
    if not isinstance(data,dict) or set(data)-{"approve","reason","mode"} or type(data.get("approve")) is not bool:
        raise ValueError("Review requires approve, reason and optional shadow/live mode")
    reason = evidence_scope.text(data.get("reason"),"reason",2000)
    mode = evidence_scope.choice(data.get("mode","shadow"),{"shadow","live"},"research mode")
    with principal.transaction(store,who,EDITORS,write=True) as (db,actor):
        row,snapshot = _verify_model(db,actor,identifier,authority=data["approve"])
        if row["owner"] == actor["name"]:
            raise PermissionError("Research model creator cannot perform independent review")
        if data["approve"] and mode=="live":
            _verify_sources(db,actor,snapshot["originals"],required=True)
        if data["approve"] and db.execute("SELECT count(*) FROM research_behavior_models WHERE tenant=? AND state='active' AND id<>?",(actor["tenant"],identifier)).fetchone()[0] >= MAX_AUTO_MODELS:
            raise CapacityError("At most 8 active research models per tenant")
        now = time.time()
        db.execute("INSERT INTO research_behavior_reviews(tenant,model_id,reviewer,approve,mode,reason,at,digest) VALUES(?,?,?,?,?,?,?,?)",
            (actor["tenant"],identifier,actor["name"],int(data["approve"]),mode,reason,now,row["digest"]))
        if data["approve"]:
            db.execute("UPDATE research_behavior_models SET state='disabled' WHERE tenant=? AND name=? AND id<>? AND state='active'",(actor["tenant"],row["name"],identifier))
        db.execute("UPDATE research_behavior_models SET state=?,reviewer=?,review_mode=?,review_reason=?,reviewed=? WHERE id=?",
            ("active" if data["approve"] else "disabled",actor["name"],mode,reason,now,identifier))
        if not db.execute("SELECT 1 FROM research_behavior_state WHERE model_id=?",(identifier,)).fetchone():
            from .research_behavior_graph import empty_state
            state = {"schema":_fusion_engine(snapshot).SCHEMA,"recent_ids":[]} if snapshot.get("fusion") else empty_state()
            cursor = db.execute("SELECT coalesce(max(seq),0) FROM research_behavior_outbox").fetchone()[0]
            db.execute("INSERT INTO research_behavior_state VALUES(?,?,?,?,?,?,NULL)",(identifier,actor["tenant"],cursor,encode(state),digest(state),now))
        return _public(db.execute("SELECT * FROM research_behavior_models WHERE id=?",(identifier,)).fetchone())


def disable(store,who,identifier,reason):
    reason = evidence_scope.text(reason,"reason",2000)
    with principal.transaction(store,who,EDITORS,write=True) as (db,actor):
        _row,_ = _verify_model(db,actor,identifier,authority=False)
        db.execute("UPDATE research_behavior_models SET state='disabled',review_reason=? WHERE id=?",(reason,identifier))
        return _public(db.execute("SELECT * FROM research_behavior_models WHERE id=?",(identifier,)).fetchone())


def quality(store,who,data):
    if not isinstance(data,dict) or set(data)-{"training_ids","validation_ids","test_ids"}:
        raise ValueError("Quality requires declared training/validation/test original IDs")
    split_ids = {key[:-4]:_ids(data[key],1024) for key in ("training_ids","validation_ids","test_ids") if key in data}
    if not {"training","validation"} <= set(split_ids):
        raise ValueError("Training and validation originals required")
    with principal.transaction(store,who) as (_,actor):
        pass
    records = _originals(store,actor,list(dict.fromkeys(x for values in split_ids.values() for x in values)))
    result = dataset_quality({key:[records[x] for x in values] for key,values in split_ids.items()})
    principal.recheck(store,actor)
    return result


def _validate_projections(db,tenant,records):
    """Keep current projection checks ordered and bounded in the caller TX.

    Analysis admits at most 32 short originals. Chunk defensively without
    widening the shared publication helper's 32-original contract or caching
    current receipt/source facts between invocations.
    """
    from . import intelligence
    identifiers=list(records)
    for offset in range(0,len(identifiers),32):
        intelligence._projections(db,tenant,{eid:records[eid] for eid in identifiers[offset:offset+32]})


def _analyze(store,who,data,*,state=None,expected_cursor=None,next_cursor=None):
    if not isinstance(data,dict) or set(data)-{"event_ids","model_id"}:
        raise ValueError("Analysis accepts original event_ids and optional model_id only")
    ids = _ids(data.get("event_ids"))
    model_id = data.get("model_id")
    if model_id is not None:
        evidence_scope.text(model_id,"model_id")
    with principal.transaction(store,who,EDITORS) as (db,actor):
        row,snapshot = _verify_model(db,actor,model_id,require_active=True) if model_id else (None,None)
    current_ids=list(ids)
    fusion=snapshot.get("fusion") if snapshot else None
    engine=_fusion_engine(snapshot)
    context_ids=[];context_exclusions=[];context_records={};current_records=None
    if fusion and state is not None:
        if (not isinstance(state,dict) or set(state)!={"schema","recent_ids"} or state["schema"]!=engine.SCHEMA
                or not isinstance(state["recent_ids"],list) or len(state["recent_ids"])>research_fusion.CONTEXT
                or any(not isinstance(eid,str) for eid in state["recent_ids"])
                or len(set(state["recent_ids"]))!=len(state["recent_ids"])):
            raise ConflictError("Invalid bounded fusion original context")
        candidates=[eid for eid in state["recent_ids"] if eid not in current_ids]
        if candidates:
            try:
                combined=_originals(store,actor,candidates+current_ids)
                if row["review_mode"]=="live" and any(r["source_authority"] is None for r in combined.values()):
                    raise PermissionError("Prior live context has no authenticated source")
                context_records={eid:record for eid,record in combined.items() if eid in candidates}
                current_records={eid:record for eid,record in combined.items() if eid in current_ids}
                context_ids=candidates
            except (KeyError,ConflictError,PermissionError):
                context_records={}
                for eid in candidates:
                    try:
                        original=_originals(store,actor,[eid])
                        if row["review_mode"]=="live" and original[eid]["source_authority"] is None:
                            raise PermissionError("Prior live context has no authenticated source")
                    except (KeyError,ConflictError,PermissionError) as exc:
                        context_exclusions.append({"event_id":eid,"reason":str(exc)[:300]})
                    else:context_records.update(original);context_ids.append(eid)
    records = {**context_records,**(current_records if current_records is not None else _originals(store,actor,current_ids))}
    ids=context_ids+current_ids
    if len(ids)>32:raise CapacityError("Fusion context and current originals exceed 32")
    indexes = sorted({r["index_name"] for r in records.values()})
    if row and not set(indexes) <= set(json.loads(row["indexes"])):
        raise PermissionError("Research analysis originals exceed model scope")
    if row and row["review_mode"]=="live" and any(record["source_authority"] is None for record in records.values()):
        raise PermissionError("Live research runtime originals require authenticated source receipts")
    features = {eid:_features(snapshot,record) for eid,record in records.items()}
    answer = None
    if row:
        answer = _worker({"operation":"research_v2_infer" if _v2(snapshot) else "research_infer","features":[features[x]["values"] for x in ids],
                          "targets":[features[x]["target"] for x in ids],"ensemble":snapshot["ensemble"]},20)
        if answer.get("status") == "unavailable":
            return answer
    results,scores = [],{}
    for position,eid in enumerate(ids):
        score = answer["scores"][position] if answer else None
        threshold = snapshot["threshold"] if snapshot else None
        scores[eid] = score
        results.append({"event_id":eid,"edge_anomaly_score":score,"threshold":threshold,
            "anomaly":bool(score is not None and score > threshold),"features":features[eid]["features"],
            "observed_relation":features[eid]["target_name"],
            "predicted_relation":ACTIONS[answer["predicted_relations"][position]] if answer else None,
            "ensemble_disagreement":answer["ensemble_disagreement"][position] if answer else None,
            "missing_features":features[eid]["missing"],"provenance":evidence_scope.reference(records[eid]),"malicious_probability":False})
    graph = analyze_graph(list(records.values()),scores,None if fusion else state)
    new_state = graph.pop("state")
    mode = row["review_mode"] if row else "shadow"
    prepared_long=None
    if fusion:
        if _v2(snapshot):
            prepared_long=research_long_horizon.prepare(store,actor,row,records)
            values=engine.evaluate(list(records.values()),scores,fusion,current_ids,history_rows=list(prepared_long["records"].values()))
        else:values=engine.evaluate(list(records.values()),scores,fusion,current_ids)
        for result in results:
            result["relation_anomaly"]=result["anomaly"]
            result["fusion"]=values[result["event_id"]]
            result["anomaly"]=result["fusion"]["anomaly"]
        final_decision=engine.decision(results,mode,fusion)
        ordered=sorted((r for r in records.values() if values[r["event_id"]]["evidence"]["identity_complete"]
            and not values[r["event_id"]]["evidence"]["late_event"]),key=lambda r:(r["event_time"],r["event_id"]))
        new_state={"schema":engine.SCHEMA,"recent_ids":[r["event_id"] for r in ordered[-research_fusion.CONTEXT:]]}
    else:
        final_decision={"anomaly":any(r["anomaly"] for r in results),"publishable":mode=="live" and any(r["anomaly"] for r in results),
            "method":"cpu_edge_relation_cross_entropy","malicious_probability":False}
    run = {"id":"RBR-"+uuid.uuid4().hex,"schema":SCHEMA,"tenant":actor["tenant"],"owner":actor["name"],"indexes":indexes,
        "event_ids":ids,"model_id":model_id,"model_digest":row["digest"] if row else None,"model_revision":row["revision"] if row else None,
        "reviewer":row["reviewer"] if row else None,"reviewed_at":row["reviewed"] if row else None,
        "created":time.time(),"mode":mode,"shadow":mode!="live","status":"completed",
        "originals":_proofs(records),"results":results,"graph":graph,
        "decision":final_decision,
        "metrics":{"cpu_inference_ms":answer["duration_ms"] if answer else None,"worker_wall_ms":answer.get("worker_wall_ms") if answer else None,
            "false_positive_cases_per_host_day":None,"case_latency_p95_ms":None,"device":"cpu","reproduction_claim":False}}
    if fusion:
        run["fusion_context"]={"context_ids":context_ids,"current_ids":current_ids,"excluded":context_exclusions,
            "input_contract_digest":fusion["contract_digest"],"baseline_digest":digest(fusion["baseline"]),
            "calibration_digest":digest(fusion["calibration"]),"automatic_learning":False}
    if prepared_long:run["long_evidence"]=prepared_long["descriptor"]
    with principal.transaction(store,actor,EDITORS,write=True) as (db,fresh):
        if fresh != actor:
            raise PermissionError("Research analysis permissions changed")
        evidence_scope.recheck(db,actor,records)
        _verify_sources(db,actor,_proofs(records),required=mode=="live")
        _validate_projections(db,actor["tenant"],records)
        if model_id:
            latest,_ = _verify_model(db,actor,model_id,require_active=True)
            if latest["digest"] != run["model_digest"] or latest["review_mode"] != mode or latest["reviewed"] != run["reviewed_at"]:
                raise ConflictError("Research model review changed during inference")
        if prepared_long:research_long_horizon.commit(store,db,actor,row,run,prepared_long,current_ids,observe=expected_cursor is not None)
        if expected_cursor is not None:
            old = db.execute("SELECT cursor FROM research_behavior_state WHERE model_id=?",(model_id,)).fetchone()
            if not old or old["cursor"] != expected_cursor:
                raise ConflictError("Research automatic cursor changed during inference")
            db.execute("UPDATE research_behavior_state SET cursor=?,state=?,digest=?,updated=?,error=NULL WHERE model_id=?",
                (next_cursor,encode(new_state),digest(new_state),time.time(),model_id))
            if fusion:
                db.execute("DELETE FROM record_case_evidence_refs WHERE tenant=? AND kind='research_behavior_context' AND record_id=?",(actor["tenant"],model_id))
                db.executemany("INSERT OR IGNORE INTO record_case_evidence_refs VALUES(?,?,?,?)",[(actor["tenant"],eid,"research_behavior_context",model_id) for eid in new_state["recent_ids"]])
        db.execute("INSERT INTO research_behavior_runs VALUES(?,?,?,?,?,?,?,?,?)",(run["id"],actor["tenant"],actor["name"],encode(indexes),model_id,run["created"],mode,encode(run),digest(run)))
        refkind = "research_behavior_anomaly" if mode=="live" and run["decision"]["anomaly"] else "research_behavior_run"
        db.executemany("INSERT OR IGNORE INTO record_case_evidence_refs VALUES(?,?,?,?)",[(actor["tenant"],eid,refkind,run["id"]) for eid in ids])
    return run


def analyze(store,who,data):
    return _analyze(store,who,data)


def get_run(store,who,identifier):
    with principal.transaction(store,who) as (db,actor):
        row = db.execute("SELECT * FROM research_behavior_runs WHERE id=? AND tenant=?",(identifier,actor["tenant"])).fetchone()
        if not row or not principal.contains(actor["allowed_indexes"],json.loads(row["indexes"])):
            raise KeyError("Research run not found")
        run = json.loads(row["body"])
        if digest(run) != row["digest"]:
            raise ConflictError("Research run snapshot hash mismatch")
        return run


def list_runs(store,who,limit=50):
    evidence_scope.integer(limit,"limit",1,100)
    with principal.transaction(store,who) as (db,actor):
        values = []
        for row in db.execute("SELECT * FROM research_behavior_runs WHERE tenant=? ORDER BY created DESC LIMIT 2000",(actor["tenant"],)):
            if not principal.contains(actor["allowed_indexes"],json.loads(row["indexes"])):
                continue
            run = json.loads(row["body"])
            if digest(run) != row["digest"]:
                raise ConflictError("Research run snapshot hash mismatch")
            values.append({key:run[key] for key in ("id","model_id","model_revision","indexes","event_ids","created","mode","shadow","status","decision","metrics")})
            if len(values) >= limit:
                break
        return {"items":values}


def validate_publication(store,db,actor,run_id,*,memo=None):
    fresh = principal.current(db,actor,EDITORS)
    if fresh != actor:
        raise PermissionError("Research publication authority changed")
    row = db.execute("SELECT * FROM research_behavior_runs WHERE id=? AND tenant=?",(run_id,actor["tenant"])).fetchone()
    if not row or not principal.contains(actor["allowed_indexes"],json.loads(row["indexes"])):
        raise KeyError("Research publication run not found")
    run = json.loads(row["body"])
    if digest(run) != row["digest"] or run["owner"] != actor["name"]:
        raise ConflictError("Research run snapshot hash or owner mismatch")
    if run["mode"] != "live" or run["shadow"] or run["status"] != "completed" or not run["decision"]["publishable"]:
        raise PermissionError("Only approved live anomalous research runs can publish")
    model,snapshot = _verify_model(db,actor,run["model_id"],require_active=True)
    if model["review_mode"] != "live" or model["digest"] != run["model_digest"] or model["revision"] != run["model_revision"] or model["reviewed"] != run["reviewed_at"]:
        raise ConflictError("Research run no longer matches its live model review")
    if set(run["event_ids"]) != {p["event_id"] for p in run["originals"]} or len(run["event_ids"]) > 32:
        raise ConflictError("Research original ancestry differs")
    if (not run["event_ids"] or len(set(run["event_ids"])) != len(run["event_ids"])
            or set(run["event_ids"]) != {r["event_id"] for r in run["results"]}
            or len(run["results"]) != len(run["event_ids"])
            or sorted({p["index_name"] for p in run["originals"]}) != run["indexes"]):
        raise ConflictError("Research result ancestry differs")
    import math
    fusion=snapshot.get("fusion")
    engine=_fusion_engine(snapshot)
    for result in run["results"]:
        score = result.get("edge_anomaly_score")
        if (type(score) not in (int,float) or not math.isfinite(score) or score < 0
                or result.get("threshold") != snapshot["threshold"]
                or (result.get("relation_anomaly") if fusion else result.get("anomaly")) is not (score > snapshot["threshold"])):
            raise ConflictError("Research anomaly decision differs from model threshold")
    if fusion:
        context=run.get("fusion_context")
        if (not isinstance(context,dict) or context.get("input_contract_digest")!=fusion["contract_digest"]
                or not isinstance(context.get("context_ids"),list) or len(context["context_ids"])>research_fusion.CONTEXT
                or not isinstance(context.get("current_ids"),list) or not context["current_ids"]
                or context["context_ids"]+context["current_ids"]!=run["event_ids"]
                or context.get("automatic_learning") is not False
                or context.get("baseline_digest")!=digest(fusion["baseline"])
                or context.get("calibration_digest")!=digest(fusion["calibration"])):
            raise ConflictError("Research fusion context binding differs")
        from . import research_publication_proof
        if research_publication_proof.reuse(store,db,actor,row,run,model,memo):
            return run
        records=_originals(store,actor,run["event_ids"],db=db)
        if _proofs(records)!=run["originals"]:
            raise ConflictError("Research fusion originals changed")
        features={eid:_features(snapshot,record) for eid,record in records.items()}
        history=None;long_body=None
        if _v2(snapshot):
            history,long_body=research_long_horizon.replay(store,db,actor,run,memo=memo)
            if isinstance(memo,dict):memo["long-verified:"+run_id]=(history,long_body)
        elif run.get("long_evidence") is not None:raise ConflictError("Legacy run cannot acquire long manifest authority")
        cache_key=digest([row["digest"],model["digest"],engine.CONTRACT_DIGEST,digest(_proofs(records)),run.get("long_evidence")])
        cached=memo.get(cache_key) if isinstance(memo,dict) else None
        if cached is None:
            answer=_worker({"operation":"research_v2_infer" if _v2(snapshot) else "research_infer","features":[features[eid]["values"] for eid in run["event_ids"]],
                "targets":[features[eid]["target"] for eid in run["event_ids"]],"ensemble":snapshot["ensemble"]},20)
            if answer.get("status")=="unavailable":raise ConflictError("CPU fusion verification unavailable")
            scores=dict(zip(run["event_ids"],answer["scores"]))
            verified=engine.evaluate(list(records.values()),scores,fusion,context["current_ids"],history_rows=list(history.values())) if history is not None else engine.evaluate(list(records.values()),scores,fusion,context["current_ids"])
            if isinstance(memo,dict):
                if len(memo)>=64:memo.pop(next(iter(memo)))
                memo[cache_key]=(scores,verified)
        else:scores,verified=cached
        for result in run["results"]:
            eid=result["event_id"]
            if (result.get("features")!=features[eid]["features"] or result["edge_anomaly_score"]!=scores[eid]
                    or result.get("fusion")!=verified[eid] or result["anomaly"] is not verified[eid]["anomaly"]):
                raise ConflictError("Research fusion score/components differ from original replay")
        if run["decision"]!=engine.decision(run["results"],run["mode"],fusion):
            raise ConflictError("Research final fusion decision differs from calibrated replay")
    if not any(r["anomaly"] for r in run["results"]):
        raise ConflictError("Research publication has no anomalous original")
    _verify_sources(db,actor,run["originals"],required=True)
    evidence_scope.recheck(db,actor,{p["event_id"]:p for p in run["originals"]})
    if fusion:
        research_publication_proof.remember(store,db,actor,row,run,model,memo,long_body)
    return run


def long_publication_evidence(store,db,actor,run_id,*,memo=None):
    """Verified complete closure; a bounded short signal never hides long parents."""
    memo={} if memo is None else memo
    run=validate_publication(store,db,actor,run_id,memo=memo)
    descriptor=run.get("long_evidence")
    if descriptor is None:return {"event_ids":list(run["event_ids"]),"proofs":run["originals"],"descriptor":None}
    cached=memo.get("long-verified:"+run_id)
    _records,body=cached if cached is not None else research_long_horizon.replay(store,db,actor,run,memo=memo)
    proofs={p["event_id"]:p for p in body["originals"]}
    proofs.update({p["event_id"]:p for p in run["originals"]})
    return {"event_ids":sorted(proofs),"proofs":[proofs[eid] for eid in sorted(proofs)],"descriptor":descriptor}


def journal_indexed(store,db,indexed_rows):
    """Indexing transaction hook: references only, no imports/framework/analysis."""
    scopes = {}
    for row in indexed_rows:
        tenant = row["tenant"]
        if tenant not in scopes:
            scopes[tenant] = [set(json.loads(m[0])) for m in db.execute("SELECT indexes FROM research_behavior_models WHERE tenant=? AND state='active'",(tenant,))]
        payload = json.loads(row["payload"]) if isinstance(row["payload"],str) else row["payload"]
        index = payload.get("index",payload.get("index_name","main"))
        if any(index in scope for scope in scopes[tenant]):
            db.execute("INSERT OR IGNORE INTO research_behavior_outbox(tenant,event_id,index_name,received) VALUES(?,?,?,?)",(tenant,row["event_id"],index,row["received"]))


def protected_ids(db,tenant,ids,now=None):
    if not ids:
        return set()
    protected={r[0] for r in db.execute("SELECT DISTINCT o.event_id FROM research_behavior_outbox o JOIN research_behavior_state s ON s.tenant=o.tenant AND o.seq>s.cursor JOIN research_behavior_models m ON m.id=s.model_id AND m.state='active' WHERE o.tenant=? AND o.event_id IN (SELECT value FROM json_each(?))",(tenant,encode(ids)))}
    for row in db.execute("SELECT s.state FROM research_behavior_state s JOIN research_behavior_models m ON m.id=s.model_id WHERE s.tenant=? AND m.state='active'",(tenant,)):
        state=json.loads(row[0])
        if state.get("schema") in {research_fusion.SCHEMA,research_fusion_v2.SCHEMA}:
            protected.update(set(state.get("recent_ids",[]))&set(ids))
    protected.update(r[0] for r in db.execute("SELECT c.event_id FROM research_horizon_cache c JOIN research_behavior_models m ON m.id=c.model_id AND m.state='active' WHERE c.tenant=? AND c.event_id IN (SELECT value FROM json_each(?))",(tenant,encode(ids))))
    return protected


def _exclude_pending(store,actor,model,pending):
    """A terminal source exclusion is durable; it must not poison later events."""
    ids=[p["event_id"] for p in pending]
    try:
        records=evidence_scope.originals(store,actor,ids)
        for record in records.values():record["source_authority"]=None
    except (KeyError,ConflictError):
        records={}
    run={"id":"RBR-"+uuid.uuid4().hex,"schema":SCHEMA,"tenant":actor["tenant"],"owner":actor["name"],
        "indexes":sorted({p["index_name"] for p in pending}),"event_ids":ids,"model_id":model["id"],"model_digest":model["digest"],
        "model_revision":model["revision"],"reviewer":model["reviewer"],"reviewed_at":model["reviewed"],"created":time.time(),
        "mode":model["review_mode"],"shadow":model["review_mode"]!="live","status":"excluded","originals":_proofs(records),"results":[],
        "graph":{"nodes":[],"edges":[],"summary_paths":[],"excluded_before_analysis":True},
        "decision":{"anomaly":False,"publishable":False,"method":"source_authority_exclusion","malicious_probability":False},
        "excluded_originals":[{"event_id":p["event_id"],"received":p["received"],"reason":p["exclusion"]} for p in pending],
        "metrics":{"cpu_inference_ms":None,"device":"cpu","real_world_detection_rate_measured":False}}
    with principal.transaction(store,actor,EDITORS,write=True) as (db,fresh):
        _verify_model(db,fresh,model["id"],require_active=True)
        cursor=db.execute("SELECT cursor FROM research_behavior_state WHERE model_id=?",(model["id"],)).fetchone()
        if not cursor or cursor["cursor"]!=model["cursor"]:
            raise ConflictError("Research exclusion cursor changed")
        if records:evidence_scope.recheck(db,fresh,records)
        db.execute("UPDATE research_behavior_state SET cursor=?,updated=?,error=? WHERE model_id=?",(pending[-1]["seq"],time.time(),encode(run["excluded_originals"]),model["id"]))
        db.execute("INSERT INTO research_behavior_runs VALUES(?,?,?,?,?,?,?,?,?)",(run["id"],actor["tenant"],actor["name"],encode(run["indexes"]),model["id"],run["created"],run["mode"],encode(run),digest(run)))
        db.executemany("INSERT OR IGNORE INTO record_case_evidence_refs VALUES(?,?,?,?)",[(actor["tenant"],eid,"research_behavior_run",run["id"]) for eid in records])
    return run


def run_due(store,now=None,cancel=None,budget=.25,max_runs=1):
    now = time.time() if now is None else now
    if type(max_runs) is not int or not 1 <= max_runs <= 8 or type(budget) not in (int,float) or not 0 < budget <= 10:
        raise ValueError("Bounded research automatic budget required")
    from . import research_behavior_lifecycle
    lifecycle = research_behavior_lifecycle.run_due(store,now,cancel,maximum=4)
    lifecycle["long_horizon"]=research_long_horizon.cleanup(store,now,maximum=4)
    began = time.monotonic()
    with store.control() as db:
        models = [dict(r) for r in db.execute("SELECT m.*,s.cursor,s.state AS graph_state,s.digest AS graph_digest FROM research_behavior_models m JOIN research_behavior_state s ON s.model_id=m.id WHERE m.state='active' AND EXISTS(SELECT 1 FROM research_behavior_outbox o WHERE o.tenant=m.tenant AND o.seq>s.cursor AND o.index_name IN (SELECT value FROM json_each(m.indexes))) ORDER BY s.updated,m.id LIMIT 64")]
    runs,errors = [],[]
    for model in models:
        if len(runs)>=max_runs or (cancel and cancel()) or time.monotonic()-began >= budget:
            break
        try:
            actor = {"name":model["owner"],"tenant":model["tenant"],"role":"analyst","allowed_indexes":json.loads(model["indexes"])}
            with store.control() as db:
                actor = principal.current(db,actor,EDITORS)
                _,snapshot=_verify_model(db,actor,model["id"],require_active=True)
                maximum=research_fusion.CONTEXT if snapshot.get("fusion") else 32
                pending = [dict(r) for r in db.execute("SELECT * FROM research_behavior_outbox WHERE tenant=? AND seq>? AND index_name IN (SELECT value FROM json_each(?)) ORDER BY seq LIMIT ?",(model["tenant"],model["cursor"],model["indexes"],maximum))]
            if not pending:
                continue
            state = json.loads(model["graph_state"])
            if digest(state) != model["graph_digest"]:
                raise ConflictError("Research graph state hash mismatch")
            # Admission-identity binding is checked again before CPU work.
            valid_prefix,excluded_prefix=[],[]
            with store.control() as db:
                receipts={r["event_id"]:r for r in db.execute("SELECT event_id,digest,received FROM receipts WHERE tenant=? AND event_id IN (SELECT value FROM json_each(?))",(model["tenant"],encode([r["event_id"] for r in pending])))}
                references={p["event_id"]:{"event_id":p["event_id"],"index_name":p["index_name"],"received":receipts[p["event_id"]]["received"],"admission_digest":receipts[p["event_id"]]["digest"]} for p in pending if p["event_id"] in receipts and receipts[p["event_id"]]["received"]==p["received"]}
                try:pins=_source_context(db,actor,references)
                except (PermissionError,ConflictError):pins=None
                for pending_row in pending:
                    try:
                        receipt = receipts.get(pending_row["event_id"])
                        if not receipt or receipt["received"] != pending_row["received"]:
                            raise ConflictError("Queued research original admission changed")
                        reference={"event_id":pending_row["event_id"],"index_name":pending_row["index_name"],"received":receipt["received"],"admission_digest":receipt["digest"]}
                        pin=pins[pending_row["event_id"]] if pins is not None else _source_pin(db,actor,reference)
                        if model["review_mode"]=="live" and pin is None:
                            raise PermissionError("Generic original has no authenticated source for live inference")
                    except (PermissionError,ConflictError) as exc:
                        if valid_prefix:break
                        excluded_prefix.append({**pending_row,"exclusion":str(exc)[:500]})
                    else:
                        if excluded_prefix:break
                        valid_prefix.append(pending_row)
            if excluded_prefix:
                runs.append(_exclude_pending(store,actor,model,excluded_prefix))
                continue
            pending=valid_prefix
            run = _analyze(store,actor,{"event_ids":[r["event_id"] for r in pending],"model_id":model["id"]},state=state,expected_cursor=model["cursor"],next_cursor=pending[-1]["seq"])
            if run.get("status") == "unavailable":
                errors.append({"model_id":model["id"],**run})
                break
            runs.append(run)
            from . import research_rebaseline
            research_rebaseline.observe(store,actor,run)
        except (ValueError,KeyError,PermissionError,ConflictError,CapacityError) as exc:
            errors.append({"model_id":model["id"],"error":type(exc).__name__,"reason":str(exc)[:500]})
            with store.control() as db:
                db.execute("UPDATE research_behavior_state SET updated=?,error=? WHERE model_id=?",(now,encode(errors[-1]),model["id"]))
    return {"processed":sum(len(r.get("fusion_context",{}).get("current_ids",r["event_ids"])) for r in runs if r["status"]=="completed"),
            "excluded":sum(len(r["event_ids"]) for r in runs if r["status"]=="excluded"),
            "runs":runs,"errors":errors,"lifecycle":lifecycle,"status":"completed" if not errors else "degraded"}


def status(store,who):
    models = list_models(store,who)["items"]
    runs = list_runs(store,who,1)["items"]
    return {"schema":SCHEMA,"shadow_default":True,"models":{"total":len(models),"active":sum(x["state"]=="active" for x in models)},
        "runs":{"total_visible_recent":len(list_runs(store,who,100)["items"]),"last":runs[0] if runs else None},
        "capabilities":CAPABILITIES,"limits":{"events_per_run":32,"nodes":128,"edges":128,"sketch_bins":128,"active_models_per_tenant":8,
        "training_events":1024,"validation_events":256,"epochs":120,"seeds":3,"cpu_threads":1,
        "normal_detail_seconds":86400,"normal_details_per_model":128,"permanent_run_hash_history":True},
        "automatic_training":False,"model_modes":["shadow","live"],"device_authority":False,"real_world_detection_rate_measured":False,
        "new_training_gate":research_fusion_v2.METHOD,"fusion_contract_digest":research_fusion_v2.CONTRACT_DIGEST,
        "default_compatible_training_gate":research_fusion.METHOD,"recommended_gate_version":"v2",
        "multi_horizon":{"seconds":list(research_fusion_v2.HORIZONS),"maximum_raw_originals":1024,"maximum_cached_originals":4096,"hash_rows":2,"bins_per_row":256,"exact_semantic_collision_correction":True,"source_completeness_attested":False},
        "legacy_gate_preserved":True,"rolling_context_originals":research_fusion.CONTEXT,"fusion_current_events_per_auto_run":research_fusion.CONTEXT}
