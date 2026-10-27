"""Each frozen-normal component changes the real gate, with abstention checks."""

import copy
import json

import pytest
from test_research_behavior import actor, event
from test_research_behavior import store as _store_fixture

from sapientia import (
    advanced_intelligence,
    connector_runtime,
    intelligence,
    principal,
    source_registry,
)
from sapientia import research_behavior as research
from sapientia import research_behavior_graph as graph
from sapientia import research_behavior_lifecycle as lifecycle
from sapientia import research_fusion as fusion
from sapientia.storage import ConflictError, encode

store = _store_fixture


def normal(i):
    reader=i%2==0
    return event(i,raw={"process_guid":"normal-reader" if reader else "normal-browser",
        "process_start_identity":"reader-start" if reader else "browser-start",
        "action":"file_read" if reader else "network_connect",
        "image":"C:/Apps/editor.exe" if reader else "C:/Apps/browser.exe",
        "command_line":"editor document.txt" if reader else "browser internal",
        "file_path":"C:/Docs/document.txt" if reader else "","file_sha256":"a"*64 if reader else "",
        "dest_ip":"" if reader else "10.0.0.8","dest_port":0 if reader else 443})


@pytest.fixture
def calibrated():
    rows=[normal(i) for i in range(48)]
    model=fusion.fit(rows[:32],rows[32:],{r["event_id"]:.001 for r in rows[32:]},.05)
    assert model["normal_validation"]["anomalies"]==0
    return model


def reads(times,offset=100):
    return [event(offset+i,event_time=1700010000+value,raw={"dest_port":0}) for i,value in enumerate(times)]


def evaluated(model,rows,loss=.001,current=None):
    return fusion.evaluate(rows,{r["event_id"]:loss for r in rows},model,current or [r["event_id"] for r in rows])


@pytest.mark.parametrize("action,legacy",[("process_create","write"),("process_created","write"),("process_creation","other")])
def test_process_creation_is_execute_only_in_new_fusion_with_legacy_ce_unchanged(action,legacy):
    row=event(1,raw={"action":action})
    assert graph.action_class(action)==legacy
    assert graph.event_features(row)["target_name"]==legacy
    assert graph.event_features(row)["target"]==graph.ACTIONS.index(legacy)
    assert len(graph.event_features(row)["values"])==24
    assert fusion._action(graph.inputs(row)["action"])=="execute"


@pytest.mark.parametrize("action",["file_create","file_write","file_read","process_start","process_exit","process_observed","network_connect","registry_set","authentication","other"])
def test_fusion_action_fallback_preserves_other_existing_action_semantics(action):
    assert fusion._action(action)==graph.action_class(action)
    if action=="process_observed":assert fusion._action(action)=="other"


def test_process_creation_normal_baseline_runtime_transition_and_sketch_agree():
    rows=[event(i,raw={"action":"process_create" if i%2==0 else "process_created"}) for i in range(48)]
    model=fusion.fit(rows[:32],rows[32:],{r["event_id"]:.001 for r in rows[32:]},.05)
    image=graph.normalize_path(graph.inputs(rows[0])["image"])
    execute_key=fusion.digest([image,"execute","execute"])
    write_key=fusion.digest([image,"write","write"])
    assert model["baseline"]["transitions"][execute_key]==31
    assert write_key not in model["baseline"]["transitions"]
    runtime=[event(100+i,raw={"action":"process_created"}) for i in range(8)]
    results=evaluated(model,runtime)
    last=results[runtime[-1]["event_id"]]
    assert last["eligibility"]["temporal"] and last["eligibility"]["sketch"]
    assert last["evidence"]["normal_transition_count"]==31 and not last["evidence"]["novel_transition"]
    assert last["raw_components"]["sketch"]==0 and not last["anomaly"]
    create=event(500,raw={"action":"process_create"});created=event(501,raw={"action":"process_created"})
    write=event(502,raw={"action":"file_write"})
    assert fusion._bucket(create)==fusion._bucket(created)
    assert fusion._bucket(create)!=fusion._bucket(write)
    assert graph.event_features(create)["values"]==graph.event_features(write)["values"]


def test_previous_fusion_implementation_contract_requires_explicit_new_review(calibrated):
    previous=copy.deepcopy(calibrated)
    previous["contract_digest"]="a6431c8551d1b2646996b0c83f8608369106ba6373942df538efd82af77d1471"
    assert previous["contract_digest"]!=fusion.CONTRACT_DIGEST
    with pytest.raises(ValueError,match="explicit training and independent review"):
        evaluated(previous,reads([0,2,4]))


def test_relation_only_gate_and_real_ablation(calibrated):
    result=next(iter(evaluated(calibrated,reads([0]),loss=.2).values()))
    assert result["anomaly"] and result["components"]["temporal"]==result["components"]["sketch"]==0
    assert not result["ablations"]["without_relation"]["anomaly"]


def test_same_incarnation_gap_only_gate_with_low_relation_loss(calibrated):
    result=list(evaluated(calibrated,reads([0,2,2000])).values())[-1]
    assert result["anomaly"] and result["components"]["relation"]<1 and result["components"]["sketch"]==0
    assert result["reasons"]==["temporal_above_calibrated_normal"]
    assert not result["ablations"]["without_temporal"]["anomaly"]


def test_long_normal_sketch_shift_only_gate_with_normal_relations_and_cadence(calibrated):
    result=list(evaluated(calibrated,reads(list(range(0,24,2)))).values())[-1]
    assert result["anomaly"] and result["components"]["relation"]<1 and result["components"]["temporal"]<1
    assert result["reasons"]==["sketch_above_calibrated_normal"]
    assert not result["ablations"]["without_sketch"]["anomaly"]


def test_joint_moderate_components_can_cross_gate_when_each_is_below_it():
    parts={"relation":.8,"temporal":.8,"sketch":.8}
    assert max(parts.values())<1 and fusion._score(parts)>1
    assert all(fusion._score(parts,(key,))<1 for key in parts)


def test_many_independent_normal_processes_do_not_fabricate_a_sequence_baseline(calibrated):
    model=copy.deepcopy(calibrated);model["baseline"]["image_transition_counts"]={}
    value=list(evaluated(model,reads([0,2,2000])).values())[-1]
    assert not value["eligibility"]["temporal"] and not value["anomaly"]


@pytest.mark.parametrize("variant",["cold","sparse","missing_identity","new_incarnation","late","duplicate"])
def test_temporal_and_sketch_abstain_on_insufficient_or_invalid_context(calibrated,variant):
    rows=reads([0,2,2000])
    current=None
    if variant=="cold":rows=rows[-1:]
    if variant=="sparse":rows=rows[-2:]
    if variant=="missing_identity":
        for row in rows:row["projection"]["device"]["boot_id"]=""
    if variant=="new_incarnation":rows[-1]["projection"]["process"]["start_identity"]="new-start"
    if variant=="late":
        rows[-1]["event_time"]=rows[0]["event_time"]-1
        current=[rows[-1]["event_id"]]
    if variant=="duplicate":
        with pytest.raises(ValueError,match="unique"):evaluated(calibrated,[rows[0],rows[0]])
        return
    result=list(evaluated(calibrated,rows,current=current).values())[-1]
    assert not result["anomaly"] and not result["eligibility"]["temporal"] and not result["eligibility"]["sketch"]


def test_runtime_anomalies_do_not_learn_or_poison_frozen_reference(calibrated):
    before=copy.deepcopy(calibrated)
    attack=reads([0,2,2000])
    first=evaluated(calibrated,attack)
    for _ in range(20):assert evaluated(calibrated,attack)==first
    assert calibrated==before and calibrated["baseline"]["automatic_learning"] is False


def test_late_arrival_inside_current_batch_is_not_silently_sorted_into_timely_context(calibrated):
    rows=reads([0,2,1])
    for number,row in enumerate(rows):row["received"]=1700020000+number
    value=evaluated(calibrated,rows)[rows[-1]["event_id"]]
    assert value["evidence"]["late_event"] and not value["eligibility"]["temporal"] and not value["eligibility"]["sketch"]
    assert not value["anomaly"]


def test_rolling_context_is_original_bound_and_not_republished(calibrated):
    rows=reads(list(range(0,24,2)))
    current=[rows[-1]["event_id"]]
    values=evaluated(calibrated,rows,current=current)
    assert values[current[0]]["anomaly"]
    assert all(not values[r["event_id"]]["anomaly"] for r in rows[:-1])


@pytest.fixture
def cpu_model(store):
    rows=[{k:v for k,v in normal(i).items() if k!="projection"} for i in range(48)]
    source=source_registry.save(store,actor("admin",role="admin"),{"index":"public","product":"json","account":"fusion-test","realm":"fusion-lab","credential_ref":"env:SAPIENTIA_CONNECTOR_FUSION_TEST","version":0})
    connector_runtime.intake(store,actor("admin",role="admin"),source["id"],{"version":1,"events":rows,"cursor":"normal","checkpoint_version":0})
    store.flush()
    model=research.train(store,actor(),{"name":"frozen-three-component-model","indexes":["public"],"training_ids":[f"research-{i}" for i in range(32)],"validation_ids":[f"research-{i}" for i in range(32,48)],"epochs":80,"seeds":[17],"normal_training_confirmed":True})
    research.review(store,actor("reviewer"),model["id"],{"approve":True,"mode":"live","reason":"Independent frozen-normal fusion component and calibration review"})
    return model,source


def admit(store,source,rows,checkpoint=1):
    values=[{k:v for k,v in row.items() if k!="projection"} for row in rows]
    connector_runtime.intake(store,actor("admin",role="admin"),source["id"],{"version":1,"events":values,"cursor":"runtime-"+str(checkpoint),"checkpoint_version":checkpoint})
    store.flush()


@pytest.mark.parametrize("kind",["temporal","sketch","normal"])
def test_real_cpu_model_low_ce_temporal_or_sketch_changes_live_publication(store,cpu_model,kind):
    model,source=cpu_model
    times=[0,2,2000] if kind=="temporal" else list(range(0,24,2)) if kind=="sketch" else [0,2,4]
    rows=reads(times)
    admit(store,source,rows)
    run=research.analyze(store,actor(),{"event_ids":[r["event_id"] for r in rows],"model_id":model["id"]})
    assert all(not r["relation_anomaly"] for r in run["results"])
    assert run["decision"]["publishable"] is (kind!="normal")
    if kind!="normal":
        assert not run["decision"]["ablation"]["without_"+kind]["anomaly"]
        signal=advanced_intelligence.publish_run(store,actor(),run["id"])
        assert signal["kind"]=="ml" and not signal["automatic_endpoint_authorization"]
        with principal.transaction(store,actor(),write=True) as (db,fresh):
            assert research.validate_publication(store,db,fresh,run["id"],memo={})
    else:
        with pytest.raises(PermissionError):advanced_intelligence.publish_run(store,actor(),run["id"])
    with store.control() as db:assert db.execute("SELECT count(*) FROM endpoint_responses").fetchone()[0]==0


@pytest.mark.parametrize("field",["component","evidence","decision","raw"])
def test_rehashed_fusion_result_forgery_rejected_by_real_original_replay(store,cpu_model,field):
    model,source=cpu_model;rows=reads([0,2,2000]);admit(store,source,rows)
    run=research.analyze(store,actor(),{"event_ids":[r["event_id"] for r in rows],"model_id":model["id"]})
    if field=="component":run["results"][-1]["fusion"]["components"]["temporal"]=100
    elif field=="evidence":run["results"][-1]["fusion"]["evidence"]["normal_transition_count"]=12345
    elif field=="raw":run["results"][-1]["fusion"]["raw_components"]["sketch"]=9
    else:run["decision"]["score"]=100
    with store.control() as db:db.execute("UPDATE research_behavior_runs SET body=?,digest=? WHERE id=?",(encode(run),fusion.digest(run),run["id"]))
    with principal.transaction(store,actor(),write=True) as (db,fresh), pytest.raises(ConflictError,match="fusion"):
        research.validate_publication(store,db,fresh,run["id"])


def test_original_legacy_ce_contract_is_not_silently_upgraded(store,cpu_model):
    model,source=cpu_model
    with store.control() as db:
        row=db.execute("SELECT snapshot FROM research_behavior_models WHERE id=?",(model["id"],)).fetchone()
        snapshot=json.loads(row[0]);snapshot.pop("fusion")
        snapshot["feature_contract_digest"]=research.LEGACY_FEATURE_CONTRACT_DIGEST
        db.execute("UPDATE research_behavior_models SET state='pending',snapshot=?,digest=? WHERE id=?",(encode(snapshot),fusion.digest(snapshot),model["id"]))
    reviewed=research.review(store,actor("reviewer"),model["id"],{"approve":True,"mode":"live","reason":"Explicit legacy CPU relation gate review"})
    assert reviewed["detection_gate"]["version"]=="legacy-0.17-ce"
    rows=reads([0,2,2000]);admit(store,source,rows)
    run=research.analyze(store,actor(),{"event_ids":[r["event_id"] for r in rows],"model_id":model["id"]})
    assert run["decision"]["method"]=="cpu_edge_relation_cross_entropy" and not run["decision"]["anomaly"]
    assert all("fusion" not in r for r in run["results"])


def test_compaction_and_outbox_gc_preserve_current_original_context(store,cpu_model):
    model,source=cpu_model;rows=reads([0,2,4]);admit(store,source,rows)
    due=research.run_due(store,budget=10)
    assert due["processed"]==3 and not due["runs"][0]["decision"]["anomaly"]
    archived=lifecycle.archive_runs(store,actor(),[due["runs"][0]["id"]],"Normal detail may compact while original context remains")["items"][0]
    assert archived["state"]=="archived"
    lifecycle.run_due(store)
    with store.control() as db:
        ids=[r["event_id"] for r in rows]
        assert research.protected_ids(db,"a",ids)==set(ids)
        assert db.execute("SELECT count(*) FROM research_behavior_outbox").fetchone()[0]==0
        assert db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE kind='research_behavior_context' AND record_id=?",(model["id"],)).fetchone()[0]==3
    newer=reads([2000],offset=200);admit(store,source,newer,checkpoint=2)
    next_run=research.run_due(store,budget=10)["runs"][0]
    assert len(next_run["event_ids"])==4 and next_run["decision"]["anomaly"]


def test_expired_previous_context_is_diagnosed_and_does_not_poison_new_current(store,cpu_model):
    _model,source=cpu_model;rows=reads([0,2,4]);admit(store,source,rows)
    research.run_due(store,budget=10)
    with store.control() as db:db.execute("DELETE FROM receipts WHERE tenant='a' AND event_id=?",(rows[0]["event_id"],))
    newer=reads([6],offset=200);admit(store,source,newer,checkpoint=2)
    due=research.run_due(store,budget=10)
    assert due["processed"]==1 and not due["errors"]
    run=due["runs"][0]
    assert run["fusion_context"]["excluded"][0]["event_id"]==rows[0]["event_id"]
    assert rows[0]["event_id"] not in run["event_ids"] and newer[0]["event_id"] in run["event_ids"]


def test_revoked_runtime_context_source_is_dropped_without_revoking_different_training_source(store,cpu_model):
    _model,training_source=cpu_model
    context_source=source_registry.save(store,actor("admin",role="admin"),{"index":"public","product":"json","account":"context-only-source","realm":"fusion-lab","credential_ref":"env:SAPIENTIA_CONNECTOR_FUSION_CONTEXT","version":0})
    rows=reads([0,2,4]);admit(store,context_source,rows,checkpoint=0)
    research.run_due(store,budget=10)
    source_registry.revoke(store,actor("admin",role="admin"),context_source["id"],1)
    newer=reads([6],offset=200);admit(store,training_source,newer,checkpoint=1)
    due=research.run_due(store,budget=10)
    assert due["processed"]==1 and not due["errors"]
    run=due["runs"][0]
    assert len(run["fusion_context"]["excluded"])==3 and run["event_ids"]==[newer[0]["event_id"]]
    assert not run["results"][0]["fusion"]["eligibility"]["temporal"]


def test_tx_local_memo_only_caches_compute_and_rechecks_current_authority(store,cpu_model,monkeypatch):
    model,source=cpu_model;rows=reads([0,2,2000]);admit(store,source,rows)
    run=research.analyze(store,actor(),{"event_ids":[r["event_id"] for r in rows],"model_id":model["id"]})
    calls=[];original=research._worker
    def counted(payload,*args):
        calls.append(payload["operation"])
        return original(payload,*args)
    monkeypatch.setattr(research,"_worker",counted)
    with principal.transaction(store,actor(),write=True) as (db,fresh):
        memo={}
        assert research.validate_publication(store,db,fresh,run["id"],memo=memo)
        assert research.validate_publication(store,db,fresh,run["id"],memo=memo)
        assert calls==["research_infer"]
        db.execute("UPDATE source_registry SET state='revoked' WHERE id=?",(source["id"],))
        with pytest.raises(PermissionError):research.validate_publication(store,db,fresh,run["id"],memo=memo)


def test_context_original_cannot_be_counted_again_as_independent_composite_evidence(store,cpu_model):
    model,source=cpu_model
    rows=reads([0,2,4])
    def reviewed(data):
        value=intelligence.save_policy(store,actor(),data)
        intelligence.review_policy(store,actor("reviewer"),value["id"],{"version":1,"approve":True,"reason":"Independent input ancestry inspection"})
        return value["id"]
    atomic=reviewed({"name":"Prior context atomic","kind":"atomic","indexes":["public"],"enabled":True,"filters":[{"field":"event.event_id","op":"eq","value":rows[0]["event_id"]}]})
    composite=reviewed({"name":"Reject overlapping prior context evidence","kind":"composite","indexes":["public"],"enabled":True,
        "inputs":[{"rule_id":"ml:research:"+model["id"],"kind":"ml"},{"rule_id":atomic,"kind":"atomic"}],"join_on":"process","minimum_independent_groups":2,"window":3000})
    admit(store,source,rows)
    first=research.run_due(store,budget=10)["runs"][0]
    assert not first["decision"]["anomaly"]
    newer=reads([2000],offset=200)
    admit(store,source,newer,checkpoint=2)
    run=research.run_due(store,budget=10)["runs"][0]
    assert run["decision"]["anomaly"] and rows[0]["event_id"] in run["event_ids"]
    advanced_intelligence.publish_run(store,actor(),run["id"])
    for _ in range(4):intelligence.run_due(store,budget=2,max_runs=8,include_ml=False)
    values=intelligence.signals(store,actor(),count=100)["items"]
    assert any(s["rule_id"]==atomic for s in values)
    assert not any(s["rule_id"]==composite for s in values)
