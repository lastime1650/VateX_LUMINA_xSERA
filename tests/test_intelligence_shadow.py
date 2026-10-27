"""Frozen graph/composite/model evidence replay without operational side effects."""

import copy
import importlib.util
import json
import time

import pytest

from sapientia import access, connector_runtime, cpu_ml, intelligence, intelligence_shadow as ish, migrations, source_registry
from sapientia.storage import CapacityError, ConflictError
from tests.test_backend_upgrade import lab, actor


@pytest.fixture
def frozen_lab(lab,monkeypatch):
    monkeypatch.setitem(migrations.SUPPORTED,"intelligence_shadow",1)
    ish.initialize(lab)
    return lab


def seed(store,broken_boot=False,precision=None):
    source=source_registry.save(store,actor(),{"index":"public","product":"json","account":"asset","realm":"lab","credential_ref":"env:SAPIENTIA_CONNECTOR_LAB","version":0})
    at=time.time()-100
    events=[]
    for n,action in enumerate(("launch","connect","write")):
        events.append({"event_id":action,"event_time":at+n,"host":"asset","raw":{"stage":action,"xdr":{"data":{
            "event":{"action":"process_created" if n==0 else "network_connection" if n==1 else "file_created"},
            "host":{"id":"device","boot_id":"other" if broken_boot and n==1 else "boot"},
            "process":{"guid":"P" if n==0 else "C","start_identity":"root" if n==0 else "child","parent":{"guid":"P","start_identity":"root"}}}}}})
        if precision is not None:
            events[-1]["raw"]["xdr"]["data"]["event"]["timestamp_precision_seconds"]=precision
    connector_runtime.intake(store,actor(),source["id"],{"version":1,"events":events,"cursor":"three","checkpoint_version":0})
    while store.flush():
        pass
    return source,at


def atomic(identifier,stage):
    return {"id":identifier,"definition":{"name":identifier,"kind":"atomic","indexes":["public"],"enabled":True,
                "filters":[{"field":"raw.stage","op":"eq","value":stage}]}}


def composite(identifier,inputs,minimum=2,join="story"):
    return {"id":identifier,"definition":{"name":identifier,"kind":"composite","indexes":["public"],"enabled":True,
                "inputs":[{"rule_id":i} for i in inputs],"minimum_independent_groups":minimum,"join_on":join,"window":300}}


def request(at,**more):
    return {"start":at-1,"end":at+10,"indexes":["public"],"baseline_policies":[],
            "candidate_policies":[atomic("A","launch"),atomic("B","connect"),atomic("C","write"),
                                   composite("AB",["A","B"]),composite("ABC",["AB","C"])],**more}


def state(store):
    with store.control() as db:
        return {name:db.execute("SELECT count(*) FROM "+name).fetchone()[0] for name in
                ("intelligence_signals","intelligence_stories","intelligence_story_nodes","intelligence_story_edges","intelligence_event_outbox",
                 "intelligence_decisions","intelligence_evidence_refs","incidents","risk_contributions","soar_runs","endpoint_responses","cpu_ml_models","cpu_ml_runs")}


def test_pure_frozen_staged_composites_parent_graph_and_identical_replay(frozen_lab):
    source,at=seed(frozen_lab)
    before=state(frozen_lab)
    result=ish.run_compare(frozen_lab,actor(),request(at))
    assert result["status"]=="complete" and not result["live_effects"]
    signals=result["candidate"]["signals"]
    assert {s["rule_id"] for s in signals}=={"A","B","C","AB","ABC"}
    last=next(s for s in signals if s["rule_id"]=="ABC")
    assert last["event_ids"]==["connect","launch","write"]
    assert len(last["parent_signal_ids"])==2 and last["evidence_dependency"]["disjoint_original_groups"]==2
    assert any(e["relation"]=="reported_parent" for e in result["candidate"]["graph"]["edges"])
    assert len({s["story_id"] for s in signals})==1
    connector_runtime.intake(frozen_lab,actor(),source["id"],{"version":1,"events":[{"event_id":"late","event_time":at+3,"host":"asset","raw":{"stage":"launch"}}],"cursor":"four","checkpoint_version":1})
    frozen_lab.flush()
    assert ish.replay(frozen_lab,actor(),result["id"])["identical"]
    assert state(frozen_lab)==before


def test_same_original_and_partial_composite_ancestry_cannot_inflate_independent_groups(frozen_lab):
    _,at=seed(frozen_lab)
    rules=[atomic("A","launch"),atomic("A2","launch"),atomic("B","connect"),
           composite("same",["A","A2"]),composite("AB",["A","B"]),composite("reuse",["AB","B"])]
    result=ish.run_compare(frozen_lab,actor(),request(at,candidate_policies=rules))
    produced={s["rule_id"] for s in result["candidate"]["signals"]}
    assert "AB" in produced and "same" not in produced and "reuse" not in produced
    rejected={d["rule_id"] for d in result["candidate"]["diagnostics"] if d["reason"]=="dependent_or_unordered_evidence"}
    assert rejected=={"same","reuse"}


def test_composite_inspects_independent_alternative_after_dependent_nearest_signal(frozen_lab):
    _,at=seed(frozen_lab)
    choice=composite("choice",["A","placeholder"])
    choice["definition"]["inputs"]=[{"rule_id":"A"},{"kind":"atomic"}]
    result=ish.run_compare(frozen_lab,actor(),request(at,candidate_policies=[atomic("A","launch"),atomic("A2","launch"),atomic("B","connect"),choice]))
    picked=next(s for s in result["candidate"]["signals"] if s["rule_id"]=="choice")
    assert picked["event_ids"]==["connect","launch"]
    assert picked["evidence_dependency"]["disjoint_original_groups"]==2


def test_reported_parent_boot_mismatch_keeps_stories_separate(frozen_lab):
    _,at=seed(frozen_lab,broken_boot=True)
    result=ish.run_compare(frozen_lab,actor(),request(at))
    assert not any(s["rule_id"]=="AB" for s in result["candidate"]["signals"])
    parent_edges=[e for e in result["candidate"]["graph"]["edges"] if e["relation"]=="reported_parent"]
    assert len(parent_edges)==1
    assert all("connect" not in e["event_ids"] for e in parent_edges)


def test_shadow_topology_cycle_budget_and_authority_fail_without_partial_rows(frozen_lab,monkeypatch):
    _,at=seed(frozen_lab)
    cyclic=[atomic("A","launch"),composite("X",["A","Y"]),composite("Y",["A","X"])]
    with pytest.raises(ValueError,match="cycle"):
        ish.run_compare(frozen_lab,actor(),request(at,candidate_policies=cyclic))
    with pytest.raises(CapacityError):
        ish.run_compare(frozen_lab,actor(),request(at,max_events=1))
    monkeypatch.setattr(ish,"MAX_COMBINATIONS",0)
    with pytest.raises(CapacityError,match="no partial success"):
        ish.run_compare(frozen_lab,actor(),request(at))
    with frozen_lab.control() as db:
        assert db.execute("SELECT count(*) FROM intelligence_shadow_runs").fetchone()[0]==0
    monkeypatch.setattr(ish,"MAX_COMBINATIONS",100000)
    result=ish.run_compare(frozen_lab,actor(),request(at))
    with pytest.raises(KeyError):
        ish.get(frozen_lab,actor("foreign","b"),result["id"])
    access.set_for_user(frozen_lab,actor("peer"),"owner",["other"])
    with pytest.raises(PermissionError):
        ish.replay(frozen_lab,actor("peer"),result["id"])


def model_seed(store):
    at=1704110400
    events=[{"event_id":f"normal-{i}","event_time":at+i,"index":"public","host":"host","raw":{"command_line":"echo normal","dest_port":443,"dest_ip":"10.1.0.2","process_depth":1}} for i in range(32)]
    events.append({"event_id":"abnormal","event_time":at+33,"index":"public","host":"host","raw":{"command_line":"x"*8192,"dest_port":65535,"dest_ip":"8.8.8.8","process_depth":32,"file_path":"C:/file"}})
    store.ingest("a",events); store.flush()
    model=cpu_ml.train(store,actor(),{"name":"frozen-model","indexes":["public"],"training_ids":[f"normal-{i}" for i in range(24)],
            "validation_ids":[f"normal-{i}" for i in range(24,32)],"epochs":60,"normal_training_confirmed":True})
    return at,model


def test_actual_pinned_cpu_weights_infer_without_live_model_runs_and_replay_after_original_retirement(frozen_lab):
    if importlib.util.find_spec("torch") is None:
        pytest.skip("Optional real CPU PyTorch runtime unavailable")
    at,model=model_seed(frozen_lab)
    before=state(frozen_lab)
    result=ish.run_compare(frozen_lab,actor(),{"start":at-1,"end":at+40,"indexes":["public"],"baseline_policies":[],"candidate_policies":[],"candidate_model_id":model["id"]})
    job=result["candidate"]["ml_job"]
    assert job["status"]=="completed" and job["executed"] and job["device"]=="cpu"
    assert any(p["event_id"]=="abnormal" and p["anomaly"] for p in job["predictions"])
    assert any(s["kind"]=="ml" and s["event_ids"]==["abnormal"] for s in result["candidate"]["signals"])
    assert state(frozen_lab)==before
    # The immutable frozen execution, unlike live ML inference, does not fetch
    # originals or current model weights again during a historical replay.
    with frozen_lab.control() as db:
        db.execute("DELETE FROM receipts WHERE tenant='a'")
        db.execute("DELETE FROM cpu_ml_models WHERE id=?",(model["id"],))
    assert ish.replay(frozen_lab,actor(),result["id"])["identical"]


def test_incompatible_requested_cpu_model_is_explicitly_excluded_and_core_replay_stays_complete(frozen_lab,monkeypatch):
    _,at=seed(frozen_lab)
    real_model={"id":"frozen-model","owner":"owner","indexes":["public"],"revision":1,"model_digest":"d"*64,
                "feature_schema":cpu_ml.FEATURE_SCHEMA,"weights":{},"weights_digest":"a"*64,"threshold":0.1,"framework_version":"frozen","definition_digest":"b"*64}
    monkeypatch.setattr(ish,"_model",lambda db,actor,indexes,identifier:real_model if identifier else None)
    monkeypatch.setattr(cpu_ml,"runtime_status",lambda **kw:{"available":False,"status":"시스템에서 호환되지 않음"})
    result=ish.run_compare(frozen_lab,actor(),request(at,candidate_model_id="frozen-model"))
    assert result["status"]=="complete" and result["candidate"]["ml_job"]["status"]=="excluded"
    assert result["candidate"]["ml_job"]["compatibility"]=="시스템에서 호환되지 않음"
    assert len(result["candidate"]["signals"])==5
    monkeypatch.setattr(cpu_ml,"runtime_status",lambda **kw:pytest.fail("Excluded frozen job must not execute after later runtime installation"))
    assert ish.replay(frozen_lab,actor(),result["id"])["identical"]


@pytest.mark.parametrize("precision,expected",[(None,False),(.6,False),(.01,True)])
def test_frozen_strict_clock_uses_known_nonoverlapping_reported_precision(frozen_lab,precision,expected):
    _,at=seed(frozen_lab,precision=precision)
    ordered=composite("strict",["A","B"])
    ordered["definition"].update(ordered=True,clock_policy="strict")
    result=ish.run_compare(frozen_lab,actor(),request(at,candidate_policies=[atomic("A","launch"),atomic("B","connect"),ordered]))
    assert any(s["rule_id"]=="strict" for s in result["candidate"]["signals"]) is expected


def test_stored_parent_pins_are_frozen_caller_pins_forbidden_and_parent_change_blocks_new_compare(frozen_lab):
    _,at=seed(frozen_lab)
    ids=[]
    for data in (atomic("A","launch"),atomic("B","connect")):
        saved=intelligence.save_policy(frozen_lab,actor(),{**data["definition"],"version":0})
        intelligence.review_policy(frozen_lab,actor("peer"),saved["id"],{"version":1,"approve":True,"reason":"Synthetic original-bound parent reviewed"})
        ids.append(saved["id"])
    data=composite("current",ids)
    saved=intelligence.save_policy(frozen_lab,actor(),{**data["definition"],"version":0})
    intelligence.review_policy(frozen_lab,actor("peer"),saved["id"],{"version":1,"approve":True,"reason":"Synthetic bounded composite reviewed"})
    ids.append(saved["id"])
    body={"start":at-1,"end":at+10,"indexes":["public"],"policy_ids":ids}
    result=ish.run_compare(frozen_lab,actor(),body)
    with frozen_lab.control() as db:
        snapshot=json.loads(db.execute("SELECT snapshot FROM intelligence_shadow_runs WHERE id=?",(result["id"],)).fetchone()[0])
    frozen_comp=next(p for p in snapshot["baseline"] if p["id"]==saved["id"])
    assert set(frozen_comp["definition"]["input_revisions"])==set(ids[:2])
    forged=composite("forged",["A","B"])
    forged["definition"]["input_revisions"]={"A":{"version":999,"definition_digest":"a"*64}}
    with pytest.raises(ValueError,match="Unknown"):
        ish.run_compare(frozen_lab,actor(),request(at,candidate_policies=[atomic("A","launch"),atomic("B","connect"),forged]))
    intelligence.save_policy(frozen_lab,actor(),{**atomic("A","write")["definition"],"version":1},ids[0])
    with pytest.raises(ConflictError,match="parent"):
        ish.run_compare(frozen_lab,actor(),body)
    assert ish.replay(frozen_lab,actor(),result["id"])["identical"]
