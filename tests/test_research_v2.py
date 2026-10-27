"""Versioned CPU and original-bound multi-day detection checks."""

import copy
import json

import pytest
from test_research_behavior import actor, definition, event, seed
from test_research_behavior import store as _store_fixture

from sapientia import connector_runtime, principal, source_registry
from sapientia import research_behavior as research
from sapientia import research_features_v2 as features
from sapientia import research_fusion_v2 as fusion

store = _store_fixture


def test_v2_action_free_features_and_legacy_width_preserved():
    one=event(1);other=copy.deepcopy(one)
    other.update(host="different",event_id="other")
    other["raw"].update(action="network_connect",ground_truth="attack",campaign="heldout")
    assert features.features(one)["values"]==features.features(other)["values"]
    assert features.features(one)["target"]!=features.features(other)["target"]
    assert len(features.features(one)["values"])==64
    assert len(research.event_features(one)["values"])==24


def _gate():
    normal=[event(i,raw={"action":"file_read" if i%2==0 else "file_write"}) for i in range(32)]
    return {"schema":fusion.SCHEMA,"method":fusion.METHOD,"contract_digest":fusion.CONTRACT_DIGEST,
        "baseline":fusion.baseline(normal),"calibration":{"relation":1,"temporal":1,"sketch":.1},"threshold":1,"weights":fusion.WEIGHTS}


def test_multiday_evidence_outside_short_window_changes_actual_decision():
    gate=_gate();rows=[]
    for i in range(20):
        rows.append(event(200+i,event_time=1700000000+i*20000,raw={"action":"network_connect","process_guid":f"new-{i}","process_start_identity":f"start-{i}"}))
    current=rows[-1]
    full=fusion.evaluate([current],{current["event_id"]:0},gate,[current["event_id"]],history_rows=rows)[current["event_id"]]
    short=fusion.evaluate([current],{current["event_id"]:0},gate,[current["event_id"]],history_rows=rows[-4:])[current["event_id"]]
    assert full["anomaly"] and full["components"]["relation"]==0 and full["components"]["temporal"]==0
    assert not full["ablations"]["without_sketch"]["anomaly"] and not short["anomaly"]
    assert full["evidence"]["windows"][-1]["observed_span_seconds"]>=302400
    assert not full["evidence"]["windows"][-1]["full_window_coverage_claimed"]


def test_exact_pattern_counts_correct_total_hash_collision(monkeypatch):
    gate=_gate();rows=[event(100+i,raw={"action":"network_connect"}) for i in range(8)]
    monkeypatch.setattr(fusion,"_bins",lambda counts,seed:([sum(counts.values())]+[0]*255,max(0,len(counts)-1)))
    result=fusion.evaluate(rows,{r["event_id"]:0 for r in rows},gate,[r["event_id"] for r in rows])
    window=result[rows[-1]["event_id"]]["evidence"]["windows"][0]
    assert window["dual_sketch_distances"]==[0,0] and window["exact_semantic_distance"]==1
    assert result[rows[-1]["event_id"]]["anomaly"]


def test_future_raw_watermark_only_suppresses_late_positive_components():
    gate=_gate()
    rows=[event(500+i,event_time=1700000100+i,received=200+i,raw={"action":"network_connect"}) for i in range(8)]
    guard=event(600,event_time=1700001000,received=100)
    result=fusion.evaluate(rows,{r["event_id"]:0 for r in rows},gate,[r["event_id"] for r in rows],history_rows=[guard,*rows])
    assert all(value["evidence"]["late_event"] and not value["anomaly"] for value in result.values())
    assert all(not value["eligibility"]["temporal"] and not value["eligibility"]["sketch"] for value in result.values())


def test_real_cpu_v2_train_live_review_long_replay_and_manual_cache_isolation(store):
    seed(store)
    trained=research.train(store,actor(),definition(gate_version="v2",epochs=12,seeds=[17]))
    assert trained["status"]=="completed" and trained["detection_gate"]["feature_width"]==64
    research.review(store,actor("reviewer"),trained["id"],{"approve":True,"mode":"live","reason":"Independent v2 review"})
    run=research.analyze(store,actor(),{"model_id":trained["id"],"event_ids":["research-100"]})
    assert run["long_evidence"]["count"]==1
    with principal.transaction(store,actor(),write=True) as (db,_):
        assert db.execute("SELECT count(*) FROM research_horizon_cache").fetchone()[0]==0
        verified=research.long_publication_evidence(store,db,actor(),run["id"])
        assert verified["event_ids"]==["research-100"]
        body=json.loads(db.execute("SELECT body FROM research_horizon_snapshots").fetchone()[0])
        assert body["coverage"]["max_originals"]==1024
    forged=copy.deepcopy(run);forged["long_evidence"]["count"]=2
    with store.control() as db:
        from sapientia.research_long_horizon import replay
        with pytest.raises(Exception,match="manifest digest/ancestry"):
            replay(store,db,actor(),forged)


def live_long_fixture(store):
    """Reusable actual CPU/runtime fixture, 48 raw ancestors vs short32."""
    source=source_registry.save(store,actor("admin",role="admin"),{"index":"public","product":"json","account":"long-fixture","realm":"long-lab","credential_ref":"env:SAPIENTIA_CONNECTOR_LONG_FIXTURE","version":0})
    normals=[event(3000+i,event_time=1700000000+i,raw={"action":"file_read" if i%2==0 else "file_write"}) for i in range(48)]
    def admit(rows,checkpoint):
        connector_runtime.intake(store,actor("admin",role="admin"),source["id"],{"version":1,"events":[{k:v for k,v in r.items() if k!="projection"} for r in rows],"cursor":f"long-{checkpoint}","checkpoint_version":checkpoint});store.flush()
    admit(normals,0)
    model=research.train(store,actor(),definition(name="long-window-normal",gate_version="v2",training_ids=[r["event_id"] for r in normals[:32]],validation_ids=[r["event_id"] for r in normals[32:]],epochs=16,seeds=[17]))
    research.review(store,actor("reviewer"),model["id"],{"approve":True,"mode":"live","reason":"Independent long-window normal baseline review"})
    rows=[event(4000+i,event_time=1700100000+i*10000,raw={"process_guid":f"window-process-{i}","process_start_identity":f"start-{i}"}) for i in range(48)]
    admit(rows,1);runs=[]
    for _ in range(3):
        due=research.run_due(store,budget=10,max_runs=1)
        assert not due["errors"];runs.extend(due["runs"])
    return model,source,runs[-1],rows


def test_cpu_live_48_original_replay_manifest_and_current_source_recheck(store):
    _model,source,run,rows=live_long_fixture(store)
    assert len(run["event_ids"])==32 and run["long_evidence"]["count"]==48
    assert run["decision"]["anomaly"] and not run["decision"]["ablation"]["without_sketch"]["anomaly"]
    assert all(not r["relation_anomaly"] for r in run["results"])
    with principal.transaction(store,actor(),write=True) as (db,_):
        memo={};proof=research.long_publication_evidence(store,db,actor(),run["id"],memo=memo)
        assert len(proof["event_ids"])==48 and rows[0]["event_id"] not in run["event_ids"] and rows[0]["event_id"] in proof["event_ids"]
        assert db.execute("SELECT count(*) FROM research_horizon_cache").fetchone()[0]==48
        db.execute("UPDATE source_registry SET state='revoked' WHERE id=?",(source["id"],))
        with pytest.raises(PermissionError):research.long_publication_evidence(store,db,actor(),run["id"],memo=memo)


def test_exact_1024_snapshot_boundary_is_reconstructed_from_current_originals(store):
    from sapientia import research_long_horizon as horizon
    from sapientia.storage import encode
    seed(store)
    trained=research.train(store,actor(),definition(gate_version="v2",epochs=5,seeds=[17]))
    research.review(store,actor("reviewer"),trained["id"],{"approve":True,"mode":"live","reason":"Independent boundary fixture"})
    source=source_registry.save(store,actor("admin",role="admin"),{"index":"public","product":"json","account":"boundary-originals","realm":"long-lab","credential_ref":"env:SAPIENTIA_CONNECTOR_BOUNDARY","version":0})
    rows=[event(10000+i,event_time=1700100000+i*500,raw={"process_guid":f"boundary-{i}","process_start_identity":f"start-{i}"}) for i in range(1025)]
    for offset in range(0,len(rows),1000):
        connector_runtime.intake(store,actor("admin",role="admin"),source["id"],{"version":1,"events":[{k:v for k,v in r.items() if k!="projection"} for r in rows[offset:offset+1000]],"cursor":f"boundary-{offset}","checkpoint_version":offset//1000})
    while store.flush():pass
    originals=research._originals(store,actor(),[r["event_id"] for r in rows])
    # Seed only the tested bounded reference cache. Source records/receipts are
    # real admitted originals; this is a capacity test, not a throughput claim.
    with store.control() as db:
        model,_=research._verify_model(db,actor(),trained["id"],require_active=True)
        for eid,record in originals.items():
            db.execute("INSERT INTO research_horizon_cache VALUES(?,?,?,?,?,?,?,?)",(model["id"],"a",eid,"public",record["event_time"],record["received"],fusion.host_key(record),encode(research._proofs({eid:record})[0])))
    current=rows[-1]["event_id"];prepared=horizon.prepare(store,actor(),model,{current:originals[current]})
    assert prepared["descriptor"]["count"]==1024 and len(prepared["records"])==1024
    assert prepared["body"]["coverage"]["coverage_saturated"] and current in prepared["records"]
    assert prepared["body"]["coverage"]["observed_span_seconds"]>=500000
    assert not prepared["body"]["coverage"]["full_population_coverage_claimed"]


def test_incompatible_model_can_be_disabled_and_independently_retired_but_never_approved(store,monkeypatch):
    from sapientia import research_behavior_lifecycle as lifecycle
    seed(store)
    model=research.train(store,actor(),definition(gate_version="v2",epochs=5,seeds=[17]))
    monkeypatch.setattr(research,"V2_FEATURE_CONTRACT_DIGEST","f"*64)
    with pytest.raises(Exception,match="snapshot hash mismatch"):
        research.review(store,actor("reviewer"),model["id"],{"approve":True,"mode":"live","reason":"Stale cannot activate"})
    disabled=research.disable(store,actor(),model["id"],"Explicit incompatible model disable")
    assert disabled["state"]=="disabled" and not disabled["detection_gate"]["implementation_compatible"]
    retired=lifecycle.retire(store,actor("reviewer"),model["id"],"Independent incompatible-model retirement")
    assert retired["retired"] and retired["model_weights_and_provenance_retained"]


def test_canonical_snapshot_tampering_still_blocks_administrative_disable(store):
    seed(store);model=research.train(store,actor(),definition(gate_version="v2",epochs=5,seeds=[17]))
    with store.control() as db:
        snapshot=json.loads(db.execute("SELECT snapshot FROM research_behavior_models WHERE id=?",(model["id"],)).fetchone()[0])
        snapshot["epochs"]+=1;db.execute("UPDATE research_behavior_models SET snapshot=? WHERE id=?",(json.dumps(snapshot),model["id"]))
    with pytest.raises(Exception,match="snapshot hash mismatch"):research.disable(store,actor(),model["id"],"Tampering must fail closed")
