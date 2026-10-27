"""Actual frozen CPU weights with captured original windows, never live writes."""

import copy
import time
from pathlib import Path

import pytest

from sapientia import connector_runtime,cpu_ml,cpu_sequence,intelligence,intelligence_shadow as ish,source_registry
from tests.test_backend_upgrade import actor,lab as _backend_lab

lab=_backend_lab


@pytest.fixture
def sequence_model(lab):
    if not cpu_ml.runtime_status().get("available"):
        pytest.skip("CPU PyTorch unavailable on this host")
    source=source_registry.save(lab,actor(),{"index":"public","product":"json","account":"asset","realm":"lab","credential_ref":"env:SAPIENTIA_CONNECTOR_LAB","version":0})
    at=time.time()-1000;events=[];manifest={"name":"Frozen bounded sequence","indexes":["public"],"epochs":12,"reviewed_dataset":True}
    serial=0
    for split,count in (("training",32),("calibration",16),("holdout",16)):
        manifest[split]=[]
        for position in range(count):
            identifiers=[];host=split+str(position);attack=position%2
            for step,action in enumerate(("auth_failure" if attack else "auth_success","process_created","network_connection")):
                identifier=host+"-"+str(step);identifiers.append(identifier)
                events.append({"event_id":identifier,"event_time":at+serial*10+step,"host":host,"raw":{"xdr":{"data":{"event":{"action":action,"outcome":"failure" if attack else "success"},"host":{"id":host,"boot_id":"boot"},"process":{"guid":host+"-P","start_identity":host+"-birth","command_line":"powershell -enc BASE64" if attack else "editor.exe document.txt","depth":3},"destination":{"ip":"8.8.8.8" if attack else "10.2.3.4","port":443},"network":{"bytes_out":50000 if attack else 100}}}}})
            manifest[split].append({"scenario_id":host,"event_ids":identifiers,"label":attack,"family":split+"-"+str(attack),"host_group":host})
            serial+=1
    connector_runtime.intake(lab,actor(),source["id"],{"version":1,"events":events,"cursor":"sequence-corpus","checkpoint_version":0});lab.flush()
    model=cpu_sequence.train(lab,actor(),manifest)
    assert model["status"]=="completed"
    return model,manifest,at


def counts(store):
    with store.control() as db:
        return {name:db.execute("SELECT count(*) FROM "+name).fetchone()[0] for name in ("intelligence_signals","intelligence_stories","incidents","risk_contributions","cpu_sequence_models","cpu_sequence_runs","intelligence_evidence_refs")}


def data(model,manifest,at):
    return {"start":at+480,"end":at+500,"indexes":["public"],"baseline_policies":[],"candidate_policies":[],"candidate_sequence_model_id":model["id"],"sequence_windows":[{"event_ids":row["event_ids"]} for row in manifest["holdout"][:2]]}


def test_actual_frozen_sequence_weights_replay_after_live_mutations_without_run_case_or_signal_writes(lab,sequence_model):
    model,manifest,at=sequence_model
    before=counts(lab)
    result=ish.run_compare(lab,actor(),data(model,manifest,at))
    job=result["candidate"]["sequence_job"]
    assert job["status"]=="completed" and job["executed"] and job["windows"]==2
    assert job["tensor_shape"]==[2,3,55] and job["padding_masked"]
    assert {tuple(row["event_ids"]) for row in job["predictions"]}=={tuple(row["event_ids"]) for row in manifest["holdout"][:2]}
    assert counts(lab)==before
    with lab.control() as db:
        # Replay deliberately uses captured immutable weights, not these later
        # live rows. The tampered model is not used for another comparison.
        db.execute("UPDATE cpu_sequence_models SET snapshot='{}' WHERE id=?",(model["id"],))
    assert ish.replay(lab,actor(),result["id"])["identical"]
    assert counts(lab)==before


def test_frozen_sequence_rejects_cross_host_window_and_feature_tensor_spoof(lab,sequence_model):
    model,manifest,at=sequence_model
    request=data(model,manifest,at)
    request["sequence_windows"]=[{"event_ids":[manifest["holdout"][0]["event_ids"][0],manifest["holdout"][1]["event_ids"][1]]}]
    with pytest.raises(ValueError,match="cannot join"):
        ish.run_compare(lab,actor(),request)
    request=data(model,manifest,at)
    request["sequence_windows"][0]["features"]=[[1.0]*55]*3
    with pytest.raises(ValueError,match="only"):
        ish.run_compare(lab,actor(),request)


@pytest.mark.parametrize("filename,engine_key",[
    ("cpu_sequence_worker.py","sequence_worker"),
    ("cpu_ml_limits.py","cpu_limits"),
    ("cpu_model_memo.py","cpu_model_memo"),
    ("ml_datasets.py","ml_dataset_authority"),
    ("cpu_sequence_features.py","sequence_features"),
    ("storage.py","canonical_storage"),
    ("release_manifest.py","manifest"),
])
def test_changed_frozen_worker_dependency_refused_before_cpu_replay(lab,sequence_model,monkeypatch,filename,engine_key):
    model,manifest,at=sequence_model
    result=ish.run_compare(lab,actor(),data(model,manifest,at))
    with lab.control() as db:
        saved=db.execute("SELECT snapshot FROM intelligence_shadow_runs WHERE id=?",(result["id"],)).fetchone()
        import json
        engine=json.loads(saved[0])["engine"]
        replay_count=db.execute("SELECT count(*) FROM intelligence_shadow_replays").fetchone()[0]
    assert engine[engine_key]==ish.release_manifest.hash_file(Path(ish.__file__).with_name(filename))
    before=counts(lab)
    actual_hash=ish.release_manifest.hash_file
    monkeypatch.setattr(ish.release_manifest,"hash_file",lambda path:"0"*64 if Path(path).name==filename else actual_hash(path))

    def forbidden(*args,**kwargs):
        pytest.fail("Engine mismatch must stop before frozen comparison or CPU replay")

    monkeypatch.setattr(ish,"_compare",forbidden)
    monkeypatch.setattr(cpu_sequence,"frozen_infer",forbidden)
    with pytest.raises(ish.ConflictError,match="evaluator changed"):
        ish.replay(lab,actor(),result["id"])
    assert counts(lab)==before
    with lab.control() as db:
        assert db.execute("SELECT count(*) FROM intelligence_shadow_replays").fetchone()[0]==replay_count


def test_model_parent_pin_is_server_derived_and_live_disable_prevents_completion(lab,sequence_model,monkeypatch):
    model,_,_=sequence_model
    # Exercise the policy controller independently of the assessment gate,
    # which is tested by the sequence model/lifecycle tests. The model loader
    # still validates real immutable source/weight/feature provenance.
    real_load=cpu_sequence._load
    monkeypatch.setattr(cpu_sequence,"_load",lambda db,who,identifier,require_review=False:real_load(db,who,identifier,False))
    definition={"name":"Pinned model parent","kind":"composite","indexes":["public"],"enabled":True,"inputs":[{"kind":"ml","rule_id":"ml:sequence:"+model["id"]},{"kind":"atomic","rule_id":"network"}],"join_on":"entity","minimum_independent_groups":2}
    created=intelligence.save_policy(lab,actor(),definition)
    stored=next(row for row in intelligence.policies(lab,actor()) if row["id"]==created["id"])
    pin=stored["definition"]["input_models"]["ml:sequence:"+model["id"]]
    assert pin["id"]==model["id"] and pin["digest"]==model["digest"] and pin["revision"]==model["revision"]
    with pytest.raises(ValueError,match="Unknown"):
        intelligence.save_policy(lab,actor(),{**definition,"input_models":copy.deepcopy(stored["definition"]["input_models"])})
    intelligence.review_policy(lab,actor("peer"),created["id"],{"version":1,"approve":True,"reason":"Independent source/feature model pin review"})
    monkeypatch.setattr(cpu_sequence,"_load",real_load)
    intelligence._composites(lab,deadline=time.monotonic()+1)
    with lab.control() as db:
        row=db.execute("SELECT * FROM intelligence_composite_state WHERE id=?",(created["id"],)).fetchone()
        assert row["error"] and db.execute("SELECT count(*) FROM intelligence_signals WHERE rule_id=?",(created["id"],)).fetchone()[0]==0
