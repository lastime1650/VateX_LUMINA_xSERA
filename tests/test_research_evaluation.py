"""Detached labels, strict holdout, actual CPU metrics and reviewed replacement."""

import copy
import json

import pytest
from test_research_behavior import actor
from test_research_behavior import store as _store_fixture

from sapientia import connector_runtime, research_synthetic, source_registry
from sapientia import research_behavior as research
from sapientia import research_evaluation as evaluation
from sapientia import research_rebaseline as rebaseline
from sapientia.storage import ConflictError

store = _store_fixture


def cohort(store):
    manifest,events=research_synthetic.generate(1200,901)
    chosen=[s for split,count in (("training",16),("validation",8),("test",8)) for s in [v for v in manifest["scenarios"] if v["split"]==split][:count]]
    ids={e for s in chosen for e in s["event_ids"]};events=[e for e in events if e["event_id"] in ids];manifest["scenarios"]=chosen
    source=source_registry.save(store,actor("admin",role="admin"),{"index":"public","product":"json","account":"evaluation-fixture","realm":"synthetic","credential_ref":"env:SAPIENTIA_CONNECTOR_EVAL_FIXTURE","version":0})
    connector_runtime.intake(store,actor("admin",role="admin"),source["id"],{"version":1,"events":events,"cursor":"eval-fixture","checkpoint_version":0});store.flush()
    dataset=evaluation.save_dataset(store,actor(),manifest)
    train=[e for s in chosen if s["split"]=="training" for e in s["event_ids"]];validation=[e for s in chosen if s["split"]=="validation" for e in s["event_ids"]]
    model=research.train(store,actor(),{"name":"Evaluation model","indexes":["public"],"training_ids":train,"validation_ids":validation,"epochs":35,"seeds":[17],"normal_training_confirmed":True,"gate_version":"v2"})
    return dataset,model,source,manifest


def test_actual_cpu_holdout_metrics_ablation_and_no_publication_or_cache_updates(store):
    dataset,model,source,manifest=cohort(store)
    result=evaluation.evaluate(store,actor(),{"dataset_id":dataset["id"],"model_id":model["id"]})
    assert len(result["scenario_results"])==8 and result["cpu_inference_ms"]>0
    assert sum(result["metrics"][k] for k in ("tp","fp","fn","tn"))==8
    assert result["metrics"]["recall"]["denominator"]==4
    assert result["metrics"]["false_positive_rate"]["denominator"]==4
    assert set(result["metrics"]["ablation"])=={"relation","temporal","sketch"}
    assert evaluation.listing(store,actor(),"datasets")["items"][0]["scenario_count"]==32
    assert evaluation.listing(store,actor(),"runs")["items"][0]["model_id"]==model["id"]
    assert not result["publishable"] and not result["runtime_state_mutated"] and not result["actual_field_performance_verified"]
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM research_behavior_runs").fetchone()[0]==0
        assert db.execute("SELECT count(*) FROM research_horizon_cache").fetchone()[0]==0
    bad=copy.deepcopy(manifest);bad["scenarios"][-1]["family"]=bad["scenarios"][0]["family"]
    with pytest.raises(ValueError,match="Independent split overlap"):evaluation.save_dataset(store,actor(),bad)
    source_registry.revoke(store,actor("admin",role="admin"),source["id"],1)
    with pytest.raises((PermissionError,ConflictError)):evaluation.dataset(store,actor(),dataset["id"],with_records=True)


def test_wilson_small_samples_and_zero_precision_are_explicit():
    assert evaluation.wilson(0,0)["estimate"] is None
    assert evaluation.wilson(0,4)["upper"]>0
    assert evaluation.wilson(4,4)["lower"]<1
    scenarios=[{"label":"normal","observed_host_key":"same-host","observation_start":0,"observation_end":86400}]*2
    metric=evaluation._metrics([{"label":"normal","anomaly":False}]*2,scenarios)
    assert metric["false_positive_scenarios_per_declared_host_day"]["normal_host_days"]==1


def test_candidate_real_training_evaluation_independent_review_atomic_promote_rollback(store):
    dataset,model,_source,_manifest=cohort(store)
    research.review(store,actor("reviewer"),model["id"],{"approve":True,"mode":"live","reason":"Initial independent baseline"})
    candidate=rebaseline.create(store,actor(),{"model_id":model["id"],"reason":"Curator supplied reviewed normal evidence"})
    prepared=rebaseline.prepare(store,actor(),candidate["id"],{"expected_revision":1,"dataset_id":dataset["id"],"epochs":35,"seeds":[29],"normal_training_confirmed":True})
    review={"expected_revision":2,"approve":True,"mode":"live","reason":"Independent measured synthetic acceptance; field deployment remains unverified","minimum_precision":0,"minimum_recall":0,"maximum_false_positive_rate":1}
    with pytest.raises(PermissionError,match="Independent reviewer"):rebaseline.review(store,actor(),candidate["id"],review)
    approved=rebaseline.review(store,actor("reviewer"),candidate["id"],review)
    with pytest.raises(ConflictError):rebaseline.promote(store,actor(),candidate["id"],{"expected_revision":2,"reason":"stale revision"})
    promoted=rebaseline.promote(store,actor(),candidate["id"],{"expected_revision":approved["revision"],"reason":"Explicit atomic replacement"})
    with store.control() as db:
        assert db.execute("SELECT state FROM research_behavior_models WHERE id=?",(model["id"],)).fetchone()[0]=="disabled"
        assert research._verify_model(db,actor(),prepared["candidate_model_id"],require_active=True)
    rolled=rebaseline.rollback(store,actor("reviewer"),candidate["id"],{"expected_revision":promoted["revision"],"reason":"Independent explicit rollback exercise"})
    assert rolled["state"]=="rolled_back"
    with store.control() as db:
        assert research._verify_model(db,actor(),model["id"],require_active=True)
        assert db.execute("SELECT state FROM research_behavior_models WHERE id=?",(prepared["candidate_model_id"],)).fetchone()[0]=="disabled"
        assert db.execute("SELECT count(*) FROM research_rebaseline_audit").fetchone()[0]==5


def test_drift_notice_never_learns_or_repeats_same_run(store):
    _dataset,model,_source,_manifest=cohort(store)
    research.review(store,actor("reviewer"),model["id"],{"approve":True,"mode":"live","reason":"Initial review"})
    with store.control() as db:before=db.execute("SELECT snapshot FROM research_behavior_models WHERE id=?",(model["id"],)).fetchone()[0]
    for i in range(5):
        run={"id":f"pressure-{i}","mode":"live","long_evidence":{"count":1},"model_id":model["id"],"model_digest":model["digest"],"created":1700000000+i,"decision":{"anomaly":True,"score":4}}
        rebaseline.observe(store,actor(),run);rebaseline.observe(store,actor(),run)
    assert len(rebaseline.listing(store,actor())["items"])==1
    with store.control() as db:
        assert db.execute("SELECT snapshot FROM research_behavior_models WHERE id=?",(model["id"],)).fetchone()[0]==before
        drift=json.loads(db.execute("SELECT state FROM research_rebaseline_drift").fetchone()[0]);assert len(drift["runs"])==5
        assert db.execute("SELECT count(*) FROM research_behavior_models").fetchone()[0]==1


def test_archive_is_independent_dependency_aware_and_preserves_hash_history(store):
    dataset,model,_source,_manifest=cohort(store)
    result=evaluation.evaluate(store,actor(),{"dataset_id":dataset["id"],"model_id":model["id"]})
    with pytest.raises(PermissionError,match="Independent reviewer"):
        evaluation.archive(store,actor(),"datasets",dataset["id"],{"reason":"creator cannot release"})
    with pytest.raises(ConflictError,match="Active or pending"):
        evaluation.archive(store,actor("reviewer"),"datasets",dataset["id"],{"reason":"pending model protected"})
    research.disable(store,actor(),model["id"],"Explicit pause for archive exercise")
    with store.control() as db:
        db.execute("INSERT INTO record_case_evidence_refs VALUES(?,?,?,?)",("a",dataset["originals"][0]["event_id"],"bookmark","archive-fixture"))
    with pytest.raises(ConflictError,match="Case or bookmark"):
        evaluation.archive(store,actor("reviewer"),"datasets",dataset["id"],{"reason":"bookmark protected"})
    with store.control() as db:db.execute("DELETE FROM record_case_evidence_refs WHERE kind='bookmark' AND record_id='archive-fixture'")
    archived=evaluation.archive(store,actor("reviewer"),"datasets",dataset["id"],{"reason":"Explicit independent archival"})
    assert archived["original_digest"]==dataset["digest"] and archived["raw_references_released"]==len(dataset["originals"])
    assert evaluation.dataset(store,actor(),dataset["id"])["archived"]
    assert evaluation.archive(store,actor("reviewer"),"datasets",dataset["id"],{"reason":"Idempotent repeat"})==archived
    with pytest.raises(ConflictError,match="Archived"):
        evaluation.evaluate(store,actor(),{"dataset_id":dataset["id"],"model_id":model["id"]})
    with pytest.raises(PermissionError):evaluation.archive(store,actor(),"runs",result["id"],{"reason":"creator cannot archive"})
    run_archive=evaluation.archive(store,actor("reviewer"),"runs",result["id"],{"reason":"Independent run archive"})
    assert run_archive["original_digest"]==result["digest"] and evaluation.get_run(store,actor(),result["id"])["archived"]
    with store.control() as db:
        assert db.execute("SELECT digest FROM research_evaluation_datasets WHERE id=?",(dataset["id"],)).fetchone()[0]==dataset["digest"]
        assert db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE kind='research_evaluation_dataset'").fetchone()[0]==0
        assert db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE kind='research_behavior_model'").fetchone()[0]>0
    assert len(research._originals(store,actor(),[p["event_id"] for p in dataset["originals"]]))==len(dataset["originals"])
