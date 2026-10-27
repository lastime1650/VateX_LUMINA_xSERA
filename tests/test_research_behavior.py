"""Research ideas are executable, bounded, original-bound and CPU evaluated."""

import copy
import json

import pytest

from sapientia import access,auth,cpu_ml_runtime,migrations,principal,research_behavior as research
from sapientia import research_behavior_graph as graph
from sapientia.storage import ConflictError,Settings,Store,encode


def event(i,**changes):
    raw = {"source_id":"sensor-one","device_uid":"device-one","boot_id":"boot-one",
           "process_guid":"process-one","process_start_identity":"start-one",
           "image":"C:/Apps/editor.exe","command_line":"editor document.txt","action":"file_read",
           "file_path":"C:/Docs/document.txt","file_sha256":"a"*64}
    raw.update(changes.pop("raw",{}))
    raw["xdr"]={"data":{"process":{"guid":raw["process_guid"],"start_identity":raw["process_start_identity"],
        "executable":raw["image"],"command_line":raw["command_line"],"parent":{"guid":raw.get("parent_process_guid"),"start_identity":raw.get("parent_process_start_identity")}},
        "host":{"id":raw["device_uid"],"boot_id":raw["boot_id"]},"file":{"path":raw["file_path"],"hash":{"sha256":raw["file_sha256"]}}}}
    projection={"source_id":"registered-unit-fixture","account":"test-account","realm":"virtual-lab",
        "process":{"guid":raw["process_guid"],"start_identity":raw["process_start_identity"],"parent_guid":raw.get("parent_process_guid"),"parent_start_identity":raw.get("parent_process_start_identity")},
        "device":{"uid":raw["device_uid"],"boot_id":raw["boot_id"]}}
    return {"event_id":f"research-{i}","event_time":1700000000+i,"index":"public","host":"test-host","raw":raw,"projection":projection,**changes}


def actor(name="trainer",tenant="a",indexes=None,role="analyst"):
    return {"name":name,"tenant":tenant,"role":role,"allowed_indexes":indexes or ["*"]}


@pytest.fixture
def store(tmp_path,monkeypatch):
    monkeypatch.setitem(migrations.SUPPORTED,"research_behavior",2)
    value=Store(Settings(tmp_path,min_free_bytes=0))
    research.initialize(value)
    for name,tenant,role in (("trainer","a","analyst"),("reviewer","a","analyst"),("admin","a","admin"),("foreign","b","analyst")):
        auth.create_user(value,name,"Research-fixture-password-2026",role,tenant)
    yield value
    value.close()


def seed(store,registered=True):
    rows=[]
    for i in range(48):
        variant = i%2
        rows.append(event(i,raw={"image":"C:/Apps/browser.exe","command_line":"browser https://internal/",
                   "file_path":"","file_sha256":"","dest_ip":"10.0.0.8","dest_port":443,"action":"network_connect"}) if variant else event(i))
    rows.extend([event(100,raw={"action":"network_connect"}),event(101)])
    rows=[{k:v for k,v in row.items() if k!="projection"} for row in rows]
    if registered:
        from sapientia import connector_runtime,source_registry
        source=source_registry.save(store,actor("admin",role="admin"),{"index":"public","product":"json","account":"test-account","realm":"virtual-lab","credential_ref":"env:SAPIENTIA_CONNECTOR_RESEARCH_FIXTURE","version":0})
        connector_runtime.intake(store,actor("admin",role="admin"),source["id"],{"version":source["version"],"events":rows,"cursor":"research-seed","checkpoint_version":0})
    else:
        store.ingest("a",rows)
    store.flush()


def definition(**changes):
    return {"name":"normal-edge-relations","indexes":["public"],"training_ids":[f"research-{i}" for i in range(32)],
            "validation_ids":[f"research-{i}" for i in range(32,48)],"epochs":60,"seeds":[17,29,43],"normal_training_confirmed":True,**changes}


def test_edge_features_are_bounded_and_exclude_evaluation_labels_and_identifiers():
    one=event(1)
    two=copy.deepcopy(one)
    two.update(event_id="other",host="other-host")
    two["raw"].update(ground_truth="attack",campaign_id="secret",scenario_label="labeled",expected_detected=True)
    assert graph.event_features(one)==graph.event_features(two)
    values=graph.event_features(one)["values"]
    assert len(values)==24 and all(0<=v<=1 for v in values)
    changed=copy.deepcopy(one)
    changed["raw"]["action"]="network_connect"
    assert graph.event_features(one)["values"]==graph.event_features(changed)["values"]
    assert graph.event_features(one)["target"]!=graph.event_features(changed)["target"]


def test_windows_nondeterministic_tokens_group_without_losing_original_paths():
    one=event(1,raw={"registry_path":"HKCU/Software/{12345678-1234-1234-1234-123456789abc}/S-1-5-21-12345-67890","action":"registry_read"})
    result=graph.analyze_graph([one])
    assert "<uuid>" in next(iter(result["prism"]["path_groups"]))
    assert "<sid>" in next(iter(result["prism"]["path_groups"]))
    assert any("12345678" in node["label"] for node in result["nodes"])


def test_process_incarnations_do_not_join_reused_pid_or_other_boot():
    one,two,three=event(1),event(2),event(3)
    two["raw"]["process_start_identity"]="start-two"
    three["raw"]["boot_id"]="boot-two"
    two["projection"]["process"]["start_identity"]="start-two"
    three["projection"]["device"]["boot_id"]="boot-two"
    result=graph.analyze_graph([one,two,three])
    processes=[n for n in result["nodes"] if n["kind"]=="process"]
    assert len(processes)==3
    assert all(t["previous_action"] is None for t in result["temporal"])


def test_missing_device_or_source_identity_is_unlinked_and_path_only_is_not_causal():
    rows=[event(i,raw={"boot_id":"","file_sha256":""}) for i in range(4)]
    result=graph.analyze_graph(rows)
    assert len(result["missing_identity"])==4
    assert len([n for n in result["nodes"] if n["kind"]=="unlinked"])==4
    assert len([n for n in result["nodes"] if n["kind"]=="file"])==4


def test_causal_paths_are_chronological_and_never_infer_future_flow():
    write=event(1,raw={"action":"file_write"})
    read=event(2,raw={"process_guid":"process-two","process_start_identity":"start-two"})
    connect=event(3,raw={"process_guid":"process-two","process_start_identity":"start-two","file_path":"","file_sha256":"","dest_ip":"10.0.0.8","dest_port":443,"action":"network_connect"})
    result=graph.analyze_graph([connect,write,read],{"research-3":9.0})
    assert any(p["event_ids"]==["research-1","research-2","research-3"] for p in result["summary_paths"])
    assert all(p["edges"]==sorted(p["edges"],key=lambda x:x["time"]) for p in result["summary_paths"])
    assert not result["device_authority"] and not result["reproduction_claim"]


def test_fixed_sketch_and_temporal_history_are_bounded_over_many_updates():
    state=None
    for offset in range(20):
        rows=[event(offset*32+i,raw={"process_guid":f"process-{offset}-{i}"}) for i in range(32)]
        value=graph.analyze_graph(rows,state=state)
        state=value["state"]
        assert len(value["nodes"])<=128 and len(value["edges"])<=128
        assert len(state["bins"])==128
        assert len(state["processes"])<=128 and len(state["transitions"])<=128
    assert state["observed"]==640
    assert not value["sketch"]["history_reconstructable_from_sketch"]
    assert len(encode(state))<65536


def test_late_event_does_not_rewind_process_or_sketch_clock():
    latest=graph.analyze_graph([event(10)])
    late=graph.analyze_graph([event(1,raw={"action":"file_write"})],state=latest["state"])
    assert late["temporal"][0]["late_event"]
    assert late["state"]["last_time"]==event(10)["event_time"]
    assert next(iter(late["state"]["processes"].values()))["action"]=="read"


@pytest.mark.parametrize("mutation",["bins","schema","processes","total"])
def test_malformed_state_cannot_be_accepted(mutation):
    state=graph.empty_state()
    state[mutation]={} if mutation in {"bins","total"} else "bad"
    with pytest.raises(ValueError):graph.analyze_graph([event(1)],state=state)


def test_windows_service_heuristics_preserve_security_events_and_raw_evidence():
    row=event(1,raw={"image":"C:/Windows/System32/lsass.exe","action":"file_write"})
    result=graph.analyze_graph([row])
    assert result["prism"]["service_ipc_candidates"][0]["suppressed"] is False
    assert result["prism"]["temporal_service_partitions"][0]["summary_only"]
    assert not result["prism"]["leaf_data_groups"]
    assert result["edges"][0]["event_id"]=="research-1"


def test_windows_temporal_service_partition_reduces_only_explanation_paths():
    first=event(1,raw={"image":"C:/Windows/System32/lsass.exe","action":"file_read"})
    distant=event(10,raw={"image":"C:/Windows/System32/lsass.exe","action":"file_write","file_path":"C:/other.txt","file_sha256":"b"*64})
    result=graph.analyze_graph([first,distant],{"research-10":9})
    assert len(result["edges"])==2
    assert not any(p["event_ids"]==["research-1","research-10"] for p in result["summary_paths"])
    nearby=event(2,raw={"image":"C:/Windows/System32/lsass.exe","action":"file_write","file_path":"C:/other.txt","file_sha256":"b"*64})
    immediate=graph.analyze_graph([first,nearby],{"research-2":9})
    assert any(p["event_ids"]==["research-1","research-2"] for p in immediate["summary_paths"])
    assert result["prism"]["original_graph_edges_removed"]==0


def test_ttp_hints_are_not_confirmed_attack_labels():
    row=event(1,raw={"image":"powershell.exe","command_line":"powershell -enc SAFE_TEXT_ONLY"})
    result=graph.analyze_graph([row])
    assert result["ttps"][0]["techniques"]==["T1059.001"]
    assert all(not p["confirmed_attack"] for p in result["summary_paths"])


def test_quality_reports_real_split_leakage_repetition_and_unknown_campaigns():
    training=[event(i) for i in range(16)]
    validation=[event(i+20,host="other-host",raw={"ground_truth":"benign"}) for i in range(8)]
    value=graph.dataset_quality({"training":training,"validation":validation})
    assert value["content_overlap"][0]["count"]==1
    assert value["host_overlap"][0]["count"]==0
    assert value["temporal_overlap"][0]["chronological"]
    assert value["background_repetition"]["training"]==1
    assert value["label_leakage_fields"]==["raw.ground_truth"]
    assert not value["detector_uses_evaluation_labels"] and not value["real_world_detection_rate_measured"]


def test_real_cpu_ensemble_training_ablation_review_live_inference_and_publication(store):
    seed(store)
    result=research.train(store,actor(),definition())
    assert result["status"]=="completed" and result["state"]=="pending"
    metrics=result["metrics"]
    assert len(metrics["seeds"])==3 and metrics["attack_precision"] is None
    assert all(v["training_cross_entropy"]<v["initial_training_cross_entropy"] for v in metrics["seeds"])
    assert all(v["validation_relation_accuracy"]>.9 for v in metrics["seeds"])
    assert all(v["semantic_feature_ablation_cross_entropy"]>v["validation_cross_entropy"] for v in metrics["seeds"])
    assert metrics["validation_cross_entropy"]<metrics["frequency_baseline_cross_entropy"]
    with pytest.raises(PermissionError,match="creator"):
        research.review(store,actor(),result["id"],{"approve":True,"reason":"self review"})
    research.review(store,actor("reviewer"),result["id"],{"approve":True,"reason":"independent original and holdout review","mode":"live"})
    run=research.analyze(store,actor(),{"event_ids":["research-100","research-101"],"model_id":result["id"]})
    assert run["mode"]=="live" and run["decision"]["publishable"]
    values={r["event_id"]:r for r in run["results"]}
    assert values["research-100"]["anomaly"] and not values["research-101"]["anomaly"]
    assert values["research-100"]["edge_anomaly_score"]>values["research-101"]["edge_anomaly_score"]
    with principal.transaction(store,actor()) as (db,fresh):
        assert research.validate_publication(store,db,fresh,run["id"])["id"]==run["id"]
    assert research.get_run(store,actor(),run["id"])["model_digest"]==result["digest"]
    research.disable(store,actor(),result["id"],"reviewed stop; preserve snapshots")
    with principal.transaction(store,actor()) as (db,fresh):
        with pytest.raises(PermissionError):research.validate_publication(store,db,fresh,run["id"])


def test_shadow_review_default_never_publishes_even_real_anomaly(store):
    seed(store)
    model=research.train(store,actor(),definition(seeds=[17]))
    research.review(store,actor("reviewer"),model["id"],{"approve":True,"reason":"shadow evaluation"})
    run=research.analyze(store,actor(),{"event_ids":["research-100"],"model_id":model["id"]})
    assert run["decision"]["anomaly"] and run["shadow"] and not run["decision"]["publishable"]
    with principal.transaction(store,actor()) as (db,fresh):
        with pytest.raises(PermissionError,match="live"):research.validate_publication(store,db,fresh,run["id"])


@pytest.mark.parametrize("change,pattern",[
    ({"validation_ids":[f"research-{i}" for i in range(8)]},"disjoint"),
    ({"normal_training_confirmed":False},"acknowledgement"),
    ({"training_ids":[f"research-{i}" for i in range(16,48)],"validation_ids":[f"research-{i}" for i in range(8)]},"Point-in-time"),
    ({"seeds":[17,17]},"seeds"),({"epochs":1000},"epochs")])
def test_training_rejects_invalid_data_and_leaky_chronology(store,change,pattern):
    seed(store)
    with pytest.raises(ValueError,match=pattern):research.train(store,actor(),definition(**change))


def test_current_scope_and_viewer_cannot_train_or_borrow_foreign_runs(store):
    seed(store)
    with pytest.raises(PermissionError):research.train(store,actor(indexes=["private"]),definition())
    run=research.analyze(store,actor(),{"event_ids":["research-100"]})
    with pytest.raises(KeyError):research.get_run(store,actor("foreign","b"),run["id"])
    with pytest.raises(KeyError):research.get_run(store,actor(indexes=["private"]),run["id"])
    assert research.list_runs(store,actor("foreign","b"))["items"]==[]


def test_model_and_run_tampering_are_detected_and_originals_never_replaced(store):
    seed(store)
    model=research.train(store,actor(),definition(seeds=[17]))
    research.review(store,actor("reviewer"),model["id"],{"approve":True,"reason":"reviewed"})
    run=research.analyze(store,actor(),{"event_ids":["research-100"],"model_id":model["id"]})
    with store.control() as db:
        body=json.loads(db.execute("SELECT body FROM research_behavior_runs WHERE id=?",(run["id"],)).fetchone()[0])
        body["decision"]["publishable"]=True
        db.execute("UPDATE research_behavior_runs SET body=? WHERE id=?",(encode(body),run["id"]))
    with pytest.raises(ConflictError,match="hash"):research.get_run(store,actor(),run["id"])
    with store.control() as db:db.execute("UPDATE research_behavior_models SET snapshot='{}' WHERE id=?",(model["id"],))
    with pytest.raises(ConflictError,match="hash"):research.analyze(store,actor(),{"event_ids":["research-100"],"model_id":model["id"]})


def test_current_reviewer_revocation_invalidates_live_model(store):
    seed(store)
    model=research.train(store,actor(),definition(seeds=[17]))
    research.review(store,actor("reviewer"),model["id"],{"approve":True,"mode":"live","reason":"reviewed"})
    access.set_for_user(store,actor("admin",role="admin"),"reviewer",["private"])
    with pytest.raises(PermissionError,match="reviewer"):research.analyze(store,actor(),{"event_ids":["research-100"],"model_id":model["id"]})


def test_automatic_outbox_runs_cpu_once_and_keeps_long_horizon_state(store):
    seed(store)
    model=research.train(store,actor(),definition(seeds=[17]))
    research.review(store,actor("reviewer"),model["id"],{"approve":True,"mode":"live","reason":"reviewed autonomous evidence-only inference"})
    row=event(200,raw={"action":"network_connect"})
    from sapientia import connector_runtime
    with store.control() as db:source=dict(db.execute("SELECT * FROM source_registry WHERE tenant='a'").fetchone())
    connector_runtime.intake(store,actor("admin",role="admin"),source["id"],{"version":source["version"],"events":[{k:v for k,v in row.items() if k!="projection"}],"cursor":"research-second","checkpoint_version":1})
    store.flush()
    # The production storage hook is owned by the parent agent; direct call
    # also verifies the journaling contract without requiring a live server.
    with store.control() as db:
        received=db.execute("SELECT received FROM receipts WHERE tenant='a' AND event_id=?",(row["event_id"],)).fetchone()[0]
        research.journal_indexed(store,db,[{"tenant":"a","event_id":row["event_id"],"received":received,"payload":row}])
    value=research.run_due(store,budget=10)
    assert value["processed"]==1 and value["runs"][0]["decision"]["publishable"]
    assert research.run_due(store,budget=10)["processed"]==0
    with store.control() as db:
        state=json.loads(db.execute("SELECT state FROM research_behavior_state WHERE model_id=?",(model["id"],)).fetchone()[0])
        assert state["schema"]==research.research_fusion.SCHEMA
        assert state["recent_ids"]==[row["event_id"]]
        assert research.protected_ids(db,"a",[row["event_id"]])=={row["event_id"]}


def test_unavailable_framework_continues_without_fabricated_scores(store,monkeypatch):
    seed(store)
    monkeypatch.setattr(research,"_worker",lambda *a,**k:{"status":"unavailable","available":False,"compatibility":"시스템에서 호환되지 않음","simulation_continues":True})
    result=research.train(store,actor(),definition())
    assert result["status"]=="unavailable" and result["simulation_continues"]
    assert research.list_models(store,actor())["items"]==[]


def test_all_research_ideas_have_honest_implementation_and_license_boundaries():
    assert {x["id"] for x in research.CAPABILITIES}=={"research_fusion","velox_edge","orthrus_paths","kairos_temporal","unicorn_sketch","windows_prism","holmes_ttp","nodlink_tree","dataset_quality"}
    assert all(x["implemented"] and x["paper_url"].startswith("https://") for x in research.CAPABILITIES)
    assert "Research-Only" in next(x for x in research.CAPABILITIES if x["id"]=="nodlink_tree")["license_note"]


def test_normal_lifecycle_compacts_details_preserving_hash_metadata_and_other_refs(store):
    from sapientia import research_behavior_lifecycle as lifecycle
    seed(store)
    run=research.analyze(store,actor(),{"event_ids":["research-100","research-101"]})
    with store.control() as db:
        before=db.execute("SELECT digest FROM research_behavior_runs WHERE id=?",(run["id"],)).fetchone()[0]
        db.execute("INSERT OR IGNORE INTO record_case_evidence_refs VALUES('a','research-100','ml_dataset','unrelated-dataset')")
    result=lifecycle.archive_runs(store,actor(),[run["id"]],"normal detail lifecycle")["items"][0]
    archived=research.get_run(store,actor(),run["id"])
    assert result["state"]=="archived" and result["original_payload_digest"]==before
    assert archived["status"]=="archived" and archived["event_ids"]==run["event_ids"]
    assert archived["originals"]==run["originals"] and archived["decision"]==run["decision"]
    assert archived["graph"]["archived"] and "features" not in archived["results"][0]
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM research_behavior_runs").fetchone()[0]==1
        assert db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE kind='research_behavior_run'").fetchone()[0]==0
        assert db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE record_id='unrelated-dataset'").fetchone()[0]==1
        assert db.execute("SELECT count(*) FROM receipts WHERE tenant='a'").fetchone()[0]==50
    with pytest.raises(KeyError):research.get_run(store,actor(indexes=["private"]),run["id"])
    with pytest.raises(KeyError):lifecycle.archive_runs(store,actor("foreign","b"),[run["id"]],"foreign forbidden")


@pytest.mark.parametrize("kind",["case","legal_hold","live_anomaly"])
def test_lifecycle_does_not_compact_case_legal_hold_or_live_anomaly(store,kind):
    from sapientia import research_behavior_lifecycle as lifecycle
    seed(store)
    if kind=="live_anomaly":
        model=research.train(store,actor(),definition(seeds=[17]))
        research.review(store,actor("reviewer"),model["id"],{"approve":True,"mode":"live","reason":"reviewed"})
        run=research.analyze(store,actor(),{"event_ids":["research-100"],"model_id":model["id"]})
    else:
        run=research.analyze(store,actor(),{"event_ids":["research-100"]})
        with store.control() as db:
            if kind=="case":db.execute("INSERT OR IGNORE INTO record_case_evidence_refs VALUES('a','research-100','bookmark','case-fixture')")
            else:db.execute("INSERT OR REPLACE INTO policies VALUES('a',30,1)")
    answer=lifecycle.archive_runs(store,actor(),[run["id"]],"bounded details")["items"][0]
    assert answer["state"]=="protected"
    assert research.get_run(store,actor(),run["id"])["graph"].get("nodes")


def test_automatic_normal_archive_uses_age_without_deleting_permanent_run(store):
    from sapientia import research_behavior_lifecycle as lifecycle
    seed(store)
    run=research.analyze(store,actor(),{"event_ids":["research-101"]})
    value=lifecycle.run_due(store,now=run["created"]+86401)
    assert value["archived"]==1 and value["permanent_run_hash_history"]
    assert research.get_run(store,actor(),run["id"])["status"]=="archived"


def test_explicit_independent_retirement_preserves_model_weights_and_other_protection(store):
    from sapientia import research_behavior_lifecycle as lifecycle
    seed(store)
    model=research.train(store,actor(),definition(seeds=[17]))
    with pytest.raises(PermissionError,match="creator"):lifecycle.retire(store,actor(),model["id"],"self retirement forbidden")
    with store.control() as db:
        db.execute("INSERT OR IGNORE INTO record_case_evidence_refs VALUES('a','research-0','ml_dataset','other-protection')")
        snapshot=db.execute("SELECT snapshot FROM research_behavior_models WHERE id=?",(model["id"],)).fetchone()[0]
    summary=lifecycle.retire(store,actor("reviewer"),model["id"],"independent retirement review")
    assert summary["training_references_released"]==48 and summary["model_weights_and_provenance_retained"]
    with store.control() as db:
        assert db.execute("SELECT snapshot FROM research_behavior_models WHERE id=?",(model["id"],)).fetchone()[0]==snapshot
        assert db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE record_id='other-protection'").fetchone()[0]==1
    with pytest.raises(ConflictError,match="Retired"):research.review(store,actor("reviewer"),model["id"],{"approve":True,"reason":"cannot revive retired"})
    assert lifecycle.retire(store,actor("reviewer"),model["id"],"idempotent repeat")["retired"]


def test_generic_self_reported_source_can_only_train_and_run_in_shadow(store):
    seed(store,registered=False)
    model=research.train(store,actor(),definition(seeds=[17]))
    with pytest.raises(PermissionError,match="authenticated source"):
        research.review(store,actor("reviewer"),model["id"],{"approve":True,"mode":"live","reason":"generic raw must not become live authority"})
    research.review(store,actor("reviewer"),model["id"],{"approve":True,"mode":"shadow","reason":"shadow only"})
    run=research.analyze(store,actor(),{"event_ids":["research-100","research-101"],"model_id":model["id"]})
    assert run["shadow"] and run["decision"]["anomaly"]
    assert all(p["source_authority"] is None for p in run["originals"])
    assert not [n for n in run["graph"]["nodes"] if n["kind"]=="process"]
    assert len(run["graph"]["missing_identity"])==2


@pytest.mark.parametrize("change",["revoke","owner_scope","receipt_missing"])
def test_training_source_current_authority_is_required_after_live_review(store,change):
    from sapientia import source_registry
    seed(store)
    model=research.train(store,actor(),definition(seeds=[17]))
    research.review(store,actor("reviewer"),model["id"],{"approve":True,"mode":"live","reason":"reviewed authenticated baseline"})
    with store.control() as db:source=dict(db.execute("SELECT * FROM source_registry WHERE tenant='a'").fetchone())
    if change=="revoke":source_registry.revoke(store,actor("admin",role="admin"),source["id"],source["version"])
    elif change=="owner_scope":access.set_for_user(store,actor("admin",role="admin"),"admin",["private"])
    else:
        with store.control() as db:db.execute("DELETE FROM source_event_receipts WHERE tenant='a' AND event_id='research-0'")
    with pytest.raises((PermissionError,ConflictError)):
        research.analyze(store,actor(),{"event_ids":["research-100"],"model_id":model["id"]})


def test_live_model_rejects_generic_runtime_originals_even_with_forged_raw_identity(store):
    seed(store)
    model=research.train(store,actor(),definition(seeds=[17]))
    research.review(store,actor("reviewer"),model["id"],{"approve":True,"mode":"live","reason":"authenticated baseline"})
    raw=event(300)
    store.ingest("a",[{k:v for k,v in raw.items() if k!="projection"}]);store.flush()
    with pytest.raises(PermissionError,match="authenticated source"):
        research.analyze(store,actor(),{"event_ids":["research-300"],"model_id":model["id"]})


def test_untrusted_live_queue_prefix_is_durably_excluded_without_blocking_authenticated_event(store):
    from sapientia import connector_runtime
    seed(store)
    model=research.train(store,actor(),definition(seeds=[17]))
    research.review(store,actor("reviewer"),model["id"],{"approve":True,"mode":"live","reason":"authenticated baseline"})
    generic={k:v for k,v in event(300).items() if k!="projection"}
    store.ingest("a",[generic]);store.flush()
    with store.control() as db:
        source=dict(db.execute("SELECT * FROM source_registry WHERE tenant='a'").fetchone())
        receipt=db.execute("SELECT received FROM receipts WHERE tenant='a' AND event_id='research-300'").fetchone()
        research.journal_indexed(store,db,[{"tenant":"a","event_id":"research-300","received":receipt["received"],"payload":generic}])
    good={k:v for k,v in event(301,raw={"action":"network_connect"}).items() if k!="projection"}
    connector_runtime.intake(store,actor("admin",role="admin"),source["id"],{"version":source["version"],"events":[good],"cursor":"good-after-untrusted","checkpoint_version":1})
    store.flush()
    excluded=research.run_due(store,budget=10)
    assert excluded["excluded"]==1 and excluded["processed"]==0
    diagnostic=research.get_run(store,actor(),excluded["runs"][0]["id"])
    assert diagnostic["status"]=="excluded" and not diagnostic["decision"]["publishable"]
    assert diagnostic["excluded_originals"][0]["event_id"]=="research-300"
    actual=research.run_due(store,budget=10)
    assert actual["processed"]==1 and actual["runs"][0]["event_ids"]==["research-301"]


def test_idle_models_from_other_tenants_cannot_starve_a_due_model(store):
    from sapientia import connector_runtime
    seed(store)
    model=research.train(store,actor(),definition(seeds=[17]))
    research.review(store,actor("reviewer"),model["id"],{"approve":True,"mode":"live","reason":"authenticated baseline"})
    with store.control() as db:
        template=dict(db.execute("SELECT * FROM research_behavior_models WHERE id=?",(model["id"],)).fetchone())
        state=dict(db.execute("SELECT * FROM research_behavior_state WHERE model_id=?",(model["id"],)).fetchone())
        source=dict(db.execute("SELECT * FROM source_registry WHERE tenant='a'").fetchone())
        for i in range(65):
            values={**template,"id":f"idle-{i}","tenant":f"idle-tenant-{i}","owner":"idle-owner"}
            db.execute("INSERT INTO research_behavior_models VALUES("+",".join("?" for _ in values)+")",list(values.values()))
            db.execute("INSERT INTO research_behavior_state VALUES(?,?,?,?,?,?,NULL)",(values["id"],values["tenant"],0,state["state"],state["digest"],0))
    row={k:v for k,v in event(400,raw={"action":"network_connect"}).items() if k!="projection"}
    connector_runtime.intake(store,actor("admin",role="admin"),source["id"],{"version":source["version"],"events":[row],"cursor":"fair-scheduler","checkpoint_version":1})
    store.flush()
    result=research.run_due(store,budget=10)
    assert result["processed"]==1 and result["runs"][0]["model_id"]==model["id"]
