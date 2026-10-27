"""Authorized real telemetry windows, immutable statistics and cold-start bounds."""

import pytest

from sapientia import access, behavior_features as features
from sapientia.storage import ConflictError
from tests.test_behavior import store as original_store, actor, START


BUCKET = 60


@pytest.fixture
def store(tmp_path):
    for value in original_store.__wrapped__(tmp_path):
        features.initialize(value)
        yield value


def definition(**extra):
    return {"name": "Actual feature training", "entity_field": "host", "indexes": ["public"],
        "start": START, "end": START+4*BUCKET, "bucket_seconds": BUCKET,
        "min_samples": 4, "min_buckets": 4, "robust_multiplier": 3, **extra}


def event(identifier, at, host="host-a", index="public", action="network_connection", outcome=None, byte=None, pair=None):
    security = {"action": action}
    if outcome is not None:
        security["outcome"] = outcome
    if byte is not None:
        security["bytes_out"] = byte
    raw = {"security": security}
    if pair:
        raw["xdr"] = {"data": {"process": {"name": pair[1], "parent": {"name": pair[0]}}}}
    return {"event_id": identifier, "event_time": at, "index": index, "host": host, "raw": raw}


def seed(store, hosts=("host-a",), bytes_value=100):
    rows = []
    for host in hosts:
        for bucket in range(4):
            at = START+bucket*BUCKET+1
            rows += [event(f"{host}-byte-{bucket}", at, host, byte=bytes_value),
                     event(f"{host}-auth-{bucket}", at+1, host, action="authentication", outcome="success"),
                     event(f"{host}-file-{bucket}", at+2, host, action="file_write"),
                     event(f"{host}-proc-{bucket}", at+3, host, action="process_create", pair=("service.exe", "worker.exe"))]
    store.ingest("a", rows)
    store.flush()


def test_all_features_detect_typed_deviation_with_complete_exact_evidence(store):
    seed(store)
    baseline = features.train(store, actor(), definition())
    digest = baseline["digest"]
    end = definition()["end"]
    observations = [event("abnormal-bytes", end+1, byte=10000),
        event("new-lineage", end+2, action="process_create", pair=("office.exe", "shell.exe"))]
    observations += [event(f"failure-{i}", end+3+i, action="authentication", outcome="failure") for i in range(6)]
    observations += [event(f"file-{i}", end+12+i, action="file_write") for i in range(6)]
    store.ingest("a", observations)
    store.flush()
    result = features.evaluate(store, actor(), baseline["id"], end, end+BUCKET)
    by_feature = {item["feature"]: item for item in result["anomalies"]}
    assert set(by_feature)=={"network_bytes_out", "authentication_failure_ratio", "file_change_count", "rare_process_lineage"}
    assert by_feature["network_bytes_out"]["value"]==10000
    assert by_feature["authentication_failure_ratio"]["value"]==1
    assert by_feature["authentication_failure_ratio"]["event_ids"]==[f"failure-{i}" for i in range(6)]
    assert by_feature["file_change_count"]["value"]==6
    assert by_feature["rare_process_lineage"]["parent_child_names"]==["office.exe", "shell.exe"]
    assert all(not item["probability_calibrated"] and not item["response_authorized"] for item in result["anomalies"])
    assert features.get(store, actor(), baseline["id"])["digest"]==digest
    assert features.get_run(store, actor(), result["id"])["baseline_digest"]==digest


def test_missing_and_mistyped_features_never_become_zero_or_fabricated_execution(store):
    seed(store)
    baseline = features.train(store, actor(), definition())
    end = definition()["end"]
    observations = [event("missing", end+1, action="unrelated"),
        event("typed-string", end+2, byte="999999"), event("typed-bool", end+3, byte=True),
        event("unknown-outcome", end+4, action="authentication"),
        event("inventory-lineage", end+5, action="process_observed", pair=("office.exe", "shell.exe"))]
    store.ingest("a", observations)
    store.flush()
    result = features.evaluate(store, actor(), baseline["id"], end, end+BUCKET)
    assert result["anomalies"]==[]
    assert len(result["warmup"])==3
    assert {item["reason"] for item in result["warmup"]}=={"missing_feature_observation"}
    assert not result["quality"]["missing_buckets_are_zero"]


def test_known_authentication_denominator_excludes_unknown_and_network_failure(store):
    seed(store)
    baseline = features.train(store, actor(), definition())
    end = definition()["end"]
    store.ingest("a", [event("known-failure", end+1, action="authentication", outcome="failure"),
        event("known-success", end+2, action="authentication", outcome="success"),
        event("unknown-auth", end+3, action="authentication"),
        event("network-failure", end+4, outcome="failure")])
    store.flush()
    result = features.evaluate(store, actor(), baseline["id"], end, end+BUCKET)
    anomaly = next(item for item in result["anomalies"] if item["feature"]=="authentication_failure_ratio")
    assert anomaly["value"]==.5
    assert set(anomaly["event_ids"])=={"known-failure", "known-success"}


def test_source_scope_owner_revocation_and_training_leakage_are_enforced(store):
    seed(store)
    baseline = features.train(store, actor(), definition())
    with pytest.raises(KeyError):
        features.get(store, actor("analyst_b", "b"), baseline["id"])
    with pytest.raises(PermissionError):
        features.train(store, actor(indexes=["private"]), definition())
    with pytest.raises(ValueError, match="leakage"):
        features.evaluate(store, actor(), baseline["id"], START, START+BUCKET)
    access.set_for_user(store, actor("admin_a"), "analyst_a", ["private"])
    with pytest.raises(PermissionError, match="owner lost"):
        features.get(store, actor("admin_a"), baseline["id"])


def test_cold_start_staleness_and_snapshot_revision_are_visible(store):
    seed(store)
    first = features.train(store, actor(), definition(min_samples=100))
    assert not first["snapshot"]["ready"]
    end = definition()["end"]
    store.ingest("a", [event("outlier", end+1, byte=10000)])
    store.flush()
    result = features.evaluate(store, actor(), first["id"], end, end+BUCKET)
    assert result["state"]=="warmup" and result["anomalies"]==[]
    second = features.train(store, actor(), definition())
    assert second["revision"]==2 and second["id"]!=first["id"]
    assert second["snapshot"]["dataset_digest"]==first["snapshot"]["dataset_digest"]
    assert second["digest"]!=first["digest"]
    late = end+31*86400
    store.ingest("a", [event("stale-outlier", late+1, byte=10000)])
    store.flush()
    result = features.evaluate(store, actor(), second["id"], late, late+BUCKET)
    assert result["state"]=="stale" and result["anomalies"]==[]


def test_leave_target_out_feature_peers_and_seasonal_cold_start(store):
    hosts = ("target", "peer-a", "peer-b", "peer-c")
    seed(store, hosts)
    baseline = features.train(store, actor(), definition(count_method="peer_robust_mad", peer_groups={name: "workstation" for name in hosts}, peer_min_entities=3))
    end = definition()["end"]
    store.ingest("a", [event("peer-outlier", end+1, host="target", byte=10000)])
    store.flush()
    result = features.evaluate(store, actor(), baseline["id"], end, end+BUCKET)
    anomaly = next(item for item in result["anomalies"] if item["feature"]=="network_bytes_out")
    assert anomaly["profile"]["peers"]==["peer-a", "peer-b", "peer-c"]
    assert anomaly["profile"]["leave_target_out"]
    seasonal = features.train(store, actor(), definition(seasonality="hour_of_week", seasonality_min_buckets=2))
    after = end+3600
    store.ingest("a", [event("unseen-seasonal-hour", after+1, byte=10000)])
    store.flush()
    result = features.evaluate(store, actor(), seasonal["id"], after, after+BUCKET)
    assert result["anomalies"]==[]
    assert any(item["reason"]=="entity_or_seasonal_cold_start" for item in result["warmup"])


def test_training_permission_change_before_commit_creates_no_snapshot(store, monkeypatch):
    seed(store)
    read = features._records
    def revoke(*args, **kwargs):
        result = read(*args, **kwargs)
        access.set_for_user(store, actor("admin_a"), "analyst_a", ["private"])
        return result
    monkeypatch.setattr(features, "_records", revoke)
    with pytest.raises(PermissionError):
        features.train(store, actor(), definition())
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM behavior_feature_baselines").fetchone()[0]==0


def test_schedule_disablement_during_analysis_prevents_any_published_result(store, monkeypatch):
    seed(store)
    baseline = features.train(store, actor(), definition())
    scheduled = features.schedule(store, actor(), {"baseline_id": baseline["id"], "enabled": True, "interval": BUCKET, "version": 0})
    with store.control() as db:
        guard = dict(db.execute("SELECT * FROM behavior_feature_schedules WHERE id=?", (scheduled["id"],)).fetchone())
    end = definition()["end"]
    store.ingest("a", [event("scheduling-outlier", end+1, byte=10000)])
    store.flush()
    read = features._records
    def disable(*args, **kwargs):
        result = read(*args, **kwargs)
        features.schedule(store, actor(), {"baseline_id": baseline["id"], "enabled": False, "interval": BUCKET, "version": 1})
        return result
    monkeypatch.setattr(features, "_records", disable)
    with pytest.raises(ConflictError, match="schedule changed"):
        features.evaluate(store, actor(), baseline["id"], end, end+BUCKET, publish=True, _schedule_guard=guard)
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM behavior_feature_runs").fetchone()[0]==0


def test_feature_http_adapter_train_inspect_evaluate_and_schedule(store):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from sapientia import case_intelligence

    seed(store)
    app = FastAPI()
    async def body(request):
        return await request.json()
    case_intelligence.register(app, store, None, lambda request, roles=None: actor(), body)
    with TestClient(app) as client:
        response = client.post("/api/v3/behavior/features/baselines", json=definition())
        assert response.status_code==201
        baseline = response.json()
        assert client.get("/api/v3/behavior/features/baselines/"+baseline["id"]).json()["digest"]==baseline["digest"]
        assert client.get("/api/v3/cases/reevaluation/config").json()["enabled"] is False
        end = definition()["end"]
        store.ingest("a", [event("http-outlier", end+1, byte=10000)])
        store.flush()
        result = client.post("/api/v3/behavior/features/baselines/"+baseline["id"]+"/evaluate", json={"start": end, "end": end+BUCKET, "mode": "shadow"}).json()
        assert result["mode"]=="shadow" and result["anomalies"] and not result["published"]
        assert client.get("/api/v3/behavior/features/runs/"+result["id"]).json()["baseline_digest"]==baseline["digest"]
        saved = client.post("/api/v3/behavior/features/schedules", json={"baseline_id": baseline["id"], "enabled": False, "interval": BUCKET, "version": 0})
        assert saved.status_code==201
        assert client.get("/api/v3/behavior/features/schedules").json()[0]["enabled"] is False


def test_scheduler_catches_up_oldest_gap_across_restart_and_rechecks_bounded_late_arrivals(store):
    seed(store)
    baseline = features.train(store, actor(), definition())
    end = definition()["end"]
    scheduled = features.schedule(store, actor(), {"baseline_id": baseline["id"], "enabled": True, "interval": BUCKET, "version": 0})
    with store.control() as db:
        db.execute("UPDATE behavior_feature_schedules SET next_run=?,last_end=? WHERE id=?", (end+BUCKET, end, scheduled["id"]))
    store.ingest("a", [event("gap-outlier-0", end+1, byte=10000), event("gap-outlier-2", end+2*BUCKET+1, byte=11000)])
    store.flush()
    assert features.run_due(store, end+4*BUCKET, budget=2, max_runs=1) == 1
    with store.control() as db:
        assert db.execute("SELECT last_end FROM behavior_feature_schedules").fetchone()[0] == end+BUCKET
    settings = store.settings
    store.close()
    from sapientia.storage import Store
    restarted = Store(settings)
    try:
        assert features.run_due(restarted, end+4*BUCKET, budget=2, max_runs=1) == 1
        # A late original in a previously completed bucket must be re-observed
        # while within the explicitly bounded two-bucket overlap.
        restarted.ingest("a", [event("late-outlier-1", end+BUCKET+1, byte=12000)])
        restarted.flush()
        assert features.run_due(restarted, end+4*BUCKET, budget=2, max_runs=1) == 1
        assert features.run_due(restarted, end+4*BUCKET, budget=2, max_runs=1) == 1
        with restarted.control() as db:
            assert db.execute("SELECT last_end FROM behavior_feature_schedules").fetchone()[0] == end+4*BUCKET
            signals = [__import__("json").loads(row[0]) for row in db.execute("SELECT event_ids FROM intelligence_signals WHERE kind='behavior'")]
            assert len(signals) == 3
            assert {ids[0] for ids in signals} == {"gap-outlier-0", "gap-outlier-2", "late-outlier-1"}
            result = __import__("json").loads(db.execute("SELECT result FROM behavior_feature_runs ORDER BY created DESC LIMIT 1").fetchone()[0])
            assert result["scheduler_contract"]["late_arrival_overlap_buckets"] == 2
            assert not result["scheduler_contract"]["unbounded_lateness_covered"]
    finally:
        restarted.close()


def test_scheduler_failure_keeps_first_unfinished_window_for_retry(store, monkeypatch):
    seed(store)
    baseline = features.train(store, actor(), definition())
    end = definition()["end"]
    scheduled = features.schedule(store, actor(), {"baseline_id": baseline["id"], "enabled": True, "interval": BUCKET, "version": 0})
    with store.control() as db:
        db.execute("UPDATE behavior_feature_schedules SET next_run=?,last_end=NULL WHERE id=?", (end+BUCKET, scheduled["id"]))
    actual = features.evaluate
    def interrupted(*args, **kwargs):
        from sapientia.storage import CapacityError
        raise CapacityError("Synthetic temporary resource pressure")
    monkeypatch.setattr(features, "evaluate", interrupted)
    assert features.run_due(store, end+3*BUCKET, budget=2) == 0
    monkeypatch.setattr(features, "evaluate", actual)
    store.ingest("a", [event("retained-first-window", end+1, byte=10000)])
    store.flush()
    assert features.run_due(store, end+5*BUCKET, budget=2) == 1
    with store.control() as db:
        assert db.execute("SELECT last_end FROM behavior_feature_schedules").fetchone()[0] == end+BUCKET
        assert db.execute("SELECT count(*) FROM intelligence_signals WHERE kind='behavior'").fetchone()[0] == 1


def test_published_feature_pages_keep_all_originals_one_dependency_and_shadow_scope(store):
    seed(store)
    baseline = features.train(store, actor(), definition())
    end = definition()["end"]
    observations = [event(f"paged-failure-{position:02}", end+position, action="authentication", outcome="failure") for position in range(40)]
    store.ingest("a", observations)
    store.flush()
    result = features.evaluate(store, actor(), baseline["id"], end, end+BUCKET, publish=True, mode="shadow")
    assert len(result["signals"])==2
    assert set().union(*(set(signal["event_ids"]) for signal in result["signals"]))=={row["event_id"] for row in observations}
    assert len({signal["metadata"]["dependency_group"] for signal in result["signals"]})==1
    assert {signal["metadata"]["page_number"] for signal in result["signals"]}=={1, 2}
    assert all(signal["mode"]=="shadow" and signal["metadata"]["complete_event_count"]==40 for signal in result["signals"])
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM incidents").fetchone()[0]==0
        assert db.execute("SELECT count(*) FROM intelligence_signals WHERE mode='shadow'").fetchone()[0]==2
    second = features.evaluate(store, actor(), baseline["id"], end, end+BUCKET, publish=True, mode="shadow")
    assert all(signal["duplicate"] for signal in second["signals"])


def test_revoked_scope_during_evaluation_prevents_signal_publication(store, monkeypatch):
    seed(store)
    baseline = features.train(store, actor(), definition())
    end = definition()["end"]
    store.ingest("a", [event("acl-drift-outlier", end+1, byte=10000)])
    store.flush()
    read = features._records
    def revoke(*args, **kwargs):
        result = read(*args, **kwargs)
        access.set_for_user(store, actor("admin_a"), "analyst_a", ["private"])
        return result
    monkeypatch.setattr(features, "_records", revoke)
    with pytest.raises((PermissionError, KeyError)):
        features.evaluate(store, actor(), baseline["id"], end, end+BUCKET, publish=True)
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM intelligence_signals").fetchone()[0]==0
        assert db.execute("SELECT count(*) FROM behavior_feature_runs").fetchone()[0]==0


def test_publication_completes_with_queued_segment_writer_without_lock_inversion(store, monkeypatch):
    import threading
    import time
    from sapientia import intelligence

    seed(store)
    baseline = features.train(store, actor(), definition())
    end = definition()["end"]
    store.ingest("a", [event("lock-order-outlier", end+1, byte=10000)])
    store.flush()
    publish = intelligence.publish_in_transaction
    finished = threading.Event()
    workers = []
    def queued_writer():
        with store.segment_lock.write(), store.write_lock:
            finished.set()
    def publish_with_pending_writer(*args, **kwargs):
        worker = threading.Thread(target=queued_writer, daemon=True)
        workers.append(worker)
        worker.start()
        deadline = time.monotonic()+1
        while not store.segment_lock.waiting and store.segment_lock.writer is None and time.monotonic()<deadline:
            time.sleep(.001)
        return publish(*args, **kwargs)
    monkeypatch.setattr(intelligence, "publish_in_transaction", publish_with_pending_writer)
    result = features.evaluate(store, actor(), baseline["id"], end, end+BUCKET, publish=True)
    assert result["signals"]
    assert finished.wait(2)
    for worker in workers:
        worker.join(1)
        assert not worker.is_alive()


@pytest.mark.parametrize("change", [{"byte_fields": ["raw.bytes", {}]}, {"count_method": "count_zscore"}, {"min_feature_events": True}])
def test_malformed_feature_configuration_rejected(store, change):
    with pytest.raises(ValueError):
        features.train(store, actor(), definition(**change))
