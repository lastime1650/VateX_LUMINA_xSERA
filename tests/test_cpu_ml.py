"""CPU model execution, original provenance, approval and revocation contracts."""

import importlib.util
import json

import pytest

from sapientia import access, auth, cpu_ml, migrations, principal
from sapientia.storage import ConflictError, Settings, Store


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setitem(migrations.SUPPORTED, "cpu_ml", 1)
    value = Store(Settings(tmp_path, min_free_bytes=0))
    cpu_ml.initialize(value)
    for name, tenant in (("trainer", "a"), ("reviewer", "a"), ("other", "b"), ("admin", "a")):
        auth.create_user(value, name, "CPU-model-test-password-2026", "admin" if name == "admin" else "analyst", tenant)
    yield value
    value.close()


def actor(name="trainer", tenant="a", indexes=None):
    return {"name": name, "tenant": tenant, "role": "admin" if name == "admin" else "analyst",
            "allowed_indexes": ["*"] if indexes is None else indexes}


def seed(store):
    events = [{"event_id": f"normal-{i}", "event_time": 1704110400+i,
               "index": "public", "host": "sample-host", "raw": {
                   "command_line": "echo normal", "dest_port": 443,
                   "dest_ip": "10.1.0.2", "process_depth": 1}}
              for i in range(32)]
    events.append({"event_id": "abnormal", "event_time": 1704110400,
                   "index": "public", "host": "sample-host", "raw": {
                       "command_line": "x"*8192, "dest_port": 65535,
                       "dest_ip": "8.8.8.8", "process_depth": 32,
                       "file_path": "C:/sample/file.exe"}})
    store.ingest("a", events)
    store.flush()


def definition(**changes):
    return {"name": "reviewed-normal-cohort", "indexes": ["public"],
            "training_ids": [f"normal-{i}" for i in range(24)],
            "validation_ids": [f"normal-{i}" for i in range(24, 32)],
            "epochs": 80, "normal_training_confirmed": True, **changes}


def test_real_cpu_training_review_original_inference_and_rollback(store):
    if importlib.util.find_spec("torch") is None:
        pytest.skip("Optional CPU PyTorch framework unavailable")
    assert cpu_ml.runtime_status(force=True)["available"]
    assert cpu_ml.runtime_status()["device"] == "cpu"
    seed(store)
    model = cpu_ml.train(store, actor(), definition())
    assert model["status"] == "completed" and not model["active"]
    assert model["metrics"]["training_mse"] < model["metrics"]["initial_training_mse"]
    assert model["metrics"]["validation_samples"] == 8
    assert not model["metrics"]["malicious_precision_recall_measured"]
    with pytest.raises(PermissionError, match="creator"):
        cpu_ml.activate(store, actor(), model["id"], "I reviewed my own cohort")
    with pytest.raises(PermissionError, match="approval"):
        cpu_ml.infer_events(store, actor(), [{"event_id": "abnormal"}], model_id=model["id"])
    shadow = cpu_ml.infer_events(store, actor(), [{"event_id": "abnormal"}], model_id=model["id"], shadow=True)
    assert shadow["shadow"] and shadow["results"][0]["anomaly"]
    cpu_ml.activate(store, actor("reviewer"), model["id"], "Reviewed original holdout and training cohort")
    assert cpu_ml.compatible_models(store, actor(), ["public"])[0]["id"] == model["id"]
    assert cpu_ml.compatible_models(store, actor(), ["private"]) == []
    with principal.transaction(store, actor(), write=True) as (db, current):
        assert cpu_ml.validate_publication(store, db, current, model["id"], model["digest"], model["revision"])["active"]
        with pytest.raises(ConflictError, match="different immutable"):
            cpu_ml.validate_publication(store, db, current, model["id"], "0"*64, model["revision"])
    # A caller's fabricated features cannot replace the persisted original.
    result = cpu_ml.infer_events(store, actor(), [
        {"event_id": "normal-31"}, {"event_id": "abnormal", "raw": {"command_line": "echo fine"}}])
    by_id = {row["event_id"]: row for row in result["results"]}
    assert by_id["abnormal"]["anomaly"]
    assert not by_id["normal-31"]["anomaly"]
    assert by_id["abnormal"]["features"]["command_length_scaled"] == 1
    assert by_id["abnormal"]["digest"] == model["digest"]
    assert len(by_id["abnormal"]["provenance"]["receipt_digest"]) == 64
    assert not by_id["abnormal"]["malicious_probability"]
    assert cpu_ml.list_models(store, actor("other", "b")) == []
    with pytest.raises(KeyError):
        cpu_ml.infer_events(store, actor("other", "b"), [{"event_id": "abnormal"}], model_id=model["id"])
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE kind='cpu_ml_model'").fetchone()[0] == 32
        assert db.execute("SELECT count(*) FROM cpu_ml_runs").fetchone()[0] == 2
    second = cpu_ml.train(store, actor(), definition(epochs=60))
    assert second["revision"] == 2 and second["digest"] != model["digest"]
    cpu_ml.activate(store, actor("reviewer"), second["id"], "Reviewed second model against first version")
    assert not next(row for row in cpu_ml.list_models(store, actor()) if row["id"] == model["id"])["active"]
    cpu_ml.rollback(store, actor("reviewer"), model["id"], "Reviewed rollback to previous stable candidate")
    assert next(row for row in cpu_ml.list_models(store, actor()) if row["id"] == model["id"])["active"]
    cpu_ml.disable(store, actor(), model["id"])
    with principal.transaction(store, actor(), write=True) as (db, current):
        with pytest.raises(PermissionError, match="approval"):
            cpu_ml.validate_publication(store, db, current, model["id"], model["digest"], model["revision"])
    assert cpu_ml.infer_events(store, actor(), [{"event_id": "abnormal"}])["status"] == "no_active_model"


def test_scope_duplicate_holdout_and_unavailable_contract(store, monkeypatch):
    with pytest.raises(ValueError, match="disjoint"):
        cpu_ml.train(store, actor(), definition(validation_ids=[f"normal-{i}" for i in range(8)]))
    with pytest.raises(PermissionError, match="scope"):
        cpu_ml.train(store, actor(indexes=["public"]), definition(indexes=["private"]))
    with pytest.raises(ValueError, match="acknowledgement"):
        cpu_ml.train(store, actor(), definition(normal_training_confirmed=False))
    unavailable = {"available": False, "status": "시스템에서 호환되지 않음", "simulation_continues": True}
    monkeypatch.setattr(cpu_ml, "_status_cache", unavailable)
    monkeypatch.setattr(cpu_ml, "_status_retry_at", cpu_ml.time.monotonic() + cpu_ml.STATUS_NEGATIVE_TTL_SECONDS)
    result = cpu_ml.train(store, actor(), definition())
    assert result["available"] is False and result["status"] == "unavailable"
    assert cpu_ml.run_due(store)["automatic_training"] is False


def test_model_integrity_and_current_reviewer_scope(store):
    if importlib.util.find_spec("torch") is None:
        pytest.skip("Optional CPU PyTorch framework unavailable")
    seed(store)
    model = cpu_ml.train(store, actor(), definition())
    cpu_ml.activate(store, actor("reviewer"), model["id"], "Independent review of source and baseline")
    access.set_for_user(store, actor("admin"), "reviewer", ["private"])
    with pytest.raises(PermissionError, match="reviewer"):
        cpu_ml.infer_events(store, actor(), [{"event_id": "abnormal"}], model_id=model["id"])
    access.set_for_user(store, actor("admin"), "reviewer", ["public"])
    with store.control() as db:
        snapshot = json.loads(db.execute("SELECT snapshot FROM cpu_ml_models WHERE id=?", (model["id"],)).fetchone()[0])
        snapshot["threshold"] = 0.99
        db.execute("UPDATE cpu_ml_models SET snapshot=? WHERE id=?", (json.dumps(snapshot), model["id"]))
    with pytest.raises(ConflictError, match="hash mismatch"):
        cpu_ml.infer_events(store, actor(), [{"event_id": "abnormal"}], model_id=model["id"])


def test_feature_schema_has_bounded_values_and_ignores_labels():
    event = {"event_time": 1704110400, "raw": {"dest_port": 99999999, "command_line": "x"*9000,
             "process_depth": 9999, "attack_label": "ground truth is not a feature"}}
    values = cpu_ml.extract_features(event)
    assert tuple(values) == cpu_ml.FEATURES
    assert all(0 <= value <= 1 for value in values.values())
    assert "attack_label" not in values


def test_nested_endpoint_features_use_explicit_original_fields():
    event = {"event_time": 1704110400, "raw": {"xdr": {"data": {
        "process": {"command_line": "x"*4096, "depth": 4, "parent": {"guid": "reported-parent"}},
        "destination": {"port": 65535, "ip": "8.8.8.8"},
        "file": {"path": "C:/observed.bin"}, "event": {"action": "file_created"}}}}}
    features = cpu_ml.extract_features(event)
    assert features["command_length_scaled"] == .5 and features["remote_port_scaled"] == 1
    assert features["network_external"] == 1 and features["file_activity"] == 1
    assert features["process_depth"] == 4/32
    del event["raw"]["xdr"]["data"]["process"]["depth"]
    assert cpu_ml.extract_features(event)["process_depth"] == 0  # A parent GUID cannot invent a depth.


@pytest.fixture
def status_probe_clock(monkeypatch):
    from types import SimpleNamespace

    clock = [100.0]
    monkeypatch.setattr(cpu_ml, "_status_cache", None)
    monkeypatch.setattr(cpu_ml, "_status_retry_at", 0.0)
    monkeypatch.setattr(cpu_ml, "time", SimpleNamespace(monotonic=lambda: clock[0], time=cpu_ml.time.time))
    return clock


def test_runtime_status_recovers_after_negative_ttl(monkeypatch, status_probe_clock):
    calls = []

    def worker(payload, timeout):
        calls.append((payload, timeout))
        return ({"worker_error": "Unavailable", "reason": "transient startup"} if len(calls) == 1 else
                {"available": True, "framework": "pytorch", "device": "cpu"})

    monkeypatch.setattr(cpu_ml, "_worker", worker)
    failed = cpu_ml.runtime_status()
    assert failed["available"] is False and failed["simulation_continues"]
    assert failed["reason"] == "transient startup"
    status_probe_clock[0] = 104.999
    assert cpu_ml.runtime_status() == failed and len(calls) == 1
    status_probe_clock[0] = 105.0
    assert cpu_ml.runtime_status()["available"] is True
    assert calls == [({"operation": "status"}, 30), ({"operation": "status"}, 30)]


def test_runtime_status_force_bypasses_deadline_negative_ttl(monkeypatch, status_probe_clock):
    from sapientia.storage import CapacityError

    calls = []

    def worker(payload, timeout):
        calls.append((payload, timeout))
        if len(calls) == 1:
            raise CapacityError("bounded startup deadline")
        return {"available": True, "framework": "pytorch", "device": "cpu"}

    monkeypatch.setattr(cpu_ml, "_worker", worker)
    assert cpu_ml.runtime_status()["reason"] == "bounded startup deadline"
    assert cpu_ml.runtime_status()["available"] is False and len(calls) == 1
    assert cpu_ml.runtime_status(force=True)["available"] is True and len(calls) == 2
    assert status_probe_clock[0] == 100.0


def test_runtime_status_persistent_failure_has_bounded_retry_rate(monkeypatch, status_probe_clock):
    calls = []

    def worker(payload, timeout):
        calls.append((payload, timeout))
        return {"available": False, "reason": "framework absent", "simulation_continues": True}

    monkeypatch.setattr(cpu_ml, "_worker", worker)
    for expected_calls in range(1, 4):
        for _ in range(10):
            assert cpu_ml.runtime_status()["available"] is False
        assert len(calls) == expected_calls
        status_probe_clock[0] += 5.0
    assert all(timeout == 30 for _, timeout in calls)


def test_runtime_status_positive_cache_and_returned_copies(monkeypatch, status_probe_clock):
    calls = []

    def worker(payload, timeout):
        calls.append((payload, timeout))
        return {"available": True, "framework": "pytorch", "device": "cpu", "version": str(len(calls))}

    monkeypatch.setattr(cpu_ml, "_worker", worker)
    first = cpu_ml.runtime_status()
    first["available"] = False
    first["device"] = "caller-mutation"
    status_probe_clock[0] += 100000.0
    cached = cpu_ml.runtime_status()
    assert cached["available"] is True and cached["device"] == "cpu" and cached["version"] == "1"
    assert len(calls) == 1 and cached is not first
    assert cpu_ml.runtime_status(force=True)["version"] == "2" and len(calls) == 2


def test_runtime_status_concurrent_cold_start_uses_one_handshake(monkeypatch, status_probe_clock):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    barrier = threading.Barrier(6)
    entered = threading.Event()
    release = threading.Event()
    calls = []

    def worker(payload, timeout):
        calls.append((payload, timeout))
        entered.set()
        assert release.wait(2), "test did not release the bounded mock handshake"
        return {"available": True, "framework": "pytorch", "device": "cpu"}

    def query():
        barrier.wait(2)
        return cpu_ml.runtime_status()

    monkeypatch.setattr(cpu_ml, "_worker", worker)
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(query) for _ in range(6)]
        try:
            assert entered.wait(2)
        finally:
            release.set()
        results = [future.result(timeout=2) for future in futures]
    assert calls == [({"operation": "status"}, 30)]
    assert all(row["available"] is True for row in results)
    assert len({id(row) for row in results}) == 6
    results[0]["device"] = "caller-mutation"
    assert cpu_ml.runtime_status()["device"] == "cpu"


def test_runtime_status_negative_ttl_begins_after_handshake(monkeypatch, status_probe_clock):
    calls = []

    def worker(payload, timeout):
        calls.append((payload, timeout))
        if len(calls) == 1:
            status_probe_clock[0] += 30.0
            return {"worker_error": "Deadline", "reason": "cold import timeout"}
        return {"available": True, "framework": "pytorch", "device": "cpu"}

    monkeypatch.setattr(cpu_ml, "_worker", worker)
    assert cpu_ml.runtime_status()["available"] is False
    assert cpu_ml._status_retry_at == 135.0
    status_probe_clock[0] = 134.999
    assert cpu_ml.runtime_status()["available"] is False and len(calls) == 1
    status_probe_clock[0] = 135.0
    assert cpu_ml.runtime_status()["available"] is True and len(calls) == 2
