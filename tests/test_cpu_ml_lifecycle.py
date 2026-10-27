"""Normal payload archival preserves permanent evidence/history contracts."""
import importlib.util
import json

import pytest

from sapientia import access, cpu_ml, cpu_ml_lifecycle
from sapientia.storage import ConflictError
from tests.test_cpu_ml import actor, definition, seed, store


def test_normal_shadow_archive_keeps_live_anomaly_model_and_other_refs(store):
    if importlib.util.find_spec("torch") is None:
        pytest.skip("Optional CPU PyTorch unavailable")
    seed(store)
    model = cpu_ml.train(store, actor(), definition())
    cpu_ml.activate(store, actor("reviewer"), model["id"], "Independent actual model review")
    live = cpu_ml.infer_events(store, actor(), [{"event_id": "normal-31"}, {"event_id": "abnormal"}], model_id=model["id"])
    shadow = cpu_ml.infer_events(store, actor(), [{"event_id": "abnormal"}], model_id=model["id"], shadow=True)
    with store.control() as db:
        db.execute("INSERT OR IGNORE INTO record_case_evidence_refs VALUES('a','normal-31','bookmark','other-protected-record')")
    result = cpu_ml_lifecycle.archive_runs(store, actor(), "autoencoder", [live["run_id"], shadow["run_id"]], "Archive normal/shadow payloads while retaining anomaly and model evidence")
    assert result["archives"][0]["normal_result_count_archived"] == 1
    assert result["archives"][1]["normal_result_count_archived"] == 1
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM cpu_ml_runs").fetchone()[0] == 2
        assert db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE kind='cpu_ml_model'").fetchone()[0] == 32
        assert db.execute("SELECT 1 FROM record_case_evidence_refs WHERE kind='bookmark' AND record_id='other-protected-record'").fetchone()
        assert db.execute("SELECT 1 FROM record_case_evidence_refs WHERE event_id='abnormal' AND kind='cpu_ml_anomaly'").fetchone()
        assert not db.execute("SELECT 1 FROM record_case_evidence_refs WHERE kind='cpu_ml_run'").fetchone()
        payload = json.loads(db.execute("SELECT result FROM cpu_ml_runs WHERE id=?", (live["run_id"],)).fetchone()[0])
        assert len(payload["results"]) == 1 and payload["results"][0]["anomaly"]
        assert len(payload["archive"]["original_payload_digest"]) == 64
    assert store.analytics_query("SELECT count(*) AS n FROM events_all WHERE tenant='a'", [], max_rows=1)["rows"][0]["n"] == 33
    again = cpu_ml_lifecycle.archive_runs(store, actor(), "autoencoder", [live["run_id"]], "Idempotent archival")
    assert again["archives"][0] == result["archives"][0]


def test_archival_rechecks_full_scope_and_immutable_payload(store):
    if importlib.util.find_spec("torch") is None:
        pytest.skip("Optional CPU PyTorch unavailable")
    seed(store)
    model = cpu_ml.train(store, actor(), definition())
    run = cpu_ml.infer_events(store, actor(), [{"event_id": "normal-31"}], model_id=model["id"], shadow=True)
    access.set_for_user(store, actor("admin"), "trainer", ["private"])
    with pytest.raises(KeyError):
        cpu_ml_lifecycle.archive_runs(store, actor(), "autoencoder", [run["run_id"]], "Scope revoked")
    with store.control() as db:
        db.execute("UPDATE cpu_ml_runs SET result='{}' WHERE id=?", (run["run_id"],))
    with pytest.raises(ConflictError, match="payload changed"):
        cpu_ml_lifecycle.archive_runs(store, actor("admin"), "autoencoder", [run["run_id"]], "Tampering must not release refs")
    with store.control() as db:
        assert db.execute("SELECT 1 FROM record_case_evidence_refs WHERE kind='cpu_ml_run' AND record_id=?", (run["run_id"],)).fetchone()


def test_inactive_model_retirement_retains_other_version_and_anomaly_refs(store):
    if importlib.util.find_spec("torch") is None:
        pytest.skip("Optional CPU PyTorch unavailable")
    seed(store)
    old = cpu_ml.train(store, actor(), definition())
    current = cpu_ml.train(store, actor(), definition(epochs=60))
    cpu_ml.activate(store, actor("reviewer"), old["id"], "Reviewed first actual candidate")
    cpu_ml.infer_events(store, actor(), [{"event_id": "abnormal"}], model_id=old["id"])
    with pytest.raises(ConflictError, match="Active"):
        cpu_ml_lifecycle.retire_model(store, actor("reviewer"), "autoencoder", old["id"], "Active retirement forbidden")
    cpu_ml.activate(store, actor("reviewer"), current["id"], "Reviewed newer immutable model")
    with pytest.raises(PermissionError, match="creator"):
        cpu_ml_lifecycle.retire_model(store, actor(), "autoencoder", old["id"], "Self retirement forbidden")
    summary = cpu_ml_lifecycle.retire_model(store, actor("reviewer"), "autoencoder", old["id"], "Independent review archives previous inactive version")
    assert summary["training_reference_count_released"] == 32 and summary["other_protected_original_count"] == 32
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM cpu_ml_models").fetchone()[0] == 2
        assert db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE kind='cpu_ml_model' AND record_id=?", (current["id"],)).fetchone()[0] == 32
        assert db.execute("SELECT 1 FROM record_case_evidence_refs WHERE kind='cpu_ml_anomaly' AND event_id='abnormal'").fetchone()
        assert not db.execute("SELECT 1 FROM record_case_evidence_refs WHERE kind='cpu_ml_model' AND record_id=?", (old["id"],)).fetchone()
    with pytest.raises(ConflictError, match="Retired"):
        cpu_ml.infer_events(store, actor(), [{"event_id": "normal-31"}], model_id=old["id"], shadow=True)
    with pytest.raises(ConflictError, match="Retired"):
        cpu_ml.rollback(store, actor("reviewer"), old["id"], "Retired version cannot be restored")
    assert next(row for row in cpu_ml.list_models(store, actor()) if row["id"] == old["id"])["retired"]
