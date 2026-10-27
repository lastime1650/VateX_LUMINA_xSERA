"""Stored dataset lifecycle, authentic synthetic intake and model source guards."""
import copy
import importlib.util
import json
import sqlite3
import threading
import time

import pytest
from fastapi.testclient import TestClient

from sapientia import (
    auth,
    cpu_ml,
    cpu_sequence,
    ml_datasets,
    principal,
    source_registry,
)
from sapientia.api import create_app
from sapientia.storage import ConflictError, Settings, Store, encode

PASSWORD = "Dataset-console-tests-only-2026"


def actor(name="admin", tenant="a", indexes=None):
    return {"name": name, "tenant": tenant, "role": "admin" if name == "admin" else "analyst",
            "allowed_indexes": ["*"] if indexes is None else indexes}


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    for name, tenant, role in (("admin", "a", "admin"), ("analyst", "a", "analyst"), ("reviewer", "a", "analyst"), ("other", "b", "analyst")):
        auth.create_user(value, name, PASSWORD, role, tenant)
    yield value
    value.close()


def imported(store, bundle="autoencoder_demo24", index="ml_synthetic_test"):
    return ml_datasets.import_bundle(store, actor(), bundle, {"expected_revision": 0, "indexes": [index]})


def finish(store, dataset, size=16):
    result = None
    for _ in range(128):
        payload = {"expected_revision": dataset["revision"], "confirmed_synthetic": True, "batch_size": size}
        if result:
            payload["materialization_id"] = result["materialization_id"]
        result = ml_datasets.materialize(store, actor(), dataset["id"], payload)
        dataset = result["dataset"]
        if result["completed"]:
            while store.flush(1000):
                pass
            return dataset, result
    raise AssertionError("Bounded materialization did not finish")


def assert_failed_atomic_link_leaves_no_candidate(store, dataset, family):
    prefix = "cpu_sequence" if family == "sequence" else "cpu_ml"
    with store.control() as db:
        before_models = db.execute("SELECT count(*) FROM "+prefix+"_models").fetchone()[0]
        before_links = db.execute("SELECT count(*) FROM ml_dataset_model_links").fetchone()[0]
        before_sources = db.execute("SELECT count(*) FROM ml_dataset_model_sources").fetchone()[0]
        before_refs = db.execute("SELECT count(*) FROM record_case_evidence_refs").fetchone()[0]
        db.execute("CREATE TRIGGER fail_dataset_link BEFORE INSERT ON ml_dataset_model_links BEGIN SELECT RAISE(ABORT,'simulated immutable model link failure'); END")
    try:
        with pytest.raises(sqlite3.IntegrityError, match="model link failure"):
            ml_datasets.train(store, actor(), dataset["id"], {"expected_revision": dataset["revision"],
                "name": "No orphan publication", "epochs": 1, "reviewed_dataset": True, "normal_training_confirmed": True})
    finally:
        with store.control() as db:
            db.execute("DROP TRIGGER fail_dataset_link")
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM "+prefix+"_models").fetchone()[0] == before_models
        assert db.execute("SELECT count(*) FROM ml_dataset_model_links").fetchone()[0] == before_links
        assert db.execute("SELECT count(*) FROM ml_dataset_model_sources").fetchone()[0] == before_sources
        assert db.execute("SELECT count(*) FROM record_case_evidence_refs").fetchone()[0] == before_refs
        assert db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE kind='ml_dataset_train'").fetchone()[0] == 0


def test_packaged_catalog_counts_are_distinct_from_installed_editable_samples(store):
    catalog = ml_datasets.bundle_catalog(store, actor())
    assert catalog["installed_sample_counts"] == {"samples": 0, "templates": 0, "materialized": 0}
    assert [(b["samples"], b["event_count"]) for b in catalog["items"]] == [(24, 24), (96, 1152), (1536, 18432)]
    small, research = imported(store, "sequence_demo96"), imported(store, "sequence_research1536")
    assert small["counts"]["training"] == 64 and research["counts"]["holdout"] == 256
    assert research["counts"]["templates"] == 1536 and research["counts"]["originals"] == 0
    page = ml_datasets.samples(store, actor(), research["id"], count=3)
    assert len(page["items"]) == 3 and page["total"] == 1536 and page["next_cursor"] == 3
    assert all("template_events" not in item and not item["event_ids"] for item in page["items"])
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM source_registry").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM cpu_sequence_models").fetchone()[0] == 0
    assert not ml_datasets.validate(store, actor(), small["id"], {"expected_revision": 1})["ready"]
    with pytest.raises(ValueError, match="Template"):
        ml_datasets.train(store, actor(), small["id"], {"expected_revision": 1, "name": "raw templates cannot train", "reviewed_dataset": True})
    research_batch = ml_datasets.materialize(store, actor(), research["id"], {"expected_revision": 1, "confirmed_synthetic": True, "batch_size": 1})
    assert research_batch["accepted_originals"] == 12 and research_batch["remaining"] == 1535


def test_optimistic_template_edit_remove_and_complete_scope_visibility(store):
    dataset = imported(store)
    sample = ml_datasets.samples(store, actor(), dataset["id"], count=1)["items"][0]
    original = ml_datasets.samples(store, actor(), dataset["id"], sid=sample["id"])["sample"]
    edited = ml_datasets.save_sample(store, actor("analyst"), dataset["id"], {"expected_revision": 1, "sample": {"scenario_id": "editable-template-id", "family": "reviewed-template-family"}}, sample["id"])
    assert edited["revision"] == 2 and edited["sample"]["template_events"] == original["template_events"]
    with pytest.raises(ConflictError):
        ml_datasets.remove_sample(store, actor(), dataset["id"], sample["id"], {"expected_revision": 1})
    assert ml_datasets.listing(store, actor("other", "b"))["total"] == 0
    with pytest.raises(KeyError):
        ml_datasets.get(store, actor("analyst", indexes=["public"]), dataset["id"])
    removed = ml_datasets.remove_sample(store, actor(), dataset["id"], sample["id"], {"expected_revision": 2})
    assert removed["dataset"]["counts"]["samples"] == 23
    history = ml_datasets.revisions(store, actor(), dataset["id"])
    assert history["total"] == 3 and history["items"][-1]["counts"]["samples"] == 24
    assert history["items"][0]["digest"] != history["items"][-1]["digest"]
    with pytest.raises(ValueError, match="Labels"):
        poisoned = copy.deepcopy(original)
        poisoned["template_events"][0]["raw"]["label"] = "attack"
        ml_datasets._sample({key: poisoned[key] for key in ("scenario_id", "family", "host_group", "split", "label", "template_events", "mode")}, "autoencoder")


def test_materialization_requires_current_admin_synthetic_scope_and_explicit_confirmation(store):
    dataset = imported(store)
    with pytest.raises(ValueError, match="confirmation"):
        ml_datasets.materialize(store, actor(), dataset["id"], {"expected_revision": 1})
    with pytest.raises(PermissionError):
        ml_datasets.materialize(store, actor("analyst"), dataset["id"], {"expected_revision": 1, "confirmed_synthetic": True})
    ordinary = imported(store, index="public")
    assert not ordinary["allowed_actions"]["materialize"]
    with pytest.raises(PermissionError, match="synthetic-only"):
        ml_datasets.materialize(store, actor(), ordinary["id"], {"expected_revision": 1, "confirmed_synthetic": True})
    with pytest.raises(ValueError):
        ml_datasets.materialize(store, actor(), dataset["id"], {"expected_revision": 1, "confirmed_synthetic": True, "batch_size": 17})
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 0


def test_custom_template_native_claims_are_overwritten_on_synthetic_admission(store):
    dataset = ml_datasets.create(store, actor(), {"expected_revision": 0, "name": "Custom template", "kind": "autoencoder", "indexes": ["ml_synthetic_custom"]})
    added = ml_datasets.save_sample(store, actor(), dataset["id"], {"expected_revision": 1, "sample": {
        "scenario_id": "custom-template", "family": "custom-normal", "host_group": "virtual-custom-host", "split": "training", "label": "normal",
        "template_events": [{"event_time": 1700000000, "host": "virtual-custom-host", "raw": {
            "agent": {"simulation": False, "native_sensor_collected": True},
            "xdr": {"data": {"agent": {"simulation": False, "native_sensor_collected": True}}}}}]}})
    result = ml_datasets.materialize(store, actor(), dataset["id"], {"expected_revision": added["revision"], "confirmed_synthetic": True})
    assert result["completed"] and not result["native_effects"]
    store.flush()
    row = store.analytics_query("SELECT raw FROM events_all WHERE tenant='a'", [], max_rows=1)["rows"][0]
    raw = json.loads(row["raw"])
    assert raw["agent"]["simulation"] and not raw["agent"]["native_sensor_collected"]
    assert raw["xdr"]["data"]["agent"]["simulation"] and not raw["xdr"]["data"]["agent"]["native_sensor_collected"]


def test_bounded_resumable_intake_authentic_receipts_and_dataset_namespaces(store):
    first = imported(store, "sequence_demo96")
    second = imported(store, "sequence_demo96")
    results = []
    for dataset in (first, second):
        result = ml_datasets.materialize(store, actor(), dataset["id"], {"expected_revision": 1, "confirmed_synthetic": True, "batch_size": 2})
        assert result["remaining"] == 94 and result["accepted_originals"] == 24
        assert result["revision"] == 2 and not result["completed"]
        assert result["native_effects"] is False and result["live_policy_isolation_guaranteed"] is False
        results.append(result)
    one = ml_datasets.samples(store, actor(), first["id"], count=100)["items"]
    two = ml_datasets.samples(store, actor(), second["id"], count=100)["items"]
    ids1 = {eid for s in one for eid in s["event_ids"]}
    ids2 = {eid for s in two for eid in s["event_ids"]}
    assert len(ids1) == len(ids2) == 24 and not ids1 & ids2
    assert not {s["host_group"] for s in one} & {s["host_group"] for s in two}
    while store.flush(1000):
        pass
    with store.control() as db:
        proofs = db.execute("SELECT * FROM source_event_receipts").fetchall()
        assert len(proofs) == 48 and len({p["source_id"] for p in proofs}) == 4
        assert all(p["source_version"] == 1 for p in proofs)
        assert db.execute("SELECT count(*) FROM connector_checkpoints WHERE version=1").fetchone()[0] == 4
        refs = db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE kind='ml_dataset'").fetchone()[0]
        assert refs == 48
    rows = store.analytics_query("SELECT raw FROM events_all WHERE tenant='a'", [], max_rows=100)["rows"]
    for row in rows:
        raw = json.loads(row["raw"])
        ml_datasets._no_truth(raw)
        assert raw["agent"]["simulation"] and raw["xdr"]["data"]["agent"]["native_sensor_collected"] is False
    old = results[0]
    continuation = ml_datasets.materialize(store, actor(), first["id"], {"expected_revision": 2, "confirmed_synthetic": True, "batch_size": 1, "materialization_id": old["materialization_id"]})
    assert continuation["remaining"] == 93 and continuation["accepted_originals"] == 36
    with pytest.raises(ConflictError):
        ml_datasets.materialize(store, actor(), first["id"], {"expected_revision": 2, "confirmed_synthetic": True, "materialization_id": old["materialization_id"]})


def test_interrupted_admission_retries_same_source_cursor_without_overwrite(store, monkeypatch):
    dataset = imported(store)
    original = ml_datasets.connector_runtime.intake
    calls = 0
    def interrupt_after_receipt(*args, **kwargs):
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 2:
            raise RuntimeError("simulated request interruption after durable source ACK")
        return result
    monkeypatch.setattr(ml_datasets.connector_runtime, "intake", interrupt_after_receipt)
    with pytest.raises(RuntimeError):
        ml_datasets.materialize(store, actor(), dataset["id"], {"expected_revision": 1, "confirmed_synthetic": True, "batch_size": 2})
    with store.control() as db:
        job = dict(db.execute("SELECT * FROM ml_dataset_materializations").fetchone())
        assert job["state"] == "pending"
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 2
    monkeypatch.setattr(ml_datasets.connector_runtime, "intake", original)
    reloaded = ml_datasets.get(store, actor(), dataset["id"])
    resume = reloaded["usage"]["materializations"][0]
    assert resume["id"] == job["id"] and resume["resumable"] and resume["owner"] == "admin"
    assert "claim" not in resume and "token" not in resume
    assert not ml_datasets.get(store, actor("reviewer"), dataset["id"])["usage"]["materializations"][0]["resumable"]
    retried = ml_datasets.materialize(store, actor(), dataset["id"], {"expected_revision": reloaded["revision"], "confirmed_synthetic": True, "batch_size": 2, "materialization_id": resume["id"]})
    assert retried["accepted_originals"] == 2
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 2
        assert db.execute("SELECT count(*) FROM source_registry").fetchone()[0] == 2
        assert db.execute("SELECT count(*) FROM connector_checkpoints WHERE version=1").fetchone()[0] == 2
        assert db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE kind='ml_dataset_materialize'").fetchone()[0] == 0


def test_revision_edit_cancels_partial_materialization_releases_only_own_job_refs(store, monkeypatch):
    dataset = imported(store)
    original = ml_datasets.connector_runtime.intake
    def fail_second(*args, **kwargs):
        if fail_second.called:
            raise RuntimeError("stop second sample")
        fail_second.called = True
        return original(*args, **kwargs)
    fail_second.called = False
    monkeypatch.setattr(ml_datasets.connector_runtime, "intake", fail_second)
    with pytest.raises(RuntimeError):
        ml_datasets.materialize(store, actor(), dataset["id"], {"expected_revision": 1, "confirmed_synthetic": True, "batch_size": 2})
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE kind='ml_dataset_materialize'").fetchone()[0] == 1
        job_id = db.execute("SELECT id FROM ml_dataset_materializations").fetchone()[0]
    edited = ml_datasets.update(store, actor(), dataset["id"], {"expected_revision": 1, "name": "Superseded draft"})
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE kind='ml_dataset_materialize'").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 1
    with pytest.raises(ConflictError):
        ml_datasets.materialize(store, actor(), dataset["id"], {"expected_revision": edited["revision"], "confirmed_synthetic": True, "materialization_id": job_id})


def test_real_sequence_bundle_materialize_validate_train_exact_revision_candidate(store):
    if importlib.util.find_spec("torch") is None:
        pytest.skip("Optional CPU PyTorch unavailable")
    dataset, materialization = finish(store, imported(store, "sequence_demo96"))
    assert materialization["accepted_originals"] == 1152
    validated = ml_datasets.validate(store, actor(), dataset["id"], {"expected_revision": dataset["revision"]})
    assert validated["ready"] and validated["counts"]["holdout"] == 16
    trained = ml_datasets.train(store, actor(), dataset["id"], {"expected_revision": dataset["revision"], "name": "Dataset console real GRU", "epochs": 2, "reviewed_dataset": True})
    model = trained["model"]
    assert trained["status"] == "completed" and not model["active"]
    assert model["split_summary"]["training"]["scenarios"] == 64
    assert model["architecture"]["type"] == "gru"
    assert trained["dataset_revision"] == dataset["revision"] and trained["dataset_digest"] == dataset["digest"]
    assert ml_datasets.get(store, actor(), dataset["id"])["usage"]["models"][0]["id"] == model["id"]
    assert_failed_atomic_link_leaves_no_candidate(store, dataset, "sequence")
    with pytest.raises(PermissionError, match="creator"):
        cpu_sequence.activate(store, actor(), model["id"], "creator must not self approve this candidate")
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE kind='ml_dataset_train'").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE kind='cpu_sequence_model' AND record_id=?", (model["id"],)).fetchone()[0] == 1152
    deleted = ml_datasets.remove(store, actor(), dataset["id"], {"expected_revision": dataset["revision"], "notes": "remove draft only"})
    assert not deleted["originals_deleted"] and not deleted["models_changed"]
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE kind='ml_dataset'").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 1152
        assert db.execute("SELECT count(*) FROM cpu_sequence_models").fetchone()[0] == 1


def test_actual_dataset_ae_guard_survives_delete_and_rejects_missing_provenance(store):
    if importlib.util.find_spec("torch") is None:
        pytest.skip("Optional CPU PyTorch unavailable")
    dataset, _ = finish(store, imported(store))
    result = ml_datasets.train(store, actor(), dataset["id"], {"expected_revision": dataset["revision"], "name": "Dataset guarded AE", "epochs": 2, "reviewed_dataset": True, "normal_training_confirmed": True})
    model = result["model"]
    assert_failed_atomic_link_leaves_no_candidate(store, dataset, "autoencoder")
    with store.control() as db:
        assert json.loads(db.execute("SELECT definition FROM cpu_ml_models").fetchone()[0])["dataset_source_guard"]["schema"] == "xsera.dataset-model-sources.v1"
    ml_datasets.remove(store, actor(), dataset["id"], {"expected_revision": dataset["revision"]})
    cpu_ml.activate(store, actor("reviewer"), model["id"], "Independent review of dataset normal source cohort")
    with principal.transaction(store, actor(), write=True) as (db, fresh):
        assert cpu_ml.validate_publication(store, db, fresh, model["id"], model["digest"], model["revision"])["active"]
        db.execute("DELETE FROM ml_dataset_model_sources WHERE model_id=?", (model["id"],))
    with pytest.raises(ConflictError, match="provenance disappeared"):
        cpu_ml.rollback(store, actor("reviewer"), model["id"], "Missing provenance must never silently become legacy")


def test_inflight_ae_source_revoke_has_no_candidate_and_keeps_pins_until_fail(store, monkeypatch):
    if importlib.util.find_spec("torch") is None:
        pytest.skip("Optional CPU PyTorch unavailable")
    dataset, _ = finish(store, imported(store))
    original = cpu_ml._worker
    def revoke_after_tensor(*args, **kwargs):
        with store.control() as db:
            assert db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE kind='ml_dataset_train'").fetchone()[0] == 24
            source = dict(db.execute("SELECT * FROM source_registry LIMIT 1").fetchone())
        source_registry.revoke(store, actor(), source["id"], source["version"])
        return original(*args, **kwargs)
    monkeypatch.setattr(cpu_ml, "_worker", revoke_after_tensor)
    with pytest.raises(PermissionError, match="source unavailable"):
        ml_datasets.train(store, actor(), dataset["id"], {"expected_revision": dataset["revision"], "name": "Must fail closed", "epochs": 1, "reviewed_dataset": True, "normal_training_confirmed": True})
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM cpu_ml_models").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM ml_dataset_model_sources").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE kind='ml_dataset_train'").fetchone()[0] == 0


def test_inflight_dataset_removal_freezes_revision_and_keeps_model_provenance(store, monkeypatch):
    if importlib.util.find_spec("torch") is None:
        pytest.skip("Optional CPU PyTorch unavailable")
    dataset, _ = finish(store, imported(store))
    original = cpu_ml._worker
    def remove_during_tensor(*args, **kwargs):
        ml_datasets.remove(store, actor(), dataset["id"], {"expected_revision": dataset["revision"]})
        with store.control() as db:
            assert db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE kind='ml_dataset_train'").fetchone()[0] == 24
            assert db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE kind='ml_dataset'").fetchone()[0] == 0
        return original(*args, **kwargs)
    monkeypatch.setattr(cpu_ml, "_worker", remove_during_tensor)
    result = ml_datasets.train(store, actor(), dataset["id"], {"expected_revision": dataset["revision"], "name": "Frozen removed revision", "epochs": 1, "reviewed_dataset": True, "normal_training_confirmed": True})
    assert result["head_changed"] and result["dataset_revision"] == dataset["revision"]
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE kind='cpu_ml_model'").fetchone()[0] == 24
        assert db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE kind='ml_dataset_train'").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM ml_dataset_model_sources").fetchone()[0] == 1


def test_current_source_revoke_and_tampered_revision_block_validate_train(store):
    dataset, _ = finish(store, imported(store))
    assert ml_datasets.validate(store, actor(), dataset["id"], {"expected_revision": dataset["revision"]})["ready"]
    with store.control() as db:
        source = dict(db.execute("SELECT * FROM source_registry LIMIT 1").fetchone())
    source_registry.revoke(store, actor(), source["id"], source["version"])
    result = ml_datasets.validate(store, actor(), dataset["id"], {"expected_revision": dataset["revision"]})
    assert not result["ready"] and "source unavailable" in result["issues"][0]["message"]
    with store.control() as db:
        body = json.loads(db.execute("SELECT summary FROM ml_dataset_revisions WHERE dataset_id=? AND revision=?", (dataset["id"], dataset["revision"])).fetchone()[0])
        body["counts"]["normal"] -= 1
        db.execute("UPDATE ml_dataset_revisions SET summary=? WHERE dataset_id=? AND revision=?", (encode(body), dataset["id"], dataset["revision"]))
    with pytest.raises(ConflictError, match="revision hash"):
        ml_datasets.validate(store, actor(), dataset["id"], {"expected_revision": dataset["revision"]})


def test_original_sample_edit_requires_registered_proof_and_no_duplicate_ids(store):
    dataset = ml_datasets.create(store, actor(), {"expected_revision": 0, "name": "Original selection", "kind": "autoencoder", "indexes": ["ml_synthetic_test"]})
    store.ingest("a", [{"event_id": "unregistered", "host": "unregistered-host", "index": "ml_synthetic_test", "event_time": 1700000000}])
    store.flush()
    with pytest.raises(ConflictError, match="receipt unavailable"):
        ml_datasets.save_sample(store, actor(), dataset["id"], {"expected_revision": 1, "sample": {
            "scenario_id": "original-selector", "family": "normal", "host_group": "unregistered-host", "split": "training", "label": "normal", "event_ids": ["unregistered"]}})
    admitted, _ = finish(store, imported(store))
    sample = ml_datasets.samples(store, actor(), admitted["id"], count=1)["items"][0]
    added = ml_datasets.save_sample(store, actor(), dataset["id"], {"expected_revision": 1, "sample": {
        "scenario_id": "selected-authentic-event", "family": "selected-normal-family", "host_group": sample["host_group"],
        "split": "training", "label": "normal", "event_ids": sample["event_ids"]}})
    assert added["sample"]["mode"] == "originals" and added["sample"]["materialized"]
    with pytest.raises(ValueError, match="multiple"):
        ml_datasets.save_sample(store, actor(), dataset["id"], {"expected_revision": 2, "sample": {
            "scenario_id": "duplicate-in-another-split", "family": "independent-calibration-family", "host_group": sample["host_group"],
            "split": "calibration", "label": "normal", "event_ids": sample["event_ids"]}})
    edited = ml_datasets.save_sample(store, actor(), dataset["id"], {"expected_revision": 2, "sample": {"family": "edited-normal-family"}}, added["sample"]["id"])
    assert edited["sample"]["event_ids"] == sample["event_ids"] and edited["revision"] == 3
    removed = ml_datasets.remove_sample(store, actor(), dataset["id"], added["sample"]["id"], {"expected_revision": 3})
    assert removed["dataset"]["counts"]["originals"] == 0
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM receipts WHERE event_id=?", (sample["event_ids"][0],)).fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE kind='ml_dataset' AND record_id=?", (admitted["id"],)).fetchone()[0] == 24


@pytest.mark.parametrize("mutation", ["source", "source_owner", "source_proof", "guard_hash"])
def test_dataset_ae_current_authority_rechecked_after_independent_activation(store, monkeypatch, mutation):
    if importlib.util.find_spec("torch") is None:
        pytest.skip("Optional CPU PyTorch unavailable")
    dataset, _ = finish(store, imported(store))
    result = ml_datasets.train(store, actor("analyst"), dataset["id"], {"expected_revision": dataset["revision"], "name": "Fresh source guard", "epochs": 1, "reviewed_dataset": True, "normal_training_confirmed": True})
    model = result["model"]
    cpu_ml.activate(store, actor("reviewer"), model["id"], "Independent current source review before activation")
    with store.control() as db:
        source = dict(db.execute("SELECT * FROM source_registry LIMIT 1").fetchone())
    if mutation == "source":
        source_registry.revoke(store, actor(), source["id"], source["version"])
    elif mutation == "source_owner":
        with store.write_lock, store.control() as db:
            db.execute("UPDATE users SET role='viewer' WHERE name='admin'")
    elif mutation == "source_proof":
        with store.write_lock, store.control() as db:
            db.execute("UPDATE source_event_receipts SET source_version=99 WHERE source_id=?", (source["id"],))
    else:
        with store.write_lock, store.control() as db:
            db.execute("UPDATE ml_dataset_model_sources SET digest=? WHERE model_id=?", ("0"*64, model["id"]))
    with pytest.raises((PermissionError, ConflictError)), principal.transaction(store, actor("analyst"), write=True) as (db, fresh):
        cpu_ml.validate_publication(store, db, fresh, model["id"], model["digest"], model["revision"])
    with pytest.raises((PermissionError, ConflictError)):
        cpu_ml.rollback(store, actor("reviewer"), model["id"], "Current authority must be checked again on rollback")


def test_real_authenticated_api_forms_revision_pagination_csrf_and_request_cap(tmp_path):
    app = create_app(Settings(tmp_path, min_free_bytes=0), background=False)
    with TestClient(app) as client:
        assert client.post("/api/setup", json={"name": "admin", "password": PASSWORD}).status_code == 200
        login = client.post("/api/login", json={"name": "admin", "password": PASSWORD})
        headers = {"x-csrf-token": login.json()["csrf"]}
        catalog = client.get("/api/v3/ml/dataset-bundles")
        assert catalog.status_code == 200 and len(catalog.json()["items"]) == 3
        response = client.post("/api/v3/ml/dataset-bundles/autoencoder_demo24/import", json={"expected_revision": 0, "indexes": ["ml_synthetic_ui"]}, headers=headers)
        assert response.status_code == 201, response.text
        dataset = response.json()
        path = "/api/v3/ml/datasets/"+dataset["id"]
        assert client.get(path+"/samples?count=2").json()["next_cursor"] == 2
        assert client.get(path+"/revisions").json()["total"] == 1
        assert client.put(path, json={"expected_revision": 1, "name": "No CSRF"}).status_code == 403
        stale = client.put(path, json={"expected_revision": 0, "name": "Stale"}, headers=headers)
        assert stale.status_code == 409
        oversized = client.post(path+"/samples", content=b"x"*(2*1024*1024+1), headers={**headers, "content-type": "application/json"})
        assert oversized.status_code == 413
        removed = client.request("DELETE", path, json={"expected_revision": 1}, headers=headers)
        assert removed.status_code == 200 and removed.json()["models_changed"] is False
        assert client.get("/api/v3/ml/datasets").json()["total"] == 0


def _persist_training_claim(store, identifier, expiry, *, tenant="a", state="running", model_id=None):
    with store.control() as db:
        db.execute("INSERT INTO ml_dataset_training_claims VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
            (identifier, tenant, "interrupted-dataset", 3, "frozen-dataset-digest", "admin", identifier+"-token",
             1., expiry, state, "sequence", model_id, None))
        db.execute("INSERT INTO record_case_evidence_refs VALUES(?,?,?,?)", (tenant, "crash-original", "ml_dataset_train", identifier))


def test_real_store_restart_expires_only_abandoned_own_refs_and_keeps_completed_candidate(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    value.ingest("a", [{"event_id": "crash-original", "index": "public"}])
    value.ingest("b", [{"event_id": "crash-original", "index": "private"}])
    value.flush()
    now = time.time()
    _persist_training_claim(value, "expired-training", now-1)
    _persist_training_claim(value, "unexpired-training", now+600)
    _persist_training_claim(value, "published-before-crash", now-1, state="completed", model_id="retained-candidate-id")
    with value.control() as db:
        for tenant, kind, record in (("a", "cpu_sequence_model", "retained-candidate-id"), ("a", "case", "case-id"),
                                    ("a", "ml_dataset", "dataset-id"), ("b", "ml_dataset_train", "expired-training")):
            db.execute("INSERT INTO record_case_evidence_refs VALUES(?,?,?,?)", (tenant, "crash-original", kind, record))
    value.close()
    reopened = Store(Settings(tmp_path, min_free_bytes=0))
    try:
        with reopened.control() as db:
            rows = {row["id"]: dict(row) for row in db.execute("SELECT * FROM ml_dataset_training_claims")}
            assert rows["expired-training"]["state"] == "expired" and rows["expired-training"]["pins_released"] == 1
            assert rows["unexpired-training"]["state"] == "running" and rows["unexpired-training"]["pins_released"] == 0
            assert rows["published-before-crash"]["state"] == "completed" and rows["published-before-crash"]["model_id"] == "retained-candidate-id"
            assert rows["published-before-crash"]["pins_released"] == 1
            refs = {(row["tenant"], row["kind"], row["record_id"]) for row in db.execute("SELECT * FROM record_case_evidence_refs")}
            assert refs == {("a", "ml_dataset_train", "unexpired-training"), ("a", "cpu_sequence_model", "retained-candidate-id"),
                            ("a", "case", "case-id"), ("a", "ml_dataset", "dataset-id"), ("b", "ml_dataset_train", "expired-training")}
            assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 2
        assert ml_datasets.run_due(reopened, now=now)["expired_training_claims"] == 0
    finally:
        reopened.close()


def test_training_recovery_preserves_active_invocations_and_is_bounded_cancelable(store):
    now = time.time()
    identifiers = ["active-a", "active-b", "abandoned-a", "abandoned-b", "abandoned-c"]
    for identifier in identifiers:
        _persist_training_claim(store, identifier, now-1)
    active_keys = [ml_datasets._training_key(store, identifier) for identifier in identifiers[:2]]
    with ml_datasets._TRAINING_LOCK:
        ml_datasets._ACTIVE_TRAINING.update(active_keys)
    try:
        cancelled = threading.Event()
        cancelled.set()
        assert ml_datasets.run_due(store, now=now, cancel=cancelled, max_runs=1)["expired_training_claims"] == 0
        assert ml_datasets.run_due(store, now=now, budget=0, max_runs=1)["expired_training_claims"] == 0
        assert ml_datasets.run_due(store, now=now, max_runs=1)["expired_training_claims"] == 1
        with store.control() as db:
            assert db.execute("SELECT count(*) FROM ml_dataset_training_claims WHERE state='expired'").fetchone()[0] == 1
            assert db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE record_id IN ('active-a','active-b')").fetchone()[0] == 2
        assert ml_datasets.run_due(store, now=now, max_runs=64)["expired_training_claims"] == 2
    finally:
        with ml_datasets._TRAINING_LOCK:
            ml_datasets._ACTIVE_TRAINING.difference_update(active_keys)
    assert ml_datasets.run_due(store, now=now, max_runs=64)["expired_training_claims"] == 2
