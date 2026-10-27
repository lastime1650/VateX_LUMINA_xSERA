"""Console forms use authenticated, persisted dataset and starter contracts."""

import pytest

from tests.test_api import client as isolated_app_fixture
from tests.test_api import sign_in


@pytest.fixture
def client(tmp_path):
    yield from isolated_app_fixture.__wrapped__(tmp_path)


def test_dataset_console_assets_and_fresh_actual_counts(client):
    assert client.get("/api/v3/ml/dataset-bundles").status_code == 401
    sign_in(client)
    page = client.get("/")
    for asset in ("console_datasets.js", "console_datasets.css", "console_policy_editor.js"):
        assert asset in page.text
        assert client.get("/static/" + asset).status_code == 200
    catalog = client.get("/api/v3/ml/dataset-bundles").json()
    assert len(catalog["items"]) == 3
    assert catalog["installed_sample_counts"] == {"samples": 0, "templates": 0, "materialized": 0}
    listing = client.get("/api/v3/ml/datasets?count=25").json()
    assert listing["items"] == [] and listing["total"] == 0
    assert client.get("/api/v3/intelligence/templates").json()["total"] == 8


def test_console_template_edit_validate_revisions_and_remove_preserve_admission_boundary(client):
    sign_in(client)
    response = client.post("/api/v3/ml/dataset-bundles/autoencoder_demo24/import", json={
        "expected_revision": 0, "name": "Console reviewed examples", "description": "Draft only",
        "indexes": ["ml_synthetic_console"],
    })
    assert response.status_code == 201, response.text
    dataset = response.json()
    base = "/api/v3/ml/datasets/" + dataset["id"]
    assert dataset["counts"]["samples"] == 24 and dataset["counts"]["materialized"] == 0
    page = client.get(base + "/samples?count=25").json()
    sample_id = page["items"][0]["id"]
    detail = client.get(base + "/samples/" + sample_id).json()
    sample = detail["sample"]
    assert detail["revision"] == dataset["revision"]
    assert sample["mode"] == "template" and sample["event_ids"] == []
    original_templates = sample["template_events"]
    metadata = {key: sample[key] for key in ("scenario_id", "split", "label", "family", "host_group")}
    metadata["scenario_id"] = "Edited reviewed normal example"
    edited = client.put(base + "/samples/" + sample_id, json={
        "expected_revision": dataset["revision"], "sample": metadata,
    })
    assert edited.status_code == 200, edited.text
    current_revision = edited.json()["revision"]
    current_sample = client.get(base + "/samples/" + sample_id).json()["sample"]
    assert current_sample["scenario_id"] == metadata["scenario_id"]
    assert current_sample["template_events"] == original_templates and current_sample["event_ids"] == []
    assert client.put(base, json={"expected_revision": dataset["revision"], "name": "Stale edit",
        "description": "", "indexes": ["ml_synthetic_console"]}).status_code == 409
    validation = client.post(base + "/validate", json={"expected_revision": current_revision}).json()
    assert validation["ready"] is False
    assert validation["issues"][0]["code"] == "templates_require_materialization"
    revisions = client.get(base + "/revisions?count=1").json()
    assert revisions["current_revision"] == current_revision
    assert len(revisions["items"]) == 1 and revisions["next_cursor"] is not None
    assert client.request("DELETE", base + "/samples/" + sample_id, json={"expected_revision": current_revision}).status_code == 200
    assert client.get(base).json()["counts"]["samples"] == 23
    assert client.get("/api/v3/ml/dataset-bundles").json()["installed_sample_counts"] == {
        "samples": 23, "templates": 23, "materialized": 0,
    }
    with client.app.state.store.control() as db:
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM intelligence_signals").fetchone()[0] == 0
    client.headers.pop("X-CSRF-Token")
    assert client.post(base + "/materialize", json={"expected_revision": current_revision,
        "confirmed_synthetic": True, "batch_size": 8}).status_code == 403


def test_console_atomic_preview_save_and_revise_stays_draft(client):
    sign_in(client)
    payload = {"indexes": ["public"], "name": "Console source observation", "enabled": False, "window": 300}
    preview = client.post("/api/v3/intelligence/templates/authentication-failure/preview", json=payload)
    assert preview.status_code == 200, preview.text
    result = preview.json()
    assert result["persisted"] is False and result["live_effects"] is False
    definition = result["definition"]
    assert definition["kind"] == "atomic" and definition["case_adapter"] is None
    saved = client.post("/api/v3/intelligence/policies", json={**definition, "version": 0})
    assert saved.status_code == 201, saved.text
    policy = saved.json()
    assert policy["state"] == "draft"
    current = next(item for item in client.get("/api/v3/intelligence/policies").json() if item["id"] == policy["id"])
    revised = client.put("/api/v3/intelligence/policies/" + policy["id"], json={
        **current["definition"], "name": "Revised console observation", "version": policy["version"],
    })
    assert revised.status_code == 200, revised.text
    assert revised.json()["state"] == "draft" and revised.json()["version"] == policy["version"] + 1
