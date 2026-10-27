"""Console endpoints use the production app's auth, CSRF and public responses."""

from tests.test_api import client, sign_in  # noqa: F401 - shared real app fixture.


def test_new_console_assets_and_authenticated_read_contracts(client, monkeypatch):
    from sapientia import cpu_ml

    monkeypatch.setattr(cpu_ml, "runtime_status", lambda: {"available": False, "device": "cpu", "framework": "pytorch", "status": "시스템에서 호환되지 않음"})
    for path in ("/api/v3/intelligence/signals", "/api/v3/ml/status", "/api/v3/cases/reevaluation/config"):
        assert client.get(path).status_code==401
    sign_in(client)
    page=client.get("/")
    assert page.status_code==200 and "console_intelligence.js" in page.text
    assert client.get("/static/console_intelligence.js").status_code==200
    assert client.get("/static/console_intelligence.css").status_code==200
    responses={path:client.get(path) for path in (
        "/api/v3/intelligence/signals", "/api/v3/intelligence/stories", "/api/v3/intelligence/decisions", "/api/v3/intelligence/policies",
        "/api/v3/ml/status", "/api/v3/ml/models", "/api/v3/ml/sequences/models", "/api/v3/ml/sequences/stream", "/api/v3/shadow/runs",
        "/api/v3/behavior/features/baselines", "/api/v3/behavior/features/schedules",
        "/api/v3/cases/reevaluation/proposals", "/api/v3/cases/reevaluation/config")}
    assert all(response.status_code==200 for response in responses.values())
    assert responses["/api/v3/intelligence/signals"].json()["items"]==[]
    assert responses["/api/v3/shadow/runs"].json()["live_effects"] is False
    assert responses["/api/v3/cases/reevaluation/config"].json()["automatic_merges"] is False
    assert responses["/api/v3/ml/status"].json()["available"] is False
    client.headers.pop("X-CSRF-Token")
    assert client.put("/api/v3/cases/reevaluation/config",json={}).status_code==403


def test_viewer_write_actions_remain_denied_by_server(client):
    sign_in(client, name="viewer", role="viewer")
    for path in ("/api/v3/ml/models", "/api/v3/ml/sequences/models", "/api/v3/ml/sequences/models/m/evaluate", "/api/v3/ml/sequences/models/m/activate", "/api/v3/ml/sequences/models/m/disable", "/api/v3/ml/models/sequence/m/retire", "/api/v3/ml/models/autoencoder/m/retire", "/api/v3/behavior/features/baselines", "/api/v3/shadow/compare", "/api/v3/intelligence/policies"):
        payload = {"notes": "Current independent reviewer required"} if path.endswith(("/activate", "/retire")) else {}
        assert client.post(path,json=payload).status_code==403
    assert client.put("/api/v3/cases/reevaluation/config",json={}).status_code==403
    assert client.get("/api/v3/intelligence/signals").status_code==200


def test_sequence_gui_training_and_assessment_routes_preserve_structured_payload(client, monkeypatch):
    from sapientia import cpu_sequence
    captured = []
    def training(store, actor, payload):
        captured.append((actor["name"], payload))
        return {"status": "completed", "model_family": "sequence", "active": False}
    monkeypatch.setattr(cpu_sequence, "train", training)
    sign_in(client)
    manifest = {"name": "Reviewed GUI manifest", "indexes": ["endpoint"], "epochs": 15, "reviewed_dataset": True,
        "training": [{"scenario_id": "ordered-window", "event_ids": ["source-first", "source-last"], "label": "attack", "family": "reviewed-family", "host_group": "reviewed-host"}],
        "calibration": [], "holdout": []}
    response = client.post("/api/v3/ml/sequences/models", json=manifest)
    assert response.status_code == 201 and not response.json()["active"]
    assert captured == [("admin", manifest)]
    assert client.get("/api/v3/ml/sequences/models/missing/assessment").status_code == 404
    client.headers.pop("X-CSRF-Token")
    assert client.post("/api/v3/ml/models/sequence/missing/retire", json={"notes": "Independent review"}).status_code == 403
