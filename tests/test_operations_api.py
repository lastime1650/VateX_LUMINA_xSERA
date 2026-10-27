import time

import pytest
from fastapi.testclient import TestClient

from sapientia import auth, detections
from sapientia.api import create_app
from sapientia.connectors import parse_line
from sapientia.storage import Settings

PASSWORD = "Synthetic-operations-test-password-2026"


@pytest.fixture
def client(tmp_path):
    app = create_app(Settings(tmp_path, min_free_bytes=0), background=False)
    with TestClient(app) as result:
        yield result


def login(client, name, role="admin", tenant="default", create=True):
    if create:
        auth.create_user(client.app.state.store, name, PASSWORD, role, tenant)
    r = client.post("/api/login", json={"name": name, "password": PASSWORD})
    assert r.status_code == 200, r.text
    client.headers["X-CSRF-Token"] = r.json()["csrf"]


def test_reference_data_version_scope_and_search(client):
    login(client, "admin_a", tenant="a")
    saved = client.put(
        "/api/lookups/approved_assets",
        json={
            "key": "host",
            "rows": [{"host": "asset1", "owner": "security"}],
            "version": 0,
        },
    )
    assert saved.status_code == 200, saved.text
    version = saved.json()["version"]
    assert version == 1
    assert (
        client.put(
            "/api/lookups/approved_assets",
            json={
                "key": "host",
                "rows": [],
                "version": 0,
            },
        ).status_code
        == 409
    )
    client.app.state.store.ingest("a", [{"event_id": "lookup-event", "host": "asset1"}])
    client.app.state.store.flush()
    result = client.post(
        "/api/search",
        json={
            "query": "search * | lookup approved_assets host AS host OUTPUT owner | table event_id owner"
        },
    )
    assert result.status_code == 200, result.text
    assert result.json()["rows"] == [{"event_id": "lookup-event", "owner": "security"}]
    login(client, "admin_b", tenant="b")
    assert client.get("/api/lookups").json() == []
    assert client.get("/api/lookups/approved_assets").status_code == 404
    assert (
        client.post(
            "/api/search",
            json={"query": "search * | lookup approved_assets host OUTPUT owner"},
        ).status_code
        == 400
    )


def test_index_scope_covers_operations_and_revokes_session(client):
    login(client, "admin_a", tenant="a")
    store = client.app.state.store
    store.ingest(
        "a",
        [
            {"event_id": "public", "index": "public"},
            {"event_id": "private", "index": "private"},
        ],
    )
    store.ingest("b", [{"event_id": "other-tenant", "index": "public"}])
    store.flush()
    grant = client.put(
        "/api/users/admin_a/indexes", json={"allowed_indexes": ["public"]}
    )
    assert grant.status_code == 200, grant.text
    assert client.get("/api/operations").status_code == 401
    login(client, "admin_a", tenant="a", create=False)
    ops = client.get("/api/operations").json()
    assert ops["queue"]["indexed"] == 1
    assert ops["node_metrics_visible"] is False
    assert "indexed_total" not in ops["indexer"] and "indexed_eps" not in ops["indexer"]
    assert ops["syslog"] == {"restricted": True}
    assert client.get("/api/audit/integrity").status_code == 403


def test_operator_checkpoint_and_optional_features(client):
    login(client, "admin_default")
    assert client.get("/api/operations").json()["node_metrics_visible"] is True
    checkpoint = client.post("/api/audit/checkpoint", json={})
    assert checkpoint.status_code == 200, checkpoint.text
    verified = client.post("/api/audit/verify", json=checkpoint.json())
    assert verified.status_code == 200 and verified.json()["valid"]
    assert client.get("/api/federation/status").json() == {"enabled": False}
    assert client.post("/api/federation/search", json={}).status_code == 404
    assert client.get("/api/sso/status").json() == {"enabled": False}
    login(client, "viewer_default", role="viewer")
    for path in (
        "/api/operations",
        "/api/detections",
        "/api/lookups",
        "/api/risk/entities",
        "/api/incidents",
    ):
        assert client.get(path).status_code == 403, path


def test_malformed_csrf_is_denied_without_server_error(client):
    login(client, "admin_malformed")
    response = client.post(
        "/api/search", json={"query": "*"}, headers=[(b"x-csrf-token", b"\xc3\xa9")]
    )
    assert response.status_code == 403


def test_canonical_template_connects_three_sources_without_persisting_preview(client):
    login(client, "analyst_cross_source", role="analyst")
    now = time.time()
    events = [
        {"raw": {"EventID": 4625, "EventData": {"TargetUserName": "alice"}}},
        parse_line(
            "CEF:0|v|p|1|42|auth|7|suser=alice act=login_failed",
            "cef",
            "cef-source",
            "cef",
        ),
        parse_line(
            '<34>1 1970-01-01T00:00:00Z host auth - - - {"user":"alice","action":"login_failed"}',
            "syslog",
            "syslog-source",
            "syslog",
        ),
        {"raw": {"EventID": 4624, "EventData": {"TargetUserName": "alice"}}},
    ]
    for i, event in enumerate(events):
        event.update(event_id=f"cross-source-{i}", event_time=now - 10 + i)
    store = client.app.state.store
    store.ingest("default", events)
    store.flush()
    templates = client.get("/api/detections/templates").json()
    definition = next(
        t["definition"]
        for t in templates
        if t["id"] == "canonical-authentication-chain"
    )
    preview = client.post(
        "/api/detections/preview", json={"definition": definition, "end": now}
    )
    assert preview.status_code == 200, preview.text
    assert preview.json()["match_count"] == 1
    assert preview.json()["matches"][0]["event_ids"] == [
        f"cross-source-{i}" for i in range(4)
    ]
    assert client.get("/api/incidents").json() == []
    assert client.post("/api/detections", json=definition).status_code == 201
    assert detections.run_due(store, now + 1) == 1
    risk = client.get("/api/risk/entities").json()
    assert risk[0]["entity"] == "alice" and risk[0]["contribution_count"] == 1
