"""Public HTTP contracts, scopes and a real Runtime-driven approval workflow."""

import time

import pytest
from fastapi.testclient import TestClient
from test_content import package

from sapientia import auth
from sapientia.api import create_app
from sapientia.storage import Settings

PASSWORD = "Synthetic-enterprise-http-password-2026"
START = 1704067200


@pytest.fixture
def client(tmp_path):
    app = create_app(Settings(tmp_path, min_free_bytes=0), background=False)
    for name, role, tenant in [
        ("admin_a", "admin", "a"),
        ("analyst_a", "analyst", "a"),
        ("approver_a", "analyst", "a"),
        ("viewer_a", "viewer", "a"),
        ("admin_b", "admin", "b"),
    ]:
        auth.create_user(app.state.store, name, PASSWORD, role, tenant)
    with TestClient(app) as value:
        yield value


def login(client, name="admin_a"):
    client.cookies.clear()
    client.headers.pop("X-CSRF-Token", None)
    response = client.post("/api/login", json={"name": name, "password": PASSWORD})
    assert response.status_code == 200, response.text
    client.headers["X-CSRF-Token"] = response.json()["csrf"]


def success(response, status=200):
    assert response.status_code == status, response.text
    return response.json()


def entity_body(alias="alice", **extra):
    return {
        "kind": "user",
        "name": "Alice",
        "aliases": [{"type": "username", "value": alias}],
        "indexes": ["public"],
        "version": 0,
        **extra,
    }


def ingest(client, rows):
    login(client)
    for offset in range(0, len(rows), 1000):
        success(
            client.post(
                "/api/v1/events", json={"events": rows[offset : offset + 1000]}
            ),
            202,
        )
    client.app.state.store.flush(5000)


def wait_json(client, url, predicate, seconds=10):
    until = time.monotonic() + seconds
    value = None
    while time.monotonic() < until:
        value = success(client.get(url))
        if predicate(value):
            return value
        time.sleep(0.05)
    raise AssertionError(f"Runtime did not reach the required state: {value}")


def test_enterprise_authentication_roles_csrf_and_json_shape(client):
    reads = [
        "/api/entities",
        "/api/behavior/baselines",
        "/api/content/packages",
        "/api/parsers",
        "/api/source-monitors",
        "/api/playbooks",
    ]
    for route in reads:
        assert client.get(route).status_code == 401
    login(client, "viewer_a")
    assert client.get("/api/entities").status_code == 200
    assert client.get("/api/content/packages").status_code == 200
    for route in [
        "/api/behavior/baselines",
        "/api/parsers",
        "/api/source-monitors",
        "/api/playbooks",
    ]:
        assert client.get(route).status_code == 403
    for route in [
        "/api/entities",
        "/api/behavior/baselines",
        "/api/playbooks",
        "/api/source-monitors",
        "/api/content/packages",
    ]:
        assert client.post(route, json={}).status_code == 403
    login(client)
    csrf = client.headers.pop("X-CSRF-Token")
    assert client.post("/api/entities", json=entity_body()).status_code == 403
    client.headers["X-CSRF-Token"] = csrf
    assert client.post("/api/entities", json=[]).status_code == 400
    assert (
        client.post(
            "/api/entities",
            content="{broken",
            headers={"Content-Type": "application/json"},
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/entities", content="{}", headers={"Content-Type": "text/plain"}
        ).status_code
        == 415
    )


def test_entity_http_crud_alias_timeline_and_current_scope(client):
    login(client, "analyst_a")
    entity = success(client.post("/api/entities", json=entity_body()))
    entity_id = entity["id"]
    assert (
        success(
            client.get(
                "/api/entities/resolve", params={"type": "username", "value": "alice"}
            )
        )["id"]
        == entity_id
    )
    assert (
        success(client.get("/api/entities/graph", params={"start": 0, "end": 100}))[
            "nodes"
        ]
        == []
    )
    ingest(
        client,
        [
            {
                "event_id": "public",
                "event_time": 100,
                "index": "public",
                "host": "h1",
                "raw": {"user": "alice"},
            },
            {
                "event_id": "private",
                "event_time": 100,
                "index": "private",
                "raw": {"user": "alice"},
            },
        ],
    )
    login(client, "analyst_a")
    timeline = success(
        client.get(
            f"/api/entities/{entity_id}/timeline",
            params={"start": 99, "end": 101, "limit": 1},
        )
    )
    assert timeline["total"] == 1 and timeline["events"][0]["event_id"] == "public"
    updated = success(
        client.put(
            f"/api/entities/{entity_id}", json=entity_body(version=1, tags=["checked"])
        )
    )
    assert updated["version"] == 2
    assert (
        client.put(
            f"/api/entities/{entity_id}", json=entity_body(version=1)
        ).status_code
        == 409
    )
    login(client, "viewer_a")
    assert success(client.get(f"/api/entities/{entity_id}"))["tags"] == ["checked"]
    login(client, "admin_b")
    assert success(client.get("/api/entities")) == []
    assert client.get(f"/api/entities/{entity_id}").status_code == 404
    login(client)
    success(
        client.put(
            "/api/users/analyst_a/indexes", json={"allowed_indexes": ["private"]}
        )
    )
    login(client, "analyst_a")
    assert client.get(f"/api/entities/{entity_id}").status_code == 404
    assert (
        client.get(
            f"/api/entities/{entity_id}/timeline", params={"start": 99, "end": 101}
        ).status_code
        == 404
    )


def test_behavior_http_train_evaluate_run_and_leakage_guard(client):
    train_end = START + 7 * 3600
    rows = [
        {
            "event_id": f"training{i}",
            "event_time": START + i * 3600 + 10,
            "index": "public",
            "host": "known",
            "raw": {"user": "alice"},
        }
        for i in range(7)
    ]
    rows += [
        {
            "event_id": f"spike{i}",
            "event_time": train_end + 10 + i,
            "index": "public",
            "host": "new",
            "raw": {"user": "alice"},
        }
        for i in range(8)
    ]
    ingest(client, rows)
    login(client, "analyst_a")
    baseline = success(
        client.post(
            "/api/behavior/baselines",
            json={
                "name": "Hourly baseline",
                "indexes": ["public"],
                "start": START,
                "end": train_end,
                "bucket_seconds": 3600,
                "min_samples": 7,
                "min_buckets": 7,
                "business_hours_utc": {
                    "start": 0,
                    "end": 24,
                    "weekdays": list(range(7)),
                },
            },
        )
    )
    assert baseline["snapshot"]["models"]["alice"]["counts"] == [1] * 7
    base_url = f"/api/behavior/baselines/{baseline['id']}"
    assert (
        client.post(
            base_url + "/evaluate", json={"start": START, "end": train_end}
        ).status_code
        == 400
    )
    result = success(
        client.post(
            base_url + "/evaluate", json={"start": train_end, "end": train_end + 3600}
        )
    )
    assert result["matched_events"] == 8 and {
        a["type"] for a in result["anomalies"]
    } == {"volume", "new_host"}
    assert (
        success(client.get(f"/api/behavior/runs/{result['id']}"))["baseline_digest"]
        == baseline["digest"]
    )
    assert (
        len(
            success(
                client.get("/api/behavior/runs", params={"baseline_id": baseline["id"]})
            )
        )
        == 1
    )
    login(client, "admin_b")
    assert success(client.get("/api/behavior/baselines")) == []
    assert client.get(base_url).status_code == 404
    login(client)
    success(client.put("/api/users/analyst_a/indexes", json={"allowed_indexes": []}))
    assert (
        client.get(base_url).status_code == 403
    )  # current owner scope independently enforced


def test_case_http_and_real_runtime_independent_approval(client):
    now = time.time()
    ingest(
        client,
        [
            {
                "event_id": "case-e1",
                "event_time": now - 2,
                "index": "public",
                "raw": {"user": "alice"},
            }
        ],
    )
    login(client, "analyst_a")
    success(
        client.post(
            "/api/detections",
            json={
                "name": "HTTP incident",
                "entity_field": "raw.security.user",
                "window": 300,
                "steps": [
                    {"filters": [{"field": "event_id", "op": "eq", "value": "case-e1"}]}
                ],
            },
        ),
        201,
    )
    client.app.state.runtime.start()
    incident = wait_json(client, "/api/incidents", bool)[0]
    case_id = incident["id"]
    case_url = f"/api/incidents/{case_id}"
    success(
        client.put(
            case_url + "/workspace",
            json={"version": 0, "priority": "high", "due_at": None, "tags": ["http"]},
        )
    )
    task = success(
        client.post(
            case_url + "/actions",
            json={
                "request_id": "task-http",
                "action": {
                    "type": "add_task",
                    "title": "Review event",
                    "mandatory": True,
                    "assignee": "analyst_a",
                },
            },
        )
    )
    assert (
        client.post(
            case_url + "/actions",
            json={
                "request_id": "close-http",
                "action": {
                    "type": "set_status",
                    "status": "resolved",
                    "note": "Not yet",
                },
            },
        ).status_code
        == 409
    )
    success(
        client.patch(
            case_url + f"/tasks/{task['id']}",
            json={
                "version": 1,
                "status": "done",
                "assignee": "analyst_a",
                "due_at": None,
            },
        )
    )
    success(
        client.post(
            case_url + "/bookmarks",
            json={"event_id": "case-e1", "label": "Original event"},
        )
    )
    exported = success(client.get(case_url + "/export"))
    assert (
        len(exported["sha256"]) == 64
        and exported["bookmarks"][0]["event_id"] == "case-e1"
    )
    playbook = success(
        client.post(
            "/api/playbooks",
            json={
                "name": "HTTP approved note",
                "version": 0,
                "steps": [
                    {
                        "id": "note",
                        "action": {
                            "type": "add_note",
                            "note": "Independent approval reviewed evidence",
                        },
                    }
                ],
            },
        )
    )
    run_url = f"/api/playbooks/{playbook['id']}/runs"
    body = {"incident_id": case_id, "request_id": "stable-http-run"}
    run = success(client.post(run_url, json=body))
    assert success(client.post(run_url, json=body))["duplicate"]
    assert (
        client.post(f"/api/playbook-runs/{run['id']}/approve", json={}).status_code
        == 403
    )
    login(client, "viewer_a")
    assert success(client.get(case_url + "/workspace"))["tasks"][0]["status"] == "done"
    assert (
        client.post(
            case_url + "/actions",
            json={
                "request_id": "viewer",
                "action": {"type": "add_note", "note": "Denied"},
            },
        ).status_code
        == 403
    )
    login(client, "admin_b")
    assert client.get(case_url + "/workspace").status_code == 404
    assert client.get(f"/api/playbook-runs/{run['id']}").status_code == 404
    login(client, "approver_a")
    assert (
        client.post(
            f"/api/playbook-runs/{run['id']}/approve", json={"approve": False}
        ).status_code
        == 400
    )
    assert (
        success(client.get(f"/api/playbook-runs/{run['id']}"))["state"]
        == "pending_approval"
    )
    success(client.post(f"/api/playbook-runs/{run['id']}/approve", json={}))
    complete = wait_json(
        client,
        f"/api/playbook-runs/{run['id']}",
        lambda value: value["state"] == "completed",
    )
    assert complete["steps"][0]["attempts"] == 1
    workspace = success(client.get(case_url + "/workspace"))
    assert [n["note"] for n in workspace["notes"]] == [
        "Independent approval reviewed evidence"
    ]
    assert client.app.state.runtime.enterprise_errors == {}


def test_parser_quarantine_monitor_routes_and_roles(client):
    login(client)
    definition = {
        "source": "vendor",
        "mappings": {"raw.security.user": "raw.vendor_user"},
        "redact_fields": ["raw.password"],
        "required_fields": ["raw.vendor_user"],
        "route_index": "public",
    }
    success(
        client.put("/api/parsers/vendor", json={"version": 0, "definition": definition})
    )
    login(client, "analyst_a")
    preview = success(
        client.post(
            "/api/parsers/preview",
            json={
                "definition": definition,
                "event": {
                    "source": "vendor",
                    "raw": {
                        "vendor_user": "alice",
                        "password": "Synthetic-not-a-secret",
                    },
                },
            },
        )
    )
    assert (
        preview["persisted"] is False
        and preview["event"]["raw"]["password"] == "[REDACTED]"
    )
    assert (
        client.put(
            "/api/parsers/denied", json={"version": 0, "definition": definition}
        ).status_code
        == 403
    )
    ingest(
        client,
        [
            {
                "event_id": "quarantined",
                "source": "vendor",
                "raw": {"password": "Synthetic-private-content"},
            }
        ],
    )
    quarantine = success(client.get("/api/quarantine"))
    assert quarantine["total_count"] == 1 and "Synthetic-private-content" not in str(
        quarantine
    )
    success(
        client.put(
            "/api/parsers/vendor",
            json={"version": 1, "definition": {**definition, "required_fields": []}},
        )
    )
    assert (
        success(
            client.post("/api/quarantine/replay", json={"event_ids": ["quarantined"]})
        )["queued"]
        == 1
    )
    client.app.state.store.flush()
    login(client, "analyst_a")
    monitor = success(
        client.post(
            "/api/source-monitors",
            json={
                "version": 0,
                "definition": {
                    "name": "Vendor monitored",
                    "source": "vendor",
                    "indexes": ["public"],
                    "required_fields": ["raw.security.user"],
                },
            },
        )
    )
    measured = success(
        client.post(f"/api/source-monitors/{monitor['id']}/evaluate", json={})
    )
    assert (
        measured["recent_events"] == 1
        and measured["missing_fields"]["raw.security.user"] == 1
    )
    login(client, "admin_b")
    assert success(client.get("/api/parsers")) == []
    assert success(client.get("/api/source-monitors")) == []
    assert (
        client.post(
            f"/api/source-monitors/{monitor['id']}/evaluate", json={}
        ).status_code
        == 404
    )


def test_content_revision_fixture_export_publish_and_sigma_http(client):
    login(client, "analyst_a")
    payload = package()
    saved = success(
        client.post(
            "/api/content/packages", json={"package": payload, "expected_version": 0}
        )
    )
    name = payload["name"]
    base = f"/api/content/packages/{name}"
    tested = success(client.post(base + "/test", json={"revision": saved["revision"]}))
    assert tested["passed"]
    exported = success(client.get(base + "/export"))
    assert (
        success(client.post("/api/content/dry-run", json=exported["package"]))[
            "changed"
        ]
        is False
    )
    assert not success(client.get(base + "/coverage"))["ready"]
    rows = payload["fixtures"][0]["events"]
    for i, item in enumerate(rows):
        item["event_id"] = f"content-http-{i}"
        item["index"] = "public"
    ingest(client, rows)
    login(client, "analyst_a")
    assert success(client.get(base + "/coverage"))["ready"]
    activation = {"revision": saved["revision"], "expected_active": None}
    assert client.post(base + "/publish", json=activation).status_code == 403
    login(client)
    assert success(client.post(base + "/publish", json=activation))["state"] == "active"
    preview = success(
        client.post(
            "/api/content/sigma/preview",
            json={
                "rule": {
                    "title": "HTTP literal",
                    "detection": {"sel": {"User": "alice"}, "condition": "sel"},
                },
                "field_mapping": {"User": "raw.security.user"},
            },
        )
    )
    assert preview["query_only"]
    login(client, "admin_b")
    assert success(client.get("/api/content/packages")) == []
    assert client.get(base).status_code == 404


def test_malformed_enterprise_payloads_and_query_parameters_are_400(client):
    login(client)
    cases = [
        ("post", "/api/entities", {"kind": []}),
        ("post", "/api/behavior/baselines", {"name": "x", "entity_field": []}),
        (
            "put",
            "/api/parsers/x",
            {"version": 0, "definition": {"source": "x", "mappings": []}},
        ),
        ("post", "/api/source-monitors", {"version": False, "definition": {}}),
        (
            "post",
            "/api/playbooks",
            {
                "name": "x",
                "version": 0,
                "steps": [{"id": "one", "action": {"type": []}}],
            },
        ),
        ("post", "/api/content/packages", {"package": {}, "unexpected": 1}),
        (
            "post",
            "/api/content/sigma/preview",
            {
                "rule": {"detection": {"sel": {"User": "*"}, "condition": "sel"}},
                "field_mapping": {"User": "raw.user"},
            },
        ),
    ]
    for method, path, data in cases:
        result = getattr(client, method)(path, json=data)
        assert result.status_code == 400, (path, result.status_code, result.text)
    for params in [
        {"start": "NaN", "end": 100},
        {"start": 0, "end": 100, "limit": "x"},
        {"end": 100},
    ]:
        assert client.get("/api/entities/graph", params=params).status_code == 400
