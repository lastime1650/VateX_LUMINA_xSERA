import json

import pytest
from fastapi.testclient import TestClient

from sapientia.api import create_app
from sapientia.auth import create_user, issue_token
from sapientia.storage import Settings

PASSWORD = "Integration-test-password-2026"


@pytest.fixture
def client(tmp_path):
    app = create_app(Settings(tmp_path, min_free_bytes=0), background=False)
    create_user(app.state.store, "admin", PASSWORD)
    with TestClient(app) as c:
        response = c.post("/api/login", json={"name": "admin", "password": PASSWORD})
        c.headers["X-CSRF-Token"] = response.json()["csrf"]
        yield c


def test_hec_ndjson_durable_deduplication_and_tenant(client):
    create_user(client.app.state.store, "collector_admin_a", PASSWORD, tenant="a")
    token = issue_token(
        client.app.state.store,
        {"name": "collector_admin_a", "tenant": "a"},
        "hec",
        allowed_indexes=["network"],
    )
    headers = {"Authorization": "Splunk " + token, "Content-Type": "application/json"}
    events = [
        {
            "event": {"action": "denied"},
            "host": "router",
            "index": "network",
            "fields": {"vatex_event_id": str(i)},
        }
        for i in range(2)
    ]
    response = client.post(
        "/services/collector/event",
        headers=headers,
        content="\n".join(json.dumps(e) for e in events),
    )
    assert response.status_code == 200, response.text
    assert response.json()["code"] == 0
    assert response.json()["accepted"] == 2
    assert (
        client.post("/services/collector", headers=headers, json=events).json()[
            "duplicate"
        ]
        == 2
    )
    client.app.state.store.flush()
    assert (
        client.app.state.store.search("a", {"query": "index=network"})["returned"] == 2
    )
    assert client.post("/api/search", json={"query": "*"}).json()["returned"] == 0
    assert (
        client.post(
            "/services/collector",
            headers=headers,
            json=[events[0], {"event": {}, "time": "NaN"}],
        ).status_code
        == 400
    )
    assert (
        client.post("/services/collector", headers=headers, content=b"\xff").status_code
        == 400
    )
    assert (
        client.post(
            "/services/collector", json={"event": "x", "tenant": "other"}
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/services/collector",
            json={"event": "x"},
            headers={"Authorization": "Splunk invalid"},
        ).status_code
        == 401
    )


def test_otlp_preservation_and_atomic_validation(client):
    payload = {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "edr"}}
                    ]
                },
                "scopeLogs": [
                    {
                        "scope": {"name": "collector"},
                        "logRecords": [
                            {
                                "severityNumber": 17,
                                "body": {"stringValue": "blocked"},
                                "attributes": [
                                    {
                                        "key": "vatex.event_id",
                                        "value": {"stringValue": "otel-1"},
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }
    assert client.post("/v1/logs", json=payload).status_code == 200
    assert client.post("/v1/logs", json=payload).status_code == 200
    client.app.state.store.flush()
    row = client.post("/api/search", json={"query": "source=edr"}).json()["rows"][0]
    assert row["severity"] == "high"
    assert row["message"] == "blocked"
    payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"].append(
        {"body": {"arrayValue": []}}
    )
    assert client.post("/v1/logs", json=payload).status_code == 400


@pytest.mark.parametrize(
    "payload",
    [
        {"resourceLogs": None},
        {"resourceLogs": [None]},
        {"resourceLogs": [{"resource": []}]},
        {"resourceLogs": [{"scopeLogs": [None]}]},
        {"resourceLogs": [{"scopeLogs": [{"logRecords": [None]}]}]},
        {"resourceLogs": [{"scopeLogs": [{"logRecords": [{"severityNumber": {}}]}]}]},
        {
            "resourceLogs": [
                {"scopeLogs": [{"logRecords": [{"body": {"doubleValue": "NaN"}}]}]}
            ]
        },
        {
            "resourceLogs": [
                {
                    "scopeLogs": [
                        {"logRecords": [{"body": {"kvlistValue": {"values": [{}]}}}]}
                    ]
                }
            ]
        },
    ],
)
def test_otlp_malformed_is_client_error(client, payload):
    assert client.post("/v1/logs", json=payload).status_code == 400


def test_dashboard_visibility_and_concurrency(client):
    payload = {
        "name": "SOC overview",
        "shared": False,
        "panels": [
            {
                "title": "Events",
                "display": "number",
                "query": {"query": "* | stats count"},
            }
        ],
    }
    response = client.post("/api/dashboards", json=payload)
    assert response.status_code == 201, response.text
    ident = response.json()["id"]
    assert len(client.get("/api/dashboards").json()) == 1
    assert (
        client.put(
            "/api/dashboards/" + ident, json={**payload, "version": 1}
        ).status_code
        == 200
    )
    assert (
        client.put(
            "/api/dashboards/" + ident, json={**payload, "version": 1}
        ).status_code
        == 409
    )
    create_user(client.app.state.store, "viewer", PASSWORD, "viewer")
    login = client.post("/api/login", json={"name": "viewer", "password": PASSWORD})
    client.headers["X-CSRF-Token"] = login.json()["csrf"]
    assert client.get("/api/dashboards").json() == []
    assert client.post("/api/dashboards", json=payload).status_code == 403
    login = client.post("/api/login", json={"name": "admin", "password": PASSWORD})
    client.headers["X-CSRF-Token"] = login.json()["csrf"]
    assert (
        client.put(
            "/api/dashboards/" + ident, json={**payload, "shared": True, "version": 2}
        ).status_code
        == 200
    )
    with client.app.state.store.control() as db:
        db.execute("UPDATE users SET tenant='other' WHERE name='viewer'")
    login = client.post("/api/login", json={"name": "viewer", "password": PASSWORD})
    client.headers["X-CSRF-Token"] = login.json()["csrf"]
    assert client.get("/api/dashboards").json() == []
