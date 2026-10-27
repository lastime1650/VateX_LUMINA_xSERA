"""Actual agent-only app and shared-store TLS-plane routing contracts."""

import time

import pytest
from fastapi.testclient import TestClient

from sapientia import auth, detections, sandbox_provider
from sapientia.api import AgentPlane, agent_plane_allowed, create_app
from sapientia.sandbox_provider_sdk import SandboxProviderWorker
from sapientia.storage import Settings
from tests import test_sandbox_provider_sdk as helpers


@pytest.fixture
def agent_app(tmp_path):
    app = create_app(
        Settings(tmp_path, min_free_bytes=0), background=False, agent_only=True
    )
    store, actors = app.state.store, {}
    for name in ("requester", "approver"):
        auth.create_user(
            store, name, "Synthetic-agent-plane-qualification-2026!", "admin", "a"
        )
        actors[name] = {
            "name": name,
            "role": "admin",
            "tenant": "a",
            "allowed_indexes": ["*"],
        }
    store.ingest(
        "a",
        [
            {
                "event_id": "plane-event",
                "event_time": time.time() - 2,
                "index": "public",
                "host": "plane-host",
                "source": "endpoint",
            }
        ],
    )
    store.flush()
    detections.save(
        store,
        actors["requester"],
        {
            "name": "Harmless plane case",
            "entity_field": "host",
            "steps": [
                {"filters": [{"field": "event_id", "op": "eq", "value": "plane-event"}]}
            ],
        },
    )
    assert detections.run_due(store, time.time() + 1) == 1
    fixture = {
        "store": store,
        "actors": actors,
        "case": detections.incident_list(store, actors["requester"])[0],
    }
    with TestClient(app, base_url="https://agent-plane.invalid") as client:
        yield app, client, fixture


def test_real_agent_only_factory_exchanges_provider_sample_without_exposing_console_routes(
    agent_app,
):
    app, client, fixture = agent_app
    assert app.state.agent_only
    private, profile = helpers.approved_provider(fixture)
    artifact = helpers.fixtures.artifact_fixture(
        fixture, b"Harmless actual agent-plane protocol sample"
    )
    manifest = sandbox_provider.request_job(
        fixture["store"], fixture["actors"]["requester"], artifact, profile["id"]
    )
    worker = SandboxProviderWorker(
        "https://agent-plane.invalid",
        "a",
        profile["id"],
        profile["key_id"],
        private,
        transport=helpers.TestTransport(client),
    )
    results = worker.run_once(
        lambda sample, request: {
            "provider_job_id": "agent-plane-engine",
            "verdict": "unknown",
            "report": {
                "summary": "Provider got hash-bound harmless bytes; no sample execution",
                "findings": [],
            },
        }
    )
    assert (
        results[0]["id"] == manifest["request_id"]
        and results[0]["result"]["provider_signature_verified"]
    )
    assert (
        results[0]["result"]["sample_sent_by_xsera"]
        and not results[0]["result"]["sample_executed_by_xsera"]
    )
    for method, path in [
        ("GET", "/"),
        ("GET", "/api/bootstrap"),
        ("POST", "/api/login"),
        ("GET", "/api/xdr/advanced/sandbox-providers"),
        ("POST", "/api/xdr/advanced/sandbox-providers"),
        ("GET", "/api/xdr/advanced/sandbox/" + manifest["request_id"]),
        (
            "POST",
            "/api/xdr/advanced/sandbox/" + manifest["request_id"] + "/attested-result",
        ),
    ]:
        assert client.request(method, path, json={}).status_code == 404


@pytest.mark.parametrize(
    "path",
    [
        "/api/agent/heartbeat",
        "/api/agent/ingest",
        "/api/agent/poll",
        "/api/agent/result",
        "/api/agent/defense-policy",
    ],
)
def test_existing_agent_paths_are_reachable_but_still_require_endpoint_credential(
    agent_app, path
):
    app, client, _ = agent_app
    result = client.post(path, json={})
    assert result.status_code == 403 and "enrollment is disabled" in result.text
    # Only the in-memory configured-status gate is enabled; this request still
    # has no endpoint credential, so no enrollment or endpoint callback runs.
    app.state.agent_distribution.config = {
        "endpoint_url": "https://agent-plane.invalid"
    }
    result = client.post(path, json={})
    assert result.status_code == 401
    assert result.json()["detail"] == "Endpoint credential required"


@pytest.mark.parametrize(
    "method,path,allowed",
    [
        ("POST", "/api/agent/register", True),
        ("POST", "/api/endpoint-agent/events", True),
        ("POST", "/api/agent/commands/RSP-" + "a" * 32 + "/artifact", True),
        ("GET", "/api/agent/poll", False),
        ("PUT", "/api/agent/ingest", False),
        ("POST", "/api/agent/ingest/extra", False),
        ("POST", "/api/agent/admin", False),
        ("POST", "/api/xdr/advanced/provider-exchange/poll", True),
        ("POST", "/api/xdr/advanced/provider-exchange/not-a-uuid/sample", False),
        (
            "POST",
            "/api/xdr/advanced/provider-exchange/"
            + "0" * 8
            + "-"
            + "0" * 4
            + "-"
            + "0" * 4
            + "-"
            + "0" * 4
            + "-"
            + "0" * 12
            + "/sample",
            True,
        ),
        ("POST", "/api/xdr/advanced/provider-exchange/profiles", False),
    ],
)
def test_plane_guard_is_exact_method_and_path_not_a_broad_prefix(method, path, allowed):
    assert (
        agent_plane_allowed({"type": "http", "method": method, "path": path}) is allowed
    )


def test_wrapper_reuses_underlying_app_and_rejects_other_routes_without_dispatch():
    dispatched = []

    async def application(scope, receive, send):
        dispatched.append(scope)
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    wrapper = AgentPlane(application)
    assert wrapper.app is application
    client = TestClient(wrapper, base_url="https://agent-plane.invalid")
    try:
        assert client.post("/api/agent/ingest", json={}).status_code == 204
        assert client.post("/api/login", json={}).status_code == 404
    finally:
        client.close()
    assert [item["path"] for item in dispatched if item["type"] == "http"] == [
        "/api/agent/ingest"
    ]
