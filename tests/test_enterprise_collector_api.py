# ruff: noqa: F811 - disposable HTTP pytest fixtures.
"""Public collector routes with protocol fixtures and actual server admission."""

import json

from test_enterprise_api import client, login, success  # noqa: F401
from test_enterprise_collectors import (
    ENV,
    SECRET,
    TENANT,
    credentials,
    signin,
    token,
    window,
)

from sapientia import enterprise_collectors as collectors

PREFIX = "/api/ops/enterprise/sources/"


def source(client):
    return success(client.post("/api/v2/sources", json={"index": "public", "product": "entra_signin", "account": TENANT, "realm": "microsoft-managed", "credential_ref": "env:" + ENV, "version": 0}), 201)


def test_http_missing_cloud_credentials_is_honest_unavailable_and_roles_are_current(client, monkeypatch, record_property):
    monkeypatch.delenv(ENV, raising=False)
    login(client)
    declared = source(client)
    path = PREFIX + declared["id"] + "/collector"
    def forbidden(*args):
        raise AssertionError("Missing cloud credentials must make no network call")
    monkeypatch.setattr(collectors, "request_https", forbidden)
    info = success(client.get(path))
    assert info["available"] is False and info["reason"] == "credential_not_configured"
    result = success(client.post(path + "/collect", json=window()))
    assert result["status"] == "unavailable" and result["requests"] == 0
    assert result["cloud_live_tested"] is False and result["live_vendor_attempted"] is False and result["live_vendor_completed"] is False
    assert client.post(path + "/collect", json={**window(), "url": "https://evil.invalid"}).status_code == 400
    login(client, "viewer_a")
    assert client.get(path).status_code == 200
    assert client.post(path + "/collect", json=window()).status_code == 403
    login(client, "analyst_a")
    assert client.post(path + "/collect", json=window()).status_code == 403
    login(client, "admin_b")
    assert client.get(path).status_code == 404
    assert client.post(path + "/collect", json=window()).status_code == 404
    record_property("collector_proof", json.dumps({"product": "cloud_environment", "provider": "actual_http_route_no_cloud_credentials", "status": result["status"], "requests": result["requests"], "cloud_live_tested": result["cloud_live_tested"], "viewer_and_analyst_collect_denied": True, "foreign_scope_denied": True}))


def test_http_collect_vendor_fixture_enters_real_source_receipts_and_checkpoint(client, monkeypatch, record_property):
    login(client)
    declared = source(client)
    monkeypatch.setenv(ENV, credentials()[ENV])
    data = window()
    original = collectors.collect
    calls = []
    def provider(method, url, headers, payload, timeout):
        calls.append((method, url))
        return token() if method == "POST" else collectors.Reply(200, {}, {"value": [signin(1, data)]})
    monkeypatch.setattr(collectors, "collect", lambda store, who, identifier, body: original(store, who, identifier, body, http=provider))
    path = PREFIX + declared["id"] + "/collector"
    assert success(client.get(path))["available"] is True
    result = success(client.post(path + "/collect", json=data))
    assert result["status"] == "completed" and result["complete"] and result["transport"] == "protocol_fixture"
    assert result["checkpoint_version"] == 1 and result["durable_records"] == 1
    assert SECRET not in json.dumps(result) and "synthetic-non-token" not in json.dumps(result)
    with client.app.state.store.control() as db:
        assert db.execute("SELECT count(*) FROM source_event_receipts").fetchone()[0] == 1
        assert db.execute("SELECT version FROM connector_checkpoints WHERE source_id=?", (declared["id"],)).fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM endpoint_responses").fetchone()[0] == 0
    record_property("collector_proof", json.dumps({"product": "entra_signin", "provider": "protocol_fixture_through_real_authenticated_http", "requests": len(calls), "receipts": 1, "checkpoint_version": result["checkpoint_version"], "host_effects": 0, "cloud_live_tested": False}))
