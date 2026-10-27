"""HTTP authentication, exact source proof and current-authority integration."""

import hashlib
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from sapientia import access, auth, detections, endpoint_artifacts, entities
from sapientia.api import create_app
from sapientia.storage import Settings

BASE = "/api/xdr/advanced"
PASSWORD = "Synthetic-advanced-api-test-password-2026"


def login(client, name):
    result = client.post("/api/login", json={"name": name, "password": PASSWORD})
    assert result.status_code == 200, result.text
    client.headers["X-CSRF-Token"] = result.json()["csrf"]


@pytest.fixture
def client(tmp_path):
    app = create_app(Settings(tmp_path, min_free_bytes=0), background=False)
    store = app.state.store
    for name, role, tenant in [
        ("requester", "admin", "a"),
        ("approver", "admin", "a"),
        ("reader", "viewer", "a"),
        ("foreign", "admin", "b"),
    ]:
        auth.create_user(store, name, PASSWORD, role, tenant)
    actor = {
        "name": "requester",
        "role": "admin",
        "tenant": "a",
        "allowed_indexes": ["*"],
    }
    now = time.time()
    store.ingest(
        "a",
        [
            {
                "event_id": "api-lease",
                "event_time": now - 2,
                "host": "api-host",
                "index": "public",
                "source": "dhcp",
                "raw": {"ip": "10.0.0.5"},
            }
        ],
    )
    store.flush()
    asset = entities.save(
        store,
        actor,
        {
            "kind": "host",
            "name": "API fixture",
            "indexes": ["public"],
            "aliases": [{"type": "hostname", "value": "api-host"}],
        },
    )
    policy = detections.save(
        store,
        actor,
        {
            "name": "API qualification policy",
            "entity_field": "host",
            "window": 300,
            "steps": [
                {"filters": [{"field": "event_id", "op": "eq", "value": "api-lease"}]}
            ],
        },
    )
    assert detections.run_due(store, time.time() + 1) == 1
    case = detections.incident_list(store, actor)[0]
    app.state.qualification = {
        "asset": asset,
        "policy": policy,
        "case": case,
        "now": now,
    }
    with TestClient(app) as result:
        login(result, "requester")
        yield result


def test_identity_http_exact_fields_revision_and_foreign_scope(client):
    q = client.app.state.qualification
    data = {
        "kind": "ip",
        "lookup": "10.0.0.5",
        "entity_id": q["asset"]["id"],
        "valid_from": q["now"] - 10,
        "valid_until": q["now"] + 60,
        "reason": "DHCP fixture",
        "evidence": [{"event_id": "api-lease", "fields": {"raw.ip": "10.0.0.5"}}],
    }
    result = client.post(BASE + "/identity", json=data)
    assert result.status_code == 201, result.text
    saved = result.json()
    assert client.put(BASE + "/identity/" + saved["id"], json=data).status_code == 409
    resolved = client.post(
        BASE + "/identity/resolve",
        json={"kind": "ip", "lookup": "10.0.0.5", "at": q["now"]},
    )
    assert resolved.status_code == 200 and resolved.json()["status"] == "resolved"
    assert len(client.get(BASE + "/identity/" + saved["id"] + "/history").json()) == 1
    login(client, "foreign")
    assert client.get(BASE + "/identity").json()["items"] == []
    assert (
        client.post(
            BASE + "/identity/" + saved["id"] + "/revoke",
            json={"version": 1, "reason": "foreign"},
        ).status_code
        == 404
    )


def test_governance_http_requires_different_admin_and_visual_revision(client):
    q = client.app.state.qualification
    data = {
        "kind": "storm",
        "policy_id": q["policy"],
        "indexes": ["public"],
        "expires": time.time() + 3600,
        "reason": "bounded API storm",
        "max_per_window": 2,
        "window_seconds": 60,
    }
    result = client.post(BASE + "/governance", json=data)
    assert result.status_code == 201, result.text
    saved = result.json()
    review = {"version": 1, "approve": True, "reason": "Peer reviewed"}
    assert (
        client.post(
            BASE + "/governance/" + saved["id"] + "/review", json=review
        ).status_code
        == 403
    )
    login(client, "approver")
    assert (
        client.post(
            BASE + "/governance/" + saved["id"] + "/review", json=review
        ).status_code
        == 200
    )
    assert client.get(BASE + "/governance").json()[0]["effective_state"] == "active"
    assert (
        client.post(
            BASE + "/governance/" + saved["id"] + "/revoke",
            json={"version": 1, "reason": "end fixture"},
        ).status_code
        == 200
    )
    assert client.get(BASE + "/governance").json()[0]["effective_state"] == "revoked"


def test_risk_and_actual_pipeline_clocks_use_current_case_scope(client):
    q = client.app.state.qualification
    saved = client.put(
        BASE + "/assets/" + q["asset"]["id"] + "/risk-context",
        json={
            "expires": time.time() + 3600,
            "exposure": "internet",
            "classification": "restricted",
            "source": "API synthetic inventory",
            "reason": "typed risk context",
        },
    )
    assert saved.status_code == 200, saved.text
    result = client.get(
        BASE + "/cases/" + q["case"]["id"] + "/priority",
        params={"entity_id": q["asset"]["id"]},
    )
    assert result.status_code == 200 and result.json()["context_state"] == "effective"
    slo = client.get(
        BASE + "/slo", params={"start": q["now"] - 30, "end": time.time() + 2}
    )
    assert slo.status_code == 200, slo.text
    assert slo.json()["event_count"] == 1 and slo.json()["coverage_complete"]
    assert slo.json()["stages"]["indexed_to_case"]["count"] == 1
    login(client, "foreign")
    assert (
        client.get(BASE + "/cases/" + q["case"]["id"] + "/priority").status_code == 404
    )
    assert (
        client.get(
            BASE + "/slo", params={"start": q["now"] - 30, "end": time.time() + 2}
        ).json()["event_count"]
        == 0
    )


def create_artifact(client):
    q, store = client.app.state.qualification, client.app.state.store
    body = b"Harmless API signature sample never executed"
    artifact_id = "ART-" + uuid.uuid4().hex
    directory = endpoint_artifacts._directory(store)
    (directory / (artifact_id + ".bin")).write_bytes(body)
    digest = hashlib.sha256(body).hexdigest()
    with store.control() as db:
        db.execute(
            "INSERT INTO endpoint_artifacts VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                artifact_id,
                uuid.uuid4().hex,
                "a",
                q["case"]["id"],
                "public",
                "api-agent",
                digest,
                len(body),
                len(body),
                "complete",
                time.time(),
                time.time(),
            ),
        )
    return artifact_id, digest


def test_file_signature_http_analyzes_completed_artifact_after_peer_review(client):
    artifact_id, digest = create_artifact(client)
    data = {
        "name": "API harmless managed exact signature",
        "indexes": ["public"],
        "expires": time.time() + 3600,
        "signatures": [
            {
                "id": "labeled",
                "name": "Harmless labeled fixture",
                "kind": "sha256",
                "value": digest,
                "verdict": "suspicious",
                "source": "API qualification",
            }
        ],
    }
    saved = client.post(BASE + "/signature-bundles", json=data)
    assert saved.status_code == 201, saved.text
    identifier = saved.json()["id"]
    assert (
        client.post(
            BASE + "/artifacts/" + artifact_id + "/analyze",
            json={"bundle_ids": [identifier]},
        ).status_code
        == 409
    )
    login(client, "approver")
    assert (
        client.post(
            BASE + "/signature-bundles/" + identifier + "/review",
            json={"version": 1, "approve": True, "reason": "Reviewed label"},
        ).status_code
        == 200
    )
    result = client.post(
        BASE + "/artifacts/" + artifact_id + "/analyze",
        json={"bundle_ids": [identifier]},
    )
    assert result.status_code == 200, result.text
    assert (
        result.json()["verdict"] == "suspicious"
        and not result.json()["sample_executed"]
    )
    case_id = client.app.state.qualification["case"]["id"]
    assert len(client.get(BASE + "/cases/" + case_id + "/verdicts").json()) == 1
    login(client, "foreign")
    assert (
        client.post(
            BASE + "/artifacts/" + artifact_id + "/analyze", json={}
        ).status_code
        == 404
    )


def test_external_pending_job_cannot_be_claimed_as_authenticated_provider(client):
    artifact_id, digest = create_artifact(client)
    job = client.post(
        BASE + "/artifacts/" + artifact_id + "/sandbox",
        json={"provider": "explicit-lab"},
    )
    assert job.status_code == 201 and not job.json()["sample_sent"]
    identifier = job.json()["id"]
    pending = client.get(BASE + "/sandbox/" + identifier)
    assert (
        pending.status_code == 200
        and pending.json()["effective_state"] == "pending_external"
    )
    result = client.post(
        BASE + "/sandbox/" + identifier + "/result",
        json={
            "sha256": digest,
            "provider": "explicit-lab",
            "provider_job_id": "imported-lab-job",
            "verdict": "unknown",
            "report_digest": "a" * 64,
            "observed_at": time.time(),
            "reason": "Explicit external claim import",
        },
    )
    assert (
        result.status_code == 200
        and not result.json()["result"]["provider_signature_verified"]
    )
    login(client, "foreign")
    assert client.get(BASE + "/sandbox/" + identifier).status_code == 404


@pytest.mark.parametrize("route", ["identity", "governance", "signature-bundles"])
def test_new_mutations_require_csrf_and_viewer_cannot_write(client, route):
    client.headers.pop("X-CSRF-Token")
    assert client.post(BASE + "/" + route, json={}).status_code == 403
    login(client, "reader")
    assert client.post(BASE + "/" + route, json={}).status_code == 403


@pytest.mark.parametrize(
    "payload", [{"kind": []}, {"kind": {}}, {"kind": True}, {"kind": "unknown"}]
)
def test_malformed_governance_json_is_400_not_server_error(client, payload):
    assert client.post(BASE + "/governance", json=payload).status_code == 400


def test_unauthenticated_routes_and_query_validation(client):
    assert (
        client.get(
            BASE + "/slo", params={"start": "nan", "end": time.time()}
        ).status_code
        == 400
    )
    assert (
        client.get(BASE + "/identity", params={"limit": "invalid"}).status_code == 400
    )
    assert (
        client.post(
            BASE + "/identity/resolve",
            json={"kind": "ip", "lookup": "10.0.0.5", "at": True},
        ).status_code
        == 400
    )
    client.cookies.clear()
    assert client.get(BASE + "/capabilities").status_code == 401
    assert client.get(BASE + "/slo", params={"start": 0, "end": 1}).status_code == 401


def test_visual_source_field_picker_query_and_policy_metadata_complete_scope(client):
    result = client.post(
        "/api/search",
        json={
            "language": "json",
            "limit": 1,
            "query": {
                "filters": [{"field": "event_id", "op": "eq", "value": "api-lease"}],
                "fields": [
                    "event_id",
                    "event_time",
                    "host",
                    "source",
                    "sourcetype",
                    "severity",
                    "index_name",
                    "raw",
                ],
            },
        },
    )
    assert result.status_code == 200, result.text
    assert result.json()["rows"][0]["event_id"] == "api-lease"
    assert (
        client.get(BASE + "/policies").json()[0]["name"] == "API qualification policy"
    )
    store = client.app.state.store
    auth.create_user(store, "limited", PASSWORD, "analyst", "a")
    access.set_for_user(
        store,
        {"name": "requester", "tenant": "a", "role": "admin", "allowed_indexes": ["*"]},
        "limited",
        ["public"],
    )
    login(client, "limited")
    assert (
        client.get(BASE + "/policies").json() == []
    )  # owner basis is '*', not the convenient sample index
    html = client.get("/").text
    assert (
        "/static/console_advanced.js" in html and "/static/console_advanced.css" in html
    )
    assert client.get("/static/console_advanced.js").status_code == 200
