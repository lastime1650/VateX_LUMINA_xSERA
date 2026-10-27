# ruff: noqa: F811 - imported pytest fixture names are reused as parameters.
"""Public HTTP Sigma custody stages and authentication on disposable stores."""

import time

from test_enterprise_api import (  # noqa: F401 - shared disposable HTTP fixture.
    client,
    login,
    success,
)
from test_sigma_imports import payload

BASE = "/api/content/sigma/imports"


def registered(client):
    return success(
        client.post(
            "/api/v2/sources",
            json={
                "index": "public",
                "product": "json",
                "account": "sigma-http-fixture",
                "realm": "virtual-lab",
                "credential_ref": "env:SAPIENTIA_CONNECTOR_SIGMA_HTTP",
                "version": 0,
            },
        ),
        201,
    )


def test_sigma_http_whole_workflow_and_fixture_does_not_admit_operational_events(
    client,
):
    assert client.get(BASE + "/status").status_code == 401
    login(client)
    data = payload(registered(client))
    value = success(client.post(BASE, json=data), 201)
    identifier = value["id"]
    assert (
        value["payload"]["source_text"] == data["source_text"]
        and value["editor"] == "admin_a"
    )
    for stage, state in [("convert", "converted"), ("validate", "validated")]:
        value = success(
            client.post(
                BASE + "/" + identifier + "/" + stage, json={"expected_revision": 1}
            )
        )
        assert value["state"] == state
    with client.app.state.store.control() as db:
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 0
        assert (
            db.execute("SELECT count(*) FROM intelligence_signals").fetchone()[0] == 0
        )
        assert db.execute("SELECT count(*) FROM incidents").fetchone()[0] == 0
    assert (
        client.post(
            BASE + "/" + identifier + "/review",
            json={"expected_revision": 1, "approve": True, "reason": "Self review"},
        ).status_code
        == 403
    )
    login(client, "approver_a")
    value = success(
        client.post(
            BASE + "/" + identifier + "/review",
            json={
                "expected_revision": 1,
                "approve": True,
                "reason": "Independent actual native fixture review",
            },
        )
    )
    assert value["state"] == "approved"
    value = success(
        client.post(
            BASE + "/" + identifier + "/activate", json={"expected_revision": 1}
        )
    )
    assert value["state"] == "active" and value["native_policy_id"]
    assert (
        success(client.get(BASE + "/" + identifier))["converted_sha256"]
        == value["converted_sha256"]
    )
    assert identifier in str(success(client.get(BASE)))


def test_viewer_foreign_edit_optimistic_revision_and_arbitrary_input_are_rejected(
    client,
):
    login(client)
    data = payload(registered(client))
    value = success(client.post(BASE, json=data), 201)
    path = BASE + "/" + value["id"]
    for bad in [
        {**data, "url": "https://example.org/rule.yaml"},
        {**data, "path": "C:/anything"},
        {**data, "format": "python"},
        {**data, "indexes": ["*"]},
    ]:
        assert client.post(BASE, json=bad).status_code == 400
    for revision in [True, 0, 2]:
        assert (
            client.post(
                path + "/convert", json={"expected_revision": revision}
            ).status_code
            == 409
        )
    login(client, "viewer_a")
    assert client.get(BASE + "/status").status_code == 200
    assert client.get(path).status_code == 200
    assert (
        client.post(path + "/convert", json={"expected_revision": 1}).status_code == 403
    )
    assert client.put(path, json={**data, "expected_revision": 1}).status_code == 403
    login(client, "admin_b")
    assert success(client.get(BASE))["items"] == []
    assert client.get(path).status_code == 404


def test_failing_native_fixture_blocks_review_and_raw_source_is_retained(client):
    login(client)
    data = payload(registered(client))
    data["fixtures"][0]["expect"] = False
    value = success(client.post(BASE, json=data), 201)
    path = BASE + "/" + value["id"]
    success(client.post(path + "/convert", json={"expected_revision": 1}))
    value = success(client.post(path + "/validate", json={"expected_revision": 1}))
    assert (
        value["state"] == "validation_failed" and value["validation"]["passed"] is False
    )
    assert value["payload"]["source_text"] == data["source_text"]
    login(client, "approver_a")
    assert client.post(path + "/review", json={"expected_revision": 1, "approve": True, "reason": "Cannot approve failed fixture"}).status_code == 409
    assert client.post(path + "/activate", json={"expected_revision": 1}).status_code == 409


def test_http_observed_mapping_and_generated_fixtures_require_explicit_draft_approval(client):
    login(client)
    declared = registered(client)
    data = payload(declared)
    data["field_mapping"]["CommandLine"] = "raw.unobserved_command"
    draft = success(client.post(BASE, json=data), 201)
    path = BASE + "/" + draft["id"]
    event = {**data["fixtures"][0]["event"], "event_id": "http-observed-schema", "event_time": time.time() - 1}
    success(client.post("/api/v2/sources/" + declared["id"] + "/intake", json={"version": 1, "events": [event], "cursor": "sigma-observed", "checkpoint_version": 0}), 202)
    client.app.state.store.flush()
    proposal = success(client.post(path + "/mapping-suggestions", json={"expected_revision": 1}))
    assert proposal["changes"]["CommandLine"] == "raw.command" and proposal["automatic_apply"] is False
    assert client.post(path + "/apply-mapping", json={"expected_revision": 1, "proposal_digest": proposal["proposal_digest"], "approve": False}).status_code == 400
    revised = success(client.post(path + "/apply-mapping", json={"expected_revision": 1, "proposal_digest": proposal["proposal_digest"], "approve": True}))
    assert revised["revision"] == 2 and revised["state"] == "imported"
    success(client.post(path + "/convert", json={"expected_revision": 2}))
    generated = success(client.post(path + "/fixture-candidates", json={"expected_revision": 2}))
    assert generated["state"] == "candidates" and generated["positive_count"] and generated["negative_count"]
    assert success(client.get(path))["state"] == "converted"
    login(client, "viewer_a")
    for suffix in ("mapping-suggestions", "fixture-candidates", "apply-mapping", "rollback"):
        assert client.post(path + "/" + suffix, json={"expected_revision": 2}).status_code == 403


def test_http_active_snapshot_continues_through_draft_and_atomic_replacement_rollback(client):
    login(client)
    data = payload(registered(client))
    draft = success(client.post(BASE, json=data), 201)
    path = BASE + "/" + draft["id"]
    def test_and_review(revision):
        success(client.post(path + "/convert", json={"expected_revision": revision}))
        success(client.post(path + "/validate", json={"expected_revision": revision}))
        login(client, "approver_a")
        success(client.post(path + "/review", json={"expected_revision": revision, "approve": True, "reason": "Independent exact native fixtures"}))
        return success(client.post(path + "/activate", json={"expected_revision": revision}))
    active = test_and_review(1)
    login(client)
    revised = success(client.put(path, json={**data, "expected_revision": 1, "severity": "critical"}))
    assert revised["state"] == "imported" and revised["active_deployment"]["revision"] == 1
    with client.app.state.store.control() as db:
        assert db.execute("SELECT state FROM intelligence_policies WHERE id=?", (active["native_policy_id"],)).fetchone()[0] == "active"
    second = test_and_review(2)
    assert second["active_deployment"]["policy_version"] == 2
    login(client)
    restored = success(client.post(path + "/rollback", json={"expected_revision": 2, "expected_policy_version": 2, "target_policy_version": 1, "reason": "Restore tested predecessor"}))
    assert restored["active_deployment"]["revision"] == 1 and restored["active_deployment"]["policy_version"] == 3
    assert restored["payload"]["severity"] == "critical"
