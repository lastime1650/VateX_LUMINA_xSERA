"""Actual HTTP console-to-connector decoder, scope and review integration."""

import pytest

from tests.test_analysis_sensors import config, sample
from tests.test_xdr_advanced_api import login

pytest_plugins = ("test_xdr_advanced_api",)
BASE = "/api/analysis/sensors"


@pytest.mark.parametrize("kind", ["process_exec", "process_exit"])
def test_tetragon_exec_exit_http_intake_uses_consistent_canonical_action(client, kind):
    created = client.post(BASE + "/sources", json=config("tetragon", mode="live"))
    assert created.status_code == 201, created.text
    saved = created.json()
    observed = sample("tetragon", "http-" + kind)
    observed["log"][kind] = observed["log"].pop("process_kprobe")
    preview = client.post(
        BASE + "/preview", json={"binding_id": saved["id"], "event": observed}
    )
    assert preview.status_code == 200, preview.text
    login(client, "approver")
    reviewed = client.post(
        BASE + "/sources/" + saved["id"] + "/review",
        json={"version": 1, "approve": True, "reason": "Review process event adapter"},
    )
    assert reviewed.status_code == 200, reviewed.text
    login(client, "requester")
    admitted = client.post(
        BASE + "/sources/" + saved["id"] + "/intake",
        json={
            "version": 1,
            "events": [observed],
            "cursor": "http-1",
            "checkpoint_version": 0,
        },
    )
    assert admitted.status_code == 202, admitted.text
    assert admitted.json()["durable"] and admitted.json()["mode"] == "live"


def test_authenticated_http_approval_preview_intake_status_and_revoke(client):
    assert len(client.get(BASE + "/catalog").json()["items"]) == 5
    result = client.post(BASE + "/sources", json=config("falco"))
    assert result.status_code == 201, result.text
    saved = result.json()
    assert (
        client.post(
            BASE + "/sources/" + saved["id"] + "/review",
            json={"version": 1, "approve": True, "reason": "self review prohibited"},
        ).status_code
        == 403
    )
    preview = client.post(
        BASE + "/preview", json={"binding_id": saved["id"], "event": sample("falco")}
    )
    assert preview.status_code == 200, preview.text
    assert preview.json()["persisted"] is False
    login(client, "approver")
    approved = client.post(
        BASE + "/sources/" + saved["id"] + "/review",
        json={
            "version": 1,
            "approve": True,
            "reason": "independent source and Case review",
        },
    )
    assert approved.status_code == 200, approved.text
    login(client, "requester")
    data = {
        "version": 1,
        "events": [sample("falco")],
        "cursor": "http-1",
        "checkpoint_version": 0,
    }
    admitted = client.post(BASE + "/sources/" + saved["id"] + "/intake", json=data)
    assert admitted.status_code == 202, admitted.text
    assert admitted.json()["durable"] is True and admitted.json()["mode"] == "replay"
    health = client.post(
        BASE + "/sources/" + saved["id"] + "/health",
        json={
            "version": 1,
            "state": "ok",
            "captured": 20,
            "dropped": 2,
            "sensor_version": "inert-test",
        },
    )
    assert (
        health.status_code == 200
        and health.json()["effective_reported_state"] == "degraded"
    )
    listed = client.get(BASE + "/sources").json()["items"][0]
    assert listed["received_originals"] == 1 and listed["checkpoint_version"] == 1
    assert (
        client.post(
            BASE + "/sources/" + saved["id"] + "/revoke",
            json={"version": 1, "reason": "retire inert fixture"},
        ).status_code
        == 200
    )
    assert (
        client.post(BASE + "/sources/" + saved["id"] + "/intake", json=data).status_code
        == 409
    )


def test_http_foreign_and_viewer_cannot_mutate_or_borrow_sensor_binding(client):
    created = client.post(BASE + "/sources", json=config())
    assert created.status_code == 201, created.text
    saved = created.json()
    login(client, "foreign")
    assert client.get(BASE + "/sources").json()["items"] == []
    assert (
        client.post(
            BASE + "/preview",
            json={"binding_id": saved["id"], "event": sample("suricata")},
        ).status_code
        == 404
    )
    login(client, "reader")
    assert client.post(BASE + "/sources", json=config()).status_code == 403
    assert (
        client.post(
            BASE + "/sources/" + saved["id"] + "/intake",
            json={
                "version": 1,
                "events": [sample("suricata")],
                "cursor": "blocked",
                "checkpoint_version": 0,
            },
        ).status_code
        == 403
    )
