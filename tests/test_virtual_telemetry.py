"""Real API intake of virtual product logs; no native telemetry/effects."""

import copy
import time

import pytest
from fastapi.testclient import TestClient

from sapientia import auth, connector_runtime, source_registry
from sapientia.api import create_app
from sapientia.collector_plugins import cisco_asa
from sapientia.storage import ConflictError, Settings
from tests.test_backend_upgrade import actor
from tools.simulation.loggers import HOSTS, PROFILES, generate


@pytest.fixture
def client(tmp_path):
    app = create_app(Settings(tmp_path / "db", min_free_bytes=0), background=False)
    auth.create_user(app.state.store, "owner", "Virtual-simulation-password-2026", "admin", "a")
    with TestClient(app) as client:
        reply = client.post("/api/login", json={"name": "owner", "password": "Virtual-simulation-password-2026"})
        assert reply.status_code == 200
        client.headers["X-CSRF-Token"] = reply.json()["csrf"]
        yield client


def register(client, profile):
    response = client.post("/api/v2/sources", json={"index": "sim_" + profile, "product": profile, "account": HOSTS[profile], "realm": "virtual-lab", "credential_ref": "env:SAPIENTIA_CONNECTOR_VIRTUAL", "version": 0})
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.parametrize("profile", PROFILES)
def test_virtual_intake_real_api_normalization_and_durable_replay(client, profile):
    source = register(client, profile)
    events, truth = generate(profile, 20, seed=17)
    body = {"version": 1, "events": events, "cursor": "page-20", "checkpoint_version": 0}
    path = "/api/v2/sources/" + source["id"] + "/intake"
    first = client.post(path, json=body)
    assert first.status_code == 202, first.text
    assert first.json()["durable"] and first.json()["accepted"] == 20
    repeat = client.post(path, json=body)
    assert repeat.status_code == 202 and repeat.json()["duplicate"] == 20
    assert repeat.json()["checkpoint_version"] == 1
    store = client.app.state.store
    store.flush()
    result = store.analytics_query("SELECT event_id,raw FROM events_all WHERE tenant=? AND index_name=?", ["a", "sim_"+profile], max_rows=100)["rows"]
    assert len(result) == 20
    assert len({r["event_id"] for r in result}) == 20
    assert all("scenario_label" not in r["raw"] for r in result)
    assert all("security" in r["raw"] for r in result)
    assert first.json()["native_capture_proven"] is False


def test_checkpoint_cannot_regress_or_reuse_cursor_with_new_data(client):
    source = register(client, "cisco_asa")
    events, _ = generate("cisco_asa", 4)
    path = "/api/v2/sources/" + source["id"] + "/intake"
    assert client.post(path, json={"version": 1, "events": events[:2], "cursor": "2", "checkpoint_version": 0}).status_code == 202
    assert client.post(path, json={"version": 1, "events": events[2:], "cursor": "4", "checkpoint_version": 0}).status_code == 409
    assert client.post(path, json={"version": 1, "events": events[2:], "cursor": "2", "checkpoint_version": 1}).status_code == 409
    with client.app.state.store.control() as db:
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 2
        assert db.execute("SELECT cursor FROM connector_checkpoints").fetchone()[0] == "2"
    assert client.post(path, json={"version": 1, "events": events[2:], "cursor": "4", "checkpoint_version": 1}).status_code == 202


def test_fortigate_device_spoof_and_revoked_source_refused(client):
    source = register(client, "fortigate")
    events, _ = generate("fortigate", 1)
    events[0]["log"] = events[0]["log"].replace(HOSTS["fortigate"], "FOREIGN-FGT")
    path = "/api/v2/sources/" + source["id"] + "/intake"
    assert client.post(path, json={"version": 1, "events": events, "cursor": "1", "checkpoint_version": 0}).status_code == 403
    assert client.post("/api/v2/sources/"+source["id"]+"/revoke", json={"version": 1}).status_code == 200
    events, _ = generate("fortigate", 1)
    assert client.post(path, json={"version": 2, "events": events, "cursor": "1", "checkpoint_version": 0}).status_code == 409


def test_asa_direction_and_unsupported_message_not_guessed():
    events, _ = generate("cisco_asa", 1)
    row = cisco_asa.envelope(events[0], "net", "ASA-01")
    assert row["raw"]["security"]["src_ip"] == "10.10.0.10"
    assert row["raw"]["security"]["dest_ip"] == "203.0.113.66"
    changed = {**events[0], "log": events[0]["log"].replace("302013", "302014")}
    with pytest.raises(ValueError, match="not qualified"):
        cisco_asa.envelope(changed, "net", "ASA-01")


def test_generator_replay_is_stable_and_ground_truth_is_separate():
    a = generate("windows", 40, seed=17, base_time=1700000000)
    b = generate("windows", 40, seed=17, base_time=1700000000)
    assert a == b
    assert len({e["id"] for e in a[0]}) == 40
    assert sum(r["scenario_label"] == "malicious" for r in a[1]) == 8
    assert all("malicious" not in str(e) for e in a[0])
