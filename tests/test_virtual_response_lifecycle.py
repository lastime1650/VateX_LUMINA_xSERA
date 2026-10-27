"""Real scoped APIs and durable fake effects; never import an OS executor."""

import json
import time
import base64

import pytest
from fastapi.testclient import TestClient

from sapientia import access, action_runtime, auth, connector_runtime, detections, effect_receipts, endpoint_response, qualification_registry, release_manifest, source_registry
from sapientia.storage import ConflictError, Store
from tests.test_backend_upgrade import actor
from tests.test_endpoint_response import response_case, claim_ack, config, source_store
from tests.test_xdr_bridge import actor as endpoint_actor
from tests.test_virtual_response import fixture
from tests.test_virtual_telemetry import client, register
from tools.simulation.loggers import ATTACK_IP, generate
from tools.virtual_response_lab import run_response_lifecycle


class Transport:
    origin = "http://127.0.0.1"

    def __init__(self, client):
        self.client = client

    def get(self, path):
        return self.client.get(path)

    def post(self, path, body):
        return self.client.post(path, json=body)


@pytest.mark.parametrize("profile", ["windows", "linux", "fortigate", "cisco_asa"])
def test_http_full_lifecycle_is_virtual_independent_reversible_and_idempotent(client, profile):
    store = client.app.state.store
    store.settings.simulation_mode = True
    auth.create_user(store, "peer", "Virtual-peer-password-2026", "admin", "a")
    source = register(client, profile)
    events, _ = generate(profile, 5, base_time=time.time()-30)
    assert client.post("/api/v2/sources/"+source["id"]+"/intake", json={"version": 1,
        "events": events, "cursor": "all", "checkpoint_version": 0}).status_code == 202
    store.flush()
    original = connector_runtime.decode(events[0], {**source, "index_name": source["index"]})["event_id"]
    detections.save(store, actor(), {"name": "Typed virtual response evidence", "entity_field": "host",
        "window": 300, "steps": [{"filters": [{"field": "event_id", "op": "eq", "value": original}]}]})
    assert detections.run_due(store, time.time()+1) == 1
    case_id = detections.incident_list(store, actor())[0]["id"]
    peer = TestClient(client.app)
    try:
        login = peer.post("/api/login", json={"name": "peer", "password": "Virtual-peer-password-2026"})
        assert login.status_code == 200
        peer.headers["X-CSRF-Token"] = login.json()["csrf"]
        network = profile in {"fortigate", "cisco_asa"}
        report = run_response_lifecycle("http://127.0.0.1", Transport(client), Transport(peer),
            case_id=case_id, source_id=source["id"], event_ids=[original], request_id="full-protocol-"+profile,
            action="block_ip" if network else "isolate_host", target={"ip": ATTACK_IP} if network else None)
        assert report["passed"] and not report["native_effect"] and not report["host_os_or_network_mutated"]
        assert report["synthetic_hardware_effect"] and not report["native_qualification"]
        assert report["response"]["states"] == ["prepared", "approved", "dispatching", "reported", "confirmed"]
        assert report["release"]["states"] == report["response"]["states"]
        assert report["final_virtual_asset"]["state"]["effect_count"] == 2
        assert not report["final_virtual_asset"]["effective_isolated"]
        assert report["final_virtual_asset"]["effective_blocked_ips"] == []
        with store.control() as db:
            assert db.execute("SELECT count(*) FROM endpoint_responses").fetchone()[0] == 0
            assert db.execute("SELECT count(*) FROM qualification_manifests").fetchone()[0] == 0
    finally:
        peer.close()


def test_adapter_refuses_nonloopback_before_any_transport_action():
    class Never:
        def get(self, _path):
            pytest.fail("Remote virtual action attempted")
    with pytest.raises(ValueError, match="loopback"):
        run_response_lifecycle("https://external.example", Never(), Never(), case_id="case", source_id="source",
            event_ids=["e"], request_id="remote")


@pytest.mark.parametrize("stage", ["prepare", "approved"])
def test_virtual_approval_expires_before_effect_and_does_not_reset_intent(client, stage):
    store, source, prepared = fixture(client)
    current = prepared
    if stage == "approved":
        current = effect_receipts.transition(store, actor("peer"), prepared["id"], 1, "approved", {})
    with store.control() as db:
        db.execute("UPDATE effect_receipts SET created=? WHERE id=?", (time.time()-301, prepared["id"]))
    with pytest.raises(ConflictError, match="expired"):
        if stage == "approved":
            action_runtime.dispatch(store, actor(), prepared["id"], current["version"])
        else:
            effect_receipts.transition(store, actor("peer"), prepared["id"], 1, "approved", {})
    assert action_runtime.asset(store, actor(), source["id"])["state"]["effect_count"] == 0
    cancelled = client.post("/api/v2/effects/"+prepared["id"]+"/cancel", json={"version": current["version"]})
    assert cancelled.status_code == 200 and cancelled.json()["state"] == "cancelled"


def test_unknown_dispatch_survives_restart_and_cannot_be_replayed(client):
    store, source, prepared = fixture(client)
    approved = effect_receipts.transition(store, actor("peer"), prepared["id"], 1, "approved", {})
    dispatched = effect_receipts.transition(store, actor(), prepared["id"], approved["version"], "dispatching", {"mode": "virtual"})
    settings = store.settings
    store.close()
    restarted = Store(settings)
    try:
        unknown = action_runtime.recover_unknown(restarted, actor(), prepared["id"], dispatched["version"])
        assert unknown["state"] == "unknown"
        with pytest.raises(ConflictError):
            action_runtime.dispatch(restarted, actor(), prepared["id"], unknown["version"])
        assert action_runtime.asset(restarted, actor(), source["id"])["state"]["effect_count"] == 0
        with restarted.control() as db:
            proof = json.loads(db.execute("SELECT proof FROM effect_receipt_history WHERE id=? AND state='unknown'", (prepared["id"],)).fetchone()[0])
            assert not proof["retry_authorized"] and not proof["verified"] and not proof["native_effect"]
    finally:
        restarted.close()


def test_confirmed_receipt_and_fake_state_survive_restart_without_second_effect(client):
    store, source, prepared = fixture(client)
    approved = effect_receipts.transition(store, actor("peer"), prepared["id"], 1, "approved", {})
    confirmed = action_runtime.dispatch(store, actor(), prepared["id"], approved["version"])
    store.close()
    restarted = Store(store.settings)
    try:
        replay = action_runtime.dispatch(restarted, actor(), prepared["id"], approved["version"])
        assert replay["duplicate"] and replay["artifact_digest"] == confirmed["artifact_digest"]
        assert action_runtime.asset(restarted, actor(), source["id"])["state"]["effect_count"] == 1
    finally:
        restarted.close()


def test_virtual_proof_cannot_be_promoted_to_native_by_manual_confirmation(client):
    store, source, prepared = fixture(client)
    approved = effect_receipts.transition(store, actor("peer"), prepared["id"], 1, "approved", {})
    dispatched = effect_receipts.transition(store, actor(), prepared["id"], approved["version"], "dispatching", {})
    reported = effect_receipts.transition(store, actor(), prepared["id"], dispatched["version"], "reported", {})
    with pytest.raises(ValueError, match="native qualification"):
        effect_receipts.transition(store, actor(), prepared["id"], reported["version"], "confirmed",
            {"verified": True, "artifact_digest": "a"*64, "mode": "native", "native_effect": True})
    assert action_runtime.asset(store, actor(), source["id"])["state"]["effect_count"] == 0


def test_current_case_version_and_full_approver_scope_checked_before_dispatch(client):
    store, source, prepared = fixture(client)
    approved = effect_receipts.transition(store, actor("peer"), prepared["id"], 1, "approved", {})
    access.set_for_user(store, actor(), "peer", ["sim_windows"])
    with pytest.raises(PermissionError):
        action_runtime.dispatch(store, actor(), prepared["id"], approved["version"])
    access.set_for_user(store, actor(), "peer", ["*"])
    with store.control() as db:
        db.execute("UPDATE incidents SET version=version+1 WHERE id=(SELECT incident_id FROM effect_receipts WHERE id=?)", (prepared["id"],))
    with pytest.raises(PermissionError):
        action_runtime.dispatch(store, actor(), prepared["id"], approved["version"])
    assert action_runtime.asset(store, actor(), source["id"])["state"]["effect_count"] == 0


@pytest.mark.parametrize("markers", [{"mode": "virtual"}, {"simulation": True}, {"synthetic_hardware_effect": True}])
def test_virtual_result_is_refused_by_genuine_endpoint_receipt_protocol(response_case, markers, monkeypatch):
    # Server protocol fixture only; no Agent executor or native OS action is invoked.
    monkeypatch.delenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", raising=False)
    store, service, identity, case_id, body = response_case
    queued = endpoint_response.create(store, endpoint_actor(), case_id, body)
    _command, receipt, ack = claim_ack(service, identity)
    assert ack["execute"]
    with pytest.raises(ValueError, match="simulation effect protocol"):
        service.response_result(identity["credential"], {**receipt, "result": {
            "type": "terminate_process", "success": True, "executed": True, "code": "synthetic",
            "detail": "Fake device readback", "data": markers}})
    current = endpoint_response.get(store, endpoint_actor(), queued["id"])
    assert current["state"] == "started" and current["result"] is None


def test_even_signed_explicit_virtual_receipt_cannot_claim_native_qualification():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    key = Ed25519PrivateKey.generate()
    trusted = {"lab": base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()}
    now = time.time()
    document = {"schema": qualification_registry.SCHEMA, "signer": "lab", "tenant": "a", "indexes": ["public"],
        "source_digest": "a"*64, "package_digest": "b"*64, "config_digest": "c"*64, "tool_digest": "d"*64,
        "platform": "virtual-windows", "capability": "host_isolation", "native": True, "passed": True,
        "checks": [{"name": "fake_state_readback", "passed": True, "artifact_digest": "e"*64}],
        "created": now-1, "expires": now+60}
    envelope = {"document": document, "signature": base64.b64encode(key.sign(release_manifest.canonical(document))).decode()}
    with pytest.raises(ValueError, match="virtual qualification"):
        qualification_registry.verify(envelope, trusted)


def test_historical_source_receipt_cannot_prepare_intent_for_revised_source_epoch(client):
    store, source, prepared = fixture(client)
    with store.control() as db:
        row = db.execute("SELECT definition,incident_id FROM effect_receipts WHERE id=?", (prepared["id"],)).fetchone()
        definition = json.loads(row["definition"])
        source_config = dict(source_registry.visible(db, actor(), source["id"]))
    revised = source_registry.save(store, actor(), {"index": source_config["index_name"],
        **{key: source_config[key] for key in ("product", "account", "realm", "credential_ref", "version")}}, source["id"])
    request = {key: definition[key] for key in ("case_version", "source_id", "action", "target", "event_ids")}
    request.update(source_version=revised["version"], request_id="new-epoch-intent")
    with pytest.raises(PermissionError, match="epoch/account"):
        effect_receipts.prepare(store, actor(), row["incident_id"], request)
    assert action_runtime.asset(store, actor(), source["id"])["state"]["effect_count"] == 0
