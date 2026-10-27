"""Peer approval, exact source/process binding, unknown retry and virtual readback."""

import json

import pytest

from sapientia import action_runtime, auth, correlation_runtime, effect_receipts
from sapientia.storage import ConflictError
from tests.test_backend_upgrade import actor
from tests.test_correlation_v2 import drain, load
from tests.test_virtual_telemetry import client


def fixture(client):
    store = client.app.state.store
    store.settings.simulation_mode = True
    auth.create_user(store, "peer", "Virtual-peer-password-2026", "admin", "a")
    plan, sources = load(client, 5)
    drain(store)
    with store.control() as db:
        contribution = db.execute("SELECT incident_id,evidence FROM risk_contributions ORDER BY id LIMIT 1").fetchone()
        case = db.execute("SELECT * FROM incidents WHERE id=?", (contribution["incident_id"],)).fetchone()
    source = sources["windows"]
    evidence = json.loads(contribution["evidence"])["event_ids"]
    asset = action_runtime.create_asset(store, actor(), {"source_id": source["id"], "asset_id": source["account"], "processes": {}})
    prepared = effect_receipts.prepare(store, actor(), case["id"], {"case_version": case["version"], "source_id": source["id"], "source_version": 1,
        "action": "isolate_host", "target": {"asset_id": asset["asset_id"], "asset_version": 1, "lease_seconds": 30}, "event_ids": evidence})
    return store, source, prepared


def test_default_instance_refuses_all_virtual_effects(client):
    with pytest.raises(PermissionError, match="explicitly isolated"):
        action_runtime.create_asset(client.app.state.store, actor(), {"source_id": "x", "asset_id": "x", "processes": {}})


def test_peer_approval_and_readback_are_virtual_only_and_idempotent(client):
    store, source, prepared = fixture(client)
    with pytest.raises(ConflictError):
        action_runtime.dispatch(store, actor(), prepared["id"], 1)
    with pytest.raises(PermissionError):
        effect_receipts.transition(store, actor(), prepared["id"], 1, "approved", {})
    peer = actor("peer")
    approved = effect_receipts.transition(store, peer, prepared["id"], 1, "approved", {})
    confirmed = action_runtime.dispatch(store, actor(), prepared["id"], approved["version"])
    assert confirmed["state"] == "confirmed" and confirmed["native_effect"] is False
    assert len(confirmed["artifact_digest"]) == 64
    model = action_runtime.asset(store, actor(), source["id"])
    assert model["effective_isolated"] and model["state"]["effect_count"] == 1
    assert action_runtime.dispatch(store, actor(), prepared["id"], approved["version"])["duplicate"]
    assert action_runtime.asset(store, actor(), source["id"])["state"]["effect_count"] == 1


def test_unknown_dispatch_is_never_blindly_repeated(client):
    store, source, prepared = fixture(client)
    approved = effect_receipts.transition(store, actor("peer"), prepared["id"], 1, "approved", {})
    executing = effect_receipts.transition(store, actor(), prepared["id"], approved["version"], "dispatching", {})
    unknown = effect_receipts.transition(store, actor(), prepared["id"], executing["version"], "unknown", {})
    with pytest.raises(ConflictError):
        action_runtime.dispatch(store, actor(), prepared["id"], unknown["version"])
    assert action_runtime.asset(store, actor(), source["id"])["state"]["effect_count"] == 0


def test_approver_revoked_before_dispatch_cannot_create_effect(client):
    store, source, prepared = fixture(client)
    approved = effect_receipts.transition(store, actor("peer"), prepared["id"], 1, "approved", {})
    with store.control() as db:
        db.execute("UPDATE users SET disabled=1 WHERE name='peer'")
    with pytest.raises(PermissionError):
        action_runtime.dispatch(store, actor(), prepared["id"], approved["version"])
    assert action_runtime.asset(store, actor(), source["id"])["state"]["effect_count"] == 0
