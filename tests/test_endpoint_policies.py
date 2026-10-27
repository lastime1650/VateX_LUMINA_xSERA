# ruff: noqa: F811 -- Imported pytest fixtures are resolved by argument name.
import copy
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi.testclient import TestClient

from sapientia import access
from sapientia import endpoint_policies as ep
from sapientia.agent_distribution import Distribution
from sapientia.api import create_app
from sapientia.endpoint_agent.Agent.defense import canonical
from sapientia.storage import ConflictError
from tests.test_agent_distribution import config, enrolled, source_store  # noqa: F401
from tests.test_xdr_bridge import PASSWORD, actor


def request(identity, request_id="stable-release"):
    return {
        "agent_id": identity["agent_id"],
        "request_id": request_id,
        "lifetime_hours": 1,
        "rules": [
            {
                "id": "fixture-only",
                "enabled": True,
                "action": "observe",
                "conditions": [
                    {"field": "process.name", "op": "eq", "value": "fixture.exe"}
                ],
            }
        ],
    }


def test_release_has_independent_key_and_peer_approval(source_store, config, monkeypatch):
    # Server protocol fixture only; no Agent executor or native OS action is invoked.
    monkeypatch.delenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", raising=False)
    service = Distribution(source_store, config)
    identity, *_ = enrolled(service)
    data = request(identity)
    row = ep.save(source_store, actor(), data)
    assert row["status"] == "pending_approval"
    assert ep.save(source_store, actor(), data) == row
    assert ep.fetch(source_store, service, identity["credential"], {})["bundle"] is None
    with pytest.raises(PermissionError):
        ep.approve(source_store, actor(), row["id"])
    approved = ep.approve(source_store, actor("admin_other"), row["id"])
    bundle = ep.fetch(source_store, service, identity["credential"], {})["bundle"]
    key = ep.public_key(source_store, "a")
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
        bytes.fromhex(bundle["signature"]), canonical(bundle["document"])
    )
    assert ep.bundle(source_store, actor(), row["id"]) == bundle
    assert approved["status"] == "active"
    assert "private_cipher" not in json.dumps(ep.listing(source_store, actor()))
    assert key not in identity["credential"]


def test_release_acl_tenant_and_request_digest(source_store, config, monkeypatch):
    # Server protocol fixture only; no Agent executor or native OS action is invoked.
    monkeypatch.delenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", raising=False)
    service = Distribution(source_store, config)
    identity, *_ = enrolled(service)
    data = request(identity)
    row = ep.save(source_store, actor(), data)
    changed = copy.deepcopy(data)
    changed["rules"][0]["enabled"] = False
    with pytest.raises(ConflictError):
        ep.save(source_store, actor(), changed)
    with pytest.raises(KeyError):
        ep.approve(source_store, actor("admin_b", "b"), row["id"])
    access.set_for_user(source_store, actor(), "admin_other", ["other"])
    with pytest.raises(KeyError):
        ep.approve(source_store, actor("admin_other"), row["id"])
    access.set_for_user(source_store, actor(), "admin_other", ["endpoint"])
    ep.approve(source_store, actor("admin_other"), row["id"])
    with source_store.control() as db:
        db.execute("UPDATE users SET disabled=1 WHERE name=?", ("admin_other",))
    with pytest.raises(PermissionError):
        ep.fetch(source_store, service, identity["credential"], {})


def test_rollback_requires_new_revision_and_new_scope(source_store, config, monkeypatch):
    # Server protocol fixture only; no Agent executor or native OS action is invoked.
    monkeypatch.delenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", raising=False)
    service = Distribution(source_store, config)
    identity, *_ = enrolled(service)
    first = ep.save(source_store, actor(), request(identity, "first"))
    next_row = ep.save(source_store, actor(), request(identity, "next"))
    ep.approve(source_store, actor("admin_other"), next_row["id"])
    with pytest.raises(ConflictError):
        ep.approve(source_store, actor("admin_other"), first["id"])
    assert (
        ep.fetch(source_store, service, identity["credential"], {})["bundle"][
            "document"
        ]["revision"]
        == 2
    )


def test_unsigned_or_invalid_rule_cannot_publish(source_store, config):
    service = Distribution(source_store, config)
    identity, *_ = enrolled(service)
    data = request(identity)
    data["rules"][0]["action"] = "arbitrary_shell"
    with pytest.raises(ValueError):
        ep.save(source_store, actor(), data)

    data = request(identity)
    data["lifetime_hours"] = 1000
    with pytest.raises(ValueError):
        ep.save(source_store, actor(), data)


def test_release_uses_replica_recorder_after_pre_replica_schema(
    source_store, config, monkeypatch
):
    # Server protocol fixture only; no Agent executor or native OS action is invoked.
    monkeypatch.delenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", raising=False)
    from contextlib import contextmanager

    from sapientia.cluster import Recorder

    service = Distribution(source_store, config)
    identity, *_ = enrolled(service)
    original = source_store.control
    recorded = []

    @contextmanager
    def controlled(local=False):
        with original(local=True) as db:
            if local:
                yield db
            else:
                recorder = Recorder(db)
                yield recorder
                recorded.extend(recorder.statements)

    monkeypatch.setattr(source_store, "control", controlled)
    row = ep.save(source_store, actor(), request(identity, "recorder-release"))
    ep.approve(source_store, actor("admin_other"), row["id"])
    assert ep.fetch(source_store, service, identity["credential"], {})["bundle"]
    assert ep.public_key(source_store, "a")
    assert any("endpoint_defense_policies" in item["sql"] for item in recorded)
    json.dumps(recorded, allow_nan=False)


def test_observation_profile_blocks_previously_active_policy_without_destroying_history(
    source_store, config, monkeypatch
):
    monkeypatch.delenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", raising=False)
    service = Distribution(source_store, config)
    identity, *_ = enrolled(service)
    old = ep.save(source_store, actor(), request(identity, "before-observe-upgrade"))
    ep.approve(source_store, actor("admin_other"), old["id"])
    previous = ep.fetch(source_store, service, identity["credential"], {})["bundle"]
    assert previous and ep.bundle(source_store, actor(), old["id"]) == previous
    monkeypatch.setenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", "1")
    draft = ep.save(source_store, actor(), request(identity, "observe-draft"))
    assert draft["status"] == "pending_approval"
    for identifier in (old["id"], draft["id"]):
        with pytest.raises(PermissionError, match="observation deployment"):
            ep.approve(source_store, actor("admin_other"), identifier)
    with pytest.raises(PermissionError, match="observation deployment"):
        ep.bundle(source_store, actor(), old["id"])
    blocked = ep.fetch(source_store, service, identity["credential"], {})
    assert blocked == {"bundle": None, "blocked": True, "reason": ep.BLOCKED_REASON}
    with pytest.raises(PermissionError, match="credential"):
        ep.fetch(source_store, service, "invalid-fixture-credential", {})
    rows = {row["id"]: row for row in ep.listing(source_store, actor())["policies"]}
    assert rows[old["id"]]["status"] == "active"
    assert rows[draft["id"]]["status"] == "pending_approval"
    assert all("signature" not in row for row in rows.values())
    with source_store.control() as db:
        assert db.execute("SELECT count(*) FROM endpoint_responses").fetchone()[0] == 0
        assert (
            db.execute(
                "SELECT signature FROM endpoint_defense_policies WHERE id=?",
                (draft["id"],),
            ).fetchone()[0]
            is None
        )
    # An explicit operator change of the deployment profile restores the
    # unchanged active revision; fetching never creates a new release.
    monkeypatch.delenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE")
    assert (
        ep.fetch(source_store, service, identity["credential"], {})["bundle"]
        == previous
    )
    monkeypatch.setenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", "1")
    service.revoke(actor(), identity["agent_id"])
    with pytest.raises(PermissionError, match="revoked"):
        ep.fetch(source_store, service, identity["credential"], {})


def test_http_observation_profile_blocks_export_approval_and_both_agent_fetch_aliases(
    source_store, config, monkeypatch
):
    monkeypatch.delenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", raising=False)
    service = Distribution(source_store, config)
    identity, *_ = enrolled(service)
    old = ep.save(source_store, actor(), request(identity, "http-old-active"))
    ep.approve(source_store, actor("admin_other"), old["id"])
    settings = source_store.settings
    source_store.close()
    app = create_app(settings, background=False)
    app.state.agent_distribution.config = config
    monkeypatch.setenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", "1")
    with TestClient(app, base_url="https://testserver") as client:
        login = client.post(
            "/api/login", json={"name": "admin_a", "password": PASSWORD}
        )
        assert login.status_code == 200
        csrf = {"x-csrf-token": login.json()["csrf"]}
        base = "/api/xdr/agents/defense-policies"
        created = client.post(
            base, json=request(identity, "http-observe-draft"), headers=csrf
        )
        assert created.status_code == 201
        assert {row["status"] for row in client.get(base).json()["policies"]} == {
            "active",
            "pending_approval",
        }
        exported = client.get(base + "/" + old["id"] + "/bundle")
        assert exported.status_code == 403 and "observation deployment" in exported.text
        reviewer = client.post(
            "/api/login", json={"name": "admin_other", "password": PASSWORD}
        )
        assert reviewer.status_code == 200
        csrf = {"x-csrf-token": reviewer.json()["csrf"]}
        for identifier in (old["id"], created.json()["id"]):
            approval = client.post(
                base + "/" + identifier + "/approve", json={}, headers=csrf
            )
            assert (
                approval.status_code == 403
                and "observation deployment" in approval.text
            )
        for path in ("/api/agent/defense-policy", "/api/endpoint-agent/defense-policy"):
            delivered = client.post(
                path,
                json={},
                headers={"authorization": "Bearer " + identity["credential"]},
            )
            assert delivered.status_code == 200
            assert delivered.json() == {
                "bundle": None,
                "blocked": True,
                "reason": ep.BLOCKED_REASON,
            }
            assert client.post(path, json={}).status_code == 401
        with app.state.store.control() as db:
            assert (
                db.execute("SELECT count(*) FROM endpoint_responses").fetchone()[0] == 0
            )
            assert (
                db.execute(
                    "SELECT count(*) FROM endpoint_defense_policies WHERE status='active'"
                ).fetchone()[0]
                == 1
            )
