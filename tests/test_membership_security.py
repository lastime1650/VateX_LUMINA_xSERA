import json
import secrets
import uuid

import pytest

from sapientia import __version__, auth
from sapientia.membership import PRODUCT, PROTOCOL, Membership
from sapientia.storage import ConflictError, Settings, Store

PASSWORD = "Membership-focused-test-secret-2026"
WHO = {"name": "administrator", "tenant": "default", "role": "admin"}


@pytest.fixture
def fleet(tmp_path):
    stores = [Store(Settings(tmp_path / str(i), min_free_bytes=0)) for i in range(2)]
    nodes = []

    def transport(address, path, data=None, pin=None):
        return (
            nodes[0].accept(data)
            if path.endswith("join")
            else nodes[0].peer_status(data)
        )

    nodes.extend(Membership(store, transport) for store in stores)
    auth.create_user(stores[0], WHO["name"], PASSWORD)
    nodes[0].create(
        WHO,
        {"name": "fleet", "address": "https://master.example", "password": PASSWORD},
    )
    yield nodes
    for store in stores:
        store.close()


def request(nonce=None):
    result = {
        "product": PRODUCT,
        "version": __version__,
        "protocol": PROTOCOL,
        "node_id": str(uuid.uuid4()),
        "address": "https://slave.example",
        "certificate_pin": None,
        "password": PASSWORD,
    }
    if nonce:
        result["enrollment_nonce"] = nonce
    return result


def status_request(payload, response):
    return {
        "group_id": response["group_id"],
        "node_id": payload["node_id"],
        "credential": response["credential"],
    }


def test_shared_password_cannot_replace_or_retrieve_existing_credential(fleet):
    payload = request()
    first = fleet[0].accept(payload)
    duplicate = fleet[0].accept(payload)
    assert duplicate["ordinal"] == first["ordinal"]
    assert "credential" not in duplicate
    assert duplicate["recovery_required"]
    assert (
        fleet[0].peer_status(status_request(payload, first))["ordinal"]
        == first["ordinal"]
    )
    with pytest.raises(ConflictError):
        fleet[0].accept({**payload, "enrollment_nonce": secrets.token_urlsafe(48)})


@pytest.mark.parametrize("credential", ["한" * 64, "\ud800" * 64, "!" * 64])
def test_malformed_peer_credentials_are_rejected_before_hashing(fleet, credential):
    payload = request()
    first = fleet[0].accept(payload)
    with pytest.raises(ValueError, match="장비 인증"):
        fleet[0].peer_status(
            {**status_request(payload, first), "credential": credential}
        )
    assert fleet[0].peer_status(status_request(payload, first))["ordinal"] == 1


def test_private_nonce_retry_is_idempotent_and_not_stored_in_plaintext(fleet):
    nonce = secrets.token_urlsafe(48)
    payload = request(nonce)
    first = fleet[0].accept(payload)
    retry = fleet[0].accept(payload)
    assert first["credential"] == retry["credential"]
    with fleet[0].store.control() as db:
        row = db.execute(
            "SELECT * FROM appliance_members WHERE node_id=?", (payload["node_id"],)
        ).fetchone()
    serialized = json.dumps(dict(row))
    assert nonce not in serialized and first["credential"] not in serialized
    fleet[0].peer_status(status_request(payload, first))
    # Once the member proves that it persisted the key, retire the retry secret.
    with pytest.raises(ConflictError):
        fleet[0].accept(payload)
    proven = fleet[0].accept({**payload, "credential": first["credential"]})
    assert proven["credential"] == first["credential"]


def test_slave_crash_after_remote_commit_reuses_private_nonce(fleet, monkeypatch):
    from sapientia import membership

    node = fleet[1]
    real_write = membership.atomic_json

    def fail_membership_persist(path, value):
        if path == node.file:
            raise OSError("simulated local membership persistence failure")
        return real_write(path, value)

    data = {
        "peer": "https://master.example",
        "address": "https://slave.example",
        "password": PASSWORD,
    }
    monkeypatch.setattr(membership, "atomic_json", fail_membership_persist)
    with pytest.raises(OSError):
        node.join(WHO, data)
    assert node.enrollment_file.exists()
    pending = node.enrollment_file.read_text(encoding="utf-8")
    assert PASSWORD not in pending
    with fleet[0].store.control() as db:
        digest = db.execute(
            "SELECT credential FROM appliance_members WHERE node_id=?",
            (node.node["node_id"],),
        ).fetchone()[0]
    monkeypatch.setattr(membership, "atomic_json", real_write)
    result = node.join(WHO, data)
    assert result["ordinal"] == 1 and not node.enrollment_file.exists()
    with fleet[0].store.control() as db:
        assert (
            db.execute(
                "SELECT credential FROM appliance_members WHERE node_id=?",
                (node.node["node_id"],),
            ).fetchone()[0]
            == digest
        )
    assert node.refresh()["ordinal"] == 1


def test_recovery_is_explicit_admin_action_and_preserves_rank(fleet):
    payload = request(secrets.token_urlsafe(48))
    first = fleet[0].accept(payload)
    for actor in ({**WHO, "role": "viewer"}, {**WHO, "tenant": "other"}):
        with pytest.raises(PermissionError):
            fleet[0].recover_member(actor, payload["node_id"])
    fleet[0].recover_member(WHO, payload["node_id"])
    with pytest.raises(ValueError):
        fleet[0].peer_status(status_request(payload, first))
    recovered = fleet[0].accept(
        {**payload, "enrollment_nonce": secrets.token_urlsafe(48)}
    )
    assert recovered["ordinal"] == first["ordinal"]
    assert recovered["credential"] != first["credential"]
