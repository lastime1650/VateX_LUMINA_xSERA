"""Operational approval isolation, revision pins and in-flight revocation."""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sapientia import access, auth, response_rehearsal
from sapientia import ops_qualification as ops
from sapientia.storage import ConflictError, Settings, Store


def actor(name="owner", tenant="a", role="admin"):
    return {"name": name, "tenant": tenant, "role": role, "allowed_indexes": ["*"]}


@pytest.fixture
def store(tmp_path):
    result = Store(Settings(tmp_path / "store", min_free_bytes=0))
    for name, tenant, role in (
        ("owner", "a", "admin"),
        ("peer", "a", "admin"),
        ("editor", "a", "admin"),
        ("foreign", "b", "admin"),
        ("analyst", "a", "analyst"),
    ):
        auth.create_user(
            result, name, "Ops-qualification-test-password-2026", role, tenant
        )
    yield result
    result.close()


def plan(store):
    return ops.save(
        store,
        actor(),
        {
            "name": "Owned twin rehearsal",
            "indexes": ["lab"],
            "kind": "response_twin",
            "expected_revision": 0,
        },
    )


def approve(store, row):
    return ops.review(
        store,
        actor("peer"),
        row["id"],
        {
            "expected_revision": row["revision"],
            "approve": True,
            "reason": "Independent scope and safety review",
        },
    )


def test_only_independent_current_admin_can_approve_and_scope_isolated(store):
    row = plan(store)
    for user in (actor(), actor("foreign", "b"), actor("analyst", role="analyst")):
        with pytest.raises((PermissionError, KeyError)):
            ops.review(
                store,
                user,
                row["id"],
                {
                    "expected_revision": 1,
                    "approve": True,
                    "reason": "Cannot self approve",
                },
            )
    with pytest.raises(ConflictError):
        ops.run(store, actor(), row["id"], {"expected_revision": 1})
    approved = approve(store, row)
    assert approved["state"] == "approved"
    assert ops.plans(store, actor("foreign", "b"))["items"] == []


def test_edit_invalidates_approval_and_editor_cannot_review(store):
    row = approve(store, plan(store))
    edited = ops.save(
        store,
        actor("editor"),
        {
            "name": "Edited scope",
            "indexes": ["lab"],
            "kind": "response_twin",
            "expected_revision": 1,
        },
        row["id"],
    )
    assert (
        edited["revision"] == 2
        and edited["state"] == "pending"
        and edited["review"] is None
    )
    with pytest.raises(ConflictError):
        ops.run(store, actor(), row["id"], {"expected_revision": 1})
    with pytest.raises(PermissionError):
        ops.review(
            store,
            actor("editor"),
            row["id"],
            {
                "expected_revision": 2,
                "approve": True,
                "reason": "Cannot approve edited own plan",
            },
        )


def test_inflight_revocation_preserves_receipt_without_qualification(
    store, monkeypatch
):
    row = approve(store, plan(store))

    def revoke_during_probe():
        access.set_for_user(store, actor(), "peer", ["unrelated"])
        return {
            "passed": True,
            "native_host_effects": 0,
            "test_scope": "approval_boundary_only",
        }

    monkeypatch.setattr(response_rehearsal, "run", revoke_during_probe)
    receipt = ops.run(store, actor(), row["id"], {"expected_revision": 1})
    assert receipt["state"] == "authority_changed" and receipt["result_digest"]
    assert ops.get_run(store, actor(), receipt["id"]) == receipt
    with pytest.raises(KeyError):
        ops.get_run(store, actor("foreign", "b"), receipt["id"])


def test_current_reviewer_acl_loss_prevents_execution(store, monkeypatch):
    row = approve(store, plan(store))
    access.set_for_user(store, actor(), "peer", ["unrelated"])
    monkeypatch.setattr(
        response_rehearsal, "run", lambda: pytest.fail("Unauthorized probe executed")
    )
    with pytest.raises(PermissionError):
        ops.run(store, actor(), row["id"], {"expected_revision": 1})
    assert ops.runs(store, actor())["items"] == []


def test_external_signer_bootstrap_export_requires_pinned_independent_approval(
    store, tmp_path, monkeypatch
):
    path = tmp_path / "external-private.pem"

    def keyfile():
        path.write_bytes(
            Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

    keyfile()
    monkeypatch.setenv("SAPIENTIA_AGENT_SIGNING_KEY_FILE", str(path))
    row = ops.save(
        store,
        actor(),
        {
            "name": "Reviewed external signer bootstrap",
            "indexes": ["lab"],
            "kind": "integrity_bootstrap",
            "expected_revision": 0,
        },
    )
    assert row["definition"]["signer_key_id"]
    with pytest.raises(ConflictError):
        ops.run(store, actor(), row["id"], {"expected_revision": 1})
    approve(store, row)
    run = ops.run(store, actor(), row["id"], {"expected_revision": 1})
    exported = run["result"]["trust_file"]
    assert run["state"] == "completed" and set(exported["keys"]) == {
        row["definition"]["signer_key_id"]
    }
    assert exported["approval"]["requester"] != exported["approval"]["reviewer"]
    assert str(path) not in str(run) and "PRIVATE KEY" not in str(run)
    keyfile()
    with pytest.raises(ConflictError):
        ops.run(store, actor(), row["id"], {"expected_revision": 1})
