import hashlib
import json
import sqlite3

import pytest

from sapientia import access, audit_integrity, auth
from sapientia.backup import backup, restore, sha256
from sapientia.storage import Settings, Store, encode

PASSWORD = "Focused-test-password-2026"
ADMIN = {"name": "administrator", "tenant": "default", "role": "admin"}


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path / "data", min_free_bytes=0))
    access.initialize(value)
    auth.create_user(value, ADMIN["name"], PASSWORD)
    auth.create_user(value, "viewer", PASSWORD, "viewer")
    yield value
    value.close()


def test_default_grant_and_explicit_deny_revoke_sessions(store):
    first = auth.login(store, "viewer", PASSWORD)
    assert auth.identity(store, first["token"])["allowed_indexes"] == ["*"]
    changed = access.set_for_user(store, ADMIN, "viewer", [])
    assert changed["sessions_revoked"]
    assert auth.identity(store, first["token"]) is None
    second = auth.login(store, "viewer", PASSWORD)
    assert auth.identity(store, second["token"])["allowed_indexes"] == []
    assert access.get_for_user(store, "viewer", "default") == []
    with store.control() as db:
        row = db.execute(
            "SELECT detail FROM audit WHERE action='user.index_access'"
        ).fetchone()
    assert json.loads(row[0])["allowed_indexes"] == []


def test_grants_are_exact_and_current_user_status_is_respected(store):
    access.set_for_user(store, ADMIN, "viewer", ["security", "main"])
    logged = auth.login(store, "viewer", PASSWORD)
    assert auth.identity(store, logged["token"])["allowed_indexes"] == [
        "main",
        "security",
    ]
    with store.control() as db:
        db.execute("UPDATE users SET disabled=1 WHERE name='viewer'")
    assert access.get_for_user(store, "viewer", "default") == []
    assert auth.identity(store, logged["token"]) is None
    assert access.get_for_user(store, "missing", "default") == []


@pytest.mark.parametrize(
    "indexes",
    [["main", "*"], ["sec*"], ["x.y"], ["main", "main"], "*", [None], ["x"] * 257],
)
def test_invalid_grants_are_rejected(indexes):
    with pytest.raises(ValueError):
        access.validate(indexes)


def test_grants_cannot_cross_tenants_or_trust_a_stale_admin_role(store):
    auth.create_user(store, "other", PASSWORD, "viewer", "other")
    with pytest.raises(KeyError):
        access.set_for_user(store, ADMIN, "other", [])
    assert access.get_for_user(store, "other", "other") == ["*"]
    with pytest.raises(PermissionError):
        access.set_for_user(store, {**ADMIN, "role": "viewer"}, "viewer", [])
    with store.control() as db:
        db.execute("UPDATE users SET role='viewer' WHERE name=?", (ADMIN["name"],))
    with pytest.raises(PermissionError):
        access.set_for_user(store, ADMIN, "viewer", [])


def test_checkpoint_verifies_append_and_detects_tail_truncation(store, tmp_path):
    path = tmp_path / "external" / "audit.json"
    checkpoint = audit_integrity.write_checkpoint(store, path)
    with store.write_lock, store.control() as db:
        store.audit(db, "default", ADMIN["name"], "later", {})
    assert audit_integrity.verify(store, path)["valid"]
    with store.control() as db:
        db.execute("DELETE FROM audit WHERE seq>=?", (checkpoint["sequence"],))
    result = audit_integrity.verify(store, checkpoint)
    assert not result["valid"]
    assert any("checkpoint" in error["reason"] for error in result["errors"])


@pytest.mark.parametrize(
    "mutation",
    [
        "UPDATE audit SET detail='tampered' WHERE seq=1",
        "UPDATE audit SET previous='wrong' WHERE seq=2",
        "UPDATE audit SET digest='not-a-digest' WHERE seq=1",
        "UPDATE audit SET digest='한글' WHERE seq=1",
        "DELETE FROM audit WHERE seq=1",
    ],
)
def test_local_audit_corruption_is_reported(store, mutation):
    with store.control() as db:
        db.execute(mutation)
    result = audit_integrity.verify(store)
    assert not result["valid"]
    with pytest.raises(ValueError):
        audit_integrity.create_checkpoint(store)


def test_external_checkpoint_detects_recomputed_chain(store, tmp_path):
    checkpoint = audit_integrity.write_checkpoint(store, tmp_path / "anchor.json")
    with store.control() as db:
        db.execute("UPDATE audit SET action='replacement' WHERE seq=1")
        previous = "0" * 64
        for row in db.execute("SELECT * FROM audit ORDER BY seq").fetchall():
            digest = hashlib.sha256(
                encode(
                    [
                        row["at"],
                        row["tenant"],
                        row["actor"],
                        row["action"],
                        row["detail"],
                        previous,
                    ]
                ).encode()
            ).hexdigest()
            db.execute(
                "UPDATE audit SET previous=?,digest=? WHERE seq=?",
                (previous, digest, row["seq"]),
            )
            previous = digest
    assert audit_integrity.verify(store)["valid"]
    assert not audit_integrity.verify(store, checkpoint)["valid"]


def test_checkpoint_must_be_outside_data_directory(store):
    with pytest.raises(ValueError, match="outside"):
        audit_integrity.write_checkpoint(store, store.path / "checkpoint.json")


def test_backup_preserves_audit_checkpoint_and_restore_verifies_it(tmp_path):
    data, snapshot, restored = (
        tmp_path / name for name in ("data", "snapshot", "restored")
    )
    store = Store(Settings(data, min_free_bytes=0))
    auth.create_user(store, "administrator", PASSWORD)
    expected = audit_integrity.create_checkpoint(store)
    store.close()
    manifest = backup(data, snapshot)
    assert manifest["audit_checkpoint"]["digest"] == expected["digest"]
    restore(snapshot, restored)
    store = Store(Settings(restored, min_free_bytes=0))
    try:
        assert audit_integrity.verify(store, expected)["valid"]
    finally:
        store.close()
    with sqlite3.connect(snapshot / "control.sqlite3") as db:
        db.execute("DELETE FROM audit")
    manifest["sha256"]["control.sqlite3"] = sha256(snapshot / "control.sqlite3")
    (snapshot / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="audit"):
        restore(snapshot, tmp_path / "refused")
    assert not (tmp_path / "refused").exists()
