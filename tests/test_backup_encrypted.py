import io
import json
import tarfile
import time

import pytest

from sapientia import auth, mfa
from sapientia.backup import _extract_archive, backup_encrypted, restore_encrypted
from sapientia.storage import Settings, Store

PASSWORD = "Encrypted-backup-account-password-2026"
PASSPHRASE = "Offline-archive-passphrase-2026"


@pytest.fixture
def archive(tmp_path):
    data, destination = tmp_path / "data", tmp_path / "backup.sapbak"
    store = Store(Settings(data, min_free_bytes=0))
    auth.create_user(store, "administrator", PASSWORD)
    session = auth.login(store, "administrator", PASSWORD)
    who = {"name": "administrator", "tenant": "default", "role": "admin"}
    secret = mfa.enroll(store, who, PASSWORD)["secret"]
    with store.control() as db:
        db.execute(
            "INSERT INTO oidc_states VALUES('state','browser','nonce','encrypted','https://idp.example','https://siem.example/callback',?,?)",
            (time.time(), time.time() + 300),
        )
        db.execute(
            "INSERT INTO oidc_mfa_challenges VALUES('challenge','browser','encrypted',?)",
            (time.time() + 180,),
        )
    (data / ".membership-enrollment.json").write_text(
        json.dumps({"enrollment_nonce": "private-retry-secret"}), encoding="utf-8"
    )
    store.ingest(
        "default", [{"event_id": "evidence", "message": "private backup evidence"}]
    )
    store.flush()
    store.close()
    result = backup_encrypted(data, destination, PASSPHRASE)
    assert result["encrypted"]
    return destination, session, secret


def test_encrypted_backup_round_trip_preserves_evidence_keys_and_revokes_sessions(
    archive, tmp_path
):
    source, session, secret = archive
    ciphertext = source.read_bytes()
    for sensitive in (
        PASSPHRASE,
        "private backup evidence",
        "private-retry-secret",
        "control.sqlite3",
        secret,
    ):
        assert sensitive.encode() not in ciphertext
    restored = tmp_path / "restored"
    assert restore_encrypted(source, restored, PASSPHRASE)["sessions_revoked"]
    store = Store(Settings(restored, min_free_bytes=0))
    try:
        assert auth.identity(store, session["token"]) is None
        assert store.search("default", {"query": "search *"})["returned"] == 1
        with store.control() as db:
            encrypted = db.execute("SELECT mfa_pending FROM users").fetchone()[0]
            assert db.execute("SELECT count(*) FROM oidc_states").fetchone()[0] == 0
            assert (
                db.execute("SELECT count(*) FROM oidc_mfa_challenges").fetchone()[0]
                == 0
            )
        assert mfa.decrypt(store, "administrator", encrypted) == secret
        assert "private-retry-secret" in (
            restored / ".membership-enrollment.json"
        ).read_text(encoding="utf-8")
    finally:
        store.close()


@pytest.mark.parametrize("tamper", ["password", "ciphertext", "tag", "header"])
def test_wrong_password_or_tampering_creates_no_restore(archive, tmp_path, tamper):
    source, _, _ = archive
    password = PASSPHRASE
    if tamper == "password":
        password = "Wrong-archive-passphrase-2026"
    else:
        data = bytearray(source.read_bytes())
        index = {"ciphertext": len(data) // 2, "tag": len(data) - 1, "header": 45}[
            tamper
        ]
        data[index] ^= 1
        source.write_bytes(data)
    target = tmp_path / "failed"
    with pytest.raises(ValueError):
        restore_encrypted(source, target, password)
    assert not target.exists()
    assert not list(tmp_path.glob(".encrypted-restore-*"))


def test_existing_restore_and_backup_destinations_are_never_overwritten(
    archive, tmp_path
):
    source, _, _ = archive
    destination = tmp_path / "existing"
    destination.mkdir()
    sentinel = destination / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    with pytest.raises(ValueError):
        restore_encrypted(source, destination, PASSPHRASE)
    with pytest.raises(ValueError):
        backup_encrypted(tmp_path / "data", source, PASSPHRASE)
    assert sentinel.read_text(encoding="utf-8") == "keep"


@pytest.mark.parametrize(
    "name,kind",
    [
        ("../escape", tarfile.REGTYPE),
        ("secrets.key", tarfile.SYMTYPE),
        ("secrets.key", tarfile.LNKTYPE),
        ("/absolute", tarfile.REGTYPE),
        ("unknown.json", tarfile.REGTYPE),
        ("manifest.json", tarfile.XHDTYPE),
    ],
)
def test_archive_extraction_rejects_traversal_links_and_extended_headers(
    tmp_path, name, kind
):
    archive = tmp_path / "crafted.tar"
    member = tarfile.TarInfo(name)
    member.type, member.size = kind, 1
    member.linkname = "../escape"
    with tarfile.open(archive, "w", format=tarfile.USTAR_FORMAT) as stream:
        stream.addfile(member, io.BytesIO(b"x"))
    with pytest.raises(ValueError):
        _extract_archive(archive, tmp_path / "extracted")
    assert not (tmp_path / "escape").exists()


def test_archive_size_limit_is_enforced_without_a_final_file(tmp_path, monkeypatch):
    import sapientia.backup as implementation

    data = tmp_path / "data"
    store = Store(Settings(data, min_free_bytes=0))
    store.close()
    monkeypatch.setattr(implementation, "MAX_ARCHIVE_BYTES", 512)
    with pytest.raises(ValueError, match="limit"):
        backup_encrypted(data, tmp_path / "refused.sapbak", PASSPHRASE)
    assert not (tmp_path / "refused.sapbak").exists()
    assert not list(data.glob(".encrypted-backup-*"))
