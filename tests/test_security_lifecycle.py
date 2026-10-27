import time

import pytest

from sapientia import auth, mfa
from sapientia.backup import backup, restore
from sapientia.storage import Settings, Store


@pytest.fixture
def store(tmp_path):
    s = Store(Settings(tmp_path, min_free_bytes=0))
    auth.create_user(s, "administrator", "Strong-password-123", first=True)
    yield s
    s.close()


WHO = {"name": "administrator", "role": "admin", "tenant": "default"}


def test_rfc6238_vector_and_replay():
    import base64

    secret = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
    assert mfa.code(secret, 1) == "287082"
    assert mfa.verify(secret, "287082", now=59) == 1
    assert mfa.verify(secret, "287082", last_counter=1, now=59) is None
    assert mfa.verify(secret, "000000", now=59) is None


def test_password_rotation_invalidates_all_sessions(store):
    first = auth.login(store, "administrator", "Strong-password-123")
    second = auth.login(store, "administrator", "Strong-password-123")
    with pytest.raises(ValueError):
        auth.change_password(store, WHO, "wrong", "Another-password-456")
    auth.change_password(store, WHO, "Strong-password-123", "Another-password-456")
    assert not auth.identity(store, first["token"])
    assert not auth.identity(store, second["token"])
    assert not auth.login(store, "administrator", "Strong-password-123")
    assert auth.login(store, "administrator", "Another-password-456")


def test_totp_enrollment_encryption_replay_and_disable(store, monkeypatch):
    session = auth.login(store, "administrator", "Strong-password-123")
    secret = mfa.enroll(store, WHO, "Strong-password-123")["secret"]
    counter = int(time.time() // 30)
    with store.control() as db:
        value = db.execute("SELECT mfa_pending FROM users").fetchone()[0]
        assert secret not in value and value != secret
    mfa.confirm(store, WHO, mfa.code(secret, counter))
    assert not auth.identity(store, session["token"])
    assert not auth.login(store, "administrator", "Strong-password-123")
    assert not auth.login(
        store, "administrator", "Strong-password-123", mfa.code(secret, counter)
    )
    assert auth.login(
        store, "administrator", "Strong-password-123", mfa.code(secret, counter + 1)
    )
    assert not auth.login(
        store, "administrator", "Strong-password-123", mfa.code(secret, counter + 1)
    )
    monkeypatch.setattr(mfa.time, "time", lambda: (counter + 2) * 30)
    mfa.disable(store, WHO, "Strong-password-123", mfa.code(secret, counter + 2))
    assert auth.login(store, "administrator", "Strong-password-123")


def test_mfa_secret_survives_verified_backup(tmp_path):
    data = tmp_path / "data"
    store = Store(Settings(data, min_free_bytes=0))
    auth.create_user(store, "administrator", "Strong-password-123", first=True)
    secret = mfa.enroll(store, WHO, "Strong-password-123")["secret"]
    store.close()
    manifest = backup(data, tmp_path / "snapshot")
    assert "secrets.key" in manifest["sha256"]
    restore(tmp_path / "snapshot", tmp_path / "restored")
    store = Store(Settings(tmp_path / "restored", min_free_bytes=0))
    try:
        with store.control() as db:
            encrypted = db.execute("SELECT mfa_pending FROM users").fetchone()[0]
        assert mfa.decrypt(store, "administrator", encrypted) == secret
    finally:
        store.close()


def test_expired_collector_and_disabled_identity(store):
    token = auth.issue_token(store, WHO, "expiring", 1)
    assert auth.identity(store, bearer=token)
    with store.control() as db:
        db.execute("UPDATE tokens SET expires=?", (time.time() - 1,))
    assert not auth.identity(store, bearer=token)
    login = auth.login(store, "administrator", "Strong-password-123")
    with store.control() as db:
        db.execute("UPDATE users SET disabled=1")
    assert not auth.identity(store, login["token"])
    assert not auth.login(store, "administrator", "Strong-password-123")
