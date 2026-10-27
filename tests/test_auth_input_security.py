import pytest

from sapientia import auth, mfa
from sapientia.storage import Settings, Store


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    auth.create_user(value, "administrator", "Security-input-password-2026")
    yield value
    value.close()


@pytest.mark.parametrize("credential", ["한" * 43, "\ud800" * 43, "!" * 43, 123])
def test_malformed_bearer_and_cookie_fail_authentication(store, credential):
    assert auth.identity(store, bearer=credential) is None
    assert auth.identity(store, cookie=credential) is None


def test_surrogate_password_and_username_are_rejected(store):
    malformed = "\ud800" * 16
    assert auth.login(store, "administrator", malformed) is None
    with pytest.raises(ValueError, match="username"):
        auth.login(store, malformed, "Security-input-password-2026")
    with pytest.raises(ValueError, match="Unicode"):
        auth.create_user(store, "invalid", malformed)
    with pytest.raises(ValueError, match="Unicode"):
        auth.digest(malformed)


def test_valid_unicode_password_remains_supported(store):
    password = "유효한-암호-Password-2026"
    auth.create_user(store, "unicode", password)
    assert auth.login(store, "unicode", password)["name"] == "unicode"


@pytest.mark.parametrize("otp", ["１２３４５６", "한" * 6, "\ud800" * 6])
def test_non_ascii_totp_is_rejected_without_digest_error(otp):
    assert mfa.verify("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", otp, now=59) is None
