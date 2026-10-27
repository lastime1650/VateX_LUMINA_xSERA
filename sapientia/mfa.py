"""RFC 6238 TOTP with encrypted secrets and one-time counter enforcement."""

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from urllib.parse import quote, urlencode

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def key(store):
    if store.replica:
        # Preserve the derivation domain across product renaming.
        return hashlib.sha256(b"SAPIENTIA-MFA-1\x00" + store.replica.key).digest()
    path = store.path / "secrets.key"
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, "wb") as stream:
            stream.write(secrets.token_bytes(32))
            stream.flush()
            os.fsync(stream.fileno())
    value = path.read_bytes()
    if len(value) != 32:
        raise RuntimeError("MFA encryption key is corrupt")
    return value


def encrypt(store, name, secret):
    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(key(store)).encrypt(nonce, secret.encode(), name.encode())
    return base64.b64encode(nonce + encrypted).decode()


def decrypt(store, name, value):
    data = base64.b64decode(value, validate=True)
    return AESGCM(key(store)).decrypt(data[:12], data[12:], name.encode()).decode()


def code(secret, counter):
    raw = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8))
    digest = hmac.new(raw, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    number = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{number % 1000000:06d}"


def verify(secret, value, last_counter=-1, now=None):
    if (
        not isinstance(value, str)
        or len(value) != 6
        or not value.isascii()
        or not value.isdigit()
    ):
        return None
    counter = int((time.time() if now is None else now) // 30)
    for candidate in (counter, counter - 1, counter + 1):
        if (
            candidate > last_counter
            and candidate >= 0
            and hmac.compare_digest(code(secret, candidate), value)
        ):
            return candidate
    return None


def enroll(store, who, password):
    from .auth import check_password

    with store.write_lock, store.control() as db:
        user = db.execute(
            "SELECT * FROM users WHERE name=? AND tenant=?",
            (who["name"], who["tenant"]),
        ).fetchone()
        if not user or not check_password(user["password"], password):
            raise ValueError("Current password verification failed")
        if user["mfa_secret"]:
            raise ValueError(
                "MFA is already enabled; disable it with current credentials before replacing it"
            )
        secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
        encrypted = encrypt(store, who["name"], secret)
        db.execute(
            "UPDATE users SET mfa_pending=?,mfa_pending_until=? WHERE name=?",
            (encrypted, time.time() + 600, who["name"]),
        )
        store.audit(db, who["tenant"], who["name"], "mfa.enroll.start", {})
    uri = (
        "otpauth://totp/"
        + quote("Vatex xSERA XDR:" + who["name"], safe="")
        + "?"
        + urlencode(
            {
                "secret": secret,
                "issuer": "Vatex xSERA XDR",
                "algorithm": "SHA1",
                "digits": 6,
                "period": 30,
            }
        )
    )
    return {"secret": secret, "uri": uri, "expires_in": 600}


def confirm(store, who, value):
    with store.write_lock, store.control() as db:
        user = db.execute(
            "SELECT * FROM users WHERE name=? AND tenant=?",
            (who["name"], who["tenant"]),
        ).fetchone()
        if (
            not user
            or not user["mfa_pending"]
            or user["mfa_pending_until"] < time.time()
        ):
            raise ValueError("MFA enrollment expired")
        counter = verify(decrypt(store, who["name"], user["mfa_pending"]), value)
        if counter is None:
            raise ValueError("Invalid authenticator code")
        db.execute(
            "UPDATE users SET mfa_secret=mfa_pending,mfa_pending=NULL,mfa_pending_until=NULL,mfa_counter=? WHERE name=?",
            (counter, who["name"]),
        )
        # Re-authenticate every session with the newly enabled second factor.
        db.execute("DELETE FROM sessions WHERE name=?", (who["name"],))
        store.audit(db, who["tenant"], who["name"], "mfa.enabled", {})
    return {"enabled": True, "sessions_revoked": True}


def disable(store, who, password, value):
    from .auth import check_password

    with store.write_lock, store.control() as db:
        user = db.execute(
            "SELECT * FROM users WHERE name=? AND tenant=?",
            (who["name"], who["tenant"]),
        ).fetchone()
        if (
            not user
            or not check_password(user["password"], password)
            or not user["mfa_secret"]
        ):
            raise ValueError("Current credentials verification failed")
        counter = verify(
            decrypt(store, who["name"], user["mfa_secret"]), value, user["mfa_counter"]
        )
        if counter is None:
            raise ValueError("Current authenticator code is invalid or already used")
        db.execute(
            "UPDATE users SET mfa_secret=NULL,mfa_counter=-1,mfa_pending=NULL,mfa_pending_until=NULL WHERE name=?",
            (who["name"],),
        )
        db.execute("DELETE FROM sessions WHERE name=?", (who["name"],))
        store.audit(db, who["tenant"], who["name"], "mfa.disabled", {})
    return {"enabled": False, "sessions_revoked": True}
