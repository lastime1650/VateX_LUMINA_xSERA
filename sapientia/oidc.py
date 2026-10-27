"""Optional OIDC Authorization Code + S256 PKCE adapter.

Configuration is operator-owned and disabled unless explicitly supplied. Only
configured subjects can sign into existing local accounts. No discovery URL,
JWT, role or username supplied by a browser is trusted as configuration.
"""

import base64
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from . import auth, mfa
from .storage import CapacityError


def initialize(store):
    with store.control(local=True) as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS oidc_states(digest TEXT PRIMARY KEY,browser_digest TEXT NOT NULL,nonce_digest TEXT NOT NULL,verifier TEXT NOT NULL,issuer TEXT NOT NULL,redirect_uri TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL)"
        )
        db.execute(
            "CREATE TABLE IF NOT EXISTS oidc_mfa_challenges(digest TEXT PRIMARY KEY,browser_digest TEXT NOT NULL,payload TEXT NOT NULL,expires REAL NOT NULL)"
        )


def load_config(path=None):
    path = path or os.environ.get("SAPIENTIA_OIDC_CONFIG")
    return json.loads(Path(path).read_text(encoding="utf-8")) if path else None


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def unb64(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("Invalid OIDC base64url value")
    try:
        return base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, TypeError):
        raise ValueError("Invalid OIDC base64url value") from None


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate OIDC JSON key")
        value[key] = item
    return value


def secure_url(value, allow_loopback=False, issuer=False):
    if (
        not isinstance(value, str)
        or len(value) > 2048
        or any(ord(c) <= 32 for c in value)
    ):
        raise ValueError("Invalid OIDC URL")
    parsed = urllib.parse.urlsplit(value)
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("Invalid OIDC URL") from None
    loopback = parsed.hostname == "localhost"
    try:
        loopback = loopback or ipaddress.ip_address(parsed.hostname or "").is_loopback
    except ValueError:
        pass
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
        or (issuer and parsed.query)
        or (
            parsed.scheme != "https"
            and not (allow_loopback and loopback and parsed.scheme == "http")
        )
    ):
        raise ValueError(
            "OIDC endpoints require verified HTTPS; HTTP is loopback-test only"
        )
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def request_json(url, data=None, headers=None):
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    opener = urllib.request.build_opener(
        NoRedirect(),
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
    )
    request = urllib.request.Request(
        url, data=data, headers=headers or {"Accept": "application/json"}
    )
    try:
        with opener.open(request, timeout=8) as response:
            raw = response.read(256 * 1024 + 1)
            if len(raw) > 256 * 1024:
                raise ValueError("OIDC provider response exceeds size limit")
            content_type = response.headers.get_content_type()
            if content_type not in {"application/json", "application/jwk-set+json"}:
                raise ValueError("OIDC provider must return JSON")
            result = json.loads(raw, object_pairs_hook=unique_object)
            if not isinstance(result, dict):
                raise ValueError("Invalid OIDC provider response")  # noqa: TRY004 - API validation uses ValueError.
            return result
    except (urllib.error.URLError, TimeoutError, OSError):
        # Provider errors may echo authorization codes or client credentials.
        raise CapacityError("OIDC provider request failed") from None


class OIDCProvider:
    def __init__(self, store, config, transport=request_json):
        if not isinstance(config, dict) or set(config) - {
            "issuer",
            "client_id",
            "client_secret_env",
            "redirect_uri",
            "subjects",
            "algorithms",
            "allow_loopback_http",
        }:
            raise ValueError("Invalid OIDC configuration")
        self.allow_loopback = config.get("allow_loopback_http", False)
        if type(self.allow_loopback) is not bool:
            raise ValueError("Invalid OIDC loopback-test option")
        self.issuer = secure_url(config.get("issuer"), self.allow_loopback, issuer=True)
        self.redirect_uri = secure_url(config.get("redirect_uri"), self.allow_loopback)
        if urllib.parse.urlsplit(self.redirect_uri).query:
            raise ValueError("OIDC redirect URI must not contain a query")
        self.client_id = config.get("client_id")
        self.subjects = config.get("subjects")
        self.algorithms = config.get("algorithms", ["RS256"])
        if (
            not isinstance(self.client_id, str)
            or not 1 <= len(self.client_id) <= 256
            or not isinstance(self.subjects, dict)
            or not self.subjects
            or len(self.subjects) > 10000
            or any(
                not isinstance(s, str)
                or not 1 <= len(s) <= 255
                or not isinstance(n, str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", n)
                for s, n in self.subjects.items()
            )
            or not isinstance(self.algorithms, list)
            or not self.algorithms
            or any(a not in {"RS256", "ES256"} for a in self.algorithms)
        ):
            raise ValueError(
                "Invalid OIDC client, subject mapping or signing algorithms"
            )
        secret_env = config.get("client_secret_env")
        if secret_env is not None and (
            not isinstance(secret_env, str)
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", secret_env)
        ):
            raise ValueError("Invalid OIDC client secret environment name")
        self.client_secret = os.environ.get(secret_env) if secret_env else None
        if secret_env and not self.client_secret:
            raise ValueError("Configured OIDC client secret is unavailable")
        self.store, self.transport = store, transport
        self.metadata, self.metadata_until = None, 0
        self.lock = threading.Lock()
        initialize(store)

    def discovery(self):
        with self.lock:
            if self.metadata and time.time() < self.metadata_until:
                return self.metadata
            value = self.transport(
                self.issuer.rstrip("/") + "/.well-known/openid-configuration"
            )
            if (
                value.get("issuer") != self.issuer
                or "code" not in value.get("response_types_supported", [])
                or "S256" not in value.get("code_challenge_methods_supported", [])
                or not set(self.algorithms)
                & set(value.get("id_token_signing_alg_values_supported", []))
            ):
                raise ValueError(
                    "OIDC discovery issuer, code flow, PKCE or signing algorithm mismatch"
                )
            method = "client_secret_basic" if self.client_secret else "none"
            if method not in value.get(
                "token_endpoint_auth_methods_supported", ["client_secret_basic"]
            ):
                raise ValueError(
                    "OIDC provider does not support configured client authentication"
                )
            for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                secure_url(value.get(name), self.allow_loopback)
            self.metadata, self.metadata_until = value, time.time() + 300
            return value

    def start(self):
        metadata = self.discovery()
        state, binding, nonce = (secrets.token_urlsafe(32) for _ in range(3))
        verifier = secrets.token_urlsafe(48)
        now = time.time()
        with self.store.write_lock, self.store.control() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM oidc_states WHERE expires<=?", (now,))
            if db.execute("SELECT count(*) FROM oidc_states").fetchone()[0] >= 1000:
                raise CapacityError("OIDC login queue is full")
            db.execute(
                "INSERT INTO oidc_states VALUES(?,?,?,?,?,?,?,?)",
                (
                    auth.digest(state),
                    auth.digest(binding),
                    auth.digest(nonce),
                    mfa.encrypt(self.store, "oidc:" + auth.digest(state), verifier),
                    self.issuer,
                    self.redirect_uri,
                    now,
                    now + 300,
                ),
            )
        parameters = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": "openid",
            "state": state,
            "nonce": nonce,
            "code_challenge": b64(hashlib.sha256(verifier.encode()).digest()),
            "code_challenge_method": "S256",
        }
        url = metadata["authorization_endpoint"]
        return {
            "authorization_url": url
            + ("&" if "?" in url else "?")
            + urllib.parse.urlencode(parameters),
            "browser_token": binding,
            "expires_in": 300,
        }

    def callback(self, state, code, browser_token, otp=None):
        if any(
            not isinstance(v, str) or not 1 <= len(v) <= bound or not v.isascii()
            for v, bound in ((state, 128), (code, 4096), (browser_token, 128))
        ):
            raise ValueError("Invalid OIDC callback")
        with self.store.write_lock, self.store.control() as db:
            db.execute("BEGIN IMMEDIATE")
            pending = db.execute(
                "SELECT * FROM oidc_states WHERE digest=?", (auth.digest(state),)
            ).fetchone()
            if (
                not pending
                or pending["expires"] <= time.time()
                or pending["issuer"] != self.issuer
                or pending["redirect_uri"] != self.redirect_uri
                or not hmac.compare_digest(
                    pending["browser_digest"], auth.digest(browser_token)
                )
            ):
                raise ValueError(
                    "OIDC login state is invalid, expired or belongs to another browser"
                )
            # Consume before network exchange; every callback succeeds at most once.
            db.execute("DELETE FROM oidc_states WHERE digest=?", (auth.digest(state),))
        metadata = self.discovery()
        verifier = mfa.decrypt(
            self.store, "oidc:" + auth.digest(state), pending["verifier"]
        )
        fields = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "code_verifier": verifier,
            "client_id": self.client_id,
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        if self.client_secret:
            credential = (
                urllib.parse.quote_plus(self.client_id)
                + ":"
                + urllib.parse.quote_plus(self.client_secret)
            )
            headers["Authorization"] = (
                "Basic " + base64.b64encode(credential.encode()).decode()
            )
        response = self.transport(
            metadata["token_endpoint"], urllib.parse.urlencode(fields).encode(), headers
        )
        claims = self.validate_token(
            response.get("id_token"), pending, code, response.get("access_token")
        )
        name = self.subjects.get(claims["sub"])
        if not name:
            raise PermissionError(
                "OIDC subject has no configured local account mapping"
            )
        with self.store.control() as db:
            user = db.execute(
                "SELECT role,disabled,mfa_secret FROM users WHERE name=?", (name,)
            ).fetchone()
        if (
            not user
            or user["disabled"]
            or user["role"] not in {"admin", "analyst", "viewer"}
        ):
            raise PermissionError("Mapped local account is unavailable")
        if user["mfa_secret"] and otp is None:
            challenge = secrets.token_urlsafe(32)
            encrypted = mfa.encrypt(
                self.store,
                "oidc-mfa:" + auth.digest(challenge),
                json.dumps(
                    {
                        "name": name,
                        "sub": claims["sub"],
                        "issuer": self.issuer,
                        "mfa_digest": auth.digest(user["mfa_secret"]),
                    },
                    separators=(",", ":"),
                ),
            )
            with self.store.write_lock, self.store.control() as db:
                db.execute(
                    "DELETE FROM oidc_mfa_challenges WHERE expires<=?", (time.time(),)
                )
                if (
                    db.execute("SELECT count(*) FROM oidc_mfa_challenges").fetchone()[0]
                    >= 1000
                ):
                    raise CapacityError("OIDC authenticator queue is full")
                db.execute(
                    "INSERT INTO oidc_mfa_challenges VALUES(?,?,?,?)",
                    (
                        auth.digest(challenge),
                        auth.digest(browser_token),
                        encrypted,
                        time.time() + 180,
                    ),
                )
            return {"mfa_required": True, "challenge": challenge, "expires_in": 180}
        return auth.verified_session(
            self.store,
            name,
            otp,
            {"issuer": self.issuer, "subject_digest": auth.digest(claims["sub"])},
        )

    def complete_mfa(self, challenge, browser_token, otp):
        """One attempt per challenge; a failed OTP requires restarting sign-in."""
        if any(
            not isinstance(v, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", v)
            for v in (challenge, browser_token)
        ):
            raise ValueError("Invalid OIDC authenticator challenge")
        with self.store.write_lock, self.store.control() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM oidc_mfa_challenges WHERE digest=?",
                (auth.digest(challenge),),
            ).fetchone()
            if (
                not row
                or row["expires"] <= time.time()
                or not hmac.compare_digest(
                    row["browser_digest"], auth.digest(browser_token)
                )
            ):
                raise ValueError(
                    "OIDC authenticator challenge is invalid, expired or belongs to another browser"
                )
            db.execute(
                "DELETE FROM oidc_mfa_challenges WHERE digest=?",
                (auth.digest(challenge),),
            )
        payload = json.loads(
            mfa.decrypt(
                self.store, "oidc-mfa:" + auth.digest(challenge), row["payload"]
            )
        )
        with self.store.control() as db:
            user = db.execute(
                "SELECT mfa_secret FROM users WHERE name=?", (payload["name"],)
            ).fetchone()
        if (
            payload.get("issuer") != self.issuer
            or self.subjects.get(payload.get("sub")) != payload.get("name")
            or not user
            or not user["mfa_secret"]
            or not hmac.compare_digest(
                auth.digest(user["mfa_secret"]), payload["mfa_digest"]
            )
        ):
            raise PermissionError(
                "Local account or authenticator changed; restart OIDC login"
            )
        return auth.verified_session(
            self.store,
            payload["name"],
            otp,
            {"issuer": self.issuer, "subject_digest": auth.digest(payload["sub"])},
        )

    def validate_token(self, token, pending, code, access_token):
        if (
            not isinstance(token, str)
            or len(token) > 16384
            or len(token.split(".")) != 3
        ):
            raise ValueError("Invalid OIDC ID token")
        parts = token.split(".")
        try:
            header, claims = (
                json.loads(unb64(part), object_pairs_hook=unique_object)
                for part in parts[:2]
            )
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise ValueError("Invalid OIDC ID token JSON") from None
        if (
            not isinstance(header, dict)
            or set(header) - {"alg", "kid", "typ"}
            or header.get("alg") not in self.algorithms
            or header.get("typ", "JWT") != "JWT"
            or not isinstance(header.get("kid"), str)
            or not 1 <= len(header["kid"]) <= 128
            or not isinstance(claims, dict)
        ):
            raise ValueError("Unsupported OIDC ID token header")
        keys = self.transport(self.discovery()["jwks_uri"]).get("keys")
        if not isinstance(keys, list) or not 1 <= len(keys) <= 100:
            raise ValueError("Invalid OIDC signing key set")
        matches = [
            key
            for key in keys
            if isinstance(key, dict) and key.get("kid") == header["kid"]
        ]
        if len(matches) != 1:
            raise ValueError("OIDC signing key is missing or ambiguous")
        key = matches[0]
        if (
            key.get("use", "sig") != "sig"
            or key.get("alg", header["alg"]) != header["alg"]
            or ("key_ops" in key and key["key_ops"] != ["verify"])
        ):
            raise ValueError("OIDC key is not authorized for this signature")
        signature, signed = unb64(parts[2]), (parts[0] + "." + parts[1]).encode()
        try:
            if header["alg"] == "RS256" and key.get("kty") == "RSA":
                n, e = (int.from_bytes(unb64(key.get(k)), "big") for k in ("n", "e"))
                if (
                    not 2048 <= n.bit_length() <= 8192
                    or not 3 <= e <= 2**32
                    or e % 2 == 0
                ):
                    raise ValueError("Invalid RSA signing key")
                rsa.RSAPublicNumbers(e, n).public_key().verify(
                    signature, signed, padding.PKCS1v15(), hashes.SHA256()
                )
            elif (
                header["alg"] == "ES256"
                and key.get("kty") == "EC"
                and key.get("crv") == "P-256"
            ):
                x, y = (unb64(key.get(k)) for k in ("x", "y"))
                if len(x) != 32 or len(y) != 32 or len(signature) != 64:
                    raise ValueError("Invalid EC signing key or signature")
                public = ec.EllipticCurvePublicNumbers(
                    int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
                ).public_key()
                public.verify(
                    encode_dss_signature(
                        int.from_bytes(signature[:32], "big"),
                        int.from_bytes(signature[32:], "big"),
                    ),
                    signed,
                    ec.ECDSA(hashes.SHA256()),
                )
            else:
                raise ValueError("OIDC signing algorithm and key type mismatch")
        except (InvalidSignature, ValueError):
            raise ValueError("OIDC ID token signature verification failed") from None
        now = time.time()
        audience = claims.get("aud")
        audiences = [audience] if isinstance(audience, str) else audience
        if (
            claims.get("iss") != self.issuer
            or not isinstance(claims.get("sub"), str)
            or not 1 <= len(claims["sub"]) <= 255
            or not isinstance(audiences, list)
            or not audiences
            or any(not isinstance(a, str) for a in audiences)
            or len(set(audiences)) != len(audiences)
            or self.client_id not in audiences
            or (len(audiences) > 1 and claims.get("azp") != self.client_id)
            or ("azp" in claims and claims["azp"] != self.client_id)
            or not isinstance(claims.get("nonce"), str)
            or not claims["nonce"].isascii()
            or not hmac.compare_digest(
                auth.digest(claims["nonce"]), pending["nonce_digest"]
            )
        ):
            raise ValueError(
                "OIDC issuer, audience, subject or nonce validation failed"
            )
        for field in ("exp", "iat"):
            value = claims.get(field)
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not -1e12 <= value <= 1e12
                or not math.isfinite(value)
            ):
                raise ValueError("Invalid OIDC token timestamps")
        if (
            claims["exp"] <= now
            or claims["iat"] > now + 60
            or claims["iat"] < pending["created"] - 60
            or claims["exp"] <= claims["iat"]
        ):
            raise ValueError(
                "OIDC token is expired or was issued outside this login transaction"
            )
        if "nbf" in claims and (
            isinstance(claims["nbf"], bool)
            or not isinstance(claims["nbf"], (int, float))
            or not -1e12 <= claims["nbf"] <= 1e12
            or not math.isfinite(claims["nbf"])
            or claims["nbf"] > now + 60
        ):
            raise ValueError("OIDC token is not yet valid")
        for claim, value in (("c_hash", code), ("at_hash", access_token)):
            if claim in claims and (
                not isinstance(value, str)
                or not value.isascii()
                or not isinstance(claims[claim], str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{22}", claims[claim])
                or not hmac.compare_digest(
                    claims[claim], b64(hashlib.sha256(value.encode()).digest()[:16])
                )
            ):
                raise ValueError("OIDC authorization response hash mismatch")
        return claims
