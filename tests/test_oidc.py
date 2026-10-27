import hashlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from sapientia import access, auth, mfa, oidc
from sapientia.storage import Settings, Store

PASSWORD = "OIDC-focused-test-password-2026"


class Provider:
    def __init__(self, algorithm="RS256"):
        self.algorithm = algorithm
        self.key = (
            rsa.generate_private_key(public_exponent=65537, key_size=2048)
            if algorithm == "RS256"
            else ec.generate_private_key(ec.SECP256R1())
        )
        public = self.key.public_key().public_numbers()
        self.jwk = {"kid": "test-key", "alg": algorithm, "use": "sig"}
        if algorithm == "RS256":
            self.jwk.update(
                kty="RSA",
                n=oidc.b64(public.n.to_bytes(256, "big")),
                e=oidc.b64(public.e.to_bytes(3, "big")),
            )
        else:
            self.jwk.update(
                kty="EC",
                crv="P-256",
                x=oidc.b64(public.x.to_bytes(32, "big")),
                y=oidc.b64(public.y.to_bytes(32, "big")),
            )
        self.claim_changes, self.header_changes = {}, {}
        self.calls = []
        self.query = None

    def token(self):
        now = time.time()
        header = {
            "alg": self.algorithm,
            "kid": "test-key",
            "typ": "JWT",
            **self.header_changes,
        }
        claims = {
            "iss": "https://idp.example",
            "sub": "subject-1",
            "aud": "siem-client",
            "exp": now + 300,
            "iat": now,
            "nonce": self.query["nonce"][0],
            **self.claim_changes,
        }
        content = (
            oidc.b64(json.dumps(header).encode())
            + "."
            + oidc.b64(json.dumps(claims).encode())
        )
        if self.algorithm == "RS256":
            signature = self.key.sign(
                content.encode(), padding.PKCS1v15(), hashes.SHA256()
            )
        else:
            r, s = decode_dss_signature(
                self.key.sign(content.encode(), ec.ECDSA(hashes.SHA256()))
            )
            signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return content + "." + oidc.b64(signature)

    def transport(self, url, data=None, headers=None):
        self.calls.append(url)
        if url.endswith("openid-configuration"):
            return {
                "issuer": "https://idp.example",
                "authorization_endpoint": "https://idp.example/authorize",
                "token_endpoint": "https://idp.example/token",
                "jwks_uri": "https://idp.example/keys",
                "response_types_supported": ["code"],
                "code_challenge_methods_supported": ["S256"],
                "id_token_signing_alg_values_supported": [self.algorithm],
                "token_endpoint_auth_methods_supported": [
                    "none",
                    "client_secret_basic",
                ],
            }
        if url.endswith("/keys"):
            return {"keys": [self.jwk]}
        assert url.endswith("/token")
        fields = parse_qs(data.decode())
        assert fields["grant_type"] == ["authorization_code"]
        assert fields["redirect_uri"] == ["https://siem.example/api/sso/callback"]
        assert (
            oidc.b64(hashlib.sha256(fields["code_verifier"][0].encode()).digest())
            == self.query["code_challenge"][0]
        )
        return {"id_token": self.token(), "access_token": "test-access-token"}


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    access.initialize(value)
    auth.create_user(value, "viewer", PASSWORD, "viewer", "soc")
    yield value
    value.close()


def adapter(store, fake=None, **overrides):
    fake = fake or Provider()
    config = {
        "issuer": "https://idp.example",
        "client_id": "siem-client",
        "redirect_uri": "https://siem.example/api/sso/callback",
        "subjects": {"subject-1": "viewer"},
        "algorithms": [fake.algorithm],
        **overrides,
    }
    return oidc.OIDCProvider(store, config, fake.transport), fake


def begin(value, fake):
    started = value.start()
    fake.query = parse_qs(urlsplit(started["authorization_url"]).query)
    assert fake.query["code_challenge_method"] == ["S256"]
    assert fake.query["scope"] == ["openid"]
    return started, fake.query["state"][0]


@pytest.mark.parametrize("algorithm", ["RS256", "ES256"])
def test_verified_code_flow_uses_local_role_tenant_acl_and_single_use_state(
    store, algorithm
):
    value, fake = adapter(store, Provider(algorithm))
    with store.control() as db:
        db.execute(
            "INSERT INTO user_index_access VALUES('soc','viewer','[\"security\"]')"
        )
    started, state = begin(value, fake)
    with store.control() as db:
        pending = dict(db.execute("SELECT * FROM oidc_states").fetchone())
    assert state not in json.dumps(pending)
    assert started["browser_token"] not in json.dumps(pending)
    assert fake.query["nonce"][0] not in json.dumps(pending)
    session = value.callback(state, "authorization-code", started["browser_token"])
    assert (
        session["name"] == "viewer"
        and session["role"] == "viewer"
        and session["tenant"] == "soc"
    )
    assert session["allowed_indexes"] == ["security"]
    assert auth.identity(store, session["token"])["name"] == "viewer"
    with pytest.raises(ValueError, match="state"):
        value.callback(state, "authorization-code", started["browser_token"])
    with store.control() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM audit WHERE action='sso.login'"
            ).fetchone()[0]
            == 1
        )


def test_state_is_bound_to_browser_and_expires(store):
    value, fake = adapter(store)
    started, state = begin(value, fake)
    with pytest.raises(ValueError, match="browser"):
        value.callback(state, "code", "different-browser")
    assert not any(url.endswith("/token") for url in fake.calls)
    with store.control() as db:
        db.execute("UPDATE oidc_states SET expires=?", (time.time() - 1,))
    with pytest.raises(ValueError, match="expired"):
        value.callback(state, "code", started["browser_token"])


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": "https://attacker.example"},
        {"aud": "other-client"},
        {"aud": ["siem-client", "other-client"]},
        {"azp": "other-client"},
        {"nonce": "wrong"},
        {"nonce": "한" * 43},
        {"nonce": "\ud800" * 43},
        {"exp": 1},
        {"exp": True},
        {"iat": 1},
        {"iat": time.time() + 9999},
        {"nbf": time.time() + 9999},
        {"c_hash": "wrong"},
        {"at_hash": "wrong"},
    ],
)
def test_signed_but_invalid_claims_never_create_sessions(store, claims):
    value, fake = adapter(store)
    fake.claim_changes = claims
    started, state = begin(value, fake)
    with pytest.raises(ValueError):
        value.callback(state, "code", started["browser_token"])
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM sessions").fetchone()[0] == 0


@pytest.mark.parametrize("position", [0, 1, 2])
@pytest.mark.parametrize("malformed", ["한" * 43, "\ud800" * 43])
def test_malformed_callback_values_do_not_consume_state(store, position, malformed):
    value, fake = adapter(store)
    started, state = begin(value, fake)
    arguments = [state, "code", started["browser_token"]]
    arguments[position] = malformed
    with pytest.raises(ValueError, match="callback"):
        value.callback(*arguments)
    assert value.callback(state, "code", started["browser_token"])["name"] == "viewer"


@pytest.mark.parametrize(
    "header",
    [
        {"alg": "none"},
        {"alg": "HS256"},
        {"jku": "https://attacker.example/keys"},
        {"kid": "missing"},
    ],
)
def test_jwt_algorithm_confusion_and_external_keys_are_rejected(store, header):
    value, fake = adapter(store)
    fake.header_changes = header
    started, state = begin(value, fake)
    with pytest.raises(ValueError):
        value.callback(state, "code", started["browser_token"])


def test_signature_is_checked_with_discovery_key(store):
    value, fake = adapter(store)
    fake.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    started, state = begin(value, fake)
    with pytest.raises(ValueError, match="signature"):
        value.callback(state, "code", started["browser_token"])


def test_unmapped_disabled_and_missing_local_users_never_get_sessions(store):
    for mapping, disabled in (
        ({"different-subject": "viewer"}, False),
        ({"subject-1": "missing"}, False),
        ({"subject-1": "viewer"}, True),
    ):
        value, fake = adapter(store, subjects=mapping)
        if disabled:
            with store.control() as db:
                db.execute("UPDATE users SET disabled=1")
        started, state = begin(value, fake)
        with pytest.raises(PermissionError):
            value.callback(state, "code", started["browser_token"])
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM sessions").fetchone()[0] == 0


def test_oidc_does_not_bypass_local_mfa(store):
    who = {"name": "viewer", "tenant": "soc", "role": "viewer"}
    secret = mfa.enroll(store, who, PASSWORD)["secret"]
    counter = int(time.time() // 30)
    mfa.confirm(store, who, mfa.code(secret, counter))
    value, fake = adapter(store)
    started, state = begin(value, fake)
    challenge = value.callback(state, "code", started["browser_token"])
    assert challenge["mfa_required"] and "token" not in challenge
    with store.control() as db:
        row = dict(db.execute("SELECT * FROM oidc_mfa_challenges").fetchone())
        assert "subject-1" not in json.dumps(row)
        assert db.execute("SELECT count(*) FROM sessions").fetchone()[0] == 0
    with pytest.raises(ValueError, match="browser"):
        value.complete_mfa(
            challenge["challenge"], "x" * 43, mfa.code(secret, counter + 1)
        )
    session = value.complete_mfa(
        challenge["challenge"], started["browser_token"], mfa.code(secret, counter + 1)
    )
    assert session["mfa_enabled"]
    with pytest.raises(ValueError):
        value.complete_mfa(
            challenge["challenge"],
            started["browser_token"],
            mfa.code(secret, counter + 2),
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://idp.example",
        "https://user:password@idp.example",
        "https://idp.example/#fragment",
    ],
)
def test_insecure_operator_configuration_is_rejected(store, url):
    with pytest.raises(ValueError):
        adapter(store, issuer=url)


def test_default_is_disabled_and_http_requires_explicit_loopback_test_option(
    monkeypatch,
):
    monkeypatch.delenv("SAPIENTIA_OIDC_CONFIG", raising=False)
    assert oidc.load_config() is None
    with pytest.raises(ValueError):
        oidc.secure_url("http://127.0.0.1:9000")
    assert oidc.secure_url("http://127.0.0.1:9000", True)
    with pytest.raises(ValueError):
        oidc.secure_url("http://192.0.2.1", True)


def test_discovery_cannot_change_issuer_or_downgrade_pkce(store):
    value, fake = adapter(store)
    original = fake.transport

    def poisoned(url, data=None, headers=None):
        result = original(url, data, headers)
        if url.endswith("openid-configuration"):
            result["issuer"] = "https://attacker.example"
        return result

    value.transport = poisoned
    with pytest.raises(ValueError, match="discovery"):
        value.start()


def test_real_loopback_provider_exchange_and_redirect_rejection(store):
    fake = Provider()

    class Handler(BaseHTTPRequestHandler):
        def reply(self, value):
            body = json.dumps(value).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", issuer + "/keys")
                self.end_headers()
            elif self.path.endswith("openid-configuration"):
                self.reply(
                    {
                        "issuer": issuer,
                        "authorization_endpoint": issuer + "/authorize",
                        "token_endpoint": issuer + "/token",
                        "jwks_uri": issuer + "/keys",
                        "response_types_supported": ["code"],
                        "code_challenge_methods_supported": ["S256"],
                        "id_token_signing_alg_values_supported": ["RS256"],
                        "token_endpoint_auth_methods_supported": ["none"],
                    }
                )
            else:
                self.reply({"keys": [fake.jwk]})

        def do_POST(self):
            data = self.rfile.read(int(self.headers["Content-Length"]))
            self.reply(fake.transport("https://idp.example/token", data, {}))

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    issuer = "http://127.0.0.1:" + str(server.server_port)
    fake.claim_changes = {"iss": issuer}
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        value = oidc.OIDCProvider(
            store,
            {
                "issuer": issuer,
                "client_id": "siem-client",
                "redirect_uri": "https://siem.example/api/sso/callback",
                "subjects": {"subject-1": "viewer"},
                "allow_loopback_http": True,
            },
        )
        started, state = begin(value, fake)
        assert (
            value.callback(state, "code", started["browser_token"])["name"] == "viewer"
        )
        from sapientia.storage import CapacityError

        with pytest.raises(CapacityError):
            oidc.request_json(issuer + "/redirect")
    finally:
        server.shutdown()
        server.server_close()
        worker.join(2)
