"""Real in-process SDK byte exchange; no external provider or TLS handshake."""

import base64
import copy
import hashlib
import time
import urllib.request

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from sapientia import file_verdicts, sandbox_provider
from sapientia import sandbox_provider_sdk as sdk
from sapientia.storage import ConflictError, encode
from tests import test_sandbox_provider_attestation as fixtures
from tests import test_xdr_advanced_api as http_fixtures

client = http_fixtures.client
platform = fixtures.platform


class TestTransport:
    __test__ = False

    def __init__(self, client):
        self.client = client
        self.requests = []

    def post(self, path, payload):
        self.requests.append((path, copy.deepcopy(payload)))
        result = self.client.post(path, json=payload)
        if result.status_code != 200:
            raise ValueError(f"Protocol test HTTP {result.status_code}: {result.text}")
        return result.content, dict(result.headers)


def approved_provider(fixture, enabled=True):
    private = Ed25519PrivateKey.generate()
    profile = sandbox_provider.save_provider(
        fixture["store"],
        fixture["actors"]["requester"],
        {
            "name": "SDK qualification provider",
            "key_id": "sdk-key-1",
            "public_key": base64.b64encode(
                private.public_key().public_bytes_raw()
            ).decode(),
            "indexes": ["public"],
            "expires": time.time() + 3600,
            "allow_sample_access": enabled,
            "reason": "Explicit harmless sample access in this isolated protocol test",
        },
    )
    sandbox_provider.review_provider(
        fixture["store"],
        fixture["actors"]["approver"],
        profile["id"],
        1,
        True,
        "Independent sample-export consent review",
    )
    return private, profile


def fixture_from_client(client):
    return {
        "store": client.app.state.store,
        "case": client.app.state.qualification["case"],
        "actors": {
            name: {
                "name": name,
                "tenant": "a",
                "role": "admin",
                "allowed_indexes": ["*"],
            }
            for name in ("requester", "approver")
        },
    }


def worker_http(client, *, enabled=True):
    fixture = fixture_from_client(client)
    private, profile = approved_provider(fixture, enabled)
    artifact, digest = http_fixtures.create_artifact(client)
    job = sandbox_provider.request_job(
        fixture["store"], fixture["actors"]["requester"], artifact, profile["id"]
    )
    signed_client = TestClient(client.app, base_url="https://protocol-test.invalid")
    transport = TestTransport(signed_client)
    worker = sdk.SandboxProviderWorker(
        "https://protocol-test.invalid",
        "a",
        profile["id"],
        profile["key_id"],
        private,
        transport=transport,
    )
    return fixture, private, profile, job, digest, transport, worker


def test_actual_sdk_polls_fetches_hash_verified_sample_calls_engine_and_records_signed_case_result(
    client,
):
    fixture, _, profile, job, digest, transport, worker = worker_http(client)
    observed = []

    def analyze(sample, manifest):
        assert (
            isinstance(sample, bytes) and hashlib.sha256(sample).hexdigest() == digest
        )
        assert manifest["request_id"] == job["request_id"]
        assert "private_key" not in manifest
        observed.append(sample)
        return {
            "provider_job_id": "synthetic-sdk-engine-job",
            "verdict": "suspicious",
            "report": {
                "summary": "Harmless synthetic test label, no sample execution",
                "findings": [],
            },
        }

    receipts = worker.run_once(analyze)
    assert len(observed) == len(receipts) == 1
    result = receipts[0]["result"]
    assert result["provider_signature_verified"] and result["sample_sent_by_xsera"]
    assert result["result_received_via"] == "authenticated provider SDK"
    assert not result["sample_executed_by_xsera"] and not result["automatic_response"]
    assert len(transport.requests) == 3 and worker.poll() == []
    history = file_verdicts.case_verdicts(
        fixture["store"], fixture["actors"]["requester"], fixture["case"]["id"]
    )
    assert history[-1]["provider_job_id"] == "synthetic-sdk-engine-job"
    with fixture["store"].control() as db:
        rows = db.execute(
            "SELECT actor FROM audit WHERE action='file.sandbox.attested_result'"
        ).fetchall()
    assert rows[-1]["actor"] == "sandbox-provider:" + profile["id"]


def test_sdk_key_is_scoped_and_sample_egress_is_explicitly_disabled_by_default(client):
    _, _, _, job, _, transport, worker = worker_http(client, enabled=False)
    callback_called = []
    with pytest.raises(ValueError, match="403"):
        worker.run_once(lambda *args: callback_called.append(args))
    assert not callback_called and len(transport.requests) == 1
    assert not job["provider_sample_pull_enabled"]


def test_provider_sample_exchange_refuses_plain_http_even_with_valid_credential(client):
    _, _, _, _, _, _, worker = worker_http(client)
    result = client.post(
        sdk.PREFIX + "/poll", json={"credential": worker.credential("poll")}
    )
    assert result.status_code == 403 and "HTTPS" in result.text


def test_credential_replay_and_operation_substitution_do_not_expose_sample(client):
    fixture, _, _, job, _, transport, worker = worker_http(client)
    credential = worker.credential("poll")
    transport.post(sdk.PREFIX + "/poll", {"credential": credential})
    with pytest.raises(ValueError, match="already used"):
        transport.post(sdk.PREFIX + "/poll", {"credential": credential})
    fresh = worker.credential("poll")
    with pytest.raises(ValueError, match="different operation"):
        transport.post(
            sdk.PREFIX + "/" + job["request_id"] + "/sample", {"credential": fresh}
        )
    status = file_verdicts.sandbox_job(
        fixture["store"], fixture["actors"]["requester"], job["request_id"]
    )
    assert not status["sample_sent_by_xsera"]


def test_service_credential_wrong_key_wrong_scope_expired_and_body_tamper_fail(
    platform,
):
    private, profile = approved_provider(platform)
    worker = sdk.SandboxProviderWorker(
        "https://example.invalid",
        "a",
        profile["id"],
        profile["key_id"],
        private,
        transport=object(),
    )
    credential = worker.credential("poll")
    credential["nonce"] = "a" * 64
    with pytest.raises(PermissionError, match="signature verification"):
        sandbox_provider.poll_jobs(platform["store"], credential)
    bad_worker = sdk.SandboxProviderWorker(
        "https://example.invalid",
        "a",
        profile["id"],
        profile["key_id"],
        Ed25519PrivateKey.generate(),
        transport=object(),
    )
    with pytest.raises(PermissionError, match="signature verification"):
        sandbox_provider.poll_jobs(platform["store"], bad_worker.credential("poll"))
    credential = worker.credential("poll")
    credential["issued_at"] = time.time() - 120
    payload = {k: v for k, v in credential.items() if k != "signature"}
    credential["signature"] = base64.b64encode(
        private.sign(encode(payload).encode())
    ).decode()
    with pytest.raises(PermissionError, match="expired"):
        sandbox_provider.poll_jobs(platform["store"], credential)
    with pytest.raises(PermissionError, match="body digest"):
        sandbox_provider.result_from_provider(
            platform["store"],
            worker.credential("complete", "job", {}),
            "job",
            {"tampered": True},
        )


def test_sdk_callback_failure_is_signed_failed_never_clean(client):
    _, _, _, _, _, _, worker = worker_http(client)

    def failed(sample, manifest):
        raise RuntimeError("private engine details should not leak")

    result = worker.run_once(failed)[0]["result"]
    assert (
        result["verdict"] == "failed" and "RuntimeError" in result["report"]["summary"]
    )
    assert "private engine details" not in result["report"]["summary"]
    assert not result["automatic_response"]


def test_corrupt_sample_never_reaches_analysis_callback(client):
    fixture, _, _, job, _, transport, worker = worker_http(client)
    original = transport.post

    def tampered(path, payload):
        body, headers = original(path, payload)
        return (
            (body + b"corruption", headers)
            if path.endswith("/sample")
            else (body, headers)
        )

    transport.post = tampered
    callback_called = []
    with pytest.raises(ValueError, match="exact request digest"):
        worker.run_once(lambda *args: callback_called.append(args))
    assert not callback_called
    assert (
        file_verdicts.sandbox_job(
            fixture["store"], fixture["actors"]["requester"], job["request_id"]
        )["state"]
        == "pending_attested"
    )


def test_completed_job_and_foreign_profile_cannot_be_read_by_another_provider(client):
    fixture, _, _, job, _, transport, worker = worker_http(client)
    other_key, other_profile = approved_provider(fixture)
    other = sdk.SandboxProviderWorker(
        "https://protocol-test.invalid",
        "a",
        other_profile["id"],
        other_profile["key_id"],
        other_key,
        transport=transport,
    )
    with pytest.raises(ValueError, match="404"):
        transport.post(
            sdk.PREFIX + "/" + job["request_id"] + "/sample",
            {"credential": other.credential("sample", job["request_id"])},
        )
    assert other.poll() == []
    worker.run_once(
        lambda *_: {
            "provider_job_id": "completed",
            "verdict": "unknown",
            "report": {"summary": "Unknown remains unknown", "findings": []},
        }
    )
    with pytest.raises(ValueError, match="409"):
        transport.post(
            sdk.PREFIX + "/" + job["request_id"] + "/sample",
            {"credential": worker.credential("sample", job["request_id"])},
        )


def test_key_or_sample_opt_in_cannot_be_mutated_after_peer_approval(platform):
    private, profile = approved_provider(platform, False)
    artifact = fixtures.artifact_fixture(platform, b"immutable harmless sample")
    with platform["store"].control() as db:
        db.execute(
            "UPDATE file_sandbox_providers SET sample_access=1 WHERE id=?",
            (profile["id"],),
        )
    with pytest.raises(ConflictError, match="trust"):
        sandbox_provider.request_job(
            platform["store"], platform["actors"]["requester"], artifact, profile["id"]
        )
    assert private.public_key().public_bytes_raw()


def test_retained_sample_corruption_is_detected_at_request_and_completion(platform):
    _, profile = approved_provider(platform)
    artifact = fixtures.artifact_fixture(platform, b"sample-one")
    path = platform["store"].path / "response-artifacts" / (artifact + ".bin")
    path.write_bytes(b"sample-two")
    with pytest.raises(ConflictError, match="digest mismatch"):
        sandbox_provider.request_job(
            platform["store"], platform["actors"]["requester"], artifact, profile["id"]
        )
    private, _, manifest = fixtures.requested(platform)
    path = (
        platform["store"].path
        / "response-artifacts"
        / (manifest["artifact_id"] + ".bin")
    )
    before = path.read_bytes()
    path.write_bytes(b"x" + before[1:])
    with pytest.raises(ConflictError, match="digest mismatch"):
        sandbox_provider.complete_job(
            platform["store"],
            platform["actors"]["requester"],
            manifest["request_id"],
            fixtures.signed(private, manifest),
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://example.invalid",
        "https://user:password@example.invalid",
        "https://example.invalid/path",
        "https://example.invalid?x=1",
        "https://example.invalid#fragment",
        "https://example.invalid:0",
    ],
)
def test_production_sdk_never_silently_uses_insecure_or_credential_url(url):
    with pytest.raises(ValueError):
        sdk.HTTPSTransport(url)


def test_production_transport_has_strict_tls_no_environment_proxy_and_no_redirect():
    transport = sdk.HTTPSTransport("https://example.invalid")
    https = next(
        handler
        for handler in transport.opener.handlers
        if isinstance(handler, urllib.request.HTTPSHandler)
    )
    assert https._context.check_hostname and https._context.verify_mode
    redirect = next(
        handler
        for handler in transport.opener.handlers
        if isinstance(handler, sdk._NoRedirect)
    )
    with pytest.raises(ValueError, match="redirect"):
        redirect.redirect_request(None, None, 302, None, {}, "https://other.invalid")


@pytest.mark.parametrize(
    "y",
    sorted(sandbox_provider.SMALL_ORDER_Y)
    + [sandbox_provider.ED25519_FIELD, sandbox_provider.ED25519_FIELD + 1],
)
@pytest.mark.parametrize("sign", [0, 1])
def test_weak_or_noncanonical_edwards_provider_key_cannot_enter_trust_registry(y, sign):
    public = (y | (sign << 255)).to_bytes(32, "little")
    with pytest.raises(ValueError, match="small-order"):
        sandbox_provider._provider_public_key(base64.b64encode(public).decode())


def test_constructor_acceptance_is_not_provider_key_validity():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    identity = bytes([1]) + bytes(31)
    # The provider registry rejects this public identity point even when the
    # crypto library accepts a 32-byte key object. It never reaches trust approval.
    Ed25519PublicKey.from_public_bytes(identity)
    with pytest.raises(ValueError, match="small-order"):
        sandbox_provider._provider_public_key(base64.b64encode(identity).decode())


def test_weak_key_cannot_be_saved_for_later_peer_approval(platform):
    identity = bytes([1]) + bytes(31)
    with pytest.raises(ValueError, match="small-order"):
        sandbox_provider.save_provider(
            platform["store"],
            platform["actors"]["requester"],
            {
                "name": "forbidden identity",
                "key_id": "weak",
                "indexes": ["public"],
                "public_key": base64.b64encode(identity).decode(),
                "expires": time.time() + 3600,
                "allow_sample_access": True,
                "reason": "This weak key must never be saved",
            },
        )
    assert (
        sandbox_provider.list_providers(
            platform["store"], platform["actors"]["requester"]
        )
        == []
    )
