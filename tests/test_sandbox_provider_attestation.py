"""Actual Ed25519 exchange, scope/revocation and static capability boundaries."""

import base64
import hashlib
import struct
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sapientia import access, file_verdicts, sandbox_provider
from sapientia.storage import ConflictError, encode
from tests import test_platform_gap_remediation as fixture_sources

platform = fixture_sources.platform
artifact_fixture = fixture_sources.artifact_fixture
pe_sample = fixture_sources.pe_sample


def trusted(fixture, *, indexes=None):
    private = Ed25519PrivateKey.generate()
    profile = sandbox_provider.save_provider(
        fixture["store"],
        fixture["actors"]["requester"],
        {
            "name": "synthetic-provider",
            "key_id": "qualification-key-1",
            "public_key": base64.b64encode(
                private.public_key().public_bytes_raw()
            ).decode(),
            "indexes": indexes or ["public"],
            "expires": time.time() + 3600,
            "reason": "Synthetic isolated protocol qualification, not a production provider",
        },
    )
    sandbox_provider.review_provider(
        fixture["store"],
        fixture["actors"]["approver"],
        profile["id"],
        1,
        True,
        "Independent trust review",
    )
    return private, profile


def requested(fixture):
    private, profile = trusted(fixture)
    artifact = artifact_fixture(fixture, b"Harmless sample retained and never executed")
    manifest = sandbox_provider.request_job(
        fixture["store"], fixture["actors"]["requester"], artifact, profile["id"]
    )
    return private, profile, manifest


def signed(private, manifest, **changes):
    report = {
        "summary": "Synthetic provider classification, no execution",
        "findings": [],
    }
    payload = {
        key: manifest[key]
        for key in (
            "protocol",
            "request_id",
            "nonce",
            "tenant",
            "artifact_id",
            "sha256",
            "provider",
            "key_id",
        )
    }
    payload.update(
        provider_job_id="synthetic-remote-job",
        verdict="unknown",
        report=report,
        report_digest=hashlib.sha256(encode(report).encode()).hexdigest(),
        observed_at=time.time(),
    )
    payload.update(changes)
    return {
        **payload,
        "signature": base64.b64encode(private.sign(encode(payload).encode())).decode(),
    }


def test_actual_signed_result_is_bound_recorded_and_has_no_execution_or_auto_response(
    platform,
):
    private, _, manifest = requested(platform)
    data = signed(private, manifest, verdict="suspicious")
    result = sandbox_provider.complete_job(
        platform["store"], platform["actors"]["requester"], manifest["request_id"], data
    )
    assert result["state"] == "completed_attested"
    evidence = result["result"]
    assert (
        evidence["provider_signature_verified"] and evidence["verdict"] == "suspicious"
    )
    assert evidence["signature"] == data["signature"]
    assert (
        not evidence["sample_executed_by_xsera"]
        and not evidence["sample_sent_by_xsera"]
    )
    assert not evidence["automatic_response"] and evidence["ml_classification"] is None
    runs = file_verdicts.case_verdicts(
        platform["store"], platform["actors"]["requester"], platform["case"]["id"]
    )
    assert runs[-1]["request_id"] == manifest["request_id"]
    pending = file_verdicts.sandbox_job(
        platform["store"], platform["actors"]["requester"], manifest["request_id"]
    )
    assert pending["attestation"]["nonce"] == manifest["nonce"]
    with pytest.raises(ConflictError):
        sandbox_provider.complete_job(
            platform["store"],
            platform["actors"]["requester"],
            manifest["request_id"],
            data,
        )


@pytest.mark.parametrize("verdict", ["unknown", "failed", "benign", "malicious"])
def test_provider_decision_does_not_become_independent_xsera_verdict_or_block(
    platform, verdict
):
    private, _, manifest = requested(platform)
    result = sandbox_provider.complete_job(
        platform["store"],
        platform["actors"]["requester"],
        manifest["request_id"],
        signed(private, manifest, verdict=verdict),
    )["result"]
    assert (
        result["verdict"] == verdict
        and "not independently confirmed" in result["attribution"]
    )
    assert not result["automatic_response"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_id", "different-request"),
        ("nonce", "a" * 64),
        ("tenant", "b"),
        ("artifact_id", "different-artifact"),
        ("sha256", "a" * 64),
        ("provider", "different-provider"),
        ("key_id", "wrong-key"),
    ],
)
def test_even_valid_provider_signature_cannot_rebind_request_sample_or_tenant(
    platform, field, value
):
    private, _, manifest = requested(platform)
    with pytest.raises(ValueError, match="exact request"):
        sandbox_provider.complete_job(
            platform["store"],
            platform["actors"]["requester"],
            manifest["request_id"],
            signed(private, manifest, **{field: value}),
        )
    assert (
        file_verdicts.sandbox_job(
            platform["store"], platform["actors"]["requester"], manifest["request_id"]
        )["state"]
        == "pending_attested"
    )


def test_payload_tamper_and_wrong_signer_are_rejected_without_state_change(platform):
    private, _, manifest = requested(platform)
    data = signed(private, manifest)
    data["verdict"] = "malicious"
    with pytest.raises(ValueError, match="signature verification"):
        sandbox_provider.complete_job(
            platform["store"],
            platform["actors"]["requester"],
            manifest["request_id"],
            data,
        )
    with pytest.raises(ValueError, match="signature verification"):
        sandbox_provider.complete_job(
            platform["store"],
            platform["actors"]["requester"],
            manifest["request_id"],
            signed(Ed25519PrivateKey.generate(), manifest),
        )
    assert (
        file_verdicts.sandbox_job(
            platform["store"], platform["actors"]["requester"], manifest["request_id"]
        )["state"]
        == "pending_attested"
    )


def test_signed_report_digest_verifies_the_actual_report_not_a_claimed_digest(platform):
    private, _, manifest = requested(platform)
    with pytest.raises(ValueError, match="report content"):
        sandbox_provider.complete_job(
            platform["store"],
            platform["actors"]["requester"],
            manifest["request_id"],
            signed(private, manifest, report_digest="a" * 64),
        )


def test_expiry_before_request_and_result_and_provider_revocation(platform):
    private, profile, manifest = requested(platform)
    data = signed(private, manifest)
    sandbox_provider.revoke_provider(
        platform["store"],
        platform["actors"]["approver"],
        profile["id"],
        1,
        "Revoke exact fixture trust",
    )
    with pytest.raises(ConflictError, match="trust"):
        sandbox_provider.complete_job(
            platform["store"],
            platform["actors"]["requester"],
            manifest["request_id"],
            data,
        )
    with pytest.raises(ConflictError):
        sandbox_provider.request_job(
            platform["store"],
            platform["actors"]["requester"],
            manifest["artifact_id"],
            profile["id"],
        )
    private, _, manifest = requested(platform)
    with platform["store"].control() as db:
        db.execute(
            "UPDATE file_sandbox_jobs SET expires=0 WHERE id=?",
            (manifest["request_id"],),
        )
    with pytest.raises(ConflictError, match="expired"):
        sandbox_provider.complete_job(
            platform["store"],
            platform["actors"]["requester"],
            manifest["request_id"],
            signed(private, manifest),
        )
    assert (
        file_verdicts.sandbox_job(
            platform["store"], platform["actors"]["requester"], manifest["request_id"]
        )["effective_state"]
        == "expired"
    )


def test_provider_authority_is_checked_again_at_completion(platform):
    private, _, manifest = requested(platform)
    access.set_for_user(
        platform["store"], platform["actors"]["requester"], "approver", ["private"]
    )
    with pytest.raises(ConflictError, match="authorities"):
        sandbox_provider.complete_job(
            platform["store"],
            platform["actors"]["requester"],
            manifest["request_id"],
            signed(private, manifest),
        )


def test_foreign_tenant_and_reader_cannot_import_attested_result(platform):
    private, _, manifest = requested(platform)
    data = signed(private, manifest)
    with pytest.raises(KeyError):
        sandbox_provider.complete_job(
            platform["store"],
            platform["actors"]["foreign"],
            manifest["request_id"],
            data,
        )
    with pytest.raises(PermissionError):
        sandbox_provider.complete_job(
            platform["store"],
            platform["actors"]["reader"],
            manifest["request_id"],
            data,
        )
    assert (
        sandbox_provider.list_providers(
            platform["store"], platform["actors"]["foreign"]
        )
        == []
    )


def test_attested_job_cannot_be_downgraded_to_an_unsigned_administrator_claim(platform):
    _, _, manifest = requested(platform)
    with pytest.raises(ValueError, match="downgrade"):
        file_verdicts.complete_sandbox(
            platform["store"],
            platform["actors"]["requester"],
            manifest["request_id"],
            {
                "sha256": manifest["sha256"],
                "provider": manifest["provider"],
                "provider_job_id": "unverified",
                "verdict": "benign",
                "report_digest": "a" * 64,
                "observed_at": time.time(),
                "reason": "Attempted downgrade",
            },
        )


@pytest.mark.parametrize(
    "extra",
    [
        {"public_key": "attacker supplied key"},
        {"algorithm": "none"},
        {"sample_sent": True},
    ],
)
def test_signature_algorithm_and_trust_key_cannot_be_selected_by_result(
    platform, extra
):
    private, _, manifest = requested(platform)
    with pytest.raises(ValueError, match="exact versioned"):
        sandbox_provider.complete_job(
            platform["store"],
            platform["actors"]["requester"],
            manifest["request_id"],
            {**signed(private, manifest), **extra},
        )


def test_provider_creation_is_draft_until_different_admin_approves(platform):
    private = Ed25519PrivateKey.generate()
    profile = sandbox_provider.save_provider(
        platform["store"],
        platform["actors"]["requester"],
        {
            "name": "draft",
            "key_id": "key-1",
            "public_key": base64.b64encode(
                private.public_key().public_bytes_raw()
            ).decode(),
            "indexes": ["public"],
            "expires": time.time() + 3600,
            "reason": "Draft fixture",
        },
    )
    artifact = artifact_fixture(platform, b"harmless")
    with pytest.raises(ConflictError):
        sandbox_provider.request_job(
            platform["store"], platform["actors"]["requester"], artifact, profile["id"]
        )
    with pytest.raises(PermissionError):
        sandbox_provider.review_provider(
            platform["store"],
            platform["actors"]["requester"],
            profile["id"],
            1,
            True,
            "Self-approve",
        )


def imported_pe():
    body = bytearray(pe_sample()) + bytearray(512)
    section = 88 + 240
    struct.pack_into("<IIII", body, section + 8, 512, 4096, 512, 512)
    struct.pack_into("<I", body, 88 + 108, 2)
    struct.pack_into("<II", body, 88 + 112 + 8, 4096, 40)
    struct.pack_into("<IIIII", body, 512, 4160, 0, 0, 4224, 4160)
    body[640:653] = b"kernel32.dll\0"
    for i, name in enumerate(
        (b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread")
    ):
        pos = 768 + i * 64
        struct.pack_into("<Q", body, 576 + i * 8, 4096 + pos - 512)
        body[pos : pos + 2] = b"\0\0"
        body[pos + 2 : pos + 3 + len(name)] = name + b"\0"
    return bytes(body)


def test_static_import_capability_uses_real_bounded_pe_table_not_string_presence():
    result = file_verdicts.inspect_bytes(imported_pe())
    assert (
        result["import_parse_status"] == "completed"
        and result["imports"][0]["library"] == "kernel32.dll"
    )
    findings = result["static_observations"]["findings"]
    assert findings[0]["indicator"] == "remote_memory_and_thread_imports"
    assert "not observed execution" in findings[0]["meaning"]
    verdict = file_verdicts.evaluate_signatures(imported_pe(), [])
    assert verdict["verdict"] == "unknown" and not verdict["sample_executed"]
    assert (
        not result["static_observations"]["trained_ml"]
        and result["ml_classification"] is None
    )
    data = file_verdicts.inspect_bytes(
        b"VirtualAllocEx WriteProcessMemory CreateRemoteThread"
    )
    assert data["static_observations"]["findings"] == []


@pytest.mark.parametrize("rva,size", [(0, 40), (4096, 19), (4096, 65537), (999999, 40)])
def test_incomplete_import_observation_is_unknown_and_incomplete_not_clean(rva, size):
    body = bytearray(imported_pe())
    struct.pack_into("<II", body, 88 + 112 + 8, rva, size)
    verdict = file_verdicts.evaluate_signatures(bytes(body), [])
    assert verdict["static"]["parse_status"] == "valid_header"
    assert verdict["static"]["import_parse_status"] == "incomplete"
    assert verdict["verdict"] == "unknown" and not verdict["coverage_complete"]


def test_report_is_bounded_and_nonfinite_observed_time_is_rejected(platform):
    private, _, manifest = requested(platform)
    for changes in (
        {"observed_at": True},
        {"report": {"summary": "x", "findings": [{}]}},
    ):
        with pytest.raises(ValueError):
            sandbox_provider.complete_job(
                platform["store"],
                platform["actors"]["requester"],
                manifest["request_id"],
                signed(private, manifest, **changes),
            )


def test_benign_and_malicious_signature_conflict_keeps_malicious_precedence():
    body = imported_pe()
    common = {
        "name": "Explicit qualification",
        "kind": "sha256",
        "value": hashlib.sha256(body).hexdigest(),
        "source": "Known synthetic label",
    }
    verdict = file_verdicts.evaluate_signatures(
        body,
        [
            {**common, "id": "allow", "verdict": "benign"},
            {**common, "id": "deny", "verdict": "malicious"},
        ],
    )
    assert verdict["verdict"] == "malicious"
