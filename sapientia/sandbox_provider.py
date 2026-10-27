"""Opt-in, peer-approved Ed25519 provider-result protocol.

Manifest exchange is available without sample egress. Actual provider sample
pull requires explicit peer-approved opt-in and a nonce-bound key credential.
A provider signs the result outside xSERA. Authentication proves request binding,
not correctness of the provider's malware decision. Missing/failed verdicts
remain unknown and never cause an automatic response.
"""

import base64
import binascii
import hashlib
import json
import re
import secrets
import time
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import endpoint_artifacts, principal
from . import evidence_scope as evidence
from .storage import CapacityError, ConflictError, encode

PROTOCOL = "xsera.sandbox-result.ed25519.v1"
ACCESS_PROTOCOL = "xsera.sandbox-access.ed25519.v1"
MAX_REPORT = 64 * 1024
MAX_PROVIDERS = 32
# Canonical Edwards small-order y coordinates, both x sign encodings rejected.
# Reference: libsodium 1.0.20-RELEASE ed25519_ref10.c,
# ge25519_has_small_order; verification still uses cryptography/OpenSSL.
ED25519_FIELD = 2**255 - 19
SMALL_ORDER_Y = {
    0,
    1,
    ED25519_FIELD - 1,
    int.from_bytes(
        bytes.fromhex(
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"
        ),
        "little",
    ),
    int.from_bytes(
        bytes.fromhex(
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"
        ),
        "little",
    ),
}


def initialize(store):
    with store.control(local=True) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS file_sandbox_providers(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,indexes TEXT NOT NULL,
          name TEXT NOT NULL,key_id TEXT NOT NULL,public_key TEXT NOT NULL,
          version INTEGER NOT NULL,requester TEXT NOT NULL,approver TEXT NOT NULL,
          state TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,
          digest TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS file_sandbox_attestations(
          job_id TEXT PRIMARY KEY,tenant TEXT NOT NULL,profile_id TEXT NOT NULL,
          profile_version INTEGER NOT NULL,profile_digest TEXT NOT NULL,
          nonce TEXT NOT NULL,protocol TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS file_sandbox_access_nonces(
          tenant TEXT NOT NULL,profile_id TEXT NOT NULL,nonce TEXT NOT NULL,
          created REAL NOT NULL,PRIMARY KEY(tenant,profile_id,nonce));
        CREATE TABLE IF NOT EXISTS file_sandbox_sample_exports(
          job_id TEXT PRIMARY KEY,tenant TEXT NOT NULL,profile_id TEXT NOT NULL,
          sha256 TEXT NOT NULL,exported REAL NOT NULL);
        """)
        columns = {
            row[1] for row in db.execute("PRAGMA table_info(file_sandbox_providers)")
        }
        if "sample_access" not in columns:
            db.execute(
                "ALTER TABLE file_sandbox_providers ADD COLUMN sample_access INTEGER NOT NULL DEFAULT 0"
            )


def _bytes(value, length, label):
    if not isinstance(value, str) or len(value) > 128:
        raise ValueError(label + " requires bounded canonical Base64")
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError(label + " requires canonical Base64") from None
    if len(result) != length or base64.b64encode(result).decode() != value:
        raise ValueError(label + " has invalid length or noncanonical encoding")
    return result


def _provider_public_key(value):
    public = _bytes(value, 32, "Ed25519 public key")
    y = int.from_bytes(public, "little") & (2**255 - 1)
    if y >= ED25519_FIELD or y in SMALL_ORDER_Y:
        raise ValueError(
            "Noncanonical or small-order Ed25519 provider key is forbidden"
        )
    return public


def _profile(row):
    result = dict(row)
    result["indexes"] = json.loads(result["indexes"])
    result["effective_state"] = (
        "expired" if result["expires"] <= time.time() else result["state"]
    )
    result["protocol"] = PROTOCOL
    result["sample_access_allowed"] = bool(result.pop("sample_access", 0))
    return result


def _visible(db, actor, identifier):
    row = db.execute(
        "SELECT * FROM file_sandbox_providers WHERE tenant=? AND id=?",
        (actor["tenant"], identifier),
    ).fetchone()
    if not row or not principal.contains(
        actor["allowed_indexes"], json.loads(row["indexes"])
    ):
        raise KeyError("Sandbox provider not found")
    return row


def _active(db, row):
    if row["state"] != "active" or row["expires"] <= time.time():
        return False
    if not _definition_intact(row):
        return False
    for name in (row["requester"], row["approver"]):
        try:
            actor = principal.current(
                db, {"name": name, "tenant": row["tenant"], "role": "admin"}, ("admin",)
            )
        except PermissionError:
            return False
        if not principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
            return False
    return bool(row["approver"] and row["approver"] != row["requester"])


def _definition_intact(row):
    try:
        _provider_public_key(row["public_key"])
    except ValueError:
        return False
    definition = {key: row[key] for key in ("name", "key_id", "public_key", "expires")}
    definition.update(
        indexes=json.loads(row["indexes"]),
        protocol=PROTOCOL,
        allow_sample_access=bool(row["sample_access"]),
    )
    if row["sample_access"] not in (0, 1):
        return False
    return hashlib.sha256(encode(definition).encode()).hexdigest() == row["digest"]


def _object(store, artifact):
    """Verify the actual retained object without nesting a writer transaction."""
    if not re.fullmatch(r"ART-[0-9a-f]{32}", artifact["id"]):
        raise ConflictError("Invalid retained artifact identity")
    path = endpoint_artifacts._directory(store) / (artifact["id"] + ".bin")
    if (
        not path.is_file()
        or path.is_symlink()
        or getattr(path.lstat(), "st_file_attributes", 0) & 0x400
    ):
        raise ConflictError("Sandbox artifact object is unavailable or linked")
    if (
        path.stat().st_size != artifact["total_bytes"]
        or not 0 <= artifact["total_bytes"] <= endpoint_artifacts.MAX_BYTES
    ):
        raise ConflictError("Sandbox supports verified artifacts up to 2 MiB; larger process executables require the local YARA analyzer")
    with path.open("rb") as stream:
        body = stream.read(endpoint_artifacts.MAX_BYTES + 1)
    if (
        len(body) != artifact["total_bytes"]
        or hashlib.sha256(body).hexdigest() != artifact["sha256"]
    ):
        raise ConflictError("Sandbox artifact object digest mismatch")
    return body


def save_provider(store, who, data):
    required = {
        "name",
        "key_id",
        "public_key",
        "indexes",
        "expires",
        "reason",
    }
    if (
        not isinstance(data, dict)
        or not required <= set(data)
        or set(data) - required - {"allow_sample_access"}
    ):
        raise ValueError(
            "Provider requires exact name/key_id/public_key/indexes/expires/reason"
        )
    name = evidence.text(data["name"], "provider name", 128)
    key_id = evidence.text(data["key_id"], "provider key ID", 128)
    public = _provider_public_key(data["public_key"])
    Ed25519PublicKey.from_public_bytes(public)
    scope = evidence.indexes(data["indexes"])
    reason = evidence.text(data["reason"], "provider trust reason", 2000)
    allow_sample_access = data.get("allow_sample_access", False)
    if type(allow_sample_access) is not bool:
        raise ValueError("allow_sample_access requires an explicit boolean")
    now = time.time()
    expires = evidence.number(
        data["expires"], "provider expires", now + 1, now + 90 * 86400
    )
    definition = {
        "name": name,
        "key_id": key_id,
        "public_key": data["public_key"],
        "indexes": scope,
        "expires": expires,
        "protocol": PROTOCOL,
        "allow_sample_access": allow_sample_access,
    }
    digest = hashlib.sha256(encode(definition).encode()).hexdigest()
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        if not principal.contains(actor["allowed_indexes"], scope):
            raise PermissionError("Provider trust scope exceeds permission")
        # Permanent execution/investigation history has no lifetime count ceiling.
        identifier = str(uuid.uuid4())
        db.execute(
            "INSERT INTO file_sandbox_providers VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                identifier,
                actor["tenant"],
                encode(scope),
                name,
                key_id,
                data["public_key"],
                1,
                actor["name"],
                "",
                "pending",
                now,
                expires,
                digest,
                int(allow_sample_access),
            ),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "file.sandbox.provider.save",
            {"id": identifier, "digest": digest, "reason": reason, "version": 1},
        )
        return _profile(_visible(db, actor, identifier))


def review_provider(store, who, identifier, version, approve, reason):
    evidence.integer(version, "provider version", 1, 2**31 - 1)
    if type(approve) is not bool:
        raise ValueError("approve must be boolean")
    evidence.text(reason, "provider review reason", 2000)
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        row = _visible(db, actor, identifier)
        if not _definition_intact(row):
            raise ConflictError("Provider trust definition changed before review")
        if (
            row["version"] != version
            or row["state"] != "pending"
            or row["expires"] <= time.time()
        ):
            raise ConflictError(
                "Provider profile is stale, expired or already reviewed"
            )
        if row["requester"] == actor["name"]:
            raise PermissionError(
                "A different administrator must approve provider trust"
            )
        requester = principal.current(
            db,
            {"name": row["requester"], "tenant": actor["tenant"], "role": "admin"},
            ("admin",),
        )
        if not principal.contains(
            requester["allowed_indexes"], json.loads(row["indexes"])
        ):
            raise PermissionError("Provider requester permission changed")
        db.execute(
            "UPDATE file_sandbox_providers SET approver=?,state=? WHERE id=?",
            (actor["name"], "active" if approve else "rejected", identifier),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "file.sandbox.provider.review",
            {
                "id": identifier,
                "version": version,
                "approve": approve,
                "reason": reason,
            },
        )
        return _profile(_visible(db, actor, identifier))


def revoke_provider(store, who, identifier, version, reason):
    evidence.integer(version, "provider version", 1, 2**31 - 1)
    evidence.text(reason, "provider revoke reason", 2000)
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        row = _visible(db, actor, identifier)
        if row["version"] != version or row["state"] == "revoked":
            raise ConflictError("Provider revision changed or already revoked")
        db.execute(
            "UPDATE file_sandbox_providers SET state='revoked' WHERE id=?",
            (identifier,),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "file.sandbox.provider.revoke",
            {"id": identifier, "version": version, "reason": reason},
        )
        return _profile(_visible(db, actor, identifier))


def list_providers(store, who):
    with principal.transaction(store, who) as (db, actor):
        rows = db.execute(
            "SELECT * FROM file_sandbox_providers WHERE tenant=? ORDER BY created,id LIMIT ?",
            (actor["tenant"], MAX_PROVIDERS + 1),
        ).fetchall()
        if len(rows) > MAX_PROVIDERS:
            raise CapacityError("Provider list bound exceeded")
        result = []
        for row in rows:
            if not principal.contains(
                actor["allowed_indexes"], json.loads(row["indexes"])
            ):
                continue
            item = _profile(row)
            if item["effective_state"] == "active" and not _active(db, row):
                item["effective_state"] = "authority_changed"
            result.append(item)
        return result


def request_job(store, who, artifact_id, profile_id, *, ttl=3600):
    """Create a nonce-bound manifest. It does not submit the sample anywhere."""
    evidence.text(profile_id, "provider profile ID", 128)
    evidence.integer(ttl, "ttl", 60, 86400)
    with principal.transaction(store, who, ("admin", "analyst"), write=True) as (
        db,
        actor,
    ):
        provider = _visible(db, actor, profile_id)
        if not _active(db, provider):
            raise ConflictError(
                "Provider trust is unapproved, expired or authority changed"
            )
        artifact = db.execute(
            "SELECT * FROM endpoint_artifacts WHERE tenant=? AND id=?",
            (actor["tenant"], artifact_id),
        ).fetchone()
        if not artifact or not principal.contains(
            actor["allowed_indexes"], [artifact["index_name"]]
        ):
            raise KeyError("Artifact not found")
        principal.incident(db, actor, artifact["incident_id"])
        if artifact["index_name"] not in json.loads(provider["indexes"]):
            raise PermissionError("Artifact index exceeds provider trust scope")
        if artifact["state"] != "complete":
            raise ConflictError("Attested sandbox requires a completed artifact")
        _object(store, artifact)
        # Durable inventory/history has no lifetime record-count ceiling.
        identifier, now, nonce = str(uuid.uuid4()), time.time(), secrets.token_hex(32)
        expires = min(now + ttl, provider["expires"])
        db.execute(
            "INSERT INTO file_sandbox_jobs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                identifier,
                actor["tenant"],
                artifact["incident_id"],
                artifact_id,
                artifact["sha256"],
                encode([artifact["index_name"]]),
                provider["name"],
                actor["name"],
                "pending_attested",
                now,
                expires,
                None,
                None,
            ),
        )
        db.execute(
            "INSERT INTO file_sandbox_attestations VALUES(?,?,?,?,?,?,?)",
            (
                identifier,
                actor["tenant"],
                profile_id,
                provider["version"],
                provider["digest"],
                nonce,
                PROTOCOL,
            ),
        )
        manifest = {
            "protocol": PROTOCOL,
            "request_id": identifier,
            "nonce": nonce,
            "tenant": actor["tenant"],
            "artifact_id": artifact_id,
            "sha256": artifact["sha256"],
            "provider": provider["name"],
            "key_id": provider["key_id"],
            "profile_id": profile_id,
            "profile_version": provider["version"],
            "profile_digest": provider["digest"],
            "created": now,
            "expires": expires,
            "sample_sent": False,
            "provider_sample_pull_enabled": bool(provider["sample_access"]),
        }
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "file.sandbox.attested_request",
            {
                "id": identifier,
                "profile_id": profile_id,
                "profile_digest": provider["digest"],
                "sha256": artifact["sha256"],
                "sample_sent": False,
            },
        )
        return manifest


def _result(data):
    if not isinstance(data, dict) or set(data) != {
        "protocol",
        "request_id",
        "nonce",
        "tenant",
        "artifact_id",
        "sha256",
        "provider",
        "key_id",
        "provider_job_id",
        "verdict",
        "report_digest",
        "report",
        "observed_at",
        "signature",
    }:
        raise ValueError("Attested result requires the exact versioned protocol fields")
    if data["protocol"] != PROTOCOL:
        raise ValueError("Unsupported provider attestation protocol")
    for key in (
        "request_id",
        "tenant",
        "artifact_id",
        "provider",
        "key_id",
        "provider_job_id",
    ):
        evidence.text(data[key], key, 128)
    for key in ("sha256", "report_digest", "nonce"):
        if not isinstance(data[key], str) or not re.fullmatch(
            r"[0-9a-f]{64}", data[key]
        ):
            raise ValueError(key + " requires an exact lowercase 256-bit value")
    evidence.choice(
        data["verdict"],
        {"malicious", "suspicious", "benign", "unknown", "failed"},
        "provider verdict",
    )
    evidence.number(data["observed_at"], "observed_at", 0, time.time())
    report = data["report"]
    if not isinstance(report, dict) or set(report) != {"summary", "findings"}:
        raise ValueError("Provider report requires summary and bounded findings")
    evidence.text(report["summary"], "provider report summary", 2000)
    findings = report["findings"]
    if not isinstance(findings, list) or len(findings) > 128:
        raise ValueError("Provider report allows at most 128 findings")
    for finding in findings:
        if not isinstance(finding, dict) or set(finding) != {"category", "description"}:
            raise ValueError("Each provider finding requires category and description")
        evidence.text(finding["category"], "provider finding category", 128)
        evidence.text(finding["description"], "provider finding description", 2000)
    report_bytes = encode(report).encode()
    if len(report_bytes) > MAX_REPORT:
        raise ValueError("Provider report exceeds 64 KiB")
    if hashlib.sha256(report_bytes).hexdigest() != data["report_digest"]:
        raise ValueError("Provider report content does not match its exact digest")
    return {key: value for key, value in data.items() if key != "signature"}, _bytes(
        data["signature"], 64, "Ed25519 result signature"
    )


def complete_job(store, who, identifier, data, *, _service_profile=None):
    signed, signature = _result(data)
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        row = db.execute(
            "SELECT * FROM file_sandbox_jobs WHERE tenant=? AND id=?",
            (actor["tenant"], identifier),
        ).fetchone()
        binding = db.execute(
            "SELECT * FROM file_sandbox_attestations WHERE tenant=? AND job_id=?",
            (actor["tenant"], identifier),
        ).fetchone()
        if (
            not row
            or not binding
            or not principal.contains(
                actor["allowed_indexes"], json.loads(row["indexes"])
            )
        ):
            raise KeyError("Attested sandbox job not found")
        principal.incident(db, actor, row["incident_id"])
        if row["state"] != "pending_attested" or row["expires"] <= time.time():
            raise ConflictError("Attested job expired or already completed")
        provider = _visible(db, actor, binding["profile_id"])
        if _service_profile is not None and provider["id"] != _service_profile:
            raise PermissionError(
                "Provider service credential cannot access a different profile"
            )
        if (
            not _active(db, provider)
            or provider["version"] != binding["profile_version"]
            or provider["digest"] != binding["profile_digest"]
        ):
            raise ConflictError(
                "Provider trust or its authorities changed after request"
            )
        expected = {
            "protocol": binding["protocol"],
            "request_id": identifier,
            "nonce": binding["nonce"],
            "tenant": row["tenant"],
            "artifact_id": row["artifact_id"],
            "sha256": row["sha256"],
            "provider": row["provider"],
            "key_id": provider["key_id"],
        }
        if (
            any(signed[key] != value for key, value in expected.items())
            or not row["created"] <= signed["observed_at"] <= row["expires"]
        ):
            raise ValueError(
                "Signed result does not bind the exact request/sample/provider/interval"
            )
        try:
            Ed25519PublicKey.from_public_bytes(
                _provider_public_key(provider["public_key"])
            ).verify(signature, encode(signed).encode())
        except InvalidSignature:
            raise ValueError("Provider result signature verification failed") from None
        artifact = db.execute(
            "SELECT * FROM endpoint_artifacts WHERE tenant=? AND id=?",
            (actor["tenant"], row["artifact_id"]),
        ).fetchone()
        if (
            not artifact
            or artifact["state"] != "complete"
            or artifact["sha256"] != row["sha256"]
            or artifact["incident_id"] != row["incident_id"]
        ):
            raise ConflictError("Exact sandbox artifact changed after request")
        _object(store, artifact)
        # Durable inventory/history has no lifetime record-count ceiling.
        now = time.time()
        record_actor = (
            "sandbox-provider:" + _service_profile
            if _service_profile
            else actor["name"]
        )
        exported = (
            db.execute(
                "SELECT 1 FROM file_sandbox_sample_exports WHERE tenant=? AND job_id=?",
                (actor["tenant"], identifier),
            ).fetchone()
            is not None
        )
        result = {
            **signed,
            "signature": data["signature"],
            "signed_payload_sha256": hashlib.sha256(
                encode(signed).encode()
            ).hexdigest(),
            "id": identifier,
            "incident_id": row["incident_id"],
            "provider_signature_verified": True,
            "provider_profile_digest": provider["digest"],
            "public_key_sha256": hashlib.sha256(
                _bytes(provider["public_key"], 32, "provider public key")
            ).hexdigest(),
            "attribution": "authenticated provider result; provider verdict not independently confirmed by xSERA",
            "sample_executed_by_xsera": False,
            "sample_sent_by_xsera": exported,
            "result_received_via": "authenticated provider SDK"
            if _service_profile
            else "authenticated administrator import",
            "automatic_response": False,
            "ml_classification": None,
        }
        db.execute(
            "UPDATE file_sandbox_jobs SET state='completed_attested',finished=?,result=? WHERE id=?",
            (now, encode(result), identifier),
        )
        db.execute(
            "INSERT INTO file_verdict_runs VALUES(?,?,?,?,?,?,?,?,?)",
            (
                identifier,
                actor["tenant"],
                row["incident_id"],
                row["artifact_id"],
                row["sha256"],
                row["indexes"],
                record_actor,
                now,
                encode(result),
            ),
        )
        store.audit(
            db,
            actor["tenant"],
            record_actor,
            "file.sandbox.attested_result",
            {
                "id": identifier,
                "verdict": signed["verdict"],
                "report_digest": signed["report_digest"],
                "provider_signature_verified": True,
                "automatic_response": False,
            },
        )
        return {"id": identifier, "state": "completed_attested", "result": result}


def _service_credential(store, credential, action, request_id="", body_sha256=None):
    """Authenticate a scoped signing key, never a caller-supplied admin identity."""
    fields = {
        "protocol",
        "tenant",
        "profile_id",
        "key_id",
        "action",
        "request_id",
        "body_sha256",
        "nonce",
        "issued_at",
        "signature",
    }
    if not isinstance(credential, dict) or set(credential) != fields:
        raise PermissionError("Exact signed provider credential required")
    if (
        credential["protocol"] != ACCESS_PROTOCOL
        or credential["action"] != action
        or credential["request_id"] != request_id
    ):
        raise PermissionError("Provider credential is bound to a different operation")
    expected_body = body_sha256 or hashlib.sha256(b"").hexdigest()
    if credential["body_sha256"] != expected_body:
        raise PermissionError("Provider credential body digest mismatch")
    for key in ("tenant", "profile_id", "key_id"):
        evidence.text(credential[key], key, 128)
    nonce = credential["nonce"]
    if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{64}", nonce):
        raise PermissionError("Provider nonce requires 256 random bits encoded as hex")
    now = time.time()
    issued = evidence.number(
        credential["issued_at"], "provider credential issued_at", 0, now + 30
    )
    if issued < now - 60:
        raise PermissionError("Provider credential has expired")
    signature = _bytes(credential["signature"], 64, "provider access signature")
    payload = {key: value for key, value in credential.items() if key != "signature"}
    with store.write_lock, store.control() as db:
        db.execute("BEGIN IMMEDIATE")
        provider = db.execute(
            "SELECT * FROM file_sandbox_providers WHERE tenant=? AND id=?",
            (credential["tenant"], credential["profile_id"]),
        ).fetchone()
        if (
            not provider
            or not _active(db, provider)
            or provider["key_id"] != credential["key_id"]
            or not provider["sample_access"]
        ):
            raise PermissionError(
                "Provider SDK access is disabled, unapproved, expired or revoked"
            )
        try:
            Ed25519PublicKey.from_public_bytes(
                _provider_public_key(provider["public_key"])
            ).verify(signature, encode(payload).encode())
        except InvalidSignature:
            raise PermissionError(
                "Provider credential signature verification failed"
            ) from None
        db.execute(
            "DELETE FROM file_sandbox_access_nonces WHERE created<?", (now - 120,)
        )
        if db.execute(
            "SELECT 1 FROM file_sandbox_access_nonces WHERE tenant=? AND profile_id=? AND nonce=?",
            (provider["tenant"], provider["id"], nonce),
        ).fetchone():
            raise PermissionError("Provider credential nonce was already used")
        if (
            db.execute(
                "SELECT count(*) FROM file_sandbox_access_nonces WHERE tenant=? AND profile_id=?",
                (provider["tenant"], provider["id"]),
            ).fetchone()[0]
            >= 256
        ):
            raise CapacityError(
                "Provider access rate bound reached; retry after credential window"
            )
        db.execute(
            "INSERT INTO file_sandbox_access_nonces VALUES(?,?,?,?)",
            (provider["tenant"], provider["id"], nonce, now),
        )
        # The approver's current authority is intersected with exact approved
        # indexes. The service never receives that user's session or broad role.
        actor = principal.current(
            db,
            {
                "name": provider["approver"],
                "tenant": provider["tenant"],
                "role": "admin",
                "allowed_indexes": json.loads(provider["indexes"]),
            },
            ("admin",),
        )
        store.audit(
            db,
            provider["tenant"],
            "sandbox-provider:" + provider["id"],
            "file.sandbox.provider_access",
            {
                "action": action,
                "request_id": request_id,
                "credential_nonce_sha256": hashlib.sha256(nonce.encode()).hexdigest(),
            },
        )
        return actor, provider["id"]


def _service_job(db, actor, profile_id, identifier):
    provider = _visible(db, actor, profile_id)
    if not _active(db, provider) or not provider["sample_access"]:
        raise PermissionError("Provider sample access no longer authorized")
    row = db.execute(
        "SELECT * FROM file_sandbox_jobs WHERE tenant=? AND id=?",
        (actor["tenant"], identifier),
    ).fetchone()
    binding = db.execute(
        "SELECT * FROM file_sandbox_attestations WHERE tenant=? AND job_id=? AND profile_id=?",
        (actor["tenant"], identifier, profile_id),
    ).fetchone()
    if (
        not row
        or not binding
        or not principal.contains(actor["allowed_indexes"], json.loads(row["indexes"]))
    ):
        raise KeyError("Provider job not found in this exact credential scope")
    principal.incident(db, actor, row["incident_id"])
    if (
        row["state"] != "pending_attested"
        or row["expires"] <= time.time()
        or binding["profile_digest"] != provider["digest"]
        or binding["profile_version"] != provider["version"]
    ):
        raise ConflictError("Provider job expired, completed or trust changed")
    manifest = {
        "protocol": binding["protocol"],
        "request_id": identifier,
        "nonce": binding["nonce"],
        "tenant": row["tenant"],
        "artifact_id": row["artifact_id"],
        "sha256": row["sha256"],
        "provider": row["provider"],
        "key_id": provider["key_id"],
        "profile_id": profile_id,
        "profile_version": provider["version"],
        "profile_digest": provider["digest"],
        "created": row["created"],
        "expires": row["expires"],
        "provider_sample_pull_enabled": True,
    }
    return row, manifest


def poll_jobs(store, credential):
    actor, profile_id = _service_credential(store, credential, "poll")
    with principal.transaction(store, actor, ("admin",)) as (db, fresh):
        rows = db.execute(
            "SELECT j.id FROM file_sandbox_jobs j JOIN file_sandbox_attestations a ON a.job_id=j.id AND a.tenant=j.tenant WHERE j.tenant=? AND a.profile_id=? AND j.state='pending_attested' AND j.expires>? ORDER BY j.created,j.id LIMIT 20",
            (fresh["tenant"], profile_id, time.time()),
        ).fetchall()
        result = []
        for row in rows:
            try:
                _, manifest = _service_job(db, fresh, profile_id, row["id"])
            except KeyError:
                continue  # Current complete Case scope no longer permits export.
            result.append(manifest)
        return {
            "protocol": ACCESS_PROTOCOL,
            "jobs": result,
            "max_jobs": 20,
            "more_may_be_pending": len(rows) == 20,
            "sample_bytes_in_response": False,
        }


def sample_for_provider(store, credential, identifier):
    actor, profile_id = _service_credential(store, credential, "sample", identifier)
    with principal.transaction(store, actor, ("admin",), write=True) as (db, fresh):
        row, _ = _service_job(db, fresh, profile_id, identifier)
        artifact = db.execute(
            "SELECT * FROM endpoint_artifacts WHERE tenant=? AND id=?",
            (fresh["tenant"], row["artifact_id"]),
        ).fetchone()
        if (
            not artifact
            or artifact["state"] != "complete"
            or artifact["sha256"] != row["sha256"]
            or artifact["incident_id"] != row["incident_id"]
        ):
            raise ConflictError("Provider sample artifact changed")
        body = _object(store, artifact)
        db.execute(
            "INSERT OR IGNORE INTO file_sandbox_sample_exports VALUES(?,?,?,?,?)",
            (identifier, fresh["tenant"], profile_id, artifact["sha256"], time.time()),
        )
        store.audit(
            db,
            fresh["tenant"],
            "sandbox-provider:" + profile_id,
            "file.sandbox.sample_export",
            {
                "request_id": identifier,
                "sha256": artifact["sha256"],
                "bytes": len(body),
                "peer_approved_sample_access": True,
                "sample_executed_by_xsera": False,
            },
        )
        return body, artifact["sha256"]


def result_from_provider(store, credential, identifier, data):
    actor, profile_id = _service_credential(
        store,
        credential,
        "complete",
        identifier,
        hashlib.sha256(encode(data).encode()).hexdigest(),
    )
    return complete_job(store, actor, identifier, data, _service_profile=profile_id)
