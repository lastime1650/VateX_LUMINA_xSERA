"""Scoped endpoint enrollment and secret-free generic source distributions.

Runtime collectors originate in the user-supplied XDR_V2/Agent tree. Packages
need an existing Python 3.10+ runtime; they are not signed standalone binaries.
"""

import hashlib
import io
import json
import os
import re
import secrets
import ssl
import time
import uuid
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import __version__, entities, pipeline, principal, xdr_bridge
from .storage import CapacityError, ConflictError, encode, normalize

ROOT = Path(__file__).with_name("endpoint_agent")
IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
PLATFORMS = ("windows", "linux")
COLLECTIONS = {
    "windows": [
        "user-mode process snapshots",
        "existing Sysmon/Security/Defender/CodeIntegrity Event Logs",
        "TCP polling",
    ],
    "linux": [
        "procfs process/TCP snapshots",
        "systemd journal",
        "existing auditd logs",
    ],
}
MAX_PACKAGE = 2 * 1024 * 1024
FILES = (
    "Agent/__init__.py",
    "Agent/core.py",
    "Agent/package_integrity.py",
    "Agent/requirements.txt",
    "Agent/memory_observability.py",
    "Agent/response.py",
    "Agent/operations.py",
    "Agent/process_artifact.py",
    "Agent/firewall_guard.py",
    "Agent/defense.py",
    "Agent/kernel_prevention.py",
    "Agent/windows_app_control.py",
    "Agent/windows_app_control_watchdog.py",
    "Agent/cli.py",
    "Agent/Windows/__init__.py",
    "Agent/Windows/main.py",
    "Agent/Windows/collector.py",
    "Agent/Windows/isolation_watchdog.py",
    "Agent/Windows/service.py",
    "Agent/Windows/tray.py",
    "Agent/Linux/__init__.py",
    "Agent/Linux/main.py",
    "Agent/Linux/collector.py",
    "Agent/Linux/isolation_watchdog.py",
    "install.ps1",
    "install.sh",
    "configure.py",
    "verify_package.py",
    "README.txt",
    "PROVENANCE.json",
)


def initialize(store):
    with store.control(local=True) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS endpoint_deployments(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,platform TEXT NOT NULL,
          host TEXT NOT NULL,index_name TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,
          token_digest TEXT,downloaded REAL,used REAL,revoked INTEGER NOT NULL DEFAULT 0);
        CREATE UNIQUE INDEX IF NOT EXISTS endpoint_enrollment_token ON endpoint_deployments(token_digest);
        CREATE TABLE IF NOT EXISTS endpoint_agents(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,platform TEXT NOT NULL,
          host TEXT NOT NULL,index_name TEXT NOT NULL,deployment_id TEXT NOT NULL,credential_digest TEXT NOT NULL UNIQUE,
          created REAL NOT NULL,expires REAL NOT NULL,last_seen REAL,health TEXT NOT NULL DEFAULT '{}',
          version TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);
        CREATE INDEX IF NOT EXISTS endpoint_agents_tenant ON endpoint_agents(tenant,host);
        CREATE TABLE IF NOT EXISTS endpoint_enrollment_recovery(
          token_digest TEXT PRIMARY KEY,recovery_digest TEXT NOT NULL,agent_id TEXT NOT NULL,
          expires REAL NOT NULL,nonce TEXT NOT NULL,response TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS endpoint_recovery_expiry ON endpoint_enrollment_recovery(expires);
        CREATE TABLE IF NOT EXISTS endpoint_credential_recovery(
          old_digest TEXT PRIMARY KEY,recovery_digest TEXT NOT NULL,agent_id TEXT NOT NULL,
          expires REAL NOT NULL,nonce TEXT NOT NULL,response TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS endpoint_rotation_expiry ON endpoint_credential_recovery(expires);
        CREATE TABLE IF NOT EXISTS endpoint_event_receipts(
          tenant TEXT NOT NULL,event_id TEXT NOT NULL,agent_id TEXT NOT NULL,index_name TEXT NOT NULL,
          payload_digest TEXT NOT NULL,receipt_digest TEXT NOT NULL,received REAL NOT NULL,
          PRIMARY KEY(tenant,event_id));
        CREATE INDEX IF NOT EXISTS endpoint_event_agent ON endpoint_event_receipts(agent_id,event_id);
        CREATE TRIGGER IF NOT EXISTS endpoint_event_receipt_delete AFTER DELETE ON receipts
        BEGIN
          DELETE FROM endpoint_event_receipts WHERE tenant=OLD.tenant AND event_id=OLD.event_id;
        END;
        """)


def _identity(value, label):
    if not isinstance(value, str) or not IDENTITY.fullmatch(value):
        raise ValueError(
            label + " must be 1..128 ASCII letters, digits, dot, underscore or hyphen"
        )
    return value


def _secret(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{30,160}", value):
        raise PermissionError("Endpoint credential is invalid")
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _encrypted_bytes(value):
    # Hex keeps replicated SQL parameters JSON-safe. Accept the candidate BLOB
    # representation only for short-lived interrupted-upgrade recovery.
    return bytes.fromhex(value) if isinstance(value, str) else bytes(value)


def load_config():
    url = os.environ.get("SAPIENTIA_AGENT_ENDPOINT_URL")
    ca = os.environ.get("SAPIENTIA_AGENT_CA_FILE")
    if not url and not ca:
        return None
    if (
        not url
        or not ca
        or len(url) > 2048
        or not url.isascii()
        or any(ord(c) < 33 for c in url)
    ):
        raise ValueError(
            "Agent distribution requires an HTTPS origin and a public CA PEM file"
        )
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("Invalid endpoint HTTPS port") from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError(
            "Agent endpoint must be a fixed HTTPS origin without credentials/path/query"
        )
    path = Path(ca)
    if not path.is_file() or path.stat().st_size > 256 * 1024:
        raise ValueError("Agent CA file is missing or exceeds 256 KiB")
    pem = path.read_bytes()
    if b"PRIVATE KEY" in pem or b"-----BEGIN CERTIFICATE-----" not in pem:
        raise ValueError("Agent CA file must contain public certificates only")
    try:
        ssl.create_default_context(cadata=pem.decode("ascii"))
    except (ValueError, UnicodeError, ssl.SSLError):
        raise ValueError(
            "Agent CA file is not a valid public PEM trust bundle"
        ) from None
    return {"endpoint_url": url.rstrip("/"), "ca_pem": pem}


def package(
    platform, deployment=None, token=None, config=None, *, development_fixture=False
):
    if platform not in PLATFORMS:
        raise ValueError("Platform must be windows or linux")
    if (
        type(development_fixture) is not bool
        or development_fixture
        and any(v is not None for v in (deployment, token, config))
    ):
        raise ValueError(
            "Development fixtures are generic packages without enrollment authority"
        )
    files = {}
    for name in FILES:
        # No browser-supplied archive path, executable, or arbitrary source traversal.
        if platform == "windows" and (
            name.startswith("Agent/Linux/") or name == "install.sh"
        ):
            continue
        if platform == "linux" and (
            name.startswith("Agent/Windows/") or name == "install.ps1"
        ):
            continue
        path = ROOT / name
        if (
            path.is_symlink()
            or not path.is_file()
            or not path.resolve().is_relative_to(ROOT.resolve())
        ):
            raise ValueError("Distribution source is unavailable")
        files[name] = path.read_bytes()
    if deployment is not None:
        if config is None or token is None:
            raise ValueError(
                "Scoped deployment requires configured HTTPS and enrollment"
            )
        files["deployment.json"] = encode(
            {
                "endpoint_url": config["endpoint_url"],
                "tenant": deployment["tenant"],
                "host": deployment["host"],
                "index": deployment["index_name"],
                "platform": platform,
                "expires_at": deployment["expires"],
            }
        ).encode()
        files["enrollment.token"] = token.encode("ascii")
        files["ca.pem"] = config["ca_pem"]
    manifest = {
        "schema": "sera.agent.package.v1",
        "distribution_profile": "development_fixture"
        if development_fixture
        else "production",
        "signature_required": not development_fixture,
        "release": __version__,
        "wire_version": 1,
        "native_qualified": False,
        "code_signed": False,
        "platform": platform,
        "runtime": "Python >=3.10 with pinned cryptography and defusedxml from Agent/requirements.txt; runtime not bundled",
        "files": {
            name: hashlib.sha256(data).hexdigest()
            for name, data in sorted(files.items())
        },
        "capabilities": [],
        "containment": False,
        "process_artifact_collection": {
            "supported": True,
            "default_enabled": False,
            "requires_local_opt_in": True,
            "requires_exact_executable_allowlist": True,
            "max_bytes": 32 * 1024 * 1024,
            "sample_execution": False,
            "process_memory_scan": False,
            "native_fleet_qualified": False,
        },
        "manual_response": {
            "default_enabled": False,
            "supported_actions": [
                "terminate_process",
                "delete_file",
                "inspect_process",
                "inspect_file",
                "collect_artifact",
                "quarantine_file",
                "restore_file",
                "isolate_host",
                "release_host",
            ],
            "persistent_execution_block": False,
            "requires": "explicit evidence-bound manual request and local opt-in/allowlists",
        },
        "kernel_prevention": {
            "default_enabled": False,
            "provider": "Windows App Control/UMCI"
            if platform == "windows"
            else "Linux fanotify FAN_OPEN_EXEC_PERM",
            "requires": "explicit local administrator opt-in and current peer-approved pinned signed hash rules",
            "scope": "finite owned native hash policy"
            if platform == "windows"
            else "immediate-child executable opens in explicitly selected private directories",
            "proprietary_driver": False,
        },
    }
    from . import release_integrity

    manifest = release_integrity.sign(manifest, development_fixture=development_fixture)
    files["manifest.json"] = json.dumps(manifest, sort_keys=True, indent=2).encode()
    if sum(len(data) for data in files.values()) > MAX_PACKAGE:
        raise CapacityError("Distribution package exceeds 2 MiB")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.external_attr = (0o700 if name.endswith(".sh") else 0o600) << 16
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)
    blob = output.getvalue()
    return (
        blob,
        hashlib.sha256(blob).hexdigest(),
        f"VATEX-LUMINA-xSERA-Agent-{platform}-python.zip",
    )


def _public_deployment(row):
    return {
        "id": row["id"],
        "tenant": row["tenant"],
        "platform": row["platform"],
        "host": row["host"],
        "index": row["index_name"],
        "expires_at": row["expires"],
        "created": row["created"],
        "status": "revoked"
        if row["revoked"]
        else "registered"
        if row["used"]
        else "expired"
        if row["expires"] <= time.time()
        else "pending",
        "package_url": "/api/xdr/agents/deployments/" + row["id"] + "/package",
    }


def _bounded_listing(db, actor, table):
    if table not in {"endpoint_agents", "endpoint_deployments"}:
        raise ValueError("Unknown endpoint listing")
    where, args = "tenant=?", [actor["tenant"]]
    if actor["allowed_indexes"] != ["*"]:
        scope = actor["allowed_indexes"]
        where += " AND index_name IN (" + (",".join("?" for _ in scope) or "NULL") + ")"
        args.extend(scope)
    pending = " AND used IS NULL" if table == "endpoint_deployments" else ""
    rows = db.execute(
        "SELECT * FROM "
        + table
        + " WHERE "
        + where
        + " ORDER BY CASE WHEN revoked=0 AND expires>?"
        + pending
        + " THEN 0 ELSE 1 END,created DESC,id DESC",
        [*args, time.time()],
    ).fetchall()
    return rows, {
        "count": len(rows),
        "limit": None,
        "truncated": False,
        "total_at_least": len(rows),
        "total": len(rows),
        "order": "usable registrations/deployments first, then latest creation; complete history",
    }


class Distribution:
    def __init__(self, store, config=None):
        self.store, self.config = store, config

    def status(self):
        from . import release_integrity

        signing = release_integrity.status()
        packages = []
        for platform in PLATFORMS if signing["available"] else ():
            blob, digest, filename = package(platform)
            packages.append(
                {
                    "platform": platform,
                    "filename": filename,
                    "url": "/api/xdr/agents/packages/" + platform,
                    "sha256": digest,
                    "size": len(blob),
                }
            )
        return {
            "package_format": "python-source-zip",
            "python_minimum": "3.10",
            "generic_packages": packages,
            "deployment_enabled": self.config is not None and signing["available"],
            "signing": signing,
            "endpoint_url": self.config["endpoint_url"] if self.config else None,
            "reason": signing.get("reason")
            if not signing["available"]
            else None
            if self.config
            else "Configure server HTTPS origin and public CA to issue bound enrollments; signed generic runtime downloads remain available",
            "remote_commands": False,
            "containment": False,
            "capabilities": [],
            "manual_response": {
                "available": True,
                "default_enabled": False,
                "actions": [
                    "terminate_process",
                    "delete_file",
                    "inspect_process",
                    "inspect_file",
                    "collect_artifact",
                    "quarantine_file",
                    "restore_file",
                    "isolate_host",
                    "release_host",
                ],
                "persistent_execution_block": False,
                "requires": "case evidence, current ACL, explicit manual confirmation, local opt-in/allowlists",
                "native_attestation": False,
                "host_isolation": "finite OS firewall lease with exact management TCP allowlist and independently armed rollback; native qualification is separate evidence",
            },
            "kernel_prevention": {
                "default_enabled": False,
                "windows": "finite owned Windows App Control/UMCI native hash policy; audit-first, explicit enforcement",
                "linux": "fanotify executable permission gate for explicitly selected private directories",
                "requires": "explicit local administrator opt-in and current peer-approved pinned signed hash rules",
                "proprietary_driver": False,
            },
            "collections": COLLECTIONS,
            "prerequisites": {
                "windows": "Administrator; installed Python 3.10+ with cryptography and defusedxml; external public trust pin; SCM service; optional existing Sysmon",
                "linux": "root; installed Python 3.10+ with cryptography and defusedxml; external public trust pin; systemd; optional existing auditd",
            },
            "limits": [
                "Source runtime package; no signed standalone EXE/MSI/ELF bundled",
                "User-mode polling can miss short-lived processes; native Event Log/auditd availability is separately reported; no proprietary kernel/eBPF driver or crash-proof anti-tamper",
                "Bounded typed investigation, process/file effects and OS firewall isolation require explicit local opt-in and allowlists (default OFF); no arbitrary shell or permanent pre-execution block",
                "Optional signed kernel prevention requires explicit local scope and pinned cryptography; Windows policies expire without automatic renewal, Linux permission blocking ends if its listener exits",
                "Provider health is agent-reported; source packages and static capabilities do not establish native OS qualification or hardware attestation",
                "Checksums detect corruption; they are not an independent code signature",
            ],
        }

    def create(self, who, data):
        if self.config is None:
            raise ValueError(
                "HTTPS agent deployment is not configured; download the generic runtime package"
            )
        from . import release_integrity

        release_integrity.public_identity()
        if not isinstance(data, dict) or set(data) - {
            "platform",
            "host",
            "index",
            "ttl_seconds",
        }:
            raise ValueError("Expected platform, host, index and optional ttl_seconds")
        platform = data.get("platform")
        if platform not in PLATFORMS:
            raise ValueError("Platform must be windows or linux")
        host = _identity(data.get("host"), "host")
        index = entities.exact_indexes([data.get("index")])[0]
        ttl = data.get("ttl_seconds", 600)
        if type(ttl) is not int or not 60 <= ttl <= 3600:
            raise ValueError("Enrollment lifetime must be 60..3600 seconds")
        now, identifier = time.time(), "DEP-" + uuid.uuid4().hex
        with principal.transaction(self.store, who, ("admin",), write=True) as (
            db,
            actor,
        ):
            if not principal.contains(actor["allowed_indexes"], [index]):
                raise PermissionError("Deployment index exceeds current permissions")
            # Durable inventory/history has no lifetime record-count ceiling.
            db.execute(
                "INSERT INTO endpoint_deployments(id,tenant,owner,platform,host,index_name,created,expires) VALUES(?,?,?,?,?,?,?,?)",
                (
                    identifier,
                    actor["tenant"],
                    actor["name"],
                    platform,
                    host,
                    index,
                    now,
                    now + ttl,
                ),
            )
            self.store.audit(
                db,
                actor["tenant"],
                actor["name"],
                "endpoint.deployment.create",
                {"id": identifier, "host": host, "index": index, "platform": platform},
            )
            row = db.execute(
                "SELECT * FROM endpoint_deployments WHERE id=?", (identifier,)
            ).fetchone()
            return _public_deployment(row)

    def deployments(self, who):
        with principal.transaction(self.store, who, ("admin",)) as (db, actor):
            rows, metadata = _bounded_listing(db, actor, "endpoint_deployments")
            return {"deployments": [_public_deployment(r) for r in rows], **metadata}

    def download(self, who, identifier):
        if self.config is None:
            raise ValueError("HTTPS deployment is not configured")
        with principal.transaction(self.store, who, ("admin",), write=True) as (
            db,
            actor,
        ):
            row = db.execute(
                "SELECT * FROM endpoint_deployments WHERE id=? AND tenant=?",
                (identifier, actor["tenant"]),
            ).fetchone()
            if not row or not principal.contains(
                actor["allowed_indexes"], [row["index_name"]]
            ):
                raise KeyError("Deployment not found")
            if row["owner"] != actor["name"]:
                raise PermissionError(
                    "Only the deployment owner can download its scoped enrollment"
                )
            if row["revoked"] or row["used"] or row["expires"] <= time.time():
                raise ConflictError("Deployment is consumed, revoked or expired")
            token = secrets.token_urlsafe(32)
            result = package(row["platform"], row, token, self.config)
            db.execute(
                "UPDATE endpoint_deployments SET token_digest=?,downloaded=? WHERE id=?",
                (_secret(token), time.time(), identifier),
            )
            self.store.audit(
                db,
                actor["tenant"],
                actor["name"],
                "endpoint.package.download",
                {"id": identifier, "sha256": result[1]},
            )
            return result

    def enroll(self, data):
        if self.config is None:
            raise PermissionError("Endpoint enrollment is disabled")
        if (
            not isinstance(data, dict)
            or not {"enrollment_token", "version"} <= set(data)
            or set(data) - {"enrollment_token", "version", "recovery_key"}
        ):
            raise ValueError(
                "Expected enrollment_token, version and optional recovery_key"
            )
        digest = _secret(data["enrollment_token"])
        recovery_key = data.get("recovery_key")
        if recovery_key is not None and (
            not isinstance(recovery_key, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{43}", recovery_key)
        ):
            raise ValueError("Recovery key must be a client-generated 256-bit secret")
        version = (
            _identity(data["version"].replace("/", "-"), "version")
            if isinstance(data["version"], str)
            else _identity(None, "version")
        )
        now = time.time()
        with self.store.write_lock, self.store.control() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "DELETE FROM endpoint_enrollment_recovery WHERE expires<=?", (now,)
            )
            recovery = db.execute(
                "SELECT * FROM endpoint_enrollment_recovery WHERE token_digest=?",
                (digest,),
            ).fetchone()
            if recovery:
                if recovery_key is None or not secrets.compare_digest(
                    recovery["recovery_digest"], _secret(recovery_key)
                ):
                    raise PermissionError("Enrollment recovery proof is invalid")
                agent = db.execute(
                    "SELECT * FROM endpoint_agents WHERE id=?", (recovery["agent_id"],)
                ).fetchone()
                if not agent or agent["revoked"] or agent["expires"] <= now:
                    raise PermissionError("Enrollment recovery is revoked or expired")
                self._owner(db, agent)
                cipher = AESGCM(hashlib.sha256(recovery_key.encode("ascii")).digest())
                result = json.loads(
                    cipher.decrypt(
                        _encrypted_bytes(recovery["nonce"]),
                        _encrypted_bytes(recovery["response"]),
                        (digest + ":" + agent["id"]).encode(),
                    )
                )
                if _secret(result["credential"]) != agent["credential_digest"]:
                    raise PermissionError(
                        "Recovered enrollment credential is no longer current"
                    )
                self.store.audit(
                    db,
                    agent["tenant"],
                    agent["id"],
                    "endpoint.register.recovered",
                    {"host": agent["host"], "index": agent["index_name"]},
                )
                return result
            row = db.execute(
                "SELECT * FROM endpoint_deployments WHERE token_digest=?", (digest,)
            ).fetchone()
            if not row or row["used"] or row["revoked"] or row["expires"] <= now:
                raise PermissionError(
                    "Enrollment is invalid, consumed, revoked or expired"
                )
            self._owner(db, row)
            if (
                db.execute(
                    "SELECT count(*) FROM endpoint_agents WHERE tenant=? AND revoked=0 AND expires>?",
                    (row["tenant"], now),
                ).fetchone()[0]
                >= 1000
            ):
                raise CapacityError(
                    "Tenant has 1000 active endpoint credentials; revoke retired agents"
                )
            if db.execute(
                "SELECT 1 FROM endpoint_agents WHERE tenant=? AND host=? AND revoked=0 AND expires>?",
                (row["tenant"], row["host"], now),
            ).fetchone():
                raise ConflictError(
                    "An active agent already owns this tenant/host; revoke it first"
                )
            credential, identifier = (
                secrets.token_urlsafe(40),
                "AGT-" + uuid.uuid4().hex,
            )
            db.execute(
                "INSERT INTO endpoint_agents(id,tenant,owner,platform,host,index_name,deployment_id,credential_digest,created,expires,last_seen,version) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    identifier,
                    row["tenant"],
                    row["owner"],
                    row["platform"],
                    row["host"],
                    row["index_name"],
                    row["id"],
                    _secret(credential),
                    now,
                    now + 90 * 86400,
                    now,
                    version,
                ),
            )
            db.execute(
                "UPDATE endpoint_deployments SET used=?,token_digest=NULL WHERE id=?",
                (now, row["id"]),
            )
            self.store.audit(
                db,
                row["tenant"],
                identifier,
                "endpoint.register",
                {"host": row["host"], "index": row["index_name"]},
            )
            result = {
                "agent_id": identifier,
                "credential": credential,
                "tenant": row["tenant"],
                "host": row["host"],
                "index": row["index_name"],
                "expires_at": now + 90 * 86400,
                "capabilities": [],
            }
            if recovery_key is not None:
                nonce = secrets.token_bytes(12)
                cipher = AESGCM(hashlib.sha256(recovery_key.encode("ascii")).digest())
                encrypted = cipher.encrypt(
                    nonce, encode(result).encode(), (digest + ":" + identifier).encode()
                )
                db.execute(
                    "INSERT INTO endpoint_enrollment_recovery VALUES(?,?,?,?,?,?)",
                    (
                        digest,
                        _secret(recovery_key),
                        identifier,
                        now + 600,
                        nonce.hex(),
                        encrypted.hex(),
                    ),
                )
            return result

    def renew(self, credential, data):
        if (
            not isinstance(data, dict)
            or set(data) != {"recovery_key"}
            or not isinstance(data["recovery_key"], str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{43}", data["recovery_key"])
        ):
            raise ValueError("Renewal requires a client-generated 256-bit recovery key")
        old_digest, key, now = _secret(credential), data["recovery_key"], time.time()
        with self.store.write_lock, self.store.control() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "DELETE FROM endpoint_credential_recovery WHERE expires<=?", (now,)
            )
            cached = db.execute(
                "SELECT * FROM endpoint_credential_recovery WHERE old_digest=?",
                (old_digest,),
            ).fetchone()
            if cached:
                if not secrets.compare_digest(cached["recovery_digest"], _secret(key)):
                    raise PermissionError(
                        "Credential renewal recovery proof is invalid"
                    )
                agent = db.execute(
                    "SELECT * FROM endpoint_agents WHERE id=?", (cached["agent_id"],)
                ).fetchone()
                if not agent or agent["revoked"] or agent["expires"] <= now:
                    raise PermissionError("Credential renewal is revoked or expired")
                self._owner(db, agent)
                result = json.loads(
                    AESGCM(hashlib.sha256(key.encode()).digest()).decrypt(
                        _encrypted_bytes(cached["nonce"]),
                        _encrypted_bytes(cached["response"]),
                        (old_digest + ":" + agent["id"]).encode(),
                    )
                )
                if _secret(result["credential"]) != agent["credential_digest"]:
                    raise PermissionError("Recovered credential is no longer current")
                return result
            agent = self._agent(db, credential)
            if db.execute(
                "SELECT 1 FROM endpoint_credential_recovery WHERE agent_id=? AND expires>?",
                (agent["id"], now),
            ).fetchone():
                raise ConflictError(
                    "A recent credential rotation is still in its recovery window"
                )
            if (
                db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='endpoint_responses'"
                ).fetchone()
                and db.execute(
                    "SELECT 1 FROM endpoint_responses WHERE agent_id=? AND (state IN ('claimed','started') OR (execution_id IS NOT NULL AND result IS NULL)) LIMIT 1",
                    (agent["id"],),
                ).fetchone()
            ):
                raise ConflictError(
                    "Report outstanding command effects before credential rotation"
                )
            new = secrets.token_urlsafe(40)
            result = {
                "agent_id": agent["id"],
                "credential": new,
                "tenant": agent["tenant"],
                "host": agent["host"],
                "index": agent["index_name"],
                "expires_at": now + 90 * 86400,
            }
            nonce = secrets.token_bytes(12)
            encrypted = AESGCM(hashlib.sha256(key.encode()).digest()).encrypt(
                nonce,
                encode(result).encode(),
                (old_digest + ":" + agent["id"]).encode(),
            )
            db.execute(
                "UPDATE endpoint_agents SET credential_digest=?,expires=? WHERE id=?",
                (_secret(new), result["expires_at"], agent["id"]),
            )
            db.execute(
                "INSERT INTO endpoint_credential_recovery VALUES(?,?,?,?,?,?)",
                (
                    old_digest,
                    _secret(key),
                    agent["id"],
                    now + 600,
                    nonce.hex(),
                    encrypted.hex(),
                ),
            )
            self.store.audit(
                db,
                agent["tenant"],
                agent["id"],
                "endpoint.credential.rotate",
                {"host": agent["host"], "index": agent["index_name"]},
            )
            return result

    def _owner(self, db, row):
        actor = principal.current(
            db,
            {
                "name": row["owner"],
                "tenant": row["tenant"],
                "role": "admin",
                "allowed_indexes": [row["index_name"]],
            },
            ("admin",),
        )
        if not principal.contains(actor["allowed_indexes"], [row["index_name"]]):
            raise PermissionError(
                "Enrollment owner no longer permits this endpoint index"
            )
        return actor

    def _agent(self, db, credential):
        row = db.execute(
            "SELECT * FROM endpoint_agents WHERE credential_digest=?",
            (_secret(credential),),
        ).fetchone()
        if not row or row["revoked"] or row["expires"] <= time.time():
            raise PermissionError("Endpoint credential is invalid, revoked or expired")
        self._owner(db, row)
        return row

    def heartbeat(self, credential, data):
        if (
            not isinstance(data, dict)
            or set(data) != {"health"}
            or not isinstance(data["health"], dict)
            or len(encode(data).encode()) > 4096
        ):
            raise ValueError("Expected a health object of at most 4 KiB")
        with self.store.write_lock, self.store.control() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._agent(db, credential)
            db.execute(
                "UPDATE endpoint_agents SET last_seen=?,health=? WHERE id=?",
                (time.time(), encode(data["health"]), row["id"]),
            )
        return {
            "server_time": time.time(),
            "poll_after_seconds": 30,
            "capabilities": [],
        }

    def poll(self, credential, data):
        from . import endpoint_response

        return endpoint_response.poll(self.store, self, credential, data)

    def response_ack(self, credential, data):
        from . import endpoint_response

        return endpoint_response.ack(self.store, self, credential, data)

    def response_result(self, credential, data):
        from . import endpoint_response

        return endpoint_response.result(self.store, self, credential, data)

    def ingest(self, credential, data):
        if (
            not isinstance(data, dict)
            or set(data) != {"events"}
            or not isinstance(data["events"], list)
            or not 1 <= len(data["events"]) <= 200
        ):
            raise ValueError("Expected 1..200 endpoint events")
        if any(
            not isinstance(event, dict) or set(event) != {"id", "data"}
            for event in data["events"]
        ):
            raise ValueError(
                "Endpoint envelopes contain only id and data; tenant/index are server-bound"
            )
        with self.store.write_lock:
            with self.store.control() as db:
                row = self._agent(db, credential)
                records = [
                    xdr_bridge.parse_event(
                        event, "agent", row["index_name"], expected_host=row["host"]
                    )
                    for event in data["events"]
                ]
                policies = pipeline.for_ingest(db, row["tenant"])
                for record in records:
                    routed, _ = pipeline.apply(
                        normalize(record), policies.get(record["source"])
                    )
                    if routed["index"] != row["index_name"]:
                        raise PermissionError(
                            "Parser route differs from the endpoint's bound index"
                        )
                tenant, agent_id = row["tenant"], row["id"]

            def admission_scope(db):
                fresh = self._agent(db, credential)
                if (
                    fresh["id"] != agent_id
                    or fresh["tenant"] != tenant
                    or fresh["host"] != row["host"]
                    or fresh["index_name"] != row["index_name"]
                ):
                    raise PermissionError("Endpoint binding changed during admission")
                return [fresh["index_name"]]

            def authenticated_origin(db, durable_records, incoming_ids, received):
                new = {record[1]: record for record in durable_records}
                for identifier in dict.fromkeys(incoming_ids):
                    receipt = db.execute(
                        "SELECT digest,received FROM receipts WHERE tenant=? AND event_id=?",
                        (tenant, identifier),
                    ).fetchone()
                    if not receipt:
                        raise PermissionError(
                            "Endpoint source requires a durable admission receipt"
                        )
                    if identifier in new:
                        bound_tenant, _, payload, original_received = new[identifier]
                        final = json.loads(payload)
                        if (
                            bound_tenant != tenant
                            or final.get("index") != row["index_name"]
                            or final.get("host") != row["host"]
                            or original_received != received
                            or receipt["received"] != received
                        ):
                            raise PermissionError(
                                "Endpoint normalized payload binding differs"
                            )
                        db.execute(
                            "INSERT INTO endpoint_event_receipts VALUES(?,?,?,?,?,?,?) ON CONFLICT(tenant,event_id) DO UPDATE SET agent_id=excluded.agent_id,index_name=excluded.index_name,payload_digest=excluded.payload_digest,receipt_digest=excluded.receipt_digest,received=excluded.received",
                            (
                                tenant,
                                identifier,
                                agent_id,
                                final["index"],
                                hashlib.sha256(payload.encode()).hexdigest(),
                                receipt["digest"],
                                receipt["received"],
                            ),
                        )
                    else:
                        proof = db.execute(
                            "SELECT * FROM endpoint_event_receipts WHERE tenant=? AND event_id=?",
                            (tenant, identifier),
                        ).fetchone()
                        if (
                            not proof
                            or proof["agent_id"] != agent_id
                            or proof["index_name"] != row["index_name"]
                            or proof["receipt_digest"] != receipt["digest"]
                            or proof["received"] != receipt["received"]
                        ):
                            # An authenticated agent retry cannot retroactively
                            # promote an existing generic/imported event to a
                            # credential-bound native-source receipt.
                            raise PermissionError(
                                "Existing event has no matching authenticated endpoint origin"
                            )

                from . import source_registry

                source_registry.native_origin(db, tenant, agent_id, incoming_ids)

            admission_scope.on_admitted = authenticated_origin

            result = self.store.ingest(
                tenant,
                records,
                agent_id,
                allowed_indexes=[row["index_name"]],
                authorization=admission_scope,
            )
            with self.store.control() as db:
                quarantined = {
                    r[0]
                    for r in db.execute(
                        "SELECT event_id FROM ingest_quarantine WHERE tenant=? AND event_id IN ("
                        + ",".join("?" for _ in records)
                        + ")",
                        [tenant, *[r["event_id"] for r in records]],
                    )
                }
                db.execute(
                    "UPDATE endpoint_agents SET last_seen=? WHERE id=?",
                    (time.time(), agent_id),
                )
            result["results"] = [
                {"id": event["id"], "quarantined": record["event_id"] in quarantined}
                for event, record in zip(data["events"], records)
            ]
            return result

    def agents(self, who):
        with principal.transaction(self.store, who) as (db, actor):
            rows, metadata = _bounded_listing(db, actor, "endpoint_agents")
            result = []
            for row in rows:
                if not principal.contains(
                    actor["allowed_indexes"], [row["index_name"]]
                ):
                    continue
                item = {
                    k: row[k]
                    for k in (
                        "id",
                        "tenant",
                        "platform",
                        "host",
                        "version",
                        "created",
                        "expires",
                        "last_seen",
                    )
                }
                item.update(
                    index=row["index_name"],
                    health=json.loads(row["health"]),
                    capabilities=[],
                    collections=COLLECTIONS[row["platform"]],
                    status="revoked"
                    if row["revoked"]
                    else "expired"
                    if row["expires"] <= time.time()
                    else "online"
                    if row["last_seen"] and row["last_seen"] > time.time() - 90
                    else "stale",
                )
                try:
                    self._owner(db, row)
                except PermissionError:
                    item["status"] = "owner_permission_revoked"
                result.append(item)
            return {"agents": result, **metadata}

    def revoke(self, who, identifier):
        with principal.transaction(self.store, who, ("admin",), write=True) as (
            db,
            actor,
        ):
            row = db.execute(
                "SELECT * FROM endpoint_agents WHERE id=? AND tenant=?",
                (identifier, actor["tenant"]),
            ).fetchone()
            if not row or not principal.contains(
                actor["allowed_indexes"], [row["index_name"]]
            ):
                raise KeyError("Agent not found")
            db.execute("UPDATE endpoint_agents SET revoked=1 WHERE id=?", (identifier,))
            db.execute(
                "UPDATE endpoint_responses SET state=CASE WHEN state='started' THEN 'unknown' ELSE 'cancelled' END,error='agent_revoked',finished=? WHERE agent_id=? AND state IN ('queued','claimed','started')",
                (time.time(), identifier),
            )
            self.store.audit(
                db,
                actor["tenant"],
                actor["name"],
                "endpoint.revoke",
                {"agent_id": identifier},
            )
            return {"revoked": True, "id": identifier}
