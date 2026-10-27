"""Fail-closed pinned Ed25519 package measurements; not OS code signing.

The trust file is provisioned outside the downloaded archive. A signed archive
can never nominate its own trusted public key. Production requires the protected
cryptography prerequisite; only explicit local fixtures can omit signatures.
"""

import base64
import hashlib
import json
import os
import re
import time
from copy import deepcopy
from pathlib import Path
from urllib.parse import urlsplit


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate integrity JSON key")
        result[key] = value
    return result


def read_json(path, maximum=1024 * 1024):
    path = Path(path).expanduser().absolute()
    for entry in (path, *path.parents):
        if (
            entry.is_symlink()
            or getattr(os.lstat(entry), "st_file_attributes", 0) & 0x400
        ):
            raise ValueError("Integrity links are forbidden")
    with path.open("rb") as stream:
        body = stream.read(maximum + 1)
    if len(body) > maximum:
        raise ValueError("Integrity JSON size exceeds limit")
    return json.loads(body, object_pairs_hook=_pairs)


def verify_signature(manifest, trusted_keys):
    signature = manifest.get("signature")
    if (
        not isinstance(signature, dict)
        or set(signature) != {"algorithm", "key_id", "value"}
        or signature["algorithm"] != "Ed25519"
        or not isinstance(signature.get("key_id"), str)
        or not re.fullmatch(r"[0-9a-f]{32}", signature["key_id"])
        or not isinstance(signature.get("value"), str)
        or len(signature["value"]) > 128
    ):
        raise ValueError("Pinned Ed25519 signature is required")
    if (
        not isinstance(trusted_keys, dict)
        or not {"schema", "keys"} <= set(trusted_keys)
        or set(trusted_keys)
        - {"schema", "keys", "approval", "bootstrap", "revoked_key_ids"}
        or trusted_keys["schema"] != "xsera.agent.trust.v1"
        or not isinstance(trusted_keys["keys"], dict)
        or len(trusted_keys["keys"]) > 256
    ):
        raise ValueError("Invalid externally provisioned trust file")
    revoked = trusted_keys.get("revoked_key_ids", [])
    if (
        not isinstance(revoked, list)
        or len(revoked) > 256
        or any(
            not isinstance(k, str) or not re.fullmatch(r"[0-9a-f]{32}", k)
            for k in revoked
        )
        or len(set(revoked)) != len(revoked)
    ):
        raise ValueError("Invalid revoked package signer list")
    if signature["key_id"] in revoked:
        raise ValueError("Package signer has been revoked")
    key = trusted_keys["keys"].get(signature["key_id"])
    if not isinstance(key, str) or not re.fullmatch(r"[0-9a-f]{64}", key):
        raise ValueError("Package signer is not in the local trusted key set")
    if hashlib.sha256(bytes.fromhex(key)).hexdigest()[:32] != signature["key_id"]:
        raise ValueError("Trusted package signer fingerprint differs")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
            base64.b64decode(signature["value"], validate=True),
            canonical({k: v for k, v in manifest.items() if k != "signature"}),
        )
    except ImportError:
        raise ValueError(
            "Signed verification requires the local cryptography runtime"
        ) from None
    except (ValueError, TypeError, InvalidSignature):
        raise ValueError("Package signature verification failed") from None
    return signature["key_id"]


def verify(
    root,
    *,
    trust_file=None,
    require_signature=None,
    installed=False,
    development_fixture=False,
):
    root = Path(root).resolve()
    manifest = read_json(root / "manifest.json")
    if not isinstance(manifest, dict):
        raise ValueError("Invalid package file manifest")  # noqa: TRY004 -- Untrusted archive validation contract.
    expected = manifest.get("files")
    if (
        manifest.get("schema") != "sera.agent.package.v1"
        or not isinstance(expected, dict)
        or not 1 <= len(expected) <= 256
    ):
        raise ValueError("Invalid package file manifest")
    profile = manifest.get("distribution_profile", "production")
    if not isinstance(profile, str) or profile not in {
        "production",
        "development_fixture",
    }:
        raise ValueError("Unknown package distribution profile")
    if type(development_fixture) is not bool or (
        require_signature is not None and type(require_signature) is not bool
    ):
        raise ValueError("Integrity verification flags must be boolean")
    if profile == "production" and (development_fixture or require_signature is False):
        raise ValueError("Production package signature cannot be downgraded")
    if profile == "development_fixture" and not development_fixture:
        raise ValueError("Development fixture package is not a production distribution")
    require_signature = (
        profile == "production" if require_signature is None else require_signature
    )
    key_id = None
    if trust_file or require_signature:
        if not trust_file:
            raise ValueError("Signed mode requires an external trusted key file")
        trust_path = Path(trust_file).expanduser()
        if not trust_path.is_absolute():
            raise ValueError("External trust file must be absolute")
        if trust_path.resolve().is_relative_to(root):
            raise ValueError(
                "Trust file must be provisioned outside the package directory"
            )
        key_id = verify_signature(manifest, read_json(trust_path, 32768))
    for name, digest in expected.items():
        if (
            not isinstance(name, str)
            or "\\" in name
            or Path(name).is_absolute()
            or ".." in Path(name).parts
            or not name
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise ValueError("Invalid package member path or digest")
    selected = {
        n: h for n, h in expected.items() if not installed or n.startswith("Agent/")
    }
    if installed and not selected:
        raise ValueError("Installed package has no measured Agent members")
    actual = set()
    scan = root / "Agent" if installed else root
    for path in scan.rglob("*"):
        if (
            path.is_symlink()
            or getattr(os.lstat(path), "st_file_attributes", 0) & 0x400
        ):
            raise ValueError("Package links are forbidden")
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            if installed and ("__pycache__" in path.parts or path.suffix == ".pyc"):
                if profile == "production":
                    raise ValueError(
                        "Unmeasured bytecode is forbidden in a production installation"
                    )
                continue
            actual.add(relative)
    if actual != set(selected) | (set() if installed else {"manifest.json"}):
        raise ValueError("Package has missing or unexpected members")
    for name, digest in selected.items():
        path = root / name
        if (
            not path.resolve().is_relative_to(root)
            or hashlib.sha256(path.read_bytes()).hexdigest() != digest
        ):
            raise ValueError("Package member checksum mismatch")
    return {
        "state": "verified_signed" if key_id else "checksum_only",
        "profile": profile,
        "key_id": key_id,
        "manifest_digest": hashlib.sha256(canonical(manifest)).hexdigest(),
        "measured_files": len(selected),
        "release": manifest.get("release"),
        "os_code_signature": False,
        "hardware_attestation": False,
        "scope": "installed_agent_files" if installed else "archive_members",
        "measured_at": time.time(),
    }


class PackageIntegrity:
    def __init__(self, config, root=None):
        options = config.get("package_integrity", {})
        if not isinstance(options, dict) or set(options) - {
            "required",
            "trust_file",
            "profile",
        }:
            raise ValueError("Invalid package_integrity local configuration")
        self._source_config = config
        self._original_options = deepcopy(options)
        self.config = deepcopy(options)
        self.profile = options.get("profile", "production")
        if not isinstance(self.profile, str) or self.profile not in {
            "production",
            "development_fixture",
        }:
            raise ValueError("Unknown package integrity profile")
        self.required = options.get("required", True)
        if type(self.required) is not bool:
            raise ValueError("package_integrity.required must be boolean")
        if self.profile == "production" and not self.required:
            raise ValueError("Production integrity cannot be disabled")
        if self.profile == "development_fixture":
            parsed = urlsplit(config.get("endpoint_url", ""))
            if (
                self.required
                or parsed.scheme not in {"http", "https"}
                or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
                or parsed.username
                or parsed.password
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError(
                    "Development fixture integrity requires an explicit loopback endpoint and required=False"
                )
        self.root = Path(root) if root else Path(__file__).resolve().parent.parent
        if (
            self.profile == "development_fixture"
            and (self.root / "manifest.json").exists()
            and read_json(self.root / "manifest.json").get(
                "distribution_profile", "production"
            )
            != "development_fixture"
        ):
            raise ValueError(
                "Production package cannot be downgraded to a development fixture"
            )
        self.startup = self.measure()
        if self.required and self.startup["state"] != "verified_signed":
            raise ValueError(
                "Required pinned package integrity failed before agent startup"
            )

    def measure(self):
        try:
            if (
                self._source_config.get("package_integrity", {})
                != self._original_options
                or self.config != self._original_options
            ):
                raise ValueError("Integrity policy changed during runtime")
            return verify(
                self.root,
                trust_file=self.config.get("trust_file"),
                require_signature=self.required,
                installed=True,
                development_fixture=self.profile == "development_fixture",
            )
        except (OSError, ValueError, TypeError, RecursionError):
            return {
                "state": "failed" if self.required else "unavailable",
                "required": self.required,
                "profile": self.profile,
                "error": "package_signature_or_file_measurement_unavailable",
                "os_code_signature": False,
                "hardware_attestation": False,
                "measured_at": time.time(),
            }
