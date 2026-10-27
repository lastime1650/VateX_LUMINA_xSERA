"""Verify archive members and mandatory externally pinned Ed25519 signatures."""

import argparse
import base64
import hashlib
import json
import os
import re
from pathlib import Path


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate integrity JSON key")
        result[key] = value
    return result


def _json(path, maximum):
    path = Path(path).expanduser().absolute()
    for item in (path, *path.parents):
        if (
            item.is_symlink()
            or getattr(os.lstat(item), "st_file_attributes", 0) & 0x400
        ):
            raise ValueError("Integrity links are forbidden")
    with path.open("rb") as stream:
        value = stream.read(maximum + 1)
    if len(value) > maximum:
        raise ValueError("Integrity JSON size exceeds limit")
    return json.loads(value, object_pairs_hook=_pairs)


def _signature(manifest, trust_file, root):
    # This independently trusted bootstrap must never import executable code
    # from an unverified archive, even its package_integrity.py member.
    if not trust_file or not Path(trust_file).is_absolute():
        raise ValueError("Signed mode requires an external absolute trusted-key file")
    trust_path = Path(trust_file).expanduser()
    trust = _json(trust_path, 32768)
    if trust_path.resolve().is_relative_to(root):
        raise ValueError("Trust file must be outside the package directory")
    signature = manifest.get("signature")
    if (
        not isinstance(signature, dict)
        or set(signature) != {"algorithm", "key_id", "value"}
        or signature["algorithm"] != "Ed25519"
        or not isinstance(signature["key_id"], str)
        or not re.fullmatch(r"[0-9a-f]{32}", signature["key_id"])
        or not isinstance(signature["value"], str)
        or len(signature["value"]) > 128
    ):
        raise ValueError("Pinned Ed25519 signature is required")
    if (
        not isinstance(trust, dict)
        or not {"schema", "keys"} <= set(trust)
        or set(trust) - {"schema", "keys", "approval", "bootstrap", "revoked_key_ids"}
        or trust["schema"] != "xsera.agent.trust.v1"
        or not isinstance(trust["keys"], dict)
        or len(trust["keys"]) > 256
    ):
        raise ValueError("Invalid externally provisioned trust file")
    revoked = trust.get("revoked_key_ids", [])
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
    public = trust["keys"].get(signature["key_id"])
    if not isinstance(public, str) or not re.fullmatch(r"[0-9a-f]{64}", public):
        raise ValueError("Package signer is not in the local trusted key set")
    if hashlib.sha256(bytes.fromhex(public)).hexdigest()[:32] != signature["key_id"]:
        raise ValueError("Trusted package signer fingerprint differs")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        data = json.dumps(
            {k: v for k, v in manifest.items() if k != "signature"},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(
            base64.b64decode(signature["value"], validate=True), data
        )
    except ImportError:
        raise ValueError(
            "Signed verification requires the local cryptography runtime"
        ) from None
    except (ValueError, TypeError, InvalidSignature):
        raise ValueError("Package signature verification failed") from None


def verify(
    root, trusted_keys=None, require_signature=None, *, development_fixture=False
):
    root = Path(root).resolve()
    manifest = _json(root / "manifest.json", 1024 * 1024)
    if not isinstance(manifest, dict):
        raise ValueError("Invalid agent package manifest")  # noqa: TRY004 -- Untrusted archive validation contract.
    expected = manifest.get("files")
    if manifest.get("schema") != "sera.agent.package.v1" or not isinstance(
        expected, dict
    ):
        raise ValueError("Invalid agent package manifest")
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
    if development_fixture != (profile == "development_fixture"):
        raise ValueError(
            "Production and development fixture profiles cannot be interchanged"
        )
    configured = os.environ.get("SERA_AGENT_REQUIRE_SIGNED_PACKAGE", "1")
    if not development_fixture and (configured != "1" or require_signature is False):
        raise ValueError("Production verification cannot disable package signatures")
    required = (
        not development_fixture if require_signature is None else require_signature
    )
    trust_file = trusted_keys or os.environ.get("SERA_AGENT_TRUSTED_KEYS_FILE")
    if required or trust_file:
        _signature(manifest, trust_file, root)
    actual = set()
    for path in root.rglob("*"):
        if (
            path.is_symlink()
            or getattr(os.lstat(path), "st_file_attributes", 0) & 0x400
        ):
            raise ValueError("Symbolic links are forbidden in an agent package")
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
    if actual != set(expected) | {"manifest.json"}:
        raise ValueError(
            "Agent package contains missing or unexpected files; extract into a fresh directory"
        )
    for name, digest in expected.items():
        path = root / name
        if (
            Path(name).is_absolute()
            or ".." in Path(name).parts
            or not path.resolve().is_relative_to(root)
        ):
            raise ValueError("Invalid package member path")
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError("Agent package checksum mismatch: " + name)
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--development-fixture",
        action="store_true",
        help="Checksum-inspect only an explicitly marked unbound development fixture; not an installation mode",
    )
    args = parser.parse_args()
    verify(Path(__file__).parent, development_fixture=args.development_fixture)
    print(
        "Package signature policy and members verified. Independently trust the verifier bootstrap and external signer pin; this is not OS code signing."
    )
