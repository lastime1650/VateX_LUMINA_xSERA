"""Configure a protected fresh install and consume its one-time token from file."""

import argparse
import hashlib
import json
import os
import platform
import re
import ssl
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from Agent.core import atomic_json, enroll
from Agent.package_integrity import read_json, verify


def _integrity(root, settings, token_file, ca_file):
    if os.environ.get("SERA_AGENT_REQUIRE_SIGNED_PACKAGE", "1") != "1":
        raise ValueError("Production installation cannot disable package signatures")
    trust = os.environ.get("SERA_AGENT_TRUSTED_KEYS_FILE")
    if not trust or not Path(trust).is_absolute():
        raise ValueError(
            "Production installation requires an external absolute trusted-key file"
        )
    verify(root, trust_file=trust, require_signature=True, installed=True)
    manifest = read_json(root / "manifest.json")
    for name, path in (
        ("configure.py", root / "configure.py"),
        ("deployment.json", Path(settings)),
        ("enrollment.token", Path(token_file)),
        ("ca.pem", Path(ca_file)),
    ):
        if manifest["files"].get(name) != hashlib.sha256(path.read_bytes()).hexdigest():
            raise ValueError(
                "Installation input differs from the signed scoped package: " + name
            )
    return {
        "profile": "production",
        "required": True,
        "trust_file": str(Path(trust).absolute()),
    }


def configure(directory, settings, token_file, ca_file):
    if sys.version_info < (3, 10):  # noqa: UP036 -- Package is independent of server Python minimum.
        raise RuntimeError("Python 3.10+ is required")
    root = Path(directory).resolve()
    data = json.loads(Path(settings).read_text(encoding="utf-8"))
    for key in ("tenant", "host", "index"):
        pattern = (
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
            if key == "host"
            else r"[A-Za-z0-9_-]{1,64}"
        )
        if not isinstance(data.get(key), str) or not re.fullmatch(pattern, data[key]):
            raise ValueError("Invalid deployment " + key)
    url = urlsplit(data.get("endpoint_url", ""))
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username
        or url.password
        or url.path not in ("", "/")
        or url.query
        or url.fragment
    ):
        raise ValueError("A verified HTTPS endpoint origin is required")
    state = root / "state"
    if (root / "config.json").exists():
        raise RuntimeError(
            "Existing installation is preserved; use an explicit operator upgrade/re-enrollment procedure"
        )
    integrity = _integrity(root, settings, token_file, ca_file)
    ca_bytes = Path(ca_file).read_bytes()
    if len(ca_bytes) > 256 * 1024 or b"PRIVATE KEY" in ca_bytes:
        raise ValueError("CA must be a bounded public certificate bundle")
    ssl.create_default_context(cadata=ca_bytes.decode("ascii"))
    state.mkdir(mode=0o700, exist_ok=True)
    (root / "ca.pem").write_bytes(ca_bytes)
    if os.name != "nt":
        os.chmod(root / "ca.pem", 0o600)
        os.chmod(state, 0o700)
    config = {
        "endpoint_url": data["endpoint_url"].rstrip("/"),
        "tenant": data["tenant"],
        "host": data["host"],
        "index": data["index"],
        "ca_file": str(root / "ca.pem"),
        "state_dir": str(state),
        "collect_interval_seconds": 5,
        "transport_timeout_seconds": 10,
        "send_batch_size": 50,
        "max_pending": 10000,
        "capture_reserve": 10000,
        "emit_initial_processes": False,
        "emit_startup_inventory": True,
        "memory_observability": {"enabled": False},
        "package_integrity": integrity,
        "response": {
            "enabled": False,
            "allow_process_termination": False,
            "allow_file_delete": False,
            "allowed_process_executables": [],
            "allowed_process_instances": [],
            "file_roots": [],
        },
    }
    # Failed enrollment leaves no config falsely suggesting a completed install.
    identity_path = state / "identity.json"
    if identity_path.exists():
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
        if (
            identity.get("tenant") != config["tenant"]
            or identity.get("host") != config["host"]
            or identity.get("index") != config["index"]
            or not identity.get("credential")
            or not identity.get("agent_id")
        ):
            raise RuntimeError(
                "Durable enrollment differs from deployment; explicit operator recovery required"
            )
    else:
        enroll(config, Path(token_file).read_text(encoding="ascii").strip())
        identity = (
            json.loads(identity_path.read_text(encoding="utf-8"))
            if identity_path.exists()
            else {}
        )
    public_key = identity.get("defense_public_key")
    if public_key is not None and (
        not isinstance(public_key, str) or not re.fullmatch(r"[0-9a-f]{64}", public_key)
    ):
        raise ValueError("Enrollment defense signing key is invalid")
    config["defense"] = {
        "enabled": False,
        "public_key": public_key,
        "bundle_file": str(state / "defense-policy.json"),
    }
    config["kernel_prevention"] = {"enabled": False}
    atomic_json(root / "config.json", config)
    return {
        "enrolled": True,
        "host": data["host"],
        "platform": platform.system(),
        "index": data["index"],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True)
    parser.add_argument("--deployment", required=True)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--ca-file", required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            configure(args.directory, args.deployment, args.token_file, args.ca_file)
        )
    )
