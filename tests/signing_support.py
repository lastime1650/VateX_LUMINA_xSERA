"""Explicit test-only signing fixtures; never weaken application defaults."""

import hashlib
import json
import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def provision_test_signer(directory):
    """Create disposable external QA material, not an owner release identity."""
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    private_file, trust_file = directory / "qa-private.pem", directory / "qa-trust.json"
    private_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    if os.name != "nt":
        private_file.chmod(0o600)
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    identifier = hashlib.sha256(public).hexdigest()[:32]
    trust_file.write_text(
        json.dumps(
            {
                "schema": "xsera.agent.trust.v1",
                "keys": {identifier: public.hex()},
                "revoked_key_ids": [],
            }
        ),
        encoding="utf-8",
    )
    return {
        "private_file": private_file,
        "trust_file": trust_file,
        "key_id": identifier,
        "public_key": public.hex(),
        "qa_only": True,
    }


@pytest.fixture
def release_signer(tmp_path, monkeypatch):
    """Request this fixture explicitly in signed-distribution test modules."""
    result = provision_test_signer(tmp_path / "external-qa-signing")
    monkeypatch.setenv("SAPIENTIA_AGENT_SIGNING_KEY_FILE", str(result["private_file"]))
    monkeypatch.setenv("SERA_AGENT_TRUSTED_KEYS_FILE", str(result["trust_file"]))
    monkeypatch.setenv("SERA_AGENT_REQUIRE_SIGNED_PACKAGE", "1")
    return result


def local_agent_development_config(config):
    """Explicit loopback-only developer runtime; no production install bypass."""
    return {
        **config,
        "endpoint_url": "https://127.0.0.1",
        "package_integrity": {
            "profile": "development_fixture",
            "required": False,
        },
    }
