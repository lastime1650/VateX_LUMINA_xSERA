"""Provision disposable external QA keys; never establish a production identity."""

import argparse
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def provision(directory, *, qa_only):
    if qa_only is not True:
        raise ValueError(
            "This utility only provisions disposable QA keys; owner release keys require an external ceremony"
        )
    directory = Path(directory).expanduser().absolute()
    if directory.resolve().is_relative_to(Path(__file__).resolve().parents[1]):
        raise ValueError(
            "QA signing material must be outside the release source and archive"
        )
    for path in (directory, *directory.parents):
        if path.exists() and (
            path.is_symlink()
            or getattr(os.lstat(path), "st_file_attributes", 0) & 0x400
        ):
            raise ValueError("QA key directories must not contain links")
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    key = Ed25519PrivateKey.generate()
    private, trust = directory / "qa-private.pem", directory / "qa-trust.json"
    value = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    descriptor = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(value)
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    identifier = hashlib.sha256(public).hexdigest()[:32]
    trust.write_text(
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
        "qa_only": True,
        "key_id": identifier,
        "private_file": str(private),
        "trust_file": str(trust),
        "owner_release_qualification": False,
        "automatic_trust_installation": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--qa-only", action="store_true", required=True)
    args = parser.parse_args()
    result = provision(args.directory, qa_only=args.qa_only)
    print(
        json.dumps(
            {
                "qa_only": result["qa_only"],
                "key_id": result["key_id"],
                "owner_release_qualification": False,
                "secret_material_printed": False,
            }
        )
    )


if __name__ == "__main__":
    main()
