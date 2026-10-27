"""Run reviewed operational HTTP workflows against only a fresh disposable Store.

Generated signing keys are disposable probe material outside the archive. They
are neither installed as machine trust nor exported in the public evidence.
"""

import argparse
import hashlib
import io
import json
import os
import secrets
import tempfile
import time
import zipfile
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from sapientia import agent_distribution, auth, release_manifest
from sapientia.api import create_app
from sapientia.endpoint_agent.Agent.package_integrity import PackageIntegrity, verify
from sapientia.storage import Settings


def qualify():
    began, source = time.time(), release_manifest.build()["source_digest"]
    with tempfile.TemporaryDirectory(prefix="xsera-ops-http-") as temporary:
        root = Path(temporary)
        private = root / "disposable-signing.pem"
        private.write_bytes(
            Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        if os.name != "nt":
            private.chmod(0o600)
        with patch.dict(os.environ, {"SAPIENTIA_AGENT_SIGNING_KEY_FILE": str(private)}):
            app = create_app(
                Settings(root / "store", min_free_bytes=0), background=False
            )
            password = secrets.token_urlsafe(32)
            for name in ("ops-author", "ops-reviewer"):
                auth.create_user(app.state.store, name, password, "admin", "ops-qa")
            with TestClient(app) as owner, TestClient(app) as peer:
                for client, name in ((owner, "ops-author"), (peer, "ops-reviewer")):
                    response = client.post(
                        "/api/login", json={"name": name, "password": password}
                    )
                    if response.status_code != 200:
                        raise AssertionError("Synthetic HTTP login failed")
                    client.headers["X-CSRF-Token"] = response.json()["csrf"]

                def post(client, path, payload, expected=200):
                    response = client.post(path, json=payload)
                    if response.status_code != expected:
                        raise AssertionError(
                            f"Owned HTTP workflow failed at {path}: {response.status_code}"
                        )
                    return response.json()

                def get(path):
                    response = owner.get(path)
                    if response.status_code != 200:
                        raise AssertionError("Owned HTTP read failed")
                    return response.json()

                source_row = post(
                    owner,
                    "/api/v2/sources",
                    {
                        "index": "ops_qa",
                        "product": "json",
                        "account": "synthetic-sequence",
                        "realm": "virtual-lab",
                        "credential_ref": "env:SAPIENTIA_CONNECTOR_OPSQUALIFY",
                        "version": 0,
                    },
                    201,
                )
                path = "/api/ops/source-slo/" + source_row["id"]
                policy = owner.put(
                    path,
                    json={
                        "expected_revision": 0,
                        "source_version": 1,
                        "sequence_path": "raw.telemetry.sequence",
                        "epoch_path": "raw.telemetry.epoch",
                        "max_silence_seconds": 1,
                        "max_gap": 0,
                        "max_reported_drop": 0,
                    },
                )
                if policy.status_code != 200:
                    raise AssertionError("Source SLO configuration failed")

                def page(numbers, cursor, checkpoint):
                    return {
                        "version": 1,
                        "events": [
                            {
                                "event_id": "ops-seq-" + str(n),
                                "event_time": began,
                                "raw": {
                                    "telemetry": {
                                        "sequence": n,
                                        "epoch": "synthetic-boot",
                                    }
                                },
                            }
                            for n in numbers
                        ],
                        "cursor": cursor,
                        "checkpoint_version": checkpoint,
                    }

                post(
                    owner,
                    "/api/v2/sources/" + source_row["id"] + "/intake",
                    page([1, 4], "first", 0),
                    202,
                )
                gap_before = get("/api/ops/source-slo")["items"][0]
                post(
                    owner,
                    "/api/v2/sources/" + source_row["id"] + "/intake",
                    page([2, 3], "late", 1),
                    202,
                )
                repeated = post(
                    owner,
                    "/api/v2/sources/" + source_row["id"] + "/intake",
                    page([2, 3], "late", 1),
                    202,
                )
                gap_after = get("/api/ops/source-slo")["items"][0]
                if (
                    gap_before["provisional_sequence_gaps"] != 2
                    or gap_after["provisional_sequence_gaps"] != 0
                    or repeated["duplicate"] != 2
                    or gap_after["counters"]["observed_unique"] != 4
                ):
                    raise AssertionError("Actual receipt/sequence recovery mismatch")
                receipts = []
                trust = None
                for kind in (
                    "integrity_bootstrap",
                    "response_twin",
                    "recovery_process",
                ):
                    row = post(
                        owner,
                        "/api/ops/qualification/plans",
                        {
                            "name": "Owned HTTP " + kind,
                            "indexes": ["ops_qa"],
                            "kind": kind,
                            "expected_revision": 0,
                        },
                        201,
                    )
                    review_path = (
                        "/api/ops/qualification/plans/" + row["id"] + "/review"
                    )
                    review = {
                        "expected_revision": 1,
                        "approve": True,
                        "reason": "Independent exact disposable software probe review",
                    }
                    own = owner.post(review_path, json=review)
                    if own.status_code != 403:
                        raise AssertionError(
                            "HTTP requester self-review was not refused"
                        )
                    post(peer, review_path, review)
                    run = post(
                        owner,
                        "/api/ops/qualification/plans/" + row["id"] + "/run",
                        {"expected_revision": 1},
                    )
                    if (
                        run["state"] != "completed"
                        or not run["qualified"]
                        or run["result"]["native_host_effects"] != 0
                    ):
                        raise AssertionError("Reviewed owned probe failed")
                    if kind == "integrity_bootstrap":
                        trust = run["result"].pop("trust_file")
                        run["result"]["trust_export"] = {
                            "key_ids": sorted(trust["keys"]),
                            "public_key_count": len(trust["keys"]),
                            "approval": trust["approval"],
                            "private_key_exported": False,
                        }
                        run["original_result_digest"] = run.pop("result_digest")
                        run["public_summary_digest"] = release_manifest.digest(
                            run["result"]
                        )
                        run["redactions"] = [
                            "Public trust artifact omitted; original durable result digest preserved separately"
                        ]
                    receipts.append(run)
                trust_file = root / "public-trust.json"
                trust_file.write_text(json.dumps(trust), encoding="utf-8")
                package_root = root / "package"
                package_root.mkdir()
                blob, digest, _ = agent_distribution.package("windows")
                with zipfile.ZipFile(io.BytesIO(blob)) as archive:
                    archive.extractall(package_root)
                measurement = verify(
                    package_root, trust_file=trust_file, require_signature=True
                )
                measured = PackageIntegrity(
                    {
                        "package_integrity": {
                            "required": True,
                            "trust_file": str(trust_file),
                        }
                    },
                    package_root,
                )
                (package_root / "Agent/core.py").write_text(
                    "synthetic modified bytes", encoding="utf-8"
                )
                tamper = measured.measure()
                if (
                    measurement["state"] != "verified_signed"
                    or tamper["state"] != "failed"
                ):
                    raise AssertionError(
                        "Pinned signature or repeated code measurement failed"
                    )
                final_slo = get("/api/ops/source-slo")["items"][0]
                if "source_silence" not in final_slo["reasons"]:
                    raise AssertionError("Real elapsed source silence was not detected")
                with app.state.store.control() as db:
                    native_rows = db.execute(
                        "SELECT count(*) FROM endpoint_responses"
                    ).fetchone()[0]
                result = {
                    "schema": "xsera.ops-hardening-evidence.v1",
                    "passed": True,
                    "source_digest": source,
                    "source_digest_at_end": release_manifest.build()["source_digest"],
                    "elapsed_seconds": time.time() - began,
                    "scope": "fresh synthetic HTTP Store plus owned temporary child-process recovery",
                    "native_host_effects": 0,
                    "native_response_rows": native_rows,
                    "reviewed_runs": receipts,
                    "integrity": {
                        "archive_sha256": hashlib.sha256(blob).hexdigest(),
                        "download_digest_matches": hashlib.sha256(blob).hexdigest()
                        == digest,
                        "measurement": measurement,
                        "after_tamper": tamper,
                        "external_ca_certification": "unavailable_not_performed",
                    },
                    "delivery": {
                        "before_late_arrival": gap_before,
                        "after_late_arrival": gap_after,
                        "after_real_silence": final_slo,
                        "duplicate_replay": repeated["duplicate"],
                    },
                    "limitations": [
                        "No real host isolation, OS command, native packet filtering or native endpoint response executed",
                        "Single-machine owned process takeover is not distributed HA certification",
                        "Signature is an application manifest with independently reviewed local public-key pin, not OS vendor code signing or hardware attestation",
                        "Pre-capture loss remains unobservable; sensor drop is reported-only unless independently measured",
                        "Physical reboot, physical power failure, actual device fleet and Yocto BSP tests remain unavailable",
                    ],
                }
                if native_rows != 0:
                    raise AssertionError("A native response was unexpectedly created")
                return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = qualify()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "passed": result["passed"],
                "native_host_effects": result["native_host_effects"],
                "reviewed_runs": len(result["reviewed_runs"]),
            }
        )
    )


if __name__ == "__main__":
    main()
