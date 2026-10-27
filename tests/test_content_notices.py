"""Detection attribution is retained from server-bound sources, not client claims."""

import copy
import hashlib
import json
from pathlib import Path

import pytest
from test_yara_manager import actor, approved, collection

from sapientia import (
    access,
    casework,
    content_notices,
    principal,
    sigma_imports,
    yara_manager,
)
from sapientia.storage import ConflictError, encode

pytest_plugins = ("test_xdr_advanced_api",)


def test_original_950_owner_declaration_preserves_source_hashes_and_separate_notices():
    root = Path(__file__).parents[1] / "sapientia/catalogs"
    provenance = json.loads((root / "provenance.json").read_text(encoding="utf-8"))
    declaration = provenance["rights_declaration"]
    assert declaration["rule_count"] == 950
    assert declaration["license"] == "Apache-2.0"
    assert declaration["independently_verified"] is False
    count = 0
    for entry in provenance["files"]:
        if entry["file"] in declaration["scope_files"]:
            raw = (root / entry["file"]).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == entry["sha256"]
            count += len(json.loads(raw.decode("utf-8-sig")))
    assert count == 950
    manifest = json.loads((root / "third_party_manifest.json").read_text(encoding="utf-8"))
    for entry in manifest["bundled_manifests_and_licenses"]:
        raw = (root.parents[1] / entry["path"]).read_bytes()
        assert len(raw) == entry["bytes"]
        assert hashlib.sha256(raw).hexdigest() == entry["sha256"]
    assert {source["license"] for source in manifest["yara"]["sources"]} == {"DRL-1.1", "MIT", "BSD-3-Clause"}


def test_all_reported_yara_authors_survive_32_match_preview_and_untrusted_metadata(client):
    # Forty independently attributed harmless rules prove that notices are not
    # silently cut to the first 32 preview rows.
    source = "\n".join(
        f'''rule Harmless_{number} {{
          meta:
            author = "Original author {number}"
            license = "DRL-1.1"
            license_url = "https://example.invalid/DRL-1.1"
            reference = "https://example.invalid/rules/{number}"
          strings: $a = "Harmless API signature sample"
          condition: $a
        }}''' for number in range(40)
    )
    rule = approved(client, source)
    artifact = collection(client)
    store = client.app.state.store
    run = yara_manager.scan_artifact(store, actor(), artifact, rule_ids=[rule])
    assert run["status"] == "completed" and len(run["matches"]) == 40
    with principal.transaction(store, actor(), write=True) as (db, fresh):
        signal = json.loads(db.execute("SELECT body FROM intelligence_signals WHERE id=?", (run["signal_id"],)).fetchone()[0])
        assert len(signal["metadata"]["matched_rules"]) == 32
        assert len(signal["metadata"]["content_notices"]["items"]) == 40
        notices = content_notices.for_signal(db, fresh, signal)
        assert notices["complete"]
        assert {item["author"] for item in notices["items"]} == {f"Original author {n}" for n in range(40)}
        assert {item["license"] for item in notices["items"]} == {"DRL-1.1"}
        assert all(item["source_url"].startswith("https://example.invalid/rules/") for item in notices["items"])
        assert all(item["source_sha256"] == run["matches"][0]["source_sha256"] for item in notices["items"])
        # Even a persisted arbitrary metadata claim cannot replace actual run
        # attribution. The immutable run identity remains the authority.
        changed = copy.deepcopy(signal)
        changed["metadata"]["content_notices"] = content_notices.bundle([{"author": "Forged"}])
        db.execute("UPDATE intelligence_signals SET body=? WHERE id=?", (encode(changed), signal["id"]))
        assert content_notices.for_signal(db, fresh, changed) == notices
        with pytest.raises(ConflictError):
            content_notices.for_signal(db, fresh, signal)
        db.execute("UPDATE intelligence_signals SET body=? WHERE id=?", (encode(signal), signal["id"]))
        assert content_notices.for_signal(db, fresh, {**signal, "duplicate": False, "story_id": "current-story-alias"}) == notices
    exported = casework.export_case(store, actor(), run["incident_id"])
    assert {item["author"] for item in exported["content_notices"]["items"] if item.get("kind") == "yara_rule"} == {f"Original author {n}" for n in range(40)}
    yara_manager.delete_rule(store, actor(), rule, 1, "Retire rule without removing historical attribution")
    with principal.transaction(store, actor()) as (db, fresh):
        assert content_notices.for_signal(db, fresh, signal) == notices
    access.set_for_user(store, actor("approver"), "requester", ["other"])
    with principal.transaction(store, actor()) as (db, fresh), pytest.raises(KeyError):
        content_notices.for_signal(db, fresh, signal)


@pytest.mark.parametrize("tag", ["!!python/object/apply:os.system ['no execution']", "!!python/object/new:subprocess.Popen [['no execution']]"])
def test_restricted_sigma_safeloader_never_constructs_python_objects(monkeypatch, tag):
    import os
    import subprocess

    def forbidden(*args, **kwargs):
        pytest.fail("Untrusted YAML must not invoke a Python object constructor")
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    with pytest.raises(ValueError, match="Sigma YAML"):
        sigma_imports._decode(tag, "yaml")


def test_case_retains_digest_checked_snapshot_if_signal_history_was_pruned(client):
    store, incident = client.app.state.store, client.app.state.qualification["case"]
    snapshot = content_notices.bundle([{"kind": "yara_rule", "author": "Historical author", "license": "DRL-1.1"}])
    with store.control() as db:
        row = db.execute("SELECT id,evidence FROM risk_contributions WHERE tenant='a' AND incident_id=? LIMIT 1", (incident["id"],)).fetchone()
        evidence = json.loads(row["evidence"])
        evidence["analysis"] = {"signal_id": "SIG-pruned-history", "content_notices": snapshot}
        db.execute("UPDATE risk_contributions SET evidence=? WHERE id=?", (encode(evidence), row["id"]))
    exported = casework.export_case(store, actor(), incident["id"])
    assert exported["content_notices"]["complete"] is False
    assert exported["content_notices"]["items"][0]["author"] == "Historical author"
    assert exported["content_notices"]["items"][0]["preservation_basis"] == "historical_case_contribution_snapshot"
    evidence["analysis"]["content_notices"]["items"][0]["author"] = "Tampered"
    with store.control() as db:
        db.execute("UPDATE risk_contributions SET evidence=? WHERE id=?", (encode(evidence), row["id"]))
    with pytest.raises(ConflictError, match="snapshot digest"):
        casework.export_case(store, actor(), incident["id"])


def test_direct_case_attached_scan_retains_author_when_signal_emission_is_disabled(client):
    rule = approved(client, '''rule NoSignal { meta: author = "Original no-signal author" license = "DRL-1.1" strings: $a = "Harmless API signature sample" condition: $a }''')
    store, artifact = client.app.state.store, collection(client)
    run = yara_manager.scan_artifact(store, actor(), artifact, rule_ids=[rule], emit_signal=False)
    assert run["signal_id"] is None
    exported = casework.export_case(store, actor(), run["incident_id"])
    assert exported["content_notices"]["complete"]
    assert any(item.get("author") == "Original no-signal author" for item in exported["content_notices"]["items"])
