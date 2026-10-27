"""Real static YARA finding ancestry, current authority and composite Cases."""

import copy
import importlib.util
import json
import time
from pathlib import Path

import pytest
from test_yara_manager import MARKER, actor, approved, collection

from sapientia import (
    access,
    casework,
    connector_runtime,
    cpu_ml,
    intelligence,
    principal,
    source_registry,
    yara_intelligence,
    yara_manager,
)

pytest_plugins = ("test_xdr_advanced_api",)


def setup_run(client, **kwargs):
    store = client.app.state.store
    identifier = approved(client)
    artifact = collection(client)
    result = yara_manager.scan_artifact(
        store, actor(), artifact, rule_ids=[identifier], **kwargs
    )
    with store.control() as db:
        signal = json.loads(
            db.execute(
                "SELECT body FROM intelligence_signals WHERE id=?",
                (result["signal_id"],),
            ).fetchone()[0]
        )
    return identifier, artifact, result, signal


def valid(store, signal, who=None, memo=None):
    with principal.transaction(store, who or actor(), write=True) as (db, fresh):
        return yara_intelligence.validate_parent(store, db, fresh, signal, memo=memo)


def artifact_path(store, identifier):
    return Path(store.path) / "response-artifacts" / (identifier + ".bin")


def test_actual_run_is_an_admissible_parent_with_preserved_author_metadata(client):
    _, _, result, signal = setup_run(client)
    store = client.app.state.store
    assert valid(store, signal)
    assert result["matches"][0]["author"] == "requester"
    with principal.transaction(store, actor(), write=True) as (db, fresh):
        assert intelligence._parent_valid(
            store, db, fresh, signal, {"indexes": ["public"]}
        )
        changed_story = {**signal, "story_id": "reconciled-story-alias"}
        assert yara_intelligence.validate_parent(store, db, fresh, changed_story)


@pytest.mark.parametrize("change", ["id", "event_ids", "features", "context_digest", "metadata"])
def test_fabricated_or_altered_signal_cannot_borrow_a_real_run(client, change):
    _, _, _, signal = setup_run(client)
    forged = copy.deepcopy(signal)
    forged[change] = {
        "id": "SIG-forged",
        "event_ids": ["not-the-original"],
        "features": {"artifact_sha256": "0" * 64, "yara_match_count": 99},
        "context_digest": "forged",
        "metadata": {**signal["metadata"], "yara_run_id": "missing-run"},
    }[change]
    assert not valid(client.app.state.store, forged)


@pytest.mark.parametrize("metadata", [None, "untrusted", []])
def test_untrusted_metadata_shape_is_ineligible_without_interrupting_the_worker(client, metadata):
    _, _, _, signal = setup_run(client)
    assert not valid(client.app.state.store, {**signal, "metadata": metadata})


def test_a_persisted_manual_finding_cannot_claim_an_actual_run_signal_identity(client):
    _, _, _, signal = setup_run(client)
    store = client.app.state.store
    forged = intelligence.publish(store, actor(), {
        "event_ids": signal["event_ids"], "kind": "finding", "rule_id": "yara:binary",
        "rule_revision": 1, "features": signal["features"], "severity": "high",
        "confidence_grade": signal["confidence_grade"], "metadata": signal["metadata"],
        "context_digest": "different-manual-context",
    })
    assert forged["id"] != signal["id"]
    assert not valid(store, forged)


@pytest.mark.parametrize("kind", ["author_scope", "author_disabled", "reviewer_scope", "rule_delete", "rule_edit", "case_false_positive", "source_receipt"])
def test_current_authority_rule_case_and_source_revocation_remove_parent_eligibility(client, kind):
    identifier, _, result, signal = setup_run(client)
    store = client.app.state.store
    if kind == "author_scope":
        access.set_for_user(store, actor("approver"), "requester", ["other"])
    elif kind == "reviewer_scope":
        access.set_for_user(store, actor(), "approver", ["other"])
    elif kind == "rule_delete":
        yara_manager.delete_rule(store, actor(), identifier, 1, "Retire test rule")
    elif kind == "rule_edit":
        current = yara_manager.get_rule(store, actor(), identifier)
        yara_manager.save_rule(store, actor(), {
            "name": current["name"], "description": current["description"],
            "source": MARKER.replace("Harmless {", "Harmless_changed {"),
            "indexes": ["public"], "enabled": True, "expected_revision": 1,
        }, identifier)
    else:
        with store.control() as db:
            if kind == "author_disabled":
                db.execute("UPDATE users SET disabled=1 WHERE name='requester'")
            elif kind == "case_false_positive":
                db.execute("UPDATE incidents SET status='false_positive' WHERE id=?", (result["incident_id"],))
            else:
                db.execute("DELETE FROM receipts WHERE event_id=?", (signal["event_ids"][0],))
    # The independent remaining operator still has read scope. Revoked run
    # authors cannot be silently replaced by the current composite operator.
    who = actor("approver") if kind in {"author_scope", "author_disabled"} else actor()
    assert not valid(store, signal, who)
    assert yara_manager.get_run(store, who, result["id"])["id"] == result["id"]


def test_unmatched_rule_deletion_does_not_invalidate_an_unchanged_real_match(client):
    store = client.app.state.store
    matched = approved(client)
    absent = approved(client, MARKER.replace("Harmless API signature sample", "ABSENT"))
    artifact = collection(client)
    result = yara_manager.scan_artifact(store, actor(), artifact, rule_ids=[matched, absent])
    with store.control() as db:
        signal = json.loads(db.execute("SELECT body FROM intelligence_signals WHERE id=?", (result["signal_id"],)).fetchone()[0])
    yara_manager.delete_rule(store, actor(), absent, 1, "Retire unmatched rule")
    assert valid(store, signal)


def test_at_least_one_current_matched_rule_suffices_and_memo_never_caches_authority(client):
    store = client.app.state.store
    one, two = approved(client), approved(client)
    artifact = collection(client)
    result = yara_manager.scan_artifact(store, actor(), artifact, rule_ids=[one, two])
    assert len(result["matches"]) == 2
    with store.control() as db:
        signal = json.loads(db.execute("SELECT body FROM intelligence_signals WHERE id=?", (result["signal_id"],)).fetchone()[0])
    yara_manager.delete_rule(store, actor(), one, 1, "One matching rule retired")
    assert valid(store, signal)
    with principal.transaction(store, actor(), write=True) as (db, fresh):
        memo = {}
        assert yara_intelligence.validate_parent(store, db, fresh, signal, memo=memo)
        db.execute("UPDATE users SET disabled=1 WHERE name='approver'")
        assert not yara_intelligence.validate_parent(store, db, fresh, signal, memo=memo)


def test_file_bytes_size_or_link_change_invalidates_the_parent_even_with_a_memo(client):
    _, identifier, _, signal = setup_run(client)
    store = client.app.state.store
    path = artifact_path(store, identifier)
    original = path.read_bytes()
    with principal.transaction(store, actor(), write=True) as (db, fresh):
        memo = {}
        assert yara_intelligence.validate_parent(store, db, fresh, signal, memo=memo)
        path.write_bytes(b"X" * len(original))
        assert not yara_intelligence.validate_parent(store, db, fresh, signal, memo=memo)
        path.write_bytes(original + b"extra")
        assert not yara_intelligence.validate_parent(store, db, fresh, signal, memo=memo)


def test_symbolic_file_link_is_not_accepted_as_the_preserved_artifact(client, tmp_path):
    _, identifier, _, signal = setup_run(client)
    store = client.app.state.store
    path = artifact_path(store, identifier)
    reference = tmp_path / "harmless-reference.bin"
    reference.write_bytes(path.read_bytes())
    path.unlink()
    try:
        path.symlink_to(reference)
    except OSError:
        pytest.skip("Host does not permit synthetic symbolic-link fixture")
    assert not valid(store, signal)


def test_command_binding_and_complete_case_scope_are_required(client):
    _, identifier, result, signal = setup_run(client)
    store = client.app.state.store
    with store.control() as db:
        db.execute("UPDATE endpoint_responses SET evidence_event_id='other-original' WHERE id=(SELECT command_id FROM endpoint_artifacts WHERE id=?)", (identifier,))
    assert not valid(store, signal)
    with store.control() as db:
        db.execute("UPDATE endpoint_responses SET evidence_event_id=? WHERE id=(SELECT command_id FROM endpoint_artifacts WHERE id=?)", (signal["event_ids"][0], identifier))
        db.execute("INSERT INTO case_bookmarks VALUES('private-bookmark','a',?,'private-event','private','full-scope fixture','requester',?,'{}')", (result["incident_id"], time.time()))
    access.set_for_user(store, actor(), "approver", ["public"])
    assert not valid(store, signal, actor("approver"))


def reviewed_policy(store, definition):
    saved = intelligence.save_policy(store, actor(), definition)
    intelligence.review_policy(store, actor("approver"), saved["id"], {
        "version": 1, "approve": True, "reason": "Independently reviewed synthetic chain",
    })
    return saved["id"]


@pytest.mark.parametrize("mode", ["atomic", "same_original", "cpu_ml"])
def test_real_yara_and_atomic_or_cpu_ml_creates_case_only_with_distinct_original_groups(client, mode):
    store, case = client.app.state.store, client.app.state.qualification["case"]
    same_original = mode == "same_original"
    if mode == "cpu_ml":
        if importlib.util.find_spec("torch") is None:
            pytest.skip("Optional CPU PyTorch unavailable")
        runtime = cpu_ml.runtime_status()
        if not runtime["available"]:
            pytest.skip("CPU PyTorch incompatible on this host")
        assert runtime["device"] == "cpu"
    # Index acknowledgement journals originals only for already active policies.
    # Install the reviewed rule before intake, exactly as a deployed pipeline.
    atomic = reviewed_policy(store, {
        "name": "Separate behavior evidence", "kind": "atomic", "indexes": ["public"], "enabled": True,
        "filters": [{"field": "raw.stage", "op": "eq", "value": "binary" if same_original else "network" if mode == "atomic" else "never"}],
    })
    source = source_registry.save(store, actor(), {
        "index": "public", "product": "json", "account": "api-host", "realm": "lab",
        "credential_ref": "env:SAPIENTIA_CONNECTOR_LAB", "version": 0,
    })
    events = [{
        "event_id": f"yara-chain-{n}", "event_time": time.time() - 10 + n, "host": "api-host",
        "raw": {"stage": stage, "xdr": {"data": {
            "process": {"guid": "same-process", "start_identity": "same-incarnation"},
            "host": {"id": "device", "boot_id": "boot"},
            "event": {"action": "process_observed" if n == 0 else "network_connection", "timestamp_precision_seconds": .01},
        }}},
    } for n, stage in enumerate(("binary", "network"))]
    if mode == "cpu_ml":
        events[1]["raw"].update(command_line="x" * 8192, dest_port=65535,
            dest_ip="8.8.8.8", process_depth=32, file_path="C:/synthetic/reference.exe")
    connector_runtime.intake(store, actor(), source["id"], {
        "version": 1, "events": events, "cursor": "fixture", "checkpoint_version": 0,
    })
    while store.flush():
        pass
    casework.bookmark(store, actor(), case["id"], {"event_id": events[0]["event_id"], "label": "Executable source original"})
    second = {"rule_id": atomic, "kind": "atomic"}
    model = None
    if mode == "cpu_ml":
        normals = [{"event_id": f"yara-normal-{i}", "event_time": time.time() - 40 + i,
            "index": "public", "host": "api-host", "raw": {
                "command_line": "echo normal", "dest_port": 443, "dest_ip": "10.1.0.2", "process_depth": 1}}
            for i in range(32)]
        store.ingest("a", normals)
        while store.flush():
            pass
        model = cpu_ml.train(store, actor(), {"name": "Real CPU model with YARA parent",
            "indexes": ["public"], "training_ids": [event["event_id"] for event in normals[:24]],
            "validation_ids": [event["event_id"] for event in normals[24:]],
            "epochs": 80, "normal_training_confirmed": True})
        assert model["status"] == "completed"
        cpu_ml.activate(store, actor("approver"), model["id"], "Independent normal-cohort and holdout review")
        second = {"rule_id": "ml:" + model["id"], "kind": "ml"}
    child = reviewed_policy(store, {
        "name": "Actual YARA plus separate behavior", "kind": "composite", "indexes": ["public"], "enabled": True,
        "inputs": [{"rule_id": "yara:binary", "kind": "finding"}, second],
        "join_on": "process", "minimum_independent_groups": 2, "window": 300,
        "case_adapter": {"entity_field": "host", "risk_score": 60, "severity": "high", "mitre": [], "cooldown": 0},
    })
    rule, artifact = approved(client), collection(client)
    with store.control() as db:
        db.execute("UPDATE endpoint_responses SET evidence_event_id=? WHERE id=(SELECT command_id FROM endpoint_artifacts WHERE id=?)", (events[0]["event_id"], artifact))
    result = yara_manager.scan_artifact(store, actor(), artifact, rule_ids=[rule])
    assert result["signal_id"] and result["matches"]
    for _ in range(6):
        intelligence.run_due(store, budget=2, max_runs=8, include_ml=mode == "cpu_ml")
    signals = intelligence.signals(store, actor(), count=100)["items"]
    combined = [signal for signal in signals if signal["rule_id"] == child]
    if same_original:
        assert combined == []
        with store.control() as db:
            assert db.execute("SELECT count(*) FROM risk_contributions WHERE policy_id=?", ("intelligence:" + child + ":1",)).fetchone()[0] == 0
    else:
        assert len(combined) == 1
        assert combined[0]["event_ids"] == [event["event_id"] for event in events]
        assert combined[0]["evidence_dependency"]["disjoint_original_groups"] == 2
        assert combined[0]["evidence_dependency"]["statistical_independence_proven"] is False
        assert combined[0]["malicious_probability"] is None
        assert not combined[0]["automatic_endpoint_authorization"]
        if mode == "cpu_ml":
            ml = [signal for signal in signals if signal["id"] in combined[0]["parent_signal_ids"] and signal["kind"] == "ml"]
            assert len(ml) == 1 and ml[0]["event_ids"] == [events[1]["event_id"]]
            assert ml[0]["model_digest"] == model["digest"]
            assert ml[0]["metadata"]["score"] > ml[0]["metadata"]["threshold"]
        with store.control() as db:
            contribution = db.execute("SELECT * FROM risk_contributions WHERE policy_id=?", ("intelligence:" + child + ":1",)).fetchone()
            assert contribution is not None
            assert json.loads(contribution["evidence"])["event_ids"] == [event["event_id"] for event in events]
            case_notices = json.loads(contribution["evidence"])["analysis"]["content_notices"]
            assert any(item.get("author") == "requester" and item.get("kind") == "yara_rule" for item in case_notices["items"])
            contribution_case = contribution["incident_id"]
            # The only command is the existing synthetic read collection fixture.
            assert db.execute("SELECT count(*) FROM endpoint_responses").fetchone()[0] == 1
            yara_signal = json.loads(db.execute("SELECT body FROM intelligence_signals WHERE id=?", (result["signal_id"],)).fetchone()[0])
        assert valid(store, yara_signal)
        exported = casework.export_case(store, actor(), contribution_case)
        assert any(item.get("author") == "requester" for item in exported["content_notices"]["items"])
        source_registry.revoke(store, actor(), source["id"], 1)
        assert not valid(store, yara_signal)
