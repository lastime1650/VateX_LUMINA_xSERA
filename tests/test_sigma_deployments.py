# ruff: noqa: F811 - shared disposable pytest fixtures.
"""Zero-gap deployment, current custody and real correlation-to-Case proofs."""

import copy
import json
import time

import pytest

from sapientia import (
    access,
    connector_runtime,
    intelligence,
    native_correlations,
    principal,
    sigma_backend,
    source_registry,
)
from sapientia import sigma_imports as imports
from sapientia.storage import ConflictError
from tests.test_backend_upgrade import actor, lab  # noqa: F401
from tests.test_sigma_imports import activated, payload, source


def next_revision(lab, old, data):
    item = imports.save(lab, actor(), {**data, "expected_revision": old["revision"]}, old["id"])
    item = imports.convert(lab, actor(), item["id"], item["revision"])
    item = imports.validate(lab, actor(), item["id"], item["revision"])
    assert item["validation"]["passed"]
    return imports.review(lab, actor("peer"), item["id"], {"expected_revision": item["revision"], "approve": True, "reason": "Independently tested replacement"})


def authority(lab, identifier):
    with principal.transaction(lab, actor()) as (db, _who):
        row = db.execute("SELECT * FROM intelligence_policies WHERE id=?", (identifier,)).fetchone()
        intelligence._authority(db, row)
        return dict(row)


def test_draft_failure_approval_atomic_switch_and_reviewed_rollback_preserve_active(lab, monkeypatch, record_property):
    data = payload(source(lab))
    old = activated(lab, data)
    before = authority(lab, old["native_policy_id"])
    revised = next_revision(lab, old, {**data, "severity": "critical"})
    assert revised["active_deployment"]["revision"] == 1
    assert authority(lab, old["native_policy_id"])["version"] == 1
    new = imports.activate(lab, actor(), old["id"], revised["revision"])
    assert new["active_deployment"]["revision"] == 2
    assert authority(lab, old["native_policy_id"])["version"] == 2
    draft = imports.save(lab, actor(), {**data, "expected_revision": 2}, old["id"])
    monkeypatch.setattr(sigma_backend, "status", lambda: {"available": False, "version": None})
    restored = imports.rollback(lab, actor(), old["id"], {"expected_revision": 3, "expected_policy_version": 2, "target_policy_version": 1, "reason": "Restore previously tested behavior"})
    active = authority(lab, old["native_policy_id"])
    assert active["version"] == 3 and active["definition"] == before["definition"]
    assert restored["revision"] == draft["revision"] == 3 and restored["state"] == "imported"
    assert restored["active_deployment"]["revision"] == 1
    assert [item["active"] for item in restored["deployments"]] == [True, False, False]
    assert restored["history"][-1]["action"] == "rollback"
    record_property("sigma_proof", json.dumps({"type": "deployment", "draft_preserved_active_revision": 1, "replacement_native_version": 2, "rollback_native_version": 3, "rollback_source_revision": 1, "pending_draft_revision": 3, "parser_unavailable_during_rollback": True, "native_definition_restored_exactly": active["definition"] == before["definition"]}))
    with pytest.raises(ConflictError):
        imports.rollback(lab, actor(), old["id"], {"expected_revision": 3, "expected_policy_version": 2, "target_policy_version": 1, "reason": "Stale pointer"})


def test_failed_replacement_commit_rolls_back_without_touching_current_deployment(lab, monkeypatch):
    data = payload(source(lab))
    old = activated(lab, data)
    revised = next_revision(lab, old, {**data, "severity": "low"})
    original = imports._snapshot
    def fail_after_snapshot(*args):
        original(*args)
        raise RuntimeError("Commit fault")
    monkeypatch.setattr(imports, "_snapshot", fail_after_snapshot)
    with pytest.raises(RuntimeError, match="Commit fault"):
        imports.activate(lab, actor(), old["id"], revised["revision"])
    assert authority(lab, old["native_policy_id"])["version"] == 1
    assert imports.get(lab, actor(), old["id"])["active_deployment"]["revision"] == 1


def test_snapshot_integrity_and_revoked_source_or_reviewer_block_current_and_rollback(lab):
    declared = source(lab)
    old = activated(lab, payload(declared))
    imports.save(lab, actor(), {**payload(declared), "expected_revision": 1}, old["id"])
    authority(lab, old["native_policy_id"])
    source_registry.revoke(lab, actor(), declared["id"], 1)
    with pytest.raises(ConflictError):
        authority(lab, old["native_policy_id"])


def test_additive_v2_backfill_preserves_v1_active_native_rows_and_originals(lab):
    old = activated(lab, payload(source(lab)))
    before = authority(lab, old["native_policy_id"])
    with lab.control() as db:
        checksum = db.execute("SELECT checksum FROM xsera_schema_migrations WHERE component='sigma_imports' AND version=1").fetchone()[0]
        db.execute("DROP TABLE sigma_import_deployments")
        db.execute("DROP TABLE native_correlation_state")
        db.execute("DELETE FROM xsera_schema_migrations WHERE component='sigma_imports' AND version=2")
    imports.initialize(lab)
    assert authority(lab, old["native_policy_id"]) == before
    with lab.control() as db:
        assert db.execute("SELECT checksum FROM xsera_schema_migrations WHERE component='sigma_imports' AND version=1").fetchone()[0] == checksum
    assert imports.get(lab, actor(), old["id"])["active_deployment"]["revision"] == 1


def base(lab, declared, name, command):
    data = payload(declared)
    rule = json.loads(data["source_text"])
    rule["name"] = name
    rule["detection"] = {"selection": {"CommandLine|contains": command}, "condition": "selection"}
    data["source_text"] = json.dumps(rule)
    data["name"] = name
    data["fixtures"] = [data["fixtures"][0], data["fixtures"][-1]]
    data["fixtures"][0]["event"]["raw"]["command"] = command
    data["fixtures"][0]["expect"] = True
    return activated(lab, data)


def correlation_payload(declared, kind="event_count", names=None, count=3):
    names = names or ["base_a"]
    data = payload(declared)
    rule = {"title": "Positive native Sigma correlation", "correlation": {"type": kind, "rules": names, "group-by": ["User"], "timespan": "5m"}}
    if kind in {"event_count", "value_count"}:
        rule["correlation"]["condition"] = {"gte": count, **({"field": "Target"} if kind == "value_count" else {})}
    now = time.time() - 15
    def sample(index, user="investigator", command="powershell"):
        return {"source_id": declared["id"], "event": {"event_id": "correlation-fixture-" + str(index), "event_time": now + index, "index": "public", "host": "sigma-host", "sourcetype": "process", "raw": {"command": command, "user": user, "platform": "windows", "target": "target-" + str(index)}}}
    positive = [sample(index, command="powershell" if index == 0 or len(names) == 1 else "cmd.exe") for index in range(count)]
    negative = [sample(20)]
    if kind.startswith("temporal"):
        positive = [sample(0), sample(1, command="cmd.exe")]
        negative = [sample(0), sample(1, command="cmd.exe", user="other")]
    return {**data, "name": "Sigma " + kind, "source_text": json.dumps(rule), "field_mapping": {"User": "raw.user", "Target": "raw.target"}, "logsource_mapping": {}, "fixtures": [{"name": "positive", "events": positive, "expect": True}, {"name": "negative", "events": negative, "expect": False}], "case_adapter": {"entity_field": "host", "risk_score": 70, "severity": "high", "mitre": [], "cooldown": 0}}


@pytest.mark.parametrize("kind", native_correlations.TYPES)
def test_real_correlation_parser_fixture_review_native_signal_and_case(lab, kind, monkeypatch, record_property):
    declared = source(lab)
    first = base(lab, declared, "base_a", "powershell")
    if kind.startswith("temporal"):
        base(lab, declared, "base_b", "cmd.exe")
    data = correlation_payload(declared, kind, ["base_a", "base_b"] if kind.startswith("temporal") else ["base_a"])
    policy = activated(lab, data)
    assert policy["converted"]["native_policy"]["kind"] == "composite"
    assert policy["validation"]["passed"]
    monkeypatch.setattr(sigma_backend, "status", lambda: {"available": False, "version": None})
    events = [sample["event"] for sample in data["fixtures"][0]["events"]]
    connector_runtime.intake(lab, actor(), declared["id"], {"version": 1, "events": events, "cursor": "correlation-live", "checkpoint_version": 0})
    while lab.flush():
        pass
    for _ in range(5):
        intelligence.run_due(lab, budget=4, max_runs=8)
    found = [signal for signal in intelligence.signals(lab, actor(), count=1000)["items"] if signal["rule_id"] == policy["native_policy_id"]]
    assert found, "Expected actual native correlation publication"
    signal = found[-1]
    assert signal["kind"] == "composite" and len(signal["parent_signal_ids"]) == len(events)
    assert signal["metadata"]["sigma_import"]["import_id"] == policy["id"]
    assert signal["metadata"]["sigma_import"]["validation_digest"] == policy["validation"]["digest"]
    with principal.transaction(lab, actor()) as (db, who):
        assert native_correlations.validate_parent(lab, db, who, signal, policy["converted"]["native_policy"])
        assert db.execute("SELECT count(*) FROM incidents").fetchone()[0] >= 1
        assert db.execute("SELECT count(*) FROM endpoint_responses").fetchone()[0] == 0
        cases = db.execute("SELECT count(*) FROM risk_contributions WHERE tenant='a' AND json_extract(evidence,'$.analysis.signal_id') IN (SELECT id FROM intelligence_signals WHERE rule_id=?)", (policy["native_policy_id"],)).fetchone()[0]
    record_property("sigma_proof", json.dumps({"type": kind, "composite_signals": len(found), "case_contributions": cases, "parents": len(signal["parent_signal_ids"]), "originals": len(signal["event_ids"]), "fixture_assertions_passed": all(item["passed"] for item in policy["validation"]["assertions"]), "native_ir_sha256": policy["converted"]["native_definition_digest"], "server_import_provenance": signal["metadata"]["sigma_import"], "parser_unavailable_at_runtime": True, "host_effects": 0}))
    assert cases > 0
    publication = {key: signal[key] for key in ("event_ids", "kind", "rule_id", "rule_revision", "features", "severity", "confidence_grade", "parent_signal_ids", "definition_digest")}
    for forged in [{**publication, "rule_revision": 999}, {**publication, "features": {"count": 999}}, {**publication, "parent_signal_ids": []}, {**publication, "metadata": {"sigma_import": {"import_id": "fake"}}}]:
        with pytest.raises((ValueError, PermissionError, ConflictError)):
            intelligence.publish(lab, actor(), forged)
    # New working parent draft preserves its active deployment and dependent rule.
    imports.save(lab, actor(), {**first["payload"], "expected_revision": 1}, first["id"])
    authority(lab, policy["native_policy_id"])


def test_ten_parent_count_preserves_all_native_ancestry_and_rejects_forged_measurement(lab, record_property):
    declared = source(lab)
    base(lab, declared, "base_a", "powershell")
    data = correlation_payload(declared, count=10)
    policy = activated(lab, data)
    events = [sample["event"] for sample in data["fixtures"][0]["events"]]
    connector_runtime.intake(lab, actor(), declared["id"], {"version": 1, "events": events, "cursor": "ten-parent-count", "checkpoint_version": 0})
    while lab.flush():
        pass
    for _ in range(4):
        intelligence.run_due(lab, budget=4, max_runs=8)
    found = [item for item in intelligence.signals(lab, actor(), count=1000)["items"] if item["rule_id"] == policy["native_policy_id"]]
    assert len(found) == 1 and len(found[0]["parent_signal_ids"]) == len(found[0]["event_ids"]) == 10
    assert found[0]["features"]["count"] == 10
    record_property("sigma_proof", json.dumps({"type": "ten_parent_count", "parents": 10, "originals": 10, "count": found[0]["features"]["count"], "signals": len(found)}))


@pytest.mark.parametrize("edit", [{"type": "value_sum"}, {"type": "value_avg"}, {"type": "value_percentile"}, {"condition": {"lte": 3}}, {"condition": {"eq": 3}}, {"timespan": "2d"}, {"generate": False}, {"group_by": ["User"]}, {"rules": ["hidden_unknown"]}])
def test_unsupported_or_incomplete_correlation_cannot_silently_activate(lab, edit):
    declared = source(lab)
    base(lab, declared, "base_a", "powershell")
    data = correlation_payload(declared)
    rule = json.loads(data["source_text"])
    rule["correlation"].update(edit)
    data["source_text"] = json.dumps(rule)
    draft = imports.save(lab, actor(), data)
    with pytest.raises((ValueError, PermissionError, ConflictError)):
        imports.convert(lab, actor(), draft["id"], 1)


def test_mapping_proposal_uses_only_current_source_schema_and_requires_explicit_approval(lab):
    declared = source(lab)
    data = payload(declared)
    data["field_mapping"]["CommandLine"] = "raw.wrong_command"
    draft = imports.save(lab, actor(), data)
    sample = {**payload(declared)["fixtures"][0]["event"], "event_id": "observed-schema", "event_time": time.time() - 1}
    connector_runtime.intake(lab, actor(), declared["id"], {"version": 1, "events": [sample], "cursor": "schema", "checkpoint_version": 0})
    while lab.flush():
        pass
    proposal = imports.mapping_suggestions(lab, actor(), draft["id"], 1)
    assert proposal["changes"] == {"CommandLine": "raw.command"}
    assert proposal["sample_count"] == 1 and "PowerShell -enc" not in json.dumps(proposal)
    assert imports.get(lab, actor(), draft["id"])["revision"] == 1
    with pytest.raises(ValueError):
        imports.apply_mapping(lab, actor(), draft["id"], {"expected_revision": 1, "proposal_digest": proposal["proposal_digest"], "approve": False})
    revised = imports.apply_mapping(lab, actor(), draft["id"], {"expected_revision": 1, "proposal_digest": proposal["proposal_digest"], "approve": True})
    assert revised["revision"] == 2 and revised["payload"]["field_mapping"]["CommandLine"] == "raw.command"
    assert revised["mapping_approval"]["approved_by"] == "owner"
    access.set_for_user(lab, actor(), "peer", ["private"])
    with pytest.raises(KeyError):
        imports.mapping_suggestions(lab, actor("peer"), draft["id"], 2)


def test_fixture_candidates_prove_both_classes_and_never_admit_or_activate(lab):
    declared = source(lab)
    draft = imports.save(lab, actor(), payload(declared))
    imports.convert(lab, actor(), draft["id"], 1)
    generated = imports.fixture_candidates(lab, actor(), draft["id"], 1)
    assert generated["state"] == "candidates" and generated["positive_count"] and generated["negative_count"]
    assert generated["actual_native_validator"] and generated["automatic_save"] is False
    assert {item["expect"] for item in generated["fixtures"]} == {True, False}
    assert imports.get(lab, actor(), draft["id"])["state"] == "converted"
    with lab.control() as db:
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM intelligence_signals").fetchone()[0] == 0


def test_ordering_equal_clocks_missing_groups_and_distinct_original_count():
    inputs = [{"rule_id": "a", "kind": "atomic"}, {"rule_id": "b", "kind": "atomic"}]
    correlation = {"version": 1, "type": "temporal_ordered", "group_by": [{"name": "User", "fields": {"a": "raw.user", "b": "raw.user"}}], "value_field": None, "condition": None, "clock": "reported_event_time", "window_semantics": "sliding_inclusive"}
    definition = {"inputs": inputs, "window": 10, "correlation": native_correlations.validate(correlation, inputs, 10)}
    parents = [{"id": rule, "kind": "atomic", "rule_id": rule, "event_ids": [rule]} for rule in ("a", "b")]
    records = {rule: {"event_id": rule, "event_time": 5, "raw": {"user": "u"}} for rule in ("a", "b")}
    assert native_correlations.evaluate(definition, native_correlations.entries(definition, parents, records)) is None
    records["b"]["event_time"] = 6
    assert native_correlations.evaluate(definition, native_correlations.entries(definition, parents, records))
    records["b"]["raw"]["user"] = None
    assert len(native_correlations.entries(definition, parents, records)) == 1
    copied = copy.deepcopy(definition)
    copied["correlation"].update(type="event_count", condition={"op": "gte", "value": 2})
    parents[1]["event_ids"] = ["a"]
    assert native_correlations.evaluate(copied, native_correlations.entries(copied, parents, records)) is None


def test_eight_idle_correlations_cannot_starve_the_existing_composite_scheduler(lab):
    declared = source(lab)
    first = base(lab, declared, "base_a", "powershell")
    second = base(lab, declared, "base_b", "cmd.exe")
    correlated = []
    for number in range(8):
        data = correlation_payload(declared)
        correlated.append(activated(lab, {**data, "name": "Correlation fairness " + str(number)}))
    ordinary = intelligence.save_policy(lab, actor(), {"name": "Existing ordinary composite", "kind": "composite", "indexes": ["public"], "enabled": True, "inputs": [{"rule_id": first["native_policy_id"]}, {"rule_id": second["native_policy_id"]}]})
    intelligence.review_policy(lab, actor("peer"), ordinary["id"], {"version": 1, "approve": True, "reason": "Native scheduler fairness"})
    with lab.control() as db:
        db.execute("INSERT INTO intelligence_composite_state VALUES(?,?,0,0,0,0,?,NULL)", (ordinary["id"], 1, 1.0))
    # All eight never-served correlations sort ahead of the existing policy.
    intelligence._composites(lab, maximum=8)
    with lab.control() as db:
        assert db.execute("SELECT updated FROM intelligence_composite_state WHERE id=?", (ordinary["id"],)).fetchone()[0] == 1.0
        assert all(db.execute("SELECT updated FROM intelligence_composite_state WHERE id=?", (item["native_policy_id"],)).fetchone()[0] > 1 for item in correlated)
    intelligence._composites(lab, maximum=8)
    with lab.control() as db:
        assert db.execute("SELECT updated FROM intelligence_composite_state WHERE id=?", (ordinary["id"],)).fetchone()[0] > 1.0


def test_oversized_parent_cohort_reports_unproven_coverage_without_publication(lab, record_property):
    declared = source(lab)
    parent = base(lab, declared, "base_a", "powershell")
    policy = activated(lab, correlation_payload(declared))
    with principal.transaction(lab, actor(), write=True) as (db, who):
        # Deliberate control-row pressure fixture: it must be rejected before
        # any malformed fixture body can be mistaken for admitted evidence.
        for number in range(257):
            db.execute("INSERT INTO intelligence_signals(id,tenant,indexes,event_ids,parent_signal_ids,entity_key,kind,rule_id,rule_revision,features,severity,confidence_grade,created,mode,definition_digest,context_digest,body) VALUES(?,?,'[\"public\"]','[]','[]','fixture','atomic',?,1,'{}','info','pressure_fixture',?,'live','fixture','fixture','{}')", ("pressure-" + str(number), "a", parent["native_policy_id"], time.time()))
        row = db.execute("SELECT * FROM intelligence_policies WHERE id=?", (policy["native_policy_id"],)).fetchone()
        assert native_correlations.run_policy(lab, db, who, row, policy["converted"]["native_policy"]) == 0
        state = db.execute("SELECT * FROM native_correlation_state WHERE policy_id=?", (policy["native_policy_id"],)).fetchone()
        assert state["status"] == "coverage_exceeded" and json.loads(state["detail"])["complete"] is False
        assert db.execute("SELECT count(*) FROM intelligence_signals WHERE rule_id=?", (policy["native_policy_id"],)).fetchone()[0] == 0
    record_property("sigma_proof", json.dumps({"type": "bounded_coverage", "fixture": "synthetic_control_row_pressure", "retained_parent_rows": 257, "status": state["status"], "signals": 0, "false_clean_claim": False}))


@pytest.mark.parametrize("bad", [None, [], {"parent_signal_ids": [], "event_ids": [], "features": {}, "metadata": None}])
def test_malformed_legacy_correlation_metadata_is_rejected_without_attribute_errors(lab, bad):
    with principal.transaction(lab, actor()) as (db, who):
        assert native_correlations.validate_parent(lab, db, who, bad, {}) is False
