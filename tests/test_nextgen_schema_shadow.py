"""Real isolated migration/intake/detector regressions against disposable stores."""

import copy
import json
import time

import pytest

from sapientia import access, connector_runtime, detections, identity_resolver, ocsf_mapping, security_schema, shadow_analysis, source_registry
from sapientia.storage import CapacityError, ConflictError
from tests.test_backend_upgrade import lab, actor


def sample():
    return {"event_id": "observed", "event_time": 100.0, "index": "public", "host": "asset", "source": "json",
            "raw": {"xdr": {"data": {"event": {"action": "process_observed", "occurrence_time": 99.0},
                                     "process": {"guid": "P", "pid": 123, "start_identity": "start"}}}}}


AUTHORITY = {"id": "source", "version": 1, "product": "json", "realm": "lab", "account": "asset"}


def test_observed_process_is_never_converted_into_launch_and_unknown_is_typed():
    event = sample()
    before = copy.deepcopy(event)
    result = security_schema.project(event, AUTHORITY)
    assert event == before
    assert result["version"] == 4 and security_schema.SUPPORTED_VERSIONS == (3, 4)
    assert result["event_semantics"]["kind"] == "observation"
    assert result["event_semantics"]["occurrence_time"] is None
    assert result["event_semantics"]["observed_time"] == 100.0
    assert result["device"]["boot_id"] is None
    assert result["ocsf"]["activity_id"] == 99
    assert result["ocsf"]["class_uid"] == 1007
    assert result["ocsf"]["unmapped"]["xsera"]["conformance_certified"] is False
    event["raw"]["xdr"]["data"]["host"] = {"boot_id": True, "id": 7}
    event["raw"]["xdr"]["data"]["event"]["timestamp_precision_seconds"] = True
    wrong = security_schema.project(event, AUTHORITY)
    assert wrong["device"]["uid"] is wrong["device"]["boot_id"] is wrong["clock_precision"] is None


def test_boot_container_and_file_generation_block_reused_process_and_path_identity():
    a = security_schema.project(sample(), AUTHORITY)
    b = copy.deepcopy(a)
    a["device"].update(uid="device", boot_id="boot-a")
    b["device"].update(uid="device", boot_id="boot-b")
    assert identity_resolver.relation_key(None, None, a, "process") != identity_resolver.relation_key(None, None, b, "process")
    assert identity_resolver.relation_key(None, None, a, "boot") != identity_resolver.relation_key(None, None, b, "boot")
    assert identity_resolver.relation_key(None, None, a, "device") == identity_resolver.relation_key(None, None, b, "device")
    a["file"]["path"] = "C:/same.exe"
    assert identity_resolver.relation_key(None, None, a, "file_object") is None
    a["file"].update(volume_id="volume", object_id="inode", generation="one")
    b = copy.deepcopy(a); b["file"]["generation"] = "two"
    assert identity_resolver.relation_key(None, None, a, "file_object") != identity_resolver.relation_key(None, None, b, "file_object")
    b = copy.deepcopy(a); b["process"].update(guid="child", parent_guid="P", parent_start_identity="wrong")
    assert identity_resolver.parent_link(a, b) is False
    b["process"]["parent_start_identity"] = "start"
    assert identity_resolver.parent_link(a, b) is True


def test_v3_projection_readers_remain_supported_without_invented_ids():
    projected = security_schema.project(sample(), AUTHORITY)
    for key in ("ocsf", "event_semantics", "device", "file", "container", "identity_contract"):
        projected.pop(key)
    projected["version"] = 3
    assert ocsf_mapping.project(projected)["metadata"]["version"] == "1.4.0"
    assert identity_resolver.relation_key(None, None, projected, "process")
    assert identity_resolver.relation_key(None, None, projected, "boot") is None


def rule(field="raw.security.action", value="process_create", name="Launch"):
    return {"name": name, "entity_field": "host", "window": 600, "interval": 30,
            "risk_score": 50, "severity": "high", "steps": [{"name": "Match", "min_count": 1,
            "filters": [{"field": field, "op": "eq", "value": value}]}]}


def freeze_input(store):
    shadow_analysis.initialize(store)
    source = source_registry.save(store, actor(), {"index": "public", "product": "json", "account": "asset", "realm": "lab",
                                                   "credential_ref": "env:SAPIENTIA_CONNECTOR_LAB", "version": 0})
    at = time.time()-100
    events = [{"event_id": "start", "event_time": at, "host": "asset", "raw": {"action": "process_created",
               "xdr": {"data": {"event": {"action": "process_created"}, "process": {"guid": "P", "start_identity": "boot/start"}}}}},
              {"event_id": "observe", "event_time": at+1, "host": "asset", "raw": {"xdr": {"data": {
                   "event": {"action": "process_observed"}, "process": {"guid": "P", "start_identity": "boot/start"}}}}}]
    connector_runtime.intake(store, actor(), source["id"], {"version": 1, "events": events, "cursor": "two", "checkpoint_version": 0})
    store.flush()
    return source, at, {"start": at-1, "end": at+10, "indexes": ["public"],
                        "baseline_rules": [{"id": "launch", "definition": rule()}],
                        "candidate_rules": [{"id": "launch", "definition": rule("raw.analysis.ocsf.activity_id", 1)}]}


def counts(store):
    with store.control() as db:
        return {table: db.execute("SELECT count(*) FROM " + table).fetchone()[0] for table in
                ("incidents", "risk_contributions", "findings", "soar_runs", "endpoint_responses", "correlation_window_progress")}


def test_real_exact_shadow_uses_ocsf_view_and_replay_is_identical_after_new_intake(lab):
    source, at, request = freeze_input(lab)
    before = counts(lab)
    result = shadow_analysis.run_compare(lab, actor(), request)
    assert result["live_effects"] is False and result["event_count"] == 2
    assert len(result["baseline"]) == len(result["candidate"]) == 1
    assert result["candidate"][0]["event_ids"] == ["start"]
    assert counts(lab) == before
    connector_runtime.intake(lab, actor(), source["id"], {"version": 1, "events": [{"event_id": "late", "event_time": at+2,
        "host": "asset", "raw": {"action": "process_created"}}], "cursor": "three", "checkpoint_version": 1})
    lab.flush()
    replayed = shadow_analysis.replay(lab, actor(), result["id"])
    assert replayed["identical"] is True
    assert replayed["result_digest"] == result["result_digest"]
    assert shadow_analysis.get(lab, actor(), result["id"])["event_count"] == 2
    assert counts(lab) == before


def test_shadow_detects_added_signal_and_does_not_create_live_case(lab):
    _, _, request = freeze_input(lab)
    request["baseline_rules"] = []
    request["candidate_rules"] = [{"id": "observation", "definition": rule("raw.analysis.projection.event_semantics.kind", "observation")}]
    result = shadow_analysis.run_compare(lab, actor(), request)
    assert len(result["comparison"]["added"]) == 1
    assert result["candidate"][0]["event_ids"] == ["observe"]
    assert counts(lab)["incidents"] == 0


def test_shadow_authority_boundaries_tamper_and_budget_reject_before_publication(lab):
    _, _, request = freeze_input(lab)
    with pytest.raises(CapacityError):
        shadow_analysis.run_compare(lab, actor(), {**request, "max_events": 1})
    with pytest.raises(ConflictError):
        shadow_analysis.run_compare(lab, actor(), {**request, "expected_context_digest": "wrong"})
    result = shadow_analysis.run_compare(lab, actor(), request)
    with pytest.raises(KeyError):
        shadow_analysis.get(lab, actor("foreign", "b"), result["id"])
    access.set_for_user(lab, actor("peer"), "owner", ["other"])
    with pytest.raises(KeyError):
        shadow_analysis.get(lab, actor(), result["id"])
    with pytest.raises(PermissionError):
        shadow_analysis.replay(lab, actor("peer"), result["id"])
    access.set_for_user(lab, actor("peer"), "owner", ["*"])
    with lab.control() as db:
        db.execute("UPDATE shadow_compare_runs SET result='{}' WHERE id=?", (result["id"],))
    with pytest.raises(ConflictError):
        shadow_analysis.get(lab, actor(), result["id"])


def test_existing_policy_owner_is_rechecked_and_frozen_state_ignores_policy_edits(lab):
    _, _, request = freeze_input(lab)
    saved = detections.save(lab, actor("peer"), rule())
    request.pop("baseline_rules"); request.pop("candidate_rules")
    request["policy_ids"] = [saved]
    result = shadow_analysis.run_compare(lab, actor(), request)
    with lab.control() as db:
        db.execute("UPDATE correlation_policies SET definition=? WHERE id=?", (json.dumps(detections.validate(rule(value="logout"))), saved))
    assert shadow_analysis.replay(lab, actor(), result["id"])["identical"]
    access.set_for_user(lab, actor(), "peer", ["other"])
    with pytest.raises(PermissionError):
        shadow_analysis.replay(lab, actor(), result["id"])


def test_shadow_context_drift_cannot_publish_half_pinned_run(lab, monkeypatch):
    source, _, request = freeze_input(lab)
    original = shadow_analysis._compare

    def changing(store, snapshot):
        result = original(store, snapshot)
        source_registry.revoke(store, actor(), source["id"], 1)
        return result

    monkeypatch.setattr(shadow_analysis, "_compare", changing)
    with pytest.raises(ConflictError):
        shadow_analysis.run_compare(lab, actor(), request)
    assert shadow_analysis.listing(lab, actor())["items"] == []


def test_frozen_exact_detector_pages_all_chains_past_128(lab):
    source, at, request = freeze_input(lab)
    events = []
    for n in range(140):
        for action, offset in (("process_created", 0.2), ("process_terminated", 0.4)):
            events.append({"event_id": f"{action}-{n:03}", "event_time": at+n+offset, "host": "asset",
                           "raw": {"action": action}})
    connector_runtime.intake(lab, actor(), source["id"], {"version": 1, "events": events,
                              "cursor": "chains", "checkpoint_version": 1})
    while lab.flush():
        pass
    definition = rule()
    definition["steps"].append({"name": "Exit", "min_count": 1, "within_seconds": 1,
                                  "filters": [{"field": "raw.security.action", "op": "eq", "value": "process_terminate"}]})
    request.update(end=at+200, baseline_rules=[{"id": "chain", "definition": definition}], candidate_rules=[{"id": "chain", "definition": definition}])
    result = shadow_analysis.run_compare(lab, actor(), request)
    assert len(result["baseline"]) == len(result["candidate"]) == 140
    assert result["comparison"]["unchanged"] == 140
    assert shadow_analysis.replay(lab, actor(), result["id"])["identical"]


def test_vendor_cannot_supply_candidate_reserved_projection_without_registered_proof(lab):
    shadow_analysis.initialize(lab)
    at = time.time()-100
    lab.ingest("a", [{"event_id": "spoof", "event_time": at, "host": "asset", "index": "public",
                       "raw": {"analysis": {"ocsf": {"activity_id": 1}}}}], "owner", ["public"])
    lab.flush()
    result = shadow_analysis.run_compare(lab, actor(), {"start": at-1, "end": at+1, "indexes": ["public"],
                "baseline_rules": [], "candidate_rules": [{"id": "launch", "definition": rule("raw.analysis.ocsf.activity_id", 1)}]})
    assert result["candidate"] == [] and result["projection_count"] == 0
