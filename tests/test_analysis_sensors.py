"""Actual decoder -> admitted originals -> approved atomic/composite -> Case.

Only owned temporary stores and inert JSON are used; no sensor or OS effect.
"""

import copy
import time
from datetime import UTC, datetime

import pytest

from sapientia import access, detections, evidence_scope, intelligence
from sapientia import sensor_adapters as sa
from sapientia.storage import ConflictError
from tests import test_backend_upgrade as backend_fixture

actor = backend_fixture.actor
lab = backend_fixture.lab


def config(sensor="suricata", **changes):
    return {
        "name": "Reviewed " + sensor,
        "sensor": sensor,
        "index": "public",
        "account": "fixture-host",
        "realm": "virtual-lab",
        "credential_ref": "env:SAPIENTIA_CONNECTOR_SENSOR",
        "mode": "replay",
        "create_case": True,
        "alert_queries": ["reviewed-alert"],
        **changes,
    }


def sample(sensor, identifier="sensor-1", alert=True):
    now = time.time() - 5
    stamp = datetime.fromtimestamp(now, UTC).isoformat()
    logs = {
        "suricata": {
            "timestamp": stamp,
            "event_type": "alert" if alert else "flow",
            "src_ip": "192.0.2.1",
            "src_port": 50000,
            "dest_ip": "198.51.100.2",
            "dest_port": 443,
            "proto": "TCP",
            **(
                {
                    "alert": {
                        "signature": "Inert test signature",
                        "signature_id": 900001,
                        "severity": 2,
                    }
                }
                if alert
                else {}
            ),
        },
        "zeek": {
            "ts": now,
            "uid": "fixture-conn",
            "id.orig_h": "192.0.2.1",
            "id.orig_p": 50000,
            "id.resp_h": "198.51.100.2",
            "id.resp_p": 443,
            "proto": "tcp",
            **(
                {"note": "Fixture::Observation", "msg": "inert notice"}
                if alert
                else {"orig_bytes": 300, "resp_bytes": 400}
            ),
        },
        "falco": {
            "time": stamp,
            "hostname": "fixture-host",
            "rule": "Inert test rule",
            "priority": "Warning" if alert else "Notice",
            "output_fields": {
                "proc.pid": 731,
                "proc.name": "inert",
                "proc.cmdline": "inert --observe",
            },
        },
        "tetragon": {
            "time": stamp,
            "node_name": "fixture-host",
            "process_kprobe": {
                "process": {
                    "pid": 731,
                    "exec_id": "reported-exec-id",
                    "binary": "/fixture/inert",
                    "start_time": stamp,
                },
                "policy_name": "reviewed-alert" if alert else "unknown-policy",
            },
        },
        "osquery": {
            "unixTime": now,
            "hostIdentifier": "fixture-host",
            "name": "reviewed-alert" if alert else "inventory",
            "action": "added",
            "columns": {"pid": "731", "name": "inert"},
        },
    }
    return {
        "id": identifier,
        "log": logs[sensor],
        **({"kind": "notice" if alert else "conn"} if sensor == "zeek" else {}),
    }


def binding(lab, sensor="suricata", **changes):
    sa.initialize(lab)
    saved = sa.save(lab, actor(), config(sensor, **changes))
    return sa.review(
        lab,
        actor("peer"),
        saved["id"],
        {
            "version": 1,
            "approve": True,
            "reason": "Reviewed inert fixture adapter, source, mode and Case scope",
        },
    )


def intake(lab, saved, events, cursor="fixture", checkpoint=0):
    return sa.intake(
        lab,
        actor(),
        saved["id"],
        {
            "version": 1,
            "events": events,
            "cursor": cursor,
            "checkpoint_version": checkpoint,
        },
    )


def tick(lab):
    while lab.flush():
        pass
    for _ in range(4):
        intelligence.run_due(lab, budget=2, max_runs=32)


@pytest.mark.parametrize("sensor", sa.SENSORS)
def test_all_five_real_parsers_receipts_atomic_signal_and_case(lab, sensor):
    saved = binding(lab, sensor)
    positive, negative = (
        sample(sensor, sensor + "-positive"),
        sample(sensor, sensor + "-negative", False),
    )
    result = intake(lab, saved, [positive, negative])
    assert (
        result["mode"] == "replay"
        and result["durable"]
        and not result["sensor_installation_verified"]
    )
    tick(lab)
    atomic = [
        r
        for r in intelligence.signals(lab, actor(), count=100)["items"]
        if r["rule_id"] == saved["policy_id"]
    ]
    assert len(atomic) == 1 and atomic[0]["event_ids"] == [positive["id"]]
    assert atomic[0]["confidence_grade"] == "replayed_sensor_alert_fixture"
    assert not atomic[0]["automatic_endpoint_authorization"]
    cases = detections.incident_list(lab, actor())
    assert len(cases) == 1
    with lab.control() as db:
        proof = db.execute(
            "SELECT * FROM source_event_receipts WHERE tenant='a' AND event_id=?",
            (positive["id"],),
        ).fetchone()
        assert proof["source_id"] == saved["source_id"]
        assert db.execute("SELECT count(*) FROM endpoint_responses").fetchone()[0] == 0
    listed = sa.listing(lab, actor())["items"][0]
    assert listed["received_originals"] == 2 and listed["coverage"] == "replay_fixture"


def test_source_review_current_acl_revocation_and_retry_boundaries(lab):
    sa.initialize(lab)
    pending = sa.save(lab, actor(), config())
    with pytest.raises(ConflictError):
        intake(lab, pending, [sample("suricata")])
    with pytest.raises(PermissionError):
        sa.review(
            lab,
            actor(),
            pending["id"],
            {"version": 1, "approve": True, "reason": "self"},
        )
    approved = sa.review(
        lab,
        actor("peer"),
        pending["id"],
        {"version": 1, "approve": True, "reason": "independent"},
    )
    event = sample("suricata")
    first = intake(lab, approved, [event])
    second = intake(lab, approved, [event])
    assert first["checkpoint_version"] == second["checkpoint_version"] == 1
    with pytest.raises(ConflictError):
        intake(lab, approved, [sample("suricata", "changed")])
    access.set_for_user(lab, actor(), "peer", ["other"])
    with pytest.raises(PermissionError):
        intake(lab, approved, [sample("suricata", "revoked-review")], "next", 1)
    assert (
        sa.listing(lab, actor())["items"][0]["effective_state"] == "authority_changed"
    )
    access.set_for_user(lab, actor(), "peer", ["*"])
    sa.revoke(
        lab, actor(), approved["id"], {"version": 1, "reason": "source retirement"}
    )
    with pytest.raises(ConflictError):
        intake(lab, approved, [sample("suricata", "revoked")], "next", 1)


def test_foreign_viewer_and_outside_index_never_receive_sensor_authority(lab):
    saved = binding(lab)
    assert sa.listing(lab, actor("foreign", "b"))["items"] == []
    with pytest.raises(KeyError):
        sa.revoke(
            lab, actor("foreign", "b"), saved["id"], {"version": 1, "reason": "foreign"}
        )
    with pytest.raises(PermissionError):
        sa.save(lab, actor("reader", role="viewer"), config())
    access.set_for_user(lab, actor(), "owner", ["other"])
    with pytest.raises(KeyError):
        intake(lab, saved, [sample("suricata")])


@pytest.mark.parametrize("sensor", sa.SENSORS)
def test_bad_timestamp_unknown_fields_oversize_and_host_mismatch_rejected(lab, sensor):
    saved = binding(lab, sensor)
    with lab.control() as db:
        source = dict(sa.source_registry.visible(db, actor(), saved["source_id"]))
    event = sample(sensor)
    invalid = {**event, "arbitrary": "decoder override"}
    with pytest.raises(ValueError):
        sa.decode(invalid, source)
    huge = copy.deepcopy(event)
    huge["log"]["oversize"] = "x" * (49 * 1024)
    with pytest.raises(ValueError):
        sa.decode(huge, source)
    broken = copy.deepcopy(event)
    broken["log"][
        "ts"
        if sensor == "zeek"
        else "unixTime"
        if sensor == "osquery"
        else "timestamp"
        if sensor == "suricata"
        else "time"
    ] = "2026-01-01T00:00:00"
    with pytest.raises(ValueError):
        sa.decode(broken, source)
    if sensor in {"falco", "tetragon", "osquery"}:
        mismatch = copy.deepcopy(event)
        mismatch["log"][
            {"falco": "hostname", "tetragon": "node_name", "osquery": "hostIdentifier"}[
                sensor
            ]
        ] = "other-device"
        with pytest.raises(PermissionError):
            sa.decode(mismatch, source)


def test_unreviewed_query_is_observation_and_reported_health_is_not_install_proof(
    lab, monkeypatch
):
    saved = binding(lab, "osquery", create_case=False)
    intake(lab, saved, [sample("osquery", "inventory", False)])
    tick(lab)
    assert not [
        s
        for s in intelligence.signals(lab, actor())["items"]
        if s["rule_id"] == saved["policy_id"]
    ]
    report = sa.health_report(
        lab,
        actor(),
        saved["id"],
        {
            "version": 1,
            "state": "degraded",
            "captured": 120,
            "dropped": 3,
            "sensor_version": "fixture-1",
        },
    )
    assert report["reported_not_independently_verified"] and report["dropped"] == 3
    assert sa.listing(lab, actor())["items"][0]["installation_verified"] is False
    monkeypatch.setattr(sa.shutil, "which", lambda _: None)
    assert all(
        e["local_runtime_status"] == "unavailable" for e in sa.catalog()["items"]
    )
    monkeypatch.setattr(sa.shutil, "which", lambda _: "/unqualified/sensor")
    assert all(
        e["local_runtime_status"] == "executable_found_not_qualified"
        and not e["installation_verified"]
        for e in sa.catalog()["items"]
    )


def test_sensor_and_independent_atomic_evidence_form_real_composite_case(lab):
    saved = binding(lab, create_case=False)
    event = sample("suricata", "sensor-flow-alert")
    other = sample("suricata", "second-flow-observation", False)
    at = datetime.fromisoformat(event["log"]["timestamp"]).timestamp()
    other["log"]["timestamp"] = datetime.fromtimestamp(at + 0.01, UTC).isoformat()
    atomic = intelligence.save_policy(
        lab,
        actor(),
        {
            "name": "Independent flow observation",
            "kind": "atomic",
            "indexes": ["public"],
            "enabled": True,
            "filters": [{"field": "event.event_id", "op": "eq", "value": other["id"]}],
        },
    )
    intelligence.review_policy(
        lab,
        actor("peer"),
        atomic["id"],
        {"version": 1, "approve": True, "reason": "separate original"},
    )
    composite = intelligence.save_policy(
        lab,
        actor(),
        {
            "name": "Sensor and flow corroboration",
            "kind": "composite",
            "indexes": ["public"],
            "enabled": True,
            "inputs": [{"rule_id": saved["policy_id"]}, {"rule_id": atomic["id"]}],
            "join_on": "flow",
            "minimum_independent_groups": 2,
            "case_adapter": {
                "entity_field": "host",
                "risk_score": 65,
                "severity": "high",
                "mitre": [],
                "cooldown": 0,
            },
        },
    )
    intelligence.review_policy(
        lab,
        actor("peer"),
        composite["id"],
        {"version": 1, "approve": True, "reason": "independent composite approval"},
    )
    intake(lab, saved, [event, other])
    tick(lab)
    combined = next(
        s
        for s in intelligence.signals(lab, actor())["items"]
        if s["rule_id"] == composite["id"]
    )
    assert set(combined["event_ids"]) == {event["id"], other["id"]}
    assert combined["evidence_dependency"]["disjoint_original_groups"] == 2
    assert len(detections.incident_list(lab, actor())) == 1


def test_decode_preserves_sensor_source_and_never_invents_process_identity(lab):
    saved = binding(lab, "falco")
    with lab.control() as db:
        source = dict(sa.source_registry.visible(db, actor(), saved["source_id"]))
    original = sample("falco")
    parsed = sa.decode(original, source)
    assert parsed["raw"]["sensor_original"] == original["log"]
    assert "guid" not in parsed["raw"]["xdr"]["data"]["process"]
    assert not parsed["raw"]["sensor_analysis"]["native_capture_proven"]
    assert not parsed["raw"]["sensor_analysis"]["packet_inspection_performed_by_xsera"]


def test_official_osquery_string_numerics_and_legacy_hostname_are_supported(lab):
    saved = binding(lab, "osquery")
    with lab.control() as db:
        source = dict(sa.source_registry.visible(db, actor(), saved["source_id"]))
    event = sample("osquery")
    event["log"]["unixTime"] = str(int(time.time() - 10))
    event["log"]["hostname"] = event["log"].pop("hostIdentifier")
    event["log"]["numerics"] = False
    parsed = sa.decode(event, source)
    assert parsed["event_time"] == int(event["log"]["unixTime"])
    assert parsed["raw"]["sensor_original"]["unixTime"] == event["log"]["unixTime"]


def test_tetragon_explicit_parent_and_container_evidence_is_preserved(lab):
    saved = binding(lab, "tetragon")
    with lab.control() as db:
        source = dict(sa.source_registry.visible(db, actor(), saved["source_id"]))
    event = sample("tetragon")
    process = event["log"]["process_kprobe"]["process"]
    process["parent_exec_id"] = "explicit-parent"
    process["pod"] = {
        "namespace": "fixture-namespace",
        "container": {"id": "reported-container"},
    }
    event["log"]["process_kprobe"]["parent"] = {"exec_id": "explicit-parent"}
    parsed = sa.decode(event, source)["raw"]["xdr"]["data"]
    assert parsed["process"]["parent"]["guid"] == "explicit-parent"
    assert parsed["container"] == {
        "id": "reported-container",
        "namespace": "fixture-namespace",
    }
    event["log"]["process_kprobe"]["parent"]["exec_id"] = "conflicting-parent"
    with pytest.raises(ValueError, match="Conflicting"):
        sa.decode(event, source)


@pytest.mark.parametrize(
    ("kind", "reported", "canonical"),
    [
        ("process_exec", "process_created", "process_create"),
        ("process_exit", "process_terminated", "process_terminate"),
    ],
)
def test_tetragon_exec_and_exit_survive_admission_and_create_reviewed_case(
    lab, kind, reported, canonical
):
    saved = binding(lab, "tetragon", mode="live")
    observed = sample("tetragon", "tetragon-" + kind)
    observed["log"][kind] = observed["log"].pop("process_kprobe")
    result = intake(lab, saved, [observed])
    assert result["durable"] and result["mode"] == "live"
    tick(lab)
    original = evidence_scope.originals(lab, actor(), [observed["id"]])[observed["id"]]
    assert original["raw"]["sensor_original"] == observed["log"]
    assert original["raw"]["security"]["action"] == canonical
    assert original["raw"]["xdr"]["data"]["event"]["action"] == reported
    signals = [
        row
        for row in intelligence.signals(lab, actor())["items"]
        if row["rule_id"] == saved["policy_id"]
    ]
    assert len(signals) == 1 and signals[0]["event_ids"] == [observed["id"]]
    assert len(detections.incident_list(lab, actor())) == 1
    with lab.control() as db:
        assert db.execute("SELECT count(*) FROM endpoint_responses").fetchone()[0] == 0
