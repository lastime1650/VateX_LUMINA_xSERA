"""Source-backed identity/governance/risk/latency and safe file verdict checks."""

import hashlib
import json
import struct
import time
import uuid

import pytest

from sapientia import (
    access,
    auth,
    detections,
    entities,
    endpoint_artifacts,
    evidence_scope,
    file_verdicts,
    pipeline_slo,
    principal,
    risk_priority,
    runtime,
    temporal_identity,
)
from sapientia import (
    detection_governance as governance,
)
from sapientia.storage import ConflictError, Settings, Store, encode


@pytest.fixture
def platform(tmp_path):
    store = Store(Settings(tmp_path, min_free_bytes=0))
    for module in (
        temporal_identity,
        governance,
        risk_priority,
        pipeline_slo,
        file_verdicts,
    ):
        module.initialize(store)
    actors = {}
    for name, tenant, role in [
        ("requester", "a", "admin"),
        ("approver", "a", "admin"),
        ("restricted", "a", "analyst"),
        ("reader", "a", "viewer"),
        ("foreign", "b", "admin"),
    ]:
        auth.create_user(
            store, name, "Synthetic-gap-qualification-password-2026", role, tenant
        )
        actors[name] = {
            "name": name,
            "tenant": tenant,
            "role": role,
            "allowed_indexes": ["*"],
        }
    access.set_for_user(store, actors["requester"], "restricted", ["public"])
    actors["restricted"]["allowed_indexes"] = ["public"]
    now = time.time()
    rows = [
        {
            "event_id": "lease",
            "event_time": now - 5,
            "index": "public",
            "source": "dhcp",
            "host": "host-a",
            "raw": {"ip": "10.0.0.10", "user": "alice", "session": "session-a"},
        },
        {
            "event_id": "nat",
            "event_time": now - 4,
            "index": "public",
            "source": "fortigate",
            "host": "host-a",
            "raw": {
                "src_ip": "203.0.113.10",
                "src_port": 40000,
                "dest_ip": "198.51.100.10",
                "dest_port": 443,
                "protocol": "tcp",
                "inner_ip": "10.0.0.10",
                "inner_port": 50000,
            },
        },
        {
            "event_id": "attack",
            "event_time": now - 3,
            "index": "public",
            "source": "endpoint",
            "host": "host-a",
            "severity": "high",
            "raw": {"user": "alice"},
        },
        {
            "event_id": "secret",
            "event_time": now - 2,
            "index": "private",
            "source": "restricted-feed",
            "host": "host-b",
            "raw": {"ip": "10.0.0.10", "user": "alice"},
        },
    ]
    store.ingest("a", rows)
    with store.control() as db:
        queue = [dict(row) for row in db.execute("SELECT * FROM queue ORDER BY seq")]
    store.flush()
    with store.control() as db:
        pipeline_slo.journal_indexed(store, db, queue)
    asset = entities.save(
        store,
        actors["requester"],
        {
            "kind": "host",
            "name": "Test asset A",
            "indexes": ["public"],
            "criticality": 5,
            "aliases": [{"type": "hostname", "value": "host-a"}],
        },
    )
    second = entities.save(
        store,
        actors["requester"],
        {
            "kind": "host",
            "name": "Test asset B",
            "indexes": ["private"],
            "criticality": 2,
            "aliases": [{"type": "hostname", "value": "host-b"}],
        },
    )
    policy = detections.save(
        store,
        actors["requester"],
        {
            "name": "Gap fixture detection",
            "entity_field": "host",
            "window": 300,
            "severity": "high",
            "risk_score": 80,
            "steps": [
                {"filters": [{"field": "event_id", "op": "eq", "value": "attack"}]}
            ],
        },
    )
    assert detections.run_due(store, time.time() + 1) == 1
    case = detections.incident_list(store, actors["requester"])[0]
    with store.control() as db:
        pipeline_slo.journal_case(
            store, db, "a", case["id"], policy, ["attack"], ["public"]
        )
        match = json.loads(
            db.execute(
                "SELECT evidence FROM risk_contributions WHERE incident_id=?",
                (case["id"],),
            ).fetchone()[0]
        )
        policy_row = dict(
            db.execute(
                "SELECT * FROM correlation_policies WHERE id=?", (policy,)
            ).fetchone()
        )
    yield {
        "store": store,
        "actors": actors,
        "now": now,
        "asset": asset,
        "second": second,
        "policy": policy_row,
        "case": case,
        "match": match,
        "queue": queue,
    }
    store.close()


def binding(fixture, *, entity=None, source="lease", session="session-a"):
    return {
        "kind": "ip",
        "lookup": "10.0.0.10",
        "entity_id": (entity or fixture["asset"])["id"],
        "session_id": session,
        "valid_from": fixture["now"] - 10,
        "valid_until": fixture["now"] + 60,
        "reason": "Explicit DHCP lease observation",
        "evidence": [{"event_id": source, "fields": {"raw.ip": "10.0.0.10"}}],
    }


def test_identity_lease_time_boundary_and_peer_overlap_are_not_ip_attribution(platform):
    store, who = platform["store"], platform["actors"]["requester"]
    first = temporal_identity.save(store, who, binding(platform))
    assert (
        temporal_identity.resolve(store, who, "ip", "10.0.0.10", platform["now"])[
            "entity_id"
        ]
        == platform["asset"]["id"]
    )
    assert (
        temporal_identity.resolve(store, who, "ip", "10.0.0.10", first["valid_until"])[
            "status"
        ]
        == "unresolved"
    )
    second = temporal_identity.save(
        store,
        who,
        binding(
            platform, entity=platform["second"], source="secret", session="session-b"
        ),
    )
    result = temporal_identity.resolve(store, who, "ip", "10.0.0.10", platform["now"])
    assert result["status"] == "ambiguous" and result["entity_id"] is None
    assert not result["automatic_attribution"]
    assert (
        temporal_identity.resolve(
            store, who, "ip", "10.0.0.10", platform["now"], "session-a"
        )["entity_id"]
        == platform["asset"]["id"]
    )
    limited = temporal_identity.resolve(
        store, platform["actors"]["restricted"], "ip", "10.0.0.10", platform["now"]
    )
    assert limited["status"] == "unresolved" and limited["entity_id"] is None
    assert (
        len(limited["candidates"]) == 1
    )  # hidden overlap cannot yield a false unique attribution
    temporal_identity.revoke(
        store, who, second["id"], second["version"], "Lease superseded"
    )
    assert (
        temporal_identity.resolve(store, who, "ip", "10.0.0.10", platform["now"])[
            "status"
        ]
        == "resolved"
    )
    assert len(temporal_identity.history(store, who, second["id"])) == 2


def test_identity_proof_cannot_invent_field_type_or_foreign_source(platform):
    store, who = platform["store"], platform["actors"]["requester"]
    data = binding(platform)
    data["lookup"] = "10.0.0.99"
    with pytest.raises(ValueError, match="Every lookup"):
        temporal_identity.save(store, who, data)
    data = binding(platform)
    data["evidence"][0]["fields"] = {"raw.user": ["alice"]}
    with pytest.raises(ValueError, match="typed scalar"):
        temporal_identity.save(store, who, data)
    with pytest.raises(KeyError):
        temporal_identity.save(store, platform["actors"]["foreign"], binding(platform))
    with pytest.raises(KeyError):
        temporal_identity.save(
            store,
            platform["actors"]["restricted"],
            binding(platform, entity=platform["second"], source="secret"),
        )
    with pytest.raises(PermissionError):
        temporal_identity.save(store, platform["actors"]["reader"], binding(platform))


def test_identity_nat_requires_exact_original_complete_five_tuple(platform):
    data = binding(platform)
    value = {
        "src_ip": "203.0.113.10",
        "src_port": 40000,
        "dest_ip": "198.51.100.10",
        "dest_port": 443,
        "protocol": "tcp",
    }
    data.update(
        kind="nat",
        lookup=value,
        translated={**value, "src_ip": "10.0.0.10", "src_port": 50000},
        evidence=[
            {
                "event_id": "nat",
                "fields": {
                    "raw." + key: item
                    for key, item in {
                        **value,
                        "inner_ip": "10.0.0.10",
                        "inner_port": 50000,
                    }.items()
                },
            }
        ],
    )
    store, who = platform["store"], platform["actors"]["requester"]
    temporal_identity.save(store, who, data)
    assert (
        temporal_identity.resolve(store, who, "nat", value, platform["now"])["status"]
        == "resolved"
    )
    assert (
        temporal_identity.resolve(
            store, who, "nat", {**value, "src_port": 40001}, platform["now"]
        )["status"]
        == "unresolved"
    )
    assert (
        temporal_identity.resolve(store, who, "ip", value["src_ip"], platform["now"])[
            "status"
        ]
        == "unresolved"
    )
    with pytest.raises(ValueError):
        temporal_identity.resolve(
            store, who, "nat", {"src_ip": value["src_ip"]}, platform["now"]
        )


def test_identity_revision_and_immutable_history_scope(platform):
    store, who = platform["store"], platform["actors"]["requester"]
    data = binding(platform)
    original = temporal_identity.save(store, who, data)
    with pytest.raises(ConflictError):
        temporal_identity.save(store, who, data, original["id"])
    updated = temporal_identity.save(
        store,
        who,
        {**data, "version": original["version"], "valid_until": platform["now"] + 120},
        original["id"],
    )
    assert updated["version"] == 2
    history = temporal_identity.history(store, who, original["id"])
    assert history[0]["record"]["valid_until"] != history[1]["record"]["valid_until"]
    assert history[0]["record"]["evidence"][0]["admission_digest"]
    assert (
        temporal_identity.list_bindings(store, platform["actors"]["foreign"])["items"]
        == []
    )


def test_identity_admission_receipt_retirement_blocks_new_proof(platform):
    store, who = platform["store"], platform["actors"]["requester"]
    with store.control() as db:
        db.execute("DELETE FROM receipts WHERE tenant='a' AND event_id='lease'")
    with pytest.raises(ConflictError, match="receipt"):
        temporal_identity.save(store, who, binding(platform))


def storm(fixture, **overrides):
    return {
        "kind": "storm",
        "policy_id": fixture["policy"]["id"],
        "indexes": ["public"],
        "expires": time.time() + 3600,
        "reason": "Per-entity bounded analyst workload",
        "max_per_window": 2,
        "window_seconds": 60,
        **overrides,
    }


def decide(fixture, suffix, *, severity="medium", entity="host-a", at=None):
    store = fixture["store"]
    match = {
        **fixture["match"],
        "event_ids": ["candidate-" + suffix],
        "severity": severity,
        "entity": entity,
    }
    with principal.transaction(
        store, fixture["actors"]["requester"], ("admin", "analyst"), write=True
    ) as (db, actor):
        return governance._govern_candidate(
            db, store, actor, fixture["policy"], match, observed_at=at
        )


def test_storm_preserves_first_events_critical_and_other_entities(platform):
    store, requester, approver = (
        platform["store"],
        platform["actors"]["requester"],
        platform["actors"]["approver"],
    )
    rule = governance.save(store, requester, storm(platform))
    assert decide(platform, "pending")[
        "allowed"
    ]  # pending rule is not a suppression authority
    with pytest.raises(PermissionError):
        governance.review(
            store, requester, rule["id"], rule["version"], True, "Self approval"
        )
    governance.review(
        store, approver, rule["id"], rule["version"], True, "Reviewed benign noise risk"
    )
    at = int(time.time() // 60) * 60 + 5
    assert decide(platform, "1", at=at)["allowed"]
    assert decide(platform, "2", at=at)["allowed"]
    third = decide(platform, "3", at=at)
    assert not third["allowed"] and third["count"] == 3
    assert decide(platform, "3", at=at)["duplicate"]
    assert decide(platform, "critical", severity="critical", at=at)["allowed"]
    assert decide(platform, "new-entity", entity="host-b", at=at)["allowed"]
    assert decide(platform, "new-window", at=at + 60)["allowed"]
    report = governance.decisions(store, requester, at - 60, at + 120)
    assert report["suppressed"] == 1 and not report["telemetry_deleted"]
    assert (
        governance.decisions(store, platform["actors"]["foreign"], at - 60, at + 120)[
            "items"
        ]
        == []
    )


def test_storm_revocation_authority_and_policy_revision_fail_open(platform):
    store, requester, approver = (
        platform["store"],
        platform["actors"]["requester"],
        platform["actors"]["approver"],
    )
    rule = governance.save(store, requester, storm(platform, max_per_window=1))
    governance.review(store, approver, rule["id"], 1, True, "Peer approval")
    at = time.time()
    decide(platform, "one", at=at)
    assert not decide(platform, "two", at=at)["allowed"]
    access.set_for_user(store, requester, "approver", [])
    assert decide(platform, "authority-lost", at=at)["allowed"]
    governance.revoke(store, requester, rule["id"], 1, "Remove exception risk")
    assert decide(platform, "revoked", at=at)["allowed"]
    with store.control() as db:
        db.execute(
            "UPDATE correlation_policies SET version=version+1 WHERE id=?",
            (platform["policy"]["id"],),
        )
    with pytest.raises(ConflictError):
        decide(platform, "old-policy")


def test_expiring_exception_requires_adjudicated_evidence_and_reapproval(platform):
    store, requester, approver = (
        platform["store"],
        platform["actors"]["requester"],
        platform["actors"]["approver"],
    )
    data = {
        "kind": "exception",
        "policy_id": platform["policy"]["id"],
        "indexes": ["public"],
        "expires": time.time() + 3600,
        "reason": "Approved synthetic maintenance",
        "case_id": platform["case"]["id"],
        "conditions": [
            {"field": "entity", "op": "eq", "value": "host-a"},
            {"field": "source", "op": "eq", "value": "endpoint"},
        ],
    }
    with pytest.raises(ConflictError, match="false_positive"):
        governance.save(store, requester, data)
    detections.update_incident(
        store,
        requester,
        platform["case"]["id"],
        {
            "status": "false_positive",
            "owner": "",
            "version": platform["case"]["version"],
            "note": "Known maintenance lab",
        },
    )
    rule = governance.save(store, requester, data)
    governance.review(
        store, approver, rule["id"], 1, True, "Positive and normal context reviewed"
    )
    assert not decide(platform, "exception")["allowed"]
    assert decide(platform, "different-host", entity="host-other")["allowed"]
    update = governance.save(store, requester, {**data, "version": 1}, rule["id"])
    assert update["state"] == "pending" and update["approver"] == ""
    assert decide(platform, "new-revision-unapproved")["allowed"]
    governance.review(
        store, approver, rule["id"], 2, True, "Reapproved exact revised definition"
    )
    with store.control() as db:
        db.execute(
            "UPDATE detection_governance_rules SET expires=? WHERE id=?",
            (time.time() - 1, rule["id"]),
        )
    assert decide(platform, "expired")["allowed"]
    # Revocation/expiry must allow the very same previously suppressed source
    # evidence to be replayed; an old durable decision is not eternal authority.
    assert decide(platform, "exception")["allowed"]
    assert governance.list_rules(store, requester)[0]["effective_state"] == "expired"


def risk_data(**overrides):
    return {
        "expires": time.time() + 3600,
        "exposure": "internet",
        "classification": "restricted",
        "source": "Synthetic explicit inventory",
        "reason": "Lab priority validation",
        "vulnerabilities": [
            {
                "id": "CVE-LAB",
                "cvss": 9.8,
                "known_exploited": True,
                "source": "Synthetic scanner observation",
                "observed_at": time.time() - 1,
            }
        ],
        **overrides,
    }


def test_priority_explains_asset_context_and_expiry_without_probability(platform):
    store, requester = platform["store"], platform["actors"]["requester"]
    context = risk_priority.save_context(
        store, requester, platform["asset"]["id"], risk_data()
    )
    result = risk_priority.case_priority(
        store, requester, platform["case"]["id"], platform["asset"]["id"]
    )
    assert 0 <= result["score"] <= 100 and result["context_state"] == "effective"
    assert (
        sum(row["contribution"] for row in result["factors"].values())
        == result["score"]
    )
    assert result["known_exploited_observed"] and not result["source_attestation"]
    assert "not malicious probability" in result["meaning"]
    no_asset = risk_priority.case_priority(store, requester, platform["case"]["id"])
    assert (
        no_asset["score"] < result["score"]
        and no_asset["context_state"] == "not_selected"
    )
    with store.control() as db:
        db.execute(
            "UPDATE asset_risk_context SET expires=? WHERE entity_id=?",
            (time.time() - 1, platform["asset"]["id"]),
        )
    expired = risk_priority.case_priority(
        store, requester, platform["case"]["id"], platform["asset"]["id"]
    )
    assert (
        expired["context_state"] == "expired"
        and expired["factors"]["exposure"]["contribution"] == 0
    )
    with pytest.raises(ConflictError):
        risk_priority.save_context(
            store, requester, platform["asset"]["id"], risk_data()
        )
    assert context["version"] == 1


def test_risk_current_revision_and_complete_case_scope(platform):
    store, requester = platform["store"], platform["actors"]["requester"]
    asset = platform["asset"]
    risk_priority.save_context(store, requester, asset["id"], risk_data())
    entities.save(
        store,
        requester,
        {
            "kind": "host",
            "name": asset["name"],
            "indexes": asset["indexes"],
            "criticality": asset["criticality"],
            "aliases": [
                {"type": item["type"], "value": item["value"]}
                for item in asset["aliases"]
            ],
            "version": asset["version"],
        },
        asset["id"],
    )
    assert (
        risk_priority.case_priority(
            store, requester, platform["case"]["id"], asset["id"]
        )["context_state"]
        == "asset_revision_changed"
    )
    with pytest.raises(KeyError):
        risk_priority.case_priority(
            store, platform["actors"]["foreign"], platform["case"]["id"]
        )
    with pytest.raises(KeyError):
        risk_priority.context(
            store, platform["actors"]["restricted"], platform["second"]["id"]
        )


def test_slo_actual_clocks_ignore_scheduled_case_time_and_separate_effects(platform):
    store, requester = platform["store"], platform["actors"]["requester"]
    now = time.time()
    with store.control() as db:
        # Case.created is intentionally the future scheduling end; the journal
        # clock records actual evidence publication and cannot use that field.
        base = db.execute(
            "SELECT min(emitted) FROM pipeline_case_clocks WHERE incident_id=?",
            (platform["case"]["id"],),
        ).fetchone()[0]
        for kind, state, success, executed, suffix in [
            ("terminate_process", "succeeded", True, True, "effect"),
            ("inspect_file", "succeeded", True, False, "read"),
            ("delete_file", "failed", False, False, "failed"),
            ("delete_file", "started", None, None, "pending"),
        ]:
            db.execute(
                "INSERT INTO endpoint_responses(id,tenant,incident_id,agent_id,host,index_name,requester,scope,request_id,request_digest,evidence_event_id,case_version,action,reason,state,created,expires,result,finished) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    suffix,
                    "a",
                    platform["case"]["id"],
                    "lab-agent",
                    "host-a",
                    "public",
                    "requester",
                    '["public"]',
                    suffix,
                    "lab",
                    "attack",
                    platform["case"]["version"],
                    encode({"type": kind}),
                    "Synthetic typed SLO fixture",
                    state,
                    base,
                    now + 300,
                    encode({"success": success, "executed": executed}),
                    now + 1 if state != "started" else None,
                ),
            )
    report = pipeline_slo.snapshot(store, requester, platform["now"] - 30, now + 5)
    assert report["coverage_complete"] and report["event_count"] == 4
    assert report["confirmed_effects"] == 1 and report["read_only_completed"] == 1
    assert (
        report["pending_responses"] == 1
        and report["failed_or_unconfirmed_responses"] == 1
    )
    assert report["stages"]["case_to_effect"]["p95_seconds"] >= 0
    assert report["stages"]["indexed_to_case"]["count"] == 1
    restricted = pipeline_slo.snapshot(
        store, platform["actors"]["restricted"], platform["now"] - 30, now + 5
    )
    assert (
        restricted["event_count"] == 3
        and "restricted-feed" not in restricted["providers"]
    )
    assert (
        pipeline_slo.snapshot(
            store, platform["actors"]["foreign"], platform["now"] - 30, now + 5
        )["event_count"]
        == 0
    )


def test_slo_missing_clocks_and_pending_cannot_report_full_coverage(platform):
    store, requester = platform["store"], platform["actors"]["requester"]
    with store.control() as db:
        db.execute("DELETE FROM pipeline_event_clocks WHERE event_id='lease'")
    store.ingest(
        "a", [{"event_id": "queued-late", "event_time": time.time(), "index": "public"}]
    )
    report = pipeline_slo.snapshot(
        store, requester, platform["now"] - 30, time.time() + 5
    )
    assert (
        not report["coverage_complete"]
        and report["missing_index_clocks"] == 1
        and report["pending_index_events"] == 1
    )
    with store.control() as db:
        db.execute(
            "UPDATE pipeline_event_clocks SET provider_time=received+60 WHERE event_id='attack'"
        )
    report = pipeline_slo.snapshot(
        store, requester, platform["now"] - 30, time.time() + 5
    )
    assert report["provider_clock_skew_events"] == 1


def test_slo_has_no_lifetime_clock_quota_and_keeps_valid_log_coverage(
    platform, monkeypatch
):
    store, requester = platform["store"], platform["actors"]["requester"]
    monkeypatch.setattr(pipeline_slo, "MAX_EVENT_CLOCKS", 4)
    store.ingest(
        "a",
        [
            {
                "event_id": "capacity-log",
                "event_time": time.time(),
                "index": "public",
                "source": "capacity-test",
            }
        ],
    )
    with store.control() as db:
        rows = [dict(row) for row in db.execute("SELECT * FROM queue")]
        result = pipeline_slo.journal_indexed(store, db, rows)
    assert result["recorded"] == 1 and result["coverage_gaps"] == 0 and not result["admission_blocked"]
    store.flush()
    report = pipeline_slo.snapshot(
        store, requester, platform["now"] - 30, time.time() + 5
    )
    assert report["event_count"] == 5 and report["missing_index_clocks"] == 0
    assert report["coverage_complete"]
    assert not any(row["stage"] == "clock_capacity" for row in report["coverage_gaps"])


def pe_sample(*, bits=64, writable=False):
    optional_size = 240 if bits == 64 else 224
    body = bytearray(512)
    body[:2] = b"MZ"
    struct.pack_into("<I", body, 0x3C, 64)
    body[64:68] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        body,
        68,
        0x8664 if bits == 64 else 0x14C,
        1,
        0,
        0,
        0,
        optional_size,
        2,
    )
    struct.pack_into("<H", body, 88, 0x20B if bits == 64 else 0x10B)
    section = 88 + optional_size
    body[section : section + 5] = b".text"
    struct.pack_into("<IIII", body, section + 8, 16, 4096, 16, 480)
    struct.pack_into(
        "<I", body, section + 36, 0x20000020 | (0x80000000 if writable else 0)
    )
    return bytes(body)


def elf_sample(*, bits=64, order="little", writable=False):
    prefix = "<" if order == "little" else ">"
    hsize, psize = (64, 56) if bits == 64 else (52, 32)
    body = bytearray(hsize + psize + 16)
    body[:7] = b"\x7fELF" + bytes(
        [2 if bits == 64 else 1, 1 if order == "little" else 2, 1]
    )
    struct.pack_into(
        prefix + ("HHIQQQIHHHHHH" if bits == 64 else "HHIIIIIHHHHHH"),
        body,
        16,
        2,
        62 if bits == 64 else 3,
        1,
        4096,
        hsize,
        0,
        0,
        hsize,
        psize,
        1,
        0,
        0,
        0,
    )
    flags = 5 | (2 if writable else 0)
    if bits == 64:
        struct.pack_into(
            prefix + "IIQQQQQQ",
            body,
            hsize,
            1,
            flags,
            hsize + psize,
            4096,
            4096,
            16,
            16,
            4096,
        )
    else:
        struct.pack_into(
            prefix + "IIIIIIII",
            body,
            hsize,
            1,
            hsize + psize,
            4096,
            4096,
            16,
            16,
            flags,
            4096,
        )
    return bytes(body)


@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("writable", [False, True])
def test_pe_observes_format_without_executing_or_claiming_authenticode(bits, writable):
    result = file_verdicts.inspect_bytes(pe_sample(bits=bits, writable=writable))
    assert (
        result["format"] == "pe"
        and result["bits"] == bits
        and result["parse_status"] == "valid_header"
    )
    assert bool(result["warnings"]) is writable
    assert not result["sample_executed"] and not result["authenticode_verified"]


@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("order", ["little", "big"])
@pytest.mark.parametrize("writable", [False, True])
def test_elf_class_endianness_segments_are_bounded(bits, order, writable):
    result = file_verdicts.inspect_bytes(
        elf_sample(bits=bits, order=order, writable=writable)
    )
    assert (
        result["format"] == "elf"
        and result["bits"] == bits
        and result["byte_order"] == order
    )
    assert (
        result["parse_status"] == "valid_header"
        and bool(result["warnings"]) is writable
    )


@pytest.mark.parametrize(
    "body",
    [
        b"MZ",
        b"\x7fELF",
        pe_sample()[:200],
        elf_sample()[:50],
        b"MZ" + b"\xff" * 62,
        b"\x7fELF" + b"\0" * 100,
    ],
)
def test_malformed_executable_is_data_not_an_execution_or_malware_verdict(body):
    result = file_verdicts.evaluate_signatures(body, [])
    assert (
        result["static"]["parse_status"] == "malformed"
        and result["verdict"] == "unknown"
    )
    assert not result["sample_executed"]


def signature(body, *, kind="sha256", verdict="malicious", identifier="exact"):
    return {
        "id": identifier,
        "name": "Harmless signature fixture",
        "kind": kind,
        "value": hashlib.sha256(body).hexdigest()
        if kind == "sha256"
        else body[:8].hex(),
        "verdict": verdict,
        "source": "Synthetic signature provenance",
    }


def test_static_signature_no_match_unknown_and_malicious_match_beats_allowlist():
    body = b"Harmless-labeled-signature-fixture"
    assert (
        file_verdicts.evaluate_signatures(body, [signature(b"other")])["verdict"]
        == "unknown"
    )
    malicious = signature(body)
    benign = signature(body, verdict="benign", identifier="allow")
    result = file_verdicts.evaluate_signatures(body, [benign, malicious])
    assert result["verdict"] == "malicious" and len(result["signature_matches"]) == 2
    literal = signature(body, kind="literal", verdict="suspicious")
    assert file_verdicts.evaluate_signatures(body, [literal])["verdict"] == "suspicious"
    assert (
        file_verdicts.evaluate_signatures(b"xx" + body, [{**literal, "offset": 0}])[
            "verdict"
        ]
        == "unknown"
    )


def bundle(body, **overrides):
    return {
        "name": "Managed harmless static fixtures",
        "indexes": ["public"],
        "expires": time.time() + 3600,
        "signatures": [signature(body)],
        **overrides,
    }


def artifact_fixture(fixture, body):
    store = fixture["store"]
    identifier = "ART-" + uuid.uuid4().hex
    endpoint_artifacts_directory = endpoint_artifacts._directory(store)
    (endpoint_artifacts_directory / (identifier + ".bin")).write_bytes(body)
    with store.control() as db:
        db.execute(
            "INSERT INTO endpoint_artifacts VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                identifier,
                uuid.uuid4().hex,
                "a",
                fixture["case"]["id"],
                "public",
                "lab-agent",
                hashlib.sha256(body).hexdigest(),
                len(body),
                len(body),
                "complete",
                time.time(),
                time.time(),
            ),
        )
    return identifier


def test_artifact_verdict_peer_review_scope_revoke_and_exact_sample(platform):
    store, requester, approver = (
        platform["store"],
        platform["actors"]["requester"],
        platform["actors"]["approver"],
    )
    body = b"Harmless-labeled-sample-never-executed"
    artifact_id = artifact_fixture(platform, body)
    rule = file_verdicts.save_bundle(store, requester, bundle(body))
    with pytest.raises(ConflictError):
        file_verdicts.analyze_artifact(store, requester, artifact_id, [rule["id"]])
    with pytest.raises(PermissionError):
        file_verdicts.review_bundle(
            store, requester, rule["id"], 1, True, "Self approval"
        )
    file_verdicts.review_bundle(
        store, approver, rule["id"], 1, True, "Synthetic exact rule reviewed"
    )
    result = file_verdicts.analyze_artifact(store, requester, artifact_id, [rule["id"]])
    assert result["verdict"] == "malicious" and not result["sample_executed"]
    assert (
        len(file_verdicts.case_verdicts(store, requester, platform["case"]["id"])) == 1
    )
    with pytest.raises(KeyError):
        file_verdicts.analyze_artifact(
            store, platform["actors"]["foreign"], artifact_id
        )
    file_verdicts.revoke_bundle(store, approver, rule["id"], 1, "Fixture finished")
    assert (
        file_verdicts.analyze_artifact(store, requester, artifact_id)["verdict"]
        == "unknown"
    )
    assert file_verdicts.list_bundles(store, platform["actors"]["foreign"]) == []


def test_signature_authority_change_and_content_corruption_block_publication(platform):
    store, requester, approver = (
        platform["store"],
        platform["actors"]["requester"],
        platform["actors"]["approver"],
    )
    body = b"Harmless exact hash"
    artifact_id = artifact_fixture(platform, body)
    rule = file_verdicts.save_bundle(store, requester, bundle(body))
    file_verdicts.review_bundle(store, approver, rule["id"], 1, True, "Peer reviewed")
    access.set_for_user(store, requester, "approver", [])
    with pytest.raises(ConflictError):
        file_verdicts.analyze_artifact(store, requester, artifact_id, [rule["id"]])
    (store.path / "response-artifacts" / (artifact_id + ".bin")).write_bytes(b"changed")
    with pytest.raises(ConflictError):
        file_verdicts.analyze_artifact(store, requester, artifact_id)


def test_external_sandbox_is_explicit_pending_claim_and_digest_bound(platform):
    store, requester, reader = (
        platform["store"],
        platform["actors"]["requester"],
        platform["actors"]["reader"],
    )
    body = b"Harmless manual external claim fixture"
    artifact_id = artifact_fixture(platform, body)
    job = file_verdicts.request_sandbox(store, requester, artifact_id, "lab-provider")
    assert job["state"] == "pending_external" and not job["sample_sent"]
    data = {
        "sha256": job["sha256"],
        "provider": "lab-provider",
        "provider_job_id": "explicit-lab-result",
        "verdict": "unknown",
        "report_digest": hashlib.sha256(b"lab report").hexdigest(),
        "observed_at": time.time(),
        "reason": "Manual provider claim; provider not authenticated",
    }
    with pytest.raises(ValueError):
        file_verdicts.complete_sandbox(
            store, requester, job["id"], {**data, "sha256": "0" * 64}
        )
    with pytest.raises(PermissionError):
        file_verdicts.complete_sandbox(store, reader, job["id"], data)
    result = file_verdicts.complete_sandbox(store, requester, job["id"], data)
    assert (
        result["state"] == "completed_external_claim"
        and not result["result"]["provider_signature_verified"]
    )
    with pytest.raises(ConflictError):
        file_verdicts.complete_sandbox(store, requester, job["id"], data)


@pytest.mark.parametrize(
    "kind,value",
    [
        ("ip", "999.1.1.1"),
        ("nat", {"src_ip": "1.2.3.4"}),
        ("user", ""),
        ("hostname", "host"),
    ],
)
def test_identity_lookup_validation(kind, value):
    with pytest.raises(ValueError):
        temporal_identity.lookup(kind, value)


@pytest.mark.parametrize("value", [True, float("nan"), float("inf"), -1, "1"])
def test_priority_rejects_nonfinite_and_boolean_evidence(value):
    with pytest.raises(ValueError):
        risk_priority.calculate(value, "high")


@pytest.mark.parametrize("criticality", [1, 2, 3, 4, 5])
def test_priority_no_active_evidence_never_fabricates_incident_from_asset(criticality):
    result = risk_priority.calculate(
        100,
        "critical",
        criticality=criticality,
        exposure="internet",
        classification="restricted",
        active_evidence=False,
    )
    assert result["score"] == 0


@pytest.mark.parametrize(
    "values,expected",
    [([], None), ([1], 1), (list(range(1, 101)), 95), ([10, 1, 3, 9], 10)],
)
def test_percentile_nearest_rank_and_empty_null(values, expected):
    assert pipeline_slo.percentiles(values)["p95_seconds"] == expected


@pytest.mark.parametrize(
    "bad",
    [
        {"kind": "sha256", "value": "not-a-hash"},
        {"kind": "literal", "value": "1234"},
        {"kind": "literal", "value": "41414141", "verdict": "benign"},
        {"kind": "yara", "value": 'include "elsewhere.yar"'},
        {"kind": "yara", "value": 'import "pe" rule x {condition:true}'},
    ],
)
def test_signature_rejects_unknown_external_include_and_weak_allowlist(bad):
    item = {
        "id": "invalid",
        "name": "invalid",
        "kind": "sha256",
        "value": "0" * 64,
        "verdict": "malicious",
        "source": "explicit fixture",
        **bad,
    }
    with pytest.raises(ValueError):
        file_verdicts.evaluate_signatures(b"harmless", [item])


def test_optional_yara_missing_is_incomplete_unknown_not_fake_match(monkeypatch):
    monkeypatch.setattr(file_verdicts.importlib.util, "find_spec", lambda _: None)
    item = {
        "id": "real-yara",
        "name": "Optional native YARA fixture",
        "kind": "yara",
        "value": 'rule labeled {strings:$s="harmless" condition:$s}',
        "verdict": "suspicious",
        "source": "Explicit optional rule",
    }
    result = file_verdicts.evaluate_signatures(b"harmless", [item])
    assert result["verdict"] == "unknown" and not result["coverage_complete"]
    assert result["signature_errors"][0]["status"] == "unavailable"


def test_executable_table_overflow_is_reported_as_malformed():
    body = bytearray(pe_sample())
    struct.pack_into("<I", body, 88 + 240 + 20, 0xFFFFFFFF)
    assert file_verdicts.inspect_bytes(bytes(body))["parse_status"] == "malformed"
    body = bytearray(elf_sample())
    struct.pack_into("<Q", body, 64 + 8, 0xFFFFFFFFFFFFFFFF)
    assert file_verdicts.inspect_bytes(bytes(body))["parse_status"] == "malformed"


@pytest.mark.parametrize("bad", [[], {}, True, 1, None])
def test_malformed_json_categories_are_validation_errors_not_type_errors(bad):
    with pytest.raises(ValueError):
        risk_priority.calculate(50, bad)
    with pytest.raises(ValueError):
        risk_priority.calculate(50, "high", exposure=bad)
    with pytest.raises(ValueError):
        file_verdicts.evaluate_signatures(
            b"harmless",
            [
                {
                    "id": "test",
                    "name": "test",
                    "source": "test",
                    "kind": bad,
                    "verdict": "malicious",
                    "value": "0" * 64,
                }
            ],
        )
    with pytest.raises(ValueError):
        temporal_identity.lookup(
            "nat",
            {
                "src_ip": "10.0.0.1",
                "dest_ip": "10.0.0.2",
                "src_port": 1234,
                "dest_port": 443,
                "protocol": bad,
            },
        )


@pytest.mark.parametrize(
    "path",
    ["raw", "raw.key[0]", "raw.key;drop", "raw." + ".".join(["x"] * 9), "__dict__"],
)
def test_evidence_field_has_no_dynamic_code_or_unbounded_jsonpath(path):
    with pytest.raises(ValueError):
        evidence_scope.field({"raw": {}}, path)


def test_storm_same_fingerprint_can_recover_when_window_or_authority_changes(platform):
    store, requester, approver = (
        platform["store"],
        platform["actors"]["requester"],
        platform["actors"]["approver"],
    )
    rule = governance.save(store, requester, storm(platform, max_per_window=1))
    governance.review(
        store, approver, rule["id"], 1, True, "Reviewed bounded storm cap"
    )
    at = int(time.time() // 60) * 60 + 5
    decide(platform, "window-first", at=at)
    assert not decide(platform, "recoverable", at=at)["allowed"]
    assert decide(platform, "recoverable", at=at + 60)["allowed"]
    governance.revoke(
        store, requester, rule["id"], 1, "Recover previously suppressed evidence"
    )
    assert decide(platform, "recoverable", at=at)["allowed"]


def test_identity_changed_inventory_revision_and_unrelated_asset_require_revalidation(
    platform,
):
    store, requester, asset = (
        platform["store"],
        platform["actors"]["requester"],
        platform["asset"],
    )
    with pytest.raises(ValueError, match="asset alias"):
        temporal_identity.save(
            store, requester, binding(platform, entity=platform["second"])
        )
    temporal_identity.save(store, requester, binding(platform))
    entities.save(
        store,
        requester,
        {
            "kind": "host",
            "name": asset["name"],
            "indexes": asset["indexes"],
            "criticality": 4,
            "aliases": [
                {"type": item["type"], "value": item["value"]}
                for item in asset["aliases"]
            ],
            "version": asset["version"],
        },
        asset["id"],
    )
    assert (
        temporal_identity.resolve(store, requester, "ip", "10.0.0.10", platform["now"])[
            "status"
        ]
        == "unresolved"
    )


def test_yara_native_timeout_and_invalid_child_output_are_not_clean(monkeypatch):
    import subprocess
    from types import SimpleNamespace

    monkeypatch.setattr(file_verdicts.importlib.util, "find_spec", lambda _: object())
    source = "rule labeled {condition:true}"

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("fixture child", 0.01)

    monkeypatch.setattr(file_verdicts.subprocess, "run", timeout)
    assert file_verdicts.yara_scan(source, b"fixture")["status"] == "timeout"
    monkeypatch.setattr(
        file_verdicts.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout='{"status":"completed","matches":{}}'
        ),
    )
    assert file_verdicts.yara_scan(source, b"fixture")["status"] == "failed"


def test_signature_update_drops_prior_approval(platform):
    store, requester, approver = (
        platform["store"],
        platform["actors"]["requester"],
        platform["actors"]["approver"],
    )
    body = b"Harmless explicit update fixture"
    artifact_id = artifact_fixture(platform, body)
    original = file_verdicts.save_bundle(store, requester, bundle(body))
    file_verdicts.review_bundle(
        store, approver, original["id"], 1, True, "Peer approved"
    )
    assert (
        file_verdicts.analyze_artifact(store, requester, artifact_id)["verdict"]
        == "malicious"
    )
    updated = file_verdicts.save_bundle(
        store, requester, bundle(body, version=1), original["id"]
    )
    assert (
        updated["version"] == 2
        and updated["state"] == "pending"
        and updated["approver"] == ""
    )
    assert (
        file_verdicts.analyze_artifact(store, requester, artifact_id)["verdict"]
        == "unknown"
    )


def test_saved_analysis_wildcard_basis_is_retained_by_slo_and_never_reduced_to_source_index(
    platform,
):
    store, requester = platform["store"], platform["actors"]["requester"]
    runtime.save_rule(
        store,
        requester,
        {
            "name": "Full-scope threshold basis",
            "query": {
                "query": "search * | table event_id event_time index_name host source severity"
            },
            "case_adapter": {"entity_field": "host"},
        },
    )
    assert runtime.run_due(store, time.time() + 1, budget=3) == 1
    with store.control() as db:
        wildcard_links = db.execute(
            "SELECT indexes FROM pipeline_case_clocks WHERE indexes='[\"*\"]'"
        ).fetchall()
    assert wildcard_links
    full = pipeline_slo.snapshot(
        store, requester, platform["now"] - 30, time.time() + 2
    )
    limited = pipeline_slo.snapshot(
        store, platform["actors"]["restricted"], platform["now"] - 30, time.time() + 2
    )
    assert full["case_linked_events"] > 0
    assert limited["case_linked_events"] == 0
    assert limited["event_count"] == 3
