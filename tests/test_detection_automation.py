import json
import time
from datetime import UTC, datetime

import pytest

from sapientia import (
    access,
    behavior,
    detection_automation,
    detections,
    entities,
    lookups,
    rule_templates,
    runtime,
    sigma_rules,
    xdr_bridge,
)
from sapientia.storage import ConflictError, Settings, Store


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    with value.control() as db:
        db.execute(
            "INSERT INTO users(name,password,role,tenant) VALUES('maker','fixture-only-no-login','admin','a')"
        )
        db.execute(
            "INSERT INTO users(name,password,role,tenant) VALUES('other','fixture-only-no-login','admin','b')"
        )
    yield value
    value.close()


def actor(scope=None):
    return {
        "name": "maker",
        "role": "admin",
        "tenant": "a",
        "allowed_indexes": ["*"] if scope is None else scope,
    }


def endpoint(
    identifier,
    at,
    command="powershell -enc lab",
    name="powershell.exe",
    user="operator",
):
    return xdr_bridge.parse_event(
        {
            "id": identifier,
            "data": {
                "@timestamp": datetime.fromtimestamp(at, UTC).isoformat(),
                "host": {"id": "h", "os": {"type": "windows"}},
                "event": {"action": "process_created"},
                "process": {"guid": identifier, "name": name, "command_line": command},
                "user": {"name": user},
            },
        },
        "agent",
        "main",
    )


def test_template_native_process_identity_and_exclusion_not_string_guess(store):
    end = time.time()
    actual = endpoint("actual", end - 2)
    wrong = endpoint("wrong-exe", end - 1, name="benign.exe")
    store.ingest("a", [actual, wrong])
    store.flush()
    original = rule_templates.detail("R-WIN-001")["original"]
    policy = rule_templates._policy(original, "main")
    assert detections.evaluate(store, "a", policy, end, ["main"])[0]["event_ids"] == [
        actual["event_id"]
    ]
    excluded = rule_templates._context_policy(
        original,
        "main",
        {
            "exclusions": [
                [{"field": "raw.xdr.data.user.name", "op": "eq", "value": "operator"}]
            ]
        },
    )
    assert detections.evaluate(store, "a", excluded, end, ["main"]) == []


def test_template_activation_gate_requires_exact_positive_and_benign_readiness(store):
    end = time.time()
    positive = endpoint("positive", end - 2)
    benign = endpoint("benign", end - 1, name="benign.exe")
    store.ingest("a", [positive, benign])
    store.flush()
    applied = rule_templates.apply(
        store, actor(), "R-WIN-001", {"index": "main", "accept_adaptation": True}
    )
    with pytest.raises(ConflictError, match="readiness"):
        detections.toggle(store, actor(), applied["id"], True, 1)
    checked = rule_templates.readiness(
        store,
        actor(),
        "R-WIN-001",
        {
            "index": "main",
            "earliest": end - 300,
            "latest": end,
            "fixtures": [
                {"label": True, "end": end, "events": [positive]},
                {"label": False, "end": end, "events": [benign]},
            ],
        },
    )
    assert (
        checked["fixture_validation"]["passed"]
        and checked["fixture_validation"]["precision"] == 1
    )
    assert not checked["telemetry_verified"] and not checked["attack_coverage_verified"]
    detections.toggle(store, actor(), applied["id"], True, 1)
    with store.control() as db:
        assert (
            db.execute(
                "SELECT enabled FROM correlation_policies WHERE id=?", (applied["id"],)
            ).fetchone()[0]
            == 1
        )


def test_failed_benign_fixture_gate_and_current_scope(store):
    end = time.time()
    suspect = endpoint("suspect", end - 1)
    store.ingest("a", [suspect])
    store.flush()
    applied = rule_templates.apply(
        store, actor(), "R-WIN-001", {"index": "main", "accept_adaptation": True}
    )
    check = rule_templates.readiness(
        store,
        actor(),
        "R-WIN-001",
        {
            "index": "main",
            "earliest": end - 30,
            "latest": end,
            "fixtures": [
                {"label": True, "end": end, "events": [suspect]},
                {"label": False, "end": end, "events": [suspect]},
            ],
        },
    )
    assert check["fixture_validation"]["false_positive"] == 1
    with pytest.raises(ConflictError, match="fixture"):
        detections.toggle(store, actor(), applied["id"], True, 1)
    with pytest.raises(PermissionError):
        rule_templates.readiness(
            store,
            actor([]),
            "R-WIN-001",
            {"index": "main", "earliest": end - 30, "latest": end},
        )


def test_scheduled_behavior_is_real_and_retry_run_idempotent(store):
    start = 1704067200
    bucket = 3600
    training = [
        {
            "event_id": f"t{i}",
            "event_time": start + i * bucket + 300,
            "host": "known",
            "raw": {"user": "alice"},
        }
        for i in range(3)
    ]
    store.ingest("a", training)
    store.flush()
    baseline = behavior.train(
        store,
        actor(),
        {
            "name": "count",
            "entity_field": "raw.security.user",
            "indexes": ["main"],
            "start": start,
            "end": start + 3 * bucket,
            "bucket_seconds": bucket,
            "min_samples": 3,
            "min_buckets": 3,
        },
    )
    end = start + 4 * bucket
    store.ingest(
        "a",
        [
            {
                "event_id": f"new{i}",
                "event_time": end - bucket + 300 + i,
                "host": "new",
                "raw": {"user": "alice"},
            }
            for i in range(6)
        ],
    )
    store.flush()
    schedule = detection_automation.save_schedule(
        store,
        actor(),
        {
            "name": "scheduled count",
            "kind": "behavior",
            "baseline_id": baseline["id"],
            "interval": bucket,
            "lookback": bucket,
            "enabled": True,
            "case_adapter": {"entity_field": "raw.security.user", "risk_score": 60},
        },
    )
    with store.control() as db:
        db.execute(
            "UPDATE analysis_schedules SET next_run=? WHERE id=?", (end, schedule["id"])
        )
    assert detection_automation.run_due(store, end + 1, budget=3) == 1
    with store.control() as db:
        first_run = db.execute("SELECT id FROM behavior_runs").fetchone()[0]
        assert db.execute("SELECT count(*) FROM incidents").fetchone()[0] == 1
        db.execute(
            "UPDATE analysis_schedules SET next_run=? WHERE id=?", (end, schedule["id"])
        )
    assert detection_automation.run_due(store, end + 2, budget=3) == 1
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM behavior_runs").fetchone()[0] == 1
        assert db.execute("SELECT id FROM behavior_runs").fetchone()[0] == first_run
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0] == 1


def test_intel_prefilter_complete_after_more_than1000_unrelated_events(store):
    end = time.time()
    lookups.save(
        store,
        actor(),
        "feed",
        lookups.threat_intel("domain", ["bücher.example"], "lab", end + 3600),
    )
    records = [
        {
            "event_id": f"noise{i}",
            "event_time": end - 2,
            "host": "h",
            "raw": {"domain": "safe.example"},
        }
        for i in range(2001)
    ]
    records.append(
        {
            "event_id": "unicode-hit",
            "event_time": end - 1,
            "host": "h",
            "raw": {"domain": "BÜCHER.EXAMPLE."},
        }
    )
    for offset in range(0, len(records), 1000):
        store.ingest("a", records[offset : offset + 1000])
    while store.flush(1000):
        pass
    schedule = detection_automation.save_schedule(
        store,
        actor(),
        {
            "name": "domain",
            "kind": "intel",
            "indexes": ["main"],
            "lookups": ["feed"],
            "enabled": True,
            "case_adapter": {"entity_field": "host"},
        },
    )
    # Anchor the intended data window independently of bulk-ingest wall time.
    with store.control() as db:
        db.execute(
            "UPDATE analysis_schedules SET next_run=? WHERE id=?", (end, schedule["id"])
        )
    assert detection_automation.run_due(store, end + 1, budget=3) == 1
    with store.control() as db:
        result = json.loads(
            db.execute(
                "SELECT result FROM analysis_schedule_runs WHERE schedule_id=?",
                (schedule["id"],),
            ).fetchone()[0]
        )
    assert result["scanned_events"] == 2002 and result["matched_events"] == 1


@pytest.mark.parametrize("condition", ["1 of sel*", "all of sel*", "2 of them"])
def test_sigma_v2_executes_lists_wildcards_exists_and_quantified_condition(
    store, condition
):
    end = time.time()
    preview = sigma_rules.preview_sigma(
        {
            "profile": "bounded-json-v2",
            "rule": {
                "title": "typed scalar subset",
                "detection": {
                    "sel_name": {"Name": ["*.exe", "*.sh"]},
                    "sel_present": {"Present|exists": True},
                    "condition": condition,
                },
            },
            "field_mapping": {"Name": "raw.name", "Present": "raw.present"},
        }
    )
    store.ingest(
        "a",
        [
            {
                "event_id": "yes",
                "event_time": end - 1,
                "raw": {"name": "safe.exe", "present": "yes"},
            },
            {"event_id": "no", "event_time": end - 1, "raw": {"name": "safe.log"}},
        ],
    )
    store.flush()
    rows = store.search("a", {**preview["query"], "earliest": end - 30, "latest": end})[
        "rows"
    ]
    assert [row["event_id"] for row in rows] == ["yes"]
    assert preview["semantic_ir"]["version"] == 2 and preview["query_only"]


def test_explicit_registered_criticality_overlay_does_not_relabel_evidence_score(store):
    entities.save(
        store,
        actor(),
        {
            "kind": "host",
            "name": "important",
            "indexes": ["main"],
            "criticality": 5,
            "aliases": [{"type": "hostname", "value": "h"}],
        },
    )
    context = entities.priority_context(store, actor(), "host", "h", 70)
    assert context["evidence_score"] == 70 and context["operational_priority"] == 84
    assert entities.priority_context(store, actor([]), "host", "h", 70) is None


def test_schedule_permission_revocation_keeps_failed_window_and_no_cases(store):
    end = time.time()
    lookups.save(
        store,
        actor(),
        "feed",
        lookups.threat_intel("ip", ["203.0.113.4"], "lab", end + 3600),
    )
    configured = detection_automation.save_schedule(
        store,
        actor(),
        {
            "name": "guard",
            "kind": "intel",
            "indexes": ["main"],
            "lookups": ["feed"],
            "enabled": True,
            "case_adapter": {"entity_field": "host"},
        },
    )
    store.ingest(
        "a",
        [
            {
                "event_id": "e",
                "host": "h",
                "event_time": end - 1,
                "raw": {"src_ip": "203.0.113.4"},
            }
        ],
    )
    store.flush()
    access.set_for_user(store, actor(), "maker", [])
    assert detection_automation.run_due(store, end + 1, budget=3) == 0
    with store.control() as db:
        row = db.execute(
            "SELECT next_run,last_end,error FROM analysis_schedules WHERE id=?",
            (configured["id"],),
        ).fetchone()
        assert row["last_end"] is None and row["error"] == "PermissionError"
        assert db.execute("SELECT count(*) FROM incidents").fetchone()[0] == 0
    assert detection_automation.list_schedules(store, actor()) == []


def test_real_ack_hook_failure_preserves_source_queue_and_replay_after_restart(
    store, monkeypatch
):
    end = time.time()
    policy = detections.save(
        store,
        actor(),
        {
            "name": "late",
            "entity_field": "host",
            "window": 300,
            "interval": 30,
            "cooldown": 0,
            "steps": [{"filters": []}],
        },
    )
    with store.control() as db:
        db.execute(
            "UPDATE correlation_policies SET last_end=?,next_run=? WHERE id=?",
            (end, end + 30, policy),
        )
    store.ingest("a", [{"event_id": "late", "host": "h", "event_time": end - 1}])
    original = detections.journal_indexed

    def fail(*args):
        original(*args)
        raise RuntimeError("synthetic ACK failure")

    monkeypatch.setattr(detections, "journal_indexed", fail)
    with pytest.raises(RuntimeError, match="ACK failure"):
        store.flush()
    with store.control(local=True) as db:
        assert db.execute("SELECT count(*) FROM queue").fetchone()[0] == 1
        assert (
            db.execute("SELECT count(*) FROM log_correlation_late_ranges").fetchone()[0]
            == 0
        )
    monkeypatch.setattr(detections, "journal_indexed", original)
    path = store.path
    store.close()
    restarted = Store(Settings(path, min_free_bytes=0))
    try:
        assert restarted.flush() == 1
        assert detection_automation.run_due(restarted, end + 2, budget=3) == 1
        with restarted.control() as db:
            assert (
                db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0] == 1
            )
    finally:
        restarted.close()


def test_relation_array_identity_is_not_treated_as_scalar(store):
    end = time.time()
    store.ingest(
        "a",
        [
            {
                "event_id": "a",
                "host": "h",
                "event_time": end - 2,
                "raw": {"sid": ["same"]},
            },
            {
                "event_id": "b",
                "host": "h",
                "event_time": end - 1,
                "raw": {"sid": ["same"]},
            },
        ],
    )
    store.flush()
    policy = detections.validate(
        {
            "name": "relation",
            "entity_field": "host",
            "steps": [{"filters": []}, {"filters": []}],
            "relation": {"mode": "same_value", "field": "raw.sid"},
        }
    )
    assert detections.evaluate(store, "a", policy, end, ["main"]) == []


def test_late_status_hides_private_and_wildcard_owner_scope(store):
    end = time.time()
    policies = []
    for name, index in (("public", "main"), ("private", "secret"), ("wildcard", None)):
        filters = (
            [] if index is None else [{"field": "index", "op": "eq", "value": index}]
        )
        identifier = detections.save(
            store,
            actor(),
            {"name": name, "entity_field": "host", "steps": [{"filters": filters}]},
        )
        policies.append(identifier)
        with store.control(local=True) as db:
            db.execute(
                "INSERT INTO log_correlation_late_ranges(policy_id,version,tenant,first_end,last_end,cursor) VALUES(?,1,'a',?,?,?)",
                (identifier, end, end, end),
            )
    assert (
        detection_automation.status(store, actor(["main"]))["late_recovery"]["ranges"]
        == 1
    )
    assert detection_automation.status(store, actor())["late_recovery"]["ranges"] == 3
    with store.control() as db:
        db.execute("UPDATE users SET disabled=1 WHERE name='maker'")
    with pytest.raises(PermissionError):
        detection_automation.status(store, actor())


def test_case_adapter_rejects_query_transformed_original_identity(store):
    end = time.time()
    store.ingest("a", [{"event_id": "actual", "host": "h", "event_time": end - 2}])
    store.flush()
    identifier=runtime.save_rule(
        store,
        actor(),
        {
            "name": "transformed",
            "query": {
                "query": 'search * | eval host="forged" | table event_id event_time index_name host source severity'
            },
            "case_adapter": {"entity_field": "host"},
        },
    )
    # Rule creation may take longer than one second on a busy test host. Pin
    # the intended window so the assertion proves rejection, not lack of work.
    with store.control() as db:
        db.execute("UPDATE rules SET next_run=? WHERE id=?",(end,identifier))
    assert runtime.run_due(store, end + 1, budget=3) == 0
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM findings").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM incidents").fetchone()[0] == 0
        assert "ConflictError" in db.execute("SELECT error FROM rules").fetchone()[0]


def test_template_labels_can_use_authorized_original_ids_without_json_editor(store):
    end = time.time()
    positive = endpoint("p", end - 2)
    negative = endpoint("n", end - 1, name="other.exe")
    store.ingest("a", [positive, negative])
    store.flush()
    result = rule_templates.readiness(
        store,
        actor(),
        "R-WIN-001",
        {
            "index": "main",
            "earliest": end - 30,
            "latest": end,
            "positive_event_ids": [positive["event_id"]],
            "negative_event_ids": [negative["event_id"]],
        },
    )
    assert result["fixture_source"] == "operator_labels_on_authorized_stored_originals"
    assert result["fixture_validation"]["passed"]


def test_exact_candidate_count_preserves_all_contributing_index_scope(store):
    end = time.time()
    store.ingest(
        "a",
        [
            {
                "event_id": f"public{i}",
                "host": "h",
                "event_time": end - 10 + i,
                "index": "main",
            }
            for i in range(3)
        ]
        + [
            {
                "event_id": "private",
                "host": "h",
                "event_time": end - 1,
                "index": "secret",
            }
        ],
    )
    store.flush()
    definition = {
        "name": "exact basis",
        "entity_field": "host",
        "cooldown": 0,
        "steps": [{"filters": [], "min_count": 3}],
    }
    identifier = detections.save(store, actor(), definition)
    preview = detections.evaluate(
        store, "a", detections.validate(definition), end, ["*"]
    )
    assert preview[0]["steps"][0]["eligible_event_count"] == 4
    assert preview[0]["event_ids"] == ["public0", "public1", "public2"]
    assert preview[0]["indexes"] == ["main", "secret"]
    narrow = detections.evaluate(
        store, "a", detections.validate(definition), end, ["main"]
    )
    assert narrow[0]["steps"][0]["eligible_event_count"] == 3
    assert narrow[0]["indexes"] == ["main"]
    with store.control() as db:
        db.execute(
            "UPDATE correlation_policies SET next_run=? WHERE id=?", (end, identifier)
        )
    assert detections.run_due(store, end + 1, budget=3) == 1
    assert len(detections.incident_list(store, actor())) == 1
    assert detections.incident_list(store, actor(["main"])) == []


def test_saved_finding_case_threshold_basis_cannot_leak_private_counts(store):
    end = time.time()
    store.ingest("a", [{"event_id": "public", "host": "h", "event_time": end - 1}])
    store.flush()
    runtime.save_rule(
        store,
        actor(),
        {
            "name": "whole source basis",
            "query": {
                "query": "search * | table event_id event_time index_name host source severity"
            },
            "case_adapter": {"entity_field": "host"},
        },
    )
    assert runtime.run_due(store, end + 1, budget=3) == 1
    assert len(detections.incident_list(store, actor())) == 1
    assert detections.incident_list(store, actor(["main"])) == []


def test_prepared_ioc_batch_validates_feed_once_and_preserves_lookup_provenance(
    store, monkeypatch
):
    end = time.time()
    lookups.save(
        store,
        actor(),
        "actual_feed",
        lookups.threat_intel("ip", ["10.1.2.3"], "lab", end + 3600),
    )
    store.ingest(
        "a",
        [
            {
                "event_id": f"hit{i}",
                "host": f"h{i}",
                "event_time": end - 1,
                "raw": {"src_ip": "10.1.2.3"},
            }
            for i in range(3)
        ],
    )
    store.flush()
    calls = []
    original = lookups.validated_snapshot

    def measured(table, now):
        calls.append(table["name"])
        return original(table, now)

    monkeypatch.setattr(lookups, "validated_snapshot", measured)
    configured = detection_automation.save_schedule(
        store,
        actor(),
        {
            "name": "prepared",
            "kind": "intel",
            "indexes": ["main"],
            "lookups": ["actual_feed"],
            "enabled": True,
            "case_adapter": {"entity_field": "host"},
        },
    )
    assert detection_automation.run_due(store, end + 1, budget=3) == 1
    assert calls == ["actual_feed"]
    with store.control() as db:
        result = json.loads(
            db.execute(
                "SELECT result FROM analysis_schedule_runs WHERE schedule_id=?",
                (configured["id"],),
            ).fetchone()[0]
        )
        contributions = [
            json.loads(row[0])
            for row in db.execute("SELECT evidence FROM risk_contributions")
        ]
    assert result["matched_events"] == 3
    assert all(
        hit["lookup"] == "actual_feed"
        for match in result["matches"]
        for hit in match["matches"]
    )
    assert len(contributions) == 3
    for contribution in contributions:
        assert {
            row["event_id"] for row in contribution["analysis"]["ioc_matches"]
        } == set(contribution["event_ids"])


@pytest.mark.parametrize(
    "trigger",
    [
        {"mode": []},
        {"mode": "aggregate", "field": "n", "op": {}, "value": 1},
        {"mode": "aggregate", "field": "n", "op": "gte", "value": 10**400},
    ],
)
def test_untrusted_trigger_types_fail_as_validation(trigger):
    with pytest.raises(ValueError):
        runtime.validate_trigger(trigger)


def test_untrusted_relation_and_schedule_types_fail_as_validation(store):
    with pytest.raises(ValueError):
        detections.validate(
            {
                "name": "bad",
                "entity_field": "host",
                "steps": [{"filters": []}],
                "relation": {"mode": [], "field": "raw.sid"},
            }
        )
    for data in (
        {"name": "bad", "kind": []},
        {"name": "bad", "kind": "intel", "indexes": ["main"], "lookups": [{}]},
    ):
        with pytest.raises(ValueError):
            detection_automation.save_schedule(store, actor(), data)


def test_scalar_sigma_guards_do_not_match_serialized_array_or_object(store):
    end = time.time()
    store.ingest(
        "a",
        [
            {
                "event_id": "scalar",
                "event_time": end - 1,
                "raw": {"value": "powershell", "number": 12},
            },
            {
                "event_id": "array",
                "event_time": end - 1,
                "raw": {"value": ["powershell"], "number": [12]},
            },
            {
                "event_id": "object",
                "event_time": end - 1,
                "raw": {"value": {"nested": "powershell"}, "number": {"n": 12}},
            },
            {
                "event_id": "numeric-string",
                "event_time": end - 1,
                "raw": {"number": "12"},
            },
            {"event_id": "missing", "event_time": end - 1},
        ],
    )
    store.flush()

    def selected(values, condition="sel", profile="bounded-json-v2"):
        preview = sigma_rules.preview_sigma(
            {
                "profile": profile,
                "rule": {
                    "title": "typed",
                    "detection": {"sel": values, "condition": condition},
                },
                "field_mapping": {"Value": "raw.value", "Number": "raw.number"},
            }
        )
        return {
            row["event_id"]
            for row in store.search(
                "a", {**preview["query"], "earliest": end - 30, "latest": end}
            )["rows"]
        }

    assert selected({"Value|contains": "powershell"}) == {"scalar"}
    assert selected({"Value|contains": "powershell"}, profile="scalar-v1") == {"scalar"}
    assert selected({"Value|exists": True}) == {"scalar"}
    assert selected({"Value|exists": False}) == {"missing", "numeric-string"}
    assert selected({"Number": 12}) == {"scalar"}
    assert selected({"Value|contains": "powershell"}, "not sel") == {
        "missing",
        "numeric-string",
        "array",
        "object",
    }


@pytest.mark.parametrize(
    "expression",
    [
        'jsontype(message,"$.x")',
        "jsontype(_raw,message)",
        'jsontype(_raw,"../../secret")',
        'jsontype(_raw,"$[*]")',
        'jsontype(_raw,"$.a.b.c.d.e.f")',
    ],
)
def test_jsontype_has_only_bound_original_json_scalar_paths(expression):
    from sapientia.query import Query, QueryError

    with pytest.raises(QueryError):
        Query.parse({"query": "search * | where " + expression + '="VARCHAR"'}).compile(
            "a"
        )


def test_untimed_single_count_equal_timestamp_overlap_uses_complete_chain(store):
    end = time.time()
    store.ingest(
        "a",
        [
            {
                "event_id": "a-both",
                "event_time": end - 1,
                "host": "h",
                "raw": {"kind": "both"},
            },
            {
                "event_id": "b-start",
                "event_time": end - 1,
                "host": "h",
                "raw": {"kind": "start"},
            },
        ],
    )
    store.flush()
    policy = detections.validate(
        {
            "name": "ties",
            "entity_field": "host",
            "steps": [
                {
                    "filters": [
                        {"field": "raw.kind", "op": "regex", "value": "^(both|start)$"}
                    ]
                },
                {"filters": [{"field": "raw.kind", "op": "eq", "value": "both"}]},
            ],
        }
    )
    result = detections.evaluate(store, "a", policy, end, ["main"])
    assert result[0]["steps"][0]["events"][0]["event_id"] == "b-start"
    assert result[0]["steps"][1]["events"][0]["event_id"] == "a-both"


def test_untimed_multicount_ambiguous_ties_fail_before_risk_and_cursor(store):
    end = time.time()
    store.ingest(
        "a",
        [
            {
                "event_id": "a-both",
                "event_time": end - 1,
                "host": "h",
                "raw": {"kind": "both"},
            },
            *[
                {
                    "event_id": f"b-start{i}",
                    "event_time": end - 1,
                    "host": "h",
                    "raw": {"kind": "start"},
                }
                for i in range(2)
            ],
        ],
    )
    store.flush()
    definition = {
        "name": "ambiguous",
        "entity_field": "host",
        "steps": [
            {
                "filters": [
                    {"field": "raw.kind", "op": "regex", "value": "^(both|start)$"}
                ],
                "min_count": 2,
            },
            {"filters": [{"field": "raw.kind", "op": "eq", "value": "both"}]},
        ],
    }
    with pytest.raises(ValueError, match="overlapping equal-timestamp"):
        detections.evaluate(store, "a", detections.validate(definition), end, ["main"])
    identifier = detections.save(store, actor(), definition)
    with store.control() as db:
        db.execute(
            "UPDATE correlation_policies SET next_run=? WHERE id=?", (end, identifier)
        )
    assert detections.run_due(store, end + 1, budget=3) == 0
    with store.control() as db:
        row = db.execute(
            "SELECT next_run,error FROM correlation_policies WHERE id=?", (identifier,)
        ).fetchone()
        assert row["next_run"] == end and "overlapping equal-timestamp" in row["error"]
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0] == 0


def test_more_than1000_entities_fails_closed_without_sampling(store):
    from sapientia.storage import CapacityError

    end = time.time()
    rows = [
        {"event_id": f"entity{i}", "event_time": end - 1, "host": f"h{i}"}
        for i in range(1001)
    ]
    store.ingest("a", rows[:1000])
    store.ingest("a", rows[1000:])
    while store.flush():
        pass
    with pytest.raises(CapacityError, match="entity limit"):
        detections.evaluate(
            store,
            "a",
            detections.validate({"name": "entities", "steps": [{"filters": []}]}),
            end,
            ["main"],
        )
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0] == 0


def test_explicit_session_relation_never_joins_other_host_or_other_session(store):
    end = time.time()
    store.ingest(
        "a",
        [
            {
                "event_id": "start",
                "host": "h",
                "event_time": end - 4,
                "raw": {"session_id": "s1", "action": "start", "user": "u"},
            },
            {
                "event_id": "other-host",
                "host": "other",
                "event_time": end - 3,
                "raw": {"session_id": "s1", "action": "end", "user": "u"},
            },
            {
                "event_id": "other-session",
                "host": "h",
                "event_time": end - 2,
                "raw": {"session_id": "s2", "action": "end", "user": "u"},
            },
            {
                "event_id": "same-session",
                "host": "h",
                "event_time": end - 1,
                "raw": {"session_id": "s1", "action": "end", "user": "u"},
            },
        ],
    )
    store.flush()
    definition = detections.validate(
        {
            "name": "session",
            "entity_field": "raw.security.user",
            "relation": {"mode": "same_value", "field": "raw.security.session_id"},
            "steps": [
                {"filters": [{"field": "raw.action", "op": "eq", "value": "start"}]},
                {"filters": [{"field": "raw.action", "op": "eq", "value": "end"}]},
            ],
        }
    )
    assert detections.evaluate(store, "a", definition, end, ["main"])[0][
        "event_ids"
    ] == ["same-session", "start"]


def test_parent_guid_relation_does_not_compare_serialized_array_identity(store):
    end = time.time()
    store.ingest(
        "a",
        [
            {
                "event_id": "parent",
                "host": "h",
                "event_time": end - 2,
                "raw": {
                    "action": "start",
                    "xdr": {"data": {"process": {"guid": '["identity"]'}}},
                },
            },
            {
                "event_id": "child",
                "host": "h",
                "event_time": end - 1,
                "raw": {
                    "action": "end",
                    "xdr": {
                        "data": {
                            "process": {
                                "guid": "child",
                                "parent": {"guid": ["identity"]},
                            }
                        }
                    },
                },
            },
        ],
    )
    store.flush()
    definition = detections.validate(
        {
            "name": "typed parent",
            "entity_field": "host",
            "relation": {"mode": "parent_guid", "field": "raw.xdr.data.process.guid"},
            "steps": [
                {"filters": [{"field": "raw.action", "op": "eq", "value": "start"}]},
                {"filters": [{"field": "raw.action", "op": "eq", "value": "end"}]},
            ],
        }
    )
    assert detections.evaluate(store, "a", definition, end, ["main"]) == []
