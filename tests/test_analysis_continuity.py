"""Adversarial continuity contracts; all data and actors are synthetic, isolated Store fixtures."""

import json
import time

import pytest

from sapientia import attack_catalog, behavior, detections, lookups, runtime, xdr_bridge
from sapientia import detection_automation as automation
from sapientia.storage import Settings, Store


@pytest.fixture
def lab(tmp_path):
    store = Store(Settings(tmp_path, min_free_bytes=0, query_timeout=15))
    runtime.initialize(store)
    with store.control() as db:
        db.execute(
            "INSERT INTO users(name,password,role,tenant) VALUES('owner','synthetic-no-login','admin','a')"
        )
    yield store
    store.close()


def actor():
    return {"name": "owner", "tenant": "a", "role": "admin", "allowed_indexes": ["*"]}


def ingest(store, rows):
    for offset in range(0, len(rows), 1000):
        store.ingest("a", rows[offset : offset + 1000])
    while store.flush(5000):
        pass


def ioc_schedule(store, end):
    lookups.save(
        store,
        actor(),
        "synthetic_ioc",
        lookups.threat_intel("ip", ["203.0.113.77"], "synthetic", time.time() + 3600),
    )
    value = automation.save_schedule(
        store,
        actor(),
        {
            "name": "synthetic-ioc",
            "kind": "intel",
            "indexes": ["main"],
            "lookups": ["synthetic_ioc"],
            "enabled": True,
            "interval": 60,
            "lookback": 60,
            "case_adapter": {"entity_field": "host", "cooldown": 300},
        },
    )
    with store.control() as db:
        db.execute(
            "UPDATE analysis_schedules SET next_run=? WHERE id=?", (end, value["id"])
        )
    return value


def test_schedule_continues_after_1000_history_bodies_without_deleting_history(lab):
    end = time.time()
    schedule = ioc_schedule(lab, end)
    with lab.control() as db:
        db.executemany(
            "INSERT INTO analysis_schedule_runs VALUES(?,?,?,?,?,?,?)",
            [
                (
                    f"historic-{i}",
                    "a",
                    "synthetic-historical",
                    i,
                    "synthetic-digest",
                    "{}",
                    i,
                )
                for i in range(1000)
            ],
        )
    ingest(
        lab,
        [
            {
                "event_id": "new-hit",
                "event_time": end - 1,
                "host": "endpoint",
                "raw": {"src_ip": "203.0.113.77"},
            }
        ],
    )
    assert automation.run_due(lab, end + 1, budget=5) == 1
    with lab.control() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM analysis_schedule_runs WHERE tenant='a'"
            ).fetchone()[0]
            == 1001
        )
        assert (
            db.execute(
                "SELECT result FROM analysis_schedule_runs WHERE id='historic-0'"
            ).fetchone()[0]
            == "{}"
        )
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0] == 1
        assert (
            db.execute(
                "SELECT next_run FROM analysis_schedules WHERE id=?", (schedule["id"],)
            ).fetchone()[0]
            == end + 60
        )


def test_distinct_process_chains_and_critical_evidence_survive_host_cooldown(lab):
    end = time.time()

    def event(identifier, action, guid, at):
        return {
            "event_id": identifier,
            "event_time": at,
            "host": "same-host",
            "raw": {
                "action": action,
                "xdr": {
                    "data": {
                        "process": {"guid": guid, "code_signature": {"trusted": False}}
                    }
                },
            },
        }

    ingest(
        lab,
        [
            event("a-start", "start", "process-A", end - 20),
            event("a-end", "end", "process-A", end - 15),
            event("b-start", "start", "process-B", end - 10),
            event("b-end", "end", "process-B", end - 5),
        ],
    )
    policy = detections.validate(
        {
            "name": "causal",
            "window": 60,
            "cooldown": 300,
            "severity": "critical",
            "relation": {"mode": "same_value", "field": "raw.xdr.data.process.guid"},
            "steps": [
                {"filters": [{"field": "raw.action", "op": "eq", "value": "start"}]},
                {
                    "filters": [{"field": "raw.action", "op": "eq", "value": "end"}],
                    "within_seconds": 30,
                },
            ],
        }
    )
    identifier = detections.save(lab, actor(), policy)
    with lab.control() as db:
        db.execute(
            "UPDATE correlation_policies SET next_run=? WHERE id=?", (end, identifier)
        )
    assert detections.run_due(lab, end, budget=5) == 1
    with lab.control() as db:
        rows = db.execute(
            "SELECT evidence FROM risk_contributions ORDER BY id"
        ).fetchall()
        assert len(rows) == 2
        assert db.execute("SELECT count(*) FROM incidents").fetchone()[0] == 2
        for row in rows:
            evidence = json.loads(row[0])
            assert evidence["episode"]["grade"] == "exact_reported_identity"
            assert (
                evidence["notification"]["critical_bypass"]
                and not evidence["notification"]["throttled"]
            )
            assert (
                evidence["steps"][0]["events"][0][
                    "raw.xdr.data.process.code_signature.trusted"
                ]
                is False
            )
            frozen = evidence["policy_snapshot"]
            assert frozen["version"] == 1 and frozen["prerequisites_available"]
            assert frozen["relation"]["field"] == "raw.xdr.data.process.guid"
            assert all(
                "raw.xdr.data.process.guid" in stage["required_fields"]
                for stage in frozen["stages"]
            )


def test_high_distinct_evidence_is_saved_during_notification_cooldown(lab):
    end = time.time() - 100
    identifier = detections.save(
        lab,
        actor(),
        {
            "name": "repeated",
            "window": 60,
            "cooldown": 300,
            "severity": "high",
            "steps": [
                {"filters": [{"field": "raw.action", "op": "eq", "value": "alert"}]}
            ],
        },
    )
    ingest(
        lab,
        [
            {
                "event_id": "first",
                "event_time": end - 20,
                "host": "h",
                "raw": {"action": "alert"},
            }
        ],
    )
    assert (
        detections.replay(lab, actor(), identifier, end - 10, 1, "first")["emitted"]
        == 1
    )
    ingest(
        lab,
        [
            {
                "event_id": "second",
                "event_time": end - 5,
                "host": "h",
                "raw": {"action": "alert"},
            }
        ],
    )
    # Move the earlier event outside the new window, while staying in cooldown.
    result = detections.replay(lab, actor(), identifier, end + 45, 1, "second")
    assert result["emitted"] == 1 and result["notification_throttled"] == 1
    with lab.control() as db:
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0] == 2


def test_successful_ioc_window_is_recovered_after_late_admission(lab):
    end = time.time()
    schedule = ioc_schedule(lab, end)
    assert automation.run_due(lab, end + 1, budget=5) == 1
    ingest(
        lab,
        [
            {
                "event_id": "late-ioc",
                "event_time": end - 10,
                "host": "h",
                "raw": {"src_ip": "203.0.113.77"},
            }
        ],
    )
    assert automation.run_due(lab, end + 2, budget=5) == 1
    with lab.control() as db:
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0] == 1
        assert (
            db.execute(
                "SELECT next_run FROM analysis_schedules WHERE id=?", (schedule["id"],)
            ).fetchone()[0]
            == end + 60
        )
        assert (
            db.execute(
                "SELECT count(*) FROM analysis_late_ranges WHERE kind='schedule'"
            ).fetchone()[0]
            == 0
        )


def test_successful_saved_search_window_is_recovered_without_cursor_regression(lab):
    end = time.time()
    rule = runtime.save_rule(
        lab,
        actor(),
        {
            "name": "saved late",
            "query": {
                "language": "json",
                "query": {
                    "fields": [
                        "event_id",
                        "event_time",
                        "index",
                        "host",
                        "source",
                        "severity",
                    ],
                    "filters": [{"field": "raw.action", "op": "eq", "value": "alert"}],
                },
            },
            "interval": 60,
            "lookback": 60,
            "case_adapter": {"entity_field": "host"},
        },
    )
    with lab.control() as db:
        db.execute("UPDATE rules SET next_run=? WHERE id=?", (end, rule))
    assert runtime.run_due(lab, end + 1, budget=5) == 1
    ingest(
        lab,
        [
            {
                "event_id": "late-saved",
                "event_time": end - 10,
                "host": "h",
                "raw": {"action": "alert"},
            }
        ],
    )
    assert runtime.run_due(lab, end + 2, budget=5) == 1
    with lab.control() as db:
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0] == 1
        assert (
            db.execute("SELECT next_run FROM rules WHERE id=?", (rule,)).fetchone()[0]
            == end + 60
        )


def test_index_ack_invalidates_computed_ioc_window_before_case_commit(lab, monkeypatch):
    end = time.time()
    schedule = ioc_schedule(lab, end)
    ingest(
        lab,
        [
            {
                "event_id": "first",
                "event_time": end - 20,
                "host": "h",
                "raw": {"src_ip": "203.0.113.77"},
            }
        ],
    )
    original = automation._intel
    injected = False

    def raced(*args, **kwargs):
        nonlocal injected
        result = original(*args, **kwargs)
        if not injected:
            injected = True
            ingest(
                lab,
                [
                    {
                        "event_id": "racing",
                        "event_time": end - 10,
                        "host": "h",
                        "raw": {"src_ip": "203.0.113.77"},
                    }
                ],
            )
        return result

    monkeypatch.setattr(automation, "_intel", raced)
    assert automation.run_due(lab, end + 1, budget=5) == 0
    with lab.control() as db:
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0] == 0
        assert (
            db.execute(
                "SELECT next_run FROM analysis_schedules WHERE id=?", (schedule["id"],)
            ).fetchone()[0]
            == end
        )
    assert automation.run_due(lab, end + 10, budget=5) == 1
    with lab.control() as db:
        assert json.loads(
            db.execute("SELECT evidence FROM risk_contributions").fetchone()[0]
        )["event_ids"] == ["first", "racing"]


def test_correlations_page_more_than1000_entities_and_checkpoint_exact_coverage(lab):
    end = time.time()
    identifier = detections.save(
        lab,
        actor(),
        {
            "name": "fleet partition",
            "window": 60,
            "cooldown": 0,
            "steps": [
                {"filters": [{"field": "raw.action", "op": "eq", "value": "alert"}]}
            ],
        },
    )
    ingest(
        lab,
        [
            {
                "event_id": f"original-{i:04}",
                "event_time": end - 5,
                "host": f"endpoint-{i:04}",
                "raw": {"action": "alert"},
            }
            for i in range(1001)
        ],
    )
    with lab.control() as db:
        db.execute(
            "UPDATE correlation_policies SET next_run=? WHERE id=?", (end, identifier)
        )
    for turn in range(100):
        if detections.run_due(lab, end + turn, budget=10) == 1:
            break
    else:
        pytest.fail("partitioned correlation window did not complete")
    with lab.control() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM risk_contributions WHERE policy_id=?",
                (identifier,),
            ).fetchone()[0]
            == 1001
        )
        originals = {
            identity
            for row in db.execute("SELECT evidence FROM risk_contributions")
            for identity in json.loads(row[0])["event_ids"]
        }
        assert originals == {f"original-{i:04}" for i in range(1001)}
        assert (
            db.execute("SELECT count(*) FROM correlation_window_progress").fetchone()[0]
            == 0
        )
        assert (
            db.execute(
                "SELECT next_run FROM correlation_policies WHERE id=?", (identifier,)
            ).fetchone()[0]
            == end + 30
        )


def test_ioc_pages_more_than1000_matching_originals_without_sampling(lab):
    end = time.time()
    schedule = ioc_schedule(lab, end)
    ingest(
        lab,
        [
            {
                "event_id": f"ioc-{i:04}",
                "event_time": end - 5,
                "host": "endpoint",
                "raw": {"src_ip": "203.0.113.77"},
            }
            for i in range(1001)
        ],
    )
    for turn in range(100):
        if automation.run_due(lab, end + turn + 1, budget=10) == 1:
            break
    else:
        pytest.fail("partitioned IOC window did not complete")
    with lab.control() as db:
        originals = {
            identity
            for row in db.execute("SELECT evidence FROM risk_contributions")
            for identity in json.loads(row[0])["event_ids"]
        }
        assert originals == {f"ioc-{i:04}" for i in range(1001)}
        result = json.loads(
            db.execute(
                "SELECT result FROM analysis_schedule_runs WHERE schedule_id=?",
                (schedule["id"],),
            ).fetchone()[0]
        )
        assert (
            result["complete"]
            and result["matched_events"] == 1001
            and result["candidate_events"] == 1001
        )
        assert result["partitions"] > 1 and result["evidence_is_sample"]
        assert (
            db.execute("SELECT count(*) FROM analysis_partition_progress").fetchone()[0]
            == 0
        )


def behavior_baseline(store, end, bucket=60, counts=(2, 2, 2), **options):
    start = end - len(counts) * bucket
    ingest(
        store,
        [
            {
                "event_id": f"train-{start}-{position}-{i}",
                "event_time": start + position * bucket + 1 + i / 10000,
                "host": "known",
                "raw": {"user": "alice"},
            }
            for position, count in enumerate(counts)
            for i in range(count)
        ],
    )
    return behavior.train(
        store,
        actor(),
        {
            "name": "synthetic baseline",
            "entity_field": "raw.security.user",
            "indexes": ["main"],
            "start": start,
            "end": end,
            "bucket_seconds": bucket,
            "min_samples": 2,
            "min_buckets": 2,
            "business_hours_utc": {"start": 0, "end": 24, "weekdays": list(range(7))},
            **options,
        },
    )


def behavior_schedule(store, baseline, end, bucket=60):
    value = automation.save_schedule(
        store,
        actor(),
        {
            "name": "synthetic behavior",
            "kind": "behavior",
            "baseline_id": baseline["id"],
            "enabled": True,
            "interval": bucket,
            "lookback": bucket,
            "case_adapter": {"entity_field": "raw.security.user", "cooldown": 300},
        },
    )
    with store.control() as db:
        db.execute(
            "UPDATE analysis_schedules SET next_run=? WHERE id=?", (end, value["id"])
        )
    return value


def test_behavior_successful_window_recovers_late_original_without_cached_empty_result(
    lab,
):
    start = int(time.time() // 60) * 60 - 120
    baseline = behavior_baseline(lab, start)
    schedule = behavior_schedule(lab, baseline, start + 60)
    assert automation.run_due(lab, start + 61, budget=5) == 1
    ingest(
        lab,
        [
            {
                "event_id": "late-new-user",
                "event_time": start + 20,
                "host": "known",
                "raw": {"user": "bob"},
            }
        ],
    )
    assert automation.run_due(lab, start + 62, budget=5) == 1
    with lab.control() as db:
        evidence = json.loads(
            db.execute("SELECT evidence FROM risk_contributions").fetchone()[0]
        )
        assert evidence["event_ids"] == ["late-new-user"]
        assert evidence["analysis"]["baseline_anomalies"][0]["type"] == "new_entity"
        assert (
            db.execute(
                "SELECT next_run FROM analysis_schedules WHERE id=?", (schedule["id"],)
            ).fetchone()[0]
            == start + 120
        )


def test_behavior_index_ack_fences_cached_partition_and_keeps_exact_recomputed_count(
    lab, monkeypatch
):
    start = int(time.time() // 60) * 60 - 120
    baseline = behavior_baseline(lab, start)
    schedule = behavior_schedule(lab, baseline, start + 60)
    ingest(
        lab,
        [
            {
                "event_id": "first-new",
                "event_time": start + 10,
                "host": "known",
                "raw": {"user": "bob"},
            }
        ],
    )
    evaluate = behavior.evaluate
    raced = False

    def index_during_analysis(*args, **kwargs):
        nonlocal raced
        value = evaluate(*args, **kwargs)
        if not raced:
            raced = True
            ingest(
                lab,
                [
                    {
                        "event_id": "racing-new",
                        "event_time": start + 20,
                        "host": "known",
                        "raw": {"user": "bob"},
                    }
                ],
            )
        return value

    monkeypatch.setattr(behavior, "evaluate", index_during_analysis)
    assert automation.run_due(lab, start + 61, budget=5) == 0
    with lab.control() as db:
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0] == 0
        assert (
            db.execute(
                "SELECT next_run FROM analysis_schedules WHERE id=?", (schedule["id"],)
            ).fetchone()[0]
            == start + 60
        )
    assert automation.run_due(lab, start + 70, budget=5) == 1
    with lab.control() as db:
        result = json.loads(
            db.execute("SELECT result FROM analysis_schedule_runs").fetchone()[0]
        )
        assert result["matched_events"] == 2 and result["anomalies"][0]["count"] == 2
        assert result["input_generation"] == 1 and result["complete"]


def test_behavior_scheduler_pages_more_than500_entities_with_full_original_coverage(
    lab,
):
    start = int(time.time() // 60) * 60 - 120
    baseline = behavior_baseline(lab, start)
    schedule = behavior_schedule(lab, baseline, start + 60)
    ingest(
        lab,
        [
            {
                "event_id": f"novel-{i:04}",
                "event_time": start + 5,
                "host": "known",
                "raw": {"user": f"user-{i:04}"},
            }
            for i in range(501)
        ],
    )
    for turn in range(50):
        if automation.run_due(lab, start + 61 + turn, budget=10) == 1:
            break
    else:
        pytest.fail("partitioned behavior window did not complete")
    with lab.control() as db:
        rows = db.execute("SELECT evidence FROM risk_contributions").fetchall()
        assert len(rows) == 501
        assert {
            identity for row in rows for identity in json.loads(row[0])["event_ids"]
        } == {f"novel-{i:04}" for i in range(501)}
        result = json.loads(
            db.execute(
                "SELECT result FROM analysis_schedule_runs WHERE schedule_id=?",
                (schedule["id"],),
            ).fetchone()[0]
        )
        assert (
            result["complete"]
            and result["matched_events"] == 501
            and result["anomaly_count"] == 501
        )
        assert result["anomalies_are_sample"] and len(result["anomalies"]) == 100
        assert (
            db.execute("SELECT count(*) FROM analysis_partition_progress").fetchone()[0]
            == 0
        )


def test_many_new_hosts_are_exactly_counted_in_one_bounded_anomaly(lab):
    start = int(time.time() // 60) * 60 - 120
    baseline = behavior_baseline(lab, start)
    ingest(
        lab,
        [
            {
                "event_id": f"new-host-{i}",
                "event_time": start + 5,
                "host": f"host-{i:04}",
                "raw": {"user": "alice"},
            }
            for i in range(301)
        ],
    )
    result = behavior.evaluate(lab, actor(), baseline["id"], start, start + 60)
    anomaly = next(row for row in result["anomalies"] if row["type"] == "new_host")
    assert anomaly["count"] == 301 and anomaly["complete_novel_event_count"]
    assert len(anomaly["hosts_sample"]) == 20 and anomaly["host_sample_truncated"]
    assert len(result["anomalies"]) == 2 and result["matched_events"] == 301


def test_robust_baseline_retains_outlier_but_resists_its_mean_masking_effect(lab):
    start = int(time.time() // 60) * 60 - 120
    baseline = behavior_baseline(
        lab, start, counts=(2, 2, 2, 2, 2, 100), count_method="robust_mad"
    )
    model = baseline["snapshot"]["models"]["alice"]
    assert model["counts"] == [2, 2, 2, 2, 2, 100] and model["mean"] > 18
    assert model["median"] == 2 and model["mad"] == 0
    ingest(
        lab,
        [
            {
                "event_id": f"robust-{i}",
                "event_time": start + 5,
                "host": "known",
                "raw": {"user": "alice"},
            }
            for i in range(8)
        ],
    )
    result = behavior.evaluate(lab, actor(), baseline["id"], start, start + 60)
    volume = next(row for row in result["anomalies"] if row["type"] == "volume")
    assert volume["count_method"] == "robust_mad" and volume["threshold"] == 5
    assert volume["z_score"] is None and volume["count"] == 8
    assert not result["quality"]["malicious_training_contamination_excluded"]


def test_selected_timezone_and_stale_model_keep_human_reviewable_signals(lab):
    bucket = 86400
    start = int(time.time() // bucket) * bucket - 2 * bucket
    baseline = behavior_baseline(
        lab,
        start,
        bucket=bucket,
        timezone="Asia/Seoul",
        max_baseline_age_seconds=3600,
        business_hours_utc={"start": 9, "end": 18, "weekdays": list(range(7))},
    )
    ingest(
        lab,
        [
            {
                "event_id": "local-business",
                "event_time": start + 3600,
                "host": "known",
                "raw": {"user": "alice"},
            },
            {
                "event_id": "local-after-hours",
                "event_time": start + 12 * 3600,
                "host": "known",
                "raw": {"user": "alice"},
            },
        ],
    )
    result = behavior.evaluate(lab, actor(), baseline["id"], start, start + bucket)
    off = next(row for row in result["anomalies"] if row["type"] == "off_hours")
    assert off["count"] == 1 and off["evidence"][0]["event_id"] == "local-after-hours"
    assert result["timezone"] == "Asia/Seoul" and result["quality"]["stale"]
    before = len(behavior.list_baselines(lab, actor()))
    with pytest.raises(ValueError, match="timezone"):
        behavior_baseline(lab, start, bucket=bucket, timezone="Mars/Olympus")
    assert len(behavior.list_baselines(lab, actor())) == before


def test_cross_source_or_timestamp_ties_do_not_fabricate_clock_or_causality_confidence():
    def event(at, source="edr", **facts):
        return {
            "event_time": at,
            "received": at + 300,
            "host": "h",
            "source": source,
            **facts,
        }

    def match(events, relation=None):
        return {"steps": [{"events": events}], "relation": relation}

    value = detections.temporal_assessment(
        match([event(1), event(2, source="firewall")])
    )
    assert value["cross_source"] and not value["automation_eligible"]
    assert value["arrival_lag_seconds"]["max"] == 300
    assert (
        not value["independent_clock_attestation"]
        and not value["arrival_lag_is_clock_skew_measurement"]
    )
    tied = detections.temporal_assessment(match([event(1), event(1)]))
    assert tied["timestamp_ties"] and not tied["automation_eligible"]
    causal = detections.temporal_assessment(
        match(
            [event(1), event(1)],
            {"mode": "same_value", "field": "raw.xdr.data.process.guid"},
        )
    )
    assert (
        causal["automation_eligible"] and causal["causal_relation_required_by_policy"]
    )
    assert not causal["independent_clock_attestation"]


def test_poll_budget_does_not_starve_a_valid_exact_analysis_page(lab, monkeypatch):
    end = time.time()
    ioc_schedule(lab, end)
    ingest(
        lab,
        [
            {
                "event_id": "slow-valid-page",
                "event_time": end - 5,
                "host": "h",
                "raw": {"src_ip": "203.0.113.77"},
            }
        ],
    )
    exact = automation._intel

    def slower(*args, **kwargs):
        time.sleep(0.3)
        return exact(*args, **kwargs)

    monkeypatch.setattr(automation, "_intel", slower)
    assert automation.run_due(lab, end + 1, budget=0.25, max_runs=2) == 1
    with lab.control() as db:
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0] == 1


def test_case_adapter_separates_independent_same_host_process_evidence(lab):
    end = time.time()
    ioc_schedule(lab, end)
    ingest(
        lab,
        [
            {
                "event_id": f"process-{i}",
                "event_time": end - 5,
                "host": "h",
                "raw": {
                    "src_ip": "203.0.113.77",
                    "xdr": {"data": {"process": {"guid": f"causal-process-{i}"}}},
                },
            }
            for i in range(2)
        ],
    )
    assert automation.run_due(lab, end + 1, budget=5) == 1
    with lab.control() as db:
        assert db.execute("SELECT count(*) FROM incidents").fetchone()[0] == 2
        assert all(
            json.loads(row[0])["episode"]["grade"] == "exact_reported_identity"
            for row in db.execute("SELECT evidence FROM risk_contributions")
        )


def test_hour_of_week_slots_require_their_own_samples_and_never_fallback_to_global(lab):
    bucket = 3600
    start = int(time.time() // bucket) * bucket - 24 * bucket
    counts = [1] * 336
    baseline = behavior_baseline(
        lab, start, bucket=bucket, counts=counts, seasonality="hour_of_week"
    )
    model = baseline["snapshot"]["models"]["alice"]
    assert len(model["seasonal_slots"]) == 168 and all(
        slot["ready"] for slot in model["seasonal_slots"].values()
    )
    ingest(
        lab,
        [
            {
                "event_id": f"seasonal-{i}",
                "event_time": start + 5,
                "host": "known",
                "raw": {"user": "alice"},
            }
            for i in range(8)
        ],
    )
    result = behavior.evaluate(lab, actor(), baseline["id"], start, start + bucket)
    volume = next(row for row in result["anomalies"] if row["type"] == "volume")
    assert volume["seasonal_slot"] is not None and volume["mean"] == 1
    cold = behavior_baseline(
        lab, start, bucket=bucket, counts=[1] * 168, seasonality="hour_of_week"
    )
    not_ready = behavior.evaluate(lab, actor(), cold["id"], start, start + bucket)
    assert not any(row["type"] == "volume" for row in not_ready["anomalies"])
    assert len(not_ready["seasonal_warmup"]) == 1


def test_actual_case_frozen_stage_prerequisites_retain_joint_typed_original_values(lab):
    end = time.time()

    def endpoint(identifier, action, at, **data):
        from datetime import UTC, datetime

        return xdr_bridge.parse_event(
            {
                "id": identifier,
                "data": {
                    "@timestamp": datetime.fromtimestamp(at, UTC).isoformat(),
                    "host": {"id": "observed-endpoint", "os": {"type": "windows"}},
                    "event": {"action": action},
                    "process": {
                        "guid": "observed-process",
                        "name": "powershell.exe",
                        "code_signature": {"trusted": False},
                    },
                    "score": 7.5,
                    **data,
                },
            },
            "agent",
            "main",
        )

    original = [
        endpoint("native-start", "process_created", end - 10),
        endpoint(
            "native-file",
            "file_created",
            end - 5,
            file={"path": "C:\\observed\\script.ps1"},
        ),
    ]
    ingest(lab, original)
    identifier = detections.save(
        lab,
        actor(),
        {
            "name": "actual prerequisites",
            "window": 60,
            "cooldown": 0,
            "mitre": ["T1059.001"],
            "relation": {"mode": "same_value", "field": "raw.xdr.data.process.guid"},
            "steps": [
                {
                    "name": "process",
                    "filters": [
                        {"field": "index", "op": "eq", "value": "main"},
                        {"field": "sourcetype", "op": "eq", "value": "aegis:endpoint"},
                        {
                            "field": "raw.xdr.schema",
                            "op": "typed_eq",
                            "value": "aegis.endpoint.v1",
                        },
                        {
                            "field": "raw.xdr.data.event.action",
                            "op": "typed_eq",
                            "value": "process_created",
                        },
                        {
                            "field": "raw.xdr.data.host.os.type",
                            "op": "typed_eq",
                            "value": "windows",
                        },
                        {
                            "field": "raw.xdr.data.process.name",
                            "op": "typed_eq",
                            "value": "powershell.exe",
                        },
                        {"field": "raw.xdr.data.score", "op": "typed_eq", "value": 7.5},
                        {"field": "raw.absent", "op": "exists", "value": 0},
                    ],
                },
                {
                    "name": "file",
                    "within_seconds": 30,
                    "filters": [
                        {
                            "field": "raw.xdr.data.event.action",
                            "op": "typed_eq",
                            "value": "file_created",
                        },
                        {
                            "field": "raw.xdr.data.file.path",
                            "op": "regex",
                            "value": "(?i)ps1$",
                        },
                    ],
                },
            ],
        },
    )
    with lab.control() as db:
        db.execute(
            "UPDATE correlation_policies SET next_run=? WHERE id=?", (end, identifier)
        )
    assert detections.run_due(lab, end, budget=5) == 1
    with lab.control() as db:
        row = db.execute(
            "SELECT incident_id,evidence FROM risk_contributions"
        ).fetchone()
        incident_id = row["incident_id"]
        evidence = json.loads(row["evidence"])
        assert all(
            "raw.absent" not in step["required_fields"]
            for step in evidence["policy_snapshot"]["stages"]
        )
        first = evidence["steps"][0]["events"][0]
        assert (
            first["raw.xdr.data.score"] == 7.5
            and first["raw.xdr.data.process.code_signature.trusted"] is False
        )
        assert (
            first["sourcetype"] == "aegis:endpoint"
            and first["raw.xdr.schema"] == "aegis.endpoint.v1"
        )
    mapped = attack_catalog.attack_context(lab, actor(), incident_id)["techniques"][0][
        "analytics"
    ][0]
    assert mapped["requirements_basis"] == "frozen_matched_policy"
    assert mapped["joint_field_evidence_count"] == 2
    assert all(stage["joint_field_evidence_count"] == 1 for stage in mapped["stages"])
    # Editing current policy cannot invent absent requirements in historical Case evidence.
    with lab.control() as db:
        db.execute(
            "UPDATE correlation_policies SET version=version+1 WHERE id=?",
            (identifier,),
        )
    retained = attack_catalog.attack_context(lab, actor(), incident_id)["techniques"][
        0
    ]["analytics"][0]
    assert (
        retained["requirements_basis"] == "frozen_matched_policy"
        and retained["joint_field_evidence_count"] == 2
    )


@pytest.mark.parametrize("complex_value", [["secret", "tail"], {"nested": "body"}])
def test_dependency_projection_does_not_serialize_complex_objects_as_scalar_evidence(
    lab, complex_value
):
    end = time.time()
    ingest(
        lab,
        [
            {
                "event_id": "complex-value",
                "event_time": end - 5,
                "host": "h",
                "raw": {"complex": complex_value},
            }
        ],
    )
    definition = detections.validate(
        {
            "name": "scalar evidence guard",
            "steps": [
                {"filters": [{"field": "raw.complex", "op": "exists", "value": 1}]}
            ],
        }
    )
    matches = detections.evaluate(lab, "a", definition, end, ["main"])
    assert (
        len(matches) == 1 and matches[0]["steps"][0]["events"][0]["raw.complex"] is None
    )
