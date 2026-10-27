import json
import time

import pytest

from sapientia import detection_automation, detections, lookups, runtime
from sapientia.storage import Settings, Store


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0, query_timeout=15))
    with value.control() as db:
        db.execute(
            "INSERT INTO users(name,password,role,tenant) VALUES('owner','test-only-no-login','admin','a')"
        )
    yield value
    value.close()


def who(scope=None):
    return {
        "name": "owner",
        "role": "admin",
        "tenant": "a",
        "allowed_indexes": ["*"] if scope is None else scope,
    }


def policy(**extra):
    return detections.validate(
        {
            "name": "exact",
            "entity_field": "host",
            "window": 300,
            "interval": 30,
            "cooldown": 0,
            "steps": [
                {
                    "name": "start",
                    "filters": [{"field": "raw.action", "op": "eq", "value": "start"}],
                    "min_count": 3,
                },
                {
                    "name": "end",
                    "filters": [{"field": "raw.action", "op": "eq", "value": "end"}],
                },
            ],
            **extra,
        }
    )


def test_exact_more_than_10000_candidates_and_authorized_tenants(store):
    end = time.time()
    events = [
        {
            "event_id": f"noise-{i}",
            "host": "busy",
            "event_time": end - 10,
            "raw": {"action": "start"},
        }
        for i in range(10020)
    ]
    events += [
        {
            "event_id": "finish",
            "host": "busy",
            "event_time": end - 1,
            "raw": {"action": "end"},
        }
    ]
    for offset in range(0, len(events), 1000):
        store.ingest("a", events[offset : offset + 1000])
    while store.flush(5000):
        pass
    result = detections.evaluate(store, "a", policy(), end, ["main"])
    assert len(result) == 1 and len(result[0]["event_ids"]) == 4
    assert detections.evaluate(store, "b", policy(), end, ["*"]) == []
    assert detections.evaluate(store, "a", policy(), end, []) == []


def test_related_timed_chain_does_not_join_unrelated_processes(store):
    end = time.time()

    def event(id, at, action, guid, parent=None):
        return {
            "event_id": id,
            "event_time": at,
            "host": "h",
            "raw": {
                "action": action,
                "xdr": {
                    "data": {"process": {"guid": guid, "parent": {"guid": parent}}}
                },
            },
        }

    store.ingest(
        "a",
        [
            event("s", end - 20, "start", "parent"),
            event("wrong", end - 10, "end", "unrelated", "other"),
            event("right", end - 5, "end", "child", "parent"),
        ],
    )
    store.flush()
    definition = policy(
        steps=[
            {"filters": [{"field": "raw.action", "op": "eq", "value": "start"}]},
            {
                "filters": [{"field": "raw.action", "op": "eq", "value": "end"}],
                "within_seconds": 30,
            },
        ],
        relation={"mode": "parent_guid", "field": "raw.xdr.data.process.guid"},
    )
    assert detections.evaluate(store, "a", definition, end, ["main"])[0][
        "event_ids"
    ] == ["right", "s"]


def test_aggregate_zero_does_not_emit_but_numeric_value_does(store):
    trigger = {"mode": "aggregate", "field": "count", "op": "gte", "value": 10}
    identifier = runtime.save_rule(
        store,
        who(),
        {
            "name": "count",
            "query": {"query": "search * | stats count"},
            "trigger": trigger,
        },
    )
    with store.control() as db:
        end = db.execute(
            "SELECT next_run FROM rules WHERE id=?", (identifier,)
        ).fetchone()[0]
    assert runtime.run_due(store, end + 1, budget=3) == 1
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM findings").fetchone()[0] == 0
    store.ingest("a", [{"event_id": str(i), "event_time": end + 1} for i in range(12)])
    store.flush()
    assert runtime.run_due(store, end + 301, budget=3) == 1
    with store.control() as db:
        evidence = json.loads(db.execute("SELECT evidence FROM findings").fetchone()[0])
    assert evidence["trigger"]["observed"] == [12]


@pytest.mark.parametrize("value", [None, True, "10", float("nan")])
def test_bad_aggregate_value_fails_closed(value):
    with pytest.raises(ValueError):
        runtime.evaluate_trigger(
            {"mode": "aggregate", "field": "n", "op": "gt", "value": 1},
            {"rows": [{"n": value}]},
        )


def test_original_finding_case_adapter_exact_once(store):
    end = time.time()
    store.ingest("a", [{"event_id": "e", "host": "h", "event_time": end - 1}])
    store.flush()
    runtime.save_rule(
        store,
        who(),
        {
            "name": "original",
            "query": {
                "language": "json",
                "query": {
                    "fields": [
                        "event_id",
                        "event_time",
                        "index_name",
                        "host",
                        "source",
                        "severity",
                    ]
                },
            },
            "case_adapter": {"entity_field": "host", "risk_score": 70, "cooldown": 0},
        },
    )
    assert runtime.run_due(store, end + 1, budget=3) == 1
    assert runtime.run_due(store, end + 301, budget=3) == 1
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM incidents").fetchone()[0] == 1


def test_late_range_ack_is_durable_and_automatic_recovery_dedups(store):
    end = time.time()
    identifier = detections.save(
        store,
        who(),
        policy(
            steps=[{"filters": [{"field": "raw.action", "op": "eq", "value": "end"}]}]
        ),
    )
    with store.control() as db:
        db.execute(
            "UPDATE correlation_policies SET last_end=?,next_run=? WHERE id=?",
            (end, end + 30, identifier),
        )
    store.ingest(
        "a",
        [
            {
                "event_id": "late",
                "host": "h",
                "event_time": end - 5,
                "raw": {"action": "end"},
            }
        ],
    )
    # Standalone proof exercises the exact same source ACK metadata contract.
    with store.control(local=True) as db:
        rows = db.execute("SELECT * FROM queue").fetchall()
        detections.journal_indexed(store, db, rows)
    store.flush()
    assert detection_automation.run_due(store, end + 1, budget=3) == 1
    assert detection_automation.run_due(store, end + 2, budget=3) == 0
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM incidents").fetchone()[0] == 1


def test_intel_nested_originals_emit_case_and_expired_feed_fails(store):
    end = time.time()
    lookups.save(
        store,
        who(),
        "ioc",
        lookups.threat_intel("ip", ["203.0.113.5"], "synthetic", end + 3600),
    )
    schedule = detection_automation.save_schedule(
        store,
        who(),
        {
            "name": "IOC",
            "kind": "intel",
            "indexes": ["main"],
            "lookups": ["ioc"],
            "enabled": True,
            "case_adapter": {"entity_field": "host", "risk_score": 60},
        },
    )
    store.ingest(
        "a",
        [
            {
                "event_id": "hit",
                "event_time": end - 1,
                "host": "h",
                "raw": {"src_ip": "203.0.113.5"},
            }
        ],
    )
    store.flush()
    assert detection_automation.run_due(store, end + 1, budget=3) == 1
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM incidents").fetchone()[0] == 1
        db.execute("UPDATE managed_lookups SET expires=?", (end - 1,))
        db.execute(
            "UPDATE analysis_schedules SET next_run=? WHERE id=?", (end, schedule["id"])
        )
    assert detection_automation.run_due(store, end + 2, budget=3) == 0
    with store.control() as db:
        assert (
            db.execute(
                "SELECT error FROM analysis_schedules WHERE id=?", (schedule["id"],)
            ).fetchone()[0]
            == "QueryError"
        )
