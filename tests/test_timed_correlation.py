import threading
import time

import pytest

from sapientia import detections, rule_templates
from sapientia.storage import CapacityError, Settings, Store


def policy(within=120):
    return detections.validate(
        {
            "name": "Timed synthetic chain",
            "window": 300,
            "steps": [
                {
                    "name": "Start",
                    "filters": [{"field": "message", "op": "eq", "value": "start"}],
                },
                {
                    "name": "End",
                    "within_seconds": within,
                    "filters": [{"field": "message", "op": "eq", "value": "end"}],
                },
            ],
        }
    )


def test_timed_chain_retries_start_and_honors_inclusive_gap_and_distinct_events(
    tmp_path,
):
    store = Store(Settings(tmp_path, min_free_bytes=0))
    try:
        now = time.time()
        store.ingest(
            "a",
            [
                {
                    "event_id": "old",
                    "event_time": now - 250,
                    "host": "qa",
                    "message": "start",
                },
                {
                    "event_id": "start",
                    "event_time": now - 130,
                    "host": "qa",
                    "message": "start",
                },
                {
                    "event_id": "end",
                    "event_time": now - 10,
                    "host": "qa",
                    "message": "end",
                },
                {
                    "event_id": "foreign-index",
                    "event_time": now - 10,
                    "host": "qa",
                    "message": "end",
                    "index": "private",
                },
            ],
        )
        store.flush()
        found = detections.evaluate(store, "a", policy(), now, ["main"])
        assert len(found) == 1 and set(found[0]["event_ids"]) == {"start", "end"}
        assert found[0]["steps"][1]["within_seconds"] == 120
        assert detections.evaluate(store, "a", policy(119), now, ["main"]) == []
        assert detections.evaluate(store, "b", policy(), now, ["main"]) == []
        same = policy()
        same["steps"][1]["filters"] = same["steps"][0]["filters"]
        result = detections.evaluate(store, "a", same, now, ["main"])
        assert all(len(row["event_ids"]) == 2 for row in result)
    finally:
        store.close()


def test_timed_candidate_and_cancellation_bounds_fail_visible():
    events = [{"event_id": str(i), "event_time": float(i)} for i in range(999)]
    streams = [{"qa": events}, {"qa": [{"event_id": "late", "event_time": 99999.0}]}]
    steps = policy()["steps"]
    budget = {"visited": 9999, "deadline": time.monotonic() + 10, "cancel": None}
    with pytest.raises(CapacityError, match="no partial"):
        detections._timed_chain(steps, streams, "qa", budget)
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(CapacityError):
        detections._timed_chain(
            steps,
            streams,
            "qa",
            {"visited": 0, "deadline": time.monotonic() + 10, "cancel": cancel},
        )


@pytest.mark.parametrize(
    "change",
    [
        {"within_seconds": 0},
        {"within_seconds": True},
        {"within_seconds": 301},
        {"within_seconds": 120, "min_count": 2},
    ],
)
def test_timed_step_validation(change):
    value = policy()
    value["steps"][1].update(change)
    with pytest.raises(ValueError):
        detections.validate(value)


def test_behavior_source_is_adapted_and_preserves_lab_host_and_timing():
    row = rule_templates.detail("R-LAB-001")
    assert row["supported"] and row["kind"] == "behavior"
    policy = row["policy_preview"]
    assert policy["enabled"] is False and len(policy["steps"]) == 2
    assert policy["steps"][1]["within_seconds"] == 120
    assert any(
        "TEST" in f["value"]
        for f in policy["steps"][0]["filters"]
        if f["op"] == "regex"
    )
    assert any("streaming" in note for note in row["adaptation_notes"])


@pytest.mark.parametrize("same_identity", [True, False])
def test_actual_lab_behavior_runs_on_typed_source_with_out_of_window_negative(tmp_path, same_identity):
    from datetime import UTC, datetime

    from sapientia import xdr_bridge

    store = Store(Settings(tmp_path, min_free_bytes=0))
    try:
        now = time.time()
        rows = []
        for identifier, action, delta in [
            ("start", "process_created", 130),
            ("followup", "defender_detection", 10),
        ]:
            rows.append(
                xdr_bridge.parse_event(
                    {
                        "id": identifier,
                        "data": {
                            "@timestamp": datetime.fromtimestamp(
                                now - delta, UTC
                            ).isoformat(),
                            "host": {"id": "TEST-EDR-LAPTOP-GT90OM8N"},
                            "process": {"guid": "actual-same-lifetime" if same_identity else identifier, "name": "powershell.exe"},
                            "event": {"action": action},
                        },
                    },
                    "agent",
                    "endpoint",
                )
            )
        store.ingest("a", rows)
        store.flush()
        definition = rule_templates._policy(
            rule_templates.detail("R-LAB-001")["original"], "endpoint"
        )
        result = detections.evaluate(store, "a", definition, now, ["endpoint"])
        if not same_identity:
            assert result == []  # A shared host cannot invent process causality.
            return
        assert len(result) == 1 and len(result[0]["event_ids"]) == 2
        definition["steps"][1]["within_seconds"] = 119
        assert detections.evaluate(store, "a", definition, now, ["endpoint"]) == []
    finally:
        store.close()
