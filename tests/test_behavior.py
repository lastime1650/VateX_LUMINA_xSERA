import copy
import threading

import pytest

from sapientia import access, auth, behavior
from sapientia.storage import CapacityError, Settings, Store

PASSWORD = "Synthetic-behavior-test-password-2026"
START = 1704067200  # Monday 2024-01-01 00:00 UTC
BUCKET = 86400


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    behavior.initialize(value)
    auth.create_user(value, "analyst_a", PASSWORD, "analyst", "a")
    auth.create_user(value, "admin_a", PASSWORD, "admin", "a")
    auth.create_user(value, "analyst_b", PASSWORD, "analyst", "b")
    yield value
    value.close()


def actor(name="analyst_a", tenant="a", indexes=None):
    return {
        "name": name,
        "tenant": tenant,
        "role": "admin" if name == "admin_a" else "analyst",
        "allowed_indexes": ["*"] if indexes is None else indexes,
    }


def definition(**extra):
    return {
        "name": "Daily login count",
        "entity_field": "raw.security.user",
        "indexes": ["public"],
        "start": START,
        "end": START + 7 * BUCKET,
        "bucket_seconds": BUCKET,
        "min_samples": 7,
        "min_buckets": 7,
        "z_threshold": 3,
        "business_hours_utc": {"start": 9, "end": 18, "weekdays": list(range(7))},
        **extra,
    }


def event(event_id, at, user="alice", host="known", index="public"):
    return {
        "event_id": event_id,
        "event_time": at,
        "index": index,
        "host": host,
        "raw": {"user": user},
    }


def seed(store, counts=None):
    rows = []
    for day, count in enumerate(counts or [2] * 7):
        rows.extend(
            event(f"train-{day}-{i}", START + day * BUCKET + 12 * 3600 + i)
            for i in range(count)
        )
    store.ingest("a", rows)
    store.flush()


def grant(store, name, indexes):
    access.set_for_user(store, actor("admin_a"), name, indexes)


def test_seeded_volume_novelty_offhours_and_immutable_train_snapshot(store):
    seed(store)
    baseline = behavior.train(store, actor(), definition())
    assert baseline["snapshot"]["models"]["alice"]["counts"] == [2] * 7
    assert baseline["summary"]["matched_events"] == 14
    assert baseline["summary"]["ready"]
    end = definition()["end"]
    store.ingest(
        "a",
        [event(f"eval-{i}", end + 12 * 3600 + i, host="new") for i in range(8)]
        + [
            event("off", end + 2 * 3600),
            event("new-user", end + 13 * 3600, user="bob"),
        ],
    )
    # Late data in the training window cannot change the frozen snapshot.
    store.ingest("a", [event("late-training", START + 12 * 3600, user="bob")])
    store.flush()
    result = behavior.evaluate(store, actor(), baseline["id"], end, end + BUCKET)
    assert result["matched_events"] == 10 and result["complete_counts"]
    assert {a["type"] for a in result["anomalies"]} == {
        "volume",
        "new_host",
        "new_entity",
        "off_hours",
    }
    assert next(a for a in result["anomalies"] if a["type"] == "volume")["count"] == 9
    assert next(a for a in result["anomalies"] if a["type"] == "new_host")["count"] == 8
    assert (
        next(a for a in result["anomalies"] if a["type"] == "off_hours")["evidence"][0][
            "event_id"
        ]
        == "off"
    )
    assert (
        next(a for a in result["anomalies"] if a["type"] == "new_entity")["entity"]
        == "bob"
    )
    assert all(
        a["evidence"] and a["evidence"][0]["index"] == "public"
        for a in result["anomalies"]
    )
    assert behavior.get(store, actor(), baseline["id"])["digest"] == baseline["digest"]
    assert (
        behavior.get_run(store, actor(), result["id"])["baseline_digest"]
        == baseline["digest"]
    )
    second = behavior.train(store, actor(), definition())
    assert second["revision"] == 2 and second["digest"] != baseline["digest"]
    assert len(behavior.list_runs(store, actor(), baseline["id"])) == 1


def test_true_z_score_zero_buckets_and_warmup(store):
    seed(store, [0, 2, 4, 2, 4, 0, 2])
    baseline = behavior.train(store, actor(), definition())
    model = baseline["snapshot"]["models"]["alice"]
    assert model["counts"] == [0, 2, 4, 2, 4, 0, 2]
    assert model["mean"] == 2 and model["stddev"] > 0
    end = definition()["end"]
    store.ingest("a", [event(f"spike{i}", end + 12 * 3600 + i) for i in range(20)])
    store.flush()
    volume = next(
        a
        for a in behavior.evaluate(store, actor(), baseline["id"], end, end + BUCKET)[
            "anomalies"
        ]
        if a["type"] == "volume"
    )
    assert volume["z_score"] == pytest.approx((20 - model["mean"]) / model["stddev"])
    cold = behavior.train(store, actor(), definition(min_samples=100))
    warm = behavior.evaluate(store, actor(), cold["id"], end, end + BUCKET)
    assert (
        warm["state"] == "warmup"
        and warm["anomalies"] == []
        and warm["matched_events"] == 20
    )


def test_exact_counts_exceed_search_row_limit_and_scopes(store):
    seed(store)
    store.ingest(
        "a", [event("private-training", START + 1, user="secret", index="private")]
    )
    store.ingest("b", [event("other-tenant", START + 1, user="other")])
    store.flush()
    grant(store, "analyst_a", ["public"])
    baseline = behavior.train(store, actor(), definition())
    assert set(baseline["snapshot"]["models"]) == {"alice"}
    end = definition()["end"]
    batch = [event(f"bulk{i}", end + 12 * 3600 + i / 10000) for i in range(2500)] + [
        {"event_id": "missing-identity", "event_time": end + 1, "index": "public"}
    ]
    for offset in range(0, len(batch), 1000):
        store.ingest("a", batch[offset : offset + 1000])
    store.ingest("a", [event("private-eval", end + 1, user="secret", index="private")])
    store.flush(5000)
    result = behavior.evaluate(store, actor(), baseline["id"], end, end + BUCKET)
    assert result["matched_events"] == 2500
    assert result["authorized_events"] == 2501 and result["missing_entity_events"] == 1
    assert (
        next(a for a in result["anomalies"] if a["type"] == "volume")["count"] == 2500
    )
    assert behavior.list_baselines(store, actor("analyst_b", "b")) == []
    with pytest.raises(KeyError):
        behavior.get(store, actor("analyst_b", "b"), baseline["id"])
    with pytest.raises(PermissionError):
        behavior.train(store, actor(), definition(indexes=["private"]))


def test_owner_acl_revocation_disables_read_and_execution_even_for_admin(store):
    seed(store)
    baseline = behavior.train(store, actor(), definition())
    end = definition()["end"]
    run = behavior.evaluate(store, actor(), baseline["id"], end, end + BUCKET)
    grant(store, "analyst_a", [])
    assert behavior.list_baselines(store, actor()) == []
    assert behavior.list_baselines(store, actor("admin_a")) == []
    with pytest.raises(PermissionError, match="owner"):
        behavior.evaluate(store, actor("admin_a"), baseline["id"], end, end + BUCKET)
    with pytest.raises(PermissionError):
        behavior.get_run(store, actor("admin_a"), run["id"])


def test_revocation_during_query_rolls_back_saved_run(store, monkeypatch):
    seed(store)
    baseline = behavior.train(store, actor(), definition())
    original = store.analytics_query

    def revoke(*args, **kwargs):
        result = original(*args, **kwargs)
        grant(store, "analyst_a", [])
        return result

    monkeypatch.setattr(store, "analytics_query", revoke)
    end = definition()["end"]
    with pytest.raises((KeyError, PermissionError)):
        behavior.evaluate(store, actor(), baseline["id"], end, end + BUCKET)
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM behavior_runs").fetchone()[0] == 0


def test_training_revocation_rolls_back_and_disabled_owner_blocks_admin(
    store, monkeypatch
):
    seed(store)
    baseline = behavior.train(store, actor(), definition())
    original = store.analytics_query

    def revoke(*args, **kwargs):
        result = original(*args, **kwargs)
        with store.control() as db:
            db.execute("UPDATE users SET disabled=1 WHERE name='analyst_a'")
        return result

    monkeypatch.setattr(store, "analytics_query", revoke)
    with pytest.raises(PermissionError):
        behavior.train(store, actor(), definition())
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM behavior_baselines").fetchone()[0] == 1
    with pytest.raises(PermissionError):
        behavior.get(store, actor("admin_a"), baseline["id"])


def test_empty_snapshot_and_per_entity_warmup_are_explicit(store):
    empty = behavior.train(store, actor(), definition())
    assert not empty["summary"]["ready"] and empty["summary"]["entities"] == 0
    seed(store)
    store.ingest("a", [event("rare", START + 12 * 3600, user="rare")])
    store.flush()
    baseline = behavior.train(store, actor(), definition())
    assert baseline["summary"]["ready"]
    assert not baseline["snapshot"]["models"]["rare"]["ready"]
    end = definition()["end"]
    store.ingest(
        "a",
        [event(f"rare-eval{i}", end + 12 * 3600 + i, user="rare") for i in range(40)],
    )
    store.flush()
    result = behavior.evaluate(store, actor(), baseline["id"], end, end + BUCKET)
    assert not any(item["type"] == "volume" for item in result["anomalies"])
    assert result["matched_events"] == 40


def test_group_bound_cancel_slots_and_training_evaluation_leakage(store, monkeypatch):
    seed(store)
    baseline = behavior.train(store, actor(), definition())
    with pytest.raises(ValueError, match="leakage"):
        behavior.evaluate(store, actor(), baseline["id"], START, START + BUCKET)
    stop = threading.Event()
    stop.set()
    with pytest.raises(RuntimeError, match="cancelled"):
        behavior.train(store, actor(), definition(), cancel=stop)
    for _ in range(store.settings.workers):
        store.query_slots.acquire(False)
    try:
        with pytest.raises(CapacityError, match="concurrency"):
            behavior.train(store, actor(), definition())
    finally:
        for _ in range(store.settings.workers):
            store.query_slots.release()
    monkeypatch.setattr(behavior, "MAX_GROUPS", 2)
    with pytest.raises(CapacityError, match="row bound"):
        behavior.train(store, actor(), definition())


@pytest.mark.parametrize(
    "change",
    [
        {"entity_field": []},
        {"indexes": ["*"]},
        {"bucket_seconds": True},
        {"start": START + 1},
        {"end": START},
        {"z_threshold": float("nan")},
        {"business_hours_utc": {"start": 18, "end": 9, "weekdays": [0]}},
    ],
)
def test_malformed_behavior_definitions(store, change):
    payload = copy.deepcopy(definition())
    payload.update(change)
    with pytest.raises(ValueError):
        behavior.train(store, actor(), payload)
