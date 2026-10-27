import json
import time

import pytest

from sapientia import auth, cpu_sequence, intelligence_sequence
from sapientia import sequence_event_time as stream
from sapientia.storage import ConflictError
from tests import test_sequence_stream as fixtures

actor, approved, deliver, records_for, store = (
    fixtures.actor,
    fixtures.approved,
    fixtures.deliver,
    fixtures.records_for,
    fixtures.store,
)


def items(values):
    return [{"id": str(n), "time": float(n)} for n in values]


def test_watermark_accepts_bounded_late_and_preserves_true_order_with_overlap():
    result = stream.advance(
        [], items([0, 2, 1, 3, 5, 4, 6, 7, 8, 9]), lateness=2, window=4, stride=2
    )
    assert result["jobs"] == [
        ["0", "1", "2", "3"],
        ["2", "3", "4", "5"],
        ["4", "5", "6", "7"],
    ]
    assert result["watermark"] == 7 and result["emitted_time"] == 7
    assert result["diagnostics"] == []
    second = stream.advance(
        result["items"],
        items([6.5, 10, 11]),
        maximum_time=result["max_time"],
        emitted_time=result["emitted_time"],
        lateness=2,
        window=4,
        stride=2,
    )
    assert second["jobs"] == [["6", "7", "8", "9"]]
    assert second["diagnostics"][0][0] == "6.5"


def test_equal_timestamps_unknown_and_old_watermark_record_not_coerced_into_order():
    result = stream.advance(
        [],
        [{"id": "a", "time": 4}, {"id": "b", "time": 4}, *items([5, 6, 7, 8])],
        lateness=2,
        window=3,
        stride=1,
    )
    assert {i for i, _ in result["diagnostics"]} == {"a", "b"}
    assert all("a" not in job and "b" not in job for job in result["jobs"])
    late = stream.advance(
        result["items"],
        items([1]),
        maximum_time=result["max_time"],
        emitted_time=result["emitted_time"],
        lateness=2,
    )
    assert late["diagnostics"][0][0] == "1"


def test_idle_flush_keeps_new_evidence_and_no_duplicate_tail():
    result = stream.advance([], items(range(12)), lateness=2, window=6, stride=3)
    flushed = stream.advance(
        result["items"],
        [],
        maximum_time=result["max_time"],
        emitted_time=result["emitted_time"],
        lateness=2,
        window=6,
        stride=3,
        finalize=True,
    )
    assert result["jobs"] == [
        ["0", "1", "2", "3", "4", "5"],
        ["3", "4", "5", "6", "7", "8"],
    ]
    assert flushed["jobs"] == [["6", "7", "8", "9", "10", "11"]]
    assert not flushed["items"]
    assert not stream.advance(
        [],
        items([5]),
        maximum_time=flushed["max_time"],
        emitted_time=flushed["emitted_time"],
        lateness=2,
    )["jobs"]


def test_buffer_has_hard_limit_and_nonfinite_times_fail():
    with pytest.raises(ValueError, match="capacity"):
        stream.advance([], items(range(129)), lateness=300)
    with pytest.raises(ValueError, match="Finite"):
        stream.advance([], [{"id": "bad", "time": float("nan")}])


def configure(store, model):
    auth.create_user(
        store, "stream_reviewer", "review-sequence-watermark-2026", "admin", "a"
    )
    config = stream.save(
        store,
        actor("admin"),
        model["id"],
        {
            "expected_revision": 0,
            "lateness_seconds": 2,
            "window": 12,
            "stride": 6,
            "idle_seconds": 5,
            "enabled": True,
        },
    )
    with pytest.raises(PermissionError, match="Independent"):
        stream.review(
            store,
            actor("admin"),
            model["id"],
            {
                "expected_revision": 1,
                "approve": True,
                "reason": "Cannot approve own stream profile",
            },
        )
    stream.review(
        store,
        {**actor("stream_reviewer"), "role": "admin"},
        model["id"],
        {
            "expected_revision": 1,
            "approve": True,
            "reason": "Checked model/source identity and bounded watermark",
        },
    )
    return config


def test_actual_approved_cpu_model_uses_reviewed_overlapping_event_time_jobs(
    store, approved
):
    model, source, base = approved
    configure(store, model)
    events = records_for(base, "new-watermark", amount=24)
    for n, event in enumerate(events):
        event["event_time"] = base[0]["event_time"] + n
    # Delayed within the permitted bound; admission ordering differs from time.
    events[1], events[2] = events[2], events[1]
    deliver(store, source, events)
    queued = stream.enqueue(store)
    with store.control() as db:
        assert queued >= 2, [
            r[0]
            for r in db.execute("SELECT reason FROM intelligence_sequence_diagnostics")
        ]
    with store.control() as db:
        jobs = [
            json.loads(r[0])
            for r in db.execute(
                "SELECT event_ids FROM intelligence_sequence_jobs ORDER BY created"
            )
        ]
        assert set(jobs[0]) & set(jobs[1])
        assert jobs[0] == [f"new-watermark-{i}" for i in range(12)]
    stream.enqueue(store, now=time.time() + 6)
    from sapientia import intelligence_sequence

    result = intelligence_sequence.run_due(store, max_runs=32)
    assert result["completed"] >= 2
    with store.control() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM intelligence_sequence_jobs WHERE state='completed'"
            ).fetchone()[0]
            >= 2
        )
        assert all(
            json.loads(r[0]) == []
            for r in db.execute("SELECT items FROM sequence_event_time_buffers")
        )


def test_profile_revision_is_optimistic_and_reviewer_scope_revocation_suspends(
    store, approved
):
    model, source, base = approved
    configure(store, model)
    from sapientia import access

    access.set_for_user(store, actor("admin"), "stream_reviewer", ["private"])
    deliver(store, source, records_for(base, "revoked-profile"))
    assert stream.enqueue(store) == 0
    with store.control() as db:
        assert (
            db.execute("SELECT state FROM sequence_event_time_config").fetchone()[0]
            == "suspended"
        )
        assert (
            db.execute("SELECT count(*) FROM intelligence_sequence_jobs").fetchone()[0]
            == 0
        )


def test_partial_idle_flush_advances_emitted_watermark():
    partial = stream.advance([], items([10, 11, 12]), lateness=5, window=12, stride=6)
    flushed = stream.advance(
        partial["items"],
        [],
        maximum_time=partial["max_time"],
        lateness=5,
        window=12,
        stride=6,
        finalize=True,
    )
    assert flushed["jobs"] == [["10", "11", "12"]] and flushed["emitted_time"] == 12
    late = stream.advance(
        [],
        items([11.5]),
        maximum_time=flushed["max_time"],
        emitted_time=flushed["emitted_time"],
        lateness=5,
    )
    assert not late["items"] and late["diagnostics"][0][0] == "11.5"


def review(store, model, revision=1, approve=True):
    return stream.review(
        store,
        {**actor("stream_reviewer"), "role": "admin"},
        model["id"],
        {
            "expected_revision": revision,
            "approve": approve,
            "reason": "Independent source and activation boundary review",
        },
    )


def revise(store, model, revision=1, enabled=True):
    return stream.save(
        store,
        actor("admin"),
        model["id"],
        {
            "expected_revision": revision,
            "lateness_seconds": 2,
            "window": 12,
            "stride": 6,
            "idle_seconds": 5,
            "enabled": enabled,
        },
    )


def test_review_retry_preserves_live_cursor_buffers_and_queued_work(store, approved):
    model, source, base = approved
    configure(store, model)
    events = records_for(base, "approval-retry", amount=24)
    deliver(store, source, events)
    stream.enqueue(store)
    with store.control() as db:
        before = [
            tuple(r) for r in db.execute("SELECT * FROM sequence_event_time_state")
        ]
        buffers = [
            tuple(r) for r in db.execute("SELECT * FROM sequence_event_time_buffers")
        ]
        jobs = [
            tuple(r) for r in db.execute("SELECT * FROM intelligence_sequence_jobs")
        ]
    deliver(store, source, records_for(base, "after-first-review", amount=3))
    assert review(store, model)["duplicate"] is True
    with store.control() as db:
        assert before == [
            tuple(r) for r in db.execute("SELECT * FROM sequence_event_time_state")
        ]
        assert buffers == [
            tuple(r) for r in db.execute("SELECT * FROM sequence_event_time_buffers")
        ]
        assert jobs == [
            tuple(r) for r in db.execute("SELECT * FROM intelligence_sequence_jobs")
        ]


def test_model_reactivation_suspends_profile_releases_old_refs_and_requires_new_pin(
    store, approved
):
    model, source, base = approved
    initial = configure(store, model)
    events = records_for(base, "old-review", amount=24)
    ids = [e["event_id"] for e in events]
    deliver(store, source, events)
    stream.enqueue(store)
    with store.control() as db:
        old_pin = json.loads(
            db.execute("SELECT definition FROM sequence_event_time_config").fetchone()[
                0
            ]
        )["model_review_id"]
        assert stream.protected_ids(
            db, "a", ids
        ) or intelligence_sequence.protected_ids(db, "a", ids)
    cpu_sequence.activate(
        store,
        actor("reviewer"),
        model["id"],
        "New independent activation must invalidate stream coverage",
    )
    with store.control() as db:
        assert (
            db.execute("SELECT state FROM sequence_event_time_config").fetchone()[0]
            == "suspended"
        )
        assert (
            db.execute("SELECT count(*) FROM sequence_event_time_buffers").fetchone()[0]
            == 0
        )
        assert not db.execute(
            "SELECT 1 FROM intelligence_sequence_jobs WHERE state IN ('pending','running')"
        ).fetchone()
        assert not stream.protected_ids(db, "a", ids)
        assert not intelligence_sequence.protected_ids(db, "a", ids)
    with pytest.raises(ConflictError, match="activation review changed"):
        review(store, model)
    assert stream.enqueue(store) == 0 and intelligence_sequence.enqueue(store) == 0
    revised = revise(store, model)
    assert revised["definition"]["model_review_id"] != old_pin
    assert (
        revised["definition"]["stream_epoch"] != initial["definition"]["stream_epoch"]
    )
    review(store, model, 2)
    fresh = records_for(base, "fresh-review", amount=24)
    deliver(store, source, fresh)
    assert stream.enqueue(store) >= 1
    with store.control() as db:
        jobs = [
            json.loads(r[0])
            for r in db.execute(
                "SELECT result FROM intelligence_sequence_jobs WHERE state='pending'"
            )
        ]
        assert all(
            j["stream_context"]["model_review_id"]
            == revised["definition"]["model_review_id"]
            for j in jobs
        )


def test_pending_profile_edit_cancels_old_work_and_pauses_legacy_without_pinning_consumed_originals(
    store, approved
):
    model, source, base = approved
    configure(store, model)
    events = records_for(base, "pending-edit", amount=24)
    deliver(store, source, events)
    stream.enqueue(store)
    revise(store, model)
    assert intelligence_sequence.enqueue(store) == 0 and stream.enqueue(store) == 0
    paused = records_for(base, "while-pending", amount=12)
    deliver(store, source, paused)
    assert intelligence_sequence.enqueue(store) == 0
    ids = [e["event_id"] for e in events + paused]
    with store.control() as db:
        assert not db.execute(
            "SELECT 1 FROM intelligence_sequence_jobs WHERE state IN ('pending','running')"
        ).fetchone()
        assert not stream.protected_ids(db, "a", ids)
        assert not intelligence_sequence.protected_ids(db, "a", ids)
    assert stream.status(store, actor("admin"))["profiles"][0]["processing"] == "paused"
    # Explicit fresh approval of a disabled profile resumes legacy exactly at
    # this new boundary, without replaying the pending interval.
    revise(store, model, revision=2, enabled=False)
    review(store, model, 3)
    assert intelligence_sequence.enqueue(store) == 0
    current = records_for(base, "resumed-legacy", amount=12)
    deliver(store, source, current)
    assert intelligence_sequence.enqueue(store) == 1
    with store.control() as db:
        job = json.loads(
            db.execute(
                "SELECT event_ids FROM intelligence_sequence_jobs WHERE state='pending'"
            ).fetchone()[0]
        )
        assert job == [e["event_id"] for e in current]


def test_completed_event_time_jobs_and_idle_buffers_release_legacy_outbox_protection(
    store, approved
):
    model, source, base = approved
    configure(store, model)
    events = records_for(base, "retention", amount=24)
    deliver(store, source, events)
    stream.enqueue(store)
    stream.enqueue(store, now=time.time() + 6)
    ids = [e["event_id"] for e in events]
    with store.control() as db:
        assert not stream.protected_ids(db, "a", ids)
        assert intelligence_sequence.protected_ids(db, "a", ids) == set(ids)
    result = intelligence_sequence.run_due(store, max_runs=32)
    assert result["completed"] >= 2
    with store.control() as db:
        assert not intelligence_sequence.protected_ids(db, "a", ids)
        assert not stream.protected_ids(db, "a", ids)
        assert (
            db.execute(
                "SELECT count(*) FROM receipts WHERE tenant=? AND event_id IN (SELECT value FROM json_each(?))",
                ("a", json.dumps(ids)),
            ).fetchone()[0]
            == 24
        )


def test_empty_watermark_eviction_admits_new_entity_and_never_discards_pending_buffers(
    store, approved, monkeypatch
):
    model, source, base = approved
    configure(store, model)
    monkeypatch.setattr(stream, "MAX_ENTITIES", 2)
    first = records_for(base, "first-watermark", amount=3)
    deliver(store, source, first)
    stream.enqueue(store)
    stream.enqueue(store, now=time.time() + 6)
    with store.control() as db:
        old_epoch = db.execute(
            "SELECT epoch FROM sequence_event_time_buffers WHERE items='[]'"
        ).fetchone()[0]
    pending = records_for(base, "pending-buffer", amount=2)
    deliver(store, source, pending)
    stream.enqueue(store)
    third = records_for(base, "new-entity", amount=3)
    deliver(store, source, third)
    stream.enqueue(store)
    with store.control() as db:
        rows = db.execute(
            "SELECT items,epoch FROM sequence_event_time_buffers"
        ).fetchall()
        assert len(rows) == 2 and old_epoch not in {r["epoch"] for r in rows}
        assert {e["event_id"] for e in pending} == {
            i["id"]
            for r in rows
            for i in json.loads(r["items"])
            if i["id"].startswith("pending-buffer")
        }
        assert any(
            "empty watermark evicted" in r[0]
            for r in db.execute("SELECT reason FROM intelligence_sequence_diagnostics")
        )
    # Both current buffers hold real originals: a fourth entity is diagnosed
    # instead of deleting either pending buffer to force apparent progress.
    fourth = records_for(base, "full-capacity", amount=2)
    deliver(store, source, fourth)
    stream.enqueue(store)
    with store.control() as db:
        assert stream.protected_ids(
            db, "a", [e["event_id"] for e in pending + third]
        ) == {e["event_id"] for e in pending + third}
        assert any(
            "entity capacity reached" in r[0]
            for r in db.execute("SELECT reason FROM intelligence_sequence_diagnostics")
        )
        assert all(
            "full-capacity" not in r[0]
            for r in db.execute("SELECT items FROM sequence_event_time_buffers")
        )


def test_profile_change_during_actual_inference_never_publishes_old_epoch(
    store, approved, monkeypatch
):
    model, source, base = approved
    configure(store, model)
    deliver(store, source, records_for(base, "racing-profile", amount=24))
    actual = cpu_sequence.infer_sequences

    def edited(*args, **kwargs):
        result = actual(*args, **kwargs)
        assert result["status"] == "completed"
        revise(store, model)
        return result

    monkeypatch.setattr(cpu_sequence, "infer_sequences", edited)
    result = intelligence_sequence.run_due(store, max_runs=32)
    assert result["completed"] == 0
    with store.control() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM intelligence_signals WHERE kind='ml'"
            ).fetchone()[0]
            == 0
        )
        assert not db.execute(
            "SELECT 1 FROM intelligence_sequence_jobs WHERE state IN ('pending','running')"
        ).fetchone()


def test_additive_v2_epoch_migration_preserves_existing_watermarks_and_v1_checksum():
    import sqlite3
    from contextlib import contextmanager

    from sapientia import migrations

    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    # The v1 schema is the released upgrade contract, not a new replacement.
    statements = [
        "CREATE TABLE IF NOT EXISTS sequence_event_time_config(model_id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,indexes TEXT NOT NULL,revision INTEGER NOT NULL,definition TEXT NOT NULL,state TEXT NOT NULL,reviewer TEXT,reason TEXT,updated REAL NOT NULL)",
        "CREATE TABLE IF NOT EXISTS sequence_event_time_state(model_id TEXT PRIMARY KEY,cursor INTEGER NOT NULL,updated REAL NOT NULL)",
        "CREATE TABLE IF NOT EXISTS sequence_event_time_buffers(model_id TEXT NOT NULL,entity TEXT NOT NULL,tenant TEXT NOT NULL,index_name TEXT NOT NULL,items TEXT NOT NULL,max_time REAL NOT NULL,emitted_time REAL,updated REAL NOT NULL,PRIMARY KEY(model_id,entity))",
    ]
    migrations.initialize(db)
    migrations.apply(db, "sequence_event_time", 1, statements)
    db.execute(
        "INSERT INTO sequence_event_time_buffers VALUES('model','entity','a','public','[]',100,99,10)"
    )
    db.commit()
    checksum = db.execute(
        "SELECT checksum FROM xsera_schema_migrations WHERE component='sequence_event_time' AND version=1"
    ).fetchone()[0]

    class UpgradeStore:
        @contextmanager
        def control(self, local=False):
            with db:
                yield db

    stream.initialize(UpgradeStore())
    row = dict(db.execute("SELECT * FROM sequence_event_time_buffers").fetchone())
    assert row == {
        "model_id": "model",
        "entity": "entity",
        "tenant": "a",
        "index_name": "public",
        "items": "[]",
        "max_time": 100.0,
        "emitted_time": 99.0,
        "updated": 10.0,
        "epoch": "legacy-unqualified",
    }
    assert (
        db.execute(
            "SELECT checksum FROM xsera_schema_migrations WHERE component='sequence_event_time' AND version=1"
        ).fetchone()[0]
        == checksum
    )
    assert (
        db.execute(
            "SELECT max(version) FROM xsera_schema_migrations WHERE component='sequence_event_time'"
        ).fetchone()[0]
        == 2
    )
    db.close()
