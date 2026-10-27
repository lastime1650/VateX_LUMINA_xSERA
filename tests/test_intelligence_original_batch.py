"""Bounded raw prefetch and one durable cursor/signal turn without auth caching."""

import threading
import time
from contextlib import contextmanager

import pytest

from sapientia import connector_runtime, evidence_scope, intelligence, principal
from sapientia.storage import ConflictError
from tests.test_backend_upgrade import actor
from tests.test_backend_upgrade import lab as _lab
from tests.test_intelligence import policy, seed

lab = _lab


def test_cancelled_or_expired_turn_does_not_open_source_queries(lab, monkeypatch):
    cancel = threading.Event()
    cancel.set()
    monkeypatch.setattr(
        lab,
        "control",
        lambda *args, **kwargs: pytest.fail("Cancelled turn opened control database"),
    )
    assert intelligence._outbox(lab, cancel=cancel) == 0
    assert intelligence._outbox(lab, deadline=time.monotonic() - 1) == 0


def test_single_owner_turn_reads_raw_once_and_commits_cursor_jobs_with_signals(
    lab, monkeypatch
):
    policy(lab, "A")
    seed(lab, stages=("A",) * 16)
    query, control = lab.analytics_query, lab.control
    counts = {"raw_queries": 0, "commits": 0}

    def measured_query(sql, *args, **kwargs):
        if sql.startswith(
            "SELECT event_id,event_time,source,sourcetype,host,severity,message,index_name,raw,received "
        ):
            counts["raw_queries"] += 1
        return query(sql, *args, **kwargs)

    @contextmanager
    def measured_control(*args, **kwargs):
        with control(*args, **kwargs) as db:
            db.set_trace_callback(
                lambda statement: counts.__setitem__(
                    "commits",
                    counts["commits"] + int(statement.strip().upper() == "COMMIT"),
                )
            )
            yield db

    monkeypatch.setattr(lab, "analytics_query", measured_query)
    monkeypatch.setattr(lab, "control", measured_control)
    assert intelligence._outbox(lab, maximum=16, deadline=time.monotonic() + 10) == 16
    assert counts == {"raw_queries": 1, "commits": 1}
    with control() as db:
        assert (
            db.execute(
                "SELECT cursor FROM intelligence_cursors WHERE worker='events'"
            ).fetchone()[0]
            == 16
        )
        assert (
            db.execute("SELECT count(*) FROM intelligence_ml_jobs").fetchone()[0] == 16
        )
        assert (
            db.execute(
                "SELECT count(*) FROM intelligence_signals WHERE kind='atomic'"
            ).fetchone()[0]
            == 16
        )
        assert (
            db.execute(
                "SELECT count(*) FROM intelligence_event_phases WHERE analysis_completed_at IS NOT NULL"
            ).fetchone()[0]
            == 16
        )


def test_crash_rolls_back_entire_turn_and_retry_is_idempotent(lab, monkeypatch):
    policy(lab, "A")
    seed(lab, stages=("A",) * 8)
    publish = intelligence.publish_in_transaction
    calls = 0

    def crash(store, db, who, data):
        nonlocal calls
        calls += 1
        if calls == 5:
            raise RuntimeError("Owned synthetic crash before batch commit")
        return publish(store, db, who, data)

    with monkeypatch.context() as m:
        m.setattr(intelligence, "publish_in_transaction", crash)
        with pytest.raises(RuntimeError, match="synthetic crash"):
            intelligence._outbox(lab, maximum=8, deadline=time.monotonic() + 10)
    with lab.control() as db:
        assert (
            db.execute(
                "SELECT cursor FROM intelligence_cursors WHERE worker='events'"
            ).fetchone()[0]
            == 0
        )
        assert (
            db.execute("SELECT count(*) FROM intelligence_signals").fetchone()[0] == 0
        )
        assert (
            db.execute("SELECT count(*) FROM intelligence_ml_jobs").fetchone()[0] == 0
        )
    assert intelligence._outbox(lab, maximum=8, deadline=time.monotonic() + 10) == 8
    assert intelligence._outbox(lab, maximum=8, deadline=time.monotonic() + 10) == 0
    with lab.control() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM intelligence_signals WHERE kind='atomic'"
            ).fetchone()[0]
            == 8
        )


@pytest.mark.parametrize("change", ["receipt", "source", "source_owner", "caller"])
def test_prefetch_rechecks_live_authority_and_receipts_on_every_hit(lab, change):
    source, events = seed(lab, stages=("A",))
    with (  # noqa: SIM117 -- Make the dependent transaction and raw-cache lifetime explicit.
        lab.segment_lock.read(deadline=time.monotonic() + 3),
        principal.transaction(lab, actor(), write=True) as (db, current),
    ):
        with evidence_scope.prefetch_transaction(
            lab, db, [(current, [events[0]["event_id"]])]
        ):
            first = evidence_scope.originals(lab, current, [events[0]["event_id"]])
            first[events[0]["event_id"]]["raw"]["stage"] = "caller-mutation"
            assert (
                evidence_scope.originals(lab, current, [events[0]["event_id"]])[
                    events[0]["event_id"]
                ]["raw"]["stage"]
                == "A"
            )
            if change == "receipt":
                db.execute(
                    "UPDATE receipts SET digest='changed' WHERE event_id=?",
                    (events[0]["event_id"],),
                )
            elif change == "source":
                db.execute(
                    "UPDATE source_registry SET state='revoked' WHERE id=?",
                    (source["id"],),
                )
            elif change == "source_owner":
                db.execute(
                    "UPDATE source_registry SET owner='peer' WHERE id=?",
                    (source["id"],),
                )
                db.execute("UPDATE users SET disabled=1 WHERE name='peer'")
            else:
                db.execute("UPDATE users SET disabled=1 WHERE name='owner'")
            with pytest.raises((PermissionError, ConflictError)):
                evidence_scope.originals(lab, current, [events[0]["event_id"]])


def test_prefetch_is_not_shared_with_other_actor_or_after_context(lab, monkeypatch):
    _, events = seed(lab, stages=("A",))
    event_id = events[0]["event_id"]
    with (  # noqa: SIM117 -- Make the dependent transaction and raw-cache lifetime explicit.
        lab.segment_lock.read(deadline=time.monotonic() + 3),
        principal.transaction(lab, actor(), write=True) as (db, current),
    ):
        with evidence_scope.prefetch_transaction(lab, db, [(current, [event_id])]):
            with pytest.raises(KeyError):
                evidence_scope.originals(lab, actor("foreign", "b"), [event_id])
    query, hits = lab.analytics_query, []

    def raw(sql, *args, **kwargs):
        hits.append(sql)
        return query(sql, *args, **kwargs)

    monkeypatch.setattr(lab, "analytics_query", raw)
    evidence_scope.originals(lab, actor(), [event_id])
    assert len(hits) == 1


def test_supplied_transaction_reads_current_receipts_without_nested_control(
    lab, monkeypatch
):
    _, events = seed(lab, stages=("A",) * 16)
    identifiers = [event["event_id"] for event in events]
    original_query = lab.analytics_query
    raw = original_query(
        "SELECT event_id,event_time,source,sourcetype,host,severity,message,index_name,raw,received "
        "FROM events_all WHERE tenant=? ORDER BY event_id",
        ["a"],
    )
    with principal.transaction(lab, actor(), write=True) as (db, current):  # noqa: SIM117 -- Restore patches before TX exit.
        with monkeypatch.context() as m:
            m.setattr(lab, "analytics_query", lambda *args, **kwargs: raw)
            m.setattr(
                lab,
                "control",
                lambda *args, **kwargs: pytest.fail("Nested receipt connection"),
            )
            records = evidence_scope.originals(lab, current, identifiers, db=db)
            assert len(records) == 16
            db.execute(
                "UPDATE receipts SET received=received+1 WHERE tenant='a' AND event_id=?",
                (identifiers[-1],),
            )
            with pytest.raises(ConflictError, match="receipt"):
                evidence_scope.originals(lab, current, identifiers, db=db)


def test_prefetched_batch_groups_receipts_sources_and_owner_checks(lab):
    _, events = seed(lab, stages=("A",) * 32)
    identifiers = [event["event_id"] for event in events]
    with (  # noqa: SIM117 -- Explicit transaction/cache boundaries are the subject.
        lab.segment_lock.read(deadline=time.monotonic() + 3),
        principal.transaction(lab, actor(), write=True) as (db, current),
    ):
        with evidence_scope.prefetch_transaction(lab, db, [(current, identifiers)]):
            statements = []
            db.set_trace_callback(statements.append)
            records = evidence_scope.originals(lab, current, identifiers, db=db)
            db.set_trace_callback(None)
            assert len(records) == 32
            for table in ("receipts", "source_event_receipts", "source_registry"):
                assert sum(f"FROM {table} WHERE" in sql for sql in statements) == 1
            assert sum("SELECT name,tenant,role" in sql for sql in statements) == 2
            db.execute(
                "DELETE FROM source_event_receipts WHERE tenant='a' AND event_id=?",
                (identifiers[-1],),
            )
            with pytest.raises(ConflictError, match="source receipt"):
                evidence_scope.originals(lab, current, identifiers, db=db)


def test_supplied_connection_must_hold_a_transaction(lab):
    _, events = seed(lab, stages=("A",))
    with lab.control() as db:
        assert not db.in_transaction
        with pytest.raises(ConflictError, match="reserved transaction"):
            evidence_scope.originals(lab, actor(), [events[0]["event_id"]], db=db)


def test_long_transaction_prefetch_uses_one_bounded_load_and_rechecks_late_original(
    lab, monkeypatch
):
    _, events = seed(lab, stages=("A",) * 65)
    identifiers = [event["event_id"] for event in events]
    query, batches = lab.analytics_query, []

    def bounded_query(sql, args, **kwargs):
        import json

        if sql.startswith("SELECT event_id,event_time,source,sourcetype,host,severity"):
            batches.append(len(json.loads(args[-1])))
        return query(sql, args, **kwargs)

    monkeypatch.setattr(lab, "analytics_query", bounded_query)
    with (
        lab.segment_lock.read(deadline=time.monotonic() + 3),
        principal.transaction(lab, actor(), write=True) as (db, current),
    ):
        with evidence_scope.prefetch_transaction(lab, db, [(current, identifiers)]):
            assert batches == [65]
            with pytest.raises(ValueError, match="1..32"):
                evidence_scope.originals(lab, current, identifiers)
            assert len(evidence_scope.originals(lab, current, identifiers[31:63])) == 32
            assert batches == [65]
            db.execute(
                "UPDATE receipts SET digest='changed-late-chunk' WHERE tenant='a' AND event_id=?",
                (identifiers[-1],),
            )
            with pytest.raises(ConflictError, match="expired or changed"):
                evidence_scope.originals(lab, current, identifiers[-1:])
        with (
            pytest.raises(ValueError, match="1056"),
            evidence_scope.prefetch_transaction(
                lab, db, [(current, [f"synthetic-{n}" for n in range(1057)])]
            ),
        ):
            pytest.fail("Oversized immutable prefetch was admitted")


def test_large_raw_cohort_falls_back_only_at_real_two_mib_result_limit(
    lab, monkeypatch
):
    import json

    source, events = seed(lab, stages=("A",) * 65)
    large = [
        {
            **event,
            "event_id": "large-" + event["event_id"],
            "raw": {**event["raw"], "padding": "A" * 35000},
        }
        for event in events
    ]
    connector_runtime.intake(
        lab,
        actor(),
        source["id"],
        {"version": 1, "events": large, "cursor": "large", "checkpoint_version": 1},
    )
    while lab.flush():
        pass
    identifiers = [event["event_id"] for event in large]
    direct = {}
    for offset in range(0, len(identifiers), 32):
        direct.update(
            evidence_scope.originals(lab, actor(), identifiers[offset : offset + 32])
        )
    query, batches, failures = lab.analytics_query, [], []

    def counted_query(sql, args, **kwargs):
        if sql.startswith("SELECT event_id,event_time,source,sourcetype,host,severity"):
            batches.append(len(json.loads(args[-1])))
        try:
            return query(sql, args, **kwargs)
        except ValueError as exc:
            failures.append(str(exc))
            raise

    monkeypatch.setattr(lab, "analytics_query", counted_query)
    with (
        lab.segment_lock.read(deadline=time.monotonic() + 3),
        principal.transaction(lab, actor(), write=True) as (db, current),
    ):
        with evidence_scope.prefetch_transaction(lab, db, [(current, identifiers)]):
            assert batches == [65, 32, 32, 1]
            assert failures == ["Result exceeds 2 MiB; reduce fields or limit"]
            cached = {}
            for offset in range(0, len(identifiers), 32):
                cached.update(
                    evidence_scope.originals(
                        lab, current, identifiers[offset : offset + 32]
                    )
                )
            assert cached == direct
            assert batches == [65, 32, 32, 1]
            db.execute("UPDATE users SET disabled=1 WHERE name='owner' AND tenant='a'")
            with pytest.raises(PermissionError):
                evidence_scope.originals(lab, current, identifiers[-1:])
        db.execute("UPDATE users SET disabled=0 WHERE name='owner' AND tenant='a'")
        db.execute(
            "DELETE FROM receipts WHERE tenant='a' AND event_id=?", (identifiers[32],)
        )
        prior = len(batches)
        with evidence_scope.prefetch_transaction(lab, db, [(current, identifiers)]):
            assert batches[prior:] == [65, 32, 32]
            assert evidence_scope.originals(lab, current, identifiers[-1:]) == {
                identifiers[-1]: direct[identifiers[-1]]
            }
            assert batches[-1] == 1
            with pytest.raises(ConflictError, match="receipt"):
                evidence_scope.originals(lab, current, identifiers[32:33])


def test_non_size_raw_failure_is_not_retried_as_chunks(lab, monkeypatch):
    _, events = seed(lab, stages=("A",) * 65)
    identifiers = [event["event_id"] for event in events]
    attempts = []

    def refused_query(*args, **kwargs):
        attempts.append(kwargs["max_rows"])
        raise RuntimeError("Synthetic raw read deadline exceeded")

    monkeypatch.setattr(lab, "analytics_query", refused_query)
    with (
        principal.transaction(lab, actor(), write=True) as (db, current),
        pytest.raises(RuntimeError, match="deadline"),
        evidence_scope.prefetch_transaction(lab, db, [(current, identifiers)]),
    ):
        pytest.fail("Raw deadline was hidden")
    assert attempts == [1056]
