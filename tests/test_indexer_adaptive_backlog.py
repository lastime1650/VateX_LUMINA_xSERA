"""Actual residual queue, rather than flush size, controls indexer pacing."""

import sqlite3
import threading
import time
from contextlib import closing
from types import SimpleNamespace

import pytest

from sapientia import log_search
from sapientia import runtime as runtime_module
from sapientia.runtime import Runtime
from sapientia.storage import Settings, Store


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0, indexing_batch=5))
    yield value
    value.close()


def queue_state(store):
    with store.control(local=True) as db:
        return {
            "queue": [
                row[0] for row in db.execute("SELECT event_id FROM queue ORDER BY seq")
            ],
            "pending": db.execute(
                "SELECT pending_documents FROM log_fts_state"
            ).fetchone()[0],
            "inflight": db.execute("SELECT count(*) FROM log_fts_inflight").fetchone()[
                0
            ],
        }


def prepare_adaptive(store, monkeypatch, *, initial=3):
    # A small test-only cap exercises the real bounded journal and source ACK.
    monkeypatch.setattr(log_search, "MAX_PENDING_DOCUMENTS", 5)
    store.ingest("a", [{"event_id": f"seed-{n}"} for n in range(initial)])
    assert store.flush(batch=5) == initial
    store.ingest("a", [{"event_id": f"new-{n}"} for n in range(5)])


class OneIterationStop(threading.Event):
    def __init__(self):
        super().__init__()
        self.waits = []

    def wait(self, timeout=None):
        self.waits.append(timeout)
        self.set()
        return True


def run_one_iteration(store, monkeypatch):
    value = Runtime(store)
    value.stop = OneIterationStop()

    def wait(stage, token, timeout):
        assert stage == "index"
        assert token == value.dispatch.token(stage)
        return value.stop.wait(timeout)

    monkeypatch.setattr(value.dispatch, "wait", wait)
    monkeypatch.setattr(store, "retain", lambda: None)
    value.loop()
    return value


def test_partial_adaptive_flush_reports_retained_queue_and_recovers(store, monkeypatch):
    prepare_adaptive(store, monkeypatch)
    value = Runtime(store)

    assert value.drain() is True
    assert value.last_indexed == value.indexed_total == 2
    assert value.last_batches == 1  # Preserve the partial-batch yield.
    assert queue_state(store) == {
        "queue": ["new-2", "new-3", "new-4"],
        "pending": 5,
        "inflight": 0,
    }

    assert log_search.drain(store, budget=2, max_documents=5)["processed"] == 5
    assert value.drain() is False
    assert value.last_indexed == 3 and value.indexed_total == 5
    assert value.last_batches == 1
    assert queue_state(store) == {"queue": [], "pending": 3, "inflight": 0}
    assert log_search.drain(store, budget=2)["processed"] == 3
    with closing(store.analytics.cursor()) as db:
        expected = sorted(
            [("a", f"seed-{n}") for n in range(3)]
            + [("a", f"new-{n}") for n in range(5)]
        )
        assert (
            db.execute(
                "SELECT tenant,event_id FROM events_all ORDER BY tenant,event_id"
            ).fetchall()
            == expected
        )
    with closing(sqlite3.connect(store.path / "log-search" / "terms.sqlite3")) as db:
        assert (
            db.execute(
                "SELECT tenant,event_id FROM registry ORDER BY tenant,event_id"
            ).fetchall()
            == expected
        )
        assert db.execute("SELECT count(*) FROM terms").fetchone()[0] == 8
    assert queue_state(store) == {"queue": [], "pending": 0, "inflight": 0}


def test_partial_flush_that_empties_queue_reports_idle(store):
    store.ingest("a", [{"event_id": str(n)} for n in range(2)])
    value = Runtime(store)
    assert value.drain() is False
    assert value.last_indexed == 2 and value.last_batches == 1
    assert queue_state(store) == {"queue": [], "pending": 2, "inflight": 0}


@pytest.mark.parametrize("population,expected_backlog", [(2, False), (3, True)])
def test_full_batch_budget_yield_uses_actual_queue(
    store, monkeypatch, population, expected_backlog
):
    store.settings.indexing_batch = 2
    store.settings.indexing_budget = 0.01
    store.ingest("a", [{"event_id": str(n)} for n in range(population)])
    clock = [100.0]
    monkeypatch.setattr(
        runtime_module,
        "time",
        SimpleNamespace(monotonic=lambda: clock[0], time=time.time),
    )
    flush = store.flush
    calls = []

    def budget_flush(batch):
        calls.append(batch)
        result = flush(batch=batch)
        clock[0] += 0.02
        return result

    monkeypatch.setattr(store, "flush", budget_flush)
    value = Runtime(store)
    assert value.drain() is expected_backlog
    assert calls == [2]
    assert value.last_indexed == 2 and value.last_batches == 1
    assert len(queue_state(store)["queue"]) == population - 2
    assert value.indexing_active_eps == 100


@pytest.mark.parametrize("received", [0.0, "future"])
def test_pending_timestamp_zero_or_future_is_still_backlog(
    store, monkeypatch, received
):
    store.ingest("a", [{"event_id": "pending"}])
    stamp = time.time() + 3600 if received == "future" else received
    with store.control(local=True) as db:
        db.execute("UPDATE queue SET received=?", (stamp,))
    monkeypatch.setattr(store, "flush", lambda batch: 0)
    value = Runtime(store)
    assert value.drain() is True
    assert queue_state(store)["queue"] == ["pending"]
    assert value.last_indexed == 0 and value.last_batches == 1
    if received == "future":
        assert value.indexing_lag == 0
    else:
        assert value.indexing_lag > 1_000_000


def test_loop_retries_successful_partial_backlog_after_short_wait(store, monkeypatch):
    prepare_adaptive(store, monkeypatch)
    value = run_one_iteration(store, monkeypatch)
    assert value.stop.waits == [0.01]
    assert value.last_error is None
    assert value.last_indexed == 2 and value.last_batches == 1
    assert queue_state(store) == {
        "queue": ["new-2", "new-3", "new-4"],
        "pending": 5,
        "inflight": 0,
    }


def test_loop_keeps_capacity_error_backoff_and_unacknowledged_queue(store, monkeypatch):
    prepare_adaptive(store, monkeypatch, initial=5)
    before = queue_state(store)
    value = run_one_iteration(store, monkeypatch)
    assert value.stop.waits == [0.25]
    assert value.last_error == "CapacityError"
    assert value.last_indexed == value.last_batches == 0
    assert queue_state(store) == before


@pytest.mark.parametrize("population", [0, 2])
def test_loop_uses_idle_wait_when_queue_is_empty_after_flush(
    store, monkeypatch, population
):
    if population:
        store.ingest("a", [{"event_id": str(n)} for n in range(population)])
    value = run_one_iteration(store, monkeypatch)
    assert value.stop.waits == [0.25]
    assert value.last_error is None and value.last_indexed == population
    assert queue_state(store)["queue"] == []


@pytest.mark.parametrize("population", [0, 1])
def test_stopped_drain_preserves_queue_and_never_flushes(
    store, monkeypatch, population
):
    if population:
        store.ingest("a", [{"event_id": "pending"}])

    def unexpected_flush(batch):
        pytest.fail("A stopped indexer must not flush")

    monkeypatch.setattr(store, "flush", unexpected_flush)
    value = Runtime(store)
    value.stop = OneIterationStop()
    value.stop.set()
    assert value.drain() is bool(population)
    value.loop()
    assert value.last_indexed == value.last_batches == 0
    assert len(queue_state(store)["queue"]) == population
    assert value.stop.waits == []


def test_stop_during_successful_flush_does_not_consume_another_batch(
    store, monkeypatch
):
    store.settings.indexing_batch = 2
    store.ingest("a", [{"event_id": str(n)} for n in range(5)])
    value = Runtime(store)
    flush = store.flush
    calls = []

    def stop_after_flush(batch):
        calls.append(batch)
        result = flush(batch=batch)
        value.stop.set()
        return result

    monkeypatch.setattr(store, "flush", stop_after_flush)
    assert value.drain() is True
    assert calls == [2]
    assert value.last_indexed == 2 and value.last_batches == 1
    assert queue_state(store) == {
        "queue": ["2", "3", "4"],
        "pending": 2,
        "inflight": 0,
    }
