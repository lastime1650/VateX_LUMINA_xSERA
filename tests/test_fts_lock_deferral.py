"""Only the background consumer may defer a busy FTS acquisition."""

import logging
import sqlite3
import time
from contextlib import closing

import pytest

from sapientia import log_search
from sapientia.runtime import Runtime
from sapientia.storage import CapacityError, Settings, Store


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    yield value
    value.close()


def ingest(store, count=3, prefix="deferred"):
    store.ingest(
        "a", [{"event_id": f"{prefix}{n}", "message": prefix} for n in range(count)]
    )
    store.flush()


def state(store):
    with store.control(local=True) as db:
        return (
            tuple(db.execute("SELECT * FROM log_fts_state").fetchone()),
            [
                tuple(r)
                for r in db.execute("SELECT * FROM log_fts_journal ORDER BY seq")
            ],
        )


def actual(store):
    with closing(sqlite3.connect(store.path / "log-search" / "terms.sqlite3")) as db:
        return (
            db.execute("SELECT count(*) FROM registry").fetchone()[0],
            db.execute("SELECT count(*) FROM terms").fetchone()[0],
        )


def test_busy_background_mutex_preserves_pending_cache_and_real_error(store):
    ingest(store)
    with store.control(local=True) as db:
        db.execute("UPDATE log_fts_state SET last_error='sqlite_busy'")
    before = state(store)
    path = store.path / "log-search" / "terms.sqlite3"
    lock = log_search._fts_lock(store)
    with lock:
        started = time.monotonic()
        assert log_search.drain(store, budget=0.01, defer_lock=True) == {
            "processed": 0,
            "deferred": "fts_lock",
        }
        assert time.monotonic() - started < 1.0
    assert state(store) == before and not path.exists()
    assert log_search.drain(store, budget=3, defer_lock=True)["processed"] == 3
    assert actual(store) == (3, 3)
    with store.control(local=True) as db:
        assert db.execute("SELECT last_error FROM log_fts_state").fetchone()[0] is None
        assert db.execute("SELECT count(*) FROM log_fts_journal").fetchone()[0] == 0


@pytest.mark.parametrize("interactive", [False, True])
def test_default_and_interactive_busy_mutex_still_fail_with_deadline(
    store, interactive
):
    ingest(store)
    with (
        log_search._fts_lock(store),
        pytest.raises(CapacityError, match="deadline.*waiting for storage"),
    ):
        if interactive:
            log_search._fts(store, time.monotonic() + 0.01)
        else:
            log_search.drain(store, budget=0.01)
    with store.control(local=True) as db:
        row = db.execute(
            "SELECT pending_documents,last_error FROM log_fts_state"
        ).fetchone()
        assert tuple(row) == (3, "deadline")


def test_deferred_mode_keeps_real_disk_quota_failure_and_replay(store, monkeypatch):
    ingest(store)
    log_search.drain(store, budget=3)
    ingest(store, 5, "newtoken")
    with monkeypatch.context() as scoped:
        scoped.setattr(store.settings, "fts_max_bytes", 1)
        with pytest.raises(CapacityError, match="disk budget"):
            log_search.drain(store, budget=3, defer_lock=True)
    assert actual(store) == (3, 3)
    with store.control(local=True) as db:
        assert tuple(
            db.execute(
                "SELECT pending_documents,last_error FROM log_fts_state"
            ).fetchone()
        ) == (5, "disk_quota")
    assert log_search.drain(store, budget=3, defer_lock=True)["processed"] == 5
    assert actual(store) == (8, 8)


def test_deferred_mode_does_not_swallow_sqlite_busy(store, monkeypatch):
    ingest(store)
    exception = sqlite3.OperationalError("private sqlite detail")
    exception.sqlite_errorcode = sqlite3.SQLITE_BUSY

    def busy(_path):
        raise exception

    monkeypatch.setattr(log_search, "_open_terms", busy)
    with pytest.raises(sqlite3.OperationalError):
        log_search.drain(store, budget=3, defer_lock=True)
    with store.control(local=True) as db:
        assert tuple(
            db.execute(
                "SELECT pending_documents,last_error FROM log_fts_state"
            ).fetchone()
        ) == (3, "sqlite_busy")


class Cycles:
    def __init__(self, runtime, maximum):
        self.runtime = runtime
        self.maximum = maximum
        self.observations = []
        self.delays = []

    def is_set(self):
        return len(self.delays) >= self.maximum

    def wait(self, delay):
        self.delays.append(delay)
        self.observations.append(self.runtime.health())


def observe_dispatch_wait(runtime, stop, monkeypatch):
    # Count committed-stage waits as well as the error backoff. The real
    # generation/close wake-up contract is covered by test_pipeline_dispatch.
    def wait(stage, token, timeout):
        assert stage == "fts"
        assert token == runtime.dispatch.token(stage)
        return stop.wait(timeout)

    monkeypatch.setattr(runtime.dispatch, "wait", wait)


def test_runtime_deferral_preserves_real_error_until_success(
    store, monkeypatch, caplog
):
    runtime = Runtime(store)
    runtime.fts_error, runtime.fts_error_code = "OperationalError", "sqlite_busy"
    stop = Cycles(runtime, 3)
    runtime.stop = stop
    observe_dispatch_wait(runtime, stop, monkeypatch)
    outcomes = iter(
        [
            {"processed": 0, "deferred": "fts_lock"},
            {"processed": 0, "deferred": "fts_lock"},
            {"processed": 1},
        ]
    )
    flags = []

    def drain(_store, **kwargs):
        flags.append(kwargs["defer_lock"])
        return next(outcomes)

    monkeypatch.setattr(log_search, "drain", drain)
    with caplog.at_level(logging.ERROR, logger="sapientia"):
        runtime.fts_loop()
    assert flags == [True, True, True]
    assert stop.delays == [0.25, 0.25, 0.01]
    for observed in stop.observations[:2]:
        assert observed["fulltext_error_code"] == "sqlite_busy"
        assert observed["fulltext_error"] == "OperationalError"
        assert observed["fulltext_deferred"] == "fts_lock"
    assert stop.observations[-1]["fulltext_error_code"] is None
    assert stop.observations[-1]["fulltext_error"] is None
    assert stop.observations[-1]["fulltext_deferred"] is None
    assert "Full-text indexing failed" not in caplog.text


def test_runtime_real_failure_after_deferral_keeps_existing_error_path(
    store, monkeypatch, caplog
):
    runtime = Runtime(store)
    stop = Cycles(runtime, 2)
    runtime.stop = stop
    observe_dispatch_wait(runtime, stop, monkeypatch)
    calls = [0]

    def drain(_store, **kwargs):
        assert kwargs["defer_lock"] is True
        calls[0] += 1
        if calls[0] == 1:
            return {"processed": 0, "deferred": "fts_lock"}
        raise CapacityError("Full-text configured disk budget exceeded")

    monkeypatch.setattr(log_search, "drain", drain)
    with caplog.at_level(logging.ERROR, logger="sapientia"):
        runtime.fts_loop()
    assert stop.delays == [0.25, 1]
    assert stop.observations[-1]["fulltext_deferred"] is None
    assert stop.observations[-1]["fulltext_error_code"] == "disk_quota"
    assert stop.observations[-1]["fulltext_error"] == "CapacityError"
    assert (
        len([r for r in caplog.records if "Full-text indexing failed" in r.message])
        == 1
    )
