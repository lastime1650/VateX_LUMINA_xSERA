"""Native document boundaries are independent of cooperative batch yields."""

import sqlite3
import threading
from contextlib import closing

import pytest

from sapientia import log_search
from sapientia.storage import Settings, Store


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    yield value
    value.close()


def ingest(store, count=10):
    store.ingest(
        "a", [{"event_id": f"atomic{n}", "message": "atomicword"} for n in range(count)]
    )
    store.flush()


def state(store):
    with store.control(local=True) as db:
        return tuple(
            db.execute(
                "SELECT pending_documents,indexed_documents FROM log_fts_state"
            ).fetchone()
        )


def actual(store):
    with closing(sqlite3.connect(store.path / "log-search" / "terms.sqlite3")) as db:
        return (
            db.execute("SELECT count(*) FROM registry").fetchone()[0],
            db.execute("SELECT count(*) FROM terms").fetchone()[0],
        )


def native_work(db):
    return db.execute(
        "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<2000) SELECT sum(x) FROM n"
    ).fetchone()


@pytest.mark.parametrize("stop", ["cooperative", "hard_deadline", "cancel"])
def test_terms_then_registry_complete_within_atomic_guard_or_replay(
    store, monkeypatch, stop
):
    ingest(store)
    original = log_search._open_terms
    clock, inserted = [0.0], [0]
    cancel = threading.Event()

    class DelayedTerms:
        def __init__(self, db):
            self.db = db

        def __getattr__(self, key):
            return getattr(self.db, key)

        def execute(self, sql, *params):
            if sql.startswith("INSERT INTO registry"):
                native_work(self.db)  # Invokes the real SQLite VM callback.
            result = self.db.execute(sql, *params)
            if sql.startswith("INSERT INTO terms"):
                inserted[0] += 1
                if inserted[0] == 3:
                    clock[0] += 0.5
                    if stop == "cancel":
                        cancel.set()
            return result

    with monkeypatch.context() as scoped:
        scoped.setattr(log_search.time, "monotonic", lambda: clock[0])
        scoped.setattr(log_search, "_open_terms", lambda p: DelayedTerms(original(p)))
        if stop == "cooperative":
            assert log_search.drain(store, budget=0.25)["processed"] == 3
        else:
            with pytest.raises(sqlite3.OperationalError, match="interrupted"):
                log_search.drain(
                    store,
                    budget=0.25,
                    cancel=cancel,
                    hard_deadline=0.25 if stop == "hard_deadline" else None,
                )
    expected = 3 if stop == "cooperative" else 0
    assert state(store) == (10 - expected, expected)
    assert actual(store) == (expected, expected)
    cancel.clear()
    assert log_search.drain(store, budget=3)["processed"] == 10 - expected
    assert state(store) == (0, 10) and actual(store) == (10, 10)


def test_checkpoint_retains_independent_native_guard(store, monkeypatch):
    ingest(store)
    original = log_search._open_terms
    clock = [0.0]

    class StalledCheckpoint:
        def __init__(self, db):
            self.db = db

        def __getattr__(self, key):
            return getattr(self.db, key)

        def execute(self, sql, *params):
            if sql.startswith("UPDATE metadata SET applied_sequence"):
                clock[0] += (
                    getattr(
                        log_search,
                        "FTS_CHECKPOINT_NATIVE_SECONDS",
                        log_search.FTS_NATIVE_SECONDS,
                    )
                    + 1
                )
                native_work(self.db)
            return self.db.execute(sql, *params)

    with monkeypatch.context() as scoped:
        scoped.setattr(log_search.time, "monotonic", lambda: clock[0])
        scoped.setattr(
            log_search, "_open_terms", lambda p: StalledCheckpoint(original(p))
        )
        with pytest.raises(sqlite3.OperationalError, match="interrupted"):
            log_search.drain(store, budget=0.25)
    assert state(store) == (10, 0) and actual(store) == (0, 0)
    assert log_search.drain(store, budget=3)["processed"] == 10
    assert actual(store) == (10, 10)


@pytest.mark.parametrize("hard_deadline", [None, 1.5])
def test_checkpoint_flush_has_separate_budget_and_keeps_interactive_deadline(
    store, monkeypatch, hard_deadline
):
    """A native two-second checkpoint is valid background work, not a document."""
    ingest(store, 10)
    original = log_search._open_terms
    clock = [0.0]

    class NativeCheckpoint:
        def __init__(self, db):
            self.db = db

        def __getattr__(self, key):
            return getattr(self.db, key)

        def execute(self, sql, *params):
            if sql.startswith("UPDATE metadata SET applied_sequence"):
                clock[0] += 2
                native_work(self.db)
            return self.db.execute(sql, *params)

    with monkeypatch.context() as scoped:
        scoped.setattr(log_search.time, "monotonic", lambda: clock[0])
        scoped.setattr(
            log_search, "_open_terms", lambda p: NativeCheckpoint(original(p))
        )
        if hard_deadline is None:
            assert log_search.drain(store, budget=0.25)["processed"] == 10
        else:
            with pytest.raises(sqlite3.OperationalError, match="interrupted"):
                log_search.drain(store, budget=0.25, hard_deadline=hard_deadline)
    expected = 10 if hard_deadline is None else 0
    assert state(store) == (10 - expected, expected)
    assert actual(store) == (expected, expected)
    assert log_search.drain(store, budget=3)["processed"] == 10 - expected
    assert state(store) == (0, 10) and actual(store) == (10, 10)


def test_interactive_fts_passes_outer_deadline_to_native_work(store, monkeypatch):
    ingest(store, 1)
    log_search.drain(store, budget=3)
    original = log_search.drain
    deadlines = []

    def observed(*args, **kwargs):
        deadlines.append(kwargs["hard_deadline"])
        return original(*args, **kwargs)

    monkeypatch.setattr(log_search, "drain", observed)
    deadline = log_search.time.monotonic() + 15
    assert log_search._fts(store, deadline).is_file()
    assert deadlines == [deadline]


def test_idle_latest_cache_does_not_write_while_long_reader_is_active(store):
    ingest(store, 1)
    log_search.drain(store, budget=3)
    with closing(
        sqlite3.connect(store.path / "log-search" / "terms.sqlite3")
    ) as reader:
        reader.execute("BEGIN")
        assert reader.execute("SELECT count(*) FROM terms").fetchone()[0] == 1
        for _ in range(3):
            assert log_search.drain(store, budget=0.25) == {"processed": 0}
        with store.control(local=True) as db:
            assert (
                db.execute("SELECT last_error FROM log_fts_state").fetchone()[0] is None
            )
        # An earlier transient error clears without attempting a cache write.
        with store.control(local=True) as db:
            db.execute("UPDATE log_fts_state SET last_error='sqlite_busy'")
        assert log_search.drain(store, budget=0.25) == {"processed": 0}
        with store.control(local=True) as db:
            assert (
                db.execute("SELECT last_error FROM log_fts_state").fetchone()[0] is None
            )
    assert actual(store) == (1, 1)


def test_real_purge_epoch_still_waits_for_reader_then_advances_safely(store):
    ingest(store, 1)
    log_search.drain(store, budget=3)
    with closing(
        sqlite3.connect(store.path / "log-search" / "terms.sqlite3")
    ) as reader:
        reader.execute("BEGIN")
        assert reader.execute("SELECT count(*) FROM terms").fetchone()[0] == 1
        with store.control(local=True) as db:
            store.segments.bump(db, purge=True, content=False)
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            log_search.drain(store, budget=0.25)
        with store.control(local=True) as db:
            assert tuple(
                db.execute("SELECT purges,last_error FROM log_fts_state").fetchone()
            ) == (
                0,
                "sqlite_busy",
            )
    assert log_search.drain(store, budget=0.25) == {"processed": 0}
    with store.control(local=True) as db:
        assert tuple(
            db.execute("SELECT purges,last_error FROM log_fts_state").fetchone()
        ) == (
            store.purge_generation,
            None,
        )
    with closing(sqlite3.connect(store.path / "log-search" / "terms.sqlite3")) as db:
        assert (
            db.execute("SELECT purges FROM metadata").fetchone()[0]
            == store.purge_generation
        )
    assert actual(store) == (1, 1)
