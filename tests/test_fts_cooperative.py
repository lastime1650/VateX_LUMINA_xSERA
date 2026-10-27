"""A cooperative yield commits progress; interrupted native rows remain atomic."""

import sqlite3
import threading
from contextlib import closing

import pytest

from sapientia import log_search
from sapientia.storage import CapacityError, Settings, Store


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    yield value
    value.close()


def ingest(store, count, prefix="e", message="prefixword"):
    store.ingest(
        "a", [{"event_id": f"{prefix}{n}", "message": message} for n in range(count)]
    )
    store.flush()


def state(store):
    with store.control(local=True) as db:
        return tuple(
            db.execute(
                "SELECT pending_documents,indexed_documents FROM log_fts_state"
            ).fetchone()
        )


def hits(store, token):
    with closing(sqlite3.connect(store.path / "log-search" / "terms.sqlite3")) as db:
        return db.execute(
            "SELECT count(*) FROM terms WHERE terms MATCH ?", (token,)
        ).fetchone()[0]


def native_work(db):
    # Real SQLite VM work invokes the installed progress callback. No wall sleep.
    return db.execute(
        "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<2000) SELECT sum(x) FROM n"
    ).fetchone()


@pytest.mark.parametrize("cancelled", [False, True])
def test_completed_prefix_checkpoint_survives_late_time_or_cancellation(
    store, monkeypatch, cancelled
):
    ingest(store, 10)
    original = log_search._open_terms
    clock = [0.0]
    inserts = [0]
    checkpoints = [0]
    cancel = threading.Event()

    class SlowCheckpoint:
        def __init__(self, db):
            self.db = db

        def __getattr__(self, key):
            return getattr(self.db, key)

        def execute(self, sql, *params):
            if sql.startswith("UPDATE metadata SET applied_sequence"):
                checkpoints[0] += 1
                clock[0] += 0.5  # Beyond the slice, inside the fresh native guard.
                native_work(self.db)
            result = self.db.execute(sql, *params)
            if sql.startswith("INSERT INTO registry"):
                inserts[0] += 1
                if inserts[0] == 3:
                    if cancelled:
                        cancel.set()
                    else:
                        clock[0] += 0.5
            return result

    with monkeypatch.context() as scoped:
        scoped.setattr(log_search.time, "monotonic", lambda: clock[0])
        scoped.setattr(
            log_search, "_open_terms", lambda path: SlowCheckpoint(original(path))
        )
        result = log_search.drain(store, budget=0.25, cancel=cancel)
    assert result["processed"] == 3
    assert result.get("cancelled", False) is cancelled
    assert checkpoints[0] == 1 and state(store) == (7, 3)
    assert hits(store, "prefixword") == 3
    cancel.clear()
    assert log_search.drain(store, budget=3, cancel=cancel)["processed"] == 7
    assert state(store) == (0, 10) and hits(store, "prefixword") == 10


def test_late_filesystem_probe_yields_without_undoing_completed_prefix(
    store, monkeypatch
):
    ingest(store, 300)
    original = log_search._check_fts_budget
    clock = [0.0]
    checks = [0]

    def late(*args, **kwargs):
        extra = args[4] if len(args) > 4 else kwargs.get("extra", 0)
        if extra:
            checks[0] += 1
            if checks[0] == 2:
                clock[0] += 1
        return original(*args, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(log_search.time, "monotonic", lambda: clock[0])
        scoped.setattr(log_search, "_check_fts_budget", late)
        result = log_search.drain(store, budget=0.25, max_documents=300)
    assert result["processed"] == 128
    assert state(store) == (172, 128) and hits(store, "prefixword") == 128
    assert log_search.drain(store, budget=3)["processed"] == 172
    assert state(store) == (0, 300)


def test_native_row_interrupt_still_rolls_back_and_replays_without_partial_row(
    store, monkeypatch
):
    ingest(store, 3, prefix="old", message="originalword")
    log_search.drain(store, budget=3)
    ingest(store, 5, prefix="new", message="newword")
    original = log_search._open_terms
    clock = [0.0]
    inserts = [0]

    class SlowNativeRow:
        def __init__(self, db):
            self.db = db

        def __getattr__(self, key):
            return getattr(self.db, key)

        def execute(self, sql, *params):
            if sql.startswith("INSERT INTO terms"):
                inserts[0] += 1
                if inserts[0] == 2:
                    clock[0] += 2
                    native_work(self.db)
            return self.db.execute(sql, *params)

    with monkeypatch.context() as scoped:
        scoped.setattr(log_search.time, "monotonic", lambda: clock[0])
        scoped.setattr(
            log_search, "_open_terms", lambda path: SlowNativeRow(original(path))
        )
        with pytest.raises(sqlite3.OperationalError, match="interrupted"):
            log_search.drain(store, budget=0.25)
    assert state(store) == (5, 3)
    assert hits(store, "originalword") == 3 and hits(store, "newword") == 0
    with store.control(local=True) as db:
        assert (
            db.execute("SELECT last_error FROM log_fts_state").fetchone()[0]
            == "sqlite_interrupted"
        )
    assert log_search.drain(store, budget=3)["processed"] == 5
    assert state(store) == (0, 8) and hits(store, "newword") == 5


def test_interactive_lock_wait_retains_requested_budget(store, monkeypatch):
    ingest(store, 1)
    waits = []

    class Unavailable:
        def acquire(self, timeout):
            waits.append(timeout)
            return False

    monkeypatch.setattr(log_search, "_fts_lock", lambda _: Unavailable())
    with pytest.raises(CapacityError, match="deadline"):
        log_search.drain(store, budget=0.25)
    assert len(waits) == 1 and 0 <= waits[0] <= 0.25
    assert state(store) == (1, 0)


@pytest.mark.parametrize(
    "kind,expected",
    [
        (sqlite3.SQLITE_INTERRUPT, "sqlite_interrupted"),
        (sqlite3.SQLITE_BUSY, "sqlite_busy"),
        (sqlite3.SQLITE_LOCKED, "sqlite_busy"),
        (sqlite3.SQLITE_CORRUPT, "sqlite_error"),
    ],
)
def test_sqlite_error_codes_never_return_payload_or_arbitrary_messages(kind, expected):
    error = sqlite3.OperationalError("synthetic-private-message")
    error.sqlite_errorcode = kind
    assert log_search.error_code(error) == expected
