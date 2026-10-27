"""Incremental tokenization, exact identity tracking and failed-build recovery."""

import sqlite3
import time
from contextlib import closing

import pytest

from sapientia import log_search, storage
from sapientia.storage import CapacityError, ConflictError, Settings, Store
from tests.capacity_helpers import purge as capacity_purge


class CursorSpy:
    def __init__(self, cursor, owner):
        self.cursor, self.owner, self.body = cursor, owner, False

    def execute(self, sql, args=None):
        self.body = sql.startswith(
            "SELECT tenant,event_id,message,raw,index_name FROM "
        )
        self.cursor.execute(sql, args or [])
        if self.body:
            self.owner.body_queries += 1
        return self

    def fetchmany(self, count):
        if self.body and self.owner.fail_batch == self.owner.body_batches:
            raise RuntimeError("synthetic body read failure")
        rows = self.cursor.fetchmany(count)
        if self.body:
            self.owner.body_batches += 1
            self.owner.body_rows += len(rows)
            if self.owner.after_body:
                self.owner.after_body()
        return rows

    def __getattr__(self, name):
        return getattr(self.cursor, name)


class AnalyticsSpy:
    def __init__(self, connection):
        self.connection = connection
        self.body_rows = self.body_batches = self.body_queries = 0
        self.fail_batch = None
        self.after_body = None

    def cursor(self):
        return CursorSpy(self.connection.cursor(), self)

    def __getattr__(self, name):
        return getattr(self.connection, name)


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    value.analytics = AnalyticsSpy(value.analytics)
    yield value
    value.close()


def ingest(store, count, prefix="e", message="oldtoken", tenant="a"):
    store.ingest(
        tenant,
        [
            {
                "event_id": prefix + str(n),
                "event_time": 100,
                "message": message,
                "raw": {"n": n, "text": message},
            }
            for n in range(count)
        ],
    )
    while store.flush():
        pass


def build(store, seconds=10):
    deadline = time.monotonic() + seconds
    with store.flush_lock, store.segment_lock.read(deadline=deadline):
        store.segments.ensure_readable(deadline=deadline)
        while True:
            try:
                return log_search._fts(store, deadline)
            except CapacityError as error:
                # Interactive indexing deliberately yields after 250 ms.
                # Wait only for that documented progress state, within the
                # original deadline; never mask actual budget/build errors.
                if str(error) != "Full-text indexing in progress; structured search remains available" or time.monotonic() >= deadline:
                    raise


def inspect(path):
    with closing(sqlite3.connect(path)) as db:
        metadata = db.execute(
            "SELECT generation,purges,format_version,documents,applied_sequence FROM metadata"
        ).fetchone()
        identities = db.execute(
            "SELECT tenant,event_id,term_rowid FROM registry ORDER BY tenant,event_id"
        ).fetchall()
        assert db.execute("SELECT count(*) FROM terms").fetchone()[0] == len(identities)
        return metadata, identities


def matches(path, term):
    with closing(sqlite3.connect(path)) as db:
        return db.execute(
            "SELECT tenant,event_id FROM terms WHERE terms MATCH ? ORDER BY tenant,event_id",
            (term,),
        ).fetchall()


def test_only_new_bodies_indexed_with_backwards_clock_and_tenant_identity(
    store, monkeypatch
):
    ingest(store, 250)
    path = build(store)
    original, rows = inspect(path)
    assert store.analytics.body_rows == 0 and original[3] == 250
    assert store.analytics.body_queries == 0
    before = store.analytics.body_rows
    old_time = time.time() - 3600
    with monkeypatch.context() as scoped:
        scoped.setattr(storage.time, "time", lambda: old_time)
        ingest(store, 2, prefix="late", message="newtoken")
        ingest(store, 1, message="othertenant", tenant="b")
    assert build(store) == path
    changed, all_rows = inspect(path)
    assert store.analytics.body_rows - before == 0
    assert store.analytics.body_queries == 0
    assert changed[3] == 253
    assert set(rows) <= set(all_rows)  # Old FTS rowids stay stable during append.
    assert matches(path, "newtoken") == [("a", "late0"), ("a", "late1")]
    assert matches(path, "othertenant") == [("b", "e0")]
    before = store.analytics.body_rows
    build(store)
    assert store.analytics.body_rows == before


def test_failed_incremental_batch_rolls_back_generation_registry_and_terms(
    store, monkeypatch
):
    ingest(store, 5)
    path = build(store)
    old_metadata, old_rows = inspect(path)
    ingest(store, 300, prefix="next", message="newtoken")
    original = log_search._check_fts_budget
    calls = 0

    def fail_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("synthetic journal body failure")
        return original(*args, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(log_search, "_check_fts_budget", fail_second)
        with pytest.raises(RuntimeError, match="synthetic journal body"):
            build(store)
    assert inspect(path) == (old_metadata, old_rows)
    assert matches(path, "newtoken") == []
    build(store)
    assert inspect(path)[0][3] == 305
    assert len(matches(path, "newtoken")) == 300


def test_retention_purge_rebuilds_before_reused_id_can_restore_old_term(
    store, monkeypatch
):
    old_time = time.time() - (store.settings.retention_days + 10) * 86400
    with monkeypatch.context() as scoped:
        scoped.setattr(storage.time, "time", lambda: old_time)
        ingest(store, 1, message="deletedsecret")
    path = build(store)
    previous = inspect(path)[0]
    assert store.retain(time.time()) == 0
    assert capacity_purge(store,event_ids=["e0"]) == 1
    assert store.purge_generation > previous[1]
    ingest(store, 1, message="replacementtoken")
    build(store)
    assert inspect(path)[0][3] == 1
    assert matches(path, "deletedsecret") == []
    assert matches(path, "replacementtoken") == [("a", "e0")]


def test_pending_retention_never_refreshes_from_stale_source(store):
    ingest(store, 1)
    path = build(store)
    capacity_purge(store,event_ids=["e0"],plan_only=True)
    with pytest.raises(ConflictError, match="Retention deletion is pending"):
        store.search("a",{"query":"*"})
    # A real capacity intent also publishes a purge epoch. FTS may expose that
    # pending epoch as indexing-in-progress rather than the structured fence;
    # neither path may serve the stale complete cache as a successful query.
    with pytest.raises((ConflictError,CapacityError),match="Retention deletion is pending|Full-text indexing in progress"),store.flush_lock,store.segment_lock.read():
        log_search._fts(store,time.monotonic()+2)
    assert inspect(path)[0][3] == 1


def test_legacy_cache_one_time_rebuild_then_append_and_deadline_rollback(store):
    ingest(store, 1)
    path = log_search.initialize(store) / "terms.sqlite3"
    with closing(sqlite3.connect(path)) as db:
        db.execute("CREATE TABLE metadata(generation TEXT)")
        db.execute("INSERT INTO metadata VALUES(?)", (log_search._generation(store),))
        db.execute("CREATE VIRTUAL TABLE terms USING fts5(tenant,event_id,message,raw)")
        db.execute("INSERT INTO terms VALUES('a','obsolete','oldsecret','{}')")
        db.commit()
    with pytest.raises(ConflictError, match="version"):
        build(store)
    log_search.rebuild(store, time.monotonic() + 10)
    assert inspect(path)[0][2:4] == (log_search.FTS_FORMAT, 1)
    assert matches(path, "oldsecret") == []
    # Target the FTS deadline itself; SegmentGate independently rejects an
    # expired deadline before an enclosing caller could reach this method.
    with (
        pytest.raises(CapacityError, match="deadline"),
        store.flush_lock,
        store.segment_lock.read(),
    ):
        log_search._fts(store, time.monotonic() - 1)
    assert inspect(path)[0][3] == 1


def test_disk_budget_failure_preserves_previous_complete_cache(store, monkeypatch):
    ingest(store, 3)
    path = build(store)
    original = inspect(path)
    ingest(store, 2, prefix="new", message="newtoken")
    monkeypatch.setattr(store.settings, "fts_max_bytes", path.stat().st_size)
    with pytest.raises(CapacityError, match="disk budget"):
        build(store)
    assert inspect(path) == original
    assert matches(path, "newtoken") == []


def test_deadline_mid_refresh_rolls_back_all_new_terms(store, monkeypatch):
    ingest(store, 3)
    path = build(store)
    original = inspect(path)
    ingest(store, 300, prefix="new", message="newtoken")
    actual_clock = time.monotonic
    expired = False
    expire_at_batch = store.analytics.body_batches + 2

    def expire_after_second_body():
        nonlocal expired
        if store.analytics.body_batches == expire_at_batch:
            expired = True

    store.analytics.after_body = expire_after_second_body
    with monkeypatch.context() as scoped:
        scoped.setattr(
            log_search.time,
            "monotonic",
            lambda: actual_clock() + (20 if expired else 0),
        )
        with pytest.raises(CapacityError, match="deadline"):
            log_search.rebuild(store, actual_clock() + 10)
    assert expired
    assert inspect(path) == original
    assert matches(path, "newtoken") == []
