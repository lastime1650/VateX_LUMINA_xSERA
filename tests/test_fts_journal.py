"""Durable full-text handoff, bounded work and fail-closed source consistency."""

import sqlite3
import time
from contextlib import closing

import pytest

from sapientia import access, auth, log_search
from sapientia.storage import CapacityError, ConflictError, Settings, Store
from tests.capacity_helpers import purge as capacity_purge

WHO = {"name": "reader", "tenant": "a", "role": "admin"}


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    auth.create_user(value, "reader", "Synthetic-only-password-2026", "admin", "a")
    yield value
    value.close()


def ingest(store, count=1, prefix="e", message="firsttoken", tenant="a", index="main"):
    store.ingest(
        tenant,
        [
            {"event_id": prefix + str(n), "message": message, "index": index}
            for n in range(count)
        ],
    )
    while store.flush():
        pass


def ready(store):
    for _ in range(100):
        log_search.drain(store, budget=3, max_documents=1000)
        if log_search.status(store, WHO)["fulltext"]["ready"]:
            return store.path / "log-search" / "terms.sqlite3"
    raise AssertionError("Synthetic small fixture did not become ready")


def terms(path, term):
    with closing(sqlite3.connect(path)) as db:
        return db.execute(
            "SELECT tenant,event_id FROM terms WHERE terms MATCH ? ORDER BY tenant,event_id",
            (term,),
        ).fetchall()


def test_no_analytics_scan_during_incremental_refresh(store):
    ingest(store, 3)
    path = ready(store)
    ingest(store, 2, prefix="new", message="secondtoken")
    original = store.analytics

    class NoSourceRead:
        def cursor(self):
            raise AssertionError(
                "FTS increment must consume journal, not scan source IDs/bodies"
            )

    store.analytics = NoSourceRead()
    try:
        log_search.drain(store, budget=3)
    finally:
        store.analytics = original
    assert terms(path, "secondtoken") == [("a", "new0"), ("a", "new1")]


def test_fts_commit_before_control_ack_replays_exactly_once(store):
    ingest(store, 4)

    def crash():
        raise RuntimeError("synthetic crash after durable FTS commit")

    with pytest.raises(RuntimeError, match="synthetic crash"):
        log_search.drain(store, budget=3, after_commit=crash)
    with store.control(local=True) as db:
        assert db.execute("SELECT count(*) FROM log_fts_journal").fetchone()[0] == 4
    path = ready(store)
    assert len(terms(path, "firsttoken")) == 4
    with store.control(local=True) as db:
        assert db.execute(
            "SELECT pending_documents,pending_bytes FROM log_fts_state"
        ).fetchone()[:] == (0, 0)


def test_source_commit_without_outbox_ack_is_fenced_until_replay(store, monkeypatch):
    store.ingest("a", [{"event_id": "committed", "message": "committedtoken"}])
    with (
        monkeypatch.context() as scoped,
        pytest.raises(CapacityError, match="journal full"),
    ):
        # Capacity may change after the read-only preflight. The final
        # append must still fence an already committed source batch.
        store.flush(
            after_commit=lambda: scoped.setattr(log_search, "MAX_PENDING_DOCUMENTS", 0)
        )
    assert store.search("a", {})["returned"] == 1  # Source commit succeeded.
    with store.control(local=True) as db:
        assert db.execute("SELECT count(*) FROM queue").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM log_fts_inflight").fetchone()[0] == 1
    assert log_search.status(store, WHO)["fulltext"]["ready"] is False
    with pytest.raises(CapacityError, match="in progress"):
        log_search.create(store, WHO, {"query": {}, "fulltext": "committedtoken"})
    store.flush()
    path = ready(store)
    assert terms(path, "committedtoken") == [("a", "committed")]


def test_missing_and_incompatible_cache_never_report_ready(store):
    assert log_search.status(store, WHO)["fulltext"]["ready"] is False
    ingest(store)
    path = ready(store)
    with closing(sqlite3.connect(path)) as db:
        db.execute("UPDATE metadata SET format_version=1")
        db.commit()
    assert log_search.status(store, WHO)["fulltext"]["ready"] is False
    with pytest.raises(ConflictError, match="version"):
        log_search.create(store, WHO, {"query": {}, "fulltext": "firsttoken"})
    path.unlink()
    assert log_search.status(store, WHO)["fulltext"]["ready"] is False


def test_truncated_acknowledged_cache_requires_bootstrap_not_empty_success(store):
    ingest(store, 3)
    path = ready(store)
    path.write_bytes(b"")
    with pytest.raises(ConflictError, match="incomplete"):
        log_search.drain(store, budget=3)
    state = log_search.status(store, WHO)["fulltext"]
    assert state["state"] == "bootstrap_required" and not state["ready"]
    log_search.rebuild(store, time.monotonic() + 10)
    assert len(terms(path, "firsttoken")) == 3


def test_budget_failure_preserves_previous_cache_and_pending_work(store, monkeypatch):
    ingest(store, 3)
    path = ready(store)
    ingest(store, 2, prefix="new", message="secondtoken")
    monkeypatch.setattr(store.settings, "fts_max_bytes", path.stat().st_size)
    with pytest.raises(CapacityError, match="disk budget"):
        log_search.drain(store, budget=3)
    assert terms(path, "secondtoken") == []
    assert terms(path, "firsttoken") == [("a", "e0"), ("a", "e1"), ("a", "e2")]
    assert log_search.status(store, WHO)["fulltext"]["state"] == "capacity_error"
    assert log_search.MAX_SNAPSHOT_BYTES == 2 * 1024**3


def test_pending_status_is_tenant_and_index_scoped(store):
    ingest(store, 2)
    ingest(store, 4, prefix="private", index="private")
    ingest(store, 7, tenant="other")
    access.set_for_user(store, WHO, "reader", ["main"])
    scoped = log_search.status(store, WHO)["fulltext"]
    assert scoped["pending_documents"] == 2
    assert scoped["pending_bytes"] > 0
    assert not scoped["ready"]


def test_purge_then_id_reuse_cannot_restore_deleted_term(store, monkeypatch):
    old = time.time() - (store.settings.retention_days + 3) * 86400
    with monkeypatch.context() as scoped:
        scoped.setattr("sapientia.storage.time.time", lambda: old)
        ingest(store, message="deletedsecret")
    path = ready(store)
    assert store.retain(time.time()) == 0
    assert capacity_purge(store,event_ids=["e0"]) == 1
    ingest(store, message="replacementtoken")
    ready(store)
    assert terms(path, "deletedsecret") == []
    assert terms(path, "replacementtoken") == [("a", "e0")]


def test_purge_only_epoch_without_deletion_does_not_force_rebuild(store):
    ingest(store)
    path = ready(store)
    with store.control(local=True) as db:
        store.segments.bump(db, purge=True, content=False)
    assert not log_search.status(store, WHO)["fulltext"]["ready"]
    ready(store)
    assert terms(path, "firsttoken") == [("a", "e0")]


def test_bounded_batch_exposes_lag_until_complete(store):
    ingest(store, 9)
    assert log_search.drain(store, budget=3, max_documents=3)["processed"] == 3
    progress = log_search.status(store, WHO)["fulltext"]
    assert progress["pending_documents"] == 6 and not progress["ready"]
    assert progress["lag_seconds"] >= 0
    assert len(terms(ready(store), "firsttoken")) == 9


def test_failed_offline_rebuild_keeps_previous_complete_cache(store, monkeypatch):
    ingest(store, 3)
    path = ready(store)
    old = path.read_bytes()
    original = log_search._check_fts_budget
    calls = 0

    def fail(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("synthetic body read failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(log_search, "_check_fts_budget", fail)
    with pytest.raises(RuntimeError, match="synthetic body"):
        log_search.rebuild(store, time.monotonic() + 10)
    assert path.read_bytes() == old
    assert not list(path.parent.glob("*.fts.pending"))


def test_legacy_existing_data_requires_explicit_offline_bootstrap(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    ingest(value, 3)
    value.close()
    with closing(sqlite3.connect(tmp_path / "control.sqlite3")) as db:
        for table in ("log_fts_state", "log_fts_journal", "log_fts_inflight"):
            db.execute("DROP TABLE " + table)
        db.commit()
    restored = Store(Settings(tmp_path, min_free_bytes=0))
    try:
        with restored.control(local=True) as db:
            assert (
                db.execute("SELECT bootstrap_required FROM log_fts_state").fetchone()[0]
                == 1
            )
        with pytest.raises(ConflictError, match="bootstrap"):
            log_search._fts(restored, time.monotonic() + 10)
        result = log_search.rebuild(restored, time.monotonic() + 10)
        assert result["current"] and result["rebuilt"] and result["documents"] == 3
        assert (
            len(terms(restored.path / "log-search" / "terms.sqlite3", "firsttoken"))
            == 3
        )
    finally:
        restored.close()


def test_committed_fts_batch_recovers_across_store_restart(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    ingest(value, 2)

    def crash():
        raise RuntimeError("synthetic crash")

    with pytest.raises(RuntimeError):
        log_search.drain(value, budget=3, after_commit=crash)
    value.close()
    reopened = Store(Settings(tmp_path, min_free_bytes=0))
    try:
        assert log_search.drain(reopened, budget=3)["processed"] == 2
        path = reopened.path / "log-search" / "terms.sqlite3"
        assert len(terms(path, "firsttoken")) == 2
        with reopened.control(local=True) as db:
            assert db.execute("SELECT count(*) FROM log_fts_journal").fetchone()[0] == 0
    finally:
        reopened.close()


@pytest.mark.parametrize("damage", ["checkpoint", "documents", "terms", "registry"])
def test_cache_checkpoint_or_schema_damage_never_reports_ready(store, damage):
    ingest(store, 3)
    path = ready(store)
    with closing(sqlite3.connect(path)) as db:
        if damage == "checkpoint":
            db.execute("UPDATE metadata SET applied_sequence=applied_sequence+1")
        elif damage == "documents":
            db.execute("UPDATE metadata SET documents=0")
        else:
            db.execute("DROP TABLE " + damage)
        db.commit()
    assert not log_search.status(store, WHO)["fulltext"]["ready"]
    with pytest.raises(ConflictError, match="rebuild"):
        log_search.drain(store, budget=3)


def test_backup_restore_missing_derived_cache_requires_bootstrap(store, tmp_path):
    from sapientia.backup import backup_online, restore

    ingest(store, 3)
    ready(store)
    snapshot, destination = tmp_path / "snapshot", tmp_path / "restored"
    backup_online(store, snapshot)
    assert not (snapshot / "log-search" / "terms.sqlite3").exists()
    restore(snapshot, destination)
    restored = Store(Settings(destination, min_free_bytes=0))
    try:
        assert restored.search("a", {})["returned"] == 3
        status = log_search.status(restored, WHO)["fulltext"]
        assert not status["ready"] and status["state"] == "bootstrap_required"
        with pytest.raises(ConflictError, match="rebuild"):
            log_search.create(restored, WHO, {"query": {}, "fulltext": "firsttoken"})
        assert (
            log_search.status(restored, WHO)["fulltext"]["state"]
            == "bootstrap_required"
        )
        log_search.rebuild(restored, time.monotonic() + 10)
        assert (
            log_search.create(restored, WHO, {"query": {}, "fulltext": "firsttoken"})[
                "rows"
            ]
            == 3
        )
    finally:
        restored.close()


def test_runtime_background_consumer_reports_and_closes_cleanly(store):
    from sapientia.runtime import Runtime

    runtime = Runtime(store)
    runtime.start()
    try:
        store.ingest(
            "a",
            [
                {"event_id": f"worker-{n}", "message": "backgroundtoken"}
                for n in range(300)
            ],
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with store.control(local=True) as db:
                queue = db.execute("SELECT count(*) FROM queue").fetchone()[0]
            if queue == 0 and log_search.status(store, WHO)["fulltext"]["ready"]:
                break
            time.sleep(0.05)
        else:
            raise AssertionError("Small synthetic fixture did not become searchable")
        assert runtime.health()["fulltext_worker_running"]
        assert runtime.health()["fulltext_error"] is None
        assert (
            len(terms(store.path / "log-search" / "terms.sqlite3", "backgroundtoken"))
            == 300
        )
    finally:
        runtime.close()
    assert not runtime.health()["fulltext_worker_running"]


def test_unacknowledged_source_commit_fence_survives_restart(tmp_path, monkeypatch):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    value.ingest("a", [{"event_id": "gap", "message": "restarttoken"}])
    with monkeypatch.context() as scoped, pytest.raises(CapacityError):
        value.flush(
            after_commit=lambda: scoped.setattr(log_search, "MAX_PENDING_DOCUMENTS", 0)
        )
    value.close()
    reopened = Store(Settings(tmp_path, min_free_bytes=0))
    try:
        with pytest.raises(CapacityError, match="in progress"):
            log_search._fts(reopened, time.monotonic() + 10)
        assert reopened.flush() == 1
        assert log_search.drain(reopened, budget=3)["processed"] == 1
        assert terms(
            reopened.path / "log-search" / "terms.sqlite3", "restarttoken"
        ) == [("a", "gap")]
    finally:
        reopened.close()
