"""Amortized probes retain actual precommit guards and source handoff fences."""

import sqlite3
from contextlib import closing
from types import SimpleNamespace

import pytest

from sapientia import log_search
from sapientia.storage import CapacityError, Settings, Store


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    yield value
    value.close()


def ingest(store, count, prefix="e", message="boundedtoken"):
    store.ingest(
        "a",
        [{"event_id": prefix + str(n), "message": message} for n in range(count)],
    )
    while store.flush():
        pass


def counts(store):
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


def test_small_document_batch_amortizes_probes_but_has_final_actual_check(
    store, monkeypatch
):
    ingest(store, 1000)
    original = log_search._check_fts_budget
    probes = []

    def probe(*args, **kwargs):
        extra = args[4] if len(args) > 4 else kwargs.get("extra", 0)
        probes.append(extra)
        return original(*args, **kwargs)

    monkeypatch.setattr(log_search, "_check_fts_budget", probe)
    assert log_search.drain(store, budget=5, max_documents=1000)["processed"] == 1000
    assert 2 <= len(probes) <= 20  # No per-document filesystem polling.
    assert probes[0] > 0 and probes[-1] == 0
    assert counts(store) == (0, 1000)
    assert hits(store, "boundedtoken") == 1000
    assert log_search.MAX_PENDING_DOCUMENTS == 100000
    assert log_search.MAX_PENDING_BYTES == 512 * 1024**2


@pytest.mark.parametrize("limit", ["disk_reserve", "database_bytes"])
def test_final_actual_budget_failure_rolls_back_whole_prefix(store, monkeypatch, limit):
    ingest(store, 3, prefix="old", message="previoustoken")
    log_search.drain(store, budget=5)
    ingest(store, 7, prefix="new", message="newtoken")
    original = log_search._check_fts_budget
    path = store.path / "log-search" / "terms.sqlite3"
    final_checked = False
    committed = False

    def probe(*args, **kwargs):
        nonlocal final_checked
        extra = args[4] if len(args) > 4 else kwargs.get("extra", 0)
        if not extra:
            final_checked = True
            if limit == "disk_reserve":
                monkeypatch.setattr(store.settings, "min_free_bytes", 100)
                monkeypatch.setattr(
                    log_search.shutil, "disk_usage", lambda _: SimpleNamespace(free=99)
                )
            else:
                # An operator may tighten the quota after the initial estimate.
                monkeypatch.setattr(
                    store.settings, "fts_max_bytes", path.stat().st_size
                )
        return original(*args, **kwargs)

    def after_commit():
        nonlocal committed
        committed = True

    monkeypatch.setattr(log_search, "_check_fts_budget", probe)
    with pytest.raises(CapacityError, match="disk reserve|disk budget"):
        log_search.drain(store, budget=5, after_commit=after_commit)
    assert final_checked and not committed
    assert counts(store) == (7, 3)
    assert hits(store, "previoustoken") == 3 and hits(store, "newtoken") == 0


def test_large_documents_get_byte_bounded_probes(store, monkeypatch):
    store.ingest(
        "a",
        [
            {
                "event_id": f"large-{n}",
                "message": "largetoken",
                "raw": {"body": "A" * 48000},
            }
            for n in range(40)
        ],
    )
    store.flush()
    original = log_search._check_fts_budget
    probes = []

    def probe(*args, **kwargs):
        extra = args[4] if len(args) > 4 else kwargs.get("extra", 0)
        probes.append(extra)
        return original(*args, **kwargs)

    monkeypatch.setattr(log_search, "_check_fts_budget", probe)
    assert log_search.drain(store, budget=10)["processed"] == 40
    assert len([value for value in probes if value]) >= 2
    assert probes[-1] == 0 and hits(store, "largetoken") == 40


@pytest.mark.parametrize("limit", ["count", "bytes", "reserve"])
def test_full_journal_preflight_defers_source_commit_and_retries_after_drain(
    store, monkeypatch, limit
):
    ingest(store, 1, prefix="old")
    store.ingest("a", [{"event_id": "next", "message": "nexttoken"}])
    committed = False

    def after_commit():
        nonlocal committed
        committed = True

    class NoSourceWork:
        def cursor(self):
            # Retention currently opens an idle cursor even with no intents.
            # The deferral must happen before any analytical SQL executes.
            return self

        def execute(self, *_args, **_kwargs):
            raise AssertionError("Backpressured batch must not execute DuckDB work")

        def close(self):
            pass

    with monkeypatch.context() as scoped:
        scoped.setattr(store, "analytics", NoSourceWork())
        if limit == "count":
            scoped.setattr(log_search, "MAX_PENDING_DOCUMENTS", 1)
        elif limit == "bytes":
            scoped.setattr(log_search, "MAX_PENDING_BYTES", 0)
        else:
            scoped.setattr(store.settings, "min_free_bytes", 1)
            scoped.setattr(
                log_search.shutil, "disk_usage", lambda _: SimpleNamespace(free=0)
            )
        with pytest.raises(CapacityError, match="journal full|disk reserve"):
            store.flush(after_commit=after_commit)
    assert not committed
    assert store.search("a", {})["returned"] == 1
    with store.control(local=True) as db:
        assert db.execute("SELECT count(*) FROM queue").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM log_fts_inflight").fetchone()[0] == 0
    log_search.drain(store, budget=5)
    assert store.flush() == 1
    log_search.drain(store, budget=5)
    assert counts(store) == (0, 2) and hits(store, "nexttoken") == 1


def test_preflight_full_count_short_circuits_payload_and_filesystem(store, monkeypatch):
    class UnreadablePayload:
        def __getitem__(self, key):
            raise AssertionError("Full-count preflight must not parse payload")

    def no_disk_probe(_):
        raise AssertionError("Full-count preflight must not probe filesystem")

    monkeypatch.setattr(log_search, "MAX_PENDING_DOCUMENTS", 0)
    monkeypatch.setattr(log_search.shutil, "disk_usage", no_disk_probe)
    with store.control(local=True) as db:
        with pytest.raises(CapacityError, match="journal full"):
            log_search.journal_preflight(store, db, [UnreadablePayload()])
        assert db.execute("SELECT count(*) FROM log_fts_inflight").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM log_fts_journal").fetchone()[0] == 0
