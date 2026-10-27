"""Ordered source prefixes retain capacity, immutable replay and FTS handoff."""

import json
import sqlite3
import time
from contextlib import closing, contextmanager

import pytest

from sapientia import log_search
from sapientia.storage import CapacityError, ConflictError, Settings, Store, encode


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    yield value
    value.close()


def queued(store):
    with store.control(local=True) as db:
        return [dict(row) for row in db.execute("SELECT * FROM queue ORDER BY seq")]


def state(store):
    with store.control(local=True) as db:
        result = dict(db.execute("SELECT * FROM log_fts_state").fetchone())
        result["inflight"] = db.execute(
            "SELECT count(*) FROM log_fts_inflight"
        ).fetchone()[0]
        return result


def replay(store, row, *, payload=None, received=None):
    with store.control(local=True) as db:
        db.execute(
            "INSERT INTO queue(tenant,event_id,payload,received) VALUES(?,?,?,?)",
            (
                row["tenant"],
                row["event_id"],
                row["payload"] if payload is None else payload,
                row["received"] if received is None else received,
            ),
        )


def assert_exact_population(store, expected):
    with closing(store.analytics.cursor()) as db:
        assert db.execute(
            "SELECT tenant,event_id FROM events_all ORDER BY tenant,event_id"
        ).fetchall() == sorted(expected)
    with closing(sqlite3.connect(store.path / "log-search" / "terms.sqlite3")) as db:
        assert db.execute(
            "SELECT tenant,event_id FROM registry ORDER BY tenant,event_id"
        ).fetchall() == sorted(expected)
        assert db.execute("SELECT count(*) FROM terms").fetchone()[0] == len(expected)
    assert state(store)["indexed_documents"] == len(expected)
    assert state(store)["pending_documents"] == state(store)["inflight"] == 0


def test_remaining_document_slots_flush_only_ordered_prefix(store, monkeypatch):
    store.ingest("old", [{"event_id": f"old-{n}"} for n in range(2)])
    assert store.flush() == 2
    expected = [("old", f"old-{n}") for n in range(2)]
    for number in range(5):
        tenant = "a" if number % 2 else "b"
        store.ingest(tenant, [{"event_id": str(number), "index": "endpoint"}])
        expected.append((tenant, str(number)))
    before = queued(store)
    monkeypatch.setattr(log_search, "MAX_PENDING_DOCUMENTS", 4)

    assert store.flush(batch=5000) == 2
    assert queued(store) == before[2:]
    assert state(store)["pending_documents"] == 4
    assert state(store)["inflight"] == 0
    with store.control(local=True) as db:
        assert [
            row[0]
            for row in db.execute("SELECT event_id FROM log_fts_journal ORDER BY seq")
        ] == ["old-0", "old-1", "0", "1"]

    # A single released slot must immediately make one more source ACK possible.
    assert log_search.drain(store, budget=5, max_documents=1)["processed"] == 1
    assert store.flush(batch=5000) == 1
    assert queued(store) == before[3:]
    while queued(store):
        log_search.drain(store, budget=5, max_documents=1)
        assert store.flush(batch=5000) >= 1
    log_search.drain(store, budget=5)
    assert_exact_population(store, expected)


def test_remaining_byte_budget_selects_exact_utf8_prefix(store, monkeypatch):
    store.ingest("a", [{"event_id": "old"}])
    store.flush()
    store.ingest(
        "a",
        [
            {"event_id": "first", "message": "한글🙂" * 10},
            {"event_id": "second", "raw": {"nested": "Ω" * 40}},
            {"event_id": "large", "raw": {"body": "界" * 4000}},
        ],
    )
    before = queued(store)
    weights = [len(row["payload"].encode()) + 256 for row in before]
    limit = state(store)["pending_bytes"] + sum(weights[:2])
    monkeypatch.setattr(log_search, "MAX_PENDING_BYTES", limit)
    assert store.flush(batch=5000) == 2
    assert queued(store) == before[2:]
    assert state(store)["pending_documents"] == 3
    assert state(store)["pending_bytes"] <= limit
    assert state(store)["inflight"] == 0


@pytest.mark.parametrize("limit", ["count", "bytes"])
def test_first_unfittable_row_is_not_skipped_or_marked(store, monkeypatch, limit):
    store.ingest(
        "a",
        [
            {"event_id": "large-first", "raw": {"body": "界" * 4000}},
            {"event_id": "small-later"},
        ],
    )
    before = queued(store)

    class NoSourceSQL:
        def cursor(self):
            return self

        def execute(self, *_args, **_kwargs):
            raise AssertionError("A zero-capacity prefix must not execute source SQL")

        def close(self):
            pass

    with monkeypatch.context() as scoped:
        scoped.setattr(store, "analytics", NoSourceSQL())
        if limit == "count":
            scoped.setattr(log_search, "MAX_PENDING_DOCUMENTS", 0)
        else:
            scoped.setattr(
                log_search,
                "MAX_PENDING_BYTES",
                len(before[1]["payload"].encode()) + 256,
            )
        with pytest.raises(CapacityError, match="journal full"):
            store.flush(batch=5000)
    assert queued(store) == before
    assert state(store)["inflight"] == state(store)["pending_documents"] == 0


def test_leading_sealed_replay_stops_at_blocked_new_row(store, monkeypatch):
    store.ingest("a", [{"event_id": "sealed-first"}, {"event_id": "sealed-later"}])
    originals = queued(store)
    store.flush()
    store.segments.seal(now=time.time() + 2 * 86400)
    replay(store, originals[0])
    store.ingest("b", [{"event_id": "new-middle"}])
    replay(store, originals[1])
    before = queued(store)
    monkeypatch.setattr(log_search, "MAX_PENDING_DOCUMENTS", 2)

    assert store.flush(batch=5000) == 1
    assert queued(store) == before[1:]
    assert state(store)["pending_documents"] == 2
    assert state(store)["inflight"] == 0
    log_search.drain(store, budget=5)
    assert store.flush(batch=5000) == 2
    log_search.drain(store, budget=5)
    assert_exact_population(
        store, [("a", "sealed-first"), ("a", "sealed-later"), ("b", "new-middle")]
    )


def test_other_tenant_same_id_still_consumes_capacity(store, monkeypatch):
    store.ingest("a", [{"event_id": "same-id"}])
    store.flush()
    store.segments.seal(now=time.time() + 2 * 86400)
    store.ingest("b", [{"event_id": "same-id"}])
    before = queued(store)
    monkeypatch.setattr(log_search, "MAX_PENDING_DOCUMENTS", 1)
    with pytest.raises(CapacityError, match="journal full"):
        store.flush()
    assert queued(store) == before
    assert state(store)["inflight"] == 0
    log_search.drain(store, budget=5)
    assert store.flush() == 1
    log_search.drain(store, budget=5)
    assert_exact_population(store, [("a", "same-id"), ("b", "same-id")])


@pytest.mark.parametrize("change", ["body", "received"])
def test_selected_sealed_replay_immutable_collision_remains_fenced(store, change):
    store.ingest("a", [{"event_id": "sealed", "message": "original"}])
    original = queued(store)[0]
    store.flush()
    store.segments.seal(now=time.time() + 2 * 86400)
    payload = None
    received = None
    if change == "body":
        event = json.loads(original["payload"])
        event["message"] = "conflicting"
        payload = encode(event)
    else:
        received = original["received"] + 1
    replay(store, original, payload=payload, received=received)
    before = queued(store)
    with pytest.raises(ConflictError, match="retained original"):
        store.flush()
    assert queued(store) == before
    assert state(store)["inflight"] == state(store)["pending_documents"] == 1
    assert store.search("a", {})["rows"][0]["message"] == "original"


def test_queue_payload_identity_mismatch_cannot_bypass_sealed_journal(
    store, monkeypatch
):
    store.ingest("a", [{"event_id": "sealed-original", "message": "originaltoken"}])
    original = queued(store)[0]
    store.flush()
    log_search.drain(store, budget=5)
    store.segments.seal(now=time.time() + 2 * 86400)
    event = json.loads(original["payload"])
    event["event_id"] = "forged-untracked"
    replay(store, original, payload=encode(event))
    before = queued(store)
    monkeypatch.setattr(log_search, "MAX_PENDING_DOCUMENTS", 0)
    with pytest.raises(ConflictError, match="identity mismatch"):
        store.flush()
    assert queued(store) == before
    assert_exact_population(store, [("a", "sealed-original")])


def test_preflight_after_prefix_selection_is_still_authoritative(store, monkeypatch):
    store.ingest("a", [{"event_id": str(n)} for n in range(3)])
    before = queued(store)
    original = log_search.journal_prefix

    def capacity_race(*args, **kwargs):
        result = original(*args, **kwargs)
        monkeypatch.setattr(log_search, "MAX_PENDING_DOCUMENTS", 0)
        return result

    monkeypatch.setattr(log_search, "journal_prefix", capacity_race)
    with pytest.raises(CapacityError, match="journal full"):
        store.flush(batch=5000)
    assert queued(store) == before
    assert store.search("a", {})["returned"] == 0
    assert state(store)["pending_documents"] == state(store)["inflight"] == 0


def test_prior_handoff_lookup_is_one_batched_primary_key_probe(store, monkeypatch):
    store.ingest("a", [{"event_id": str(n)} for n in range(5)])
    before = queued(store)
    selected_sequences = [row["seq"] for row in before[:3]]
    sql = "SELECT seq FROM log_fts_inflight WHERE seq IN (SELECT CAST(value AS INTEGER) FROM json_each(?))"
    with store.control(local=True) as db:
        plan = [
            row[3]
            for row in db.execute(
                "EXPLAIN QUERY PLAN " + sql, (encode(selected_sequences),)
            )
        ]
    assert any(
        "SEARCH log_fts_inflight USING INTEGER PRIMARY KEY" in step for step in plan
    )
    assert not any("SCAN log_fts_inflight" in step for step in plan)
    original = store.control
    statements = []

    @contextmanager
    def traced(local=False):
        with original(local=local) as db:
            db.set_trace_callback(statements.append)
            yield db

    monkeypatch.setattr(store, "control", traced)
    assert store.flush(batch=3) == 3
    probes = [
        statement
        for statement in statements
        if statement.startswith("SELECT seq FROM log_fts_inflight WHERE seq IN")
    ]
    assert len(probes) == 1
    assert "'" + encode(selected_sequences) + "'" in probes[0]
    assert queued(store) == before[3:]


def test_postcommit_failure_restarts_with_smaller_prefix_exactly_once(
    tmp_path, monkeypatch
):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    try:
        value.ingest("a", [{"event_id": "old"}])
        value.flush()
        value.ingest("a", [{"event_id": str(n)} for n in range(4)])
        before = queued(value)
        monkeypatch.setattr(log_search, "MAX_PENDING_DOCUMENTS", 3)

        def capacity_race():
            monkeypatch.setattr(log_search, "MAX_PENDING_DOCUMENTS", 0)

        with pytest.raises(CapacityError, match="journal full"):
            value.flush(batch=5000, after_commit=capacity_race)
        assert queued(value) == before
        assert value.search("a", {})["returned"] == 3
        assert state(value)["inflight"] == 2
        assert state(value)["pending_documents"] == 1
    finally:
        value.close()

    monkeypatch.setattr(log_search, "MAX_PENDING_DOCUMENTS", 2)
    restored = Store(Settings(tmp_path, min_free_bytes=0))
    try:
        assert restored.flush(batch=5000) == 1
        assert queued(restored) == before[1:]
        assert state(restored)["inflight"] == 1
        assert state(restored)["pending_documents"] == 2
        while queued(restored):
            log_search.drain(restored, budget=5, max_documents=1)
            assert restored.flush(batch=5000) >= 1
        log_search.drain(restored, budget=5)
        assert_exact_population(
            restored, [("a", "old"), *(("a", str(n)) for n in range(4))]
        )
    finally:
        restored.close()


@pytest.mark.parametrize("seal", [False, True])
def test_offline_rebuild_then_queued_commit_replay_is_idempotent(store, seal):
    store.ingest("a", [{"event_id": "rebuilt", "message": "rebuilttoken"}])

    def crash():
        raise RuntimeError("synthetic source commit before handoff")

    with pytest.raises(RuntimeError, match="before handoff"):
        store.flush(after_commit=crash)
    assert state(store)["inflight"] == 1
    result = log_search.rebuild(store, time.monotonic() + 10)
    assert result["documents"] == 1 and result["current"]
    assert queued(store) and state(store)["inflight"] == 0
    if seal:
        store.segments.seal(now=time.time() + 2 * 86400)
    assert store.flush() == 1
    log_search.drain(store, budget=5)
    assert_exact_population(store, [("a", "rebuilt")])


def test_source_commit_then_seal_still_recovers_fulltext_handoff(store):
    store.ingest("a", [{"event_id": "committed", "message": "recoverytoken"}])

    def crash():
        raise RuntimeError("synthetic source commit before handoff")

    with pytest.raises(RuntimeError, match="before handoff"):
        store.flush(after_commit=crash)
    assert store.segments.seal(now=time.time() + 2 * 86400)["sealed_events"] == 1
    assert store.flush() == 1
    log_search.drain(store, budget=5)
    with closing(sqlite3.connect(store.path / "log-search" / "terms.sqlite3")) as db:
        assert (
            db.execute(
                "SELECT count(*) FROM terms WHERE terms MATCH 'recoverytoken'"
            ).fetchone()[0]
            == 1
        )
        assert db.execute("SELECT count(*) FROM registry").fetchone()[0] == 1
    with store.control(local=True) as db:
        assert db.execute("SELECT count(*) FROM queue").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM log_fts_inflight").fetchone()[0] == 0
        assert db.execute(
            "SELECT pending_documents,indexed_documents FROM log_fts_state"
        ).fetchone()[:] == (0, 1)
