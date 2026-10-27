"""Available handoff capacity advances only a fitting ordered source prefix."""

import sqlite3
from contextlib import closing

import pytest

from sapientia import log_search
from sapientia.storage import CapacityError, ConflictError


@pytest.fixture
def db():
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.execute(
            "CREATE TABLE log_fts_state(singleton INTEGER PRIMARY KEY,"
            "pending_documents INTEGER,pending_bytes INTEGER)"
        )
        connection.execute("INSERT INTO log_fts_state VALUES(1,0,0)")
        yield connection


def rows(count, payload="{}"):
    return [
        {"tenant": "a", "event_id": f"e{n}", "payload": payload} for n in range(count)
    ]


def set_pending(db, documents=0, weight=0):
    db.execute(
        "UPDATE log_fts_state SET pending_documents=?,pending_bytes=?",
        (documents, weight),
    )


def test_realistic_partial_slots_preserve_hard_document_cap(db):
    set_pending(db, 95262, 123775627)
    before = db.total_changes
    assert log_search.journal_prefix(None, db, rows(5000)) == 4738
    assert db.total_changes == before  # Capacity selection is read-only.
    set_pending(db, 99999)
    assert log_search.journal_prefix(None, db, rows(5000)) == 1


def test_byte_limit_uses_encoded_payload_and_stops_without_skipping(db):
    values = rows(3, "한글")
    unit = len("한글".encode()) + 256
    set_pending(db, weight=log_search.MAX_PENDING_BYTES - unit * 2)
    assert log_search.journal_prefix(None, db, values) == 2
    set_pending(db, weight=log_search.MAX_PENDING_BYTES - unit + 1)
    with pytest.raises(CapacityError, match="journal full"):
        log_search.journal_prefix(None, db, values)


def test_sealed_replays_are_free_but_cannot_pass_a_blocked_new_row(db):
    set_pending(db, log_search.MAX_PENDING_DOCUMENTS, log_search.MAX_PENDING_BYTES)
    values = rows(3)
    assert (
        log_search.journal_prefix(
            None, db, values, sealed_keys={("a", "e0"), ("a", "e2")}
        )
        == 1
    )
    with pytest.raises(CapacityError, match="journal full"):
        log_search.journal_prefix(None, db, values, sealed_keys={("a", "e2")})
    assert (
        log_search.journal_prefix(
            None, db, values, sealed_keys={("a", f"e{n}") for n in range(3)}
        )
        == 3
    )


def test_sealed_identity_is_tenant_bound(db):
    set_pending(db, log_search.MAX_PENDING_DOCUMENTS)
    with pytest.raises(CapacityError):
        log_search.journal_prefix(None, db, rows(1), sealed_keys={("b", "e0")})


def test_selection_does_not_bypass_later_authoritative_preflight(db):
    values = rows(2)
    assert log_search.journal_prefix(None, db, values) == 2
    set_pending(db, log_search.MAX_PENDING_DOCUMENTS)
    with pytest.raises(CapacityError, match="journal full"):
        log_search.journal_preflight(None, db, values)


def test_empty_and_invalid_state(db):
    assert log_search.journal_prefix(None, db, []) == 0
    set_pending(db, -1)
    with pytest.raises(ConflictError, match="counters"):
        log_search.journal_prefix(None, db, rows(1))
    db.execute("DELETE FROM log_fts_state")
    with pytest.raises(ConflictError, match="initialization"):
        log_search.journal_prefix(None, db, rows(1))
