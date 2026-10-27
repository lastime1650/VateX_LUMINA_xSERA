"""Native snapshot serialization preserves values and exports frozen bytes."""

import hashlib
import math
import sqlite3
from contextlib import closing

import pytest

from sapientia import access, auth, log_search, principal
from sapientia.query import FIELDS
from sapientia.storage import CapacityError, ConflictError, Settings, Store, encode

WHO = {"name": "reader", "tenant": "a", "role": "analyst"}
ADMIN = {"name": "admin", "tenant": "a", "role": "admin"}


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0, query_timeout=15))
    auth.create_user(value, "reader", "Testing-only-password-2026", "analyst", "a")
    auth.create_user(value, "other", "Testing-only-password-2026", "analyst", "a")
    auth.create_user(value, "admin", "Testing-only-password-2026", "admin", "a")
    yield value
    value.close()


def assert_typed_equal(actual, expected):
    assert type(actual) is type(expected)
    if isinstance(expected, dict):
        assert set(actual) == set(expected)
        for key, item in expected.items():
            assert_typed_equal(actual[key], item)
    elif isinstance(expected, list):
        assert len(actual) == len(expected)
        for left, right in zip(actual, expected):
            assert_typed_equal(left, right)
    elif isinstance(expected, float):
        assert actual.hex() == expected.hex()
    else:
        assert actual == expected


def stored_bytes(store, identifier):
    path = store.path / "log-search" / (identifier + ".sqlite3")
    with closing(sqlite3.connect(path)) as db:
        return b"".join(
            (row[0] + "\n").encode()
            for row in db.execute("SELECT payload FROM rows ORDER BY position")
        )


@pytest.mark.parametrize("stamp", [0.0, -0.0, 1e-6, 1e-7, 1e6])
def test_native_nested_values_and_frozen_export_bytes(store, stamp):
    raw = {
        "integers": [2**53 + 1, 2**64, 2**127 + 1, 2**128 + 1, 10**200, -(2**128 + 1)],
        "floats": [0.0, -0.0, 1e-6, 1e-7, 1e20, 1e100],
        "text": '한글😀\n\t\r\b\f\\"\u0000',
        "nested": {"z": [True, False, None, {"a": "é"}], "a": []},
    }
    store.ingest(
        "a",
        [
            {
                "event_id": "fidelity",
                "event_time": stamp,
                "message": raw["text"],
                "raw": raw,
            }
        ],
    )
    store.flush()
    result = log_search.create(store, WHO, {"query": {}})
    page = log_search.page(store, WHO, result["id"])
    assert result["rows"] == page["total"] == page["returned"] == 1
    item = page["rows"][0]
    assert set(item) == FIELDS
    assert_typed_equal(item["raw"], raw)
    assert_typed_equal(item["event_time"], stamp)
    assert math.isfinite(item["received"]) and type(item["received"]) is float
    assert item["message"] == raw["text"] and item["index_name"] == "main"
    raw_bytes = stored_bytes(store, result["id"])
    exported, text = log_search.ndjson(store, WHO, result["id"])
    info = log_search.download_info(store, WHO, result["id"])
    assert text.encode() == raw_bytes
    assert (
        hashlib.sha256(raw_bytes).hexdigest()
        == result["sha256_ndjson"]
        == exported["sha256_ndjson"]
        == info["sha256"]
    )
    assert info["bytes"] == len(raw_bytes)
    # Native float spelling differs from Python; re-encoding a page is unsafe.
    assert raw_bytes != (encode(item) + "\n").encode()


def test_native_selection_order_scope_owner_and_revocation(store):
    store.ingest(
        "a",
        [
            {"event_id": "z"},
            {"event_id": "a"},
            {"event_id": "private", "index": "private"},
        ],
    )
    store.ingest("b", [{"event_id": "foreign"}])
    store.flush()
    access.set_for_user(store, ADMIN, "reader", ["main"])
    result = log_search.create(store, WHO, {"query": {}})
    page = log_search.page(store, WHO, result["id"])
    assert [row["event_id"] for row in page["rows"]] == ["a", "z"]
    with pytest.raises(KeyError):
        log_search.page(store, {**WHO, "name": "other"}, result["id"])
    access.set_for_user(store, ADMIN, "reader", [])
    with pytest.raises(PermissionError):
        log_search.ndjson(store, WHO, result["id"])


def test_legacy_python_encoded_spool_remains_exact_after_restart(store):
    store.ingest(
        "a",
        [
            {
                "event_id": "legacy",
                "event_time": 1e-6,
                "raw": {"tiny": 1e-7, "huge": 2**128 + 1},
            }
        ],
    )
    store.flush()
    result = log_search.create(store, WHO, {"query": {}})
    item = log_search.page(store, WHO, result["id"])["rows"][0]
    legacy_payload = encode(item)
    legacy_bytes = (legacy_payload + "\n").encode()
    with closing(
        sqlite3.connect(store.path / "log-search" / (result["id"] + ".sqlite3"))
    ) as db:
        db.execute("UPDATE rows SET payload=?", (legacy_payload,))
        db.commit()
    with store.control(local=True) as db:
        db.execute(
            "UPDATE log_snapshots SET digest=?,ndjson_bytes=NULL WHERE id=?",
            (hashlib.sha256(legacy_bytes).hexdigest(), result["id"]),
        )
    settings = store.settings
    store.close()
    reopened = Store(settings)
    try:
        assert (
            log_search.ndjson(reopened, WHO, result["id"])[1].encode() == legacy_bytes
        )
        assert log_search.download_info(reopened, WHO, result["id"])["bytes"] == len(
            legacy_bytes
        )
        assert_typed_equal(
            log_search.page(reopened, WHO, result["id"])["rows"][0], item
        )
    finally:
        reopened.close()


def test_native_create_avoids_python_event_decode_and_encode(store, monkeypatch):
    store.ingest("a", [{"event_id": "native", "raw": {"tiny": 1e-7}}])
    store.flush()
    original = log_search.encode

    def no_event_encode(value):
        if isinstance(value, dict) and set(value) == FIELDS:
            raise AssertionError("Snapshot rows must be serialized natively")
        return original(value)

    monkeypatch.setattr(log_search, "encode", no_event_encode)
    result = log_search.create(store, WHO, {"query": {}})
    assert result["rows"] == 1
    assert log_search.ndjson(store, WHO, result["id"])[1].encode() == stored_bytes(
        store, result["id"]
    )


def test_page_byte_budget_and_snapshot_payload_cap_remain(store, monkeypatch):
    store.ingest(
        "a", [{"event_id": str(n), "message": "X" * 32000} for n in range(100)]
    )
    store.flush()
    result = log_search.create(store, WHO, {"query": {}})
    first, text = log_search.ndjson(store, WHO, result["id"], limit=5000)
    assert 1 < first["returned"] < 100 and first["next_after"] is not None
    assert (
        len(text.encode()) <= 2 * 1024**2 + 5000
    )  # Existing payload bound plus line feeds.
    monkeypatch.setattr(log_search, "MAX_SNAPSHOT_BYTES", 1000)
    with pytest.raises(CapacityError, match="disk budget"):
        log_search.create(store, WHO, {"query": {}})
    assert not list((store.path / "log-search").glob("*.pending"))
    with store.control(local=True) as db:
        assert db.execute("SELECT count(*) FROM log_snapshots").fetchone()[0] == 1


@pytest.mark.parametrize("change", ["scope", "purge"])
def test_native_snapshot_publication_rechecks_scope_and_purge(
    store, monkeypatch, change
):
    store.ingest("a", [{"event_id": "guard"}])
    store.flush()
    original = principal.recheck

    def changed(value, actor, *args, **kwargs):
        if change == "scope":
            access.set_for_user(value, ADMIN, "reader", [])
        else:
            value.segments.bump(purge=True, content=False)
        return original(value, actor, *args, **kwargs)

    monkeypatch.setattr(principal, "recheck", changed)
    with pytest.raises((PermissionError, ConflictError)):
        log_search.create(store, WHO, {"query": {}})
    assert not list((store.path / "log-search").glob("*.pending"))
    assert not list((store.path / "log-search").glob("*.sqlite3"))
    with store.control(local=True) as db:
        assert db.execute("SELECT count(*) FROM log_snapshots").fetchone()[0] == 0
