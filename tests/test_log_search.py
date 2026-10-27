import hashlib
import time

import pytest

from sapientia import auth, log_search
from sapientia.storage import ConflictError, Settings, Store


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0, query_timeout=30))
    auth.create_user(value, "reader", "Testing-only-password-2026", "analyst", "a")
    auth.create_user(value, "other", "Testing-only-password-2026", "analyst", "a")
    yield value
    value.close()


WHO = {"name": "reader", "tenant": "a", "role": "analyst"}


def ingest(store, count, tenant="a", prefix="e", message="ordinary event"):
    for offset in range(0, count, 1000):
        store.ingest(
            tenant,
            [
                {"event_id": prefix + str(n), "message": message, "raw": {"n": n}}
                for n in range(offset, min(count, offset + 1000))
            ],
        )
    while store.flush():
        pass


def test_complete_snapshot_pages_over_1000_stable_across_new_ingest(store):
    ingest(store, 2117)
    result = log_search.create(store, WHO, {"query": {}})
    assert result["rows"] == 2117 and result["truncated"] is False
    ingest(store, 12, prefix="new")
    rows, cursor, payload = [], 0, b""
    while True:
        page, text = log_search.ndjson(store, WHO, result["id"], cursor, 173)
        rows.extend(page["rows"])
        payload += text.encode()
        if page["next_after"] is None:
            break
        cursor = page["next_after"]
    assert len(rows) == len({r["event_id"] for r in rows}) == 2117
    assert not any(r["event_id"].startswith("new") for r in rows)
    assert hashlib.sha256(payload).hexdigest() == result["sha256_ndjson"]
    assert log_search.close(store, WHO, result["id"])["closed"]
    with pytest.raises(KeyError):
        log_search.page(store, WHO, result["id"])


def test_indexed_phrase_search_is_tenant_scoped_and_refreshes(store):
    ingest(store, 3, message="PowerShell credential access")
    ingest(store, 4, tenant="b", message="PowerShell credential access")
    first = log_search.create(
        store, WHO, {"query": {}, "fulltext": '"credential access"'}
    )
    assert first["rows"] == 3
    ingest(store, 2, prefix="new", message="PowerShell credential access")
    assert (
        log_search.create(
            store, WHO, {"query": {}, "fulltext": "PowerShell AND credential"}
        )["rows"]
        == 5
    )
    assert (
        log_search.create(store, WHO, {"query": {}, "fulltext": "nonexistent"})["rows"]
        == 0
    )
    with pytest.raises(ValueError):
        log_search.create(store, WHO, {"query": {}, "fulltext": '"unterminated'})


def test_cursor_owner_tenant_and_current_permissions(store):
    ingest(store, 3)
    result = log_search.create(store, WHO, {"query": {}})
    for other in ({**WHO, "name": "other"}, {**WHO, "tenant": "b"}):
        with pytest.raises((KeyError, PermissionError)):
            log_search.page(store, other, result["id"])
    with store.control() as db:
        db.execute(
            "INSERT OR REPLACE INTO user_index_access VALUES(?,?,?)",
            ("a", "reader", '["main"]'),
        )
    with pytest.raises(PermissionError):
        log_search.page(store, WHO, result["id"])


def test_snapshot_expiry_and_no_arbitrary_sql(store):
    ingest(store, 1)
    result = log_search.create(store, WHO, {"query": {}})
    with store.control(local=True) as db:
        db.execute(
            "UPDATE log_snapshots SET expires=? WHERE id=?",
            (time.time() - 1, result["id"]),
        )
    with pytest.raises(ConflictError):
        log_search.page(store, WHO, result["id"])
    assert log_search.maintenance(store)["expired"] == 1
    assert not (store.path / "log-search" / (result["id"] + ".sqlite3")).exists()
    for payload in (
        {"query": {"language": "sql", "query": "DROP TABLE events"}},
        {"sql": "select * from events"},
        {"query": {"query": {"group_by": []}}},
    ):
        with pytest.raises(ValueError):
            log_search.create(store, WHO, payload)


def test_structured_filters_are_applied_with_fulltext(store):
    ingest(store, 30, message="alpha beta")
    result = log_search.create(
        store,
        WHO,
        {
            "query": {
                "query": {"filters": [{"field": "raw.n", "op": "gte", "value": 20}]}
            },
            "fulltext": "alpha",
        },
    )
    assert result["rows"] == 10
    assert all(
        row["raw"]["n"] >= 20
        for row in log_search.page(store, WHO, result["id"])["rows"]
    )


def test_pending_retention_fences_legacy_cached_copies(store):
    ingest(store, 1)
    result = log_search.create(store, WHO, {"query": {}, "fulltext": "ordinary"})
    with store.control(local=True) as db:
        db.execute(
            "INSERT INTO retention_intents VALUES(?,?,?,?,?)",
            ("crash", "a", time.time() + 1, '["e0"]', time.time()),
        )
    with pytest.raises(ConflictError, match="pending"):
        log_search.page(store, WHO, result["id"])
    with pytest.raises(ConflictError, match="pending"):
        log_search.create(store, WHO, {"query": {}, "fulltext": "ordinary"})
    # Retention fences reads while the durable tombstone journal catches up;
    # the cache remains private and is not rebuilt from stale source bodies.
    assert (store.path / "log-search" / "terms.sqlite3").exists()


def test_storage_wait_obeys_explicit_deadline(store):
    import threading

    from sapientia.storage import CapacityError

    entered, release = threading.Event(), threading.Event()

    def hold():
        with store.flush_lock:
            entered.set()
            release.wait(3)

    thread = threading.Thread(target=hold)
    thread.start()
    assert entered.wait(2)
    started = time.monotonic()
    try:
        with pytest.raises(CapacityError, match="deadline"):
            log_search.maintenance(store, deadline=time.monotonic() + 0.05)
        assert time.monotonic() - started < 1
    finally:
        release.set()
        thread.join(3)


def test_complete_export_rejects_segment_integrity_damage(store):
    ingest(store, 3)
    store.segments.seal(now=time.time() + 2 * 86400)
    segment = next((store.path / "log-segments").rglob("*.parquet"))
    with segment.open("r+b") as file:
        file.seek(24)
        original = file.read(1)
        file.seek(24)
        file.write(bytes([original[0] ^ 1]))
    with pytest.raises(RuntimeError, match="integrity|checksum|SHA|Segment"):
        log_search.create(store, WHO, {"query": {}, "fulltext": "ordinary"})
