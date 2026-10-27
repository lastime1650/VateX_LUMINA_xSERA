import hashlib
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from sapientia.connectors import parse_line
from sapientia.query import Query, QueryError
from sapientia.runtime import run_due, save_rule
from sapientia.storage import (
    CapacityError,
    ConflictError,
    Settings,
    Store,
    encode,
    normalize,
)


@pytest.fixture
def store(tmp_path):
    s = Store(Settings(tmp_path, min_free_bytes=0))
    yield s
    s.close()


def event(i="1", **kwargs):
    return {
        "event_id": str(i),
        "event_time": time.time() - 10,
        "source": "firewall",
        "host": "edge-01",
        "severity": "high",
        "message": "Connection denied",
        **kwargs,
    }


def test_health_source_total_is_not_top_thirty_limit(store):
    store.ingest("default", [event(str(i), source=f"source-{i}") for i in range(31)])
    store.flush()
    health = store.health("default")
    assert health["source_count"] == 31
    assert len(health["sources"]) == 30


def query(text="search *", **kwargs):
    return {
        "language": "spl",
        "query": text,
        "earliest": 0,
        "latest": time.time() + 100,
        **kwargs,
    }


def test_durable_visibility_and_restart(tmp_path):
    settings = Settings(tmp_path, min_free_bytes=0)
    s = Store(settings)
    s.ingest("a", [event()])
    assert s.health("a")["pending"] == 1
    assert s.search("a", query())["returned"] == 0
    s.close()
    s = Store(settings)
    assert s.flush() == 1
    assert s.search("a", query())["returned"] == 1
    s.close()
    s = Store(settings)
    assert s.health("a")["pending"] == 0
    assert s.health("a")["indexed"] == 1
    s.close()


def test_crash_after_analytics_commit_replays_once(store):
    store.ingest("a", [event()])

    def fail():
        raise RuntimeError("injected power loss")

    with pytest.raises(RuntimeError):
        store.flush(after_commit=fail)
    assert store.health("a")["pending"] == 1
    assert store.health("a")["indexed"] == 1
    store.flush()
    assert store.health("a")["pending"] == 0
    assert store.health("a")["indexed"] == 1


def test_idempotency_conflict_and_atomic_batch(store):
    e = event()
    assert store.ingest("a", [e, e])["accepted"] == 1
    assert store.ingest("a", [e])["duplicate"] == 1
    with pytest.raises(ConflictError):
        store.ingest("a", [event("2"), dict(e, message="changed")])
    assert store.health("a")["pending"] == 1
    store.flush()
    assert store.ingest("a", [e])["duplicate"] == 1


def test_missing_timestamp_retry_stable(store):
    e = {"event_id": "stable", "message": "same"}
    store.ingest("a", [e])
    assert store.ingest("a", [e])["duplicate"] == 1


def test_tenant_isolation(store):
    e = event()
    store.ingest("a", [e])
    store.ingest("b", [e, event("2")])
    store.flush()
    assert store.search("a", query())["returned"] == 1
    assert store.search("b", query())["returned"] == 2
    assert store.search("c", query())["returned"] == 0


def test_capacity_rolls_back_and_preserves_pending(store):
    store.settings.max_queue = 1
    store.ingest("a", [event()])
    with pytest.raises(CapacityError):
        store.ingest("a", [event("2")])
    assert store.health("a")["pending"] == 1
    store.flush()
    assert store.ingest("a", [event("2")])["accepted"] == 1


def test_disk_reserve_rejects_without_receipt(store):
    store.settings.min_free_bytes = 10**18
    with pytest.raises(CapacityError):
        store.ingest("a", [event()])
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 0


def test_legacy_age_policy_and_hold_do_not_override_permanent_storage(store):
    store.ingest("a", [event(event_time=1)])
    store.flush()
    assert store.retain() == 0  # old source time is not old receipt time
    with store.control() as db:
        db.execute("INSERT INTO policies VALUES('a',1,1)")
    assert store.retain(time.time() + 86400 * 100) == 0
    with store.control() as db:
        db.execute("UPDATE policies SET hold=0")
    assert store.retain(time.time() + 86400 * 100) == 0
    assert store.health("a")["indexed"] == 1
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM receipts WHERE tenant='a'").fetchone()[0] == 1


def test_retention_never_drops_pending(store):
    store.ingest("a", [event()])
    assert store.retain(time.time() + 86400 * 100) == 0
    assert store.health("a")["pending"] == 1


def test_concurrent_ingest_and_audit_chain(store):
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(lambda i: store.ingest("a", [event(i)]), range(40)))
    store.flush()
    assert store.health("a")["indexed"] == 40
    with store.control() as db:
        rows = db.execute("SELECT * FROM audit ORDER BY seq").fetchall()
    previous = "0" * 64
    for row in rows:
        assert row["previous"] == previous
        assert (
            row["digest"]
            == hashlib.sha256(
                encode(
                    [
                        row["at"],
                        row["tenant"],
                        row["actor"],
                        row["action"],
                        row["detail"],
                        previous,
                    ]
                ).encode()
            ).hexdigest()
        )
        previous = row["digest"]


def test_single_process_lock(store):
    with pytest.raises(RuntimeError, match="already in use"):
        Store(store.settings)


def test_stats_full_count_not_sample(store):
    store.ingest("a", [event(i, source="fw" if i < 7 else "edr") for i in range(10)])
    store.flush()
    data = store.search(
        "a", query("search * | stats count by source | sort -count", limit=1)
    )
    assert data["rows"] == [{"source": "fw", "count": 7}]


def test_json_equals_spl(store):
    store.ingest("a", [event(1), event(2, severity="low")])
    store.flush()
    a = store.search("a", query("search severity=high | stats count by host"))
    b = store.search(
        "a",
        query(
            {
                "filters": [{"field": "severity", "op": "eq", "value": "high"}],
                "group_by": ["host"],
            },
            language="json",
        ),
    )
    assert a["rows"] == b["rows"] == [{"host": "edge-01", "count": 1}]


def test_sql_injection_is_data(store):
    store.ingest("a", [event()])
    store.flush()
    data = {"filters": [{"field": "message", "op": "eq", "value": "' OR 1=1 --"}]}
    assert store.search("a", query(data, language="json"))["returned"] == 0
    assert store.health("a")["indexed"] == 1


def test_search_concurrency_bounded(store):
    for _ in range(store.settings.workers):
        store.query_slots.acquire()
    try:
        with pytest.raises(CapacityError):
            store.search("a", query())
    finally:
        for _ in range(store.settings.workers):
            store.query_slots.release()


@pytest.mark.parametrize(
    "text",
    [
        "search * | eval x=read_csv('private')",
        "search * | join host",
        "search host=x OR",
        "search tenant=a",
        "search * | head 0",
        "search * | head -2 | stats count",
        "search * | stats count by",
        "search tenant=*",
        "search `macro`",
        "search * | sort tenant",
        "search * | stats nonexistent(bytes)",
        "search * | table host | search high",
        "search * |",
        'search "unterminated',
    ],
)
def test_unsupported_queries_fail_closed(text):
    with pytest.raises(QueryError):
        Query.parse(query(text))


@pytest.mark.parametrize(
    "payload",
    [
        {"language": "sql", "query": "SELECT 1"},
        {"query": "*", "earliest": float("nan")},
        {"query": "*", "limit": 1001},
        {"query": "*", "tenant": "other"},
        {"language": "json", "query": {"fields": ["tenant"]}},
        {
            "language": "json",
            "query": {"filters": [{"field": "host", "op": "raw", "value": "x"}]},
        },
        {"language": "json", "query": {"fields": ["host"], "sql": "DROP TABLE events"}},
        {"language": "json", "query": {"group_by": ["host"], "sort": "message"}},
    ],
)
def test_query_validation(payload):
    with pytest.raises(QueryError):
        Query.parse(payload)


@pytest.mark.parametrize(
    "e",
    [
        None,
        [],
        {"tenant": "other"},
        {"severity": "invalid"},
        {"message": "가" * 32768},
        {"event_time": float("inf")},
        {"event_time": True},
        {"event_id": ""},
    ],
)
def test_event_validation(e):
    with pytest.raises(ValueError):
        normalize(e)


def test_scheduler_restart_and_finding_dedup(store):
    from sapientia.auth import create_user
    create_user(store, "analyst", "Testing-only-password-2026", "analyst", "a")
    store.ingest("a", [event()])
    store.flush()
    rid = save_rule(
        store,
        {"tenant": "a", "name": "analyst", "role": "analyst", "allowed_indexes": ["*"]},
        {
            "name": "High activity",
            "query": query("search severity=high"),
            "interval": 30,
            "lookback": 60,
            "threshold": 1,
        },
    )
    assert run_due(store, time.time() + 1) == 1
    assert run_due(store, time.time() + 1) == 0
    with store.control() as db:
        row = db.execute("SELECT last_end FROM rules WHERE id=?", (rid,)).fetchone()
        db.execute("UPDATE rules SET next_run=? WHERE id=?", (row[0], rid))
    run_due(store, time.time() + 1)
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM findings").fetchone()[0] == 1


def test_syslog_and_cef_adapters():
    s = parse_line(
        "<34>1 2003-10-11T22:14:15.003Z host app 123 ID - denied",
        "syslog",
        "syslog",
        "1",
    )
    assert s["host"] == "host" and s["severity"] == "high"
    c = parse_line(
        "CEF:0|Vendor|Firewall|1|42|Blocked|9|src=10.0.0.1", "cef", "cef", "2"
    )
    assert c["severity"] == "critical" and c["raw"]["vendor"] == "Vendor"
