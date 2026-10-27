import copy
import time

import pytest

from sapientia import lookups
from sapientia.query import Query, QueryError
from sapientia.storage import ConflictError, Settings, Store

ADMIN = {"name": "admin", "tenant": "a", "role": "admin"}


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    lookups.initialize(value)
    yield value
    value.close()


def search(store, text, allowed_indexes=None):
    payload = {"query": text, "earliest": 0, "latest": 2000000000, "limit": 1000}
    tables = lookups.for_query(store, "a", payload)
    q = Query.parse(payload)
    sql, args = q.compile("a", allowed_indexes=allowed_indexes, lookup_tables=tables)
    con = store.analytics.cursor()
    try:
        con.execute(sql, args)
        columns = [c[0] for c in con.description]
        return [dict(zip(columns, row)) for row in con.fetchall()]
    finally:
        con.close()


@pytest.fixture
def inventory(store):
    lookups.save(
        store,
        ADMIN,
        "assets",
        {
            "key": "ip",
            "rows": [
                {"ip": "10.0.0.1", "owner": "SOC", "risk": 80},
                {"ip": "10.0.0.2", "owner": "Finance", "risk": 50},
            ],
        },
    )
    store.ingest(
        "a",
        [
            {
                "event_id": "1",
                "event_time": 100,
                "index": "public",
                "raw": {"ip": "10.0.0.1", "owner": "Original"},
            },
            {
                "event_id": "2",
                "event_time": 101,
                "index": "restricted",
                "raw": {"ip": "10.0.0.2"},
            },
            {
                "event_id": "3",
                "event_time": 102,
                "index": "public",
                "raw": {"ip": "unknown", "owner": "Keep"},
            },
        ],
    )
    store.ingest(
        "b", [{"event_id": "hidden", "event_time": 100, "raw": {"ip": "10.0.0.1"}}]
    )
    store.flush()
    return store


def test_lookup_matches_exactly_without_fanout_and_preserves_unmatched(inventory):
    assert search(
        inventory,
        "* | lookup assets ip OUTPUT owner,risk | sort event_id | table event_id,owner,risk",
    ) == [
        {"event_id": "1", "owner": "SOC", "risk": "80"},
        {"event_id": "2", "owner": "Finance", "risk": "50"},
        {"event_id": "3", "owner": "Keep", "risk": None},
    ]
    assert search(
        inventory,
        "* | lookup assets ip AS raw.ip OUTPUT owner AS team,risk AS score | stats count,sum(score) AS total",
    ) == [{"count": 3, "total": 130.0}]


def test_outputnew_fills_missing_fields_and_retains_existing(inventory):
    assert search(
        inventory,
        "* | lookup assets ip OUTPUTNEW owner,risk | sort event_id | table event_id,owner,risk",
    ) == [
        {"event_id": "1", "owner": "Original", "risk": "80"},
        {"event_id": "2", "owner": "Finance", "risk": "50"},
        {"event_id": "3", "owner": "Keep", "risk": None},
    ]


def test_lookup_after_transform_and_index_scope_before_lookup_windows(inventory):
    assert search(
        inventory,
        "* | lookup assets ip OUTPUT risk | sort 0 event_time | streamstats sum(risk) AS running | table event_id,running",
        ["public"],
    ) == [
        {"event_id": "1", "running": 80.0},
        {"event_id": "3", "running": 80.0},
    ]
    assert search(
        inventory,
        "* | stats count by ip | lookup assets ip OUTPUT owner | sort ip | table ip,count,owner",
    ) == [
        {"ip": "10.0.0.1", "count": 1, "owner": "SOC"},
        {"ip": "10.0.0.2", "count": 1, "owner": "Finance"},
        {"ip": "unknown", "count": 1, "owner": None},
    ]


def test_tenant_snapshots_owner_versions_and_write_permissions(store):
    data = {"key": "ip", "rows": [{"ip": "x", "owner": "a"}]}
    first = lookups.save(store, ADMIN, "assets", data)
    assert first["version"] == 1 and first["owner"] == "admin"
    assert "rows" not in lookups.list_for(store, ADMIN)[0]
    assert lookups.list_for(store, ADMIN)[0]["row_count"] == 1
    with pytest.raises(KeyError):
        lookups.get(store, "b", "assets")
    other = lookups.save(
        store,
        {**ADMIN, "tenant": "b"},
        "assets",
        {"key": "ip", "rows": [{"ip": "x", "owner": "b"}]},
    )
    assert other["rows"][0]["owner"] == "b"
    with pytest.raises(PermissionError):
        lookups.save(store, {**ADMIN, "role": "analyst"}, "assets", data)
    with pytest.raises(ConflictError):
        lookups.save(store, ADMIN, "assets", data)
    assert (
        lookups.save(
            store, {**ADMIN, "name": "second_admin"}, "assets", {**data, "version": 1}
        )["version"]
        == 2
    )
    assert lookups.get(store, "a", "assets")["owner"] == "admin"


def test_missing_expired_and_invalid_snapshots_fail_explicitly(store):
    q = Query.parse({"query": "* | lookup unavailable ip OUTPUT owner"})
    with pytest.raises(QueryError, match="unavailable"):
        q.compile("a")
    with pytest.raises(QueryError, match="unavailable"):
        lookups.for_query(store, "a", q.body)
    lookups.save(
        store,
        ADMIN,
        "assets",
        {"key": "ip", "rows": [{"ip": "x", "owner": "a"}], "expires": time.time() + 60},
    )
    with store.control() as db:
        db.execute("UPDATE managed_lookups SET expires=?", (time.time() - 1,))
    assert lookups.get(store, "a", "assets")["expired"]
    with pytest.raises(QueryError, match="expired"):
        lookups.for_query(store, "a", "* | lookup assets ip OUTPUT owner")
    with pytest.raises(QueryError):
        q.compile(
            "a",
            lookup_tables={
                "unavailable": {
                    "key": "ip",
                    "rows": [{"ip": "x", "owner": "a"}, {"ip": "x", "owner": "b"}],
                }
            },
        )


def test_lookup_literal_data_stays_bound_and_empty_schema_is_supported(store):
    payload = "'; SELECT read_csv('private'); --"
    lookups.save(
        store, ADMIN, "labels", {"key": "ip", "rows": [{"ip": "x", "label": payload}]}
    )
    store.ingest("a", [{"event_id": "1", "event_time": 100, "raw": {"ip": "x"}}])
    store.flush()
    query = "* | lookup labels ip OUTPUT label | table label"
    tables = lookups.for_query(store, "a", query)
    sql, args = Query.parse({"query": query}).compile("a", lookup_tables=tables)
    assert payload not in sql and any(
        payload in arg for arg in args if isinstance(arg, str)
    )
    assert search(store, query) == [{"label": payload}]
    lookups.save(
        store, ADMIN, "empty", {"key": "ip", "columns": ["ip", "label"], "rows": []}
    )
    assert search(store, "* | lookup empty ip OUTPUT label | table label") == [
        {"label": None}
    ]


@pytest.mark.parametrize(
    "body",
    [
        {"key": "ip", "rows": [{"ip": "x"}, {"ip": "x"}]},
        {"key": "ip", "rows": [{"ip": 1}]},
        {"key": "ip", "rows": [{"ip": "x", "object": {}}]},
        {"key": "ip", "rows": [{"ip": "x", "value": float("nan")}]},
        {"key": "ip", "rows": [{"ip": "x", "value": 10**400}]},
        {"key": "ip", "rows": [{"ip": "x"}], "columns": ["ip", "ip"]},
        {"key": "ip", "rows": [{"ip": "x"}], "columns": ["ip", []]},
        {"key": "ip", "rows": [{"ip": "x"}], "expires": time.time() - 1},
        {"key": "ip", "rows": [{"ip": "x"}], "version": True},
        {"key": "ip", "rows": [{"ip": "x"}], "url": "https://example.com/feed"},
    ],
)
def test_invalid_lookup_definitions_are_atomic(store, body):
    with pytest.raises(ValueError):
        lookups.save(store, ADMIN, "invalid", body)
    assert lookups.list_for(store, ADMIN) == []


def test_lookup_resource_budgets():
    with pytest.raises(ValueError, match="10000"):
        lookups.validate_rows("key", [{"key": str(i)} for i in range(10001)])
    with pytest.raises(ValueError, match="20"):
        lookups.validate_rows("key", [{"key": "x", **{f"f{i}": i for i in range(20)}}])
    with pytest.raises(ValueError, match="2 MiB"):
        lookups.validate_rows(
            "key", [{"key": str(i), "value": "x" * 4096} for i in range(600)]
        )


@pytest.mark.parametrize(
    "query",
    [
        "* | lookup ../file.csv ip OUTPUT owner",
        "* | lookup feed ip",
        "* | lookup feed ip AS OUTPUT owner",
        "* | lookup feed ip OUTPUT owner AS tenant",
        "* | lookup feed ip OUTPUT owner AS",
        "* | lookup feed ip OUTPUT owner AS x,risk AS x",
    ],
)
def test_unsupported_lookup_syntax_rejected(query):
    with pytest.raises(QueryError):
        Query.parse({"query": query})


def test_typed_intel_validation_enrichment_provenance_and_expiry(store):
    deadline = time.time() + 3600
    ip_feed = lookups.threat_intel(
        "ip",
        ["2001:0db8::1", "10.0.0.1"],
        "approved-local-feed",
        deadline,
        confidence=90,
    )
    domain_feed = lookups.threat_intel(
        "domain", ["Example.COM."], "approved-domain-feed", deadline, confidence=75
    )
    hash_feed = lookups.threat_intel("hash", ["A" * 64], "approved-hash-feed", deadline)
    for name, body in (
        ("ips", ip_feed),
        ("domains", domain_feed),
        ("hashes", hash_feed),
    ):
        lookups.save(store, ADMIN, name, body)
    snapshots = {
        name: lookups.get(store, "a", name) for name in ("ips", "domains", "hashes")
    }
    original = {
        "message": "source unchanged",
        "raw": {"src_ip": "2001:db8:0::1", "domain": "EXAMPLE.com", "hash": "a" * 64},
    }
    before = copy.deepcopy(original)
    result = lookups.enrich_event(original, snapshots)
    assert original == before
    assert result["raw"]["src_ip"] == before["raw"]["src_ip"]
    matches = result["raw"]["threat_intel"]
    assert {m["kind"] for m in matches} == {"ip", "domain", "hash"}
    assert all(m["provenance"] and m["expires"] == deadline for m in matches)
    with pytest.raises(QueryError, match="expired"):
        lookups.enrich_event(original, snapshots, now=deadline + 1)
    with pytest.raises(ValueError, match="overwrite"):
        lookups.enrich_event({"raw": {"threat_intel": "original evidence"}}, snapshots)


@pytest.mark.parametrize(
    "kind,value",
    [("ip", "999.1.1.1"), ("domain", "https://example.com"), ("hash", "xyz")],
)
def test_bad_threat_indicator_rejected(kind, value):
    with pytest.raises(ValueError):
        lookups.threat_intel(kind, [value], "source", time.time() + 100)


def test_threat_intel_requires_expiry_confidence_and_unique_normalized_key(store):
    with pytest.raises(ValueError, match="expiry"):
        lookups.save(
            store,
            ADMIN,
            "intel",
            {
                "key": "indicator",
                "kind": "ip",
                "provenance": "source",
                "rows": [{"indicator": "10.0.0.1", "confidence": 80}],
            },
        )
    with pytest.raises(ValueError, match="confidence"):
        lookups.threat_intel(
            "ip", ["10.0.0.1"], "source", time.time() + 100, confidence=101
        )
    with pytest.raises(ValueError, match="unique"):
        lookups.threat_intel(
            "domain", ["Example.com", "example.com."], "source", time.time() + 100
        )
