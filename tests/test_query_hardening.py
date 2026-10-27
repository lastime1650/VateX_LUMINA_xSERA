import json
from datetime import UTC, datetime

import pytest

from sapientia.connectors import parse_line
from sapientia.query import Query, QueryError
from sapientia.runtime import save_rule
from sapientia.storage import Settings, Store


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    yield value
    value.close()


def execute(store, query, allowed_indexes=None, language="spl"):
    parsed = Query.parse(
        {
            "query": query,
            "language": language,
            "earliest": 0,
            "latest": 2000000000,
            "limit": 1000,
        }
    )
    sql, args = parsed.compile("a", allowed_indexes=allowed_indexes)
    con = store.analytics.cursor()
    try:
        con.execute(sql, args)
        columns = [c[0] for c in con.description]
        return [dict(zip(columns, r)) for r in con.fetchall()]
    finally:
        con.close()


@pytest.mark.parametrize(
    "values,expected",
    [
        ([2, 10, 3], ("2", "10")),
        (["2", "10", "3"], ("2", "10")),
        (["banana", "Apple", "zebra"], ("Apple", "zebra")),
        ([10, "2", "banana", "Apple", None], ("2", "banana")),
        ([None, 10, None, 2], ("2", "10")),
        ([None, None], (None, None)),
    ],
)
def test_min_max_numeric_text_mixed_and_null(store, values, expected):
    store.ingest(
        "a",
        [
            {"event_id": str(i), "event_time": 100 + i, "raw": {"n": value}}
            for i, value in enumerate(values)
        ],
    )
    store.flush()
    assert execute(store, "* | stats min(n) AS lo,max(n) AS hi") == [
        {"lo": expected[0], "hi": expected[1]}
    ]


def test_min_max_preserves_materialized_number_and_window_order(store):
    store.ingest(
        "a",
        [
            {"event_id": str(i), "event_time": 100 + i, "raw": {"n": n}}
            for i, n in enumerate([2, 10, 3])
        ],
    )
    store.flush()
    assert execute(
        store,
        "* | eval n=tonumber(n) | stats min(n) AS lo,max(n) AS hi | eval range=hi-lo | table lo,hi,range",
    ) == [{"lo": 2.0, "hi": 10.0, "range": 8.0}]
    rows = execute(
        store, "* | sort 0 _time | streamstats min(n) AS lo,max(n) AS hi | table lo,hi"
    )
    assert rows == [
        {"lo": "2", "hi": "2"},
        {"lo": "2", "hi": "10"},
        {"lo": "2", "hi": "10"},
    ]


@pytest.mark.parametrize(
    "index,expected",
    [(0, "a"), (2, "c"), (-1, "c"), (-2, "b"), (-3, "a"), (-4, None), (3, None)],
)
def test_mvindex_positive_and_negative(store, index, expected):
    query = (
        f'| makeresults | eval value=mvindex(split("a,b,c",","),{index}) | table value'
    )
    assert execute(store, query) == [{"value": expected}]


@pytest.mark.parametrize("language", ["spl", "json"])
def test_free_text_finds_raw_and_message_without_duplicate_rows(store, language):
    store.ingest(
        "a",
        [
            {
                "event_id": "raw",
                "event_time": 100,
                "message": "other",
                "raw": {"indicator": "ThreatMarker"},
            },
            {
                "event_id": "message",
                "event_time": 101,
                "message": "threatmarker",
                "raw": {},
            },
            {
                "event_id": "both",
                "event_time": 102,
                "message": "threatmarker",
                "raw": {"indicator": "threatmarker"},
            },
            {"event_id": "none", "event_time": 103, "message": "other"},
        ],
    )
    store.ingest(
        "b", [{"event_id": "hidden", "event_time": 100, "message": "threatmarker"}]
    )
    store.flush()
    query = (
        "THREATMARKER | table event_id"
        if language == "spl"
        else {"text": "THREATMARKER", "fields": ["event_id"]}
    )
    assert {r["event_id"] for r in execute(store, query, language=language)} == {
        "raw",
        "message",
        "both",
    }


@pytest.mark.parametrize(
    "timestamp",
    [
        "2003-10-11T22:14:15.003Z",
        "2003-10-12T07:14:15.003+09:00",
        "2003-10-11T18:14:15.003-04:00",
    ],
)
def test_syslog_uses_original_timezone_aware_time(store, timestamp):
    line = f"<34>1 {timestamp} host app 123 ID - denied"
    event = parse_line(line, "syslog", "syslog", "timestamp")
    expected = datetime(2003, 10, 11, 22, 14, 15, 3000, tzinfo=UTC).timestamp()
    assert event["event_time"] == pytest.approx(expected)
    assert event["raw"]["source_timestamp"] == timestamp
    store.ingest("a", [event])
    store.flush()
    assert execute(store, "event_id=timestamp | table event_time")[0][
        "event_time"
    ] == pytest.approx(expected)


@pytest.mark.parametrize(
    "timestamp",
    [
        "2003-10-11T22:14:15",
        "2003-10-11 22:14:15Z",
        "2003-02-30T22:14:15Z",
        "2003-10-11T22:14:15+25:00",
        "2003-10-11T22:14:15.1234567Z",
    ],
)
def test_syslog_rejects_ambiguous_or_invalid_timestamp(timestamp):
    with pytest.raises(ValueError):
        parse_line(
            f"<34>1 {timestamp} host app 123 ID - denied", "syslog", "syslog", "badtime"
        )


def test_syslog_nil_time_preserves_receipt_time_default():
    event = parse_line(
        "<34>1 - host app 123 ID - denied", "syslog", "syslog", "niltime"
    )
    assert "event_time" not in event
    assert event["raw"]["source_timestamp"] == "-"


@pytest.mark.parametrize(
    "query",
    [
        '* | regex message="(?=denied)"',
        '* | rex "(?<capture>a)(?=b)"',
        '* | eval matched=match(message,"(?=denied)")',
        '* | eval replaced=replace(message,"(?=denied)","x")',
        '* | regex message="["',
        "* | eval matched=match(message,raw.pattern)",
    ],
)
def test_re2_invalid_patterns_are_rejected_before_rule_save(store, query):
    with pytest.raises(QueryError):
        Query.parse({"query": query})
    with pytest.raises(QueryError):
        save_rule(
            store,
            {"name": "analyst", "tenant": "a"},
            {"name": "invalid regex", "query": {"query": query}},
        )
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM rules").fetchone()[0] == 0


def test_re2_literal_patterns_execute_and_remain_bound(store):
    store.ingest(
        "a", [{"event_id": "pattern", "event_time": 100, "message": "denied 42"}]
    )
    store.flush()
    assert execute(
        store,
        '* | regex message="denied [0-9]+" | rex "(?<number>[0-9]+)" | eval matched=match(message,"denied"),label=replace(message,"[0-9]+","x") | table number,matched,label',
    ) == [{"number": "42", "matched": True, "label": "denied x"}]
    payload = ".*; SELECT read_csv('private')"
    parsed = Query.parse({"query": "* | regex message=" + json.dumps(payload)})
    sql, args = parsed.compile("a")
    assert payload not in sql and payload in args


@pytest.fixture
def indexes(store):
    store.ingest(
        "a",
        [
            {
                "event_id": "public1",
                "event_time": 100,
                "index": "public",
                "raw": {"n": 2},
            },
            {
                "event_id": "restricted1",
                "event_time": 101,
                "index": "restricted",
                "raw": {"n": 100},
            },
            {
                "event_id": "public2",
                "event_time": 102,
                "index": "public",
                "raw": {"n": 3},
            },
        ],
    )
    store.ingest(
        "b",
        [
            {
                "event_id": "other",
                "event_time": 103,
                "index": "public",
                "raw": {"n": 1000},
            }
        ],
    )
    store.flush()
    return store


def test_spl_index_scope_applies_before_aggregate_window_and_mutations(indexes):
    assert execute(indexes, "index=* | stats count,sum(n) AS total", ["public"]) == [
        {"count": 2, "total": 5.0}
    ]
    assert execute(indexes, "index=restricted | stats count", ["public"]) == [
        {"count": 0}
    ]
    assert execute(indexes, '* | eval index="public" | stats count', ["public"]) == [
        {"count": 2}
    ]
    assert execute(
        indexes,
        "* | sort 0 _time | streamstats sum(n) AS total | table event_id,total",
        ["public"],
    ) == [{"event_id": "public1", "total": 2.0}, {"event_id": "public2", "total": 5.0}]
    assert execute(indexes, "* | stats count", []) == [{"count": 0}]
    assert execute(indexes, "* | stats count", ["*"]) == [{"count": 3}]
    assert execute(indexes, "* | stats count", None) == [{"count": 3}]
    assert execute(indexes, "| makeresults count=2 | stats count", []) == [{"count": 2}]


def test_json_index_scope_filters_before_groups_and_allows_index_projection(indexes):
    query = {"group_by": ["index_name"]}
    assert execute(indexes, query, ["public"], "json") == [
        {"index_name": "public", "count": 2}
    ]
    assert (
        execute(indexes, {"fields": ["event_id", "index", "_indextime"]}, [], "json")
        == []
    )
    rows = execute(
        indexes, {"fields": ["event_id", "index", "_indextime"]}, ["public"], "json"
    )
    assert {r["index_name"] for r in rows} == {"public"}
    assert all(isinstance(r["received"], float) for r in rows)


@pytest.mark.parametrize(
    "scope",
    [
        "public",
        ("public",),
        ["public*"],
        ["public;DROP TABLE events"],
        ["public", "*"],
        [None],
        [""],
        ["a" * 65],
        ["public"] * 257,
    ],
)
@pytest.mark.parametrize(
    "language,body", [("spl", "* | stats count"), ("json", {"group_by": []})]
)
def test_index_scopes_fail_closed(language, body, scope):
    parsed = Query.parse({"language": language, "query": body})
    with pytest.raises(QueryError):
        parsed.compile("a", allowed_indexes=scope)


def test_index_scope_is_bound_not_interpolated():
    for payload in ({"query": "*"}, {"language": "json", "query": {}}):
        sql, args = Query.parse(payload).compile(
            "a", allowed_indexes=["restricted", "public"]
        )
        assert "restricted" not in sql and "public" not in sql
        assert "restricted" in args and "public" in args
