import json
import math
import time

import duckdb
import pytest

from sapientia.query import QueryError
from sapientia.spl import SPLQuery
from sapientia.storage import Settings, Store


def query(text, limit=1000):
    return SPLQuery.parse(
        {"query": text, "earliest": 0, "latest": 1000, "limit": limit}
    )


def compiled(text, allowed=None, tenant="a", limit=1000):
    return query(text, limit).compile(
        tenant, allowed_indexes=["main"] if allowed is None else allowed
    )


def initial_cte(sql):
    return sql.split("\n", 1)[0]


def execute(db, text, allowed=None, tenant="a", reference_order=False, limit=1000):
    sql, args = compiled(text, allowed, tenant, limit)
    if reference_order:
        sql = sql.replace(
            "q0 AS (SELECT *,0::BIGINT AS __order",
            "q0 AS (SELECT *,row_number() OVER "
            "(ORDER BY event_time DESC,event_id) AS __order",
            1,
        )
    cursor = db.execute(sql, args)
    names = [column[0] for column in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


@pytest.fixture
def events():
    db = duckdb.connect(":memory:", config={"enable_external_access": "false"})
    db.execute(
        "CREATE TABLE events_all(tenant VARCHAR,event_id VARCHAR,event_time DOUBLE,"
        "received DOUBLE,source VARCHAR,sourcetype VARCHAR,host VARCHAR,"
        "severity VARCHAR,message VARCHAR,raw JSON,index_name VARCHAR)"
    )
    rows = []
    for i in range(6):
        raw = {"bytes": i * 10, "fraction": i / 10, "payload": "x" * 4096}
        if i < 4:
            raw["region"] = "west" if i < 2 else "east"
        rows.append(
            (
                "a",
                f"e{i}",
                100 + i,
                200 + i,
                "fw" if i < 3 else "edr",
                "synthetic",
                f"edge-{i % 2}",
                "high" if i % 2 == 0 else "low",
                "allow" if i % 2 == 0 else "deny",
                json.dumps(raw),
                "main",
            )
        )
    rows += [
        (
            "a",
            "hidden",
            106,
            206,
            "secret",
            "synthetic",
            "hidden",
            "high",
            "secret",
            '{"bytes":9000}',
            "blocked",
        ),
        (
            "b",
            "foreign",
            106,
            206,
            "foreign",
            "synthetic",
            "foreign",
            "high",
            "secret",
            '{"bytes":9999}',
            "main",
        ),
    ]
    db.executemany("INSERT INTO events_all VALUES(?,?,?,?,?,?,?,?,?,?,?)", rows)
    try:
        yield db
    finally:
        db.close()


@pytest.mark.parametrize(
    "function,expected",
    [
        ("count", 6),
        ("sum", 150),
        ("avg", 25),
        ("mean", 25),
        ("min", "0"),
        ("max", "50"),
        ("median", 30),
        ("dc", 6),
        ("distinct_count", 6),
        ("stdev", math.sqrt(350)),
        ("stdevp", math.sqrt(1750 / 6)),
        ("var", 350),
        ("varp", 1750 / 6),
    ],
)
def test_commutative_scalar_values_and_reference_order(events, function, expected):
    text = f"search * | stats {function}(raw.bytes) AS result"
    sql, _ = compiled(text)
    assert "0::BIGINT AS __order" in initial_cte(sql)
    actual = execute(events, text)[0]["result"]
    reference = execute(events, text, reference_order=True)[0]["result"]
    if isinstance(expected, str) or function in {
        "count",
        "dc",
        "distinct_count",
        "sum",
    }:
        assert actual == reference == expected
    else:
        assert actual == pytest.approx(expected)
        assert reference == pytest.approx(expected)


def test_mixed_case_aliases_conditional_count_and_fraction_tolerance(events):
    text = (
        '* | StAtS CoUnT AS N, count(eval(severity="high")) AS high, '
        "SuM(raw.bytes) AS SequenceSum, DC(event_id) AS Unique, "
        "avg(raw.fraction) AS average, stdev(raw.fraction) AS deviation"
    )
    result = execute(events, text)[0]
    assert {name: result[name] for name in ("N", "high", "SequenceSum", "Unique")} == {
        "N": 6,
        "high": 3,
        "SequenceSum": 150,
        "Unique": 6,
    }
    assert result["average"] == pytest.approx(0.25)
    assert result["deviation"] == pytest.approx(math.sqrt(0.035))
    reference = execute(events, text, reference_order=True)[0]
    assert result == pytest.approx(reference)


@pytest.mark.parametrize(
    "prefix,count,total",
    [
        ("severity=high", 3, 60),
        (
            'search (source=fw OR source=edr) | where tonumber(raw.bytes)>=20 | regex message="allow"',
            2,
            60,
        ),
        ('search * | regex message!="deny" | where tonumber(raw.bytes)>=20', 2, 60),
        ("regex message=" + json.dumps(r"stats first\|list"), 0, None),
    ],
)
def test_filter_only_prefixes_preserve_results(events, prefix, count, total):
    text = prefix + " | stats count AS n,sum(raw.bytes) AS total"
    assert "0::BIGINT AS __order" in initial_cte(compiled(text)[0])
    assert execute(events, text) == execute(events, text, reference_order=True)
    assert execute(events, text) == [{"n": count, "total": total}]


def test_empty_and_missing_scalar_fields(events):
    assert execute(
        events, "* | stats count(raw.absent) AS n,sum(raw.absent) AS total"
    ) == [{"n": 0, "total": None}]
    assert execute(events, "host=absent | stats count AS n,dc(host) AS hosts") == [
        {"n": 0, "hosts": 0}
    ]


def test_compiler_generated_conditional_label_is_quoted(events):
    assert execute(events, '* | stats count(eval(severity="high"))') == [
        {'count(eval(severity="high"))': 3}
    ]


@pytest.mark.parametrize(
    "function", ["first", "last", "list", "values", "latest", "earliest"]
)
def test_order_sensitive_first_stats_keep_source_window(events, function):
    text = f"* | stats count AS n,{function}(raw.bytes) AS ordered"
    assert "row_number() OVER (ORDER BY event_time DESC,event_id)" in initial_cte(
        compiled(text)[0]
    )
    result = execute(events, text)[0]
    assert result["n"] == 6
    if function in {"first", "latest"}:
        assert result["ordered"] == "50"
    elif function in {"last", "earliest"}:
        assert result["ordered"] == "0"
    elif function == "list":
        assert result["ordered"] == ["50", "40", "30", "20", "10", "0"]
    else:
        assert set(result["ordered"]) == {"0", "10", "20", "30", "40", "50"}


@pytest.mark.parametrize(
    "prefix",
    [
        "eval value=raw.bytes",
        "table host,raw.bytes",
        "fields host,raw.bytes",
        "rename host AS device",
        "sort 0 event_id",
        "head 2",
        "tail 2",
        "reverse",
        "dedup host",
        "eventstats count AS peers",
        "streamstats count AS running",
        "timechart span=1m count",
        'rex "(?<tag>allow|deny)"',
        "spath path=bytes output=amount",
        'fillnull value="unknown" host',
        "top 1 source",
        "rare 1 source",
        "makeresults count=2",
    ],
)
def test_any_nonfilter_prefix_retains_source_window(prefix):
    sql, _ = compiled(prefix + " | stats count AS n")
    assert "row_number() OVER (ORDER BY event_time DESC,event_id)" in initial_cte(sql)


def test_managed_lookup_prefix_keeps_source_window():
    parsed = query("* | lookup assets ip AS raw.ip OUTPUT owner | stats count AS n")
    sql, _ = parsed.compile(
        "a",
        allowed_indexes=["main"],
        lookup_tables={
            "assets": {
                "key": "ip",
                "columns": ["ip", "owner"],
                "rows": [{"ip": "127.0.0.1", "owner": "SOC"}],
            }
        },
    )
    assert "row_number() OVER (ORDER BY event_time DESC,event_id)" in initial_cte(sql)


def test_grouped_ties_use_all_group_keys_and_preserve_primary(events):
    text = "* | stats count AS n by host,source"
    assert execute(events, text) == [
        {"host": "edge-0", "source": "fw", "n": 2},
        {"host": "edge-1", "source": "edr", "n": 2},
        {"host": "edge-0", "source": "edr", "n": 1},
        {"host": "edge-1", "source": "fw", "n": 1},
    ]
    assert execute(events, text) == execute(events, text, reference_order=True)
    assert execute(events, text, limit=1) == [
        {"host": "edge-0", "source": "fw", "n": 2}
    ]


def test_grouped_null_keys_are_last(events):
    assert execute(events, "* | stats count AS n by raw.region") == [
        {"raw.region": "east", "n": 2},
        {"raw.region": "west", "n": 2},
        {"raw.region": None, "n": 2},
    ]


@pytest.mark.parametrize(
    "suffix,expected",
    [
        ("head 1", [{"source": "edr", "n": 3}]),
        ("tail 1", [{"source": "fw", "n": 3}]),
        ("stats first(source) AS selected", [{"selected": "edr"}]),
        ("stats last(source) AS selected", [{"selected": "fw"}]),
        ("stats list(source) AS selected", [{"selected": ["edr", "fw"]}]),
        (
            "streamstats count AS sequence | table source,sequence",
            [{"source": "edr", "sequence": 1}, {"source": "fw", "sequence": 2}],
        ),
    ],
)
def test_downstream_order_sensitive_commands_use_stable_group_order(
    events, suffix, expected
):
    text = "* | stats count AS n by source | " + suffix
    assert "0::BIGINT AS __order" in initial_cte(compiled(text)[0])
    assert execute(events, text) == expected
    assert execute(events, text, reference_order=True) == expected


def test_timechart_keeps_source_window_and_adds_group_ties(events):
    text = "* | timechart span=1m count by source"
    assert "row_number() OVER (ORDER BY event_time DESC,event_id)" in initial_cte(
        compiled(text)[0]
    )
    assert execute(events, text) == [
        {"_time": 60.0, "source": "edr", "count": 3},
        {"_time": 60.0, "source": "fw", "count": 3},
    ]


def test_prefix_selection_and_first_last_semantics_remain(events):
    assert execute(events, "* | head 2 | stats count AS n,sum(raw.bytes) AS total") == [
        {"n": 2, "total": 90}
    ]
    assert execute(
        events,
        "* | sort 0 event_id | stats first(raw.bytes) AS first,last(raw.bytes) AS last",
    ) == [{"first": "0", "last": "50"}]


def test_repeated_compile_keeps_tenant_and_index_scope_bound(events):
    parsed = query("* | stats count AS n,sum(raw.bytes) AS total")
    cases = [
        ("a", ["main"], 6, 150),
        ("a", [], 0, None),
        ("a", ["blocked"], 1, 9000),
        ("b", ["main"], 1, 9999),
        ("a", ["*"], 7, 9150),
        ("a", ["main"], 6, 150),
    ]
    for tenant, scope, count, total in cases:
        sql, args = parsed.compile(tenant, allowed_indexes=scope)
        assert args[:3] == [tenant, 0.0, 1000.0]
        assert "WHERE tenant=? AND event_time>=? AND event_time<? AND" in initial_cte(
            sql
        )
        assert events.execute(sql, args).fetchall() == [(count, total)]
    assert execute(events, "index=blocked | stats count AS n", allowed=["main"]) == [
        {"n": 0}
    ]


@pytest.mark.parametrize(
    "text",
    [
        "* | stats unknown(raw.bytes)",
        "* | stats sum",
        "* | stats count AS n,count AS n",
        "* | stats count by tenant",
        "* | where __order=1 | stats count",
        "* | stats sum(__order)",
    ],
)
def test_optimization_does_not_relax_parser_validation(text):
    with pytest.raises(QueryError):
        query(text)


def test_store_hot_sealed_mix_preserves_scoped_exact_aggregate(tmp_path):
    store = Store(Settings(tmp_path / "data", min_free_bytes=0))
    try:
        now = time.time()
        store.ingest(
            "a",
            [
                {
                    "event_id": "old-0",
                    "index": "main",
                    "event_time": now,
                    "raw": {"sequence": 0},
                },
                {
                    "event_id": "old-1",
                    "index": "main",
                    "event_time": now,
                    "raw": {"sequence": 1},
                },
                {
                    "event_id": "hidden",
                    "index": "blocked",
                    "event_time": now,
                    "raw": {"sequence": 9000},
                },
            ],
        )
        store.ingest(
            "b",
            [
                {
                    "event_id": "foreign",
                    "index": "main",
                    "event_time": now,
                    "raw": {"sequence": 9999},
                }
            ],
        )
        store.flush()
        assert (
            store.segments.seal(tenant="a", index="main", now=now + 2 * 86400)[
                "sealed_events"
            ]
            == 2
        )
        store.ingest(
            "a",
            [
                {
                    "event_id": "fresh",
                    "index": "main",
                    "event_time": now,
                    "raw": {"sequence": 2},
                }
            ],
        )
        store.flush()
        payload = {
            "query": "* | stats count AS n,dc(event_id) AS ids,sum(raw.sequence) AS total,min(raw.sequence) AS low,max(raw.sequence) AS high",
            "earliest": 0,
            "latest": now + 1,
        }
        assert store.search("a", payload, allowed_indexes=["main"])["rows"] == [
            {"n": 3, "ids": 3, "total": 3.0, "low": "0", "high": "2"}
        ]
        assert store.search("a", payload, allowed_indexes=[])["rows"] == [
            {"n": 0, "ids": 0, "total": None, "low": None, "high": None}
        ]
        assert (
            store.search("b", payload, allowed_indexes=["main"])["rows"][0]["total"]
            == 9999
        )
    finally:
        store.close()
