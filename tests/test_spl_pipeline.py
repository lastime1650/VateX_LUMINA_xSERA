import time

import pytest

from sapientia.query import Query, QueryError
from sapientia.storage import Settings, Store


@pytest.fixture
def store(tmp_path):
    s = Store(Settings(tmp_path, min_free_bytes=0))
    s.ingest(
        "a",
        [
            {
                "event_id": str(i),
                "event_time": 100 + i * 10,
                "host": "edge-0" + str(i % 2),
                "source": "fw" if i < 3 else "edr",
                "severity": "high" if i % 2 == 0 else "low",
                "message": f"denied src=10.0.0.{i} bytes={i * 10}",
                "raw": {"bytes": i * 10, "network": {"port": 443 if i % 2 else 80}},
            }
            for i in range(6)
        ],
    )
    s.ingest("b", [{"event_id": "secret", "event_time": 105, "host": "hidden"}])
    s.flush()
    yield s
    s.close()


def search(store, text):
    return store.search(
        "a", {"query": text, "earliest": 0, "latest": 1000, "limit": 1000}
    )["rows"]


def test_boolean_wildcard_missing_and_index(store):
    assert search(store, "index=main host=edge-* NOT severity=high | stats count") == [
        {"count": 3}
    ]
    assert search(store, "(source=fw OR source=edr) severity=high | stats count") == [
        {"count": 3}
    ]
    assert search(store, "source=fw OR severity=high host=edge-01 | stats count") == [
        {"count": 1}
    ]
    assert search(store, "NOT absent=* | stats count") == [{"count": 6}]
    assert search(store, "index=other | stats count") == [{"count": 0}]


def test_eval_where_aggregate_and_post_transform(store):
    assert search(
        store,
        '* | eval amount=tonumber(bytes)*2, label=if(amount>=60,"large","small") | where amount>=40 AND label="large" | stats count AS n,sum(amount) AS total,avg(amount) AS average by source | sort source',
    ) == [{"source": "edr", "n": 3, "total": 240.0, "average": 80.0}]
    assert search(
        store,
        "* | stats count by source | where count=3 | table source,count | sort source",
    ) == [{"source": "edr", "count": 3}, {"source": "fw", "count": 3}]


def test_head_is_a_pipeline_stage(store):
    assert search(store, "* | head 2 | stats count") == [{"count": 2}]
    assert search(store, "* | sort 0 event_id | tail 2 | table event_id") == [
        {"event_id": "5"},
        {"event_id": "4"},
    ]


def test_sort_spaced_direction_limit_and_type(store):
    assert search(store, "* | sort limit=2 - num(bytes) | table event_id") == [
        {"event_id": "5"},
        {"event_id": "4"},
    ]
    assert search(store, "* | sort event_time desc | head 2 | table event_id") == [
        {"event_id": "5"},
        {"event_id": "4"},
    ]
    with pytest.raises(QueryError):
        Query.parse({"query": "* | sort event_time -"})


def test_streaming_and_event_statistics(store):
    rows = search(
        store,
        "* | sort 0 event_time | streamstats count AS running,sum(bytes) AS cumulative | table event_id,running,cumulative",
    )
    assert [r["running"] for r in rows] == [1, 2, 3, 4, 5, 6]
    assert rows[-1]["cumulative"] == 150
    rows = search(store, "* | eventstats count AS peers by host | table host,peers")
    assert all(r["peers"] == 3 for r in rows)
    rows = search(
        store,
        "* | sort 0 event_time | streamstats window=2 count AS n | table event_id,n",
    )
    assert [r["n"] for r in rows] == [1, 2, 2, 2, 2, 2]


def test_aggregate_semantics(store):
    rows = search(
        store,
        '* | stats count(bytes) AS present,count(eval(severity="high")) AS high,dc(host) AS hosts,sum(bytes) AS total,median(bytes) AS median,earliest(bytes) AS first,latest(bytes) AS last',
    )
    assert rows == [
        {
            "present": 6,
            "high": 3,
            "hosts": 2,
            "total": 150.0,
            "median": 30.0,
            "first": "0",
            "last": "50",
        }
    ]
    values = search(store, "* | stats values(host) AS hosts")[0]["hosts"]
    assert set(values) == {"edge-00", "edge-01"}


def test_bucket_rex_and_spath(store):
    assert search(store, "* | timechart span=1m count") == [
        {"_time": 60.0, "count": 2},
        {"_time": 120.0, "count": 4},
    ]
    rows = search(
        store,
        '* | rex "src=(?<src>[0-9.]+)" | spath path=network.port output=port | sort event_id | table src,port',
    )
    assert rows[0] == {"src": "10.0.0.0", "port": "80"}
    assert rows[-1] == {"src": "10.0.0.5", "port": "443"}


def test_dedup_rename_fillnull_and_top(store):
    rows = search(
        store, "* | dedup host | table host | rename host AS device | sort device"
    )
    assert rows == [{"device": "edge-00"}, {"device": "edge-01"}]
    rows = search(
        store, '* | eval absent=null() | fillnull value="unknown" absent | table absent'
    )
    assert all(r["absent"] == "unknown" for r in rows)
    assert search(store, "* | top 1 source")[0]["percent"] == 50


def test_generating_expression_functions(store):
    rows = search(
        store,
        '| makeresults count=3 | streamstats count AS n | eval tag=if(n=1,"first","other"),v=round(pow(n,2),0) | table n,tag,v',
    )
    assert rows == [
        {"n": 1, "tag": "first", "v": 1.0},
        {"n": 2, "tag": "other", "v": 4.0},
        {"n": 3, "tag": "other", "v": 9.0},
    ]


@pytest.mark.parametrize(
    "text",
    [
        '* | eval a=read_csv("C:/secret")',
        '* | eval a=__import__("os")',
        '* | where tenant="b"',
        '* | eval tenant="b"',
        "* | stats count by tenant",
        "* | eval a=(1+2",
        "* | eval a=1; DROP TABLE events",
        '* | rex "(?<tenant>.*)"',
        "* | spath path=network[*] output=port",
        "* | join [ search * ]",
        "* | rename host AS tenant",
        "* | sort -tenant",
        "* | eval a=" + "(" * 50 + "1" + ")" * 50,
    ],
)
def test_unsafe_queries_rejected(text):
    with pytest.raises(QueryError):
        Query.parse({"query": text, "earliest": 0, "latest": time.time()})
