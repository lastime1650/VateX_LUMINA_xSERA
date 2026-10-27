import copy
import time

import pytest

from sapientia.query import Query
from sapientia.sigma_rules import preview_sigma
from sapientia.storage import Settings, Store


def sigma():
    return {
        "rule": {
            "title": "Suspicious command",
            "logsource": {"category": "process_creation"},
            "detection": {
                "suspicious": {"CommandLine|contains": "PowerShell"},
                "trusted": {"User": "SYSTEM"},
                "condition": "suspicious and not trusted",
            },
        },
        "field_mapping": {"CommandLine": "raw.command", "User": "raw.user"},
        "logsource_mapping": {"category": {"field": "sourcetype", "value": "process"}},
    }


def test_sigma_actual_query_preserves_not_missing_and_source_scope(tmp_path):
    result = preview_sigma(sigma())
    assert result["query_only"]
    store = Store(Settings(tmp_path, min_free_bytes=0))
    now = time.time()
    events = [
        {
            "event_id": "yes",
            "raw": {"command": "powershell -enc payload", "user": "Alice"},
        },
        {"event_id": "missing-user", "raw": {"command": "PowerShell"}},
        {"event_id": "trusted", "raw": {"command": "POWERSHELL", "user": "system"}},
        {
            "event_id": "wrong-source",
            "sourcetype": "proxy",
            "raw": {"command": "PowerShell", "user": "Alice"},
        },
        {"event_id": "missing-command", "raw": {"user": "Alice"}},
    ]
    for event in events:
        event.setdefault("sourcetype", "process")
        event["event_time"] = now - 1
    try:
        store.ingest("a", events)
        store.flush()
        payload = {**result["query"], "earliest": now - 60, "latest": now + 1}
        assert {
            r["event_id"]
            for r in store.search("a", payload, allowed_indexes=["main"])["rows"]
        } == {"yes", "missing-user"}
        assert store.search("a", payload, allowed_indexes=[])["rows"] == []
        assert store.search("b", payload, allowed_indexes=["main"])["rows"] == []
    finally:
        store.close()


@pytest.mark.parametrize(
    "modifier,value,accepted,rejected",
    [
        ("startswith", "C:\\Tools\\", "c:\\tools\\safe.exe", "xC:\\Tools\\safe.exe"),
        ("endswith", ".exe", "calc.EXE", "calc.exe.bak"),
        ("contains", "a.b", "xxA.Byy", "axb"),
        ("equals", "한글", "한글", "한글x"),
        ("equals", 'x" OR 1=1 --', 'x" OR 1=1 --', "other"),
    ],
)
def test_string_modifiers_are_literal_case_insensitive_bound_queries(
    tmp_path, modifier, value, accepted, rejected
):
    body = {
        "rule": {
            "title": "Literal",
            "detection": {"sel": {"Data|" + modifier: value}, "condition": "sel"},
        },
        "field_mapping": {"Data": "raw.data"},
    }
    preview = preview_sigma(body)
    q = Query.parse(preview["query"])
    sql, args = q.compile("tenant", allowed_indexes=["main"])
    assert value not in sql and args
    store = Store(Settings(tmp_path, min_free_bytes=0))
    try:
        now = time.time()
        store.ingest(
            "a",
            [
                {"event_id": "yes", "event_time": now - 1, "raw": {"data": accepted}},
                {"event_id": "no", "event_time": now - 1, "raw": {"data": rejected}},
            ],
        )
        store.flush()
        assert [
            r["event_id"]
            for r in store.search(
                "a", {**preview["query"], "latest": now + 1}, allowed_indexes=["main"]
            )["rows"]
        ] == ["yes"]
    finally:
        store.close()


@pytest.mark.parametrize(
    "change",
    [
        lambda b: b["rule"]["detection"].update(condition="1 of them"),
        lambda b: b["rule"]["detection"].update(condition="unknown"),
        lambda b: b["rule"]["detection"].update(
            suspicious={"CommandLine|contains": ["a", "b"]}
        ),
        lambda b: b["rule"]["detection"].update(suspicious={"CommandLine|re": "a.*"}),
        lambda b: b["rule"]["detection"].update(suspicious={"CommandLine": "*.exe"}),
        lambda b: b["rule"]["detection"].update(suspicious={"CommandLine": None}),
        lambda b: b["rule"]["detection"].update(timeframe="5m"),
        lambda b: b["rule"].update(correlation={"type": "event_count"}),
        lambda b: b.update(logsource_mapping={}),
        lambda b: b["field_mapping"].update(CommandLine="raw;select * from events"),
    ],
)
def test_unsupported_sigma_semantics_never_silently_disappear(change):
    body = copy.deepcopy(sigma())
    change(body)
    with pytest.raises(ValueError):
        preview_sigma(body)


def test_sigma_boolean_precedence_and_explicit_source_mapping():
    body = {
        "rule": {
            "title": "Grouped",
            "detection": {
                "a": {"Data": 1},
                "b": {"Data": 2},
                "c": {"Other": 3},
                "condition": "(a or b) and not c",
            },
        },
        "field_mapping": {"Data": "raw.data", "Other": "raw.other"},
    }
    preview = preview_sigma(body)
    sql, values = Query.parse(preview["query"]).compile("a")
    assert " OR " in sql and " AND " in sql and "NOT" in sql
    assert {1, 2, 3} <= {x for x in values if type(x) in {int, float}}
