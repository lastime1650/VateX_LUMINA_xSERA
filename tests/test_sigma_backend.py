import time

import pytest

from sapientia import sigma_backend, sigma_rules
from sapientia.storage import Settings, Store


def body(selection, condition="sel"):
    return {
        "profile": "pysigma-json-v3",
        "rule": {
            "title": "Bounded actual pySigma AST",
            "logsource": {"category": "process_creation"},
            "detection": {"sel": selection, "condition": condition},
        },
        "field_mapping": {
            "CommandLine": "raw.command",
            "Count": "raw.count",
            "Other": "raw.other",
            "Flag": "raw.flag",
        },
        "logsource_mapping": {"category": {"field": "sourcetype", "value": "process"}},
    }


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    now = time.time() - 1
    records = [
        {
            "event_id": "first",
            "event_time": now,
            "sourcetype": "process",
            "raw": {
                "command": "POWERSHELL -NoProfile a.b",
                "count": 5,
                "other": "POWERSHELL -NoProfile a.b",
                "flag": True,
            },
        },
        {
            "event_id": "second",
            "event_time": now,
            "sourcetype": "process",
            "raw": {
                "command": "powershell",
                "count": "5",
                "other": "different",
                "flag": "true",
            },
        },
        {
            "event_id": "third",
            "event_time": now,
            "sourcetype": "process",
            "raw": {
                "command": "PowerShell",
                "count": 2,
                "other": "powershell",
                "flag": False,
            },
        },
        {
            "event_id": "null",
            "event_time": now,
            "sourcetype": "process",
            "raw": {"command": None},
        },
        {"event_id": "missing", "event_time": now, "sourcetype": "process", "raw": {}},
        {
            "event_id": "wrong-source",
            "event_time": now,
            "sourcetype": "proxy",
            "raw": {"command": "POWERSHELL -NoProfile a.b", "count": 5, "flag": True},
        },
    ]
    value.ingest("a", records)
    value.flush()
    yield value
    value.close()


@pytest.mark.parametrize(
    "selection,expected",
    [
        ({"CommandLine|contains|all": ["powershell", "-noprofile"]}, {"first"}),
        ({"CommandLine|cased": "PowerShell"}, {"third"}),
        ({"CommandLine|re|i": "^powershell$"}, {"second", "third"}),
        ({"Count|gte": 3}, {"first"}),
        ({"Flag": True}, {"first"}),
        ({"CommandLine|fieldref": "Other"}, {"first", "third"}),
        ({"CommandLine|exists": True}, {"first", "second", "third", "null"}),
        ({"CommandLine|exists": False}, {"missing"}),
        (
            [{"Count": 2}, {"CommandLine|contains|all": ["-NoProfile", "a.b"]}],
            {"first", "third"},
        ),
    ],
)
def test_upstream_ast_executes_real_query_with_scope_and_type_fidelity(
    store, selection, expected
):
    result = sigma_rules.preview_sigma(body(selection))
    assert result["upstream"]["available"] and result["semantic_ir"]["version"] == 3
    query = {**result["query"], "earliest": 0, "latest": time.time() + 1}
    assert {
        r["event_id"]
        for r in store.search("a", query, allowed_indexes=["main"])["rows"]
    } == expected
    assert not store.search("b", query, allowed_indexes=["main"])["rows"]
    assert not store.search("a", query, allowed_indexes=[])["rows"]


@pytest.mark.parametrize(
    "selection",
    [
        {"CommandLine|base64": "x"},
        {"CommandLine|fieldref": "Unmapped"},
        {"CommandLine|re": "(?<=unsafe)backreference"},
        {"CommandLine|re": "a" * 513},
        {"Count|gte": float("inf")},
    ],
)
def test_unsupported_or_unbounded_semantics_fail_closed(selection):
    with pytest.raises(ValueError):
        sigma_rules.preview_sigma(body(selection))


def test_missing_source_mapping_and_correlation_document_are_never_discarded():
    data = body({"CommandLine": "*powershell*"})
    data["logsource_mapping"] = {}
    with pytest.raises(ValueError):
        sigma_rules.preview_sigma(data)
    data = body({"CommandLine": "*powershell*"})
    data["rule"]["correlation"] = {"type": "event_count"}
    with pytest.raises(ValueError):
        sigma_rules.preview_sigma(data)


def test_parser_missing_is_visible_without_legacy_profile_semantics_change(monkeypatch):
    assert sigma_backend.status()["profile"] == "pysigma-json-v3"
    data = body({"CommandLine|contains|all": ["a", "b"]})
    data["profile"] = "bounded-json-v2"
    with pytest.raises(ValueError):
        sigma_rules.preview_sigma(data)


def test_fieldref_numeric_values_match_across_json_integer_and_double(store):
    now = time.time() - 1
    store.ingest(
        "a",
        [
            {
                "event_id": "numeric-ref",
                "event_time": now,
                "sourcetype": "process",
                "raw": {"count": 5, "other": 5.0},
            }
        ],
    )
    store.flush()
    result = sigma_rules.preview_sigma(body({"Count|fieldref": "Other"}))
    assert {
        r["event_id"]
        for r in store.search(
            "a",
            {**result["query"], "earliest": 0, "latest": now + 2},
            allowed_indexes=["main"],
        )["rows"]
    } == {"numeric-ref"}
