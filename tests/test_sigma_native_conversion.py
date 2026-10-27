# ruff: noqa: F811 - imported pytest fixture names are reused as parameters.
"""Native typed Sigma AST semantics are checked against real preview queries."""

import json
import time

import pytest
from test_sigma_backend import (  # noqa: F401 - real disposable query fixture.
    body,
    store,
)

from sapientia import native_predicates, sigma_backend


@pytest.mark.parametrize(
    "selection",
    [
        {"CommandLine|contains|all": ["powershell", "-noprofile"]},
        {"CommandLine|cased": "PowerShell"},
        {"CommandLine|re|i": "^powershell$"},
        {"Count|gte": 3},
        {"Count|lt": 3},
        {"Count": 5},
        {"Flag": True},
        {"Flag": False},
        {"CommandLine|fieldref": "Other"},
        {"CommandLine|exists": True},
        {"CommandLine|exists": False},
        {"CommandLine": None},
        [{"Count": 2}, {"CommandLine|contains|all": ["-NoProfile", "a.b"]}],
    ],
)
def test_native_scalar_semantics_equal_real_preview_without_boolean_flattening(
    store, selection
):
    converted = sigma_backend.native_preview(body(selection))
    query = {**converted["query"], "earliest": 0, "latest": time.time() + 1}
    expected = {
        row["event_id"]
        for row in store.search("a", query, allowed_indexes=["main"])["rows"]
    }
    rows = store.search(
        "a",
        {
            "language": "spl",
            "query": "search * | fields event_id sourcetype raw",
            "earliest": 0,
            "latest": time.time() + 1,
        },
        allowed_indexes=["main"],
    )["rows"]
    observed = set()
    for row in rows:
        raw = json.loads(row["raw"]) if isinstance(row["raw"], str) else row["raw"]
        if native_predicates.matches(
            {"event": row, "raw": raw, "projection": {}},
            converted["native_condition_tree"],
        ):
            observed.add(row["event_id"])
    assert observed == expected


@pytest.mark.parametrize(
    "selection,mapped",
    [
        ({"Count": 5}, "host"),
        ({"Flag": True}, "host"),
        ({"CommandLine": "5"}, "event_time"),
    ],
)
def test_native_conversion_refuses_implicit_envelope_type_casts(selection, mapped):
    data = body(selection)
    data["field_mapping"][next(iter(selection)).split("|")[0]] = mapped
    with pytest.raises(ValueError):
        sigma_backend.native_preview(data)
