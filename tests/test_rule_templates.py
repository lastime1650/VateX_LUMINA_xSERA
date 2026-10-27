import json
import time

import pytest

from sapientia import access, auth, detections, rule_templates, xdr_bridge
from sapientia.query import Query, QueryError
from sapientia.storage import Settings, Store


@pytest.fixture
def store_actor(tmp_path):
    store = Store(Settings(tmp_path, min_free_bytes=0))
    auth.create_user(
        store, "template_admin", "Synthetic-template-password-2026", "admin", "a"
    )
    actor = {"name": "template_admin", "tenant": "a", "role": "admin"}
    yield store, actor
    store.close()


def test_all_source_ids_preserved_and_supported_policies_disabled():
    summary = rule_templates.summary()
    assert (summary["total"], summary["supported"], summary["unsupported"]) == (
        962,
        962,
        0,
    )
    rows = []
    for offset in range(0, 962, 100):
        rows.extend(rule_templates.listing(offset=offset, limit=100)["items"])
    assert len({row["id"] for row in rows}) == 962
    assert len([row for row in rows if not row["id"].startswith("R-XSR-")]) == 950
    assert summary["curated_causal_hypotheses"] == 12
    for row in rows:
        assert row["enabled"] is False
        full = rule_templates.detail(row["id"])
        assert type(full["original"]["enabled"]) is bool
        if row["supported"]:
            assert full["policy_preview"]["enabled"] is False
        else:
            assert full["policy_preview"] is None and row["kind"] == "behavior"
    assert any(
        "Historical ATT&CK" in note for row in rows for note in row["adaptation_notes"]
    )


def test_listing_is_bounded_filtered_and_not_mutable():
    value = rule_templates.listing(
        search="T1059.001", platform="windows", supported=True, limit=2
    )
    assert len(value["items"]) == 2 and value["total"] > 2
    value["items"][0]["adaptation_notes"].clear()
    assert rule_templates.detail(value["items"][0]["id"])["adaptation_notes"]
    for kwargs in [{"limit": 101}, {"offset": -1}, {"platform": "invalid"}]:
        with pytest.raises(ValueError):
            rule_templates.listing(**kwargs)


def test_every_generated_pattern_is_accepted_by_actual_re2_engine():
    import duckdb

    patterns = set()
    for row in rule_templates._library().values():
        definition = rule_templates._policy(row["original"], "endpoint")
        for step in definition["steps"]:
            patterns.update(f["value"] for f in step["filters"] if f["op"] == "regex")
    with duckdb.connect(":memory:") as db:
        db.executemany(
            "SELECT regexp_matches('', ?)", [(pattern,) for pattern in sorted(patterns)]
        )
    assert len(patterns) > 500


@pytest.mark.parametrize(
    "op,value",
    [
        ("typed_eq", 2**53),
        ("typed_in", "[" + "9" * 1000 + "]"),
        ("eq", 2**100),
        ("typed_in", '[1,"1"]'),
    ],
)
def test_unrepresentable_or_mixed_typed_numbers_rejected(op, value):
    with pytest.raises(QueryError):
        Query.parse(
            {
                "language": "json",
                "query": {
                    "filters": [{"field": "raw.value", "op": op, "value": value}]
                },
            }
        )


def test_import_requires_acceptance_and_current_index_scope(store_actor):
    store, actor = store_actor
    for payload in [
        {"index": "endpoint"},
        {"index": "endpoint", "accept_adaptation": False},
        {"index": "*", "accept_adaptation": True},
    ]:
        with pytest.raises(ValueError):
            rule_templates.apply(store, actor, "R-WIN-001", payload)
    bad = rule_templates.detail("R-LAB-001")["original"]
    bad["stages"][0]["match"] = {"any": bad["stages"][0]["match"]["all"]}
    with pytest.raises(ValueError, match="unsupported"):
        rule_templates._policy(bad, "endpoint")
    access.set_for_user(store, actor, actor["name"], ["endpoint"])
    with pytest.raises(PermissionError):
        rule_templates.apply(
            store, actor, "R-WIN-001", {"index": "private", "accept_adaptation": True}
        )
    result = rule_templates.apply(
        store, actor, "R-WIN-001", {"index": "endpoint", "accept_adaptation": True}
    )
    row = detections.list_policies(store, actor)[0]
    assert row["id"] == result["id"] and row["enabled"] == 0
    assert row["definition"]["enabled"] is False
    assert row["definition"]["steps"][0]["filters"][0]["value"] == "endpoint"
    with store.control() as db:
        db.execute("UPDATE users SET disabled=1 WHERE name=?", (actor["name"],))
    with pytest.raises(PermissionError):
        rule_templates.apply(
            store, actor, "R-WIN-001", {"index": "endpoint", "accept_adaptation": True}
        )


def test_real_typed_endpoint_rule_evaluates_without_other_tenant_or_index(store_actor):
    store, _actor = store_actor
    now = time.time()

    def endpoint(
        identifier, os="WINDOWS", command="powershell -ENC harmless", host="qa-host"
    ):
        from datetime import UTC, datetime

        return xdr_bridge.parse_event(
            {
                "id": identifier,
                "data": {
                    "@timestamp": datetime.fromtimestamp(now - 2, UTC).isoformat(),
                    "host": {"id": host, "os": {"type": os}},
                    "process": {
                        "guid": identifier,
                        "name": "powershell.exe",
                        "command_line": command,
                    },
                    "event": {"action": "PROCESS_CREATED"},
                },
            },
            "agent",
            "endpoint",
        )

    matched = endpoint("match")
    store.ingest(
        "a",
        [
            matched,
            endpoint("other-os", os="linux"),
            endpoint("benign", command="powershell benign"),
        ],
    )
    private = endpoint("private")
    private["index"] = "private"
    store.ingest("a", [private])
    store.ingest("b", [endpoint("foreign")])
    store.flush(100)
    definition = rule_templates._policy(
        rule_templates.detail("R-WIN-001")["original"], "endpoint"
    )
    matches = detections.evaluate(
        store, "a", definition, now, allowed_indexes=["endpoint"]
    )
    assert len(matches) == 1 and matches[0]["event_ids"] == [matched["event_id"]]
    assert detections.evaluate(store, "a", definition, now, allowed_indexes=[]) == []


def search(store, filters):
    return store.search(
        "a",
        {
            "language": "json",
            "earliest": 1,
            "latest": time.time() + 10,
            "query": {"filters": filters, "fields": ["event_id"]},
            "limit": 100,
        },
    )["rows"]


def test_json_typed_numeric_membership_exists_and_null(store_actor):
    store, _ = store_actor
    values = [None, "", 0, False, 5985, "5985", [5985], 5986.0]
    store.ingest(
        "a",
        [
            {"event_id": str(i), "raw": {"nested": {"value": value}}}
            for i, value in enumerate(values)
        ]
        + [{"event_id": "missing", "raw": {}}],
    )
    store.flush()

    def ids(op, value):
        return {
            row["event_id"]
            for row in search(
                store, [{"field": "raw.nested.value", "op": op, "value": value}]
            )
        }

    assert ids("exists", 0) == {"0", "missing"}
    assert ids("exists", 1) == {"1", "2", "3", "4", "5", "6", "7"}
    assert ids("typed_eq", 5985) == {"4"}
    assert ids("number_gte", 5985) == {"4", "7"}
    assert ids("typed_in", json.dumps([5985, 5986])) == {"4", "7"}
    assert ids("typed_in", json.dumps(["5985"])) == {"5"}
    assert ids("regex", "^5985$") == {"5"}
    assert ids("regex", "(?s).*") == {"1", "5"}


@pytest.mark.parametrize(
    "pattern",
    [
        "(?=x)",
        "(x)\\1",
        "(?P<n>x)",
        "x{1,2}",
        "[a-z]",
        "a++",
        "a*?",
        "(?i:abc)",
        "x\\d",
        "a" * 1025,
        "x\n",
        "(" * 500 + "x" + ")" * 500,
    ],
)
def test_unsafe_or_outside_profile_regex_rejected(pattern):
    with pytest.raises(QueryError):
        Query.parse(
            {
                "language": "json",
                "query": {
                    "filters": [{"field": "message", "op": "regex", "value": pattern}]
                },
            }
        )


def test_re2_is_bound_and_nonnumeric_unicode_difference_explicit(store_actor):
    store, _ = store_actor
    store.ingest(
        "a",
        [
            {
                "event_id": "match",
                "message": "x' OR 1=1 --",
                "raw": {"value": "Straße"},
            },
            {"event_id": "other", "message": "other", "raw": {"value": "strasse"}},
        ],
    )
    store.flush()
    assert {
        row["event_id"]
        for row in search(
            store, [{"field": "message", "op": "regex", "value": "^x' OR 1=1 --$"}]
        )
    } == {"match"}
    assert {
        row["event_id"]
        for row in search(
            store, [{"field": "raw.value", "op": "regex", "value": "(?i)^strasse$"}]
        )
    } == {"other"}
    assert any(
        "casefold" in note
        for note in rule_templates.detail("R-WIN-001")["adaptation_notes"]
    )
    Query.parse({"language": "json", "query": {"fields": ["raw.a.b.c.d.e.f.g.h"]}})
    with pytest.raises(QueryError):
        Query.parse(
            {"language": "json", "query": {"fields": ["raw.a.b.c.d.e.f.g.h.i"]}}
        )
