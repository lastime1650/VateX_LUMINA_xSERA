import pytest

from sapientia import intelligence, principal
from sapientia import native_predicates as native
from sapientia.storage import ConflictError
from tests.test_backend_upgrade import actor
from tests.test_backend_upgrade import lab as _lab
from tests.test_intelligence import seed, tick

lab = _lab


def tree(root):
    return {"version": 1, "root": root}


def leaf(op, field="raw.value", **args):
    return {"op": op, "field": field, **args}


@pytest.mark.parametrize(
    "value,expected", [(None, True), ([], True), ("", True), (False, True)]
)
def test_exists_is_key_presence_including_null_and_containers(value, expected):
    predicate = tree(leaf("exists", value=True))
    assert native.matches({"raw": {"value": value}}, predicate) is expected
    assert not native.matches({"raw": {}}, predicate)
    assert native.matches({"raw": {}}, tree(leaf("is_null")))


@pytest.mark.parametrize(
    "value,expected", [(True, False), ("5", False), (5, True), (5.0, True)]
)
def test_numeric_equality_does_not_coerce_boolean_or_string(value, expected):
    assert (
        native.matches({"raw": {"value": value}}, tree(leaf("eq", value=5))) is expected
    )


def test_nested_boolean_re2_and_field_comparison_keep_semantics():
    predicate = tree(
        {
            "op": "and",
            "args": [
                {
                    "op": "or",
                    "args": [
                        leaf("regex", pattern="(?i)^power(shell)?$"),
                        leaf("eq", field="raw.second", value=True),
                    ],
                },
                {"op": "not", "arg": leaf("eq", field="raw.excluded", value=True)},
                leaf(
                    "field_eq", field="raw.n", other="raw.other", case_sensitive=False
                ),
            ],
        }
    )
    assert native.matches(
        {"raw": {"value": "PowerShell", "n": 5, "other": 5.0}}, predicate
    )
    assert not native.matches(
        {"raw": {"value": "ordinary", "n": 5, "other": 5}}, predicate
    )
    assert not native.matches(
        {"raw": {"value": "Power", "n": True, "other": 1}}, predicate
    )
    assert not native.matches(
        {"raw": {"value": "Power", "excluded": True, "n": 5, "other": 5}}, predicate
    )
    # Python int equality avoids a false match from lossy double conversion.
    assert not native.matches(
        {"raw": {"a": 9007199254740992, "b": 9007199254740993}},
        tree(leaf("field_eq", field="raw.a", other="raw.b", case_sensitive=False)),
    )
    assert native.matches(
        {"raw": {"a": "Straße", "b": "straße"}},
        tree(leaf("field_eq", field="raw.a", other="raw.b", case_sensitive=False)),
    )


@pytest.mark.parametrize(
    "root",
    [
        leaf("regex", pattern="(?<=unsafe)lookbehind"),
        leaf("regex", pattern=r"(x)\1"),
        leaf("regex", pattern="x" * 513),
        leaf("eq", field="raw.ground_truth", value=True),
        leaf("eq", field="raw.__class__.label", value=True),
        leaf("exists", value=1),
        leaf("gt", value=True),
        {"op": "eval", "code": "arbitrary"},
        {"op": "and", "args": []},
        {"op": "not", "arg": leaf("eq", value=True), "other": 1},
    ],
)
def test_invalid_or_unsafe_semantics_are_rejected(root):
    with pytest.raises(ValueError):
        native.validate(tree(root))


def test_oversized_invalid_scalar_cannot_turn_not_into_true_or_hide_under_or():
    negative = {"op": "not", "arg": leaf("regex", pattern="x")}
    for predicate in (
        tree(negative),
        tree({"op": "or", "args": [leaf("eq", field="raw.ok", value=True), negative]}),
    ):
        with pytest.raises(ValueError, match="64 KiB"):
            native.matches({"raw": {"value": "x" * 65537, "ok": True}}, predicate)
    with pytest.raises(ValueError):
        native.matches(
            {"raw": {"value": float("nan")}},
            tree({"op": "not", "arg": leaf("gt", value=1)}),
        )


def test_native_tree_executes_without_sigma_and_preserves_case_and_review(
    lab, monkeypatch
):
    predicate = tree(
        {
            "op": "and",
            "args": [
                {
                    "op": "or",
                    "args": [
                        leaf("eq", field="raw.stage", value="A"),
                        leaf("eq", field="raw.stage", value="C"),
                    ],
                },
                {"op": "not", "arg": leaf("eq", field="raw.stage", value="B")},
            ],
        }
    )
    definition = {
        "name": "Native JSON Boolean behavior",
        "kind": "atomic",
        "indexes": ["public"],
        "enabled": True,
        "condition_tree": predicate,
        "case_adapter": {
            "entity_field": "host",
            "risk_score": 60,
            "severity": "high",
            "mitre": [],
            "cooldown": 0,
        },
    }
    saved = intelligence.save_policy(lab, actor(), definition)
    with pytest.raises(PermissionError):
        intelligence.review_policy(
            lab,
            actor(),
            saved["id"],
            {"version": 1, "approve": True, "reason": "Self review forbidden"},
        )
    intelligence.review_policy(
        lab,
        actor("peer"),
        saved["id"],
        {
            "version": 1,
            "approve": True,
            "reason": "Independent native condition tree review",
        },
    )
    seed(lab)
    tick(lab)
    matches = [
        r
        for r in intelligence.signals(lab, actor(), count=100)["items"]
        if r["rule_id"] == saved["id"]
    ]
    assert {eid for row in matches for eid in row["event_ids"]} == {
        "event-0",
        "event-2",
    }
    with lab.control() as db:
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0] == 2
        assert db.execute("SELECT count(*) FROM endpoint_responses").fetchone()[0] == 0
    # A contract mismatch cannot keep an old approval alive.
    monkeypatch.setattr(native, "CONTRACT_DIGEST", "changed-contract")
    with principal.transaction(lab, actor(), write=True) as (db, _):
        row = db.execute(
            "SELECT * FROM intelligence_policies WHERE id=?", (saved["id"],)
        ).fetchone()
        with pytest.raises(ConflictError):
            intelligence._authority(db, row)


def test_flat_filters_are_unchanged_and_cannot_be_mixed_with_tree(lab):
    assert (
        intelligence._matches(
            {"raw": {"n": 1.0}}, [{"field": "raw.n", "op": "eq", "value": 1}]
        )
        is False
    )
    with pytest.raises(ValueError):
        intelligence.save_policy(
            lab,
            actor(),
            {
                "name": "ambiguous",
                "kind": "atomic",
                "indexes": ["public"],
                "filters": [{"field": "raw.x", "op": "eq", "value": True}],
                "condition_tree": tree(leaf("eq", value=True)),
            },
        )


def test_execution_limit_is_diagnosed_per_policy_and_later_events_continue(
    lab, monkeypatch
):
    for name, fields in [
        ("bounded tree", {"condition_tree": tree(leaf("regex", pattern="^good$"))}),
        (
            "other native rule",
            {"filters": [{"field": "raw.stage", "op": "eq", "value": "valid"}]},
        ),
    ]:
        saved = intelligence.save_policy(
            lab,
            actor(),
            {
                "name": name,
                "kind": "atomic",
                "indexes": ["public"],
                "enabled": True,
                **fields,
            },
        )
        intelligence.review_policy(
            lab,
            actor("peer"),
            saved["id"],
            {
                "version": 1,
                "approve": True,
                "reason": "Independent scalar bounded evaluation",
            },
        )
    import time

    import duckdb

    actual_db = native._db()

    class Limited:
        def execute(self, sql, parameters):
            if parameters and parameters[0] == "fixture-resource-limit":
                raise duckdb.OutOfMemoryException("Owned fixture execution limit")
            return actual_db.execute(sql, parameters)

    monkeypatch.setattr(native, "_db", lambda: Limited())

    now = time.time() - 2
    lab.ingest(
        "a",
        [
            {
                "event_id": "oversized",
                "event_time": now,
                "index": "public",
                "host": "host",
                "raw": {"value": "fixture-resource-limit", "stage": "valid"},
            },
            {
                "event_id": "good",
                "event_time": now + 1,
                "index": "public",
                "host": "host",
                "raw": {"value": "good", "stage": "valid"},
            },
        ],
    )
    while lab.flush():
        pass
    tick(lab)
    with lab.control() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM intelligence_decisions WHERE reason='predicate_excluded'"
            ).fetchone()[0]
            == 1
        )
        assert (
            db.execute(
                "SELECT count(*) FROM intelligence_signals WHERE kind='atomic'"
            ).fetchone()[0]
            == 3
        )
