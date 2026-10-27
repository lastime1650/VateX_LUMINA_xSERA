"""A public-only run cannot hide its reviewed model's wider index scope."""

import pytest

from sapientia import (
    access,
    advanced_intelligence,
    auth,
    connector_runtime,
    intelligence,
    principal,
    source_registry,
)
from sapientia import research_behavior as research
from tests import test_research_fusion as fixtures

actor, store = fixtures.actor, fixtures.store


@pytest.fixture
def scoped_model(store):
    auth.create_user(
        store, "limited", "Model-scope-regression-password-2026", "analyst", "a"
    )
    access.set_for_user(store, actor("admin", role="admin"), "limited", ["public"])
    sources = {}
    for index in ("public", "private"):
        source = source_registry.save(
            store,
            actor("admin", role="admin"),
            {
                "index": index,
                "product": "json",
                "account": "research-scope-" + index,
                "realm": "virtual-lab",
                "credential_ref": "env:SAPIENTIA_CONNECTOR_MODEL_SCOPE",
                "version": 0,
            },
        )
        sources[index] = source
        rows = []
        for i in range(48):
            if (i % 2 == 0) != (index == "public"):
                continue
            row = {
                key: value
                for key, value in fixtures.normal(i).items()
                if key != "projection"
            }
            row["index"] = index
            rows.append(row)
        connector_runtime.intake(
            store,
            actor("admin", role="admin"),
            source["id"],
            {
                "version": 1,
                "events": rows,
                "cursor": "training",
                "checkpoint_version": 0,
            },
        )
    while store.flush():
        pass
    model = research.train(
        store,
        actor(),
        {
            "name": "Two-index normal fusion baseline",
            "indexes": ["public", "private"],
            "training_ids": ["research-" + str(i) for i in range(32)],
            "validation_ids": ["research-" + str(i) for i in range(32, 48)],
            "epochs": 80,
            "seeds": [17],
            "normal_training_confirmed": True,
        },
    )
    research.review(
        store,
        actor("reviewer"),
        model["id"],
        {
            "approve": True,
            "mode": "live",
            "reason": "Independent full-scope fusion review",
        },
    )
    rows = [
        {key: value for key, value in row.items() if key != "projection"}
        for row in fixtures.reads([0, 2, 2000])
    ]
    connector_runtime.intake(
        store,
        actor("admin", role="admin"),
        sources["public"]["id"],
        {
            "version": 1,
            "events": rows,
            "cursor": "runtime",
            "checkpoint_version": 1,
        },
    )
    while store.flush():
        pass
    run = research.analyze(
        store,
        actor(),
        {"model_id": model["id"], "event_ids": [row["event_id"] for row in rows]},
    )
    assert run["indexes"] == ["public"] and run["decision"]["publishable"]
    assert all(not row["relation_anomaly"] for row in run["results"])
    return model, run, sources


def test_research_signal_validation_and_publication_require_full_model_scope(
    store, scoped_model
):
    model, run, _sources = scoped_model
    signal = advanced_intelligence.publish_run(store, actor(), run["id"])
    with principal.transaction(store, actor("limited", indexes=["public"])) as (
        db,
        limited,
    ):
        with pytest.raises(KeyError):
            research._verify_model(db, limited, model["id"], require_active=True)
        with pytest.raises(KeyError):
            intelligence._input_model_pin(
                store, db, limited, "ml:research:" + model["id"]
            )
        with pytest.raises(KeyError):
            advanced_intelligence.validate_signal(store, db, limited, signal)
        assert not advanced_intelligence.validate_parent(store, db, limited, signal)
        assert not intelligence._parent_valid(
            store, db, limited, signal, {"indexes": ["public"]}
        )
    with pytest.raises(KeyError):
        advanced_intelligence.publish_run(
            store, actor("limited", indexes=["public"]), run["id"]
        )
    with principal.transaction(
        store, actor("reviewer", indexes=["public", "private"])
    ) as (db, full):
        assert (
            advanced_intelligence.validate_signal(store, db, full, signal)["id"]
            == run["id"]
        )
        assert advanced_intelligence.validate_parent(store, db, full, signal)
        assert intelligence._parent_valid(
            store, db, full, signal, {"indexes": ["public", "private"]}
        )
    assert (
        advanced_intelligence.publish_run(
            store, actor("reviewer", indexes=["public", "private"]), run["id"]
        )["id"]
        == signal["id"]
    )


def test_actual_kind_only_composite_rejects_hidden_model_but_full_scope_can_join(
    store, scoped_model
):
    _model, run, sources = scoped_model
    parent = intelligence.save_policy(
        store,
        actor(),
        {
            "name": "Separate public atomic evidence",
            "kind": "atomic",
            "indexes": ["public"],
            "enabled": True,
            "filters": [{"field": "raw.scope_confirmation", "op": "eq", "value": True}],
        },
    )
    intelligence.review_policy(
        store,
        actor("reviewer"),
        parent["id"],
        {"version": 1, "approve": True, "reason": "Independent public evidence"},
    )
    policies = {}
    for name, indexes in (("limited", ["public"]), ("trainer", ["public", "private"])):
        policies[name] = intelligence.save_policy(
            store,
            actor(name, indexes=indexes),
            {
                "name": "Kind-only ML composite " + name,
                "kind": "composite",
                "indexes": indexes,
                "enabled": True,
                "inputs": [{"kind": "ml"}, {"kind": "atomic", "rule_id": parent["id"]}],
                "join_on": "process",
                "window": 86400,
                "minimum_independent_groups": 2,
            },
        )
        intelligence.review_policy(
            store,
            actor("reviewer"),
            policies[name]["id"],
            {
                "version": 1,
                "approve": True,
                "reason": "Independent declared scope review",
            },
        )
    signal = advanced_intelligence.publish_run(store, actor(), run["id"])
    with principal.transaction(store, actor("limited", indexes=["public"])) as (
        db,
        _limited,
    ):
        policy = db.execute(
            "SELECT * FROM intelligence_policies WHERE id=?",
            (policies["limited"]["id"],),
        ).fetchone()
        owner, definition = intelligence._authority(db, policy)
        assert not intelligence._parent_valid(store, db, owner, signal, definition)
    confirmation = {
        key: value
        for key, value in fixtures.reads([2001], offset=250)[0].items()
        if key != "projection"
    }
    confirmation["raw"]["scope_confirmation"] = True
    connector_runtime.intake(
        store,
        actor("admin", role="admin"),
        sources["public"]["id"],
        {
            "version": 1,
            "events": [confirmation],
            "cursor": "confirmation",
            "checkpoint_version": 2,
        },
    )
    while store.flush():
        pass
    for _ in range(5):
        intelligence.run_due(store, budget=2, max_runs=8, include_ml=False)
    signals = intelligence.signals(store, actor(), count=1000)["items"]
    assert not any(row["rule_id"] == policies["limited"]["id"] for row in signals)
    combined = [row for row in signals if row["rule_id"] == policies["trainer"]["id"]]
    assert combined and all(
        confirmation["event_id"] in row["event_ids"]
        and signal["id"] in row["parent_signal_ids"]
        for row in combined
    )
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM endpoint_responses").fetchone()[0] == 0


def test_full_model_scope_is_rechecked_after_cached_parent_validation(
    store, scoped_model
):
    _model, run, _sources = scoped_model
    signal = advanced_intelligence.publish_run(store, actor(), run["id"])
    access.set_for_user(
        store, actor("admin", role="admin"), "limited", ["public", "private"]
    )
    memo = {"research": {}}
    with principal.transaction(
        store, actor("limited", indexes=["public", "private"])
    ) as (db, full):
        assert advanced_intelligence.validate_parent(store, db, full, signal, memo=memo)
    access.set_for_user(store, actor("admin", role="admin"), "limited", ["public"])
    with principal.transaction(
        store, actor("limited", indexes=["public", "private"])
    ) as (db, limited):
        assert not advanced_intelligence.validate_parent(
            store, db, limited, signal, memo=memo
        )
        assert not intelligence._parent_valid(
            store, db, limited, signal, {"indexes": ["public"]}, memo=memo
        )
