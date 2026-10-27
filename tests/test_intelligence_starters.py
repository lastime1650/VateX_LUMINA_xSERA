"""Console starters use actual policies, model reviews, scopes and HTTP auth."""

import importlib.util
import time

import pytest

from sapientia import (
    access,
    auth,
    cpu_ml,
    cpu_sequence,
    intelligence,
    normalization,
    source_registry,
)
from sapientia import (
    intelligence_starters as starters,
)
from sapientia.storage import ConflictError, Settings, Store
from tests.test_api import client, sign_in  # noqa: F401 - shared real HTTP fixture.
from tests.test_cpu_sequence import seed_dataset


def actor(name="owner", tenant="a", role="admin"):
    return {"name": name, "tenant": tenant, "role": role, "allowed_indexes": ["*"]}


@pytest.fixture
def lab(tmp_path):
    value = Store(Settings(tmp_path / "db", min_free_bytes=0))
    for name, role, tenant in (
        ("owner", "admin", "a"),
        ("peer", "admin", "a"),
        ("parent", "admin", "a"),
        ("reviewer", "admin", "a"),
        ("foreign", "admin", "b"),
        ("reader", "viewer", "a"),
    ):
        auth.create_user(
            value, name, "Starter-template-test-password-2026", role, tenant
        )
    try:
        yield value
    finally:
        value.close()


def counts(store):
    with store.control() as db:
        return {
            table: db.execute("SELECT count(*) FROM " + table).fetchone()[0]
            for table in (
                "correlation_policies",
                "intelligence_policies",
                "intelligence_signals",
                "incidents",
                "endpoint_responses",
                "effect_receipts",
            )
        }


def parent_policy(store, name="Parent", indexes=None, review=True, kind="atomic"):
    definition = {
        "name": name,
        "kind": kind,
        "indexes": indexes or ["public"],
        "enabled": True,
    }
    definition.update(
        {"filters": [{"field": "raw.stage", "op": "eq", "value": name}]}
        if kind == "atomic"
        else {
            "inputs": [
                {"rule_id": "external-a", "kind": "atomic"},
                {"rule_id": "external-b", "kind": "atomic"},
            ]
        }
    )
    saved = intelligence.save_policy(store, actor("parent"), definition)
    if review:
        intelligence.review_policy(
            store,
            actor("reviewer"),
            saved["id"],
            {
                "version": 1,
                "approve": True,
                "reason": "Independent current parent review",
            },
        )
    return saved["id"]


@pytest.fixture
def model(lab):
    if importlib.util.find_spec("torch") is None:
        pytest.skip("Optional CPU PyTorch unavailable")
    events = [
        {
            "event_id": "normal-" + str(i),
            "event_time": time.time() - 100 + i,
            "index": "public",
            "host": "sample-host",
            "raw": {
                "command_line": "echo normal",
                "dest_port": 443,
                "process_depth": 1,
            },
        }
        for i in range(24)
    ]
    lab.ingest("a", events)
    while lab.flush():
        pass
    trained = cpu_ml.train(
        lab,
        actor(),
        {
            "name": "Actual starter CPU model",
            "indexes": ["public"],
            "training_ids": [e["event_id"] for e in events[:16]],
            "validation_ids": [e["event_id"] for e in events[16:]],
            "normal_training_confirmed": True,
            "epochs": 1,
        },
    )
    assert trained["status"] == "completed"
    return trained


def bind(model, parents, **values):
    return {
        "indexes": ["public"],
        "model_rule_id": "ml:" + model["id"],
        "parent_policy_ids": parents,
        **values,
    }


def test_catalog_and_all_atomic_previews_install_nothing(lab):
    before = counts(lab)
    listing = starters.listing(lab, actor())
    assert (listing["total"], listing["atomic"], listing["composite"]) == (8, 6, 2)
    assert not listing["installed"] and not listing["enabled"]
    assert len({item["id"] for item in listing["items"]}) == 8
    for item in listing["items"]:
        if item["kind"] != "atomic":
            continue
        preview = starters.preview(lab, actor(), item["id"], {"indexes": ["public"]})
        assert preview["definition"]["filters"] == item["filters"]
        assert (
            not preview["definition"]["enabled"]
            and preview["definition"]["case_adapter"] is None
        )
        assert (
            not preview["persisted"]
            and not preview["live_effects"]
            and not preview["automatic_response_authorized"]
        )
        assert "input_models" not in preview["definition"]
    listing["items"][0]["filters"][0]["value"] = "fabricated"
    assert (
        starters.listing(lab, actor())["items"][0]["filters"][0]["value"]
        == "authentication"
    )
    assert counts(lab) == before


@pytest.mark.parametrize(
    "identifier,event",
    [
        ("authentication-failure", {"raw": {"action": "login_failed"}}),
        ("authentication-success", {"raw": {"action": "login_success"}}),
        (
            "endpoint-process-created",
            {
                "sourcetype": "aegis:endpoint",
                "raw": {
                    "xdr": {
                        "schema": "aegis.endpoint.v1",
                        "data": {"event": {"action": "process_created"}},
                    }
                },
            },
        ),
        (
            "endpoint-file-deleted",
            {
                "sourcetype": "aegis:endpoint",
                "raw": {
                    "xdr": {
                        "schema": "aegis.endpoint.v1",
                        "data": {"event": {"action": "file_deleted"}},
                    }
                },
            },
        ),
        (
            "network-blocked",
            {
                "sourcetype": "fortigate:kv",
                "raw": {"fortigate": {"type": "traffic", "action": "deny"}},
            },
        ),
        (
            "endpoint-network-connection",
            {
                "sourcetype": "aegis:endpoint",
                "raw": {
                    "xdr": {
                        "schema": "aegis.endpoint.v1",
                        "data": {"event": {"action": "network_connection"}},
                    }
                },
            },
        ),
    ],
)
def test_atomic_conditions_match_real_normalized_source_and_reject_other_events(
    lab, identifier, event
):
    original = normalization.normalize(
        {
            "event_id": "starter",
            "source": "test",
            "host": "sample-host",
            "sourcetype": "json",
            **event,
        }
    )
    definition = starters.preview(lab, actor(), identifier, {"indexes": ["public"]})[
        "definition"
    ]
    assert intelligence._matches(
        {"event": original, "raw": original["raw"]}, definition["filters"]
    )
    assert not intelligence._matches(
        {"event": {"sourcetype": "unrelated"}, "raw": {}}, definition["filters"]
    )


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"indexes": ["*"]},
        {"indexes": []},
        {"indexes": ["public"], "enabled": 1},
        {"indexes": ["public"], "window": float("nan")},
        {"indexes": ["public"], "filters": []},
        {"indexes": ["public"], "ground_truth": "attack"},
        {"indexes": ["public"], "create_case": True},
    ],
)
def test_atomic_template_rejects_invalid_scope_or_caller_filter_replacement(lab, data):
    with pytest.raises(ValueError):
        starters.preview(lab, actor(), "authentication-failure", data)
    assert counts(lab)["intelligence_policies"] == 0


def test_current_principal_scope_and_viewer_preview(lab):
    assert starters.listing(lab, actor("reader", role="viewer"))["total"] == 8
    with pytest.raises(PermissionError):
        starters.preview(
            lab,
            actor("reader", role="viewer"),
            "authentication-failure",
            {"indexes": ["public"]},
        )
    access.set_for_user(lab, actor(), "owner", ["other"])
    with pytest.raises(PermissionError):
        starters.preview(
            lab, actor(), "authentication-failure", {"indexes": ["public"]}
        )
    with pytest.raises(KeyError):
        starters.preview(lab, actor(), "not-a-template", {"indexes": ["other"]})


def test_actual_reviewed_model_composite_preview_save_and_independent_review(
    lab, model
):
    parents = [parent_policy(lab, "A"), parent_policy(lab, "B")]
    data = bind(model, parents, enabled=True, create_case=True, join_on="flow")
    with pytest.raises(PermissionError, match="approval"):
        starters.preview(lab, actor(), "ml-with-two-atomics", data)
    cpu_ml.activate(
        lab,
        actor("peer"),
        model["id"],
        "Actual immutable training originals independently reviewed",
    )
    before = counts(lab)
    preview = starters.preview(lab, actor(), "ml-with-two-atomics", data)
    assert counts(lab) == before
    definition = preview["definition"]
    assert (
        definition["minimum_independent_groups"] == 3
        and definition["join_on"] == "flow"
    )
    assert definition["case_adapter"]["case_grouping"] == "require_exact_identity"
    assert "input_models" not in definition and "input_revisions" not in definition
    assert preview["bindings"]["model"]["digest"] == model["digest"]
    assert {row["id"] for row in preview["bindings"]["parents"]} == set(parents)
    saved = intelligence.save_policy(lab, actor(), definition)
    assert saved["state"] == "draft"
    actual = next(
        item
        for item in intelligence.policies(lab, actor())
        if item["id"] == saved["id"]
    )
    assert (
        actual["definition"]["input_models"][data["model_rule_id"]]["digest"]
        == model["digest"]
    )
    assert set(actual["definition"]["input_revisions"]) == set(parents)
    with pytest.raises(PermissionError):
        intelligence.review_policy(
            lab,
            actor(),
            saved["id"],
            {"version": 1, "approve": True, "reason": "Self approval rejected"},
        )
    assert (
        intelligence.review_policy(
            lab,
            actor("peer"),
            saved["id"],
            {
                "version": 1,
                "approve": True,
                "reason": "Independent original-scope review",
            },
        )["state"]
        == "active"
    )
    assert all(
        counts(lab)[table] == 0
        for table in (
            "intelligence_signals",
            "incidents",
            "endpoint_responses",
            "effect_receipts",
        )
    )
    cpu_ml.disable(lab, actor(), model["id"])
    with pytest.raises(PermissionError, match="approval"):
        starters.preview(lab, actor(), "ml-with-two-atomics", data)


@pytest.mark.parametrize(
    "change,error",
    [
        ("missing", KeyError),
        ("foreign", KeyError),
        ("draft", ConflictError),
        ("composite", ValueError),
        ("undeclared", PermissionError),
        ("revoked_owner", PermissionError),
        ("revoked_reviewer", PermissionError),
    ],
)
def test_composite_rejects_ineligible_current_parent(lab, model, change, error):
    cpu_ml.activate(
        lab, actor("peer"), model["id"], "Independent actual CPU model review"
    )
    parent = parent_policy(
        lab,
        indexes=["private"] if change == "undeclared" else None,
        review=change != "draft",
        kind="composite" if change == "composite" else "atomic",
    )
    who = actor()
    if change == "missing":
        parent = "not-present"
    elif change == "foreign":
        who = actor("foreign", "b")
        # A current tenant model cannot make a foreign parent's ID visible.
        with pytest.raises(KeyError):
            starters.preview(lab, who, "ml-with-one-atomic", bind(model, [parent]))
        return
    elif change.startswith("revoked"):
        access.set_for_user(
            lab,
            actor(),
            "parent" if change == "revoked_owner" else "reviewer",
            ["other"],
        )
    with pytest.raises(error):
        starters.preview(lab, who, "ml-with-one-atomic", bind(model, [parent]))


@pytest.mark.parametrize(
    "data",
    [
        {"indexes": ["public"], "model_rule_id": "ml:m", "parent_policy_ids": []},
        {
            "indexes": ["public"],
            "model_rule_id": "ml:m",
            "parent_policy_ids": ["p", "p"],
        },
        {
            "indexes": ["public"],
            "model_rule_id": "ml:m",
            "parent_policy_ids": ["p", "q", "r"],
        },
        {
            "indexes": ["public"],
            "model_rule_id": "broad-model-kind",
            "parent_policy_ids": ["p", "q"],
        },
        {
            "indexes": ["public"],
            "model_rule_id": "ml:m",
            "parent_policy_ids": ["p", "q"],
            "create_case": 1,
        },
        {
            "indexes": ["public"],
            "model_rule_id": "ml:m",
            "parent_policy_ids": ["p", "q"],
            "join_on": "arbitrary",
        },
        {
            "indexes": ["public"],
            "model_rule_id": "ml:m",
            "parent_policy_ids": ["p", "q"],
            "input_models": {},
        },
    ],
)
def test_composite_rejects_unbounded_or_ambiguous_bindings_before_model_lookup(
    lab, data
):
    with pytest.raises(ValueError):
        starters.preview(lab, actor(), "ml-with-two-atomics", data)


def test_real_sequence_model_approval_all_sources_and_reviewer_rechecked(tmp_path):
    if importlib.util.find_spec("torch") is None:
        pytest.skip("Optional CPU PyTorch unavailable")
    store = Store(Settings(tmp_path / "sequence", min_free_bytes=0))
    try:
        for name in ("trainer", "reviewer", "admin"):
            auth.create_user(
                store, name, "Starter-sequence-test-password-2026", "admin", "a"
            )
        who = actor("trainer")
        dataset = seed_dataset(store)
        model = cpu_sequence.train(store, who, {**dataset, "epochs": 1})
        assert model["status"] == "completed"
        parent = intelligence.save_policy(
            store,
            who,
            {
                "name": "Network context",
                "kind": "atomic",
                "indexes": ["public"],
                "enabled": True,
                "filters": [
                    {
                        "field": "raw.xdr.data.event.action",
                        "op": "eq",
                        "value": "network_connection",
                    }
                ],
            },
        )
        intelligence.review_policy(
            store,
            actor("admin"),
            parent["id"],
            {
                "version": 1,
                "approve": True,
                "reason": "Independent exact context review",
            },
        )
        body = {
            "indexes": ["public"],
            "model_rule_id": "ml:sequence:" + model["id"],
            "parent_policy_ids": [parent["id"]],
        }
        with pytest.raises(PermissionError):
            starters.preview(store, who, "ml-with-one-atomic", body)
        assert (
            cpu_sequence.evaluate(store, actor("reviewer"), model["id"])["status"]
            == "completed"
        )
        cpu_sequence.activate(
            store,
            actor("reviewer"),
            model["id"],
            "Independent actual GRU holdout and originals review",
        )
        preview = starters.preview(store, who, "ml-with-one-atomic", body)
        assert preview["bindings"]["model"]["model_family"] == "sequence"
        assert (
            preview["definition"]["case_adapter"] is None
            and not preview["definition"]["enabled"]
        )
        access.set_for_user(store, actor("admin"), "reviewer", ["other"])
        with pytest.raises(PermissionError, match="reviewer"):
            starters.preview(store, who, "ml-with-one-atomic", body)
        access.set_for_user(store, actor("admin"), "reviewer", ["public"])
        source = source_registry.listing(store, actor("admin"))[0]
        source_registry.revoke(store, actor("admin"), source["id"], source["version"])
        with pytest.raises(PermissionError, match="source"):
            starters.preview(store, who, "ml-with-one-atomic", body)
    finally:
        store.close()


def test_http_catalog_preview_csrf_role_and_no_install(client):  # noqa: F811 - shared HTTP fixture.
    route = "/api/v3/intelligence/templates"
    preview = route + "/authentication-failure/preview"
    assert client.get(route).status_code == 401
    assert client.post(preview, json={"indexes": ["public"]}).status_code == 401
    sign_in(client)
    result = client.get(route)
    assert result.status_code == 200 and result.json()["total"] == 8
    response = client.post(preview, json={"indexes": ["public"]})
    assert response.status_code == 200 and not response.json()["persisted"]
    assert counts(client.app.state.store)["intelligence_policies"] == 0
    assert (
        client.post(
            route + "/unknown/preview", json={"indexes": ["public"]}
        ).status_code
        == 404
    )
    csrf = client.headers.pop("X-CSRF-Token")
    assert client.post(preview, json={"indexes": ["public"]}).status_code == 403
    client.headers["X-CSRF-Token"] = csrf
    sign_in(client, name="viewer", role="viewer")
    assert client.get(route).status_code == 200
    assert client.post(preview, json={"indexes": ["public"]}).status_code == 403
