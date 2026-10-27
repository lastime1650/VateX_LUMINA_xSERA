import copy
import json
import time

import pytest

from sapientia import access, auth, content, detections
from sapientia.storage import ConflictError, Settings, Store


@pytest.fixture
def lab(tmp_path):
    store = Store(Settings(tmp_path, min_free_bytes=0))
    content.initialize(store)
    for name, tenant, role in [
        ("admin_a", "a", "admin"),
        ("analyst_a", "a", "analyst"),
        ("viewer_a", "a", "viewer"),
        ("admin_b", "b", "admin"),
    ]:
        auth.create_user(
            store, name, "Synthetic-content-fixture-password", role, tenant
        )
    actor = {
        "name": "admin_a",
        "tenant": "a",
        "role": "admin",
        "allowed_indexes": ["*"],
    }
    yield store, actor
    store.close()


def package():
    now = time.time()

    def event(action, at, user="alice"):
        return {
            "event_time": at,
            "source": "fixture",
            "sourcetype": "lab_auth",
            "raw": {"user": user, "action": action},
        }

    return {
        "schema_version": 1,
        "name": "auth-sequence",
        "title": "Failed then successful authentication",
        "prerequisites": {
            "indexes": ["public"],
            "sources": [
                {
                    "category": "authentication",
                    "sourcetypes": ["lab_auth"],
                    "required_fields": ["raw.security.user", "raw.security.action"],
                }
            ],
        },
        "rules": [
            {
                "key": "failed-success",
                "policy": {
                    "name": "Failure then success",
                    "entity_field": "raw.security.user",
                    "window": 300,
                    "risk_score": 40,
                    "mitre": ["T1078"],
                    "steps": [
                        {
                            "name": "Failure",
                            "filters": [
                                {
                                    "field": "raw.action",
                                    "op": "eq",
                                    "value": "login_failed",
                                }
                            ],
                        },
                        {
                            "name": "Success",
                            "filters": [
                                {
                                    "field": "raw.action",
                                    "op": "eq",
                                    "value": "login_success",
                                }
                            ],
                        },
                    ],
                },
            }
        ],
        "fixtures": [
            {
                "name": "ordered",
                "end": now,
                "events": [
                    event("login_failed", now - 30),
                    event("login_success", now - 20),
                ],
                "expect": {"failed-success": ["alice"]},
            },
            {
                "name": "reversed",
                "end": now,
                "events": [
                    event("login_success", now - 30),
                    event("login_failed", now - 20),
                ],
                "expect": {"failed-success": []},
            },
        ],
    }


def prepare(store, actor, body=None):
    body = body or package()
    saved = content.save(store, actor, body)
    assert content.test(store, actor, body["name"], saved["revision"])["passed"]
    return body, saved


def source_events(store, body, tenant="a", index="public", user=None):
    events = copy.deepcopy(body["fixtures"][0]["events"])
    for i, event in enumerate(events):
        event["event_id"] = f"live-{tenant}-{index}-{user or 'alice'}-{i}"
        event["index"] = index
        if user:
            event["raw"]["user"] = user
    store.ingest(tenant, events)
    store.flush()


def test_fixture_executes_actual_ordered_query_without_ingesting(lab):
    store, actor = lab
    body, saved = prepare(store, actor)
    assert content.get(store, actor, body["name"])["state"] == "tested"
    assert store.search(
        "a", {"language": "spl", "query": "stats count"}, allowed_indexes=["*"]
    )["rows"] == [{"count": 0}]
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM queue").fetchone()[0] == 0
        assert (
            db.execute("SELECT count(*) FROM correlation_policies").fetchone()[0] == 0
        )
    exported = content.export_package(store, actor, body["name"])
    dry = content.dry_run(store, actor, exported["package"])
    assert dry["revision"] == saved["revision"] and not dry["changed"]
    assert content.list_for(store, actor)[0]["mitre"] == ["T1078"]


@pytest.mark.parametrize("sealed", [False, True])
def test_fixture_relation_is_isolated_from_matching_live_hot_and_sealed_data(lab, sealed):
    store, actor = lab
    body = package()
    source_events(store, body, user="live-only-user")
    if sealed:
        assert store.segments.seal(now=time.time()+2*86400)["sealed_events"] == 2
    saved = content.save(store, actor, body)
    result = content.test(store, actor, body["name"], saved["revision"])
    assert result["passed"]
    assert [assertion["observed"] for assertion in result["assertions"]] == [["alice"], []]
    assert store.search("a", {"query": '* | stats count by raw.security.user'})["rows"] == [
        {"raw.security.user": "live-only-user", "count": 2}
    ]


def test_publish_requires_exact_passing_test_and_live_source_fields(lab):
    store, actor = lab
    body = package()
    saved = content.save(store, actor, body)
    assert not content.coverage(store, actor, body["name"])["ready"]
    with pytest.raises(ValueError, match="prerequisites"):
        content.publish(store, actor, body["name"], saved["revision"])
    source_events(store, body)
    assert content.coverage(store, actor, body["name"])["ready"]
    with pytest.raises(ValueError, match="passing fixture"):
        content.publish(store, actor, body["name"], saved["revision"])
    assert content.test(store, actor, body["name"])["passed"]
    assert (
        content.publish(store, actor, body["name"], saved["revision"])["state"]
        == "active"
    )


def test_failed_fixture_cannot_publish(lab):
    store, actor = lab
    body = package()
    body["fixtures"][0]["expect"]["failed-success"] = ["incorrect-user"]
    saved = content.save(store, actor, body)
    result = content.test(store, actor, body["name"])
    assert not result["passed"] and result["assertions"][0]["observed"] == ["alice"]
    source_events(store, body)
    with pytest.raises(ValueError, match="passing fixture"):
        content.publish(store, actor, body["name"], saved["revision"])


def test_publish_runs_real_policy_with_scope_and_rollback_restores_definition(lab):
    store, actor = lab
    body, first = prepare(store, actor)
    source_events(store, body)
    source_events(store, body, index="private", user="secret-user")
    active = content.publish(store, actor, body["name"], first["revision"])
    assert detections.run_due(store, time.time() + 1, budget=2) == 1
    risks = detections.entity_risk(store, actor)
    assert [r["entity"] for r in risks] == ["alice"]
    current = content.get(store, actor, body["name"])
    changed = copy.deepcopy(body)
    changed["rules"][0]["policy"]["risk_score"] = 90
    second = content.save(store, actor, changed, expected_version=current["version"])
    assert second["revision"] != first["revision"]
    content.test(store, actor, body["name"])
    updated = content.publish(
        store,
        actor,
        body["name"],
        second["revision"],
        expected_active=first["revision"],
    )
    assert updated["policy_ids"] == active["policy_ids"]
    with pytest.raises(ConflictError):
        content.rollback(
            store,
            actor,
            body["name"],
            first["revision"],
            expected_active=first["revision"],
        )
    content.rollback(
        store,
        actor,
        body["name"],
        first["revision"],
        expected_active=second["revision"],
    )
    with store.control() as db:
        policy = json.loads(
            db.execute(
                "SELECT definition FROM correlation_policies WHERE id=?",
                (active["policy_ids"][0],),
            ).fetchone()[0]
        )
        assert policy["risk_score"] == 40
        assert all(
            step["filters"][-1] == {"field": "index", "op": "eq", "value": "public"}
            for step in policy["steps"]
        )
        assert (
            db.execute(
                "SELECT count(*) FROM audit WHERE action='content.rollback'"
            ).fetchone()[0]
            == 1
        )


def test_rollout_policy_changes_and_audit_are_one_transaction(lab, monkeypatch):
    store, actor = lab
    body, saved = prepare(store, actor)
    source_events(store, body)
    audit = store.audit

    def fail(db, tenant, name, action, detail):
        if action == "content.publish":
            raise RuntimeError("Synthetic audit write failure")
        audit(db, tenant, name, action, detail)

    monkeypatch.setattr(store, "audit", fail)
    with pytest.raises(RuntimeError, match="Synthetic"):
        content.publish(store, actor, body["name"], saved["revision"])
    with store.control() as db:
        assert (
            db.execute("SELECT count(*) FROM correlation_policies").fetchone()[0] == 0
        )
        assert db.execute("SELECT count(*) FROM content_policy_map").fetchone()[0] == 0
        assert (
            db.execute("SELECT active_revision FROM content_packages").fetchone()[0]
            is None
        )


def test_scope_and_current_account_enforced_on_every_path(lab):
    store, actor = lab
    body, saved = prepare(store, actor)
    restricted = {
        "name": "analyst_a",
        "tenant": "a",
        "role": "analyst",
        "allowed_indexes": ["*"],
    }
    access.set_for_user(store, actor, "analyst_a", ["private"])
    assert content.list_for(store, restricted) == []
    for operation in [
        lambda: content.get(store, restricted, body["name"]),
        lambda: content.test(store, restricted, body["name"]),
        lambda: content.export_package(store, restricted, body["name"]),
        lambda: content.dry_run(store, restricted, body),
    ]:
        with pytest.raises(PermissionError):
            operation()
    outsider = {"name": "admin_b", "tenant": "b", "role": "admin"}
    with pytest.raises(KeyError, match="unavailable"):
        content.get(store, outsider, body["name"], saved["revision"])
    with store.write_lock, store.control() as db:
        db.execute("UPDATE users SET disabled=1 WHERE name='admin_a'")
    with pytest.raises(PermissionError):
        content.get(store, actor, body["name"])


def test_save_version_and_revision_checksum_protect_immutability(lab):
    store, actor = lab
    body, saved = prepare(store, actor)
    with pytest.raises(ValueError, match="SHA256"):
        content.get(store, actor, body["name"], "invalid-revision")
    with pytest.raises(KeyError):
        content.get(store, actor, body["name"], "0" * 64)
    with pytest.raises(ConflictError):
        content.save(store, actor, body)
    again = content.save(store, actor, body, expected_version=saved["version"])
    assert again["revision"] == saved["revision"]
    assert again["state"] == "tested"
    with store.write_lock, store.control() as db:
        db.execute(
            "UPDATE content_revisions SET payload=replace(payload,'Failure then success','Tampered policy')"
        )
    with pytest.raises(ConflictError, match="checksum"):
        content.get(store, actor, body["name"])


def test_existing_package_scope_cannot_be_replaced_by_restricted_editor(lab):
    store, actor = lab
    body, saved = prepare(store, actor)
    changed = copy.deepcopy(body)
    changed["prerequisites"]["indexes"] = ["private"]
    for fixture in changed["fixtures"]:
        for event in fixture["events"]:
            event["index"] = "private"
    editor = {"name": "analyst_a", "tenant": "a", "role": "analyst"}
    access.set_for_user(store, actor, "analyst_a", ["private"])
    with pytest.raises(PermissionError):
        content.save(store, editor, changed, expected_version=saved["version"])
    with pytest.raises(ConflictError, match="immutable"):
        content.save(store, actor, changed, expected_version=saved["version"])


def test_rollback_requires_real_prior_rollout_and_admin(lab):
    store, actor = lab
    body, saved = prepare(store, actor)
    source_events(store, body)
    with pytest.raises(ValueError, match="previously activated"):
        content.rollback(store, actor, body["name"], saved["revision"])
    analyst = {"name": "analyst_a", "tenant": "a", "role": "analyst"}
    with pytest.raises(PermissionError):
        content.publish(store, analyst, body["name"], saved["revision"])
    with store.write_lock, store.control() as db:
        db.execute("UPDATE users SET role='analyst' WHERE name='admin_a'")
    with pytest.raises(PermissionError):
        content.publish(store, actor, body["name"], saved["revision"])


@pytest.mark.parametrize(
    "change",
    [
        lambda b: b["prerequisites"].update(indexes=["*"]),
        lambda b: b["prerequisites"].update(indexes=["public", "private"]),
        lambda b: b["fixtures"][1].update(expect={"failed-success": ["alice"]}),
        lambda b: b["fixtures"][0]["events"][0].update(index="private"),
        lambda b: b["fixtures"][0]["events"][0].pop("event_time"),
        lambda b: b["prerequisites"]["sources"][0].update(
            required_fields=["raw; DROP TABLE events"]
        ),
        lambda b: b["rules"][0]["policy"]["steps"][0].update(
            filters=[{"field": "host", "op": "eq", "value": "x"}] * 20
        ),
    ],
)
def test_invalid_packages_fail_explicitly(change):
    body = package()
    change(body)
    with pytest.raises(ValueError):
        content.validate(body)


def test_permission_change_during_fixture_test_prevents_persist(lab, monkeypatch):
    store, actor = lab
    body = package()
    saved = content.save(store, actor, body)
    original = store.analytics_query
    changed = False

    def query(*args, **kwargs):
        nonlocal changed
        result = original(*args, **kwargs)
        if not changed:
            changed = True
            with store.write_lock, store.control() as db:
                db.execute(
                    "UPDATE user_index_access SET allowed_indexes='[]' WHERE name='admin_a'"
                )
                if not db.execute(
                    "SELECT 1 FROM user_index_access WHERE name='admin_a'"
                ).fetchone():
                    db.execute(
                        "INSERT INTO user_index_access VALUES('a','admin_a','[]')"
                    )
        return result

    monkeypatch.setattr(store, "analytics_query", query)
    with pytest.raises(PermissionError):
        content.test(store, actor, body["name"], saved["revision"])
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM content_tests").fetchone()[0] == 0
