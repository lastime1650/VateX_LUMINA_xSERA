import copy
import json
import time

import pytest

from sapientia import access, auth, connector_runtime, principal, source_registry
from sapientia import online_analytics as online
from sapientia.storage import ConflictError, Settings, Store


def actor(name="admin", tenant="a", role="admin"):
    return {"name": name, "tenant": tenant, "role": role, "allowed_indexes": ["*"]}


def event(i, shift=False):
    data = {
        "host": {"id": "online-device", "boot_id": "online-boot"},
        "event": {"action": "network_connect" if shift else "process_start"},
        "process": {
            "name": "n" * 128 if shift else "editor",
            "command_line": "X " * 1024 if shift else "editor document.txt",
        },
        "destination": {
            "ip": "8.8.8.8" if shift else "10.0.0.1",
            "port": 65535 if shift else 0,
        },
        "network": {"protocol": "tcp"} if shift else {},
        "file": {"path": "x" * 512 if shift else ""},
    }
    return {
        "event_id": f"online-{i}",
        "index": "public",
        "event_time": 1700000000 + i,
        "host": "online-host",
        "raw": {"xdr": {"data": data}},
    }


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    for name, tenant, role in [
        ("admin", "a", "admin"),
        ("reviewer", "a", "admin"),
        ("viewer", "a", "viewer"),
        ("foreign", "b", "admin"),
    ]:
        auth.create_user(
            value, name, "Online-model-fixture-password-2026", role, tenant
        )
    yield value
    value.close()


def deliver(store, source, events):
    with store.control() as db:
        old = db.execute(
            "SELECT version FROM connector_checkpoints WHERE source_id=?", (source,)
        ).fetchone()
        version = old[0] if old else 0
    connector_runtime.intake(
        store,
        actor(),
        source,
        {
            "version": 1,
            "events": events,
            "cursor": "batch-" + str(version),
            "checkpoint_version": version,
        },
    )
    while store.flush():
        pass


@pytest.fixture
def model(store):
    source = source_registry.save(
        store,
        actor(),
        {
            "index": "public",
            "product": "json",
            "account": "online-source",
            "realm": "virtual-lab",
            "credential_ref": "env:SAPIENTIA_CONNECTOR_ONLINE_TEST",
            "version": 0,
        },
    )
    deliver(store, source["id"], [event(i) for i in range(32)])
    model = online.train(
        store,
        actor(),
        {
            "name": "Reviewed normal CPU baseline",
            "indexes": ["public"],
            "normal_event_ids": [f"online-{i}" for i in range(32)],
        },
    )
    assert model["state"] == "pending_review"
    with pytest.raises(PermissionError):
        online.review(
            store,
            actor(),
            model["id"],
            {
                "expected_revision": 1,
                "approve": True,
                "reason": "Cannot self approve normal baseline",
            },
        )
    online.review(
        store,
        actor("reviewer"),
        model["id"],
        {
            "expected_revision": 1,
            "approve": True,
            "reason": "Independent review of all selected normal source originals",
        },
    )
    return model, source["id"]


def test_real_river_scores_and_adwin_drift_without_live_training_or_device_actions(
    store, model
):
    _baseline, source = model
    with store.control() as db:
        before = db.execute(
            "SELECT body,digest FROM online_analytics_models"
        ).fetchone()
    deliver(store, source, [event(100), event(101, True)])
    result = online.run_due(store)["runs"][0]
    assert result["status"] == "completed" and result["scores"][1] > result["scores"][0]
    assert (
        result["anomaly"] and result["signal_id"] and not result["automatic_training"]
    )
    with store.control() as db:
        after = db.execute("SELECT body,digest FROM online_analytics_models").fetchone()
        assert tuple(after) == tuple(before)
        signal = json.loads(
            db.execute(
                "SELECT body FROM intelligence_signals WHERE id=?",
                (result["signal_id"],),
            ).fetchone()[0]
        )
        fresh = principal.current(db, actor())
        assert online.validate_parent(store, db, fresh, signal)
        forged = copy.deepcopy(signal)
        forged["features"]["online_anomaly_score"] = 0
        assert not online.validate_parent(store, db, fresh, forged)
        for malformed in (None, [], 3, "bad"):
            forged = copy.deepcopy(signal)
            forged["metadata"] = malformed
            assert not online.validate_parent(store, db, fresh, forged)
        assert db.execute("SELECT count(*) FROM endpoint_responses").fetchone()[0] == 0
    drift, history = online.drift_scores([0.0] * 128, [1.0] * 64)
    assert drift and len(history) <= 512


def test_automatic_outbox_exactly_once_and_duplicate_review_does_not_skip_pending(
    store, model
):
    baseline, source = model
    deliver(store, source, [event(100)])
    with store.control() as db:
        before = tuple(
            db.execute("SELECT cursor,scores FROM online_analytics_state").fetchone()
        )
    result = online.review(
        store,
        actor("reviewer"),
        baseline["id"],
        {
            "expected_revision": 1,
            "approve": True,
            "reason": "Retry the same completed baseline review",
        },
    )
    assert result["duplicate"]
    with store.control() as db:
        assert (
            tuple(
                db.execute(
                    "SELECT cursor,scores FROM online_analytics_state"
                ).fetchone()
            )
            == before
        )
    assert online.run_due(store)["processed"] == 1
    assert online.run_due(store)["processed"] == 0


def test_source_revocation_and_current_permissions_invalidate_model(store, model):
    baseline, source = model
    deliver(store, source, [event(100, True)])
    source_registry.revoke(store, actor(), source, 1)
    with pytest.raises(PermissionError):
        online.analyze(
            store, actor(), {"model_id": baseline["id"], "event_ids": ["online-100"]}
        )
    assert online.run_due(store)["processed"] == 0
    assert online.list_models(store, actor("foreign", "b"))["items"] == []
    access.set_for_user(store, actor(), "viewer", ["private"])
    assert not online.list_models(store, actor("viewer", role="viewer"))["items"]


def test_retired_model_is_terminal_and_originals_are_not_deleted(store, model):
    baseline, _source = model
    ids = ["online-0", "online-1"]
    with store.control() as db:
        count = db.execute("SELECT count(*) FROM receipts").fetchone()[0]
        assert online.protected_ids(db, "a", ids) == set(ids)
    online.retire(
        store,
        actor(),
        baseline["id"],
        "Retire approved baseline while preserving run history",
    )
    with pytest.raises(ConflictError, match="Retired"):
        online.review(
            store,
            actor("reviewer"),
            baseline["id"],
            {
                "expected_revision": 1,
                "approve": True,
                "reason": "Retired models cannot be reactivated",
            },
        )
    with store.control() as db:
        assert online.protected_ids(db, "a", ids) == set()
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == count


def test_generic_unregistered_normal_data_cannot_activate_baseline(store):
    store.ingest("a", [event(i) for i in range(16)])
    store.flush()
    with pytest.raises(PermissionError, match="Authenticated"):
        online.train(
            store,
            actor(),
            {
                "name": "untrusted normal",
                "indexes": ["public"],
                "normal_event_ids": [f"online-{i}" for i in range(16)],
            },
        )


def test_feature_contract_excludes_labels_and_ids():
    original = event(1)
    tampered = copy.deepcopy(original)
    tampered["event_id"] = "other"
    tampered["raw"].update(label="malicious", scenario_id="attack", ground_truth=True)
    assert online.features(original) == online.features(tampered)


def test_manual_replay_is_shadow_and_cannot_poison_live_drift_history(store, model):
    baseline, source = model
    deliver(store, source, [event(100, True)])
    with store.control() as db:
        before = tuple(
            db.execute("SELECT cursor,scores FROM online_analytics_state").fetchone()
        )
    for _ in range(3):
        run = online.analyze(
            store, actor(), {"model_id": baseline["id"], "event_ids": ["online-100"]}
        )
        assert run["mode"] == "shadow" and run["signal_id"] is None
    with store.control() as db:
        assert (
            tuple(
                db.execute(
                    "SELECT cursor,scores FROM online_analytics_state"
                ).fetchone()
            )
            == before
        )
    assert online.run_due(store)["processed"] == 1


def test_generic_poison_is_durably_excluded_and_later_source_original_progresses(
    store, model
):
    _baseline, source = model
    store.ingest("a", [event(99, True)])
    while store.flush():
        pass
    deliver(store, source, [event(100, True)])
    assert online.run_due(store)["processed"] == 0
    runs = online.list_runs(store, actor())["items"]
    excluded = [r for r in runs if r["status"] == "excluded"]
    assert len(excluded) == 1 and excluded[0]["event_ids"] == ["online-99"]
    assert excluded[0]["signal_id"] is None
    with store.control() as db:
        assert (
            json.loads(
                db.execute("SELECT scores FROM online_analytics_state").fetchone()[0]
            )
            == []
        )
    assert online.run_due(store)["processed"] == 1
    assert online.run_due(store)["processed"] == 0
    assert online.list_models(store, actor())["items"][0]["state"] == "active"


def test_legal_hold_preserves_normal_details_then_release_compacts_only_details(
    store, model
):
    baseline, source = model
    deliver(store, source, [event(100)])
    original = online.analyze(
        store, actor(), {"model_id": baseline["id"], "event_ids": ["online-100"]}
    )
    assert not original["anomaly"]
    with store.control() as db:
        for i in range(140):
            run = {
                **original,
                "id": "retention-fixture-" + str(i),
                "created": time.time() - 1000 - i,
            }
            db.execute(
                "INSERT INTO online_analytics_runs VALUES(?,?,?,?,?,0,0,?,?,0)",
                (
                    run["id"],
                    "a",
                    baseline["id"],
                    json.dumps(["public"]),
                    run["created"],
                    json.dumps(run),
                    online._hash(run),
                ),
            )
        db.execute("INSERT OR REPLACE INTO policies VALUES('a',30,1)")
        receipt_count = db.execute("SELECT count(*) FROM receipts").fetchone()[0]
    online.analyze(
        store, actor(), {"model_id": baseline["id"], "event_ids": ["online-100"]}
    )
    with store.control() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM online_analytics_runs WHERE compact=1"
            ).fetchone()[0]
            == 0
        )
        db.execute("UPDATE policies SET hold=0 WHERE tenant='a'")
    online.analyze(
        store, actor(), {"model_id": baseline["id"], "event_ids": ["online-100"]}
    )
    with store.control() as db:
        compact = json.loads(
            db.execute(
                "SELECT body FROM online_analytics_runs WHERE compact=1 LIMIT 1"
            ).fetchone()[0]
        )
        assert (
            compact["full_run_digest"]
            and compact["score_summary"]
            and "scores" not in compact
        )
        assert compact["event_ids"] == ["online-100"]
        assert (
            db.execute("SELECT count(*) FROM receipts").fetchone()[0] == receipt_count
        )
