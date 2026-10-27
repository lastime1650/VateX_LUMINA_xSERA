"""Runtime source authority remains independent of a valid normal baseline."""

import copy
import json

import pytest

from sapientia import access, auth, intelligence, principal, source_registry
from sapientia import online_analytics as online
from tests import test_online_analytics as fixtures

actor, event, deliver = fixtures.actor, fixtures.event, fixtures.deliver
store, model = fixtures.store, fixtures.model


@pytest.fixture
def runtime_signal(store, model):
    baseline, normal_source = model
    auth.create_user(
        store,
        "runtime_owner",
        "Runtime-source-fixture-password-2026",
        "admin",
        "a",
    )
    runtime_source = source_registry.save(
        store,
        actor("runtime_owner"),
        {
            "index": "public",
            "product": "json",
            "account": "runtime-source",
            "realm": "virtual-lab",
            "credential_ref": "env:SAPIENTIA_CONNECTOR_RUNTIME_TEST",
            "version": 0,
        },
    )
    assert normal_source != runtime_source["id"]
    deliver(store, runtime_source["id"], [event(100, True)])
    result = online.run_due(store)["runs"][0]
    assert result["mode"] == "live" and result["anomaly"] and result["signal_id"]
    with store.control() as db:
        signal = json.loads(
            db.execute(
                "SELECT body FROM intelligence_signals WHERE id=?",
                (result["signal_id"],),
            ).fetchone()[0]
        )
        fresh = principal.current(db, actor())
        assert online.validate_parent(store, db, fresh, signal)
        assert intelligence._parent_valid(
            store, db, fresh, signal, {"indexes": ["public"]}
        )
    return baseline, runtime_source, signal


@pytest.mark.parametrize(
    "change", ["scope", "disabled", "role", "deleted", "source_revoked"]
)
def test_runtime_source_revalidation_does_not_rely_on_training_source(
    store, runtime_signal, change
):
    baseline, runtime_source, signal = runtime_signal
    if change == "scope":
        access.set_for_user(store, actor(), "runtime_owner", ["private"])
    elif change == "source_revoked":
        source_registry.revoke(store, actor(), runtime_source["id"], 1)
    else:
        with principal.transaction(store, actor(), write=True) as (db, _fresh):
            if change == "disabled":
                db.execute("UPDATE users SET disabled=1 WHERE name='runtime_owner'")
            elif change == "role":
                db.execute("UPDATE users SET role='viewer' WHERE name='runtime_owner'")
            else:
                db.execute("DELETE FROM users WHERE name='runtime_owner'")
    with store.control() as db:
        fresh = principal.current(db, actor())
        # Source A and its independently reviewed normal model are still valid.
        assert (
            online._model(db, fresh, baseline["id"], active=True)[0]["id"]
            == baseline["id"]
        )
        # Source B must be checked again before a saved finding can join a Case.
        assert not online.validate_parent(store, db, fresh, signal)
        assert not intelligence._parent_valid(
            store, db, fresh, signal, {"indexes": ["public"]}
        )


@pytest.mark.parametrize("change", ["digest", "received", "missing_source_receipt"])
def test_runtime_original_receipt_is_revalidated(store, runtime_signal, change):
    baseline, _runtime_source, signal = runtime_signal
    with principal.transaction(store, actor(), write=True) as (db, fresh):
        if change == "digest":
            db.execute(
                "UPDATE receipts SET digest=? WHERE tenant='a' AND event_id='online-100'",
                ("0" * 64,),
            )
        elif change == "received":
            db.execute(
                "UPDATE receipts SET received=received+1 WHERE tenant='a' AND event_id='online-100'"
            )
        else:
            db.execute(
                "DELETE FROM source_event_receipts WHERE tenant='a' AND event_id='online-100'"
            )
        assert (
            online._model(db, fresh, baseline["id"], active=True)[0]["id"]
            == baseline["id"]
        )
        assert not online.validate_parent(store, db, fresh, signal)
        assert not intelligence._parent_valid(
            store, db, fresh, signal, {"indexes": ["public"]}
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [("kind", "ml"), ("kind", "atomic"), ("mode", "shadow"), ("mode", None)],
)
def test_runtime_signal_kind_and_mode_are_exact(store, runtime_signal, field, value):
    _baseline, _runtime_source, signal = runtime_signal
    forged = copy.deepcopy(signal)
    forged[field] = value
    with store.control() as db:
        fresh = principal.current(db, actor())
        assert online.validate_parent(store, db, fresh, signal)
        assert not online.validate_parent(store, db, fresh, forged)
        assert not intelligence._parent_valid(
            store, db, fresh, forged, {"indexes": ["public"]}
        )
