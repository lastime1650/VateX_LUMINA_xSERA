"""Original case evidence is pinned locally across tier movement and expiry."""

import json
import time

import pytest

from sapientia import casework
from sapientia import log_governance as governance
from sapientia.storage import ConflictError
from tests.test_casework import case as synthetic_case_fixture


@pytest.fixture
def case(tmp_path):
    yield from synthetic_case_fixture.__wrapped__(tmp_path)


def admin(actor):
    return {**actor, "name": "admin_a", "role": "admin"}


def get(case):
    store, actor, identifier = case
    return governance.get_case_hold(store, admin(actor), identifier)


def test_case_hold_includes_contributions_and_bookmarks_and_survives_retention(case):
    store, actor, identifier = case
    casework.bookmark(
        store,
        actor,
        identifier,
        {"event_id": "private-event", "label": "Supporting original"},
    )
    before = get(case)
    assert before["evidence_count"] == before["originals_available"] == 2
    assert before["held_count"] == 0 and before["unheld_current_evidence"] == 2
    held = governance.hold_case(
        store,
        admin(actor),
        identifier,
        {"version": before["version"], "reason": "Synthetic legal preservation"},
    )
    assert held["held_count"] == held["held_current_evidence"] == 2
    assert (
        held["complete"]
        and held["protects_future_evidence"] is False
        and held["immutable"] is False
    )
    assert held["version"] == before["version"] + 1
    now = time.time()
    store.segments.seal(now=now + 2 * 86400)
    assert store.retain(now + 100 * 86400) == 0
    assert store.search("a", {"query": "*"})["returned"] == 2
    released = governance.release_case_hold(
        store,
        admin(actor),
        identifier,
        {"version": held["version"], "reason": "Synthetic release authorized"},
    )
    assert released["released"] == 2 and released["version"] == held["version"] + 1
    # Releasing a legal hold does not authorize age deletion under the current
    # permanent/capacity policy. Pressure cleanup is a separate worker.
    assert store.retain(now + 100 * 86400) == 0
    status = get(case)
    assert status["held_count"] == 0 and status["missing_originals"] == 0
    assert status["originals_available"] == 2
    assert len(casework.export_case(store, actor, identifier)["bookmarks"]) == 1
    with store.control() as db:
        audits = {row[0] for row in db.execute("SELECT action FROM audit")}
    assert {"logs.case.hold", "logs.case.hold.release"} <= audits


def test_hold_requires_current_admin_complete_case_scope_and_version(case):
    store, actor, identifier = case
    casework.bookmark(
        store,
        actor,
        identifier,
        {"event_id": "private-event", "label": "Private original"},
    )
    version = get(case)["version"]
    data = {"version": version, "reason": "Synthetic hold"}
    with pytest.raises(PermissionError):
        governance.hold_case(store, actor, identifier, data)
    with pytest.raises(KeyError):
        governance.hold_case(
            store, {**admin(actor), "allowed_indexes": ["public"]}, identifier, data
        )
    with pytest.raises(KeyError):
        governance.get_case_hold(
            store,
            {
                "name": "outsider",
                "tenant": "b",
                "role": "analyst",
                "allowed_indexes": ["*"],
            },
            identifier,
        )
    with pytest.raises(ConflictError):
        governance.hold_case(
            store, admin(actor), identifier, {**data, "version": version + 1}
        )
    governance.hold_case(store, admin(actor), identifier, data)
    with pytest.raises(ConflictError):
        governance.release_case_hold(store, admin(actor), identifier, data)
    with store.control() as db:
        db.execute("UPDATE users SET disabled=1 WHERE name='admin_a'")
    with pytest.raises(PermissionError):
        governance.release_case_hold(
            store, admin(actor), identifier, {**data, "version": version + 1}
        )


@pytest.mark.parametrize("missing", ["original", "receipt"])
def test_missing_original_or_admission_receipt_rejects_all_holds(case, missing):
    store, actor, identifier = case
    casework.bookmark(
        store,
        actor,
        identifier,
        {"event_id": "private-event", "label": "Still available"},
    )
    version = get(case)["version"]
    if missing == "original":
        store.analytics.execute("DELETE FROM events WHERE event_id='case-event'")
    else:
        with store.control() as db:
            db.execute("DELETE FROM receipts WHERE event_id='case-event'")
    status = get(case)
    assert status["unavailable_originals"] == 1
    assert status["missing_originals"] == (1 if missing == "original" else 0)
    assert status["missing_receipts"] == (1 if missing == "receipt" else 0)
    with pytest.raises(ConflictError, match="no partial"):
        governance.hold_case(
            store,
            admin(actor),
            identifier,
            {"version": version, "reason": "Must be complete"},
        )
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM log_evidence_holds").fetchone()[0] == 0
        assert (
            db.execute(
                "SELECT version FROM incidents WHERE id=?", (identifier,)
            ).fetchone()[0]
            == version
        )


def test_full_large_evidence_population_preserves_atomic_missing_original_failure(case):
    store, actor, identifier = case
    with store.control() as db:
        db.execute(
            "UPDATE risk_contributions SET evidence=? WHERE incident_id=?",
            (
                json.dumps(
                    {"event_ids": [f"event-{number}" for number in range(5001)]}
                ),
                identifier,
            ),
        )
    with pytest.raises(ConflictError, match="no partial"):
        governance.hold_case(
            store, admin(actor), identifier, {"version": 1, "reason": "No truncation"}
        )
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM log_evidence_holds").fetchone()[0] == 0
    status=get(case)
    assert status["evidence_count"]==5001 and status["missing_originals"]==5001
    assert len(status["missing_event_ids"])==5001 and not status["missing_event_ids_truncated"]


def test_more_than_five_thousand_originals_can_be_held_completely(case):
    store,actor,identifier=case
    ids=["held-"+str(i) for i in range(5001)]
    for start in range(0,len(ids),1000):
        store.ingest("a",[{"event_id":i,"index":"public","host":"fixture"} for i in ids[start:start+1000]])
        store.flush(1000)
    with store.control() as db:
        db.execute("UPDATE risk_contributions SET evidence=? WHERE incident_id=?",(json.dumps({"event_ids":ids}),identifier))
    held=governance.hold_case(store,admin(actor),identifier,{"version":1,"reason":"Entire current evidence population"})
    assert held["evidence_count"]==held["held_count"]==5001 and held["complete"]
    assert held["limit"] is None


def test_new_bookmark_exposes_unheld_snapshot_and_refresh_pins_it(case):
    store, actor, identifier = case
    first = governance.hold_case(
        store, admin(actor), identifier, {"version": 1, "reason": "Initial snapshot"}
    )
    casework.bookmark(
        store,
        actor,
        identifier,
        {"event_id": "private-event", "label": "Later evidence"},
    )
    status = get(case)
    assert status["evidence_count"] == 2 and status["held_count"] == 1
    assert status["unheld_current_evidence"] == 1 and status["complete"] is False
    fresh = governance.hold_case(
        store,
        admin(actor),
        identifier,
        {"version": first["version"], "reason": "Review and refresh snapshot"},
    )
    assert fresh["complete"] and fresh["held_count"] == 2


@pytest.mark.parametrize(
    "data",
    [
        {},
        {"version": True, "reason": "No"},
        {"version": 1, "reason": " "},
        {"version": 1, "reason": "\ud800"},
        {"version": 1, "reason": "ok", "expires": 0},
    ],
)
def test_hold_input_is_strict(case, data):
    store, actor, identifier = case
    with pytest.raises(ValueError):
        governance.hold_case(store, admin(actor), identifier, data)


def test_hold_and_read_recheck_account_after_segment_lock_wait(case, monkeypatch):
    store, actor, identifier = case
    original = governance.principal.current

    def revoke(db, who, roles):
        db.execute("UPDATE users SET must_change=1 WHERE name='admin_a'")
        return original(db, who, roles)

    monkeypatch.setattr(governance.principal, "current", revoke)
    with pytest.raises(PermissionError):
        governance.hold_case(
            store,
            admin(actor),
            identifier,
            {"version": 1, "reason": "Cannot use stale identity"},
        )
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM log_evidence_holds").fetchone()[0] == 0
