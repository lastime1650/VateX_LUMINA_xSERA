"""Exact-transaction raw reuse preserves current authority and atomic replay."""
import json
import time

import pytest

from sapientia import evidence_scope
from sapientia import intelligence as core
from sapientia.storage import Store
from tests.test_backend_upgrade import actor
from tests.test_backend_upgrade import lab as _backend_lab
from tests.test_intelligence import composites, policy, seed

lab = _backend_lab


def prepared(store):
    first, _ = policy(store, "A")
    second, _ = policy(store, "B")
    source, _ = seed(store, stages=("A", "B"))
    assert core._outbox(store, maximum=32) == 2
    child = composites(store, "Reusable exact originals", [{"rule_id": first["id"]}, {"rule_id": second["id"]}], case_adapter={"entity_field": "host", "risk_score": 60, "severity": "high", "mitre": [], "cooldown": 0})
    return child, source


def counts(store, identifier):
    with store.control() as db:
        return (
            db.execute("SELECT count(*) FROM intelligence_signals WHERE rule_id=?", (identifier,)).fetchone()[0],
            db.execute("SELECT count(*) FROM risk_contributions WHERE policy_id=?", ("intelligence:" + identifier + ":1",)).fetchone()[0],
        )


def test_composite_publication_and_case_share_one_raw_fetch_and_exact_memo(lab, monkeypatch, record_property):
    child, _ = prepared(lab)
    queries, calls = [], []
    original_query, original_publish, original_case = lab.analytics_query, core.publish_in_transaction, core._case

    def query(*args, **kwargs):
        queries.append(args[0])
        return original_query(*args, **kwargs)

    def publish(store, db, who, data, *, memo=None):
        assert db.in_transaction and memo is not None
        calls.append(("publish", id(db), id(memo), who))
        return original_publish(store, db, who, data, memo=memo)

    def case(store, db, who, *args, memo=None):
        assert db.in_transaction and memo is not None
        calls.append(("case", id(db), id(memo), who))
        return original_case(store, db, who, *args, memo=memo)

    monkeypatch.setattr(lab, "analytics_query", query)
    monkeypatch.setattr(core, "publish_in_transaction", publish)
    monkeypatch.setattr(core, "_case", case)
    assert core._composites(lab, deadline=time.monotonic()+2) == 1
    assert len(queries) == 1 and counts(lab, child["id"]) == (1, 1)
    assert [item[0] for item in calls] == ["publish", "case"]
    assert calls[0][1:] == calls[1][1:]
    evidence_scope.originals(lab, actor(), ["event-0", "event-1"])
    assert len(queries) == 2  # The completed transaction grants no reuse.
    assert core._composites(lab) == 0
    record_property("composite_reuse_proof", json.dumps({"raw_queries_for_composite_and_case": 1, "composite_signals": 1, "case_contributions": 1, "same_db_actor_memo": True, "fresh_raw_query_after_transaction": True, "host_effects": 0}))


@pytest.mark.parametrize("change", ["receipt", "source", "source_receipt", "caller", "scope", "source_owner"])
def test_changed_authority_between_signal_and_case_rolls_back_entire_composite(lab, monkeypatch, change):
    child, source = prepared(lab)
    original_case = core._case

    def changed(store, db, who, *args, memo=None):
        if change == "receipt":
            db.execute("UPDATE receipts SET digest='changed' WHERE tenant='a' AND event_id='event-1'")
        elif change == "source":
            db.execute("UPDATE source_registry SET state='revoked' WHERE id=?", (source["id"],))
        elif change == "source_receipt":
            db.execute("UPDATE source_event_receipts SET source_version=999 WHERE tenant='a' AND event_id='event-1'")
        elif change == "caller":
            db.execute("UPDATE users SET disabled=1 WHERE tenant='a' AND name='owner'")
        elif change == "scope":
            db.execute("INSERT OR REPLACE INTO user_index_access VALUES('a','owner','[\"private\"]')")
        else:
            db.execute("UPDATE source_registry SET owner='peer' WHERE id=?", (source["id"],))
            db.execute("UPDATE users SET disabled=1 WHERE tenant='a' AND name='peer'")
        return original_case(store, db, who, *args, memo=memo)

    with monkeypatch.context() as patch:
        patch.setattr(core, "_case", changed)
        assert core._composites(lab) == 0
    assert counts(lab, child["id"]) == (0, 0)
    # The failed TX also rolls back its transient tamper and durable cohort
    # progress, so the next turn retries real current evidence successfully.
    assert core._composites(lab) == 1
    assert counts(lab, child["id"]) == (1, 1)


def test_other_actor_does_not_reuse_composite_owner_raw_facts(lab, monkeypatch):
    child, _ = prepared(lab)
    original_query, original_case = lab.analytics_query, core._case
    queries = []

    def query(*args, **kwargs):
        queries.append(args[0])
        return original_query(*args, **kwargs)

    def case(store, db, who, *args, memo=None):
        assert evidence_scope.originals(store, actor("peer"), ["event-0", "event-1"])
        with pytest.raises(KeyError):
            evidence_scope.originals(store, actor("foreign", "b"), ["event-0"])
        return original_case(store, db, who, *args, memo=memo)

    monkeypatch.setattr(lab, "analytics_query", query)
    monkeypatch.setattr(core, "_case", case)
    assert core._composites(lab) == 1
    assert len(queries) == 3 and counts(lab, child["id"]) == (1, 1)


def test_crash_after_case_write_rolls_back_and_replays_once_after_restart(lab, monkeypatch):
    child, _ = prepared(lab)
    original_case = core._case

    def crash(*args, **kwargs):
        outcome = original_case(*args, **kwargs)
        assert outcome["emitted"] == 1
        raise RuntimeError("Simulated interruption before reserved TX commit")

    with monkeypatch.context() as patch:
        patch.setattr(core, "_case", crash)
        with pytest.raises(RuntimeError, match="Simulated interruption"):
            core._composites(lab)
    assert counts(lab, child["id"]) == (0, 0)
    settings = lab.settings
    lab.close()
    reopened = Store(settings)
    try:
        assert core._composites(reopened) == 1
        assert core._composites(reopened) == 0
        assert counts(reopened, child["id"]) == (1, 1)
    finally:
        reopened.close()
