"""Internal bulk reads retain public bounds and fresh transactional authority."""

import copy
import json

import pytest

from sapientia import connector_runtime, evidence_scope, principal
from sapientia.storage import ConflictError
from tests.test_backend_upgrade import actor
from tests.test_backend_upgrade import lab as _lab_fixture
from tests.test_intelligence import seed

lab = _lab_fixture


@pytest.fixture(autouse=True)
def owned_low_disk_reserve(lab):
    # Only this task-owned Store, so CI disk occupancy cannot prevent telemetry.
    with lab.control() as db:
        db.execute("UPDATE record_management_policy SET definition=json_set(definition,'$.min_free_percent',1) WHERE singleton=1")


def test_many_one_query_has_exact_singleton_parity_and_public_bound(lab, monkeypatch):
    _, rows = seed(lab, stages=("A",) * 65)
    ids = [r["event_id"] for r in rows]
    expected = {}
    for offset in range(0, len(ids), 32):
        expected.update(evidence_scope.originals(lab, actor(), ids[offset:offset+32]))
    original, batches = lab.analytics_query, []

    def measured(sql, args, **kwargs):
        batches.append(len(json.loads(args[-1])))
        return original(sql, args, **kwargs)

    monkeypatch.setattr(lab, "analytics_query", measured)
    assert evidence_scope.originals_many(lab, actor(), ids) == expected
    assert batches == [65]
    with pytest.raises(ValueError, match="1..32"):
        evidence_scope.originals(lab, actor(), ids)
    for invalid in (ids+[ids[0]], [], [f"large-{i}" for i in range(1057)]):
        with pytest.raises(ValueError):
            evidence_scope.originals_many(lab, actor(), invalid)


def test_many_two_mib_fallback_only_and_does_not_retry_authority_error(lab, monkeypatch):
    _, rows = seed(lab, stages=("A",) * 65)
    ids = [r["event_id"] for r in rows]
    original, batches = lab.analytics_query, []

    def bounded(sql, args, **kwargs):
        count = len(json.loads(args[-1])); batches.append(count)
        if count > 32:
            raise ValueError("Result exceeds 2 MiB; reduce fields or limit")
        return original(sql, args, **kwargs)

    monkeypatch.setattr(lab, "analytics_query", bounded)
    assert len(evidence_scope.originals_many(lab, actor(), ids)) == 65
    assert batches == [65, 32, 32, 1]
    batches.clear()

    def refused(*args, **kwargs):
        batches.append(True)
        raise PermissionError("Synthetic changed scope")

    monkeypatch.setattr(lab, "analytics_query", refused)
    with pytest.raises(PermissionError, match="changed scope"):
        evidence_scope.originals_many(lab, actor(), ids)
    assert batches == [True]


@pytest.mark.parametrize("change", ["caller", "source", "owner", "receipt", "source_receipt"])
def test_many_warm_prefetch_rechecks_changes_and_rollback_cannot_leak(lab, change):
    source, rows = seed(lab, stages=("A",) * 65)
    ids = [r["event_id"] for r in rows]
    before = evidence_scope.originals_many(lab, actor(), ids)
    with principal.transaction(lab, actor(), write=True) as (db, current):  # noqa: SIM117 -- Cache must end before the fresh transaction below.
        with evidence_scope.prefetch_transaction(lab, db, [(current, ids)]):
            found = evidence_scope.originals_many(lab, current, ids, db=db)
            assert found == before
            found[ids[-1]]["raw"]["stage"] = "mutation"
            assert evidence_scope.originals_many(lab, current, ids, db=db) == before
            db.execute("SAVEPOINT owned_authority_change")
            if change == "caller":
                db.execute("UPDATE users SET disabled=1 WHERE name='owner' AND tenant='a'")
            elif change == "source":
                db.execute("UPDATE source_registry SET state='revoked' WHERE id=?", (source["id"],))
            elif change == "owner":
                db.execute("UPDATE source_registry SET owner='peer' WHERE id=?", (source["id"],))
                db.execute("UPDATE users SET disabled=1 WHERE name='peer' AND tenant='a'")
            elif change == "receipt":
                db.execute("DELETE FROM receipts WHERE tenant='a' AND event_id=?", (ids[-1],))
            else:
                db.execute("DELETE FROM source_event_receipts WHERE tenant='a' AND event_id=?", (ids[-1],))
            with pytest.raises((PermissionError, ConflictError)):
                evidence_scope.originals_many(lab, current, ids, db=db)
            db.execute("ROLLBACK TO owned_authority_change")
            assert evidence_scope.originals_many(lab, current, ids, db=db) == before
    # New TX has no authority/facts cache, including an actual changed receipt.
    with principal.transaction(lab, actor(), write=True) as (db, current):
        db.execute("UPDATE receipts SET received=received+1 WHERE tenant='a' AND event_id=?", (ids[-1],))
        with pytest.raises(ConflictError, match="receipt"):
            evidence_scope.originals_many(lab, current, ids, db=db)


def test_many_requires_reserved_tx_and_actual_copy_not_reference(lab):
    _, rows = seed(lab, stages=("A",) * 2)
    ids = [r["event_id"] for r in rows]
    with lab.control() as db, pytest.raises(ConflictError, match="reserved transaction"):
        evidence_scope.originals_many(lab, actor(), ids, db=db)
    first = evidence_scope.originals_many(lab, actor(), ids)
    saved = copy.deepcopy(first)
    first[ids[0]]["raw"]["stage"] = "mutation"
    assert evidence_scope.originals_many(lab, actor(), ids) == saved


def test_many_actual_large_raw_result_falls_back_with_exact_parity(lab, monkeypatch):
    source, rows = seed(lab, stages=("A",) * 65)
    large = [{**r, "event_id": "large-"+r["event_id"], "raw": {**r["raw"], "padding": "A"*35000}} for r in rows]
    connector_runtime.intake(lab, actor(), source["id"], {"version": 1, "events": large, "cursor": "large", "checkpoint_version": 1})
    while lab.flush():
        pass
    ids = [r["event_id"] for r in large]
    direct = {}
    for offset in range(0, len(ids), 32):
        direct.update(evidence_scope.originals(lab, actor(), ids[offset:offset+32]))
    original, batches = lab.analytics_query, []

    def measured(sql, args, **kwargs):
        batches.append(len(json.loads(args[-1])))
        return original(sql, args, **kwargs)

    monkeypatch.setattr(lab, "analytics_query", measured)
    with principal.transaction(lab, actor(), write=True) as (db, current):
        assert evidence_scope.originals_many(lab, current, ids, db=db) == direct
        assert batches == [65, 32, 32, 1]
        db.execute("DELETE FROM receipts WHERE tenant='a' AND event_id=?", (ids[32],))
        with pytest.raises(ConflictError, match="receipt"):
            evidence_scope.originals_many(lab, current, ids, db=db)
