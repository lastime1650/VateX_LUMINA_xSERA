"""Real CPU replay reuse with fresh authority, complete ancestry and isolation."""
# ruff: noqa: F811 - imported disposable Store fixture.

import copy
import json

import pytest
from test_research_behavior import actor
from test_research_v2 import live_long_fixture, store  # noqa: F401

from sapientia import (
    advanced_intelligence,
    evidence_scope,
    intelligence,
    principal,
    research_behavior,
    research_long_horizon,
    signal_evidence,
)
from sapientia.storage import ConflictError


@pytest.fixture(autouse=True)
def owned_reserve(store):
    with store.control() as db:
        db.execute("UPDATE record_management_policy SET definition=json_set(definition,'$.min_free_percent',1) WHERE singleton=1")


def test_one_pure_replay_per_reserved_publication_and_same_complete_case(store, monkeypatch):
    _model, _source, run, rows = live_long_fixture(store)
    replay = research_long_horizon.replay
    calls = []; copies = []
    copied = evidence_scope._copy_facts

    def counted(*args, **kwargs):
        calls.append(args[3]["id"])
        return replay(*args, **kwargs)

    monkeypatch.setattr(research_long_horizon, "replay", counted)
    def measured(value):
        copies.append(len(value))
        return copied(value)
    monkeypatch.setattr(evidence_scope, "_copy_facts", measured)
    signal = advanced_intelligence.publish_run(store, actor(), run["id"])
    # Publication crosses the bridge, ancestry closure and ML validator. They
    # still check fresh authority, but no longer replay all48 raw rows4 times.
    assert calls == [run["id"]]
    assert copies.count(48) == 1
    assert signal["features"] == advanced_intelligence._data(run)["features"]
    assert signal["metadata"]["evidence_manifest"] == run["long_evidence"]
    expected = sorted(row["event_id"] for row in rows)
    with principal.transaction(store, actor(), write=True) as (db, current), evidence_scope.prefetch_transaction(store, db, [(current, expected)]), intelligence._authority_memo(db) as memo:
        calls.clear()
        complete = signal_evidence.ancestry(store, db, current, signal, memo=memo["research"])
        assert complete["event_ids"] == expected and calls == [run["id"]]
        outcome = intelligence._case(store, db, current, {"id": "proof-case", "version": 1, "kind": "atomic"},
            {"name": "Reviewed exact long replay", "case_adapter": {"entity_field": "host", "risk_score": 40, "severity": "high", "mitre": [], "cooldown": 0}}, signal, memo=memo)
        assert outcome["emitted"] == 1
        # Emitting a Case writes unrelated rows; fresh selected-row and source
        # checks still allow reuse of the same immutable model/run/raw proof.
        assert calls == [run["id"]]
    with store.control() as db:
        retained = {row[0] for row in db.execute("SELECT event_id FROM record_case_evidence_refs WHERE kind='contribution'")}
    assert set(expected) <= retained
    assert advanced_intelligence.publish_run(store, actor(), run["id"])["duplicate"]


def test_reuse_cannot_hide_mutation_revocation_new_prefetch_or_changed_raw(store, monkeypatch):
    model, source, run, rows = live_long_fixture(store)
    ids = sorted(row["event_id"] for row in rows)
    historical = next(eid for eid in ids if eid not in run["event_ids"])
    replay = research_long_horizon.replay
    calls = []

    def counted(*args, **kwargs):
        calls.append(args[3]["id"])
        return replay(*args, **kwargs)

    monkeypatch.setattr(research_long_horizon, "replay", counted)
    memo = {}
    with principal.transaction(store, actor(), write=True) as (db, current):
        with evidence_scope.prefetch_transaction(store, db, [(current, ids)]):
            first = research_behavior.validate_publication(store, db, current, run["id"], memo=memo)
            query = []
            db.set_trace_callback(query.append)
            assert research_behavior.validate_publication(store, db, current, run["id"], memo=memo) == first
            db.set_trace_callback(None)
            assert calls == [run["id"]]
            assert any("FROM source_registry" in sql for sql in query)
            assert any("FROM source_event_receipts" in sql for sql in query)
            assert any("FROM receipts" in sql for sql in query)
            db.execute("UPDATE research_behavior_state SET updated=updated+1 WHERE model_id=?", (model["id"],))
            assert research_behavior.validate_publication(store, db, current, run["id"], memo=memo) == run
            assert calls == [run["id"]]
            # Returned bodies and the old string-keyed pure-result cache are
            # not proof authority or ancestry inputs on a later guarded reuse.
            first["decision"]["score"] = -999
            memo["long-verified:" + run["id"]] = ({}, {"originals": []})
            assert research_behavior.long_publication_evidence(store, db, current, run["id"], memo=memo)["event_ids"] == ids
            changes = [
                ("UPDATE source_registry SET state='revoked' WHERE id=?", (source["id"],)),
                ("DELETE FROM receipts WHERE tenant='a' AND event_id=?", (historical,)),
                ("UPDATE research_behavior_reviews SET approve=0 WHERE model_id=?", (model["id"],)),
                ("UPDATE users SET disabled=1 WHERE tenant='a' AND name='reviewer'", ()),
                ("UPDATE research_horizon_snapshots SET body='{}' WHERE run_id=?", (run["id"],)),
                ("UPDATE research_behavior_runs SET body=json_set(body,'$.decision.score',-999) WHERE id=?", (run["id"],)),
                ("UPDATE research_behavior_models SET snapshot=json_set(snapshot,'$.epochs',999) WHERE id=?", (model["id"],)),
            ]
            for sql, values in changes:
                db.execute("SAVEPOINT negative_probe")
                db.execute(sql, values)
                with pytest.raises((PermissionError, ConflictError, KeyError)):
                    research_behavior.validate_publication(store, db, current, run["id"], memo=memo)
                db.execute("ROLLBACK TO negative_probe")
                db.execute("RELEASE negative_probe")
            research_behavior.validate_publication(store, db, current, run["id"], memo=memo)
        # A new prefetch has a distinct private token even in this same DB.
        prior = len(calls)
        with evidence_scope.prefetch_transaction(store, db, [(current, ids)]):
            assert research_behavior.validate_publication(store, db, current, run["id"], memo=memo) == run
        assert len(calls) == prior + 1
    # A fresh transaction must read actual current raw bytes again. Inject a
    # changed backend row to represent tampering without touching any real file.
    query = store.analytics_query

    def tampered(sql, *args, **kwargs):
        answer = query(sql, *args, **kwargs)
        if "FROM events_all" in sql:
            answer = copy.deepcopy(answer)
            for row in answer["rows"]:
                if row["event_id"] == historical:
                    body = json.loads(row["raw"]) if isinstance(row["raw"], str) else row["raw"]
                    body["message"] = "changed after the earlier proof transaction"
                    row["raw"] = json.dumps(body)
        return answer

    monkeypatch.setattr(store, "analytics_query", tampered)
    with principal.transaction(store, actor(), write=True) as (db, current), evidence_scope.prefetch_transaction(store, db, [(current, ids)]), pytest.raises(ConflictError, match="originals changed"):
        research_behavior.validate_publication(store, db, current, run["id"], memo=memo)
