"""Fresh batched source authority preserves exact proofs and revocation."""

import pytest
from test_research_behavior import actor, seed
from test_research_behavior import store as _store_fixture

from sapientia import intelligence
from sapientia import research_behavior as research
from sapientia.storage import ConflictError

store = _store_fixture


def test_batch_source_pins_equal_singletons_with_bounded_query_count(store):
    seed(store)
    records=research._originals(store,actor(),[f"research-{i}" for i in range(48)])
    proofs=research._proofs(records)
    with store.control() as db:
        queries=[];db.set_trace_callback(lambda sql:queries.append(sql) if sql.lstrip().upper().startswith("SELECT") else None)
        batch=research._source_context(db,actor(),records);batch_count=len(queries);queries.clear()
        singles={p["event_id"]:research._source_pin(db,actor(),p) for p in proofs};single_count=len(queries)
        db.set_trace_callback(None)
        assert batch==singles and batch_count<=8 and single_count>=batch_count*20
        assert all(record["projection"]==intelligence._projection(db,"a",record) for record in records.values())
        research._verify_sources(db,actor(),proofs,required=True)
        db.execute("UPDATE users SET disabled=1 WHERE tenant='a' AND name='admin'")
        with pytest.raises(PermissionError):research._verify_sources(db,actor(),proofs,required=True)


def test_source_receipt_rebinding_and_missing_source_cannot_hide_in_batch(store):
    seed(store)
    records=research._originals(store,actor(),["research-0","research-1"]);proofs=research._proofs(records)
    with store.control() as db:
        db.execute("UPDATE source_event_receipts SET receipt_digest='changed' WHERE tenant='a' AND event_id='research-1'")
        with pytest.raises(ConflictError,match="source admission receipt differs"):
            research._verify_sources(db,actor(),proofs,required=True)
