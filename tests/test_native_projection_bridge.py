"""Credential-bound synthetic native envelope to indexed source projection."""
import json

import pytest

from sapientia import agent_distribution as ad, source_registry
from tests.test_agent_distribution import source_store, config, enrolled
from tests.test_xdr_bridge import actor, event


def test_enrolled_events_become_v2_input_without_generic_promotion(source_store,config):
    service=ad.Distribution(source_store,config)
    identity,_,_,_=enrolled(service)
    payload={"events":[event(host="HOST-01")]}
    assert service.ingest(identity["credential"],payload)["accepted"]==1
    assert service.ingest(identity["credential"],payload)["duplicate"]==1
    source_store.flush()
    with source_store.control() as db:
        row=db.execute("SELECT source_id,source_definition FROM source_event_receipts").fetchone()
        proof=db.execute("SELECT agent_id FROM endpoint_event_receipts").fetchone()
        assert row["source_id"]=="agent:"+proof["agent_id"]
        projection=json.loads(db.execute("SELECT projection FROM event_projections").fetchone()[0])
        assert projection["source_id"]==row["source_id"]
        assert projection["native_capture_proven"] is False
    source_registry.revoke(source_store,actor(),row["source_id"],json.loads(row["source_definition"])["version"])
    with pytest.raises(PermissionError):
        service.ingest(identity["credential"],payload)


def test_generic_receipt_cannot_gain_native_provenance(source_store,config):
    from sapientia import xdr_bridge
    service=ad.Distribution(source_store,config)
    identity,_,_,_=enrolled(service)
    payload=event(host="HOST-01")
    record=xdr_bridge.parse_event(payload,"agent","endpoint",expected_host="HOST-01")
    source_store.ingest("a",[record])
    with pytest.raises(PermissionError):
        service.ingest(identity["credential"],{"events":[payload]})
    with source_store.control() as db:
        assert db.execute("SELECT count(*) FROM source_event_receipts").fetchone()[0]==0
