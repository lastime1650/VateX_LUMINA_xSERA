"""Actual 48-original CPU behavior result -> signal -> Case and retained pages."""
# ruff: noqa: F811 - imported disposable fixtures.

import pytest
from test_research_behavior import actor
from test_research_v2 import live_long_fixture, store  # noqa: F401

from sapientia import (
    access,
    advanced_intelligence,
    api_research_trace,
    intelligence,
    principal,
    research_behavior,
    signal_evidence,
)
from sapientia.storage import ConflictError


def test_actual_long_ancestry_case_protection_pages_and_retired_history(store,monkeypatch):
    model,_source,run,_rows=live_long_fixture(store)
    inference_calls=[]
    raw_reads=[]
    worker=research_behavior._worker
    query=store.analytics_query
    def counted(payload,*args,**kwargs):
        if payload.get('operation')=='research_v2_infer':inference_calls.append(payload)
        return worker(payload,*args,**kwargs)
    monkeypatch.setattr(research_behavior,'_worker',counted)
    def queried(sql,*args,**kwargs):
        if 'FROM events_all' in sql:raw_reads.append(sql)
        return query(sql,*args,**kwargs)
    monkeypatch.setattr(store,'analytics_query',queried)
    signal=advanced_intelligence.publish_run(store,actor(),run['id'])
    assert len(inference_calls)==1
    assert len(raw_reads)==1  # One bounded transaction load for all 48 originals.
    assert len(signal['event_ids'])==32
    assert signal['metadata']['evidence_manifest']['count']==48
    with principal.transaction(store,actor(),write=True) as (db,fresh):
        full=signal_evidence.ancestry(store,db,fresh,signal)
        assert len(full['event_ids'])==48
        outcome=intelligence._case(store,db,fresh,{'id':'long-case-test','version':1,'kind':'atomic'},
            {'name':'Actual reviewed long model evidence','case_adapter':{'entity_field':'host','risk_score':40,'severity':'high','mitre':[],'cooldown':0}},signal)
        assert outcome['emitted']==1
    with store.control() as db:
        retained={r[0] for r in db.execute("SELECT event_id FROM record_case_evidence_refs WHERE kind='contribution'")}
        assert set(full['event_ids'])<=retained
    first=signal_evidence.page(store,actor(),signal['id'])
    second=signal_evidence.page(store,actor(),signal['id'],first['next_offset'])
    assert len(first['items'])==32 and len(second['items'])==16
    assert {r['event_id'] for r in first['items']+second['items']}==set(full['event_ids'])
    traced=api_research_trace.trace(store,actor(),run['id'])
    assert traced['publication']['signal_id']==signal['id'] and len(traced['cases'])==1
    research_behavior.disable(store,actor(),model['id'],'Retain historical investigation while disabling new detection')
    assert signal_evidence.page(store,actor(),signal['id'])['total']==48
    assert len(api_research_trace.trace(store,actor(),run['id'])['cases'])==1
    access.set_for_user(store,actor('admin',role='admin'),'trainer',['other'])
    with pytest.raises(KeyError):signal_evidence.page(store,actor(),signal['id'])
    with pytest.raises(KeyError):api_research_trace.trace(store,actor(),run['id'])


def test_manifest_and_publication_cannot_borrow_another_execution(store):
    _model,_source,run,_rows=live_long_fixture(store)
    signal=advanced_intelligence.publish_run(store,actor(),run['id'])
    with store.control() as db:
        db.execute("UPDATE signal_evidence_manifests SET body='{}' WHERE signal_id=?",(signal['id'],))
    with pytest.raises(ConflictError,match='manifest hash'):
        signal_evidence.page(store,actor(),signal['id'])
    with store.control() as db:
        db.execute('UPDATE advanced_research_publications SET signal_id=? WHERE run_id=?',('SIG-nonexistent',run['id']))
    with pytest.raises(ConflictError,match='Publication binding'):
        api_research_trace.trace(store,actor(),run['id'])
