"""Fresh research batch projection matches legacy flow association exactly."""

import json

import pytest
from test_research_behavior import actor, event, seed
from test_research_behavior import store as _store_fixture
from test_research_fusion import admit, reads
from test_research_fusion import cpu_model as _cpu_model_fixture

from sapientia import (
    advanced_intelligence,
    connector_runtime,
    intelligence_sequence,
    principal,
)
from sapientia import research_behavior as research

store = _store_fixture
cpu_model = _cpu_model_fixture


@pytest.fixture(autouse=True)
def owned_reserve(store):
    with store.control() as db:
        db.execute("UPDATE record_management_policy SET definition=json_set(definition,'$.min_free_percent',1) WHERE singleton=1")


def test_fresh_batched_association_is_exact_and_queries_do_not_scale_with_32_records(store):
    seed(store)
    ids = [f"research-{i}" for i in range(32)]
    with principal.transaction(store, actor(), write=True) as (db, current):
        queries=[];db.set_trace_callback(queries.append)
        expected=intelligence_sequence._association(store,db,current,ids,"fallback")
        old_count=len(queries);queries.clear()
        actual=advanced_intelligence._association(store,db,current,ids,"fallback")
        new_count=len(queries);db.set_trace_callback(None)
        assert expected==actual=="fallback" and new_count<old_count/3
        records=research._originals(store,current,ids,db=db)
        assert len({r["projection"]["event_id"] for r in records.values()})==32
        records[ids[0]]["projection"]["process"]["guid"]="mutation"
        assert research._originals(store,current,ids,db=db)[ids[0]]["projection"]["process"]["guid"]!="mutation"


def test_reported_flow_association_parity_and_current_owner_revocation(store):
    seed(store)
    with store.control() as db:
        source=db.execute("SELECT id FROM source_registry WHERE tenant='a'").fetchone()[0]
    rows=[event(200+i,raw={"security":{"src_ip":"10.0.0.1","dest_ip":"8.8.8.8","src_port":50000+i,"dest_port":443,"protocol":"tcp","action":"network_connect"}}) for i in range(2)]
    connector_runtime.intake(store,actor("admin",role="admin"),source,{"version":1,"events":[{k:v for k,v in r.items() if k!="projection"} for r in rows],"cursor":"flow","checkpoint_version":1})
    store.flush();ids=[r["event_id"] for r in rows]
    with principal.transaction(store,actor(),write=True) as (db,current):
        old=intelligence_sequence._association(store,db,current,ids,"fallback")
        assert old!="fallback" and advanced_intelligence._association(store,db,current,ids,"fallback")==old
        db.execute("UPDATE users SET disabled=1 WHERE tenant='a' AND name='admin'")
        with pytest.raises(PermissionError):
            advanced_intelligence._association(store,db,current,ids,"fallback")


def test_current_and_context_are_one_original_read_without_changing_window(store,cpu_model,monkeypatch):
    _model,source=cpu_model
    prior=reads([0,2,4]);admit(store,source,prior)
    first=research.run_due(store,budget=10)["runs"][0]
    newer=reads([6,8],offset=200);admit(store,source,newer,checkpoint=2)
    query=store.analytics_query;cohorts=[]

    def measured(sql,args,**kwargs):
        if sql.startswith("SELECT event_id,event_time,source,sourcetype,host,severity,message,index_name,raw,received "):
            cohorts.append(json.loads(args[-1]))
        return query(sql,args,**kwargs)

    monkeypatch.setattr(store,"analytics_query",measured)
    due=research.run_due(store,budget=10)
    assert not due["errors"] and due["processed"]==2
    run=due["runs"][0]
    expected=first["fusion_context"]["current_ids"]+[r["event_id"] for r in newer]
    assert cohorts==[expected] and run["event_ids"]==expected
    assert run["fusion_context"]["context_ids"]==[r["event_id"] for r in prior]
    assert run["fusion_context"]["current_ids"]==[r["event_id"] for r in newer]
    assert all(r["fusion"]["evidence"]["context_only"]==(r["event_id"] in {p["event_id"] for p in prior}) for r in run["results"])
