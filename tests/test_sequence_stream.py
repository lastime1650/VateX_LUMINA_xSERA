"""Actual approved CPU inference over durable, scoped stream windows."""

import copy
import json
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sapientia import access,connector_runtime,cpu_sequence,evidence_scope,intelligence,intelligence_sequence as stream,source_registry
from sapientia.storage import Store
from tests.test_cpu_sequence import actor,seed_dataset,store as _sequence_store

store=_sequence_store


@pytest.fixture
def approved(store):
    data=seed_dataset(store);data["epochs"]=50
    model=cpu_sequence.train(store,actor(),data)
    if model.get("status")!="completed":
        pytest.skip("CPU framework unavailable for actual streamed model test")
    assessment=cpu_sequence.evaluate(store,actor("reviewer"),model["id"])
    assert assessment["metrics"]["samples"]==16
    cpu_sequence.activate(store,actor("reviewer"),model["id"],"Independent held-out source/feature review")
    declaration=intelligence.save_policy(store,actor(),{"name":"Stream intake declaration","kind":"atomic","indexes":["public"],"enabled":True,"filters":[{"field":"raw.never","op":"eq","value":"never"}]})
    intelligence.review_policy(store,actor("reviewer"),declaration["id"],{"version":1,"approve":True,"reason":"Independent stream scope, without a Case adapter"})
    # A recognized fixture exercises publication. Accuracy belongs to the
    # independent assessment; this replay is a scheduler integration test.
    sample=next(item for item in assessment["scenarios"] if item["label"]==1 and item["predicted_attack"])
    records=store.analytics_query("SELECT event_id,event_time,host,raw FROM events_all WHERE tenant='a' AND event_id IN (SELECT unnest(?)) ORDER BY event_time",[sample["event_ids"]],max_rows=12)["rows"]
    with store.control() as db:
        source=json.loads(db.execute("SELECT definition FROM cpu_sequence_models WHERE id=?",(model["id"],)).fetchone()[0])["sources"][0]["id"]
    return model,source,records


def records_for(base,tag,amount=12,**changes):
    events=[]
    for n in range(amount):
        original=base[n%12]
        raw=json.loads(original["raw"]);raw.pop("security",None);data=raw["xdr"]["data"]
        data["host"].update(id="device-"+tag,boot_id="boot-"+tag,name=tag)
        data["user"].update(id="user-"+tag,session_id="session-"+tag)
        if isinstance(data.get("authentication"),dict):
            data["authentication"]["session_id"]="session-"+tag
        value={"event_id":tag+"-"+str(n),"event_time":original["event_time"]+(n//12)*120,"host":tag,"raw":raw}
        for path,replacement in changes.items():
            current=value
            parts=path.split(".")
            for part in parts[:-1]:
                current=current.setdefault(part,{})
            current[parts[-1]]=replacement
        events.append(value)
    return events


def deliver(store,source,events):
    with store.control() as db:
        checkpoint=db.execute("SELECT version FROM connector_checkpoints WHERE tenant='a' AND source_id=?",(source,)).fetchone()
    version=checkpoint[0] if checkpoint else 0
    connector_runtime.intake(store,actor("admin"),source,{"version":1,"events":events,"cursor":"stream-"+str(version),"checkpoint_version":version})
    while store.flush():
        pass


def test_more_than_32_pending_originals_become_actual_cpu_ml_signals_without_cases(store,approved):
    model,source,base=approved
    events=[event for n in range(3) for event in records_for(base,"actual-window-"+str(n))]
    deliver(store,source,events)
    for _ in range(3):
        stream.enqueue(store,maximum=128)
    with store.control() as db:
        jobs=db.execute("SELECT * FROM intelligence_sequence_jobs WHERE model_id=?",(model["id"],)).fetchall()
        assert len(jobs)==3 and all(len(json.loads(row["event_ids"]))==12 for row in jobs)
    result=stream.run_due(store,max_runs=32)
    assert result["completed"]==3 and result["signals"]>=1
    signals=[row for row in intelligence.signals(store,actor(),count=100)["items"] if row["rule_id"]=="ml:sequence:"+model["id"]]
    assert all(len(row["event_ids"])==12 and row["features"]["model_family"]=="sequence" for row in signals)
    with store.control() as db:
        answer=json.loads(db.execute("SELECT result FROM cpu_sequence_runs WHERE model_id=? ORDER BY created DESC LIMIT 1",(model["id"],)).fetchone()[0])
        assert answer["input_tensor_shape"]==[3,12,55] and answer["worker_reused"]
        assert db.execute("SELECT count(*) FROM incidents").fetchone()[0]==0
        assert db.execute("SELECT count(*) FROM intelligence_sequence_jobs WHERE state='completed'").fetchone()[0]==3


@pytest.mark.parametrize("change",[
    {"host":"other-host"},
    {"raw.xdr.data.host.id":"other-device"},
    {"raw.xdr.data.host.boot_id":"other-boot"},
    {"raw.xdr.data.user.id":"other-user"},
    {"raw.xdr.data.user.session_id":"other-session"},
    {"raw.xdr.data.container.id":"other-container"},
    {"raw.xdr.data.container.namespace":"other-namespace"},
])
def test_stream_cannot_build_one_window_across_reported_identity_boundaries(store,approved,change):
    model,source,base=approved
    first=records_for(base,"identity",amount=6)
    second=records_for(base,"identity-other",amount=6)
    # Preserve all identities except the field under test, with different IDs
    # and times so identity separation is the only reason for two windows.
    for n,row in enumerate(second):
        row["raw"]=copy.deepcopy(first[n]["raw"]);row["host"]="identity"
        row["event_time"]+=6
        for path,replacement in change.items():
            current=row;parts=path.split(".")
            for part in parts[:-1]: current=current.setdefault(part,{})
            current[parts[-1]]=replacement
    deliver(store,source,[*first,*second]);stream.enqueue(store)
    with store.control() as db:
        buffers=db.execute("SELECT event_ids FROM intelligence_sequence_buffers WHERE model_id=?",(model["id"],)).fetchall()
        assert len(buffers)==2
        assert {tuple(json.loads(row[0])) for row in buffers}=={tuple(row["event_id"] for row in first),tuple(row["event_id"] for row in second)}
        assert db.execute("SELECT count(*) FROM intelligence_sequence_jobs").fetchone()[0]==0


def test_stream_cannot_join_other_authenticated_source_and_missing_or_masked_incarnation(store,approved):
    model,source,base=approved
    other=source_registry.save(store,actor("admin"),{"index":"public","product":"json","account":"other-source","realm":"synthetic","credential_ref":"env:SAPIENTIA_CONNECTOR_OTHER_STREAM","version":0})
    first=records_for(base,"same-device",amount=6)
    second=records_for(base,"other-ids",amount=6)
    for n,row in enumerate(second):
        row["raw"]=copy.deepcopy(first[n]["raw"]);row["host"]="same-device";row["event_time"]+=6
    deliver(store,source,first);deliver(store,other["id"],second)
    deliver(store,source,records_for(base,"masked",amount=3,**{"raw.xdr.data.host.id":"[REDACTED]"}))
    stream.enqueue(store)
    with store.control() as db:
        buffers=[json.loads(row[0]) for row in db.execute("SELECT event_ids FROM intelligence_sequence_buffers WHERE model_id=?",(model["id"],))]
        assert len(buffers)==2 and not any(any(identifier.startswith("masked") for identifier in ids) for ids in buffers)
        assert db.execute("SELECT count(*) FROM intelligence_sequence_jobs").fetchone()[0]==0


def test_expired_running_lease_recovers_after_restart_without_duplicate_signal(store,approved):
    model,source,base=approved;events=records_for(base,"recover")
    deliver(store,source,events);stream.enqueue(store)
    with store.control() as db:
        db.execute("UPDATE intelligence_sequence_jobs SET state='running',started=?",(time.time()-121,))
        assert set(row["event_id"] for row in events)<=stream.protected_ids(db,"a",[row["event_id"] for row in events])
    settings=store.settings;store.close();reopened=Store(settings)
    try:
        assert stream.run_due(reopened)["completed"]==1
        before=len(intelligence.signals(reopened,actor())["items"])
        assert stream.run_due(reopened)["completed"]==0
        assert len(intelligence.signals(reopened,actor())["items"])==before
        with reopened.control() as db:
            assert db.execute("SELECT state FROM intelligence_sequence_jobs").fetchone()[0]=="completed"
    finally:
        reopened.close()


@pytest.mark.parametrize("change",["source","model","reviewer"])
def test_changed_authority_after_real_inference_aborts_publication(store,approved,monkeypatch,change):
    model,source,base=approved;deliver(store,source,records_for(base,"racing"))
    actual=cpu_sequence.infer_sequences
    def changed(*args,**kwargs):
        result=actual(*args,**kwargs)
        assert result["status"]=="completed"
        if change=="source": source_registry.revoke(store,actor("admin"),source,1)
        elif change=="model": cpu_sequence.disable(store,actor(),model["id"])
        else: access.set_for_user(store,actor("admin"),"reviewer",["private"])
        return result
    monkeypatch.setattr(cpu_sequence,"infer_sequences",changed)
    result=stream.run_due(store)
    assert result.get("completed")==0
    assert not any(row["rule_id"]=="ml:sequence:"+model["id"] for row in intelligence.signals(store,actor())["items"])
    with store.control() as db:
        assert db.execute("SELECT state FROM intelligence_sequence_jobs").fetchone()[0]=="excluded"
        assert db.execute("SELECT count(*) FROM incidents").fetchone()[0]==0


def test_explicit_disable_releases_only_sequence_queue_and_buffer_protection(store,approved):
    model,source,base=approved
    complete=records_for(base,"queued");partial=records_for(base,"buffered",amount=6)
    events=complete+partial;deliver(store,source,events);stream.enqueue(store)
    ids=[row["event_id"] for row in events]
    with store.control() as db:
        assert stream.protected_ids(db,"a",ids)==set(ids)
        originals=db.execute("SELECT count(*) FROM receipts").fetchone()[0]
    cpu_sequence.disable(store,actor(),model["id"])
    with store.control() as db:
        assert stream.protected_ids(db,"a",ids)==set()
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0]==originals
        assert db.execute("SELECT count(*) FROM intelligence_sequence_buffers").fetchone()[0]==0
        assert db.execute("SELECT state FROM intelligence_sequence_jobs").fetchone()[0]=="excluded"


def test_fresh_reactivation_cancels_previous_claim_before_actual_result_publication(store,approved,monkeypatch):
    model,source,base=approved;deliver(store,source,records_for(base,"reactivation"))
    actual=cpu_sequence.infer_sequences
    def reviewed_again(*args,**kwargs):
        result=actual(*args,**kwargs)
        cpu_sequence.activate(store,actor("reviewer"),model["id"],"Fresh same-model review supersedes earlier in-flight lease")
        return result
    monkeypatch.setattr(cpu_sequence,"infer_sequences",reviewed_again)
    assert stream.run_due(store)["completed"]==0
    with store.control() as db:
        job=db.execute("SELECT state,error FROM intelligence_sequence_jobs").fetchone()
        assert job["state"]=="excluded" and "fresh activation" in job["error"]
        assert db.execute("SELECT count(*) FROM intelligence_signals WHERE kind='ml'").fetchone()[0]==0


def test_status_api_hides_model_stream_from_incomplete_current_scope(store,approved):
    model,source,base=approved;deliver(store,source,records_for(base,"visible-status"));stream.enqueue(store)
    app=FastAPI()
    current={"indexes":["private"]}
    stream.register(app,store,None,lambda request:actor(indexes=current["indexes"]),None)
    with TestClient(app) as client:
        assert client.get("/api/v3/ml/sequences/stream").json()["states"]==[]
        current["indexes"]=["public"]
        visible=client.get("/api/v3/ml/sequences/stream").json()["states"]
        assert len(visible)==1 and visible[0]["model_id"]==model["id"] and visible[0]["authority_rechecked"]
        access.set_for_user(store,actor("admin"),"reviewer",["private"])
        assert client.get("/api/v3/ml/sequences/stream").json()["states"]==[]


def test_only_independently_reviewed_cross_source_composite_emits_case_from_actual_sequence_signal(store,approved):
    model,source,base=approved;events=records_for(base,"case-sequence")
    deliver(store,source,events);assert stream.run_due(store)["signals"]==1
    signal=next(row for row in intelligence.signals(store,actor())["items"] if row["rule_id"]=="ml:sequence:"+model["id"])
    originals=evidence_scope.originals(store,actor(),signal["event_ids"])
    with store.control() as db:
        flow=next(projection["flow"] for original in sorted(originals.values(),key=lambda value:value["event_time"],reverse=True) if (projection:=intelligence._projection(db,actor()["tenant"],original)) and projection.get("flow"))
        assert db.execute("SELECT count(*) FROM incidents").fetchone()[0]==0
    declaration=intelligence.save_policy(store,actor(),{"name":"Independent network confirmation","kind":"atomic","indexes":["public"],"enabled":True,"filters":[{"field":"raw.network_confirm","op":"eq","value":True}]})
    intelligence.review_policy(store,actor("reviewer"),declaration["id"],{"version":1,"approve":True,"reason":"Independent registered network evidence"})
    definition={"name":"Reviewed sequence and network Case","kind":"composite","indexes":["public"],"enabled":True,"window":900,"inputs":[{"kind":"ml","rule_id":"ml:sequence:"+model["id"]},{"rule_id":declaration["id"]}],"join_on":"entity","minimum_independent_groups":2,"case_adapter":{"entity_field":"host","risk_score":75,"severity":"high","cooldown":0}}
    composite=intelligence.save_policy(store,actor(),definition)
    network=source_registry.save(store,actor("admin"),{"index":"public","product":"json","account":"network-confirmation","realm":"synthetic","credential_ref":"env:SAPIENTIA_CONNECTOR_NET_CONFIRM","version":0})
    deliver(store,network["id"],[{"event_id":"network-confirmation","event_time":events[-1]["event_time"],"host":"virtual-firewall","raw":{"security":flow,"network_confirm":True}}])
    for _ in range(4): intelligence.run_due(store,include_ml=False,budget=2,max_runs=8)
    with store.control() as db: assert db.execute("SELECT count(*) FROM incidents").fetchone()[0]==0
    intelligence.review_policy(store,actor("reviewer"),composite["id"],{"version":1,"approve":True,"reason":"Independent full-scope model revision and disjoint network original review"})
    for _ in range(4): intelligence._composites(store,deadline=time.monotonic()+2)
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM incidents").fetchone()[0]==1
        body=json.loads(db.execute("SELECT body FROM intelligence_signals WHERE rule_id=?",(composite["id"],)).fetchone()[0])
        assert set(body["event_ids"])=={*signal["event_ids"],"network-confirmation"}
        assert len(body["event_ids"])==13 and body["evidence_dependency"]["disjoint_original_groups"]==2
        assert db.execute("SELECT count(*) FROM endpoint_responses").fetchone()[0]==0
