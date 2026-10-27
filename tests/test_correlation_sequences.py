"""Actual backend regression of synthetic sequence/session/count evidence."""
import copy
import json
import time

import pytest

from sapientia import correlation_runtime as cr, detection_readiness, pressure_retention
from tests.test_virtual_telemetry import client
from tests.test_correlation_v2 import load, drain
from tests.test_backend_upgrade import actor


def revise(store, plan, **extra):
    old=cr.listing(store,actor())[0]["definition"]
    data={k:old[k] for k in ("name","version","sources","steps","window","within_seconds","enabled","case_adapter")}
    return cr.save(store,actor(),{**data,**extra},plan["id"])


def json_chain(client, stamps, precision=None, count=1, relation="flow", ordered=True):
    source=client.post("/api/v2/sources",json={"index":"public","product":"json","account":"asset","realm":"lab","credential_ref":"env:SAPIENTIA_CONNECTOR_TEST","version":0}).json()
    events=[]
    for stage,stamp in enumerate(stamps):
        for n in range(count if stage==0 else 1):
            events.append({"event_id":f"stage-{stage}-{n}","event_time":stamp,"host":"asset","raw":{"security":{"action":str(stage),"src_ip":"10.0.0.1","dest_ip":"10.0.0.2","src_port":50000,"dest_port":443,"protocol":"tcp"},
                                                                                                           "xdr":{"data":{"event":{"timestamp_precision_seconds":precision}}}}})
    response=client.post("/api/v2/sources/"+source["id"]+"/intake",json={"version":1,"events":events,"cursor":"all","checkpoint_version":0})
    assert response.status_code==202,response.text
    store=client.app.state.store; store.flush()
    steps=[{"product":"json","filters":[{"field":"action","op":"eq","value":str(i)}]} for i in range(len(stamps))]
    if count>1:
        steps[0].update(min_count=count,max_count=count)
    return cr.save(store,actor(),{"name":"Ordered synthetic chain","version":0,"sources":[source["id"]],"window":600,"within_seconds":10,"enabled":True,
                                 "relation":relation,"ordered":ordered,"clock_policy":"strict" if precision is not None else "reported","steps":steps,
                                 "case_adapter":{"entity_field":"raw.analysis.resolved_entity","risk_score":60,"severity":"high","mitre":[],"cooldown":0}})


def test_v2_only_readiness_and_scoped_diagnostics(client):
    plan,_=load(client,5); store=client.app.state.store
    state=detection_readiness.status(store,actor())
    assert state["counts"]["correlation_plans"]["healthy"]==1
    assert state["automatic_case_readiness"]=="configured_not_certified"
    drain(store)
    assert cr.listing(store,actor())[0]["diagnostics"]["matched"]==1


@pytest.mark.parametrize("ordered,strict,expected",[(False,False,1),(True,False,0),(True,True,0)])
def test_equal_or_unknown_clocks_cannot_claim_strict_order(client,ordered,strict,expected):
    at=time.time()-100
    plan=json_chain(client,[at,at,at],ordered=ordered)
    store=client.app.state.store
    revise(store,plan,ordered=ordered,clock_policy="strict" if strict else "reported")
    drain(store)
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0]==expected


@pytest.mark.parametrize("precision,stamps,expected",[(0,[0,1,2],1),(1,[0,1,2],0),(0,[2,1,0],0)])
def test_order_interval_and_direction_uses_real_admission(client,precision,stamps,expected):
    at=time.time()-100
    json_chain(client,[at+x for x in stamps],precision=precision)
    store=client.app.state.store; drain(store)
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0]==expected


def test_threshold_roles_preserve_all_original_ids(client):
    at=time.time()-100
    json_chain(client,[at,at+1,at+2],count=3,ordered=False)
    store=client.app.state.store; drain(store)
    with store.control() as db:
        rows=db.execute("SELECT evidence FROM risk_contributions").fetchall()
        assert len(rows)==1 and len(json.loads(rows[0][0])["event_ids"])==5


def test_changed_projection_is_not_accepted_as_original_evidence(client):
    load(client,5); store=client.app.state.store
    with store.control() as db:
        row=db.execute("SELECT seq,projection FROM event_projections ORDER BY seq LIMIT 1").fetchone()
        data=json.loads(row["projection"]); data["host"]="spoof"
        db.execute("UPDATE event_projections SET projection=? WHERE seq=?",(json.dumps(data),row["seq"]))
    cr.run_due(store,budget=1)
    assert cr.listing(store,actor())[0]["error"]=="ConflictError"


def test_volume_retention_preserves_unprocessed_detector_window(client):
    plan,_=load(client,5); store=client.app.state.store
    with store.control() as db:
        ids=[r[0] for r in db.execute("SELECT event_id FROM event_projections")]
        assert pressure_retention.protected_ids(store,db,"a",ids)==set(ids)
    # This assertion precedes Case creation: protection cannot depend on a Case.
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM incidents").fetchone()[0]==0


@pytest.mark.parametrize("value",[0,True,33,"2"])
def test_role_counts_are_typed_and_not_a_history_quota(client,value):
    plan,_=load(client,5); store=client.app.state.store
    definition=cr.listing(store,actor())[0]["definition"]
    steps=copy.deepcopy(definition["steps"])
    steps[0].update(min_count=value,max_count=value)
    with pytest.raises(ValueError):
        revise(store,plan,steps=steps)


def test_source_revision_is_not_silently_rebound_to_old_plan(client):
    plan,sources=load(client,5); store=client.app.state.store
    from sapientia import source_registry
    source_registry.revoke(store,actor(),sources["windows"]["id"],1)
    cr.run_due(store,budget=1)
    assert cr.listing(store,actor())[0]["error"]=="PermissionError"


def test_capacity_worker_deletes_only_old_unprotected_input_and_detector_finishes(client,monkeypatch):
    import shutil

    at=time.time()-100
    json_chain(client,[at,at+1,at+2])
    store=client.app.state.store
    store.ingest("a",[{"event_id":"old-unprotected","event_time":at-10000,"index":"public"}]); store.flush()
    from sapientia import auth, record_governance
    auth.create_user(store,"capacity-admin","Capacity-fixture-only-password-2026","admin","default")
    record_governance.configure(store,{"name":"capacity-admin","tenant":"default","role":"admin"},{"version":1,"min_free_percent":20})
    disk=shutil.disk_usage(store.path)
    monkeypatch.setattr(shutil,"disk_usage",lambda path:type(disk)(100*1024**2,95*1024**2,5*1024**2))
    state=pressure_retention.step(store)
    assert state["deleted_rows"]==1 and state["protected_scanned"]==3
    state=pressure_retention.step(store)
    assert state["state"]=="blocked" and state["deleted_rows"]==1
    # Capacity denial is explicit; the pending sequence remains complete.
    drain(store)
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0]==1
        assert db.execute("SELECT count(*) FROM event_projections").fetchone()[0]==3

