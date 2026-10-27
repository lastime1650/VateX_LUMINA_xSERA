"""Shared governance, lifecycle and Case provenance for synthetic v2 plans."""
import copy
import json
import time

import pytest

from sapientia import access, detector_ops, detection_governance as gov
from sapientia.storage import ConflictError
from tests.test_virtual_telemetry import client
from tests.test_correlation_v2 import load, drain
from tests.test_backend_upgrade import actor


def test_v2_candidates_receive_durable_governance_and_plan_snapshot(client):
    plan,_=load(client,5); store=client.app.state.store; drain(store)
    with store.control() as db:
        row=db.execute("SELECT policy_id,evidence FROM risk_contributions").fetchone()
        evidence=json.loads(row["evidence"])
        assert len(evidence["steps"])==3
        assert evidence["analysis"]["plan_snapshot"]["sources"]
        assert db.execute("SELECT count(*) FROM detection_governance_decisions WHERE policy_id=?",(row["policy_id"],)).fetchone()[0]==1
        assert detector_ops.policy(db,actor(),row["policy_id"])["version"]==1
    drain(store)
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0]==1


def test_v2_storm_policy_can_be_registered_before_any_case(client):
    plan,_=load(client,5); store=client.app.state.store
    policy="v2:"+plan["id"]+":1"
    saved=gov.save(store,actor(),{"kind":"storm","policy_id":policy,"indexes":["sim_windows","sim_cisco_asa","sim_fortigate"],"expires":time.time()+600,"reason":"Synthetic volume qualification","max_per_window":1,"window_seconds":60,"bypass_severities":["critical"],"version":0})
    assert saved["state"]=="pending"
    # It remains inactive until a different principal explicitly approves it.
    drain(store)
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0]==1


def test_superseded_v2_registry_cannot_authorize_new_governance(client):
    plan,_=load(client,5); store=client.app.state.store
    from tests.test_correlation_sequences import revise
    revise(store,plan,ordered=True)
    with store.control() as db:
        with pytest.raises(ConflictError):
            detector_ops.policy(db,actor(),"v2:"+plan["id"]+":1")


def test_registry_and_diagnostics_hide_other_tenants(client):
    plan,_=load(client,5); store=client.app.state.store; drain(store)
    with store.control() as db:
        with pytest.raises(KeyError):
            detector_ops.policy(db,actor("foreign","b"),"v2:"+plan["id"]+":1")
    from sapientia import record_governance
    access.set_for_user(store,actor(),"owner",["unrelated"])
    assert record_governance.page(store,actor(),"detector_diagnostics")["records"]==[]


def test_descriptor_cannot_change_immutable_revision(client):
    plan,_=load(client,5); store=client.app.state.store
    with store.control() as db:
        row=detector_ops.policy(db,actor(),"v2:"+plan["id"]+":1")
        data=json.loads(row["definition"]); data["risk_score"]+=1
        with pytest.raises(ConflictError):
            detector_ops.register(db,row,data,actor(),"v2-positive-flow")


def test_active_v2_governor_suppresses_case_only_and_records_emitter_outcome(client,monkeypatch):
    from sapientia import auth, correlation_runtime as cr
    from tests.test_correlation_sequences import json_chain

    fixed=time.time()
    monkeypatch.setattr(gov.time,"time",lambda:fixed)
    plan=json_chain(client,[fixed-100,fixed-99,fixed-98])
    store=client.app.state.store
    source=cr.listing(store,actor())[0]["definition"]["sources"][0]
    rows=[{"event_id":"second-"+str(i),"event_time":fixed-70+i,"host":"asset","raw":{"security":{"action":str(i),"src_ip":"10.0.0.1","dest_ip":"10.0.0.2","src_port":50000,"dest_port":443,"protocol":"tcp"}}} for i in range(3)]
    reply=client.post("/api/v2/sources/"+source+"/intake",json={"version":1,"events":rows,"cursor":"second","checkpoint_version":1})
    assert reply.status_code==202,reply.text
    store.flush()
    auth.create_user(store,"peer","Synthetic-peer-review-2026","admin","a")
    item=gov.save(store,actor(),{"kind":"storm","policy_id":"v2:"+plan["id"]+":1","indexes":["public"],"expires":fixed+600,"reason":"Qualified synthetic noise","max_per_window":1,"window_seconds":3600,"bypass_severities":["critical"],"version":0})
    gov.review(store,actor("peer"),item["id"],item["version"],True,"Independent administrator review")
    drain(store)
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0]==1
        decisions=[json.loads(r[0]) for r in db.execute("SELECT decision FROM detection_governance_decisions")]
        assert len(decisions)==2 and sum(not r["allowed"] for r in decisions)==1
        detail=[json.loads(r[0]) for r in db.execute("SELECT detail FROM detector_diagnostics WHERE reason='matched'")]
        assert sum(r["emission"]["governance_suppressed"] for r in detail)==1
        assert db.execute("SELECT count(*) FROM event_projections").fetchone()[0]==6


def test_existing_v2_plan_registration_is_backfilled_without_new_matches(client):
    plan,_=load(client,5); store=client.app.state.store; drain(store)
    with store.control() as db:
        projections=[tuple(r) for r in db.execute("SELECT seq,projection FROM event_projections ORDER BY seq")]
        contributions=db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0]
        db.execute("DELETE FROM detector_registry")
    detector_ops.initialize(store)
    detector_ops.initialize(store)
    with store.control() as db:
        assert detector_ops.policy(db,actor(),"v2:"+plan["id"]+":1")["version"]==1
        assert db.execute("SELECT count(*) FROM detector_registry").fetchone()[0]==1
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0]==contributions
        assert [tuple(r) for r in db.execute("SELECT seq,projection FROM event_projections ORDER BY seq")]==projections

