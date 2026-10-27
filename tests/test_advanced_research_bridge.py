"""Real CPU/source -> common ML -> independent sensor composite -> Case."""

import copy
import json
import time

import pytest

from sapientia import access,advanced_intelligence,auth,connector_runtime,intelligence,principal,research_behavior,source_registry
from sapientia.storage import ConflictError,encode
from test_research_behavior import actor,definition,event,seed,store


@pytest.fixture
def trained(store):
    seed(store)
    auth.create_user(store,"policy_owner","Independent-policy-password-2026","analyst","a")
    model=research_behavior.train(store,actor(),definition(seeds=[17]))
    research_behavior.review(store,actor("reviewer"),model["id"],{"approve":True,"mode":"live","reason":"Independent authenticated normal and chronological holdout review"})
    return model


def runtime_original(store,*,same_original=False):
    with store.control() as db:source=dict(db.execute("SELECT * FROM source_registry WHERE tenant='a' ORDER BY id LIMIT 1").fetchone())
    row=event(300,event_id="bridge-anomaly",event_time=time.time()-3,raw={"action":"network_connect","stage":"binary",
        "security":{"src_ip":"10.0.0.3","dest_ip":"10.0.0.8","src_port":31337,"dest_port":443,"protocol":"tcp"}})
    envelope={k:v for k,v in row.items() if k!="projection"}
    connector_runtime.intake(store,actor("admin",role="admin"),source["id"],{"version":source["version"],"events":[envelope],"cursor":"bridge-anomaly","checkpoint_version":1})
    store.flush()
    return source,row


def published(store,model):
    source,row=runtime_original(store)
    run=research_behavior.analyze(store,actor(),{"event_ids":[row["event_id"]],"model_id":model["id"]})
    assert run["decision"]["publishable"]
    signal=advanced_intelligence.publish_run(store,actor(),run["id"])
    return source,row,run,signal


def reviewed(store,definition):
    saved=intelligence.save_policy(store,actor("policy_owner"),definition)
    intelligence.review_policy(store,actor("reviewer"),saved["id"],{"version":1,"approve":True,"reason":"Independent sensor and immutable model input review"})
    return saved["id"]


def valid(store,signal,who=None):
    with principal.transaction(store,who or actor("policy_owner"),write=True) as (db,fresh):
        return advanced_intelligence.validate_parent(store,db,fresh,signal)


def test_real_cpu_publish_is_exactly_once_and_other_policy_owner_can_validate(store,trained):
    _,_,run,signal=published(store,trained)
    again=advanced_intelligence.publish_run(store,actor(),run["id"])
    assert signal["id"]==again["id"] and again["duplicate"]
    assert valid(store,signal)
    with principal.transaction(store,actor("policy_owner"),write=True) as (db,fresh):
        assert intelligence._parent_valid(store,db,fresh,signal,{"indexes":["public"]})
        assert db.execute("SELECT count(*) FROM intelligence_signals WHERE rule_id=?",("ml:research:"+trained["id"],)).fetchone()[0]==1
    assert signal["malicious_probability"] is None and not signal["automatic_endpoint_authorization"]
    assert signal["metadata"]["graph_digest"]


@pytest.mark.parametrize("same_original",[False,True])
def test_real_research_plus_sensor_original_creates_case_only_with_distinct_evidence(store,trained,same_original):
    atomic=reviewed(store,{"name":"Independent network telemetry","kind":"atomic","indexes":["public"],"enabled":True,
        "filters":[{"field":"raw.stage","op":"eq","value":"binary" if same_original else "network"}]})
    child=reviewed(store,{"name":"Research CPU plus separate network telemetry","kind":"composite","indexes":["public"],"enabled":True,
        "inputs":[{"rule_id":"ml:research:"+trained["id"],"kind":"ml"},{"rule_id":atomic,"kind":"atomic"}],
        "join_on":"flow","minimum_independent_groups":2,"window":300,
        "case_adapter":{"entity_field":"host","risk_score":60,"severity":"high","mitre":[],"cooldown":0}})
    _,_,run,signal=published(store,trained)
    if not same_original:
        source=source_registry.save(store,actor("admin",role="admin"),{"index":"public","product":"json","account":"separate-network-sensor","realm":"virtual-lab","credential_ref":"env:SAPIENTIA_CONNECTOR_RESEARCH_NETWORK","version":0})
        row={"event_id":"bridge-network","event_time":time.time()-2,"host":"test-host","raw":{"stage":"network","security":{
            "action":"network_connect","src_ip":"10.0.0.3","dest_ip":"10.0.0.8","src_port":31337,"dest_port":443,"protocol":"tcp"}}}
        connector_runtime.intake(store,actor("admin",role="admin"),source["id"],{"version":1,"events":[row],"cursor":"bridge-network","checkpoint_version":0})
        store.flush()
    for _ in range(8):intelligence.run_due(store,budget=2,max_runs=8,include_ml=False)
    signals=intelligence.signals(store,actor("policy_owner"),count=100)["items"]
    combined=[s for s in signals if s["rule_id"]==child]
    with store.control() as db:
        contributions=db.execute("SELECT * FROM risk_contributions WHERE policy_id=?",("intelligence:"+child+":1",)).fetchall()
        assert db.execute("SELECT count(*) FROM endpoint_responses").fetchone()[0]==0
    if same_original:
        assert combined==[] and contributions==[]
    else:
        assert len(combined)==1 and len(contributions)==1
        assert combined[0]["event_ids"]==["bridge-anomaly","bridge-network"]
        assert combined[0]["evidence_dependency"]["disjoint_original_groups"]==2
        assert combined[0]["evidence_dependency"]["statistical_independence_proven"] is False
        assert json.loads(contributions[0]["evidence"])["event_ids"]==combined[0]["event_ids"]
        assert contributions[0]["incident_id"]
    assert valid(store,signal)


@pytest.mark.parametrize("field",["metadata","context_digest","model_digest","features","event_ids","id"])
def test_forged_common_signal_cannot_borrow_real_research_run(store,trained,field):
    _,_,run,signal=published(store,trained)
    changed=copy.deepcopy(signal)
    changed[field]={"metadata":None,"context_digest":"forged","model_digest":"0"*64,"features":{"research_anomaly_score":999},"event_ids":["research-101"],"id":"SIG-forged"}[field]
    assert not valid(store,changed)


@pytest.mark.parametrize("kind",["model_disable","reviewer_scope","source_revoke","source_owner_scope","source_receipt"])
def test_current_revocation_removes_common_parent_eligibility(store,trained,kind):
    source,_,_,signal=published(store,trained)
    if kind=="model_disable":research_behavior.disable(store,actor(),trained["id"],"stop reviewed model")
    elif kind=="reviewer_scope":access.set_for_user(store,actor("admin",role="admin"),"reviewer",["private"])
    elif kind=="source_revoke":source_registry.revoke(store,actor("admin",role="admin"),source["id"],source["version"])
    elif kind=="source_owner_scope":access.set_for_user(store,actor("admin",role="admin"),"admin",["private"])
    else:
        with store.control() as db:db.execute("DELETE FROM source_event_receipts WHERE tenant='a' AND event_id='bridge-anomaly'")
    assert not valid(store,signal)


def test_publication_worker_recovers_run_after_cursor_commit_without_duplicate(store,trained):
    runtime_original(store)
    result=research_behavior.run_due(store,budget=10)
    assert result["processed"]==1
    value=advanced_intelligence.run_due(store)
    assert value["published"]==1
    assert advanced_intelligence.run_due(store)["published"]==0
    with store.control() as db:
        signal=json.loads(db.execute("SELECT body FROM intelligence_signals WHERE rule_id=?",("ml:research:"+trained["id"],)).fetchone()[0])
    assert valid(store,signal)
