"""Synthetic identity contracts; no native OS collection or host actions."""
import copy

import pytest

from sapientia import identity_resolver as ir, temporal_identity
from tests.test_platform_gap_remediation import platform, binding


def projection():
    return {"realm":"lab","account":"host-01","source_id":"source-01","source_version":1,
            "event_id":"one","event_time":100.0,"projection_digest":"a"*64,
            "flow":{"src_ip":"10.0.0.1","src_port":1000,"dest_ip":"10.0.0.2","dest_port":443,"protocol":"tcp"},
            "process":{"guid":"process-A","start_identity":"boot/start","parent_guid":None},
            "auth":{"uid":"SID-1","session_id":"session-A","account":"host-01"},
            "cloud":{"account_id":"123456789012","principal_id":"ROLE:session-A","session_id":"ASIA-key","issuer_arn":"arn:aws:iam::123456789012:role/A"},
            "actor":{"name":"alice"},"clock_precision":None}


@pytest.mark.parametrize("mode",["process","auth_session","cloud_session","flow"])
def test_relation_is_realm_scoped(mode):
    a=projection(); b=copy.deepcopy(a); b["realm"]="other"
    assert ir.relation_key(None,None,a,mode)!=ir.relation_key(None,None,b,mode)


@pytest.mark.parametrize("path",["source_id","account","process.start_identity","process.guid"])
def test_pid_or_guid_alone_does_not_cross_process_incarnation(path):
    a=projection(); b=copy.deepcopy(a)
    parts=path.split("."); target=b if len(parts)==1 else b[parts[0]]
    target[parts[-1]]="other"
    assert ir.relation_key(None,None,a,"process")!=ir.relation_key(None,None,b,"process")


@pytest.mark.parametrize("value",[None,"",True,{},1000,"a\nb"])
def test_invalid_guid_cannot_become_an_identity(value):
    a=projection(); a["process"]["guid"]=value
    assert ir.relation_key(None,None,a,"process") is None


def test_reverse_flow_requires_explicit_bidirectional_mode():
    a=projection(); b=copy.deepcopy(a); f=a["flow"]
    b["flow"]={**f,"src_ip":f["dest_ip"],"dest_ip":f["src_ip"],"src_port":f["dest_port"],"dest_port":f["src_port"]}
    assert ir.relation_key(None,None,a,"flow")!=ir.relation_key(None,None,b,"flow")
    assert ir.relation_key(None,None,a,"bidirectional_flow")==ir.relation_key(None,None,b,"bidirectional_flow")


def test_cloud_session_is_account_role_and_token_bound():
    a=projection(); b=copy.deepcopy(a); b["source_id"]="other-collector"
    assert ir.relation_key(None,None,a,"cloud_session")==ir.relation_key(None,None,b,"cloud_session")
    for field in a["cloud"]:
        b=copy.deepcopy(a); b["cloud"][field]="different"
        assert ir.relation_key(None,None,a,"cloud_session")!=ir.relation_key(None,None,b,"cloud_session")


def test_parent_link_requires_distinct_exact_child_and_preserves_no_authority():
    a=projection(); b=copy.deepcopy(a)
    a["flow"]=b["flow"]=None
    b.update(event_id="two",event_time=101)
    b["process"].update(guid="process-B",parent_guid="process-A",start_identity="boot/child")
    result=ir.resolve_for_analysis(None,None,[a,b],2,"parent_process")
    assert result["status"]=="associated" and len(result["links"])==1
    assert result["causality_proven"] is result["automatic_endpoint_authorization"] is False
    b["process"]["parent_guid"]="unrelated"
    assert ir.resolve_for_analysis(None,None,[a,b],2,"parent_process")["status"]=="unresolved"


def test_parent_cycle_and_empty_observation_never_become_association():
    a=projection(); b=copy.deepcopy(a); c=copy.deepcopy(a)
    a["flow"]=b["flow"]=c["flow"]=None
    b["process"].update(guid="process-B",parent_guid="process-A")
    c["process"]["parent_guid"]="process-B"
    assert ir.resolve_for_analysis(None,None,[a,b,c],2,"parent_process")["status"]=="unresolved"
    assert ir.resolve_for_analysis(None,None,[],2,"process")["status"]=="unresolved"


def test_approved_nat_matches_translation_expires_and_rejects_overlap(platform):
    store=platform["store"]; actor=platform["actors"]["requester"]
    flow={"src_ip":"203.0.113.10","src_port":40000,"dest_ip":"198.51.100.10","dest_port":443,"protocol":"tcp"}
    translated={**flow,"src_ip":"10.0.0.10","src_port":50000}
    data=binding(platform)
    data.update(kind="nat",lookup=flow,translated=translated,evidence=[{"event_id":"nat","fields":{"raw."+k:v for k,v in {**flow,"inner_ip":"10.0.0.10","inner_port":50000}.items()}}])
    saved=temporal_identity.save(store,actor,data)
    a=projection(); a.update(event_time=platform["now"],flow=flow)
    b=copy.deepcopy(a); b["flow"]=translated
    assert ir.relation_key(store,actor,a,"approved_nat")==ir.relation_key(store,actor,b,"approved_nat")
    b["event_time"]=saved["valid_until"]
    assert ir.relation_key(store,actor,b,"approved_nat") is None
    temporal_identity.save(store,actor,data)
    assert ir.relation_key(store,actor,a,"approved_nat") is None

