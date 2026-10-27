"""Mixed-case safety, exact evidence identity, regrouping and schema regressions."""

import copy
import hashlib
import json
import time

import pytest

from sapientia import (
    access,
    casework,
    detection_readiness,
    detections,
    normalization,
    risk_priority,
    xdr_bridge,
)
from sapientia import contribution_verdicts as verdicts
from sapientia import detection_governance as governance
from sapientia.storage import ConflictError, encode
from tests.test_casework import case as synthetic_case_fixture


@pytest.fixture
def case(tmp_path):
    yield from synthetic_case_fixture.__wrapped__(tmp_path)


def rows(case):
    store, actor, identifier = case
    with store.control() as db:
        return [dict(r) for r in db.execute("SELECT * FROM risk_contributions WHERE tenant=? AND incident_id=? ORDER BY id",
                                          (actor["tenant"], identifier))]


def second(case):
    store, actor, identifier = case
    first = rows(case)[0]
    data = json.loads(first["evidence"])
    data["event_ids"] = ["private-event"]
    data["steps"][0]["events"] = [{"event_id":"private-event","event_time":first["at"],"index":"private","host":"host-b"}]
    with store.control() as db:
        db.execute("INSERT INTO risk_contributions VALUES(?,?,?,?,?,?,?,?,?,?)",
                   ("second-evidence", actor["tenant"], identifier, "other-policy", "bob", "raw.user",
                    first["at"], 90, encode(data), encode(["private"])))
    return first["id"], "second-evidence"


def label(case, contribution, classification, version=0):
    return verdicts.adjudicate(*case, contribution,
                             {"classification":classification,"reason":"Independent synthetic analyst judgement","version":version})


def status(case, value):
    store, actor, identifier = case
    current = detections.incident_detail(store, actor, identifier)
    return detections.update_incident(store, actor, identifier,
          {"status":value,"owner":"","version":current["version"],"note":"Explicit synthetic judgement"})


def test_mixed_case_keeps_true_attack_when_other_contribution_is_false_positive(case):
    benign, malicious = second(case)
    label(case, benign, "false_positive")
    label(case, malicious, "true_positive")
    priority = risk_priority.case_priority(*case)
    assert priority["active_evidence_count"] == 1 and priority["evidence_score"] == 90
    assert priority["adjudication_counts"] == {"true_positive":1,"false_positive":1,"expected_activity":0,"unknown":0}
    assert priority["malicious_probability"] is None
    with pytest.raises(ConflictError, match="true-positive"):
        status(case, "false_positive")
    assert detections.entity_risk(case[0], case[1])[0]["entity"] == "bob"


def test_partial_judgement_cannot_hide_unreviewed_case_evidence(case):
    benign, _ = second(case)
    label(case, benign, "expected_activity")
    with pytest.raises(ConflictError, match="unknown"):
        status(case, "false_positive")
    assert risk_priority.case_priority(*case)["active_evidence_count"] == 1


def test_legacy_bulk_fp_and_reopen_preserve_independent_judgements(case):
    benign, _ = second(case)
    status(case, "false_positive")
    assert risk_priority.case_priority(*case)["active_evidence_count"] == 0
    label(case, benign, "expected_activity", version=1)
    status(case, "triage")
    result = verdicts.list_verdicts(*case)
    assert {r["classification"] for r in result["items"]} == {"expected_activity", "unknown"}
    assert risk_priority.case_priority(*case)["active_evidence_count"] == 1


def test_new_true_positive_reopens_a_case_previously_dismissed(case):
    contribution = rows(case)[0]["id"]
    status(case, "false_positive")
    result = label(case, contribution, "true_positive", version=1)
    assert result["incident_status"] == "triage" and result["active"]


def test_verdict_version_scope_and_changed_snapshot_are_enforced(case):
    contribution = rows(case)[0]["id"]
    label(case, contribution, "false_positive")
    with pytest.raises(ConflictError):
        label(case, contribution, "true_positive")
    with case[0].control() as db:
        db.execute("UPDATE risk_contributions SET evidence=? WHERE id=?", (encode({"event_ids":["different-original"]}), contribution))
        row = db.execute("SELECT * FROM risk_contributions WHERE id=?", (contribution,)).fetchone()
        assert verdicts.classification(db, row)["stale"]
        assert db.execute("SELECT count(*) FROM risk_contributions r WHERE "+verdicts.active_predicate()).fetchone()[0] == 1


def test_revoked_or_partial_principal_cannot_classify_full_case(case):
    first, second_id = second(case)
    actor = {**case[1],"allowed_indexes":["public"]}
    with pytest.raises(KeyError):
        verdicts.adjudicate(case[0],actor,case[2],first,{"classification":"false_positive","reason":"Unsafe scope","version":0})
    with case[0].control() as db:
        db.execute("UPDATE users SET disabled=1 WHERE name=?",(case[1]["name"],))
    with pytest.raises(PermissionError):
        label(case, second_id, "true_positive")


def test_split_moves_exact_ids_without_duplicate_risk_and_retains_labels(case):
    benign, malicious = second(case)
    label(case, benign, "expected_activity")
    before = detections.incident_detail(*case)
    result = verdicts.regroup(*case,"split",{"version":before["version"],"reason":"Separate independent episodes","contribution_ids":[malicious]})
    assert not result["duplicate_evidence_created"]
    with case[0].control() as db:
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0] == 2
        assert db.execute("SELECT incident_id FROM risk_contributions WHERE id=?",(malicious,)).fetchone()[0] == result["target_id"]
    assert risk_priority.case_priority(*case)["active_evidence_count"] == 0
    assert risk_priority.case_priority(case[0],case[1],result["target_id"])["active_evidence_count"] == 1
    assert verdicts.movement_history(*case)["items"][0]["kind"] == "split"


def test_merge_retains_original_investigation_access_and_mandatory_tasks(case):
    _, moved = second(case)
    before = detections.incident_detail(*case)
    split = verdicts.regroup(*case,"split",{"version":before["version"],"reason":"Separate then link","contribution_ids":[moved]})
    task = casework.act(*case,{"request_id":"required-original","action":{"type":"add_task","title":"Original evidence review","description":"","mandatory":True}})
    source = detections.incident_detail(*case)
    target = detections.incident_detail(case[0],case[1],split["target_id"])
    merged = verdicts.regroup(*case,"merge",{"version":source["version"],"reason":"Analyst confirmed related campaign","target_id":target["id"],"target_version":target["version"]})
    assert detections.incident_detail(*case)["contribution_count"] == 0
    assert casework.workspace(*case)["tasks"][0]["id"] == task["id"]
    with case[0].control() as db, pytest.raises(ConflictError, match="required tasks"):
        casework.require_resolution(db,case[1],merged["target_id"])
    assert len(detections.incident_detail(case[0],case[1],merged["target_id"])["contributions"]) == 2


@pytest.mark.parametrize("bad", [[], ["absent"], ["second-evidence","second-evidence"]])
def test_invalid_split_is_atomic(case,bad):
    second(case)
    before = rows(case)
    with pytest.raises(ValueError):
        verdicts.regroup(*case,"split",{"version":1,"reason":"Invalid selection","contribution_ids":bad})
    assert rows(case) == before


def test_exact_exception_context_does_not_leak_across_same_host_processes():
    match={"entity":"host-a","entity_field":"host","severity":"high","steps":[{"events":[{"host":"host-a","source":"endpoint","raw.xdr.data.process.hash.sha256":"a"*64,"raw.xdr.data.process.guid":"process-one"}]}]}
    conditions=[{"field":"entity","op":"eq","value":"host-a"},{"field":"process_hash","op":"eq","value":"a"*64}]
    assert governance._matches(governance._conditions(conditions),governance._candidate("policy",match))
    other=copy.deepcopy(match);other["steps"][0]["events"][0]["raw.xdr.data.process.hash.sha256"]="b"*64
    assert not governance._matches(conditions,governance._candidate("policy",other))
    missing=copy.deepcopy(match);missing["steps"][0]["events"].append({"host":"host-a","source":"endpoint"})
    assert not governance._matches(conditions,governance._candidate("policy",missing))


def test_readiness_does_not_certify_empty_or_partially_visible_deployments(case):
    report = detection_readiness.status(case[0],case[1])
    assert report["state"] == "onboarding_required" and not report["automatic_activation"]
    assert report["counts"]["endpoint_agents"]["total"] == 0
    assert not report["commercial_accuracy_certified"]
    restricted = detection_readiness.status(case[0],{**case[1],"allowed_indexes":["public"]})
    assert restricted["counts"] is None and restricted["automatic_case_readiness"] == "unknown"


def test_exact_exception_can_use_individual_expected_activity_in_mixed_case(case):
    harmless, malicious = second(case)
    label(case, harmless, "expected_activity")
    label(case, malicious, "true_positive")
    source = rows(case)[0]
    if source["id"] != harmless:
        source = rows(case)[1]
    data = {"kind":"exception","policy_id":source["policy_id"],"indexes":["public"],
            "expires":time.time()+3600,"reason":"Known harmless administrator activity",
            "conditions":[{"field":"entity","op":"eq","value":source["entity"]}],"case_id":case[2]}
    rule = governance.save(case[0],case[1],data)
    approver = {"name":"admin_a","tenant":"a","role":"admin","allowed_indexes":["*"]}
    approved = governance.review(case[0],approver,rule["id"],1,True,"Independently reviewed exact source judgement")
    assert approved["state"] == "active"
    with case[0].control() as db:
        row = db.execute("SELECT * FROM detection_governance_rules WHERE id=?",(rule["id"],)).fetchone()
        assert governance._approved(db,row)
    label(case, harmless, "true_positive",version=1)
    with case[0].control() as db:
        row = db.execute("SELECT * FROM detection_governance_rules WHERE id=?",(rule["id"],)).fetchone()
        assert not governance._approved(db,row)


@pytest.mark.parametrize("action,canonical", [("process_created","process_create"),("network_connection","network_connection"),("powershell_script_block","script_execution")])
def test_native_action_canonical_alias_keeps_raw_and_idempotency(action,canonical):
    raw={"action":action,"xdr":{"data":{"event":{"action":action}}}}
    result=normalization.normalize({"raw":raw})
    assert result["raw"]["security"]["action"] == canonical
    assert result["raw"]["action"] == action and result["raw"]["xdr"] == raw["xdr"]
    assert normalization.normalize(result) == result


def script_observation():
    text="Write-Output 'observed harmless script'"
    return {"@timestamp":"2026-10-13T00:00:00+00:00","host":{"id":"host-a"},
            "event":{"module":"script","provider":"Microsoft-Windows-PowerShell/Operational","code":"4104","action":"powershell_script_block"},
            "agent":{"collector":"windows-event-log","process_identity_kind":"unavailable_for_windows_event_log_observation","process_response_eligible":False},
            "process":{"name":"powershell.exe"},
            "powershell":{"script_block":text,"original_length":len(text),"sha256":hashlib.sha256(text.encode()).hexdigest(),"truncated":False,"complete":True,"message_number":1,"message_total":1}}


def test_script_signal_keeps_observation_without_fabricating_execution_identity():
    event=script_observation()
    typed=xdr_bridge._typed(event)
    assert typed["process"]["name"] == "powershell.exe" and "guid" not in typed["process"]
    for modification in ({"process":{"guid":"invented"}}, {"powershell":{**event["powershell"],"message_total":2}}, {"powershell":{**event["powershell"],"sha256":"b"*64}}):
        with pytest.raises(ValueError):
            xdr_bridge._typed({**event,**modification})


def test_readiness_distinguishes_alert_only_and_unready_baseline(case):
    store, actor, _ = case
    with store.control() as db:
        db.execute("UPDATE correlation_policies SET enabled=0 WHERE tenant=?", (actor['tenant'],))
        db.execute("INSERT INTO rules VALUES(?,?,?,?,?,?,?,?,?,?,?)", ('alert-only', actor['tenant'], 'Alert only', '{}', 60, 60, 1, 1, time.time(), None, None))
        db.execute("INSERT INTO behavior_baselines VALUES(?,?,?,?,?,?,?,?,?,?)", ('warmup', actor['tenant'], actor['name'], 'Cold start', 1, time.time(), encode(['public']), '{}', encode({'ready':False}), 'synthetic-digest'))
    report = detection_readiness.status(store,actor)
    assert report['counts']['rules']['enabled'] == 1
    assert report['counts']['rules']['case_capable_enabled'] == 0
    assert report['automatic_case_readiness'] == 'not_configured'
    assert report['counts']['behavior_baselines']['ready'] == 0
    assert 'no_trained_behavior_baseline' in report['warnings']
    assert 'behavior_baseline_cold_start' in report['warnings']


def test_legacy_exception_peer_must_read_complete_source_case(case):
    second(case)
    status(case, 'false_positive')
    source = rows(case)[0]
    if source['id'] == 'second-evidence':
        source = rows(case)[1]
    rule = governance.save(case[0],case[1],{'kind':'exception','policy_id':source['policy_id'],
        'indexes':['public'],'expires':time.time()+3600,'reason':'Legacy source qualification',
        'conditions':[{'field':'entity','op':'eq','value':source['entity']}],'case_id':case[2]})
    administrator = {'name':'admin_a','tenant':'a','role':'admin'}
    with case[0].control() as db:
        db.execute("INSERT INTO users(name,password,role,tenant) VALUES('policy_owner','fixture-only-no-login','analyst','a')")
        db.execute('UPDATE correlation_policies SET owner=? WHERE id=?',('policy_owner',source['policy_id']))
    access.set_for_user(case[0],administrator,'policy_owner',['public'])
    access.set_for_user(case[0],administrator,'admin_a',['public'])
    with pytest.raises(ConflictError):
        governance.review(case[0],{'name':'admin_a','tenant':'a','role':'admin'},rule['id'],1,True,'Cannot see the complete mixed source')


def test_attack_prerequisites_are_per_stage_and_cannot_rewrite_history():
    from sapientia.attack_catalog import _analytic_prerequisites
    snapshot={'version':1,'entity_field':'host','relation':None,'stages':[
        {'name':'script','required_fields':['host','raw.script']},
        {'name':'network','required_fields':['host','raw.remote']} ]}
    evidence={'evaluation':{'policy_version':1},'policy_snapshot':snapshot,'steps':[
        {'step':'script','events':[{'host':'same','raw.script':'observed'}]},
        {'step':'network','events':[{'host':'same','raw.remote':'remote'}]} ]}
    policy={'version':2,'definition':{'entity_field':'host','steps':[{'name':'edited','filters':[{'field':'raw.changed'}]}]}}
    result=_analytic_prerequisites(policy,evidence)
    assert result['requirements_basis']=='frozen_matched_policy'
    assert result['joint_field_evidence_count']==2
    assert 'raw.changed' not in result['required_fields']
    del evidence['policy_snapshot']
    legacy=_analytic_prerequisites(policy,evidence)
    assert legacy['requirements_basis']=='unavailable' and legacy['joint_field_evidence_count'] is None


def test_soar_snapshot_binds_individual_adjudication_and_temporal_warnings(case):
    from sapientia import soar
    contribution=rows(case)[0]
    evidence=json.loads(contribution['evidence'])
    evidence['temporal']={'automation_eligible':False}
    with case[0].control() as db:
        db.execute('UPDATE risk_contributions SET evidence=? WHERE id=?',(encode(evidence),contribution['id']))
        _, before=soar._evidence(db,case[1],case[2])
    assert before['temporally_uncertain_contributions']==1
    assert before['independent_approval_required']
    label(case,contribution['id'],'expected_activity')
    with case[0].control() as db:
        _, after=soar._evidence(db,case[1],case[2])
    assert before['digest'] != after['digest']
    assert after['inactive_adjudicated_contributions']==1
