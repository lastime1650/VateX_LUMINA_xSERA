"""Registered synthetic session/process evidence through intake and Case emission."""
import json
import time

import pytest

from sapientia import correlation_runtime as cr
from tests.test_virtual_telemetry import client
from tests.test_backend_upgrade import actor
from tests.test_correlation_v2 import drain


@pytest.mark.parametrize("relation",["process","auth_session","cloud_session","parent_process"])
@pytest.mark.parametrize("broken",[False,True])
def test_non_flow_identity_is_connected_only_with_complete_matching_context(client,relation,broken):
    sources=[]
    for account in (["collector-a","collector-b"] if relation=="cloud_session" else ["asset"]):
        reply=client.post("/api/v2/sources",json={"index":"public","product":"json","account":account,"realm":"lab","credential_ref":"env:SAPIENTIA_CONNECTOR_TEST","version":0})
        assert reply.status_code==201,reply.text
        sources.append(reply.json())
    at=time.time()-100
    events=[]
    for stage in range(3):
        process={"guid":"P","start_identity":"boot/start"}
        if relation=="parent_process":
            process={"guid":"P"+str(stage),"start_identity":"boot/start-"+str(stage),"parent":{"guid":"P"+str(stage-1)}}
        raw={"security":{"action":str(stage)},"xdr":{"data":{"process":process,"user":{"id":"SID-a","session_id":"session-a"}}},
             "cloudtrail":{"recipientAccountId":"123456789012","userIdentity":{"principalId":"ROLE:session","accessKeyId":"ASIA-session","sessionContext":{"sessionIssuer":{"arn":"arn:aws:iam::123456789012:role/test"}}}}}
        if broken and stage==1:
            if relation=="process":
                process["start_identity"]="reused-GUID-other-incarnation"
            elif relation=="parent_process":
                process["parent"]["guid"]="unrelated"
            elif relation=="auth_session":
                raw["xdr"]["data"]["user"]["session_id"]="other-session"
            else:
                raw["cloudtrail"]["userIdentity"]["accessKeyId"]="other-token"
        events.append({"event_id":"stage-"+str(stage),"event_time":at+stage,"host":"asset","raw":raw})
    for i,source in enumerate(sources):
        selected=[event for stage,event in enumerate(events) if stage%len(sources)==i]
        reply=client.post("/api/v2/sources/"+source["id"]+"/intake",json={"version":1,"events":selected,"cursor":"all","checkpoint_version":0})
        assert reply.status_code==202,reply.text
    store=client.app.state.store; store.flush()
    cr.save(store,actor(),{"name":"Identity pipeline","version":0,"sources":[s["id"] for s in sources],"window":600,"within_seconds":10,"enabled":True,"relation":relation,"ordered":True,
                          "steps":[{"product":"json","filters":[{"field":"action","op":"eq","value":str(i)}]} for i in range(3)],
                          "case_adapter":{"entity_field":"raw.analysis.resolved_entity","risk_score":60,"cooldown":0}})
    drain(store)
    with store.control() as db:
        rows=db.execute("SELECT evidence FROM risk_contributions").fetchall()
        assert len(rows)==(0 if broken else 1)
        if rows:
            evidence=json.loads(rows[0][0])
            identity=evidence["analysis"]["identity"]
            assert identity["relation_mode"]==relation and len(identity["links"])==2
            assert set(evidence["event_ids"])=={"stage-0","stage-1","stage-2"}
            assert not identity["causality_proven"] and not identity["automatic_endpoint_authorization"]
        else:
            assert db.execute("SELECT count(*) FROM detector_diagnostics WHERE reason='ambiguous_or_missing_peer'").fetchone()[0]==1
