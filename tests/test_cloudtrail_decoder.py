"""Recipient/caller distinction, exact replay identity and no fake provenance."""

import copy
import datetime

import pytest

from sapientia.collector_plugins.aws_cloudtrail import envelope
from tests.test_virtual_telemetry import client


def record():
    return {"eventVersion": "1.11", "eventID": "00fb13ae-bf27-4fdd-8d2a-69f687c1b102",
            "eventTime": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "eventSource": "sts.amazonaws.com", "eventName": "AssumeRole", "awsRegion": "ap-northeast-2",
            "recipientAccountId": "111122223333", "sourceIPAddress": "AWS Internal/1",
            "userIdentity": {"type": "AssumedRole", "accountId": "999988887777",
                             "principalId": "ROLE:session", "sessionContext": {"sessionIssuer": {"arn": "arn:aws:iam::999988887777:role/Test"}}},
            "sharedEventID": "fafbbc76-c207-4d96-9f64-5d2686fd3b4f", "requestParameters": {"roleSessionName": "virtual-session"}}


def test_caller_is_separate_and_internal_service_name_is_not_ip():
    data = record()
    parsed = envelope(data, "aws", "111122223333")
    assert parsed["raw"]["cloudtrail"] == data
    assert "src_ip" not in parsed["raw"]["security"]
    assert parsed["raw"]["cloudtrail"]["userIdentity"]["accountId"] != "111122223333"
    assert envelope(data, "aws", "111122223333")["event_id"] == parsed["event_id"]
    with pytest.raises(PermissionError):
        envelope(data, "aws", "000000000000")
    data["eventVersion"] = "2.0"
    with pytest.raises(ValueError):
        envelope(data, "aws", "111122223333")


def test_cloudtrail_real_source_api_atomic_replay_and_account_spoof(client):
    source = client.post("/api/v2/sources", json={"index": "aws", "product": "cloudtrail", "account": "111122223333", "realm": "virtual-lab", "credential_ref": "env:SAPIENTIA_CONNECTOR_LAB", "version": 0}).json()
    path = "/api/v2/sources/"+source["id"]+"/intake"
    data = record()
    body = {"version": 1, "events": [data], "cursor": "one", "checkpoint_version": 0}
    assert client.post(path, json=body).json()["accepted"] == 1
    assert client.post(path, json=body).json()["duplicate"] == 1
    forged = copy.deepcopy(body)
    forged["events"][0]["recipientAccountId"] = "000000000000"
    assert client.post(path, json=forged).status_code == 403
    store = client.app.state.store
    store.flush()
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM event_projections").fetchone()[0] == 1
    assert client.post("/api/v2/sources", json={"index": "aws", "product": "unknown_vendor", "account": "111122223333", "realm": "virtual-lab", "credential_ref": "env:SAPIENTIA_CONNECTOR_LAB", "version": 0}).status_code == 400
