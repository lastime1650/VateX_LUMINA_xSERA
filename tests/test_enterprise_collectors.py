# ruff: noqa: F811 - shared disposable pytest fixtures.
"""Vendor protocol fixtures with real source admission and durable checkpoints."""

import datetime
import json
import urllib.parse

import pytest

from sapientia import enterprise_collectors as collectors
from sapientia import source_registry
from tests.test_backend_upgrade import actor, lab  # noqa: F401

TENANT = "11111111-1111-4111-8111-111111111111"
CLIENT = "22222222-2222-4222-8222-222222222222"
USER = "33333333-3333-4333-8333-333333333333"
OTHER = "44444444-4444-4444-8444-444444444444"
SECRET = "synthetic-local-fixture-only"
ENV = "SAPIENTIA_CONNECTOR_ENTERPRISELAB"


def declared(lab, product="entra_signin"):
    return source_registry.save(lab, actor(), {"index": "public", "product": product, "account": TENANT, "realm": "microsoft-managed", "credential_ref": "env:" + ENV, "version": 0})


def credentials(**changes):
    return {ENV: json.dumps({"tenant_id": TENANT, "client_id": CLIENT, "client_secret": SECRET, "publisher_id": TENANT, **changes})}


def window(product="entra_signin", checkpoint=0):
    now = datetime.datetime.now(datetime.UTC).replace(microsecond=0)
    return {"source_version": 1, "checkpoint_version": checkpoint, "start": (now - datetime.timedelta(hours=1)).isoformat().replace("+00:00", "Z"), "end": now.isoformat().replace("+00:00", "Z"), "content_type": "Audit.Exchange" if product == "m365_audit" else None}


def signin(number, data):
    return {"id": "signin-" + str(number), "createdDateTime": data["end"], "userId": USER, "userPrincipalName": "virtual@example.invalid", "ipAddress": "192.0.2.10", "status": {"errorCode": 0}}


def audit(number, data, tenant=TENANT):
    return {"Id": "audit-" + str(number), "CreationTime": data["end"], "OrganizationId": tenant, "Operation": "New-InboxRule", "Workload": "Exchange", "RecordType": 1, "UserId": "virtual@example.invalid", "UserKey": USER, "ClientIP": "192.0.2.20", "ResultStatus": "Succeeded"}


def token():
    return collectors.Reply(200, {}, {"access_token": "synthetic-non-token", "token_type": "Bearer"})


def counts(lab):
    with lab.control() as db:
        return {"receipts": db.execute("SELECT count(*) FROM source_event_receipts").fetchone()[0], "checkpoint": db.execute("SELECT coalesce(max(version),0) FROM connector_checkpoints").fetchone()[0]}


def test_graph_actual_admission_receipt_precedes_next_page_and_replay_deduplicates(lab, record_property):
    source = declared(lab)
    data = window()
    next_url = "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=page-two"
    calls = []
    def provider(method, url, headers, payload, timeout):
        calls.append((method, url))
        assert 0 < timeout <= 10
        if method == "POST":
            assert url == "https://login.microsoftonline.com/" + TENANT + "/oauth2/v2.0/token"
            form = urllib.parse.parse_qs(payload.decode())
            assert form["scope"] == ["https://graph.microsoft.com/.default"] and form["client_secret"] == [SECRET]
            return token()
        assert headers["Authorization"] == "Bearer synthetic-non-token"
        if "$skiptoken" in url:
            assert counts(lab)["receipts"] >= 1 and counts(lab)["checkpoint"] >= 1
            return collectors.Reply(200, {}, {"value": [signin(2, data)]})
        return collectors.Reply(200, {}, {"value": [signin(1, data)], "@odata.nextLink": next_url})
    result = collectors.collect(lab, actor(), source["id"], data, http=provider, environment=credentials())
    assert result["status"] == "completed" and result["complete"] and result["checkpoint_version"] == 2
    assert result["durable_records"] == 2 and counts(lab) == {"receipts": 2, "checkpoint": 2}
    assert not result["cloud_live_tested"] and result["transport"] == "protocol_fixture"
    assert SECRET not in json.dumps(result) and "synthetic-non-token" not in json.dumps(result)
    replay = collectors.collect(lab, actor(), source["id"], {**data, "checkpoint_version": 2}, http=provider, environment=credentials())
    assert replay["complete"] and counts(lab)["receipts"] == 2
    record_property("collector_proof", json.dumps({"product": "entra_signin", "provider": "protocol_fixture", "pages": result["pages"], "receipts": counts(lab)["receipts"], "initial_checkpoint_version": result["checkpoint_version"], "replay_checkpoint_version": replay["checkpoint_version"], "receipt_before_next_page_asserted": True, "live_cloud_tested": False}))


def test_office_reads_only_existing_subscription_and_admits_blobs_before_next_blob(lab, record_property):
    source = declared(lab, "m365_audit")
    data = window("m365_audit")
    calls = []
    def provider(method, url, headers, payload, timeout):
        calls.append((method, url))
        if method == "POST":
            assert urllib.parse.parse_qs(payload.decode())["scope"] == ["https://manage.office.com/.default"]
            return token()
        assert "PublisherIdentifier=" + TENANT in url
        if "/subscriptions/list" in url:
            return collectors.Reply(200, {}, [{"contentType": "Audit.Exchange", "status": "enabled"}])
        if "/subscriptions/content" in url:
            return collectors.Reply(200, {}, [{"contentType": "Audit.Exchange", "contentId": "blob-" + str(number), "contentUri": "https://manage.office.com/api/v1.0/" + TENANT + "/activity/feed/audit/blob-" + str(number)} for number in (1, 2)])
        if "/audit/blob-2" in url:
            assert counts(lab) == {"receipts": 1, "checkpoint": 1}
            return collectors.Reply(200, {}, [audit(2, data)])
        return collectors.Reply(200, {}, [audit(1, data)])
    result = collectors.collect(lab, actor(), source["id"], data, http=provider, environment=credentials())
    assert result["complete"] and result["durable_records"] == 2 and result["checkpoint_version"] == 2
    assert [method for method, _ in calls] == ["POST", "GET", "GET", "GET", "GET"]
    assert not any("/subscriptions/start" in url or "/subscriptions/stop" in url for _, url in calls)
    assert counts(lab) == {"receipts": 2, "checkpoint": 2}
    record_property("collector_proof", json.dumps({"product": "m365_audit", "provider": "protocol_fixture", "requests": result["requests"], "receipts": 2, "checkpoint_version": 2, "subscription_creation": False, "live_cloud_tested": False}))


def test_missing_subscription_is_unavailable_without_vendor_mutation_or_fake_receipts(lab):
    source = declared(lab, "m365_audit")
    calls = []
    def provider(method, url, headers, payload, timeout):
        calls.append((method, url))
        return token() if method == "POST" else collectors.Reply(200, {}, [{"contentType": "Audit.Exchange", "status": "disabled"}])
    result = collectors.collect(lab, actor(), source["id"], window("m365_audit"), http=provider, environment=credentials())
    assert result["status"] == "unavailable" and result["reason"] == "subscription_required" and not result["complete"]
    assert counts(lab) == {"receipts": 0, "checkpoint": 0} and len(calls) == 2


@pytest.mark.parametrize("environment,reason", [({}, "credential_not_configured"), ({ENV: "invalid " + SECRET}, "credential_configuration_invalid"), (credentials(tenant_id=OTHER), "credential_tenant_mismatch")])
def test_credentials_and_tenant_pin_fail_before_network_without_leaking_secrets(lab, environment, reason):
    source = declared(lab)
    def forbidden(*args):
        raise AssertionError("Invalid credentials must not reach transport")
    result = collectors.collect(lab, actor(), source["id"], window(), http=forbidden, environment=environment)
    assert result["reason"] == reason and result["status"] == "unavailable" and result["requests"] == 0
    assert not result["cloud_live_tested"] and not result["live_vendor_attempted"] and not result["live_vendor_completed"]
    assert SECRET not in json.dumps(result) and ENV not in json.dumps(result)


@pytest.mark.parametrize("url", ["http://127.0.0.1/private", "https://evil.example/v1.0/auditLogs/signIns", "https://graph.microsoft.com@evil.example/v1.0/auditLogs/signIns", "https://graph.microsoft.com/v1.0/users", "https://graph.microsoft.com/v1.0/auditLogs/../users", "https://graph.microsoft.com/v1.0/auditLogs/%73ignIns", "https://graph.microsoft.com:444/v1.0/auditLogs/signIns", "https://graph.microsoft.com/v1.0/auditLogs/signIns#token"])
def test_graph_nextlink_cannot_redirect_credentials_or_advance_untrusted_page(lab, url):
    source = declared(lab)
    data = window()
    calls = []
    def provider(method, target, headers, payload, timeout):
        calls.append(target)
        return token() if method == "POST" else collectors.Reply(200, {}, {"value": [signin(1, data)], "@odata.nextLink": url})
    result = collectors.collect(lab, actor(), source["id"], data, http=provider, environment=credentials())
    assert result["reason"] == "unsafe_vendor_url" and result["complete"] is False
    assert counts(lab) == {"receipts": 0, "checkpoint": 0} and len(calls) == 2


def test_office_content_uri_pins_https_host_tenant_path_and_publisher():
    for url in ["https://127.0.0.1/private", "https://manage.office.com/api/v1.0/" + OTHER + "/activity/feed/audit/blob", "https://manage.office.com/api/v1.0/" + TENANT + "/activity/feed/subscriptions/start", "https://manage.office.com/api/v1.0/" + TENANT + "/activity/feed/audit/blob?PublisherIdentifier=" + OTHER]:
        with pytest.raises(collectors.CollectorFault, match="unsafe_vendor_url"):
            collectors._url(url, TENANT, "blob", TENANT)
    assert collectors.NoRedirect().redirect_request(None, None, 302, "moved", {}, "https://evil.invalid/") is None


def test_rate_limit_after_admitted_page_retains_receipts_and_checkpoint_without_secret_error_body(lab):
    source = declared(lab)
    data = window()
    def provider(method, url, headers, payload, timeout):
        if method == "POST":
            return token()
        if "$skiptoken" in url:
            return collectors.Reply(429, {"Retry-After": "999999"}, {"error": SECRET})
        return collectors.Reply(200, {}, {"value": [signin(1, data)], "@odata.nextLink": "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=second"})
    result = collectors.collect(lab, actor(), source["id"], data, http=provider, environment=credentials())
    assert result["status"] == "rate_limited" and result["retry_after_seconds"] == 300
    assert result["checkpoint_version"] == 1 and counts(lab) == {"receipts": 1, "checkpoint": 1}
    assert SECRET not in json.dumps(result) and not result["complete"]


def test_revocation_during_next_page_cannot_admit_second_record(lab):
    source = declared(lab)
    data = window()
    def provider(method, url, headers, payload, timeout):
        if method == "POST":
            return token()
        if "$skiptoken" in url:
            source_registry.revoke(lab, actor(), source["id"], 1)
            return collectors.Reply(200, {}, {"value": [signin(2, data)]})
        return collectors.Reply(200, {}, {"value": [signin(1, data)], "@odata.nextLink": "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=second"})
    result = collectors.collect(lab, actor(), source["id"], data, http=provider, environment=credentials())
    assert result["status"] == "authority_changed" and counts(lab) == {"receipts": 1, "checkpoint": 1}


@pytest.mark.parametrize("reply", [collectors.Reply(403, {}, {"error": SECRET}), collectors.Reply(302, {}, {"error": SECRET}), collectors.Reply(200, {}, {"access_token": SECRET, "token_type": []})])
def test_vendor_failures_and_malformed_oauth_do_not_echo_reply_or_claim_live_verification(lab, reply):
    source = declared(lab)
    result = collectors.collect(lab, actor(), source["id"], window(), http=lambda *args: reply, environment=credentials())
    assert not result["complete"] and not result["cloud_live_tested"] and not result["live_vendor_completed"]
    assert SECRET not in json.dumps(result) and counts(lab) == {"receipts": 0, "checkpoint": 0}


def test_empty_pagination_is_bounded_and_does_not_forge_a_checkpoint(lab):
    source = declared(lab)
    calls = []
    def provider(method, url, headers, payload, timeout):
        calls.append(url)
        return token() if method == "POST" else collectors.Reply(200, {}, {"value": [], "@odata.nextLink": "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=" + str(len(calls))})
    result = collectors.collect(lab, actor(), source["id"], window(), http=provider, environment=credentials())
    assert result["status"] == "partial" and result["reason"] == "page_limit"
    assert result["pages"] == collectors.MAX_PAGES and len(calls) == collectors.MAX_PAGES + 1
    assert counts(lab) == {"receipts": 0, "checkpoint": 0}


def test_default_https_reader_enforces_byte_bound_before_json_or_error_echo(monkeypatch):
    class Response:
        status = 200
        def __init__(self):
            self.headers = {}
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return None
        def read1(self, count):
            return b"x" * count
        read = read1
    class Opener:
        def open(self, request, timeout):
            return Response()
    monkeypatch.setattr(collectors.urllib.request, "build_opener", lambda *args: Opener())
    monkeypatch.setattr(collectors, "MAX_BYTES", 8)
    with pytest.raises(collectors.CollectorFault, match="response_bytes_exceeded"):
        collectors.request_https("GET", "https://graph.microsoft.com/v1.0/auditLogs/signIns", {}, None, 1)


def test_default_transport_selection_alone_never_claims_cloud_qualification(lab, monkeypatch):
    source = declared(lab)
    monkeypatch.setenv(ENV, credentials()[ENV])
    monkeypatch.setattr(collectors, "request_https", lambda *args: collectors.Reply(403, {}, {"error": SECRET}))
    result = collectors.collect(lab, actor(), source["id"], window())
    assert result["live_vendor_attempted"] is True and result["live_vendor_completed"] is False
    assert result["cloud_live_tested"] is False and SECRET not in json.dumps(result)
