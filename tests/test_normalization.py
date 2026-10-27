import copy
import json

import pytest

from sapientia import normalization
from sapientia.connectors import parse_line
from sapientia.query import Query
from sapientia.storage import Settings, Store


@pytest.mark.parametrize("event_id,outcome", [(4624, "success"), (4625, "failure")])
def test_windows_authentication_uses_target_and_retains_evidence(event_id, outcome):
    event = {
        "raw": {
            "System": {"EventID": event_id},
            "EventData": {
                "TargetUserName": "Alice",
                "TargetDomainName": "ACME",
                "SubjectUserName": "SYSTEM",
                "IpAddress": "::ffff:192.0.2.4",
                "ProcessName": r"C:\Windows\lsass.exe",
            },
        }
    }
    original = copy.deepcopy(event)
    result = normalization.normalize(event)
    security = result["raw"]["security"]
    assert event == original
    assert {k: v for k, v in result["raw"].items() if k != "security"} == original[
        "raw"
    ]
    assert security["user"] == r"ACME\Alice"
    assert security["action"] == "authentication"
    assert security["outcome"] == outcome
    assert security["src_ip"] == "192.0.2.4"
    assert security["process"] == r"C:\Windows\lsass.exe"
    assert security["schema"] == "sapientia-security"
    assert security["version"] == 1
    assert security["mapping"] == "windows-eventdata-v1"
    assert security["provenance"]["user"] == [
        "raw.EventData.TargetUserName",
        "raw.EventData.TargetDomainName",
    ]
    assert normalization.normalize(result) == result


def test_windows_process_creator_and_camelcase_collector_fields():
    result = normalization.normalize(
        {
            "raw": {
                "win": {
                    "system": {"eventID": "4688"},
                    "eventdata": {
                        "subjectUserName": "creator",
                        "subjectDomainName": "ACME",
                        "targetUserName": "target",
                        "newProcessName": r"C:\cmd.exe",
                    },
                }
            }
        }
    )["raw"]["security"]
    assert result["user"] == r"ACME\creator"
    assert result["process"] == r"C:\cmd.exe"
    assert (result["action"], result["outcome"]) == ("process_create", "success")


@pytest.mark.parametrize(
    "raw",
    [
        {
            "Event": {
                "System": {"EventID": {"#text": "4625"}},
                "EventData": {"TargetUserName": "alice"},
            }
        },
        {"winlog": {"event_id": 4625, "event_data": {"TargetUserName": "alice"}}},
    ],
)
def test_windows_nested_and_winlog_formats(raw):
    security = normalization.normalize({"raw": raw})["raw"]["security"]
    assert (security["user"], security["outcome"]) == ("alice", "failure")


def test_windows_never_substitutes_actor_for_missing_target():
    security = normalization.normalize(
        {
            "raw": {
                "EventID": 4625,
                "EventData": {"SubjectUserName": "SYSTEM", "IpAddress": "-"},
            }
        }
    )["raw"]["security"]
    assert "user" not in security and "src_ip" not in security
    assert security["outcome"] == "failure"


@pytest.mark.parametrize("event_id", [4626, True, "4625.0"])
def test_unknown_windows_events_do_not_invent_authentication(event_id):
    event = {"raw": {"EventID": event_id, "EventData": {"TargetUserName": "alice"}}}
    assert normalization.normalize(event) == event


def test_syslog_json_enrichment_preserves_original_timestamp_and_line():
    payload = '{"user":"alice","action":"login_failed","src_ip":"2001:0db8::1"}'
    line = "<34>1 2025-01-02T03:04:05Z host auth - - - " + payload
    event = parse_line(line, "syslog", "collector", "1")
    original = copy.deepcopy(event)
    normalized = normalization.normalize(event)
    security = normalized["raw"]["security"]
    assert (security["user"], security["action"], security["outcome"]) == (
        "alice",
        "authentication",
        "failure",
    )
    assert security["src_ip"] == "2001:db8::1"
    assert security["mapping"] == "rfc5424-json-v1"
    assert security["provenance"]["user"] == ["message.JSON.user"]
    assert normalized["raw"]["line"] == line
    assert normalized["event_time"] == original["event_time"]
    assert normalized["message"] == original["message"]
    assert event == original


@pytest.mark.parametrize(
    "message",
    [
        "- login_failed user=alice from 192.0.2.4",
        '- {"user":"alice","user":"bob","action":"login_failed"}',
        '- {"user":"alice"} trailing prose',
        '- ["alice"]',
    ],
)
def test_syslog_prose_and_ambiguous_json_are_not_guessed(message):
    event = {
        "sourcetype": "syslog:rfc5424",
        "message": message,
        "raw": {"line": message},
    }
    assert normalization.normalize(event) == event


def test_cef_standard_extensions_escapes_and_evidence():
    line = r"CEF:0|vendor|product|1|42|auth|7|src=192.0.2.4 dst=198.51.100.8 suser=ACME\\alice act=login_failed sproc=C:\\auth.exe"
    event = parse_line(line, "cef", "collector", "2")
    security = normalization.normalize(event)["raw"]["security"]
    assert security["user"] == r"ACME\alice"
    assert security["process"] == r"C:\auth.exe"
    assert security["src_ip"] == "192.0.2.4"
    assert security["dest_ip"] == "198.51.100.8"
    assert security["action"] == "authentication"
    assert security["outcome"] == "failure"
    assert security["mapping"] == "cef-extension-v1"
    assert "security" not in event["raw"]


def test_cef_ambiguous_principals_and_processes_are_omitted():
    security = normalization.normalize(
        {
            "sourcetype": "cef",
            "raw": {
                "extension": "suser=alice duser=bob sproc=client dproc=server act=login outcome=failure"
            },
        }
    )["raw"]["security"]
    assert "user" not in security and "process" not in security
    assert security["conflicts"] == ["process", "user"]
    assert security["outcome"] == "failure"


@pytest.mark.parametrize(
    "extension",
    [r"suser=alice suser=bob act=login_failed", r"suser=alice\q act=login_failed"],
)
def test_invalid_cef_extensions_do_not_supply_fields(extension):
    event = {"sourcetype": "cef", "raw": {"extension": extension}}
    assert normalization.normalize(event) == event


def test_structured_and_otlp_fields_with_conflicting_outcome():
    security = normalization.normalize(
        {
            "raw": {
                "attributes": {
                    "user.name": "alice",
                    "source.address": "192.0.2.4",
                    "destination.address": "198.51.100.8",
                    "process.executable": "/bin/auth",
                    "event.action": "login_failed",
                    "event.outcome": "success",
                }
            }
        }
    )["raw"]["security"]
    assert security["user"] == "alice"
    assert security["process"] == "/bin/auth"
    assert security["action"] == "authentication"
    assert "outcome" not in security
    assert security["conflicts"] == ["outcome"]
    assert security["provenance"]["user"] == ['raw.attributes["user.name"]']


def test_conflicting_generic_identity_never_picks_arbitrary_alias():
    security = normalization.normalize(
        {
            "raw": {
                "user": "alice",
                "username": "bob",
                "action": "login_failed",
                "src_ip": "invalid",
                "dest_ip": "0.0.0.0",
            }
        }
    )["raw"]["security"]
    assert (
        "user" not in security
        and "src_ip" not in security
        and "dest_ip" not in security
    )
    assert security["conflicts"] == ["user"]


@pytest.mark.parametrize(
    "event",
    [
        {"raw": {}},
        {"raw": "unchanged"},
        {"raw": {"irrelevant": "value"}},
        {"raw": {"user": "-", "action": "unknown_action", "outcome": "blocked"}},
    ],
)
def test_no_empty_metadata_and_source_security_is_preserved(event):
    original = copy.deepcopy(event)
    result = normalization.normalize(event)
    assert result == original and event == original
    assert result is not event
    if isinstance(event["raw"], dict):
        assert result["raw"] is not event["raw"]


@pytest.mark.parametrize("security", [None, {"user": "source-provided"}])
def test_invalid_or_conflicting_canonical_cannot_suppress_source_mapping(security):
    event = {"raw": {"security": security, "user": "alice"}}
    original = copy.deepcopy(event)
    with pytest.raises(ValueError):
        normalization.normalize(event)
    assert event == original


def test_canonical_fields_correlate_windows_cef_and_syslog_in_isolated_store(tmp_path):
    events = [
        {
            "event_id": "windows",
            "event_time": 100,
            "raw": {
                "EventID": 4625,
                "EventData": {"TargetUserName": "alice"},
            },
        },
        parse_line(
            "CEF:0|v|p|1|42|auth|7|suser=alice act=login_failed",
            "cef",
            "collector",
            "cef",
        ),
        parse_line(
            '<34>1 1970-01-01T00:01:42Z host auth - - - {"username":"alice","action":"login_success"}',
            "syslog",
            "collector",
            "syslog",
        ),
    ]
    events[1]["event_time"] = 101
    store = Store(Settings(tmp_path, min_free_bytes=0))
    try:
        store.ingest("a", [normalization.normalize(event) for event in events])
        store.flush()
        parsed = Query.parse(
            {
                "query": "* | stats count BY raw.security.user,raw.security.action",
                "earliest": 0,
                "latest": 1000,
            }
        )
        sql, args = parsed.compile("a")
        con = store.analytics.cursor()
        try:
            row = con.execute(sql, args).fetchone()
            assert (
                row is not None
                and 3 in row
                and "alice" in row
                and "authentication" in row
            )
            originals = {
                eid: json.loads(raw)
                for eid, raw in con.execute(
                    "SELECT event_id,raw FROM events"
                ).fetchall()
            }
            assert originals["windows"]["EventData"] == events[0]["raw"]["EventData"]
            assert originals["syslog"]["line"] == events[2]["raw"]["line"]
        finally:
            con.close()
    finally:
        store.close()
