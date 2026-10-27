"""Native XML observations; never invent a created process for a denied image."""
# ruff: noqa: F811 -- Imported pytest sensor fixture is injected by argument name.

import xml.etree.ElementTree as ET

import pytest

from sapientia import xdr_bridge
from sapientia.endpoint_agent.Agent.Windows import collector as windows
from tests.test_agent_remediation import (  # noqa: F401 - pytest fixture
    channel,
    sensor,
    xml,
)

POLICY = "{0B917648-8B6E-4F84-A6A7-A71529106BBA}"
NAME = windows.CODE_INTEGRITY_CHANNEL


@pytest.mark.parametrize("code", [3076, 3077, 3089])
def test_native_ci_preserves_original_observation_and_never_invents_process(
    sensor, monkeypatch, code
):
    fields = {
        "FileNameBuffer": r"\Device\HarddiskVolume3\owned\payload.exe",
        "ProcessNameBuffer": r"\Device\HarddiskVolume3\Windows\System32\parent.exe",
        "PolicyGUID": POLICY,
        "PolicyName": "Vatex LUMINA xSERA owned",
        "SHA256FlatHash": "a" * 64,
        "SHA256Hash": "b" * 64,
        "RequestedSigningLevel": "8",
        "ValidatedSigningLevel": "0",
        "Status": "0xc0000428",
        "PublisherName": "fixture publisher",
        "SignatureIndex": "0",
        "TotalSignatureCount": "1",
    }
    root = xml(42, code, fields)
    system = root.find("{*}System")
    namespace = "http://schemas.microsoft.com/win/2004/08/events/event"
    ET.SubElement(system, "{" + namespace + "}Execution", ProcessID="4")
    ET.SubElement(
        system, "{" + namespace + "}Correlation", ActivityID="{native-activity}"
    )
    channel(monkeypatch, [root], NAME)
    event = sensor._log_events("HOST")[0]
    data = event["data"]
    normalized = xdr_bridge.parse_event(
        event, "agent", "endpoint", expected_host="HOST"
    )
    assert normalized["raw"]["xdr"]["data"] == data
    assert (
        data["event"]["code"] == str(code)
        and data["event"]["module"] == "code_integrity"
    )
    assert "process" not in data
    assert data["file"]["path"] == fields["FileNameBuffer"]
    assert data["file"]["hash"]["sha256"] == "a" * 64
    ci = data["code_integrity"]
    assert ci["hash"]["authenticode_sha256"] == "b" * 64
    assert ci["logging_process_pid"] == 4
    assert "target_image_created" not in ci
    if code == 3077:
        assert ci["image_loaded"] is False
    else:
        assert "image_loaded" not in ci
    assert ci["initiator"]["executable"] == fields["ProcessNameBuffer"]
    assert ci["policy_id"] == POLICY and ci["activity_id"] == "{native-activity}"
    assert ci["status"] == 0xC0000428 and ci["requested_signing_level"] == 8
    assert ci["original_fields"] == fields
    assert (
        data["agent"]["process_identity_kind"]
        == "unavailable_for_code_integrity_observation"
    )
    assert sensor.providers[NAME]["state"] == "ready"
    assert sensor.cursors[NAME]["record"] == 42


def test_authenticode_digest_is_not_silently_mapped_to_flat_sha256(sensor, monkeypatch):
    fields = {
        "FileNameBuffer": r"C:\owned\payload.exe",
        "SHA256Hash": "c" * 64,
        "SHA256FlatHash": "invalid",
    }
    channel(monkeypatch, [xml(1, 3077, fields)], NAME)
    data = sensor._log_events("HOST")[0]["data"]
    assert not data["file"]["hash"]
    assert data["code_integrity"]["hash"]["authenticode_sha256"] == "c" * 64
    assert "process" not in data


def test_native_dll_denial_is_image_load_evidence_not_a_process_creation_claim(sensor, monkeypatch):
    channel(monkeypatch, [xml(1, 3077, {"FileNameBuffer": r"\Device\HarddiskVolume3\owned\library.dll"})], NAME)
    event = sensor._log_events("HOST")[0]
    data = event["data"]
    assert data["event"]["action"] == "image_load_denied"
    assert data["code_integrity"]["image_loaded"] is False
    assert "process" not in data and "target_image_created" not in data["code_integrity"]
    normalized = xdr_bridge.parse_event(event, "agent", "endpoint", expected_host="HOST")
    assert normalized["raw"]["action"] == "image_load_denied"


def test_signer_observation_can_have_no_file_or_process_identity(sensor, monkeypatch):
    channel(
        monkeypatch,
        [
            xml(
                1,
                3089,
                {
                    "PublisherName": "fixture",
                    "SignatureType": "1",
                    "VerificationError": "0",
                },
            )
        ],
        NAME,
    )
    data = sensor._log_events("HOST")[0]["data"]
    assert data["event"]["action"] == "code_signature_metadata"
    assert "process" not in data and "path" not in data["file"]
    assert data["code_integrity"]["signature"]["verification_error"] == 0


def test_ci_priority_cursor_pages_reset_and_retry(sensor, monkeypatch):
    first = xml(20, 3077, {"PolicyGUID": POLICY})
    channel(monkeypatch, [first], NAME)
    initial = sensor._log_events("HOST", limit=1)
    assert len(initial) == 1 and sensor.cursors[NAME]["record"] == 20
    assert sensor._log_events("HOST", limit=1) == []
    channel(monkeypatch, [xml(1, 3077, {"PolicyGUID": POLICY})], NAME)
    reset = sensor._log_events("HOST", limit=1)
    assert len(reset) == 1 and reset[0]["id"] != initial[0]["id"]
    assert sensor.cursors[NAME]["epoch"] == 1
    assert sensor.providers[NAME]["code"] == "channel_reset_or_retention_gap"


def test_ci_field_sizes_and_malformed_numeric_values_are_bounded(sensor, monkeypatch):
    fields = {
        "FileNameBuffer": "C:\\owned\\" + "a" * 2000,
        "Status": "garbage",
        "RequestedSigningLevel": "-1",
        "SHA256Hash": "c" * 65,
    }
    fields.update({f"extra-{i}": "x" * 4096 for i in range(100)})
    channel(monkeypatch, [xml(1, 3077, fields)], NAME)
    data = sensor._log_events("HOST")[0]["data"]
    assert len(data["file"]["path"]) == 512
    assert len(data["code_integrity"]["original_fields"]) == 64
    assert all(
        len(value) <= 512
        for value in data["code_integrity"]["original_fields"].values()
    )
    assert (
        "status" not in data["code_integrity"]
        and "requested_signing_level" not in data["code_integrity"]
    )
    assert not data["code_integrity"]["hash"]


def test_ci_provider_error_is_visible_and_cursor_not_advanced(sensor, monkeypatch):
    def unavailable(name, **_kwargs):
        if name == NAME:
            raise RuntimeError("native channel unavailable")
        return []

    monkeypatch.setattr(windows, "_xml_events", unavailable)
    assert sensor._log_events("HOST") == []
    assert sensor.providers[NAME]["state"] == "error"
    assert NAME not in sensor.cursors
