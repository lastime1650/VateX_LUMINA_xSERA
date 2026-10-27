"""Native event facts must not invent process lifetimes or bind creator as child."""
# ruff: noqa: F811 -- Imported pytest sensor fixture is injected by argument name.

from datetime import UTC, datetime

import pytest

from sapientia import endpoint_response, xdr_bridge
from tests.test_agent_remediation import channel, sensor, windows, xml  # noqa: F401

OBSERVER = "unavailable_for_windows_event_log_observation"


def sampled_process(pid=128, birth_delta=100, ppid=0, name="child.exe"):
    born = (
        int(datetime(2026, 10, 12, tzinfo=UTC).timestamp() * 10_000_000)
        + 116444736000000000
    )
    return {
        "pid": pid,
        "birth": None if birth_delta is None else born + birth_delta,
        "ppid": ppid,
        "name": name,
        "executable": "C:\\owned\\" + name,
    }


def test_temporarily_inaccessible_birth_neither_exits_nor_falsely_binds_live_event(
    sensor, monkeypatch
):
    current = [sampled_process()]
    monkeypatch.setattr(windows, "_process_rows", lambda: current)
    assert len(sensor._process_events("HOST")) == 1
    native_guid = "{11111111-2222-3333-4444-555555555555}"
    sensor.provider_processes[native_guid] = (128, current[0]["birth"])
    old_key = next(iter(sensor.last_rows))
    current[:] = [sampled_process(birth_delta=None)]
    assert sensor._process_events("HOST") == []
    assert not sensor.last_rows and old_key in sensor.process_history
    assert old_key in sensor.seen and native_guid in sensor.provider_processes
    channel(
        monkeypatch,
        [
            xml(
                1,
                3,
                {
                    "ProcessId": "128",
                    "ProcessGuid": native_guid,
                    "Image": r"C:\owned\child.exe",
                },
            )
        ],
    )
    data = sensor._log_events("HOST")[0]["data"]
    assert data["agent"]["process_response_eligible"] is False
    assert "start_identity" not in data["process"]
    current[:] = [sampled_process()]
    assert (
        sensor._process_events("HOST") == []
    )  # Same birth restoration is not new creation.
    current.clear()
    exit_event = sensor._process_events("HOST")[0]["data"]
    assert exit_event["event"]["action"] == "process_terminated"
    assert (
        exit_event["agent"]["process_exit_evidence_kind"]
        == "inferred_missing_from_snapshot"
    )
    assert exit_event["agent"]["observation_time"] == exit_event["@timestamp"]
    assert exit_event["agent"]["process_response_eligible"] is False
    assert sensor._process_events("HOST") == []


def test_known_reused_pid_ends_old_instance_after_an_uncertain_snapshot(
    sensor, monkeypatch
):
    current = [sampled_process()]
    monkeypatch.setattr(windows, "_process_rows", lambda: current)
    first = sensor._process_events("HOST")[0]["data"]["process"]["guid"]
    current[:] = [sampled_process(birth_delta=None)]
    assert sensor._process_events("HOST") == []
    current[:] = [sampled_process(birth_delta=200)]
    events = sensor._process_events("HOST")
    assert len(events) == 2
    created, ended = [event["data"] for event in events]
    assert created["process"]["guid"] != first and ended["process"]["guid"] == first
    assert ended["agent"]["process_exit_evidence_kind"] == "inferred_pid_reuse"
    assert len(sensor.process_history) == 1


@pytest.mark.parametrize(
    "parent_birth,allowed", [(50, True), (200, False), (None, False)]
)
def test_sampled_parent_must_have_been_born_by_child_creation(
    sensor, monkeypatch, parent_birth, allowed
):
    rows = [
        sampled_process(ppid=64),
        sampled_process(pid=64, birth_delta=parent_birth, name="parent.exe"),
    ]
    monkeypatch.setattr(windows, "_process_rows", lambda: rows)
    data = next(
        event["data"]
        for event in sensor._process_events("HOST")
        if event["data"]["process"]["pid"] == 128
    )
    parent = data["process"]["parent"]
    assert parent["pid"] == 64
    assert bool(parent["guid"]) is allowed and bool(parent["name"]) is allowed


def test_uncertain_process_history_and_live_snapshot_restore_on_queue_rollback(
    sensor, monkeypatch
):
    current = [sampled_process()]
    monkeypatch.setattr(windows, "_process_rows", lambda: current)
    sensor._process_events("HOST")
    previous = sensor.last_rows.copy()
    sensor.begin_cycle()
    current[:] = [sampled_process(birth_delta=None)]
    sensor._process_events("HOST")
    assert not sensor.last_rows and sensor.process_history == previous
    sensor.rollback()
    assert sensor.last_rows == previous and sensor.process_history == previous


def test_failed_process_snapshot_keeps_history_without_live_identity_binding(
    sensor, monkeypatch
):
    monkeypatch.setattr(windows, "_process_rows", lambda: [sampled_process()])
    sensor._process_events("HOST")
    previous = sensor.last_rows.copy()

    def unavailable():
        raise OSError("Owned simulated snapshot access loss")

    monkeypatch.setattr(windows, "_process_rows", unavailable)
    assert sensor._process_events("HOST") == []
    assert not sensor.last_rows and sensor.process_history == previous
    assert sensor.providers["toolhelp"]["state"] == "error"


def creation_fields():
    return {
        "NewProcessId": "0x80",
        "NewProcessName": r"C:\owned\child.exe",
        "ProcessId": "0x40",
        "ParentProcessName": r"C:\owned\parent.exe",
    }


def test_4688_maps_real_child_and_creator_without_claiming_a_native_lifetime(
    sensor, monkeypatch
):
    fields = creation_fields()
    channel(monkeypatch, [xml(1, 4688, fields)], "Security")
    event = sensor._log_events("HOST")[0]
    data = event["data"]
    assert (
        data["process"]["pid"] == 128
        and data["process"]["executable"] == fields["NewProcessName"]
    )
    assert data["process"]["parent"]["pid"] == 64
    assert data["process"]["parent"]["executable"] == fields["ParentProcessName"]
    assert data["agent"]["process_identity_kind"] == "windows_creation_event_record"
    assert data["agent"]["process_response_eligible"] is False
    assert "start_identity" not in data["process"]
    xdr_bridge.parse_event(event, "agent", "endpoint", expected_host="HOST")
    with pytest.raises(ValueError, match="start identity"):
        endpoint_response.action(
            {
                "type": "terminate_process",
                "process_guid": data["process"]["guid"],
                "pid": 128,
            },
            "windows",
        )


def test_real_4688_birth_proves_child_lifetime_never_creator_lifetime(
    sensor, monkeypatch
):
    born = (
        int(datetime(2026, 10, 12, tzinfo=UTC).timestamp() * 10_000_000)
        + 116444736000000000
    )
    sensor.last_rows = {
        "child": {
            "pid": 128,
            "birth": born,
            "name": "child.exe",
            "executable": r"C:\owned\child.exe",
        },
        "creator": {"pid": 64, "birth": born - 10_000_000, "name": "parent.exe"},
    }
    channel(monkeypatch, [xml(1, 4688, creation_fields())], "Security")
    data = sensor._log_events("HOST")[0]["data"]
    assert data["process"]["pid"] == 128 and data["process"][
        "start_identity"
    ] == "windows:" + str(born)
    assert data["agent"]["process_identity_kind"] == "windows_live_creation_time"
    assert data["agent"]["process_response_eligible"] is True
    assert "provider_process_guid" not in data["agent"]
    assert data["agent"]["creation_event_identity"] != data["process"]["guid"]


@pytest.mark.parametrize("actual", [r"C:\different\child.exe", None])
def test_same_pid_birth_and_basename_cannot_enrich_a_wrong_or_unknown_full_image(
    sensor, monkeypatch, actual
):
    born = (
        int(datetime(2026, 10, 12, tzinfo=UTC).timestamp() * 10_000_000)
        + 116444736000000000
    )
    sensor.last_rows = {
        "child": {"pid": 128, "birth": born, "name": "child.exe", "executable": actual}
    }
    channel(monkeypatch, [xml(1, 4688, creation_fields())], "Security")
    data = sensor._log_events("HOST")[0]["data"]
    assert data["agent"]["process_identity_kind"] == "windows_creation_event_record"
    assert data["agent"]["process_response_eligible"] is False
    assert "start_identity" not in data["process"]


def test_cached_native_guid_does_not_override_wrong_image_on_a_later_event(
    sensor, monkeypatch
):
    born = (
        int(datetime(2026, 10, 12, tzinfo=UTC).timestamp() * 10_000_000)
        + 116444736000000000
    )
    sensor.last_rows = {
        "child": {
            "pid": 128,
            "birth": born,
            "name": "child.exe",
            "executable": r"C:\owned\child.exe",
        }
    }
    sensor.provider_processes = {"real-provider-guid": (128, born)}
    channel(
        monkeypatch,
        [
            xml(
                1,
                3,
                {
                    "ProcessGuid": "real-provider-guid",
                    "ProcessId": "128",
                    "Image": r"C:\different\child.exe",
                },
            )
        ],
    )
    data = sensor._log_events("HOST")[0]["data"]
    assert data["process"]["guid"] == "real-provider-guid"
    assert "start_identity" not in data["process"]
    assert data["agent"]["process_response_eligible"] is False


@pytest.mark.parametrize(
    "code,provider",
    [
        (4624, "Security"),
        (4625, "Security"),
        (4648, "Security"),
        (4768, "Security"),
        (4769, "Security"),
        (4689, "Security"),
        (4657, "Security"),
        (4663, "Security"),
        (5156, "Security"),
        (5157, "Security"),
        (1116, "Microsoft-Windows-Windows Defender/Operational"),
        (1117, "Microsoft-Windows-Windows Defender/Operational"),
        (6, "Microsoft-Windows-Sysmon/Operational"),
    ],
)
def test_missing_lifetime_is_an_observation_and_reported_pid_stays_out_of_process(
    sensor, monkeypatch, code, provider
):
    fields = {
        "ProcessId": "0x40",
        "ProcessName": r"C:\owned\reported.exe",
        "TargetUserName": "fixture",
    }
    channel(monkeypatch, [xml(1, code, fields)], provider)
    event = sensor._log_events("HOST")[0]
    data = event["data"]
    assert data["process"]["name"] == "reported.exe"
    assert not {"pid", "guid", "start", "start_identity", "parent"} & set(data["process"])
    assert data["agent"]["process_identity_kind"] == OBSERVER
    assert data["agent"]["process_response_eligible"] is False
    assert data["windows_event"]["observed_process"]["pid"] == 64
    assert "guid" not in data["windows_event"]["observed_process"]
    assert data["windows_event"]["original_fields"] == fields
    xdr_bridge.parse_event(event, "agent", "endpoint", expected_host="HOST")
    data["process"]["pid"] = 64
    with pytest.raises(ValueError):
        xdr_bridge.parse_event(event, "agent", "endpoint", expected_host="HOST")


def test_native_sysmon_guid_retains_valid_historical_identity_without_response_birth(
    sensor, monkeypatch
):
    channel(
        monkeypatch,
        [
            xml(
                1,
                3,
                {
                    "ProcessGuid": "actual-provider-guid",
                    "ProcessId": "42",
                    "Image": r"C:\owned\observed.exe",
                },
            )
        ],
    )
    data = sensor._log_events("HOST")[0]["data"]
    assert data["process"]["guid"] == "actual-provider-guid"
    assert data["agent"]["process_identity_kind"] == "windows_provider_process_guid"
    assert data["agent"]["process_response_eligible"] is False
    assert "start_identity" not in data["process"]


def test_creation_record_identity_changes_after_channel_clear_or_same_id_replacement(
    sensor, monkeypatch
):
    records = [xml(1, 4688, creation_fields())]
    channel(monkeypatch, records, "Security")
    old = sensor._log_events("HOST")[0]
    records[:] = [xml(1, 4688, creation_fields(), timestamp="2026-10-12T00:01:00Z")]
    new = sensor._log_events("HOST")[0]
    assert old["data"]["process"]["guid"] != new["data"]["process"]["guid"]
    assert new["data"]["agent"]["channel_epoch"] == 1


def test_network_security_native_processid_and_application_preserved_as_observation(
    sensor, monkeypatch
):
    channel(
        monkeypatch,
        [
            xml(
                1,
                5156,
                {
                    "ProcessID": "128",
                    "Application": r"\device\harddiskvolume3\owned\app.exe",
                },
            )
        ],
        "Security",
    )
    data = sensor._log_events("HOST")[0]["data"]
    assert data["process"]["executable"].endswith("app.exe")
    assert not {"pid", "guid", "start", "start_identity", "parent"} & set(data["process"])
    assert data["agent"]["process_response_eligible"] is False
    assert data["windows_event"]["observed_process"]["pid"] == 128
    assert data["windows_event"]["observed_process"]["executable"].endswith("app.exe")
