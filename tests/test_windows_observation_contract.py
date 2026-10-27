"""Unbound native observations are preserved without ghost process nodes."""

from datetime import UTC, datetime

import pytest

from sapientia import xdr_bridge
from tests.test_xdr_bridge import START, actor, ingest

pytest_plugins = ["tests.test_xdr_bridge"]


def observed(provider, code, action, module):
    return {
        "@timestamp": datetime.fromtimestamp(START, UTC).isoformat(),
        "host": {"id": "host1"},
        "event": {
            "provider": provider,
            "code": code,
            "action": action,
            "module": module,
        },
        "agent": {
            "collector": "windows-event-log",
            "process_identity_kind": "unavailable_for_windows_event_log_observation",
        },
        "windows_event": {
            "observed_process": {"pid": 42, "executable": "historical.exe"}
        },
    }


ROWS = [
    (provider, code, action, module)
    for provider, (module, actions) in xdr_bridge.WINDOWS_OBSERVATION_EVENTS.items()
    for code, action in actions.items()
]


@pytest.mark.parametrize("row", ROWS)
def test_exact_provider_code_action_observation_has_no_invented_process(row):
    data = xdr_bridge._typed(observed(*row))
    assert "process" not in data
    assert data["windows_event"]["observed_process"]["pid"] == 42


@pytest.mark.parametrize(
    "field",
    [
        "guid",
        "pid",
        "start_identity",
        "parent.guid",
        "parent.pid",
        "parent.start_identity",
    ],
)
def test_observation_marker_cannot_bypass_fake_process_identity(field):
    data = observed("Security", "4624", "logon_success", "security")
    data["process"] = {}
    target = data["process"]
    if field.startswith("parent."):
        target = target.setdefault("parent", {})
        field = field.split(".")[1]
    target[field] = 42 if field == "pid" else "fabricated"
    with pytest.raises(ValueError, match="cannot invent"):
        xdr_bridge._typed(data)


@pytest.mark.parametrize(
    "field,value",
    [
        ("provider", "unknown"),
        ("code", "99999"),
        ("action", "process_created"),
        ("module", "sysmon"),
        ("code", []),
        ("provider", {}),
    ],
)
def test_wrong_or_malformed_observation_contract_is_rejected(field, value):
    data = observed("Security", "4624", "logon_success", "security")
    data["event"][field] = value
    with pytest.raises(ValueError):
        xdr_bridge._typed(data)


def test_login_and_defender_evidence_does_not_create_ghost_graph_nodes(store):
    login = observed("Security", "4624", "logon_success", "security")
    defender = observed(
        "Microsoft-Windows-Windows Defender/Operational",
        "1116",
        "defender_detection",
        "security",
    )
    intake = ingest(
        store,
        [
            {"id": "native-unbound-login", "data": login},
            {"id": "native-unbound-defender", "data": defender},
        ],
    )
    assert intake["accepted"] == 2
    store.flush()
    assert xdr_bridge.process_tree(store, actor(), START, START + 100)["nodes"] == []
    assert xdr_bridge.telemetry(store, actor(), START, START + 100)["total"] == 2
