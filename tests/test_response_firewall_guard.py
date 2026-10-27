"""Pure policy-state checks; no actual host isolation or firewall mutation."""

import copy
import importlib

import pytest

from sapientia.endpoint_agent.Agent.core import response

guard = importlib.import_module(response.__package__ + ".firewall_guard")


def state():
    return {
        "modify_state": 0,
        "profiles": {
            profile: {"enabled": True, "excluded": []} for profile in (1, 2, 4)
        },
    }


def test_explicit_enabled_profiles_and_local_rule_effect_required():
    assert guard.verify(state()) is True


@pytest.mark.parametrize(
    "fault", ["override", "disabled", "excluded", "unknown", "bool", "missing_profile"]
)
def test_unknown_or_ineffective_windows_policy_denies(fault):
    value = copy.deepcopy(state())
    if fault == "override":
        value["modify_state"] = 1
    elif fault == "disabled":
        value["profiles"][2]["enabled"] = False
    elif fault == "excluded":
        value["profiles"][4]["excluded"] = ["Ethernet"]
    elif fault == "unknown":
        value["profiles"][1]["enabled"] = None
    elif fault == "bool":
        value["modify_state"] = False
    else:
        value["profiles"].pop(4)
    with pytest.raises(PermissionError):
        guard.verify(value)


def test_partial_cleanup_still_attempts_every_owned_rule(monkeypatch):
    operations = importlib.import_module(response.__package__ + ".operations")
    calls = []

    def batch(identifier, rules, **kwargs):
        calls.append((identifier, rules, kwargs))
        raise OSError("Synthetic native owned removal error")

    monkeypatch.setattr(operations.os, "name", "nt")
    monkeypatch.setattr(operations, "_windows_batch", batch)
    with pytest.raises(OSError):
        operations._driver("1" * 32, {"allowlist": [], "endpoints": []}, release=True)
    assert (
        len(calls) == 1
        and list(calls[0][1])[:2]
        == [
            "Lumina-Isolation-" + "1" * 32 + "-in",
            "Lumina-Isolation-" + "1" * 32 + "-out",
        ]
        and calls[0][2]["release"] is True
        and len(calls[0][1]) == 2560
    )


def test_invalid_low_level_receipt_never_reaches_os_tool(monkeypatch):
    operations = importlib.import_module(response.__package__ + ".operations")
    monkeypatch.setattr(
        operations, "_run", lambda *args, **kwargs: pytest.fail("No OS tool expected")
    )
    with pytest.raises(ValueError):
        operations._driver("id;bad", {"allowlist": [], "endpoints": []}, release=True)
