"""Observation release blocks new and already queued native changes."""
import json

import pytest

from sapientia import endpoint_response as response


@pytest.mark.parametrize("kind", sorted(response.ACTIONS - response.READ_ACTIONS))
def test_observation_profile_rejects_native_actions_before_any_database_use(monkeypatch, kind):
    monkeypatch.setenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", "1")
    with pytest.raises(PermissionError, match="blocks native"):
        response._guard(None, {"action": json.dumps({"type": kind})})


@pytest.mark.parametrize("kind", sorted(response.READ_ACTIONS))
def test_observation_profile_keeps_investigation_available(monkeypatch, kind):
    monkeypatch.setenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", "1")
    response._deployment_guard({"type": kind})


def test_source_install_default_does_not_silently_change_configured_response_policy(monkeypatch):
    monkeypatch.delenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", raising=False)
    response._deployment_guard({"type": "isolate_host"})
