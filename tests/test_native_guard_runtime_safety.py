"""Identity/worker liveness and native harmless parent-process handle proof."""

import json
import os
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest
from cryptography.exceptions import InvalidSignature

from sapientia import xdr_bridge
from sapientia.endpoint_agent.Agent import core
from sapientia.endpoint_agent.Agent.Windows.isolation_watchdog import ParentProcess


def observation(kind):
    common = {"host": {"id": "owned-host"}, "process": {"executable": "harmless-image"}}
    if kind == "windows":
        common.update(
            event={
                "module": "code_integrity",
                "provider": "Microsoft-Windows-CodeIntegrity/Operational",
                "code": "3077",
                "action": "execution_denied",
            },
            agent={
                "collector": "windows-event-log",
                "process_identity_kind": "unavailable_for_code_integrity_observation",
            },
        )
    else:
        common.update(
            event={
                "module": "kernel_prevention",
                "provider": "linux.fanotify",
                "action": "execution_denied",
            },
            agent={
                "collector": "linux-kernel-exec-permission",
                "process_identity_kind": "unavailable_for_kernel_permission_observation",
            },
        )
    return common


@pytest.mark.parametrize("kind", ["windows", "linux"])
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
def test_permission_observation_cannot_claim_executed_process_identity(kind, field):
    data = observation(kind)
    target = data["process"]
    if field.startswith("parent."):
        target = target.setdefault("parent", {})
        field = field.split(".")[1]
    target[field] = 12345 if field == "pid" else "forged-identity"
    with pytest.raises(ValueError, match="cannot invent"):
        xdr_bridge._typed(data)


@pytest.mark.parametrize("kind,field", [("windows", "code"), ("linux", "action")])
@pytest.mark.parametrize("malformed", [[], {}])
def test_malformed_observation_discriminator_is_validation_error(
    kind, field, malformed
):
    data = observation(kind)
    data["event"][field] = malformed
    with pytest.raises(ValueError):
        xdr_bridge._typed(data)


def test_bad_signature_defers_fetch_without_killing_control_worker_or_old_cache():
    agent = core.Agent.__new__(core.Agent)
    agent._error_lock = threading.Lock()
    agent.errors = {}
    agent.last_error = None
    agent.kernel_prevention = object()
    agent._post = lambda *_args: {"bundle": {"invalid": True}}
    cache = {"approved_revision": 7}

    def update(*_args, **_kwargs):
        raise InvalidSignature

    agent.defense = SimpleNamespace(update=update, cache=cache)
    assert agent._attempt("defense_policy", agent._fetch_policy) is None
    assert agent.errors == {"defense_policy": "ValueError"}
    assert cache == {"approved_revision": 7}
    assert agent._attempt("still-running", lambda: True)


@pytest.mark.parametrize("state", ["degraded", "expired", "stopped", "closing"])
def test_expired_or_stopped_opted_in_guard_degrades_fleet_heartbeat(state):
    agent = core.Agent.__new__(core.Agent)
    agent.last_error = None
    agent._provider_health = {"status": "ok"}
    agent._pending_metric = agent._quarantined_metric = agent._evaluation_metric = 0
    agent.queue = SimpleNamespace(max_pending=100, capture_reserve=100)
    agent.memory_observability = None
    agent.config = {"response": {"enabled": False}}
    agent.defense = None
    measurements = []

    def measure_package():
        measurements.append(True)
        return {"state": "unavailable", "required": False,
                "os_code_signature": False, "hardware_attestation": False}

    # This unit fixture bypasses Agent.__init__; real package verification and
    # tamper-triggered degradation are exercised in test_release_integrity.
    agent.package_integrity = SimpleNamespace(measure=measure_package)
    agent.kernel_prevention = SimpleNamespace(
        status=lambda: {"enabled": True, "state": state}
    )
    agent._isolation_status = lambda: {"enabled": False}
    agent._post = lambda _route, body: body
    health = agent.heartbeat()["health"]
    assert health["status"] == "degraded"
    assert health["package_integrity"]["state"] == "unavailable"
    assert measurements == [True]


def test_large_kernel_scope_heartbeat_is_bounded_and_keeps_private_detail():
    directories = ["/opt/" + "x" * 480 + str(i) for i in range(32)]
    original = {
        "status": "degraded",
        "kernel_prevention": {
            "state": "expired",
            "enabled": True,
            "watched_directories": directories,
        },
        "providers": {"status": "ok"},
        "defense": {"enabled": False},
        "host_isolation": {"enabled": False},
    }
    result = core.bounded_heartbeat(original)
    assert len(json.dumps(result, ensure_ascii=False).encode()) <= 3500
    assert result["status"] == "degraded" and result["details_omitted"]
    assert result["kernel_prevention"]["directory_count"] == 32
    assert len(result["kernel_prevention"]["directory_scope_sha256"]) == 64
    assert original["kernel_prevention"]["watched_directories"] is directories


def test_multibyte_large_components_keep_degradation_within_byte_budget():
    long_values = {
        key: "가" * 5000
        for key in ("status", "state", "support", "policy_sha256", "error")
    }
    original = {
        "status": "degraded",
        "providers": long_values,
        "defense": long_values,
        "kernel_prevention": long_values,
        "host_isolation": long_values,
    }
    result = core.bounded_heartbeat(original)
    assert len(json.dumps(result, ensure_ascii=False).encode()) <= 3500
    assert result["status"] == "degraded" and result["details_omitted"]


@pytest.mark.skipif(os.name != "nt", reason="Windows native harmless process handle")
def test_rollback_parent_handle_tracks_exit_of_exact_native_process():
    child = subprocess.Popen(
        [
            getattr(sys, "_base_executable", sys.executable),
            "-I",
            "-c",
            "import sys; print('ready',flush=True); sys.stdin.read()",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    held = None
    try:
        assert child.stdout.readline().strip() == b"ready"
        held = ParentProcess(child.pid)
        assert held.alive()
        original = held.handle
        child.stdin.close()
        child.wait(timeout=3)
        assert not held.alive() and held.handle == original
    finally:
        if held:
            held.close()
        if child.poll() is None:
            child.kill()
            child.wait(timeout=3)
        child.stdout.close()
