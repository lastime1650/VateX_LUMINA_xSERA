"""Local lease safety is independent of response opt-in and network health."""

import importlib
import threading
from contextlib import contextmanager

from sapientia.endpoint_agent.Agent import core

response = core.response
operations = importlib.import_module(response.__package__ + ".operations")


def client(tmp_path, monkeypatch):
    value = core.Agent.__new__(core.Agent)
    value.directory = tmp_path
    value.config = {
        "response": {"enabled": False, "quarantine_dir": str(tmp_path / "private")}
    }
    value.stop = threading.Event()
    value.errors = {}
    value.last_error = None
    value._error_lock = threading.RLock()
    value._renew_at = float("inf")
    value._policy_at = float("inf")
    value.identity = {}
    value.defense = None
    value.kernel_prevention = None
    calls, held = [], [False]

    @contextmanager
    def lock(directory):
        assert directory == tmp_path and not held[0]
        held[0] = True
        try:
            yield
        finally:
            held[0] = False

    def poll():
        assert not held[0], "The response poll owns a separate lock"
        calls.append("poll")

    value.poll = poll
    value.heartbeat = lambda: calls.append("heartbeat")
    monkeypatch.setattr(response, "Lock", lock)
    return value, calls, held


def test_local_recovery_precedes_failed_network_and_poll_without_nested_lock(
    tmp_path, monkeypatch
):
    value, calls, held = client(tmp_path, monkeypatch)

    def recover(settings):
        assert held[0] and settings is value.config["response"]
        calls.append("owned-lease-recovered")
        return [{"isolation_id": "a" * 32, "state": "lease_expired"}]

    def heartbeat():
        calls.append("network-unavailable")
        raise OSError("No network credentials are needed for local cleanup")

    monkeypatch.setattr(operations, "recover_linux_isolation", recover)
    value.heartbeat = heartbeat
    value._control_cycle(0, 0)
    assert calls == ["owned-lease-recovered", "network-unavailable", "poll"]
    assert value.errors == {"heartbeat": "OSError"}


def test_unconfirmed_native_recovery_is_visible_and_retried_on_next_due_poll(
    tmp_path, monkeypatch
):
    value, calls, held = client(tmp_path, monkeypatch)
    attempts = []

    def recover(_settings):
        assert held[0]
        attempts.append(True)
        if len(attempts) == 1:
            raise TimeoutError("Owned rules remain unconfirmed")
        return [{"isolation_id": "b" * 32, "state": "lease_expired"}]

    monkeypatch.setattr(operations, "recover_linux_isolation", recover)
    value._control_cycle(0, 0)
    assert value.errors["isolation_recovery"] == "TimeoutError"
    value._control_cycle(float("inf"), 0)
    assert len(attempts) == 2 and "isolation_recovery" not in value.errors
    assert calls.count("poll") == 2


def test_no_configured_private_catalog_performs_no_recovery(tmp_path, monkeypatch):
    value, calls, _held = client(tmp_path, monkeypatch)
    value.config["response"].pop("quarantine_dir")
    monkeypatch.setattr(
        operations,
        "recover_linux_isolation",
        lambda *_args: (_ for _ in ()).throw(AssertionError("No private catalog")),
    )
    value._control_cycle(0, 0)
    assert calls == ["heartbeat", "poll"]
