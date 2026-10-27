"""Owned nonce protocol/connection-incarnation tests; no firewall effects."""

import socket
import threading
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from tools import qualify_windows_isolation as qualification

NONCE = "a" * 32


class Channel:
    def __init__(self, failure=None, stale=False):
        self.failure, self.stale = failure, stale
        self.messages, self.pending, self.closed = [], bytearray(), False

    def getpeername(self):
        return qualification.NONCE_PEER

    def getsockname(self):
        return ("192.0.2.42", 50001)

    def fileno(self):
        return 123

    def settimeout(self, seconds):
        assert 0 < seconds <= 1

    def sendall(self, message):
        self.messages.append(message)
        self.pending.extend(
            message if not self.stale else (NONCE + ":" + "0" * 32 + "\n").encode()
        )

    def recv(self, maximum):
        if self.failure is not None:
            raise self.failure
        result = bytes(self.pending[: min(maximum, 13)])
        del self.pending[: len(result)]
        return result

    def close(self):
        self.closed = True


def install(monkeypatch, channel):
    connections = []

    def connect(peer, *, timeout):
        assert peer == ("192.0.2.41", 20200) and timeout == 1
        connections.append(peer)
        return channel

    monkeypatch.setattr(qualification.socket, "create_connection", connect)
    return connections


def test_fragmented_echo_keeps_same_connection_and_changes_every_sequence(monkeypatch):
    channel = Channel()
    connections = install(monkeypatch, channel)
    session = qualification.NonceSession(NONCE)
    assert session.exchange() and session.exchange()
    proof = session.evidence()
    assert len(connections) == 1 and proof["socket_fileno"] == 123
    assert proof["local_tuple"] == ["192.0.2.42", 50001]
    assert proof["same_socket_no_reconnect"] and len(proof["attempts"]) == 2
    assert len(set(channel.messages)) == 2 and all(
        len(message) == 66 for message in channel.messages
    )
    session.close()
    assert channel.closed


@pytest.mark.parametrize(
    "error", [TimeoutError(), ConnectionResetError(), BrokenPipeError()]
)
def test_no_reconnect_or_retry_after_established_exchange_fails(monkeypatch, error):
    channel = Channel()
    connections = install(monkeypatch, channel)
    session = qualification.NonceSession(NONCE)
    assert session.exchange()
    channel.failure = error
    assert session.exchange() is False
    with pytest.raises(RuntimeError, match="reused or reconnected"):
        session.exchange()
    assert len(connections) == 1 and len(channel.messages) == 2
    assert (
        session.evidence()["attempts"][-1]["unresponsive_reason"]
        == type(error).__name__
    )
    session.close()


def test_stale_sequence_is_peer_error_not_success_or_isolation_denial(monkeypatch):
    channel = Channel(stale=True)
    install(monkeypatch, channel)
    session = qualification.NonceSession(NONCE)
    with pytest.raises(RuntimeError, match="stale or invalid"):
        session.exchange()
    with pytest.raises(RuntimeError, match="reused or reconnected"):
        session.exchange()
    session.close()


def test_oversized_peer_frame_fails_closed(monkeypatch):
    channel = Channel()
    install(monkeypatch, channel)
    session = qualification.NonceSession(NONCE)
    channel.sendall = lambda _message: channel.pending.extend(b"x" * 129)
    with pytest.raises(RuntimeError, match="oversized"):
        session.exchange()
    session.close()


def test_fresh_probe_closes_socket_even_when_peer_protocol_is_invalid(monkeypatch):
    channel = Channel(stale=True)
    install(monkeypatch, channel)
    with pytest.raises(RuntimeError, match="stale or invalid"):
        qualification.nonce_probe(NONCE)
    assert channel.closed


def test_probe_rejects_invalid_nonce_before_opening_any_socket(monkeypatch):
    monkeypatch.setattr(
        qualification.socket,
        "create_connection",
        lambda *a, **k: pytest.fail("No socket"),
    )
    for nonce in [None, "", "A" * 32, "a" * 33, "a" * 31 + "\n"]:
        with pytest.raises(ValueError):
            qualification.NonceSession(nonce)


def test_changed_socket_peer_is_rejected_and_closed(monkeypatch):
    channel = Channel()
    channel.getpeername = lambda: ("203.0.113.9", 20200)
    install(monkeypatch, channel)
    with pytest.raises(PermissionError, match="peer changed"):
        qualification.NonceSession(NONCE)
    assert channel.closed


def peer_metadata():
    return {
        "bind_ip": "192.0.2.41",
        "port": 20200,
        "accepted_peer": "192.0.2.42",
        "nonce": NONCE,
        "protocol": "xsera.nonce.v2",
        "maximum_lifetime_seconds": 180,
        "created": 1000,
        "expires": 1175,
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("bind_ip", "192.0.2.40"),
        ("port", 443),
        ("accepted_peer", "127.0.0.1"),
        ("nonce", "A" * 32),
        ("protocol", "xsera.nonce.v1"),
        ("maximum_lifetime_seconds", 3600),
        ("created", True),
        ("expires", 1114),
        ("expires", 1181),
        ("expires", float("nan")),
    ],
)
def test_peer_scope_protocol_and_finite_ttl_required_before_native_window(
    monkeypatch, field, value
):
    monkeypatch.setattr(qualification.time, "time", lambda: 1000)
    proof = peer_metadata()
    assert qualification.validate_nonce_peer(proof) == NONCE
    proof[field] = value
    with pytest.raises(PermissionError):
        qualification.validate_nonce_peer(proof)


def test_real_loopback_stream_keeps_one_os_socket_for_two_unique_requests(monkeypatch):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(2)
    received, failure = [], []

    def echo():
        try:
            with listener.accept()[0] as channel:
                channel.settimeout(2)
                with channel.makefile("rb") as stream:
                    for _ in range(2):
                        frame = stream.readline(129)
                        received.append(frame)
                        channel.sendall(frame[:11])
                        channel.sendall(frame[11:])
        except OSError as error:
            failure.append(error)
        finally:
            listener.close()

    worker = threading.Thread(target=echo, daemon=True)
    worker.start()
    monkeypatch.setattr(qualification, "NONCE_PEER", listener.getsockname())
    session = qualification.NonceSession(NONCE)
    try:
        original = session.evidence()
        assert session.exchange() and session.exchange()
        final = session.evidence()
        assert original["socket_fileno"] == final["socket_fileno"]
        assert original["local_tuple"] == final["local_tuple"]
        assert len(set(received)) == 2 and all(len(frame) == 66 for frame in received)
    finally:
        session.close()
        worker.join(timeout=3)
        listener.close()
    assert not worker.is_alive() and not failure


def test_native_window_rejects_fresh_only_block_when_established_session_still_exchanges(
    monkeypatch, tmp_path
):
    """A fresh-only firewall cannot satisfy the native isolation gate."""
    import json

    proof = tmp_path / "peer.json"
    proof.write_text(json.dumps(peer_metadata()), encoding="utf-8")
    harness = tmp_path / "Agent/Windows/firewall_profile_test_guard.py"
    harness.parent.mkdir(parents=True)
    harness.write_text("# harmless local test guard fixture", encoding="utf-8")
    calls, fresh = [], iter([True, True, False])
    monkeypatch.setattr(qualification.time, "time", lambda: 1000)
    monkeypatch.setattr(qualification, "observed_controller_peers", dict)
    monkeypatch.setattr(qualification.response, "_no_links", lambda *_: None)
    monkeypatch.setattr(qualification.cli, "_protected", lambda *_a, **_k: None)
    monkeypatch.setattr(qualification, "nonce_probe", lambda _nonce: next(fresh))
    established = SimpleNamespace(exchange=lambda: True, close=lambda: None)
    monkeypatch.setattr(qualification, "NonceSession", lambda _nonce: established)
    trial = qualification.Trial.__new__(qualification.Trial)
    trial.root, trial.config = tmp_path, {"response": {"quarantine_dir": str(tmp_path)}}
    trial.heartbeat = lambda: True
    trial.start_worker = lambda: None
    trial.record = lambda *a, **k: calls.append(a[0])
    trial.native_state = lambda: {
        "active": [{"isolation_id": "b" * 32, "guard_alive": True}]
    }
    trial.command = lambda _target: {"result": {"data": {"isolation_id": "b" * 32}}}
    guard = SimpleNamespace(
        profiles=lambda: {"1": True, "2": False, "4": False},
        PLAN_NAME="profile-plan.json",
        arm=lambda _path: SimpleNamespace(pid=123),
        set_profiles=lambda _profiles: calls.append("test-only-profile-enable"),
    )
    trial.modules = [
        None,
        SimpleNamespace(inspect_process=lambda *_: {"start_identity": "windows:1"}),
        SimpleNamespace(network_definition=lambda _: ({"endpoints": []}, "digest")),
        SimpleNamespace(_windows_owned=lambda _: []),
        None,
        guard,
    ]
    with pytest.raises(AssertionError, match="established and fresh"):
        trial.run_window(proof)
    assert (
        "preexisting_nonmanagement_tcp_session_suppressed_after_native_isolation"
        not in calls
    )


@pytest.mark.parametrize("paused", [False, True])
def test_worker_uses_actual_control_cycle_and_pause_suppresses_all_agent_recovery(
    monkeypatch, tmp_path, paused
):
    """The independent lease proof cannot silently rely on agent recovery."""
    import json
    import os

    (tmp_path / "config.json").write_text(
        json.dumps({"endpoint_url": "https://127.0.0.1:18788", "host": "owned-test"}),
        encoding="utf-8",
    )
    if paused:
        (tmp_path / "worker-pause.json").write_text("{}", encoding="utf-8")
    calls = []

    class Agent:
        def __init__(self, _config, _callback):
            self.directory, self.stop, self.defense = tmp_path, threading.Event(), None
            self.queue = SimpleNamespace(close=lambda: calls.append("queue-closed"))

        def _control_cycle(self, heartbeat_at, poll_at):
            calls.append((heartbeat_at, poll_at))
            (tmp_path / "worker-stop.json").write_text("{}", encoding="utf-8")
            return 30.0, 5.0

    monkeypatch.setattr(qualification, "owned_root", lambda _: tmp_path)
    monkeypatch.setattr(
        qualification,
        "load_downloaded",
        lambda _: (
            SimpleNamespace(Agent=Agent, RunLock=lambda _: nullcontext()),
            SimpleNamespace(inspect_process=lambda *_: {"pid": os.getpid()}),
            None,
            None,
            None,
            None,
        ),
    )

    def pause(_seconds):
        if paused:
            (tmp_path / "worker-stop.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(qualification.time, "sleep", pause)
    assert qualification.worker(tmp_path) == 0
    if paused:
        assert calls == ["queue-closed"]
        assert json.loads((tmp_path / "worker-paused.json").read_text())[
            "polling_stopped"
        ]
    else:
        assert calls == [(0.0, 0.0), "queue-closed"]
