import asyncio
import json
import os
import secrets
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cluster_readiness import wait_brokers_ready

from sapientia import auth
from sapientia.storage import CapacityError, ConflictError, Settings, Store


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def quorum(tmp_path, monkeypatch):
    executable = Path(__file__).resolve().parents[1] / "vendor/nats/nats-server.exe"
    if os.name != "nt":
        import shutil

        executable = Path(shutil.which("nats-server") or "/usr/local/bin/nats-server")
    if not executable.exists():
        pytest.skip(
            "Run tools/fetch_nats.py, or install the pinned NATS server on Linux"
        )
    ports = [port() for _ in range(3)]
    routes = [port() for _ in range(3)]
    token = secrets.token_urlsafe(32)
    monkeypatch.setenv("SAPIENTIA_NATS_TOKEN", token)
    monkeypatch.setenv("SAPIENTIA_CLUSTER_KEY", secrets.token_urlsafe(48))
    processes = []
    handles = []
    configs = []

    def start(i):
        stdout = (tmp_path / f"broker-{i}.log").open("ab")
        handles.append(stdout)
        p = subprocess.Popen(
            [str(executable), "-c", str(configs[i])],
            stdout=stdout,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        processes[i] = p

    for i in range(3):
        config = {
            "server_name": f"sap-qa-{i}",
            "host": "127.0.0.1",
            "port": ports[i],
            "max_payload": 8 * 1024**2,
            "authorization": {"token": token},
            "jetstream": {
                "store_dir": str(tmp_path / f"broker-{i}"),
                "max_file_store": 1024**3,
                "sync_interval": "always",
            },
            "cluster": {
                "name": "SAP-QA",
                "host": "127.0.0.1",
                "port": routes[i],
                "routes": [
                    f"nats://127.0.0.1:{p}" for j, p in enumerate(routes) if j != i
                ],
            },
        }
        path = tmp_path / f"broker-{i}.json"
        path.write_text(json.dumps(config))
        configs.append(path)
        processes.append(None)
    try:
        for i in range(3):
            start(i)
        for p in ports:
            deadline = time.monotonic() + 10
            while True:
                try:
                    with socket.create_connection(("127.0.0.1", p), 0.2):
                        break
                except OSError:
                    if time.monotonic() > deadline:
                        pytest.fail(
                            "Broker did not start: "
                            + "\n".join(
                                (tmp_path / f"broker-{i}.log").read_text()
                                for i in range(3)
                            )
                        )
                    time.sleep(0.1)
        asyncio.run(wait_brokers_ready(ports, token))

        def node(name):
            path = tmp_path / f"{name}.json"
            path.write_text(
                json.dumps(
                    {
                        "node_id": name,
                        "cluster_id": "test",
                        "replicas": 3,
                        "servers": [f"nats://127.0.0.1:{p}" for p in ports],
                        "journal_max_bytes": 512 * 1024**2,
                    }
                )
            )
            return Store(Settings(tmp_path / name, min_free_bytes=0, cluster=path))

        yield node, processes, start
    finally:
        for p in processes:
            if p and p.poll() is None:
                p.terminate()
                p.wait(10)
        for h in handles:
            h.close()


def retry(fn):
    deadline = time.monotonic() + 35
    while True:
        try:
            return fn()
        except (ConflictError, CapacityError):
            if time.monotonic() > deadline:
                raise
            time.sleep(0.02)


def test_replicated_identity_events_failover_and_rebuild(quorum):
    node, brokers, restart = quorum
    a, b = node("a"), node("b")
    c = None
    try:
        auth.create_user(a, "administrator", "Strong-password-123", first=True)
        logged = auth.login(b, "administrator", "Strong-password-123")
        assert logged and auth.identity(a, logged["token"])["role"] == "admin"
        who = {"name": "administrator", "tenant": "default"}
        token = auth.issue_token(a, who, "collector")
        assert auth.identity(b, bearer=token)["tenant"] == "default"
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(
                pool.map(
                    lambda i: retry(
                        lambda: (a if i % 2 else b).ingest(
                            "default", [{"event_id": str(i), "message": "replicated"}]
                        )
                    ),
                    range(20),
                )
            )
        b.replica.catch_up()
        a.replica.catch_up()
        a.flush()
        b.flush()
        assert a.health("default")["indexed"] == b.health("default")["indexed"] == 20
        # A single broker loss retains the required two-of-three quorum.
        brokers[0].terminate()
        brokers[0].wait(10)
        accepted = retry(
            lambda: b.ingest("default", [{"event_id": "after-broker-loss"}])
        )
        assert accepted["durable"]
        a.close()
        a = None
        # A new application node reconstructs identities and admitted events.
        c = node("replacement")
        assert auth.identity(c, bearer=token)
        while c.flush():
            pass
        assert c.health("default")["indexed"] == 21
        assert (
            c.ingest("default", [{"event_id": "after-broker-loss"}])["duplicate"] == 1
        )
        # Two failed brokers: an unavailable quorum must never return a durable ack.
        brokers[1].terminate()
        brokers[1].wait(10)
        with pytest.raises(CapacityError):
            c.ingest("default", [{"event_id": "uncertain-commit"}])
        restart(0)
        restart(1)
        time.sleep(2)
        result = retry(lambda: c.ingest("default", [{"event_id": "uncertain-commit"}]))
        assert result["accepted"] + result["duplicate"] == 1
        b.replica.catch_up()
        c.replica.catch_up()
        while b.flush():
            pass
        while c.flush():
            pass
        assert b.health("default")["indexed"] == c.health("default")["indexed"] == 22
    finally:
        for s in (a, b, c):
            if s:
                s.close()


def test_tampered_replay_is_rejected(quorum):
    node, _, _ = quorum
    store = node("guard")
    try:
        payload, _, _ = store.replica.pack(0, "0" * 64, [])
        value = json.loads(payload)
        value["command"]["statements"] = [
            {"sql": "DELETE FROM users", "params": [], "many": False}
        ]
        with pytest.raises(RuntimeError, match="authentication"):
            store.replica.decode(json.dumps(value).encode())
    finally:
        store.close()
