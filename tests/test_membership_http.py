"""Five independent application processes; real HTTP Slave-to-Master forwarding.

Loopback HTTP is test-only. Appliance-to-appliance network traffic requires TLS.
"""

import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx

from sapientia.auth import create_user
from sapientia.storage import Settings, Store


def test_five_process_join_via_slave_and_persistent_membership(tmp_path):
    project = Path(__file__).resolve().parents[1]
    password = secrets.token_urlsafe(32)
    join_secret = secrets.token_urlsafe(32)
    processes, clients, logs, addresses = [], [], [], []
    # Reserve distinct ephemeral ports together, then release immediately before
    # startup. A conflict fails the test rather than killing an unrelated server.
    reservations = [socket.socket() for _ in range(5)]
    try:
        for sock in reservations:
            sock.bind(("127.0.0.1", 0))
            addresses.append("http://127.0.0.1:" + str(sock.getsockname()[1]))
    finally:
        for sock in reservations:
            sock.close()
    try:
        for index, address in enumerate(addresses):
            data = tmp_path / f"node-{index}"
            store = Store(Settings(data, min_free_bytes=0))
            create_user(store, "test_admin", password)
            store.close()
            log = (tmp_path / f"node-{index}.log").open("ab")
            logs.append(log)
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "sapientia",
                    "--data",
                    str(data),
                    "serve",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    address.rsplit(":", 1)[1],
                ],
                cwd=project,
                stdout=log,
                stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            processes.append(process)
            client = httpx.Client(base_url=address, timeout=20, trust_env=False)
            clients.append(client)
            deadline = time.monotonic() + 20
            while True:
                assert process.poll() is None, "Isolated test server exited"
                try:
                    if client.get("/api/bootstrap").status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                if time.monotonic() > deadline:
                    raise AssertionError("Isolated server startup deadline exceeded")
                time.sleep(0.05)
            response = client.post(
                "/api/login", json={"name": "test_admin", "password": password}
            )
            assert response.status_code == 200
            client.headers["X-CSRF-Token"] = response.json()["csrf"]
        response = clients[0].post(
            "/api/cluster/master",
            json={
                "name": "Five-process QA",
                "address": addresses[0],
                "password": join_secret,
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["role"] == "Master"
        for index in range(1, 5):
            # All later nodes join through Slave 1, not directly through Master.
            response = clients[index].post(
                "/api/cluster/join",
                json={
                    "peer": addresses[0 if index == 1 else 1],
                    "address": addresses[index],
                    "password": join_secret,
                },
            )
            assert response.status_code == 200, response.text
            assert response.json()["role"] == f"Slave {index}"
            assert response.json()["master_url"] == addresses[0]
            assert response.json()["data_replication_ready"] is False
        response = clients[1].post("/api/cluster/refresh", json={})
        assert response.status_code == 200
        assert len(response.json()["members"]) == 5
        assert [member["ordinal"] for member in response.json()["members"]] == list(
            range(5)
        )
        assert "credential" not in response.text
        # Each process persisted its own identity, without claiming shared logs.
        for index, client in enumerate(clients):
            state = client.get("/api/cluster").json()
            assert state["ordinal"] == index
            assert client.get("/api/health").json()["deployment"] == "single-node"
        # Losing Master must not let Slave 1 fabricate an enrollment number.
        processes[0].terminate()
        processes[0].wait(10)
        response = clients[1].post("/api/cluster/refresh", json={})
        assert response.status_code == 503
        assert clients[1].get("/api/cluster").json()["role"] == "Slave 1"
    finally:
        for client in clients:
            client.close()
        for process in processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(5)
        for log in logs:
            log.close()
