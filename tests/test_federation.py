"""Real loopback peer servers exercise scope, reduction, replay, failure and TLS."""

import json
import secrets
import socket
import threading
import time
from contextlib import contextmanager

import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from sapientia import access, auth
from sapientia.api import create_app
from sapientia.federation import PEER_PATH, Federation, FederationError, signed_headers
from sapientia.storage import Settings, Store
from tools.qualification import certificate


@contextmanager
def node(
    tmp_path,
    monkeypatch,
    number,
    tls=False,
    grant_indexes=None,
    delay=0,
    redirect=False,
):
    secret = secrets.token_urlsafe(32)
    variable, key_id = f"FEDERATION_TEST_{number}", f"pair{number}"
    monkeypatch.setenv(variable, secret)
    store = Store(Settings(tmp_path / str(number), min_free_bytes=0))
    store.ingest(
        "a",
        [
            {
                "event_id": f"shared-{n}",
                "event_time": 100 + n,
                "host": "common",
                "index": "main",
            }
            for n in range(number + 1)
        ],
    )
    store.ingest(
        "a",
        [
            {
                "event_id": "private",
                "event_time": 200,
                "host": "private",
                "index": "private",
            }
        ],
    )
    store.ingest("b", [{"event_id": "other-tenant", "event_time": 300}])
    store.flush()
    grant = {
        "key_id": key_id,
        "secret_env": variable,
        "tenants": ["a"],
        "indexes": grant_indexes if grant_indexes is not None else ["main"],
    }
    federation = Federation(store, {"grants": [grant]})
    app = FastAPI()

    @app.post(PEER_PATH)
    async def peer(request: Request):
        if redirect:
            return JSONResponse(
                {"detail": "redirect"},
                307,
                headers={"location": "http://127.0.0.1:8787/"},
            )
        if delay:
            import asyncio

            await asyncio.sleep(delay)
        try:
            return await run_in_threadpool(
                federation.handle_peer, await request.body(), request.headers
            )
        except FederationError as exc:
            return JSONResponse({"detail": str(exc)}, exc.status_code)

    bound = socket.socket()
    bound.bind(("127.0.0.1", 0))
    bound.listen()
    port = bound.getsockname()[1]
    options = {}
    cert_path = None
    if tls:
        cert_path, key = certificate(tmp_path)
        options = {"ssl_certfile": str(cert_path), "ssl_keyfile": str(key)}
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", **options)
    )
    thread = threading.Thread(target=lambda: server.run(sockets=[bound]), daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.01)
    assert server.started
    peer_config = {
        "name": f"node{number}",
        "url": f"{'https' if tls else 'http'}://127.0.0.1:{port}",
        "key_id": key_id,
        "secret_env": variable,
        "tenants": ["a"],
        "indexes": ["main", "private"],
    }
    if cert_path:
        peer_config["ca_file"] = str(cert_path)
    try:
        yield store, federation, peer_config, secret
    finally:
        server.should_exit = True
        thread.join(5)
        bound.close()
        assert not thread.is_alive()
        store.close()


def payload(body, limit=1000):
    return {
        "language": "json",
        "query": body,
        "earliest": 0,
        "latest": 1000,
        "limit": limit,
    }


@pytest.fixture
def master(tmp_path):
    store = Store(Settings(tmp_path / "master", min_free_bytes=0))
    yield store
    store.close()


def config(peers, **kwargs):
    return {
        "include_local": False,
        "allow_loopback_http": True,
        "peers": peers,
        **kwargs,
    }


def test_three_real_nodes_reduce_exact_counts_and_preserve_node_identity(
    master, tmp_path, monkeypatch
):
    with (
        node(tmp_path, monkeypatch, 0) as one,
        node(tmp_path, monkeypatch, 1) as two,
        node(tmp_path, monkeypatch, 2) as three,
    ):
        federation = Federation(master, config([one[2], two[2], three[2]]))
        result = federation.search(
            {"tenant": "a"}, payload({"group_by": ["host"], "sort": "count"}), ["*"]
        )
        assert result["rows"] == [{"host": "common", "count": 6}]
        assert len(result["nodes"]) == 3 and all(
            node["access_scope"] == ["main"] for node in result["nodes"]
        )
        events = federation.search(
            {"tenant": "a"},
            payload({"fields": ["event_id", "event_time"]}, 3),
            ["main"],
        )
        assert [row["event_time"] for row in events["rows"]] == [102, 101, 101]
        assert len({row["_federated_id"] for row in events["rows"]}) == 3
        assert events["complete"] is True and events["limit"] == 3
        denied = federation.search(
            {"tenant": "a"}, payload({"group_by": [], "sort": "count"}), []
        )
        assert denied["rows"] == [{"count": 0}]


def test_signature_replay_recipient_tenant_and_tampering_rejected(
    tmp_path, monkeypatch
):
    with node(tmp_path, monkeypatch, 0) as (_, federation, peer, secret):
        body = json.dumps(
            {
                "version": 1,
                "recipient": peer["key_id"],
                "tenant": "a",
                "allowed_indexes": ["main", "private"],
                "payload": payload({"group_by": [], "sort": "count"}),
            }
        ).encode()
        headers = signed_headers(peer["key_id"], secret, body)
        assert federation.handle_peer(body, headers)["rows"] == [{"count": 1}]
        with pytest.raises(FederationError, match="replay"):
            federation.handle_peer(body, headers)
        with pytest.raises(FederationError, match="authentication"):
            federation.handle_peer(body + b" ", headers)
        for field in ("authorization", "x-sapientia-signature"):
            malformed = {**headers, field: "non-ascii-\u00e9"}
            with pytest.raises(FederationError) as denied:
                federation.handle_peer(body, malformed)
            assert denied.value.status_code == 401
        value = json.loads(body)
        value["recipient"] = "other-key"
        changed = json.dumps(value).encode()
        with pytest.raises(FederationError, match="envelope"):
            federation.handle_peer(
                changed, signed_headers(peer["key_id"], secret, changed)
            )
        value["recipient"], value["tenant"] = peer["key_id"], "b"
        changed = json.dumps(value).encode()
        with pytest.raises(FederationError, match="tenant"):
            federation.handle_peer(
                changed, signed_headers(peer["key_id"], secret, changed)
            )
        with pytest.raises(FederationError, match="Expired"):
            federation.handle_peer(
                body,
                signed_headers(peer["key_id"], secret, body, stamp=time.time() - 3600),
            )


def test_group_cap_and_peer_failure_never_return_partial_counts(
    master, tmp_path, monkeypatch
):
    with node(tmp_path, monkeypatch, 2) as good:
        federation = Federation(master, config([good[2]], max_groups=1))
        with pytest.raises(FederationError, match="group cap|HTTP 413"):
            federation.search(
                {"tenant": "a"},
                payload({"group_by": ["event_id"], "sort": "count"}),
                ["main"],
            )
        broken = {**good[2], "name": "unreachable", "url": "http://127.0.0.1:1"}
        federation = Federation(master, config([good[2], broken], timeout=0.5))
        with pytest.raises(
            FederationError, match="unavailable|without returning partial"
        ):
            federation.search(
                {"tenant": "a"}, payload({"group_by": [], "sort": "count"}), ["main"]
            )


def test_https_ca_is_verified_and_redirects_are_not_followed(
    master, tmp_path, monkeypatch
):
    with node(tmp_path, monkeypatch, 0, tls=True) as secured:
        federation = Federation(master, {"include_local": False, "peers": [secured[2]]})
        assert federation.search(
            {"tenant": "a"}, payload({"group_by": [], "sort": "count"}), ["main"]
        )["rows"] == [{"count": 1}]
        untrusted = dict(secured[2])
        del untrusted["ca_file"]
        federation = Federation(master, {"include_local": False, "peers": [untrusted]})
        with pytest.raises(FederationError, match="unavailable"):
            federation.search(
                {"tenant": "a"}, payload({"group_by": [], "sort": "count"}), ["main"]
            )
    with node(tmp_path, monkeypatch, 3, redirect=True) as redirected:
        federation = Federation(master, config([redirected[2]]))
        with pytest.raises(FederationError, match="HTTP 307"):
            federation.search(
                {"tenant": "a"}, payload({"group_by": [], "sort": "count"}), ["main"]
            )


def test_deadline_and_explicit_protocol_limit(master, tmp_path, monkeypatch):
    with node(tmp_path, monkeypatch, 0, delay=0.3) as slow:
        federation = Federation(master, config([slow[2]], timeout=0.1))
        start = time.monotonic()
        with pytest.raises(FederationError):
            federation.search(
                {"tenant": "a"}, payload({"group_by": [], "sort": "count"}), ["main"]
            )
        assert time.monotonic() - start < 0.25
        with pytest.raises(FederationError, match="SPL is unsupported"):
            federation.search({"tenant": "a"}, {"query": "*"}, ["main"])
        with pytest.raises(FederationError, match="explicit"):
            federation.search({"tenant": "a"}, payload({}), None)
        with pytest.raises(FederationError, match="HTTP federation"):
            Federation(master, {"include_local": False, "peers": [slow[2]]})


def test_registered_api_auth_scope_csrf_and_origin_audit(tmp_path, monkeypatch):
    monkeypatch.setenv("FED_API_PAIR_SECRET", secrets.token_urlsafe(32))
    configuration = tmp_path / "federation.json"
    configuration.write_text(
        json.dumps(
            {
                "grants": [
                    {
                        "key_id": "pair",
                        "secret_env": "FED_API_PAIR_SECRET",
                        "tenants": ["default"],
                        "indexes": ["main"],
                    }
                ]
            }
        )
    )
    app = create_app(
        Settings(tmp_path / "api", min_free_bytes=0, federation=configuration),
        background=False,
    )
    with TestClient(app) as client:
        store = app.state.store
        auth.create_user(store, "administrator", "Long-testing-password-2026")
        assert client.get("/api/federation/status").status_code == 401
        login = client.post(
            "/api/login",
            json={"name": "administrator", "password": "Long-testing-password-2026"},
        ).json()
        client.headers["X-CSRF-Token"] = login["csrf"]
        store.ingest(
            "default",
            [
                {"event_id": "public", "event_time": 100},
                {"event_id": "private", "event_time": 100, "index": "private"},
            ],
        )
        store.flush()
        query = payload({"group_by": [], "sort": "count"})
        assert client.post("/api/federation/search", json=query).json()["rows"] == [
            {"count": 2}
        ]
        access.set_for_user(
            store,
            {"name": "administrator", "tenant": "default", "role": "admin"},
            "administrator",
            ["main"],
        )
        login = client.post(
            "/api/login",
            json={"name": "administrator", "password": "Long-testing-password-2026"},
        ).json()
        client.headers["X-CSRF-Token"] = login["csrf"]
        assert client.post("/api/federation/search", json=query).json()["rows"] == [
            {"count": 1}
        ]
        with store.control() as db:
            audits = db.execute(
                "SELECT detail FROM audit WHERE action='federation.search' ORDER BY seq"
            ).fetchall()
        assert len(audits) == 2 and json.loads(audits[-1][0])["access_scope"] == [
            "main"
        ]
        collector = client.post("/api/tokens", json={"name": "collector"}).json()[
            "token"
        ]
        assert (
            client.post(
                "/api/federation/search",
                headers={"authorization": "Bearer " + collector},
                json=query,
            ).status_code
            == 403
        )
        assert (
            client.post(
                PEER_PATH, headers={"authorization": "Bearer " + collector}, json={}
            ).status_code
            == 401
        )
        del client.headers["X-CSRF-Token"]
        assert client.post("/api/federation/search", json=query).status_code == 403
