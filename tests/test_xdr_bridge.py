"""Synthetic AEGIS protocol compatibility, lineage, scope and verified TLS."""

import copy
import hashlib
import json
import ssl
import threading
from contextlib import contextmanager
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sapientia import access, api_xdr, auth, pipeline, xdr_bridge
from sapientia.api import create_app
from sapientia.storage import CapacityError, ConflictError, Settings, Store
from tools.qa_console_seed import seed
from tools.qualification import certificate

PASSWORD = "Synthetic-XDR-protocol-password-2026"
START = 1704067200


def actor(name="admin_a", tenant="a", role="admin"):
    return {"name": name, "tenant": tenant, "role": role, "allowed_indexes": ["*"]}


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    for name, tenant, role in (
        ("admin_a", "a", "admin"),
        ("analyst_a", "a", "analyst"),
        ("admin_b", "b", "admin"),
    ):
        auth.create_user(value, name, PASSWORD, role, tenant)
    yield value
    value.close()


def event(ident="one", guid="root-guid", parent=None, host="host1", pid=100, at=0):
    data = {
        "@timestamp": datetime.fromtimestamp(START + at, UTC).isoformat(),
        "host": {"id": host, "os": {"type": "windows"}},
        "process": {
            "guid": guid,
            "pid": pid,
            "name": "synthetic.exe",
            "command_line": "synthetic --read-only",
        },
        "event": {"action": "process_created", "severity": "low"},
        "user": {"name": "synthetic-user"},
    }
    if parent:
        data["process"]["parent"] = {"guid": parent}
    return {"id": ident, "data": data}


def ingest(store, rows, tenant="a", index="endpoint"):
    return xdr_bridge.intake(
        store,
        actor("admin_" + tenant, tenant),
        {"format": "agent", "index": index, "events": rows},
    )


def test_real_agent_envelope_stable_identity_and_atomic_batch(store):
    row = event()
    parsed = xdr_bridge.parse_event(row, "agent", "endpoint", expected_host="host1")
    assert parsed["host"] == "host1" and parsed["event_time"] == START
    assert parsed["raw"]["xdr"]["data"]["process"]["guid"] == "root-guid"
    with pytest.raises(PermissionError):
        xdr_bridge.parse_event(row, "agent", "endpoint", expected_host="different-host")
    assert ingest(store, [row])["accepted"] == 1
    assert ingest(store, [row])["duplicate"] == 1
    changed = copy.deepcopy(row)
    changed["data"]["process"]["command_line"] = "different"
    with pytest.raises(ConflictError):
        ingest(store, [changed])
    bad = event("bad")
    del bad["data"]["process"]["guid"]
    with pytest.raises(ValueError):
        ingest(store, [event("new"), bad])
    store.flush()
    result = xdr_bridge.telemetry(store, actor(), START, START + 100)
    assert result["total"] == 1


@pytest.mark.parametrize(
    "path,value",
    [
        (("process", "guid"), None),
        (("process", "pid"), True),
        (("process", "pid"), -1),
        (("process", "command_line"), "x" * 8193),
        (("source", "port"), 65536),
        (("source", "ip"), "not-an-ip"),
        (("host", "id"), ["host1"]),
        (("process", "parent", "guid"), {"unexpected": 1}),
        (("@timestamp",), "2024-01-01T00:00:00"),
        (("event", "severity"), "dangerous"),
    ],
)
def test_typed_contract_rejects_pid_only_and_invalid_fields(path, value):
    row = event()
    target = row["data"]
    for key in path[:-1]:
        target = target.setdefault(key, {})
    target[path[-1]] = value
    with pytest.raises(ValueError):
        xdr_bridge.parse_event(row, "agent", "endpoint")


def test_original_legacy_adapter_and_normalized_xdr_event(store):
    legacy = {
        "id": "legacy-1",
        "data": {
            "EndpointId": "host1",
            "ProcessGuid": "legacy-guid",
            "ParentProcessGuid": "parent-guid",
            "ProcessId": 12,
            "Image": r"C:\Synthetic\legacy.exe",
            "EventID": 3,
            "UtcTime": "2024-01-01 00:00:01",
            "SourceIp": "192.0.2.1",
            "SourcePort": "1234",
            "DestinationIp": "192.0.2.2",
            "DestinationPort": "443",
        },
    }
    parsed = xdr_bridge.parse_event(legacy, "legacy", "endpoint")
    data = parsed["raw"]["xdr"]["data"]
    assert data["process"]["name"] == "legacy.exe"
    assert data["event"]["action"] == "network_connection"
    assert data["source"]["port"] == 1234
    server = {
        "id": "remote-id",
        "tenant": "remote-tenant",
        "source": "edr",
        "normalized": event()["data"],
        "session_id": "SES-existing",
    }
    assert (
        xdr_bridge.intake(
            store,
            actor(),
            {"format": "server", "index": "endpoint", "events": [server]},
        )["accepted"]
        == 1
    )
    store.flush()
    rows = xdr_bridge.telemetry(store, actor(), START, START + 100)["rows"]
    assert rows[0]["xdr"]["original_session_id"] == "SES-existing"
    assert (
        xdr_bridge.telemetry(store, actor("admin_b", "b"), START, START + 100)["total"]
        == 0
    )


def test_guid_lineage_child_before_parent_pid_reuse_and_host_separation(store):
    ingest(
        store,
        [
            event("child", "child-guid", "parent-guid", pid=42),
            event("parent", "parent-guid", pid=42, at=1),
            event("reuse", "reused-pid-new-guid", pid=42, at=2),
            event("same-guid-other-host", "child-guid", host="host2", pid=42, at=3),
        ],
    )
    store.flush()
    result = xdr_bridge.process_tree(store, actor(), START, START + 100)
    assert result["matched_events"] == 4 and len(result["nodes"]) == 4
    assert len(result["edges"]) == 1 and len(result["sessions"]) == 3
    child = next(
        n for n in result["nodes"] if n["guid"] == "child-guid" and n["host"] == "host1"
    )
    parent = next(n for n in result["nodes"] if n["guid"] == "parent-guid")
    assert child["parent"] == parent["id"] and not parent["placeholder"]
    assert result["edges"][0]["relation"] == "reported_parent_guid"
    assert sum(s["event_count"] for s in result["sessions"]) == 4


def test_private_parent_is_placeholder_without_hidden_metadata_and_current_scope(store):
    ingest(store, [event("public-child", "child", "private-parent")], index="endpoint")
    ingest(store, [event("secret-parent", "private-parent", at=1)], index="private")
    ingest(store, [event("other-tenant", "other-guid")], tenant="b")
    store.flush()
    access.set_for_user(store, actor(), "analyst_a", ["endpoint"])
    analyst = actor("analyst_a", role="analyst")
    result = xdr_bridge.process_tree(store, analyst, START, START + 100)
    assert result["matched_events"] == 1
    parent = next(n for n in result["nodes"] if n["guid"] == "private-parent")
    assert (
        parent["placeholder"] and parent["name"] is None and parent["event_count"] == 0
    )
    assert "secret-parent" not in json.dumps(result) and "other-guid" not in json.dumps(
        result
    )
    access.set_for_user(store, actor(), "analyst_a", [])
    assert xdr_bridge.telemetry(store, analyst, START, START + 100)["total"] == 0
    with pytest.raises(PermissionError):
        xdr_bridge.intake(
            store,
            analyst,
            {"format": "agent", "index": "endpoint", "events": [event("denied")]},
        )


def test_intake_cannot_write_to_private_parser_route(store):
    pipeline.save(
        store,
        actor(),
        "endpoint-parser",
        {
            "version": 0,
            "definition": {
                "source": "aegis-xdr",
                "mappings": {},
                "redact_fields": [],
                "required_fields": [],
                "route_index": "private",
            },
        },
    )
    access.set_for_user(store, actor(), "analyst_a", ["endpoint"])
    with pytest.raises(PermissionError, match="parser route"):
        xdr_bridge.intake(
            store,
            actor("analyst_a", role="analyst"),
            {"format": "agent", "index": "endpoint", "events": [event()]},
        )
    assert store.health("a")["pending"] == 0


@pytest.mark.parametrize("kind", ["cycle", "parent_conflict", "pid_conflict"])
def test_ambiguous_lineage_fails_explicitly(store, kind):
    if kind == "cycle":
        rows = [event("first", "a", "b"), event("second", "b", "a", at=1)]
    elif kind == "parent_conflict":
        rows = [event("first", "a", "b"), event("second", "a", "c", at=1)]
    else:
        rows = [event("first", "a", pid=1), event("second", "a", pid=2, at=1)]
    ingest(store, rows)
    store.flush()
    with pytest.raises(ConflictError):
        xdr_bridge.process_tree(store, actor(), START, START + 100)


def test_full_count_sampling_caps_cancel_and_acl_change(store, monkeypatch):
    ingest(store, [event(str(n), at=n) for n in range(30)])
    store.flush()
    result = xdr_bridge.telemetry(store, actor(), START, START + 100, limit=5)
    assert result["total"] == 30 and result["returned"] == 5 and result["truncated"]
    tree = xdr_bridge.process_tree(store, actor(), START, START + 100)
    assert (
        tree["nodes"][0]["event_count"] == 30
        and len(tree["nodes"][0]["evidence"]) == 20
    )
    stop = threading.Event()
    stop.set()
    with pytest.raises(CapacityError):
        xdr_bridge.process_tree(store, actor(), START, START + 100, cancel=stop)
    monkeypatch.setattr(xdr_bridge, "MAX_EVENTS", 10)
    with pytest.raises(CapacityError):
        xdr_bridge.process_tree(store, actor(), START, START + 100)
    monkeypatch.setattr(xdr_bridge, "MAX_EVENTS", 5000)
    original = store.analytics_query

    def revoke(*args, **kw):
        result = original(*args, **kw)
        access.set_for_user(store, actor(), "analyst_a", [])
        return result

    monkeypatch.setattr(store, "analytics_query", revoke)
    with pytest.raises(PermissionError):
        xdr_bridge.telemetry(
            store, actor("analyst_a", role="analyst"), START, START + 100
        )


@contextmanager
def remote(tmp_path, monkeypatch, *, redirect=False):
    cert, key = certificate(tmp_path)
    expected = "synthetic-xdr-global-admin-test-token"
    monkeypatch.setenv("XDR_BRIDGE_TEST_TOKEN", expected)
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers.get("Authorization")))
            if redirect:
                self.send_response(302)
                self.send_header("Location", "https://127.0.0.1:8787/")
                self.end_headers()
                return
            payload = {
                "agents": [
                    {
                        "id": "AGT-1",
                        "tenant": "remote-a",
                        "host": "host1",
                        "version": "aegis-agent/0.1",
                        "last_seen": START,
                        "online": True,
                        "revoked": False,
                        "capabilities": ["collect_inventory", "isolate_host"],
                        "credential_hash": "do-not-return",
                        "health": {"private": "do-not-return"},
                    },
                    {"id": "AGT-other", "tenant": "remote-b", "host": "host1"},
                    {
                        "id": "AGT-other-host",
                        "tenant": "remote-a",
                        "host": "host-secret",
                    },
                ],
                "commands": [{"reason": "do-not-return"}],
            }
            data = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
    config = {
        "base_url": "https://127.0.0.1:" + str(server.server_address[1]),
        "allowed_hosts": ["127.0.0.1"],
        "allowed_ips": ["127.0.0.1"],
        "secret_env": "XDR_BRIDGE_TEST_TOKEN",
        "ca_file": str(cert),
        "certificate_sha256": pin,
        "bindings": {
            "a": {
                "remote_tenant": "remote-a",
                "hosts": ["host1"],
                "indexes": ["endpoint"],
            }
        },
    }
    try:
        yield config, seen
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


def test_verified_tls_pinned_server_summary_is_tenant_host_filtered_and_secret_free(
    store, tmp_path, monkeypatch
):
    with remote(tmp_path, monkeypatch) as (config, seen):
        bridge = xdr_bridge.Bridge(config)
        assert (
            bridge.status()["credential_available"]
            and not bridge.status()["containment_enabled"]
        )
        result = bridge.summary(store, actor())
        assert result["returned"] == 1 and result["agents"][0]["capabilities"] == [
            "collect_inventory"
        ]
        assert seen == [("/api/agents", "Bearer synthetic-xdr-global-admin-test-token")]
        assert "do-not-return" not in json.dumps(result) and "TOKEN" not in json.dumps(
            bridge.status()
        )
        with pytest.raises(ValueError, match="not configured"):
            bridge.summary(store, actor("admin_b", "b"))
        with pytest.raises(PermissionError):
            bridge.summary(store, actor("analyst_a", role="analyst"))
        config["certificate_sha256"] = "0" * 64
        with pytest.raises(PermissionError, match="pin"):
            xdr_bridge.Bridge(config).summary(store, actor())
        # A pin never replaces the CA/hostname verification requirement.
        config.pop("ca_file")
        with pytest.raises(ValueError, match="TLS"):
            xdr_bridge.Bridge(config).summary(store, actor())


def test_remote_redirect_denied_and_default_disabled(store, tmp_path, monkeypatch):
    disabled = xdr_bridge.Bridge()
    assert (
        not disabled.status()["configured"]
        and not disabled.status()["containment_enabled"]
    )
    with pytest.raises(ValueError):
        disabled.summary(store, actor())
    with remote(tmp_path, monkeypatch, redirect=True) as (config, seen):
        with pytest.raises(ValueError, match="302"):
            xdr_bridge.Bridge(config).summary(store, actor())
        assert len(seen) == 1
        config["base_url"] = config["base_url"].replace("https:", "http:")
        with pytest.raises(ValueError, match="HTTPS"):
            xdr_bridge.Bridge(config)


def test_public_http_auth_csrf_roles_typed_intake_and_process_projection(tmp_path):
    app = create_app(Settings(tmp_path, min_free_bytes=0), background=False)
    for name, role in (("admin_a", "admin"), ("viewer_a", "viewer")):
        auth.create_user(app.state.store, name, PASSWORD, role, "a")
    with TestClient(app) as client:
        assert client.get("/api/xdr/status").status_code == 401
        login = client.post(
            "/api/login", json={"name": "admin_a", "password": PASSWORD}
        )
        assert login.status_code == 200
        payload = {"format": "agent", "index": "endpoint", "events": [event()]}
        assert client.post("/api/xdr/intake", json=payload).status_code == 403
        client.headers["X-CSRF-Token"] = login.json()["csrf"]
        response = client.post("/api/xdr/intake", json=payload)
        assert response.status_code == 202, response.text
        assert (
            client.post("/api/xdr/intake", json={"format": "wrong"}).status_code == 400
        )
        app.state.store.flush()
        tree = client.get(f"/api/xdr/process-tree?start={START}&end={START + 100}")
        assert tree.status_code == 200 and tree.json()["matched_events"] == 1
        assert client.get("/api/xdr/telemetry?start=bad&end=1").status_code == 400
        assert not client.get("/api/xdr/status").json()["containment_enabled"]
        assert client.post("/api/xdr/isolate", json={}).status_code == 404
        client.cookies.clear()
        login = client.post(
            "/api/login", json={"name": "viewer_a", "password": PASSWORD}
        )
        client.headers["X-CSRF-Token"] = login.json()["csrf"]
        assert (
            client.get(
                f"/api/xdr/telemetry?start={START}&end={START + 100}"
            ).status_code
            == 200
        )
        assert client.post("/api/xdr/intake", json=payload).status_code == 403


def test_explicit_isolated_qa_seed_uses_real_policy_case_and_pending_approval(store):
    with pytest.raises(ValueError, match="isolated"):
        seed(store, actor())
    (store.path / ".qa-synthetic-only").touch()
    result = seed(store, actor())
    assert result["synthetic"] and result["replay"]["emitted"] > 0
    assert (
        xdr_bridge.process_tree(store, actor(), result["start"], result["end"])[
            "matched_events"
        ]
        == 4
    )
    with store.control() as db:
        row = db.execute(
            "SELECT state FROM soar_runs WHERE id=?",
            (result["pending_approval_run_id"],),
        ).fetchone()
        assert row["state"] == "pending_approval"


def test_config_environment_registration_is_explicit_and_status_redacts_secrets(
    tmp_path, monkeypatch
):
    config = {
        "base_url": "https://xdr.example.invalid",
        "allowed_hosts": ["xdr.example.invalid"],
        "allowed_ips": ["192.0.2.10"],
        "secret_env": "QA_XDR_BRIDGE_SECRET",
        "bindings": {
            "a": {"remote_tenant": "xdr-a", "hosts": ["host1"], "indexes": ["endpoint"]}
        },
    }
    path = tmp_path / "operator-xdr.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    monkeypatch.setenv("SAPIENTIA_XDR_CONFIG", str(path))
    monkeypatch.setenv("QA_XDR_BRIDGE_SECRET", "Ephemeral-configuration-test-secret")
    app = create_app(Settings(tmp_path / "data", min_free_bytes=0), background=False)
    auth.create_user(app.state.store, "admin_a", PASSWORD, "admin", "a")
    with TestClient(app) as client:
        login = client.post(
            "/api/login", json={"name": "admin_a", "password": PASSWORD}
        )
        assert login.status_code == 200
        response = client.get("/api/xdr/status")
        assert response.status_code == 200
        assert response.json()["configured"] and response.json()["credential_available"]
        for secret in (
            str(path),
            config["secret_env"],
            "Ephemeral-configuration-test-secret",
        ):
            assert secret not in response.text
    path.write_text('{"base_url":"http://unsafe.invalid"}', encoding="utf-8")
    with pytest.raises(ValueError):
        api_xdr.register(FastAPI(), None, None, None, None)
