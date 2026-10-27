# ruff: noqa: F811 -- Imported pytest fixtures are injected by argument name.
"""Evidence-bound command receipts plus real harmless native OS effects."""

import copy
import hashlib
import hmac
import io
import json
import os
import stat
import subprocess
import sys
import time
import uuid
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from sapientia import access, casework, detections
from sapientia import agent_distribution as ad
from sapientia import endpoint_response as er
from sapientia.api import create_app
from sapientia.endpoint_agent.Agent.core import response as executor
from sapientia.storage import ConflictError, encode
from tests.signing_support import release_signer  # noqa: F401
from tests.test_agent_distribution import config, enrolled, source_store  # noqa: F401
from tests.test_xdr_bridge import PASSWORD, actor, event

pytestmark = pytest.mark.usefixtures("release_signer")


@pytest.fixture
def response_case(source_store, config, release_signer):
    store = source_store
    service = ad.Distribution(store, config)
    identity, _, _, _ = enrolled(service)
    now = time.time()
    row = event(host="HOST-01", pid=123, guid="synthetic-guid")
    row["data"]["@timestamp"] = datetime.fromtimestamp(now - 2, UTC).isoformat()
    row["data"]["process"]["start_identity"] = "windows:1234567890"
    row["data"]["file"] = {
        "path": "C:\\PrivateQA\\synthetic.txt",
        "hash": {"sha256": "a" * 64},
    }
    service.ingest(identity["credential"], {"events": [row]})
    store.flush()
    detections.save(
        store,
        actor(),
        {
            "name": "Synthetic response evidence",
            "entity_field": "host",
            "window": 300,
            "steps": [{"filters": [{"field": "host", "op": "eq", "value": "HOST-01"}]}],
        },
    )
    assert detections.run_due(store, time.time() + 1) == 1
    incident = detections.incident_list(store, actor())[0]["id"]
    listing = er.listing(store, actor(), incident)
    body = {
        "agent_id": identity["agent_id"],
        "evidence_event_id": listing["events"][0]["event_id"],
        "case_version": listing["case_version"],
        "request_id": "synthetic-response-1",
        "reason": "Explicit harmless qualification",
        "action": {
            "type": "terminate_process",
            "process_guid": "synthetic-guid",
            "pid": 123,
            "start_identity": "windows:1234567890",
        },
    }
    return store, service, identity, incident, body


def claim_ack(service, identity):
    delivery = service.poll(identity["credential"], {})
    command = delivery["command"]
    assert hmac.compare_digest(
        delivery["signature"],
        hmac.new(
            identity["credential"].encode(), encode(command).encode(), hashlib.sha256
        ).hexdigest(),
    )
    receipt = {
        "command_id": command["id"],
        "lease_token": command["lease_token"],
        "execution_id": uuid.uuid4().hex,
    }
    return command, receipt, service.response_ack(identity["credential"], receipt)


def test_command_identity_exact_receipt_and_no_case_side_effect(response_case, monkeypatch):
    # Server protocol fixture only; no Agent executor or native OS action is invoked.
    monkeypatch.delenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", raising=False)
    store, service, identity, incident, body = response_case
    first = er.create(store, actor(), incident, body)
    assert er.create(store, actor(), incident, body)["duplicate"]
    changed = copy.deepcopy(body)
    changed["reason"] = "Different intent"
    with pytest.raises(ConflictError):
        er.create(store, actor(), incident, changed)
    command, receipt, ack = claim_ack(service, identity)
    assert ack["execute"] and command["id"] == first["id"]
    assert service.poll(identity["credential"], {})["command"] is None
    with pytest.raises(ConflictError):
        er.cancel(store, actor(), first["id"])
    altered = {**receipt, "execution_id": uuid.uuid4().hex}
    with pytest.raises(ConflictError):
        service.response_ack(identity["credential"], altered)
    outcome = {
        "success": True,
        "executed": True,
        "type": "terminate_process",
        "code": "terminated",
        "detail": "Synthetic fixture reports a confirmed effect",
    }
    assert (
        service.response_result(identity["credential"], {**receipt, "result": outcome})[
            "state"
        ]
        == "succeeded"
    )
    assert service.response_result(
        identity["credential"], {**receipt, "result": outcome}
    )["duplicate"]
    with pytest.raises(ConflictError):
        service.response_result(
            identity["credential"],
            {**receipt, "result": {**outcome, "detail": "conflict"}},
        )
    assert casework.workspace(store, actor(), incident)["incident"]["status"] == "new"


@pytest.mark.parametrize(
    "change",
    [
        "viewer",
        "tenant",
        "index",
        "guid",
        "pid",
        "start",
        "case_version",
        "event",
        "agent",
    ],
)
def test_scope_and_exact_evidence_reject_before_queue(response_case, change):
    store, _service, _identity, incident, body = response_case
    who = actor()
    if change == "viewer":
        who = actor("viewer_a", "a", "viewer")
    elif change == "tenant":
        who = actor("admin_b", "b")
    elif change == "index":
        access.set_for_user(store, who, "admin_a", [])
    elif change == "guid":
        body["action"]["process_guid"] = "unrelated-guid"
    elif change == "pid":
        body["action"]["pid"] = 124
    elif change == "start":
        body["action"]["start_identity"] = "windows:1234567891"
    elif change == "case_version":
        body["case_version"] += 1
    elif change == "event":
        body["evidence_event_id"] = "not-in-case"
    else:
        body["agent_id"] = "unrelated-agent"
    with pytest.raises((KeyError, PermissionError, ValueError, ConflictError)):
        er.create(store, who, incident, body)
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM endpoint_responses").fetchone()[0] == 0


def test_case_changes_between_claim_ack_fail_closed(response_case, monkeypatch):
    # Server protocol fixture only; no Agent executor or native OS action is invoked.
    monkeypatch.delenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", raising=False)
    store, service, identity, incident, body = response_case
    item = er.create(store, actor(), incident, body)
    command = service.poll(identity["credential"], {})["command"]
    casework.act(
        store,
        actor(),
        incident,
        {
            "request_id": "case-change",
            "action": {
                "type": "set_status",
                "status": "triage",
                "note": "Current analyst changed case",
            },
        },
    )
    ack = service.response_ack(
        identity["credential"],
        {
            "command_id": item["id"],
            "lease_token": command["lease_token"],
            "execution_id": uuid.uuid4().hex,
        },
    )
    assert (
        not ack["execute"] and er.get(store, actor(), item["id"])["state"] == "failed"
    )


def test_revocation_expiry_and_claim_lease_recovery(response_case, monkeypatch):
    # Server protocol fixture only; no Agent executor or native OS action is invoked.
    monkeypatch.delenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", raising=False)
    store, service, identity, incident, body = response_case
    item = er.create(store, actor(), incident, body)
    first = service.poll(identity["credential"], {})["command"]
    assert service.poll(identity["credential"], {})["command"] is None
    with store.control() as db:
        db.execute(
            "UPDATE endpoint_responses SET lease_until=? WHERE id=?",
            (time.time() - 1, item["id"]),
        )
    second = service.poll(identity["credential"], {})["command"]
    assert second["id"] == first["id"] and second["lease_token"] != first["lease_token"]
    with pytest.raises(PermissionError):
        service.response_ack(
            identity["credential"],
            {
                "command_id": item["id"],
                "lease_token": first["lease_token"],
                "execution_id": uuid.uuid4().hex,
            },
        )
    service.revoke(actor(), identity["agent_id"])
    assert er.get(store, actor(), item["id"])["state"] == "cancelled"
    with pytest.raises(PermissionError):
        service.poll(identity["credential"], {})


def test_file_identity_matches_case_evidence_and_rejects_shell(response_case, monkeypatch):
    # Server protocol fixture only; no Agent executor or native OS action is invoked.
    monkeypatch.delenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", raising=False)
    store, _, _, incident, body = response_case
    body["action"] = {
        "type": "delete_file",
        "path": "C:\\PrivateQA\\synthetic.txt",
        "sha256": "a" * 64,
    }
    assert er.create(store, actor(), incident, body)["state"] == "queued"
    for path in (
        "C:\\PrivateQA\\..\\Windows\\file",
        "\\\\server\\share\\file",
        "C:\\PrivateQA\\file:stream",
    ):
        with pytest.raises(ValueError):
            er.action({**body["action"], "path": path}, "windows")
    with pytest.raises(ValueError):
        er.action({"type": "shell", "command": "anything"}, "windows")


def test_native_exact_process_termination_and_pid_reuse_guard(tmp_path):
    if os.name != "nt" and not hasattr(os, "pidfd_open"):
        pytest.skip("Native termination requires Windows or Linux pidfd")
    child = subprocess.Popen(
        [sys._base_executable, "-I", "-B", "-c", "import time;time.sleep(60)"],
        **({"creationflags": 0x08000000} if os.name == "nt" else {}),
    )
    try:
        info = executor.inspect_process(child.pid, "SYNTHETIC-HOST")
        action = {
            "type": "terminate_process",
            "process_guid": info["guid"],
            "pid": child.pid,
            "start_identity": info["start_identity"],
        }
        settings = {
            "enabled": True,
            "allow_process_termination": True,
            "allowed_process_executables": [info["executable"]],
            "allowed_process_instances": [
                {"pid": child.pid, "start_identity": info["start_identity"]}
            ],
        }
        assert not executor.execute(action, "SYNTHETIC-HOST", {})["success"]
        assert not executor.execute(
            {**action, "start_identity": info["start_identity"] + "1"},
            "SYNTHETIC-HOST",
            settings,
        )["success"]
        assert not executor.execute(action, "WRONG-HOST", settings)["success"]
        assert child.poll() is None
        result = executor.execute(action, "SYNTHETIC-HOST", settings)
        assert result["success"] and result["executed"] is True
        child.wait(timeout=3)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()


def test_native_file_delete_hash_guard_root_and_hardlinks(tmp_path):
    root = tmp_path.resolve()
    (root / executor.MARKER).write_text(executor.MARKER_TEXT)
    file = root / "SYNTHETIC-DELETE.txt"
    file.write_bytes(b"Harmless synthetic qualification file")
    settings = {"enabled": True, "allow_file_delete": True, "file_roots": [str(root)]}
    action = {
        "type": "delete_file",
        "path": str(file),
        "sha256": hashlib.sha256(file.read_bytes()).hexdigest(),
    }
    assert (
        not executor.execute({**action, "sha256": "0" * 64}, "QA", settings)["success"]
        and file.exists()
    )
    assert (
        not executor.execute(action, "QA", {**settings, "file_roots": []})["success"]
        and file.exists()
    )
    link = root / "hardlink.txt"
    os.link(file, link)
    assert (
        not executor.execute(action, "QA", settings)["success"]
        and file.exists()
        and link.exists()
    )
    link.unlink()
    assert executor.execute(action, "QA", settings)["success"] and not file.exists()


def test_native_self_and_parent_are_protected():
    info = executor.inspect_process(os.getpid(), "QA")
    action = {
        "type": "terminate_process",
        "process_guid": info["guid"],
        "pid": os.getpid(),
        "start_identity": info["start_identity"],
    }
    result = executor.execute(
        action,
        "QA",
        {
            "enabled": True,
            "allow_process_termination": True,
            "allowed_process_executables": [info["executable"]],
        },
    )
    assert not result["success"] and result["executed"] is False


def delivery(identity, command_id="RSP-qa"):
    command = {
        "id": command_id,
        "agent_id": identity["agent_id"],
        "tenant": identity["tenant"],
        "host": identity["host"],
        "index": "endpoint",
        "incident_id": "CASE-QA",
        "case_version": 1,
        "action": {"type": "delete_file", "path": "synthetic", "sha256": "a" * 64},
        "expires_at": time.time() + 300,
        "lease_until": time.time() + 30,
        "lease_token": "a" * 43,
    }
    return {
        "command": command,
        "signature": hmac.new(
            identity["credential"].encode(),
            executor.canonical(command).encode(),
            hashlib.sha256,
        ).hexdigest(),
    }


def test_local_receipt_loss_retries_report_never_os_effect(tmp_path, monkeypatch):
    identity = {
        "agent_id": "AGT-qa",
        "tenant": "a",
        "host": "QA",
        "credential": "b" * 43,
    }
    data, calls, effects = delivery(identity), [], []

    def post(route, body):
        calls.append(route)
        if route.endswith("ack"):
            return {
                "execute": True,
                "command_id": body["command_id"],
                "execution_id": body["execution_id"],
                "execute_until": time.time() + 20,
            }
        if route.endswith("result") and calls.count(route) == 1:
            raise OSError("Synthetic ACK loss")
        return {"ok": True}

    agent = SimpleNamespace(
        identity=identity,
        config={"state_dir": str(tmp_path), "index": "endpoint", "response": {}},
        _post=post,
    )
    monkeypatch.setattr(
        executor,
        "execute",
        lambda *args: (
            effects.append(args)
            or {
                "success": True,
                "executed": True,
                "type": "delete_file",
                "code": "deleted",
                "detail": "Synthetic callback only",
            }
        ),
    )
    ledger = executor.Ledger(tmp_path)
    try:
        with pytest.raises(OSError):
            ledger.handle(agent, data)
        ledger.handle(agent, data)
        assert len(effects) == 1 and calls.count("/api/agent/ack") == 1
    finally:
        ledger.close()


def test_crash_marker_becomes_unknown_and_lock_excludes_live_recovery(tmp_path):
    with executor.Lock(tmp_path):
        with pytest.raises(RuntimeError), executor.Lock(tmp_path):
            pass
        ledger = executor.Ledger(tmp_path)
        ledger.db.execute(
            "INSERT INTO executions VALUES(?,?,?,?,?,'executing',NULL,0)",
            ("RSP-crash", "a", uuid.uuid4().hex, "b" * 43, "delete_file"),
        )
        ledger.db.commit()
        ledger.close()
    with executor.Lock(tmp_path):
        ledger = executor.Ledger(tmp_path)
        try:
            pending = ledger.pending()
            assert (
                len(pending) == 1
                and json.loads(pending[0]["result"])["executed"] is None
            )
            assert pending[0]["state"] == "unknown"
        finally:
            ledger.close()


def test_http_response_requires_csrf_and_endpoint_ack_verified_https(response_case, monkeypatch):
    # Server protocol fixture only; no Agent executor or native OS action is invoked.
    monkeypatch.delenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", raising=False)
    store, service, identity, incident, body = response_case
    settings = store.settings
    store.close()
    app = create_app(settings, background=False)
    app.state.agent_distribution.config = service.config
    with TestClient(app, base_url="https://testserver") as client:
        login = client.post(
            "/api/login", json={"name": "admin_a", "password": PASSWORD}
        )
        assert login.status_code == 200
        headers = {"x-csrf-token": login.json()["csrf"]}
        route = "/api/incidents/" + incident + "/agent-response"
        assert client.post(route, json=body).status_code == 403
        assert (
            client.post(
                route,
                json=body,
                headers={**headers, "origin": "https://untrusted.example.test"},
            ).status_code
            == 403
        )
        queued = client.post(route, json=body, headers=headers)
        assert queued.status_code == 201
        bearer = {"authorization": "Bearer " + identity["credential"]}
        response = client.post("/api/agent/poll", json={}, headers=bearer)
        assert response.status_code == 200, response.text
        claim = response.json()["command"]
        ack = {
            "command_id": claim["id"],
            "lease_token": claim["lease_token"],
            "execution_id": uuid.uuid4().hex,
        }
        assert (
            client.post(
                "http://testserver/api/agent/ack", json=ack, headers=bearer
            ).status_code
            == 403
        )
        assert client.post("/api/agent/ack", json=ack).status_code == 401
        assert (
            client.post(
                "/api/agent/ack",
                json=ack,
                headers={b"authorization": b"Bearer \xff\xfe"},
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/api/agent/ack",
                json=ack,
                headers={**bearer, "x-forwarded-proto": "https"},
            ).status_code
            == 403
        )
        assert (
            client.post("/api/agent/ack", json=ack, headers=bearer).json()["execute"]
            is True
        )


def test_signature_tamper_has_no_ack_or_execution(tmp_path, monkeypatch):
    identity = {
        "agent_id": "AGT-qa",
        "tenant": "a",
        "host": "QA",
        "credential": "b" * 43,
    }
    data = delivery(identity)
    data["command"]["action"]["path"] = "tampered"
    calls = []
    agent = SimpleNamespace(
        identity=identity,
        config={"state_dir": str(tmp_path), "index": "endpoint"},
        _post=lambda *a: calls.append(a),
    )
    monkeypatch.setattr(executor, "execute", lambda *a: calls.append("effect"))
    ledger = executor.Ledger(tmp_path)
    try:
        with pytest.raises(PermissionError):
            ledger.handle(agent, data)
        assert calls == []
    finally:
        ledger.close()


@pytest.mark.parametrize("after_ack", [False, True])
def test_requester_revocation_and_expired_started_unknown_no_replay(
    response_case, after_ack, monkeypatch
):
    # Server protocol fixture only; no Agent executor or native OS action is invoked.
    monkeypatch.delenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", raising=False)
    store, service, identity, incident, body = response_case
    item = er.create(store, actor(), incident, body)
    delivery = service.poll(identity["credential"], {})["command"]
    if after_ack:
        receipt = {
            "command_id": item["id"],
            "lease_token": delivery["lease_token"],
            "execution_id": uuid.uuid4().hex,
        }
        assert service.response_ack(identity["credential"], receipt)["execute"]
        with store.control() as db:
            db.execute(
                "UPDATE endpoint_responses SET expires=? WHERE id=?",
                (time.time() - 1, item["id"]),
            )
        assert service.poll(identity["credential"], {})["command"] is None
        assert er.get(store, actor(), item["id"])["state"] == "unknown"
    else:
        with store.control() as db:
            db.execute(
                "UPDATE endpoint_responses SET requester='analyst_a' WHERE id=?",
                (item["id"],),
            )
        access.set_for_user(store, actor("admin_other"), "analyst_a", [])
        receipt = {
            "command_id": item["id"],
            "lease_token": delivery["lease_token"],
            "execution_id": uuid.uuid4().hex,
        }
        assert not service.response_ack(identity["credential"], receipt)["execute"]
        assert er.get(store, actor("admin_other"), item["id"])["state"] == "failed"


def test_local_cli_policy_explicit_confirmation_marker_and_disable(tmp_path):
    if os.name == "nt":
        import ctypes

        if not ctypes.windll.shell32.IsUserAnAdmin():
            pytest.skip("Policy CLI intentionally requires local administrator")
    elif os.geteuid() != 0:
        pytest.skip("Policy CLI intentionally requires root")
    root = tmp_path.resolve() / "local-cli-private-state"
    root.mkdir()
    from sapientia.backup import _private_directory

    _private_directory(root, created=True)
    allowed = root / "narrow-qa-files"
    allowed.mkdir(mode=0o700)
    config = root / "config.json"
    original = {
        "endpoint_url": "https://example.test",
        "ca_file": str(root / "ca.pem"),
        "tenant": "synthetic",
        "host": "QA",
        "state_dir": str(root / "state"),
        "index": "endpoint",
    }
    config.write_text(json.dumps(original), encoding="utf-8")
    installed = root / "installed"
    installed.mkdir()
    with zipfile.ZipFile(
        io.BytesIO(ad.package("windows" if os.name == "nt" else "linux")[0])
    ) as archive:
        archive.extractall(installed)
    entry = (
        installed / "Agent" / ("Windows" if os.name == "nt" else "Linux") / "main.py"
    )
    prefix = [
        sys.executable,
        "-I",
        "-B",
        str(entry),
        "response-policy",
        "--config",
        str(config),
    ]
    enabling = [
        "--enable-response",
        "--allow-file-root",
        str(allowed),
        "--mark-file-roots",
    ]
    cli_source = installed / "Agent/cli.py"
    if os.name == "nt":
        acl_tool = (
            Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/icacls.exe"
        )
        subprocess.run(
            [str(acl_tool), str(cli_source), "/grant", "*S-1-5-32-545:M"],
            capture_output=True,
            check=True,
        )
    else:
        cli_source.chmod(0o666)
    unsafe = subprocess.run(
        prefix + enabling + ["--confirm-response-policy"],
        capture_output=True,
        check=False,
    )
    assert unsafe.returncode != 0 and json.loads(config.read_text()) == original
    assert not (allowed / executor.MARKER).exists()
    if os.name == "nt":
        subprocess.run(
            [str(acl_tool), str(cli_source), "/remove:g", "*S-1-5-32-545"],
            capture_output=True,
            check=True,
        )
    else:
        cli_source.chmod(0o600)
    rejected = subprocess.run(prefix + enabling, capture_output=True, check=False)
    assert rejected.returncode != 0 and json.loads(config.read_text()) == original
    assert not (allowed / executor.MARKER).exists()
    enabled = subprocess.run(
        prefix + enabling + ["--confirm-response-policy"],
        capture_output=True,
        check=False,
    )
    assert enabled.returncode == 0, enabled.stderr.decode(errors="replace")
    applied = json.loads(config.read_text())["response"]
    assert (
        applied["enabled"]
        and applied["allow_file_delete"]
        and not applied["allow_process_termination"]
    )
    assert (allowed / executor.MARKER).read_text() == executor.MARKER_TEXT
    broad = subprocess.run(
        prefix
        + [
            "--enable-response",
            "--allow-file-root",
            str(Path.home()),
            "--mark-file-roots",
            "--confirm-response-policy",
        ],
        capture_output=True,
        check=False,
    )
    assert (
        broad.returncode != 0 and json.loads(config.read_text())["response"] == applied
    )
    disabled = subprocess.run(
        prefix + ["--disable-response", "--confirm-response-policy"],
        capture_output=True,
        check=False,
    )
    assert (
        disabled.returncode == 0
        and json.loads(config.read_text())["response"]["enabled"] is False
    )


@pytest.mark.parametrize(
    "malformed",
    [
        None,
        [],
        "bad",
        {"xdr": []},
        {"xdr": {"schema": "aegis.endpoint.v1", "data": []}},
        {"xdr": {"schema": "aegis.endpoint.v1", "data": {"host": "bad"}}},
    ],
)
def test_malformed_generic_xdr_targets_are_skipped_in_case_api(
    response_case, malformed
):
    store, service, _identity, incident, _body = response_case
    event_id = "malformed-generic-" + uuid.uuid4().hex
    store.ingest(
        "a",
        [
            {
                "event_id": event_id,
                "event_time": time.time(),
                "host": "HOST-01",
                "index": "endpoint",
                "raw": malformed,
            }
        ],
    )
    store.flush()
    casework.bookmark(
        store,
        actor(),
        incident,
        {
            "event_id": event_id,
            "label": "Malformed generic event must not break target projection",
        },
    )
    settings = store.settings
    store.close()
    app = create_app(settings, background=False)
    app.state.agent_distribution.config = service.config
    with TestClient(app, base_url="https://testserver") as client:
        assert (
            client.post(
                "/api/login", json={"name": "admin_a", "password": PASSWORD}
            ).status_code
            == 200
        )
        response = client.get("/api/incidents/" + incident + "/agent-response")
        assert response.status_code == 200, response.text
        assert all(row["event_id"] != event_id for row in response.json()["events"])


@pytest.mark.parametrize("restore_fails", [True, False])
def test_linux_claim_hash_failure_reports_unknown_when_restore_fails(
    tmp_path, monkeypatch, restore_fails
):
    # Exercise Linux control flow on Windows without pretending to qualify a
    # Linux kernel. Mock only the syscall boundary, including restoration.
    target = tmp_path.resolve() / "synthetic.txt"
    calls = []
    info = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o600,
        st_nlink=1,
        st_size=3,
        st_dev=1,
        st_ino=2,
        st_mtime_ns=0,
    )
    reads = iter((b"abc", b""))

    def link(*args, **kwargs):
        calls.append("restore")
        if restore_fails:
            raise FileExistsError("Synthetic concurrent original-path recreation")

    fake = SimpleNamespace(
        name="posix",
        O_RDONLY=0,
        O_DIRECTORY=0,
        O_NOFOLLOW=0,
        open=lambda *a, **kw: 10,
        stat=lambda *a, **kw: info,
        fstat=lambda *a: info,
        read=lambda *a: next(reads),
        rename=lambda *a, **kw: calls.append("claim"),
        unlink=lambda *a, **kw: calls.append("unlink"),
        link=link,
        close=lambda *a: calls.append("close"),
    )
    monkeypatch.setattr(executor, "os", fake)
    monkeypatch.setattr(executor, "_file_target", lambda *a: target)
    outcome = executor.execute(
        {"type": "delete_file", "path": str(target), "sha256": "0" * 64},
        "QA",
        {"enabled": True, "allow_file_delete": True},
    )
    assert "claim" in calls and "restore" in calls and not outcome["success"]
    if restore_fails:
        assert outcome["executed"] is None and outcome["code"] == "effect_unconfirmed"
        assert (
            str(target.parent) in outcome["detail"]
            and ".lumina-response-" in outcome["detail"]
        )
        assert "unlink" not in calls
    else:
        assert outcome["executed"] is False and outcome["code"] == "target_rejected"
        assert "unlink" in calls
