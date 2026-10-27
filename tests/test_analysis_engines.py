"""Evidence checks, actual framed adapters and real loopback protocol transport."""
import hashlib
import json
import socket
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from test_xdr_advanced_api import login
from test_yara_manager import actor, collection

from sapientia import access
from sapientia import analysis_engines as engines
from sapientia.storage import ConflictError

pytest_plugins = ("test_xdr_advanced_api",)


@pytest.fixture
def ready(client):
    engines.initialize(client.app.state.store)
    return client


def test_default_unavailable_never_becomes_clean(ready, monkeypatch):
    for name in ("XSERA_ANALYSIS_SITE_PACKAGES", "XSERA_CLAMAV_PORT", "XSERA_CAPE_URL", "XSERA_ENABLE_EMULATION"):
        monkeypatch.delenv(name, raising=False)
    store = ready.app.state.store
    artifact = collection(ready)
    statuses = engines.status(store, actor())
    assert {x["id"] for x in statuses["engines"]} == set(engines.ENGINES)
    assert statuses["native_sample_execution"] is False
    for name in ("clamav", "speakeasy"):
        result = engines.scan_artifact(store, actor(), artifact, name)
        assert result["status"] == "unavailable"
        assert result["verdict"] == "unknown" and result["signal_id"] is None
    # FLOSS is bundled by the qualified profile. These plain-text bytes are
    # deliberately unsupported input, not a PE/ELF success fixture.
    floss_status = next(item for item in statuses["engines"] if item["id"] == "floss")
    result = engines.scan_artifact(store, actor(), artifact, "floss")
    if floss_status["available"]:
        assert result["status"] == "error" and result.get("error")
        assert result["engine_version"] == floss_status["version"]
    else:
        assert result["status"] == "unavailable"
    assert result["verdict"] == "unknown" and result["signal_id"] is None
    assert len(engines.list_runs(store, actor())["items"]) == 3
    with pytest.raises(KeyError):
        engines.scan_artifact(store, {**actor("foreign"), "tenant": "b"}, artifact, "capa")
    with pytest.raises(PermissionError):
        engines.scan_artifact(store, actor("reader", "viewer"), artifact, "capa")


@pytest.mark.parametrize("url", ["https://evil.example", "http://localhost:1234", "http://127.0.0.1:1234/path", "http://u:p@127.0.0.1:1234", "http://127.0.0.1:1234?x=1"])
def test_cape_arbitrary_destination_is_never_accepted(monkeypatch, url):
    monkeypatch.setenv("XSERA_CAPE_URL", url)
    assert engines.engine_status("cape")["available"] is False
    with pytest.raises(ValueError):
        engines._config("cape")


def test_real_worker_uninstalled_engine_and_corrupt_frame(monkeypatch):
    from sapientia import yara_runtime

    monkeypatch.delenv("XSERA_ANALYSIS_SITE_PACKAGES", raising=False)
    # A genuinely dependency-free child, even when the parent ships FLOSS.
    # -S removes interpreter site initialization; the trusted bootstrap adds
    # no package paths. The production launcher and environment are unchanged.
    command = yara_runtime.isolated_command
    monkeypatch.setattr(yara_runtime.site, "getsitepackages", list)
    def stdlib_only(script):
        args = command(script)
        args.insert(2, "-S")
        return args
    monkeypatch.setattr(yara_runtime, "isolated_command", stdlib_only)
    checked = engines._worker({"operation": "status", "engine": "floss"}, engines._config("floss"), timeout=5)
    assert checked.get("available") is False
    assert checked["version"] is None and checked["rule_digest"] is None
    assert "not installed" in checked["reason"]
    bad = engines._worker({"operation": "scan", "engine": "unknown"}, engines._config("floss"), timeout=5)
    assert bad["status"] == "error"


def test_actual_worker_deadline_cannot_leave_delayed_child(tmp_path):
    # Large installed rule hashing is not required to verify the caller's deadline.
    result = engines._worker({"operation": "status", "engine": "floss"}, engines._config("floss"), timeout=0.0001)
    assert result["status"] == "timeout"


def test_real_child_cancellation_kills_before_delayed_write(tmp_path, monkeypatch):
    marker = tmp_path / "must-not-survive-worker-cancellation.txt"
    original_read = Path.read_text
    source = "import sys,time,pathlib\nsys.stdin.readline()\ntime.sleep(1)\npathlib.Path(" + repr(str(marker)) + ").write_text('unexpected')\nprint('{}')\n"
    def substitute(path, *args, **kwargs):
        return source if path.name == "analysis_engine_worker.py" else original_read(path, *args, **kwargs)
    monkeypatch.setattr(Path, "read_text", substitute)
    cancel = threading.Event()
    timer = threading.Timer(0.15, cancel.set)
    timer.start()
    began = time.monotonic()
    result = engines._worker({"operation": "status", "engine": "floss"}, engines._config("floss"), timeout=10, cancel=cancel)
    timer.join()
    assert result["status"] == "error" and result["cancelled"]
    assert time.monotonic() - began < 2
    time.sleep(1.1)
    assert not marker.exists()


def _recv_zero(stream):
    data = bytearray()
    while not data.endswith(b"\0"):
        data.extend(stream.recv(1))
    return bytes(data)


def _exact(stream, count):
    out = bytearray()
    while len(out) < count:
        chunk = stream.recv(count - len(out))
        if not chunk:
            raise ValueError("Fixture client disconnected")
        out.extend(chunk)
    return bytes(out)


class ClamdFixture:
    """Protocol fixture only: asserts bytes received, not an installed ClamAV."""
    def __init__(self, reply="stream: Fixture.Signature FOUND"):
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen()
        self.port = self.socket.getsockname()[1]
        self.bodies, self.errors = [], []
        self.reply = reply
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        try:
            # Scan status, actual bytes, then explicit VERSION verification.
            for _ in range(2):
                stream, _ = self.socket.accept()
                with stream:
                    command = _recv_zero(stream)
                    if command == b"zVERSION\0":
                        stream.sendall(b"ClamAV fixture/1/test\0")
                    elif command == b"zINSTREAM\0":
                        chunks = []
                        while size := struct.unpack("!I", _exact(stream, 4))[0]:
                            chunks.append(_exact(stream, size))
                        self.bodies.append(b"".join(chunks))
                        stream.sendall(self.reply.encode() + b"\0")
                    else:
                        raise AssertionError(command)
        except BaseException as exc:  # noqa: BLE001 - Fixture failures are surfaced by the calling test.
            self.errors.append(repr(exc))
        finally:
            self.socket.close()


@pytest.mark.parametrize("reply,verdict,status", [("stream: Fixture.Signature FOUND", "suspicious", "completed"), ("stream: OK", "unknown", "completed"), ("stream: size limit exceeded ERROR", "unknown", "error")])
def test_actual_loopback_clamd_protocol_and_exact_finding(ready, monkeypatch, reply, verdict, status):
    daemon = ClamdFixture(reply)
    monkeypatch.setenv("XSERA_CLAMAV_PORT", str(daemon.port))
    store, artifact = ready.app.state.store, collection(ready)
    result = engines.scan_artifact(store, actor(), artifact, "clamav")
    daemon.thread.join(timeout=3)
    assert not daemon.errors and daemon.bodies == [b"Harmless API signature sample never executed"]
    assert result["status"] == status and result["verdict"] == verdict
    assert any(item["engine"] == "clamav" and item["license"].startswith("GPL-2.0") and item["bundled_runtime"] is False for item in result["content_notices"]["items"])
    assert bool(result["signal_id"]) is (verdict == "suspicious")
    if result["signal_id"]:
        with store.control() as db:
            signal = json.loads(db.execute("SELECT body FROM intelligence_signals WHERE id=?", (result["signal_id"],)).fetchone()[0])
            assert engines.validate_parent(store, db, actor(), signal)
            from sapientia import content_notices
            assert signal["metadata"]["content_notices"] == result["content_notices"]
            assert content_notices.for_signal(db, actor(), signal) == result["content_notices"]
            for malformed in (None, [], "", 1):
                assert not engines.validate_parent(store, db, actor(), {**signal, "metadata": malformed})
            original = db.execute("SELECT action FROM endpoint_responses WHERE id=(SELECT command_id FROM endpoint_artifacts WHERE id=?)", (artifact,)).fetchone()[0]
            changed = json.loads(original)
            changed["path"] = "/different/collection-claim.bin"
            db.execute("UPDATE endpoint_responses SET action=? WHERE id=(SELECT command_id FROM endpoint_artifacts WHERE id=?)", (json.dumps(changed), artifact))
            assert not engines.validate_parent(store, db, actor(), signal)
            db.execute("UPDATE endpoint_responses SET action=? WHERE id=(SELECT command_id FROM endpoint_artifacts WHERE id=?)", (original, artifact))
            assert engines.validate_parent(store, db, actor(), signal)
            forged = {**signal, "features": {"artifact_sha256": "f" * 64}}
            assert not engines.validate_parent(store, db, actor(), forged)
        (store.path / "response-artifacts" / (artifact + ".bin")).write_bytes(b"tamper")
        with store.control() as db:
            assert not engines.validate_parent(store, db, actor(), signal)


def test_revocation_during_analysis_prevents_result_and_signal(ready, monkeypatch):
    store, artifact = ready.app.state.store, collection(ready)
    monkeypatch.setattr(engines, "engine_status", lambda engine, **kwargs: {"available": True, "version": "fixture", "rule_digest": "1" * 64, "sample_execution": "none"})
    def changed(*args, **kwargs):
        access.set_for_user(store, actor("approver"), "requester", ["other"])
        return {"status": "completed", "verdict": "unknown", "summary": {"capability_count": 1}}
    monkeypatch.setattr(engines, "_analyze", changed)
    with pytest.raises((KeyError, PermissionError)):
        engines.scan_artifact(store, actor(), artifact, "capa")
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM analysis_engine_runs").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM intelligence_signals WHERE rule_id LIKE 'analysis-engine:%'").fetchone()[0] == 0


def test_http_rejects_arbitrary_command_fields_and_reader_write(ready):
    login(ready, "requester")
    artifact = collection(ready)
    base = "/api/analysis-engines"
    assert ready.post(base + "/runs", json={"artifact_id": artifact, "engine": "capa", "path": "C:/anything.exe"}).status_code == 400
    assert ready.post(base + "/runs", json={"artifact_id": artifact, "engine": "shell"}).status_code == 400
    assert ready.get(base + "/status").status_code == 200
    login(ready, "reader")
    assert ready.post(base + "/runs", json={"artifact_id": artifact, "engine": "capa"}).status_code == 403


def test_capa_release_rule_bytes_and_license_are_pinned():
    root = Path(engines.__file__).parent / "catalogs" / "capa"
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["license"] == "Apache-2.0"
    assert manifest["commit"] == "2af9fbfc1c9b4634dbeb76b5d34fca9389fa7f80"
    assert manifest["rule_files"] == 1042
    for entry in manifest["files"]:
        content = (root / entry["path"]).read_bytes()
        assert len(content) == entry["bytes"] and hashlib.sha256(content).hexdigest() == entry["sha256"]
    assert b"Apache License" in (root / "LICENSE.txt").read_bytes()


def test_optional_real_capa_floss_on_copied_benign_runtime(ready):
    """A supported local install is exercised; absence is an explicit assertion."""
    store, artifact = ready.app.state.store, collection(ready)
    body = Path(getattr(sys, "_base_executable", sys.executable)).read_bytes()
    sha = hashlib.sha256(body).hexdigest()
    (store.path / "response-artifacts" / (artifact + ".bin")).write_bytes(body)
    with store.control() as db:
        db.execute("UPDATE endpoint_artifacts SET sha256=?,total_bytes=?,received=? WHERE id=?", (sha, len(body), len(body), artifact))
        row = db.execute("SELECT command_id FROM endpoint_artifacts WHERE id=?", (artifact,)).fetchone()
        command = json.loads(db.execute("SELECT action FROM endpoint_responses WHERE id=?", (row[0],)).fetchone()[0])
        command["sha256"] = sha
        db.execute("UPDATE endpoint_responses SET action=? WHERE id=?", (json.dumps(command), row[0]))
    for engine in ("capa", "floss"):
        details = engines.engine_status(engine)
        result = engines.scan_artifact(store, actor(), artifact, engine)
        assert result["sha256"] == sha and not result["native_sample_execution"]
        assert result["verdict"] == "unknown"
        if not details["available"]:
            assert result["status"] == "unavailable" and result["signal_id"] is None
        else:
            assert result["status"] == "completed", result
            assert result["summary"].get("capability_count", result["summary"].get("string_count", 0)) > 0
            assert result["signal_id"]
            cached = engines.scan_artifact(store, actor(), artifact, engine)
            assert cached["cache_hit"] and cached["status"] == "completed"
            with store.control() as db:
                signal = json.loads(db.execute("SELECT body FROM intelligence_signals WHERE id=?", (result["signal_id"],)).fetchone()[0])
                assert engines.validate_parent(store, db, actor(), signal)


class CapeFixture:
    """HTTP contract fixture; no guest/VM or real malware execution exists here."""
    def __init__(self, sha):
        outer = self
        self.uploads, self.sha, self.report_sha = [], sha, sha
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def answer(self, body):
                content = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            def do_GET(self):
                if self.path == "/apiv2/cuckoo/status/":
                    self.answer({"error": False, "data": {"version": "contract-fixture"}})
                elif self.path == "/apiv2/tasks/view/42/":
                    self.answer({"error": False, "data": {"id": 42, "status": "reported"}})
                elif self.path == "/apiv2/tasks/get/report/42/json/":
                    self.answer({"info": {"id": 42}, "target": {"file": {"sha256": outer.report_sha}}, "signatures": [{"name": "inert-fixture-observation", "description": "Contract fixture only"}]})
                else:
                    self.send_error(404)
            def do_POST(self):
                if self.path != "/apiv2/tasks/create/file/":
                    self.send_error(404)
                    return
                outer.uploads.append(self.rfile.read(int(self.headers["Content-Length"])))
                self.answer({"error": False, "data": {"task_ids": [42]}})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def test_real_local_cape_upload_requires_peer_and_pinned_exact_report(ready, monkeypatch):
    store, artifact = ready.app.state.store, collection(ready)
    sha = hashlib.sha256(b"Harmless API signature sample never executed").hexdigest()
    service = CapeFixture(sha)
    monkeypatch.setenv("XSERA_CAPE_URL", "http://127.0.0.1:" + str(service.port))
    monkeypatch.setenv("XSERA_CAPE_VERSION", "contract-fixture")
    monkeypatch.setenv("XSERA_CAPE_RULE_DIGEST", "a" * 64)
    try:
        with pytest.raises(KeyError):
            engines.scan_artifact(store, actor(), artifact, "cape")
        assert not service.uploads
        consent = engines.request_approval(store, actor(), {"artifact_id": artifact, "engine": "cape", "reason": "Explicit inert bytes upload contract test"})
        with pytest.raises(PermissionError):
            engines.review_approval(store, actor(), consent["id"], {"approve": True, "reason": "self approval must fail"})
        assert not service.uploads
        engines.review_approval(store, actor("approver"), consent["id"], {"approve": True, "reason": "Exact hash and local destination reviewed"})
        run = engines.scan_artifact(store, actor(), artifact, "cape", approval_id=consent["id"])
        assert run["status"] == "pending" and run["signal_id"] is None and run["sample_executed"] is None
        assert len(service.uploads) == 1 and b"Harmless API signature sample never executed" in service.uploads[0]
        with pytest.raises(ConflictError):
            engines.scan_artifact(store, actor(), artifact, "cape", approval_id=consent["id"])
        assert len(service.uploads) == 1
        with store.control() as db:
            db.execute("UPDATE analysis_engine_approvals SET expires=0 WHERE id=?", (consent["id"],))
        service.report_sha = "f" * 64
        with pytest.raises(ConflictError):
            engines.poll_run(store, actor(), run["id"])
        assert engines.get_run(store, actor(), run["id"])["status"] == "pending"
        service.report_sha = sha
        complete = engines.poll_run(store, actor(), run["id"])
        assert complete["status"] == "completed" and complete["verdict"] == "unknown"
        assert complete["signal_id"] and complete["sha256"] == sha
        with store.control() as db:
            signal = json.loads(db.execute("SELECT body FROM intelligence_signals WHERE id=?", (complete["signal_id"],)).fetchone()[0])
            assert engines.validate_parent(store, db, actor(), signal)
        access.set_for_user(store, actor(), "approver", ["other"])
        with store.control() as db:
            assert not engines.validate_parent(store, db, actor(), signal)
    finally:
        service.close()


def test_auto_only_process_files_and_disabled_runtime_are_terminal(ready, monkeypatch):
    monkeypatch.delenv("XSERA_ANALYSIS_SITE_PACKAGES", raising=False)
    # Explicit disabled-runtime fixture: parent installation is not a test
    # precondition, and unavailable jobs must never call the scanning adapter.
    monkeypatch.setenv("XSERA_ANALYSIS_AUTO_ENGINES", "capa,floss")
    monkeypatch.setattr(engines, "engine_status", lambda engine, **kwargs: {
        "id": engine, "available": False, "enabled": False, "version": None,
        "rule_digest": None, "config_digest": None, "reason": "Explicit disabled-runtime fixture",
    })
    def forbidden_scan(*args, **kwargs):
        pytest.fail("Disabled automatic engine must not scan a collected file")
    monkeypatch.setattr(engines, "scan_artifact", forbidden_scan)
    store = ready.app.state.store
    ordinary = collection(ready)
    process = collection(ready, process=True)
    assert engines.run_due(store) == 0
    with store.control() as db:
        jobs = [dict(row) for row in db.execute("SELECT * FROM analysis_engine_auto_jobs")]
    assert {j["artifact_id"] for j in jobs} == {process}
    assert ordinary not in {j["artifact_id"] for j in jobs}
    assert {j["engine"] for j in jobs} == {"capa", "floss"}
    assert {j["state"] for j in jobs} == {"unavailable"}
    assert engines.run_due(store) == 0
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM analysis_engine_auto_jobs").fetchone()[0] == 2
        assert db.execute("SELECT count(*) FROM analysis_engine_runs").fetchone()[0] == 0


@pytest.mark.parametrize("bad", [None, [], "invalid", 1, False])
def test_cape_malformed_health_and_upload_objects_are_not_success(monkeypatch, bad):
    monkeypatch.setenv("XSERA_CAPE_URL", "http://127.0.0.1:12345")
    monkeypatch.setenv("XSERA_CAPE_VERSION", "contract-fixture")
    monkeypatch.setenv("XSERA_CAPE_RULE_DIGEST", "a" * 64)
    monkeypatch.setattr(engines, "_cape_http", lambda *args, **kwargs: {"data": bad})
    status = engines.engine_status("cape", fresh=True)
    assert not status["available"] and "invalid health data" in status["reason"]
    with pytest.raises(ValueError, match="invalid upload data"):
        engines._analyze("cape", engines._config("cape"), {"available": True}, b"inert", hashlib.sha256(b"inert").hexdigest())


@pytest.mark.parametrize("bad_path", ["data", "info", "target", "file", "signatures"])
def test_cape_malformed_report_does_not_finalize_pending_run(ready, monkeypatch, bad_path):
    store, artifact = ready.app.state.store, collection(ready)
    sha = hashlib.sha256(b"Harmless API signature sample never executed").hexdigest()
    monkeypatch.setenv("XSERA_CAPE_URL", "http://127.0.0.1:12345")
    monkeypatch.setenv("XSERA_CAPE_VERSION", "contract-fixture")
    monkeypatch.setenv("XSERA_CAPE_RULE_DIGEST", "a" * 64)
    report = {"info": {"id": 42}, "target": {"file": {"sha256": sha}}, "signatures": []}
    def contract(config, method, route, *args, **kwargs):
        if route.endswith("cuckoo/status/"):
            return {"data": {"version": "contract-fixture"}}
        if route.endswith("tasks/create/file/"):
            return {"data": {"task_ids": [42]}}
        if route.endswith("tasks/view/42/"):
            return {"data": {"status": "reported"}}
        return {"data": report}
    monkeypatch.setattr(engines, "_cape_http", contract)
    consent = engines.request_approval(store, actor(), {"artifact_id": artifact, "engine": "cape", "reason": "Malformed report contract test"})
    engines.review_approval(store, actor("approver"), consent["id"], {"approve": True, "reason": "Inert report contract reviewed"})
    run = engines.scan_artifact(store, actor(), artifact, "cape", approval_id=consent["id"])
    assert run["status"] == "pending"
    if bad_path == "data":
        report = []
    elif bad_path == "file":
        report["target"]["file"] = []
    elif bad_path == "signatures":
        report["signatures"] = [None]
    else:
        report[bad_path] = []
    with pytest.raises(ValueError):
        engines.poll_run(store, actor(), run["id"])
    saved = engines.get_run(store, actor(), run["id"])
    assert saved["status"] == "pending" and saved["signal_id"] is None
