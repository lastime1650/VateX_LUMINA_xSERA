"""Optional evidence-bound CPU/file engines; no implicit endpoint authority.

Paths and service ports come only from trusted server configuration. The API
accepts completed artifact IDs and fixed engine names, never commands/URLs.
"""
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import queue
import re
import site
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit
import uuid

from . import content_notices, endpoint_artifacts, evidence_scope as evidence, migrations, principal, release_manifest
from .storage import CapacityError, ConflictError, encode

ENGINES = ("capa", "floss", "clamav", "speakeasy", "cape")
EDITORS = ("admin", "analyst")
MAX_BYTES = 32 * 1024 * 1024
MAX_REPORT = 2 * 1024 * 1024
WALL_SECONDS = 120
CAPA_MANIFEST_SHA256 = "139faa3d3230f50490dddb3171d903603b7a76adfd5f3479a4a91faa54044e5d"
_gate = threading.BoundedSemaphore(1)
_status_lock = threading.Lock()
_status_cache = {}


def initialize(store):
    migrations.apply_store(store, "analysis_engines", [
        "CREATE TABLE IF NOT EXISTS analysis_engine_runs(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,incident_id TEXT NOT NULL,artifact_id TEXT NOT NULL,index_name TEXT NOT NULL,actor TEXT NOT NULL,created REAL NOT NULL,body TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS analysis_engine_case ON analysis_engine_runs(tenant,incident_id,created)",
        "CREATE TABLE IF NOT EXISTS analysis_engine_cache(tenant TEXT NOT NULL,cache_key TEXT NOT NULL,created REAL NOT NULL,body TEXT NOT NULL,PRIMARY KEY(tenant,cache_key))",
        "CREATE TABLE IF NOT EXISTS analysis_engine_approvals(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,incident_id TEXT NOT NULL,artifact_id TEXT NOT NULL,index_name TEXT NOT NULL,sha256 TEXT NOT NULL,engine TEXT NOT NULL,requester TEXT NOT NULL,approver TEXT,state TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,body TEXT NOT NULL)",
    ])
    migrations.apply_store(store, "analysis_engines", [
        "CREATE TABLE IF NOT EXISTS analysis_engine_auto_jobs(artifact_id TEXT NOT NULL,engine TEXT NOT NULL,tenant TEXT NOT NULL,actor TEXT NOT NULL,state TEXT NOT NULL,updated REAL NOT NULL,result_id TEXT,error TEXT,pin TEXT,PRIMARY KEY(artifact_id,engine))",
    ], version=2)


def _engine(value):
    return evidence.choice(value, ENGINES, "analysis engine")


def _config(engine):
    data = {"engine": engine, "max_bytes": MAX_BYTES, "wall_seconds": WALL_SECONDS, "adapter_revision": 1}
    if engine in {"capa", "floss", "speakeasy"}:
        extra = os.environ.get("XSERA_ANALYSIS_SITE_PACKAGES", "")
        if extra:
            path = Path(extra)
            if not path.is_absolute() or not path.is_dir() or path.is_symlink() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400:
                raise ValueError("Analysis site-packages must be a trusted absolute local directory")
        data["site_packages"] = extra
        data["rules"] = os.environ.get("XSERA_CAPA_RULES", str(Path(__file__).parent / "catalogs" / "capa" / "rules")) if engine == "capa" else ""
        data["release_manifest"] = {"path": str(Path(__file__).parent / "catalogs" / "capa" / "manifest.json"), "sha256": CAPA_MANIFEST_SHA256} if engine == "capa" and not os.environ.get("XSERA_CAPA_RULES") else None
        data["enabled"] = engine != "speakeasy" or os.environ.get("XSERA_ENABLE_EMULATION") == "1"
    elif engine == "clamav":
        port = os.environ.get("XSERA_CLAMAV_PORT", "")
        data.update(enabled=bool(port), host="127.0.0.1", port=int(port) if port else None)
        if port and not 1 <= data["port"] <= 65535:
            raise ValueError("Invalid local clamd port")
    else:
        url = os.environ.get("XSERA_CAPE_URL", "")
        if url:
            parsed = urlsplit(url)
            if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1"} or parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment or not parsed.port:
                raise ValueError("CAPE requires an explicit loopback HTTP origin and port")
        data.update(enabled=bool(url), url=url, version=os.environ.get("XSERA_CAPE_VERSION", ""), rule_digest=os.environ.get("XSERA_CAPE_RULE_DIGEST", ""))
        if data["enabled"] and (not data["version"] or not re.fullmatch(r"[a-f0-9]{64}", data["rule_digest"])):
            data["enabled"] = False
            data["reason"] = "Pin the local CAPE version and rule/config manifest SHA256 before enabling sample upload"
    return data


def _digest(value):
    return release_manifest.digest(value)


def _worker(request, config, *, timeout=WALL_SECONDS, cancel=None):
    """Bound both pipe readers and the real direct child; never shell out."""
    from . import cpu_ml_limits
    from .yara_runtime import isolated_command
    script = Path(__file__).with_name("analysis_engine_worker.py").read_text(encoding="utf-8")
    if config.get("site_packages"):
        script = "import sys\nsys.path.insert(0," + repr(config["site_packages"]) + ")\n" + script
    # A trusted module docstring must remain first for __future__ independence;
    # this worker deliberately contains no future directives.
    env = {key: os.environ[key] for key in ("SYSTEMROOT", "SystemRoot", "WINDIR", "TEMP", "TMP", "HOME") if key in os.environ}
    env.update(PYTHONUTF8="1", OMP_NUM_THREADS="1", MKL_NUM_THREADS="1", CAPA_SAVE_WORKSPACE="", FLOSS_CACHE="")
    frame = (encode(request) + "\n").encode("utf-8")
    with tempfile.TemporaryDirectory(prefix="xsera-engine-") as directory:
        env.update(HOME=directory, USERPROFILE=directory, APPDATA=directory, LOCALAPPDATA=directory,
                   XDG_CACHE_HOME=directory, XDG_CONFIG_HOME=directory, XDG_DATA_HOME=directory,
                   USER="xsera-worker", USERNAME="xsera-worker")
        try:
            child = subprocess.Popen(isolated_command(script), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=directory, env=env, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0, start_new_session=os.name != "nt")
        except OSError:
            return {"status": "unavailable", "error": "Isolated engine interpreter unavailable", "summary": {}}
        handle = None
        try:
            handle, limits = cpu_ml_limits.assign_windows(child.pid)
            if os.name == "nt" and not limits.get("os_enforced"):
                return {"status": "unavailable", "error": "Required Windows worker containment could not be applied", "summary": {}}
            answers = queue.Queue()
            def read(name, pipe):
                try:
                    value = pipe.read(MAX_REPORT + 1)
                    answers.put((name, value))
                except (OSError, ValueError):
                    answers.put((name, b""))
            for name, pipe in (("stdout", child.stdout), ("stderr", child.stderr)):
                threading.Thread(target=read, args=(name, pipe), daemon=True).start()
            child.stdin.write(frame)
            child.stdin.close()
            deadline, received = time.monotonic() + timeout, {}
            while len(received) < 2:
                if cancel is not None and cancel.is_set():
                    return {"status": "error", "error": "Engine worker cancelled during shutdown; explicit rerun required", "cancelled": True, "summary": {}}
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return {"status": "timeout", "error": "Engine wall deadline exceeded", "summary": {}}
                try:
                    name, value = answers.get(timeout=min(0.1, remaining))
                except queue.Empty:
                    continue
                if len(value) > MAX_REPORT:
                    return {"status": "error", "error": "Engine output budget exceeded", "summary": {}}
                received[name] = value
                if time.monotonic() > deadline:
                    return {"status": "timeout", "error": "Engine wall deadline exceeded", "summary": {}}
            child.wait(timeout=max(0.001, deadline - time.monotonic()))
            if child.returncode:
                return {"status": "error", "error": "Isolated engine process failed", "summary": {}}
            result = json.loads(received["stdout"])
            if not isinstance(result, dict):
                raise ValueError("Invalid engine result")
            result.pop("resource_path", None)
            return result
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "error": "Engine wall deadline exceeded", "summary": {}}
        except (OSError, ValueError, TypeError):
            return {"status": "error", "error": "Invalid isolated engine response", "summary": {}}
        finally:
            if child.poll() is None:
                if os.name != "nt":
                    import signal
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    child.kill()
            cpu_ml_limits.close_windows(handle)
            child.wait(timeout=3)
            for pipe in (child.stdout, child.stderr):
                pipe.close()


def _clam(command, body=None):
    config = _config("clamav")
    if not config["enabled"]:
        raise ConnectionError("Local clamd is not configured")
    with socket.create_connection(("127.0.0.1", config["port"]), timeout=5) as stream:
        deadline = time.monotonic() + 20
        def budget():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout("clamd wall deadline exceeded")
            stream.settimeout(remaining)
        budget()
        stream.sendall(b"z" + command.encode("ascii") + b"\0")
        if body is not None:
            for start in range(0, len(body), 65536):
                part = body[start:start + 65536]
                budget()
                stream.sendall(struct.pack("!I", len(part)) + part)
            budget()
            stream.sendall(struct.pack("!I", 0))
        result = bytearray()
        while not result.endswith(b"\0"):
            budget()
            part = stream.recv(min(4096, 65537 - len(result)))
            if not part:
                raise ValueError("Incomplete local clamd response")
            result.extend(part)
            if len(result) > 65536:
                raise ValueError("Local clamd response over budget")
        return bytes(result[:-1]).decode("utf-8", "replace")


def _cape_http(config, method, route, payload=None, headers=None):
    parsed = urlsplit(config["url"])
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    merged = dict(headers or {})
    token = os.environ.get("XSERA_CAPE_TOKEN")
    if token:
        merged["Authorization"] = "Token " + token
    try:
        connection.request(method, route, body=payload, headers=merged)
        response = connection.getresponse()
        data = response.read(MAX_REPORT + 1)
        if not 200 <= response.status < 300 or len(data) > MAX_REPORT:
            raise ValueError("Local CAPE rejected the request or exceeded the response budget")
        result = json.loads(data)
        if not isinstance(result, dict) or result.get("error") is True:
            raise ValueError("Local CAPE returned an error")
        return result
    finally:
        connection.close()


def _cape_object(value, label):
    if not isinstance(value, dict):
        raise ValueError("Local CAPE returned an invalid " + label + " object")
    return value


def engine_status(engine, *, fresh=False):
    _engine(engine)
    try:
        cache_key = _digest([engine, _config(engine)])
    except (OSError, ValueError):
        return _engine_status(engine)
    if not fresh:
        with _status_lock:
            cached = _status_cache.get(cache_key)
            if cached and time.monotonic() - cached[0] < 30:
                return {**cached[1], "probe_cached": True}
    result = _engine_status(engine)
    with _status_lock:
        if len(_status_cache) >= 16:
            _status_cache.pop(next(iter(_status_cache)))
        _status_cache[cache_key] = (time.monotonic(), dict(result))
    return result


def _engine_status(engine):
    try:
        config = _config(engine)
        result = {"id": engine, "available": False, "enabled": config["enabled"], "version": None, "rule_digest": None, "sample_execution": "sandbox" if engine == "cape" else "emulated" if engine == "speakeasy" else "none", "reason": config.get("reason")}
        if not config["enabled"]:
            result["reason"] = result["reason"] or "Optional local service/emulation is disabled by server configuration"
        elif engine in {"capa", "floss", "speakeasy"}:
            checked = _worker({"operation": "status", "engine": engine, "rules": config.get("rules"), "release_manifest": config.get("release_manifest")}, config, timeout=10)
            result.update({k: v for k, v in checked.items() if k in {"available", "version", "rule_digest", "resource_count", "reason"}})
            if checked.get("status") in {"error", "timeout", "unavailable"}:
                result["reason"] = checked.get("error")
        elif engine == "clamav":
            version = _clam("VERSION")
            if not version.startswith("ClamAV "):
                raise ValueError("Unexpected local clamd version response")
            result.update(available=True, version=version, rule_digest=hashlib.sha256(version.encode()).hexdigest(),
                          rule_digest_basis="clamd_VERSION_metadata_not_database_bytes", database_content_attested=False)
        else:
            health = _cape_http(config, "GET", "/apiv2/cuckoo/status/")
            observed = _cape_object(health.get("data", {}), "health data").get("version")
            if observed is not None and observed != config["version"]:
                raise ValueError("Local CAPE version differs from the pinned version")
            result.update(available=True, version=config["version"], rule_digest=config["rule_digest"],
                          rule_digest_basis="operator_pinned_local_manifest", database_content_attested=False,
                          version_observed=observed is not None)
        result["config_digest"] = _digest(config)
        return result
    except (OSError, ValueError, ConnectionError, http.client.HTTPException) as exc:
        return {"id": engine, "available": False, "enabled": False, "version": None, "rule_digest": None, "reason": type(exc).__name__ + ": " + str(exc)[:256], "config_digest": None, "sample_execution": "sandbox" if engine == "cape" else "emulated" if engine == "speakeasy" else "none"}


def status(store, who):
    with principal.transaction(store, who):
        pass
    return {"engines": [engine_status(engine) for engine in ENGINES], "max_artifact_bytes": MAX_BYTES, "no_match_verdict": "unknown", "native_sample_execution": False, "cape_peer_approval": True}


def _artifact(store, who, artifact_id):
    with principal.transaction(store, who, EDITORS) as (_, actor):
        pass
    body, _, sha = endpoint_artifacts.download(store, actor, artifact_id)
    if len(body) > MAX_BYTES:
        raise CapacityError("File exceeds the analysis byte budget")
    with principal.transaction(store, actor, EDITORS) as (db, actor):
        item = db.execute("SELECT * FROM endpoint_artifacts WHERE tenant=? AND id=?", (actor["tenant"], artifact_id)).fetchone()
        command = db.execute("SELECT * FROM endpoint_responses WHERE tenant=? AND id=?", (actor["tenant"], item["command_id"])).fetchone()
        if not command or command["state"] != "completed":
            raise ConflictError("Completed exact collection command is required")
        endpoint_artifacts.artifact_limit(db, item)
        if command["incident_id"] != item["incident_id"] or command["index_name"] != item["index_name"] or command["agent_id"] != item["agent_id"]:
            raise ConflictError("Artifact differs from the collection command")
        principal.incident(db, actor, item["incident_id"])
        source_id = command["evidence_event_id"]
        item = dict(item)
        item["_command_digest"] = _digest(dict(command))
    originals = evidence.originals(store, actor, [source_id])
    return actor, item, body, sha, originals


def _recheck(store, db, actor, artifact, originals, sha):
    from .yara_intelligence import _intact
    case = principal.incident(db, actor, artifact["incident_id"])
    if case["status"] == "false_positive":
        raise ConflictError("False-positive Case cannot publish new analysis")
    evidence.recheck(db, actor, originals)
    row = db.execute("SELECT * FROM endpoint_artifacts WHERE tenant=? AND id=?", (actor["tenant"], artifact["id"])).fetchone()
    if not row or dict(row) != {k: v for k, v in artifact.items() if not k.startswith("_")} or row["state"] != "complete" or row["sha256"] != sha or not _intact(store, db, row, None):
        raise ConflictError("Retained artifact changed during analysis")
    command = db.execute("SELECT * FROM endpoint_responses WHERE tenant=? AND id=?", (actor["tenant"], row["command_id"])).fetchone()
    endpoint_artifacts.artifact_limit(db, row)
    if not command or command["state"] != "completed" or [command["evidence_event_id"]] != sorted(originals):
        raise ConflictError("Collection evidence changed during analysis")
    if artifact.get("_command_digest") != _digest(dict(command)):
        raise ConflictError("Frozen collection command changed during analysis")
    from . import endpoint_response
    if any(not endpoint_response._member(db, actor, artifact["incident_id"], identifier) for identifier in originals):
        raise ConflictError("Collection original is no longer a member of this Case")
    for identifier in originals:
        source = db.execute("SELECT s.source_version,r.version,r.state FROM source_event_receipts s LEFT JOIN source_registry r ON r.tenant=s.tenant AND r.id=s.source_id WHERE s.tenant=? AND s.event_id=?", (actor["tenant"], identifier)).fetchone()
        if source and (source["state"] != "active" or source["version"] != source["source_version"]):
            raise ConflictError("Telemetry source authority changed")


def list_artifacts(store, who, *, incident_id=None):
    from . import yara_manager
    result = yara_manager.list_artifacts(store, who, incident_id=incident_id)
    result["items"] = [item for item in result["items"] if item["state"] == "complete"]
    result["total"] = len(result["items"])
    return result


def _approval(db, actor, identifier, artifact, engine, *, active=True, run_id=None):
    row = db.execute("SELECT * FROM analysis_engine_approvals WHERE tenant=? AND id=?", (actor["tenant"], identifier)).fetchone()
    if not row or not principal.contains(actor["allowed_indexes"], [row["index_name"]]):
        raise KeyError("Upload approval not found")
    if row["artifact_id"] != artifact["id"] or row["sha256"] != artifact["sha256"] or row["engine"] != engine or row["incident_id"] != artifact["incident_id"] or (run_id is None and row["expires"] <= time.time()):
        raise ConflictError("Upload approval expired or differs from this artifact")
    consent = json.loads(row["body"])
    if run_id is not None and consent.get("used_run_id") != run_id:
        raise ConflictError("Sandbox result differs from the one consented upload attempt")
    if active:
        if row["state"] != "active" or row["requester"] == row["approver"]:
            raise ConflictError("Independent active upload approval is required")
        for name in (row["requester"], row["approver"]):
            current = principal.current(db, {"name": name, "tenant": actor["tenant"], "role": "admin"}, ("admin",))
            if not principal.contains(current["allowed_indexes"], [row["index_name"]]):
                raise PermissionError("Upload approval authority changed")
            principal.incident(db, current, artifact["incident_id"])
        if consent["config_digest"] != _digest(_config(engine)):
            raise ConflictError("Local sandbox configuration changed; obtain a new approval")
    return row


def request_approval(store, who, data):
    if not isinstance(data, dict) or set(data) != {"artifact_id", "engine", "reason"} or data["engine"] != "cape":
        raise ValueError("CAPE approval requires artifact_id,engine,reason")
    reason = evidence.text(data["reason"], "reason", 1024)
    actor, artifact, _, sha, originals = _artifact(store, who, data["artifact_id"])
    config = _config("cape")
    if not config["enabled"]:
        raise ConflictError("Configure and pin the local CAPE service first")
    with principal.transaction(store, actor, ("admin",), write=True) as (db, fresh):
        _recheck(store, db, fresh, artifact, originals, sha)
        item = {"id": "AE-APP-" + uuid.uuid4().hex, "engine": "cape", "artifact_id": artifact["id"], "incident_id": artifact["incident_id"], "sha256": sha, "requester": fresh["name"], "approver": None, "state": "pending", "created": time.time(), "expires": time.time() + 3600, "reason": reason, "config_digest": _digest(config), "sample_destination": config["url"]}
        db.execute("INSERT INTO analysis_engine_approvals VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (item["id"], fresh["tenant"], item["incident_id"], item["artifact_id"], artifact["index_name"], sha, "cape", fresh["name"], None, "pending", item["created"], item["expires"], encode(item)))
        store.audit(db, fresh["tenant"], fresh["name"], "analysis_engine.upload_request", {"id": item["id"], "artifact_id": artifact["id"], "sha256": sha})
        return item


def review_approval(store, who, identifier, data):
    if not isinstance(data, dict) or set(data) != {"approve", "reason"} or type(data["approve"]) is not bool:
        raise ValueError("Review requires approve:boolean and reason")
    reason = evidence.text(data["reason"], "reason", 1024)
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        row = db.execute("SELECT * FROM analysis_engine_approvals WHERE tenant=? AND id=?", (actor["tenant"], identifier)).fetchone()
        if not row:
            raise KeyError("Upload approval not found")
        artifact = db.execute("SELECT * FROM endpoint_artifacts WHERE tenant=? AND id=?", (actor["tenant"], row["artifact_id"])).fetchone()
        if not artifact:
            raise KeyError("Approval artifact no longer retained")
        row = _approval(db, actor, identifier, artifact, "cape", active=False)
        principal.incident(db, actor, row["incident_id"])
        if row["requester"] == actor["name"]:
            raise PermissionError("Another administrator must review sample upload")
        if row["state"] != "pending":
            raise ConflictError("Upload approval was already reviewed")
        item = json.loads(row["body"])
        item.update(approver=actor["name"], state="active" if data["approve"] else "rejected", review_reason=reason)
        db.execute("UPDATE analysis_engine_approvals SET approver=?,state=?,body=? WHERE id=?", (actor["name"], item["state"], encode(item), identifier))
        store.audit(db, actor["tenant"], actor["name"], "analysis_engine.upload_review", {"id": identifier, "state": item["state"]})
        return item


def list_approvals(store, who, *, incident_id=None):
    with principal.transaction(store, who) as (db, actor):
        if incident_id:
            principal.incident(db, actor, incident_id)
        items = []
        for row in db.execute("SELECT * FROM analysis_engine_approvals WHERE tenant=? ORDER BY created DESC LIMIT 500", (actor["tenant"],)):
            if (incident_id and row["incident_id"] != incident_id) or not principal.contains(actor["allowed_indexes"], [row["index_name"]]):
                continue
            try:
                principal.incident(db, actor, row["incident_id"])
            except (KeyError, PermissionError):
                continue
            item = json.loads(row["body"])
            if item["expires"] <= time.time() and not item.get("used_run_id"):
                item["state"] = "expired"
            items.append(item)
        return {"items": items, "total": len(items), "limit": 500}


def _analyze(engine, config, details, body, sha, *, timeout=WALL_SECONDS, cancel=None):
    if not details["available"]:
        return {"status": "unavailable", "verdict": "unknown", "summary": {}, "error": details["reason"]}
    if engine in {"capa", "floss", "speakeasy"}:
        with tempfile.TemporaryDirectory(prefix="xsera-analysis-input-") as folder:
            path = Path(folder) / "sample.bin"
            path.write_bytes(body)
            return _worker({"operation": "scan", "engine": engine, "path": str(path), "sha256": sha, "rules": config.get("rules"), "release_manifest": config.get("release_manifest"), "expected": {"version": details["version"], "rule_digest": details["rule_digest"]}}, config, timeout=timeout, cancel=cancel)
    if engine == "clamav":
        try:
            answer = _clam("INSTREAM", body)
            if answer == "stream: OK":
                return {"status": "completed", "verdict": "unknown", "summary": {"detections": [], "meaning": "No signature match is not proof of a clean file"}}
            if answer.startswith("stream: ") and answer.endswith(" FOUND"):
                return {"status": "completed", "verdict": "suspicious", "summary": {"detections": [{"name": answer[8:-6][:512]}]}}
            return {"status": "error", "verdict": "unknown", "summary": {}, "error": "Local clamd could not complete the scan"}
        except socket.timeout:
            return {"status": "timeout", "verdict": "unknown", "summary": {}, "error": "Local clamd deadline exceeded"}
        except (OSError, ValueError) as exc:
            return {"status": "unavailable", "verdict": "unknown", "summary": {}, "error": type(exc).__name__}
    boundary = "xsera" + uuid.uuid4().hex
    payload = ("--" + boundary + '\r\nContent-Disposition: form-data; name="file"; filename="' + sha + '.bin"\r\nContent-Type: application/octet-stream\r\n\r\n').encode() + body + ("\r\n--" + boundary + "--\r\n").encode()
    response = _cape_http(config, "POST", "/apiv2/tasks/create/file/", payload, {"Content-Type": "multipart/form-data; boundary=" + boundary})
    tasks = _cape_object(response.get("data"), "upload data").get("task_ids")
    if not isinstance(tasks, list) or len(tasks) != 1 or type(tasks[0]) is not int or tasks[0] < 1:
        raise ValueError("CAPE did not return one exact task ID")
    return {"status": "pending", "verdict": "unknown", "summary": {"task_id": tasks[0], "meaning": "Submitted to explicitly approved local sandbox; report is not ready"}}


def scan_artifact(store, who, artifact_id, engine, *, emit_signal=True, approval_id=None, expected_pin=None, timeout=WALL_SECONDS, cancel=None):
    _engine(engine)
    if type(emit_signal) is not bool:
        raise ValueError("emit_signal requires boolean")
    if type(timeout) not in {int, float} or not math.isfinite(timeout) or not 0 < timeout <= WALL_SECONDS:
        raise ValueError("Engine wall budget must be within 0..120 seconds")
    if cancel is not None and cancel.is_set():
        raise ConflictError("Automatic file analysis cancelled during shutdown")
    actor, artifact, body, sha, originals = _artifact(store, who, artifact_id)
    config, details = _config(engine), engine_status(engine, fresh=True)
    if expected_pin is not None and expected_pin != {key: details.get(key) for key in ("version", "rule_digest", "config_digest")}:
        raise ConflictError("Automatic job engine/version/rules/config pin changed; rerun manually")
    run_id = "AE-RUN-" + uuid.uuid4().hex
    with principal.transaction(store, actor, EDITORS, write=engine == "cape") as (db, fresh):
        _recheck(store, db, fresh, artifact, originals, sha)
        if engine == "cape":
            approval = _approval(db, fresh, approval_id, artifact, engine)
            if details["available"]:
                consent = json.loads(approval["body"])
                if consent.get("used_run_id"):
                    raise ConflictError("This exact upload consent was already consumed; review its run or obtain a new approval")
                consent.update(used_run_id=run_id, used_at=time.time())
                db.execute("UPDATE analysis_engine_approvals SET body=? WHERE id=?", (encode(consent), approval_id))
                store.audit(db, fresh["tenant"], fresh["name"], "analysis_engine.upload_claimed", {"approval_id": approval_id, "run_id": run_id, "sha256": sha})
    key = _digest([sha, engine, details["version"], details["rule_digest"], _digest(config)])
    began, cache_hit = time.perf_counter(), False
    with principal.transaction(store, actor, EDITORS) as (db, _):
        row = db.execute("SELECT body FROM analysis_engine_cache WHERE tenant=? AND cache_key=?", (actor["tenant"], key)).fetchone()
        cached = json.loads(row[0]) if row and engine not in {"cape", "clamav"} else None
    if cached and details["available"]:
        answer, cache_hit = cached, True
    else:
        if not _gate.acquire(blocking=False):
            raise CapacityError("Another file analysis engine is busy; retry shortly")
        try:
            try:
                answer = _analyze(engine, config, details, body, sha, timeout=timeout, cancel=cancel)
            except socket.timeout:
                answer = {"status": "timeout", "verdict": "unknown", "summary": {}, "error": "Local service deadline exceeded"}
            except (OSError, ValueError, http.client.HTTPException) as exc:
                answer = {"status": "error", "verdict": "unknown", "summary": {}, "error": type(exc).__name__ + ": " + str(exc)[:256]}
        finally:
            _gate.release()
    if answer.get("status") not in {"completed", "pending", "unavailable", "timeout", "error"} or not isinstance(answer.get("summary"), dict):
        answer = {"status": "error", "summary": {}, "error": "Unsupported engine response schema", "verdict": "unknown"}
    # Capabilities/strings/emulated APIs are not malware verdicts.
    if answer["status"] != "completed" or engine != "clamav":
        answer["verdict"] = "unknown"
    result = {**answer, "id": "AE-RUN-" + uuid.uuid4().hex, "engine": engine, "artifact_id": artifact_id, "incident_id": artifact["incident_id"], "sha256": sha, "event_ids": sorted(originals), "engine_version": details["version"], "rule_digest": details["rule_digest"], "config_digest": _digest(config), "cache_key": key, "cache_hit": cache_hit, "created": time.time(), "duration_ms": round((time.perf_counter() - began) * 1000, 3), "signal_id": None, "approval_id": approval_id if engine == "cape" else None, "sample_executed": engine == "cape" and answer["status"] in {"pending", "completed"}, "sample_execution": details["sample_execution"], "native_sample_execution": False, "emit_signal_requested": emit_signal, "originals": [evidence.reference(r) for r in originals.values()]}
    result["id"] = run_id
    result["collection_command_digest"] = artifact["_command_digest"]
    result["wall_budget_seconds"] = timeout
    result["sample_executed"] = None if engine == "cape" else False
    result["content_notices"] = content_notices.bundle([content_notices.engine(engine, version=result["engine_version"], rule_digest=result["rule_digest"])])
    if engine == "capa":
        result["content_notices"] = content_notices.merge(result["content_notices"], content_notices.bundle([{
            "kind": "analysis_rule_pack", "engine": "capa", "rule_digest": result["rule_digest"],
            "license": "Apache-2.0" if config.get("release_manifest") else "unspecified",
            "source_url": "https://github.com/mandiant/capa-rules" if config.get("release_manifest") else "",
            "commit": "2af9fbfc1c9b4634dbeb76b5d34fca9389fa7f80" if config.get("release_manifest") else "",
            "license_file": "sapientia/catalogs/capa/LICENSE.txt" if config.get("release_manifest") else "",
            "matched_rule_authors": [{"rule": item.get("name"), "authors": item.get("authors", []), "references": item.get("references", [])} for item in result.get("summary", {}).get("capabilities", [])],
            "rights_basis": "bundled_upstream_manifest" if config.get("release_manifest") else "operator_supplied_rules_require_separate_license_review",
        }]))
    with store.segment_lock.read(deadline=time.monotonic() + 3), principal.transaction(store, actor, EDITORS, write=True) as (db, fresh):
        _recheck(store, db, fresh, artifact, originals, sha)
        if _digest(_config(engine)) != result["config_digest"]:
            raise ConflictError("Engine configuration changed during analysis")
        if engine == "cape":
            _approval(db, fresh, approval_id, artifact, engine, run_id=result["id"] if details["available"] else None)
        _publish(store, db, fresh, result, emit_signal)
        db.execute("INSERT INTO analysis_engine_runs VALUES(?,?,?,?,?,?,?,?)", (result["id"], fresh["tenant"], result["incident_id"], artifact_id, artifact["index_name"], fresh["name"], result["created"], encode(result)))
        if result["status"] == "completed" and engine not in {"cape", "clamav"} and not cache_hit:
            db.execute("INSERT OR REPLACE INTO analysis_engine_cache VALUES(?,?,?,?)", (fresh["tenant"], key, time.time(), encode(answer)))
            db.execute("DELETE FROM analysis_engine_cache WHERE tenant=? AND (created<? OR cache_key IN (SELECT cache_key FROM analysis_engine_cache WHERE tenant=? ORDER BY created DESC LIMIT -1 OFFSET 128))", (fresh["tenant"], time.time() - 7 * 86400, fresh["tenant"]))
        store.audit(db, fresh["tenant"], fresh["name"], "analysis_engine.scan", {"id": result["id"], "engine": engine, "artifact_id": artifact_id, "status": result["status"], "sha256": sha, "cache_hit": cache_hit})
    return result


def _publish(store, db, actor, result, emit):
    if not emit or result["status"] != "completed":
        return
    summary = result["summary"]
    count = summary.get("capability_count", summary.get("string_count", summary.get("api_calls", len(summary.get("detections", [])))))
    if not count:
        return
    from . import intelligence
    signal = intelligence.publish_in_transaction(store, db, actor, {"event_ids": result["event_ids"], "kind": "finding", "rule_id": "analysis-engine:" + result["engine"], "rule_revision": 1, "features": {"artifact_sha256": result["sha256"], "analysis_observation_count": count, "malware_signature_match": result["verdict"] == "suspicious"}, "severity": "high" if result["verdict"] == "suspicious" else "info", "confidence_grade": "local_engine_observation", "context_digest": _digest([result["sha256"], result["engine"], result["engine_version"], result["rule_digest"], result["config_digest"], actor["name"]]), "metadata": {"analysis_engine_run_id": result["id"], "artifact_id": result["artifact_id"], "engine": result["engine"], "dependency_group": "artifact:" + result["sha256"], "malware_probability_calibrated": False, "sample_execution": result["sample_execution"], "content_notices": result.get("content_notices", content_notices.bundle())}})
    result["signal_id"] = signal["id"]


def get_run(store, who, identifier):
    with principal.transaction(store, who) as (db, actor):
        row = db.execute("SELECT * FROM analysis_engine_runs WHERE tenant=? AND id=?", (actor["tenant"], identifier)).fetchone()
        if not row or not principal.contains(actor["allowed_indexes"], [row["index_name"]]):
            raise KeyError("Analysis run not found")
        principal.incident(db, actor, row["incident_id"])
        return json.loads(row["body"])


def list_runs(store, who, *, incident_id=None):
    with principal.transaction(store, who) as (db, actor):
        if incident_id:
            principal.incident(db, actor, incident_id)
        items = []
        for row in db.execute("SELECT * FROM analysis_engine_runs WHERE tenant=? ORDER BY created DESC LIMIT 500", (actor["tenant"],)):
            if (incident_id and row["incident_id"] != incident_id) or not principal.contains(actor["allowed_indexes"], [row["index_name"]]):
                continue
            try:
                principal.incident(db, actor, row["incident_id"])
            except (KeyError, PermissionError):
                continue
            items.append(json.loads(row["body"]))
            if len(items) == 100:
                break
        return {"items": items, "total": len(items), "limit": 100}


def poll_run(store, who, identifier):
    saved = get_run(store, who, identifier)
    if saved["engine"] != "cape" or saved["status"] != "pending":
        raise ConflictError("Only a pending CAPE task can be polled")
    actor, artifact, _, sha, originals = _artifact(store, who, saved["artifact_id"])
    config = _config("cape")
    with principal.transaction(store, actor, EDITORS) as (db, fresh):
        _recheck(store, db, fresh, artifact, originals, sha)
        _approval(db, fresh, saved["approval_id"], artifact, "cape", run_id=saved["id"])
    task = saved["summary"]["task_id"]
    response = _cape_http(config, "GET", "/apiv2/tasks/view/" + str(task) + "/")
    state = _cape_object(response.get("data"), "task data").get("status")
    if state not in {"reported", "completed"}:
        if state in {"failed_analysis", "failed_processing", "failed_reporting", "recovered"}:
            saved.update(status="error", error="Local sandbox task failed", summary={"task_id": task})
        else:
            return {**saved, "provider_state": str(state)[:64]}
    else:
        report = _cape_http(config, "GET", "/apiv2/tasks/get/report/" + str(task) + "/json/")
        report = _cape_object(report.get("data", report), "report")
        target = _cape_object(report.get("target"), "report target")
        file = _cape_object(target.get("file"), "report target file")
        info = _cape_object(report.get("info"), "report info")
        if file.get("sha256") != sha or info.get("id") != task:
            raise ConflictError("Sandbox report file/task identity does not match this exact upload")
        signatures = report.get("signatures", [])
        if not isinstance(signatures, list) or len(signatures) > 10000 or any(not isinstance(item, dict) for item in signatures):
            raise ValueError("Unsupported CAPE signatures schema")
        detections = [{"name": str(item.get("name", ""))[:256], "description": str(item.get("description", ""))[:1024]} for item in signatures[:128] if isinstance(item, dict)]
        saved.update(status="completed", verdict="unknown", sample_executed=True, summary={"task_id": task, "detections": detections, "signature_count": len(signatures), "truncated": len(signatures) > 128, "meaning": "Local sandbox behavior observations; not calibrated malware proof"}, report_digest=_digest(report))
    with store.segment_lock.read(deadline=time.monotonic() + 3), principal.transaction(store, actor, EDITORS, write=True) as (db, fresh):
        _recheck(store, db, fresh, artifact, originals, sha)
        _approval(db, fresh, saved["approval_id"], artifact, "cape", run_id=saved["id"])
        current = db.execute("SELECT body FROM analysis_engine_runs WHERE tenant=? AND id=?", (fresh["tenant"], identifier)).fetchone()
        if not current or json.loads(current[0])["status"] != "pending":
            raise ConflictError("Sandbox run was already finalized")
        _publish(store, db, fresh, saved, saved["emit_signal_requested"])
        db.execute("UPDATE analysis_engine_runs SET body=? WHERE tenant=? AND id=?", (encode(saved), fresh["tenant"], identifier))
        store.audit(db, fresh["tenant"], fresh["name"], "analysis_engine.cape_result", {"id": identifier, "status": saved["status"], "sha256": sha})
    return saved


def validate_parent(store, db, actor, body, memo=None):
    """A capability is eligible evidence only while its exact file/run survives."""
    try:
        if not isinstance(body, dict) or not isinstance(body.get("metadata"), dict):
            return False
        actor = principal.current(db, actor, EDITORS)
        meta = body["metadata"]
        row = db.execute("SELECT * FROM analysis_engine_runs WHERE tenant=? AND id=?", (actor["tenant"], meta.get("analysis_engine_run_id"))).fetchone()
        stored = db.execute("SELECT body FROM intelligence_signals WHERE tenant=? AND id=?", (actor["tenant"], body["id"])).fetchone()
        if not row or not stored or {k: v for k, v in json.loads(stored[0]).items() if k != "story_id"} != {k: v for k, v in body.items() if k != "story_id"}:
            return False
        run = json.loads(row["body"])
        if run["status"] != "completed" or run["signal_id"] != body["id"] or run["event_ids"] != body["event_ids"] or body["rule_id"] != "analysis-engine:" + run["engine"] or body.get("mode") != "live" or meta.get("artifact_id") != row["artifact_id"] or _digest(_config(run["engine"])) != run["config_digest"]:
            return False
        author = principal.current(db, {"name": row["actor"], "tenant": actor["tenant"], "role": "analyst"}, EDITORS)
        if not principal.contains(author["allowed_indexes"], [row["index_name"]]) or not principal.contains(actor["allowed_indexes"], [row["index_name"]]):
            return False
        principal.incident(db, author, row["incident_id"])
        artifact = db.execute("SELECT * FROM endpoint_artifacts WHERE tenant=? AND id=?", (actor["tenant"], row["artifact_id"])).fetchone()
        if not artifact or artifact["incident_id"] != row["incident_id"] or artifact["index_name"] != row["index_name"]:
            return False
        _recheck(store, db, actor, {**dict(artifact), "_command_digest": run["collection_command_digest"]}, {item["event_id"]: item for item in run["originals"]}, run["sha256"])
        if run["engine"] == "cape":
            _approval(db, actor, run["approval_id"], artifact, "cape", run_id=run["id"])
        return body.get("context_digest") == _digest([run["sha256"], run["engine"], run["engine_version"], run["rule_digest"], run["config_digest"], row["actor"]])
    except (KeyError, ValueError, TypeError, AttributeError, OSError, PermissionError, ConflictError):
        return False


def run_due(store, cancel=None):
    """Discover only expressly collected process images; one bounded job per turn.

    New resources never silently retry a failed run. The automatic job freezes
    the engine, resource and configuration digest; manual rerun is explicit.
    """
    if cancel is not None and cancel.is_set():
        return 0
    configured = os.environ.get("XSERA_ANALYSIS_AUTO_ENGINES", "capa,floss")
    selected = [name for name in configured.split(",") if name in {"capa", "floss"}]
    if not selected:
        return 0
    with store.control() as db:
        rows = db.execute("SELECT a.id,a.tenant,r.requester FROM endpoint_artifacts a JOIN endpoint_responses r ON r.id=a.command_id WHERE a.state='complete' AND r.state='completed' AND json_extract(r.action,'$.source')='process_executable' AND EXISTS(SELECT 1 FROM json_each(?) n WHERE NOT EXISTS(SELECT 1 FROM analysis_engine_auto_jobs j WHERE j.artifact_id=a.id AND j.engine=n.value)) ORDER BY a.updated LIMIT 8", (encode(selected),)).fetchall()
    probes = {name: engine_status(name) for name in selected} if rows else {}
    with store.write_lock, store.control(local=True) as db:
        # A crash leaves no trusted successful result. Do not blindly retry
        # engine execution whose resource pin is now unknown.
        db.execute("UPDATE analysis_engine_auto_jobs SET state='error',error='Worker interrupted; explicit manual rerun required',updated=? WHERE state='running' AND updated<?", (time.time(), time.time() - WALL_SECONDS - 30))
        for row in rows:
            for name in selected:
                details = probes[name]
                pin = {key: details.get(key) for key in ("version", "rule_digest", "config_digest")}
                db.execute("INSERT OR IGNORE INTO analysis_engine_auto_jobs VALUES(?,?,?,?,?,?,NULL,?,?)", (row["id"], name, row["tenant"], row["requester"], "pending" if details["available"] else "unavailable", time.time(), None if details["available"] else details["reason"], encode(pin)))
        job = db.execute("SELECT * FROM analysis_engine_auto_jobs WHERE state='pending' ORDER BY updated LIMIT 1").fetchone()
        if not job:
            return 0
        db.execute("UPDATE analysis_engine_auto_jobs SET state='running',updated=? WHERE artifact_id=? AND engine=?", (time.time(), job["artifact_id"], job["engine"]))
    try:
        result = scan_artifact(store, {"name": job["actor"], "tenant": job["tenant"], "role": "analyst"}, job["artifact_id"], job["engine"], expected_pin=json.loads(job["pin"]), timeout=20, cancel=cancel)
        state, identifier = result["status"], result["id"]
        error = result.get("error")
    except CapacityError as exc:
        state, identifier, error = "pending", None, str(exc)[:512]
    except (KeyError, PermissionError, ValueError, OSError, ConflictError) as exc:
        state, identifier, error = "excluded", None, str(exc)[:512]
    with store.write_lock, store.control(local=True) as db:
        db.execute("UPDATE analysis_engine_auto_jobs SET state=?,updated=?,result_id=?,error=? WHERE artifact_id=? AND engine=?", (state, time.time(), identifier, error, job["artifact_id"], job["engine"]))
    return int(state == "completed")
