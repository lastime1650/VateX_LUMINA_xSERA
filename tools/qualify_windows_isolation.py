"""Real Windows firewall proof with a separately approved finite profile window.

Default preparation downloads/enrolls a unique agent and enables only its typed
local response policy; it never changes firewall profiles or rules. Execution
requires --allow-profile-test and a separately provisioned owned Ubuntu nonce
probe. All global profile restoration is owned by an independent, handshaked,
private-plan guard before the explicit temporary enable. Production isolation
continues to reject disabled profiles.
"""
# ruff: noqa: BLE001 -- Retain native failures and attempt exact owned rollback.

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import traceback
import uuid
import zipfile
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sapientia.endpoint_agent.Agent import cli, response

STAGE = Path(__file__).resolve().parents[1]
WORK = STAGE.parent
PEERS = (
    ("104.18.32.47", 443),
    ("172.64.155.209", 443),
    ("18.64.5.206", 443),
    ("54.238.74.142", 9443),
)
CONTROLLERS = {21500: "codex.exe", 20012: "python.exe"}
REQUIRED = {
    "Agent/core.py",
    "Agent/response.py",
    "Agent/operations.py",
    "Agent/firewall_guard.py",
    "Agent/cli.py",
    "Agent/Windows/isolation_watchdog.py",
    "Agent/Windows/collector.py",
}
LOCAL_HARNESS = "Agent/Windows/firewall_profile_test_guard.py"


def observed_controller_peers():
    """Observe only reviewed management processes, requiring every peer covered."""
    if os.name != "nt":
        raise PermissionError("Controller peer observation requires native Windows")
    script = (
        "@(Get-NetTCPConnection -State Established -ErrorAction Stop | "
        "Select-Object RemoteAddress,RemotePort,OwningProcess) | "
        "ConvertTo-Json -Compress -Depth 2"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode or len(result.stdout) > 1024 * 1024:
        raise RuntimeError("Bounded native controller socket observation failed")
    rows = json.loads(result.stdout)
    if not isinstance(rows, list) or len(rows) > 10000:
        raise RuntimeError("Native controller socket table is not bounded rows")
    selected = {}
    identities = []
    for pid, executable in CONTROLLERS.items():
        identity = response.inspect_process(pid, "qa-controller")
        if Path(identity["executable"]).name.casefold() != executable:
            raise PermissionError("Reviewed management process identity changed")
        identities.append(identity)
        active = [
            row
            for row in rows
            if isinstance(row, dict)
            and type(row.get("OwningProcess")) is int
            and row["OwningProcess"] == pid
            and type(row.get("RemotePort")) is int
            and row["RemotePort"] in (443, 9443)
            and isinstance(row.get("RemoteAddress"), str)
            and row["RemoteAddress"] not in ("127.0.0.1", "::1")
        ]
        if not active:
            raise PermissionError(
                "Reviewed management process has no established critical peer"
            )
        for row in active:
            peer = (row["RemoteAddress"], row["RemotePort"])
            if peer not in PEERS:
                raise PermissionError(
                    "Current critical controller peer is outside reviewed set: "
                    + peer[0]
                    + ":"
                    + str(peer[1])
                )
            selected.setdefault(peer, set()).add(pid)
    return {
        "observed_at": time.time(),
        "state": "Established",
        "peers": [
            {"address": peer[0], "port": peer[1], "process_ids": sorted(pids)}
            for peer, pids in sorted(selected.items())
        ],
        "management_process_identities": identities,
        "all_current_critical_peers_covered": True,
        "alternate_cdn_peers_need_not_both_be_established": True,
    }


def owned_root(path):
    path = Path(path)
    response._no_links(path)
    path = path.resolve(strict=True)
    if (
        path.parent != WORK.resolve(strict=True)
        or not re.fullmatch(r"native-windows-isolation-[0-9a-f]{32}", path.name)
        or (path / ".qa-synthetic-only").read_text(encoding="utf-8")
        != "synthetic-only\n"
    ):
        raise PermissionError(
            "Exact uniquely owned synthetic Windows isolation root required"
        )
    cli._protected(path, secret=True)
    return path


def source_package(blob, root):
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        names = archive.namelist()
        manifest = json.loads(archive.read("manifest.json"))
        if (
            len(names) != len(set(names))
            or len(names) > 100
            or not REQUIRED <= set(names)
            or set(names) != set(manifest["files"]) | {"manifest.json"}
        ):
            raise PermissionError("Downloaded package source/member contract differs")
        for item in archive.infolist():
            name = Path(item.filename)
            if (
                item.is_dir()
                or name.is_absolute()
                or ".." in name.parts
                or item.file_size > 1024 * 1024
                or (item.external_attr >> 16) & 0o170000 == 0o120000
            ):
                raise PermissionError("Unsafe downloaded source member")
            body = archive.read(item)
            if (
                item.filename != "manifest.json"
                and hashlib.sha256(body).hexdigest() != manifest["files"][item.filename]
            ):
                raise PermissionError("Downloaded source checksum mismatch")
            source = STAGE / "sapientia/endpoint_agent" / item.filename
            if item.filename.startswith("Agent/") and body != source.read_bytes():
                raise PermissionError(
                    "Downloaded agent does not contain current reviewed code"
                )
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
        return {name: manifest["files"][name] for name in sorted(REQUIRED)}


def load_downloaded(root):
    name = "qa_windows_isolation_" + uuid.uuid4().hex
    spec = importlib.util.spec_from_file_location(
        name,
        root / "Agent/__init__.py",
        submodule_search_locations=[str(root / "Agent")],
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return tuple(
        __import__(name + suffix, fromlist=["*"])
        for suffix in (
            ".core",
            ".response",
            ".operations",
            ".firewall_guard",
            ".Windows.collector",
            ".Windows.firewall_profile_test_guard",
        )
    )


def checked_cli(root):
    args = [
        sys.executable,
        "-I",
        "-B",
        str(root / "Agent/Windows/main.py"),
        "response-policy",
        "--config",
        str(root / "config.json"),
        "--enable-response",
        "--allow-host-isolation",
        "--isolation-max-seconds",
        "30",
        "--confirm-response-policy",
    ]
    for address, port in (*PEERS, ("127.0.0.1", 18788)):
        args.extend(["--management-endpoint", "outbound," + address + "," + str(port)])
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=25,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        (root / "response-policy-failure.txt").write_text(
            result.stderr, encoding="utf-8"
        )
        raise RuntimeError("Downloaded stopped-agent typed response-policy CLI failed")
    return json.loads((root / "config.json").read_text(encoding="utf-8"))


NONCE_PEER = ("192.0.2.41", 20200)
NONCE_PROTOCOL = "xsera.nonce.v2"


class NonceSession:
    """One owned TCP incarnation; blocked exchanges never reconnect or retry."""

    def __init__(self, nonce):
        if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce):
            raise ValueError("Fixed owned probe requires exact bounded nonce")
        self.nonce, self.channel, self.attempts = nonce, None, []
        self.failed = False
        self.channel = socket.create_connection(NONCE_PEER, timeout=1)
        try:
            if self.channel.getpeername() != NONCE_PEER:
                raise PermissionError("Owned nonce socket peer changed")
            self.local_tuple = self.channel.getsockname()
            self.socket_fileno = self.channel.fileno()
        except Exception:
            self.close()
            raise

    def exchange(self):
        if self.channel is None or self.failed or len(self.attempts) >= 128:
            raise RuntimeError("Owned nonce socket cannot be reused or reconnected")
        sequence = uuid.uuid4().hex
        message = (self.nonce + ":" + sequence + "\n").encode("ascii")
        observation = {"sequence": sequence, "allowed": False}
        self.attempts.append(observation)
        deadline = time.monotonic() + 1
        received = bytearray()
        try:
            self.channel.settimeout(max(0.001, deadline - time.monotonic()))
            self.channel.sendall(message)
            while b"\n" not in received:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Owned same-socket exchange deadline ended")
                self.channel.settimeout(remaining)
                part = self.channel.recv(129 - len(received))
                if not part:
                    self.failed = True
                    observation["unresponsive_reason"] = "peer_closed"
                    return False
                received.extend(part)
                if len(received) > 128:
                    self.failed = True
                    raise RuntimeError("Owned nonce peer returned an oversized frame")
            if bytes(received) != message:
                self.failed = True
                raise RuntimeError(
                    "Owned nonce peer returned a stale or invalid sequence"
                )
            observation["allowed"] = True
            return True
        except OSError as error:
            self.failed = True
            observation["unresponsive_reason"] = type(error).__name__
            return False

    def evidence(self):
        return {
            "protocol": NONCE_PROTOCOL,
            "peer": list(NONCE_PEER),
            "local_tuple": list(self.local_tuple),
            "socket_fileno": self.socket_fileno,
            "same_socket_no_reconnect": True,
            "attempts": list(self.attempts),
        }

    def close(self):
        if self.channel is not None:
            self.channel.close()
            self.channel = None


def nonce_probe(nonce):
    """A distinct fresh connection; invalid peer replies are test failures."""
    session = None
    try:
        session = NonceSession(nonce)
        return session.exchange()
    except OSError:
        return False
    finally:
        if session is not None:
            session.close()


def validate_nonce_peer(probe):
    """Use the private controller's conservative local TTL, not remote time."""
    now = time.time()
    if (
        not isinstance(probe, dict)
        or probe.get("bind_ip") != NONCE_PEER[0]
        or probe.get("port") != NONCE_PEER[1]
        or probe.get("accepted_peer") != "192.0.2.42"
        or probe.get("protocol") != NONCE_PROTOCOL
        or probe.get("maximum_lifetime_seconds") != 180
        or type(probe.get("created")) not in (int, float)
        or type(probe.get("expires")) not in (int, float)
        or not probe["created"] <= now < probe["expires"] <= probe["created"] + 180
        or probe["expires"] - now < 115
        or not isinstance(probe.get("nonce"), str)
        or not re.fullmatch(r"[0-9a-f]{32}", probe["nonce"])
    ):
        raise PermissionError(
            "Owned v2 nonce peer and sufficient finite local TTL required"
        )
    return probe["nonce"]


def worker(root):
    root = owned_root(root)
    runtime, native_response, _ops, _firewall, _collector, _profile_guard = (
        load_downloaded(root)
    )
    config = json.loads((root / "config.json").read_text(encoding="utf-8"))
    if config["endpoint_url"] != "https://127.0.0.1:18788":
        raise PermissionError(
            "Worker can access only the dedicated local TLS QA listener"
        )
    agent = runtime.Agent(config, None)
    until, heartbeat_at, poll_at = time.monotonic() + 180, 0.0, 0.0
    try:
        with runtime.RunLock(agent.directory):
            (root / "worker-ready.json").write_text(
                json.dumps(
                    native_response.inspect_process(os.getpid(), config["host"])
                ),
                encoding="utf-8",
            )
            while time.monotonic() < until and not (root / "worker-stop.json").exists():
                if (root / "worker-pause.json").exists():
                    agent.stop.set()
                    (root / "worker-paused.json").write_text(
                        json.dumps(
                            {
                                "polling_stopped": True,
                                "pid": os.getpid(),
                                "at": time.time(),
                            }
                        ),
                        encoding="utf-8",
                    )
                    time.sleep(0.1)
                    continue
                heartbeat_at, poll_at = agent._control_cycle(heartbeat_at, poll_at)
                time.sleep(0.2)
    finally:
        agent.stop.set()
        agent.queue.close()
        if agent.defense:
            agent.defense.close()
    return 0


class Trial:
    def __init__(self, fixture, output, root=None):
        import httpx

        from tools.qualify_security_flow import private_directory

        fixture = fixture.resolve(strict=True)
        response._no_links(fixture)
        if (
            fixture.parent != (WORK / "native-linux-0.10").resolve(strict=True)
            or (fixture.parent / ".qa-synthetic-only").read_text().strip()
            != "synthetic-only"
        ):
            raise PermissionError(
                "Only the existing exact marked native QA fixture is accepted"
            )
        cli._protected(fixture, secret=True)
        self.fixture_path, self.fixture = (
            fixture,
            json.loads(fixture.read_text(encoding="utf-8-sig")),
        )
        if (
            self.fixture["endpoint_url"] != "https://127.0.0.1:18788"
            or self.fixture["console_url"] != "http://127.0.0.1:18787"
        ):
            raise PermissionError("Only dedicated local QA ports are accepted")
        (
            self.output,
            self.checks,
            self.responses,
            self.guard_process,
            self.worker_process,
        ) = output, [], [], None, None
        self.established_nonce_session = None
        self.root = (
            owned_root(root)
            if root
            else WORK / ("native-windows-isolation-" + uuid.uuid4().hex)
        )
        if root is None:
            private_directory(self.root)
            (self.root / ".qa-synthetic-only").write_text(
                "synthetic-only\n", encoding="utf-8"
            )
        self.client = httpx.Client(
            base_url=self.fixture["endpoint_url"],
            verify=ssl.create_default_context(cafile=self.fixture["ca_file"]),
            trust_env=False,
            timeout=10,
            headers={"Origin": self.fixture["endpoint_url"]},
        )
        person = self.fixture["admin"]
        authenticated = self.client.post(
            "/api/login",
            json={"name": person["username"], "password": person["password"]},
        )
        if authenticated.status_code != 200:
            raise RuntimeError("Private QA account could not authenticate")
        self.client.headers["X-CSRF-Token"] = authenticated.json()["csrf"]
        if root:
            prepared = json.loads((self.root / "prepared.json").read_text())
            if (
                prepared["qualification_helper_sha256"]
                != hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            ):
                raise PermissionError("Prepared native qualification helper changed")
            self.host, self.case_id, self.source_sha256 = (
                prepared["host"],
                prepared["case_id"],
                prepared["source_sha256"],
            )
            for name, digest in self.source_sha256.items():
                path = self.root / name
                if (
                    hashlib.sha256(path.read_bytes()).hexdigest() != digest
                    or path.read_bytes()
                    != (STAGE / "sapientia/endpoint_agent" / name).read_bytes()
                ):
                    raise PermissionError(
                        "Prepared downloaded source is no longer current reviewed code"
                    )
            self.guard_source_sha256 = prepared["local_test_guard_sha256"]
            guard_source = self.root / LOCAL_HARNESS
            if (
                hashlib.sha256(guard_source.read_bytes()).hexdigest()
                != self.guard_source_sha256
                or guard_source.read_bytes()
                != (STAGE / "sapientia/endpoint_agent" / LOCAL_HARNESS).read_bytes()
            ):
                raise PermissionError("Private local test-harness guard source changed")
            self.modules = load_downloaded(self.root)
            self.config = json.loads((self.root / "config.json").read_text())
            self.identity = json.loads(
                (Path(self.config["state_dir"]) / "identity.json").read_text()
            )

    def api(self, method, path, *, expected=200, binary=False, **kwargs):
        result = self.client.request(method, path, **kwargs)
        if result.status_code != expected:
            raise RuntimeError(
                f"Dedicated QA {method} {path}: HTTP {result.status_code}, expected {expected}"
            )
        return result if binary else result.json()

    def record(self, name, **detail):
        self.checks.append({"name": name, "passed": True, **detail})
        print(json.dumps({"check": name, "passed": True}), flush=True)

    def wait(self, callback, predicate, seconds=20):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            value = callback()
            if predicate(value):
                return value
            time.sleep(0.1)
        raise TimeoutError("Native bounded qualification wait expired")

    def prepare(self):
        self.controller_observation = observed_controller_peers()
        self.record(
            "current_critical_controller_peers_covered_before_preparation",
            **self.controller_observation,
        )
        self.host = "QA-WINDOWS-ISOLATION-" + self.root.name[-12:]
        deployment = self.api(
            "POST",
            "/api/xdr/agents/deployments",
            expected=201,
            json={
                "platform": "windows",
                "host": self.host,
                "index": "endpoint_windows_isolation",
                "ttl_seconds": 600,
            },
        )
        package = self.api("POST", deployment["package_url"], binary=True, json={})
        if (
            hashlib.sha256(package.content).hexdigest()
            != package.headers["X-Package-SHA256"]
        ):
            raise PermissionError(
                "Authenticated package digest header differs from body"
            )
        self.source_sha256 = source_package(package.content, self.root)
        # This reviewed QA helper is deliberately not part of the downloadable
        # product agent ZIP. Adding its inert private test module leaves every
        # authenticated downloaded product source byte unchanged.
        guard_source = (STAGE / "sapientia/endpoint_agent" / LOCAL_HARNESS).read_bytes()
        (self.root / LOCAL_HARNESS).write_bytes(guard_source)
        self.guard_source_sha256 = hashlib.sha256(guard_source).hexdigest()
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(self.root / "configure.py"),
                "--directory",
                str(self.root),
                "--deployment",
                str(self.root / "deployment.json"),
                "--token-file",
                str(self.root / "enrollment.token"),
                "--ca-file",
                str(self.root / "ca.pem"),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=25,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode:
            (self.root / "configuration-failure.txt").write_text(
                result.stderr, encoding="utf-8"
            )
            raise RuntimeError("Downloaded TLS enrollment configure CLI failed")
        (self.root / "enrollment.token").unlink()
        self.config = checked_cli(self.root)
        self.identity = json.loads(
            (Path(self.config["state_dir"]) / "identity.json").read_text()
        )
        self.modules = load_downloaded(self.root)
        runtime, _response, _ops, _fw, collector_module, _profile_guard = self.modules
        sensor = collector_module.WindowsCollector(emit_initial=True, event_log=False)
        records = [
            row
            for row in sensor._process_events(self.host)
            if row["data"].get("process", {}).get("pid") == os.getpid()
        ]
        if len(records) != 1:
            raise AssertionError(
                "Actual native Toolhelp collector did not identify this exact qualification PID"
            )
        agent = runtime.Agent(self.config, None)
        try:
            agent.queue.add(records[0])
            if agent.flush() != 1:
                raise AssertionError(
                    "Actual enrolled agent's durable native source delivery failed"
                )
            agent.heartbeat()
        finally:
            agent.queue.close()
            if agent.defense:
                agent.defense.close()
        policy = self.api(
            "POST",
            "/api/detections",
            expected=201,
            json={
                "name": "Native Windows isolation evidence " + self.host,
                "entity_field": "host",
                "window": 300,
                "risk_score": 80,
                "severity": "high",
                "steps": [
                    {"filters": [{"field": "host", "op": "eq", "value": self.host}]}
                ],
            },
        )
        cases = self.wait(
            lambda: self.api("GET", "/api/incidents"),
            lambda value: any(row["entity"] == self.host for row in value),
        )
        case = next(row for row in cases if row["entity"] == self.host)
        self.case_id = case["id"]
        self.api(
            "PATCH",
            "/api/detections/" + policy["id"],
            json={"enabled": False, "version": 1},
        )
        context = self.api("GET", "/api/incidents/" + self.case_id + "/agent-response")
        if not any(
            row["response_eligible"]
            and row["verified_agent_id"] == self.identity["agent_id"]
            for row in context["events"]
        ):
            raise AssertionError(
                "Native enrolled source was not eligible for this exact agent/case"
            )
        (self.root / "prepared.json").write_text(
            json.dumps(
                {
                    "host": self.host,
                    "case_id": self.case_id,
                    "agent_id": self.identity["agent_id"],
                    "source_sha256": self.source_sha256,
                    "local_test_guard_sha256": self.guard_source_sha256,
                    "qualification_helper_sha256": hashlib.sha256(
                        Path(__file__).read_bytes()
                    ).hexdigest(),
                    "controller_observation": self.controller_observation,
                    "prepared": time.time(),
                    "firewall_changed": False,
                }
            ),
            encoding="utf-8",
        )
        self.record(
            "native_downloaded_windows_tls_enrollment_typed_cli_toolhelp_source_case",
            agent_id=self.identity["agent_id"],
            case_id=self.case_id,
            firewall_changed=False,
        )

    def start_worker(self):
        self.worker_process = subprocess.Popen(
            [
                getattr(sys, "_base_executable", sys.executable),
                "-I",
                "-B",
                str(Path(__file__).resolve()),
                "--worker",
                "--prepared-root",
                str(self.root),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=(self.root / "worker-errors.txt").open("w", encoding="utf-8"),
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        self.wait(lambda: (self.root / "worker-ready.json").exists(), bool, 10)
        self.worker_identity = json.loads((self.root / "worker-ready.json").read_text())
        if self.worker_identity["pid"] != self.worker_process.pid:
            raise PermissionError("Native worker readiness PID differs")

    def command(self, action):
        begin = time.monotonic()
        context = self.api("GET", "/api/incidents/" + self.case_id + "/agent-response")
        source = next(
            row
            for row in context["events"]
            if row["response_eligible"]
            and row["verified_agent_id"] == self.identity["agent_id"]
        )
        queued = self.api(
            "POST",
            "/api/incidents/" + self.case_id + "/agent-response",
            expected=201,
            json={
                "agent_id": self.identity["agent_id"],
                "evidence_event_id": source["event_id"],
                "case_version": context["case_version"],
                "request_id": "native-windows-fw-" + uuid.uuid4().hex,
                "reason": "User-authorized finite Windows QA network proof, independent exact profile rollback prearmed",
                "action": action,
            },
        )
        completed = self.wait(
            lambda: self.api("GET", "/api/agent-responses/" + queued["id"]),
            lambda row: row["state"] in {"succeeded", "failed", "unknown"},
            30,
        )
        self.responses.append(completed)
        completed["qualification_roundtrip_seconds"] = round(
            time.monotonic() - begin, 4
        )
        if (
            completed.get("started") is not None
            and completed.get("finished") is not None
        ):
            completed["server_execution_seconds"] = round(
                completed["finished"] - completed["started"], 4
            )
        if (
            completed["state"] != "succeeded"
            or completed["result"].get("success") is not True
            or completed["result"].get("executed") is not True
        ):
            raise AssertionError(
                "Actual signed typed agent network action was not confirmed"
            )
        return completed

    def native_state(self):
        return self.modules[2].isolation_status(self.config["response"])

    def heartbeat(self):
        runtime = self.modules[0]
        value = runtime.Transport(
            self.config["endpoint_url"], self.config["ca_file"]
        ).post(
            "/api/agent/heartbeat",
            {"health": {"status": "ok", "qualification": "native_windows_isolation"}},
            self.identity["credential"],
        )
        return isinstance(value, dict)

    def run_window(self, probe_file):
        self.controller_observation = observed_controller_peers()
        self.record(
            "current_critical_controller_peers_covered_before_firewall_window",
            **self.controller_observation,
        )
        response._no_links(probe_file)
        cli._protected(probe_file, secret=True)
        probe = json.loads(probe_file.read_text(encoding="utf-8-sig"))
        nonce = validate_nonce_peer(probe)
        if not nonce_probe(nonce) or not self.heartbeat():
            raise AssertionError(
                "Actual fixed nonce and authenticated TLS management baselines failed"
            )
        established = self.established_nonce_session = NonceSession(nonce)
        if not established.exchange():
            raise AssertionError("Owned established nonce baseline did not exchange")
        self.start_worker()
        guard = self.modules[5]
        original = guard.profiles()
        definition, digest = self.modules[2].network_definition(self.config["response"])
        native_parent = self.modules[1].inspect_process(
            os.getpid(), "qa-profile-parent"
        )
        self.plan = {
            "schema": "xsera.qa-firewall-profile-plan.v1",
            "plan_id": uuid.uuid4().hex,
            "root": str(self.root),
            "state_dir": self.config["response"]["quarantine_dir"],
            "original_profiles": original,
            "management_definition": definition,
            "management_digest": digest,
            "created": time.time(),
            "active_seconds": 100,
            "parent_pid": os.getpid(),
            "parent_start_identity": native_parent["start_identity"],
            "guard_sha256": hashlib.sha256(
                (
                    self.root / "Agent/Windows/firewall_profile_test_guard.py"
                ).read_bytes()
            ).hexdigest(),
        }
        plan_path = self.root / guard.PLAN_NAME
        plan_path.write_text(json.dumps(self.plan), encoding="utf-8")
        self.guard_process = guard.arm(plan_path)
        self.window_deadline = time.monotonic() + 100
        self.record(
            "independent_exact_profile_guard_handshake_before_any_profile_enable",
            original_profiles=original,
            max_guard_seconds=120,
            guard_pid=self.guard_process.pid,
        )
        self.controller_observation = observed_controller_peers()
        self.record(
            "current_critical_controller_peers_rechecked_immediately_before_profile_enable",
            **self.controller_observation,
        )
        if probe["expires"] - time.time() < 105:
            raise TimeoutError(
                "Owned nonce peer lacks lifetime for the finite profile window"
            )
        guard.set_profiles({"1": True, "2": True, "4": True})
        if not nonce_probe(nonce) or not established.exchange():
            raise AssertionError(
                "Temporary profile enable changed a fresh or established nonce baseline; no isolation proof can proceed"
            )
        first = self.command(
            {"type": "isolate_host", "management_allowlist_digest": digest}
        )
        identifier = first["result"]["data"]["isolation_id"]
        isolated = self.native_state()
        owned_rule_count = len(self.modules[3]._windows_owned(identifier))
        established_allowed = established.exchange()
        if (
            established_allowed
            or nonce_probe(nonce)
            or not self.heartbeat()
            or not any(
                row["isolation_id"] == identifier and row["guard_alive"]
                for row in isolated["active"]
            )
        ):
            raise AssertionError(
                "Actual Windows owned rules did not deny established and fresh nonce traffic while preserving authenticated TLS and independent rollback"
            )
        self.record(
            "preexisting_nonmanagement_tcp_session_suppressed_after_native_isolation",
            isolation_id=identifier,
            baseline_before_profile_enable=True,
            baseline_after_profile_enable=True,
            same_socket_exchange_during_isolation=False,
            **established.evidence(),
        )
        established.close()
        self.command(
            {
                "type": "release_host",
                "management_allowlist_digest": digest,
                "isolation_id": identifier,
            }
        )
        if not nonce_probe(nonce) or self.native_state()["active"]:
            raise AssertionError("Exact owned release did not restore nonce traffic")
        self.record(
            "native_signed_case_queue_isolate_nonce_denied_tls_alive_manual_release_restored",
            isolation_id=identifier,
            before_nonce_allowed=True,
            isolated_nonce_denied=True,
            established_nonce_denied=True,
            authenticated_tls_during_isolation=True,
            after_nonce_allowed=True,
            owned_rule_count=owned_rule_count,
            isolate_roundtrip_seconds=first["qualification_roundtrip_seconds"],
        )
        if self.window_deadline - time.monotonic() < 48:
            raise TimeoutError(
                "Independent profile window lacks reserve for a distinct 30-second lease proof"
            )
        second = self.command(
            {"type": "isolate_host", "management_allowlist_digest": digest}
        )
        identifier = second["result"]["data"]["isolation_id"]
        if nonce_probe(nonce):
            raise AssertionError(
                "Second native isolation did not deny the fresh nonce connection"
            )
        (self.root / "worker-pause.json").write_text('{"pause":true}', encoding="utf-8")
        paused = self.wait(lambda: (self.root / "worker-paused.json").exists(), bool, 5)
        if not paused or self.worker_process.poll() is not None:
            raise AssertionError(
                "Agent polling did not stop with the hosting incarnation still alive"
            )

        def lease_restoration():
            state = self.native_state()
            return {
                "state": state,
                # Group disable can restore traffic before the last owned rule
                # is removed. Probe once cleanup is durably confirmed so the
                # bounded peer is not exhausted by fresh connections in flight.
                "nonce": nonce_probe(nonce) if not state["active"] else False,
                "profiles": guard.profiles(),
                "worker_alive": self.worker_process.poll() is None,
            }

        restored = self.wait(
            lease_restoration,
            lambda value: value["nonce"] and not value["state"]["active"],
            38,
        )
        if (
            restored["profiles"] != {"1": True, "2": True, "4": True}
            or not restored["worker_alive"]
            or self.guard_process.poll() is not None
        ):
            raise AssertionError(
                "Traffic restoration was not attributable to the separate product lease watchdog"
            )
        self.modules[3].verify_removed_windows(identifier)
        self.record(
            "actual_product_lease_watchdog_removed_owned_rules_with_agent_polling_stopped",
            isolation_id=identifier,
            agent_polling_stopped=True,
            hosting_pid_kept_alive=True,
            profile_guard_still_armed=True,
            original_profiles_not_yet_restored=True,
            safety_lease_seconds=30,
            nonce_restored=True,
        )

    def cleanup(self):
        errors = []
        if self.established_nonce_session is not None:
            self.established_nonce_session.close()
        if self.worker_process is not None:
            (self.root / "worker-stop.json").write_text(
                '{"stop":true}', encoding="utf-8"
            )
            try:
                self.worker_process.wait(timeout=25)
            except subprocess.TimeoutExpired:
                actual = self.modules[1].inspect_process(
                    self.worker_process.pid, self.host
                )
                if actual["start_identity"] != self.worker_identity["start_identity"]:
                    raise PermissionError(
                        "Owned worker PID incarnation changed; no termination permitted"
                    )
                self.worker_process.terminate()
                self.worker_process.wait(timeout=5)
        if self.guard_process is not None:
            (self.root / "firewall-profile-window-complete.json").write_text(
                json.dumps({"plan_id": self.plan["plan_id"], "complete": True}),
                encoding="utf-8",
            )
            try:
                self.guard_process.wait(timeout=25)
                result = json.loads(
                    (self.root / "firewall-profile-guard-result.json").read_text()
                )
                if (
                    not result["passed"]
                    or self.modules[5].profiles() != self.plan["original_profiles"]
                ):
                    raise AssertionError(
                        "Independent exact-profile restoration or owned-rule cleanup unconfirmed"
                    )
                self.record(
                    "independent_guard_restored_all_original_enabled_bits_and_removed_only_owned_rules",
                    **result,
                )
            except Exception as exc:
                errors.append(type(exc).__name__)
        self.client.close()
        if errors:
            raise RuntimeError(
                "Native firewall cleanup is unconfirmed: " + ",".join(errors)
            )


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--prepared-root", type=Path)
    parser.add_argument("--probe-file", type=Path)
    parser.add_argument("--allow-profile-test", action="store_true")
    parser.add_argument("--worker", action="store_true")
    args = parser.parse_args(argv)
    if os.name != "nt":
        raise PermissionError(
            "This qualification requires the actual authorized Windows host"
        )
    if args.worker:
        if not args.prepared_root:
            parser.error("Worker requires exact owned prepared root")
        return worker(args.prepared_root)
    if not args.fixture or not args.output:
        parser.error("Private fixture and retained public evidence path required")
    if args.allow_profile_test and (not args.probe_file or not args.prepared_root):
        parser.error(
            "Native effects require an independently prepared exact root and coordinated probe file"
        )
    trial, failed, cleanup_error = None, None, None
    try:
        trial = Trial(args.fixture, args.output, args.prepared_root)
        if not args.prepared_root:
            trial.prepare()
        if args.allow_profile_test:
            trial.run_window(args.probe_file)
    except Exception as exc:
        failed = {"type": type(exc).__name__, "message": str(exc)}
        (args.output.parent / (args.output.stem + "-failure.txt")).write_text(
            traceback.format_exc(), encoding="utf-8"
        )
    finally:
        if trial:
            try:
                trial.cleanup()
            except Exception as exc:
                cleanup_error = {"type": type(exc).__name__, "message": str(exc)}
        report = {
            "schema": "xsera.native-windows-isolation-qualification.v1",
            "passed": failed is None and cleanup_error is None,
            "native_isolation_qualified": bool(
                args.allow_profile_test and failed is None and cleanup_error is None
            ),
            "existing_nonmanagement_tcp_session_qualified": bool(
                args.allow_profile_test
                and failed is None
                and cleanup_error is None
                and trial
                and any(
                    check["name"]
                    == "preexisting_nonmanagement_tcp_session_suppressed_after_native_isolation"
                    for check in trial.checks
                )
            ),
            "phase": "native_effects"
            if args.allow_profile_test
            else "prepared_no_firewall_effects",
            "checks": trial.checks if trial else [],
            "responses": trial.responses if trial else [],
            "root": str(trial.root) if trial else None,
            "failure": failed,
            "cleanup_error": cleanup_error,
            "created": time.time(),
            "qualification_helper_sha256": hashlib.sha256(
                Path(__file__).read_bytes()
            ).hexdigest(),
            "reviewed_controller_peers": [
                {"address": address, "port": port} for address, port in PEERS
            ],
            "limits": [
                "The profile enable is a separately authorized finite test-only prerequisite, never product behavior.",
                "Agent polling is stopped but hosting PID deliberately remains alive for the lease timer proof, distinguishing timer rollback from parent-death rollback.",
                "Owned exact firewall rules only; no global policy/default-action/other-rule modification.",
                "This native proof is on one current Windows host, not a universal OS/vendor certification.",
                "Fresh and preexisting IPv4 TCP exchanges are measured against one owned peer; IPv6, UDP, raw traffic and all possible applications require separate qualification.",
                "Only four reviewed management IPs are preserved. Future CDN/DNS peer drift during the finite local window can interrupt remote tool control until the independent guard restores the exact original profiles.",
            ],
        }
        args.output.write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(
            json.dumps(
                {
                    "passed": report["passed"],
                    "phase": report["phase"],
                    "native_isolation_qualified": report["native_isolation_qualified"],
                    "report": str(args.output),
                }
            ),
            flush=True,
        )
    return 0 if failed is None and cleanup_error is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
