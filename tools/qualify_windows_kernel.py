"""Bounded real Windows App Control proof against one unique harmless QA image.

Requires explicit --allow-native-policy. Uses only the dedicated localhost QA
fixture; production is checked read-only. Every native policy has an independent
watchdog before audit/enforce, and finally removes its exact newly owned ID.
Secrets stay in private fixture/config files and never enter the public report.
"""
# ruff: noqa: BLE001 -- Preserve real qualification failures and always attempt owned-only native rollback.

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
import ssl
import subprocess
import sys
import time
import traceback
import uuid
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import httpx

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sapientia.endpoint_agent.Agent import windows_app_control as control
from tools.qualify_security_flow import private_directory

STAGE = Path(__file__).resolve().parents[1]
WORK = STAGE.parent
REQUIRED = {
    "Agent/kernel_prevention.py",
    "Agent/windows_app_control.py",
    "Agent/windows_app_control_watchdog.py",
    "Agent/Windows/collector.py",
    "Agent/cli.py",
    "Agent/core.py",
}
ENROLLMENT_FILES = {"deployment.json", "enrollment.token", "ca.pem"}


def qa_session(client, person, account, cache_file, endpoint):
    """Reuse only our private, still authenticated QA session; never bypass login."""
    cached = {"endpoint_url": endpoint, "sessions": {}}
    if cache_file.exists():
        control.watchdog.no_links(cache_file)
        metadata = cache_file.stat()
        if metadata.st_nlink != 1 or not 1 <= metadata.st_size <= 32 * 1024:
            raise PermissionError("Private QA session cache must be ordinary and bounded")
        cached = json.loads(cache_file.read_text(encoding="utf-8"))
        if (
            not isinstance(cached, dict)
            or cached.get("endpoint_url") != endpoint
            or not isinstance(cached.get("sessions"), dict)
            or set(cached["sessions"]) - {"admin", "peer"}
        ):
            raise PermissionError("Private QA session cache endpoint/account mismatch")
    previous = cached["sessions"].get(account)
    if previous:
        if (
            not isinstance(previous, dict)
            or previous.get("username") != person["username"]
            or not isinstance(previous.get("csrf"), str)
            or not 1 <= len(previous["csrf"]) <= 256
            or not isinstance(previous.get("cookies"), dict)
            or not 1 <= len(previous["cookies"]) <= 16
            or not all(
                isinstance(key, str)
                and isinstance(value, str)
                and 1 <= len(key) <= 128
                and 1 <= len(value) <= 1024
                for key, value in previous["cookies"].items()
            )
        ):
            raise PermissionError("Private QA session cache identity is invalid")
        client.cookies.update(previous["cookies"])
        client.headers["X-CSRF-Token"] = previous["csrf"]
        validation = client.get("/api/me")
        if validation.status_code == 200:
            who = validation.json()
            if who.get("name") != person["username"] or who.get("tenant") != person["tenant"]:
                raise PermissionError("Cached QA session does not match the intended principal")
            return
        if validation.status_code not in {401, 403}:
            raise RuntimeError("Dedicated QA session validation failed")
        client.cookies.clear()
        client.headers.pop("X-CSRF-Token", None)
    result = client.post(
        "/api/login", json={"name": person["username"], "password": person["password"]}
    )
    if result.status_code != 200:
        raise RuntimeError(f"Dedicated QA account login HTTP {result.status_code}; no retry or throttle bypass")
    client.headers["X-CSRF-Token"] = result.json()["csrf"]
    cached["sessions"][account] = {
        "username": person["username"],
        "csrf": client.headers["X-CSRF-Token"],
        "cookies": dict(client.cookies.items()),
    }
    control.watchdog.atomic_json(cache_file, cached)


def verified_package(blob, directory):
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        names = archive.namelist()
        if (
            len(names) != len(set(names))
            or not REQUIRED <= set(names)
            or not ENROLLMENT_FILES <= set(names)
            or set(names) != set(manifest["files"]) | {"manifest.json"}
            or len(names) > 80
        ):
            raise PermissionError("Downloaded package manifest/member set is invalid")
        for item in archive.infolist():
            name = Path(item.filename)
            if (
                item.is_dir()
                or name.is_absolute()
                or name.drive
                or ".." in name.parts
                or item.file_size > 1024 * 1024
                or (item.external_attr >> 16) & 0o170000 == 0o120000
            ):
                raise PermissionError("Unsafe downloaded package member")
            body = archive.read(item)
            if (
                item.filename != "manifest.json"
                and hashlib.sha256(body).hexdigest() != manifest["files"][item.filename]
            ):
                raise PermissionError("Downloaded package member checksum mismatch")
            if (
                item.filename in REQUIRED
                and body
                != (STAGE / "sapientia/endpoint_agent" / item.filename).read_bytes()
            ):
                raise PermissionError("QA package is not the currently reviewed source")
            target = directory / name
            if not target.absolute().is_relative_to(directory.absolute()):
                raise PermissionError(
                    "Downloaded member would escape the private agent root"
                )
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
    return manifest


def listeners():
    output = control._run_ps(
        Path("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"),
        "$rows=@(Get-NetTCPConnection -State Listen -LocalPort 8787,8788 | Select-Object LocalAddress,LocalPort,OwningProcess); [Console]::Write(($rows|ConvertTo-Json -Compress))",
        {},
    )
    value = json.loads(output)
    rows = value if isinstance(value, list) else [value]
    if {row["LocalPort"] for row in rows} != {8787, 8788}:
        raise AssertionError(
            "Both operating production listeners must exist before qualification"
        )
    return sorted(
        rows,
        key=lambda row: (row["LocalPort"], row["LocalAddress"], row["OwningProcess"]),
    )


def load_downloaded(directory):
    name = "qa_native_windows_" + uuid.uuid4().hex
    spec = importlib.util.spec_from_file_location(
        name,
        directory / "Agent/__init__.py",
        submodule_search_locations=[str(directory / "Agent")],
    )
    package = importlib.util.module_from_spec(spec)
    sys.modules[name] = package
    spec.loader.exec_module(package)
    runtime = __import__(name + ".core", fromlist=["Agent"])
    native = __import__(name + ".windows_app_control", fromlist=["WindowsAppControl"])
    collector = __import__(name + ".Windows.collector", fromlist=["WindowsCollector"])
    return runtime, native, collector


def run_cli(directory, mode):
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            str(directory / "Agent/Windows/main.py"),
            "kernel-policy",
            "--config",
            str(directory / "config.json"),
            "--enable-kernel-prevention",
            "--kernel-directory",
            str(directory / "owned-targets"),
            "--kernel-rule-id",
            "deny-owned-windows",
            "--kernel-mode",
            mode,
            "--kernel-lease-seconds",
            "120",
            "--confirm-kernel-policy",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=25,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if result.returncode:
        (directory / "cli-failure.txt").write_text(result.stderr, encoding="utf-8")
        raise RuntimeError("Downloaded protected local kernel-policy CLI failed")
    return json.loads((directory / "config.json").read_text(encoding="utf-8"))


def compiled_payload(directory):
    folder = directory / "owned-targets"
    folder.mkdir()
    source, target = folder / "owned-payload.cs", folder / "unique-owned-payload.exe"
    nonce = uuid.uuid4().hex
    prefix = str(folder) + "\\"
    source.write_text(
        "using System; using System.IO; public class QANative_"
        + nonce
        + ' { public static int Main(string[] a) { if(a.Length!=1 || !a[0].StartsWith(@"'
        + prefix.replace('"', '""')
        + '")) return 2; File.WriteAllText(a[0],"main-executed-'
        + nonce
        + '"); return 0; } }',
        encoding="utf-8",
    )
    compiler = Path("C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe")
    result = subprocess.run(
        [str(compiler), "/nologo", "/target:exe", "/out:" + str(target), str(source)],
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if result.returncode or not target.is_file():
        raise RuntimeError("Harmless unique C# native image compilation failed")
    return target, hashlib.sha256(target.read_bytes()).hexdigest(), nonce


def execute(target, marker, *, denied):
    if marker.exists():
        raise AssertionError(
            "Owned marker must not exist before this execution attempt"
        )
    error = None
    try:
        result = subprocess.run(
            [str(target), str(marker)],
            capture_output=True,
            check=False,
            timeout=8,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        code = result.returncode
    except OSError as failure:
        error = {
            "errno": failure.errno,
            "winerror": getattr(failure, "winerror", None),
            "message": str(failure)[:512],
        }
        code = None
    if denied:
        if marker.exists() or error is None and code == 0:
            raise AssertionError(
                "Native policy did not prevent the harmless payload side effect"
            )
    elif error is not None or code != 0 or not marker.is_file():
        raise AssertionError("Allowed harmless native payload did not execute")
    return {"marker_created": marker.exists(), "returncode": code, "os_error": error}


def collect_ci(collector_module, identifier, target, *, code, baseline):
    sensor = collector_module.WindowsCollector.__new__(
        collector_module.WindowsCollector
    )
    sensor.cursors = {
        collector_module.CODE_INTEGRITY_CHANNEL: {"record": baseline, "epoch": 0}
    }
    sensor.providers, sensor.provider_processes, sensor.last_rows = {}, {}, {}
    sensor.host_name, sensor.emit_initial = "owned-qualification", True
    namespace = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        roots = collector_module._xml_events(
            collector_module.CODE_INTEGRITY_CHANNEL, count=2000, after=baseline
        )
        found = []
        for root in roots:
            if root.findtext(namespace + "System/" + namespace + "EventID") != str(
                code
            ):
                continue
            fields = {
                row.get("Name", ""): row.text
                for row in root.findall(
                    ".//" + namespace + "EventData/" + namespace + "Data"
                )
            }
            values = [str(v).casefold() for v in fields.values() if v is not None]
            if not any(
                identifier.strip("{}").casefold() in v for v in values
            ) or not any(target.name.casefold() in v for v in values):
                continue
            found.append(root)
        if found:
            # Use the real collector mapper/cursor implementation, filtering only
            # this run's native CI events to avoid replaying unrelated host logs.
            original = collector_module._xml_events

            def own_query(
                channel, count=100, after=None, record_id=None, records=found
            ):
                if channel != collector_module.CODE_INTEGRITY_CHANNEL:
                    return []
                if record_id is not None:
                    return []
                return records[-count:] if after is None else records

            collector_module._xml_events = own_query
            try:
                return sensor._log_events("fixture-host"), [
                    __import__("xml.etree.ElementTree", fromlist=["tostring"]).tostring(
                        root, encoding="unicode"
                    )
                    for root in found
                ]
            finally:
                collector_module._xml_events = original
        time.sleep(0.1)
    raise AssertionError(
        "Actual CodeIntegrity event was not found for this exact policy and denied/audited image"
    )


class Trial:
    def __init__(self, fixture, output):
        fixture = fixture.resolve(strict=True)
        expected_parent = (WORK / "native-linux-0.10").resolve(strict=True)
        control.watchdog.no_links(fixture)
        if (
            fixture.parent != expected_parent
            or (expected_parent / ".qa-synthetic-only")
            .read_text(encoding="utf-8")
            .strip()
            != "synthetic-only"
        ):
            raise PermissionError(
                "Only the explicitly marked native QA fixture is accepted"
            )
        self.fixture = json.loads(fixture.read_text(encoding="utf-8-sig"))
        if (
            self.fixture["endpoint_url"] != "https://127.0.0.1:18788"
            or self.fixture["console_url"] != "http://127.0.0.1:18787"
        ):
            raise ValueError(
                "Only the dedicated localhost native qualification service is accepted"
            )
        self.output, self.clients, self.checks, self.adapters = output, {}, [], []
        self.directory = WORK / ("native-windows-kernel-" + uuid.uuid4().hex)
        private_directory(self.directory)
        (self.directory / ".qa-synthetic-only").write_text(
            "synthetic-only\n", encoding="utf-8"
        )
        self.context = ssl.create_default_context(cafile=self.fixture["ca_file"])
        for name, person in (
            ("admin", self.fixture["admin"]),
            ("peer", self.fixture["peeradmin"]),
        ):
            client = httpx.Client(
                base_url=self.fixture["endpoint_url"],
                verify=self.context,
                trust_env=False,
                timeout=10,
                headers={"Origin": self.fixture["endpoint_url"]},
            )
            qa_session(client, person, name, fixture.parent / "linux-qa-sessions.json", self.fixture["endpoint_url"])
            self.clients[name] = client
        self.before_listeners = listeners()
        self.before_policies = control.NativeAppControl().inventory()

    def api(
        self, method, path, *, account="admin", expected=200, binary=False, **kwargs
    ):
        value = self.clients[account].request(method, path, **kwargs)
        if value.status_code != expected:
            raise RuntimeError(
                f"Dedicated QA {method} {path}: HTTP {value.status_code}, expected {expected}"
            )
        return value if binary else value.json()

    def record(self, name, **details):
        self.checks.append({"name": name, "passed": True, **details})
        print(json.dumps({"check": name, "passed": True}), flush=True)

    def provision(self):
        self.host = "QA-WINDOWS-KERNEL-" + self.directory.name[-12:]
        deployment = self.api(
            "POST",
            "/api/xdr/agents/deployments",
            expected=201,
            json={
                "platform": "windows",
                "host": self.host,
                "index": "endpoint_windows",
                "ttl_seconds": 600,
            },
        )
        package = self.api("POST", deployment["package_url"], binary=True, json={})
        package_digest = hashlib.sha256(package.content).hexdigest()
        if package_digest != package.headers["X-Package-SHA256"]:
            raise AssertionError("Authenticated package body digest mismatch")
        verified_package(package.content, self.directory)
        if not all((self.directory / name).is_file() for name in ENROLLMENT_FILES):
            raise PermissionError(
                "Verified bound enrollment material is missing before configuration"
            )
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(self.directory / "configure.py"),
                "--directory",
                str(self.directory),
                "--deployment",
                str(self.directory / "deployment.json"),
                "--token-file",
                str(self.directory / "enrollment.token"),
                "--ca-file",
                str(self.directory / "ca.pem"),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=25,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if result.returncode:
            (self.directory / "configuration-failure.txt").write_text(
                result.stderr, encoding="utf-8"
            )
            raise RuntimeError("Downloaded TLS enrollment configurator failed")
        (self.directory / "enrollment.token").unlink()
        self.runtime, self.native, self.collector = load_downloaded(self.directory)
        self.config = json.loads(
            (self.directory / "config.json").read_text(encoding="utf-8")
        )
        self.identity = json.loads(
            (Path(self.config["state_dir"]) / "identity.json").read_text(
                encoding="utf-8"
            )
        )
        self.record(
            "downloaded_verified_current_windows_agent_tls_enrollment",
            agent_id=self.identity["agent_id"],
            package_sha256=package_digest,
        )

    def approve(self, target, digest):
        policy = self.api(
            "POST",
            "/api/xdr/agents/defense-policies",
            expected=201,
            json={
                "agent_id": self.identity["agent_id"],
                "request_id": "native-windows-kernel-" + uuid.uuid4().hex,
                "lifetime_hours": 1,
                "rules": [
                    {
                        "id": "deny-owned-windows",
                        "name": "Unique owned harmless Windows native image",
                        "enabled": True,
                        "action": "terminate_process",
                        "severity": "critical",
                        "mitre": ["T1204.002"],
                        "conditions": [
                            {
                                "field": "file.hash.sha256",
                                "op": "eq",
                                "value": digest,
                                "ignore_case": False,
                            },
                            {
                                "field": "process.executable",
                                "op": "eq",
                                "value": str(target),
                                "ignore_case": False,
                            },
                        ],
                    }
                ],
            },
        )
        self.api(
            "POST",
            "/api/xdr/agents/defense-policies/" + policy["id"] + "/approve",
            account="admin",
            expected=403,
            json={},
        )
        self.api(
            "POST",
            "/api/xdr/agents/defense-policies/" + policy["id"] + "/approve",
            account="peer",
            json={},
        )
        # Exercise the real downloaded kernel-only fetch/cache route before any
        # controller starts. Reactive effects remain disabled.
        self.config = run_cli(self.directory, "audit")
        agent = self.runtime.Agent(self.config, SimpleNamespace())
        try:
            agent._fetch_policy()
            bundle = json.loads(
                Path(self.config["defense"]["bundle_file"]).read_text(encoding="utf-8")
            )
            if (
                agent.defense.settings["enabled"] is not False
                or agent.defense.db is not None
            ):
                raise AssertionError(
                    "Kernel-only fetch unexpectedly enabled the reactive engine"
                )
        finally:
            agent.kernel_prevention.close()
            agent.defense.close()
            agent.queue.close()
        self.record(
            "peer_approved_tenant_host_agent_bound_exact_hash_policy",
            release_id=policy["id"],
            revision=bundle["document"]["revision"],
        )

    def native_mode(self, mode, target):
        self.config = run_cli(self.directory, mode)
        bound = dict(
            self.config,
            **{
                field: self.identity[field]
                for field in ("tenant", "host", "agent_id", "index")
            },
        )
        latest = self.collector._xml_events(
            self.collector.CODE_INTEGRITY_CHANNEL, count=1
        )
        baseline = (
            int(latest[0].findtext("{*}System/{*}EventRecordID")) if latest else 0
        )
        adapter = self.native.WindowsAppControl(bound, self.runtime.response)
        self.adapters.append(adapter)
        try:
            adapter.start()
            state = adapter.status()
            if (
                state["state"] != "active"
                or state["mode"] != mode
                or not state["independent_rollback_watchdog"]
            ):
                raise AssertionError("Native policy mode/watchdog state not confirmed")
            if state["kernel_permission_denial"] != (mode == "enforce"):
                raise AssertionError("Audit/enforcement capability state is incorrect")
            effect = execute(
                target,
                self.directory / "owned-targets" / (mode + "-marker.txt"),
                denied=mode == "enforce",
            )
            native_code = 3076 if mode == "audit" else 3077
            events, raw = collect_ci(
                self.collector,
                adapter.identifier,
                target,
                code=native_code,
                baseline=baseline,
            )
            for event in events:
                event["data"]["host"]["id"] = self.host
                assert "process" not in event["data"]
            (self.directory / (mode + "-native-ci.xml")).write_text(
                "\n".join(raw), encoding="utf-8"
            )
            transport = self.runtime.Transport(
                self.config["endpoint_url"], self.config["ca_file"]
            )
            receipt = transport.post(
                "/api/agent/ingest", {"events": events}, self.identity["credential"]
            )
            (self.directory / (mode + "-native-admission-receipt.json")).write_text(
                json.dumps(receipt, indent=2), encoding="utf-8"
            )
            if (
                receipt.get("accepted") != len(events)
                or receipt.get("quarantined", 0) != 0
                or any(row.get("quarantined") for row in receipt.get("results", []))
            ):
                raise AssertionError(
                    "Actual native CodeIntegrity observations were not admitted by the SIEM"
                )
            self.record(
                "real_native_"
                + mode
                + "_payload_and_code_integrity_"
                + str(native_code),
                policy_id=adapter.identifier,
                effect=effect,
                native_events=len(events),
                siem_accepted=receipt["accepted"],
                no_invented_process_identity=True,
                watchdog_verified_before_apply=True,
            )
            if mode == "enforce":
                self.enforce_event_ids = [event["id"] for event in events]
        finally:
            adapter.close()
            if not adapter.rollback_result or not adapter.rollback_result["removed"]:
                raise AssertionError(
                    "Exact newly owned App Control policy removal was not confirmed"
                )
        allowed = execute(
            target,
            self.directory / "owned-targets" / (mode + "-after-removal-marker.txt"),
            denied=False,
        )
        self.record(
            mode + "_owned_policy_removed_and_payload_runs_again",
            policy_id=adapter.identifier,
            removed=True,
            after_removal=allowed,
        )

    def run(self):
        self.provision()
        target, digest, nonce = compiled_payload(self.directory)
        self.record(
            "unique_compiled_harmless_pe_baseline",
            sha256=digest,
            nonce=nonce,
            effect=execute(
                target,
                self.directory / "owned-targets/baseline-marker.txt",
                denied=False,
            ),
        )
        self.approve(target, digest)
        self.native_mode("audit", target)
        self.native_mode("enforce", target)
        self.case_flow()

    def case_flow(self):
        definition = {
            "name": "Actual Windows kernel denial " + self.directory.name[-8:],
            "entity_field": "host",
            "window": 600,
            "interval": 30,
            "cooldown": 600,
            "risk_score": 100,
            "severity": "critical",
            "mitre": ["T1204.002"],
            "steps": [
                {
                    "name": "Native CodeIntegrity 3077",
                    "filters": [
                        {"field": "host", "op": "eq", "value": self.host},
                        {
                            "field": "raw.action",
                            "op": "eq",
                            "value": "execution_denied",
                        },
                        {
                            "field": "raw.xdr.data.event.code",
                            "op": "eq",
                            "value": "3077",
                        },
                    ],
                }
            ],
        }
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            preview = self.api(
                "POST",
                "/api/detections/preview",
                json={"definition": definition, "end": time.time() + 30},
            )
            if preview["match_count"] >= 1:
                break
            time.sleep(0.2)
        else:
            raise AssertionError(
                "Native Windows CI denial was not searchable by the actual detection engine"
            )
        created = self.api("POST", "/api/detections", expected=201, json=definition)
        policy = next(
            (row for row in self.api("GET", "/api/detections") if row["id"] == created["id"]),
            None,
        )
        if policy is None or type(policy.get("version")) is not int:
            raise AssertionError("New native CI detection version could not be read")
        try:
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                cases = self.api("GET", "/api/incidents")
                case = next(
                    (row for row in cases if row.get("entity") == self.host), None
                )
                if case:
                    break
                time.sleep(0.2)
            else:
                raise AssertionError(
                    "Native Windows CI denial did not create an actual critical Case"
                )
            attack = self.api("GET", "/api/incidents/" + case["id"] + "/attack-context")
            if attack["threat_score"] != 100 or attack["severity"] != "critical":
                raise AssertionError(
                    "Native prevention Case priority differed from the configured rule"
                )
            self.record(
                "actual_native_ci_denial_to_detection_critical_case",
                case_id=case["id"],
                threat_score=100,
                severity="critical",
                mitre=["T1204.002"],
            )
        finally:
            self.api(
                "PATCH",
                "/api/detections/" + policy["id"],
                json={"enabled": False, "version": policy["version"]},
            )

    def close(self):
        for adapter in reversed(self.adapters):
            adapter.close()
        after = control.NativeAppControl().inventory()
        if after != self.before_policies:
            raise AssertionError(
                "App Control inventory differs from the exact pre-test state"
            )
        if listeners() != self.before_listeners:
            raise AssertionError(
                "Production listener PID/address/port continuity failed"
            )
        self.record(
            "prior_native_policies_and_operating_listener_pids_preserved",
            existing_policies=len(after),
            operating_listeners=self.before_listeners,
        )
        for client in self.clients.values():
            client.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--allow-native-policy", action="store_true")
    args = parser.parse_args(argv)
    if os.name != "nt" or not args.allow_native_policy:
        parser.error("Actual Windows and explicit --allow-native-policy are required")
    trial, error, cleanup_error = None, None, None
    try:
        trial = Trial(args.fixture, args.output)
        trial.run()
    except Exception:
        error = traceback.format_exc()
    finally:
        if trial:
            try:
                trial.close()
            except Exception:
                cleanup_error = traceback.format_exc()
        report = {
            "passed": error is None and cleanup_error is None,
            "completed_utc": datetime.now(UTC).isoformat(),
            "platform": "actual-current-Windows",
            "native_policy_user_optin": args.allow_native_policy,
            "checks": trial.checks if trial else [],
            "owned_root": str(trial.directory) if trial else None,
            "error": error,
            "cleanup_error": cleanup_error,
            "mocked_native_effects": False,
            "proprietary_xsera_kernel_driver": False,
            "firewall_isolation_performed": False,
            "test_data_removed": False,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(
            json.dumps(
                {
                    "passed": report["passed"],
                    "checks": len(report["checks"]),
                    "output": str(args.output),
                }
            ),
            flush=True,
        )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
