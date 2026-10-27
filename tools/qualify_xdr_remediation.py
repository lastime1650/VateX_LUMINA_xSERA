"""Native-producer and synthetic 1,000-event XDR remediation qualification on 8788/8790.

Only processes spawned by this run and files created in its private directory
are response targets. Production 8787 and its data are never accessed.
"""

import argparse
import hashlib
import importlib
import importlib.util
import json
import os
import secrets
import subprocess
import sys
import time
import traceback
import uuid
from datetime import UTC, datetime
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import qualify_security_flow as base


class Trial(base.Qualification):
    def __init__(self, *args):
        super().__init__(*args)
        self.targets = []
        self.command_results = []

    def provision_agents(self):
        for host, platform, index in [
            ("QA-WINDOWS-01", "windows", "endpoint_windows"),
            ("QA-WINDOWS-02", "windows", "endpoint_windows"),
            ("QA-LINUX-NOISE", "linux", "endpoint_linux"),
        ]:
            self.provision(platform, host, index)
        self.record("three_downloaded_agents_one_time_tls_enrolled")

    def templates(self):
        analyst = self.clients["qa_analyst"]
        overview = self.json(analyst, "GET", "/api/rule-templates/summary")
        assert overview["total"] == 950 and overview["enabled"] is False
        page = self.json(analyst, "GET", "/api/rule-templates", params={"limit": 50})
        assert page["library_total"] == 950 and len(page["items"]) == 50
        template = self.json(analyst, "GET", "/api/rule-templates/R-WIN-001")
        assert template["supported"] and not template["enabled"]
        self.request(
            analyst,
            "POST",
            "/api/rule-templates/R-WIN-001/apply",
            json={"index": "endpoint_windows", "accept_adaptation": False},
            expected=400,
        )
        applied = self.json(
            analyst,
            "POST",
            "/api/rule-templates/R-WIN-001/apply",
            json={"index": "endpoint_windows", "accept_adaptation": True},
            expected=201,
        )
        assert not applied["enabled"]
        self.request(
            self.clients["qa_viewer"],
            "POST",
            "/api/rule-templates/R-WIN-001/apply",
            json={"index": "endpoint_windows", "accept_adaptation": True},
            expected=403,
        )
        self.template_summary = overview
        self.record(
            "950_starter_templates_reference_and_explicit_disabled_import", **overview
        )

    def prepare_targets(self):
        """Concrete harmless targets; executor opt-in is scoped to this run."""
        for number, host in enumerate(("QA-WINDOWS-01", "QA-WINDOWS-02"), 1):
            endpoint = self.endpoint_agents[host]
            directory = Path(endpoint["config"]["state_dir"]).parent
            package_name = "xsera_response_package_" + uuid.uuid4().hex
            spec = importlib.util.spec_from_file_location(
                package_name,
                directory / "Agent/__init__.py",
                submodule_search_locations=[str(directory / "Agent")],
            )
            package = importlib.util.module_from_spec(spec)
            sys.modules[package_name] = package
            spec.loader.exec_module(package)
            response = importlib.import_module(package_name + ".response")
            process = subprocess.Popen(
                [
                    getattr(sys, "_base_executable", sys.executable),
                    "-c",
                    "import time; time.sleep(900)",
                ],
                cwd=self.directory,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            target = {
                "host": host,
                "process": process,
                "endpoint": endpoint,
                "ip": "10.77.0." + str(number * 10),
                "response_module": response,
            }
            self.targets.append(target)
            identity = response.inspect_process(process.pid, host)
            target["identity"] = identity
            files = self.directory / ("response-files-" + str(number))
            files.mkdir()
            (files / ".lumina-response-root").write_text(
                "allow-manual-file-delete\n", encoding="utf-8"
            )
            payload = files / "harmless-synthetic-payload.txt"
            payload.write_text(
                "Synthetic inert QA file; not malware.\n", encoding="utf-8"
            )
            target["file"] = payload
            target["sha256"] = hashlib.sha256(payload.read_bytes()).hexdigest()
            self.configure_response(target, files)
        self.record("two_harmless_owned_processes_and_two_inert_files_created")

    def local_cli(self, target, command, flags):
        config = target["endpoint"]["config"]
        directory = Path(config["state_dir"]).parent
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                "-B",
                str(directory / "Agent/Windows/main.py"),
                command,
                "--config",
                str(directory / "config.json"),
                *flags,
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        json.loads(completed.stdout)
        config.update(
            json.loads((directory / "config.json").read_text(encoding="utf-8"))
        )
        return config

    def configure_response(self, target, files):
        identity = target["identity"]
        self.local_cli(
            target,
            "response-policy",
            [
                "--enable-response",
                "--allow-process-executable",
                identity["executable"],
                "--allow-process-instance",
                str(identity["pid"]) + ":" + identity["start_identity"],
                "--allow-file-root",
                str(files),
                "--confirm-response-policy",
            ],
        )
        capabilities = target["response_module"].capabilities(
            target["endpoint"]["config"]
        )
        assert set(capabilities["actions"]) == {"terminate_process", "delete_file"}

    def endpoint_records(self):
        totals = {}
        self.native_rows = 0
        for host, endpoint in self.endpoint_agents.items():
            platform = endpoint["public"]["platform"]
            target = next((x for x in self.targets if x["host"] == host), None)
            native = None
            if target:
                native = self.native_process(target)
                self.native_rows += 1
            rows = []
            for number in range(200):
                at = self.start + 5 + number % 100
                data = {
                    "@timestamp": datetime.fromtimestamp(at, UTC).isoformat(),
                    "host": {"id": host, "os": {"type": platform}},
                    "process": {
                        "guid": host + "-noise-" + str(number),
                        "pid": 10000 + number,
                        "parent": {"guid": host + "-noise-parent-" + str(number // 20)},
                        "name": "svchost.exe"
                        if platform == "windows"
                        else "systemd-worker",
                        "command_line": "synthetic benign background task",
                    },
                    "source": {"ip": "10.88.0." + str(1 + number % 200)},
                    "event": {
                        "action": (
                            "process_created",
                            "dns_query",
                            "file_created",
                            "authentication_success",
                            "network_connection",
                            "inventory_snapshot",
                        )[number % 6],
                        "severity": "info",
                    },
                    "dns": {"question": {"name": "updates.example.test"}},
                    "destination": {"ip": "203.0.113.25", "port": 443},
                    "test": {
                        "synthetic": True,
                        "classification": "noise",
                        "scenario": "xsera-1000",
                    },
                }
                if target and number < 3:
                    action = (
                        "process_created",
                        "credential_access",
                        "network_connection",
                    )[number]
                    identity = target["identity"]
                    native_at = datetime.fromisoformat(
                        native["data"]["@timestamp"]
                    ).timestamp()
                    data["@timestamp"] = datetime.fromtimestamp(
                        native_at + number * 0.001, UTC
                    ).isoformat()
                    data["process"] = {
                        key: identity[key]
                        for key in ("guid", "pid", "start_identity", "executable")
                    }
                    data["process"].update(
                        name="harmless-qa-python",
                        command_line="inert sleep process owned by this test",
                    )
                    data["source"]["ip"] = target["ip"]
                    data["event"] = {"action": action, "severity": "high"}
                    data["file"] = {
                        "path": str(target["file"]),
                        "hash": {"sha256": target["sha256"]},
                    }
                    data["test"]["classification"] = "synthetic-suspicious"
                if target and number == 0:
                    # Preserve actual Toolhelp producer identity and birth timestamp.
                    native["data"].update(
                        source=data["source"], file=data["file"], test=data["test"]
                    )
                    rows.append(native)
                else:
                    rows.append({"id": host + "-event-" + str(number), "data": data})
            # Reverse arrival exercises event-time correlation and real durable queue.
            instance = endpoint["core"].Agent(endpoint["config"], None)
            instance.queue.add_many(list(reversed(rows)))
            sent = 0
            while instance.queue.size():
                flushed = instance.flush()
                assert flushed > 0
                sent += flushed
            assert sent == 200
            instance.heartbeat()
            instance.queue.close()
            totals[host] = len(rows)
        self.record(
            "six_hundred_endpoint_events_durable_verified_tls_queue", counts=totals
        )

    def network_records(self):
        rows = []
        for number in range(400):
            suspicious = number < 2
            srcip = (
                self.targets[number]["ip"]
                if suspicious
                else f"10.89.{number // 200}.{1 + number % 200}"
            )
            fields = {
                "date": "2026-10-08",
                "time": "00:00:00",
                "tz": "+0900",
                "eventtime": str(
                    int(
                        (time.time() if suspicious else self.start + number % 100)
                        * 10**9
                    )
                ),
                "devid": "FGT-SYNTHETIC-ONLY",
                "devname": "QA-FORTIGATE",
                "logid": "0419016384" if suspicious else "0000000013",
                "type": "utm" if suspicious or number % 19 == 0 else "traffic",
                "subtype": "ips" if suspicious or number % 19 == 0 else "forward",
                "level": "alert" if suspicious else "notice",
                "srcip": srcip,
                "srcport": str(30000 + number),
                "dstip": "198.51.100.20" if suspicious else "203.0.113.25",
                "dstport": "53" if number % 7 == 0 else "443",
                "proto": "17" if number % 7 == 0 else "6",
                "action": "deny"
                if suspicious or number % 19 == 0
                else ("accept" if number % 2 else "close"),
                "srcintf": "internal",
                "dstintf": "wan1",
                "policyid": "25",
                "sessionid": str(90000 + number),
                "sentbyte": "4096",
                "rcvdbyte": "8192",
                "msg": "synthetic suspicious session"
                if suspicious
                else "synthetic normal HTTPS",
            }
            text = " ".join(f'{key}="{value}"' for key, value in fields.items())
            rows.append({"id": "FGT-" + str(number), "log": text})
        body = {"index": "network", "events": list(reversed(rows))}
        reply = self.json(
            self.clients["qa_analyst"],
            "POST",
            "/api/fortigate/intake",
            json=body,
            expected=202,
        )
        assert reply["accepted"] == 400 and reply["durable"]
        retry = self.json(
            self.clients["qa_analyst"],
            "POST",
            "/api/fortigate/intake",
            json=body,
            expected=202,
        )
        assert retry["accepted"] == 0 and retry["duplicate"] == 400
        self.request(
            self.clients["qa_viewer"],
            "POST",
            "/api/fortigate/intake",
            json=body,
            expected=403,
        )
        self.request(
            self.clients["qa_windows_reader"],
            "POST",
            "/api/fortigate/intake",
            json=body,
            expected=403,
        )
        self.record(
            "four_hundred_fortigate_kv_events_noise_retries_acl_and_raw_session_fields"
        )
        summary = self.wait(
            self.clients["qa_admin"],
            "/api/console/summary",
            lambda x: x["telemetry"]["event_count"] == 1000,
            params={"start": self.start - 1, "end": time.time() + 1},
        )
        self.record(
            "exact_thousand_searchable_events_992_noise_8_scenario_records",
            events=summary["telemetry"]["event_count"],
            noise=992,
            suspicious=8,
        )

    def detect_mixed(self):
        self.end = time.time() + 1
        definition = {
            "name": "SYNTHETIC XDR endpoint credential / network / FortiGate UTM",
            "entity_field": "raw.security.src_ip",
            "window": 600,
            "interval": 30,
            "cooldown": 600,
            "risk_score": 90,
            "severity": "critical",
            "mitre": ["T1003", "T1059.001", "T1071.001"],
            "steps": [
                {
                    "name": action,
                    "filters": [
                        {"field": "index", "op": "eq", "value": "endpoint_windows"},
                        {"field": "source", "op": "eq", "value": "aegis-xdr"},
                        {"field": "raw.action", "op": "eq", "value": action},
                    ],
                }
                for action in (
                    "process_created",
                    "credential_access",
                    "network_connection",
                )
            ]
            + [
                {
                    "name": "FortiGate UTM denial",
                    "filters": [
                        {"field": "index", "op": "eq", "value": "network"},
                        {"field": "source", "op": "eq", "value": "fortigate"},
                        {"field": "raw.fortigate.type", "op": "eq", "value": "utm"},
                        {"field": "raw.fortigate.action", "op": "eq", "value": "deny"},
                    ],
                }
            ],
        }
        analyst = self.clients["qa_analyst"]
        preview = self.json(
            analyst,
            "POST",
            "/api/detections/preview",
            json={"definition": definition, "end": self.end},
        )
        assert preview["match_count"] == 2 and not preview["persisted"]
        policy = self.json(
            analyst, "POST", "/api/detections", json=definition, expected=201
        )
        cases = self.wait(analyst, "/api/incidents", lambda x: len(x) == 2)
        self.json(
            analyst,
            "PATCH",
            "/api/detections/" + policy["id"],
            json={"enabled": False, "version": 1},
        )
        assert {x["entity"] for x in cases} == {x["ip"] for x in self.targets}
        for target in self.targets:
            case = next(x for x in cases if x["entity"] == target["ip"])
            target["case_id"] = case["id"]
            context = self.json(
                analyst, "GET", "/api/incidents/" + case["id"] + "/attack-context"
            )
            assert context["threat_score"] == 90 and context["severity"] == "critical"
            assert {x["id"] for x in context["techniques"]} == {
                "T1003",
                "T1059.001",
                "T1071.001",
            }
            self.scenarios.append(
                {
                    "host": target["host"],
                    "entity_ip": target["ip"],
                    "incident_id": case["id"],
                    "attack_context": context,
                }
            )
        self.record(
            "mixed_endpoint_firewall_ordered_scheduler_two_cases_zero_noise_cases",
            cases=2,
            false_positive_cases=0,
        )

    def respond(self):
        analyst = self.clients["qa_analyst"]
        pending = []
        for target in self.targets:
            case = "/api/incidents/" + target["case_id"]
            state = self.json(analyst, "GET", case + "/agent-response")
            event = next(
                e
                for e in state["events"]
                if e["process"]["guid"] == target["identity"]["guid"]
                and e["file"].get("sha256") == target["sha256"]
            )
            assert (
                event["response_eligible"]
                and event["verified_agent_id"]
                == target["endpoint"]["public"]["agent_id"]
            )
            target["response_event_id"] = event["event_id"]
            agent_id = target["endpoint"]["public"]["agent_id"]
            assert any(a["id"] == agent_id for a in state["agents"])
            commands = [
                {
                    "type": "delete_file",
                    "path": str(target["file"]),
                    "sha256": target["sha256"],
                },
                {
                    "type": "terminate_process",
                    "process_guid": target["identity"]["guid"],
                    "pid": target["identity"]["pid"],
                    "start_identity": target["identity"]["start_identity"],
                },
            ]
            for action in commands:
                body = {
                    "agent_id": agent_id,
                    "evidence_event_id": event["event_id"],
                    "case_version": state["case_version"],
                    "request_id": target["host"] + "-" + action["type"],
                    "reason": "Explicit manual QA response to inert target created by this run only.",
                    "action": action,
                }
                self.request(
                    self.clients["qa_viewer"],
                    "POST",
                    case + "/agent-response",
                    json=body,
                    expected=403,
                )
                self.request(
                    self.clients["qa_other_admin"],
                    "POST",
                    case + "/agent-response",
                    json=body,
                    expected=404,
                )
                command = self.json(
                    analyst, "POST", case + "/agent-response", json=body, expected=201
                )
                assert command["state"] == "queued"
                duplicate = self.json(
                    analyst, "POST", case + "/agent-response", json=body, expected=201
                )
                assert duplicate["duplicate"] and duplicate["id"] == command["id"]
                pending.append((target, command["id"], action["type"]))
        self.record(
            "four_explicit_case_evidence_bound_commands_duplicate_and_role_tenant_guards"
        )
        before = self.json(
            analyst,
            "GET",
            "/api/console/summary",
            params={"start": self.start - 1, "end": time.time() + 1},
        )
        assert before["cases"]["response_modes"]["manual"] == 2
        assert before["cases"]["endpoint_responses"]["requested"] == 4
        assert before["cases"]["endpoint_responses"]["confirmed_effects"] == 0
        self.restart("manual_commands_queued_durable")
        for target in self.targets:
            instance = target["endpoint"]["core"].Agent(
                target["endpoint"]["config"], None
            )
            instance.heartbeat()
            for _ in range(2):
                assert instance.poll()
            assert instance.poll() is None
            instance.queue.close()
        for target, command_id, kind in pending:
            command = self.json(
                self.clients["qa_analyst"], "GET", "/api/agent-responses/" + command_id
            )
            assert (
                command["state"] == "succeeded"
                and command["result"]["executed"] is True
            )
            self.command_results.append(command)
            if kind == "terminate_process":
                target["process"].wait(timeout=5)
                assert target["process"].poll() is not None
            else:
                assert not target["file"].exists()
        self.record(
            "actual_downloaded_agent_receives_signed_commands_acks_and_executes_four_confirmed_windows_os_effects",
            terminated_processes=2,
            deleted_files=2,
        )
        self.restart("manual_command_results_durable")
        for target in self.targets:
            instance = target["endpoint"]["core"].Agent(
                target["endpoint"]["config"], None
            )
            assert instance.poll() is None
            instance.queue.close()
        self.record(
            "completed_endpoint_commands_not_replayed_after_server_and_agent_restart"
        )
        analyst = self.clients["qa_analyst"]
        book = self.json(
            analyst,
            "POST",
            "/api/playbooks",
            json={
                "name": "SYNTHETIC independently approved closure after confirmed manual agent response",
                "version": 0,
                "steps": [
                    {
                        "id": "review",
                        "action": {
                            "type": "add_note",
                            "note": "Harmless QA process and inert file response receipts independently reviewed.",
                        },
                    },
                    {
                        "id": "resolve",
                        "action": {
                            "type": "set_status",
                            "status": "resolved",
                            "note": "Synthetic case closed after confirmed manual endpoint response.",
                        },
                    },
                ],
            },
        )
        for target in self.targets:
            run = self.json(
                analyst,
                "POST",
                "/api/playbooks/" + book["id"] + "/runs",
                json={
                    "incident_id": target["case_id"],
                    "request_id": target["host"] + "-closure",
                },
            )
            runpath = "/api/playbook-runs/" + run["id"]
            self.request(analyst, "POST", runpath + "/approve", json={}, expected=403)
            self.json(
                self.clients["qa_approver"], "POST", runpath + "/approve", json={}
            )
            complete = self.wait(
                analyst,
                runpath,
                lambda x: x["state"] in {"completed", "failed", "unknown"},
            )
            assert complete["state"] == "completed"
            target["run_id"] = run["id"]
            next(
                x for x in self.scenarios if x["incident_id"] == target["case_id"]
            ).update(
                final_status="resolved", run_id=run["id"], actual_endpoint_effects=2
            )
        self.record("independent_approved_playbook_review_and_resolve_two_cases")

    def finish(self):
        self.summary = self.json(
            self.clients["qa_analyst"],
            "GET",
            "/api/console/summary",
            params={"start": self.start - 1, "end": time.time() + 1},
        )
        self.audit = self.json(self.clients["qa_admin"], "GET", "/api/audit/integrity")
        assert self.audit["valid"]
        assert self.summary["telemetry"]["event_count"] == 1000
        assert self.summary["cases"]["total"] == self.summary["cases"]["resolved"] == 2
        assert self.summary["cases"]["open"] == 0
        assert self.summary["cases"]["endpoint_responses"]["confirmed_effects"] == 4
        self.record(
            "audit_chain_valid_after_manual_endpoint_responses",
            count=self.audit["count"],
        )

    def native_process(self, target, process=None):
        response = target["response_module"]
        native = importlib.import_module(response.__package__ + ".Windows.collector")
        process = process or target["process"]
        original = native._process_rows
        # OS enumeration is real; only the owned test PID reaches the test store.
        rows = [row for row in original() if row["pid"] == process.pid]
        assert len(rows) == 1 and rows[0]["birth"]
        native._process_rows = lambda: rows
        try:
            collector = native.WindowsCollector(emit_initial=True, event_log=False)
            produced = collector._process_events(target["host"])
        finally:
            native._process_rows = original
        assert len(produced) == 1
        identity = response.inspect_process(process.pid, target["host"])
        assert produced[0]["data"]["process"]["guid"] == identity["guid"]
        assert (
            produced[0]["data"]["process"]["start_identity"]
            == identity["start_identity"]
        )
        return produced[0]

    def extra_responses(self):
        analyst = self.clients["qa_analyst"]
        target = self.targets[0]
        target["file"].write_text(
            "Synthetic inert QA file; not malware.\n", encoding="utf-8"
        )
        assert (
            hashlib.sha256(target["file"].read_bytes()).hexdigest() == target["sha256"]
        )
        config = target["endpoint"]["config"]
        self.local_cli(
            target,
            "response-policy",
            [
                "--enable-response",
                "--allow-file-root",
                str(target["file"].parent),
                "--allow-investigation",
                "--allow-quarantine",
                "--allow-restore",
                "--confirm-response-policy",
            ],
        )
        assert {
            "inspect_file",
            "collect_artifact",
            "quarantine_file",
            "restore_file",
        } <= set(target["response_module"].capabilities(config)["actions"])
        case = "/api/incidents/" + target["case_id"]
        current = self.json(analyst, "GET", case)
        self.json(
            analyst,
            "PATCH",
            case,
            json={
                "status": "triage",
                "owner": current["owner"],
                "version": current["version"],
                "note": "Reopened to qualify typed SOAR and reversible evidence response.",
            },
        )
        instance = target["endpoint"]["core"].Agent(config, None)
        instance.heartbeat()
        try:
            for kind in ("inspect_file", "collect_artifact"):
                state = self.json(analyst, "GET", case + "/agent-response")
                command = self.json(
                    analyst,
                    "POST",
                    case + "/agent-response",
                    expected=201,
                    json={
                        "agent_id": target["endpoint"]["public"]["agent_id"],
                        "evidence_event_id": target["response_event_id"],
                        "case_version": state["case_version"],
                        "request_id": "extra-" + kind,
                        "reason": "Owned inert QA file only",
                        "action": {
                            "type": kind,
                            "path": str(target["file"]),
                            "sha256": target["sha256"],
                        },
                    },
                )
                assert instance.poll()
                receipt = self.json(
                    analyst, "GET", "/api/agent-responses/" + command["id"]
                )
                assert (
                    receipt["state"] == "succeeded"
                    and receipt["result"]["success"] is True
                    and receipt["result"]["executed"] is False
                )
                self.command_results.append(receipt)
                if kind == "collect_artifact":
                    artifact_id = receipt["result"]["data"]["server_artifact_id"]
                    downloaded = self.request(
                        analyst,
                        "GET",
                        "/api/endpoint-artifacts/" + artifact_id + "/download",
                    )
                    assert downloaded.content == target["file"].read_bytes()
                    assert (
                        hashlib.sha256(downloaded.content).hexdigest()
                        == target["sha256"]
                    )
                    self.request(
                        self.clients["qa_other_admin"],
                        "GET",
                        "/api/endpoint-artifacts/" + artifact_id + "/download",
                        expected=404,
                    )
            self.record(
                "actual_file_inspection_remote_artifact_verified_bytes_and_tenant_acl"
            )
            endpoint_action = {
                "type": "endpoint_response",
                "agent_id": target["endpoint"]["public"]["agent_id"],
                "evidence_event_id": target["response_event_id"],
                "reason": "Approved typed SOAR on owned inert QA file",
                "action": {
                    "type": "quarantine_file",
                    "path": str(target["file"]),
                    "sha256": target["sha256"],
                },
            }
            restore = json.loads(json.dumps(endpoint_action))
            restore["action"].update(
                type="restore_file",
                quarantine_id={
                    "from_step": "quarantine",
                    "field": "data.quarantine_id",
                },
            )
            book = self.json(
                analyst,
                "POST",
                "/api/playbooks",
                json={
                    "name": "QA typed quarantine restore receipt DAG",
                    "version": 0,
                    "steps": [
                        {"id": "quarantine", "action": endpoint_action},
                        {
                            "id": "restore",
                            "depends_on": ["quarantine"],
                            "action": restore,
                        },
                        {
                            "id": "wrong_branch",
                            "depends_on": ["restore"],
                            "when": {
                                "all": [
                                    {
                                        "step": "restore",
                                        "field": "success",
                                        "op": "eq",
                                        "value": False,
                                    }
                                ]
                            },
                            "action": {"type": "add_note", "note": "Must be skipped"},
                        },
                        {
                            "id": "resolve",
                            "depends_on": ["restore"],
                            "action": {
                                "type": "set_status",
                                "status": "resolved",
                                "note": "Verified quarantine and exact restored bytes",
                            },
                        },
                    ],
                },
            )
            run = self.json(
                analyst,
                "POST",
                "/api/playbooks/" + book["id"] + "/runs",
                json={"incident_id": target["case_id"], "request_id": "typed-qa-flow"},
            )
            path = "/api/playbook-runs/" + run["id"]
            self.request(analyst, "POST", path + "/approve", json={}, expected=403)
            self.json(self.clients["qa_approver"], "POST", path + "/approve", json={})
            self.wait(analyst, path, lambda x: x["state"] == "waiting")
            assert (
                self.json(analyst, "GET", case)["status"] != "resolved"
                and target["file"].exists()
            )
            assert instance.poll()
            assert not target["file"].exists()
            self.record(
                "typed_soar_waits_for_actual_receipt_no_premature_resolve_and_native_quarantine"
            )
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                instance.poll()
                state = self.json(analyst, "GET", path)
                if state["state"] in ("completed", "failed", "unknown"):
                    break
                time.sleep(0.1)
            assert state["state"] == "completed", state["state"]
            assert (
                next(
                    step for step in state["steps"] if step["step_id"] == "wrong_branch"
                )["state"]
                == "skipped"
            )
            assert (
                target["file"].exists()
                and hashlib.sha256(target["file"].read_bytes()).hexdigest()
                == target["sha256"]
            )
            assert self.json(analyst, "GET", case)["status"] == "resolved"
            commands = self.json(analyst, "GET", case + "/agent-response")["commands"]
            typed = [
                command
                for command in commands
                if command["action"]["type"] in ("quarantine_file", "restore_file")
            ]
            assert len(typed) == 2 and all(
                command["state"] == "succeeded"
                and command["result"]["executed"] is True
                for command in typed
            )
            self.command_results.extend(typed)
            self.record(
                "typed_soar_output_receipt_restore_conditional_skip_and_final_resolved"
            )
        finally:
            instance.defense.close()
            instance.queue.close()

    def local_defense(self):
        target = self.targets[0]
        admin = self.clients["qa_admin"]
        name = "qa_release_peer"
        person = {
            "role": "admin",
            "tenant": "default",
            "indexes": ["*"],
            "initial": secrets.token_urlsafe(24),
            "password": secrets.token_urlsafe(24),
        }
        self.details["accounts"][name] = person
        self.json(
            admin,
            "POST",
            "/api/users",
            json={"name": name, "password": person["initial"], "role": "admin"},
        )
        peer = self.login(name)
        config = target["endpoint"]["config"]
        public = target["endpoint"]["public"]
        body = {
            "agent_id": public["agent_id"],
            "request_id": "qa-signed-local",
            "lifetime_hours": 1,
            "rules": [
                {
                    "id": "owned-python",
                    "name": "Owned QA process only",
                    "enabled": True,
                    "action": "terminate_process",
                    "severity": "high",
                    "mitre": ["T1059"],
                    "conditions": [
                        {"field": "host.os.type", "op": "eq", "value": "windows"},
                        {
                            "field": "event.action",
                            "op": "eq",
                            "value": "process_created",
                        },
                        {
                            "field": "process.name",
                            "op": "eq",
                            "value": Path(target["identity"]["executable"]).name,
                        },
                    ],
                }
            ],
        }
        policy = self.json(
            admin, "POST", "/api/xdr/agents/defense-policies", json=body, expected=201
        )
        route = "/api/xdr/agents/defense-policies/" + policy["id"] + "/approve"
        self.request(admin, "POST", route, json={}, expected=403)
        self.json(peer, "POST", route, json={})
        bundle = self.json(
            target["endpoint"]["client"], "POST", "/api/agent/defense-policy", json={}
        )
        process = subprocess.Popen(
            [
                getattr(sys, "_base_executable", sys.executable),
                "-c",
                "import time;time.sleep(900)",
            ],
            cwd=self.directory,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        try:
            native = self.native_process(target, process)
            identity = target["response_module"].inspect_process(
                process.pid, target["host"]
            )
            self.local_cli(
                target,
                "response-policy",
                [
                    "--enable-response",
                    "--allow-process-executable",
                    identity["executable"],
                    "--allow-process-instance",
                    str(identity["pid"]) + ":" + identity["start_identity"],
                    "--allow-termination",
                    "--allow-file-root",
                    str(target["file"].parent),
                    "--allow-investigation",
                    "--allow-quarantine",
                    "--allow-restore",
                    "--confirm-response-policy",
                ],
            )
            self.local_cli(
                target,
                "defense-policy",
                ["--enable-defense", "--confirm-defense-policy"],
            )
            config["agent_id"] = public["agent_id"]
            defense_module = importlib.import_module(
                target["response_module"].__package__ + ".defense"
            )
            engine = defense_module.Defense(config, target["response_module"])
            try:
                engine.update(bundle["bundle"])
                # No network request is made by this evaluation; native identity comes from Toolhelp.
                results = engine.evaluate([native])
                assert (
                    len(results) == 1
                    and results[0]["data"]["local_defense"]["outcome"]["success"]
                    is True
                )
                process.wait(timeout=5)
                assert process.poll() is not None
                repeated = engine.evaluate([native])
                assert repeated == results
                self.record(
                    "peer_signed_policy_verified_pinned_key_offline_reactive_native_process_effect_and_durable_no_replay",
                    native_producer=True,
                    kernel_pre_execution=False,
                )
            finally:
                engine.close()
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
        self.local_cli(
            target, "defense-policy", ["--disable-defense", "--confirm-defense-policy"]
        )
        self.local_cli(
            target,
            "response-policy",
            ["--disable-response", "--confirm-response-policy"],
        )

    def close(self):
        for target in self.targets:
            process = target["process"]
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
        super().close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--stop-after", action="store_true")
    args = parser.parse_args(argv)
    output = args.report.resolve()
    if not (
        output.is_relative_to(base.WORK)
        or output.is_relative_to(base.WORKSPACE / "outputs")
    ):
        parser.error("Report must stay under task work/ or outputs/")
    base.ensure_free(base.TLS_PORT)
    base.ensure_free(base.UI_PORT)
    directory = base.WORK / ("security-flow-" + uuid.uuid4().hex)
    base.private_directory(directory)
    (directory / base.MARKER).write_text("synthetic-only\n", encoding="utf-8")
    base.certificate(directory)
    roles = {
        "qa_admin": ("admin", "default", ["*"]),
        "qa_other_admin": ("admin", "_qa_other", ["*"]),
        "qa_analyst": (
            "analyst",
            "default",
            ["endpoint_windows", "endpoint_linux", "network"],
        ),
        "qa_approver": (
            "analyst",
            "default",
            ["endpoint_windows", "endpoint_linux", "network"],
        ),
        "qa_viewer": (
            "viewer",
            "default",
            ["endpoint_windows", "endpoint_linux", "network"],
        ),
        "qa_windows_reader": ("analyst", "default", ["endpoint_windows"]),
    }
    details = {
        "synthetic_only": True,
        "tls_url": base.BASE,
        "browser_url": base.UI_BASE,
        "accounts": {
            name: {
                "role": role,
                "tenant": tenant,
                "indexes": indexes,
                "password": secrets.token_urlsafe(24),
                **(
                    {"initial": secrets.token_urlsafe(24)}
                    if "admin" not in name
                    else {}
                ),
            }
            for name, (role, tenant, indexes) in roles.items()
        },
    }
    private = directory / "credentials.json"
    private.write_text(json.dumps(details, indent=2), encoding="utf-8")
    service = base.Service(directory)
    trial = Trial(directory, service, details)
    report = {
        "schema": "vatex.lumina.xsera.qualification.v1",
        "product": "Vatex LUMINA xSERA",
        "synthetic_only": True,
        "live_accessed": False,
        "passed": False,
        "started_at": time.time(),
        "transport": {"agent": base.BASE, "verified_ca": True, "gui": base.UI_BASE},
        "limitations": [
            "Synthetic FortiGate records; no physical firewall or real attack.",
            "Windows test-host harmless process/file responses only; native Linux OS execution not qualified.",
            "One-time process termination is not persistent execution prevention or host isolation.",
            "Local and SOAR response require explicit opt-in/exact allowlists and peer approval. Local defense is reactive user mode; no kernel pre-execution claim.",
        ],
    }
    try:
        service.start()
        trial.accounts()
        private.write_text(json.dumps(details, indent=2), encoding="utf-8")
        trial.templates()
        trial.provision_agents()
        trial.prepare_targets()
        trial.endpoint_records()
        trial.network_records()
        trial.detect_mixed()
        trial.respond()
        trial.finish()
        trial.extra_responses()
        trial.local_defense()
        trial.summary = trial.json(
            trial.clients["qa_analyst"],
            "GET",
            "/api/console/summary",
            params={"start": trial.start - 1, "end": time.time() + 1},
        )
        assert trial.summary["telemetry"]["event_count"] == 1000
        assert (
            trial.summary["cases"]["resolved"] == 2
            and trial.summary["cases"]["open"] == 0
        )
        assert trial.summary["cases"]["endpoint_responses"]["confirmed_effects"] == 6
        trial.audit = trial.json(
            trial.clients["qa_admin"], "GET", "/api/audit/integrity"
        )
        assert trial.audit["valid"]
        report.update(
            passed=True,
            console_summary=trial.summary,
            audit=trial.audit,
            native_toolhelp_records=trial.native_rows,
        )
    except Exception as exc:  # noqa: BLE001 - Save redacted failures, never credentials.
        (directory / "failure.private.txt").write_text(
            traceback.format_exc(), encoding="utf-8"
        )
        report["failure"] = {
            "type": type(exc).__name__,
            "message": str(exc)
            if isinstance(exc, (AssertionError, TimeoutError, NotImplementedError))
            else "Inspect private logs.",
            "frames": [
                {"file": Path(x.filename).name, "line": x.lineno, "function": x.name}
                for x in traceback.extract_tb(exc.__traceback__)
            ],
        }
    finally:
        trial.close()
        private.write_text(json.dumps(details, indent=2), encoding="utf-8")
        if args.stop_after or not report["passed"]:
            service.stop()
        report.update(
            checks=trial.checks,
            scenarios=trial.scenarios,
            responses=trial.command_results,
            agent_packages=trial.agent_packages,
            server_starts=service.starts,
            server_retained=bool(report["passed"] and not args.stop_after),
            private_credentials_file=str(private),
            finished_at=time.time(),
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    print(
        json.dumps(
            {
                "passed": report["passed"],
                "checks": len(trial.checks),
                "report": str(output),
            }
        )
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
