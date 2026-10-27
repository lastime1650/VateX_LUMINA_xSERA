"""Four independent virtual device processes -> actual loopback HTTPS xSERA."""

import argparse
import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import uvicorn

from sapientia import auth, release_manifest
from sapientia.api import create_app
from sapientia.storage import Settings
from tools.qualification import certificate
from tools.simulation.loggers import ATTACK_IP, HOSTS, PROFILES, Transport, generate


def wait(callback, predicate, timeout=45):
    until = time.monotonic() + timeout
    last = None
    while time.monotonic() < until:
        try:
            last = callback()
            if predicate(last):
                return last
        except (OSError, ValueError):
            pass
        time.sleep(.2)
    raise RuntimeError("Virtual lab stage did not complete within its budget")


def run(work_base, output, *, count=100, seed=17):
    if type(count) is not int or not 5 <= count <= 1000:
        raise ValueError("Virtual cohort requires 5..1000 events per device")
    work_base = Path(work_base).resolve()
    output = Path(output).resolve()
    production = Path(__file__).resolve().parents[2] / "data"
    if work_base == production or production in work_base.parents or output == production or production in output.parents:
        raise ValueError("Virtual lab cannot use production data paths")
    work_base.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="xsera-virtual-", dir=work_base))
    (directory / "virtual-lab.json").write_text('{"synthetic":true,"native_sensor_collected":false}', encoding="utf-8")
    cert, key = certificate(directory)
    password = secrets.token_urlsafe(32)
    config = Settings(directory / "data", min_free_bytes=0, simulation_mode=True)
    # Avoid inheriting remote bridge/agent/SSO configuration into an isolated lab.
    inherited = {k: v for k, v in os.environ.items() if k.startswith("SAPIENTIA_")}
    try:
        for k in inherited:
            os.environ.pop(k)
        app = create_app(config, background=True)
    finally:
        os.environ.update(inherited)
    for name in ("virtual-owner", "virtual-peer"):
        auth.create_user(app.state.store, name, password, "admin", "virtual-lab")
    bound = socket.socket()
    bound.bind(("127.0.0.1", 0))
    port = bound.getsockname()[1]
    if port in {8787, 8788}:
        bound.close()
        app.state.runtime.close()
        app.state.store.close()
        raise RuntimeError("Reserved production listener cannot be used")
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, ssl_certfile=str(cert), ssl_keyfile=str(key), log_level="error", access_log=False, timeout_graceful_shutdown=5))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [bound]}, name="xsera-virtual-https", daemon=True)
    thread.start()
    result = {"schema": "xsera.virtual-lab-result.v1", "synthetic": True, "native_sensor_collected": False,
              "independently_hidden_holdout": False, "host_effects_executed": False,
              "origin": "loopback HTTPS with verified ephemeral CA", "source_digest": release_manifest.build()["source_digest"],
              "seed": seed, "per_device": count, "devices": {}, "checks": []}
    try:
        wait(lambda: server.started, bool, timeout=15)
        owner = Transport(f"https://127.0.0.1:{port}", "virtual-owner", password, cert)
        sources = {}
        for profile in PROFILES:
            sources[profile] = owner.post("/api/v2/sources", {"index": "sim_"+profile, "product": profile,
                "account": HOSTS[profile], "realm": "virtual-lab", "credential_ref": "env:SAPIENTIA_CONNECTOR_VIRTUAL", "version": 0})
        definition = {"name": "Virtual destination IOC across device domains", "entity_field": "raw.security.src_ip",
                      "window": 600, "interval": 30, "cooldown": 0, "mitre": ["T1071.001"],
                      "steps": [{"name": "Observed virtual destination", "filters": [{"field": "raw.security.dest_ip", "op": "eq", "value": ATTACK_IP}]}]}
        policy = owner.post("/api/detections", definition)
        base_time = time.time() - 120
        truth = {p: generate(p, count, seed=seed, base_time=base_time)[1] for p in PROFILES}
        (directory / "ground-truth.json").write_text(json.dumps(truth, indent=2), encoding="utf-8")
        v2_plan = owner.post("/api/v2/correlations", {"name": "Virtual Windows/Cisco/FortiGate exact reported flow", "version": 0,
            "sources": [sources[p]["id"] for p in ("windows", "cisco_asa", "fortigate")], "window": 600, "within_seconds": 2, "enabled": True,
            "steps": [{"product": p, "filters": [{"field": "flow.dest_ip", "op": "eq", "value": ATTACK_IP}]} for p in ("windows", "cisco_asa", "fortigate")],
            "case_adapter": {"entity_field": "raw.analysis.resolved_entity", "risk_score": 60, "severity": "high", "mitre": ["T1071.001"], "cooldown": 0}})
        for profile in PROFILES:
            entries = generate(profile, min(count, 1000), seed=seed, base_time=base_time)[0]
            processes = {e["data"]["process"]["guid"]: {"pid": e["data"]["process"]["pid"], "start_identity": e["data"]["process"]["start_identity"], "alive": True}
                         for e in entries if "data" in e}
            owner.post("/api/v2/simulation/assets", {"source_id": sources[profile]["id"], "asset_id": HOSTS[profile], "processes": processes})
        env = {k: v for k, v in os.environ.items() if not k.startswith("SAPIENTIA_")}
        env.update(SAPIENTIA_SIM_USER="virtual-owner", SAPIENTIA_SIM_PASSWORD=password, PYTHONDONTWRITEBYTECODE="1")

        def launch(profile):
            cmd = [sys.executable, "-B", "-m", "tools.simulation.loggers", "--profile", profile,
                   "--origin", f"https://127.0.0.1:{port}", "--source-id", sources[profile]["id"], "--ca", str(cert),
                   "--count", str(count), "--seed", str(seed), "--base-time", str(base_time), "--shuffle", "--repeat", "2"]
            completed = subprocess.run(cmd, cwd=Path(__file__).resolve().parents[2], env=env, capture_output=True, text=True,
                                       timeout=120, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            if completed.returncode:
                (directory / (profile+"-failure.txt")).write_text(completed.stderr[-16000:], encoding="utf-8")
                raise RuntimeError("Virtual logger failed: " + profile)
            report = json.loads(completed.stdout)
            if report["accepted"] != count or report["duplicates"] != count:
                raise AssertionError("Virtual delivery/retry counts differ")
            return profile, report

        with ThreadPoolExecutor(max_workers=4) as workers:
            for profile, report in workers.map(launch, PROFILES):
                result["devices"][profile] = report
        def population(profile):
            answer = owner.post("/api/search", {"language": "spl", "query": f"index=sim_{profile} | stats count as n, dc(event_id) as ids"})
            return answer["rows"][0] if answer["rows"] else {"n": 0, "ids": 0}
        for profile in PROFILES:
            observed = wait(lambda p=profile: population(p), lambda r: int(r["n"]) == count)
            if int(observed["ids"]) != count:
                raise AssertionError("Duplicate indexed virtual event identity")
            result["devices"][profile]["indexed"] = int(observed["n"])
        result["checks"].append({"name": "four-process HTTPS admission/index/retransmission", "passed": True})
        cases = wait(lambda: owner.get("/api/incidents"), lambda rows: len(rows) >= 2)
        result["cases"] = [{"id": c["id"], "entity": c["entity"], "status": c["status"]} for c in cases]
        result["checks"].append({"name": "actual scheduled detector created Cases", "passed": True})
        expected_chains = (count+4)//5
        v2_status = wait(lambda: owner.get("/api/v2/correlations"), lambda rows: any(r["id"] == v2_plan["id"] and r["emitted_contributions"] == expected_chains for r in rows), timeout=max(45, count*.15))
        result["cross_domain_plan"] = next({"id": r["id"], "emitted_contributions": r["emitted_contributions"], "error": r["error"]} for r in v2_status if r["id"] == v2_plan["id"])
        expected = set()
        for seq in range(0, count, 5):
            ids = []
            for profile in ("windows", "cisco_asa", "fortigate"):
                source_id = truth[profile][seq]["source_event_id"]
                if profile == "windows":
                    # Existing endpoint v1 wire identity, independently computed
                    # from the generator's known original ID (no detector labels).
                    source_id = hashlib.sha256(json.dumps(["aegis.endpoint.v1", HOSTS[profile], source_id], separators=(",", ":")).encode()).hexdigest()
                ids.append(source_id)
            expected.add(tuple(sorted(ids)))
        observed_chains = set()
        for case in owner.get("/api/incidents"):
            if not case["entity"].startswith("flow:"):
                continue
            detail = owner.get("/api/incidents/"+case["id"])
            for contribution in detail["contributions"]:
                if contribution["policy_id"] == "v2:"+v2_plan["id"]+":1":
                    observed_chains.add(tuple(sorted(contribution["evidence"]["event_ids"])))
        tp, fn, fp = len(expected & observed_chains), len(expected-observed_chains), len(observed_chains-expected)
        result["known_scenario_quality"] = {"unit": "three-product original-evidence tuple", "expected_positive": len(expected),
            "true_positive": tp, "false_negative": fn, "unexpected_evidence_tuple": fp, "native": False,
            "holdout": False, "labels_transmitted": False, "commercial_accuracy_claim": False}
        if fn or fp or tp != expected_chains:
            raise AssertionError("Original-evidence tuples differ from known virtual ground truth")
        result["checks"].append({"name": "Windows/Cisco/FortiGate exact reported-flow original-evidence association", "passed": True})
        replay = owner.post("/api/detections/"+policy["id"]+"/replay", {"end": time.time(), "version": 1, "request_id": "virtual-final-evidence"})
        result["detection_replay"] = replay
        # Exercise actual peer-approved SOAR, using local Case actions only.
        book = owner.post("/api/playbooks", {"name": "Virtual investigation", "version": 0,
            "steps": [{"id": "note", "action": {"type": "add_note", "note": "Synthetic virtual device evidence reviewed"}},
                      {"id": "task", "action": {"type": "add_task", "title": "Review virtual source provenance", "mandatory": True}}]})
        run = owner.post("/api/playbooks/"+book["id"]+"/runs", {"incident_id": cases[0]["id"], "request_id": "virtual-soar"})
        peer = Transport(f"https://127.0.0.1:{port}", "virtual-peer", password, cert)
        peer.post("/api/playbook-runs/"+run["id"]+"/approve", {})
        soar = wait(lambda: owner.get("/api/playbook-runs/"+run["id"]), lambda r: r["state"] == "completed")
        result["playbook"] = {"id": run["id"], "state": soar["state"], "peer_approved": True}
        result["checks"].append({"name": "peer approval -> actual SOAR -> Case note/task", "passed": True})
        flow_case = next(c for c in owner.get("/api/incidents") if c["entity"].startswith("flow:"))
        detail = owner.get("/api/incidents/"+flow_case["id"])
        evidence_ids = detail["contributions"][0]["evidence"]["event_ids"]
        virtual_source = sources["windows"]
        asset = owner.get("/api/v2/simulation/assets/"+virtual_source["id"])
        effect = owner.post("/api/v2/incidents/"+flow_case["id"]+"/effects/prepare", {"case_version": detail["version"], "source_id": virtual_source["id"], "source_version": 1,
            "action": "isolate_host", "target": {"asset_id": asset["asset_id"], "asset_version": asset["version"], "lease_seconds": 30}, "event_ids": evidence_ids})
        approved = peer.post("/api/v2/effects/"+effect["id"]+"/approve", {"version": effect["version"]})
        confirmed = owner.post("/api/v2/effects/"+effect["id"]+"/simulate", {"version": approved["version"]})
        model = owner.get("/api/v2/simulation/assets/"+virtual_source["id"])
        if not model["effective_isolated"] or model["state"]["effect_count"] != 1 or confirmed["native_effect"] is not False:
            raise AssertionError("Virtual isolation postcondition differs")
        retry = owner.post("/api/v2/effects/"+effect["id"]+"/simulate", {"version": approved["version"]})
        if not retry["duplicate"]:
            raise AssertionError("Virtual effect was repeated")
        release = owner.post("/api/v2/incidents/"+flow_case["id"]+"/effects/prepare", {"case_version": detail["version"], "source_id": virtual_source["id"], "source_version": 1,
            "action": "release_host", "target": {"asset_id": asset["asset_id"], "asset_version": model["version"], "isolation_id": effect["id"]}, "event_ids": evidence_ids})
        approval = peer.post("/api/v2/effects/"+release["id"]+"/approve", {"version": release["version"]})
        restored = owner.post("/api/v2/effects/"+release["id"]+"/simulate", {"version": approval["version"]})
        model = owner.get("/api/v2/simulation/assets/"+virtual_source["id"])
        if model["effective_isolated"] or model["state"]["effect_count"] != 2:
            raise AssertionError("Owned virtual release postcondition differs")
        result["virtual_response"] = {"isolation": confirmed, "release": restored, "effect_count": 2, "duplicate_reexecution": False, "native_effect": False}
        result["checks"].append({"name": "peer-approved virtual isolation/readback/idempotence/owned release", "passed": True})
        def simulate(profile, action, parameters, selected_case=flow_case, selected_ids=evidence_ids):
            detail = owner.get("/api/incidents/"+selected_case["id"])
            source = sources[profile]
            model = owner.get("/api/v2/simulation/assets/"+source["id"])
            effect = owner.post("/api/v2/incidents/"+selected_case["id"]+"/effects/prepare", {"case_version": detail["version"], "source_id": source["id"], "source_version": 1,
                "action": action, "target": {"asset_id": model["asset_id"], "asset_version": model["version"], **parameters}, "event_ids": selected_ids})
            approved = peer.post("/api/v2/effects/"+effect["id"]+"/approve", {"version": effect["version"]})
            result = owner.post("/api/v2/effects/"+effect["id"]+"/simulate", {"version": approved["version"]})
            if result["state"] != "confirmed" or result["native_effect"] is not False:
                raise AssertionError("Typed virtual effect lacks model readback")
            return result
        # The selected flow Case identifies one exact synthetic process.
        windows_events = generate("windows", count, seed=seed, base_time=base_time)[0]
        selected = next(e for e in windows_events if hashlib.sha256(json.dumps(["aegis.endpoint.v1", HOSTS["windows"], e["id"]], separators=(",", ":")).encode()).hexdigest() in evidence_ids)
        process = selected["data"]["process"]
        terminated = simulate("windows", "terminate_process", {"process_guid": process["guid"], "pid": process["pid"], "start_identity": process["start_identity"]})
        state = owner.get("/api/v2/simulation/assets/"+sources["windows"]["id"])["state"]
        if state["processes"][process["guid"]]["alive"] or state["effect_count"] != 3:
            raise AssertionError("Virtual process termination readback differs")
        network_effects = {}
        for profile in ("cisco_asa", "fortigate"):
            blocked = simulate(profile, "block_ip", {"ip": ATTACK_IP, "lease_seconds": 30})
            state = owner.get("/api/v2/simulation/assets/"+sources[profile]["id"])
            if ATTACK_IP not in state["effective_blocked_ips"]:
                raise AssertionError("Virtual network block not observed")
            unblocked = simulate(profile, "unblock_ip", {"ip": ATTACK_IP, "block_id": blocked["id"]})
            state = owner.get("/api/v2/simulation/assets/"+sources[profile]["id"])
            if state["effective_blocked_ips"] or state["state"]["effect_count"] != 2:
                raise AssertionError("Owned virtual network unblock differs")
            network_effects[profile] = {"block": blocked, "unblock": unblocked, "effect_count": 2}
        # The recent Case list is deliberately capped at 200; use the existing
        # authorized entity-evidence page for the older Linux investigation.
        linux_page = wait(lambda: owner.get("/api/risk/evidence?entity_field=raw.security.src_ip&entity=10.10.0.20&count=1"), lambda r: bool(r["contributions"]))
        linux_contribution = linux_page["contributions"][0]
        linux_case = {"id": linux_contribution["incident_id"]}
        linux_ids = linux_contribution["evidence"]["event_ids"][:32]
        linux_isolate = simulate("linux", "isolate_host", {"lease_seconds": 30}, linux_case, linux_ids)
        linux_release = simulate("linux", "release_host", {"isolation_id": linux_isolate["id"]}, linux_case, linux_ids)
        linux_model = owner.get("/api/v2/simulation/assets/"+sources["linux"]["id"])
        if linux_model["effective_isolated"] or linux_model["state"]["effect_count"] != 2:
            raise AssertionError("Virtual Linux isolation release differs")
        result["virtual_response"].update(terminate_process=terminated, network=network_effects,
            linux={"isolation": linux_isolate, "release": linux_release, "effect_count": 2}, total_confirmed_effects=9, effect_count=3)
        result["checks"].append({"name": "exact virtual process termination and Cisco/FortiGate/Linux owned effects", "passed": True})
        result["passed"] = True
    except Exception as exc:
        result.update(passed=False, failure_type=type(exc).__name__, failure=str(exc))
        raise
    finally:
        server.should_exit = True
        thread.join(timeout=15)
        if thread.is_alive():
            result["passed"] = False
            result["cleanup_failed"] = True
        bound.close()
        result["work_directory"] = str(directory)
        result["elapsed_scope"] = "Generated known scenarios; not native/independent detection accuracy"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False)+"\n", encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--seed", type=int, default=17)
    args = parser.parse_args()
    result = run(args.work_dir, args.report, count=args.count, seed=args.seed)
    print(json.dumps({"passed": result["passed"], "devices": len(result["devices"]), "synthetic": True}))


if __name__ == "__main__":
    main()
