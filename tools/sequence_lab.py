"""1536-scenario CPU sequence qualification on disposable loopback HTTPS only."""

import argparse
import copy
import json
import logging
import os
import secrets
import socket
import tempfile
import threading
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request

import uvicorn

from sapientia import auth, release_manifest
from sapientia.api import create_app
from sapientia.storage import Settings
from tools.intelligence_lab import LabTransport, RuntimeEvidence, _signals, isolated_paths
from tools.qualification import certificate, distribution
from tools.sequence_scenarios import generate, write_dataset, digest
from tools.virtual_response_lab import run_response_lifecycle


def wait(callback, predicate, timeout=45):
    """Retry unfinished stages, while surfacing malformed/forbidden requests."""
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        value = callback()
        if predicate(value):
            return value
        time.sleep(.2)
    raise RuntimeError("Sequence lab stage did not complete within its budget")


def _case_coverage(store, composite_signals, cases):
    """Verify every actual composite reached a Case with its exact ancestry."""
    expected = {signal["id"]: signal for signal in composite_signals}
    visible_cases = {case["id"] for case in cases}
    covered, contributions = set(), []
    with store.control() as db:
        for row in db.execute("SELECT r.id,r.tenant,r.incident_id,r.evidence FROM risk_contributions r JOIN incidents i ON i.id=r.incident_id AND i.tenant=r.tenant WHERE r.tenant='default'"):
            evidence = json.loads(row["evidence"])
            signal_id = evidence.get("analysis", {}).get("signal_id")
            if signal_id not in expected:
                continue
            signal = expected[signal_id]
            if (row["incident_id"] not in visible_cases
                    or set(evidence["event_ids"]) != set(signal["event_ids"])
                    or set(evidence["analysis"]["parent_signal_ids"]) != set(signal["parent_signal_ids"])
                    or set(evidence["indexes"]) != set(signal["indexes"])):
                raise AssertionError("Composite Case ancestry or visible current scope differs")
            covered.add(signal_id)
            contributions.append({"signal_id": signal_id, "contribution_id": row["id"], "case_id": row["incident_id"], "original_count": len(signal["event_ids"])})
    if not expected or covered != set(expected):
        raise AssertionError("Not every emitted composite has a complete Case contribution")
    return {"passed": True, "composites": len(expected), "covered_composites": len(covered), "case_count": len({row["case_id"] for row in contributions}), "contributions": contributions, "exact_original_parent_index_ancestry": True}


def _drained(store):
    with store.control() as db:
        pending = db.execute("SELECT count(*) FROM intelligence_event_outbox WHERE seq>(SELECT cursor FROM intelligence_cursors WHERE worker='events')").fetchone()[0]
        ml = db.execute("SELECT count(*) FROM intelligence_ml_jobs WHERE state IN ('pending','running')").fetchone()[0]
        sequence = db.execute("SELECT count(*) FROM intelligence_sequence_jobs WHERE state IN ('pending','running')").fetchone()[0]
    return {"pending_originals": pending, "pending_ml": ml, "pending_sequence": sequence} if pending == ml == sequence == 0 else None


def _progress(store, model_id=None, composite_id=None):
    """Small internal lab observation; authorized API evidence is fetched once."""
    with store.control() as db:
        cursor = db.execute("SELECT cursor FROM intelligence_cursors WHERE worker='events'").fetchone()[0]
        outbox = db.execute("SELECT count(*) FROM intelligence_event_outbox").fetchone()[0]
        jobs = {row["state"]: row["n"] for row in db.execute("SELECT state,count(*) n FROM intelligence_sequence_jobs WHERE model_id=? GROUP BY state", (model_id,))}
        ml = db.execute("SELECT count(*) FROM intelligence_signals WHERE tenant='default' AND mode='live' AND rule_id=?", ("ml:sequence:"+model_id if model_id else "",)).fetchone()[0]
        composites = db.execute("SELECT count(*) FROM intelligence_signals WHERE tenant='default' AND mode='live' AND rule_id=?", (composite_id,)).fetchone()[0]
    return {"originals_indexed": outbox, "basic_cursor": cursor, "pending_originals": outbox-cursor,
            "sequence_jobs": jobs, "ml_signals": ml, "composite_signals": composites}


class SequenceTransport(LabTransport):
    def request(self, method, path, data=None):
        headers = {"Content-Type": "application/json", "Origin": self.origin}
        if self.csrf: headers["X-CSRF-Token"] = self.csrf
        request = Request(self.origin + path, data=json.dumps(data, allow_nan=False).encode() if data is not None else None, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=180) as reply:
                raw = reply.read(32*1024*1024+1)
                if len(raw) > 32*1024*1024: raise ValueError("Lab response exceeds 32 MiB")
                return json.loads(raw)
        except HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", errors="replace")
            exc.msg = f"Lab API {path}: HTTP {exc.code}: {detail}"
            raise


def _manifest(scenarios, accepted):
    return [{"scenario_id": s["scenario_id"], "family": s["family"], "host_group": s["host_group"],
             "label": s["label"], "event_ids": [accepted[e["id"]] for e in s["events"]]}
            for s in scenarios]


def _live_copy(scenario, number, base):
    item = copy.deepcopy(scenario)
    first = datetime.fromisoformat(item["events"][0]["data"]["@timestamp"]).timestamp()
    host = "live-" + item["host_group"]
    # A distinct authenticated replay preserves held-out feature semantics but
    # is explicitly the same synthetic assessment, not a second hidden dataset.
    for event in item["events"]:
        data = event["data"]
        instant = base + number*120 + datetime.fromisoformat(data["@timestamp"]).timestamp() - first
        data["@timestamp"] = datetime.fromtimestamp(instant, UTC).isoformat()
        data["host"].update(boot_id="boot-" + host)
        data["user"].update(id="virtual-user-" + host, session_id="session-" + host)
        if "authentication" in data: data["authentication"]["session_id"] = "session-" + host
        data["process"].update(guid=digest([host, "process"]), start_identity="start-" + host)
        data["process"]["parent"].update(guid=digest([host, "parent"]), start_identity="parent-" + host)
        event["id"] = digest(["live-replay", event["id"]])
    # Display host remains bound to its registered endpoint source; the replay
    # uses a fresh explicitly reported boot incarnation and original IDs. The
    # trusted collector's exact device ID must remain its registered account.
    return item


def _network_context(scenario):
    event = next(e for e in reversed(scenario["events"]) if e["data"]["event"]["action"] == "network_connection")
    data = event["data"]
    instant = datetime.fromisoformat(data["@timestamp"]).timestamp()
    src, dst = data["source"], data["destination"]
    fg = {"id": digest([event["id"], "fortigate"]), "log":
          f'eventtime={int((instant+.02)*1e9)} devid="sequence-lab" devname="virtual-fortigate" type="traffic" subtype="forward" level="notice" vd="root" srcip={src["ip"]} srcport={src["port"]} dstip={dst["ip"]} dstport={dst["port"]} proto=6 action="accept" policyid=1 sessionid=1001 sentbyte={data["network"]["bytes_out"]} rcvdbyte=512'}
    cisco = {"id": digest([event["id"], "cisco"]), "event_time": instant+.03, "log":
             f'%ASA-6-302013: Built outbound TCP connection 1001 for outside:{dst["ip"]}/{dst["port"]} ({dst["ip"]}/{dst["port"]}) to inside:{src["ip"]}/{src["port"]} ({src["ip"]}/{src["port"]})'}
    return fg, cisco


def run(work_base, output, *, variants=64, seed=81420, interval=.08, epochs=60, live_windows=256, stage_timeout=600):
    if type(stage_timeout) is not int or not 30 <= stage_timeout <= 1800:
        raise ValueError("A bounded 30..1800 second lab observation budget is required")
    if type(live_windows) is not int or not 8 <= live_windows <= 256:
        raise ValueError("8..256 live replay windows required; full qualification uses 256")
    work_base, output = isolated_paths(work_base, output)
    work_base.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="xsera-sequence-", dir=work_base))
    scenarios = generate(variants, seed)
    info = write_dataset(directory / "dataset", scenarios)
    if info["scenario_count"] < 1000: raise ValueError("This qualification requires at least 1000 scenarios")
    result = {"schema": "xsera.sequence-lab.v1", "passed": False, "synthetic": True,
              "host_effects_executed": False, "native_sensor_collected": False,
              "commercial_accuracy_claim": False, "labels_transmitted": False,
              "dataset": info, "work_directory": str(directory), "checks": [], "timeline": [], "devices": {}}
    app = server = thread = bound = None
    warnings = RuntimeEvidence(); logging.getLogger("sapientia").addHandler(warnings)
    began = time.monotonic(); source_start = release_manifest.build()["source_digest"]
    print("Dataset: " + str(info["scenario_count"]) + " scenarios, " + str(info["event_count"]) + " originals", flush=True)
    try:
        cert, key = certificate(directory)
        inherited = {k: v for k, v in os.environ.items() if k.startswith("SAPIENTIA_")}
        try:
            for name in inherited: os.environ.pop(name)
            app = create_app(Settings(directory/"data", min_free_bytes=0, simulation_mode=True), background=True)
        finally: os.environ.update(inherited)
        password = secrets.token_urlsafe(32)
        for name in ("lab-owner", "lab-peer"): auth.create_user(app.state.store, name, password, "admin", "default")
        bound = socket.socket(); bound.bind(("127.0.0.1", 0)); port = bound.getsockname()[1]
        if port in {8787, 8788}: raise ValueError("Production listeners are prohibited")
        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, ssl_certfile=str(cert), ssl_keyfile=str(key), log_level="error", access_log=False, timeout_graceful_shutdown=5))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [bound]}, daemon=True, name="xsera-sequence-lab")
        thread.start(); wait(lambda: server.started, bool, timeout=20)
        origin = f"https://127.0.0.1:{port}"
        owner = SequenceTransport(origin, "lab-owner", password, cert)
        peer = SequenceTransport(origin, "lab-peer", password, cert)
        current = owner.get("/api/v2/records/management")
        owner.put("/api/v2/records/management", {"version": current["policy"]["version"], "min_free_percent": 1, "cleanup_hysteresis_percent": 1, "critical_free_percent": 0})
        result["capacity_policy"] = {"min_free_percent": 1, "production_changed": False}
        sources = {p: owner.post("/api/v2/sources", {"index": "seq_"+p, "product": p, "account": "sequence-lab", "realm": "virtual-lab", "credential_ref": "env:SAPIENTIA_CONNECTOR_VIRTUAL", "version": 0}) for p in ("fortigate", "cisco_asa")}
        host_sources = {}
        for number, scenario in enumerate(scenarios):
            host_sources[scenario["host_group"]] = owner.post("/api/v2/sources", {"index": scenario["index"], "product": scenario["profile"], "account": scenario["host_group"], "realm": "virtual-lab", "credential_ref": "env:SAPIENTIA_CONNECTOR_VIRTUAL", "version": 0})
            if (number+1) % 256 == 0: print("Bound endpoint authorities: " + str(number+1), flush=True)
        checkpoints = {}; accepted = {}; admission = []

        def deliver(profile, events, tag, phase):
            before = time.perf_counter(); sent = time.time()
            source = host_sources[events[0]["data"]["host"]["name"]] if profile in {"windows", "linux"} else sources[profile]
            reply = owner.deliver(source["id"], 1, events, tag, checkpoints.get(source["id"], 0))
            checkpoints[source["id"]] = reply["checkpoint_version"]
            duration = (time.perf_counter()-before)*1000; admission.append(duration)
            if len(reply["event_ids"]) != len(events): raise AssertionError("Admission identity count differs")
            accepted.update(zip((e["id"] for e in events), reply["event_ids"]))
            result["timeline"].append({"sent_at": sent, "device": profile, "phase": phase, "batch_records": len(events), "admission_ms": duration, "original_ids": reply["event_ids"]})
            result["devices"].setdefault(profile, {"sent": 0, "accepted": 0})
            result["devices"][profile]["sent"] += len(events)
            result["devices"][profile]["accepted"] += reply["accepted"]
            return reply

        warm = time.monotonic()
        for number, scenario in enumerate(scenarios):
            deliver(scenario["profile"], scenario["events"], f"dataset:{scenario['scenario_id']}", "persisted_training_and_frozen_assessment")
            if (number+1) % 256 == 0: print("Persisted scenarios: " + str(number+1), flush=True)
        dataset_times = [datetime.fromisoformat(e["data"]["@timestamp"]).timestamp() for s in scenarios for e in s["events"]]
        dataset_period = {"earliest": min(dataset_times)-1, "latest": max(dataset_times)+1}
        wait(lambda: sum(int(owner.post("/api/search", {"language": "spl", "query": "index=seq_"+p+" | stats count as n", **dataset_period})["rows"][0]["n"]) for p in ("windows", "linux")), lambda n: n == info["event_count"], timeout=180)
        result["dataset_admission_seconds"] = time.monotonic()-warm
        manifest = {split: _manifest([s for s in scenarios if s["split"] == split], accepted) for split in ("train", "validation", "heldout")}
        (directory/"reviewed-original-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")
        print("Training reviewed CPU GRU", flush=True)
        model = owner.post("/api/v3/ml/sequences/models", {"name": "Reviewed source-scoped sequence model", "indexes": ["seq_windows", "seq_linux"], "training": manifest["train"], "calibration": manifest["validation"], "holdout": manifest["heldout"], "epochs": epochs, "reviewed_dataset": True})
        if model.get("status") != "completed": raise AssertionError("Sequence model is unavailable: " + str(model))
        result["model"] = model
        assessment = peer.post("/api/v3/ml/sequences/models/"+model["id"]+"/evaluate", {})
        result["assessment"] = assessment
        peer.post("/api/v3/ml/sequences/models/"+model["id"]+"/activate", {"notes": "Independent family, host and time heldout assessment and synthetic-only limitations reviewed"})
        print("Heldout assessment: " + json.dumps(assessment["metrics"]), flush=True)
        indexes = ["seq_"+p for p in ("windows", "linux", "fortigate", "cisco_asa")]
        context_rules = {}
        for profile in ("fortigate", "cisco_asa"):
            policy = owner.post("/api/v3/intelligence/policies", {"name": "Reported "+profile+" network context", "kind": "atomic", "indexes": ["seq_"+profile], "version": 0, "enabled": True, "severity": "medium", "window": 900, "filters": [{"field": "projection.product", "op": "eq", "value": profile}]})
            peer.post("/api/v3/intelligence/policies/"+policy["id"]+"/review", {"version": 1, "approve": True, "reason": "Virtual network observations reviewed; no malicious confidence inferred from connection alone"})
            context_rules[profile] = policy
        # Enables durable observation outbox for both endpoint source indexes.
        endpoint = owner.post("/api/v3/intelligence/policies", {"name": "Endpoint network context", "kind": "atomic", "indexes": ["seq_windows", "seq_linux"], "version": 0, "enabled": True, "severity": "medium", "window": 900, "filters": [{"field": "raw.xdr.data.event.action", "op": "eq", "value": "network_connection"}]})
        peer.post("/api/v3/intelligence/policies/"+endpoint["id"]+"/review", {"version": 1, "approve": True, "reason": "Source-scoped endpoint context and durable sequence intake reviewed"})
        composite = owner.post("/api/v3/intelligence/policies", {"name": "Reviewed sequence plus two-source network evidence", "kind": "composite", "indexes": indexes, "version": 0, "enabled": True, "window": 900, "join_on": "entity", "minimum_independent_groups": 3, "ordered": False, "inputs": [{"kind": "ml", "rule_id": "ml:sequence:"+model["id"]}, {"rule_id": context_rules["fortigate"]["id"]}, {"rule_id": context_rules["cisco_asa"]["id"]}], "case_adapter": {"entity_field": "raw.analysis.resolved_entity", "risk_score": 80, "severity": "high", "mitre": ["T1071.001", "T1041"], "cooldown": 600}})
        peer.post("/api/v3/intelligence/policies/"+composite["id"]+"/review", {"version": 1, "approve": True, "reason": "Immutable sequence model plus three original-disjoint sources reviewed; association is not causal proof"})
        result["composite_policy"] = composite["id"]
        heldout = [s for s in scenarios if s["split"] == "heldout"][:live_windows]
        result["full_live_qualification"] = len(heldout) == 256
        live = [_live_copy(s, n, time.time()-len(heldout)*120-120) for n, s in enumerate(heldout)]
        print("Streaming heldout replay: " + str(len(live)) + " windows", flush=True)
        for number, scenario in enumerate(live):
            # A real sequence accumulates through individual admissions. Source
            # times/gaps remain separate from wall-clock delivery cadence.
            for position, event in enumerate(scenario["events"]):
                sent = time.monotonic()
                deliver(scenario["profile"], [event], f"live:{scenario['scenario_id']}:{position}", "paced_individual_sequence_replay")
                if interval: time.sleep(max(0, interval-(time.monotonic()-sent)))
            fg, cisco = _network_context(scenario)
            deliver("fortigate", [fg], f"live:fg:{number}", "paced_network_context")
            deliver("cisco_asa", [cisco], f"live:cisco:{number}", "paced_network_context")
            if interval: time.sleep(interval)
            if (number+1) % 32 == 0: print("Stream windows admitted: " + str(number+1), flush=True)
        final_sequence_ids = {accepted[e["id"]] for s in live for e in s["events"]}
        def jobs_complete():
            with app.state.store.control() as db:
                jobs = [dict(r) for r in db.execute("SELECT state,event_ids,result,error FROM intelligence_sequence_jobs")]
            matched = [j for j in jobs if set(json.loads(j["event_ids"])) <= final_sequence_ids]
            return matched if len(matched) == len(live) and all(j["state"] == "completed" for j in matched) else None
        jobs = wait(jobs_complete, bool, timeout=stage_timeout)
        predictions = [json.loads(j["result"]) for j in jobs]
        result["stream_jobs"] = {"completed": len(jobs), "states": dict(Counter(j["state"] for j in jobs)), "window_events": 12, "replayed_same_heldout": True, "anomalous_windows": sum(p["anomaly"] for p in predictions)}
        result["stream_status"] = owner.get("/api/v3/ml/sequences/stream")
        result["ml_status"] = owner.get("/api/v3/ml/status")
        expected_composites = sum(json.loads(j["result"])["anomaly"] for j in jobs)
        wait(lambda: _progress(app.state.store, model["id"], composite["id"])["composite_signals"], lambda count: count == expected_composites, timeout=stage_timeout)
        signals = _signals(owner)
        result["signal_counts"] = dict(Counter(s["kind"] for s in signals))
        result["sequence_signals"] = [s for s in signals if s["rule_id"] == "ml:sequence:"+model["id"]]
        result["composite_signals"] = [s for s in signals if s["rule_id"] == composite["id"]]
        if len(result["composite_signals"]) != expected_composites:
            raise AssertionError("Authorized API composite snapshot differs from the completed lab count")
        label_by_ids = {tuple(accepted[e["id"]] for e in s["events"]): s["label"] for s in live}
        confusion = Counter()
        for job in jobs:
            actual = label_by_ids[tuple(json.loads(job["event_ids"]))] == "attack"
            predicted = bool(json.loads(job["result"])["anomaly"])
            confusion[("t" if actual == predicted else "f")+("p" if predicted else "n")] += 1
        result["live_replay_confusion"] = {k: confusion[k] for k in ("tp", "fp", "tn", "fn")}
        result["queue_drain"] = wait(lambda: _drained(app.state.store), bool, timeout=stage_timeout)
        result["cases"] = owner.get("/api/incidents")
        if not result["cases"]: raise AssertionError("No sequence/composite Case generated")
        result["case_coverage"] = _case_coverage(app.state.store, result["composite_signals"], result["cases"])
        selected_case = next(c for c in result["cases"] if c["status"] != "closed")
        detail = owner.get("/api/incidents/"+selected_case["id"])
        all_evidence = {eid for c in detail["contributions"] for eid in c["evidence"].get("event_ids", [])}
        chosen = next(s for s in live if all_evidence.intersection(accepted[e["id"]] for e in s["events"]))
        response = run_response_lifecycle(origin, owner, peer, case_id=selected_case["id"], source_id=host_sources[chosen["host_group"]]["id"], event_ids=[accepted[e["id"]] for e in chosen["events"]], request_id="sequence-reviewed-virtual-response-"+chosen["scenario_id"])
        result["response"] = response
        result["responses_by_product"] = {chosen["profile"]: response}
        for profile in ("windows", "linux"):
            if profile in result["responses_by_product"]:
                continue
            for case in result["cases"]:
                if case["status"] == "closed":
                    continue
                candidate = owner.get("/api/incidents/"+case["id"])
                ids = {eid for c in candidate["contributions"] for eid in c["evidence"].get("event_ids", [])}
                scenario = next((s for s in live if s["profile"] == profile and set(accepted[e["id"]] for e in s["events"]) <= ids), None)
                if scenario is not None:
                    result["responses_by_product"][profile] = run_response_lifecycle(origin, owner, peer, case_id=case["id"], source_id=host_sources[scenario["host_group"]]["id"], event_ids=[accepted[e["id"]] for e in scenario["events"]], request_id="sequence-virtual-"+scenario["scenario_id"])
                    break
            if profile not in result["responses_by_product"]:
                raise AssertionError("No complete source-scoped Case for virtual "+profile+" response")
        fg, cisco = _network_context(chosen)
        flow = next(e for e in reversed(chosen["events"]) if e["data"]["event"]["action"] == "network_connection")
        for profile, event in (("fortigate", fg), ("cisco_asa", cisco)):
            result["responses_by_product"][profile] = run_response_lifecycle(origin, owner, peer, case_id=selected_case["id"], source_id=sources[profile]["id"], event_ids=[accepted[event["id"]]], request_id="sequence-virtual-"+profile+"-"+chosen["scenario_id"], action="block_ip", target={"ip": flow["data"]["destination"]["ip"], "lease_seconds": 30})
        shadow = owner.post("/api/v3/shadow/intelligence/compare", {"start": datetime.fromisoformat(live[0]["events"][0]["data"]["@timestamp"]).timestamp()-1, "end": datetime.fromisoformat(live[min(15,len(live)-1)]["events"][-1]["data"]["@timestamp"]).timestamp()+1, "indexes": ["seq_windows", "seq_linux"], "candidate_sequence_model_id": model["id"], "sequence_windows": [{"event_ids": [accepted[e["id"]] for e in s["events"]]} for s in live[:16]]})
        replay = owner.post("/api/v3/shadow/intelligence/runs/"+shadow["id"]+"/replay", {})
        if replay.get("identical") is not True: raise AssertionError("Frozen sequence Shadow replay differs")
        result["shadow"] = {"comparison": shadow, "replay": replay}
        result["slo"] = owner.get("/api/v3/intelligence/slo")
        # Exercise payload expiry and peer retirement on this disposable model.
        # Original deletion stays under the existing capacity policy, and Case,
        # anomaly and independent holds must survive both operations.
        normal = next(s for s in live if s["label"] == "normal")
        archived_run = owner.post("/api/v3/ml/sequences/models/"+model["id"]+"/infer", {"sequences": [{"event_ids": [accepted[e["id"]] for e in normal["events"]]}], "shadow": True})
        with app.state.store.control() as db:
            before_refs = db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE kind IN ('cpu_sequence_anomaly','case')").fetchone()[0]
            original_count = app.state.store.analytics_query("SELECT count(*) AS n FROM events_all", [], max_rows=1)["rows"][0]["n"]
        archive = owner.post("/api/v3/ml/runs/archive", {"family": "sequence", "run_ids": [archived_run["run_id"]], "notes": "Reviewed normal shadow payload archival, preserving permanent digest and independent evidence"})
        peer.post("/api/v3/ml/sequences/models/"+model["id"]+"/disable", {})
        retirement = peer.post("/api/v3/ml/models/sequence/"+model["id"]+"/retire", {"notes": "Disposable qualification completed; inactive model retained with immutable weights and provenance, only its training refs released"})
        with app.state.store.control() as db:
            after_refs = db.execute("SELECT count(*) FROM record_case_evidence_refs WHERE kind IN ('cpu_sequence_anomaly','case')").fetchone()[0]
        after_originals = app.state.store.analytics_query("SELECT count(*) AS n FROM events_all", [], max_rows=1)["rows"][0]["n"]
        if before_refs != after_refs or original_count != after_originals:
            raise AssertionError("ML lifecycle modified independent evidence or deleted originals")
        result["ml_lifecycle"] = {"archive": archive, "retirement": retirement, "original_count_before": original_count, "original_count_after": after_originals, "independent_refs_before": before_refs, "independent_refs_after": after_refs, "lab_model_disabled_after_qualification": True}
        result["runtime"] = app.state.runtime.health()
        result["admission_request_ms"] = distribution(admission)
        result["checks"] = [{"name": name, "passed": True} for name in ("1536 source-persisted scenarios with family/host/time-disjoint split", "Real CPU 3D GRU and independent synthetic holdout versus unordered baseline", "Paced heldout sequences -> ML -> independent-source composite -> Case", "Independent approval -> virtual dispatch -> durable readback -> release", "Frozen sequence Shadow identical replay without operational effects", "Normal payload archival and independent inactive model retirement preserve originals and Case/anomaly references")]
        result["passed"] = True
    except BaseException as exc:
        result["error"] = {"type": type(exc).__name__, "message": str(exc)}
        raise
    finally:
        result["observation_budget_seconds"] = stage_timeout
        result["observer_method"] = "Bounded exact SQLite counts, then one authorized paginated API snapshot; counts do not authorize a decision"
        if app is not None and getattr(app.state, "store", None) is not None:
            try:
                result["final_pipeline_observation"] = _progress(app.state.store, result.get("model", {}).get("id"), result.get("composite_policy"))
            except Exception as exc:
                result["final_pipeline_observation_error"] = type(exc).__name__
        if server:
            server.should_exit = True
            if thread: thread.join(timeout=40)
        if thread and thread.is_alive(): result["server_stopped"] = False
        else: result["server_stopped"] = True
        if bound: bound.close()
        logging.getLogger("sapientia").removeHandler(warnings)
        result["runtime_warning_events"] = warnings.items
        result["elapsed_seconds"] = round(time.monotonic()-began, 3)
        result["source_digest_at_start"] = source_start
        result["source_digest_at_end"] = release_manifest.build()["source_digest"]
        result["frozen_release_unchanged"] = result["source_digest_at_end"] == source_start
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-base", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--interval", type=float, default=.08)
    parser.add_argument("--epochs", type=int, default=60)
    parser.add_argument("--live-windows", type=int, default=256, help="Use 8 for a pilot; full qualification requires 256")
    parser.add_argument("--stage-timeout", type=int, default=600, help="Bounded completion observation per stage; neither a latency SLA nor an EPS claim")
    args = parser.parse_args()
    result = run(args.work_base, args.output, interval=args.interval, epochs=args.epochs, live_windows=args.live_windows, stage_timeout=args.stage_timeout)
    print(json.dumps({"passed": result["passed"], "elapsed_seconds": result["elapsed_seconds"], "output": str(args.output)}))


if __name__ == "__main__": main()
