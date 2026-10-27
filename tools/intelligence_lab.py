"""Paced 200-event loopback HTTPS lab against disposable xSERA state only."""

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
from tools.qualification import certificate, distribution
from tools.simulation.loggers import ATTACK_IP, HOSTS, PROFILES, Transport, generate
from tools.simulation.run_lab import wait

ORDER=("windows","linux","fortigate","cisco_asa")


class RuntimeEvidence(logging.Handler):
    def __init__(self):
        super().__init__(logging.WARNING)
        self.items=[]

    def emit(self,record):
        message=record.getMessage()
        if len(self.items)<100 and any(word in message.lower() for word in ("worker","indexing","deferred")):
            self.items.append({"at":record.created,"level":record.levelname,"message":message[:500]})


class LabTransport(Transport):
    def request(self,method,path,data=None):
        headers={"Content-Type":"application/json","Origin":self.origin}
        if self.csrf:
            headers["X-CSRF-Token"]=self.csrf
        request=Request(self.origin+path,data=json.dumps(data,allow_nan=False).encode() if data is not None else None,headers=headers,method=method)
        with self.opener.open(request,timeout=45) as reply:
            raw=reply.read(16*1024*1024+1)
            if len(raw)>16*1024*1024:
                raise ValueError("Lab response exceeds 16 MiB")
            return json.loads(raw)

    def post(self,path,data):
        return self.request("POST",path,data)

    def get(self,path):
        return self.request("GET",path)

    def put(self,path,data):
        return self.request("PUT",path,data)


def plan(seed=81213,base_time=None):
    """Labels stay in a separate assessment file; never enter device telemetry."""
    base_time=int(time.time()//60)*60-300 if base_time is None else base_time
    devices,truth={},[]
    for profile in ORDER:
        benign,benign_truth=generate(profile,50,seed=seed,scenario="benign",base_time=base_time)
        mixed,mixed_truth=generate(profile,50,seed=seed,scenario="mixed",base_time=base_time)
        devices[profile]=benign[:25]+mixed[25:]
        labels=benign_truth[:25]+mixed_truth[25:]
        for n,(event,label) in enumerate(zip(devices[profile],labels)):
            instant=base_time+n*4 if n<25 else base_time+120+(n-25)*2
            if "data" in event:
                data=event["data"]
                data["@timestamp"]=datetime.fromtimestamp(instant,UTC).isoformat()
                data["host"]["boot_id"]="virtual-boot-"+profile
                data["event"]["timestamp_precision_seconds"]=.01
                data["event"]["clock_quality"]="synthetic_reported_clock"
                if n:
                    prior=devices[profile][n-1]["data"]["process"]
                    data["process"]["parent"]={"guid":prior["guid"],"start_identity":prior["start_identity"],"name":prior["name"]}
                if label["scenario_label"]=="malicious":
                    first=devices[profile][25]["data"]["process"]
                    # Recurring suspicious connections belong to the same
                    # reported process incarnation, allowing an actual later
                    # contribution to verify a manually merged Case route.
                    if n>25:
                        for key in ("guid","pid","start_identity","parent"):
                            data["process"][key]=copy.deepcopy(first[key])
                        data["event"]["action"]="network_connection"
                    data["process"]["command_line"]+=" # "+"SIMULATED_ARGUMENT "*250
                    data["process"]["depth"]=20
            elif profile=="fortigate":
                parts=event["log"].split(" ",1)
                event["log"]=f"eventtime={int(instant*10**9)} "+parts[1]
                if label["scenario_label"]=="malicious":
                    event["log"]=event["log"].replace("sentbyte=1024","sentbyte=1048576")
            else:
                event["event_time"]=instant
            truth.append({**label,"sequence":n,"reported_time":instant,"training_phase":n<25})
    return devices,truth,float(base_time)


def isolated_paths(work_base,output):
    source_root=Path(__file__).resolve().parents[1]
    production=(source_root/"data").resolve()
    values=[Path(work_base).resolve(),Path(output).resolve()]
    if any(path==production or production in path.parents for path in values):
        raise ValueError("The intelligence lab cannot use production data paths")
    return values


def _signals(owner):
    rows,cursor=[],0
    while True:
        page=owner.get(f"/api/v3/intelligence/signals?cursor={cursor}&count=1000")
        rows.extend(page["items"])
        if page["next_cursor"] is None:
            return rows
        cursor=page["next_cursor"]


def _index_population(owner,profile):
    result=owner.post("/api/search",{"language":"spl","query":f"index=lab_{profile} | stats count as n, dc(event_id) as ids"})
    return result["rows"][0] if result["rows"] else {"n":0,"ids":0}


def _case_for_rule(owner,rule_id):
    for case in owner.get("/api/incidents"):
        detail=owner.get("/api/incidents/"+case["id"])
        if any(c["policy_id"]=="intelligence:"+rule_id+":1" for c in detail["contributions"]):
            return detail
    return None


def run(work_base,output,*,seed=81213,interval=.2):
    if type(interval) not in (int,float) or not .15<=interval<=.25:
        raise ValueError("Use individual-device pacing between .15 and .25 seconds")
    work_base,output=isolated_paths(work_base,output)
    work_base.mkdir(parents=True,exist_ok=True)
    directory=Path(tempfile.mkdtemp(prefix="xsera-intelligence-",dir=work_base))
    events,truth,base=plan(seed)
    (directory/"telemetry.json").write_text(json.dumps(events,ensure_ascii=False,indent=2),encoding="utf-8")
    (directory/"ground-truth.json").write_text(json.dumps(truth,ensure_ascii=False,indent=2),encoding="utf-8")
    result={"schema":"xsera.intelligence-lab.v1","passed":False,"synthetic":True,"native_sensor_collected":False,"host_effects_executed":False,
            "commercial_accuracy_claim":False,"independent_hidden_holdout":False,"labels_transmitted":False,"seed":seed,"per_device":50,
            "work_directory":str(directory),"origin":"verified ephemeral loopback HTTPS","interval_seconds":interval,"checks":[],
            "devices":{p:{"sent":0,"accepted":0,"duplicate":0,"indexed":0} for p in ORDER},"timeline":[]}
    app=server=thread=bound=None
    runtime_evidence=RuntimeEvidence(); logging.getLogger("sapientia").addHandler(runtime_evidence)
    began=time.monotonic()
    try:
        cert,key=certificate(directory)
        password=secrets.token_urlsafe(32)
        inherited={k:v for k,v in os.environ.items() if k.startswith("SAPIENTIA_")}
        try:
            for key_name in inherited:
                os.environ.pop(key_name)
            app=create_app(Settings(directory/"data",min_free_bytes=0,simulation_mode=True),background=True)
        finally:
            os.environ.update(inherited)
        for name in ("lab-owner","lab-peer"):
            auth.create_user(app.state.store,name,password,"admin","default")
        bound=socket.socket(); bound.bind(("127.0.0.1",0)); port=bound.getsockname()[1]
        if port in {8787,8788}:
            raise RuntimeError("Reserved production listeners cannot be used")
        server=uvicorn.Server(uvicorn.Config(app,host="127.0.0.1",port=port,ssl_certfile=str(cert),ssl_keyfile=str(key),log_level="error",access_log=False,timeout_graceful_shutdown=5))
        thread=threading.Thread(target=server.run,kwargs={"sockets":[bound]},daemon=True,name="xsera-intelligence-lab")
        thread.start(); wait(lambda:server.started,bool,timeout=15)
        owner=LabTransport(f"https://127.0.0.1:{port}","lab-owner",password,cert)
        peer=LabTransport(f"https://127.0.0.1:{port}","lab-peer",password,cert)
        current=owner.get("/api/v2/records/management")
        capacity=owner.put("/api/v2/records/management",{"version":current["policy"]["version"],"min_free_percent":1,"cleanup_hysteresis_percent":1,"critical_free_percent":0})
        result["isolated_capacity_policy"]={"min_free_percent":capacity["min_free_percent"],"production_changed":False}
        sources={p:owner.post("/api/v2/sources",{"index":"lab_"+p,"product":p,"account":HOSTS[p],"realm":"virtual-lab","credential_ref":"env:SAPIENTIA_CONNECTOR_VIRTUAL","version":0}) for p in ORDER}
        indexes=["lab_"+p for p in ORDER]
        rules={}
        for p in ORDER:
            definition={"name":"Lab "+p+" destination","kind":"atomic","indexes":["lab_"+p],"version":0,"enabled":True,"severity":"high","window":900,
                        "filters":[{"field":"projection.product","op":"eq","value":p},{"field":"raw.security.dest_ip","op":"eq","value":ATTACK_IP}]}
            if p in {"windows","linux"}:
                definition["case_adapter"]={"entity_field":"raw.analysis.resolved_entity","risk_score":50,"severity":"high","mitre":["T1071.001"],"cooldown":600}
            rules[p]=owner.post("/api/v3/intelligence/policies",definition)
            peer.post("/api/v3/intelligence/policies/"+rules[p]["id"]+"/review",{"version":1,"approve":True,"reason":"Synthetic source and exact original-bound definition reviewed"})
        composite=owner.post("/api/v3/intelligence/policies",{"name":"Lab Windows FortiGate Cisco three-source flow","kind":"composite","indexes":["lab_windows","lab_fortigate","lab_cisco_asa"],"version":0,"enabled":True,"window":900,"join_on":"flow","minimum_independent_groups":3,"ordered":False,
               "inputs":[{"rule_id":rules[p]["id"]} for p in ("windows","fortigate","cisco_asa")],"case_adapter":{"entity_field":"raw.analysis.resolved_entity","risk_score":80,"severity":"high","mitre":["T1071.001"],"cooldown":600}})
        peer.post("/api/v3/intelligence/policies/"+composite["id"]+"/review",{"version":1,"approve":True,"reason":"Three reported flow sources reviewed; association is not native causal proof"})
        result["policies"]={p:r["id"] for p,r in rules.items()}; result["composite_policy"]=composite["id"]
        result["case_reevaluation_config"]=owner.put("/api/v3/cases/reevaluation/config",{"indexes":indexes,"enabled":True,"exact_attachment":True,"interval":30,"version":0})
        checkpoints={p:0 for p in ORDER}; accepted_ids={p:[] for p in ORDER}; wire_to_admitted={}
        timing,ack_ms=[],[]; merge=None; baseline=None; model=None
        for n in range(50):
            if n==25:
                for p in ORDER:
                    wait(lambda p=p:_index_population(owner,p),lambda r:int(r["n"])==25,timeout=60)
                endpoint_ids=[eid for i in range(25) for p in ("windows","linux") for eid in [accepted_ids[p][i]]]
                compatibility=owner.get("/api/v3/ml/status"); result["ml_runtime"]=compatibility
                if compatibility.get("available"):
                    model=owner.post("/api/v3/ml/models",{"name":"Lab normal endpoint CPU model","indexes":["lab_windows","lab_linux"],"training_ids":endpoint_ids[:40],"validation_ids":endpoint_ids[40:],"epochs":80,"normal_training_confirmed":True})
                    if model.get("status")=="completed":
                        peer.post("/api/v3/ml/models/"+model["id"]+"/activate",{"notes":"Forty normal training originals and ten disjoint held-out originals reviewed"})
                        result["cpu_model"]={k:model[k] for k in ("id","digest","revision","metrics","features","threshold")}; result["cpu_model"]["peer_approved"]=True
                    else:
                        result["cpu_model"]={"status":"excluded","compatibility":"시스템에서 호환되지 않음"}; model=None
                else:
                    result["cpu_model"]={"status":"excluded","compatibility":"시스템에서 호환되지 않음"}
                baseline=owner.post("/api/v3/behavior/features/baselines",{"name":"Lab normal network-byte and lineage baseline","entity_field":"host","indexes":indexes,
                          "start":base,"end":base+120,"bucket_seconds":60,"min_samples":10,"min_buckets":2,"min_feature_events":1,"robust_multiplier":3,"byte_fields":["raw.fortigate.sentbyte"]})
                result["ueba_baseline"]={"id":baseline["id"],"digest":baseline["digest"],"ready":baseline["snapshot"]["ready"],"training_events":baseline["snapshot"]["events"]}
                result["checks"].append({"name":"100 benign originals indexed; 40/10 CPU and UEBA training cohorts separated","passed":True})
            if n==41:
                def indexed_frontier():
                    with app.state.store.control() as db:
                        maximum=db.execute("SELECT coalesce(max(seq),0) FROM intelligence_event_outbox").fetchone()[0]
                        cursor=db.execute("SELECT cursor FROM intelligence_cursors WHERE worker='events'").fetchone()[0]
                        return {"maximum":maximum,"cursor":cursor,"complete":maximum==cursor}
                wait(indexed_frontier,lambda r:r["complete"] and r["maximum"]==164,timeout=120)
                windows=wait(lambda:_case_for_rule(owner,rules["windows"]["id"]),bool,timeout=90)
                linux=wait(lambda:_case_for_rule(owner,rules["linux"]["id"]),bool,timeout=90)
                movement=owner.post("/api/incidents/"+windows["id"]+"/merge",{"version":windows["version"],"target_id":linux["id"],"target_version":linux["version"],"reason":"Synthetic analyst review links these training-scenario investigations"})
                merge={"source_id":windows["id"],"target_id":linux["id"],"movement":movement}
            for p in ORDER:
                before=time.monotonic(); sent_at=time.time(); timing.append(before)
                cursor=f"paced:{p}:{n+1}"
                reply=owner.deliver(sources[p]["id"],1,[events[p][n]],cursor,checkpoints[p])
                ack_ms.append((time.monotonic()-before)*1000)
                if reply["accepted"]!=1 or len(reply["event_ids"])!=1:
                    raise AssertionError("One paced wire record did not yield one durable admission")
                checkpoints[p]=reply["checkpoint_version"]
                admitted=reply["event_ids"][0]; accepted_ids[p].append(admitted); wire_to_admitted[events[p][n]["id"]]=admitted
                reported_time=base+n*4 if n<25 else base+120+(n-25)*2
                result["timeline"].append({"sent_at":sent_at,"time_basis":"server admission clock UTC epoch; reported source time separately","device":p,"event_id":admitted,"reported_event_time":reported_time,"admission_ms":ack_ms[-1],"phase":"normal_training" if n<25 else "mixed_evaluation"})
                result["devices"][p]["sent"]+=1; result["devices"][p]["accepted"]+=reply["accepted"]
                time.sleep(max(0,interval-(time.monotonic()-before)))
        # Exact replay of the last cursor leaves the 50-record populations intact.
        for p in ORDER:
            duplicate=owner.deliver(sources[p]["id"],1,[events[p][-1]],f"paced:{p}:50",checkpoints[p]-1)
            result["devices"][p]["duplicate"]=duplicate["duplicate"]
            population=wait(lambda p=p:_index_population(owner,p),lambda r:int(r["n"])==50,timeout=90)
            if int(population["ids"])!=50 or duplicate["duplicate"]!=1:
                raise AssertionError("Idempotent intake or exact indexed population differs")
            result["devices"][p]["indexed"]=50
        result["delivery"]={"admission_ms":distribution(ack_ms),"gap_seconds":distribution([b-a for a,b in zip(timing,timing[1:])]),"wire_records":200,"individual_verified_https_requests":204,
                            "reported_window":{"start":base,"training_end":base+120,"evaluation_end":base+180},"pacing_method":"interleaved individual records; historical normal warm-up then reported attack window"}
        result["checks"].append({"name":"50 Windows + 50 Linux + 50 FortiGate + 50 Cisco paced HTTPS and idempotent retransmission","passed":True})
        signals=wait(lambda:_signals(owner),lambda rows:len([r for r in rows if r["rule_id"]==composite["id"]])==5,timeout=180)
        known={tuple(sorted(wire_to_admitted[events[p][n]["id"]] for p in ("windows","fortigate","cisco_asa"))) for n in range(25,50,5)}
        observed={tuple(sorted(r["event_ids"])) for r in signals if r["rule_id"]==composite["id"]}
        if observed!=known:
            raise AssertionError("Three-source composite original tuples differ from synthetic ground truth")
        result["signals"]={"counts":dict(Counter(s["kind"] for s in signals)),"items":signals,"composites":[s for s in signals if s["rule_id"]==composite["id"]],"original_tuples_match":True}
        result["synthetic_quality"]={"unit":"known three-source original tuple","expected":5,"true_positive":5,"false_negative":0,"unexpected":0,"precision":1.0,"recall":1.0,"sensor_recall_measured":False,"labels_transmitted":False,"independent_holdout":False}
        result["checks"].append({"name":"Atomic signals -> three-source composites -> evidence-bound Cases","passed":True})
        if merge:
            later=accepted_ids["windows"][45]
            def route_check():
                detail=owner.get("/api/incidents/"+merge["target_id"])
                return detail if any(later in c["evidence"].get("event_ids",[]) for c in detail["contributions"]) else None
            updated=wait(route_check,bool,timeout=120)
            result["case_route"]={"source_id":merge["source_id"],"target_id":merge["target_id"],"movement":merge["movement"],"later_event_id":later,
                                  "later_signal_attached_to_target":True,"target_contributions":len(updated["contributions"])}
            result["checks"].append({"name":"Manual Case merge -> later paced Windows original follows reviewed target route","passed":True})
        feature_run=owner.post("/api/v3/behavior/features/baselines/"+baseline["id"]+"/evaluate",{"start":base+120,"end":base+180,"publish":True})
        result["ueba_evaluation"]=feature_run
        if not any(a["feature"]=="network_bytes_out" for a in feature_run.get("anomalies",[])):
            raise AssertionError("Known synthetic network-byte deviation was not found")
        result["checks"].append({"name":"Separate UEBA training/evaluation -> network-byte anomaly -> common Signal","passed":True})
        all_ids=[rule["id"] for rule in rules.values()]+[composite["id"]]
        frozen=owner.post("/api/v3/shadow/intelligence/compare",{"start":base,"end":base+180,"indexes":indexes,"policy_ids":all_ids,
                            **({"candidate_model_id":model["id"]} if model else {})})
        replayed=owner.post("/api/v3/shadow/intelligence/runs/"+frozen["id"]+"/replay",{})
        if not replayed["identical"] or frozen["status"]!="complete":
            raise AssertionError("Full frozen signal/graph/composite/model replay was not identical")
        result["full_shadow"]={"comparison":frozen,"replay":replayed}
        result["checks"].append({"name":"Frozen graph/composite/CPU weight evaluation -> identical evidence/result replay","passed":True})
        result["stories"]=owner.get("/api/v3/intelligence/stories")
        result["cases"]=owner.get("/api/incidents")
        result["case_details"]=[owner.get("/api/incidents/"+case["id"]) for case in result["cases"]]
        result["diagnostics"]=owner.get("/api/v3/intelligence/decisions?count=1000")
        result["case_proposals"]=owner.get("/api/v3/cases/reevaluation/proposals?count=100")
        result["runtime"]=app.state.runtime.health()
        with app.state.store.control() as db:
            result["ml_jobs"]=[dict(r) for r in db.execute("SELECT state,count(*) AS n FROM intelligence_ml_jobs GROUP BY state")]
            result["projection_versions"]=[dict(r) for r in db.execute("SELECT json_extract(projection,'$.version') AS version,count(*) AS n FROM event_projections GROUP BY version")]
            result["story_edges"]=[dict(r) for r in db.execute("SELECT relation,count(*) AS n FROM intelligence_story_edges GROUP BY relation")]
            result["source_receipts"]=db.execute("SELECT count(*) FROM source_event_receipts").fetchone()[0]
            result["ml_runs"]=[json.loads(r[0]) for r in db.execute("SELECT result FROM cpu_ml_runs WHERE tenant='default' ORDER BY created")]
        if model:
            live_ml=wait(lambda:_signals(owner),lambda rows:any(s["kind"]=="ml" for s in rows),timeout=120)
            result["live_ml_anomalies"]=len([s for s in live_ml if s["kind"]=="ml"])
            result["checks"].append({"name":"Reviewed CPU model -> actual asynchronous ML anomaly Signals","passed":True})
        def completed_frontier():
            with app.state.store.control() as db:
                maximum=db.execute("SELECT coalesce(max(seq),0) FROM intelligence_event_outbox").fetchone()[0]
                cursor=db.execute("SELECT cursor FROM intelligence_cursors WHERE worker='events'").fetchone()[0]
                pending=db.execute("SELECT count(*) FROM intelligence_ml_jobs WHERE state='pending'").fetchone()[0]
                return {"maximum":maximum,"cursor":cursor,"pending_model_jobs":pending,"complete":maximum==cursor==200 and pending==0}
        result["completed_frontier"]=wait(completed_frontier,lambda r:r["complete"],timeout=180)
        final_signals=_signals(owner)
        result["signals"]["items"]=final_signals; result["signals"]["counts"]=dict(Counter(s["kind"] for s in final_signals))
        result["runtime"]=app.state.runtime.health()
        with app.state.store.control() as db:
            result["ml_jobs"]=[dict(r) for r in db.execute("SELECT state,count(*) AS n FROM intelligence_ml_jobs GROUP BY state")]
            result["ml_runs"]=[json.loads(r[0]) for r in db.execute("SELECT result FROM cpu_ml_runs WHERE tenant='default' ORDER BY created")]
        if result["runtime"].get("intelligence_worker_error") or result["runtime"].get("error"):
            raise AssertionError("An actual core or intelligence worker error remains")
        result["runtime_warning_events"]=runtime_evidence.items
        result["source_digest"]=release_manifest.build()["source_digest"]
        result["passed"]=True
    except Exception as exc:
        result.update(passed=False,failure_type=type(exc).__name__,failure=str(exc))
        if isinstance(exc,HTTPError):
            result["http_failure_body"]=exc.read(4096).decode("utf-8",errors="replace")
        raise
    finally:
        logging.getLogger("sapientia").removeHandler(runtime_evidence)
        result["runtime_warning_events"]=runtime_evidence.items
        if server:
            server.should_exit=True
        if thread:
            thread.join(timeout=25)
            if thread.is_alive():
                result.update(passed=False,cleanup_failed=True)
                server.force_exit=True
                thread.join(timeout=5)
        elif app:
            app.state.runtime.close(); app.state.store.close()
        if bound:
            bound.close()
        result["server_stopped"]=not thread or not thread.is_alive()
        result["elapsed_seconds"]=round(time.monotonic()-began,3)
        output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text(json.dumps(result,ensure_ascii=False,indent=2,allow_nan=False)+"\n",encoding="utf-8")
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir",type=Path,required=True)
    parser.add_argument("--report",type=Path,required=True)
    parser.add_argument("--seed",type=int,default=81213)
    parser.add_argument("--interval",type=float,default=.2)
    args=parser.parse_args()
    result=run(args.work_dir,args.report,seed=args.seed,interval=args.interval)
    print(json.dumps({"passed":result["passed"],"devices":4,"telemetry":200,"server_stopped":result["server_stopped"]}))


if __name__=="__main__":
    main()
