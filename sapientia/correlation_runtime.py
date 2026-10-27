"""Frozen indexed-frontier, bounded cross-product reported-flow correlation."""

import json
import math
import time
import uuid

from . import detection_automation, detections, detector_ops, evidence_scope, identity_resolver, migrations, principal, release_manifest, source_registry
from .storage import CapacityError, ConflictError, encode

FIELDS = {"product", "action", "outcome", "flow.src_ip", "flow.dest_ip", "flow.src_port", "flow.dest_port", "process.name", "process.command_line", "actor.uid", "actor.name"}
FIELDS.update({"process.guid","process.start_identity","process.parent_guid","auth.session_id","auth.uid","cloud.account_id","cloud.principal_id","cloud.session_id","cloud.issuer_arn","cloud.service","cloud.action"})
PAGE = 16


def initialize(store):
    migrations.apply_store(store, "correlation_v2", [
        "CREATE TABLE IF NOT EXISTS correlation_plans(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,indexes TEXT NOT NULL,definition TEXT NOT NULL,version INTEGER NOT NULL,enabled INTEGER NOT NULL,completed_seq INTEGER NOT NULL DEFAULT 0,snapshot_seq INTEGER NOT NULL DEFAULT 0,anchor_after INTEGER NOT NULL DEFAULT 0,last_run REAL NOT NULL DEFAULT 0,error TEXT)"])
    migrations.apply_store(store, "correlation_v2", ["ALTER TABLE correlation_plans ADD COLUMN frozen_end REAL NOT NULL DEFAULT 0"], version=2)


def field(projection, path):
    value = projection
    for key in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def matches(projection, step):
    if projection["product"] != step["product"]:
        return False
    for item in step["filters"]:
        actual, expected = field(projection, item["field"]), item["value"]
        if item["op"] == "eq" and (type(actual) is not type(expected) or actual != expected):
            return False
        if item["op"] == "contains" and (not isinstance(actual, str) or not isinstance(expected, str) or expected not in actual):
            return False
    return True


def step_sql(step):
    """Compile the existing literal allowlist, retaining exact JSON scalar type."""
    clauses = ["json_extract(projection,'$.product')=?"]
    args = [step["product"]]
    for item in step["filters"]:
        path = "$."+item["field"]
        expected = item["value"]
        if item["op"] == "contains":
            if not isinstance(expected, str):
                clauses.append("0")
                continue
            clauses.append("json_type(projection,?)='text' AND instr(json_extract(projection,?),?)>0")
            args.extend((path,path,expected))
        else:
            kind = {str:"text", int:"integer", float:"real", bool:"true" if expected else "false"}[type(expected)]
            clauses.append("json_type(projection,?)=? AND json_extract(projection,?)=?")
            args.extend((path,kind,path,expected))
    return " AND ".join("("+c+")" for c in clauses),args


def candidates(db, actor, plan, frontier, end, anchor, step, used=(), store=None, child=False):
    """Two qualified records suffice to establish ambiguity, without a cohort cap."""
    clause,args = step_sql(step)
    low=max(0,end-plan["window"],anchor["event_time"]-plan["within_seconds"])
    high=min(end,anchor["event_time"]+plan["within_seconds"])
    mode=plan.get("relation","flow")
    key=identity_resolver.relation_key(store,actor,anchor,mode)
    exact=" AND json_extract(projection,'$.flow')=?" if mode=="flow" else ""
    rows=db.execute("SELECT * FROM event_projections WHERE tenant=? AND source_id IN (SELECT value FROM json_each(?)) AND seq<=? AND event_time>=? AND event_time<=? AND event_time<? AND json_extract(projection,'$.realm')=?"+exact+" AND "+clause+" ORDER BY event_time,seq",
        (actor["tenant"],encode(plan["sources"]),frontier,low,high,end,anchor["realm"],*([encode(anchor["flow"])] if exact else []),*args))
    found=[]
    for row in rows:
        projection=json.loads(row["projection"])
        linked = identity_resolver.relation_key(store,actor,projection,mode)==key
        if mode=="parent_process" and child:
            linked=bool(identity_resolver.relation_key(store,actor,projection,mode)) and identity_resolver.parent_link(anchor, projection)
        if linked and projection["event_id"] not in used and matches(projection,step):
            found.append((row,projection))
            if len(found)==step.get("max_count",1)+1:
                break
    return found


def validate(data):
    required={"name", "version", "sources", "steps", "window", "within_seconds", "enabled", "case_adapter"}
    if not isinstance(data, dict) or not required<=set(data) or set(data)-required-{"relation","ordered","clock_policy"}:
        raise ValueError("Exact v2 positive-flow plan fields required")
    if not isinstance(data["name"], str) or not 1 <= len(data["name"]) <= 120 or type(data["version"]) is not int or data["version"] < 0 or type(data["enabled"]) is not bool:
        raise ValueError("Typed plan name/version/enabled required")
    if type(data["window"]) is not int or not 30 <= data["window"] <= 86400 or type(data["within_seconds"]) not in (int, float) or not math.isfinite(data["within_seconds"]) or not 0 <= data["within_seconds"] <= 300:
        raise ValueError("Bounded flow time window required")
    if not isinstance(data["sources"], list) or not 1 <= len(data["sources"]) <= 16 or any(not isinstance(s, str) or not 1 <= len(s) <= 128 for s in data["sources"]) or len(set(data["sources"])) != len(data["sources"]):
        raise ValueError("Unique registered sources required")
    if not isinstance(data["steps"], list) or not 1 <= len(data["steps"]) <= 8:
        raise ValueError("Bounded positive flow steps required")
    for step in data["steps"]:
        if not isinstance(step, dict) or not {"product","filters"}<=set(step) or set(step)-{"product","filters","min_count","max_count"} or not isinstance(step["product"], str) or not 1 <= len(step["product"]) <= 128 or not isinstance(step["filters"], list) or len(step["filters"]) > 16:
            raise ValueError("Typed product/filter step required")
        for f in step["filters"]:
            if not isinstance(f, dict) or set(f) != {"field", "op", "value"} or not isinstance(f["field"],str) or f["field"] not in FIELDS or not isinstance(f["op"],str) or f["op"] not in {"eq", "contains"} or type(f["value"]) not in (str, int, bool, float):
                raise ValueError("Unsupported positive-flow filter")
            if isinstance(f["value"], str) and len(f["value"]) > 2048 or type(f["value"]) is float and not math.isfinite(f["value"]):
                raise ValueError("Filter value budget exceeded")
        if type(step.get("min_count",1)) is not int or type(step.get("max_count",1)) is not int or not 1<=step.get("min_count",1)<=step.get("max_count",1)<=32:
            raise ValueError("Role count requires 1 <= min <= max <= 32")
    if sum(s.get("max_count",1) for s in data["steps"])>32 or data.get("relation")=="parent_process" and any(s.get("max_count",1)!=1 for s in data["steps"]):
        raise ValueError("Case role evidence exceeds 32; parent links require exact roles")
    adapter = detection_automation.validate_case_adapter(data["case_adapter"])
    if not isinstance(data.get("relation","flow"),str) or data.get("relation","flow") not in identity_resolver.MODES or type(data.get("ordered",False)) is not bool or not isinstance(data.get("clock_policy","reported"),str) or data.get("clock_policy","reported") not in {"reported","strict"}:
        raise ValueError("Typed relation/order/clock policy required")
    if adapter is None or adapter["entity_field"] != "raw.analysis.resolved_entity":
        raise ValueError("V2 requires explicit derived association entity and Case adapter")
    if len(encode(data)) > 16384:
        raise ValueError("Plan budget exceeded")
    return {**data, "case_adapter": adapter}


def save(store, who, data, identifier=None):
    plan = validate(data)
    with principal.transaction(store, who, ("admin", "analyst"), write=True) as (db, actor):
        sources = [source_registry.visible(db, actor, i) for i in plan["sources"]]
        if any(s["state"] != "active" for s in sources):
            raise ValueError("Active source prerequisites required")
        if {s["product"] for s in sources} != {s["product"] for s in plan["steps"]}:
            raise ValueError("Plan step products differ from registered source prerequisites")
        indexes = sorted({s["index_name"] for s in sources})
        old = db.execute("SELECT * FROM correlation_plans WHERE tenant=? AND id=?", (actor["tenant"], identifier)).fetchone() if identifier else None
        if identifier and (not old or not principal.contains(actor["allowed_indexes"], json.loads(old["indexes"]))):
            raise KeyError("Plan not found")
        if old and (old["version"] != plan["version"] or actor["role"] != "admin" and old["owner"] != actor["name"]) or not old and plan["version"] != 0:
            raise ConflictError("Plan revision/owner changed")
        identifier = identifier or uuid.uuid4().hex
        version = plan["version"] + 1
        definition = {**plan, "version": version, "source_versions": {s["id"]: s["version"] for s in sources}}
        db.execute("INSERT INTO correlation_plans(id,tenant,owner,indexes,definition,version,enabled) VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET definition=excluded.definition,indexes=excluded.indexes,version=excluded.version,enabled=excluded.enabled,completed_seq=0,snapshot_seq=0,anchor_after=0,frozen_end=0,error=NULL", (identifier, actor["tenant"], actor["name"], encode(indexes), encode(definition), version, int(plan["enabled"])))
        store.audit(db, actor["tenant"], actor["name"], "correlation.v2.save", {"id": identifier, "version": version})
        detector_ops.register(db,{"id":"v2:"+identifier+":"+str(version),"tenant":actor["tenant"],"version":version},
                              {**plan["case_adapter"],"steps":[],"evaluation_delay":0},{**actor,"name":old["owner"] if old else actor["name"],"allowed_indexes":indexes},"v2-positive-flow")
        return {"id": identifier, "version": version, "enabled": plan["enabled"], "semantics": "positive_reported_flow_association", "native_capture_proven": False}


def listing(store, who):
    with principal.transaction(store, who) as (db, actor):
        result = []
        for r in db.execute("SELECT * FROM correlation_plans WHERE tenant=? ORDER BY id", (actor["tenant"],)):
            if not principal.contains(actor["allowed_indexes"], json.loads(r["indexes"])):
                continue
            emitted = db.execute("SELECT count(*) FROM risk_contributions WHERE tenant=? AND policy_id=?", (actor["tenant"], "v2:"+r["id"]+":"+str(r["version"]))).fetchone()[0]
            reasons={x[0]:x[1] for x in db.execute("SELECT reason,count(*) FROM detector_diagnostics WHERE tenant=? AND detector_id=? AND version=? GROUP BY reason",(actor["tenant"],r["id"],r["version"]))}
            result.append({"id": r["id"], "version": r["version"], "enabled": bool(r["enabled"]), "definition": json.loads(r["definition"]), "error": r["error"], "last_run": r["last_run"], "emitted_contributions": emitted,"diagnostics":reasons})
        return result


def run_due(store, now=None, cancel=None, budget=.25, max_runs=2):
    now = time.time() if now is None else now
    started, attempted = time.monotonic(), 0
    with store.control(local=True) as db:
        candidates = [dict(r) for r in db.execute("SELECT * FROM correlation_plans WHERE enabled=1 ORDER BY last_run,id LIMIT ?", (min(max_runs, 16),))]
    for item in candidates:
        if cancel is not None and cancel.is_set() or time.monotonic()-started >= budget:
            break
        try:
            _page(store, item, now, cancel, budget)
        except (ValueError, PermissionError, KeyError, CapacityError, RuntimeError) as exc:
            with store.control() as db:
                db.execute("UPDATE correlation_plans SET error=?,last_run=? WHERE id=?", (type(exc).__name__, now, item["id"]))
        attempted += 1
    return attempted


def _page(store, item, now, cancel, budget):
    started = time.monotonic()
    who = {"name": item["owner"], "tenant": item["tenant"], "role": "analyst", "allowed_indexes": json.loads(item["indexes"])}
    with store.segment_lock.read(deadline=time.monotonic()+3), principal.transaction(store, who, ("admin", "analyst"), write=True) as (db, actor):
        current = db.execute("SELECT * FROM correlation_plans WHERE id=?", (item["id"],)).fetchone()
        if not current or not current["enabled"] or current["version"] != item["version"]:
            raise ConflictError("Plan changed before execution")
        plan = json.loads(current["definition"])
        for source_id, version in plan["source_versions"].items():
            source = source_registry.visible(db, actor, source_id)
            if source["state"] != "active" or source["version"] != version:
                raise PermissionError("Source prerequisite changed")
        maximum = db.execute("SELECT coalesce(max(seq),0) FROM event_projections WHERE tenant=? AND source_id IN (SELECT value FROM json_each(?))", (actor["tenant"], encode(plan["sources"]))).fetchone()[0]
        frontier = current["snapshot_seq"] or maximum
        end = current["frozen_end"] or now
        if frontier <= current["completed_seq"]:
            db.execute("UPDATE correlation_plans SET last_run=? WHERE id=?", (now, item["id"]))
            return
        clause,args = step_sql(plan["steps"][0])
        rows = db.execute("SELECT * FROM event_projections WHERE tenant=? AND source_id IN (SELECT value FROM json_each(?)) AND seq<=? AND seq>? AND event_time>=? AND event_time<? AND "+clause+" ORDER BY seq LIMIT ?", (actor["tenant"], encode(plan["sources"]), frontier, current["anchor_after"], max(0,end-plan["window"]), end,*args,PAGE+1)).fetchall()
        anchors = [(r,json.loads(r["projection"])) for r in rows]
        page = anchors[:PAGE]
        processed = []
        for anchor_row, anchor in page:
            if processed and time.monotonic()-started >= budget:
                break
            if cancel is not None and cancel.is_set():
                raise CapacityError("V2 page cancelled")
            processed.append(anchor_row["seq"])
            mode=plan.get("relation","flow")
            def decision(reason, detail=None):
                detector_ops.diagnostic(db,actor,item["id"],item["version"],anchor["event_id"],reason,detail)
            key = identity_resolver.relation_key(store,actor,anchor,mode)
            if not key:
                decision("missing_or_unresolved_identity")
                continue
            # The anchor is also a product role. Two contemporaneous matching
            # endpoint/process reports must not each claim the same network
            # evidence merely because one was chosen as the anchor.
            peers = candidates(db,actor,plan,frontier,end,anchor,plan["steps"][0],store=store)
            first=plan["steps"][0]
            if not first.get("min_count",1)<=len(peers)<=first.get("max_count",1):
                decision("ambiguous_anchor" if peers else "no_anchor")
                continue
            chain = peers
            roles=[list(peers)]
            used = {p["event_id"] for _,p in chain}
            ambiguous = False
            for step in plan["steps"][1:]:
                reference=chain[-1][1] if mode=="parent_process" else anchor
                found = candidates(db,actor,plan,frontier,end,reference,step,used,store=store,child=mode=="parent_process")
                if not step.get("min_count",1)<=len(found)<=step.get("max_count",1):
                    ambiguous = True
                    break
                chain.extend(found)
                roles.append(list(found))
                used.update(p["event_id"] for _,p in found)
            if ambiguous:
                decision("ambiguous_or_missing_peer")
                continue
            if plan.get("ordered"):
                invalid=False
                for (_,previous),(_,following) in zip(chain,chain[1:]):
                    if plan.get("clock_policy")=="strict":
                        a,b=previous.get("clock_precision"),following.get("clock_precision")
                        invalid=type(a) not in (int,float) or type(b) not in (int,float) or previous["event_time"]+a>=following["event_time"]-b
                    else:
                        invalid=previous["event_time"]>=following["event_time"]
                    if invalid:
                        break
                if invalid:
                    decision("order_or_clock_uncertain")
                    continue
            association = identity_resolver.resolve_for_analysis(store, actor, [p for r,p in chain], plan["within_seconds"],mode)
            if association["status"] != "associated":
                decision("identity_"+association["status"])
                continue
            originals = evidence_scope.originals(store, actor, sorted(used))
            for r,p in chain:
                if originals[p["event_id"]]["admission_digest"] != r["receipt_digest"]:
                    raise ConflictError("Projection/original digest changed")
                if release_manifest.digest({k:v for k,v in p.items() if k!="projection_digest"})!=p["projection_digest"]:
                    raise ConflictError("Projection content digest changed")
            entity = ("flow:" if mode=="flow" else mode+":") + key
            events = {o["event_id"]:{"event_id": o["event_id"], "event_time": o["event_time"], "received": o["received"], "host": o["host"], "source": o["source"], "index": o["index_name"], "severity": o["severity"],
                                     **{path:evidence_scope.field(o,path) for path in ("raw.xdr.data.process.guid","raw.xdr.data.process.start_identity","raw.xdr.data.event.timestamp_precision_seconds","raw.security.session_id")}} for o in originals.values()}
            adapter = plan["case_adapter"]
            from .detection_governance import CONTEXT_PATHS

            for ident,event in events.items():
                for path in {p for paths in CONTEXT_PATHS.values() for p in paths}|{"raw.xdr.data.process.code_signature.trusted"}:
                    event[path]=evidence_scope.field(originals[ident],path)
            match = {"entity": entity, "entity_field": adapter["entity_field"], "steps": [{"step":str(i),"product":plan["steps"][i]["product"],"matched":len(role),"events":[events[p["event_id"]] for _,p in role]} for i,role in enumerate(roles)],
                     "event_ids": sorted(used), "indexes": json.loads(current["indexes"]), "window_start": min(o["event_time"] for o in originals.values()), "window_end": end,
                     "risk_weight": adapter["risk_score"], "severity": adapter["severity"], "mitre": adapter["mitre"],
                     "explanation": "Explicit source-reported "+mode+" association; causal ownership and native efficacy remain unproven",
                     "analysis": {"identity": association, "plan_digest": release_manifest.digest(plan), "plan_snapshot":plan,"frontier": frontier}}
            policy = {"id": "v2:"+item["id"]+":"+str(item["version"]), "tenant": actor["tenant"], "name": plan["name"], "version": item["version"]}
            outcome=detections._emit_matches(db, store, policy, {**adapter, "steps": [], "evaluation_delay": 0}, [match], end,
                                     mode="v2-positive-flow", scheduled_end=end, actor=actor["name"], guard=actor, cancel=cancel)
            decision("matched",{"events":len(used),"relation":mode,"ordered":plan.get("ordered",False),"emission":outcome})
        complete = len(anchors) <= len(processed)
        db.execute("UPDATE correlation_plans SET completed_seq=?,snapshot_seq=?,anchor_after=?,frozen_end=?,last_run=?,error=NULL WHERE id=? AND version=?",
                   (frontier if complete else current["completed_seq"], 0 if complete else frontier,
                    0 if complete else processed[-1], 0 if complete else end, now, item["id"], item["version"]))
