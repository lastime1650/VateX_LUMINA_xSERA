"""Versioned CPU semantic/temporal/multi-window gate with exact replay inputs."""

import collections
import json
import math
from pathlib import Path

from . import research_compute_cache
from . import research_features_v2 as features_v2
from .release_manifest import hash_file
from .research_behavior_graph import digest, inputs, process_identity
from .research_fusion import _action

SCHEMA="xsera.research-fusion.v2"
METHOD="cpu_relation_temporal_multihorizon_fusion_v2"
HORIZONS=(3600,86400,604800)
MAX_ORIGINALS=1024
CONTEXT=16
COMPONENTS=("relation","temporal","sketch")
WEIGHTS={key:.55 for key in COMPONENTS}
CONTRACT_DIGEST=digest({"schema":SCHEMA,"implementation":hash_file(Path(__file__)),
    "features":hash_file(Path(__file__).with_name("research_features_v2.py")),
    "worker":hash_file(Path(__file__).with_name("research_v2_worker.py")),"horizons":HORIZONS,
    "maximum_originals":MAX_ORIGINALS,"sketch":"two independent 256-bin rows plus authoritative exact semantic counts"})
COMPATIBLE_CONTRACTS=frozenset({CONTRACT_DIGEST,"4916a91f05d0161cbddcf6cfb14eec4a254177d3483365057fd61f0e88797647"})


def _metadata(row):
    data=inputs(row)
    def calculate():
        role=features_v2.role(row);action=_action(data["action"])
        host=digest([data["source_id"],data["device"],data["realm"],data["account"]]) if all((data["source_id"],data["device"])) else None
        return {"role":role,"action":action,"host":host,"identity":process_identity(data),
            "pattern":json.dumps((role,action,features_v2.target_kind(row)),separators=(",",":"))}
    return research_compute_cache.compute("fusion-metadata:"+CONTRACT_DIGEST,data,calculate)


def host_key(row):
    return _metadata(row)["host"]


def pattern_key(row):return _metadata(row)["pattern"]


def _bins(counts,seed):
    result=[0.0]*256;occupied=collections.defaultdict(set)
    for key,value in counts.items():
        bucket=int(digest([seed,key])[:8],16)%256
        result[bucket]+=value;occupied[bucket].add(key)
    return result,sum(len(v)-1 for v in occupied.values())


def _distance(observed,expected):
    osum=sum(observed.values());esum=sum(expected.values())
    if not osum or not esum:return 0.0
    return sum(abs(observed.get(k,0)/osum-expected.get(k,0)/esum) for k in set(observed)|set(expected))/2


def _distribution(observed,expected,eligible):
    def calculate():
        dual=[];collisions=[]
        for seed in (731,1699):
            observed_bins,oc=_bins(observed,seed);expected_bins,ec=_bins(expected,seed)
            dual.append(_distance(dict(enumerate(observed_bins)),dict(enumerate(expected_bins))) if eligible else 0.0)
            collisions.append(oc+ec)
        return {"exact":_distance(observed,expected) if eligible else 0.0,"dual":dual,"collisions":collisions}
    # Preserve dictionary insertion order as well as counts, retaining the
    # original floating-point reduction order. No baseline or score is learned.
    return research_compute_cache.compute("distribution:"+CONTRACT_DIGEST+":"+str(id(_bins))+":"+str(id(_distance)),
        [list(observed.items()),list(expected.items()),eligible],calculate)


def baseline(rows):
    previous={};transitions=collections.Counter();role_counts=collections.Counter();role_transitions=collections.Counter();gaps=collections.defaultdict(list);patterns=collections.defaultdict(collections.Counter)
    for row in sorted(rows,key=lambda x:(x["event_time"],x["event_id"])):
        meta=_metadata(row);identity=meta["identity"];role=meta["role"];action=meta["action"]
        if not identity:continue
        role_counts[role]+=1;patterns[role][pattern_key(row)]+=1
        old=previous.get(identity)
        if old:
            key=digest([role,old["action"],action]);transitions[key]+=1;role_transitions[role]+=1
            gaps[key].append(max(0,row["event_time"]-old["time"]))
        previous[identity]={"action":action,"time":row["event_time"]}
    return {"schema":SCHEMA,"role_counts":dict(role_counts),"role_transition_counts":dict(role_transitions),"transitions":dict(transitions),
        "gaps":{k:{"median":sorted(v)[len(v)//2],"count":len(v)} for k,v in gaps.items()},
        "patterns":{k:dict(v) for k,v in patterns.items()},"frozen":True,"automatic_learning":False,
        "maximum_originals":MAX_ORIGINALS,"training_originals_digest":digest([r["event_id"] for r in rows])}


def window_metrics(history,reference,row,*,indexed=None,metadata=None):
    meta=metadata if metadata is not None else _metadata(row)
    host=meta["host"];role=meta["role"];at=row["event_time"]
    expected=reference["patterns"].get(role,{})
    result=[]
    for horizon in HORIZONS:
        values=[r for r in (indexed or {}).get((host,role),[]) if at-horizon<=r[0]<=at] if indexed is not None else [(r["event_time"],pattern_key(r)) for r in history if host is not None and host_key(r)==host and features_v2.role(r)==role and at-horizon<=r["event_time"]<=at]
        observed=collections.Counter(r[1] for r in values)
        span=max((r[0] for r in values),default=at)-min((r[0] for r in values),default=at)
        minimum_span=0 if horizon==3600 else horizon*.5
        eligible=bool(host and len(values)>=8 and reference["role_counts"].get(role,0)>=8 and span>=minimum_span)
        statistics=_distribution(observed,expected,eligible)
        result.append({"seconds":horizon,"originals":len(values),"observed_span_seconds":span,"minimum_span_seconds":minimum_span,
            "eligible":eligible,"exact_semantic_distance":statistics["exact"],"dual_sketch_distances":statistics["dual"],"hash_collision_count":statistics["collisions"],
            "collision_correction":"exact canonical semantic pattern counts determine score", "source_completeness_attested":False,
            "observed_fraction_of_horizon":min(1,span/horizon),"full_window_coverage_claimed":False})
    return result


def _facts(history,current_ids,metadata=None):
    current_ids=set(current_ids);previous={};watermarks={};facts={}
    for row in sorted(history,key=lambda r:(r.get("received",r["event_time"]),r["event_time"],r["event_id"])):
        meta=metadata[row["event_id"]] if metadata is not None else _metadata(row)
        identity=meta["identity"];host=meta["host"];at=row["event_time"]
        role=meta["role"];action=meta["action"];old=previous.get(identity) if identity else None
        late=bool(host and host in watermarks and at<watermarks[host])
        facts[row["event_id"]]={"role":role,"action":action,"previous":old,"late":late,"identity_complete":bool(identity),"context_only":row["event_id"] not in current_ids}
        if identity and not late:
            previous[identity]={"action":action,"time":at,"count":(old["count"] if old else 0)+1}
            watermarks[host]=max(at,watermarks.get(host,at))
    return facts


def _score(parts,disabled=()):
    values={k:0.0 if k in disabled else v for k,v in parts.items()}
    return max(max(values.values()),sum(WEIGHTS[k]*v for k,v in values.items()))


def evaluate(rows,scores,model,current_ids,*,history_rows=None):
    if model.get("schema")!=SCHEMA or model.get("contract_digest") not in COMPATIBLE_CONTRACTS:raise ValueError("V2 gate contract changed; retraining and independent review required")
    if not rows or len(rows)>32 or len({r["event_id"] for r in rows})!=len(rows):raise ValueError("1..32 unique v2 inference originals required")
    history={r["event_id"]:r for r in (history_rows or rows)}
    history.update({r["event_id"]:r for r in rows})
    if len(history)>MAX_ORIGINALS:raise ValueError("Long inference raw ancestry exceeds 1024")
    history=list(history.values());metadata={r["event_id"]:_metadata(r) for r in history}
    facts=_facts(history,current_ids,metadata);reference=model["baseline"];result={}
    indexed=collections.defaultdict(list)
    for historical in history:
        meta=metadata[historical["event_id"]]
        indexed[(meta["host"],meta["role"])].append((historical["event_time"],meta["pattern"]))
    for row in rows:
        eid=row["event_id"];fact=facts[eid];old=fact["previous"];role=fact["role"]
        key=digest([role,old["action"] if old else None,fact["action"]]);count=reference["transitions"].get(key,0)
        temporal_ok=bool(fact["identity_complete"] and old and old["count"]>=2 and not fact["late"] and reference["role_transition_counts"].get(role,0)>=7)
        gap=max(0,row["event_time"]-old["time"]) if old else None;normal=reference["gaps"].get(key)
        deviation=0.0
        if normal and gap is not None:
            expected=math.log1p(max(.05,normal["median"]));deviation=min(4.0,abs(math.log1p(max(.05,gap))-expected)/max(.25,expected))
        temporal=max(1.25 if count==0 else 1/(1+count),deviation) if temporal_ok else 0.0
        windows=window_metrics(history,reference,row,indexed=indexed,metadata=metadata[eid])
        sketch_ok=not fact["late"] and fact["identity_complete"] and any(w["eligible"] for w in windows)
        sketch=max((w["exact_semantic_distance"] for w in windows if w["eligible"]),default=0.0) if sketch_ok else 0.0
        ce=float(scores.get(eid,0))
        if not math.isfinite(ce) or ce<0:raise ValueError("Finite v2 relation loss required")
        raw={"relation":ce,"temporal":temporal,"sketch":sketch}
        parts={k:min(4.0,v/model["calibration"][k]) for k,v in raw.items()}
        score=_score(parts);active=not fact["context_only"];anomaly=active and score>model["threshold"]
        reasons=[k+"_above_calibrated_normal" for k,v in parts.items() if v>model["threshold"]]
        if anomaly and not reasons:reasons=["joint_moderate_components_above_calibrated_normal"]
        result[eid]={"schema":SCHEMA,"score":score,"threshold":model["threshold"],"anomaly":anomaly,"components":parts,"raw_components":raw,
            "eligibility":{"relation":True,"temporal":temporal_ok,"sketch":sketch_ok},
            "evidence":{"role":role,"observed_action":fact["action"],"previous_action":old["action"] if old else None,
                "prior_process_observations":old["count"] if old else 0,"normal_transition_count":count,"gap_seconds":gap,
                "late_event":fact["late"],"identity_complete":fact["identity_complete"],"context_only":not active,"windows":windows},
            "reasons":reasons if active else ["context_original_not_republished"],
            "ablations":{"without_"+k:{"score":_score(parts,(k,)),"anomaly":active and _score(parts,(k,))>model["threshold"]} for k in COMPONENTS},
            "baseline_digest":digest(reference),"calibration_digest":digest(model["calibration"]),"malicious_probability":False}
    return result


def fit(training,validation,validation_scores,relation_threshold):
    reference=baseline(training)
    candidate={"schema":SCHEMA,"method":METHOD,"contract_digest":CONTRACT_DIGEST,"baseline":reference,"weights":WEIGHTS,
        "calibration":{"relation":float(relation_threshold),"temporal":1.0,"sketch":1.0},"threshold":1.0,
        "calibration_ids":[r["event_id"] for r in validation],"calibration_method":"chronological normal holdout maximum plus fixed margin; test labels excluded","automatic_learning":False}
    def replay():
        combined={};history=[];ordered=sorted(validation,key=lambda r:(r["event_time"],r["event_id"]))
        for offset in range(0,len(ordered),16):
            batch=ordered[offset:offset+16];history=(history+batch)[-MAX_ORIGINALS:]
            combined.update(evaluate(batch,validation_scores,candidate,[r["event_id"] for r in batch],history_rows=history))
        return combined
    measured=replay()
    candidate["calibration"]["temporal"]=max(.25,max(v["raw_components"]["temporal"] for v in measured.values())+.15)
    candidate["calibration"]["sketch"]=max(.10,max(v["raw_components"]["sketch"] for v in measured.values())+.10)
    measured=replay();candidate["threshold"]=max(1.0,max(v["score"] for v in measured.values())+.1)
    measured=replay()
    candidate["normal_validation"]={"count":len(validation),"anomalies":sum(v["anomaly"] for v in measured.values()),"maximum_score":max(v["score"] for v in measured.values()),
        "component_maxima":{k:max(v["components"][k] for v in measured.values()) for k in COMPONENTS},
        "ablation_anomalies":{k:sum(v["ablations"]["without_"+k]["anomaly"] for v in measured.values()) for k in COMPONENTS}}
    return candidate


def decision(results,mode,model):
    values=[r["fusion"] for r in results if not r["fusion"]["evidence"]["context_only"]]
    return {"method":METHOD,"score":max(v["score"] for v in values),"threshold":model["threshold"],"components":{k:max(v["components"][k] for v in values) for k in COMPONENTS},
        "anomaly":any(v["anomaly"] for v in values),"publishable":mode=="live" and any(v["anomaly"] for v in values),
        "reasons":sorted({r for v in values if v["anomaly"] for r in v["reasons"]}),
        "ablation":{"without_"+k:{"anomaly":any(v["ablations"]["without_"+k]["anomaly"] for v in values)} for k in COMPONENTS},
        "fusion_contract_digest":model["contract_digest"],"malicious_probability":False}
