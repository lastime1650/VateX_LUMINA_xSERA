"""Frozen-normal CPU relation/temporal/sketch fusion, not a paper reproduction.

Only explicitly selected normal training originals build the reference. Runtime
observations never update it. Every rolling input is retained as an original
reference in the run; no opaque mutable statistic can authorize a live signal.
"""

import math
from collections import Counter, defaultdict
from pathlib import Path

from .release_manifest import hash_file
from .research_behavior_graph import (
    action_class,
    digest,
    inputs,
    normalize_path,
    process_identity,
)

SCHEMA = "xsera.research-fusion.v1"
METHOD = "cpu_relation_temporal_sketch_fusion_v1"
CONTEXT = 16
WINDOW_MIN = 8
MIN_NORMAL_IMAGE = 8
MIN_NORMAL_TRANSITIONS = 7
HALF_LIFE = 86400
COMPONENTS = ("relation", "temporal", "sketch")
WEIGHTS = {key: .55 for key in COMPONENTS}
CONTRACT_DIGEST = digest({"schema":SCHEMA,"implementation":hash_file(Path(__file__)),
    "formula":"max(max(eligible normalized components),0.55*sum(eligible normalized components))",
    "context":CONTEXT,"window_min":WINDOW_MIN,"half_life":HALF_LIFE})


def _image(row):
    return normalize_path(inputs(row)["image"])


def _action(value):
    # Preserve the 0.17 CE taxonomy in research_behavior_graph. New fusion
    # baselines and runtime statistics use the canonical process-create meaning.
    return "execute" if value in {"process_create", "process_created", "process_creation"} else action_class(value)


def _bucket(row):
    value=inputs(row)
    target=value["registry"] or value["file"] or ("network" if value["dest_ip"] else "observation")
    return int(digest([normalize_path(value["image"]),normalize_path(target),_action(value["action"])])[:8],16)%128


def _histogram(rows):
    bins=[0.0]*128
    end=max((r["event_time"] for r in rows),default=0)
    for row in rows:
        bins[_bucket(row)]+=.5**(min(max(0,end-row["event_time"]),30*HALF_LIFE)/HALF_LIFE)
    total=sum(bins)
    return [v/total if total else 0.0 for v in bins]


def baseline(rows):
    previous={};transitions=Counter();images=Counter();image_transitions=Counter();gaps=defaultdict(list)
    trusted=[]
    for row in sorted(rows,key=lambda r:(r["event_time"],r["event_id"])):
        data=inputs(row);identity=process_identity(data);image=_image(row)
        if not identity:continue
        trusted.append(row);images[image]+=1
        action=_action(data["action"])
        old=previous.get(identity)
        if old:
            key=digest([image,old["action"],action]);transitions[key]+=1
            image_transitions[image]+=1
            gaps[key].append(max(0,row["event_time"]-old["time"]))
        previous[identity]={"action":action,"time":row["event_time"]}
    return {"schema":SCHEMA,"observations":len(trusted),"image_counts":dict(images),"image_transition_counts":dict(image_transitions),
        "transitions":dict(transitions),"gaps":{k:{"median":sorted(v)[len(v)//2],"maximum":max(v),"count":len(v)} for k,v in gaps.items()},
        "bins":_histogram(trusted),"size":128,"half_life_seconds":HALF_LIFE,
        "frozen":True,"automatic_learning":False,"training_originals_digest":digest([r["event_id"] for r in rows])}


def _raw(rows,reference,current_ids):
    previous={};history=[];result={};current_ids=set(current_ids)
    watermark=None
    # Context is replayed first; a later-arriving old event must not silently
    # become timely merely because sorting moves it before established context.
    context=sorted((r for r in rows if r["event_id"] not in current_ids),key=lambda r:(r["event_time"],r["event_id"]))
    current=sorted((r for r in rows if r["event_id"] in current_ids),
        key=lambda r:(r.get("received",r["event_time"]),r["event_time"],r["event_id"]))
    for row in context+current:
        data=inputs(row);identity=process_identity(data);image=_image(row)
        action=_action(data["action"]);at=row["event_time"];old=previous.get(identity) if identity else None
        late=bool(watermark is not None and at<watermark)
        temporal_ok=bool(identity and old and old["count"]>=2 and not late and reference["image_counts"].get(image,0)>=MIN_NORMAL_IMAGE
            and reference["image_transition_counts"].get(image,0)>=MIN_NORMAL_TRANSITIONS)
        key=digest([image,old["action"] if old else None,action])
        count=reference["transitions"].get(key,0)
        gap=max(0,at-old["time"]) if old else None
        gap_reference=reference["gaps"].get(key)
        gap_score=0.0
        if gap_reference and gap is not None:
            # Multiplicative deviation; ordinary floating point timestamp noise
            # below 50ms does not count as changed cadence.
            actual=math.log1p(max(.05,gap));normal=math.log1p(max(.05,gap_reference["median"]))
            gap_score=min(4.0,abs(actual-normal)/max(.25,normal))
        temporal=max((1.25 if count==0 else 1/(1+count)),gap_score) if temporal_ok else 0.0
        admitted=bool(identity and not late)
        candidate=(history+[row])[-CONTEXT:] if admitted else history
        sketch_ok=bool(admitted and len(candidate)>=WINDOW_MIN and reference["observations"]>=16)
        distribution=_histogram(candidate) if sketch_ok else [0.0]*128
        sketch=sum(abs(a-b) for a,b in zip(distribution,reference["bins"]))/2 if sketch_ok else 0.0
        result[row["event_id"]]={"raw":{"temporal":temporal,"sketch":sketch},
            "eligibility":{"relation":True,"temporal":temporal_ok,"sketch":sketch_ok},
            "evidence":{"same_process_incarnation":bool(identity and old),"prior_process_observations":old["count"] if old else 0,
                "normal_image_support":reference["image_counts"].get(image,0),"normal_transition_count":count,
                "normal_image_transition_support":reference["image_transition_counts"].get(image,0),
                "novel_transition":count==0,"gap_seconds":gap,"gap_deviation":gap_score,
                "late_event":late,"window_originals":len(candidate),"identity_complete":bool(identity),
                "context_only":row["event_id"] not in current_ids}}
        if admitted:
            previous[identity]={"action":action,"time":at,"count":(old["count"] if old else 0)+1}
            history=candidate;watermark=max(at,watermark if watermark is not None else at)
    return result


def _score(components,disabled=()):
    values={k:(0.0 if k in disabled else components[k]) for k in COMPONENTS}
    return max(max(values.values()),sum(WEIGHTS[k]*v for k,v in values.items()))


def fit(training,validation,validation_scores,relation_threshold):
    reference=baseline(training)
    context=sorted(training,key=lambda r:(r["event_time"],r["event_id"]))[-CONTEXT:]
    ids=[r["event_id"] for r in validation]
    def replay(model=None):
        history=list(context);combined={}
        ordered=sorted(validation,key=lambda r:(r["event_time"],r["event_id"]))
        for offset in range(0,len(ordered),CONTEXT):
            batch=ordered[offset:offset+CONTEXT];current=[r["event_id"] for r in batch]
            value=evaluate(history+batch,validation_scores,model,current) if model else _raw(history+batch,reference,current)
            combined.update({eid:value[eid] for eid in current})
            history=(history+batch)[-CONTEXT:]
        return combined
    raw=replay()
    calibration={"relation":float(relation_threshold),
        "temporal":max(.25,max((v["raw"]["temporal"] for v in raw.values() if not v["evidence"]["context_only"]),default=0)+.15),
        "sketch":max(.10,max((v["raw"]["sketch"] for v in raw.values() if not v["evidence"]["context_only"]),default=0)+.10)}
    candidate={"schema":SCHEMA,"method":METHOD,"contract_digest":CONTRACT_DIGEST,"baseline":reference,
        "calibration":calibration,"weights":WEIGHTS,"threshold":1.0,
        "calibration_ids":ids,"calibration_end":max(r["event_time"] for r in validation),
        "calibration_method":"normal chronological holdout maximum plus margin; no attack/test label use",
        "automatic_learning":False,"relation_threshold":float(relation_threshold)}
    evaluated=replay(candidate)
    candidate["threshold"]=max(1.0,max((x["score"] for x in evaluated.values() if not x["evidence"]["context_only"]),default=0)+.10)
    evaluated=replay(candidate)
    candidate["normal_validation"]={"count":len(validation),"anomalies":sum(v["anomaly"] for v in evaluated.values()),
        "maximum_score":max((v["score"] for v in evaluated.values() if not v["evidence"]["context_only"]),default=0),
        "component_maxima":{k:max((v["components"][k] for v in evaluated.values() if not v["evidence"]["context_only"]),default=0) for k in COMPONENTS},
        "ablation_anomalies":{k:sum(v["ablations"]["without_"+k]["anomaly"] for v in evaluated.values()) for k in COMPONENTS}}
    return candidate


def evaluate(rows,scores,model,current_ids):
    if model.get("schema")!=SCHEMA or model.get("contract_digest")!=CONTRACT_DIGEST or model.get("weights")!=WEIGHTS:
        raise ValueError("Fusion contract changed; explicit training and independent review required")
    if len(rows)>32 or len({r["event_id"] for r in rows})!=len(rows):
        raise ValueError("Fusion requires at most 32 unique original inputs")
    raw=_raw(rows,model["baseline"],current_ids);result={}
    for row in rows:
        eid=row["event_id"];facts=raw[eid];ce=float(scores.get(eid,0))
        if not math.isfinite(ce) or ce<0:raise ValueError("Finite nonnegative relation loss required")
        parts={"relation":min(4.0,ce/model["calibration"]["relation"]),
            **{k:min(4.0,facts["raw"][k]/model["calibration"][k]) if facts["eligibility"][k] else 0.0 for k in ("temporal","sketch")}}
        score=_score(parts);eligible=not facts["evidence"]["context_only"]
        threshold=model["threshold"];anomaly=eligible and score>threshold
        reasons=[k+"_above_calibrated_normal" for k,v in parts.items() if v>threshold]
        if anomaly and not reasons:reasons=["joint_moderate_components_above_calibrated_normal"]
        result[eid]={"schema":SCHEMA,"score":score,"threshold":threshold,"anomaly":anomaly,
            "components":parts,"raw_components":{"relation":ce,**facts["raw"]},"eligibility":facts["eligibility"],
            "evidence":facts["evidence"],"reasons":reasons if eligible else ["context_original_not_republished"],
            "joint_score":sum(WEIGHTS[k]*v for k,v in parts.items()),
            "ablations":{"without_"+k:{"score":_score(parts,(k,)),"anomaly":eligible and _score(parts,(k,))>threshold} for k in COMPONENTS},
            "baseline_digest":digest(model["baseline"]),"calibration_digest":digest(model["calibration"]),"malicious_probability":False}
    return result


def decision(results,mode,model):
    values=[r["fusion"] for r in results if not r["fusion"]["evidence"]["context_only"]]
    return {"method":METHOD,"score":max(v["score"] for v in values),"threshold":model["threshold"],
        "components":{k:max(v["components"][k] for v in values) for k in COMPONENTS},
        "anomaly":any(v["anomaly"] for v in values),"publishable":mode=="live" and any(v["anomaly"] for v in values),
        "reasons":sorted({reason for v in values if v["anomaly"] for reason in v["reasons"]}),
        "ablation":{"without_"+k:{"anomaly":any(v["ablations"]["without_"+k]["anomaly"] for v in values)} for k in COMPONENTS},
        "fusion_contract_digest":CONTRACT_DIGEST,"malicious_probability":False}
