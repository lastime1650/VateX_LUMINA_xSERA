"""Role-scoped, leave-one-entity-out immutable peer profiles.

Peer roles are explicit analyst configuration, not untrusted log assertions.
Robust dispersion is explainable; it is not a calibrated malware probability.
"""
import math
import statistics


def configure(data):
    groups=data.get("peer_groups",{})
    if not isinstance(groups,dict) or any(not isinstance(k,str) or not 1<=len(k)<=256 or not isinstance(v,str) or not 1<=len(v)<=128 or any(ord(c)<32 for c in k+v) for k,v in groups.items()):
        raise ValueError("Explicit typed entity-to-peer-role mapping required")
    minimum=data.get("peer_min_entities",3)
    if type(minimum) is not int or not 2<=minimum<=1000:
        raise ValueError("Peer minimum must be 2..1000")
    if data.get("count_method")=="peer_robust_mad" and not groups:
        raise ValueError("Peer model requires explicit roles")
    return {"peer_groups":dict(groups),"peer_min_entities":minimum}


def profile(snapshot, definition, entity, slot=None):
    role=definition.get("peer_groups",{}).get(entity)
    peers=[]
    excluded=[]
    values=[]
    if role:
        for name,model in sorted(snapshot["models"].items()):
            if name==entity or definition["peer_groups"].get(name)!=role:
                continue
            selected=model.get("seasonal_slots",{}).get(str(slot)) if slot is not None else model
            if not model.get("ready") or model.get("quality",{}).get("review_required") or not selected or not selected.get("ready",model["ready"]):
                excluded.append(name)
                continue
            value=selected["median"]
            if not math.isfinite(value):
                raise ValueError("Invalid immutable peer statistic")
            peers.append(name)
            values.append(value)
    minimum=definition.get("peer_min_entities",3)
    ready=len(values)>=minimum
    median=statistics.median(values) if ready else None
    mad=statistics.median(abs(v-median) for v in values) if ready else None
    return {"ready":ready,"role":role,"peer_entities":peers,"excluded_entities":excluded,"peer_denominator":len(values),
            "minimum":minimum,"median":median,"mad":mad,
            "threshold":median+definition.get("robust_multiplier",3)*max(1,1.4826*mad) if ready else None,
            "leave_target_out":True,"probability_calibrated":False,
            "qualification":"statistical deviation; native efficacy unverified"}
