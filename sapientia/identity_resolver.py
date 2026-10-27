"""Scope-bounded reported-flow association; never grants endpoint authority."""

import json

from . import release_manifest, temporal_identity, principal, entities


def flow_key(projection):
    flow = projection.get("flow")
    if not flow:
        return None
    return release_manifest.digest({"realm": projection["realm"], "flow": flow})


MODES={"flow","bidirectional_flow","process","parent_process","auth_session","cloud_session","approved_entity","approved_nat","device","boot","container","file_object"}


def identity_text(value):
    return isinstance(value,str) and 1<=len(value)<=2048 and all(ord(c)>=32 for c in value) and "[REDACTED]" not in value


def incarnation(projection):
    """Only explicitly reported scope; do not invent host/boot/container IDs."""
    device=projection.get("device",{})
    container=projection.get("container",{})
    return [device.get("uid"),device.get("boot_id"),container.get("uid")]


def parent_link(previous, following):
    a,b=previous.get("process",{}),following.get("process",{})
    if not all(previous.get(k)==following.get(k) for k in ("source_id","account","realm")) or b.get("guid")==a.get("guid") or b.get("parent_guid")!=a.get("guid"):
        return False
    # A supplied incarnation mismatch is never repaired by a shared parent GUID.
    if incarnation(previous)!=incarnation(following):
        return False
    asserted=b.get("parent_start_identity")
    return asserted is None or identity_text(asserted) and asserted==a.get("start_identity")


def relation_key(store, actor, projection, mode="flow"):
    if mode not in MODES:
        raise ValueError("Unsupported identity relation")
    realm=projection["realm"]
    if mode in {"flow","bidirectional_flow"}:
        flow=projection.get("flow")
        if not flow:
            return None
        if mode=="bidirectional_flow":
            reverse={**flow,"src_ip":flow["dest_ip"],"src_port":flow["dest_port"],"dest_ip":flow["src_ip"],"dest_port":flow["src_port"]}
            flow=min((flow,reverse),key=lambda f:json.dumps(f,sort_keys=True))
        return release_manifest.digest({"realm":realm,"flow":flow})
    if mode in {"process","parent_process"}:
        process=projection.get("process",{})
        if not identity_text(process.get("guid")) or not identity_text(process.get("start_identity")):
            return None
        value=[projection["source_id"],projection["account"],process["guid"],process["start_identity"]]
        if any(incarnation(projection)):
            value.append(incarnation(projection))
    elif mode in {"device","boot","container","file_object"}:
        device=projection.get("device",{})
        value=[projection["source_id"],projection["account"]]
        if mode=="device":
            if not identity_text(device.get("uid")):
                return None
            value.append(device["uid"])
        elif mode=="boot":
            if not identity_text(device.get("boot_id")):
                return None
            value.extend([device.get("uid"),device["boot_id"]])
        elif mode=="container":
            container=projection.get("container",{})
            if not identity_text(container.get("uid")):
                return None
            value.extend([device.get("uid"),device.get("boot_id"),container["uid"],container.get("namespace")])
        else:
            file=projection.get("file",{})
            if not all(identity_text(file.get(k)) for k in ("volume_id","object_id","generation")):
                return None
            value.extend([device.get("uid"),*[file[k] for k in ("volume_id","object_id","generation")]])
    elif mode=="auth_session":
        auth=projection.get("auth",{})
        if not identity_text(auth.get("session_id")) or not identity_text(auth.get("uid")):
            return None
        value=[projection["source_id"],auth["account"],auth["uid"],auth["session_id"]]
    elif mode=="cloud_session":
        cloud=projection.get("cloud",{})
        if not all(identity_text(cloud.get(k)) for k in ("account_id","principal_id","session_id","issuer_arn")):
            return None
        value=[cloud[k] for k in ("account_id","principal_id","session_id","issuer_arn")]
    elif mode=="approved_entity":
        address=(projection.get("flow") or {}).get("src_ip")
        user=projection.get("actor",{}).get("name")
        if not address and not user:
            return None
        binding=temporal_identity.resolve(store,actor,"ip" if address else "user",address or user,projection["event_time"])
        if binding["status"]!="resolved":
            return None
        # Multiple session observations remain ambiguous even for one entity.
        sessions={r["binding"]["session_id"] for r in binding["candidates"]}
        if len(sessions)!=1:
            return None
        value=[binding["entity_id"],next(iter(sessions))]
    else:
        flow=projection.get("flow")
        if not flow:
            return None
        from .storage import encode
        with principal.transaction(store,actor) as (db,current):
            rows=db.execute("SELECT * FROM temporal_identity_bindings WHERE tenant=? AND kind='nat' AND state='active' AND valid_from<=? AND valid_until>? AND (lookup_key=? OR json_extract(definition,'$.translated')=?)",
                            (current["tenant"],projection["event_time"],projection["event_time"],encode(flow),encode(flow))).fetchall()
            if len(rows)!=1 or not principal.contains(current["allowed_indexes"],json.loads(rows[0]["indexes"])):
                return None
            row=rows[0]
            entity=entities._visible(db,current,row["entity_id"])
            if json.loads(row["definition"]).get("entity_version")!=entity["version"]:
                return None
            value=[row["id"],row["version"],row["entity_id"],row["session_id"]]
    return release_manifest.digest({"realm":realm,"mode":mode,"value":value})


def resolve_for_analysis(store, actor, projections, within_seconds, mode="flow"):
    if not 0 <= within_seconds <= 300 or len(projections) > 32:
        raise ValueError("Bounded temporal flow resolution required")
    if not projections:
        return {"status":"unresolved","automatic_endpoint_authorization":False}
    keys = {relation_key(store,actor,p,mode) for p in projections}
    times = [p["event_time"] for p in projections]
    parent_chain=mode=="parent_process" and len({p["process"].get("guid") for p in projections})==len(projections) and all(
        parent_link(a,b)
        for a,b in zip(projections,projections[1:]))
    if None in keys or (mode=="parent_process" and not parent_chain) or (len(keys)!=1 and not parent_chain) or max(times)-min(times) > within_seconds:
        return {"status": "unresolved", "automatic_endpoint_authorization": False}
    processes = {(p["source_id"], p["account"], p["process"]["guid"]) for p in projections if identity_text(p["process"].get("guid"))}
    if mode in {"flow","bidirectional_flow","approved_nat"} and len(processes) > 1:
        return {"status": "ambiguous", "automatic_endpoint_authorization": False}
    # Existing analyst-approved temporal observations remain explicit evidence.
    address=(projections[0].get("flow") or {}).get("src_ip")
    binding = temporal_identity.resolve(store, actor, "ip", address, min(times)) if address else {"status":"unresolved"}
    source_id, account, process = next(iter(processes)) if len(processes)==1 else (None, None, None)
    return {"status": "associated", "key": relation_key(store,actor,projections[0],mode), "basis": "exact_reported_five_tuple_and_realm" if mode=="flow" else "scoped_"+mode,
            "grade": "source_reported_temporal_association", "causality_proven": False,
            "process_source": source_id, "account": account, "process_guid": process,
            "approved_identity": binding["entity_id"] if binding["status"] == "resolved" else None,
            "identity_binding_status": binding["status"],
            "relation_mode":mode,
            "links":[{"from":projections[i-1]["event_id"],"to":projections[i]["event_id"],"basis":mode,"realm":projections[i]["realm"]} for i in range(1,len(projections))],
            "evidence": [{"event_id": p["event_id"], "projection_digest": p["projection_digest"], "source_version": p["source_version"]} for p in projections],
            "clock_assurance": "reported_precision" if all(type(p.get("clock_precision")) in (int,float) for p in projections) else "unknown",
            "automatic_endpoint_authorization": False, "native_capture_proven": False}
