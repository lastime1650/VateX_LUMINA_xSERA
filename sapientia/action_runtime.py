"""Peer-approved virtual-device effects; this module never mutates a host/appliance."""

import json
import time

from . import action_registry, effect_receipts, evidence_scope, migrations, principal, release_manifest, source_registry
from .storage import ConflictError, encode


def initialize(store):
    migrations.apply_store(store, "action_runtime", [
        "CREATE TABLE IF NOT EXISTS virtual_assets(tenant TEXT NOT NULL,source_id TEXT NOT NULL,asset_id TEXT NOT NULL,source_version INTEGER NOT NULL,state TEXT NOT NULL,version INTEGER NOT NULL,updated REAL NOT NULL,PRIMARY KEY(tenant,source_id))"])


def require_simulation(store):
    if getattr(store.settings, "simulation_mode", False) is not True:
        raise PermissionError("Virtual effects require an explicitly isolated simulation instance")


def create_asset(store, who, data):
    require_simulation(store)
    if not isinstance(data, dict) or set(data) != {"source_id", "asset_id", "processes"} or not isinstance(data["processes"], dict) or len(data["processes"]) > 1000 or len(encode(data)) > 512*1024:
        raise ValueError("Bounded virtual asset definition required")
    for guid, process in data["processes"].items():
        if not isinstance(guid, str) or not 1 <= len(guid) <= 256 or not isinstance(process, dict) or set(process) != {"pid", "start_identity", "alive"} or type(process["pid"]) is not int or not 1 <= process["pid"] < 2**32 or type(process["alive"]) is not bool or not isinstance(process["start_identity"], str) or not 1 <= len(process["start_identity"]) <= 256:
            raise ValueError("Exact virtual process identity required")
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        source = source_registry.visible(db, actor, data["source_id"])
        if source["state"] != "active" or source["realm"] != "virtual-lab" or source["account"] != data["asset_id"]:
            raise PermissionError("Virtual asset differs from source authority")
        if db.execute("SELECT 1 FROM virtual_assets WHERE tenant=? AND source_id=?", (actor["tenant"], source["id"])).fetchone():
            raise ConflictError("Virtual asset already exists; cannot reset its effect history")
        state = {"processes": data["processes"], "isolation": None, "blocked_ips": {}, "effect_count": 0}
        db.execute("INSERT INTO virtual_assets VALUES(?,?,?,?,?,1,?)", (actor["tenant"], source["id"], data["asset_id"], source["version"], encode(state), time.time()))
        store.audit(db, actor["tenant"], actor["name"], "virtual.asset.create", {"source_id": source["id"]})
        return {"asset_id": data["asset_id"], "version": 1, "mode": "virtual", "native_effect": False, "synthetic_hardware_effect": True}


def asset(store, who, source_id):
    require_simulation(store)
    with principal.transaction(store, who) as (db, actor):
        source_registry.visible(db, actor, source_id)
        row = db.execute("SELECT * FROM virtual_assets WHERE tenant=? AND source_id=?", (actor["tenant"], source_id)).fetchone()
        if not row:
            raise KeyError("Virtual asset not found")
        state = json.loads(row["state"])
        return {"asset_id": row["asset_id"], "version": row["version"], "state": state, "mode": "virtual", "native_effect": False, "synthetic_hardware_effect": True,
                "effective_isolated": bool(state["isolation"] and state["isolation"]["expires"] > time.time()),
                "effective_blocked_ips": sorted(ip for ip, value in state["blocked_ips"].items() if value["expires"] > time.time())}


def dispatch(store, who, identifier, expected_version):
    require_simulation(store)
    with store.segment_lock.read(deadline=time.monotonic()+3), store.write_lock:
        with principal.transaction(store, who, ("admin", "analyst")) as (db, actor):
            effect = effect_receipts.visible(db, actor, identifier)
            if effect["state"] == "confirmed":
                proof = db.execute("SELECT proof FROM effect_receipt_history WHERE id=? AND state='confirmed' ORDER BY version DESC LIMIT 1", (identifier,)).fetchone()
                return {"id": identifier, "state": "confirmed", "version": effect["version"], "duplicate": True, **(json.loads(proof[0]) if proof else {}), "mode": "virtual", "native_effect": False, "synthetic_hardware_effect": True}
            if effect["state"] != "approved" or type(expected_version) is not int or effect["version"] != expected_version:
                raise ConflictError("Virtual dispatch requires current approved effect")
            definition = json.loads(effect["definition"])
            source = source_registry.visible(db, actor, definition["source_id"])
            effect_receipts.require_current_virtual_authority(effect, source)
            target = action_registry.validate(definition["action"], definition["target"], source["product"])
            model = db.execute("SELECT * FROM virtual_assets WHERE tenant=? AND source_id=?", (actor["tenant"], source["id"])).fetchone()
            if not model or source["realm"] != "virtual-lab" or model["source_version"] != source["version"] or target["asset_id"] != model["asset_id"] or target["asset_version"] != model["version"]:
                raise ConflictError("Virtual asset/source version changed")
            proof_ids = effect_receipts.current_source_originals(db, actor, source, definition["event_ids"])
            originals = evidence_scope.originals(store, actor, proof_ids)
            if definition["action"] == "terminate_process":
                observed = [r["raw"].get("xdr", {}).get("data", {}).get("process", {}) for r in originals.values()]
                if not any(p.get("guid") == target["process_guid"] and p.get("pid") == target["pid"] and p.get("start_identity") == target["start_identity"] for p in observed):
                    raise PermissionError("Exact process incarnation proof required")
            if "ip" in target and not any(target["ip"] in {r["raw"].get("security", {}).get("src_ip"), r["raw"].get("security", {}).get("dest_ip")} for r in originals.values()):
                raise PermissionError("Target IP not observed in source evidence")
        claimed = effect_receipts.transition(store, who, identifier, expected_version, "dispatching", {"mode": "virtual"})
        with principal.transaction(store, who, ("admin", "analyst"), write=True) as (db, actor):
            effect = effect_receipts.visible(db, actor, identifier)
            case = principal.incident(db, actor, effect["incident_id"])
            source = source_registry.visible(db, actor, definition["source_id"])
            effect_receipts.require_current_virtual_authority(effect, source)
            model = db.execute("SELECT * FROM virtual_assets WHERE tenant=? AND source_id=?", (actor["tenant"], source["id"])).fetchone()
            for name in (effect["requester"], effect["approver"]):
                current = principal.current(db, {"name": name, "tenant": effect["tenant"], "role": "analyst", "allowed_indexes": json.loads(effect["indexes"])}, ("admin", "analyst"))
                if not principal.contains(current["allowed_indexes"], json.loads(effect["indexes"])):
                    raise PermissionError("Virtual effect principal scope changed")
            if not model or effect["state"] != "dispatching" or effect["version"] != claimed["version"] or case["version"] != effect["case_version"] or source["state"] != "active" or source["version"] != definition["source_version"] or model["version"] != target["asset_version"]:
                raise ConflictError("Virtual execution authority changed")
            state = json.loads(model["state"])
            before = release_manifest.digest(state)
            action = definition["action"]
            if action == "isolate_host":
                if state["isolation"] and state["isolation"]["expires"] > time.time():
                    raise ConflictError("Virtual isolation is already owned")
                state["isolation"] = {"id": identifier, "expires": time.time()+target["lease_seconds"]}
            elif action == "release_host":
                if not state["isolation"] or state["isolation"]["id"] != target["isolation_id"]:
                    raise PermissionError("Only the exact owned virtual isolation can be released")
                state["isolation"] = None
            elif action == "terminate_process":
                process = state["processes"].get(target["process_guid"])
                if not process or not process["alive"] or process["pid"] != target["pid"] or process["start_identity"] != target["start_identity"]:
                    raise ConflictError("Virtual process incarnation changed")
                process["alive"] = False
            elif action == "block_ip":
                entry = state["blocked_ips"].get(target["ip"])
                if entry and entry["expires"] > time.time():
                    raise ConflictError("Virtual block is already owned")
                state["blocked_ips"][target["ip"]] = {"id": identifier, "expires": time.time()+target["lease_seconds"]}
            elif action == "unblock_ip":
                entry = state["blocked_ips"].get(target["ip"])
                if not entry or entry["id"] != target["block_id"]:
                    raise PermissionError("Only the exact owned virtual block can be removed")
                del state["blocked_ips"][target["ip"]]
            state["effect_count"] += 1
            db.execute("UPDATE virtual_assets SET state=?,version=version+1,updated=? WHERE tenant=? AND source_id=?", (encode(state), time.time(), actor["tenant"], source["id"]))
            observed = json.loads(db.execute("SELECT state FROM virtual_assets WHERE tenant=? AND source_id=?", (actor["tenant"], source["id"])).fetchone()[0])
            if observed != state:
                raise ConflictError("Virtual postcondition readback differs")
            receipt = {"mode": "virtual", "verified": True, "native_effect": False, "synthetic_hardware_effect": True,
                       "native_qualification": False, "provider": source["product"], "realm": source["realm"], "before_digest": before,
                       "after_digest": release_manifest.digest(observed), "action": action, "target": target,
                       "artifact_digest": release_manifest.digest({"effect_id": identifier, "state": observed})}
            # Both protocol result and durable postcondition are recorded in the
            # same transaction as the in-memory-device state. A lost HTTP reply
            # cannot leave a committed fake effect without its final receipt.
            reported_version = effect["version"]+1
            db.execute("INSERT INTO effect_receipt_history VALUES(?,?,?,?,?,?)", (identifier, reported_version, actor["name"], "reported", encode({**receipt, "postcondition": "virtual_state_readback"}), time.time()))
            version = reported_version+1
            db.execute("UPDATE effect_receipts SET state='confirmed',version=?,updated=? WHERE id=?", (version, time.time(), identifier))
            db.execute("INSERT INTO effect_receipt_history VALUES(?,?,?,?,?,?)", (identifier, version, actor["name"], "confirmed", encode(receipt), time.time()))
            store.audit(db, actor["tenant"], actor["name"], "virtual.effect.confirmed", {"id": identifier, "artifact_digest": receipt["artifact_digest"]})
            return {"id": identifier, "state": "confirmed", "version": version, "duplicate": False, **receipt}


def recover_unknown(store, who, identifier, expected_version):
    """Fence an interrupted fake dispatch; never infer success or replay it."""
    require_simulation(store)
    with principal.transaction(store, who, ("admin", "analyst")) as (db, actor):
        row = effect_receipts.visible(db, actor, identifier)
        definition = json.loads(row["definition"])
        source = source_registry.visible(db, actor, definition["source_id"])
        if source["realm"] != "virtual-lab":
            raise PermissionError("Recovery adapter only accepts virtual-lab effects")
    return effect_receipts.transition(store, who, identifier, expected_version, "unknown", {
        "mode": "virtual", "native_effect": False, "synthetic_hardware_effect": True,
        "verified": False, "reason": "interrupted_dispatch_requires_readback_review", "retry_authorized": False})
