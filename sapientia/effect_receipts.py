"""Evidence/current-authority-bound effect records with unknown recovery fencing."""

import json
import re
import time

from . import evidence_scope, migrations, principal, release_manifest
from .storage import ConflictError, encode

TRANSITIONS = {
    "prepared": {"approved", "cancelled"}, "approved": {"dispatching", "cancelled"},
    "dispatching": {"reported", "unknown", "failed"},
    "reported": {"confirmed", "partial", "unknown", "failed"},
    "unknown": {"confirmed", "failed"}, "partial": {"confirmed", "compensated"},
    "confirmed": {"compensated"}, "failed": set(), "cancelled": set(), "compensated": set()}
VIRTUAL_APPROVAL_TTL = 300


def require_current_virtual_authority(row, source, now=None):
    """A lab approval is finite even before its separately leased fake effect."""
    if source["realm"] == "virtual-lab" and (time.time() if now is None else now) >= row["created"] + VIRTUAL_APPROVAL_TTL:
        raise ConflictError("Virtual effect approval expired; cancel and prepare a new intent")


def current_source_originals(db, actor, source, event_ids):
    """A reused registry ID cannot transfer an old observation to a new account."""
    wanted = {"id": source["id"], "version": source["version"],
              **{key: source[key] for key in ("product", "account", "realm")}}
    rows = db.execute("""SELECT r.event_id,r.source_definition FROM source_event_receipts r
      JOIN receipts p ON p.tenant=r.tenant AND p.event_id=r.event_id AND p.digest=r.receipt_digest
      WHERE r.tenant=? AND r.source_id=? AND r.source_version=? AND r.index_name=?
      AND r.event_id IN (SELECT value FROM json_each(?))""",
      (actor["tenant"], source["id"], source["version"], source["index_name"], encode(event_ids))).fetchall()
    ids = [row["event_id"] for row in rows if row["source_definition"] and json.loads(row["source_definition"]) == wanted]
    if not ids:
        raise PermissionError("Current target source epoch/account evidence required; historical authority cannot be rebound")
    return ids


def initialize(store):
    migrations.apply_store(store, "effects", [
        "CREATE TABLE IF NOT EXISTS effect_receipts(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,incident_id TEXT NOT NULL,case_version INTEGER NOT NULL,indexes TEXT NOT NULL,requester TEXT NOT NULL,approver TEXT,definition TEXT NOT NULL,state TEXT NOT NULL,version INTEGER NOT NULL,created REAL NOT NULL,updated REAL NOT NULL)",
        "CREATE TABLE IF NOT EXISTS effect_receipt_history(id TEXT NOT NULL,version INTEGER NOT NULL,actor TEXT NOT NULL,state TEXT NOT NULL,proof TEXT NOT NULL,at REAL NOT NULL,PRIMARY KEY(id,version))"])


def prepare(store, who, incident_id, definition):
    allowed = {"case_version", "source_id", "source_version", "action", "target", "event_ids"}
    if not isinstance(definition, dict) or set(definition)-allowed-{"request_id"} or not allowed<=set(definition) or type(definition["case_version"]) is not int or type(definition["source_version"]) is not int:
        raise ValueError("Exact versioned effect definition required")
    if "request_id" in definition and (not isinstance(definition["request_id"], str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", definition["request_id"])):
        raise ValueError("Bounded effect intent identifier required")
    if not isinstance(definition["target"], dict) or not 1 <= len(definition["target"]) <= 16 or not isinstance(definition["action"], str) or not 1 <= len(definition["action"]) <= 128:
        raise ValueError("Bounded typed action/target required")
    ids = definition["event_ids"]
    if not isinstance(ids, list) or not 1 <= len(ids) <= 32 or any(not isinstance(i, str) or not 1 <= len(i) <= 256 for i in ids) or len(set(ids)) != len(ids) or len(encode(definition)) > 16384:
        raise ValueError("Exact original evidence required")
    from . import endpoint_response, source_registry
    with store.segment_lock.read(deadline=time.monotonic()+3), principal.transaction(store, who, ("admin", "analyst"), write=True) as (db, actor):
        case = principal.incident(db, actor, incident_id)
        if case["version"] != definition["case_version"]:
            raise ConflictError("Case version changed")
        source = source_registry.visible(db, actor, definition["source_id"])
        if source["state"] != "active" or source["version"] != definition["source_version"]:
            raise ConflictError("Source authority changed")
        if source["realm"] == "virtual-lab":
            from . import action_registry, action_runtime
            action_runtime.require_simulation(store)
            action_registry.validate(definition["action"], definition["target"], source["product"])
            current_source_originals(db, actor, source, ids)
        if any(not endpoint_response._member(db, actor, incident_id, i) for i in ids):
            raise ValueError("Effect evidence is not in this Case")
        rows = evidence_scope.originals(store, actor, ids)
        indexes = sorted({r["index_name"] for r in rows.values()} | {source["index_name"]})
        bound = {**definition, "tenant": actor["tenant"], "incident_id": incident_id,
                 "provider": source["product"], "account": source["account"], "realm": source["realm"],
                 "evidence_digest": release_manifest.digest(rows)}
        identifier = release_manifest.digest(bound)
        now = time.time()
        inserted = db.execute("INSERT OR IGNORE INTO effect_receipts VALUES(?,?,?,?,?,?,NULL,?,'prepared',1,?,?)",
                   (identifier, actor["tenant"], incident_id, case["version"], encode(indexes), actor["name"], encode(bound), now, now))
        if inserted.rowcount:
            db.execute("INSERT INTO effect_receipt_history VALUES(?,1,?,'prepared',?,?)", (identifier, actor["name"], encode({"dispatch_authorized": False}), now))
        row = visible(db, actor, identifier)
        store.audit(db, actor["tenant"], actor["name"], "effect.prepare", {"id": identifier})
        return {"id": identifier, "state": row["state"], "version": row["version"], "effect_key": identifier, "duplicate": not bool(inserted.rowcount), "dispatch_authorized": False,
                "approval_expires": row["created"] + VIRTUAL_APPROVAL_TTL if source["realm"] == "virtual-lab" else None,
                "qualification": "virtual_workflow_only" if source["realm"] == "virtual-lab" else "independent_provider_qualification_required"}


def visible(db, actor, identifier):
    row = db.execute("SELECT * FROM effect_receipts WHERE tenant=? AND id=?", (actor["tenant"], identifier)).fetchone()
    if not row or not principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
        raise KeyError("Effect not found")
    principal.incident(db, actor, row["incident_id"])
    return row


def transition(store, who, identifier, expected_version, state, proof):
    if state not in TRANSITIONS or not isinstance(proof, dict) or len(encode(proof)) > 16384:
        raise ValueError("Bounded effect state/proof required")
    from . import source_registry
    with principal.transaction(store, who, ("admin", "analyst"), write=True) as (db, actor):
        row = visible(db, actor, identifier)
        if type(expected_version) is not int or row["version"] != expected_version or state not in TRANSITIONS[row["state"]]:
            raise ConflictError("Effect version/state changed")
        case = principal.incident(db, actor, row["incident_id"])
        definition = json.loads(row["definition"])
        source = source_registry.visible(db, actor, definition["source_id"])
        if state in {"approved", "dispatching"}:
            require_current_virtual_authority(row, source)
            requester = principal.current(db, {"name": row["requester"], "tenant": row["tenant"], "role": "analyst", "allowed_indexes": json.loads(row["indexes"])}, ("admin", "analyst"))
            if not principal.contains(requester["allowed_indexes"], json.loads(row["indexes"])) or case["version"] != row["case_version"] or source["state"] != "active" or source["version"] != definition["source_version"]:
                raise PermissionError("Effect authority/snapshot changed")
            if source["realm"] == "virtual-lab":
                current_source_originals(db, actor, source, definition["event_ids"])
        approver = row["approver"]
        if state == "approved":
            if actor["name"] == row["requester"]:
                raise PermissionError("A different current principal must approve")
            approver = actor["name"]
        if state == "dispatching":
            peer = principal.current(db, {"name": approver, "tenant": row["tenant"], "role": "analyst", "allowed_indexes": json.loads(row["indexes"])}, ("admin", "analyst"))
            if not principal.contains(peer["allowed_indexes"], json.loads(row["indexes"])):
                raise PermissionError("Effect approver scope changed")
        if state in {"confirmed", "compensated"} and (proof.get("verified") is not True or not isinstance(proof.get("artifact_digest"), str) or not re.fullmatch(r"[0-9a-f]{64}", proof["artifact_digest"])):
            raise ValueError("Explicit postcondition artifact required")
        if source["realm"] == "virtual-lab" and state in {"confirmed", "compensated"} and (proof.get("mode") != "virtual" or proof.get("native_effect") is not False or proof.get("synthetic_hardware_effect") is not True):
            raise ValueError("Virtual provider evidence cannot be promoted to native qualification")
        version = row["version"] + 1
        db.execute("UPDATE effect_receipts SET state=?,version=?,approver=?,updated=? WHERE id=?", (state, version, approver, time.time(), identifier))
        db.execute("INSERT INTO effect_receipt_history VALUES(?,?,?,?,?,?)", (identifier, version, actor["name"], state, encode(proof), time.time()))
        store.audit(db, actor["tenant"], actor["name"], "effect." + state, {"id": identifier, "version": version})
        return {"id": identifier, "version": version, "state": state, "effect_execution": False}
