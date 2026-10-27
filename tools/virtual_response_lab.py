"""Loopback-only virtual response protocol adapter; no OS executor is imported.

The transports expose get(path) and post(path, dict), like the paced lab's
authenticated transport. The server must independently permit simulation_mode
and the source must belong to virtual-lab. No secret or transport object is
included in the returned report.
"""

import json
import time
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit


class VirtualLifecycleError(RuntimeError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def _origin(value):
    url = urlsplit(value)
    if url.scheme not in {"http", "https"} or url.hostname not in {"127.0.0.1", "localhost", "::1"} or url.username or url.password or url.path not in {"", "/"} or url.query or url.fragment:
        raise ValueError("Virtual response lab requires an explicit loopback origin")
    return value.rstrip("/")


def _call(transport, path, data=None):
    try:
        response = transport.get(path) if data is None else transport.post(path, data)
    except HTTPError as exc:
        raise VirtualLifecycleError("Virtual response protocol refused the request", exc.code) from exc
    if hasattr(response, "status_code"):
        if response.status_code >= 400:
            raise VirtualLifecycleError("Virtual response protocol refused the request", response.status_code)
        response = response.json()
    if not isinstance(response, (dict, list)):
        raise VirtualLifecycleError("Malformed virtual response protocol reply")
    return response


def _virtual(reply):
    if reply.get("mode") != "virtual" or reply.get("native_effect") is not False or reply.get("synthetic_hardware_effect") is not True:
        raise VirtualLifecycleError("Reply lacks explicit synthetic, non-native provenance")


def _dispatch(requester, approver, case_id, source, evidence, action, target, request_id):
    case = _call(requester, "/api/incidents/" + quote(case_id, safe=""))
    path = "/api/v2/incidents/" + quote(case_id, safe="") + "/effects/prepare"
    prepared = _call(requester, path, {"case_version": case["version"], "source_id": source["id"],
        "source_version": source["version"], "event_ids": evidence, "action": action,
        "target": target, "request_id": request_id})
    if prepared.get("state") != "prepared" or prepared.get("qualification") != "virtual_workflow_only" or prepared.get("dispatch_authorized") is not False:
        raise VirtualLifecycleError("A fresh, unapproved virtual intent is required")
    prefix = "/api/v2/effects/" + prepared["id"]
    approved = _call(approver, prefix + "/approve", {"version": prepared["version"]})
    confirmed = _call(requester, prefix + "/simulate", {"version": approved["version"]})
    _virtual(confirmed)
    if confirmed.get("state") != "confirmed" or confirmed.get("native_qualification") is not False:
        raise VirtualLifecycleError("Virtual readback did not confirm the simulated postcondition")
    history = _call(requester, prefix + "/history")["history"]
    states = [row["state"] for row in history]
    if states != ["prepared", "approved", "dispatching", "reported", "confirmed"]:
        raise VirtualLifecycleError("Approval, dispatch, result and postcondition history is incomplete")
    proofs = [json.loads(row["proof"]) for row in history if row["state"] in {"reported", "confirmed"}]
    for proof in proofs:
        _virtual(proof)
    replay = _call(requester, prefix + "/simulate", {"version": approved["version"]})
    _virtual(replay)
    if replay.get("duplicate") is not True or replay.get("artifact_digest") != confirmed["artifact_digest"]:
        raise VirtualLifecycleError("Lost-reply replay changed the virtual receipt")
    return {"effect_id": prepared["id"], "case_version": case["version"], "action": action,
        "approval_expires": prepared["approval_expires"], "states": states,
        "history": history, "receipt": confirmed, "duplicate_dispatch_preserved": True}


def run_response_lifecycle(origin, requester, approver, *, case_id, source_id, event_ids,
                           request_id, action="isolate_host", target=None,
                           processes=None, release=True):
    """Review and execute a typed fake-device intent, optionally reverse its lease.

    Independent logged-in users are checked by the real server. event_ids must
    already be original evidence in this Case and prove the selected source.
    For block_ip, target supplies ip; for terminate_process it supplies the exact
    GUID/PID/start incarnation. Only virtual asset/receipt state is changed.
    """
    origin = _origin(origin)
    for transport in (requester, approver):
        observed = getattr(transport, "origin", getattr(transport, "base_url", origin))
        if _origin(str(observed)) != origin:
            raise ValueError("Response transports must use the same loopback origin")
    if not isinstance(event_ids, list) or not 1<=len(event_ids)<=32 or len(set(event_ids))!=len(event_ids):
        raise ValueError("1..32 distinct stored original IDs required")
    if action not in {"isolate_host", "block_ip", "terminate_process"} or not isinstance(request_id, str) or not 1<=len(request_id)<=110:
        raise ValueError("A bounded typed virtual intent is required")
    source = next((row for row in _call(requester, "/api/v2/sources") if row["id"] == source_id), None)
    if not source or source.get("realm") != "virtual-lab" or source.get("state") != "active":
        raise PermissionError("Only an active explicit virtual-lab source is accepted")
    started = time.monotonic()
    asset_path = "/api/v2/simulation/assets/" + quote(source_id, safe="")
    try:
        before = _call(requester, asset_path)
    except VirtualLifecycleError as exc:
        if exc.status != 404:
            raise
        _call(requester, "/api/v2/simulation/assets", {"source_id": source_id,
            "asset_id": source["account"], "processes": processes or {}})
        before = _call(requester, asset_path)
    _virtual(before)
    bound = {"asset_id": source["account"], "asset_version": before["version"], **(target or {})}
    if action in {"isolate_host", "block_ip"}:
        bound.setdefault("lease_seconds", 30)
    run = _dispatch(requester, approver, case_id, source, event_ids, action, bound, request_id)
    after = _call(requester, asset_path)
    _virtual(after)
    if after["state"]["effect_count"] != before["state"]["effect_count"]+1:
        raise VirtualLifecycleError("Duplicate dispatch affected fake device more than once")
    if action == "isolate_host" and not after["effective_isolated"]:
        raise VirtualLifecycleError("Virtual isolation postcondition is absent")
    if action == "block_ip" and bound["ip"] not in after["effective_blocked_ips"]:
        raise VirtualLifecycleError("Virtual IP-block postcondition is absent")
    release_run = None
    if release and action in {"isolate_host", "block_ip"}:
        undo = {"asset_id": source["account"], "asset_version": after["version"]}
        if action == "isolate_host":
            undo["isolation_id"] = run["effect_id"]
            reverse_action = "release_host"
        else:
            undo.update({"block_id": run["effect_id"], "ip": bound["ip"]})
            reverse_action = "unblock_ip"
        release_run = _dispatch(requester, approver, case_id, source, event_ids,
                                reverse_action, undo, request_id + ":release")
        after = _call(requester, asset_path)
        if (action == "isolate_host" and after["effective_isolated"]) or (action == "block_ip" and bound["ip"] in after["effective_blocked_ips"]):
            raise VirtualLifecycleError("Owned virtual effect was not released")
    return {"schema": "xsera.virtual-response-lab.v1", "passed": True,
        "mode": "virtual", "native_effect": False, "synthetic_hardware_effect": True,
        "host_os_or_network_mutated": False, "native_qualification": False,
        "case_id": case_id, "source_id": source_id, "source_product": source["product"],
        "event_ids": event_ids, "response": run, "release": release_run,
        "final_virtual_asset": after, "elapsed_seconds": time.monotonic()-started,
        "limits": ["Synthetic device state only", "No physical appliance or host prevention proof",
                   "Approval and receipt correctness do not measure commercial efficacy or MTTR"]}
