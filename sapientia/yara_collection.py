"""Original-selected executable collection through the ordinary Case/agent guards."""

import re

from . import endpoint_artifacts, endpoint_response
from .storage import ConflictError


def targets(store, who, incident_id):
    listing = endpoint_response.listing(store, who, incident_id)
    agents = {item["id"]: item for item in listing["agents"]}
    items = []
    for event in listing["events"]:
        process = event["process"]
        agent = agents.get(event.get("verified_agent_id"))
        descriptor = {"event_id": event["event_id"], "evidence_event_id": event["event_id"],
            "agent_id": event.get("verified_agent_id"), "index": event["index_name"], "host": event["host"],
            "case_version": listing["case_version"], "process_guid": process.get("guid"), "pid": process.get("pid"),
            "start_identity": process.get("start_identity"), "path": process.get("executable"), "sha256": process.get("sha256"),
            "eligible": False, "prepare_eligible": False, "needs_prepare": not isinstance(process.get("sha256"), str) or re.fullmatch(r"[0-9a-fA-F]{64}", process.get("sha256", "")) is None,
            "reason": "The original lacks an enrolled current process identity", "action": None, "prepare_action": None}
        if agent and event.get("response_eligible"):
            prepare = {"type": "inspect_process", "process_guid": process.get("guid"), "pid": process.get("pid"),
                "start_identity": process.get("start_identity"), "path": process.get("executable"), "capture_executable_evidence": True}
            try:
                descriptor["prepare_action"] = endpoint_response.action(prepare, agent["platform"])
                descriptor["prepare_eligible"] = True
                if descriptor["needs_prepare"]:
                    descriptor["reason"] = "Explicit inspection must publish a new hash-bearing original; then add that original to the Case"
                else:
                    descriptor["action"] = endpoint_response.action({key: descriptor[key] for key in ("process_guid", "pid", "start_identity", "path", "sha256")} | {
                        "type": "collect_artifact", "source": "process_executable", "max_bytes": endpoint_artifacts.PROCESS_MAX_BYTES}, agent["platform"])
                    descriptor["eligible"] = True
                    descriptor["reason"] = "Exact admitted original selected; the agent must still revalidate local opt-in, live identity, path and bytes"
            except (KeyError, ValueError, TypeError):
                descriptor["reason"] = "Original process GUID/PID/start identity, executable path or SHA256 is incomplete or unsupported"
        descriptor["id"] = descriptor["target_id"] = "YCT-" + endpoint_response._digest({
            "case_version": listing["case_version"], "event_id": event["event_id"], "agent_id": descriptor["agent_id"],
            "process": process, "receipt_digest": event.get("verified_receipt_digest")})[:32]
        items.append(descriptor)
    return {"incident_id": incident_id, "case_version": listing["case_version"], "items": items,
        "commands": listing["commands"], "max_process_bytes": endpoint_artifacts.PROCESS_MAX_BYTES,
        "legacy_file_max_bytes": endpoint_artifacts.MAX_BYTES,
        "local_opt_in_required": True, "automatic_case_membership": False,
        "semantics": "Explicit read-only disk executable collection; no code execution, memory dump, host blocking or hardware attestation"}


def request(store, who, data):
    fields = {"incident_id", "event_id", "agent_id", "case_version", "request_id", "reason"}
    if not isinstance(data, dict) or not fields <= set(data) or set(data) - fields - {"prepare_only", "target_id"}:
        raise ValueError("Select a Case original, agent and current Case version; arbitrary path/hash/action inputs are forbidden")
    if type(data.get("prepare_only", False)) is not bool or type(data["case_version"]) is not int:
        raise ValueError("Typed preparation flag and current Case version required")
    selected = targets(store, who, data["incident_id"])
    if selected["case_version"] != data["case_version"]:
        raise ConflictError("Case changed; reload executable collection targets")
    item = next((item for item in selected["items"] if item["event_id"] == data["event_id"] and item["agent_id"] == data["agent_id"]), None)
    if not item:
        raise KeyError("Case original is not bound to this enrolled agent")
    if "target_id" in data and item["id"] != data["target_id"]:
        raise ConflictError("Original executable collection target changed")
    prepare = data.get("prepare_only", False)
    if not item["prepare_eligible" if prepare else "eligible"]:
        raise ValueError(item["reason"])
    result = endpoint_response.create(store, who, data["incident_id"], {
        "agent_id": item["agent_id"], "evidence_event_id": item["event_id"], "case_version": data["case_version"],
        "request_id": data["request_id"], "reason": data["reason"], "action": item["prepare_action" if prepare else "action"]})
    return {**result, "collection_target_id": item["id"], "prepare_only": prepare,
        "automatic_case_membership": False, "native_effects_requested": False}
