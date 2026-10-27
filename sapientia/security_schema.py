"""Versioned derived security projection; original admission bytes are untouched."""

import ipaddress
import json
import math

from .release_manifest import digest, hash_file
from . import ocsf_mapping

VERSION = 4
SUPPORTED_VERSIONS = (3, 4)
PARSER_DIGEST = digest({"schema": VERSION, "implementation": hash_file(__file__), "ocsf_mapping": ocsf_mapping.MAPPING_DIGEST})


def get(value, path):
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def reported_text(value, maximum=2048):
    """Unknown and mistyped identity attributes stay unknown, never stringify."""
    return value if isinstance(value, str) and 1 <= len(value) <= maximum and all(ord(c) >= 32 for c in value) and "[REDACTED]" not in value else None


def reported_number(value, maximum=253402300799):
    return value if type(value) in (int, float) and math.isfinite(value) and 0 <= value <= maximum else None


def _enrich(result, event, endpoint):
    action = reported_text(get(endpoint, "event.action")) or result.get("action")
    observed = action in {"process_observed", "process_inventory", "memory_observation"}
    reported_observed = reported_number(get(endpoint, "event.observed_time"))
    occurrence = reported_number(get(endpoint, "event.occurrence_time"))
    # A process found by a snapshot has an observation time, not a launch time.
    result["event_semantics"] = {
        "reported_action": action,
        "kind": "observation" if observed else "reported_activity",
        "occurrence_time": None if observed else occurrence,
        "observed_time": reported_observed if reported_observed is not None else event["event_time"] if observed else None,
        "server_received_time": reported_number(event.get("received")),
        "ordering_basis": "reported_event_time",
        "clock_quality": reported_text(get(endpoint, "event.clock_quality"), 128),
        "timestamp_precision_seconds": result["clock_precision"],
        "clock_offset_seconds": get(endpoint, "event.clock_offset_seconds") if type(get(endpoint, "event.clock_offset_seconds")) in (int, float) and math.isfinite(get(endpoint, "event.clock_offset_seconds")) else None,
        "native_occurrence_proven": False,
    }
    result["device"] = {
        "uid": reported_text(get(endpoint, "host.id")) or reported_text(get(endpoint, "device.id")),
        "boot_id": reported_text(get(endpoint, "host.boot_id")),
        "agent_id": reported_text(get(endpoint, "agent.id")),
    }
    result["container"] = {"uid": reported_text(get(endpoint, "container.id")), "namespace": reported_text(get(endpoint, "container.namespace"))}
    result["file"] = {"object_id": reported_text(get(endpoint, "file.id")) or reported_text(get(endpoint, "file.object_id")),
                      "volume_id": reported_text(get(endpoint, "file.volume_id")),
                      "generation": reported_text(get(endpoint, "file.generation")),
                      "path": reported_text(get(endpoint, "file.path")),
                      "sha256": reported_text(get(endpoint, "file.hash.sha256"), 64)}
    result["process"]["parent_start_identity"] = reported_text(get(endpoint, "process.parent.start_identity"))
    result["identity_contract"] = {"version": 2, "pid_is_identity": False, "path_is_identity": False, "reported_only": True}


def project(event, authority):
    raw = event.get("raw", {})
    sec = raw.get("security", {})
    endpoint = get(raw, "xdr.data") or {}
    fg = raw.get("fortigate", {})
    asa = raw.get("cisco_asa", {})
    for label,value in (("security",sec),("endpoint",endpoint),("fortigate",fg),("cisco_asa",asa)):
        if not isinstance(value,dict):
            raise ValueError("Typed security object required: "+label)
    source = get(endpoint, "source") or {}
    dest = get(endpoint, "destination") or {}
    if not isinstance(source,dict) or not isinstance(dest,dict):
        raise ValueError("Typed endpoint network objects required")
    src_port = source.get("port", sec.get("src_port", fg.get("srcport")))
    dest_port = dest.get("port", sec.get("dest_port", fg.get("dstport")))
    protocol = get(endpoint, "network.protocol") or sec.get("protocol") or asa.get("protocol") or fg.get("proto")
    protocol = {"6": "tcp", "17": "udp"}.get(str(protocol), str(protocol).lower())
    flow = None
    src_ip, dest_ip = sec.get("src_ip"), sec.get("dest_ip")
    if src_ip and dest_ip and type(src_port) is int and type(dest_port) is int and 1 <= src_port <= 65535 and 1 <= dest_port <= 65535 and protocol in {"tcp", "udp"}:
        flow = {"src_ip": str(ipaddress.ip_address(src_ip)), "src_port": src_port,
                "dest_ip": str(ipaddress.ip_address(dest_ip)), "dest_port": dest_port, "protocol": protocol}
    precision = get(endpoint, "event.timestamp_precision_seconds")
    if type(precision) not in (int, float) or not math.isfinite(precision) or not 0 <= precision <= 86400:
        precision = None
    result = {"schema": "xsera.security-projection", "version": VERSION, "parser_digest": PARSER_DIGEST,
              "event_id": event["event_id"], "event_time": event["event_time"], "index_name": event["index"],
              "host": event["host"], "source": event["source"], "product": authority["product"],
              "source_id": authority["id"], "source_version": authority["version"],
              "realm": authority["realm"], "account": authority["account"],
              "action": sec.get("action"), "outcome": sec.get("outcome"), "flow": flow,
              "actor": {"uid": get(endpoint, "user.id"), "name": sec.get("user")},
              "process": {k: get(endpoint, "process."+k) for k in ("guid", "pid", "name", "start_identity", "command_line")},
              "clock_precision": precision,
              "assurance": "authenticated_source_assertion", "native_capture_proven": False,
              "simulation": get(endpoint, "agent.simulation") is True or authority["realm"] == "virtual-lab"}
    ct=raw.get("cloudtrail") or {}
    if not isinstance(ct,dict):
        raise ValueError("Typed CloudTrail object required")
    caller=ct.get("userIdentity") or {}
    if not isinstance(caller,dict):
        raise ValueError("Typed cloud identity required")
    result["process"]["parent_guid"] = get(endpoint,"process.parent.guid")
    result["auth"]={"session_id":get(endpoint,"user.session_id") or get(endpoint,"authentication.session_id") or sec.get("session_id"),
                    "uid":get(endpoint,"user.id"),"account":authority["account"]}
    result["cloud"]={"account_id":ct.get("recipientAccountId"),"region":ct.get("awsRegion"),
                     "principal_id":caller.get("principalId"),"arn":caller.get("arn"),
                     "session_id":caller.get("accessKeyId"),"issuer_arn":get(caller,"sessionContext.sessionIssuer.arn"),
                     "service":ct.get("eventSource"),"action":ct.get("eventName")}
    _enrich(result, event, endpoint)
    result["ocsf"] = ocsf_mapping.project(result)
    result["projection_digest"] = digest(result)
    return result
