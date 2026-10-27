"""Typed action schemas; virtual qualification is separate from native support."""

import ipaddress

SCHEMAS = {
    "isolate_host": {"asset_id", "asset_version", "lease_seconds"},
    "release_host": {"asset_id", "asset_version", "isolation_id"},
    "terminate_process": {"asset_id", "asset_version", "process_guid", "pid", "start_identity"},
    "block_ip": {"asset_id", "asset_version", "ip", "lease_seconds"},
    "unblock_ip": {"asset_id", "asset_version", "ip", "block_id"},
}


def validate(action, target, product):
    if action not in SCHEMAS or not isinstance(target, dict) or set(target) != SCHEMAS[action]:
        raise ValueError("Exact typed virtual action target required")
    if not isinstance(target["asset_id"], str) or not 1 <= len(target["asset_id"]) <= 256 or type(target["asset_version"]) is not int or target["asset_version"] < 1:
        raise ValueError("Versioned virtual asset required")
    if action in {"isolate_host", "release_host", "terminate_process"} and product not in {"windows", "linux"}:
        raise ValueError("Endpoint action requires an endpoint product")
    if action in {"block_ip", "unblock_ip"} and product not in {"fortigate", "cisco_asa"}:
        raise ValueError("Network action requires a network product")
    if "lease_seconds" in target and (type(target["lease_seconds"]) is not int or not 5 <= target["lease_seconds"] <= 300):
        raise ValueError("Finite virtual effect lease required")
    if "ip" in target:
        ipaddress.ip_address(target["ip"])
    if "pid" in target and (type(target["pid"]) is not int or not 1 <= target["pid"] < 2**32):
        raise ValueError("Typed process PID required")
    for key in ("process_guid", "start_identity", "isolation_id", "block_id"):
        if key in target and (not isinstance(target[key], str) or not 1 <= len(target[key]) <= 256):
            raise ValueError("Exact process/effect identity required")
    return dict(target)
