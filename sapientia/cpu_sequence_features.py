"""Label-free semantic features for source-scoped, ordered CPU sequences."""
import hashlib
import ipaddress
import math
import re
from pathlib import Path

from .storage import encode

FEATURE_SCHEMA = "xsera.cpu-sequence-features.v1"
FEATURES = (
    "hour_sin", "hour_cos", "gap_log", "elapsed_log", "command_length",
    "command_encoded", "command_shell", "command_download", "command_credential",
    "command_remote_admin", "command_script", "process_depth", "parent_present",
    "kind_process", "kind_network", "kind_auth", "kind_file", "kind_dns",
    "kind_registry", "kind_email", "kind_cloud", "kind_other", "auth_failure",
    "auth_success", "network_external", "port_web", "port_dns", "port_remote_admin",
    "port_other", "network_out_log", "network_in_log", "protocol_tcp", "protocol_udp",
    "protocol_other", "file_executable", "file_sensitive", "file_hash_present",
    "file_delete", "file_write", "dns_length", "registry_autorun",
    "email_attachments_log", "email_link", "cloud_write", "cloud_privilege",
    "missing_command", "missing_process_depth", "missing_network_dest",
    "missing_network_bytes", "missing_auth_outcome", "missing_file", "missing_dns",
    "missing_registry", "missing_email", "missing_cloud",
)
MAX_STEPS = 32
FEATURE_CONTRACT_DIGEST = hashlib.sha256(encode({
    "schema": FEATURE_SCHEMA, "features": FEATURES, "max_steps": MAX_STEPS,
    "time": "UTC reported event time; strictly increasing, forward-only relative gaps",
    "identity": "authenticated source + exact index + reported host/boot/user/session/container/namespace identities",
    "missingness": "explicit binary missing features; step padding excluded by lengths",
    "labels": "external reviewed manifest only; no raw labels, family, scenario or truth",
    "semantic_contract": 1,
    "implementation_digest": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
}).encode()).hexdigest()


def get(value, path):
    for item in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(item)
    return value


def number(value):
    return float(value) if type(value) in (int, float) and math.isfinite(value) and value >= 0 else None


def _log(value, limit):
    value = number(value)
    return math.log1p(min(value or 0, limit))/math.log1p(limit)


def _text(value):
    return value[:8192].lower() if isinstance(value, str) else ""


def extract(event, previous_time=None, first_time=None):
    raw = event.get("raw", {})
    data = get(raw, "xdr.data") or {}
    sec = raw.get("security", {}) if isinstance(raw, dict) else {}
    if not isinstance(sec, dict):
        sec = {}
    def value(path, *fallback):
        item = get(data, path)
        if item is not None:
            return item
        return next((sec.get(p) for p in fallback if sec.get(p) is not None), None)
    stamp = float(event["event_time"])
    phase = stamp % 86400/86400*2*math.pi
    action = _text(value("event.action", "action"))
    category = _text(value("event.category", "category"))
    command_value = value("process.command_line", "command_line")
    command = _text(command_value)
    process_name = _text(value("process.name", "process_name"))
    command_context = process_name + " " + command
    depth = number(value("process.depth", "process_depth"))
    auth = value("authentication.outcome", "outcome")
    if auth is None:
        auth = value("event.outcome", "outcome")
    outcome = _text(auth)
    destination = value("destination.ip", "dest_ip")
    try:
        external = float(ipaddress.ip_address(destination).is_global)
    except (ValueError, TypeError):
        external = 0.
    port = number(value("destination.port", "dest_port"))
    byte_out = value("network.bytes_out", "bytes_out", "sent_bytes")
    byte_in = value("network.bytes_in", "bytes_in", "received_bytes")
    protocol = _text(value("network.protocol", "protocol"))
    file_path_value = value("file.path", "file_path")
    file_path = _text(file_path_value).replace("\\", "/")
    dns = value("dns.query", "dns_query")
    registry = value("registry.key", "registry_key")
    attachments = value("email.attachment_count", "attachment_count")
    cloud = value("cloud.action", "cloud_action")
    cloud_action = _text(cloud)
    kinds = {
        "process": category == "process" or action.startswith(("process_", "script_", "powershell_")),
        "network": category in {"network", "firewall"} or action.startswith(("network_", "connection_", "firewall_")),
        "auth": category in {"authentication", "identity", "auth"} or action.startswith(("auth_", "authentication_", "login_", "logon_")),
        "file": category == "file" or action.startswith("file_"),
        "dns": category == "dns" or action.startswith("dns_"),
        "registry": category == "registry" or action.startswith("registry_"),
        "email": category in {"email", "mail"} or action.startswith(("email_", "mail_")),
        "cloud": category == "cloud" or action.startswith("cloud_"),
    }
    flags = lambda *terms: float(any(term in command_context for term in terms))
    result = {
        "hour_sin": (math.sin(phase)+1)/2, "hour_cos": (math.cos(phase)+1)/2,
        "gap_log": _log(max(0, stamp-(previous_time if previous_time is not None else stamp)), 86400),
        "elapsed_log": _log(max(0, stamp-(first_time if first_time is not None else stamp)), 86400),
        "command_length": min(len(command), 8192)/8192,
        "command_encoded": flags("-encodedcommand", "-enc ", "base64", "frombase64string"),
        "command_shell": flags("powershell", "pwsh", "cmd.exe", "/bin/sh", "/bin/bash"),
        "command_download": flags("invoke-webrequest", "downloadstring", "curl ", "wget ", "bitsadmin"),
        "command_credential": flags("lsass", "sekurlsa", "mimikatz", "/etc/shadow", "vaultcmd"),
        "command_remote_admin": flags("psexec", "winrm", "mstsc", "ssh ", "wmic "),
        "command_script": flags(".ps1", ".vbs", ".js", "python", "bash", "cscript", "wscript"),
        "process_depth": min(depth or 0, 32)/32,
        "parent_present": float(bool(value("process.parent.guid"))),
        **{"kind_"+k: float(v) for k, v in kinds.items()},
        "kind_other": float(not any(kinds.values())),
        "auth_failure": float(kinds["auth"] and (outcome in {"failure", "failed", "denied", "error"} or "fail" in action)),
        "auth_success": float(kinds["auth"] and (outcome in {"success", "succeeded", "allowed"} or "success" in action)),
        "network_external": external, "port_web": float(port in {80, 443, 8080, 8443}),
        "port_dns": float(port == 53), "port_remote_admin": float(port in {22, 23, 135, 139, 445, 3389, 5985, 5986}),
        "port_other": float(port is not None and port not in {80, 443, 8080, 8443, 53, 22, 23, 135, 139, 445, 3389, 5985, 5986}),
        "network_out_log": _log(byte_out, 10**9), "network_in_log": _log(byte_in, 10**9),
        "protocol_tcp": float(protocol in {"tcp", "6"}), "protocol_udp": float(protocol in {"udp", "17"}),
        "protocol_other": float(bool(protocol) and protocol not in {"tcp", "udp", "6", "17"}),
        "file_executable": float(bool(re.search(r"\.(?:exe|dll|sys|ps1|vbs|sh|py|js)$", file_path))),
        "file_sensitive": float(any(p in file_path for p in ("/system32/", "/.ssh/", "/etc/shadow", "/etc/passwd", "/startup/"))),
        "file_hash_present": float(isinstance(value("file.hash.sha256"), str) and bool(re.fullmatch(r"[0-9a-fA-F]{64}", value("file.hash.sha256")))),
        "file_delete": float(kinds["file"] and any(p in action for p in ("delete", "remove"))),
        "file_write": float(kinds["file"] and any(p in action for p in ("write", "create", "modif"))),
        "dns_length": min(len(_text(dns)), 253)/253,
        "registry_autorun": float(any(p in _text(registry) for p in ("currentversion/run", "currentversion\\run", "winlogon", "services"))),
        "email_attachments_log": _log(attachments, 100), "email_link": float(bool(value("email.link"))),
        "cloud_write": float(any(p in cloud_action for p in ("put", "create", "update", "delete", "attach", "assume"))),
        "cloud_privilege": float(any(p in cloud_action for p in ("policy", "role", "credential", "accesskey", "permission"))),
        "missing_command": float(not isinstance(command_value, str)), "missing_process_depth": float(depth is None),
        "missing_network_dest": float(destination is None or port is None),
        "missing_network_bytes": float(number(byte_out) is None and number(byte_in) is None),
        "missing_auth_outcome": float(auth is None), "missing_file": float(file_path_value is None),
        "missing_dns": float(dns is None), "missing_registry": float(registry is None),
        "missing_email": float(attachments is None and value("email.link") is None), "missing_cloud": float(cloud is None),
    }
    return [result[name] for name in FEATURES]


def vectors(records):
    times = [float(r["event_time"]) for r in records]
    if not 2 <= len(records) <= MAX_STEPS or any(b <= a for a, b in zip(times, times[1:])):
        raise ValueError("A sequence requires 2..32 strictly increasing reported event times")
    return [extract(record, times[i-1] if i else None, times[0]) for i, record in enumerate(records)]
