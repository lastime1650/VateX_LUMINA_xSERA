"""AEGIS XDR 2.4 telemetry adapters and bounded, authorized endpoint projections.

Protocol reviewed in XDR_V2/xdr/{adapters,engine,server,agents}.py and
Agent/core.py. PID alone never identifies a process. Reported parent GUIDs are
evidence of sensor-reported lineage, not proof of execution or network causality.
No enrollment credential, agent command, isolation or arbitrary shell API exists
here. The optional remote bridge only reads a fixed, filtered agent summary.
"""

import copy
import hashlib
import http.client
import ipaddress
import json
import math
import ntpath
import os
import re
import socket
import ssl
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from . import entities, pipeline, principal
from .query import index_predicate
from .storage import CapacityError, ConflictError, encode, normalize

SCHEMA = "aegis.endpoint.v1"
READ_ONLY = ["collect_inventory", "collect_processes"]
MAX_EVENTS = 5000
MAX_NODES = 1000
MAX_RESPONSE = 2 * 1024 * 1024
EDIT = ("admin", "analyst")


def _text(value, label, maximum=256):
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise ValueError(label + " must be a bounded nonempty string")
    if any(ord(c) < 32 for c in value):
        raise ValueError(label + " contains control characters")
    return value


def _get(data, path):
    for part in path.split("."):
        if not isinstance(data, dict):
            return None
        data = data.get(part)
    return data


def _put(data, path, value):
    parts = path.split(".")
    for part in parts[:-1]:
        data = data.setdefault(part, {})
    data[parts[-1]] = value


def _timestamp(value, *, legacy=False):
    if not isinstance(value, str):
        raise ValueError("Endpoint @timestamp must be ISO8601 with timezone")  # noqa: TRY004 - Invalid JSON is HTTP 400.
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            if not legacy:
                raise ValueError("timezone missing")
            parsed = parsed.replace(tzinfo=UTC)  # Sysmon UtcTime contract.
        result = parsed.timestamp()
        if not math.isfinite(result) or result < 0:
            raise ValueError("invalid timestamp")
        return result
    except (ValueError, OverflowError):
        raise ValueError("Endpoint @timestamp must be ISO8601 with timezone") from None


WINDOWS_OBSERVATION_EVENTS = {
    "Microsoft-Windows-PowerShell/Operational": (
        "script",
        {"4103": "powershell_command", "4104": "powershell_script_block"},
    ),
    "Security": (
        "security",
        {
            "4688": "process_created",
            "4689": "process_terminated",
            "4657": "registry_value_set",
            "4663": "file_accessed",
            "5156": "network_connection",
            "5157": "connection_blocked",
            "4624": "logon_success",
            "4625": "logon_failed",
            "4648": "explicit_credentials",
            "4768": "kerberos_ticket_requested",
            "4769": "kerberos_service_ticket_requested",
        },
    ),
    "Microsoft-Windows-Windows Defender/Operational": (
        "security",
        {
            "1116": "defender_detection",
            "1117": "defender_remediation",
        },
    ),
    "Microsoft-Windows-Sysmon/Operational": (
        "sysmon",
        {
            "1": "process_created",
            "3": "network_connection",
            "5": "process_terminated",
            "6": "driver_loaded",
            "7": "image_loaded",
            "8": "remote_thread_created",
            "10": "process_accessed",
            "11": "file_created",
            "13": "registry_value_set",
            "14": "registry_value_renamed",
            "22": "dns_query",
            "23": "file_deleted",
            "25": "process_tampered",
            "26": "file_deleted",
        },
    ),
}


def _windows_unbound_observation(data):
    provider, code = _get(data, "event.provider"), _get(data, "event.code")
    if not isinstance(provider, str) or not isinstance(code, str):
        return False
    module, actions = WINDOWS_OBSERVATION_EVENTS.get(provider, (None, {}))
    return (
        module is not None
        and _get(data, "event.module") == module
        and code in actions
        and _get(data, "event.action") == actions[code]
        and _get(data, "agent.collector") == "windows-event-log"
        and _get(data, "agent.process_identity_kind")
        == "unavailable_for_windows_event_log_observation"
    )


def _typed(data):
    if not isinstance(data, dict):
        raise ValueError("Endpoint data must be an object")  # noqa: TRY004 - Invalid JSON is HTTP 400.
    try:
        body = json.dumps(data, ensure_ascii=False, allow_nan=False).encode()
    except (ValueError, TypeError, RecursionError):
        raise ValueError("Endpoint data must be bounded finite JSON") from None
    if len(body) > 64 * 1024:
        raise ValueError("Endpoint data exceeds 64 KiB")
    data = copy.deepcopy(data)
    _text(_get(data, "host.id"), "host.id")
    code_integrity_observation = (
        _get(data, "event.module") == "code_integrity"
        and _get(data, "event.provider")
        == "Microsoft-Windows-CodeIntegrity/Operational"
        and _get(data, "event.code") in ("3076", "3077", "3089")
        and _get(data, "agent.collector") == "windows-event-log"
        and _get(data, "agent.process_identity_kind")
        == "unavailable_for_code_integrity_observation"
    )
    kernel_permission_observation = (
        _get(data, "event.module") == "kernel_prevention"
        and _get(data, "event.provider") == "linux.fanotify"
        and _get(data, "event.action") in ("execution_denied", "execution_allowed")
        and _get(data, "agent.collector") == "linux-kernel-exec-permission"
        and _get(data, "agent.process_identity_kind")
        == "unavailable_for_kernel_permission_observation"
    )
    if (
        code_integrity_observation
        or kernel_permission_observation
        or _windows_unbound_observation(data)
    ):
        if any(
            _get(data, field) is not None
            for field in (
                "process.guid",
                "process.pid",
                "process.start_identity",
                "process.parent.guid",
                "process.parent.pid",
                "process.parent.start_identity",
            )
        ):
            raise ValueError("Unbound observations cannot invent an execution identity")
    else:
        _text(_get(data, "process.guid"), "process.guid")
    for path in (
        "host.name",
        "host.os.type",
        "user.name",
        "process.parent.guid",
        "process.name",
        "process.executable",
        "process.parent.name",
        "event.action",
        "event.module",
        "event.code",
        "event.provider",
        "file.path",
        "registry.path",
        "dns.question.name",
        "agent.collector",
    ):
        value = _get(data, path)
        if value is not None:
            _text(value, path, 512)
    command = _get(data, "process.command_line")
    if command is not None and (not isinstance(command, str) or len(command) > 8192):
        raise ValueError("process.command_line must be at most 8192 characters")
    script = data.get("powershell")
    if script is not None:
        allowed = {"script_block", "original_length", "sha256", "truncated", "script_block_id",
                   "message_number", "message_total", "complete"}
        required = {"script_block", "original_length", "sha256", "truncated", "complete"}
        if (not isinstance(script, dict) or set(script) - allowed or not required <= set(script)
            or _get(data, "event.provider") != "Microsoft-Windows-PowerShell/Operational"
            or _get(data, "event.code") not in {"4103", "4104"}
            or _get(data, "event.module") != "script"):
            raise ValueError("PowerShell observation requires an allowlisted provider and typed fidelity metadata")
        text = script["script_block"]
        length = script["original_length"]
        sha = script["sha256"]
        if (not isinstance(text, str) or len(text) > 8192 or type(length) is not int
            or not len(text) <= length <= 16 * 1024 * 1024 or type(script["truncated"]) is not bool
            or script["truncated"] != (length > len(text)) or not isinstance(sha, str)
            or not re.fullmatch(r"[0-9a-f]{64}", sha)):
            raise ValueError("Invalid PowerShell text length, digest or truncation metadata")
        if not script["truncated"] and hashlib.sha256(text.encode()).hexdigest() != sha:
            raise ValueError("PowerShell untruncated text digest mismatch")
        if "script_block_id" in script:
            _text(script["script_block_id"], "script_block_id", 256)
        number, total = script.get("message_number"), script.get("message_total")
        if ((number is None) != (total is None) or
            (number is not None and (type(number) is not int or type(total) is not int
             or not 1 <= number <= total <= 10000)) or type(script["complete"]) is not bool
            or script["complete"] and (number != 1 or total != 1 or script["truncated"])):
            raise ValueError("PowerShell fragment completeness cannot be invented")
    for path in (
        "process.pid",
        "process.parent.pid",
        "source.port",
        "destination.port",
    ):
        value = _get(data, path)
        maximum = 65535 if path.endswith("port") else 2**32 - 1
        if value is not None and (type(value) is not int or not 0 <= value <= maximum):
            raise ValueError(path + " must be a bounded integer")
    for path in ("source.ip", "destination.ip"):
        value = _get(data, path)
        if value is not None:
            try:
                if not isinstance(value, str):
                    raise ValueError("IP must be a string")  # noqa: TRY004 - Invalid JSON is HTTP 400.
                _put(data, path, str(ipaddress.ip_address(value)))
            except ValueError:
                raise ValueError(path + " must be an IP address") from None
    _timestamp(data.get("@timestamp"))
    return data


def parse_event(event, format, index, expected_host=None):
    """Adapt an agent envelope, normalized XDR event, or original Sysmon JSON.

    `expected_host` is for a trusted collector binding. A caller-supplied host is
    telemetry, not a substitute for AEGIS enrollment authentication.
    """
    indexes = entities.exact_indexes([index])
    if not isinstance(event, dict) or format not in {"agent", "server", "legacy"}:
        raise ValueError("Expected agent, server or legacy endpoint event")
    identifier = _text(event.get("id"), "event id", 200)
    session_id = None
    if format == "legacy":
        raw = event.get("data")
        if not isinstance(raw, dict):
            raise ValueError("Legacy event requires data object")
        data = {}
        fields = {
            "EndpointId": "host.id",
            "User": "user.name",
            "ProcessGuid": "process.guid",
            "ParentProcessGuid": "process.parent.guid",
            "ProcessId": "process.pid",
            "CommandLine": "process.command_line",
            "SourceIp": "source.ip",
            "SourcePort": "source.port",
            "DestinationIp": "destination.ip",
            "DestinationPort": "destination.port",
            "Protocol": "network.protocol",
            "TargetFilename": "file.path",
        }
        for source, destination in fields.items():
            if raw.get(source) is not None:
                value = raw[source]
                if (
                    destination.endswith(".port")
                    and isinstance(value, str)
                    and value.isdecimal()
                ):
                    value = int(value)
                _put(data, destination, value)
        if raw.get("Image"):
            _put(
                data, "process.name", ntpath.basename(_text(raw["Image"], "Image", 512))
            )
        instant = _timestamp(raw.get("UtcTime"), legacy=True)
        data["@timestamp"] = datetime.fromtimestamp(instant, UTC).isoformat()
        actions = {
            "1": "process_created",
            "3": "network_connection",
            "5": "process_terminated",
            "10": "process_access",
            "11": "file_created",
            "22": "dns_query",
        }
        _put(data, "event.action", actions.get(str(raw.get("EventID")), "legacy_event"))
    else:
        if format == "server":
            if event.get("source") != "edr":
                raise ValueError("Only endpoint source edr is supported")
            data = event.get("normalized")
            session_id = event.get("session_id")
            if session_id is not None:
                _text(session_id, "original XDR session ID")
        else:
            data = event.get("data")
    data = _typed(data)
    host = data["host"]["id"]
    if expected_host is not None and host != _text(expected_host, "expected host"):
        raise PermissionError(
            "Endpoint host differs from the trusted collector binding"
        )
    event_time = _timestamp(data["@timestamp"])
    severity = _get(data, "event.severity") or "info"
    if severity not in {"debug", "info", "low", "medium", "high", "critical"}:
        raise ValueError("Unsupported endpoint severity")
    xdr = {
        "schema": SCHEMA,
        "original_event_id": identifier,
        "original_session_id": session_id,
        "data": data,
    }
    # A retry preserves identity and content; GUID disambiguates PID reuse.
    event_id = hashlib.sha256(encode([SCHEMA, host, identifier]).encode()).hexdigest()
    raw = {"xdr": xdr}
    for key, path in (
        ("user", "user.name"),
        ("src_ip", "source.ip"),
        ("dest_ip", "destination.ip"),
        ("process_name", "process.name"),
        ("action", "event.action"),
    ):
        value = _get(data, path)
        if value is not None:
            raw[key] = value
    return {
        "event_id": event_id,
        "event_time": event_time,
        "source": "aegis-xdr",
        "sourcetype": "aegis:endpoint",
        "host": host,
        "severity": severity,
        "message": _get(data, "event.action") or "endpoint_event",
        "index": indexes[0],
        "raw": raw,
    }


def intake(store, who, data):
    if not isinstance(data, dict) or set(data) != {"format", "index", "events"}:
        raise ValueError("Expected format, index and events")
    events = data["events"]
    if not isinstance(events, list) or not 1 <= len(events) <= 200:
        raise ValueError("Expected 1..200 endpoint events")
    records = [parse_event(event, data["format"], data["index"]) for event in events]
    if len(encode(records).encode()) > MAX_RESPONSE:
        raise ValueError("Endpoint batch exceeds 2 MiB")
    # Keep current ACL and parser-route authorization stable through admission.
    with store.write_lock:
        with store.control() as db:
            actor = principal.current(db, who, EDIT)
            policies = pipeline.for_ingest(db, actor["tenant"])
            for record in records:
                routed, _ = pipeline.apply(
                    normalize(record), policies.get(record["source"])
                )
                if not principal.contains(
                    actor["allowed_indexes"], sorted({record["index"], routed["index"]})
                ):
                    raise PermissionError(
                        "Endpoint index or parser route exceeds current permissions"
                    )
        return store.ingest(
            actor["tenant"],
            records,
            actor["name"],
            allowed_indexes=actor["allowed_indexes"],
            authorization=lambda db: principal.current(db, who, EDIT)[
                "allowed_indexes"
            ],
        )


def _selection(store, who, start, end, host):
    start, end = entities.window(start, end)
    if host is not None:
        _text(host, "host")
    with principal.transaction(store, who) as (_, actor):
        predicate, indexes = index_predicate(actor["allowed_indexes"])
    where = (
        "tenant=? AND event_time>=? AND event_time<? AND json_extract_string(raw,'$.xdr.schema')=? AND "
        + predicate
    )
    args = [actor["tenant"], start, end, SCHEMA, *indexes]
    if host is not None:
        where += " AND host=?"
        args.append(host)
    return actor, where, args


def _analytics(store, *args, **kwargs):
    try:
        return store.analytics_query(*args, **kwargs)
    except RuntimeError as exc:
        raise CapacityError(str(exc)) from None


def telemetry(store, who, start, end, host=None, limit=100, cancel=None):
    if type(limit) is not int or not 1 <= limit <= 500:
        raise ValueError("Endpoint telemetry limit must be 1..500")
    actor, where, args = _selection(store, who, start, end, host)
    result = _analytics(
        store,
        "SELECT event_id,event_time,index_name,host,json_extract(raw,'$.xdr') AS xdr,count(*) OVER() AS total FROM events_all WHERE "
        + where
        + " ORDER BY event_time,event_id LIMIT ?",
        [*args, limit],
        cancel=cancel,
        max_rows=limit,
        timeout=min(10, store.settings.query_timeout),
    )
    rows = result["rows"]
    total = rows[0]["total"] if rows else 0
    for row in rows:
        row.pop("total")
        row["xdr"] = json.loads(row["xdr"])
    principal.recheck(store, actor)
    return {
        "rows": rows,
        "total": total,
        "returned": len(rows),
        "truncated": total > len(rows),
        "limit": limit,
        "start": start,
        "end": end,
    }


def process_tree(store, who, start, end, host=None, cancel=None):
    actor, where, args = _selection(store, who, start, end, host)
    until = time.monotonic() + min(10, store.settings.query_timeout)
    rows = _analytics(
        store,
        "SELECT event_id,event_time,index_name,host,json_extract(raw,'$.xdr') AS xdr FROM events_all WHERE "
        + where
        + " ORDER BY event_time,event_id",
        args,
        cancel=cancel,
        max_rows=MAX_EVENTS,
        timeout=max(0.001, until - time.monotonic()),
    )["rows"]
    nodes, edges = {}, {}

    def node(host_id, guid):
        key = hashlib.sha256(
            encode([actor["tenant"], host_id, guid]).encode()
        ).hexdigest()
        if key not in nodes:
            if len(nodes) >= MAX_NODES:
                raise CapacityError(
                    "Endpoint process node bound exceeded; narrow the window"
                )
            nodes[key] = {
                "id": key,
                "host": host_id,
                "guid": guid,
                "parent": None,
                "placeholder": True,
                "pid": None,
                "name": None,
                "command_line": None,
                "event_count": 0,
                "first": None,
                "last": None,
                "terminated": False,
                "evidence": [],
                "original_session_ids": [],
            }
        return nodes[key]

    for row in rows:
        if time.monotonic() >= until or (
            cancel and (cancel() if callable(cancel) else cancel.is_set())
        ):
            raise CapacityError("Endpoint projection cancelled or deadline exceeded")
        xdr = json.loads(row["xdr"])
        data = _typed(xdr.get("data"))
        host_id, guid = data["host"]["id"], _get(data, "process.guid")
        if host_id != row["host"]:
            raise ConflictError(
                "Stored endpoint host does not match telemetry identity"
            )
        if guid is None:
            continue  # An unbound observation does not establish an executed process node.
        item = node(host_id, guid)
        parent_guid = _get(data, "process.parent.guid")
        parent = node(host_id, parent_guid) if parent_guid else None
        if parent:
            if item["parent"] and item["parent"] != parent["id"]:
                raise ConflictError("Conflicting parent GUID for one endpoint process")
            item["parent"] = parent["id"]
            edge = edges.setdefault(
                (parent["id"], item["id"]),
                {
                    "source": parent["id"],
                    "target": item["id"],
                    "relation": "reported_parent_guid",
                    "evidence": [],
                    "reported_events": 0,
                },
            )
            edge["reported_events"] += 1
            if len(edge["evidence"]) < 20:
                edge["evidence"].append(
                    {
                        "event_id": row["event_id"],
                        "index": row["index_name"],
                        "event_time": row["event_time"],
                    }
                )
        pid = _get(data, "process.pid")
        if item["pid"] is not None and pid is not None and item["pid"] != pid:
            raise ConflictError("Conflicting PID for one endpoint process GUID")
        item.update(
            placeholder=False,
            pid=pid if pid is not None else item["pid"],
            name=_get(data, "process.name") or item["name"],
            command_line=_get(data, "process.command_line") or item["command_line"],
        )
        item["event_count"] += 1
        item["first"] = (
            row["event_time"]
            if item["first"] is None
            else min(item["first"], row["event_time"])
        )
        item["last"] = row["event_time"]
        item["terminated"] |= _get(data, "event.action") == "process_terminated"
        if len(item["evidence"]) < 20:
            item["evidence"].append(
                {
                    "event_id": row["event_id"],
                    "index": row["index_name"],
                    "event_time": row["event_time"],
                }
            )
        sid = xdr.get("original_session_id")
        if sid and sid not in item["original_session_ids"]:
            _text(sid, "original session ID")
            item["original_session_ids"].append(sid)
    sessions = {}
    for item in nodes.values():
        root, seen = item, set()
        while root["parent"]:
            if time.monotonic() >= until or (
                cancel and (cancel() if callable(cancel) else cancel.is_set())
            ):
                raise CapacityError(
                    "Endpoint projection cancelled or deadline exceeded"
                )
            if root["id"] in seen:
                raise ConflictError("Endpoint parent GUID cycle")
            seen.add(root["id"])
            root = nodes[root["parent"]]
        session = sessions.setdefault(
            root["id"],
            {
                "id": "projection:" + root["id"],
                "host": root["host"],
                "root": root["id"],
                "nodes": [],
                "event_count": 0,
            },
        )
        session["nodes"].append(item["id"])
        session["event_count"] += item["event_count"]
    result = {
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "sessions": list(sessions.values()),
        "matched_events": len(rows),
        "complete_within_window": True,
        "start": start,
        "end": end,
        "limits": {
            "events": MAX_EVENTS,
            "nodes": MAX_NODES,
            "evidence_per_node_or_edge": 20,
        },
        "semantics": "Sensor-reported same-host process GUID parentage only. PID is display metadata. Projection sessions are connected trees in this authorized window, not AEGIS persisted session lifecycle, ownership or network causation.",
    }
    if len(encode(result).encode()) > MAX_RESPONSE:
        raise CapacityError("Endpoint process projection exceeds 2 MiB")
    principal.recheck(store, actor)
    return result


class Bridge:
    """Disabled by default; explicit HTTPS/Bearer/IP/tenant-bound read-only client."""

    def __init__(self, config=None):
        self.config = copy.deepcopy(config)
        self.slot = threading.BoundedSemaphore(1)
        if config is None:
            return
        required = {
            "base_url",
            "allowed_hosts",
            "allowed_ips",
            "secret_env",
            "bindings",
        }
        if (
            not isinstance(config, dict)
            or not required <= set(config)
            or set(config) - required - {"ca_file", "certificate_sha256"}
        ):
            raise ValueError("Invalid XDR bridge configuration fields")
        parsed = urlparse(config["base_url"])
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("XDR bridge requires an HTTPS server origin")
        if (
            not isinstance(config["allowed_hosts"], list)
            or parsed.hostname not in config["allowed_hosts"]
        ):
            raise ValueError("XDR server hostname must be explicitly allowlisted")
        if (
            not isinstance(config["allowed_ips"], list)
            or not 1 <= len(config["allowed_ips"]) <= 16
        ):
            raise ValueError("XDR bridge requires 1..16 explicit server IPs")
        self.ips = {str(ipaddress.ip_address(value)) for value in config["allowed_ips"]}
        if not isinstance(config["secret_env"], str) or not re.fullmatch(
            r"[A-Z][A-Z0-9_]{0,127}", config["secret_env"]
        ):
            raise ValueError(
                "XDR bridge requires a secret environment variable reference"
            )
        pin = config.get("certificate_sha256")
        if pin is not None and (
            not isinstance(pin, str) or not re.fullmatch(r"[0-9a-f]{64}", pin)
        ):
            raise ValueError(
                "XDR certificate pin must be a lowercase SHA256 hex digest"
            )
        if (
            not isinstance(config["bindings"], dict)
            or not 1 <= len(config["bindings"]) <= 64
        ):
            raise ValueError("XDR bridge requires explicit tenant bindings")
        for tenant, binding in config["bindings"].items():
            _text(tenant, "local tenant")
            if not isinstance(binding, dict) or set(binding) != {
                "remote_tenant",
                "hosts",
                "indexes",
            }:
                raise ValueError("Binding requires remote_tenant, hosts and indexes")
            _text(binding["remote_tenant"], "remote tenant")
            entities.exact_indexes(binding["indexes"])
            if (
                not isinstance(binding["hosts"], list)
                or not 1 <= len(binding["hosts"]) <= 256
            ):
                raise ValueError("Binding requires 1..256 explicit endpoint hosts")
            for host in binding["hosts"]:
                _text(host, "endpoint host")
        self.host, self.port = parsed.hostname, parsed.port or 443
        self.context = ssl.create_default_context(cafile=config.get("ca_file"))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2

    def status(self):
        return {
            "configured": self.config is not None,
            "credential_available": bool(
                self.config and os.environ.get(self.config["secret_env"])
            ),
            "remote_read_only": True,
            "agent_supported_actions": READ_ONLY,
            "containment_enabled": False,
            "containment_reason": "This legacy remote bridge is read-only. Native xSERA enrolled agents support separately authorized typed isolation/release through their evidence-bound command queue and finite local safety lease.",
            "automatic_import": False,
        }

    def summary(self, store, who):
        with principal.transaction(store, who, ("admin",)) as (_, actor):
            binding = self.config and self.config["bindings"].get(actor["tenant"])
            if not binding:
                raise ValueError("XDR remote bridge is not configured for this tenant")
            if not principal.contains(actor["allowed_indexes"], binding["indexes"]):
                raise PermissionError("XDR binding exceeds current index permissions")
        secret = os.environ.get(self.config["secret_env"], "")
        if (
            not secret
            or len(secret) > 512
            or not secret.isascii()
            or any(ord(c) < 33 for c in secret)
        ):
            raise ValueError("XDR bridge credential is unavailable or malformed")
        if not self.slot.acquire(blocking=False):
            raise CapacityError("XDR bridge request is already in progress")
        connection, timer = None, None
        try:
            # A numeric explicit target avoids DNS rebinding and resolver stalls;
            # HTTPSConnection retains the configured hostname for TLS SNI/checks.
            address = min(self.ips)
            connection = http.client.HTTPSConnection(
                self.host, self.port, timeout=3, context=self.context
            )
            connection._create_connection = (
                lambda unused, timeout=None, source_address=None: (
                    socket.create_connection(
                        (address, self.port), timeout, source_address
                    )
                )
            )
            connection.connect()
            bound_socket = connection.sock

            def expire():
                try:
                    bound_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            timer = threading.Timer(4, expire)
            timer.daemon = True
            timer.start()
            pin = self.config.get("certificate_sha256")
            if (
                pin
                and hashlib.sha256(
                    connection.sock.getpeercert(binary_form=True)
                ).hexdigest()
                != pin
            ):
                raise PermissionError("XDR server certificate pin mismatch")
            connection.request(
                "GET",
                "/api/agents",
                headers={
                    "Authorization": "Bearer " + secret,
                    "Accept": "application/json",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            if response.status != 200:
                raise ValueError("XDR summary returned HTTP " + str(response.status))
            raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise CapacityError("XDR summary exceeds 2 MiB")
            payload = json.loads(raw)
            if not isinstance(payload, dict) or not isinstance(
                payload.get("agents"), list
            ):
                raise ValueError("Invalid XDR agent summary")  # noqa: TRY004 - Invalid remote JSON is HTTP 400.
            agents = []
            for item in payload["agents"]:
                if (
                    not isinstance(item, dict)
                    or item.get("tenant") != binding["remote_tenant"]
                    or item.get("host") not in binding["hosts"]
                ):
                    continue
                for key in ("id", "host", "version"):
                    _text(item.get(key), "remote agent " + key)
                last_seen = item.get("last_seen")
                if (
                    type(last_seen) not in (int, float)
                    or not math.isfinite(last_seen)
                    or last_seen < 0
                ):
                    raise ValueError("Invalid remote agent last_seen")
                if (
                    type(item.get("online")) is not bool
                    or type(item.get("revoked")) is not bool
                    or not isinstance(item.get("capabilities"), list)
                ):
                    raise ValueError("Invalid remote agent state")
                agents.append(
                    {
                        key: item.get(key)
                        for key in (
                            "id",
                            "host",
                            "version",
                            "last_seen",
                            "online",
                            "revoked",
                        )
                    }
                )
                agents[-1]["capabilities"] = [
                    action
                    for action in READ_ONLY
                    if action in item.get("capabilities", [])
                ]
            principal.recheck(store, actor, ("admin",))
            return {
                "agents": agents,
                "returned": len(agents),
                "read_only": True,
                "containment_enabled": False,
            }
        except PermissionError:
            raise
        except (
            OSError,
            http.client.HTTPException,
            json.JSONDecodeError,
            UnicodeDecodeError,
        ):
            raise ValueError(
                "XDR summary failed; verify server configuration and TLS"
            ) from None
        finally:
            if timer:
                timer.cancel()
            if connection:
                connection.close()
            self.slot.release()


def load_config(path=None):
    if path is None:
        return Bridge()
    path = Path(path)
    if not path.is_file() or path.stat().st_size > 64 * 1024:
        raise ValueError("XDR bridge config must be a JSON file <=64 KiB")
    return Bridge(json.loads(path.read_text(encoding="utf-8")))
