"""Versioned, conservative security field mappings; no CIM conformance claim.

Explicit source fields supply canonical values. A supplied raw.security object
is validated and checked against those fields; it cannot suppress enrichment or
override a conflicting source value. Consistent source-only fields are labelled
unverified. Mapping metadata records source paths, not source authenticity.
"""

import copy
import ipaddress
import json
import math
import re

SCHEMA = "sapientia-security"
VERSION = 1
MAPPINGS = {
    "windows-eventdata-v1": "Windows 4624/4625 target logon identity and 4688 process creator",
    "cef-extension-v1": "Explicit CEF extension keys; ambiguous source/destination identities are omitted",
    "rfc5424-json-v1": "Complete JSON Syslog message with explicit structured security fields",
    "structured-fields-v1": "Explicit JSON, HEC event and OTLP attribute field names",
    "fortigate-kv-v1": "Validated FortiGate traffic/UTM key=value fields",
    "cisco-asa-connection-v1": "ASA 302013/302015/106023 bounded decoder; source assertions remain explicit",
    "managed-parser-v1": "Typed parser mapping checked against its actual source paths",
    "source-provided-v1": "Typed source-only fields, not independently verified",
}
AUTH_ACTIONS = {
    "authentication": None,
    "authenticate": None,
    "login": None,
    "logon": None,
    "login_failed": "failure",
    "logon_failed": "failure",
    "authentication_failure": "failure",
    "authentication_failed": "failure",
    "login_success": "success",
    "logon_success": "success",
    "authentication_success": "success",
    "authenticated": "success",
}
OTHER_ACTIONS = {
    "process_create": "process_create",
    "process_creation": "process_create",
    "process_created": "process_create",
    "process_start": "process_create",
    "process_inventory": "process_inventory",
    "memory_observation": "memory_observation",
    "process_terminated": "process_terminate",
    "network_connection": "network_connection",
    "connection_blocked": "network_connection",
    "dns_query": "dns_query",
    "file_created": "file_create",
    "file_deleted": "file_delete",
    "registry_value_set": "registry_change",
    "registry_value_renamed": "registry_change",
    "remote_thread_created": "remote_thread_create",
    "process_accessed": "process_access",
    "process_tampered": "process_tamper",
    "powershell_command": "script_execution",
    "powershell_script_block": "script_execution",
    "allow": "allow",
    "allowed": "allow",
    "permit": "allow",
    "permitted": "allow",
    "block": "block",
    "blocked": "block",
    "deny": "block",
    "denied": "block",
    "logout": "logout",
    "logoff": "logout",
}
OUTCOMES = {
    "success": "success",
    "successful": "success",
    "succeeded": "success",
    "ok": "success",
    "failure": "failure",
    "failed": "failure",
    "error": "failure",
    "unsuccessful": "failure",
}


def manifest():
    return {"schema": SCHEMA, "version": VERSION, "mappings": dict(MAPPINGS)}


def _get(root, path):
    for key in path:
        if not isinstance(root, dict) or key not in root:
            return None
        root = root[key]
    return root


def _path(prefix, path):
    return prefix + "".join(
        "." + key
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key)
        else "[" + json.dumps(key) + "]"
        for key in path
    )


def _text(value, limit=256):
    if not isinstance(value, str):
        return None
    value = value.strip()
    if (
        not value
        or value == "-"
        or "[REDACTED]" in value
        or len(value) > limit
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        return None
    return value


def _ip(value):
    value = _text(value)
    if value is None or "%" in value:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if address.is_unspecified:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return str(address.ipv4_mapped)
    return str(address)


def _pick(sources, paths, convert=_text):
    found = []
    for root, prefix in sources:
        for path in paths:
            value = convert(_get(root, path))
            if value is not None:
                found.append((value, _path(prefix, path)))
    distinct = {value for value, _ in found}
    if len(distinct) != 1:
        return None, [], len(distinct) > 1
    return found[0][0], sorted({path for _, path in found}), False


def _record(fields, provenance, conflicts, name, picked):
    value, paths, conflict = picked
    if conflict:
        conflicts.add(name)
    if value is not None:
        fields[name] = value
        provenance[name] = paths


def _action(fields, provenance, conflicts, action, outcome):
    action_value, action_paths, action_conflict = action
    outcome_value, outcome_paths, outcome_conflict = outcome
    if action_conflict:
        conflicts.add("action")
    if outcome_conflict:
        conflicts.add("outcome")
    implied = None
    if action_value in AUTH_ACTIONS:
        fields["action"] = "authentication"
        provenance["action"] = action_paths
        implied = AUTH_ACTIONS[action_value]
    elif action_value in OTHER_ACTIONS:
        fields["action"] = OTHER_ACTIONS[action_value]
        provenance["action"] = action_paths
    if implied and outcome_value and implied != outcome_value:
        conflicts.add("outcome")
    elif not outcome_conflict:
        if outcome_value:
            fields["outcome"] = outcome_value
            provenance["outcome"] = outcome_paths
        elif implied:
            fields["outcome"] = implied
            provenance["outcome"] = action_paths


def _action_text(value):
    text = _text(value)
    return text.lower() if text else None


def _outcome(value):
    text = _action_text(value)
    return OUTCOMES.get(text)


def _generic(sources):
    fields, provenance, conflicts = {}, {}, set()
    _record(
        fields,
        provenance,
        conflicts,
        "user",
        _pick(
            sources,
            [
                ("user",),
                ("username",),
                ("user_name",),
                ("principal",),
                ("user", "name"),
                ("user.name",),
                ("enduser.id",),
            ],
        ),
    )
    _record(
        fields,
        provenance,
        conflicts,
        "src_ip",
        _pick(
            sources,
            [
                ("src_ip",),
                ("source_ip",),
                ("src",),
                ("source", "address"),
                ("source", "ip"),
                ("source.address",),
            ],
            _ip,
        ),
    )
    _record(
        fields,
        provenance,
        conflicts,
        "dest_ip",
        _pick(
            sources,
            [
                ("dest_ip",),
                ("dst_ip",),
                ("destination_ip",),
                ("dst",),
                ("destination", "address"),
                ("destination", "ip"),
                ("destination.address",),
            ],
            _ip,
        ),
    )
    process = _pick(
        sources,
        [
            ("process_path",),
            ("process", "executable"),
            ("process", "path"),
            ("process.executable",),
        ],
        lambda value: _text(value, 1024),
    )
    if process[0] is None and not process[2]:
        process = _pick(
            sources,
            [("process",), ("process_name",), ("process", "name")],
            lambda value: _text(value, 1024),
        )
    _record(fields, provenance, conflicts, "process", process)
    for name, paths in {
        "process_guid": [("process", "guid")],
        "parent_process_guid": [("process", "parent", "guid")],
        "session_id": [("session", "id"), ("session_id",)],
        "device_id": [("host", "id"), ("device", "id")],
    }.items():
        _record(fields, provenance, conflicts, name, _pick(sources, paths))
    for name, kind, paths in [
        (
            "domain",
            "domain",
            [("domain",), ("dns", "question", "name"), ("dns", "name")],
        ),
        ("file_hash", "hash", [("file", "hash", "sha256"), ("file_hash",), ("hash",)]),
    ]:
        _record(
            fields,
            provenance,
            conflicts,
            name,
            _pick(sources, paths, lambda value, k=kind: _indicator(k, value)),
        )
    _action(
        fields,
        provenance,
        conflicts,
        _pick(
            sources, [("action",), ("event", "action"), ("event.action",)], _action_text
        ),
        _pick(
            sources, [("outcome",), ("event", "outcome"), ("event.outcome",)], _outcome
        ),
    )
    return fields, provenance, conflicts


def _windows(raw):
    candidates = [
        (raw, "raw", [("EventID",), ("System", "EventID")], "EventData"),
        (raw.get("Event"), "raw.Event", [("System", "EventID")], "EventData"),
        (raw.get("winlog"), "raw.winlog", [("event_id",)], "event_data"),
        (raw.get("win"), "raw.win", [("system", "eventID")], "eventdata"),
    ]
    for root, prefix, paths, data_name in candidates:
        data = _get(root, (data_name,))
        if not isinstance(data, dict):
            continue

        def event_number(value):
            if isinstance(value, dict):
                value = value.get("#text")
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, str))
                or str(value) not in {"4624", "4625", "4688"}
            ):
                return None
            return str(value)

        event_id, event_paths, conflict = _pick([(root, prefix)], paths, event_number)
        if event_id is None or conflict:
            continue
        fields, provenance, conflicts = {}, {}, set()
        fields["action"] = "process_create" if event_id == "4688" else "authentication"
        fields["outcome"] = "failure" if event_id == "4625" else "success"
        provenance["action"], provenance["outcome"] = event_paths, event_paths
        source = [(data, prefix + "." + data_name)]
        user_name = "SubjectUserName" if event_id == "4688" else "TargetUserName"
        domain_name = "SubjectDomainName" if event_id == "4688" else "TargetDomainName"
        user, user_paths, user_conflict = _pick(
            source, [(user_name,), (user_name[0].lower() + user_name[1:],)]
        )
        domain, domain_paths, domain_conflict = _pick(
            source, [(domain_name,), (domain_name[0].lower() + domain_name[1:],)]
        )
        if user_conflict or domain_conflict:
            conflicts.add("user")
        elif user and user != "S-1-0-0":
            if domain and domain != "." and "\\" not in user and "@" not in user:
                user = domain + "\\" + user
                user_paths += domain_paths
            if len(user) <= 256:
                fields["user"], provenance["user"] = user, user_paths
        _record(
            fields,
            provenance,
            conflicts,
            "src_ip",
            _pick(source, [("IpAddress",), ("ipAddress",)], _ip),
        )
        process_name = "NewProcessName" if event_id == "4688" else "ProcessName"
        _record(
            fields,
            provenance,
            conflicts,
            "process",
            _pick(
                source,
                [(process_name,), (process_name[0].lower() + process_name[1:],)],
                lambda value: _text(value, 1024),
            ),
        )
        return fields, provenance, conflicts
    return None


def _cef(extension):
    if isinstance(extension, dict):
        return extension
    if not isinstance(extension, str) or len(extension) > 65536:
        return None
    starts = list(re.finditer(r"(?:^|\s)([A-Za-z][A-Za-z0-9_]{0,63})=", extension))
    if not starts or starts[0].start() != 0 or len(starts) > 128:
        return None
    fields = {}
    for number, match in enumerate(starts):
        key = match[1]
        if key in fields:
            return None
        end = starts[number + 1].start() if number + 1 < len(starts) else len(extension)
        value = extension[match.end() : end].rstrip()
        # Consume escapes once, including the two characters in a literal slash.
        # Checking every slash separately would reject valid DOMAIN\\\\user values.
        decoded, offset = [], 0
        while offset < len(value):
            char = value[offset]
            if char == "\\":
                offset += 1
                if offset == len(value) or value[offset] not in "\\=nr":
                    return None
                char = {"n": "\n", "r": "\r"}.get(value[offset], value[offset])
            decoded.append(char)
            offset += 1
        fields[key] = "".join(decoded)
    return fields


def _cef_fields(extension):
    data = _cef(extension)
    if data is None:
        return None
    sources = [(data, "raw.extension")]
    fields, provenance, conflicts = {}, {}, set()
    _record(
        fields, provenance, conflicts, "user", _pick(sources, [("suser",), ("duser",)])
    )
    _record(fields, provenance, conflicts, "src_ip", _pick(sources, [("src",)], _ip))
    _record(fields, provenance, conflicts, "dest_ip", _pick(sources, [("dst",)], _ip))
    _record(
        fields,
        provenance,
        conflicts,
        "process",
        _pick(sources, [("sproc",), ("dproc",)], lambda value: _text(value, 1024)),
    )
    _action(
        fields,
        provenance,
        conflicts,
        _pick(sources, [("act",)], _action_text),
        _pick(sources, [("outcome",)], _outcome),
    )
    return fields, provenance, conflicts


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(
                "Duplicate JSON keys cannot supply canonical security fields"
            )
        result[key] = value
    return result


def _fortigate(event, raw):
    data = raw.get("fortigate")
    if event.get("sourcetype") != "fortigate:kv" or not isinstance(data, dict):
        return None
    fields, provenance, conflicts = {}, {}, set()
    for origin, target in (("srcip", "src_ip"), ("dstip", "dest_ip")):
        _record(
            fields,
            provenance,
            conflicts,
            target,
            _pick([(data, "raw.fortigate")], [(origin,)], _ip),
        )
    action = data.get("action")
    if (
        isinstance(action, str)
        and "[REDACTED]" not in action
        and isinstance(data.get("type"), str)
        and data["type"] in {"traffic", "utm"}
    ):
        fields["action"] = "network_connection"
        provenance["action"] = ["raw.fortigate.action"]
        outcome = (
            "blocked"
            if action in {"deny", "block", "blocked", "dropped"}
            else "observed"
            if action in {"accept", "allow", "close"}
            else None
        )
        if outcome:
            fields["outcome"] = outcome
            provenance["outcome"] = ["raw.fortigate.action"]
    return fields, provenance, conflicts


def _derive(event, raw):
    mapped = _fortigate(event, raw)
    if mapped is not None:
        return "fortigate-kv-v1", mapped
    mapping, mapped = "windows-eventdata-v1", _windows(raw)
    if mapped is None and event.get("sourcetype") == "cef":
        mapping, mapped = "cef-extension-v1", _cef_fields(raw.get("extension"))
    if mapped is None:
        sources = [(raw, "raw")]
        if isinstance(raw.get("event"), dict):
            sources.append((raw["event"], "raw.event"))
        if isinstance(raw.get("attributes"), dict):
            sources.append((raw["attributes"], "raw.attributes"))
        if isinstance(raw.get("xdr"), dict) and isinstance(
            raw["xdr"].get("data"), dict
        ):
            sources.append((raw["xdr"]["data"], "raw.xdr.data"))
        mapping = "structured-fields-v1"
        if event.get("sourcetype") == "syslog:rfc5424":
            message = event.get("message", "")
            if isinstance(message, str):
                message = message.removeprefix("- ").strip()
                if message.startswith("{") and len(message) <= 32768:
                    try:
                        payload = json.loads(message, object_pairs_hook=_unique_object)
                    except (ValueError, RecursionError):
                        payload = None
                    if isinstance(payload, dict):
                        sources.append((payload, "message.JSON"))
                        mapping = "rfc5424-json-v1"
        mapped = _generic(sources)
    return mapping, mapped


_METADATA = {
    "schema",
    "version",
    "mapping",
    "provenance",
    "conflicts",
    "unverified_fields",
}
_CONVERTERS = {
    "user": _text,
    "src_ip": _ip,
    "dest_ip": _ip,
    "process": lambda value: _text(value, 1024),
    "process_guid": _text,
    "parent_process_guid": _text,
    "session_id": _text,
    "device_id": _text,
    "domain": lambda value: _indicator("domain", value),
    "file_hash": lambda value: _indicator("hash", value),
    "action": _action_text,
    "outcome": lambda value: (
        value if value in {"success", "failure", "blocked", "observed"} else None
    ),
}


def _indicator(kind, value):
    from .lookups import normalize_indicator

    try:
        return normalize_indicator(kind, value)
    except ValueError:
        return None


def _provided(value):
    if not isinstance(value, dict) or len(value) > 64:
        raise ValueError("raw.security must be a bounded object")
    if "schema" in value and value["schema"] != SCHEMA:
        raise ValueError("Unsupported canonical security schema")
    if "version" in value and (
        type(value["version"]) is not int or value["version"] != VERSION
    ):
        raise ValueError("Unsupported canonical security version")
    if "mapping" in value and (
        not isinstance(value["mapping"], str) or value["mapping"] not in MAPPINGS
    ):
        raise ValueError("Unsupported canonical security mapping")
    provenance = value.get("provenance", {})
    if (
        not isinstance(provenance, dict)
        or len(provenance) > 64
        or any(
            not isinstance(paths, list)
            or len(paths) > 32
            or any(not isinstance(path, str) or len(path) > 256 for path in paths)
            for paths in provenance.values()
        )
    ):
        raise ValueError("Invalid canonical security provenance")
    for name in ("conflicts", "unverified_fields"):
        if name in value and (
            not isinstance(value[name], list)
            or len(value[name]) > 64
            or any(not isinstance(item, str) or len(item) > 64 for item in value[name])
        ):
            raise ValueError("Invalid canonical security metadata")
    fields = {}
    for name, item in value.items():
        if name in _METADATA:
            continue
        if not isinstance(name, str) or not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]{0,63}", name
        ):
            raise ValueError("Invalid canonical security field")
        if isinstance(item, str) and "[REDACTED]" in item:
            # Redacted placeholders are evidence, never an entity identity.
            continue
        if name in _CONVERTERS:
            try:
                converted = _CONVERTERS[name](item)
            except TypeError:
                converted = None
            if converted is None:
                raise ValueError("Invalid canonical security value: " + name)
            fields[name] = converted
        elif (
            isinstance(item, str)
            and _text(item, 1024) is not None
            or (
                type(item) is bool
                or (type(item) is int and -(2**63) <= item < 2**63)
                or (type(item) is float and math.isfinite(item))
            )
        ):
            fields[name] = item
        else:
            raise ValueError(
                "Canonical security extensions must be bounded scalar values"
            )
    return fields, provenance


def normalize(event):
    if not isinstance(event, dict):
        raise TypeError("Security normalization requires an event object")
    result = copy.deepcopy(event)
    raw = result.get("raw")
    if not isinstance(raw, dict):
        return result
    supplied = raw.get("security")
    supplied_fields, supplied_paths = (
        _provided(supplied) if "security" in raw else ({}, {})
    )
    mapping, mapped = _derive(result, raw)
    fields, provenance, conflicts = mapped
    unverified, parser_fields = [], []
    for name, value in supplied_fields.items():
        if name in conflicts or (name in fields and fields[name] != value):
            raise ValueError(
                "Canonical security conflicts with explicit source field: " + name
            )
        if name in fields:
            continue
        fields[name] = value
        paths = supplied_paths.get(name, [])
        # A parser claim is checked against actual data, never trusted merely
        # because the collector supplied metadata bearing a server mapping name.
        verified = (
            supplied.get("mapping") == "managed-parser-v1"
            and paths
            and all(
                re.fullmatch(r"raw(?:\.[A-Za-z_][A-Za-z0-9_]{0,63}){1,5}", path)
                and not path.startswith("raw.security.")
                and _get(result, path.split(".")) == value
                for path in paths
            )
        )
        provenance[name] = sorted(set(paths)) if verified else ["raw.security." + name]
        (parser_fields if verified else unverified).append(name)
    if parser_fields:
        mapping = "managed-parser-v1"
    elif fields and len(unverified) == len(fields):
        mapping = "source-provided-v1"
    raw.pop("security", None)
    if fields:
        raw["security"] = {
            "schema": SCHEMA,
            "version": VERSION,
            "mapping": mapping,
            **fields,
            "provenance": provenance,
        }
        if conflicts:
            raw["security"]["conflicts"] = sorted(conflicts)
        if unverified:
            raw["security"]["unverified_fields"] = sorted(unverified)
    return result
