"""Bounded, source-reported provenance research features and summaries.

Original implementations inspired by published research, not paper reproductions.
The graph is an explanation of admitted telemetry, never proof of actual data flow.
No evaluation labels, event IDs, host names or campaign labels train the model.
"""

import hashlib
import ipaddress
import json
import math
import re
from collections import Counter, defaultdict

SCHEMA = "xsera.research-edge.v1"
ACTIONS = ("execute", "read", "write", "connect", "authentication", "registry", "other")
FEATURES = tuple([f"source_token_{i}" for i in range(8)] + [f"target_token_{i}" for i in range(8)] + [
    "command_length", "encoded_command", "external_destination", "destination_port",
    "executable_target", "registry_target", "parent_identity_present", "process_identity_present"])
MAX_EVENTS = 32
MAX_NODES = 128
MAX_EDGES = 128
SKETCH_SIZE = 128
MAX_TEMPORAL_KEYS = 128
LABEL_FIELDS = frozenset({"ground_truth", "scenario_label", "expected_detected", "attack_label", "label", "campaign", "campaign_id"})


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _text(value, limit=4096):
    return value[:limit] if isinstance(value, str) else ""


def normalize_path(value):
    """Group nondeterministic path tokens for explanation, retaining original elsewhere."""
    value = _text(value).replace("\\", "/").lower()
    value = re.sub(r"s-1-\d+(?:-\d+){2,}", "<sid>", value)
    value = re.sub(r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?", "<uuid>", value)
    value = re.sub(r"(?<=/users/)[^/]+", "<user>", value)
    value = re.sub(r"\b[0-9a-f]{16,}\b", "<hash>", value)
    return re.sub(r"\b\d{4,}\b", "<number>", value)


def _get(value, path):
    for part in path.split("."):
        value = value.get(part) if isinstance(value, dict) else None
    return value


def _pick(*values):
    return next((value for value in values if value is not None and value != ""), None)


def inputs(event):
    raw = event.get("raw", {})
    if isinstance(raw, str):
        raw = json.loads(raw)
    raw = raw if isinstance(raw, dict) else {}
    projection = event.get("projection") or {}
    security = raw.get("security") if isinstance(raw.get("security"), dict) else {}
    endpoint = _get(raw, "xdr.data") or {}
    def take(field, *paths):
        return _pick(security.get(field), raw.get(field), *[_get(endpoint, p) for p in paths])
    process = projection.get("process", {})
    device = projection.get("device", {})
    return {
        "action": _text(_pick(projection.get("action"), take("action", "event.action"), raw.get("event_type")), 120).lower(),
        "command": _text(take("command_line", "process.command_line"), 8192),
        "image": _text(_pick(process.get("executable"), process.get("path"), take("image", "process.executable"))),
        "file": _text(take("file_path", "file.path")),
        "sha256": _text(_pick(take("file_sha256", "file.hash.sha256"), take("sha256")), 64),
        "registry": _text(take("registry_path", "registry.path")),
        "dest_ip": _text(take("dest_ip", "destination.ip"), 128),
        "dest_port": take("dest_port", "destination.port"),
        "src_ip": _text(take("src_ip", "source.ip"), 128),
        "src_port": take("src_port", "source.port"),
        "transport": _text(take("transport", "network.transport"), 32),
        "process_guid": _text(process.get("guid"), 256),
        "start": _text(process.get("start_identity"), 256),
        "parent_guid": _text(process.get("parent_guid"), 256),
        "parent_start": _text(process.get("parent_start_identity"), 256),
        "device": _text(device.get("uid"), 256),
        "boot": _text(device.get("boot_id"), 256),
        "source_id": _text(projection.get("source_id"), 256),
        "account": _text(projection.get("account"), 256),
        "realm": _text(projection.get("realm"), 256),
        "os": _text(_pick(take("os", "host.os.type"), raw.get("platform")), 64).lower(),
    }


def action_class(value):
    if any(p in value for p in ("exec", "process_start", "procstart", "spawn")):
        return "execute"
    if any(p in value for p in ("connect", "network", "netconn", "socket", "dns")):
        return "connect"
    if any(p in value for p in ("auth", "login", "logon", "credential")):
        return "authentication"
    if any(p in value for p in ("registry", "regmod", "reg_")):
        return "registry"
    if any(p in value for p in ("write", "create", "modify", "delete", "unlink", "rename")):
        return "write"
    if any(p in value for p in ("read", "open", "load")):
        return "read"
    return "other"


def _tokens(text):
    result = [0.0] * 8
    tokens = re.findall(r"[a-z][a-z0-9_.-]{0,63}", normalize_path(text))[:64]
    for token in tokens:
        code = hashlib.sha256(token.encode()).digest()
        result[code[0] % 8] += 1.0 / max(1, len(tokens))
    return result


def event_features(event):
    data = inputs(event)
    target = data["registry"] or data["file"] or data["dest_ip"]
    try:
        external = float(ipaddress.ip_address(data["dest_ip"]).is_global)
    except ValueError:
        external = 0.0
    port = data["dest_port"]
    try:
        port = float(port)
    except (ValueError, TypeError):
        port = 0.0
    if not math.isfinite(port):
        port = 0.0
    command = data["command"].lower()
    values = _tokens(data["image"] + " " + data["command"]) + _tokens(target) + [
        len(data["command"])/8192,
        float(bool(re.search(r"(?:^|\s)-(?:enc|encodedcommand)(?:\s|$)", command))),
        external, min(65535.0, max(0.0, port))/65535,
        float(target.lower().endswith((".exe", ".dll", ".ps1", ".sh", ".elf"))),
        float(bool(data["registry"])), float(bool(data["parent_guid"] and data["parent_start"])),
        float(bool(data["process_guid"] and data["start"])),
    ]
    return {"schema": SCHEMA, "values": values, "features": dict(zip(FEATURES, values)),
            "target": ACTIONS.index(action_class(data["action"])), "target_name": action_class(data["action"]),
            "missing": [key for key in ("image", "process_guid", "start", "source_id", "device", "boot") if not data[key]]}


def process_identity(data, parent=False):
    guid, start = (data["parent_guid"], data["parent_start"]) if parent else (data["process_guid"], data["start"])
    if not all((data["source_id"], data["device"], data["boot"], guid, start)):
        return None
    return "process:" + digest([data["source_id"], data["device"], data["boot"], data["realm"], data["account"], guid, start])


def empty_state():
    return {"schema": SCHEMA, "bins": [0.0]*SKETCH_SIZE, "total": 0, "last_time": None,
            "transitions": {}, "processes": {}, "actions": {}, "observed": 0}


def _state(state):
    state = json.loads(json.dumps(state)) if state is not None else empty_state()
    if (not isinstance(state, dict) or set(state) != set(empty_state()) or state.get("schema") != SCHEMA
            or not isinstance(state["bins"], list) or len(state["bins"]) != SKETCH_SIZE
            or any(type(v) not in (int, float) or not math.isfinite(v) or not 0 <= v <= 1e9 for v in state["bins"])
            or any(not isinstance(state[k], dict) or len(state[k]) > MAX_TEMPORAL_KEYS for k in ("transitions", "processes", "actions"))):
        raise ValueError("Invalid bounded research state")
    for key in ("total", "observed"):
        if type(state[key]) is not int or not 0 <= state[key] <= 10**12:
            raise ValueError("Invalid research state counter")
    if state["last_time"] is not None and (type(state["last_time"]) not in (int, float) or not math.isfinite(state["last_time"])):
        raise ValueError("Invalid research state timestamp")
    for count in state["transitions"].values():
        if type(count) is not int or not 0 <= count <= 10**9:
            raise ValueError("Invalid transition count")
    if any(not isinstance(k,str) or len(k)>128 for name in ("transitions","processes","actions") for k in state[name]):
        raise ValueError("Invalid bounded state identity")
    if any(k not in ACTIONS or type(v) is not int or not 0<=v<=10**9 for k,v in state["actions"].items()):
        raise ValueError("Invalid action statistics")
    for item in state["processes"].values():
        if not isinstance(item, dict) or item.get("action") not in ACTIONS or type(item.get("time")) not in (int, float) or not math.isfinite(item["time"]):
            raise ValueError("Invalid temporal process state")
    return state


def _remember(mapping, key, value):
    if key in mapping:
        del mapping[key]
    mapping[key] = value
    while len(mapping) > MAX_TEMPORAL_KEYS:
        if isinstance(value,dict):
            oldest=min(mapping,key=lambda k:(mapping[k]["time"],k))
        else:
            oldest=min(mapping,key=lambda k:(mapping[k],k))
        del mapping[oldest]


def _ttp(data):
    command = data["command"].lower()
    paths = (data["file"] + " " + data["registry"]).lower()
    tags = []
    if "powershell" in (data["image"] + command).lower() and re.search(r"-(?:enc|encodedcommand)(?:\s|$)", command):
        tags.append("T1059.001")
    if "currentversion\\run" in paths or "currentversion/run" in paths:
        if any(token in data["action"] for token in ("write","create","set","modify")):
            tags.append("T1547.001")
    if "lsass" in (command + paths) and any(x in command for x in ("dump", "comsvcs", "minidump")):
        tags.append("T1003.001")
    if any(x in command for x in ("psexec", "wmic /node", "winrm", "invoke-command -computername")):
        tags.append("T1021")
    return tags


def analyze_graph(events, scores=None, state=None):
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS:
        raise ValueError("1..32 original events required for bounded graph analysis")
    if len({e["event_id"] for e in events}) != len(events):
        raise ValueError("Graph originals must be unique")
    if any(type(e.get("event_time")) not in (int, float) or not math.isfinite(e["event_time"]) for e in events):
        raise ValueError("Finite original event timestamps required")
    state = _state(state)
    initial_bins = list(state["bins"])
    scores = scores or {}
    nodes, edges, temporal, ttps = {}, [], [], []
    service_ids=set()
    missing = []
    prisma = {"service_ipc_candidates": [], "temporal_service_partitions": [], "path_groups": {}, "leaf_data_groups": []}
    services = {"svchost.exe", "services.exe", "lsass.exe", "explorer.exe", "msmpeng.exe"}
    def node(identifier, kind, label, event_id):
        if identifier not in nodes and len(nodes) < MAX_NODES:
            nodes[identifier] = {"id": identifier, "kind": kind, "label": _text(label, 512), "event_ids": []}
        if identifier in nodes and event_id not in nodes[identifier]["event_ids"]:
            nodes[identifier]["event_ids"].append(event_id)
    for event in sorted(events, key=lambda e: (e["event_time"], e["event_id"])):
        identifier, at, data = event["event_id"], event["event_time"], inputs(event)
        source = process_identity(data)
        feature = event_features(event)
        action = feature["target_name"]
        if not source:
            missing.append({"event_id": identifier, "reason": "source/device/boot/process incarnation incomplete; no inferred process linkage"})
            source = "unlinked:" + digest(identifier)
        node(source, "process" if not source.startswith("unlinked:") else "unlinked", data["image"] or "unknown process", identifier)
        target_path = data["registry"] or data["file"]
        if target_path:
            # A path alone is not a versioned file identity. Do not claim a
            # write/read dependency between unrelated path observations.
            versioned = all((data["source_id"],data["device"],data["boot"])) and re.fullmatch(r"[0-9a-fA-F]{64}", data["sha256"])
            version = data["sha256"] if versioned else identifier
            target = "data:" + digest([data["source_id"], data["device"], data["boot"], target_path, version])
            node(target, "registry" if data["registry"] else "file", target_path, identifier)
            group = normalize_path(target_path)
            prisma["path_groups"].setdefault(group, []).append(identifier)
        elif data["dest_ip"]:
            target = "flow:" + digest([data["source_id"], data["device"], data["boot"], source, data["src_ip"], data["src_port"], data["dest_ip"], data["dest_port"], data["transport"]])
            node(target, "socket", data["dest_ip"] + ":" + str(data["dest_port"] or "?"), identifier)
        else:
            target = "event:" + digest(identifier)
            node(target, "observation", action, identifier)
        parent = process_identity(data, parent=True)
        if parent and source.startswith("process:"):
            node(parent, "process", "reported parent", identifier)
            edges.append({"from": parent, "to": source, "action": "reported_parent", "event_id": identifier, "time": at, "basis": "reported_process_incarnations"})
        access = "read" if any(x in data["action"] for x in ("read","query","load")) else "write" if any(x in data["action"] for x in ("write","create","set","modify","delete")) else "unknown"
        left, right = (target, source) if action in {"read", "authentication"} or access=="read" else (source, target)
        edges.append({"from": left, "to": right, "action": action, "access":access,"event_id": identifier, "time": at, "basis": "reported_event", "anomaly_score": scores.get(identifier)})
        previous = state["processes"].get(source)
        transition = digest([normalize_path(data["image"]), previous["action"] if previous else "<start>", action])
        count = state["transitions"].get(transition, 0)
        temporal.append({"event_id": identifier, "novel_transition": count == 0,
                         "rarity": 1/(1+count), "previous_action": previous["action"] if previous else None,
                         "gap_seconds": max(0, at-previous["time"]) if previous else None,
                         "late_event": bool(previous and at < previous["time"]),
                         "scope": "same process incarnation" if source.startswith("process:") else "unlinked observation"})
        if source.startswith("process:") and (not previous or at >= previous["time"]):
            _remember(state["processes"], source, {"action": action, "time": at})
        _remember(state["transitions"], transition, min(10**9, count+1))
        _remember(state["actions"], action, min(10**9, state["actions"].get(action, 0)+1))
        # Fixed-size exponentially-decayed graph-feature sketch (24h half-life).
        if state["last_time"] is not None and at > state["last_time"]:
            decay = 0.5**(min(at-state["last_time"], 30*86400)/86400)
            state["bins"] = [v*decay for v in state["bins"]]
        pattern = [normalize_path(data["image"]), normalize_path(target_path) if target_path else "network" if data["dest_ip"] else "observation", action]
        bucket = int(digest(pattern)[:8], 16) % SKETCH_SIZE
        age = max(0,(state["last_time"] or at)-at)
        state["bins"][bucket] = min(1e9, state["bins"][bucket]+0.5**(min(age,30*86400)/86400))
        state["last_time"] = max(at, state["last_time"] if state["last_time"] is not None else at)
        state["observed"] = min(10**12, state["observed"]+1)
        state["total"] = min(10**12, state["total"]+1)
        tags = _ttp(data)
        if tags:
            ttps.append({"event_id": identifier, "techniques": tags, "process_id": source,
                         "basis": "reported text heuristic; not confirmed attack"})
        image = normalize_path(data["image"])
        basename = image.rsplit("/", 1)[-1]
        if basename in services and "windows" in image:
            service_ids.add(source)
            prisma["service_ipc_candidates"].append({"event_id": identifier, "process_id": source,
                "suppressed": False, "reason": "name/path is not proof of trusted service integrity"})
            prisma["temporal_service_partitions"].append({"event_id": identifier, "process_id": source,
                "partition": int(at//2), "window_seconds": 2, "summary_only": True})
    truncated = len(edges) > MAX_EDGES
    edges = edges[:MAX_EDGES]
    degrees = Counter([e["from"] for e in edges] + [e["to"] for e in edges])
    for item in nodes.values():
        if item["kind"] in {"file", "registry"} and degrees[item["id"]] == 1:
            attached = next(e for e in edges if item["id"] in (e["from"], e["to"]))
            if attached["access"] == "read":
                prisma["leaf_data_groups"].append({"node_id": item["id"], "event_ids": item["event_ids"], "summary_only": True})
    # A bounded greedy causal-path summary, not NodLink code or an STP solver.
    # Service IPC summaries never suppress originals or substantive alerts.
    adjacency = defaultdict(list)
    for edge in edges:
        adjacency[edge["to"]].append(edge)
    anchors = sorted(edges, key=lambda e: (-(e.get("anomaly_score") or 0), -e["time"], e["event_id"]))[:8]
    paths, seen = [], set()
    for anchor in anchors:
        path, visited, current = [anchor], {anchor["to"], anchor["from"]}, anchor
        for _ in range(7):
            candidates = [e for e in adjacency[current["from"]] if e["time"] <= current["time"] and e["from"] not in visited
                          and (current["from"] not in service_ids or current["time"]-e["time"]<=2)]
            if not candidates:
                break
            chosen = max(candidates, key=lambda e: (e["time"], e["event_id"]))
            visited.add(chosen["from"])
            path.insert(0, chosen)
            current = chosen
        ids = tuple(dict.fromkeys(e["event_id"] for e in path))
        if ids not in seen:
            paths.append({"event_ids": list(ids), "edges": path, "bounded_greedy": True, "confirmed_attack": False})
            seen.add(ids)
    total_before, total_after = sum(initial_bins), sum(state["bins"])
    distance = sum(abs(a/max(1,total_before)-b/max(1,total_after)) for a,b in zip(initial_bins,state["bins"]))/2
    return {"nodes": list(nodes.values()), "edges": edges, "summary_paths": paths, "temporal": temporal,
            "sketch": {"size": SKETCH_SIZE, "observed": state["observed"], "distance_from_prior": min(1.0,distance),
                       "half_life_seconds": 86400, "history_reconstructable_from_sketch": False},
            "prism": {**prisma,"summary_service_max_gap_seconds":2,"original_graph_edges_removed":0}, "ttps": ttps, "missing_identity": missing,
            "truncated": truncated, "evidence_limit": MAX_EVENTS, "state": state,
            "reproduction_claim": False, "memory_scan": False, "device_authority": False}


def dataset_quality(splits):
    """Audit split leakage and synthetic background without treating labels as features."""
    if not isinstance(splits, dict) or not {"training", "validation"} <= set(splits) or set(splits)-{"training","validation","test"}:
        raise ValueError("training/validation/test split records required")
    if any(not isinstance(rows, list) or len(rows) > 2048 for rows in splits.values()):
        raise ValueError("At most 2048 records per quality split")
    facts, counts, leak_fields = {}, {}, set()
    def labels(value, prefix="raw", depth=0):
        if depth > 8 or not isinstance(value, dict):
            return
        for key, item in list(value.items())[:128]:
            if key.lower() in LABEL_FIELDS:
                leak_fields.add(prefix+"."+key)
            labels(item, prefix+"."+key, depth+1)
    for name, rows in splits.items():
        ids = [r["event_id"] for r in rows]
        patterns = [digest({"features": event_features(r)["values"], "action": event_features(r)["target"]}) for r in rows]
        hist = Counter(patterns)
        hosts = {r.get("host") for r in rows if r.get("host")}
        campaign_values = [_pick(_get(r, "raw.campaign_id"), _get(r,"raw.campaign")) for r in rows]
        campaigns = {v for v in campaign_values if isinstance(v,str) and 0<len(v)<=256}
        times = [r["event_time"] for r in rows]
        for row in rows:
            labels(row.get("raw", {}))
        facts[name] = {"ids": set(ids), "patterns": set(patterns), "hosts": hosts, "campaigns": campaigns,
                       "time_min": min(times) if times else None, "time_max": max(times) if times else None}
        counts[name] = {"records": len(rows), "unique_event_ids": len(set(ids)), "unique_patterns": len(hist),
                        "unique_hosts": len(hosts), "campaigns_labeled": len(campaigns),
                        "time_min": facts[name]["time_min"], "time_max": facts[name]["time_max"],
                        "largest_pattern_fraction": max(hist.values(), default=0)/max(1,len(rows)),
                        "duplicate_ids_within_split": len(ids)-len(set(ids))}
    overlaps = {"duplicate_event_ids": [], "content_overlap": [], "host_overlap": [], "campaign_overlap": [], "temporal_overlap": []}
    names = list(facts)
    for i, left in enumerate(names):
        for right in names[i+1:]:
            a, b = facts[left], facts[right]
            pair = {"left": left, "right": right}
            for result, field in (("duplicate_event_ids","ids"),("content_overlap","patterns"),("host_overlap","hosts"),("campaign_overlap","campaigns")):
                overlaps[result].append({**pair, "count": len(a[field]&b[field])})
            overlap = bool(a["time_min"] is not None and b["time_min"] is not None and a["time_max"] >= b["time_min"] and b["time_max"] >= a["time_min"])
            overlaps["temporal_overlap"].append({**pair, "overlap": overlap,
                "chronological": a["time_max"] is not None and b["time_min"] is not None and a["time_max"] < b["time_min"]})
    warnings = []
    if any(x["count"] for x in overlaps["duplicate_event_ids"]): warnings.append("Original IDs cross dataset splits")
    if any(x["count"] for x in overlaps["content_overlap"]): warnings.append("Equivalent model input/action patterns cross splits; not an independent behavior holdout")
    if any(x["count"] for x in overlaps["host_overlap"]): warnings.append("Host-disjoint performance is unmeasured")
    if any(x["count"] for x in overlaps["campaign_overlap"]): warnings.append("Campaigns cross splits")
    if any(not x["chronological"] for x in overlaps["temporal_overlap"]): warnings.append("Point-in-time split order is not strictly chronological")
    if any(x["largest_pattern_fraction"] > .5 for x in counts.values()): warnings.append("Repetitive background may inflate performance")
    if leak_fields: warnings.append("Evaluation-only fields present in originals; excluded from detector features")
    if any(not x["campaigns_labeled"] for x in counts.values()): warnings.append("Campaign-disjoint validation unavailable without campaign annotations")
    return {"schema": "xsera.research-dataset-quality.v1", "splits": counts, **overlaps,
            "background_repetition": {k:v["largest_pattern_fraction"] for k,v in counts.items()},
            "label_leakage_fields": sorted(leak_fields), "warnings": warnings,
            "detector_uses_evaluation_labels": False, "real_world_detection_rate_measured": False}
