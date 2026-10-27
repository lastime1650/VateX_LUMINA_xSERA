"""Deterministic, harmless, separated sequence scenarios; truth never is telemetry.

24 disjoint scenario families x 64 variants = 1536 sequences by default.
Attack and benign pairs share an event multiset; temporal order changes. This
tests sequence sensitivity and does not establish real malware effectiveness.
All destinations are documentation addresses or .invalid domains; no payload
is run, no device is contacted and no host action is performed.
"""

import argparse
import hashlib
import json
import random
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

SCHEMA = "xsera.synthetic-sequence-dataset.v1"
MECHANISMS = ("credential-access", "archive-egress", "persistence-beacon",
              "identity-mail-export", "cloud-permission-egress", "destructive-file-chain")
CONTEXTS = ("interactive-workstation", "scheduled-service", "remote-administration", "maintenance-session")
FAMILIES = tuple(f"{m}/{c}" for c in CONTEXTS for m in MECHANISMS)
PARTITIONS = {"train": tuple(range(16)), "validation": tuple(range(16, 20)),
              "heldout": tuple(range(20, 24))}
OFFSETS = {"train": -110 * 86400, "validation": -65 * 86400, "heldout": -25 * 86400}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def _stages(mechanism):
    # Both labels contain exactly these kinds and semantic properties. Only
    # order and thus the transition context distinguish each matched pair.
    bags = (
        ("logon_failed", "logon_failed", "logon_success", "process_created", "file_accessed", "file_archived", "network_connection", "registry_value_set", "file_deleted", "process_terminated", "logoff", "dns_query"),
        ("logon_success", "process_created", "file_accessed", "file_accessed", "file_archived", "dns_query", "network_connection", "network_connection", "file_deleted", "process_terminated", "logoff", "file_created"),
        ("logon_success", "process_created", "file_created", "registry_value_set", "scheduled_task_created", "process_created", "dns_query", "network_connection", "network_connection", "network_connection", "process_terminated", "logoff"),
        ("logon_failed", "logon_success", "oauth_grant", "token_used", "mail_rule_created", "mail_accessed", "mail_exported", "network_connection", "file_created", "token_revoked", "logoff", "dns_query"),
        ("logon_success", "cloud_role_assumed", "cloud_policy_changed", "cloud_object_listed", "cloud_object_read", "file_archived", "network_connection", "cloud_object_deleted", "cloud_policy_changed", "token_revoked", "logoff", "dns_query"),
        ("logon_success", "process_created", "file_accessed", "file_renamed", "file_deleted", "backup_deleted", "file_created", "file_renamed", "network_connection", "process_terminated", "logoff", "dns_query"),
    )
    normal_orders = (
        (2, 3, 4, 11, 6, 5, 7, 8, 9, 10, 0, 1),
        (0, 1, 5, 6, 7, 11, 2, 3, 4, 8, 9, 10),
        (0, 4, 1, 6, 7, 2, 5, 8, 9, 3, 10, 11),
        (1, 3, 5, 11, 7, 8, 2, 4, 6, 9, 10, 0),
        (0, 1, 3, 4, 11, 6, 5, 7, 9, 10, 2, 8),
        (0, 1, 8, 11, 6, 3, 7, 2, 9, 10, 4, 5),
    )
    return bags[mechanism], normal_orders[mechanism]


def _category(action):
    if action.startswith(("logon", "logoff", "token", "oauth")): return "authentication"
    if action.startswith("cloud_"): return "cloud"
    if action.startswith("mail_"): return "email"
    if action.startswith(("file_", "backup_")): return "file"
    if action in {"network_connection", "dns_query"}: return "network"
    if action.startswith(("registry_", "scheduled_")): return "registry"
    return "process"


def _event(action, stage, instant, scenario, pair_random):
    profile, host = scenario["profile"], scenario["host_group"]
    pair, family = scenario["variant"] // 2, scenario["family_number"]
    process_name = "powershell.exe" if profile == "windows" else "bash"
    command = ("powershell.exe -NoProfile -File C:\\Lab\\maintenance.ps1" if profile == "windows"
               else "/usr/bin/bash /opt/lab/maintenance.sh")
    # No class marker, scenario identifier or family string in prediction inputs.
    data = {"@timestamp": datetime.fromtimestamp(instant, UTC).isoformat(),
            "host": {"id": host, "name": host, "boot_id": "boot-" + host, "os": {"type": profile}},
            "user": {"id": "virtual-user-" + host, "name": "lab-user", "session_id": "session-" + host},
            "process": {"guid": digest([host, "process"]), "pid": 11000 + pair,
                        "start_identity": "start-" + host, "name": process_name,
                        "command_line": command, "depth": 2 + pair % 3,
                        "parent": {"guid": digest([host, "parent"]), "name": "services.exe" if profile == "windows" else "systemd", "start_identity": "parent-" + host}},
            "event": {"action": action, "category": _category(action), "module": _category(action),
                      "outcome": "failure" if action == "logon_failed" else "success", "severity": "info",
                      "timestamp_precision_seconds": .001, "clock_quality": "synthetic_reported_clock"},
            "agent": {"collector": "xsera-sequence-python-lab", "simulation": True, "native_sensor_collected": False}}
    if _category(action) == "authentication":
        data["authentication"] = {"action": action, "outcome": data["event"]["outcome"], "session_id": "session-" + host}
    if action in {"network_connection", "dns_query"}:
        data["source"] = {"ip": "10.44." + str(family) + "." + str(10 + scenario["variant"]), "port": 51000 + pair}
        data["destination"] = {"ip": "203.0.113." + str(20 + family), "port": (443, 8443, 22, 53)[pair % 4]}
        data["network"] = {"protocol": "tcp", "bytes_out": (pair_random % 4096 + 1024) * (1 + stage % 3), "bytes_in": 512 + pair % 64}
        if action == "dns_query": data["dns"] = {"query": "sync" + str(pair % 8) + ".lab.invalid"}
    if _category(action) == "file":
        data["file"] = {"path": "C:\\Lab\\records\\maintenance.bin" if profile == "windows" else "/opt/lab/records/maintenance.bin",
                        "action": action, "hash": {"sha256": digest([family, pair, stage, "harmless-file"])}}
    if _category(action) == "registry": data["registry"] = {"key": "Lab/Maintenance", "action": action}
    if _category(action) == "email": data["email"] = {"action": action, "attachment_count": pair % 4, "provider": "virtual-mail"}
    if _category(action) == "cloud": data["cloud"] = {"action": action, "resource_type": "object-storage", "provider": "virtual-cloud"}
    return {"id": digest([scenario["scenario_id"], stage, "wire-event"]), "data": data}


def generate(variants_per_family=64, seed=81420, base_time=None):
    if type(variants_per_family) is not int or not 2 <= variants_per_family <= 128 or variants_per_family % 2:
        raise ValueError("2..128 even variants per family required")
    if type(seed) is not int: raise ValueError("Integer seed required")
    base_time = int(time.time()) if base_time is None else int(base_time)
    scenarios = []
    for split, family_numbers in PARTITIONS.items():
        for local_family, family in enumerate(family_numbers):
            bag, normal_order = _stages(family % len(MECHANISMS))
            for variant in range(variants_per_family):
                pair = variant // 2
                profile = "windows" if (pair + family) % 2 == 0 else "linux"
                scenario_id = digest([SCHEMA, seed, family, variant])[:24]
                scenario = {"scenario_id": scenario_id, "family": FAMILIES[family], "family_number": family,
                            "split": split, "label": "attack" if variant % 2 else "normal",
                            "host_group": "seq-" + profile[:3] + "-" + scenario_id,
                            "profile": profile, "index": "seq_" + profile, "variant": variant,
                            "synthetic": True, "native_sensor_collected": False}
                rng = random.Random(digest([seed, family, pair]))
                begin = base_time + OFFSETS[split] + local_family * 36 * 3600 + pair * 600
                gap = rng.uniform(.8, 5.0)
                # Match the first and last observations too: neither a final
                # token shortcut nor a bag-of-events classifier solves the
                # controlled task. The middle transition order must matter.
                middle = tuple(i for i in normal_order if i not in (0, len(bag)-1))
                order = tuple(range(len(bag))) if scenario["label"] == "attack" else (0, *middle, len(bag)-1)
                pair_random = rng.randrange(1 << 20)
                scenario["events"] = [_event(bag[stage], stage, begin + position * gap, scenario, pair_random)
                                      for position, stage in enumerate(order)]
                scenario["truth"] = {"mechanism": MECHANISMS[family % 6], "order_only_control": True,
                                     "native_attack_executed": False, "real_threat_accuracy_claim": False}
                scenarios.append(scenario)
    validate(scenarios)
    return scenarios


def validate(scenarios):
    groups = {split: [s for s in scenarios if s["split"] == split] for split in PARTITIONS}
    if any(not values for values in groups.values()): raise ValueError("All three partitions required")
    if len({s["scenario_id"] for s in scenarios}) != len(scenarios): raise ValueError("Duplicate scenarios")
    for a in groups:
        for b in groups:
            if a >= b: continue
            for field in ("family", "host_group", "scenario_id"):
                if {s[field] for s in groups[a]} & {s[field] for s in groups[b]}: raise ValueError("Partition leakage: " + field)
            times_a = [datetime.fromisoformat(e["data"]["@timestamp"]).timestamp() for s in groups[a] for e in s["events"]]
            times_b = [datetime.fromisoformat(e["data"]["@timestamp"]).timestamp() for s in groups[b] for e in s["events"]]
            if not (max(times_a) < min(times_b) or max(times_b) < min(times_a)): raise ValueError("Partition time overlap")
    for scenario in scenarios:
        if not 2 <= len(scenario["events"]) <= 32: raise ValueError("Bounded sequence required")
        previous = None
        for event in scenario["events"]:
            data = event["data"]
            if any(k in data for k in ("label", "truth", "split", "family", "scenario_id")): raise ValueError("Truth leaked to telemetry")
            instant = datetime.fromisoformat(data["@timestamp"]).timestamp()
            if previous is not None and instant <= previous: raise ValueError("Strict source sequence order required")
            previous = instant
            if data["host"]["name"] != scenario["host_group"] or data["agent"]["simulation"] is not True: raise ValueError("Identity/simulation mismatch")
    return {"schema": SCHEMA, "scenario_count": len(scenarios),
            "event_count": sum(len(s["events"]) for s in scenarios),
            "partitions": {k: {"scenarios": len(v), "families": len({s['family'] for s in v}),
                               "labels": dict(Counter(s['label'] for s in v))} for k, v in groups.items()},
            "family_host_time_disjoint": True, "truth_transmitted": False,
            "synthetic": True, "native_sensor_collected": False, "dataset_digest": digest(scenarios)}


def write_dataset(destination, scenarios):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "scenarios.jsonl").write_text("".join(json.dumps(s, ensure_ascii=False, allow_nan=False) + "\n" for s in scenarios), encoding="utf-8")
    manifest = validate(scenarios)
    (destination / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--variants", type=int, default=64)
    parser.add_argument("--seed", type=int, default=81420)
    parser.add_argument("--base-time", type=int)
    args = parser.parse_args()
    print(json.dumps(write_dataset(args.output, generate(args.variants, args.seed, args.base_time))))


if __name__ == "__main__": main()
