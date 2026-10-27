"""Explicit synthetic fixtures for an isolated GUI QA store; never auto-run.

The caller must create <store.path>/.qa-synthetic-only before calling seed().
No credentials, original XDR data, shell execution or external requests are used.
"""

import time
from datetime import UTC, datetime
from pathlib import Path

from sapientia import (
    behavior,
    casework,
    detections,
    entities,
    principal,
    soar,
    xdr_bridge,
)


def seed(store, who):
    marker = store.path / ".qa-synthetic-only"
    if (
        not marker.is_file()
        or str(store.path.resolve()).casefold()
        == str((Path(__file__).resolve().parents[1] / "data").resolve()).casefold()
    ):
        raise ValueError(
            "Synthetic GUI fixtures require an explicitly marked isolated QA store"
        )
    with principal.transaction(store, who, ("admin",)) as (_, actor):
        if not principal.contains(actor["allowed_indexes"], ["endpoint"]):
            raise PermissionError("QA fixture index endpoint is not authorized")
    base = int(time.time() // 60) * 60 - 480
    prefix = "synthetic-gui-" + str(base)

    def endpoint(ident, guid, offset, parent=None, action="process_created", **extra):
        process = {
            "guid": guid,
            "pid": 100 + offset,
            "name": "synthetic-" + ident + ".exe",
            "command_line": "synthetic fixture only; no process executed",
        }
        if parent:
            process["parent"] = {"guid": parent}
        return {
            "id": prefix + "-" + ident,
            "data": {
                "@timestamp": datetime.fromtimestamp(base + offset, UTC).isoformat(),
                "host": {"id": "qa-endpoint-01", "os": {"type": "windows"}},
                "process": process,
                "event": {
                    "action": action,
                    "severity": "high" if action == "defender_detection" else "info",
                },
                "user": {"name": "qa-user"},
                "test": {"synthetic": True},
                **extra,
            },
        }

    rows = [
        endpoint("root", "qa-root-" + str(base), 0),
        endpoint("shell", "qa-shell-" + str(base), 30, "qa-root-" + str(base)),
        endpoint(
            "network",
            "qa-shell-" + str(base),
            45,
            "qa-root-" + str(base),
            "network_connection",
            source={"ip": "192.0.2.10", "port": 52000},
            destination={"ip": "198.51.100.10", "port": 443},
        ),
        endpoint(
            "alert",
            "qa-child-" + str(base),
            90,
            "qa-shell-" + str(base),
            "defender_detection",
            file={"path": "C:/Synthetic/sample.txt"},
        ),
    ]
    # The network observation reports the same immutable process identity/PID.
    rows[2]["data"]["process"]["pid"] = rows[1]["data"]["process"]["pid"]
    rows[2]["data"]["process"]["name"] = rows[1]["data"]["process"]["name"]
    admission = xdr_bridge.intake(
        store, actor, {"format": "agent", "index": "endpoint", "events": rows}
    )
    training = [
        {
            "event_id": f"{prefix}-train-{bucket}-{i}",
            "event_time": base - 180 + bucket * 60 + i,
            "host": "qa-endpoint-01",
            "index": "endpoint",
            "source": "qa-synthetic",
            "raw": {"user": "qa-user", "test": {"synthetic": True}},
        }
        for bucket in range(3)
        for i in range(2)
    ]
    evaluation = [
        {
            "event_id": f"{prefix}-burst-{i}",
            "event_time": base + 121 + i,
            "host": "qa-endpoint-02",
            "index": "endpoint",
            "source": "qa-synthetic",
            "raw": {"user": "qa-user", "test": {"synthetic": True}},
        }
        for i in range(8)
    ]
    store.ingest(actor["tenant"], training + evaluation, actor["name"])
    for _ in range(8):
        if not store.flush(5000):
            break
    else:
        raise RuntimeError(
            "Synthetic QA store did not drain within the bounded seed budget"
        )
    registered = entities.save(
        store,
        actor,
        {
            "kind": "host",
            "name": "Synthetic QA endpoint",
            "aliases": [{"type": "hostname", "value": "qa-endpoint-01"}],
            "indexes": ["endpoint"],
            "criticality": 4,
            "tags": ["synthetic", "gui-qa"],
            "version": 0,
        },
    )
    policy = detections.save(
        store,
        actor,
        {
            "name": "SYNTHETIC — process then endpoint detection",
            "entity_field": "host",
            "window": 900,
            "interval": 30,
            "cooldown": 900,
            "risk_score": 60,
            "severity": "high",
            "enabled": False,
            "steps": [
                {
                    "name": "Process observed",
                    "filters": [
                        {"field": "index", "op": "eq", "value": "endpoint"},
                        {"field": "source", "op": "eq", "value": "aegis-xdr"},
                        {"field": "raw.action", "op": "eq", "value": "process_created"},
                    ],
                },
                {
                    "name": "Synthetic endpoint alert",
                    "filters": [
                        {"field": "index", "op": "eq", "value": "endpoint"},
                        {"field": "source", "op": "eq", "value": "aegis-xdr"},
                        {
                            "field": "raw.action",
                            "op": "eq",
                            "value": "defender_detection",
                        },
                    ],
                },
            ],
        },
    )
    replay = detections.replay(store, actor, policy, base + 180, 1, prefix)
    incidents = [
        row
        for row in detections.incident_list(store, actor)
        if row["entity"] == "qa-endpoint-01"
    ]
    if not incidents:
        raise RuntimeError(
            "Synthetic correlation did not create its evidence-backed case"
        )
    incident = incidents[0]["id"]
    casework.configure(
        store,
        actor,
        incident,
        {
            "version": 0,
            "priority": "high",
            "due_at": time.time() + 3600,
            "tags": ["synthetic", "gui-qa"],
        },
    )
    casework.act(
        store,
        actor,
        incident,
        {
            "request_id": prefix + "-note",
            "action": {
                "type": "add_note",
                "note": "SYNTHETIC GUI QA: no attack, isolation or shell command was executed.",
            },
        },
    )
    casework.act(
        store,
        actor,
        incident,
        {
            "request_id": prefix + "-task",
            "action": {
                "type": "add_task",
                "title": "Review sensor-reported process lineage",
                "description": "Synthetic fixture; inspect GUID edge and source-event IDs",
                "mandatory": True,
                "due_at": time.time() + 3600,
            },
        },
    )
    evidence_id = xdr_bridge.parse_event(rows[-1], "agent", "endpoint")["event_id"]
    casework.bookmark(
        store,
        actor,
        incident,
        {"event_id": evidence_id, "label": "Synthetic endpoint alert evidence"},
    )
    playbook = soar.save(
        store,
        actor,
        {
            "name": "SYNTHETIC — approved local investigation note",
            "version": 0,
            "steps": [
                {
                    "id": "review_note",
                    "action": {
                        "type": "add_note",
                        "note": "Synthetic approval workflow completed; remote containment remains unsupported.",
                    },
                }
            ],
        },
    )
    pending = soar.start_run(store, actor, playbook["id"], incident, prefix + "-run")
    baseline = behavior.train(
        store,
        actor,
        {
            "name": "SYNTHETIC — one minute user volume",
            "entity_field": "raw.security.user",
            "indexes": ["endpoint"],
            "start": base - 180,
            "end": base,
            "bucket_seconds": 60,
            "min_samples": 6,
            "min_buckets": 3,
            "z_threshold": 3,
            "business_hours_utc": {"start": 9, "end": 18, "weekdays": [0, 1, 2, 3, 4]},
        },
    )
    run = behavior.evaluate(store, actor, baseline["id"], base + 120, base + 180)
    return {
        "synthetic": True,
        "start": base - 180,
        "end": base + 180,
        "host": "qa-endpoint-01",
        "admission": admission,
        "entity_id": registered["id"],
        "policy_id": policy,
        "replay": replay,
        "incident_id": incident,
        "playbook_id": playbook["id"],
        "pending_approval_run_id": pending["id"],
        "baseline_id": baseline["id"],
        "behavior_run_id": run["id"],
    }
