"""Licensed, local ATT&CK reference data and complete authorized case context.

ATT&CK describes adversary behavior. It supplies neither case severity nor
threat scores; those values below come exclusively from configured evidence.
"""

import copy
import hashlib
import json
import math
import time
from functools import lru_cache
from pathlib import Path

from . import casework, contribution_verdicts, principal
from .storage import CapacityError, encode

DATA = Path(__file__).with_name("catalogs")
TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "defense-impairment",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]
SEVERITIES = ["unknown", "debug", "info", "low", "medium", "high", "critical"]
SCORE_DEFINITION = {
    "id": "case-evidence-max-v1",
    "formula": "min(100, max(0, max(contribution.weight, default=0)))",
    "meaning": "Highest configured policy evidence priority in the complete authorized case; not a probability or MITRE rating",
    "aggregation": "Maximum prevents duplicate/replayed evidence from increasing the score",
    "severity_source": "Maximum valid evidence.severity; MITRE supplies no severity",
    "scope": "All contributions in the complete authorized case, without page filtering",
}


@lru_cache(maxsize=1)
def _catalog():
    blob = (DATA / "enterprise-v19.2.json").read_bytes()
    manifest = json.loads((DATA / "provenance.json").read_text(encoding="utf-8"))
    expected = next(
        x["sha256"] for x in manifest["files"] if x["file"] == "enterprise-v19.2.json"
    )
    if hashlib.sha256(blob).hexdigest() != expected:
        raise ValueError("ATT&CK catalog digest mismatch")
    value = json.loads(blob.decode("utf-8-sig"))
    if value["domain"] != "enterprise-attack" or value["version"] != "19.2":
        raise ValueError("Unsupported ATT&CK reference version")
    return value


def metadata():
    catalog = _catalog()
    return {
        "version": catalog["version"],
        "domain": catalog["domain"],
        "source": catalog["source"],
        "source_sha256": catalog["source_sha256"],
        "copyright": catalog["copyright"],
        "license": catalog["license"],
        "technique_count": len(catalog["techniques"]),
        "tactic_count": len(catalog["tactics"]),
        "severity_note": "MITRE ATT&CK does not define event severity or case threat scores",
    }


def tactics():
    rows = []
    for value in _catalog()["tactics"].values():
        item = {key: value[key] for key in ("id", "name", "shortname", "url")}
        item["order"] = (
            TACTIC_ORDER.index(item["shortname"])
            if item["shortname"] in TACTIC_ORDER
            else len(TACTIC_ORDER)
        )
        rows.append(item)
    return sorted(rows, key=lambda item: (item["order"], item["id"]))


def technique(identifier, detail=False):
    if not isinstance(identifier, str) or identifier not in _catalog()["techniques"]:
        raise KeyError("ATT&CK technique not found")
    value = _catalog()["techniques"][identifier]
    keys = [
        "id",
        "name",
        "url",
        "is_subtechnique",
        "parent",
        "tactics",
        "platforms",
        "deprecated",
        "revoked",
    ]
    if detail:
        keys.extend(
            [
                "description",
                "subtechniques",
                "data_components",
                "detection_strategies",
                "mitigations",
            ]
        )
    return copy.deepcopy({key: value.get(key) for key in keys})


def listing(
    search="", tactic=None, platform=None, include_inactive=False, offset=0, limit=100
):
    if (
        not isinstance(search, str)
        or len(search) > 200
        or type(include_inactive) is not bool
    ):
        raise ValueError("Invalid ATT&CK search")
    if (
        type(offset) is not int
        or not 0 <= offset <= 10000
        or type(limit) is not int
        or not 1 <= limit <= 200
    ):
        raise ValueError("ATT&CK offset 0..10000 and limit 1..200 required")
    if tactic is not None and tactic not in _catalog()["tactics"]:
        raise ValueError("Unknown ATT&CK tactic")
    if platform is not None and (not isinstance(platform, str) or len(platform) > 64):
        raise ValueError("Invalid platform")
    selected = []
    for identifier, row in sorted(_catalog()["techniques"].items()):
        if not include_inactive and (row["deprecated"] or row["revoked"]):
            continue
        if tactic and tactic not in row["tactics"]:
            continue
        if platform and platform.casefold() not in [
            x.casefold() for x in row["platforms"]
        ]:
            continue
        if search.casefold() not in (identifier + " " + row["name"]).casefold():
            continue
        selected.append(identifier)
    return {
        **metadata(),
        "tactics": tactics(),
        "techniques": [technique(x) for x in selected[offset : offset + limit]],
        "total": len(selected),
        "offset": offset,
        "limit": limit,
        "include_inactive": include_inactive,
    }


def _severity(values):
    return max(
        (value for value in values if value in SEVERITIES),
        key=SEVERITIES.index,
        default="unknown",
    )


def _analytic_prerequisites(policy, evidence):
    """Use matched revision and per-stage fields; policy edits cannot rewrite history."""
    version = evidence.get("evaluation", {}).get("policy_version")
    snapshot = evidence.get("policy_snapshot")
    basis = "unavailable"
    stages, relation = [], None
    if isinstance(snapshot, dict) and snapshot.get("version") == version and version is not None:
        stages = snapshot.get("stages", [])
        relation = snapshot.get("relation")
        basis = "frozen_matched_policy"
    elif policy and version is not None and policy["version"] == version:
        definition = policy["definition"]
        relation = definition.get("relation")
        for position, step in enumerate(definition.get("steps", [])):
            fields = {condition["field"] for condition in step.get("filters", [])
                      if not (condition["op"] == "exists" and not condition.get("value"))}
            fields.add(definition["entity_field"])
            if relation:
                fields.add(relation["field"])
                if relation["mode"] == "parent_guid" and position:
                    fields.add("raw.xdr.data.process.parent.guid")
            stages.append({"name": step["name"], "required_fields": sorted(fields)})
        basis = "unchanged_legacy_policy_revision"
    evaluated = []
    for stage in stages:
        fields = stage["required_fields"]
        events = [event for observed in evidence.get("steps", []) if observed.get("step") == stage["name"]
                  for event in observed.get("events", [])]
        evaluated.append({"name": stage["name"], "required_fields": fields,
                          "required_field_types": stage.get("required_field_types"),
                          "event_count": len(events),
                          "joint_field_evidence_count": sum(all(field in event and event[field] is not None for field in fields) for event in events)})
    return {"requirements_basis": basis, "stages": evaluated, "relation": relation,
            "required_fields": sorted({field for stage in evaluated for field in stage["required_fields"]}),
            "joint_field_evidence_count": sum(stage["joint_field_evidence_count"] for stage in evaluated) if evaluated else None,
            "joint_field_semantics": "Per-stage field presence, not independent adversary-procedure or maliciousness validation"}


def attack_context(store, who, incident_id):
    with principal.transaction(store, who) as (_, actor):
        pass
    material = casework.export_case(store, actor, incident_id)
    with principal.transaction(store, actor) as (db, actor):
        verdicts = {row["id"]: contribution_verdicts.classification(db, row)
                    for row in material["contributions"]}
        policy_definitions = {}
        for row in material["contributions"]:
            policy = db.execute("SELECT version,definition FROM correlation_policies WHERE tenant=? AND id=?",
                                (actor["tenant"], row["policy_id"])).fetchone()
            if policy:
                policy_definitions[row["policy_id"]] = {"version": policy["version"], "definition": json.loads(policy["definition"])}
    mapped, weights, severities, event_ids, hosts, warnings = (
        {},
        [],
        [],
        set(),
        set(),
        set(),
    )
    for row in material["contributions"]:
        evidence = json.loads(row["evidence"])
        weight = row["weight"]
        if type(weight) not in (int, float) or not math.isfinite(weight):
            raise ValueError("Invalid stored contribution weight")
        weight = min(100, max(0, weight))
        verdict = verdicts[row["id"]]
        if not verdict["active"]:
            weight = 0
        weights.append(weight)
        severity = evidence.get("severity", "unknown")
        severity = severity if severity in SEVERITIES else "unknown"
        severities.append(severity if verdict["active"] else "info")
        ids = evidence.get("event_ids", [])
        mitre = evidence.get("mitre", [])
        if (
            not isinstance(ids, list)
            or not all(isinstance(x, str) for x in ids)
            or not isinstance(mitre, list)
            or not all(isinstance(x, str) for x in mitre)
        ):
            raise ValueError("Invalid stored contribution evidence")
        event_ids.update(ids)
        if row["entity_field"] in {"host", "raw.xdr.data.host.id"}:
            hosts.add(row["entity"])
        for identifier in set(mitre):
            if identifier not in mapped:
                try:
                    item = technique(identifier)
                    item["known"] = True
                    if item["deprecated"] or item["revoked"]:
                        warnings.add(
                            "Historical ATT&CK tag retained without replacement: "
                            + identifier
                        )
                except KeyError:
                    item = {
                        "id": identifier,
                        "name": identifier,
                        "known": False,
                        "tactics": [],
                        "platforms": [],
                        "url": None,
                        "deprecated": False,
                        "revoked": False,
                    }
                    warnings.add("Unknown ATT&CK evidence tag: " + identifier)
                mapped[identifier] = {
                    **item,
                    "policy_ids": set(),
                    "contribution_ids": set(),
                    "evidence_event_ids": set(),
                    "severities": [],
                    "weights": [],
                    "active_contribution_count": 0,
                    "adjudication_counts": {key: 0 for key in contribution_verdicts.CLASSIFICATIONS},
                    "analytics": [],
                }
            item = mapped[identifier]
            item["policy_ids"].add(row["policy_id"])
            item["contribution_ids"].add(row["id"])
            item["evidence_event_ids"].update(ids)
            item["severities"].append(severity if verdict["active"] else "info")
            item["weights"].append(weight)
            item["active_contribution_count"] += int(verdict["active"])
            item["adjudication_counts"][verdict["classification"]] += 1
            policy = policy_definitions.get(row["policy_id"])
            prerequisites = _analytic_prerequisites(policy, evidence)
            item["analytics"].append({
                "policy_id": row["policy_id"], "policy_version": evidence.get("evaluation", {}).get("policy_version"),
                "current_policy_version": (policy or {}).get("version"),
                "contribution_id": row["id"], "classification": verdict["classification"],
                **prerequisites,
                "coverage_state": "rule_tag_matched",
                "causality": evidence.get("episode_basis", "see explicit event relationships; tag alone is not causality"),
                "independently_validated_adversary_detection": False,
            })
    for item in mapped.values():
        item["severity"] = _severity(item.pop("severities"))
        item["score"] = round(max(item.pop("weights"), default=0), 2)
        for key in ("policy_ids", "contribution_ids", "evidence_event_ids"):
            item[key] = sorted(item[key])
        item["contribution_count"] = len(item["contribution_ids"])
    result = {
        "incident_id": incident_id,
        "catalog_version": _catalog()["version"],
        "generated_at": time.time(),
        "severity": _severity(severities),
        "threat_score": round(max(weights, default=0), 2),
        "score_definition": copy.deepcopy(SCORE_DEFINITION),
        "contribution_count": len(material["contributions"]),
        "evidence_event_count": len(event_ids),
        "techniques": [mapped[key] for key in sorted(mapped)],
        "hosts": sorted(hosts),
        "warnings": sorted(warnings),
        "active_contribution_count": sum(int(v["active"]) for v in verdicts.values()),
        "coverage_definition": {
            "states": ["declared_tag", "telemetry_ready", "rule_tag_matched", "procedure_tested", "independent_holdout_tested"],
            "current_case_scope": "rule_tag_matched with original event evidence and analyst classifications",
            "validated_technique_detection_count": None,
            "meaning": "ATT&CK cells are policy hypotheses; tested/holdout coverage requires separate frozen evaluation evidence",
        },
    }
    from .entities import priority_context

    incident = material["incident"]
    result["entity_priority_context"] = priority_context(
        store,
        actor,
        incident["entity_field"],
        incident["entity"],
        result["threat_score"],
    )
    if len(encode(result).encode()) > 2 * 1024 * 1024:
        raise CapacityError(
            "Complete ATT&CK case context exceeds 2 MiB; no partial score emitted"
        )
    principal.recheck(store, actor)
    return result
