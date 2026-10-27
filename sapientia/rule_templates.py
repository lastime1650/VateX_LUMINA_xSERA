"""Disabled XDR starter library, with explicit SIEM adaptation contracts.

These are source-derived hypotheses, not certified detections. Importing a
template never enables it or asserts telemetry/ATT&CK coverage.
"""

import copy
import hashlib
import json
import math
import re
import time
from functools import lru_cache

from . import attack_catalog, detections, principal
from .query import Query

PACKS = [
    "endpoint_rules_100.json",
    "endpoint_rules_additional_200.json",
    "endpoint_rules_expansion_600.json",
    "rules_lab_50.json",
    "endpoint_behavior_curated_12.json",
]
PROFILE = "endpoint-context-re2-v2"
RISK = {"info": 5, "low": 15, "medium": 40, "high": 70, "critical": 90}
NOTES = [
    "Explicit SIEM adaptation: case-insensitive text uses RE2 Unicode simple folding, not the source Python casefold; multi-character Unicode folds can differ",
    "Text predicates require scalar JSON strings; source list-valued contains is not reproduced",
    "Typed nested endpoint fields under raw.xdr.data are required; unrelated log formats do not match",
    "SIEM fixed evaluation windows, evidence caps and cooldown replace the source in-memory threshold lifecycle; preview and tune before enabling",
    "Behavior adaptation emits deterministic complete paths for distinct terminal events; exact process identity is mandatory, not the source streaming lifecycle",
    "Import creates a disabled policy. Field presence and meaningful adversary coverage require local telemetry validation",
    "Command-only PowerShell process-created rules additionally require reported process.name powershell.exe/pwsh.exe/powershell/pwsh; never infer executable identity from a command substring",
]


def _condition(value):
    if not isinstance(value, dict) or set(value) - {
        "field",
        "operator",
        "value",
        "ignore_case",
    }:
        raise ValueError("Unsupported condition fields")
    field = value.get("field")
    if not isinstance(field, str) or not re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){0,5}", field
    ):
        raise ValueError("Unsupported endpoint field path")
    field = "raw.xdr.data." + field
    op, expected, ignore = (
        value.get("operator"),
        value.get("value"),
        value.get("ignore_case", False),
    )
    if type(ignore) is not bool:
        raise ValueError("ignore_case must be boolean")
    if op == "exists" and type(expected) is bool:
        return {"field": field, "op": "exists", "value": int(expected)}
    if op == "in" and isinstance(expected, list) and not ignore:
        return {
            "field": field,
            "op": "typed_in",
            "value": json.dumps(expected, ensure_ascii=False),
        }
    if op in {
        "equals",
        "greater_or_equal",
        "greater_than",
        "less_or_equal",
        "less_than",
    } and type(expected) in (int, float):
        mapped = {
            "equals": "typed_eq",
            "greater_or_equal": "number_gte",
            "greater_than": "number_gt",
            "less_or_equal": "number_lte",
            "less_than": "number_lt",
        }[op]
        return {"field": field, "op": mapped, "value": expected}
    if not isinstance(expected, str) or not expected.isascii():
        raise ValueError(
            "Only ASCII string constants are supported by this explicit RE2 adaptation"
        )
    if op == "equals" and not ignore:
        return {"field": field, "op": "typed_eq", "value": expected}
    literal = re.escape(expected)
    if op == "equals":
        pattern = "^" + literal + "$"
    elif op == "contains":
        pattern = literal
    elif op == "startswith":
        pattern = "^" + literal
    elif op == "endswith":
        pattern = literal + "$"
    elif op == "wildcard":
        if "[" in expected or "]" in expected:
            raise ValueError("Source wildcard character classes are unsupported")
        pattern = (
            "^"
            + "".join(
                ".*" if char == "*" else "." if char == "?" else re.escape(char)
                for char in expected
            )
            + "$"
        )
    else:
        raise ValueError("Unsupported endpoint operator: " + str(op))
    return {
        "field": field,
        "op": "regex",
        "value": ("(?i)" if ignore else "") + "(?s)" + pattern,
    }


def _policy(rule, index):
    if rule.get("scope") != "host.id" or rule.get("timeout_action") != "reset":
        raise ValueError("Unsupported source scope or timeout behavior")
    common = [
        {"field": "index", "op": "eq", "value": index},
        {"field": "sourcetype", "op": "eq", "value": "aegis:endpoint"},
        {"field": "raw.xdr.schema", "op": "typed_eq", "value": "aegis.endpoint.v1"},
    ]
    steps = []
    if rule.get("kind") == "threshold":
        conditions = rule.get("conditions")
        if not isinstance(conditions, list) or not conditions:
            raise ValueError("Only a nonempty conjunction of conditions is supported")
        if not isinstance(rule.get("threshold"), dict) or set(rule["threshold"]) != {
            "count"
        }:
            raise ValueError("Unsupported threshold semantics")
        steps.append(
            {
                "name": "Source threshold conditions",
                "filters": [
                    *common,
                    *[_condition(condition) for condition in conditions],
                ],
                "min_count": rule["threshold"]["count"],
            }
        )
    elif rule.get("kind") == "behavior":
        if rule.get("language_version") != 2 or rule.get("exceptions"):
            raise ValueError(
                "Behavior exceptions or non-v2 rule language are unsupported"
            )
        stages = rule.get("stages")
        if not isinstance(stages, list) or not 2 <= len(stages) <= 8:
            raise ValueError("Behavior adaptation requires 2..8 stages")
        for stage in stages:
            if not isinstance(stage, dict) or set(stage) - {
                "id",
                "name",
                "match",
                "within_seconds",
            }:
                raise ValueError("Unsupported behavior stage fields")
            match = stage.get("match")
            if (
                not isinstance(match, dict)
                or set(match) != {"all"}
                or not isinstance(match["all"], list)
                or not match["all"]
            ):
                raise ValueError(
                    "Behavior stages require nonempty flat match.all; OR/NOT/nested trees are unsupported"
                )
            item = {
                "name": stage.get("name", stage.get("id", "Stage"))[:80],
                "filters": [
                    *common,
                    *[_condition(condition) for condition in match["all"]],
                ],
                "min_count": 1,
            }
            if "within_seconds" in stage:
                item["within_seconds"] = stage["within_seconds"]
            steps.append(item)
    else:
        raise ValueError("Unsupported source rule kind")
    if (
        rule["kind"] == "threshold"
        and "powershell" in rule.get("name", "").lower()
        and any(c.get("field") == "process.command_line" for c in rule["conditions"])
        and any(
            c.get("field") == "event.action"
            and str(c.get("value", "")).lower() == "process_created"
            for c in rule["conditions"]
        )
        and not any(
            c.get("field") in {"process.name", "process.executable"}
            for c in rule["conditions"]
        )
    ):
        steps[0]["filters"].append(
            {
                "field": "raw.xdr.data.process.name",
                "op": "regex",
                "value": "(?i)^(powershell|pwsh)(\\.exe)?$",
            }
        )
    for item in steps:
        Query.parse({"language": "json", "query": {"filters": item["filters"]}})
    return detections.validate(
        {
            "name": ("[XDR template " + rule["id"] + "] " + rule["name"])[:120],
            "entity_field": "host",
            "window": rule["window_seconds"],
            "interval": min(30, rule["window_seconds"]),
            "cooldown": rule["cooldown_seconds"],
            "risk_score": RISK[rule["severity"]],
            "severity": rule["severity"],
            "mitre": rule.get("mitre", []),
            "enabled": False,
            "steps": steps,
            **(
                {
                    "relation": rule.get(
                        "relation",
                        {"mode": "same_value", "field": "raw.xdr.data.process.guid"},
                    )
                }
                if rule["kind"] == "behavior"
                else {}
            ),
        }
    )


@lru_cache(maxsize=1)
def _library():
    manifest = json.loads(
        (attack_catalog.DATA / "provenance.json").read_text(encoding="utf-8")
    )
    digests = {row["file"]: row["sha256"] for row in manifest["files"]}
    rows = {}
    for pack in PACKS:
        blob = (attack_catalog.DATA / pack).read_bytes()
        if hashlib.sha256(blob).hexdigest() != digests[pack]:
            raise ValueError("Template pack digest mismatch: " + pack)
        for rule in json.loads(blob.decode("utf-8-sig")):
            identifier = rule.get("id")
            if not isinstance(identifier, str) or identifier in rows:
                raise ValueError("Duplicate or invalid source template ID")
            notes, reasons = list(NOTES), []
            for tag in rule.get("mitre", []):
                try:
                    item = attack_catalog.technique(tag)
                    if item["deprecated"] or item["revoked"]:
                        notes.append(
                            "Historical ATT&CK tag preserved, not remapped: " + tag
                        )
                except KeyError:
                    reasons.append("Unknown ATT&CK tag: " + tag)
            try:
                _policy(rule, "_selected_index")
            except (ValueError, KeyError, TypeError) as exc:
                reasons.append(str(exc))
            platform = (
                "windows"
                if "WIN" in identifier
                else "linux"
                if "LIN" in identifier or "LNX" in identifier
                else "lab"
            )
            if pack == "rules_lab_50.json":
                notes.append(
                    "Synthetic lab pack includes a fixed source host restriction; retained unchanged and may not match your deployed host"
                )
            if not rule.get("enabled", False):
                notes.append(
                    "Original source pack disabled this rule pending additional sensor/field readiness; importing a template does not install or validate that sensor"
                )
            rows[identifier] = {
                "id": identifier,
                "name": rule.get("name", identifier),
                "description": rule.get("description", ""),
                "kind": rule.get("kind"),
                "severity": rule.get("severity"),
                "mitre": rule.get("mitre", []),
                "platform": platform,
                "pack": pack,
                "supported": not reasons,
                "support_level": "adapted" if not reasons else "unsupported",
                "source_semantics_equal": False,
                "source_default_enabled": rule.get("enabled", False),
                "telemetry_verified": False,
                "origin": rule.get("origin", "user-supplied-XDR-starter"),
                "qualification": rule.get("qualification", "unqualified"),
                "causality_required": rule.get("kind") == "behavior",
                "unsupported_reasons": reasons,
                "adaptation_notes": notes,
                "adaptation_profile": PROFILE,
                "enabled": False,
                "original": rule,
            }
    return rows


def summary():
    rows = _library()
    return {
        "total": len(rows),
        "supported": sum(row["supported"] for row in rows.values()),
        "unsupported": sum(not row["supported"] for row in rows.values()),
        "curated_causal_hypotheses": sum(
            row["origin"] == "xsera-curated" for row in rows.values()
        ),
        "enabled": False,
        "adaptation_profile": PROFILE,
        "policy_limit_per_tenant": 200,
        "catalog_version": attack_catalog.metadata()["version"],
        "provenance": json.loads(
            (attack_catalog.DATA / "provenance.json").read_text(encoding="utf-8")
        ),
    }


def listing(search="", platform=None, supported=None, offset=0, limit=50):
    if (
        not isinstance(search, str)
        or len(search) > 200
        or platform not in {None, "windows", "linux", "lab"}
        or (supported is not None and type(supported) is not bool)
    ):
        raise ValueError("Invalid template filters")
    if (
        type(offset) is not int
        or not 0 <= offset <= 10000
        or type(limit) is not int
        or not 1 <= limit <= 100
    ):
        raise ValueError("Template offset 0..10000 and limit 1..100 required")
    selected = [
        row
        for _, row in sorted(_library().items())
        if (platform is None or row["platform"] == platform)
        and (supported is None or row["supported"] is supported)
        and search.casefold()
        in (row["id"] + " " + row["name"] + " " + " ".join(row["mitre"])).casefold()
    ]
    return {
        "items": [
            copy.deepcopy(
                {key: value for key, value in row.items() if key != "original"}
            )
            for row in selected[offset : offset + limit]
        ],
        "total": len(selected),
        "offset": offset,
        "limit": limit,
        "enabled": False,
        "adaptation_profile": PROFILE,
        "library_total": len(_library()),
    }


def detail(identifier):
    try:
        row = copy.deepcopy(_library()[identifier])
    except (KeyError, TypeError):
        raise KeyError("Rule template not found") from None
    row["policy_preview"] = (
        _policy(row["original"], "_selected_index") if row["supported"] else None
    )
    return row


def apply(store, who, identifier, data):
    if (
        not isinstance(data, dict)
        or not {"index", "accept_adaptation"} <= set(data)
        or set(data) - {"index", "accept_adaptation", "context_filters", "exclusions"}
        or data["accept_adaptation"] is not True
    ):
        raise ValueError("An exact index and accept_adaptation:true are required")
    index = data["index"]
    if not isinstance(index, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", index):
        raise ValueError("One exact logical index is required")
    row = detail(identifier)
    if not row["supported"]:
        raise ValueError(
            "Template is unsupported: " + "; ".join(row["unsupported_reasons"])
        )
    policy = _context_policy(row["original"], index, data)
    with store.write_lock:
        with principal.transaction(store, who, ("admin", "analyst")) as (_, actor):
            if not principal.contains(actor["allowed_indexes"], [index]):
                raise PermissionError("Template index exceeds current user grant")
        policy_id = detections.save(
            store, actor, policy, activation_gate=(identifier, index)
        )
    return {
        "id": policy_id,
        "template_id": identifier,
        "enabled": False,
        "adaptation_profile": PROFILE,
        "warnings": row["adaptation_notes"],
        "index": index,
    }


def readiness(store, who, identifier, data):
    """Actual authorized field counts plus operator-labelled executable fixtures.

    Field presence is a prerequisite, never a sensor/attack coverage assertion.
    Fixtures are isolated from live events and measure only supplied examples.
    """
    if not isinstance(data, dict) or set(data) - {
        "index",
        "earliest",
        "latest",
        "fixtures",
        "positive_event_ids",
        "negative_event_ids",
        "context_filters",
        "exclusions",
    }:
        raise ValueError(
            "Readiness accepts exact index/time window and optional labelled fixtures"
        )
    index = data.get("index")
    if not isinstance(index, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", index):
        raise ValueError("Readiness requires an exact index")
    start, end = data.get("earliest"), data.get("latest")
    if (
        type(start) not in (int, float)
        or type(end) not in (int, float)
        or not math.isfinite(start)
        or not math.isfinite(end)
        or not 0 <= start < end
        or end - start > 7 * 86400
    ):
        raise ValueError("Readiness window must be finite and at most seven days")
    with principal.transaction(store, who, ("admin", "analyst")) as (_, actor):
        if not principal.contains(actor["allowed_indexes"], [index]):
            raise PermissionError("Readiness index is unavailable")
    row = detail(identifier)
    policy = _context_policy(row["original"], index, data)
    required = sorted(
        {
            condition["field"]
            for step in policy["steps"]
            for condition in step["filters"]
            if condition["field"].startswith("raw.")
            and not (condition["op"] == "exists" and not condition["value"])
        }
    )
    if policy.get("relation"):
        required = sorted(
            set(required)
            | {policy["relation"]["field"]}
            | (
                {"raw.xdr.data.process.parent.guid"}
                if policy["relation"]["mode"] == "parent_guid"
                else set()
            )
        )
    from .query import column

    projections = [
        "count(*) AS total",
        *[
            f"count(*) FILTER(WHERE {column(field)} IS NOT NULL) AS f{i}"
            for i, field in enumerate(required)
        ],
    ]
    sql = (
        "SELECT "
        + ",".join(projections)
        + " FROM events_all WHERE tenant=? AND index_name=? AND event_time>=? AND event_time<? AND sourcetype='aegis:endpoint' AND json_extract_string(raw,'$.xdr.schema')='aegis.endpoint.v1'"
    )
    found = store.analytics_query(
        sql, [actor["tenant"], index, start, end], max_rows=1
    )["rows"][0]
    counts = {field: found[f"f{i}"] for i, field in enumerate(required)}
    joint = {}
    for position, step in enumerate(policy["steps"]):
        relevant = [
            item
            for item in step["filters"]
            if item["field"].startswith("raw.")
            and not (item["op"] == "exists" and not item["value"])
        ]
        stage_fields = sorted({item["field"] for item in relevant})
        if policy.get("relation"):
            stage_fields.append(policy["relation"]["field"])
            if policy["relation"]["mode"] == "parent_guid" and position > 0:
                stage_fields.append("raw.xdr.data.process.parent.guid")
        predicates = []
        arguments = [actor["tenant"], index, start, end]
        for field in sorted(set(stage_fields)):
            types = {"VARCHAR"}
            conditions = [item for item in relevant if item["field"] == field]
            if any(
                item["op"].startswith("number_")
                or type(item["value"]) in (int, float)
                and item["op"] == "typed_eq"
                for item in conditions
            ):
                types = {"BIGINT", "UBIGINT", "DOUBLE"}
            if conditions and all(item["op"] == "exists" for item in conditions):
                types = {"VARCHAR", "BIGINT", "UBIGINT", "DOUBLE", "BOOLEAN"}
            predicates.append(
                "json_type(raw,?) IN ("
                + ",".join("'" + t + "'" for t in sorted(types))
                + ")"
            )
            arguments.append("$." + field[4:])
        # Action and schema are sensor prerequisites, not a demand to execute malware live.
        for condition in relevant:
            if (
                condition["field"].endswith(".event.action")
                and condition["op"] == "typed_eq"
            ):
                predicates.append(column(condition["field"]) + "=?")
                arguments.append(condition["value"])
        original_conditions = (
            row["original"].get("conditions", [])
            if row["original"]["kind"] == "threshold"
            else row["original"]["stages"][position]["match"]["all"]
        )
        for condition in original_conditions:
            if (
                condition.get("field") == "event.action"
                and condition.get("operator") == "equals"
                and isinstance(condition.get("value"), str)
            ):
                predicates.append(
                    "lower(json_extract_string(raw,'$.xdr.data.event.action'))=lower(?)"
                )
                arguments.append(condition["value"])
        count = store.analytics_query(
            "SELECT count(*) AS n FROM events_all WHERE tenant=? AND index_name=? AND event_time>=? AND event_time<? AND sourcetype='aegis:endpoint' AND json_extract_string(raw,'$.xdr.schema')='aegis.endpoint.v1'"
            + (" AND " + " AND ".join(predicates) if predicates else ""),
            arguments,
            max_rows=1,
        )["rows"][0]["n"]
        joint[str(position)] = count
    result = {
        "template_id": identifier,
        "index": index,
        "window": {"start": start, "end": end},
        "observed_endpoint_events": found["total"],
        "required_fields": required,
        "field_present_events": counts,
        "joint_stage_field_events": joint,
        "joint_stage_prerequisites_observed": all(joint.values()),
        "unobserved_fields": [field for field, n in counts.items() if not n],
        "telemetry_prerequisites_observed": bool(found["total"])
        and all(counts.values())
        and all(joint.values()),
        "telemetry_verified": False,
        "attack_coverage_verified": False,
        "source_semantics_equal": False,
        "enabled": False,
    }
    fixtures = data.get("fixtures")
    if "positive_event_ids" in data or "negative_event_ids" in data:
        if fixtures is not None or not {
            "positive_event_ids",
            "negative_event_ids",
        } <= set(data):
            raise ValueError(
                "Choose explicit fixtures or both positive/negative original event ID lists"
            )
        fixtures = []
        for name, label in (
            ("positive_event_ids", True),
            ("negative_event_ids", False),
        ):
            ids = data[name]
            if (
                not isinstance(ids, list)
                or not 1 <= len(ids) <= 100
                or any(
                    not isinstance(item, str) or not 1 <= len(item) <= 256
                    for item in ids
                )
                or len(set(ids)) != len(ids)
            ):
                raise ValueError(
                    "Labelled original event IDs require1..100 unique identities"
                )
            selected = store.analytics_query(
                "SELECT event_id,event_time,source,sourcetype,host,severity,message,raw,index_name FROM events_all WHERE tenant=? AND index_name=? AND event_time>=? AND event_time<? AND event_id IN (SELECT value->>'$' FROM json_each(?)) ORDER BY event_time,event_id",
                [actor["tenant"], index, start, end, json.dumps(ids)],
                max_rows=100,
            )["rows"]
            if len(selected) != len(ids):
                raise ValueError(
                    "Labelled original evidence is missing from the authorized index/window"
                )
            events = []
            for event in selected:
                event = dict(event)
                event["index"] = event.pop("index_name")
                event["raw"] = json.loads(event["raw"])
                events.append(event)
            fixtures.append({"label": label, "end": end, "events": events})
        result["fixture_source"] = "operator_labels_on_authorized_stored_originals"
    if fixtures is not None:
        if not isinstance(fixtures, list) or not 2 <= len(fixtures) <= 12:
            raise ValueError("Provide 2..12 labelled positive/negative fixtures")
        from .content import _FixtureStore
        from .storage import normalize

        observations = []
        total_events = 0
        for fixture in fixtures:
            if (
                not isinstance(fixture, dict)
                or set(fixture) != {"label", "end", "events"}
                or type(fixture["label"]) is not bool
                or not isinstance(fixture["events"], list)
                or len(fixture["events"]) > 100
            ):
                raise ValueError("Fixture requires boolean label/end and <=100 events")
            if (
                type(fixture["end"]) not in (int, float)
                or not math.isfinite(fixture["end"])
                or not 0 < fixture["end"] <= time.time() + 86400
            ):
                raise ValueError("Fixture end must be a finite supported time")
            events = [normalize(event) for event in fixture["events"]]
            total_events += len(events)
            if total_events > 400 or any(event["index"] != index for event in events):
                raise ValueError(
                    "Fixtures require selected index and <=400 total events"
                )
            observed = bool(
                detections.evaluate(
                    _FixtureStore(store, actor["tenant"], events),
                    actor["tenant"],
                    policy,
                    fixture["end"],
                    [index],
                )
            )
            observations.append({"label": fixture["label"], "observed": observed})
        if not {True, False} <= {item["label"] for item in observations}:
            raise ValueError(
                "Positive and benign negative fixture labels are mandatory"
            )
        tp = sum(x["label"] and x["observed"] for x in observations)
        fp = sum(not x["label"] and x["observed"] for x in observations)
        fn = sum(x["label"] and not x["observed"] for x in observations)
        result["fixture_validation"] = {
            "observations": observations,
            "passed": all(x["label"] == x["observed"] for x in observations),
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "scope": "Only supplied labelled examples; not production accuracy or adversary coverage",
        }
    with principal.transaction(store, actor, ("admin", "analyst"), write=True) as (
        db,
        fresh,
    ):
        if not principal.contains(fresh["allowed_indexes"], [index]):
            raise PermissionError("Readiness permissions changed")
        digest = hashlib.sha256(encode_policy(policy).encode()).hexdigest()
        db.execute(
            "INSERT INTO template_readiness VALUES(?,?,?,?,?,?) ON CONFLICT(tenant,template_id,index_name) DO UPDATE SET definition_digest=excluded.definition_digest,result=excluded.result,updated=excluded.updated",
            (
                actor["tenant"],
                identifier,
                index,
                digest,
                json.dumps(
                    result, ensure_ascii=False, allow_nan=False, separators=(",", ":")
                ),
                time.time(),
            ),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "template.readiness",
            {
                "template_id": identifier,
                "index": index,
                "prerequisites": result["telemetry_prerequisites_observed"],
                "fixture_passed": result.get("fixture_validation", {}).get(
                    "passed", False
                ),
            },
        )
    return result


def encode_policy(policy):
    from .storage import encode

    return encode(detections.validate(policy))


def _context_policy(rule, index, data):
    policy = _policy(rule, index)
    filters = data.get("context_filters", [])
    if not isinstance(filters, list) or len(filters) > 8:
        raise ValueError("Template context accepts up to8 explicit AND filters")
    for step in policy["steps"]:
        step["filters"].extend(copy.deepcopy(filters))
        if data.get("exclusions"):
            step["exclusions"] = copy.deepcopy(data["exclusions"])
    return detections.validate(policy)
