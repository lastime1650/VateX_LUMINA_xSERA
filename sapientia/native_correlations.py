"""Bounded positive Sigma correlations executed by the native signal pipeline.

The approved JSON is independent of pySigma at execution. Windows slide over
reported event time; equal timestamps cannot establish temporal ordering.
"""

import itertools
import json
import re
import time

from . import evidence_scope, principal, release_manifest
from .storage import ConflictError, encode

TYPES = ("event_count", "value_count", "temporal", "temporal_ordered")
MAX_COHORT = 256
MAX_ORIGINALS = 32
CONTRACT_DIGEST = release_manifest.digest({"version": 1, "implementation": release_manifest.hash_file(__file__), "window": "inclusive-sliding-reported-event-time", "ordering": "strict-event-time", "count": "unique-originals", "bounds": [MAX_COHORT, MAX_ORIGINALS]})


def _path(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:raw(?:\.[A-Za-z_][A-Za-z0-9_]{0,63}){1,8}|event\.(?:event_id|event_time|host|source|sourcetype|severity|message|index_name))", value):
        raise ValueError("Correlation requires an exact scalar raw/event field")
    if any(part in {"label", "ground_truth", "scenario_label", "expected_detected"} for part in value.split(".")):
        raise ValueError("Evaluation labels are not correlation evidence")
    return value


def validate(value, inputs, window):
    keys = {"version", "type", "group_by", "value_field", "condition", "clock", "window_semantics"}
    if not isinstance(value, dict) or set(value) != keys or type(value.get("version")) is not int or value.get("version") != 1 or value.get("type") not in TYPES:
        raise ValueError("Supported native correlation v1 required")
    if value["clock"] != "reported_event_time" or value["window_semantics"] != "sliding_inclusive":
        raise ValueError("Explicit reported-event-time sliding window required")
    if type(window) is not int or not 1 <= window <= 86400 or not isinstance(inputs, list) or not 1 <= len(inputs) <= 8 or any(not isinstance(item, dict) or set(item) != {"rule_id", "kind"} or item["kind"] != "atomic" or not isinstance(item["rule_id"], str) for item in inputs):
        raise ValueError("Correlation requires 1..8 exact atomic inputs and 1..86400 seconds")
    identifiers = {item["rule_id"] for item in inputs}
    if len(identifiers) != len(inputs):
        raise ValueError("Correlation inputs must be distinct")
    groups = value["group_by"]
    if not isinstance(groups, list) or not 1 <= len(groups) <= 4:
        raise ValueError("Correlation requires 1..4 explicit grouping fields")
    canonical = []
    for item in groups:
        if not isinstance(item, dict) or set(item) != {"name", "fields"} or not isinstance(item["fields"], dict) or set(item["fields"]) != identifiers:
            raise ValueError("Every grouping field needs an explicit path for every parent")
        evidence_scope.text(item["name"], "group field", 120)
        canonical.append({"name": item["name"], "fields": {key: _path(path) for key, path in sorted(item["fields"].items())}})
    if len({item["name"] for item in canonical}) != len(canonical):
        raise ValueError("Duplicate grouping field")
    condition, field = value["condition"], value["value_field"]
    if value["type"] in {"event_count", "value_count"}:
        if not isinstance(condition, dict) or set(condition) != {"op", "value"} or not isinstance(condition["op"], str) or condition["op"] not in {"gte", "gt"} or type(condition["value"]) is not int or not 1 <= condition["value"] <= (31 if condition["op"] == "gt" else 32):
            raise ValueError("Positive gte 1..32 / gt 1..31 count required; absence/upper-bound counts are unsupported")
    elif condition is not None or len(inputs) < 2:
        raise ValueError("Temporal correlations require 2..8 rules and all rules, without a threshold override")
    if value["type"] == "value_count":
        if not isinstance(field, dict) or set(field) != identifiers:
            raise ValueError("Value count requires an explicit scalar path for every parent")
        field = {key: _path(path) for key, path in sorted(field.items())}
    elif field is not None:
        raise ValueError("Only value_count accepts value_field")
    return {**value, "group_by": canonical, "value_field": field}


def _scalar(record, path):
    value = record if path.startswith("event.") else record.get("raw", {})
    for part in path.split(".")[1:]:
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    if type(value) not in (str, int, float, bool) or isinstance(value, str) and len(value.encode()) > 4096:
        return None
    # bool is distinct; equal numeric values share one identity.
    if type(value) is float and value.is_integer():
        value = int(value)
    return ("number", value) if type(value) in (int, float) else (type(value).__name__, value)


def entries(definition, parents, records):
    correlation = definition["correlation"]
    wanted = {item["rule_id"] for item in definition["inputs"]}
    result = []
    for parent in parents:
        rule = parent["rule_id"]
        if rule not in wanted or parent["kind"] != "atomic" or len(parent["event_ids"]) != 1:
            raise ConflictError("Correlation parent must be an exact one-original atomic rule")
        record = records[parent["event_ids"][0]]
        group = tuple(_scalar(record, field["fields"][rule]) for field in correlation["group_by"])
        if any(value is None for value in group):
            continue  # Missing/null/structured grouping fields cannot create a join.
        value = _scalar(record, correlation["value_field"][rule]) if correlation["value_field"] else None
        result.append({"parent": parent, "record": record, "group": group, "value": value, "time": record["event_time"]})
    return result


def evaluate(definition, candidates):
    """Evaluate one complete candidate window; used by fixtures and publication."""
    correlation = definition["correlation"]
    if not candidates or len({entry["group"] for entry in candidates}) != 1:
        return None
    if max(item["time"] for item in candidates) - min(item["time"] for item in candidates) > definition["window"]:
        return None
    identifiers = {item["record"]["event_id"] for item in candidates}
    if len(identifiers) > MAX_ORIGINALS or len({item["parent"]["id"] for item in candidates}) > MAX_ORIGINALS:
        raise ValueError("Correlation evidence coverage exceeds 32 originals/parents")
    kind = correlation["type"]
    if kind in {"event_count", "value_count"}:
        count = len(identifiers) if kind == "event_count" else len({item["value"] for item in candidates if item["value"] is not None})
        condition = correlation["condition"]
        passed = count >= condition["value"] if condition["op"] == "gte" else count > condition["value"]
        return {"type": kind, "count": count, "group_digest": release_manifest.digest(candidates[0]["group"])} if passed else None
    required = [item["rule_id"] for item in definition["inputs"]]
    buckets = [[item for item in candidates if item["parent"]["rule_id"] == rule] for rule in required]
    if not all(buckets):
        return None
    if kind == "temporal_ordered":
        previous = None
        for bucket in buckets:
            choices = [item["time"] for item in bucket if previous is None or item["time"] > previous]
            if not choices:
                return None
            previous = min(choices)
    return {"type": kind, "matched_rule_types": len(required), "group_digest": release_manifest.digest(candidates[0]["group"]), "strict_order": kind == "temporal_ordered"}


def validate_publication(store, db, actor, data, definition):
    from . import intelligence
    if not isinstance(data, dict) or not isinstance(data.get("metadata", {}), dict) or not isinstance(data.get("features"), dict) or not isinstance(data.get("parent_signal_ids"), list) or not isinstance(data.get("event_ids"), list):
        raise ValueError("Typed correlation evidence, parents and metadata required")  # noqa: TRY004 - HTTP and legacy evidence validation use ValueError.
    if definition.get("correlation_contract") != CONTRACT_DIGEST:
        raise ConflictError("Correlation evaluator changed; review a new conversion")
    if data.get("kind") != "composite" or data.get("definition_digest") != release_manifest.digest(definition):
        raise ConflictError("Correlation signal must pin its current native definition")
    policy = db.execute("SELECT * FROM intelligence_policies WHERE tenant=? AND id=?", (actor["tenant"], data.get("rule_id"))).fetchone()
    if not policy or policy["version"] != data.get("rule_revision") or policy["kind"] != "composite" or json.loads(policy["definition"]) != definition:
        raise ConflictError("Correlation signal revision differs from current policy")
    intelligence._authority(db, policy)
    if not principal.contains(actor["allowed_indexes"], definition["indexes"]):
        raise PermissionError("Publishing requires complete current correlation scope")
    parents = []
    for identifier in data.get("parent_signal_ids", []):
        row = db.execute("SELECT body FROM intelligence_signals WHERE tenant=? AND id=? AND mode='live'", (actor["tenant"], identifier)).fetchone()
        if not row:
            raise ConflictError("Current correlation parent unavailable")
        parent = json.loads(row["body"])
        if not intelligence._parent_valid(store, db, actor, parent, definition):
            raise ConflictError("Correlation parent authority or original expired")
        parents.append(parent)
    if not 1 <= len(parents) <= MAX_ORIGINALS:
        raise ConflictError("Correlation requires 1..32 current atomic parents")
    event_ids = sorted({identifier for parent in parents for identifier in parent["event_ids"]})
    if sorted(data.get("event_ids", [])) != event_ids:
        raise ConflictError("Correlation signal original ancestry differs")
    records = evidence_scope.originals(store, actor, event_ids)
    evidence_scope.recheck(db, actor, records)
    candidates = entries(definition, parents, records)
    result = evaluate(definition, candidates)
    if len(candidates) != len(parents) or not result:
        raise ConflictError("Current original values do not satisfy approved correlation")
    if data.get("features") != result or data.get("metadata", {}).get("correlation", result) != result:
        raise ConflictError("Correlation measurement differs from actual original values")


def validate_parent(store, db, actor, signal, definition):
    try:
        validate_publication(store, db, actor, signal, definition)
        return True
    except (ValueError, KeyError, PermissionError, ConflictError):
        return False


def run_policy(store, db, actor, policy, definition, *, deadline=None, cancel=None, memo=None):
    from . import intelligence
    state = db.execute("SELECT * FROM native_correlation_state WHERE policy_id=?", (policy["id"],)).fetchone()
    last_seq = state["last_seq"] if state and state["version"] == policy["version"] else 0
    rules = [item["rule_id"] for item in definition["inputs"]]
    rows = db.execute("SELECT seq,body FROM intelligence_signals WHERE tenant=? AND mode='live' AND kind='atomic' AND rule_id IN (SELECT value FROM json_each(?)) AND created>=? ORDER BY seq LIMIT ?", (actor["tenant"], encode(rules), time.time() - definition["window"], MAX_COHORT + 1)).fetchall()
    def progress(status, detail, cursor=last_seq):
        db.execute("INSERT INTO native_correlation_state VALUES(?,?,?,?,?,?) ON CONFLICT(policy_id) DO UPDATE SET version=excluded.version,last_seq=excluded.last_seq,status=excluded.status,detail=excluded.detail,updated=excluded.updated", (policy["id"], policy["version"], cursor, status, encode(detail), time.time()))
    if len(rows) > MAX_COHORT:
        progress("coverage_exceeded", {"reason": "retained_parent_cohort_exceeds_256", "complete": False})
        return 0
    if not rows or max(row["seq"] for row in rows) <= last_seq:
        return 0
    candidates, parents = [], []
    for row in rows:
        if cancel is not None and cancel.is_set() or deadline and time.monotonic() >= deadline:
            progress("yielded", {"complete": False})
            return 0
        parent = json.loads(row["body"])
        if intelligence._parent_valid(store, db, actor, parent, definition, memo=memo):
            parents.append(parent)
    # Read current evidence in bounded batches, retaining receipt checks.
    records = {}
    identifiers = sorted({identifier for parent in parents for identifier in parent["event_ids"]})
    for offset in range(0, len(identifiers), MAX_ORIGINALS):
        if cancel is not None and cancel.is_set() or deadline and time.monotonic() >= deadline:
            progress("yielded", {"complete": False})
            return 0
        records.update(evidence_scope.originals(store, actor, identifiers[offset:offset + MAX_ORIGINALS]))
    candidates = entries(definition, parents, records)
    emitted = 0
    for _, grouped in itertools.groupby(sorted(candidates, key=lambda item: encode(item["group"])), key=lambda item: item["group"]):
        group = list(grouped)
        for end in sorted({item["time"] for item in group}):
            if cancel is not None and cancel.is_set() or deadline and time.monotonic() >= deadline:
                progress("yielded", {"complete": False})
                return emitted
            window = [item for item in group if end - definition["window"] <= item["time"] <= end]
            try:
                result = evaluate(definition, window)
            except ValueError:
                progress("coverage_exceeded", {"reason": "window_exceeds_32_originals_or_parents", "complete": False})
                return emitted
            if not result:
                continue
            chosen = {item["parent"]["id"]: item["parent"] for item in window}
            ids = sorted({identifier for parent in chosen.values() for identifier in parent["event_ids"]})
            context = release_manifest.digest(sorted(parent["context_digest"] for parent in chosen.values()))
            identifier = "SIG-" + release_manifest.digest([actor["tenant"], "live", "composite", policy["id"], policy["version"], ids, sorted(chosen), context])
            if db.execute("SELECT 1 FROM intelligence_signals WHERE tenant=? AND id=?", (actor["tenant"], identifier)).fetchone():
                continue  # Durable retry skips already validated emission work.
            signal = intelligence.publish_in_transaction(store, db, actor, {"event_ids": ids, "kind": "composite", "rule_id": policy["id"], "rule_revision": policy["version"], "features": result, "severity": definition["severity"], "confidence_grade": definition["confidence_grade"], "parent_signal_ids": list(chosen), "entity_key": "sigma-group:" + result["group_digest"], "window": definition["window"], "definition_digest": release_manifest.digest(definition), "context_digest": context, "metadata": {"correlation": result, "reported_association_only": True, "complete_bounded_window": True}}, memo=memo)
            if not signal.get("duplicate"):
                intelligence._case(store, db, actor, policy, definition, signal, memo=memo)
                emitted += 1
    progress("completed", {"complete": True, "parent_cohort": len(rows), "emitted": emitted}, max(row["seq"] for row in rows))
    return emitted
