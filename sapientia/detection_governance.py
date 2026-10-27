"""Versioned expiring false-positive exceptions and durable storm governance.

Only the private engine hook accepts candidate objects; callers must construct
them from original server-side detection evidence. Governance never removes logs
or claims that suppressed observations were resolved. Critical signals bypass
storm suppression. Every decision retains its fingerprint and explanation.
"""

import hashlib
import json
import re
import time
import uuid

from . import contribution_verdicts, principal
from . import evidence_scope as evidence
from .storage import CapacityError, ConflictError, encode

SEVERITIES = {"low", "medium", "high", "critical", "info"}
CONTEXT_PATHS = {
    "process_guid": ("raw.xdr.data.process.guid", "raw.security.process_guid"),
    "parent_guid": ("raw.xdr.data.process.parent.guid",),
    "process_hash": ("raw.xdr.data.process.hash.sha256",),
    "process_executable": ("raw.xdr.data.process.executable", "raw.security.process"),
    "process_command_line": ("raw.xdr.data.process.command_line",),
    "process_signer": ("raw.xdr.data.process.code_signature.subject_name",),
    "user": ("raw.xdr.data.user.name", "raw.security.user"),
    "session_id": ("raw.xdr.data.session.id", "raw.security.session_id"),
}
PRECISE_FIELDS = {"process_guid", "parent_guid", "process_hash", "process_executable",
                  "process_command_line", "process_signer", "session_id"}
FIELDS = {"entity", "entity_field", "severity", "policy_id", "source", "host",
          "signer_verified", *CONTEXT_PATHS}


def _field(event, path):
    if path in event:
        return event[path]
    value = event
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _context_value(event, name):
    values = [_field(event, p) for p in CONTEXT_PATHS[name]]
    values = {v for v in values if isinstance(v, str) and v and len(v) <= 8192}
    if len(values) != 1:
        return None
    value = next(iter(values))
    if name == "process_hash":
        return value.lower() if re.fullmatch(r"[0-9a-fA-F]{64}", value) else None
    if name == "process_signer" and _field(event, "raw.xdr.data.process.code_signature.trusted") is not True:
        return None
    return value


def initialize(store):
    with store.control(local=True) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS detection_governance_rules(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,policy_id TEXT NOT NULL,
          policy_version INTEGER NOT NULL,kind TEXT NOT NULL,indexes TEXT NOT NULL,
          definition TEXT NOT NULL,version INTEGER NOT NULL,state TEXT NOT NULL,
          requester TEXT NOT NULL,approver TEXT NOT NULL,created REAL NOT NULL,
          updated REAL NOT NULL,expires REAL NOT NULL);
        CREATE INDEX IF NOT EXISTS detection_governance_policy ON
          detection_governance_rules(tenant,policy_id,state,expires);
        CREATE TABLE IF NOT EXISTS detection_governance_history(
          tenant TEXT NOT NULL,id TEXT NOT NULL,version INTEGER NOT NULL,
          action TEXT NOT NULL,actor TEXT NOT NULL,at REAL NOT NULL,record TEXT NOT NULL,
          PRIMARY KEY(tenant,id,version,action));
        CREATE TABLE IF NOT EXISTS detection_governance_decisions(
          tenant TEXT NOT NULL,fingerprint TEXT NOT NULL,policy_id TEXT NOT NULL,
          policy_version INTEGER NOT NULL,indexes TEXT NOT NULL,created REAL NOT NULL,
          decision TEXT NOT NULL,PRIMARY KEY(tenant,fingerprint));
        CREATE INDEX IF NOT EXISTS detection_governance_decision_time ON
          detection_governance_decisions(tenant,created);
        CREATE TABLE IF NOT EXISTS detection_storm_buckets(
          tenant TEXT NOT NULL,rule_id TEXT NOT NULL,rule_version INTEGER NOT NULL,
          entity_key TEXT NOT NULL,window_start INTEGER NOT NULL,count INTEGER NOT NULL,
          suppressed INTEGER NOT NULL,PRIMARY KEY(tenant,rule_id,rule_version,entity_key,window_start));
        """)


def _policy(db, actor, identifier):
    from . import detector_ops

    row = detector_ops.policy(db,actor,identifier)
    definition = json.loads(row["definition"])
    owner = principal.current(
        db,
        {"name": row["owner"], "tenant": row["tenant"], "role": "analyst", **({"allowed_indexes":json.loads(row["indexes"])} if row.get("indexes") else {})},
        ("admin", "analyst"),
    )
    if not principal.contains(actor["allowed_indexes"], owner["allowed_indexes"]):
        raise KeyError("Detection policy not found in the complete owner scope")
    return row, definition


def _candidate(policy_id, match):
    events = [
        event for step in match.get("steps", []) for event in step.get("events", [])
    ]
    result = {
        "entity": match["entity"],
        "entity_field": match["entity_field"],
        "severity": match["severity"],
        "policy_id": policy_id,
        "source": [row.get("source") for row in events],
        "host": [row.get("host") for row in events],
    }
    # Every contributing event must satisfy the context. A missing/ambiguous
    # event never inherits another process's trusted hash or signer.
    for name in CONTEXT_PATHS:
        result[name] = [_context_value(event, name) for event in events]
    result["signer_verified"] = [
        "true" if _field(event, "raw.xdr.data.process.code_signature.trusted") is True else None
        for event in events
    ]
    return result


def _conditions(value):
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        raise ValueError("1..16 exact exception conditions are required")
    result = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"field", "op", "value"}:
            raise ValueError("Condition requires field, op and value")
        if (
            not isinstance(item["field"], str)
            or item["field"] not in FIELDS
            or not isinstance(item["op"], str)
            or item["op"] not in {"eq", "in"}
        ):
            raise ValueError("Use explicit candidate fields with eq/in")
        values = item["value"] if item["op"] == "in" else [item["value"]]
        if not isinstance(values, list) or not 1 <= len(values) <= 16:
            raise ValueError("Exception values must be 1..16 strings")
        for entry in values:
            if item["field"] == "process_command_line":
                if not isinstance(entry, str) or not entry or len(entry) > 8192:
                    raise ValueError("Exact command-line context requires 1..8192 characters")
            else:
                evidence.text(entry, "condition value", 512)
            if item["field"] == "process_hash" and not re.fullmatch(r"[0-9a-f]{64}", entry):
                raise ValueError("Process hash requires lowercase SHA256")
            if item["field"] == "signer_verified" and entry != "true":
                raise ValueError("Only an explicitly verified signer can form trusted context")
        result.append(dict(item))
    # A policy-wide severity exception would hide unrelated incidents.
    if not any(item["field"] == "entity" for item in result):
        raise ValueError("An exception must bind an explicit entity")
    return result


def _scope_quality(conditions):
    return "exact_context" if any(c["field"] in PRECISE_FIELDS for c in conditions) else "broad_host_policy"


def _maintenance(value, now, expires):
    if not isinstance(value, dict) or set(value) != {"starts_at", "ends_at"}:
        raise ValueError("Maintenance requires starts_at and ends_at epoch seconds")
    start = evidence.number(value["starts_at"], "starts_at", now - 1, expires)
    end = evidence.number(value["ends_at"], "ends_at", max(now + 1, start + 1), expires)
    return {"starts_at": start, "ends_at": end}


def _matches(conditions, candidate):
    for condition in conditions:
        actual = candidate.get(condition["field"])
        permitted = (
            condition["value"] if condition["op"] == "in" else [condition["value"]]
        )
        if isinstance(actual, list):
            if not actual or any(value not in permitted for value in actual):
                return False
        elif actual not in permitted:
            return False
    return True


def _serialize(row, now=None):
    result = dict(row)
    result["indexes"] = json.loads(result["indexes"])
    result["definition"] = json.loads(result["definition"])
    result["effective_state"] = (
        "expired"
        if result["expires"] <= (time.time() if now is None else now)
        else result["state"]
    )
    return result


def _visible(db, actor, identifier):
    row = db.execute(
        "SELECT * FROM detection_governance_rules WHERE tenant=? AND id=?",
        (actor["tenant"], identifier),
    ).fetchone()
    if not row or not principal.contains(
        actor["allowed_indexes"], json.loads(row["indexes"])
    ):
        raise KeyError("Governance rule not found")
    return row


def save(store, who, data, identifier=None):
    keys = {
        "kind",
        "policy_id",
        "indexes",
        "expires",
        "reason",
        "conditions",
        "case_id",
        "max_per_window",
        "window_seconds",
        "bypass_severities",
        "version",
        "maintenance",
    }
    if not isinstance(data, dict) or set(data) - keys:
        raise ValueError("Unknown governance rule property")
    kind = evidence.choice(data.get("kind"), {"exception", "storm"}, "governance kind")
    policy_id = evidence.text(data.get("policy_id"), "policy_id")
    scope = evidence.indexes(data.get("indexes"))
    now = time.time()
    expires = evidence.number(data.get("expires"), "expires", now + 1, now + 31 * 86400)
    version = evidence.integer(data.get("version", 0), "version", 0, 2**31 - 1)
    definition = {"reason": evidence.text(data.get("reason"), "reason", 2000)}
    if kind == "exception":
        if set(data) & {"max_per_window", "window_seconds", "bypass_severities"}:
            raise ValueError("Storm properties cannot appear in an exception")
        definition["conditions"] = _conditions(data.get("conditions"))
        definition["scope_quality"] = _scope_quality(definition["conditions"])
        definition["critical_bypass"] = definition["scope_quality"] == "broad_host_policy"
        if "maintenance" in data:
            definition["maintenance"] = _maintenance(data["maintenance"], now, expires)
        definition["case_id"] = evidence.text(data.get("case_id"), "case_id")
    else:
        if set(data) & {"conditions", "case_id", "maintenance"}:
            raise ValueError("Exception properties cannot appear in a storm rule")
        definition["max_per_window"] = evidence.integer(
            data.get("max_per_window"), "max_per_window", 1, 10000
        )
        definition["window_seconds"] = evidence.integer(
            data.get("window_seconds", 60), "window_seconds", 10, 3600
        )
        bypass = data.get("bypass_severities", ["high", "critical"])
        if (
            not isinstance(bypass, list)
            or any(
                not isinstance(item, str) or item not in SEVERITIES for item in bypass
            )
            or len(set(bypass)) != len(bypass)
            or "critical" not in bypass
        ):
            raise ValueError("Unique bypass severities must include critical")
        definition["bypass_severities"] = sorted(bypass)
        definition["key"] = "policy_version+exact_entity+server_observation_window"
    with principal.transaction(store, who, ("admin", "analyst"), write=True) as (
        db,
        actor,
    ):
        policy, _ = _policy(db, actor, policy_id)
        if not principal.contains(actor["allowed_indexes"], scope):
            raise PermissionError("Governance scope exceeds current permission")
        old = _visible(db, actor, identifier) if identifier else None
        if (old["version"] if old else 0) != version:
            raise ConflictError("Governance rule version changed")
        if kind == "exception":
            incident = principal.incident(db, actor, definition["case_id"])
            contributions = db.execute(
                "SELECT * FROM risk_contributions WHERE tenant=? AND incident_id=? AND policy_id=?",
                (actor["tenant"], definition["case_id"], policy_id),
            ).fetchall()
            adjudicated = [(row, contribution_verdicts.classification(db, row)) for row in contributions]
            eligible = [(row, verdict) for row, verdict in adjudicated
                        if verdict["classification"] in {"false_positive", "expected_activity"}]
            if incident["status"] != "false_positive" and not eligible:
                raise ConflictError("Exception must cite false_positive or expected_activity evidence explicitly adjudicated by an analyst")
            if incident["status"] != "false_positive":
                contributions = [row for row, _ in eligible]
            if not contributions or not any(
                _matches(
                    definition["conditions"],
                    _candidate(policy_id, json.loads(row["evidence"])),
                )
                for row in contributions
            ):
                raise ValueError(
                    "Exception conditions must match the cited case's actual policy evidence"
                )
            basis = sorted(
                {index for row in contributions for index in json.loads(row["indexes"])}
            )
            if not set(basis) <= set(scope):
                raise ValueError(
                    "Exception indexes must contain its complete false-positive evidence scope"
                )
            definition["source_fingerprints"] = [
                hashlib.sha256(row["evidence"].encode()).hexdigest()
                for row in contributions
            ]
            definition["case_version"] = incident["version"]
            if eligible:
                definition["source_verdicts"] = [{"contribution_id":row["id"], "version":verdict["version"],
                                                 "evidence_sha256":hashlib.sha256(row["evidence"].encode()).hexdigest()}
                                                for row, verdict in eligible]
        # Durable inventory/history has no lifetime record-count ceiling.
        identifier = identifier or str(uuid.uuid4())
        db.execute(
            "INSERT INTO detection_governance_rules VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET policy_id=excluded.policy_id,policy_version=excluded.policy_version,kind=excluded.kind,"
            "indexes=excluded.indexes,definition=excluded.definition,version=excluded.version,state=excluded.state,requester=excluded.requester,"
            "approver=excluded.approver,updated=excluded.updated,expires=excluded.expires",
            (
                identifier,
                actor["tenant"],
                policy_id,
                policy["version"],
                kind,
                encode(scope),
                encode(definition),
                version + 1,
                "pending",
                actor["name"],
                "",
                now,
                now,
                expires,
            ),
        )
        row = _visible(db, actor, identifier)
        db.execute(
            "INSERT INTO detection_governance_history VALUES(?,?,?,?,?,?,?)",
            (
                actor["tenant"],
                identifier,
                version + 1,
                "save",
                actor["name"],
                now,
                encode(_serialize(row)),
            ),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "detection.governance.save",
            {
                "id": identifier,
                "version": version + 1,
                "kind": kind,
                "expires": expires,
            },
        )
        return _serialize(row)


def review(store, who, identifier, version, approve, reason):
    evidence.integer(version, "version", 1, 2**31 - 1)
    if type(approve) is not bool:
        raise ValueError("approve must be boolean")
    evidence.text(reason, "review reason", 2000)
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        row = _visible(db, actor, identifier)
        policy, _ = _policy(db, actor, row["policy_id"])
        if (
            row["version"] != version
            or row["state"] != "pending"
            or row["expires"] <= time.time()
            or policy["version"] != row["policy_version"]
        ):
            raise ConflictError(
                "Governance revision is stale, expired or no longer pending"
            )
        if actor["name"] == row["requester"]:
            raise PermissionError(
                "A different active administrator must review this revision"
            )
        requester = principal.current(
            db,
            {"name": row["requester"], "tenant": actor["tenant"], "role": "analyst"},
            ("admin", "analyst"),
        )
        if not principal.contains(
            requester["allowed_indexes"], json.loads(row["indexes"])
        ):
            raise PermissionError("Requester permissions changed")
        now = time.time()
        if approve and not _approved(db, {**dict(row), "approver": actor["name"]}):
            raise ConflictError("Governance source judgement or current approval authority changed")
        db.execute(
            "UPDATE detection_governance_rules SET state=?,approver=?,updated=? WHERE id=?",
            ("active" if approve else "rejected", actor["name"], now, identifier),
        )
        result = _serialize(_visible(db, actor, identifier))
        db.execute(
            "INSERT INTO detection_governance_history VALUES(?,?,?,?,?,?,?)",
            (
                actor["tenant"],
                identifier,
                version,
                "approve" if approve else "reject",
                actor["name"],
                now,
                encode({**result, "review_reason": reason}),
            ),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "detection.governance.review",
            {
                "id": identifier,
                "version": version,
                "approve": approve,
                "reason": reason,
            },
        )
        return result


def revoke(store, who, identifier, version, reason):
    evidence.integer(version, "version", 1, 2**31 - 1)
    evidence.text(reason, "revocation reason", 2000)
    with principal.transaction(store, who, ("admin", "analyst"), write=True) as (
        db,
        actor,
    ):
        row = _visible(db, actor, identifier)
        if row["version"] != version or row["state"] == "revoked":
            raise ConflictError("Governance revision changed or is already revoked")
        now = time.time()
        db.execute(
            "UPDATE detection_governance_rules SET state='revoked',updated=? WHERE id=?",
            (now, identifier),
        )
        result = _serialize(_visible(db, actor, identifier))
        db.execute(
            "INSERT INTO detection_governance_history VALUES(?,?,?,?,?,?,?)",
            (
                actor["tenant"],
                identifier,
                version,
                "revoke",
                actor["name"],
                now,
                encode({**result, "revocation_reason": reason}),
            ),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "detection.governance.revoke",
            {"id": identifier, "version": version, "reason": reason},
        )
        return result


def _approved(db, row):
    scope = json.loads(row["indexes"])
    try:
        requester = principal.current(
            db,
            {"name": row["requester"], "tenant": row["tenant"], "role": "analyst"},
            ("admin", "analyst"),
        )
        approver = principal.current(
            db,
            {"name": row["approver"], "tenant": row["tenant"], "role": "admin"},
            ("admin",),
        )
        if not (
            row["requester"] != row["approver"]
            and principal.contains(requester["allowed_indexes"], scope)
            and principal.contains(approver["allowed_indexes"], scope)
        ):
            return False
        if row["kind"] == "exception":
            definition = json.loads(row["definition"])
            case = principal.incident(db, requester, definition["case_id"])
            principal.incident(db, approver, definition["case_id"])
            if definition.get("source_verdicts"):
                for basis in definition["source_verdicts"]:
                    source = db.execute("SELECT * FROM risk_contributions WHERE tenant=? AND id=?",
                                        (row["tenant"], basis["contribution_id"])).fetchone()
                    if not source:
                        return False
                    verdict = contribution_verdicts.classification(db, source)
                    if (verdict["classification"] not in {"false_positive", "expected_activity"}
                        or verdict["version"] != basis["version"]
                        or hashlib.sha256(source["evidence"].encode()).hexdigest() != basis["evidence_sha256"]):
                        return False
                    principal.incident(db, requester, source["incident_id"])
                    principal.incident(db, approver, source["incident_id"])
            elif (
                case["status"] != "false_positive"
                or case["version"] != definition["case_version"]
            ):
                return False
        return True
    except PermissionError:
        return False
    except KeyError:
        return False


def _govern_candidate(db, store, actor, policy, match, *, observed_at=None):
    """Engine-only, within the same write transaction as candidate emission.

    policy and match MUST be server-derived validated policy/evidence records.
    At capacity the candidate is allowed and an explicit unrecorded flag is
    returned, so overload cannot silently turn into a detection blackout.
    """
    actor = principal.current(db, actor, ("admin", "analyst"))
    if actor["tenant"] != policy["tenant"] or not principal.contains(
        actor["allowed_indexes"], match["indexes"]
    ):
        raise PermissionError("Candidate exceeds the current complete evidence scope")
    from . import detector_ops

    current = detector_ops.policy(db,actor,policy["id"])
    if current["version"] != policy["version"]:
        raise ConflictError("Candidate policy revision changed")
    now = (
        time.time()
        if observed_at is None
        else evidence.number(observed_at, "observed_at")
    )
    rows = db.execute(
        "SELECT * FROM detection_governance_rules WHERE tenant=? AND policy_id=? AND policy_version=? AND state='active' AND expires>? ORDER BY kind,id",
        (actor["tenant"], policy["id"], policy["version"], now),
    ).fetchall()
    if len(rows) > 2000:
        raise CapacityError("Governance evaluation rule bound exceeded")
    rows = [
        row
        for row in rows
        if set(match["indexes"]) <= set(json.loads(row["indexes"]))
        and _approved(db, row)
        and (
            not json.loads(row["definition"]).get("maintenance")
            or json.loads(row["definition"])["maintenance"]["starts_at"] <= now
            < json.loads(row["definition"])["maintenance"]["ends_at"]
        )
    ]
    authority = []
    for row in rows:
        definition = json.loads(row["definition"])
        authority.append(
            [
                row["id"],
                row["version"],
                row["expires"],
                int(now // definition["window_seconds"])
                if row["kind"] == "storm"
                else None,
            ]
        )
    # Current authority/window is part of the decision identity. An expired or
    # revoked exception must not permanently suppress the same replay evidence.
    fingerprint = hashlib.sha256(
        encode(
            [
                policy["id"],
                policy["version"],
                match["entity_field"],
                match["entity"],
                sorted(match["event_ids"]),
                authority,
            ]
        ).encode()
    ).hexdigest()
    prior = db.execute(
        "SELECT indexes,decision FROM detection_governance_decisions WHERE tenant=? AND fingerprint=?",
        (actor["tenant"], fingerprint),
    ).fetchone()
    if prior:
        if not principal.contains(
            actor["allowed_indexes"], json.loads(prior["indexes"])
        ):
            raise PermissionError("Decision requires the complete original scope")
        return {**json.loads(prior["decision"]), "duplicate": True}
    result = {
        "allowed": True,
        "reason": "no_active_governance_match",
        "fingerprint": fingerprint,
        "duplicate": False,
        "decision_recorded": True,
    }
    # Permanent execution/investigation history has no lifetime count ceiling.
    candidate = _candidate(policy["id"], match)
    for row in rows:
        definition = json.loads(row["definition"])
        if row["kind"] == "exception" and _matches(definition["conditions"], candidate):
            if match["severity"] == "critical" and _scope_quality(definition["conditions"]) == "broad_host_policy":
                result.update(reason="critical_bypassed_broad_exception", scope_quality="broad_host_policy")
                continue
            result.update(
                allowed=False,
                reason="approved_expiring_false_positive_exception",
                rule_id=row["id"],
                rule_version=row["version"],
                expires=row["expires"],
                scope_quality=_scope_quality(definition["conditions"]),
            )
            break
        if (
            row["kind"] != "storm"
            or match["severity"] in definition["bypass_severities"]
        ):
            continue
        width = definition["window_seconds"]
        start = int(now // width) * width
        key = hashlib.sha256(
            encode([match["entity_field"], match["entity"]]).encode()
        ).hexdigest()
        bucket = db.execute(
            "SELECT count,suppressed FROM detection_storm_buckets WHERE tenant=? AND rule_id=? AND rule_version=? AND entity_key=? AND window_start=?",
            (actor["tenant"], row["id"], row["version"], key, start),
        ).fetchone()
        count = (bucket["count"] if bucket else 0) + 1
        suppressed = count > definition["max_per_window"]
        db.execute(
            "INSERT INTO detection_storm_buckets VALUES(?,?,?,?,?,?,?) ON CONFLICT(tenant,rule_id,rule_version,entity_key,window_start) DO UPDATE SET count=excluded.count,suppressed=excluded.suppressed",
            (
                actor["tenant"],
                row["id"],
                row["version"],
                key,
                start,
                count,
                (bucket["suppressed"] if bucket else 0) + int(suppressed),
            ),
        )
        if suppressed:
            result.update(
                allowed=False,
                reason="approved_per_entity_storm_window",
                rule_id=row["id"],
                rule_version=row["version"],
                count=count,
                window_start=start,
                window_end=start + width,
                max_per_window=definition["max_per_window"],
            )
            break
    db.execute(
        "INSERT INTO detection_governance_decisions VALUES(?,?,?,?,?,?,?)",
        (
            actor["tenant"],
            fingerprint,
            policy["id"],
            policy["version"],
            encode(match["indexes"]),
            now,
            encode(result),
        ),
    )
    if not result["allowed"]:
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "detection.governance.suppress",
            {**result, "event_ids": match["event_ids"], "telemetry_deleted": False},
        )
    return result


def list_rules(store, who):
    with principal.transaction(store, who) as (db, actor):
        rows = db.execute(
            "SELECT * FROM detection_governance_rules WHERE tenant=? ORDER BY updated DESC,id",
            (actor["tenant"],),
        ).fetchall()
        if len(rows) > 2000:
            raise CapacityError("Governance list bound exceeded")
        result = []
        for row in rows:
            if not principal.contains(
                actor["allowed_indexes"], json.loads(row["indexes"])
            ):
                continue
            item = _serialize(row)
            policy = db.execute(
                "SELECT version FROM correlation_policies WHERE tenant=? AND id=?",
                (actor["tenant"], row["policy_id"]),
            ).fetchone()
            if item["effective_state"] == "active":
                item["effective_state"] = (
                    "policy_revision_changed"
                    if not policy or policy[0] != row["policy_version"]
                    else "authority_or_case_changed"
                    if not _approved(db, row)
                    else "active"
                )
            result.append(item)
        return result


def list_policies(store, who):
    """Only metadata whose complete current policy-owner scope is authorized."""
    with principal.transaction(store, who, ("admin", "analyst")) as (db, actor):
        rows = db.execute(
            "SELECT id FROM correlation_policies WHERE tenant=? ORDER BY name,id",
            (actor["tenant"],),
        ).fetchall()
        if len(rows) > 2000:
            raise CapacityError("Governance policy selection bound exceeded")
        result = []
        for item in rows:
            try:
                row, _ = _policy(db, actor, item["id"])
            except (KeyError, PermissionError):
                continue
            result.append(
                {
                    "id": row["id"],
                    "name": row["name"],
                    "version": row["version"],
                    "owner": row["owner"],
                }
            )
        return result


def decisions(store, who, start, end, *, limit=100):
    start, end = evidence.number(start, "start"), evidence.number(end, "end")
    if not start < end or end - start > 31 * 86400:
        raise ValueError("Decision window must be positive and at most 31 days")
    evidence.integer(limit, "limit", 1, 500)
    with principal.transaction(store, who) as (db, actor):
        rows = db.execute(
            "SELECT * FROM detection_governance_decisions WHERE tenant=? AND created>=? AND created<? ORDER BY created DESC,fingerprint",
            (actor["tenant"], start, end),
        ).fetchall()
        visible = [
            {
                **dict(row),
                "indexes": json.loads(row["indexes"]),
                "decision": json.loads(row["decision"]),
            }
            for row in rows
            if principal.contains(actor["allowed_indexes"], json.loads(row["indexes"]))
        ]
        return {
            "items": visible,
            "total_visible": len(visible),
            "suppressed": sum(not row["decision"]["allowed"] for row in visible),
            "truncated": False,
            "telemetry_deleted": False,
        }


def prune(store, who, before):
    raise PermissionError("Permanent recording forbids deleting investigation history")
    before = evidence.number(before, "before", 0, time.time() - 86400)
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        if actor["allowed_indexes"] != ["*"]:
            raise PermissionError(
                "Governance retention requires unrestricted tenant scope"
            )
        deleted = db.execute(
            "DELETE FROM detection_governance_decisions WHERE tenant=? AND created<?",
            (actor["tenant"], before),
        ).rowcount
        buckets = db.execute(
            "DELETE FROM detection_storm_buckets WHERE tenant=? AND window_start<?",
            (actor["tenant"], before - 3600),
        ).rowcount
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "detection.governance.prune",
            {"before": before, "decisions": deleted, "buckets": buckets},
        )
        return {"decisions": deleted, "buckets": buckets, "rule_history_retained": True}
