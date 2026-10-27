"""Original-row saved findings to common signals, with terminal item isolation.

Aggregate, wildcard-scope and projected/fabricated samples never acquire
invented original ancestry. Existing findings cursor/diagnostics are reused.
"""

import hashlib
import json
import time

from . import access, evidence_scope, intelligence, principal, release_manifest
from .storage import CapacityError, ConflictError, encode

EDITORS = ("admin", "analyst")
SEVERITY = {name: position for position, name in enumerate(("info", "low", "medium", "high", "critical"))}


def initialize(store):
    # Root initializes the intelligence migration before this module.
    with store.control(local=True) as db:
        db.execute("INSERT OR IGNORE INTO intelligence_cursors VALUES('findings',0)")


def _rule_digest(rule):
    return release_manifest.digest({key: rule[key] for key in ("id", "query", "interval", "lookback", "threshold")})


def _scope(evidence):
    if not isinstance(evidence, dict):
        raise ValueError("Finding evidence must be an object")
    value = access.validate(evidence.get("access_scope"))
    if not value or value == ["*"]:
        raise ValueError("Finding requires a complete exact index scope")
    return value


def _rule(db, tenant, rule_id, indexes):
    row = db.execute("SELECT r.*,x.owner AS execution_owner FROM rules r LEFT JOIN rule_execution x ON x.rule_id=r.id WHERE r.id=? AND r.tenant=?",
                     (rule_id, tenant)).fetchone()
    if not row or not row["enabled"]:
        raise KeyError("Saved search is missing or disabled")
    owner = principal.current(db, {"name": row["execution_owner"], "tenant": tenant, "role": "analyst"}, EDITORS)
    if not principal.contains(owner["allowed_indexes"], indexes):
        raise PermissionError("Saved search owner no longer has full finding scope")
    return row, owner


def _samples(evidence):
    sample = evidence.get("sample")
    if not isinstance(sample, list) or not 1 <= len(sample) <= 32:
        raise ValueError("Finding requires bounded original-row samples")
    ids = []
    for row in sample:
        if not isinstance(row, dict) or not {"event_id", "event_time", "host", "source"} <= set(row) or not {"index", "index_name"} & set(row):
            raise ValueError("Aggregate/projected samples do not prove complete original identity")
        ids.append(evidence_scope.text(row["event_id"], "sample original ID"))
    if len(ids) != len(set(ids)):
        raise ValueError("Finding original sample IDs must be unique")
    return sample, ids


def _export(store, db, finding):
    evidence = json.loads(finding["evidence"])
    if finding["status"] == "false_positive":
        raise ValueError("Finding is currently an analyst false positive")
    indexes = _scope(evidence)
    rule, owner = _rule(db, finding["tenant"], finding["rule_id"], indexes)
    policy = None
    for candidate in db.execute("SELECT * FROM intelligence_policies WHERE tenant=? AND state='active' ORDER BY updated,id", (finding["tenant"],)).fetchall():
        if not principal.contains(json.loads(candidate["indexes"]), indexes):
            continue
        try:
            intelligence._authority(db, candidate)
            policy = candidate
            break
        except (PermissionError, KeyError, ConflictError):
            continue
    if not policy:
        raise PermissionError("No independently reviewed current bridge policy covers full finding scope")
    sample, ids = _samples(evidence)
    originals = evidence_scope.originals(store, owner, ids)
    evidence_scope.recheck(db, owner, originals)
    if {original["index_name"] for original in originals.values()} != set(indexes):
        # Common signals derive their read scope from originals. A finding
        # whose aggregate/existence covers a wider scope must not be narrowed
        # to its first ten sampled originals for publication.
        raise PermissionError("Finding's complete read scope cannot be represented by sampled originals")
    for row in sample:
        original = originals[row["event_id"]]
        if original["index_name"] not in indexes:
            raise PermissionError("Finding original lies outside its complete declared scope")
        if (any(row[key] != original[key] for key in ("event_time", "host", "source"))
                or row.get("index_name", row.get("index")) != original["index_name"]):
            raise ConflictError("Finding sample identity differs from admitted original")
    severity = max((r["severity"] if r["severity"] in SEVERITY else "info" for r in originals.values()), key=lambda name: SEVERITY[name])
    rule_digest = _rule_digest(rule)
    signal = intelligence.publish_in_transaction(store, db, owner, {
        "event_ids": sorted(ids), "kind": "finding", "rule_id": "finding:"+finding["rule_id"],
        "rule_revision": 1, "features": {"sample_original_count": len(ids)},
        "severity": severity, "confidence_grade": "saved_search_original_row_hypothesis",
        "definition_digest": rule_digest,
        "context_digest": release_manifest.digest({"finding_id": finding["id"], "evidence": evidence, "rule_definition_digest": rule_digest}),
        "metadata": {"finding_id": finding["id"], "finding_scope": indexes,
                     "sample_subset_only": True, "matched_at_least": evidence.get("matched_at_least"),
                     "rule_definition_digest": rule_digest, "bridge_policy_id": policy["id"],
                     "bridge_policy_revision": policy["version"], "verdict": "consult current finding status",
                     "ground_truth_used": False}})
    return signal


def _diagnostic(db, finding, reason, detail):
    try:
        evidence = json.loads(finding["evidence"])
        evidence = evidence if isinstance(evidence, dict) else {}
    except (ValueError, TypeError):
        evidence = {}
    scope = evidence.get("access_scope")
    try:
        scope = access.validate(scope)
    except ValueError:
        scope = ["*"]  # Failure details remain visible only to full-scope users.
    db.execute("INSERT INTO intelligence_decisions(tenant,policy_id,version,indexes,signal_id,reason,detail,at) VALUES(?,?,?,?,?,?,?,?)",
               (finding["tenant"], "finding:"+finding["id"], finding["version"], encode(scope or ["*"]), None, reason, encode(detail), time.time()))


def run_due(store, now=None, cancel=None, budget=.25, max_runs=16):
    if type(max_runs) is not int or not 1 <= max_runs <= 100:
        raise ValueError("Finding bridge batch must be 1..100")
    until = time.monotonic()+max(.01, min(10, budget))
    with store.control() as db:
        cursor = db.execute("SELECT cursor FROM intelligence_cursors WHERE worker='findings'").fetchone()[0]
        findings = [dict(row) for row in db.execute("SELECT rowid AS sequence,* FROM findings WHERE rowid>? ORDER BY rowid LIMIT ?", (cursor, max_runs)).fetchall()]
    published = excluded = retries = 0
    for finding in findings:
        if (cancel is not None and cancel.is_set()) or time.monotonic() >= until:
            break
        try:
            # Gate order matches the indexer/lifecycle: a pending segment writer
            # cannot block a nested source query while we hold the SQLite writer.
            with store.segment_lock.read(deadline=time.monotonic()+min(5, store.settings.query_timeout)), store.write_lock, store.control() as db:
                db.execute("BEGIN IMMEDIATE")
                fresh = db.execute("SELECT rowid AS sequence,* FROM findings WHERE id=? AND tenant=?", (finding["id"], finding["tenant"])).fetchone()
                if not fresh:
                    raise KeyError("Finding disappeared during bridge inspection")
                signal = _export(store, db, fresh)
                _diagnostic(db, fresh, "finding_exported", {"finding_id": fresh["id"], "signal_id": signal["id"], "sample_subset_only": True})
                db.execute("UPDATE intelligence_cursors SET cursor=? WHERE worker='findings'", (finding["sequence"],))
                published += int(not signal["duplicate"])
        except (PermissionError, KeyError, ConflictError, ValueError, CapacityError, RuntimeError) as exc:
            with store.write_lock, store.control() as db:
                db.execute("BEGIN IMMEDIATE")
                attempts = db.execute("SELECT count(*) FROM intelligence_decisions WHERE tenant=? AND policy_id=? AND reason='finding_retry'",
                                      (finding["tenant"], "finding:"+finding["id"])).fetchone()[0]
                transient = isinstance(exc, (CapacityError, RuntimeError)) and attempts < 2
                _diagnostic(db, finding, "finding_retry" if transient else "finding_excluded", {"finding_id": finding["id"], "error": type(exc).__name__, "reason": str(exc)[:400], "attempt": attempts+1, "sample_ancestry_invented": False})
                if transient:
                    retries += 1
                    break
                db.execute("UPDATE intelligence_cursors SET cursor=? WHERE worker='findings'", (finding["sequence"],))
                excluded += 1
    return {"published": published, "excluded": excluded, "retry": retries}


def validate_parent(db, actor, body):
    """Return whether a finding/legacy parent still has active scoped judgement."""
    if body.get("kind") not in {"finding", "legacy"}:
        return True
    try:
        actor = principal.current(db, actor, EDITORS)
        metadata = body.get("metadata", {})
        if body["kind"] == "legacy":
            from . import contribution_verdicts
            row = db.execute("SELECT * FROM risk_contributions WHERE tenant=? AND id=?", (actor["tenant"], metadata.get("contribution_id"))).fetchone()
            if not row or not principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
                return False
            if set(json.loads(row["evidence"]).get("event_ids", [])) != set(body.get("event_ids", [])):
                return False
            if row["policy_id"] != body.get("rule_id"):
                return False
            expected = metadata.get("contribution_evidence_digest")
            if expected is not None and hashlib.sha256(row["evidence"].encode()).hexdigest() != expected:
                return False
            case = principal.incident(db, actor, row["incident_id"])
            return case["status"] != "false_positive" and contribution_verdicts.classification(db, row)["active"]
        finding = db.execute("SELECT * FROM findings WHERE tenant=? AND id=?", (actor["tenant"], metadata.get("finding_id"))).fetchone()
        if not finding or finding["status"] == "false_positive":
            return False
        indexes = _scope(json.loads(finding["evidence"]))
        if not principal.contains(actor["allowed_indexes"], indexes):
            return False
        rule, _ = _rule(db, actor["tenant"], finding["rule_id"], indexes)
        if _rule_digest(rule) != metadata.get("rule_definition_digest"):
            return False
        policy = db.execute("SELECT * FROM intelligence_policies WHERE tenant=? AND id=?", (actor["tenant"], metadata.get("bridge_policy_id"))).fetchone()
        if not policy or policy["version"] != metadata.get("bridge_policy_revision"):
            return False
        intelligence._authority(db, policy)
        return True
    except (KeyError, PermissionError, ConflictError, ValueError, TypeError):
        return False
