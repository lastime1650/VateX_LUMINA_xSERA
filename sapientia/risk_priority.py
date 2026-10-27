"""Explainable operational priority from evidence and explicit asset context.

This fixed, published model ranks analyst work. It is not an empirically
calibrated malware probability, a CVSS replacement or a prediction model.
Expired context is excluded instead of becoming an everlasting exposure claim.
"""

import json
import time

from . import contribution_verdicts, entities, principal
from . import evidence_scope as evidence
from .storage import CapacityError, ConflictError, encode

MODEL = "xsera.operational-priority.v1"
SEVERITY = {"info": 0, "low": 20, "medium": 45, "high": 70, "critical": 100}
EXPOSURE = {"isolated": 0, "internal": 35, "internet": 100, "unknown": 0}
CLASSIFICATION = {"public": 0, "internal": 25, "confidential": 65, "restricted": 100}


def initialize(store):
    with store.control(local=True) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS asset_risk_context(
          tenant TEXT NOT NULL,entity_id TEXT NOT NULL,entity_version INTEGER NOT NULL,
          indexes TEXT NOT NULL,version INTEGER NOT NULL,owner TEXT NOT NULL,
          updated REAL NOT NULL,expires REAL NOT NULL,definition TEXT NOT NULL,
          PRIMARY KEY(tenant,entity_id));
        CREATE TABLE IF NOT EXISTS asset_risk_context_history(
          tenant TEXT NOT NULL,entity_id TEXT NOT NULL,version INTEGER NOT NULL,
          actor TEXT NOT NULL,at REAL NOT NULL,record TEXT NOT NULL,
          PRIMARY KEY(tenant,entity_id,version));
        """)


def save_context(store, who, entity_id, data):
    if not isinstance(data, dict) or set(data) - {
        "version",
        "expires",
        "exposure",
        "classification",
        "vulnerabilities",
        "source",
        "reason",
    }:
        raise ValueError("Unknown asset risk context property")
    version = evidence.integer(data.get("version", 0), "version", 0, 2**31 - 1)
    now = time.time()
    expires = evidence.number(data.get("expires"), "expires", now + 1, now + 90 * 86400)
    exposure, classification = (
        data.get("exposure", "unknown"),
        data.get("classification", "internal"),
    )
    evidence.choice(exposure, EXPOSURE, "exposure")
    evidence.choice(classification, CLASSIFICATION, "classification")
    source = evidence.text(data.get("source"), "context source", 2000)
    reason = evidence.text(data.get("reason"), "context reason", 2000)
    vulnerabilities = data.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list) or len(vulnerabilities) > 32:
        raise ValueError("At most 32 vulnerability observations are supported")
    ids = set()
    normalized = []
    for item in vulnerabilities:
        if not isinstance(item, dict) or set(item) != {
            "id",
            "cvss",
            "known_exploited",
            "source",
            "observed_at",
        }:
            raise ValueError(
                "Vulnerability requires id/cvss/known_exploited/source/observed_at"
            )
        identifier = evidence.text(item["id"], "vulnerability id", 128)
        if identifier in ids:
            raise ValueError("Duplicate vulnerability identifier")
        ids.add(identifier)
        if type(item["known_exploited"]) is not bool:
            raise ValueError("known_exploited must be an explicit boolean observation")
        normalized.append(
            {
                "id": identifier,
                "cvss": evidence.number(item["cvss"], "cvss", 0, 10),
                "known_exploited": item["known_exploited"],
                "source": evidence.text(item["source"], "vulnerability source", 2000),
                "observed_at": evidence.number(
                    item["observed_at"], "observed_at", max(0, now - 90 * 86400), now
                ),
            }
        )
    definition = {
        "exposure": exposure,
        "classification": classification,
        "vulnerabilities": normalized,
        "source": source,
        "reason": reason,
        "claim_type": "explicit administrator supplied inventory; source quality not independently attested",
    }
    with principal.transaction(store, who, ("admin", "analyst"), write=True) as (
        db,
        actor,
    ):
        entity = entities._visible(db, actor, entity_id)
        old = db.execute(
            "SELECT * FROM asset_risk_context WHERE tenant=? AND entity_id=?",
            (actor["tenant"], entity_id),
        ).fetchone()
        if old and not principal.contains(
            actor["allowed_indexes"], json.loads(old["indexes"])
        ):
            raise KeyError("Asset risk context not found")
        if (old["version"] if old else 0) != version:
            raise ConflictError("Asset risk context version changed")
        db.execute(
            "INSERT INTO asset_risk_context VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant,entity_id) DO UPDATE SET entity_version=excluded.entity_version,indexes=excluded.indexes,version=excluded.version,owner=excluded.owner,updated=excluded.updated,expires=excluded.expires,definition=excluded.definition",
            (
                actor["tenant"],
                entity_id,
                entity["version"],
                encode(entity["indexes"]),
                version + 1,
                actor["name"],
                now,
                expires,
                encode(definition),
            ),
        )
        result = {
            "entity_id": entity_id,
            "entity_version": entity["version"],
            "indexes": entity["indexes"],
            "version": version + 1,
            "expires": expires,
            "updated": now,
            "owner": actor["name"],
            "definition": definition,
        }
        db.execute(
            "INSERT INTO asset_risk_context_history VALUES(?,?,?,?,?,?)",
            (
                actor["tenant"],
                entity_id,
                version + 1,
                actor["name"],
                now,
                encode(result),
            ),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "asset.risk_context.save",
            {"entity_id": entity_id, "version": version + 1, "expires": expires},
        )
        return result


def context(store, who, entity_id):
    with principal.transaction(store, who) as (db, actor):
        entity = entities._visible(db, actor, entity_id)
        row = db.execute(
            "SELECT * FROM asset_risk_context WHERE tenant=? AND entity_id=?",
            (actor["tenant"], entity_id),
        ).fetchone()
        if not row or not principal.contains(
            actor["allowed_indexes"], json.loads(row["indexes"])
        ):
            raise KeyError("Asset risk context not found")
        return {
            **dict(row),
            "indexes": json.loads(row["indexes"]),
            "definition": json.loads(row["definition"]),
            "effective": row["expires"] > time.time()
            and row["entity_version"] == entity["version"],
        }


def calculate(
    evidence_score,
    severity,
    *,
    criticality=None,
    exposure="unknown",
    classification="public",
    vulnerabilities=None,
    evidence_confidence="unverified",
    active_evidence=True,
):
    """Pure documented model, available for planning and explanation."""
    score = evidence.number(evidence_score, "evidence_score", 0, 100)
    evidence.choice(severity, SEVERITY, "severity")
    evidence.choice(exposure, EXPOSURE, "exposure")
    evidence.choice(classification, CLASSIFICATION, "classification")
    evidence.choice(
        evidence_confidence,
        {
            "unverified",
            "admitted",
            "enrolled_endpoint",
            "mixed_sources",
            "partially_admitted",
        },
        "source admission confidence",
    )
    if type(active_evidence) is not bool:
        raise ValueError("active_evidence must be boolean")
    criticality = (
        1 if criticality is None else evidence.integer(criticality, "criticality", 1, 5)
    )
    vulnerabilities = [] if vulnerabilities is None else vulnerabilities
    if not isinstance(vulnerabilities, list) or len(vulnerabilities) > 32:
        raise ValueError("At most 32 vulnerabilities are supported")
    vuln_score = 0
    exploited = False
    for item in vulnerabilities:
        if not isinstance(item, dict):
            raise ValueError("Vulnerability observation must be an object")  # noqa: TRY004 - JSON/API validation is HTTP 400.
        cvss = evidence.number(item.get("cvss"), "cvss", 0, 10)
        if type(item.get("known_exploited")) is not bool:
            raise ValueError("known_exploited must be boolean")
        exploited |= item["known_exploited"]
        vuln_score = max(
            vuln_score, min(100, cvss * 10 + (15 if item["known_exploited"] else 0))
        )
    factors = {
        "evidence": {"value": score, "weight": 0.55},
        "severity": {"value": SEVERITY[severity], "weight": 0.20},
        "asset_criticality": {"value": (criticality - 1) * 25, "weight": 0.10},
        "exposure": {"value": EXPOSURE[exposure], "weight": 0.05},
        "vulnerability": {"value": vuln_score, "weight": 0.05},
        "data_impact": {"value": CLASSIFICATION[classification], "weight": 0.05},
    }
    for item in factors.values():
        item["contribution"] = round(item["value"] * item["weight"], 4)
    priority = (
        round(sum(item["contribution"] for item in factors.values()), 2)
        if active_evidence
        else 0
    )
    return {
        "model": MODEL,
        "score": min(100, max(0, priority)),
        "tier": "critical"
        if priority >= 80
        else "high"
        if priority >= 60
        else "medium"
        if priority >= 35
        else "low",
        "factors": factors,
        "known_exploited_observed": exploited,
        "evidence_confidence": evidence_confidence,
        "formula": "0.55*evidence + 0.20*severity + 0.10*asset + 0.05*exposure + 0.05*vulnerability + 0.05*data_impact; no active evidence => 0",
        "meaning": "Operational analyst priority, not malicious probability; bounded configured model, no learned calibration",
        "source_attestation": False,
        "malicious_probability": None,
        "probability_calibration": "not_established",
    }


def case_priority(store, who, incident_id, entity_id=None):
    """Current complete-case evidence plus an explicitly selected asset context."""
    with principal.transaction(store, who) as (db, actor):
        incident = principal.incident(db, actor, incident_id)
        rows = db.execute(
            "SELECT * FROM risk_contributions WHERE tenant=? AND incident_id=? ORDER BY at,id",
            (actor["tenant"], incident_id),
        ).fetchall()
        # Permanent execution/investigation history has no lifetime count ceiling.
        weights, severities, event_ids = [], [], set()
        verdict_counts = {key: 0 for key in contribution_verdicts.CLASSIFICATIONS}
        evidence_groups = set()
        stale_verdicts = 0
        for row in rows:
            if not principal.contains(
                actor["allowed_indexes"], json.loads(row["indexes"])
            ):
                raise KeyError("Case not found in complete evidence scope")
            verdict = contribution_verdicts.classification(db, row)
            verdict_counts[verdict["classification"]] += 1
            stale_verdicts += int(verdict["stale"])
            if not verdict["active"]:
                continue
            match = json.loads(row["evidence"])
            evidence_groups.add(encode(sorted(set(match.get("event_ids", [])))))
            weights.append(row["weight"])
            if match.get("severity") in SEVERITY:
                severities.append(match["severity"])
            event_ids.update(match.get("event_ids", []))
            if len(event_ids) > 1024:
                raise CapacityError(
                    "Priority source evidence exceeds 1,024 events; narrow the case"
                )
        severity = max(severities, key=SEVERITY.get) if severities else "info"
        model_args = {}
        asset = None
        context_state = "not_selected"
        if entity_id is not None:
            asset = entities._visible(db, actor, entity_id)
            # Association is explicit and visible; never choose by an IP string.
            model_args["criticality"] = asset["criticality"]
            row = db.execute(
                "SELECT * FROM asset_risk_context WHERE tenant=? AND entity_id=?",
                (actor["tenant"], entity_id),
            ).fetchone()
            context_state = "missing"
            if row and principal.contains(
                actor["allowed_indexes"], json.loads(row["indexes"])
            ):
                context_state = (
                    "expired"
                    if row["expires"] <= time.time()
                    else "asset_revision_changed"
                    if row["entity_version"] != asset["version"]
                    else "effective"
                )
                if context_state == "effective":
                    definition = json.loads(row["definition"])
                    model_args.update(
                        {
                            key: definition[key]
                            for key in ("exposure", "classification", "vulnerabilities")
                        }
                    )
        admitted = 0
        enrolled = 0
        for event_id in event_ids:
            admitted += int(
                db.execute(
                    "SELECT 1 FROM receipts WHERE tenant=? AND event_id=?",
                    (actor["tenant"], event_id),
                ).fetchone()
                is not None
            )
            enrolled += int(
                db.execute(
                    "SELECT 1 FROM endpoint_event_receipts e JOIN receipts r ON r.tenant=e.tenant AND r.event_id=e.event_id AND r.digest=e.receipt_digest AND r.received=e.received WHERE e.tenant=? AND e.event_id=?",
                    (actor["tenant"], event_id),
                ).fetchone()
                is not None
            )
        result = calculate(
            max(weights, default=0),
            severity,
            evidence_confidence="enrolled_endpoint"
            if event_ids and enrolled == len(event_ids)
            else "mixed_sources"
            if enrolled
            else "admitted"
            if event_ids and admitted == len(event_ids)
            else "partially_admitted"
            if admitted
            else "unverified",
            active_evidence=bool(weights) and incident["status"] != "false_positive",
            **model_args,
        )
        return {
            **result,
            "incident_id": incident_id,
            "incident_version": incident["version"],
            "incident_status": incident["status"],
            "asset_id": entity_id,
            "asset_association": "explicit analyst selection" if entity_id else "none",
            "context_state": context_state,
            "evidence_score": max(weights, default=0),
            "evidence_count": len(rows),
            "active_evidence_count": len(weights),
            "adjudication_counts": verdict_counts,
            "evidence_quality": {
                "model": "xsera.explainable-evidence-quality.v1",
                "exact_evidence_groups": len(evidence_groups),
                "repeated_evidence_sets": len(weights) - len(evidence_groups),
                "stale_verdicts": stale_verdicts,
                "technique_attribution": "policy hypothesis, not independent adversary classification",
                "malicious_probability": None,
                "probability_calibration": "not_established",
                "meaning": "Admission confidence and analyst labels are separate from configured operational priority",
            },
            "event_ids": sorted(event_ids),
            "source_provenance": {
                "event_ids": len(event_ids),
                "admitted": admitted,
                "enrolled_endpoint": enrolled,
                "missing_current_receipts": len(event_ids) - admitted,
            },
            "exposure_unknown": model_args.get("exposure", "unknown") == "unknown",
        }
