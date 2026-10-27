"""Explicit onboarding/enablement state; no automatic unqualified-rule activation."""

import json
import time

from . import principal


def status(store, who):
    with principal.transaction(store, who, ("admin", "analyst")) as (db, actor):
        if actor["allowed_indexes"] != ["*"]:
            return {"state": "complete_tenant_scope_required", "counts": None,
                    "automatic_case_readiness": "unknown", "automatic_activation": False,
                    "meaning": "Aggregate tenant readiness is not exposed outside complete index scope"}
        counts = {}
        for name in ("rules", "correlation_policies", "analysis_schedules", "behavior_baselines", "endpoint_agents"):
            counts[name] = {"total": db.execute(f"SELECT count(*) FROM {name} WHERE tenant=?", (actor["tenant"],)).fetchone()[0]}
        for name in ("rules", "correlation_policies", "analysis_schedules"):
            counts[name]["enabled"] = db.execute(f"SELECT count(*) FROM {name} WHERE tenant=? AND enabled=1", (actor["tenant"],)).fetchone()[0]
        counts["rules"]["case_capable_enabled"] = db.execute(
            "SELECT count(*) FROM rules r JOIN rule_detection_options o ON o.rule_id=r.id "
            "WHERE r.tenant=? AND r.enabled=1 AND o.case_adapter IS NOT NULL",
            (actor["tenant"],),
        ).fetchone()[0]
        counts["analysis_schedules"]["case_capable_enabled"] = sum(
            json.loads(row[0]).get("case_adapter") is not None
            for row in db.execute("SELECT definition FROM analysis_schedules WHERE tenant=? AND enabled=1", (actor["tenant"],))
        )
        counts["behavior_baselines"]["ready"] = sum(
            json.loads(row[0]).get("ready") is True
            for row in db.execute("SELECT snapshot FROM behavior_baselines WHERE tenant=?", (actor["tenant"],))
        )
        counts["behavior_baselines"]["cold_start"] = counts["behavior_baselines"]["total"] - counts["behavior_baselines"]["ready"]
        now = time.time()
        counts["endpoint_agents"]["active_credentials"] = db.execute(
            "SELECT count(*) FROM endpoint_agents WHERE tenant=? AND revoked=0 AND expires>?",
            (actor["tenant"], now),
        ).fetchone()[0]
        counts["endpoint_agents"]["recent_heartbeat"] = db.execute(
            "SELECT count(*) FROM endpoint_agents WHERE tenant=? AND revoked=0 AND expires>? AND last_seen>=?",
            (actor["tenant"], now, now-180),
        ).fetchone()[0]
        errors = {}
        plans=[dict(r) for r in db.execute("SELECT * FROM correlation_plans WHERE tenant=?",(actor["tenant"],))]
        healthy_v2=0
        for plan in plans:
            if not plan["enabled"]:
                continue
            definition=json.loads(plan["definition"])
            healthy_v2+=int(not plan["error"] and all(
                db.execute("SELECT 1 FROM source_registry WHERE tenant=? AND id=? AND state='active' AND version=?",(actor["tenant"],sid,version)).fetchone()
                for sid,version in definition["source_versions"].items()))
        counts["correlation_plans"]={"total":len(plans),"enabled":sum(bool(p["enabled"]) for p in plans),"healthy":healthy_v2}
        for name in ("correlation_policies", "analysis_schedules"):
            errors[name] = db.execute(f"SELECT count(*) FROM {name} WHERE tenant=? AND enabled=1 AND failures>0",
                                     (actor["tenant"],)).fetchone()[0]
        enabled = sum(counts[n].get("enabled", 0) for n in ("rules", "correlation_policies", "analysis_schedules"))
        case_enabled = (counts["rules"]["case_capable_enabled"] + counts["correlation_policies"]["enabled"]
                        + counts["analysis_schedules"]["case_capable_enabled"]+healthy_v2)
        enabled+=counts["correlation_plans"]["enabled"]
        errors["correlation_plans"]=counts["correlation_plans"]["enabled"]-healthy_v2
        warnings = []
        if not counts["endpoint_agents"]["active_credentials"]:
            warnings.append("no_enrolled_endpoint")
        elif not counts["endpoint_agents"]["recent_heartbeat"]:
            warnings.append("no_recent_endpoint_heartbeat")
        if not enabled:
            warnings.append("no_enabled_detector")
        if not counts["behavior_baselines"]["ready"]:
            warnings.append("no_trained_behavior_baseline")
        if counts["behavior_baselines"]["cold_start"]:
            warnings.append("behavior_baseline_cold_start")
        if not case_enabled:
            warnings.append("no_enabled_case_adapter")
        if any(errors.values()):
            warnings.append("analysis_worker_errors")
        return {"schema": "xsera.detection-readiness.v1", "generated_at": now,
                "state": "onboarding_required" if not case_enabled or (not counts["endpoint_agents"]["active_credentials"] and not healthy_v2) else "configured_requires_sensor_and_efficacy_qualification",
                "counts": counts, "analysis_errors": errors, "warnings": warnings,
                "automatic_case_readiness": "not_configured" if not case_enabled else "configured_not_certified",
                "automatic_activation": False,
                "sensor_capture_proven": False,
                "commercial_accuracy_certified": False,
                "next_steps": [
                    {"id":"enroll", "route":"agents", "title":"Enroll actual endpoints with verified TLS and inspect per-channel health"},
                    {"id":"observe", "route":"analysis", "title":"Check joint typed fields and true sensor prerequisites"},
                    {"id":"qualify", "route":"content", "title":"Qualify curated content with benign twins and withheld evaluation data"},
                    {"id":"enable", "route":"analysis", "title":"Enable measured observe-only detectors before response policies"},
                ],
                "meaning": "Enablement and heartbeat are prerequisites, not sensor coverage or detection-accuracy evidence"}
