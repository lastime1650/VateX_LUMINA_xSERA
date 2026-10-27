"""Bounded console projections from measured, tenant/index-authorized populations.

The analytical and control stores have separate snapshots. Counts describe the
specified cohort, not a limited table page. No network or product writes occur.
"""

import math
import sqlite3
import time

from . import principal
from .query import index_predicate
from .storage import CapacityError

SECONDS = 5.0
TABLE_LIMIT = 50
SOURCE_LIMIT = 100
BUCKETS = 48
SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")


class _Budget:
    def __init__(self, cancel, deadline=None):
        self.deadline = (
            min(time.monotonic() + SECONDS, deadline)
            if deadline is not None
            else time.monotonic() + SECONDS
        )
        self.cancel = cancel

    def stopped(self):
        requested = (
            self.cancel()
            if callable(self.cancel)
            else bool(self.cancel and self.cancel.is_set())
        )
        return requested or time.monotonic() >= self.deadline

    def remaining(self):
        if self.stopped():
            raise CapacityError(
                "Console summary cancelled or its 5 second deadline expired"
            )
        return max(0.001, self.deadline - time.monotonic())


def _window(start, end, now):
    end = now if end is None else end
    start = end - 86400 if start is None and isinstance(end, (int, float)) else start
    for value in (start, end):
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            raise ValueError("Console start and end must be finite epoch timestamps")
    if not 0 <= start < end <= now + 1 or end - start > 366 * 86400:
        raise ValueError(
            "Console window requires 0 <= start < end <= now and at most 366 days"
        )
    return float(start), float(end)


def _json_value(expression, path):
    # Expression/path are server literals, never request-derived SQL.
    return f"json_extract(CASE WHEN json_valid({expression}) THEN {expression} ELSE '{{}}' END,'{path}')"


def _scope(scope, expression):
    """Require every recorded index, including historical scope, to be authorized."""
    if scope == ["*"]:
        return "1=1", []
    if not scope:
        return "0=1", []
    slots = ",".join("?" for _ in scope)
    return (
        (
            f"CASE WHEN json_valid({expression}) THEN CASE WHEN json_type({expression})='array' "
            f"THEN json_array_length({expression})>0 AND NOT EXISTS(SELECT 1 FROM json_each({expression}) j "
            f"WHERE j.type!='text' OR j.value NOT IN ({slots})) ELSE 0 END ELSE 0 END"
        ),
        scope,
    )


def _playbook_scope(scope):
    """Match SOAR revision privacy, including fail-closed legacy endpoints."""
    if scope == ["*"]:
        return "1=1", []
    expression = (
        "coalesce((SELECT ps.indexes FROM soar_playbook_scopes ps "
        "WHERE ps.playbook_id=sr.playbook_id AND ps.version=sr.revision), "
        "CASE WHEN json_valid(sr.definition) THEN CASE "
        "WHEN json_type(sr.definition,'$.steps')='array' AND NOT EXISTS("
        "SELECT 1 FROM json_each(sr.definition,'$.steps') step "
        "WHERE json_extract(step.value,'$.action.type')='endpoint_response') "
        "THEN '[]' ELSE '[\"*\"]' END ELSE '[\"*\"]' END)"
    )
    constrained, args = _scope(scope, expression)
    # Generic books have an empty pinned scope and retain tenant visibility.
    return (
        (
            f"((CASE WHEN json_valid({expression}) THEN json_type({expression})='array' "
            f"AND json_array_length({expression})=0 ELSE 0 END) OR ({constrained}))"
        ),
        args,
    )


def _severity(expression):
    value = _json_value(expression, "$.severity")
    return f"CASE {value} WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 WHEN 'debug' THEN 1 ELSE 0 END"


def _level(number):
    return {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info"}.get(
        number, "unknown"
    )


def _groups(rows, key, fixed=()):
    result = dict.fromkeys(fixed, 0)
    for row in rows:
        result[row[key]] = row["count"]
    return result


def _telemetry(store, actor, start, end, width, budget):
    predicate, grants = index_predicate(actor["allowed_indexes"])
    where = f"tenant=? AND received>=? AND received<? AND ({predicate})"
    args = [actor["tenant"], start, end, *grants]
    size = "octet_length(encode(raw))+octet_length(encode(message))"

    def query(sql, extra=(), maximum=1):
        budget.remaining()
        return store.analytics_query(
            sql,
            [*args, *extra],
            cancel=budget.stopped,
            max_rows=maximum,
            timeout=budget.remaining(),
        )["rows"]

    totals = query(
        f"SELECT count(*) AS event_count,coalesce(sum({size}),0) AS stored_payload_bytes,"
        "count(DISTINCT source) AS source_count,count(DISTINCT sourcetype) AS sourcetype_count,"
        "count(DISTINCT (source,sourcetype)) AS source_pair_count,"
        "count(DISTINCT CASE WHEN host!='' AND host!='unknown' THEN host END) AS observed_host_count,"
        "min(received) AS first_received,max(received) AS last_received,max(event_time) AS last_event_time,"
        "quantile_cont(greatest(received-event_time,0),0.95) AS arrival_lag_p95_seconds,"
        "count(*) FILTER(WHERE event_time>received) AS future_timestamp_events "
        f"FROM events_all WHERE {where}"
    )[0]
    sources = query(
        "SELECT source,sourcetype,count(*) AS event_count,"
        f"sum({size}) AS stored_payload_bytes,min(received) AS first_received,"
        "max(received) AS last_received,max(event_time) AS last_event_time,"
        "quantile_cont(greatest(received-event_time,0),0.95) AS arrival_lag_p95_seconds "
        f"FROM events_all WHERE {where} GROUP BY source,sourcetype "
        f"ORDER BY event_count DESC,source,sourcetype LIMIT {SOURCE_LIMIT}",
        maximum=SOURCE_LIMIT,
    )
    series = store.analytics_query(
        "SELECT cast(floor((received-?)/?) AS INTEGER) AS bucket,count(*) AS event_count,"
        f"sum({size}) AS stored_payload_bytes FROM events_all WHERE {where} GROUP BY bucket ORDER BY bucket",
        [start, width, *args],
        cancel=budget.stopped,
        max_rows=BUCKETS,
        timeout=budget.remaining(),
    )["rows"]
    by_bucket = {r["bucket"]: r for r in series}
    totals.update(
        {
            "bytes_definition": "UTF-8 bytes in stored raw JSON plus stored message columns; not transport bytes or compressed disk size",
            "lag_definition": "max(received-event_time,0); future timestamps counted separately",
            "sources": sources,
            "source_rows_truncated": totals["source_pair_count"] > len(sources),
            "series": [
                {
                    "start": start + i * width,
                    "end": min(end, start + (i + 1) * width),
                    "event_count": by_bucket.get(i, {}).get("event_count", 0),
                    "stored_payload_bytes": by_bucket.get(i, {}).get(
                        "stored_payload_bytes", 0
                    ),
                }
                for i in range(BUCKETS)
            ],
        }
    )
    return totals


def _control(store, actor, start, end, now, width, budget):
    with store.control() as db:
        db.execute("PRAGMA busy_timeout=100")
        db.set_progress_handler(lambda: int(budget.stopped()), 1000)
        try:
            db.execute("BEGIN")
            if principal.current(db, actor) != actor:
                raise PermissionError("Permissions changed during console summary")

            def rows(sql, args=()):
                budget.remaining()
                return [dict(r) for r in db.execute(sql, args)]

            risk_scope, risk_args = _scope(actor["allowed_indexes"], "r.indexes")
            if actor["allowed_indexes"] == ["*"]:
                bookmark, bookmark_args = "1=1", []
            else:
                slots = ",".join("?" for _ in actor["allowed_indexes"]) or "NULL"
                bookmark = f"NOT EXISTS(SELECT 1 FROM case_bookmarks b WHERE b.tenant=i.tenant AND b.incident_id=i.id AND b.index_name NOT IN ({slots}))"
                bookmark_args = actor["allowed_indexes"]
            visible = (
                "WITH visible_incidents AS (SELECT i.* FROM incidents i WHERE i.tenant=? "
                "AND EXISTS(SELECT 1 FROM risk_contributions r WHERE r.tenant=i.tenant AND r.incident_id=i.id) "
                "AND NOT EXISTS(SELECT 1 FROM risk_contributions r WHERE r.tenant=i.tenant AND r.incident_id=i.id "
                f"AND NOT ({risk_scope})) AND ({bookmark})), "
                "cohort AS (SELECT i.*,coalesce(w.priority,'medium') AS priority,w.due_at,"
                "w.incident_id IS NOT NULL AS workspace_configured,"
                f"(SELECT max({_severity('r.evidence')}) FROM risk_contributions r "
                "WHERE r.tenant=i.tenant AND r.incident_id=i.id) AS severity_rank "
                "FROM visible_incidents i LEFT JOIN case_workspaces w ON w.tenant=i.tenant AND w.incident_id=i.id "
                "WHERE i.created>=? AND i.created<?) "
            )
            snapshot_scope, snapshot_args = _scope(
                actor["allowed_indexes"],
                _json_value("sr.snapshot", "$.evidence.indexes"),
            )
            playbook_scope, playbook_args = _playbook_scope(actor["allowed_indexes"])
            legacy_feedback = (
                "EXISTS(SELECT 1 FROM incident_feedback f WHERE f.tenant=c.tenant AND f.incident_id=c.id "
                "AND NOT EXISTS(SELECT 1 FROM case_action_receipts a WHERE a.tenant=f.tenant "
                "AND a.incident_id=f.incident_id AND a.at=f.at "
                f"AND {_json_value('a.result', '$.type')}='set_status' "
                f"AND {_json_value('a.result', '$.status')}=f.status))"
            )
            endpoint_scope, endpoint_args = _scope(
                actor["allowed_indexes"], "json_array(er.index_name)"
            )
            visible += (
                ", authorized_runs AS (SELECT sr.* FROM soar_runs sr JOIN cohort c ON c.tenant=sr.tenant AND c.id=sr.incident_id "
                f"WHERE ({snapshot_scope}) AND ({playbook_scope})), authorized_endpoint AS (SELECT er.* FROM endpoint_responses er "
                "JOIN cohort c ON c.tenant=er.tenant AND c.id=er.incident_id "
                f"WHERE ({endpoint_scope}) AND NOT EXISTS(SELECT 1 FROM endpoint_response_workflow ew "
                "WHERE ew.response_id=er.id AND NOT EXISTS(SELECT 1 FROM authorized_runs ar WHERE ar.id=ew.run_id))), modes AS (SELECT c.*,CASE "
                "WHEN EXISTS(SELECT 1 FROM authorized_runs s WHERE s.incident_id=c.id AND s.state IN ('queued','retry','sending','waiting')) THEN 'executing' "
                "WHEN EXISTS(SELECT 1 FROM authorized_runs s WHERE s.incident_id=c.id AND s.state='pending_approval') THEN 'awaiting_approval' "
                "WHEN EXISTS(SELECT 1 FROM authorized_runs s WHERE s.incident_id=c.id AND (s.state IN ('failed','unknown') OR (s.state='cancelled' AND EXISTS(SELECT 1 FROM soar_steps st WHERE st.run_id=s.id AND st.state='completed')))) THEN 'attention' "
                "WHEN EXISTS(SELECT 1 FROM authorized_endpoint er WHERE er.incident_id=c.id AND er.state IN ('failed','unknown')) THEN 'attention' "
                "WHEN EXISTS(SELECT 1 FROM authorized_runs s WHERE s.incident_id=c.id AND s.state='completed') THEN 'completed' "
                "WHEN EXISTS(SELECT 1 FROM case_action_receipts a WHERE a.tenant=c.tenant AND a.incident_id=c.id AND NOT EXISTS("
                "SELECT 1 FROM soar_runs s JOIN soar_steps st ON st.run_id=s.id WHERE s.tenant=a.tenant AND s.incident_id=a.incident_id AND a.action_key=s.id||':'||st.step_id)) "
                "OR EXISTS(SELECT 1 FROM authorized_endpoint er WHERE er.incident_id=c.id AND er.state IN ('queued','claimed','started','succeeded')) "
                f"OR ({legacy_feedback}) THEN 'manual' "
                "ELSE 'unhandled' END AS response_mode FROM cohort c) "
            )
            cohort_args = [
                actor["tenant"],
                *risk_args,
                *bookmark_args,
                start,
                end,
                *snapshot_args,
                *playbook_args,
                *endpoint_args,
            ]
            cohort_totals = rows(
                visible + "SELECT count(*) AS total,"
                "coalesce(sum(status IN ('new','triage')),0) AS open,"
                "coalesce(sum(status='resolved'),0) AS resolved,"
                "coalesce(sum(status='false_positive'),0) AS false_positive,"
                "coalesce(sum(due_at IS NOT NULL),0) AS sla_configured,"
                "coalesce(sum(due_at IS NOT NULL AND due_at<? AND status IN ('new','triage')),0) AS overdue "
                "FROM cohort",
                [*cohort_args, now],
            )[0]
            cases = {
                key: cohort_totals[key]
                for key in ("total", "open", "resolved", "false_positive")
            }
            cases["sla"] = {
                "configured": cohort_totals["sla_configured"],
                "overdue": cohort_totals["overdue"],
                "basis": "Explicit case due_at, overdue only for currently new/triage cases at generated_at",
            }
            cases["by_severity"] = dict.fromkeys(SEVERITIES, 0)
            for row in rows(
                visible
                + "SELECT severity_rank,count(*) AS count FROM cohort GROUP BY severity_rank",
                cohort_args,
            ):
                cases["by_severity"][_level(row["severity_rank"])] = row["count"]
            cases["by_priority"] = _groups(
                rows(
                    visible
                    + "SELECT priority,count(*) AS count FROM cohort GROUP BY priority",
                    cohort_args,
                ),
                "priority",
                ("critical", "high", "medium", "low"),
            )
            cases["recent"] = rows(
                visible
                + f"SELECT * FROM modes ORDER BY updated DESC,id LIMIT {TABLE_LIMIT}",
                cohort_args,
            )
            for item in cases["recent"]:
                item["severity"] = _level(item.pop("severity_rank"))
            cases["rows_truncated"] = cases["total"] > len(cases["recent"])
            series = rows(
                visible
                + "SELECT cast((created-?)/? AS INTEGER) AS bucket,count(*) AS count FROM cohort GROUP BY bucket",
                [*cohort_args, start, width],
            )
            per_bucket = {r["bucket"]: r["count"] for r in series}
            cases["series"] = [
                {
                    "start": start + i * width,
                    "end": min(end, start + (i + 1) * width),
                    "created": per_bucket.get(i, 0),
                }
                for i in range(BUCKETS)
            ]
            cases["cohort_definition"] = (
                "Incidents created in [start,end); current status, maximum recorded contribution severity across complete incident context"
            )
            cases["creation_origin"] = "correlation_policy"
            cases["response_modes"] = _groups(
                rows(
                    visible
                    + "SELECT response_mode,count(*) AS count FROM modes GROUP BY response_mode",
                    cohort_args,
                ),
                "response_mode",
                (
                    "executing",
                    "awaiting_approval",
                    "attention",
                    "completed",
                    "manual",
                    "unhandled",
                ),
            )
            cases["response_mode_definition"] = (
                "One category per case from all authorized recorded response history, precedence executing SOAR > awaiting_approval > attention (failed/unknown SOAR or endpoint response, or SOAR cancelled after a completed step) > completed SOAR run > manual local action receipt, queued/claimed/started/succeeded endpoint response or legacy analyst judgement > unhandled. Feedback paired with a set_status receipt at the same time/status is attributed through that receipt. Cancelled-only responses without an OS effect are unhandled. Manual endpoint requests are not automated SOAR actions. A completed workflow does not imply case resolution or endpoint containment."
            )

            cases["response_outcomes"] = rows(
                visible
                + "SELECT response_mode,status,count(*) AS count FROM modes GROUP BY response_mode,status ORDER BY response_mode,status",
                cohort_args,
            )
            finding_scope, finding_args = _scope(
                actor["allowed_indexes"], _json_value("f.evidence", "$.access_scope")
            )
            finding_rows = rows(
                f"SELECT f.status,count(*) AS count FROM findings f WHERE f.tenant=? AND f.created>=? AND f.created<? AND ({finding_scope}) GROUP BY f.status",
                [actor["tenant"], start, end, *finding_args],
            )
            evidence_rows = rows(
                visible
                + f"SELECT {_severity('r.evidence')} AS severity_rank,count(*) AS count "
                "FROM risk_contributions r JOIN visible_incidents i ON i.tenant=r.tenant AND i.id=r.incident_id "
                "WHERE r.at>=? AND r.at<? GROUP BY severity_rank",
                [*cohort_args, start, end],
            )
            evidence_by_severity = dict.fromkeys(SEVERITIES, 0)
            for row in evidence_rows:
                evidence_by_severity[_level(row["severity_rank"])] = row["count"]
            issues = {
                "saved_search_findings": {
                    "total": sum(r["count"] for r in finding_rows),
                    "by_status": _groups(
                        finding_rows,
                        "status",
                        ("new", "triage", "resolved", "false_positive"),
                    ),
                },
                "correlation_evidence": {
                    "total": sum(evidence_by_severity.values()),
                    "by_severity": evidence_by_severity,
                    "definition": "Persisted correlation risk contributions dated in [start,end), including resolved/false-positive history; not a decayed risk score or a unique incident count",
                },
                "combined_total": None,
                "definition": "Finding, correlation contribution and incident counts are separate populations and must not be added",
            }

            response_rows = rows(
                visible
                + ", linked AS (SELECT a.*,sr.id AS run_id,st.state AS step_state FROM case_action_receipts a "
                "JOIN cohort i ON i.tenant=a.tenant AND i.id=a.incident_id "
                "LEFT JOIN soar_runs sr ON sr.tenant=a.tenant AND sr.incident_id=a.incident_id AND EXISTS("
                "SELECT 1 FROM soar_steps x WHERE x.run_id=sr.id AND a.action_key=sr.id||':'||x.step_id) "
                "LEFT JOIN soar_steps st ON st.run_id=sr.id AND a.action_key=sr.id||':'||st.step_id "
                f"WHERE a.at>=? AND a.at<? AND (sr.id IS NULL OR (({snapshot_scope}) AND ({playbook_scope})))) "
                "SELECT CASE WHEN run_id IS NULL THEN 'manual' WHEN step_state='completed' THEN 'soar' ELSE 'unattributed' END AS origin,count(*) AS count FROM linked GROUP BY origin",
                [*cohort_args, start, end, *snapshot_args, *playbook_args],
            )
            cases["response_actions"] = {
                **_groups(response_rows, "origin", ("soar", "manual", "unattributed")),
                "definition": "Idempotent local action receipts in the selected window on the case cohort; SOAR requires a matching completed step, pending linked receipts are unattributed. These are action counts, not case counts.",
            }
            endpoint_counts = _groups(
                rows(visible + "SELECT state,count(*) AS count FROM authorized_endpoint "
                     "WHERE created>=? AND created<? GROUP BY state", [*cohort_args, start, end]),
                "state", ("queued", "claimed", "started", "succeeded", "failed", "unknown", "expired", "cancelled"),
            )
            effects = rows(
                visible + "SELECT coalesce(sum(state='succeeded' AND (CASE WHEN json_valid(result) THEN json_type(result,'$.success') END)='true' AND (CASE WHEN json_valid(result) THEN json_type(result,'$.executed') END)='true' AND (CASE WHEN json_valid(action) THEN json_extract(action,'$.type') END) IN ('terminate_process','delete_file','quarantine_file','restore_file','isolate_host','release_host')),0) AS mutations, "
                "coalesce(sum(state='succeeded' AND (CASE WHEN json_valid(result) THEN json_type(result,'$.success') END)='true' AND (CASE WHEN json_valid(result) THEN json_type(result,'$.executed') END)='false' AND (CASE WHEN json_valid(action) THEN json_extract(action,'$.type') END) IN ('inspect_process','inspect_file','collect_artifact')),0) AS read_only "
                "FROM authorized_endpoint WHERE created>=? AND created<?", [*cohort_args,start,end],
            )[0]
            cases["endpoint_responses"] = {
                "by_state": endpoint_counts,
                "requested": sum(endpoint_counts.values()),
                "confirmed_effects": effects["mutations"],
                "read_only_completed": effects["read_only"],
                "definition": "Evidence-bound manual/SOAR commands created in the selected window on the visible case cohort. Confirmed effects require succeeded plus a boolean successful executed=true receipt; read-only completions are separate. The authenticated agent report is not independent host attestation, persistent prevention or case resolution. Counts are separate from local/SOAR action receipts.",
            }

            entity_scope, entity_args = _scope(actor["allowed_indexes"], "e.indexes")
            inventory = rows(
                f"SELECT kind,count(*) AS count FROM entity_inventory e WHERE e.tenant=? AND ({entity_scope}) GROUP BY kind",
                [actor["tenant"], *entity_args],
            )
            assets = {
                "explicit_inventory": {
                    "total": sum(r["count"] for r in inventory),
                    "by_kind": _groups(
                        inventory, "kind", ("host", "device", "user", "ip")
                    ),
                },
                "definition": "Explicit registered entities are current inventory; observed host strings are measured telemetry, with no inferred alias merge or endpoint protection state",
            }

            monitor_scope, monitor_args = _scope(
                actor["allowed_indexes"], _json_value("m.definition", "$.indexes")
            )
            monitor_where = f"m.tenant=? AND ({monitor_scope})"
            status = f"CASE WHEN m.enabled=0 THEN 'disabled' WHEN m.result IS NULL THEN 'not_evaluated' WHEN {_json_value('m.result', '$.status')} IN ('healthy','degraded') THEN {_json_value('m.result', '$.status')} ELSE 'unknown' END"
            monitor_totals = rows(
                f"SELECT {status} AS status,count(*) AS count FROM source_monitors m WHERE {monitor_where} GROUP BY status",
                [actor["tenant"], *monitor_args],
            )
            monitors = rows(
                f"SELECT m.id,m.name,m.enabled,m.last_run,{status} AS status,"
                f"{_json_value('m.definition', '$.source')} AS source,"
                f"{_json_value('m.result', '$.last_seen')} AS last_seen,"
                f"{_json_value('m.result', '$.silence_seconds')} AS silence_seconds "
                f"FROM source_monitors m WHERE {monitor_where} ORDER BY m.name,m.id LIMIT {TABLE_LIMIT}",
                [actor["tenant"], *monitor_args],
            )
            integrations = {
                "configured_source_monitors": sum(r["count"] for r in monitor_totals),
                "monitor_statuses": _groups(
                    monitor_totals,
                    "status",
                    ("healthy", "degraded", "not_evaluated", "disabled", "unknown"),
                ),
                "monitors": monitors,
                "monitor_rows_truncated": sum(r["count"] for r in monitor_totals)
                > len(monitors),
                "definition": "Configured silence/lag/field-presence monitors and observed event sources; a source name is not proof of a vendor connector or XDR enrollment",
            }
            budget.remaining()
            return issues, cases, assets, integrations
        except sqlite3.OperationalError as exc:
            if "interrupted" in str(exc).lower() or "locked" in str(exc).lower():
                raise CapacityError(
                    "Console control query deadline/capacity exceeded; retry or narrow the window"
                ) from None
            raise
        finally:
            db.set_progress_handler(None, 0)


def summary(store, who, start=None, end=None, *, cancel=None, _deadline=None):
    budget = _Budget(cancel, _deadline)
    now = time.time()
    start, end = _window(start, end, now)
    width = (end - start) / BUCKETS
    budget.remaining()
    with store.control() as db:
        actor = principal.current(db, who)
    telemetry = _telemetry(store, actor, start, end, width, budget)
    principal.recheck(store, actor)
    issues, cases, assets, integrations = _control(
        store, actor, start, end, now, width, budget
    )
    principal.recheck(store, actor)
    budget.remaining()
    assets["observed_hosts"] = telemetry["observed_host_count"]
    integrations["observed_sources"] = telemetry["source_count"]
    return {
        "schema": "sapientia.console.v1",
        "generated_at": now,
        "window": {
            "start": start,
            "end": end,
            "bucket_seconds": width,
            "timezone": "UTC",
            "telemetry_time_basis": "received",
        },
        "telemetry": telemetry,
        "issues": issues,
        "cases": cases,
        "assets": assets,
        "integrations": integrations,
        "consistency": "Analytical telemetry and transactional operational state use separate read snapshots; each projection uses complete current tenant/index authorization",
        "limits": {
            "deadline_seconds": SECONDS,
            "case_rows": TABLE_LIMIT,
            "source_rows": SOURCE_LIMIT,
            "buckets": BUCKETS,
            "population_aggregates_truncated": False,
        },
    }
