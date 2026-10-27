"""Server-clock evidence for provider -> index -> case -> confirmed effect SLOs.

Instrumentation is bounded and never prevents log admission at its own quota.
Coverage loss is explicit. Percentiles are exact nearest-rank statistics for the
reported authorized cohort, not extrapolated enterprise guarantees. Provider
time is an untrusted source clock and negative deltas are counted separately.
"""

import json
import math
import time

from . import access, principal
from . import evidence_scope as evidence
from .query import index_predicate
from .storage import CapacityError, encode

MAX_EVENT_CLOCKS = None
MAX_CASE_LINKS = None
MAX_COHORT = 50000
READ_ONLY = {"inspect_process", "inspect_file", "collect_artifact"}


def initialize(store):
    with store.control(local=True) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS pipeline_event_clocks(
          tenant TEXT NOT NULL,event_id TEXT NOT NULL,index_name TEXT NOT NULL,
          provider TEXT NOT NULL,provider_time REAL NOT NULL,received REAL NOT NULL,
          indexed REAL NOT NULL,receipt_digest TEXT NOT NULL,
          PRIMARY KEY(tenant,event_id));
        CREATE INDEX IF NOT EXISTS pipeline_clock_cohort ON
          pipeline_event_clocks(tenant,received,event_id);
        CREATE TABLE IF NOT EXISTS pipeline_case_clocks(
          tenant TEXT NOT NULL,event_id TEXT NOT NULL,incident_id TEXT NOT NULL,
          policy_id TEXT NOT NULL,indexes TEXT NOT NULL,emitted REAL NOT NULL,
          PRIMARY KEY(tenant,event_id,incident_id,policy_id));
        CREATE INDEX IF NOT EXISTS pipeline_case_emission ON
          pipeline_case_clocks(tenant,incident_id,emitted);
        CREATE TABLE IF NOT EXISTS pipeline_clock_gaps(
          tenant TEXT NOT NULL,index_name TEXT NOT NULL,provider TEXT NOT NULL,
          day INTEGER NOT NULL,stage TEXT NOT NULL,count INTEGER NOT NULL,
          PRIMARY KEY(tenant,index_name,provider,day,stage));
        """)


def _gap(db, tenant, index, provider, received, stage):
    day = int(received // 86400) * 86400
    db.execute(
        "INSERT INTO pipeline_clock_gaps VALUES(?,?,?,?,?,1) ON CONFLICT(tenant,index_name,provider,day,stage) DO UPDATE SET count=count+1",
        (tenant, index, provider, day, stage),
    )


def journal_indexed(store, db, indexed_rows, *, at=None):
    """Call at the existing durable source-ACK transaction, before commit.

    The timestamp is when the source becomes indexed in this transaction, not
    index-drain completion, source event time or the interactive query clock.
    """
    at = time.time() if at is None else evidence.number(at, "indexed timestamp")
    counts = {}
    recorded, gaps = 0, 0
    for item in indexed_rows:
        tenant, event_id = item["tenant"], item["event_id"]
        payload = (
            json.loads(item["payload"])
            if isinstance(item["payload"], str)
            else item["payload"]
        )
        index = payload.get("index", payload.get("index_name", "main"))
        provider = payload.get("source", "unknown")
        received = evidence.number(item["received"], "received")
        provider_time = evidence.number(payload.get("event_time"), "provider time")
        proof = db.execute(
            "SELECT digest,received FROM receipts WHERE tenant=? AND event_id=?",
            (tenant, event_id),
        ).fetchone()
        if not proof or proof["received"] != received or at < received:
            _gap(db, tenant, index, provider, received, "invalid_admission_clock")
            gaps += 1
            continue
        if db.execute(
            "SELECT 1 FROM pipeline_event_clocks WHERE tenant=? AND event_id=?",
            (tenant, event_id),
        ).fetchone():
            continue
        if tenant not in counts:
            counts[tenant] = db.execute(
                "SELECT count(*) FROM pipeline_event_clocks WHERE tenant=?", (tenant,)
            ).fetchone()[0]
        # Store every valid clock/link; no lifetime instrumentation quota.
        db.execute(
            "INSERT INTO pipeline_event_clocks VALUES(?,?,?,?,?,?,?,?)",
            (
                tenant,
                event_id,
                index,
                provider,
                provider_time,
                received,
                at,
                proof["digest"],
            ),
        )
        counts[tenant] += 1
        recorded += 1
    return {"recorded": recorded, "coverage_gaps": gaps, "admission_blocked": False}


def journal_case(
    store, db, tenant, incident_id, policy_id, event_ids, indexes, *, at=None
):
    """Engine-only: call after the actual contribution insert, same transaction."""
    at = time.time() if at is None else evidence.number(at, "emission timestamp")
    scope = access.validate(indexes)
    if not scope:
        raise ValueError("Case clocks require the complete nonempty evidence basis")
    if not isinstance(event_ids, list) or len(event_ids) > 10000:
        raise ValueError("Bounded server-derived source event IDs are required")
    count = db.execute(
        "SELECT count(*) FROM pipeline_case_clocks WHERE tenant=?", (tenant,)
    ).fetchone()[0]
    recorded, gaps = 0, 0
    for event_id in sorted(set(event_ids)):
        clock = db.execute(
            "SELECT * FROM pipeline_event_clocks WHERE tenant=? AND event_id=?",
            (tenant, event_id),
        ).fetchone()
        if not clock:
            # Absence may predate instrumentation; never invent an index clock.
            gaps += 1
            continue
        if (
            not principal.contains(scope, [clock["index_name"]])
            or at < clock["indexed"]
        ):
            _gap(
                db,
                tenant,
                clock["index_name"],
                clock["provider"],
                clock["received"],
                "invalid_case_clock",
            )
            gaps += 1
            continue
        if db.execute(
            "SELECT 1 FROM pipeline_case_clocks WHERE tenant=? AND event_id=? AND incident_id=? AND policy_id=?",
            (tenant, event_id, incident_id, policy_id),
        ).fetchone():
            continue
        # Store every valid clock/link; no lifetime instrumentation quota.
        db.execute(
            "INSERT INTO pipeline_case_clocks VALUES(?,?,?,?,?,?)",
            (tenant, event_id, incident_id, policy_id, encode(scope), at),
        )
        count += 1
        recorded += 1
    return {"recorded": recorded, "coverage_gaps": gaps}


def percentiles(values):
    values = sorted(
        evidence.number(item, "duration", 0, 253402300799) for item in values
    )

    def percentile(q):
        return values[max(0, math.ceil(q * len(values)) - 1)] if values else None

    return {
        "count": len(values),
        "p50_seconds": percentile(0.50),
        "p95_seconds": percentile(0.95),
        "p99_seconds": percentile(0.99),
        "max_seconds": values[-1] if values else None,
        "method": "exact nearest rank; no samples => null",
    }


def snapshot(store, who, start, end):
    start, end = evidence.number(start, "start"), evidence.number(end, "end")
    if not start < end or end - start > 31 * 86400:
        raise ValueError("SLO cohort window must be positive and at most 31 days")
    with principal.transaction(store, who) as (_, actor):
        pass
    predicate, scope_args = index_predicate(actor["allowed_indexes"])
    expected_indexed = store.analytics_query(
        "SELECT count(*) AS total FROM events_all WHERE tenant=? AND received>=? AND received<? AND "
        + predicate,
        [actor["tenant"], start, end, *scope_args],
        timeout=min(5, store.settings.query_timeout),
        max_rows=1,
    )["rows"][0]["total"]
    inspected_actor = actor
    with principal.transaction(store, who) as (db, actor):
        if actor != inspected_actor:
            raise PermissionError("Permissions changed during cohort inspection")
        rows = db.execute(
            "SELECT * FROM pipeline_event_clocks WHERE tenant=? AND received>=? AND received<? ORDER BY received,event_id",
            (actor["tenant"], start, end),
        ).fetchall()
        rows = [
            dict(row)
            for row in rows
            if principal.contains(actor["allowed_indexes"], [row["index_name"]])
        ]
        if len(rows) > MAX_COHORT:
            raise CapacityError(
                "SLO cohort exceeds 50,000 visible events; narrow its window"
            )
        gaps = db.execute(
            "SELECT * FROM pipeline_clock_gaps WHERE tenant=? AND day>=? AND day<=? ORDER BY day,index_name,stage LIMIT 10001",
            (actor["tenant"], int(start // 86400) * 86400, int(end // 86400) * 86400),
        ).fetchall()
        if len(gaps) > 10000:
            raise CapacityError("SLO coverage gap bound exceeded")
        gaps = [
            dict(row)
            for row in gaps
            if principal.contains(actor["allowed_indexes"], [row["index_name"]])
        ]
        stages = {
            key: []
            for key in (
                "provider_to_received",
                "received_to_indexed",
                "indexed_to_case",
                "case_to_effect",
                "received_to_effect",
            )
        }
        clock_skew, case_events = 0, 0
        missing_case_clock, confirmed, read_only, pending, failed = 0, 0, 0, 0, 0
        provider_counts = {}
        earliest_cases = {}
        event_clocks = {row["event_id"]: row for row in rows}
        queued = db.execute(
            "SELECT payload FROM queue WHERE tenant=? AND received>=? AND received<? LIMIT 100001",
            (actor["tenant"], start, end),
        ).fetchall()
        if len(queued) > 100000:
            raise CapacityError("SLO queued cohort bound exceeded")
        queue_pending = sum(
            principal.contains(
                actor["allowed_indexes"],
                [json.loads(row["payload"]).get("index", "main")],
            )
            for row in queued
        )
        for row in rows:
            provider_counts[row["provider"]] = (
                provider_counts.get(row["provider"], 0) + 1
            )
            if row["provider_time"] > row["received"]:
                clock_skew += 1
            else:
                stages["provider_to_received"].append(
                    row["received"] - row["provider_time"]
                )
            stages["received_to_indexed"].append(row["indexed"] - row["received"])
        if event_clocks:
            links = db.execute(
                "SELECT * FROM pipeline_case_clocks WHERE tenant=? AND event_id IN (SELECT value FROM json_each(?)) ORDER BY emitted,incident_id,event_id",
                (actor["tenant"], encode(sorted(event_clocks))),
            ).fetchall()
            # Store every valid clock/link; no lifetime instrumentation quota.
            visible_cases, visible_events = set(), set()
            for link in links:
                if not principal.contains(
                    actor["allowed_indexes"], json.loads(link["indexes"])
                ):
                    continue
                try:
                    principal.incident(db, actor, link["incident_id"])
                except KeyError:
                    continue
                visible_cases.add(link["incident_id"])
                if link["event_id"] not in visible_events:
                    stages["indexed_to_case"].append(
                        link["emitted"] - event_clocks[link["event_id"]]["indexed"]
                    )
                    visible_events.add(link["event_id"])
                earliest_cases[link["incident_id"]] = min(
                    earliest_cases.get(link["incident_id"], link["emitted"]),
                    link["emitted"],
                )
            case_events = len(visible_events)
            if visible_cases:
                responses = db.execute(
                    "SELECT * FROM endpoint_responses WHERE tenant=? AND incident_id IN (SELECT value FROM json_each(?)) ORDER BY created,id LIMIT 10001",
                    (actor["tenant"], encode(sorted(visible_cases))),
                ).fetchall()
                if len(responses) > 10000:
                    raise CapacityError("SLO response bound exceeded")
                for response in responses:
                    if not principal.contains(
                        actor["allowed_indexes"], json.loads(response["scope"])
                    ) or not principal.contains(
                        actor["allowed_indexes"], [response["index_name"]]
                    ):
                        continue
                    action = json.loads(response["action"])
                    result = (
                        json.loads(response["result"]) if response["result"] else {}
                    )
                    if response["state"] in {"queued", "claimed", "started"}:
                        pending += 1
                        continue
                    if response["state"] != "succeeded":
                        failed += 1
                        continue
                    if action.get("type") in READ_ONLY:
                        read_only += 1
                        continue
                    if (
                        result.get("success") is not True
                        or result.get("executed") is not True
                        or response["finished"] is None
                    ):
                        failed += 1
                        continue
                    emitted = earliest_cases[response["incident_id"]]
                    clock = event_clocks.get(response["evidence_event_id"])
                    if response["finished"] < emitted:
                        missing_case_clock += 1
                        continue
                    confirmed += 1
                    stages["case_to_effect"].append(response["finished"] - emitted)
                    if clock and response["finished"] >= clock["received"]:
                        stages["received_to_effect"].append(
                            response["finished"] - clock["received"]
                        )
        return {
            "schema": "xsera.pipeline-slo.v1",
            "start": start,
            "end": end,
            "cohort_basis": "server admission received time [start,end), current complete tenant/index authorization",
            "event_count": len(rows),
            "expected_indexed_events": expected_indexed,
            "missing_index_clocks": max(0, expected_indexed - len(rows)),
            "pending_index_events": queue_pending,
            "providers": provider_counts,
            "stages": {key: percentiles(value) for key, value in stages.items()},
            "case_linked_events": case_events,
            "unlinked_events": len(rows) - case_events,
            "confirmed_effects": confirmed,
            "read_only_completed": read_only,
            "pending_responses": pending,
            "failed_or_unconfirmed_responses": failed,
            "provider_clock_skew_events": clock_skew,
            "invalid_effect_clock": missing_case_clock,
            "coverage_gaps": gaps,
            "coverage_complete": not gaps
            and expected_indexed == len(rows)
            and queue_pending == 0,
            "limits": {
                "max_event_clocks_per_tenant": MAX_EVENT_CLOCKS,
                "max_visible_cohort": MAX_COHORT,
                "max_case_links_per_tenant": MAX_CASE_LINKS,
            },
            "meaning": "Observed bounded cohort latency; no enterprise certification or hardware effect attestation. Unlinked events may be benign, not a measured detection failure.",
        }


def prune(store, who, before):
    raise PermissionError("Permanent recording forbids deleting investigation history")
    before = evidence.number(before, "before", 0, time.time() - 86400)
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        if actor["allowed_indexes"] != ["*"]:
            raise PermissionError(
                "SLO clock retention requires unrestricted tenant scope"
            )
        removed = db.execute(
            "DELETE FROM pipeline_event_clocks WHERE tenant=? AND received<?",
            (actor["tenant"], before),
        ).rowcount
        links = db.execute(
            "DELETE FROM pipeline_case_clocks WHERE tenant=? AND event_id NOT IN (SELECT event_id FROM pipeline_event_clocks WHERE tenant=?)",
            (actor["tenant"], actor["tenant"]),
        ).rowcount
        gaps = db.execute(
            "DELETE FROM pipeline_clock_gaps WHERE tenant=? AND day<?",
            (actor["tenant"], int(before // 86400) * 86400),
        ).rowcount
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "pipeline.slo.prune",
            {
                "before": before,
                "event_clocks": removed,
                "case_links": links,
                "gap_days": gaps,
            },
        )
        return {
            "event_clocks": removed,
            "case_links": links,
            "gap_days": gaps,
            "logs_deleted": False,
        }
