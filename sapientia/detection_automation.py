"""Explicit scheduled statistical/IOC analysis and durable event-time recovery.

No learned threat probability, autonomous response, or external feed download.
Late ranges are local analytic ACK metadata; configured schedules are tenant data.
"""

import hashlib
import json
import math
import re
import time
import uuid
from collections import defaultdict

from . import detections, principal
from .query import column, index_predicate
from .storage import CapacityError, ConflictError, encode

EDIT = ("admin", "analyst")
CONTEXT_FIELDS = [
    "raw.xdr.data.process.guid",
    "raw.xdr.data.process.executable",
    "raw.xdr.data.process.command_line",
    "raw.xdr.data.process.hash.sha256",
    "raw.xdr.data.process.code_signature.subject_name",
    "raw.xdr.data.process.code_signature.trusted",
    "raw.xdr.data.process.parent.guid",
    "raw.xdr.data.user.name",
    "raw.xdr.data.session.id",
    "raw.security.process",
    "raw.security.user",
    "raw.security.process_guid",
    "raw.security.session_id",
    "raw.xdr.data.event.timestamp_precision_seconds",
    "raw.xdr.data.event.clock_quality",
    "raw.xdr.data.event.sequence",
    "raw.xdr.data.host.boot_id",
]


def _original_context(row):
    raw = row.get("raw", {})
    if isinstance(raw, str):
        raw = json.loads(raw)
    result = {}
    for field in CONTEXT_FIELDS:
        value = row.get(field)
        if field not in row:
            value = raw
            for part in field.split(".")[1:]:
                value = value.get(part) if isinstance(value, dict) else None
        if value is None or type(value) in (str, int, float, bool):
            result[field] = value
    return result


def initialize(store):
    with store.control(local=True) as db:
        from . import analysis_history

        analysis_history.initialize(db)
        db.executescript("""
        CREATE TABLE IF NOT EXISTS log_correlation_late_ranges(
          policy_id TEXT NOT NULL,version INTEGER NOT NULL,tenant TEXT NOT NULL,
          first_end REAL NOT NULL,last_end REAL NOT NULL,cursor REAL NOT NULL,
          revision INTEGER NOT NULL DEFAULT 1,retry_at REAL NOT NULL DEFAULT 0,
          failures INTEGER NOT NULL DEFAULT 0,error TEXT,PRIMARY KEY(policy_id,version));
        CREATE INDEX IF NOT EXISTS log_correlation_late_due ON log_correlation_late_ranges(retry_at,tenant,cursor);
        CREATE TABLE IF NOT EXISTS analysis_schedules(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,name TEXT NOT NULL,
          kind TEXT NOT NULL,definition TEXT NOT NULL,enabled INTEGER NOT NULL,
          next_run REAL NOT NULL,version INTEGER NOT NULL DEFAULT 1,
          last_end REAL,retry_at REAL NOT NULL DEFAULT 0,failures INTEGER NOT NULL DEFAULT 0,error TEXT);
        CREATE INDEX IF NOT EXISTS analysis_schedule_due ON analysis_schedules(enabled,retry_at,next_run);
        CREATE TABLE IF NOT EXISTS analysis_schedule_runs(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,schedule_id TEXT NOT NULL,
          window_end REAL NOT NULL,definition_digest TEXT NOT NULL,result TEXT NOT NULL,created REAL NOT NULL,
          UNIQUE(schedule_id,window_end,definition_digest));
        CREATE TABLE IF NOT EXISTS analysis_late_ranges(
          kind TEXT NOT NULL,source_id TEXT NOT NULL,definition_digest TEXT NOT NULL,
          tenant TEXT NOT NULL,first_end REAL NOT NULL,last_end REAL NOT NULL,cursor REAL NOT NULL,
          revision INTEGER NOT NULL DEFAULT 1,retry_at REAL NOT NULL DEFAULT 0,
          failures INTEGER NOT NULL DEFAULT 0,error TEXT,
          PRIMARY KEY(kind,source_id,definition_digest));
        CREATE INDEX IF NOT EXISTS analysis_late_due ON analysis_late_ranges(retry_at,tenant,cursor);
        CREATE TABLE IF NOT EXISTS rule_late_options(rule_id TEXT PRIMARY KEY,horizon INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS analysis_window_inputs(
          kind TEXT NOT NULL,source_id TEXT NOT NULL,definition_digest TEXT NOT NULL,
          tenant TEXT NOT NULL,window_start REAL NOT NULL,window_end REAL NOT NULL,
          scope TEXT NOT NULL,generation INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY(kind,source_id,definition_digest,window_end));
        CREATE TABLE IF NOT EXISTS analysis_partition_progress(
          kind TEXT NOT NULL,source_id TEXT NOT NULL,definition_digest TEXT NOT NULL,
          window_end REAL NOT NULL,generation INTEGER NOT NULL,cursor TEXT,
          summary TEXT NOT NULL,PRIMARY KEY(kind,source_id,definition_digest,window_end));
        """)


def validate_case_adapter(data):
    if data is None:
        return None
    if not isinstance(data, dict) or set(data) - {
        "entity_field",
        "risk_score",
        "severity",
        "mitre",
        "cooldown",
        "name",
        "case_grouping",
    }:
        raise ValueError("Case adapter requires an explicit entity/priority policy")
    policy = detections.validate(
        {
            **data,
            "name": data.get("name", "Analysis evidence"),
            "steps": [{"filters": []}],
            "enabled": False,
        }
    )
    result = {
        key: policy[key]
        for key in (
            "name",
            "entity_field",
            "risk_score",
            "severity",
            "mitre",
            "cooldown",
        )
    }
    if "case_grouping" in policy:
        result["case_grouping"] = policy["case_grouping"]
    return result


def emit_rows(
    db,
    store,
    actor,
    source_id,
    adapter,
    rows,
    at,
    mode,
    *,
    extra=None,
    basis_indexes=None,
):
    """Emit only original, currently authorized event identities. Caller owns TX."""
    adapter = validate_case_adapter(adapter)
    if adapter is None:
        return {"emitted": 0, "disabled": True}
    actor = principal.current(db, actor, EDIT)
    if basis_indexes is not None and not principal.contains(
        actor["allowed_indexes"], basis_indexes
    ):
        raise PermissionError("Case analysis basis scope is unavailable")
    groups = defaultdict(list)
    if not isinstance(rows, list) or len(rows) > 1000:
        raise CapacityError("Case adapter evidence bound is 1000 original event rows")
    for row in rows:
        entity = row.get(adapter["entity_field"])
        index = row.get("index_name", row.get("index"))
        if (
            not isinstance(entity, str)
            or not 1 <= len(entity) <= 256
            or not isinstance(row.get("event_id"), str)
            or not row["event_id"]
            or type(row.get("event_time")) not in (int, float)
            or not math.isfinite(row["event_time"])
            or not isinstance(index, str)
        ):
            raise ValueError(
                "Case adapter requires original event_id/event_time/index and a string entity"
            )
        if not principal.contains(actor["allowed_indexes"], [index]):
            raise PermissionError("Case adapter event index is unavailable")
        original_event = {
            **_original_context(row),
            **{
                key: row.get(key, "")
                for key in (
                    "event_id",
                    "event_time",
                    "received",
                    "host",
                    "source",
                    "severity",
                )
            },
            "index": index,
            adapter["entity_field"]: entity,
        }
        episode = detections._episode(
            {
                "entity": entity,
                "entity_field": adapter["entity_field"],
                "steps": [{"events": [original_event]}],
            }
        )
        groups[(entity, episode["key"])].append(original_event)
    matches = []
    for (entity, _episode_key), events in sorted(groups.items()):
        unique = {row["event_id"]: row for row in events}
        events = sorted(
            unique.values(), key=lambda row: (row["event_time"], row["event_id"])
        )
        analysis = dict(extra or {})
        if "ioc_matches" in analysis:
            analysis["ioc_matches"] = [
                item for item in analysis["ioc_matches"] if item["event_id"] in unique
            ]
        if "baseline_anomalies" in analysis:
            analysis["baseline_anomalies"] = [
                item
                for item in analysis["baseline_anomalies"]
                if any(event["event_id"] in unique for event in item["evidence"])
            ]
        indexes = sorted({row["index"] for row in events} | set(basis_indexes or []))
        if basis_indexes == ["*"]:
            indexes = ["*"]
        match = {
            "entity": entity,
            "entity_field": adapter["entity_field"],
            "steps": [{"step": mode, "matched": len(events), "events": events}],
            "event_ids": sorted(unique),
            "indexes": indexes,
            "window_start": min(row["event_time"] for row in events),
            "window_end": at,
            "risk_weight": adapter["risk_score"],
            "severity": adapter["severity"],
            "mitre": adapter["mitre"],
            "explanation": "Explicit opt-in "
            + mode
            + " adapter; configured priority, original evidence identities.",
            "analysis": analysis,
        }
        if len(encode(match).encode()) > detections.MAX_EVIDENCE_BYTES:
            raise CapacityError("Case adapter evidence exceeds 512 KiB")
        matches.append(match)
    if len(encode(matches).encode()) > detections.MAX_RESPONSE_BYTES:
        raise CapacityError("Case adapter batch exceeds 2 MiB")
    policy = {
        "id": source_id,
        "tenant": actor["tenant"],
        "name": adapter["name"],
        "version": 1,
    }
    if source_id.startswith("analysis:"):
        current=db.execute("SELECT version FROM analysis_schedules WHERE tenant=? AND id=?",(actor["tenant"],source_id.split(":",1)[1])).fetchone()
        if current:
            policy["version"]=current["version"]
    definition = {**adapter, "evaluation_delay": 0}
    return detections._emit_matches(
        db,
        store,
        policy,
        definition,
        matches,
        at,
        mode=mode,
        scheduled_end=at,
        actor=actor["name"],
        guard=actor,
    )


def journal_indexed(store, db, rows):
    """Coalesce affected successful windows atomically with source queue ACK.

    Constant one range/policy/version, at most 200 policies per tenant. Positive
    late_recovery limits retrospectivity; outside that configured horizon is
    explicitly not automatically recovered. No source/cache query or new lock.
    """
    by_tenant = defaultdict(list)
    for row in rows:
        event = json.loads(row["payload"])
        by_tenant[row["tenant"]].append(event["event_time"])
    for tenant, times in by_tenant.items():
        for active in db.execute(
            "SELECT * FROM analysis_window_inputs WHERE tenant=?", (tenant,)
        ).fetchall():
            if any(active["window_start"] <= at < active["window_end"] for at in times):
                db.execute(
                    "UPDATE analysis_window_inputs SET generation=generation+1 WHERE kind=? AND source_id=? AND definition_digest=? AND window_end=?",
                    (
                        active["kind"],
                        active["source_id"],
                        active["definition_digest"],
                        active["window_end"],
                    ),
                )
        for progress in db.execute(
            "SELECT policy_id,version,data_end,window_start FROM correlation_window_progress WHERE tenant=?",
            (tenant,),
        ).fetchall():
            if any(
                progress["window_start"] <= at < progress["data_end"] for at in times
            ):
                db.execute(
                    "UPDATE correlation_window_progress SET entity_after=NULL,terminal_after=NULL,revision=revision+1 "
                    "WHERE policy_id=? AND version=? AND data_end=?",
                    (progress["policy_id"], progress["version"], progress["data_end"]),
                )
        for policy in db.execute(
            "SELECT id,version,definition,last_end FROM correlation_policies WHERE tenant=? AND enabled=1 AND last_end IS NOT NULL",
            (tenant,),
        ):
            definition = json.loads(policy["definition"])
            horizon = definition.get("late_recovery", 900)
            if not horizon:
                continue
            anchor, interval = policy["last_end"], definition["interval"]
            first, last = None, None
            for at in times:
                if at >= anchor or at + definition["window"] < anchor - horizon:
                    continue
                low = max(anchor - horizon, at)
                # Completed intervals are anchored to the policy's actual cursor,
                # not epoch boundaries; latest is exclusive and earliest inclusive.
                start = anchor - math.floor((anchor - low) / interval) * interval
                if start <= at:
                    start += interval
                finish = (
                    anchor
                    - math.ceil(
                        (anchor - min(anchor, at + definition["window"])) / interval
                    )
                    * interval
                )
                if start <= finish and start > 0:
                    first = start if first is None else min(first, start)
                    last = finish if last is None else max(last, finish)
            if first is not None:
                db.execute(
                    """INSERT INTO log_correlation_late_ranges(policy_id,version,tenant,first_end,last_end,cursor) VALUES(?,?,?,?,?,?)
                  ON CONFLICT(policy_id,version) DO UPDATE SET first_end=min(first_end,excluded.first_end),last_end=max(last_end,excluded.last_end),cursor=min(cursor,excluded.cursor),revision=revision+1,retry_at=0""",
                    (policy["id"], policy["version"], tenant, first, last, first),
                )
        for kind, records in (
            (
                "schedule",
                db.execute(
                    "SELECT * FROM analysis_schedules WHERE tenant=? AND enabled=1 AND last_end IS NOT NULL",
                    (tenant,),
                ).fetchall(),
            ),
            (
                "saved_search",
                db.execute(
                    "SELECT * FROM rules WHERE tenant=? AND enabled=1 AND last_end IS NOT NULL",
                    (tenant,),
                ).fetchall(),
            ),
        ):
            for record in records:
                if kind == "schedule":
                    definition = json.loads(record["definition"])
                    width, interval, horizon = (
                        definition["lookback"],
                        definition["interval"],
                        definition.get("late_recovery", 900),
                    )
                else:
                    width, interval = record["lookback"], record["interval"]
                    option = db.execute(
                        "SELECT horizon FROM rule_late_options WHERE rule_id=?",
                        (record["id"],),
                    ).fetchone()
                    horizon = option[0] if option else 900
                if not horizon:
                    continue
                first, last = _affected_ends(
                    times, record["last_end"], width, interval, horizon
                )
                if first is not None:
                    digest = late_definition_digest(kind, record)
                    db.execute(
                        "INSERT INTO analysis_late_ranges(kind,source_id,definition_digest,tenant,first_end,last_end,cursor) VALUES(?,?,?,?,?,?,?) "
                        "ON CONFLICT(kind,source_id,definition_digest) DO UPDATE SET first_end=min(first_end,excluded.first_end),last_end=max(last_end,excluded.last_end),cursor=min(cursor,excluded.cursor),revision=revision+1,retry_at=0",
                        (kind, record["id"], digest, tenant, first, last, first),
                    )


def _affected_ends(times, anchor, width, interval, horizon):
    first, last = None, None
    for at in times:
        if at >= anchor or at + width < anchor - horizon:
            continue
        low = max(anchor - horizon, at)
        start = anchor - math.floor((anchor - low) / interval) * interval
        if start <= at:
            start += interval
        finish = (
            anchor - math.ceil((anchor - min(anchor, at + width)) / interval) * interval
        )
        if start <= finish and start > 0:
            first = start if first is None else min(first, start)
            last = finish if last is None else max(last, finish)
    return first, last


def late_definition_digest(kind, record):
    if kind == "schedule":
        material = [kind, record["definition"], record["version"]]
    elif kind == "saved_search":
        material = [
            kind,
            record["query"],
            record["interval"],
            record["lookback"],
            record["threshold"],
        ]
    else:
        raise ValueError("Unsupported late analysis family")
    return hashlib.sha256(encode(material).encode()).hexdigest()


def late_work(db, kind, now, maximum=8):
    table = {"schedule": "analysis_schedules", "saved_search": "rules"}.get(kind)
    if table is None:
        raise ValueError("Unsupported late analysis family")
    result = []
    for late in db.execute(
        "SELECT * FROM analysis_late_ranges WHERE kind=? AND retry_at<=? ORDER BY cursor,tenant,source_id LIMIT ?",
        (kind, now, maximum),
    ).fetchall():
        source = db.execute(
            f"SELECT * FROM {table} WHERE id=? AND tenant=? AND enabled=1",
            (late["source_id"], late["tenant"]),
        ).fetchone()
        if (
            source is None
            or late_definition_digest(kind, source) != late["definition_digest"]
        ):
            continue
        row = dict(source)
        row["_late"] = dict(late)
        row["_ordinary_next_run"] = row["next_run"]
        row["next_run"] = late["cursor"]
        result.append(row)
    return result


def check_late(db, row):
    late = row.get("_late") if isinstance(row, dict) else None
    if late is None:
        return
    current = db.execute(
        "SELECT revision,cursor FROM analysis_late_ranges WHERE kind=? AND source_id=? AND definition_digest=?",
        (late["kind"], late["source_id"], late["definition_digest"]),
    ).fetchone()
    if (
        not current
        or current["revision"] != late["revision"]
        or current["cursor"] != late["cursor"]
    ):
        raise ConflictError("Late analysis input generation changed")


def finish_late(db, row, interval):
    check_late(db, row)
    late = row["_late"]
    values = (
        late["kind"],
        late["source_id"],
        late["definition_digest"],
        late["revision"],
    )
    if late["cursor"] + interval > late["last_end"]:
        db.execute(
            "DELETE FROM analysis_late_ranges WHERE kind=? AND source_id=? AND definition_digest=? AND revision=?",
            values,
        )
    else:
        db.execute(
            "UPDATE analysis_late_ranges SET cursor=cursor+?,retry_at=0,failures=0,error=NULL WHERE kind=? AND source_id=? AND definition_digest=? AND revision=?",
            (interval, *values),
        )


def fail_late(db, row, now, exc):
    late = row["_late"]
    db.execute(
        "UPDATE analysis_late_ranges SET retry_at=?,failures=failures+1,error=? WHERE kind=? AND source_id=? AND definition_digest=? AND revision=?",
        (
            now + 5,
            type(exc).__name__,
            late["kind"],
            late["source_id"],
            late["definition_digest"],
            late["revision"],
        ),
    )


def register_input(store, kind, row, start, end, scope):
    digest = late_definition_digest(kind, row)
    with store.write_lock, store.control() as db:
        db.execute(
            "INSERT INTO analysis_window_inputs(kind,source_id,definition_digest,tenant,window_start,window_end,scope) VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(kind,source_id,definition_digest,window_end) DO NOTHING",
            (kind, row["id"], digest, row["tenant"], start, end, encode(scope)),
        )
        value = dict(
            db.execute(
                "SELECT * FROM analysis_window_inputs WHERE kind=? AND source_id=? AND definition_digest=? AND window_end=?",
                (kind, row["id"], digest, end),
            ).fetchone()
        )
        if value["scope"] != encode(scope):
            db.execute(
                "UPDATE analysis_window_inputs SET scope=?,generation=generation+1 WHERE kind=? AND source_id=? AND definition_digest=? AND window_end=?",
                (encode(scope), kind, row["id"], digest, end),
            )
            value = dict(
                db.execute(
                    "SELECT * FROM analysis_window_inputs WHERE kind=? AND source_id=? AND definition_digest=? AND window_end=?",
                    (kind, row["id"], digest, end),
                ).fetchone()
            )
    return value


def check_input(db, value, *, finish=False):
    keys = (
        value["kind"],
        value["source_id"],
        value["definition_digest"],
        value["window_end"],
    )
    current = db.execute(
        "SELECT generation,scope FROM analysis_window_inputs WHERE kind=? AND source_id=? AND definition_digest=? AND window_end=?",
        keys,
    ).fetchone()
    if (
        not current
        or current["generation"] != value["generation"]
        or current["scope"] != value["scope"]
    ):
        raise ConflictError("Indexed analysis input generation or scope changed")
    if finish:
        db.execute(
            "DELETE FROM analysis_window_inputs WHERE kind=? AND source_id=? AND definition_digest=? AND window_end=?",
            keys,
        )


def register_partition(store, value):
    keys = (
        value["kind"],
        value["source_id"],
        value["definition_digest"],
        value["window_end"],
    )
    with store.write_lock, store.control() as db:
        db.execute(
            "INSERT INTO analysis_partition_progress VALUES(?,?,?,?,?,NULL,'{}') ON CONFLICT(kind,source_id,definition_digest,window_end) DO NOTHING",
            (*keys, value["generation"]),
        )
        state = dict(
            db.execute(
                "SELECT * FROM analysis_partition_progress WHERE kind=? AND source_id=? AND definition_digest=? AND window_end=?",
                keys,
            ).fetchone()
        )
        if state["generation"] != value["generation"]:
            db.execute(
                "UPDATE analysis_partition_progress SET generation=?,cursor=NULL,summary='{}' WHERE kind=? AND source_id=? AND definition_digest=? AND window_end=?",
                (value["generation"], *keys),
            )
            state.update(generation=value["generation"], cursor=None, summary="{}")
    state["summary"] = json.loads(state["summary"])
    state["cursor"] = (
        json.loads(state["cursor"]) if state["cursor"] is not None else None
    )
    return state


def commit_partition(db, value, state, result, complete, cursor):
    check_input(db, value)
    keys = (
        value["kind"],
        value["source_id"],
        value["definition_digest"],
        value["window_end"],
    )
    current = db.execute(
        "SELECT generation,cursor FROM analysis_partition_progress WHERE kind=? AND source_id=? AND definition_digest=? AND window_end=?",
        keys,
    ).fetchone()
    expected = encode(state["cursor"]) if state["cursor"] is not None else None
    if (
        not current
        or current["generation"] != value["generation"]
        or current["cursor"] != expected
    ):
        raise ConflictError("Analysis partition cursor changed")
    summary = dict(state["summary"])
    summary["partitions"] = summary.get("partitions", 0) + 1
    summary["matched_events"] = summary.get("matched_events", 0) + result.get(
        "matched_events", 0
    )
    summary["candidate_events"] = summary.get("candidate_events", 0) + result.get(
        "candidate_events", 0
    )
    summary["scanned_events"] = result.get(
        "scanned_events", summary.get("scanned_events", 0)
    )
    if "scanned_entities" in result:
        summary["scanned_entities"] = result["scanned_entities"]
    summary["complete"] = bool(complete)
    summary["input_generation"] = value["generation"]
    summary["matches_sample"] = (
        summary.get("matches_sample", []) + result.get("matches", [])
    )[:100]
    summary["evidence_is_sample"] = summary["matched_events"] > len(
        summary["matches_sample"]
    )
    if "anomalies" in result:
        summary["anomaly_count"] = summary.get("anomaly_count", 0) + len(
            result["anomalies"]
        )
        summary["anomalies_sample"] = (
            summary.get("anomalies_sample", []) + result["anomalies"]
        )[:100]
        summary["anomalies_are_sample"] = summary["anomaly_count"] > len(
            summary["anomalies_sample"]
        )
        summary["seasonal_warmup_count"] = summary.get(
            "seasonal_warmup_count", 0
        ) + len(result.get("seasonal_warmup", []))
        summary["seasonal_warmup_sample"] = (
            summary.get("seasonal_warmup_sample", [])
            + result.get("seasonal_warmup", [])
        )[:100]
        quality = result.get("quality", {})
        summary["volume_observed_buckets"] = summary.get(
            "volume_observed_buckets", 0
        ) + quality.get("volume_observed_buckets", 0)
        summary["volume_outlier_buckets"] = summary.get(
            "volume_outlier_buckets", 0
        ) + quality.get("volume_outlier_buckets", 0)
    if "feed_versions" in result:
        summary["feed_versions"] = result["feed_versions"]
    if complete:
        db.execute(
            "DELETE FROM analysis_partition_progress WHERE kind=? AND source_id=? AND definition_digest=? AND window_end=?",
            keys,
        )
    else:
        db.execute(
            "UPDATE analysis_partition_progress SET cursor=?,summary=? WHERE kind=? AND source_id=? AND definition_digest=? AND window_end=?",
            (encode(cursor), encode(summary), *keys),
        )
    return summary


def _late_due(store, now, iteration, maximum=8):
    with store.control(local=True) as db:
        rows = db.execute(
            "SELECT l.* FROM correlation_policies p CROSS JOIN log_correlation_late_ranges l WHERE p.enabled=1 AND l.policy_id=p.id AND l.version=p.version AND l.retry_at<=? ORDER BY l.cursor,l.tenant,l.policy_id LIMIT ?",
            (now, maximum),
        ).fetchall()
    completed = 0
    for row in rows:
        if iteration.is_set():
            break
        signal = detections.page_deadline(store, iteration.cancel)
        try:
            with store.control() as db:
                policy = db.execute(
                    "SELECT * FROM correlation_policies WHERE id=? AND tenant=?",
                    (row["policy_id"], row["tenant"]),
                ).fetchone()
                if (
                    not policy
                    or not policy["enabled"]
                    or policy["version"] != row["version"]
                ):
                    raise PermissionError(
                        "Late recovery policy is disabled, missing or changed"
                    )
                definition = json.loads(policy["definition"])
                owner = detections._owner_actor(db, policy)
                if db.execute(
                    "SELECT 1 FROM queue WHERE tenant=? LIMIT 1", (row["tenant"],)
                ).fetchone():
                    raise CapacityError(
                        "Late recovery waits for admitted tenant events"
                    )
            page = detections.prepare_window_page(
                store,
                policy,
                definition,
                row["cursor"],
                owner["allowed_indexes"],
                signal,
            )
            matches = page["matches"]
            with store.write_lock, store.control() as db:
                db.execute("BEGIN IMMEDIATE")
                current = db.execute(
                    "SELECT * FROM correlation_policies WHERE id=?", (row["policy_id"],)
                ).fetchone()
                if (
                    not current
                    or not current["enabled"]
                    or current["version"] != row["version"]
                    or current["definition"] != policy["definition"]
                ):
                    raise ConflictError("Late recovery policy changed")
                fresh = detections._owner_actor(db, current, owner["allowed_indexes"])
                detections._emit_matches(
                    db,
                    store,
                    current,
                    definition,
                    matches,
                    row["cursor"],
                    mode="automatic_late_recovery",
                    scheduled_end=row["cursor"] + definition.get("evaluation_delay", 0),
                    actor="correlation-engine",
                    guard=fresh,
                    cancel=signal,
                )
                finished = detections.commit_window_page(db, page)
            if not finished:
                continue
            with store.write_lock, store.control(local=True) as db:
                db.execute("BEGIN IMMEDIATE")
                if row["cursor"] + definition["interval"] > row["last_end"]:
                    db.execute(
                        "DELETE FROM log_correlation_late_ranges WHERE policy_id=? AND version=? AND revision=?",
                        (row["policy_id"], row["version"], row["revision"]),
                    )
                else:
                    db.execute(
                        "UPDATE log_correlation_late_ranges SET cursor=cursor+?,failures=0,retry_at=0,error=NULL WHERE policy_id=? AND version=? AND revision=?",
                        (
                            definition["interval"],
                            row["policy_id"],
                            row["version"],
                            row["revision"],
                        ),
                    )
            completed += 1
        except Exception as exc:  # noqa: BLE001 - Preserve durable failed recovery range.
            with store.write_lock, store.control(local=True) as db:
                db.execute(
                    "UPDATE log_correlation_late_ranges SET failures=failures+1,retry_at=?,error=? WHERE policy_id=? AND version=?",
                    (now + 5, type(exc).__name__, row["policy_id"], row["version"]),
                )
    return completed


def _definition(store, db, actor, data):
    if not isinstance(data, dict) or set(data) - {
        "name",
        "kind",
        "interval",
        "lookback",
        "enabled",
        "baseline_id",
        "indexes",
        "lookups",
        "fields",
        "case_adapter",
        "late_recovery",
    }:
        raise ValueError("Unknown analysis schedule property")
    name, kind = data.get("name"), data.get("kind")
    if (
        not isinstance(name, str)
        or not 1 <= len(name) <= 120
        or not isinstance(kind, str)
        or kind not in {"behavior", "intel"}
    ):
        raise ValueError("Schedule requires bounded name and behavior/intel kind")
    interval, lookback = data.get("interval", 300), data.get("lookback", 300)
    if (
        type(interval) is not int
        or type(lookback) is not int
        or not 30 <= interval <= lookback <= 86400
        or type(data.get("enabled", False)) is not bool
    ):
        raise ValueError(
            "Explicit schedule interval/lookback 30..86400 and boolean enabled required"
        )
    result = {
        "name": name,
        "kind": kind,
        "interval": interval,
        "lookback": lookback,
        "enabled": data.get("enabled", False),
        "case_adapter": validate_case_adapter(data.get("case_adapter")),
        "late_recovery": data.get("late_recovery", 900),
    }
    if (
        type(result["late_recovery"]) is not int
        or not 0 <= result["late_recovery"] <= 86400
    ):
        raise ValueError("late_recovery must be integer0..86400 seconds")
    if kind == "behavior":
        from . import behavior

        baseline, _ = behavior._load(db, actor, data.get("baseline_id"))
        training = json.loads(baseline["definition"])
        bucket = training["bucket_seconds"]
        if interval % bucket or lookback % bucket or lookback // bucket > 336:
            raise ValueError(
                "Behavior interval/lookback must align to baseline buckets"
            )
        result.update(
            baseline_id=baseline["id"],
            indexes=json.loads(baseline["indexes"]),
            bucket_seconds=bucket,
            training_end=training["end"],
        )
    else:
        from . import lookups
        from .entities import exact_indexes

        result["indexes"] = exact_indexes(data.get("indexes"))
        names = data.get("lookups")
        if (
            not isinstance(names, list)
            or not 1 <= len(names) <= 8
            or any(not isinstance(name, str) for name in names)
            or len(set(names)) != len(names)
        ):
            raise ValueError("Intel schedule requires 1..8 explicit managed feeds")
        for name in names:
            lookups.name_checked(name)
            table = db.execute(
                "SELECT kind FROM managed_lookups WHERE tenant=? AND name=?",
                (actor["tenant"], name),
            ).fetchone()
            if not table or table["kind"] not in {"ip", "domain", "hash"}:
                raise ValueError("Managed threat-intel feed is unavailable")
        fields = data.get(
            "fields",
            {
                "ip": ["raw.security.src_ip", "raw.security.dest_ip"],
                "domain": [
                    "raw.security.domain",
                    "raw.domain",
                    "raw.xdr.data.dns.question.name",
                ],
                "hash": [
                    "raw.security.file_hash",
                    "raw.file_hash",
                    "raw.hash",
                    "raw.xdr.data.file.hash.sha256",
                ],
            },
        )
        if not isinstance(fields, dict) or set(fields) - {"ip", "domain", "hash"}:
            raise ValueError("Intel fields must map typed indicator kinds")
        for values in fields.values():
            if not isinstance(values, list) or not 1 <= len(values) <= 8:
                raise ValueError("Intel kind requires 1..8 fields")
            for field in values:
                column(field)
        result.update(lookups=names, fields=fields)
    if not principal.contains(actor["allowed_indexes"], result["indexes"]):
        raise PermissionError("Schedule indexes exceed current scope")
    return result


def save_schedule(store, who, data):
    with principal.transaction(store, who, EDIT, write=True) as (db, actor):
        definition = _definition(store, db, actor, data)
        # Durable inventory/history has no lifetime record-count ceiling.
        identifier = str(uuid.uuid4())
        now = time.time()
        if definition["kind"] == "behavior":
            now = max(
                definition["training_end"] + definition["lookback"],
                math.floor(now / definition["bucket_seconds"])
                * definition["bucket_seconds"],
            )
        db.execute(
            "INSERT INTO analysis_schedules(id,tenant,owner,name,kind,definition,enabled,next_run) VALUES(?,?,?,?,?,?,?,?)",
            (
                identifier,
                actor["tenant"],
                actor["name"],
                definition["name"],
                definition["kind"],
                encode(definition),
                int(definition["enabled"]),
                now,
            ),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "analysis.schedule.create",
            {
                "id": identifier,
                "kind": definition["kind"],
                "enabled": definition["enabled"],
                "case_opt_in": definition["case_adapter"] is not None,
            },
        )
        from . import detector_ops

        detector_ops.register_schedule(db,db.execute("SELECT * FROM analysis_schedules WHERE id=?",(identifier,)).fetchone())
    return {"id": identifier, "version": 1, "definition": definition}


def list_schedules(store, who):
    with principal.transaction(store, who) as (db, actor):
        rows = db.execute(
            "SELECT * FROM analysis_schedules WHERE tenant=? ORDER BY name,id",
            (actor["tenant"],),
        ).fetchall()
        return [
            {**dict(row), "definition": json.loads(row["definition"])}
            for row in rows
            if (row["owner"] == actor["name"] or actor["role"] == "admin")
            and principal.contains(
                actor["allowed_indexes"], json.loads(row["definition"])["indexes"]
            )
        ]


def toggle_schedule(store, who, identifier, enabled, version):
    if type(enabled) is not bool or type(version) is not int:
        raise ValueError("enabled/version required")
    with principal.transaction(store, who, EDIT, write=True) as (db, actor):
        row = db.execute(
            "SELECT * FROM analysis_schedules WHERE tenant=? AND id=?",
            (actor["tenant"], identifier),
        ).fetchone()
        if not row or (row["owner"] != actor["name"] and actor["role"] != "admin"):
            raise KeyError("Schedule not found")
        if row["version"] != version:
            raise ConflictError("Schedule changed")
        db.execute(
            "UPDATE analysis_schedules SET enabled=?,version=version+1 WHERE id=?",
            (int(enabled), identifier),
        )
        from . import detector_ops

        detector_ops.register_schedule(db,db.execute("SELECT * FROM analysis_schedules WHERE id=?",(identifier,)).fetchone())
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "analysis.schedule.toggle",
            {"id": identifier, "enabled": enabled},
        )
    return {"id": identifier, "version": version + 1, "enabled": enabled}


def _originals(store, actor, event_ids, entity_field, signal):
    if not event_ids:
        return []
    columns = list(
        dict.fromkeys(
            [
                "event_id",
                "event_time",
                "received",
                "index_name",
                "host",
                "source",
                "severity",
                "raw",
                entity_field,
            ]
        )
    )
    scope, scope_args = index_predicate(actor["allowed_indexes"])
    sql = (
        "SELECT "
        + ",".join(
            column(c) + ((' AS "' + c + '"') if c.startswith("raw.") else "")
            for c in columns
        )
        + " FROM events_all WHERE tenant=? AND event_id IN (SELECT value->>'$' FROM json_each(?)) AND "
        + scope
        + " ORDER BY event_time,event_id"
    )
    result = store.analytics_query(
        sql,
        [actor["tenant"], encode(sorted(set(event_ids))), *scope_args],
        cancel=signal,
        max_rows=1000,
    )
    if result["returned"] != len(set(event_ids)):
        raise CapacityError(
            "Analysis original evidence is unavailable or exceeds bound"
        )
    if any(
        not principal.contains(actor["allowed_indexes"], [row["index_name"]])
        for row in result["rows"]
    ):
        raise PermissionError("Analysis evidence scope changed")
    return result["rows"]


def prepare_case_rows(store, actor, adapter, rows, signal=None):
    """Verify query identities before obtaining the SQLite writer (no gate inversion)."""
    if (
        not isinstance(rows, list)
        or len(rows) > 1000
        or any(
            not isinstance(row.get("event_id"), str) or not row["event_id"]
            for row in rows
        )
    ):
        raise ValueError("Case adapter requires bounded original event IDs")
    originals = _originals(
        store, actor, [row["event_id"] for row in rows], adapter["entity_field"], signal
    )
    indexed = {row["event_id"]: row for row in originals}
    for row in rows:
        original = indexed[row["event_id"]]
        for key in (
            "event_time",
            "host",
            "source",
            "severity",
            adapter["entity_field"],
        ):
            if row.get(key) != original.get(key):
                raise ConflictError(
                    "Case adapter query transformed original evidence identity/body"
                )
        if row.get("index_name", row.get("index")) != original["index_name"]:
            raise ConflictError(
                "Case adapter query transformed original evidence index"
            )
    return originals


def _intel(
    store,
    actor,
    definition,
    end,
    signal,
    *,
    cursor=None,
    scanned_total=None,
    page_size=128,
):
    from . import lookups

    tables = {
        name: lookups.get(store, actor["tenant"], name)
        for name in definition["lookups"]
    }
    prepared = lookups.prepare_threat_tables(tables)
    fields = list(
        dict.fromkeys(
            [
                "event_id",
                "event_time",
                "received",
                "index_name",
                "host",
                "source",
                "severity",
                "raw",
                *(
                    [definition["case_adapter"]["entity_field"]]
                    if definition["case_adapter"]
                    else []
                ),
            ]
        )
    )
    from .query import index_predicate

    scope, scope_args = index_predicate(
        principal.intersection(actor["allowed_indexes"], definition["indexes"])
    )
    where = "tenant=? AND event_time>=? AND event_time<? AND " + scope
    args = [actor["tenant"], max(0, end - definition["lookback"]), end, *scope_args]
    total = (
        scanned_total
        if scanned_total is not None
        else store.analytics_query(
            "SELECT count(*) AS total FROM events_all WHERE " + where,
            args,
            cancel=signal,
            max_rows=1,
        )["rows"][0]["total"]
    )
    clauses, indicator_args = [], []
    for table in tables.values():
        kind = table["kind"]
        indicators = encode([row[table["key"]] for row in table["rows"]])
        for field in definition["fields"].get(kind, []):
            value = column(field)
            comparable = (
                f"lower(rtrim(CAST({value} AS VARCHAR),'.'))"
                if kind == "domain"
                else f"lower(CAST({value} AS VARCHAR))"
                if kind == "hash"
                else value
            )
            clause = comparable + " IN (SELECT value->>'$' FROM json_each(?))"
            # Preserve exact Python normalization for Unicode domains and custom
            # IPv6 spellings; these extra candidates are not silently discarded.
            if kind == "domain":
                clause += f" OR regexp_matches(CAST({value} AS VARCHAR),'[^ -~]')"
            elif kind == "ip" and not field.startswith("raw.security."):
                clause += f" OR contains(CAST({value} AS VARCHAR),':')"
            clauses.append("(" + clause + ")")
            indicator_args.append(indicators)
    selection = ",".join(
        column(field) + ((' AS "' + field + '"') if field.startswith("raw.") else "")
        for field in fields
    )
    cursor_sql = ""
    cursor_args = []
    if cursor is not None:
        cursor_sql = " AND (event_time>? OR (event_time=? AND event_id>?))"
        cursor_args = [cursor[0], cursor[0], cursor[1]]
    result = store.analytics_query(
        "SELECT "
        + selection
        + " FROM events_all WHERE "
        + where
        + " AND ("
        + (" OR ".join(clauses) or "FALSE")
        + ")"
        + cursor_sql
        + " ORDER BY event_time,event_id LIMIT "
        + str(page_size + 1),
        [*args, *indicator_args, *cursor_args],
        cancel=signal,
        max_rows=page_size + 1,
    )
    more = result["returned"] > page_size
    rows = result["rows"][:page_size]
    matched, details = [], []
    for row in rows:
        if signal.is_set():
            raise CapacityError("IOC analysis scheduling deadline exhausted")
        event = dict(row)
        event["raw"] = json.loads(row["raw"])
        enriched = lookups.enrich_event(
            event, tables, definition["fields"], _prepared=prepared
        )
        hits = enriched["raw"]["threat_intel"]
        if hits:
            matched.append(row)
            details.append({"event_id": row["event_id"], "matches": hits})
    return {
        "method": "exact_local_ioc",
        "matched_events": len(matched),
        "scanned_events": total,
        "candidate_events": len(rows),
        "matches": details,
        "feed_versions": {name: table["version"] for name, table in tables.items()},
        "has_more": more,
        "next_cursor": [rows[-1]["event_time"], rows[-1]["event_id"]] if rows else None,
        "partition_size": page_size,
    }, matched


def run_due(store, now=None, cancel=None, budget=1.0, max_runs=8):
    now = time.time() if now is None else now
    if (
        type(budget) not in (int, float)
        or not math.isfinite(budget)
        or not 0.01 <= budget <= 30
    ):
        raise ValueError("Analysis iteration budget must be finite .01..30 seconds")
    if type(max_runs) is not int or not 1 <= max_runs <= 8:
        raise ValueError("Analysis max_runs must be integer1..8")
    iteration = detections._Until(cancel, time.monotonic() + budget)
    completed = _late_due(store, now, iteration, max_runs)
    with store.control() as db:
        ordinary = [
            dict(row)
            for row in db.execute(
                "SELECT * FROM (SELECT *,row_number() OVER(PARTITION BY tenant ORDER BY next_run,id) AS rank FROM analysis_schedules WHERE enabled=1 AND next_run<=? AND retry_at<=?) ORDER BY rank,next_run,id LIMIT ?",
                (now, now, max_runs),
            ).fetchall()
        ]
        rows = (late_work(db, "schedule", now, max(1, max_runs // 2)) + ordinary)[
            :max_runs
        ]
    for row in rows:
        if iteration.is_set():
            break
        signal = detections.page_deadline(store, cancel)
        try:
            definition, end = json.loads(row["definition"]), row["next_run"]
            with store.control() as db:
                actor = principal.current(
                    db,
                    {
                        "name": row["owner"],
                        "tenant": row["tenant"],
                        "role": "analyst",
                        "allowed_indexes": definition["indexes"],
                    },
                    EDIT,
                )
                if not principal.contains(
                    actor["allowed_indexes"], definition["indexes"]
                ):
                    raise PermissionError("Analysis owner lost required index scope")
                if db.execute(
                    "SELECT 1 FROM queue WHERE tenant=? AND received<=? LIMIT 1",
                    (row["tenant"], end),
                ).fetchone():
                    raise CapacityError("Analysis waits for indexed tenant input")
            input_window = register_input(
                store,
                "schedule",
                row,
                end - definition["lookback"],
                end,
                definition["indexes"],
            )
            partition = register_partition(store, input_window)
            if row["kind"] == "behavior":
                from . import behavior

                bucket = definition["bucket_seconds"]
                part_cursor = partition["cursor"] or {
                    "bucket_start": end - definition["lookback"],
                    "entity_after": None,
                }
                bucket_start = part_cursor["bucket_start"]
                bucket_end = bucket_start + bucket
                entities = behavior.entity_page(
                    store,
                    actor,
                    definition["baseline_id"],
                    bucket_start,
                    bucket_end,
                    part_cursor["entity_after"],
                    signal,
                )

                result = behavior.evaluate(
                    store,
                    actor,
                    definition["baseline_id"],
                    bucket_start,
                    bucket_end,
                    cancel=signal,
                    run_key=row["id"]
                    + ":"
                    + str(row["version"])
                    + ":input:"
                    + str(input_window["generation"])
                    + (
                        ":late:" + str(row["_late"]["revision"])
                        if row.get("_late")
                        else ""
                    ),
                    selected_entities=entities,
                )
                full_coverage = (
                    {
                        key: partition["summary"][key]
                        for key in ("scanned_events", "scanned_entities")
                    }
                    if "scanned_entities" in partition["summary"]
                    else behavior.coverage(
                        store,
                        actor,
                        definition["baseline_id"],
                        end - definition["lookback"],
                        end,
                        signal,
                    )
                )
                result = {
                    **result,
                    "execution_mode": "scheduled",
                    "automatic_detection": True,
                    "case_opt_in": definition["case_adapter"] is not None,
                    "has_more": len(entities) == 16 or bucket_end < end,
                    "next_cursor": {
                        "bucket_start": bucket_start,
                        "entity_after": entities[-1],
                    }
                    if len(entities) == 16
                    else {"bucket_start": bucket_end, "entity_after": None},
                    "partition_size": 16,
                    **full_coverage,
                }
                ids = [
                    event["event_id"]
                    for anomaly in result["anomalies"]
                    for event in anomaly["evidence"]
                ]
                evidence = (
                    _originals(
                        store,
                        actor,
                        ids,
                        definition["case_adapter"]["entity_field"],
                        signal,
                    )
                    if definition["case_adapter"]
                    else []
                )
            else:
                result, evidence = _intel(
                    store,
                    actor,
                    definition,
                    end,
                    signal,
                    cursor=partition["cursor"],
                    scanned_total=partition["summary"].get("scanned_events"),
                    page_size=16 if definition["case_adapter"] else 128,
                )
                if partition["summary"].get("feed_versions") not in (
                    None,
                    result["feed_versions"],
                ):
                    with store.write_lock, store.control() as db:
                        db.execute(
                            "UPDATE analysis_window_inputs SET generation=generation+1 WHERE kind=? AND source_id=? AND definition_digest=? AND window_end=?",
                            (
                                input_window["kind"],
                                input_window["source_id"],
                                input_window["definition_digest"],
                                input_window["window_end"],
                            ),
                        )
                    raise ConflictError(
                        "IOC feed revision changed during partitioned window; restart exact coverage"
                    )
            if signal.is_set():
                raise CapacityError("Analysis scheduling budget exhausted")
            packed = encode(result)
            if len(packed.encode()) > 1024 * 1024:
                raise CapacityError("Scheduled analysis result exceeds 1 MiB")
            with principal.transaction(store, actor, EDIT, write=True) as (db, fresh):
                current = db.execute(
                    "SELECT * FROM analysis_schedules WHERE id=?", (row["id"],)
                ).fetchone()
                if (
                    not current
                    or not current["enabled"]
                    or current["version"] != row["version"]
                    or current["definition"] != row["definition"]
                    or (not row.get("_late") and current["next_run"] != end)
                ):
                    raise ConflictError("Analysis schedule changed")
                if not principal.contains(
                    fresh["allowed_indexes"], definition["indexes"]
                ):
                    raise PermissionError(
                        "Analysis permissions changed before Case emission"
                    )
                check_input(db, input_window)
                check_late(db, row)
                digest = hashlib.sha256(row["definition"].encode()).hexdigest()
                if row["kind"] == "intel":
                    for name, version in result["feed_versions"].items():
                        current_feed = db.execute(
                            "SELECT version,expires FROM managed_lookups WHERE tenant=? AND name=?",
                            (row["tenant"], name),
                        ).fetchone()
                        if (
                            not current_feed
                            or current_feed["version"] != version
                            or current_feed["expires"] is None
                            or current_feed["expires"] <= time.time()
                        ):
                            raise ConflictError(
                                "Managed IOC feed changed or expired before Case emission"
                            )
                if definition["case_adapter"] and evidence:
                    emit_rows(
                        db,
                        store,
                        fresh,
                        "analysis:" + row["id"],
                        definition["case_adapter"],
                        evidence,
                        end,
                        row["kind"],
                        extra={
                            "definition_digest": digest,
                            "result_id": result.get("id"),
                            "method": result.get("method", "count_baseline"),
                            "baseline_quality": result.get("quality"),
                            **(
                                {
                                    "ioc_matches": result["matches"],
                                    "feed_versions": result["feed_versions"],
                                }
                                if row["kind"] == "intel"
                                else {
                                    "baseline_anomalies": result["anomalies"],
                                    "baseline_digest": result["baseline_digest"],
                                }
                                if "baseline_digest" in result
                                else {"baseline_anomalies": result["anomalies"]}
                            ),
                        },
                        basis_indexes=definition["indexes"]
                        if row["kind"] == "behavior"
                        else None,
                    )
                finished = not result.get("has_more", False)
                if partition is not None:
                    summary = commit_partition(
                        db,
                        input_window,
                        partition,
                        result,
                        finished,
                        result["next_cursor"],
                    )
                    if finished:
                        result = {
                            **result,
                            **summary,
                            "summary_only": True,
                            "start": end - definition["lookback"],
                            "end": end,
                        }
                        if row["kind"] == "intel":
                            result.update(
                                method="exact_local_ioc",
                                matches=summary["matches_sample"],
                            )
                        else:
                            observed = summary["volume_observed_buckets"]
                            outliers = summary["volume_outlier_buckets"]
                            result.update(
                                anomalies=summary["anomalies_sample"],
                                entities=summary["scanned_entities"],
                                seasonal_warmup=summary["seasonal_warmup_sample"],
                                seasonal_warmup_is_sample=summary[
                                    "seasonal_warmup_count"
                                ]
                                > len(summary["seasonal_warmup_sample"]),
                                quality={
                                    **result["quality"],
                                    "volume_observed_buckets": observed,
                                    "volume_outlier_buckets": outliers,
                                    "volume_outlier_fraction": outliers / observed
                                    if observed
                                    else None,
                                    "shadow_retraining_review_required": observed >= 10
                                    and outliers / observed > 0.2,
                                },
                                complete_counts=True,
                                partition_entities=None,
                                authorized_events=summary["scanned_events"],
                                missing_entity_events=max(
                                    0,
                                    summary["scanned_events"]
                                    - summary["matched_events"],
                                ),
                            )
                        packed = encode(result)
                db.execute(
                    "INSERT INTO analysis_schedule_runs VALUES(?,?,?,?,?,?,?) ON CONFLICT(schedule_id,window_end,definition_digest) DO UPDATE SET result=excluded.result,created=excluded.created",
                    (
                        str(uuid.uuid4()),
                        row["tenant"],
                        row["id"],
                        end,
                        digest,
                        packed,
                        time.time(),
                    ),
                )
                from . import analysis_history

                retention = analysis_history.retain(
                    db, row["tenant"], "analysis_schedule_runs"
                )
                if retention["archived_bodies"]:
                    store.audit(
                        db,
                        row["tenant"],
                        fresh["name"],
                        "analysis.history.archive",
                        retention,
                    )
                if not finished:
                    store.audit(
                        db,
                        row["tenant"],
                        fresh["name"],
                        "analysis.partition",
                        {
                            "schedule_id": row["id"],
                            "window_end": end,
                            "input_generation": input_window["generation"],
                            "partition_size": result.get("partition_size"),
                            "complete": False,
                        },
                    )
                    continue
                check_input(db, input_window, finish=True)
                if row.get("_late"):
                    finish_late(db, row, definition["interval"])
                else:
                    db.execute(
                        "UPDATE analysis_schedules SET next_run=?,last_end=?,retry_at=0,failures=0,error=NULL WHERE id=?",
                        (end + definition["interval"], end, row["id"]),
                    )
                store.audit(
                    db,
                    row["tenant"],
                    fresh["name"],
                    "analysis.schedule.run",
                    {
                        "id": row["id"],
                        "end": end,
                        "method": row["kind"],
                        "case_opt_in": definition["case_adapter"] is not None,
                    },
                )
            completed += 1
        except Exception as exc:  # noqa: BLE001 - Isolate and persist one schedule's failed window.
            with store.write_lock, store.control() as db:
                if row.get("_late"):
                    fail_late(db, row, now, exc)
                    continue
                db.execute(
                    "UPDATE analysis_schedules SET failures=failures+1,retry_at=?,error=? WHERE id=? AND version=? AND next_run=?",
                    (
                        now + 5,
                        type(exc).__name__,
                        row["id"],
                        row["version"],
                        row["next_run"],
                    ),
                )
    return completed


def status(store, who):
    schedules = list_schedules(store, who)
    with principal.transaction(store, who) as (db, actor):
        visible = []
        for policy in db.execute(
            "SELECT * FROM correlation_policies WHERE tenant=? AND enabled=1",
            (actor["tenant"],),
        ):
            try:
                owner = detections._owner_actor(db, policy)
            except PermissionError:
                continue
            definition = json.loads(policy["definition"])
            exact = []
            for step in definition["steps"]:
                indexes = [
                    f["value"]
                    for f in step["filters"]
                    if f["field"] in {"index", "index_name"}
                    and f["op"] == "eq"
                    and isinstance(f["value"], str)
                ]
                if not indexes or any(
                    not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", index) for index in indexes
                ):
                    exact = None
                    break
                exact.extend(indexes)
            scope = (
                principal.intersection(owner["allowed_indexes"], sorted(set(exact)))
                if exact is not None
                else owner["allowed_indexes"]
            )
            if principal.contains(actor["allowed_indexes"], scope):
                visible.append(policy["id"])
        late = db.execute(
            "SELECT count(*) AS ranges,coalesce(sum(l.failures),0) AS failures,min(l.cursor) AS oldest_window FROM log_correlation_late_ranges l JOIN correlation_policies p ON p.id=l.policy_id AND p.version=l.version WHERE l.tenant=? AND l.policy_id IN (SELECT value FROM json_each(?))",
            (actor["tenant"], encode(visible)),
        ).fetchone()
        visible_sources = {"schedule": {}, "saved_search": {}}
        for schedule in schedules:
            try:
                owner = principal.current(
                    db,
                    {
                        "name": schedule["owner"],
                        "tenant": actor["tenant"],
                        "role": "analyst",
                    },
                    EDIT,
                )
            except PermissionError:
                continue
            if schedule["enabled"] and principal.contains(
                owner["allowed_indexes"], schedule["definition"]["indexes"]
            ):
                record = {**schedule, "definition": encode(schedule["definition"])}
                visible_sources["schedule"][schedule["id"]] = late_definition_digest(
                    "schedule", record
                )
        for rule in db.execute(
            "SELECT r.*,x.owner FROM rules r JOIN rule_execution x ON x.rule_id=r.id WHERE r.tenant=? AND r.enabled=1",
            (actor["tenant"],),
        ):
            try:
                owner = principal.current(
                    db,
                    {
                        "name": rule["owner"],
                        "tenant": actor["tenant"],
                        "role": "analyst",
                    },
                    EDIT,
                )
            except PermissionError:
                continue
            # Saved queries may touch the complete owner scope. Do not infer a
            # narrow footprint from an arbitrary query and leak private metadata.
            if principal.contains(actor["allowed_indexes"], owner["allowed_indexes"]):
                visible_sources["saved_search"][rule["id"]] = late_definition_digest(
                    "saved_search", rule
                )

        def aggregate(rows):
            rows = list(rows)
            return {
                "ranges": len(rows),
                "failures": sum(row["failures"] for row in rows),
                "oldest_window": min((row["cursor"] for row in rows), default=None),
            }

        families = {"correlation": dict(late)}
        for kind, sources in visible_sources.items():
            families[kind] = aggregate(
                row
                for row in db.execute(
                    "SELECT * FROM analysis_late_ranges WHERE tenant=? AND kind=?",
                    (actor["tenant"], kind),
                )
                if sources.get(row["source_id"]) == row["definition_digest"]
            )
        active_inputs = [
            row
            for row in db.execute(
                "SELECT * FROM analysis_window_inputs WHERE tenant=?",
                (actor["tenant"],),
            )
            if visible_sources.get(row["kind"], {}).get(row["source_id"])
            == row["definition_digest"]
            and principal.contains(actor["allowed_indexes"], json.loads(row["scope"]))
        ]
        correlation_progress = db.execute(
            "SELECT count(*) FROM correlation_window_progress w JOIN correlation_policies p ON p.id=w.policy_id AND p.version=w.version WHERE w.tenant=? AND p.enabled=1 AND w.policy_id IN (SELECT value FROM json_each(?))",
            (actor["tenant"], encode(visible)),
        ).fetchone()[0]
        history = None
        if actor["allowed_indexes"] == ["*"]:
            history = {
                table: db.execute(
                    f"SELECT count(*) FROM {table} WHERE tenant=?", (actor["tenant"],)
                ).fetchone()[0]
                for table in (
                    "behavior_runs",
                    "analysis_schedule_runs",
                    "analysis_history_receipts",
                )
            }
    return {
        "schedules": schedules,
        "late_recovery": dict(late),
        "late_recovery_families": families,
        "partition_progress": {
            "correlation_windows": correlation_progress,
            "analysis_windows": len(active_inputs),
            "oldest_analysis_window": min(
                (row["window_end"] for row in active_inputs), default=None
            ),
            "cursor_advances_only_after_complete_window": True,
        },
        "history_retention": {
            "counts": history,
            "tenant_counts_require_complete_index_scope": True,
            "full_result_limit_per_table": 1000,
            "compact_receipt_limit": 100000,
            "compact_receipt_seconds": 31 * 86400,
            "lifetime_detection_quota": False,
            "source_or_case_evidence_removed": False,
        },
        "bounds": {
            "policies_per_tenant": 200,
            "schedules_per_tenant": 64,
            "analysis_runs_per_tenant": 1000,
            "runs_per_iteration": 8,
            "late_range_rows": "one per active policy/version or analysis source/definition digest",
            "correlation_candidate_entities_per_page": 16,
            "correlation_terminal_paths_per_page": 128,
            "behavior_entities_per_bucket_page": 16,
            "ioc_candidates_per_page_with_case_adapter": 16,
            "preview_and_training_bounds_are_separate": True,
            "iteration_budget_mode": "between bounded pages; each exact page has a finite native/total deadline",
            "max_late_horizon_seconds": 86400,
        },
        "model_semantics": "Versioned statistical counts and explicit local IOCs; no learned threat probability or autonomous response",
    }
