"""Explainable immutable count baselines; manual analysis, not packaged ML/UEBA."""

import hashlib
import json
import math
import re
import statistics
import time
import uuid

from . import principal
from .entities import EDITORS, deadline, exact_indexes, query, window
from .query import column, index_predicate
from .storage import CapacityError, encode

ENTITY_FIELDS = {
    "host",
    "raw.security.user",
    "raw.security.src_ip",
    "raw.security.dest_ip",
}
MAX_GROUPS = 10000
MAX_ENTITIES = 500
MAX_ANOMALIES = 200


def initialize(store):
    with store.control(local=True) as db:
        from . import analysis_history

        analysis_history.initialize(db)
        db.executescript("""
        CREATE TABLE IF NOT EXISTS behavior_baselines(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,name TEXT NOT NULL,
          revision INTEGER NOT NULL,created REAL NOT NULL,indexes TEXT NOT NULL,
          definition TEXT NOT NULL,snapshot TEXT NOT NULL,digest TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS behavior_baseline_owner ON behavior_baselines(tenant,owner,created);
        CREATE TABLE IF NOT EXISTS behavior_runs(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,baseline_id TEXT NOT NULL,
          created REAL NOT NULL,start REAL NOT NULL,end REAL NOT NULL,digest TEXT NOT NULL,
          result TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS behavior_runs_owner ON behavior_runs(tenant,owner,created);
        """)


def _integer(value, label, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{label} must be an integer in {low}..{high}")
    return value


def _definition(data):
    allowed = {
        "name",
        "entity_field",
        "indexes",
        "start",
        "end",
        "bucket_seconds",
        "min_samples",
        "min_buckets",
        "z_threshold",
        "novelty_min_events",
        "business_hours_utc",
        "timezone",
        "count_method",
        "seasonality",
        "seasonality_min_buckets",
        "robust_multiplier",
        "max_baseline_age_seconds",
        "peer_groups",
        "peer_min_entities",
    }
    if not isinstance(data, dict) or set(data) - allowed:
        raise ValueError("Unknown behavior training property")
    name = data.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 128:
        raise ValueError("Baseline name requires 1..128 characters")
    field = data.get("entity_field", "raw.security.user")
    if not isinstance(field, str) or field not in ENTITY_FIELDS:
        raise ValueError("Unsupported behavior entity field")
    definition = {
        "name": name,
        "entity_field": field,
        "indexes": exact_indexes(data.get("indexes")),
        "bucket_seconds": _integer(
            data.get("bucket_seconds", 3600), "bucket_seconds", 60, 86400
        ),
        "min_samples": _integer(
            data.get("min_samples", 20), "min_samples", 1, 1000000000
        ),
        "min_buckets": _integer(data.get("min_buckets", 7), "min_buckets", 2, 336),
        "novelty_min_events": _integer(
            data.get("novelty_min_events", 1), "novelty_min_events", 1, 1000000000
        ),
    }
    threshold = data.get("z_threshold", 3)
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, (int, float))
        or not math.isfinite(threshold)
        or not 1 <= threshold <= 100
    ):
        raise ValueError("z_threshold must be finite in 1..100")
    definition["z_threshold"] = float(threshold)
    timezone = data.get("timezone", "UTC")
    if (
        not isinstance(timezone, str)
        or not 1 <= len(timezone) <= 128
        or not re.fullmatch(r"[A-Za-z_]+(?:/[A-Za-z0-9_+.-]+){0,2}", timezone)
    ):
        raise ValueError("timezone must be a bounded IANA timezone name")
    method = data.get("count_method", "count_zscore")
    seasonality = data.get("seasonality", "none")
    if (
        not isinstance(method, str)
        or not isinstance(seasonality, str)
        or method not in {"count_zscore", "robust_mad", "peer_robust_mad"}
        or seasonality not in {"none", "hour_of_week"}
    ):
        raise ValueError("Unsupported count_method or seasonality")
    definition.update(
        timezone=timezone,
        count_method=method,
        seasonality=seasonality,
        seasonality_min_buckets=_integer(
            data.get("seasonality_min_buckets", 2), "seasonality_min_buckets", 2, 336
        ),
        max_baseline_age_seconds=_integer(
            data.get("max_baseline_age_seconds", 30 * 86400),
            "max_baseline_age_seconds",
            3600,
            365 * 86400,
        ),
    )
    multiplier = data.get("robust_multiplier", 3)
    if (
        type(multiplier) not in (int, float)
        or not math.isfinite(multiplier)
        or not 1 <= multiplier <= 100
    ):
        raise ValueError("robust_multiplier must be finite1..100")
    definition["robust_multiplier"] = float(multiplier)
    from . import peer_behavior

    definition.update(peer_behavior.configure(data))
    if seasonality == "hour_of_week" and (
        definition["bucket_seconds"] > 3600 or 3600 % definition["bucket_seconds"]
    ):
        raise ValueError(
            "hour_of_week seasonality requires hour-aligned subhour buckets"
        )
    hours = data.get(
        "business_hours_utc", {"start": 9, "end": 18, "weekdays": [0, 1, 2, 3, 4]}
    )
    if not isinstance(hours, dict) or set(hours) != {"start", "end", "weekdays"}:
        raise ValueError("Explicit business_hours_utc start/end/weekdays required")
    a = _integer(hours["start"], "business start", 0, 23)
    b = _integer(hours["end"], "business end", 1, 24)
    days = hours["weekdays"]
    if (
        a >= b
        or not isinstance(days, list)
        or not days
        or len(days) > 7
        or any(type(d) is not int or d not in range(7) for d in days)
    ):
        raise ValueError(
            "Business hours must be a non-wrapping interval in the selected timezone and weekdays 0=Monday..6=Sunday"
        )
    definition["business_hours_utc"] = {
        "start": a,
        "end": b,
        "weekdays": sorted(set(days)),
    }
    definition["start"], definition["end"] = _aligned(
        data.get("start"), data.get("end"), definition["bucket_seconds"]
    )
    return definition


def _aligned(start, end, bucket):
    start, end = window(start, end)
    if start % bucket or end % bucket or (end - start) / bucket > 336:
        raise ValueError(
            "Windows must align to epoch bucket boundaries and contain at most 336 buckets"
        )
    return start, end


def _owner(db, baseline):
    return principal.current(
        db,
        {
            "name": baseline["owner"],
            "tenant": baseline["tenant"],
            "role": "analyst",
            "allowed_indexes": json.loads(baseline["indexes"]),
        },
        EDITORS,
    )


def _load(db, actor, baseline_id):
    row = db.execute(
        "SELECT * FROM behavior_baselines WHERE tenant=? AND id=?",
        (actor["tenant"], baseline_id),
    ).fetchone()
    if not row or (row["owner"] != actor["name"] and actor["role"] != "admin"):
        raise KeyError("Baseline not found")
    indexes = json.loads(row["indexes"])
    if not principal.contains(actor["allowed_indexes"], indexes):
        raise KeyError("Baseline not found")
    owner = _owner(db, row)
    if not principal.contains(owner["allowed_indexes"], indexes):
        raise PermissionError(
            "Baseline owner lost required index permission; retrain with a new scope"
        )
    return dict(row), owner


def _public(row, snapshot=False):
    result = dict(row)
    result["definition"] = json.loads(result["definition"])
    result["indexes"] = json.loads(result["indexes"])
    state = json.loads(result.pop("snapshot"))
    result["summary"] = {
        key: state[key]
        for key in (
            "matched_events",
            "authorized_events",
            "missing_entity_events",
            "entities",
            "buckets",
            "ready",
            "method",
        )
    }
    if snapshot:
        result["snapshot"] = state
    return result


def _groups(
    store,
    actor,
    definition,
    start,
    end,
    until,
    cancel,
    models=None,
    selected_entities=None,
):
    """One read snapshot: exact count/host/off-hours facts across the full window."""
    entity = column(definition["entity_field"])
    predicate, indexes = index_predicate(definition["indexes"])
    hours = definition["business_hours_utc"]
    days = ",".join(str(d) for d in hours["weekdays"])
    zone = definition.get("timezone", "UTC")
    local = "timezone(?,to_timestamp(event_time))"
    off_hours = f"(date_part('hour',{local}) < {hours['start']} OR date_part('hour',{local}) >= {hours['end']} OR date_part('isodow',{local})-1 NOT IN ({days}))"
    parameters = [start, definition["bucket_seconds"], zone, zone, zone]
    slot = (
        f"((date_part('isodow',{local})-1)*24+date_part('hour',{local}))"
        if definition.get("seasonality") == "hour_of_week"
        else "0"
    )
    if definition.get("seasonality") == "hour_of_week":
        parameters.extend([zone, zone])
    sql = (
        "WITH facts AS (SELECT event_id,event_time,index_name,host,"
        + entity
        + " AS entity,"
        "CAST(floor((event_time-?)/?) AS INTEGER) AS bucket,"
        + off_hours
        + " AS off_hours,"
        + slot
        + " AS slot_id FROM events_all WHERE tenant=? AND event_time>=? AND event_time<? AND "
        + predicate
        + (
            " AND CAST("
            + entity
            + " AS VARCHAR) IN (SELECT value->>'$' FROM json_each(?))"
            if selected_entities is not None
            else ""
        )
        + "),grouped AS (SELECT entity,bucket,host,max(slot_id) AS slot_id,count(*) AS n,sum(CASE WHEN off_hours THEN 1 ELSE 0 END) AS off_count,"
        "min(event_time) AS first_time,arg_min(event_id,struct_pack(t:=event_time,i:=event_id)) AS first_id,"
        "arg_min(index_name,struct_pack(t:=event_time,i:=event_id)) AS first_index,"
        "min(event_time) FILTER(WHERE off_hours) AS off_time,"
        "arg_min(event_id,struct_pack(t:=event_time,i:=event_id)) FILTER(WHERE off_hours) AS off_id,"
        "arg_min(index_name,struct_pack(t:=event_time,i:=event_id)) FILTER(WHERE off_hours) AS off_index "
        "FROM facts GROUP BY entity,bucket,host) "
    )
    parameters.extend([actor["tenant"], start, end, *indexes])
    if selected_entities is not None:
        parameters.append(encode(selected_entities))
    if models is None:
        sql += "SELECT * FROM grouped ORDER BY entity,bucket,host"
    else:
        sql += " ,known AS (SELECT key AS entity,value AS hosts FROM json_each(?)),marked AS (SELECT g.*,CASE WHEN host IS NOT NULL AND host<>'' AND host<>'unknown' AND NOT EXISTS(SELECT 1 FROM json_each(k.hosts) h WHERE h.value->>'$'=g.host) THEN 1 ELSE 0 END AS novel FROM grouped g LEFT JOIN known k ON CAST(g.entity AS VARCHAR)=k.entity) SELECT entity,bucket,NULL AS host,max(slot_id) AS slot_id,sum(n) AS n,sum(off_count) AS off_count,min(first_time) AS first_time,arg_min(first_id,struct_pack(t:=first_time,i:=first_id)) AS first_id,arg_min(first_index,struct_pack(t:=first_time,i:=first_id)) AS first_index,min(off_time) AS off_time,arg_min(off_id,struct_pack(t:=off_time,i:=off_id)) FILTER(WHERE off_count>0) AS off_id,arg_min(off_index,struct_pack(t:=off_time,i:=off_id)) FILTER(WHERE off_count>0) AS off_index,sum(CASE WHEN novel=1 THEN n ELSE 0 END) AS novel_n,count(*) FILTER(WHERE novel=1) AS novel_hosts,to_json(list_slice(list(host ORDER BY host) FILTER(WHERE novel=1),1,20)) AS novel_hosts_sample,min(first_time) FILTER(WHERE novel=1) AS novel_time,arg_min(first_id,struct_pack(t:=first_time,i:=first_id)) FILTER(WHERE novel=1) AS novel_id,arg_min(first_index,struct_pack(t:=first_time,i:=first_id)) FILTER(WHERE novel=1) AS novel_index FROM marked GROUP BY entity,bucket ORDER BY entity,bucket"
        parameters.append(
            encode({key: value["hosts"] for key, value in models.items()})
        )
    rows = query(
        store,
        sql,
        parameters,
        until,
        MAX_GROUPS,
        cancel,
    )["rows"]
    authorized = sum(row["n"] for row in rows)
    rows = [
        row
        for row in rows
        if row["entity"] not in (None, "")
        and not (definition["entity_field"] == "host" and row["entity"] == "unknown")
    ]
    if len({r["entity"] for r in rows}) > MAX_ENTITIES:
        raise CapacityError(
            "Behavior entity bound exceeded (500); narrow indexes/window"
        )
    if any(len(row["entity"]) > 256 for row in rows):
        raise CapacityError("Behavior identity exceeds 256 characters")
    return rows, authorized


def _check_stop(until, cancel):
    requested = cancel() if callable(cancel) else bool(cancel and cancel.is_set())
    if requested or time.monotonic() >= until:
        raise CapacityError("Behavior operation cancelled or deadline exceeded")


def _slot_keys(store, definition, stamps, cancel=None):
    rows = store.analytics_query(
        "WITH times AS (SELECT CAST(value->>'$' AS DOUBLE) AS epoch FROM json_each(?)),localized AS (SELECT epoch,timezone(?,to_timestamp(epoch)) AS local FROM times) SELECT epoch,CAST((date_part('isodow',local)-1)*24+date_part('hour',local) AS INTEGER) AS slot FROM localized ORDER BY epoch",
        [encode(stamps), definition.get("timezone", "UTC")],
        cancel=cancel,
        max_rows=336,
    )["rows"]
    return {row["epoch"]: row["slot"] for row in rows}


def _robust(values):
    median = statistics.median(values)
    mad = statistics.median(abs(value - median) for value in values)
    return {
        "median": median,
        "mad": mad,
        "mean": statistics.mean(values),
        "stddev": statistics.pstdev(values),
        "bucket_samples": len(values),
    }


def train(store, who, data, cancel=None):
    definition = _definition(data)
    with principal.transaction(store, who, EDITORS) as (_, actor):
        if not principal.contains(actor["allowed_indexes"], definition["indexes"]):
            raise PermissionError("Training indexes exceed current permissions")
    until = deadline(store)
    try:
        query(
            store,
            "SELECT date_part('hour',timezone(?,to_timestamp(?))) AS local_hour",
            [definition["timezone"], definition["start"]],
            until,
            1,
            cancel,
        )
    except Exception as exc:
        if "Unknown TimeZone" in str(exc):
            raise ValueError("Unknown IANA timezone") from exc
        raise
    rows, authorized = _groups(
        store, actor, definition, definition["start"], definition["end"], until, cancel
    )
    buckets = int(
        (definition["end"] - definition["start"]) / definition["bucket_seconds"]
    )
    stamps = [
        definition["start"] + position * definition["bucket_seconds"]
        for position in range(buckets)
    ]
    slots = (
        _slot_keys(store, definition, stamps, cancel)
        if definition.get("seasonality") == "hour_of_week"
        else {}
    )
    models, total = {}, 0
    for row in rows:
        model = models.setdefault(
            row["entity"], {"counts": [0] * buckets, "hosts": set(), "evidence": []}
        )
        model["counts"][row["bucket"]] += row["n"]
        if row["host"] and row["host"] != "unknown":
            model["hosts"].add(row["host"])
        total += row["n"]
        if len(model["evidence"]) < 5:
            model["evidence"].append(_evidence(row))
    for model in models.values():
        model["hosts"] = sorted(model["hosts"])
        model["samples"] = sum(model["counts"])
        model["mean"] = statistics.mean(model["counts"])
        model["stddev"] = statistics.pstdev(model["counts"])
        model.update(_robust(model["counts"]))
        if slots:
            by_slot = {}
            for position, count in enumerate(model["counts"]):
                by_slot.setdefault(str(slots[stamps[position]]), []).append(count)
            model["seasonal_slots"] = {
                slot: {
                    **_robust(values),
                    "ready": len(values) >= definition["seasonality_min_buckets"],
                }
                for slot, values in by_slot.items()
            }
        excess = sum(
            value
            > model["median"] + definition["robust_multiplier"] * max(1, model["mad"])
            for value in model["counts"]
        )
        model["quality"] = {
            "outlier_bucket_fraction": excess / buckets,
            "review_required": excess / buckets > 0.2,
            "malicious_training_contamination_excluded": False,
            "telemetry_gap_excluded": False,
        }
        model["ready"] = (
            buckets >= definition["min_buckets"]
            and model["samples"] >= definition["min_samples"]
        )
    snapshot = {
        "method": definition["count_method"]
        + "; "
        + definition["seasonality"]
        + "; known-host/entity set; explicit local business hours",
        "matched_events": total,
        "authorized_events": authorized,
        "missing_entity_events": authorized - total,
        "entities": len(models),
        "buckets": buckets,
        "ready": buckets >= definition["min_buckets"]
        and total >= definition["min_samples"],
        "models": models,
        "training_evidence_limit_per_entity": 5,
    }
    packed = encode(snapshot)
    if len(packed.encode()) > 1024 * 1024:
        raise CapacityError("Baseline snapshot exceeds 1 MiB; narrow the scope")
    digest = hashlib.sha256(
        encode({"definition": definition, "snapshot": snapshot}).encode()
    ).hexdigest()
    _check_stop(until, cancel)
    with principal.transaction(store, actor, EDITORS, write=True) as (db, fresh):
        if fresh != actor or not principal.contains(
            fresh["allowed_indexes"], definition["indexes"]
        ):
            raise PermissionError("Training permissions changed; retry")
        # Durable inventory/history has no lifetime record-count ceiling.
        revision = db.execute(
            "SELECT coalesce(max(revision),0)+1 FROM behavior_baselines WHERE tenant=? AND owner=? AND name=?",
            (fresh["tenant"], fresh["name"], definition["name"]),
        ).fetchone()[0]
        baseline_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO behavior_baselines VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                baseline_id,
                fresh["tenant"],
                fresh["name"],
                definition["name"],
                revision,
                time.time(),
                encode(definition["indexes"]),
                encode(definition),
                packed,
                digest,
            ),
        )
        store.audit(
            db,
            fresh["tenant"],
            fresh["name"],
            "behavior.train",
            {
                "id": baseline_id,
                "revision": revision,
                "digest": digest,
                "events": total,
                "indexes": definition["indexes"],
            },
        )
        return _public(
            db.execute(
                "SELECT * FROM behavior_baselines WHERE id=?", (baseline_id,)
            ).fetchone(),
            True,
        )


def get(store, who, baseline_id):
    with principal.transaction(store, who) as (db, actor):
        row, _ = _load(db, actor, baseline_id)
        return _public(row, True)


def list_baselines(store, who):
    with principal.transaction(store, who) as (db, actor):
        rows = db.execute(
            "SELECT id FROM behavior_baselines WHERE tenant=? ORDER BY created DESC,id",
            (actor["tenant"],),
        ).fetchall()
        # Durable inventory/history has no lifetime record-count ceiling.
        result = []
        for row in rows:
            try:
                value, _ = _load(db, actor, row["id"])
            except (KeyError, PermissionError):
                continue
            result.append(_public(value))
        return result


def _evidence(row, off=False):
    prefix = "off" if off else "first"
    return {
        "event_id": row[prefix + "_id"],
        "event_time": row["off_time" if off else "first_time"],
        "index": row[prefix + "_index"],
    }


def entity_page(store, who, baseline_id, start, end, after=None, cancel=None, limit=16):
    """Scheduler-only exact entity paging; manual preview retains its explicit bounds."""
    with principal.transaction(store, who) as (db, actor):
        baseline, _ = _load(db, actor, baseline_id)
    definition = json.loads(baseline["definition"])
    value = column(definition["entity_field"])
    scope, args = index_predicate(definition["indexes"])
    sql = (
        "SELECT DISTINCT CAST("
        + value
        + " AS VARCHAR) AS entity FROM events_all WHERE tenant=? AND event_time>=? AND event_time<? AND "
        + scope
        + " AND "
        + value
        + " IS NOT NULL AND CAST("
        + value
        + " AS VARCHAR)<>''"
    )
    values = [actor["tenant"], start, end, *args]
    if definition["entity_field"] == "host":
        sql += " AND host<>'unknown'"
    if after is not None:
        sql += " AND CAST(" + value + " AS VARCHAR)>?"
        values.append(after)
    sql += " ORDER BY entity LIMIT ?"
    values.append(limit)
    return [
        row["entity"]
        for row in store.analytics_query(sql, values, cancel=cancel, max_rows=limit)[
            "rows"
        ]
    ]


def authorized_count(store, who, baseline_id, start, end, cancel=None):
    with principal.transaction(store, who) as (db, actor):
        baseline, _ = _load(db, actor, baseline_id)
    scope, args = index_predicate(json.loads(baseline["indexes"]))
    return store.analytics_query(
        "SELECT count(*) AS n FROM events_all WHERE tenant=? AND event_time>=? AND event_time<? AND "
        + scope,
        [actor["tenant"], start, end, *args],
        cancel=cancel,
        max_rows=1,
    )["rows"][0]["n"]


def coverage(store, who, baseline_id, start, end, cancel=None):
    with principal.transaction(store, who) as (db, actor):
        baseline, _ = _load(db, actor, baseline_id)
    definition = json.loads(baseline["definition"])
    entity = column(definition["entity_field"])
    valid = entity + " IS NOT NULL AND CAST(" + entity + " AS VARCHAR)<>''"
    if definition["entity_field"] == "host":
        valid += " AND host<>'unknown'"
    scope, args = index_predicate(definition["indexes"])
    return store.analytics_query(
        "SELECT count(*) AS scanned_events,count(DISTINCT CAST("
        + entity
        + " AS VARCHAR)) FILTER(WHERE "
        + valid
        + ") AS scanned_entities "
        "FROM events_all WHERE tenant=? AND event_time>=? AND event_time<? AND "
        + scope,
        [actor["tenant"], start, end, *args],
        cancel=cancel,
        max_rows=1,
    )["rows"][0]


def evaluate(
    store,
    who,
    baseline_id,
    start,
    end,
    cancel=None,
    run_key=None,
    *,
    selected_entities=None,
):
    with principal.transaction(store, who) as (db, actor):
        baseline, owner = _load(db, actor, baseline_id)
        if run_key is not None:
            if not isinstance(run_key, str) or not 1 <= len(run_key) <= 256:
                raise ValueError("Behavior run key requires 1..256 characters")
            run_id = hashlib.sha256(
                encode(
                    [
                        baseline_id,
                        baseline["digest"],
                        start,
                        end,
                        run_key,
                        selected_entities,
                    ]
                ).encode()
            ).hexdigest()
            previous = db.execute(
                "SELECT * FROM behavior_runs WHERE id=? AND tenant=?",
                (run_id, actor["tenant"]),
            ).fetchone()
            if previous:
                if (
                    previous["owner"] != actor["name"]
                    or previous["digest"] != baseline["digest"]
                ):
                    raise PermissionError("Behavior cached run is unavailable")
                return {
                    "id": run_id,
                    **json.loads(previous["result"]),
                    "duplicate": True,
                }
    definition, snapshot = (
        json.loads(baseline["definition"]),
        json.loads(baseline["snapshot"]),
    )
    start, end = _aligned(start, end, definition["bucket_seconds"])
    if start < definition["end"]:
        raise ValueError(
            "Evaluation must start at or after training end; train/evaluation leakage is forbidden"
        )
    until = deadline(store)
    rows, authorized = _groups(
        store,
        actor,
        definition,
        start,
        end,
        until,
        cancel,
        snapshot["models"],
        selected_entities,
    )
    counts, hosts, off_counts, first, off_first = {}, {}, {}, {}, {}
    for row in rows:
        key = (row["entity"], row["bucket"])
        counts[key] = counts.get(key, 0) + row["n"]
        if key not in first or (row["first_time"], row["first_id"]) < (
            first[key]["first_time"],
            first[key]["first_id"],
        ):
            first[key] = row
        hosts.setdefault(row["entity"], {}).setdefault(row["host"], []).append(row)
        off_counts[key] = off_counts.get(key, 0) + row["off_count"]
        if row["off_count"] and (
            key not in off_first
            or (row["off_time"], row["off_id"])
            < (off_first[key]["off_time"], off_first[key]["off_id"])
        ):
            off_first[key] = row
    anomalies = []
    seasonal_warmup = []
    volume_observations, volume_outliers = 0, 0

    def emit(kind, entity, count, explanation, evidence, **facts):
        if len(anomalies) >= MAX_ANOMALIES:
            raise CapacityError(
                "Anomaly bound exceeded (200); narrow evaluation window"
            )
        anomalies.append(
            {
                "type": kind,
                "entity": entity,
                "count": count,
                "explanation": explanation,
                "evidence": [evidence],
                "evidence_limit": 1,
                "evidence_is_sample": count > 1,
                **facts,
            }
        )

    if snapshot["ready"]:
        for (entity, bucket), count in counts.items():
            _check_stop(until, cancel)
            model = snapshot["models"].get(entity)
            bucket_start = start + bucket * definition["bucket_seconds"]
            if definition.get("count_method")=="peer_robust_mad":
                from . import peer_behavior

                peer=peer_behavior.profile(snapshot,definition,entity,
                                           first[(entity,bucket)]["slot_id"] if definition.get("seasonality")=="hour_of_week" else None)
                if not peer["ready"]:
                    seasonal_warmup.append({"entity":entity,"bucket_start":bucket_start,"reason":"peer_scope_or_population_not_ready","peer":peer})
                else:
                    volume_observations+=1
                    if count>=peer["threshold"] and count>peer["median"]:
                        volume_outliers+=1
                        emit("peer_volume",entity,count,"Observed count exceeds role-matched leave-target-out immutable median/MAD threshold",
                             _evidence(first[(entity,bucket)]),bucket_start=bucket_start,peer=peer,threshold=peer["threshold"],count_method="peer_robust_mad")
            elif model and model["ready"]:
                selected_model = model
                if definition.get("seasonality") == "hour_of_week":
                    selected_model = model.get("seasonal_slots", {}).get(
                        str(first[(entity, bucket)]["slot_id"])
                    )
                    if not selected_model or not selected_model.get("ready"):
                        seasonal_warmup.append(
                            {
                                "entity": entity,
                                "slot": first[(entity, bucket)]["slot_id"],
                                "bucket_start": bucket_start,
                            }
                        )
                        selected_model = None
                mean, sd = (
                    (selected_model["mean"], selected_model["stddev"])
                    if selected_model
                    else (0, 0)
                )
                zscore = (count - mean) / sd if sd else None
                # With zero variance, require an explicit additive z_threshold excess.
                threshold = (
                    mean + definition["z_threshold"] * sd
                    if sd
                    else mean + definition["z_threshold"]
                )
                robust = definition.get("count_method") == "robust_mad"
                if robust and selected_model:
                    threshold = selected_model["median"] + definition.get(
                        "robust_multiplier", 3
                    ) * max(1, selected_model["mad"])
                    mean = selected_model["median"]
                    zscore = None
                if selected_model:
                    volume_observations += 1
                if selected_model and count >= threshold and count > mean:
                    volume_outliers += 1
                    emit(
                        "volume",
                        entity,
                        count,
                        "Observed bucket count exceeds the configured immutable median/MAD threshold"
                        if robust
                        else "Observed bucket count exceeds the trained mean by the configured dispersion threshold",
                        _evidence(first[(entity, bucket)]),
                        bucket_start=bucket_start,
                        mean=mean,
                        stddev=sd,
                        z_score=zscore,
                        threshold=threshold,
                        zero_variance=not bool(sd),
                        count_method=definition.get("count_method", "count_zscore"),
                        median=selected_model.get("median"),
                        mad=selected_model.get("mad"),
                        seasonal_slot=first[(entity, bucket)]["slot_id"]
                        if definition.get("seasonality") == "hour_of_week"
                        else None,
                    )
            if off_counts[(entity, bucket)] >= definition["novelty_min_events"]:
                emit(
                    "off_hours",
                    entity,
                    off_counts[(entity, bucket)],
                    "Explicit local business-hours policy matched events outside the permitted hours/weekdays",
                    _evidence(off_first[(entity, bucket)], True),
                    bucket_start=bucket_start,
                    business_hours_utc=definition["business_hours_utc"],
                    timezone=definition.get("timezone", "UTC"),
                )
        for entity, entity_hosts in hosts.items():
            model = snapshot["models"].get(entity)
            all_rows = [row for group in entity_hosts.values() for row in group]
            total = sum(row["n"] for row in all_rows)
            first_row = min(
                all_rows, key=lambda row: (row["first_time"], row["first_id"])
            )
            if not model and total >= definition["novelty_min_events"]:
                emit(
                    "new_entity",
                    entity,
                    total,
                    "Entity was absent from the immutable training snapshot",
                    _evidence(first_row),
                )
            elif model and model["ready"]:
                novel = [row for row in all_rows if row["novel_n"]]
                host_count = sum(row["novel_n"] for row in novel)
                if host_count >= definition["novelty_min_events"]:
                    sample = min(
                        novel, key=lambda row: (row["novel_time"], row["novel_id"])
                    )
                    host_pairs = sum(row["novel_hosts"] for row in novel)
                    host_sample = sorted(
                        {
                            host
                            for row in novel
                            for host in json.loads(row["novel_hosts_sample"] or "[]")
                        }
                    )[:20]
                    emit(
                        "new_host",
                        entity,
                        host_count,
                        "Exact novelty-event count across all hosts; displayed host names and original evidence are a bounded sample, ownership is not inferred",
                        {
                            "event_id": sample["novel_id"],
                            "event_time": sample["novel_time"],
                            "index": sample["novel_index"],
                        },
                        host=host_sample[0] if host_pairs == 1 else None,
                        hosts_sample=host_sample,
                        novel_host_bucket_pairs=host_pairs,
                        host_sample_truncated=host_pairs > len(host_sample),
                        complete_novel_event_count=True,
                    )
    _check_stop(until, cancel)
    matched = sum(row["n"] for row in rows)
    result = {
        "baseline_id": baseline_id,
        "baseline_revision": baseline["revision"],
        "baseline_digest": baseline["digest"],
        "start": start,
        "end": end,
        "matched_events": matched,
        "authorized_events": authorized,
        "missing_entity_events": authorized - matched,
        "entities": len(hosts),
        "state": "ready" if snapshot["ready"] else "warmup",
        "anomalies": anomalies,
        "training": {
            "start": definition["start"],
            "end": definition["end"],
            "matched_events": snapshot["matched_events"],
            "min_samples": definition["min_samples"],
            "min_buckets": definition["min_buckets"],
        },
        "complete_counts": True,
        "limits": {
            "groups": MAX_GROUPS,
            "entities": MAX_ENTITIES,
            "anomalies": MAX_ANOMALIES,
            "evidence_per_anomaly": 1,
        },
        "automatic_detection": False,
        "method": definition.get("count_method", "count_zscore"),
        "timezone": definition.get("timezone", "UTC"),
        "seasonality": definition.get("seasonality", "none"),
        "seasonal_warmup": seasonal_warmup,
        "partition_entities": selected_entities,
        "quality": {
            "baseline_age_seconds": max(0, end - definition["end"]),
            "stale": end - definition["end"]
            > definition.get("max_baseline_age_seconds", 30 * 86400),
            "training_review_required": any(
                model.get("quality", {}).get("review_required", False)
                for model in snapshot["models"].values()
            ),
            "volume_observed_buckets": volume_observations,
            "volume_outlier_buckets": volume_outliers,
            "volume_outlier_fraction": volume_outliers / volume_observations
            if volume_observations
            else None,
            "shadow_retraining_review_required": volume_observations >= 10
            and volume_outliers / volume_observations > 0.2,
            "drift_semantics": "Observed volume threshold exceedance is a review signal, not proof of benign drift; baseline is never changed automatically",
            "malicious_training_contamination_excluded": False,
            "probability_calibrated": False,
            "stale_action": "preserve signals and request shadow retraining; never automatically allow anomalous activity",
        },
    }
    packed = encode(result)
    if len(packed.encode()) > 1024 * 1024:
        raise CapacityError("Behavior run exceeds 1 MiB")
    with principal.transaction(store, actor, write=True) as (db, fresh):
        current, fresh_owner = _load(db, fresh, baseline_id)
        if (
            fresh != actor
            or fresh_owner != owner
            or current["digest"] != baseline["digest"]
        ):
            raise PermissionError(
                "Behavior permissions or snapshot changed during evaluation"
            )
        run_id = run_id if run_key is not None else str(uuid.uuid4())
        previous = db.execute(
            "SELECT * FROM behavior_runs WHERE id=?", (run_id,)
        ).fetchone()
        if previous:
            return {"id": run_id, **json.loads(previous["result"]), "duplicate": True}
        db.execute(
            "INSERT INTO behavior_runs VALUES(?,?,?,?,?,?,?,?,?)",
            (
                run_id,
                actor["tenant"],
                actor["name"],
                baseline_id,
                time.time(),
                start,
                end,
                baseline["digest"],
                packed,
            ),
        )
        from . import analysis_history

        retention = analysis_history.retain(db, actor["tenant"], "behavior_runs")
        if retention["archived_bodies"]:
            store.audit(
                db,
                actor["tenant"],
                actor["name"],
                "behavior.history.archive",
                retention,
            )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "behavior.evaluate",
            {
                "id": run_id,
                "baseline_id": baseline_id,
                "digest": baseline["digest"],
                "events": result["matched_events"],
                "anomalies": len(anomalies),
                "indexes": definition["indexes"],
            },
        )
    return {"id": run_id, **result}


def get_run(store, who, run_id):
    with principal.transaction(store, who) as (db, actor):
        row = db.execute(
            "SELECT * FROM behavior_runs WHERE tenant=? AND id=?",
            (actor["tenant"], run_id),
        ).fetchone()
        if not row or (row["owner"] != actor["name"] and actor["role"] != "admin"):
            raise KeyError("Behavior run not found")
        _load(db, actor, row["baseline_id"])
        return {"id": row["id"], "created": row["created"], **json.loads(row["result"])}


def list_runs(store, who, baseline_id=None):
    with principal.transaction(store, who) as (db, actor):
        args, where = [actor["tenant"]], "tenant=?"
        if baseline_id is not None:
            _load(db, actor, baseline_id)
            where += " AND baseline_id=?"
            args.append(baseline_id)
        rows = db.execute(
            "SELECT id,owner,baseline_id,created,start,end,digest FROM behavior_runs WHERE "
            + where
            + " ORDER BY created DESC,id",
            args,
        ).fetchall()
        # Permanent execution/investigation history has no lifetime count ceiling.
        result = []
        for row in rows:
            if row["owner"] != actor["name"] and actor["role"] != "admin":
                continue
            try:
                _load(db, actor, row["baseline_id"])
            except (KeyError, PermissionError):
                continue
            result.append(dict(row))
        return result
