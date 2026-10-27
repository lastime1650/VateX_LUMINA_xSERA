"""Evidence-backed feature UEBA with immutable training and visible cold starts.

Reported byte deltas, known authentication outcomes, process-name pairs and
file change activity are statistical observations. They neither establish
malice nor authorize an endpoint action. Missing telemetry is never zero.
"""

import hashlib
import json
import math
import statistics
import time
import uuid

from . import behavior, evidence_scope as evidence, migrations, principal
from .entities import deadline, query
from .query import column, index_predicate
from .storage import CapacityError, ConflictError, encode

EDIT = ("admin", "analyst")
FEATURES = ("network_bytes_out", "authentication_failure_ratio", "file_change_count")
BYTE_FIELDS = ("raw.security.bytes_out", "raw.xdr.data.network.bytes_out", "raw.network.bytes_out")
FILE_ACTIONS = {"file_create", "file_created", "file_write", "file_modify", "file_modified", "file_change", "file_changed", "file_delete", "file_deleted", "file_rename"}
MAX_EVENTS = 10000
MAX_ANOMALIES = 200
MAX_EVIDENCE = 256
CONTRACT = {
    "version": "xsera.ueba-features.v1",
    "bytes": "Typed nonnegative per-event byte deltas; cumulative counters require a source-specific delta adapter",
    "authentication": "Only explicit authentication actions with known success/failure outcomes enter the denominator",
    "lineage": "Novel reported parent/child names on creation events; process inventory does not establish execution",
    "file_activity": "Explicit file change actions only; absence of events is not proof of absence of changes",
    "probability_calibrated": False,
}


def initialize(store):
    with store.control(local=True) as db:
        schema = """
        CREATE TABLE IF NOT EXISTS behavior_feature_baselines(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,name TEXT NOT NULL,
          revision INTEGER NOT NULL,created REAL NOT NULL,indexes TEXT NOT NULL,
          definition TEXT NOT NULL,snapshot TEXT NOT NULL,digest TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS behavior_feature_owner
          ON behavior_feature_baselines(tenant,owner,created);
        CREATE TABLE IF NOT EXISTS behavior_feature_runs(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,baseline_id TEXT NOT NULL,
          created REAL NOT NULL,start REAL NOT NULL,end REAL NOT NULL,digest TEXT NOT NULL,
          result TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS behavior_feature_schedules(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,baseline_id TEXT NOT NULL,
          indexes TEXT NOT NULL,enabled INTEGER NOT NULL,interval INTEGER NOT NULL,
          version INTEGER NOT NULL,next_run REAL NOT NULL,last_end REAL,error TEXT,
          UNIQUE(tenant,baseline_id));
        """
        migrations.apply(db, "behavior_features", 1, [part.strip() for part in schema.split(";") if part.strip()])


def _definition(data):
    allowed = {"name", "entity_field", "indexes", "start", "end", "bucket_seconds",
        "min_samples", "min_buckets", "robust_multiplier", "seasonality", "timezone",
        "seasonality_min_buckets", "count_method", "peer_groups", "peer_min_entities",
        "max_baseline_age_seconds", "min_feature_events", "byte_fields"}
    if not isinstance(data, dict) or set(data)-allowed:
        raise ValueError("Unknown feature baseline property")
    common = {key: value for key, value in data.items() if key not in {"min_feature_events", "byte_fields"}}
    common.setdefault("count_method", "robust_mad")
    definition = behavior._definition(common)
    if definition["count_method"] not in {"robust_mad", "peer_robust_mad"}:
        raise ValueError("Feature baselines use robust_mad or peer_robust_mad")
    definition["min_feature_events"] = evidence.integer(data.get("min_feature_events", 1), "min_feature_events", 1, 10000)
    fields = data.get("byte_fields", list(BYTE_FIELDS))
    if not isinstance(fields, list) or not fields or len(fields)>8 or any(not isinstance(value, str) for value in fields) or len(set(fields))!=len(fields):
        raise ValueError("1..8 distinct scalar byte delta fields required")
    for path in fields:
        evidence.field({}, path)
    definition["byte_fields"] = fields
    definition["feature_contract"] = CONTRACT
    return definition


def _load(db, actor, identifier):
    row = db.execute("SELECT * FROM behavior_feature_baselines WHERE tenant=? AND id=?", (actor["tenant"], identifier)).fetchone()
    if not row or (row["owner"] != actor["name"] and actor["role"] != "admin") or not principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
        raise KeyError("Feature baseline not found")
    owner = principal.current(db, {"name": row["owner"], "tenant": row["tenant"], "role": "analyst", "allowed_indexes": json.loads(row["indexes"])}, EDIT)
    if not principal.contains(owner["allowed_indexes"], json.loads(row["indexes"])):
        raise PermissionError("Baseline owner lost required index permissions")
    return dict(row)


def _public(row):
    result = dict(row)
    for name in ("indexes", "definition", "snapshot"):
        result[name] = json.loads(result[name])
    return result


def get(store, who, identifier):
    with principal.transaction(store, who) as (db, actor):
        return _public(_load(db, actor, identifier))


def list_baselines(store, who):
    with principal.transaction(store, who) as (db, actor):
        items = []
        for row in db.execute("SELECT id FROM behavior_feature_baselines WHERE tenant=? ORDER BY created DESC,id LIMIT 201", (actor["tenant"],)):
            try:
                value = _public(_load(db, actor, row["id"]))
            except (KeyError, PermissionError):
                continue
            items.append({key: value[key] for key in ("id", "name", "revision", "indexes", "created", "digest")})
            if len(items)>200:
                raise CapacityError("Feature inventory exceeds 200 visible baselines; use a narrower inventory scope")
        return items


def _records(store, actor, definition, start, end, until, cancel):
    predicate, args = index_predicate(definition["indexes"])
    field = column(definition["entity_field"])
    rows = query(store, "SELECT event_id,event_time,index_name,raw,host,CAST("+field+
        " AS VARCHAR) AS entity FROM events_all WHERE tenant=? AND event_time>=? AND event_time<? AND "+predicate+
        " ORDER BY event_time,event_id LIMIT 10001", [actor["tenant"], start, end, *args], until, MAX_EVENTS, cancel)["rows"]
    if len(rows)>MAX_EVENTS:
        raise CapacityError("Feature window exceeds 10000 events; narrow indexes/time")
    for row in rows:
        row["raw"] = json.loads(row["raw"]) if isinstance(row["raw"], str) else row["raw"]
    return rows


def _first(record, paths):
    return next((value for path in paths if (value := evidence.field(record, path)) is not None), None)


def _features(record, definition):
    byte = _first(record, definition["byte_fields"])
    byte = float(byte) if type(byte) in (int, float) and math.isfinite(byte) and 0<=byte<=2**53 else None
    action = _first(record, ("raw.security.action", "raw.xdr.data.event.action", "raw.event.action"))
    outcome = _first(record, ("raw.security.outcome", "raw.xdr.data.event.outcome", "raw.event.outcome"))
    auth = action in {"authentication", "authenticate", "login", "logon", "login_failed", "login_success", "authentication_failure", "authentication_success"}
    known_auth = auth and outcome in {"success", "failure"}
    parent = _first(record, ("raw.xdr.data.process.parent.name", "raw.process.parent.name"))
    child = _first(record, ("raw.xdr.data.process.name", "raw.process.name"))
    pair = [parent, child] if action in {"process_create", "process_created", "process_start"} and all(isinstance(value, str) and 1<=len(value)<=256 for value in (parent, child)) else None
    return {"byte": byte, "known_auth": known_auth, "auth_failed": known_auth and outcome=="failure",
            "file_changed": action in FILE_ACTIONS, "lineage": encode(pair) if pair else None}


def _aggregate(records, definition, start, until, cancel):
    groups, missing = {}, 0
    for record in records:
        behavior._check_stop(until, cancel)
        entity = record["entity"]
        if not isinstance(entity, str) or not 1<=len(entity)<=256 or (definition["entity_field"]=="host" and entity=="unknown"):
            missing += 1
            continue
        position = int((record["event_time"]-start)//definition["bucket_seconds"])
        group = groups.setdefault((entity, position), {"bytes": 0., "byte_ids": [], "auth_ids": [],
            "auth_failures": 0, "file_ids": [], "lineages": {}, "index_by_id": {}, "events": 0})
        group["events"] += 1
        group["index_by_id"][record["event_id"]] = record["index_name"]
        values = _features(record, definition)
        if values["byte"] is not None:
            group["bytes"] += values["byte"]
            group["byte_ids"].append(record["event_id"])
        if values["known_auth"]:
            group["auth_ids"].append(record["event_id"])
            group["auth_failures"] += int(values["auth_failed"])
        if values["file_changed"]:
            group["file_ids"].append(record["event_id"])
        if values["lineage"]:
            group["lineages"].setdefault(values["lineage"], []).append(record["event_id"])
        if len({name for name, _ in groups})>500:
            raise CapacityError("Feature window exceeds 500 entities")
    return groups, missing


def _values(group, definition):
    minimum = definition["min_feature_events"]
    return {
        "network_bytes_out": group["bytes"] if len(group["byte_ids"])>=minimum else None,
        "authentication_failure_ratio": group["auth_failures"]/len(group["auth_ids"]) if len(group["auth_ids"])>=minimum else None,
        "file_change_count": len(group["file_ids"]) if len(group["file_ids"])>=minimum else None,
    }


def _stat(values, samples, definition, minimum_buckets=None):
    median = statistics.median(values) if values else None
    mad = statistics.median(abs(value-median) for value in values) if values else None
    return {"median": median, "mad": mad, "observed_buckets": len(values), "samples": samples,
            "ready": len(values)>=(minimum_buckets or definition["min_buckets"]) and samples>=definition["min_samples"]}


def train(store, who, data, cancel=None):
    definition = _definition(data)
    with principal.transaction(store, who, EDIT) as (_, actor):
        if not principal.contains(actor["allowed_indexes"], definition["indexes"]):
            raise PermissionError("Feature training indexes exceed current permissions")
    until = deadline(store)
    rows = _records(store, actor, definition, definition["start"], definition["end"], until, cancel)
    groups, missing = _aggregate(rows, definition, definition["start"], until, cancel)
    stamps = [definition["start"]+i*definition["bucket_seconds"] for i in range(int((definition["end"]-definition["start"])/definition["bucket_seconds"]))]
    # DuckDB validates the IANA zone also when training has no observations.
    slots = behavior._slot_keys(store, definition, stamps, cancel)
    models = {}
    for (entity, position), group in groups.items():
        model = models.setdefault(entity, {"features": {}, "lineages": {}, "events": 0})
        model["events"] += group["events"]
        for pair, ids in group["lineages"].items():
            model["lineages"][pair] = model["lineages"].get(pair, 0)+len(ids)
            if len(model["lineages"])>512:
                raise CapacityError("Training entity exceeds 512 lineage pairs")
        for feature, value in _values(group, definition).items():
            if value is None:
                continue
            stat = model["features"].setdefault(feature, {"values": [], "samples": 0, "slots": {}})
            count = len(group[{"network_bytes_out": "byte_ids", "authentication_failure_ratio": "auth_ids", "file_change_count": "file_ids"}[feature]])
            stat["values"].append(value)
            stat["samples"] += count
            slot = str(slots[stamps[position]])
            seasonal = stat["slots"].setdefault(slot, {"values": [], "samples": 0})
            seasonal["values"].append(value)
            seasonal["samples"] += count
    for model in models.values():
        model["lineage_ready"] = model["events"]>=definition["min_samples"] and sum(model["lineages"].values())>=definition["min_samples"]
        for feature, stat in list(model["features"].items()):
            model["features"][feature] = {**_stat(stat["values"], stat["samples"], definition),
                "seasonal_slots": {slot: _stat(value["values"], value["samples"], definition, definition["seasonality_min_buckets"])
                    for slot, value in stat["slots"].items()}}
    dataset_digest = hashlib.sha256(encode([[row["event_id"], row["index_name"], row["event_time"], hashlib.sha256(encode(row["raw"]).encode()).hexdigest()] for row in rows]).encode()).hexdigest()
    snapshot = {"schema": CONTRACT["version"], "models": models, "events": len(rows), "missing_entity_events": missing,
        "ready": any(model["lineage_ready"] or any(stat["ready"] for stat in model["features"].values()) for model in models.values()),
        "dataset_digest": dataset_digest, "known_training_contamination_excluded": False,
        "sensor_loss_excluded": False, "missing_buckets_are_zero": False, "contract": CONTRACT}
    if len(encode(snapshot).encode())>2*1024*1024:
        raise CapacityError("Feature snapshot exceeds 2 MiB")
    digest = hashlib.sha256(encode([definition, snapshot]).encode()).hexdigest()
    behavior._check_stop(until, cancel)
    with principal.transaction(store, actor, EDIT, write=True) as (db, fresh):
        if actor!=fresh or not principal.contains(fresh["allowed_indexes"], definition["indexes"]):
            raise PermissionError("Feature training permissions changed")
        revision = db.execute("SELECT coalesce(max(revision),0)+1 FROM behavior_feature_baselines WHERE tenant=? AND owner=? AND name=?", (actor["tenant"], actor["name"], definition["name"])).fetchone()[0]
        identifier = str(uuid.uuid4())
        db.execute("INSERT INTO behavior_feature_baselines VALUES(?,?,?,?,?,?,?,?,?,?)", (identifier, actor["tenant"], actor["name"], definition["name"], revision, time.time(), encode(definition["indexes"]), encode(definition), encode(snapshot), digest))
        store.audit(db, actor["tenant"], actor["name"], "behavior.features.train", {"id": identifier, "digest": digest, "revision": revision, "indexes": definition["indexes"], "events": len(rows)})
        return _public(db.execute("SELECT * FROM behavior_feature_baselines WHERE id=?", (identifier,)).fetchone())


def _profile(snapshot, definition, entity, feature, slot):
    model = snapshot["models"].get(entity, {})
    selected = model.get("features", {}).get(feature)
    if definition["seasonality"]=="hour_of_week":
        selected = selected.get("seasonal_slots", {}).get(str(slot)) if selected else None
    if definition["count_method"]=="peer_robust_mad":
        role = definition["peer_groups"].get(entity)
        values, names = [], []
        if role:
            for name, peer in snapshot["models"].items():
                if name==entity or definition["peer_groups"].get(name)!=role:
                    continue
                stat = peer.get("features", {}).get(feature)
                if definition["seasonality"]=="hour_of_week":
                    stat = stat.get("seasonal_slots", {}).get(str(slot)) if stat else None
                if stat and stat["ready"]:
                    values.append(stat["median"])
                    names.append(name)
        ready = len(values)>=definition["peer_min_entities"]
        median = statistics.median(values) if ready else None
        return {"ready": ready, "median": median, "mad": statistics.median(abs(value-median) for value in values) if ready else None,
                "peers": sorted(names), "leave_target_out": True, "reason": "peer_or_seasonal_cold_start"}
    return {**(selected or {"ready": False}), "reason": "entity_or_seasonal_cold_start"}


def evaluate(store, who, identifier, start, end, cancel=None, *, publish=False, mode="live", _schedule_guard=None):
    if type(publish) is not bool:
        raise ValueError("Typed publish boolean required")
    evidence.choice(mode, {"live", "shadow"}, "feature evaluation mode")
    with principal.transaction(store, who, EDIT if publish else ("admin", "analyst", "viewer")) as (db, actor):
        baseline = _load(db, actor, identifier)
    definition, snapshot = json.loads(baseline["definition"]), json.loads(baseline["snapshot"])
    start, end = behavior._aligned(start, end, definition["bucket_seconds"])
    if start<definition["end"]:
        raise ValueError("Evaluation must follow training; train/evaluation leakage is forbidden")
    until = deadline(store)
    records = _records(store, actor, definition, start, end, until, cancel)
    groups, missing = _aggregate(records, definition, start, until, cancel)
    stamps = [start+i*definition["bucket_seconds"] for i in range(int((end-start)/definition["bucket_seconds"]))]
    slots = behavior._slot_keys(store, definition, stamps, cancel)
    anomalies, warmup = [], []
    stale = end-definition["end"]>definition["max_baseline_age_seconds"]

    def emit(entity, feature, value, ids, group, bucket, **facts):
        if len(anomalies)>=MAX_ANOMALIES or len(ids)>MAX_EVIDENCE:
            raise CapacityError("Feature anomaly/evidence bound exceeded; narrow the evaluation window")
        anomalies.append({"entity": entity, "entity_field": definition["entity_field"], "feature": feature,
            "value": value, "event_ids": sorted(ids), "indexes": sorted({group["index_by_id"][value] for value in ids}),
            "bucket_start": bucket, "confidence_grade": "statistical_deviation", "probability_calibrated": False,
            "response_authorized": False, **facts})

    for (entity, position), group in groups.items():
        behavior._check_stop(until, cancel)
        bucket = start+position*definition["bucket_seconds"]
        for feature, value in _values(group, definition).items():
            profile = _profile(snapshot, definition, entity, feature, slots[bucket])
            if value is None or not profile["ready"] or stale:
                warmup.append({"entity": entity, "feature": feature, "bucket_start": bucket, "reason": "stale_baseline" if stale else "missing_feature_observation" if value is None else profile["reason"]})
                continue
            floor = .05 if feature=="authentication_failure_ratio" else 1
            threshold = profile["median"]+definition["robust_multiplier"]*max(floor, 1.4826*profile["mad"])
            if value>profile["median"] and value>=threshold:
                ids = group[{"network_bytes_out": "byte_ids", "authentication_failure_ratio": "auth_ids", "file_change_count": "file_ids"}[feature]]
                emit(entity, feature, value, ids, group, bucket, threshold=threshold, profile=profile)
        model = snapshot["models"].get(entity)
        if not stale and model and model["lineage_ready"]:
            for pair, ids in group["lineages"].items():
                if pair not in model["lineages"]:
                    emit(entity, "rare_process_lineage", len(ids), ids, group, bucket,
                         parent_child_names=json.loads(pair), threshold=None,
                         explanation="Reported parent/child name pair absent from immutable training; causal identity and malice are unproven")
        elif group["lineages"]:
            warmup.append({"entity": entity, "feature": "rare_process_lineage", "bucket_start": bucket, "reason": "stale_baseline" if stale else "lineage_cold_start"})
    run_id = str(uuid.uuid4())
    result = {"id": run_id, "schema": CONTRACT["version"], "baseline_id": identifier, "baseline_digest": baseline["digest"],
        "baseline_revision": baseline["revision"], "start": start, "end": end, "events": len(records),
        "missing_entity_events": missing, "state": "stale" if stale else "ready" if snapshot["ready"] else "warmup",
        "anomalies": anomalies, "warmup": warmup, "probability_calibrated": False, "response_authorized": False,
        "quality": {"sensor_loss_excluded": False, "training_contamination_excluded": False, "missing_buckets_are_zero": False},
        "signals": [], "published": publish, "mode": mode}
    if _schedule_guard is not None:
        result["scheduler_contract"] = {"continuity": "oldest_unprocessed_completed_interval",
            "late_arrival_overlap_buckets": 2, "unbounded_lateness_covered": False,
            "scheduled_end": end}
    if len(encode(result).encode())>2*1024*1024:
        raise CapacityError("Feature result exceeds 2 MiB")
    # Original verification in the publisher takes the segment read gate.
    # Acquire it before the control writer, matching indexing/retention order.
    with store.segment_lock.read(deadline=time.monotonic()+3), principal.transaction(store, actor, EDIT if publish else ("admin", "analyst", "viewer"), write=True) as (db, fresh):
        current = _load(db, fresh, identifier)
        if fresh!=actor or current["digest"]!=baseline["digest"]:
            raise PermissionError("Feature evaluation permissions/snapshot changed")
        if _schedule_guard is not None:
            live = db.execute("SELECT * FROM behavior_feature_schedules WHERE id=? AND tenant=?", (_schedule_guard["id"], fresh["tenant"])).fetchone()
            if not live or not live["enabled"] or live["version"]!=_schedule_guard["version"] or live["owner"]!=fresh["name"] or live["last_end"]!=_schedule_guard["last_end"] or live["next_run"]!=_schedule_guard["next_run"]:
                raise ConflictError("Feature schedule changed while evaluating; no signal published")
        if publish:
            result["signals"] = _publish(db, store, fresh, baseline, definition, anomalies, mode)
        db.execute("INSERT INTO behavior_feature_runs VALUES(?,?,?,?,?,?,?,?,?)", (run_id, actor["tenant"], actor["name"], identifier, time.time(), start, end, baseline["digest"], encode(result)))
        store.audit(db, actor["tenant"], actor["name"], "behavior.features.evaluate", {"id": run_id, "baseline_id": identifier, "anomalies": len(anomalies), "published": publish})
    return result


def _publish(db, store, actor, baseline, definition, anomalies, mode):
    """Publisher is provided by the common Signal layer; no autonomous effects."""
    from . import intelligence

    published = []
    for anomaly in anomalies:
        # Evidence pages share one dependency unit. A multi-page byte anomaly is
        # one observation, rather than multiple independent votes for malice.
        dependency = hashlib.sha256(encode([actor["tenant"], baseline["digest"], anomaly]).encode()).hexdigest()
        pages = [anomaly["event_ids"][offset:offset+32] for offset in range(0, len(anomaly["event_ids"]), 32)]
        for number, ids in enumerate(pages, 1):
            payload = {"kind": "behavior", "rule_id": baseline["id"], "rule_revision": baseline["revision"],
                "event_ids": ids,
                "entity_key": "UEBA-"+hashlib.sha256(encode([actor["tenant"], definition["indexes"], anomaly["entity_field"], anomaly["entity"]]).encode()).hexdigest(),
                "features": {"feature": anomaly["feature"], "value": anomaly["value"],
                    "threshold": anomaly.get("threshold"), "baseline_digest": baseline["digest"], "probability_calibrated": False},
                "severity": "medium", "confidence_grade": "statistical_deviation", "mode": mode,
                "context_digest": baseline["digest"],
                "metadata": {"baseline_digest": baseline["digest"], "feature_contract": CONTRACT["version"],
                    "observation": anomaly, "dependency_group": dependency,
                    "complete_event_count": len(anomaly["event_ids"]), "page_number": number, "page_count": len(pages)}}
            # Common publisher validates every page's original receipts and ACL.
            published.append(intelligence.publish_in_transaction(store, db, actor, payload))
    return published


def get_run(store, who, identifier):
    with principal.transaction(store, who) as (db, actor):
        row = db.execute("SELECT * FROM behavior_feature_runs WHERE tenant=? AND id=?", (actor["tenant"], identifier)).fetchone()
        if not row or (row["owner"]!=actor["name"] and actor["role"]!="admin"):
            raise KeyError("Feature run not found")
        _load(db, actor, row["baseline_id"])
        return json.loads(row["result"])


def schedule(store, who, data):
    if not isinstance(data, dict) or set(data)!={"baseline_id", "enabled", "interval", "version"}:
        raise ValueError("baseline_id, enabled, interval and version required")
    if type(data["enabled"]) is not bool:
        raise ValueError("Typed enabled boolean required")
    interval = evidence.integer(data["interval"], "interval", 60, 86400)
    version = evidence.integer(data["version"], "version", 0, 2**31-1)
    with principal.transaction(store, who, EDIT, write=True) as (db, actor):
        baseline = _load(db, actor, data["baseline_id"])
        definition = json.loads(baseline["definition"])
        if interval!=definition["bucket_seconds"]:
            raise ValueError("Feature schedule interval must equal its aligned baseline bucket")
        old = db.execute("SELECT * FROM behavior_feature_schedules WHERE tenant=? AND baseline_id=?", (actor["tenant"], baseline["id"])).fetchone()
        if (old["version"] if old else 0)!=version:
            raise ConflictError("Feature schedule version changed")
        identifier = old["id"] if old else str(uuid.uuid4())
        now = time.time()
        next_run = math.ceil(now/interval)*interval
        db.execute("INSERT INTO behavior_feature_schedules VALUES(?,?,?,?,?,?,?,?,?,NULL,NULL) "
            "ON CONFLICT(tenant,baseline_id) DO UPDATE SET owner=excluded.owner,enabled=excluded.enabled,"
            "interval=excluded.interval,version=excluded.version,next_run=excluded.next_run,error=NULL",
            (identifier, actor["tenant"], actor["name"], baseline["id"], baseline["indexes"], int(data["enabled"]), interval, version+1, next_run))
        result = {"id": identifier, **data, "version": version+1, "next_run": next_run}
        store.audit(db, actor["tenant"], actor["name"], "behavior.features.schedule", result)
        return result


def schedules(store, who):
    with principal.transaction(store, who) as (db, actor):
        items = []
        for row in db.execute("SELECT * FROM behavior_feature_schedules WHERE tenant=? ORDER BY id", (actor["tenant"],)):
            if row["owner"]!=actor["name"] and actor["role"]!="admin":
                continue
            try:
                _load(db, actor, row["baseline_id"])
            except (KeyError, PermissionError):
                continue
            items.append({**dict(row), "indexes": json.loads(row["indexes"]), "enabled": bool(row["enabled"])})
        return items


def run_due(store, now=None, cancel=None, budget=1., max_runs=2):
    now = evidence.number(time.time() if now is None else now, "scheduler time")
    budget = evidence.number(budget, "budget", .01, 10)
    max_runs = evidence.integer(max_runs, "max_runs", 1, 8)
    until, completed = time.monotonic()+budget, 0
    with store.control() as db:
        rows = [dict(row) for row in db.execute("SELECT * FROM behavior_feature_schedules WHERE enabled=1 AND next_run<=? ORDER BY next_run,id LIMIT ?", (now, max_runs))]
    for row in rows:
        if time.monotonic()>=until or (cancel and cancel.is_set()):
            break
        actor = {"name": row["owner"], "tenant": row["tenant"], "role": "analyst", "allowed_indexes": json.loads(row["indexes"])}
        latest = math.floor(now/row["interval"])*row["interval"]
        # A delayed/restarted worker resumes its earliest unfinished bucket.
        # Two earlier buckets are re-read for bounded late arrival; publisher
        # idempotency preserves identical observations without duplicate votes.
        end = row["last_end"]+row["interval"] if row["last_end"] is not None else row["next_run"]
        if end>latest:
            continue
        try:
            baseline = get(store, actor, row["baseline_id"])
            start = max(baseline["definition"]["end"], end-3*row["interval"])
            # All publication is evidence-idempotent, even if the scheduler is restarted.
            evaluate(store, actor, row["baseline_id"], start, end, cancel, publish=True, _schedule_guard=row)
            with store.control() as db:
                db.execute("UPDATE behavior_feature_schedules SET next_run=?,last_end=?,error=NULL WHERE id=? AND version=? AND next_run=? AND last_end IS ?", (end+row["interval"], end, row["id"], row["version"], row["next_run"], row["last_end"]))
            completed += 1
        except (ValueError, PermissionError, KeyError, CapacityError, ConflictError) as exc:
            with store.control() as db:
                db.execute("UPDATE behavior_feature_schedules SET next_run=?,last_end=COALESCE(last_end,?),error=? WHERE id=? AND version=? AND next_run=? AND last_end IS ?", (now+row["interval"], end-row["interval"], str(exc)[:500], row["id"], row["version"], row["next_run"], row["last_end"]))
    return completed


def register(app, store, runtime, who, body):
    from fastapi import Request
    from starlette.concurrency import run_in_threadpool

    @app.get("/api/v3/behavior/features/baselines")
    async def inventory(request: Request):
        return await run_in_threadpool(list_baselines, store, who(request))

    @app.post("/api/v3/behavior/features/baselines", status_code=201)
    async def training(request: Request):
        return await run_in_threadpool(train, store, who(request, EDIT), await body(request))

    @app.get("/api/v3/behavior/features/baselines/{identifier}")
    async def baseline(identifier: str, request: Request):
        return await run_in_threadpool(get, store, who(request), identifier)

    @app.post("/api/v3/behavior/features/baselines/{identifier}/evaluate")
    async def evaluation(identifier: str, request: Request):
        data = await body(request)
        if not isinstance(data, dict) or set(data)-{"start", "end", "publish", "mode"} or not {"start", "end"}<=set(data):
            raise ValueError("start, end and optional publish/mode required")
        return await run_in_threadpool(evaluate, store, who(request, EDIT), identifier, data["start"], data["end"], publish=data.get("publish", False), mode=data.get("mode", "live"))

    @app.get("/api/v3/behavior/features/runs/{identifier}")
    async def result(identifier: str, request: Request):
        return await run_in_threadpool(get_run, store, who(request), identifier)

    @app.post("/api/v3/behavior/features/schedules", status_code=201)
    async def scheduling(request: Request):
        return await run_in_threadpool(schedule, store, who(request, EDIT), await body(request))

    @app.get("/api/v3/behavior/features/schedules")
    async def schedule_inventory(request: Request):
        return await run_in_threadpool(schedules, store, who(request))
