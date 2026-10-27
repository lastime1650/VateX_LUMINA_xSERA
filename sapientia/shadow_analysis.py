"""Receipt-bound immutable historical comparisons with no operational writes.

The exact legacy detector evaluates a frozen local DuckDB copy. Candidate rules
may address the new derived projection/OCSF view at raw.analysis.projection and
raw.analysis.ocsf. No Case, contribution, SOAR, command, or cursor is emitted.
"""

import copy
import json
import time
import uuid
from types import SimpleNamespace

import duckdb

from . import detections, entities, evidence_scope, identity_resolver, migrations, principal, release_manifest, security_schema
from .query import index_predicate
from .storage import CapacityError, ConflictError, Store, encode

SCHEMA = "xsera.shadow-comparison.v1"
MAX_EVENTS = 5000
MAX_RULES = 16
MAX_BYTES = 16 * 1024 * 1024


def initialize(store):
    migrations.apply_store(store, "shadow_analysis", [
        "CREATE TABLE IF NOT EXISTS shadow_compare_runs(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,indexes TEXT NOT NULL,created REAL NOT NULL,start REAL NOT NULL,end REAL NOT NULL,snapshot_digest TEXT NOT NULL,result_digest TEXT NOT NULL,snapshot TEXT NOT NULL,result TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS shadow_compare_scope ON shadow_compare_runs(tenant,id)",
        "CREATE TABLE IF NOT EXISTS shadow_compare_replays(id TEXT PRIMARY KEY,run_id TEXT NOT NULL,tenant TEXT NOT NULL,owner TEXT NOT NULL,created REAL NOT NULL,snapshot_digest TEXT NOT NULL,result_digest TEXT NOT NULL,identical INTEGER NOT NULL)",
    ])


def _engine():
    from . import normalization, ocsf_mapping, query
    result = {name: release_manifest.hash_file(module.__file__) for name, module in
            (("detector", detections), ("query", query), ("schema", security_schema),
             ("identity", identity_resolver), ("ocsf", ocsf_mapping), ("normalization", normalization))}
    result.update(shadow=release_manifest.hash_file(__file__), duckdb_version=duckdb.__version__)
    return result


def _owner(db, tenant, name, indexes):
    row = db.execute("SELECT role FROM users WHERE tenant=? AND name=?", (tenant, name)).fetchone()
    if not row:
        raise PermissionError("A frozen rule owner is unavailable")
    actor = principal.current(db, {"name": name, "tenant": tenant, "role": row["role"]}, ("admin", "analyst"))
    if not principal.contains(actor["allowed_indexes"], indexes):
        raise PermissionError("A frozen rule owner's current index grants no longer cover the snapshot")


def _context(db, actor, indexes):
    """Pin scoped state; unscoped config is represented by hashes, never secrets."""
    result = {}
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for table in ("source_registry", "parser_policies", "managed_lookups", "entity_inventory",
                  "entity_aliases", "temporal_identity_bindings", "behavior_baselines", "behavior_feature_baselines",
                  "intelligence_policies", "cpu_ml_models", "cpu_ml_active", "cpu_ml_reviews", "ml_models"):
        if table not in tables:
            continue
        columns = {r[1] for r in db.execute("PRAGMA table_info(" + table + ")")}
        if "tenant" not in columns:
            continue
        captured = []
        rows = db.execute("SELECT * FROM " + table + " WHERE tenant=?", (actor["tenant"],)).fetchall()
        if len(rows) > 5000:
            raise CapacityError("Shadow context budget exceeded; narrow the tenant context")
        visible_entities = set()
        if table == "entity_aliases":
            for entity in db.execute("SELECT id,indexes FROM entity_inventory WHERE tenant=?", (actor["tenant"],)):
                if principal.contains(indexes, json.loads(entity["indexes"])):
                    visible_entities.add(entity["id"])
        visible_models = set()
        if table in {"cpu_ml_active", "cpu_ml_reviews"} and "cpu_ml_models" in tables:
            for model in db.execute("SELECT id,indexes FROM cpu_ml_models WHERE tenant=?", (actor["tenant"],)):
                if principal.contains(indexes, json.loads(model["indexes"])):
                    visible_models.add(model["id"])
        for row in rows:
            record = dict(row)
            if "indexes" in columns and not principal.contains(indexes, json.loads(record["indexes"])):
                continue
            if "index_name" in columns and record["index_name"] not in indexes:
                continue
            if table == "entity_aliases" and record["entity_id"] not in visible_entities:
                continue
            if table in {"cpu_ml_active", "cpu_ml_reviews"} and record["model_id"] not in visible_models:
                continue
            # Model weights and tenant-wide parser/TI data stay represented by
            # an immutable fingerprint. Legacy evaluation does not consume them.
            if table in {"parser_policies", "managed_lookups", "cpu_ml_models", "ml_models"}:
                record = {"fingerprint": release_manifest.digest(record),
                          **{k: record[k] for k in ("id", "name", "version", "revision", "digest") if k in record}}
            captured.append(record)
        result[table] = sorted(captured, key=encode)
    if len(encode(result).encode()) > 4 * 1024 * 1024:
        raise CapacityError("Shadow context exceeds 4 MiB")
    return result


def context_status(store, who, indexes):
    indexes = entities.exact_indexes(indexes)
    with principal.transaction(store, who) as (db, actor):
        if not principal.contains(actor["allowed_indexes"], indexes):
            raise PermissionError("Shadow indexes exceed current grants")
        context = _context(db, actor, indexes)
        return {"indexes": indexes, "context_digest": release_manifest.digest(context), "engine": _engine(),
                "projection_version": security_schema.VERSION, "live_effects": False}


def _rules(db, actor, indexes, values, policy_ids=None):
    result = []
    if values is not None:
        if not isinstance(values, list) or len(values) > MAX_RULES:
            raise ValueError("Up to 16 shadow rules per side required")
        for item in values:
            if not isinstance(item, dict) or set(item) != {"id", "definition"}:
                raise ValueError("Shadow rules require exact id and definition fields")
            evidence_scope.text(item["id"], "rule id", 128)
            result.append({"id": item["id"], "owner": actor["name"], "definition": detections.validate(item["definition"])})
    else:
        if policy_ids is not None and (not isinstance(policy_ids, list) or len(policy_ids) > MAX_RULES or any(not isinstance(i,str) or not 1 <= len(i) <= 128 for i in policy_ids) or len(set(policy_ids)) != len(policy_ids)):
            raise ValueError("Up to 16 unique current policy IDs required")
        rows = db.execute("SELECT * FROM correlation_policies WHERE tenant=? ORDER BY id", (actor["tenant"],)).fetchall()
        selected = [r for r in rows if r["id"] in policy_ids] if policy_ids is not None else [r for r in rows if r["enabled"]]
        if policy_ids is not None and len(selected) != len(policy_ids):
            raise KeyError("Shadow policy not found")
        if len(selected) > MAX_RULES:
            raise CapacityError("Select at most 16 explicit policies for comparison")
        for row in selected:
            _owner(db, actor["tenant"], row["owner"], indexes)
            result.append({"id": row["id"], "owner": row["owner"], "definition": json.loads(row["definition"])})
    if len({r["id"] for r in result}) != len(result):
        raise ValueError("Shadow rule IDs must be unique per side")
    return sorted(result, key=lambda r: r["id"])


class _FrozenStore:
    def __init__(self, live, snapshot, derived=False):
        self.settings = SimpleNamespace(query_timeout=min(10, live.settings.query_timeout))
        self.query_slots = live.query_slots
        self.analytics = duckdb.connect(":memory:", config={"memory_limit": "256MB", "threads": "1", "enable_external_access": "false"})
        self.analytics.execute("CREATE TABLE events_all(tenant VARCHAR,event_id VARCHAR,event_time DOUBLE,received DOUBLE,source VARCHAR,sourcetype VARCHAR,host VARCHAR,severity VARCHAR,message VARCHAR,raw VARCHAR,index_name VARCHAR)")
        rows = []
        for event in snapshot["events"]:
            raw = copy.deepcopy(event["raw"])
            if derived:
                existing = raw.get("analysis")
                analysis = {k:v for k,v in existing.items() if k not in {"projection","ocsf"}} if isinstance(existing, dict) else {}
                raw["analysis"] = analysis
                captured = snapshot["projections"].get(event["event_id"])
                source = snapshot["sources"].get(event["event_id"]) if captured else None
                if source:
                    envelope = {**event, "index": event["index_name"], "raw": raw}
                    projection = security_schema.project(envelope, source)
                    # Reserved derived fields are generated only from admission-
                    # bound source authority, never inherited vendor assertions.
                    raw["analysis"] = {**analysis, "projection": projection, "ocsf": projection["ocsf"]}
            rows.append((snapshot["tenant"], event["event_id"], event["event_time"], event["received"], event["source"], event["sourcetype"], event["host"], event["severity"], event["message"], encode(raw), event["index_name"]))
        if rows:
            self.analytics.executemany("INSERT INTO events_all VALUES(?,?,?,?,?,?,?,?,?,?,?)", rows)

    def analytics_query(self, sql, args, **kwargs):
        return Store._analytics_query(self, sql, args, **kwargs)

    def close(self):
        self.analytics.close()


def _decisions(live, snapshot, rules, derived):
    frozen = _FrozenStore(live, snapshot, derived)
    decisions = []
    try:
        for rule in rules:
            definition = rule["definition"]
            after = None
            while True:
                matches = detections.evaluate(frozen, snapshot["tenant"], definition, snapshot["end"], snapshot["indexes"],
                                               chain_after=after, scheduler_page=True)
                for match in matches:
                    decisions.append({"rule_id": rule["id"], "rule_digest": release_manifest.digest(definition),
                                      "entity": match["entity"], "event_ids": match["event_ids"], "indexes": match["indexes"],
                                      "risk_weight": match["risk_weight"], "severity": match["severity"], "mitre": match["mitre"],
                                      "evidence": [{"event_id": eid, "admission_digest": snapshot["receipts"][eid]["digest"],
                                                    "record_digest": snapshot["events_digest"][eid]} for eid in match["event_ids"]]})
                if len(decisions) > 5000 or len(encode(decisions).encode()) > MAX_BYTES:
                    raise CapacityError("Shadow decision budget exceeded; narrow the window/rules")
                if not matches.has_more:
                    break
                if matches.after == after:
                    raise ConflictError("Shadow exact-detector cursor did not advance")
                after = matches.after
    finally:
        frozen.close()
    return sorted(decisions, key=encode)


def _compare(live, snapshot):
    baseline = _decisions(live, snapshot, snapshot["baseline"], False)
    candidate = _decisions(live, snapshot, snapshot["candidate"], True)
    # A matching semantic decision retains its identity across a rule revision.
    def key(item):
        return encode({k: item[k] for k in ("rule_id", "entity", "event_ids")})
    left, right = {key(d): d for d in baseline}, {key(d): d for d in candidate}
    shared = set(left) & set(right)
    changed = [{"baseline": left[k], "candidate": right[k]} for k in sorted(shared) if left[k] != right[k]]
    return {"schema": SCHEMA, "mode": "isolated_shadow", "live_effects": False,
            "window": {"start": snapshot["start"], "end": snapshot["end"], "frozen": True},
            "event_count": len(snapshot["events"]), "projection_count": len(snapshot["projections"]),
            "engine": snapshot["engine"], "context_digest": snapshot["context_digest"],
            "baseline": baseline, "candidate": candidate,
            "comparison": {"added": [right[k] for k in sorted(set(right)-set(left))],
                           "removed": [left[k] for k in sorted(set(left)-set(right))],
                           "changed": changed, "unchanged": len(shared)-len(changed)},
            "limitations": ["evaluates frozen admitted telemetry, not sensor recall",
                            "legacy exact detector with candidate derived schema; no live AI or Case execution",
                            "context fingerprints pin unused parser/TI/model configuration; this engine does not claim to re-execute those capabilities"]}


def run_compare(store, who, data):
    allowed = {"start", "end", "indexes", "policy_ids", "baseline_rules", "candidate_rules", "max_events", "expected_context_digest"}
    if not isinstance(data, dict) or set(data)-allowed or not {"start", "end", "indexes"} <= set(data):
        raise ValueError("Exact shadow window/index fields required")
    start, end = entities.window(data["start"], data["end"])
    if end-start > 7 * 86400:
        raise ValueError("Shadow windows are bounded to seven days")
    indexes = entities.exact_indexes(data["indexes"])
    maximum = evidence_scope.integer(data.get("max_events", MAX_EVENTS), "max_events", 1, MAX_EVENTS)
    with principal.transaction(store, who, ("admin", "analyst")) as (db, actor):
        if not principal.contains(actor["allowed_indexes"], indexes):
            raise PermissionError("Shadow indexes exceed current grants")
        baseline = _rules(db, actor, indexes, data.get("baseline_rules"), data.get("policy_ids"))
        candidate = _rules(db, actor, indexes, data["candidate_rules"]) if "candidate_rules" in data else copy.deepcopy(baseline)
        if not baseline and not candidate:
            raise ValueError("At least one baseline or candidate rule required")
        context = _context(db, actor, indexes)
    context_digest = release_manifest.digest(context)
    if data.get("expected_context_digest", context_digest) != context_digest:
        raise ConflictError("Shadow context version changed")
    predicate, args = index_predicate(indexes)
    records = store.analytics_query("SELECT event_id,event_time,received,source,sourcetype,host,severity,message,raw,index_name FROM events_all WHERE tenant=? AND " + predicate + " AND event_time>=? AND event_time<? ORDER BY event_time,event_id LIMIT ?",
                                    [actor["tenant"], *args, start, end, maximum+1], max_rows=maximum+1)["rows"]
    if len(records) > maximum:
        raise CapacityError("Frozen shadow event budget exceeded; no partial comparison was performed")
    snapshot = {"schema": SCHEMA, "tenant": actor["tenant"], "owner": actor["name"], "indexes": indexes,
                "start": start, "end": end, "engine": _engine(), "context": context, "context_digest": context_digest,
                "baseline": baseline, "candidate": candidate, "receipts": {}, "projections": {}, "sources": {},
                "events": [], "events_digest": {}, "frontier_seq": 0}
    with principal.transaction(store, actor, ("admin", "analyst")) as (db, fresh):
        if fresh != actor:
            raise PermissionError("Permissions changed while freezing shadow evidence")
        for record in records:
            proof = db.execute("SELECT digest,received FROM receipts WHERE tenant=? AND event_id=?", (actor["tenant"], record["event_id"])).fetchone()
            if not proof or proof["received"] != record["received"]:
                raise ConflictError("Frozen shadow source admission unavailable")
            event = {**record, "raw": json.loads(record["raw"]) if isinstance(record["raw"], str) else record["raw"]}
            eid = event["event_id"]
            snapshot["events"].append(event)
            snapshot["events_digest"][eid] = release_manifest.digest(event)
            snapshot["receipts"][eid] = dict(proof)
            projected = db.execute("SELECT * FROM event_projections WHERE tenant=? AND event_id=? ORDER BY seq DESC LIMIT 1", (actor["tenant"], eid)).fetchone()
            if projected:
                snapshot["projections"][eid] = json.loads(projected["projection"])
                snapshot["frontier_seq"] = max(snapshot["frontier_seq"], projected["seq"])
                source = db.execute("SELECT source_definition FROM source_event_receipts WHERE tenant=? AND event_id=?", (actor["tenant"], eid)).fetchone()
                if source and source[0]:
                    snapshot["sources"][eid] = json.loads(source[0])
    if len(encode(snapshot).encode()) > MAX_BYTES:
        raise CapacityError("Frozen shadow snapshot exceeds 16 MiB")
    result = _compare(store, snapshot)
    identifier = uuid.uuid4().hex
    snapshot_digest, result_digest = release_manifest.digest(snapshot), release_manifest.digest(result)
    with principal.transaction(store, actor, ("admin", "analyst"), write=True) as (db, fresh):
        if fresh != actor or release_manifest.digest(_context(db, fresh, indexes)) != context_digest or _engine() != snapshot["engine"]:
            raise ConflictError("Shadow authority/context changed before publication")
        for rule in baseline + candidate:
            _owner(db, actor["tenant"], rule["owner"], indexes)
        for event in snapshot["events"]:
            proof = db.execute("SELECT digest,received FROM receipts WHERE tenant=? AND event_id=?", (actor["tenant"], event["event_id"])).fetchone()
            if not proof or dict(proof) != snapshot["receipts"][event["event_id"]]:
                raise ConflictError("Original source changed before shadow publication")
        db.execute("INSERT INTO shadow_compare_runs VALUES(?,?,?,?,?,?,?,?,?,?,?)", (identifier, actor["tenant"], actor["name"], encode(indexes), time.time(), start, end, snapshot_digest, result_digest, encode(snapshot), encode(result)))
        store.audit(db, actor["tenant"], actor["name"], "shadow.compare", {"id": identifier, "snapshot_digest": snapshot_digest, "result_digest": result_digest, "live_effects": False})
    return {"id": identifier, "snapshot_digest": snapshot_digest, "result_digest": result_digest, **result}


def _visible(db, actor, identifier):
    row = db.execute("SELECT * FROM shadow_compare_runs WHERE tenant=? AND id=?", (actor["tenant"], identifier)).fetchone()
    if not row or not principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
        raise KeyError("Shadow comparison not found")
    snapshot = json.loads(row["snapshot"])
    if release_manifest.digest(snapshot) != row["snapshot_digest"] or release_manifest.digest(json.loads(row["result"])) != row["result_digest"]:
        raise ConflictError("Shadow snapshot/result integrity failed")
    for rule in snapshot["baseline"] + snapshot["candidate"]:
        _owner(db, actor["tenant"], rule["owner"], snapshot["indexes"])
    return row, snapshot


def get(store, who, identifier):
    with principal.transaction(store, who) as (db, actor):
        row, _ = _visible(db, actor, identifier)
        return {"id": identifier, "snapshot_digest": row["snapshot_digest"], "result_digest": row["result_digest"], **json.loads(row["result"])}


def listing(store, who, cursor=None, count=50):
    evidence_scope.integer(count, "count", 1, 100)
    if cursor is not None:
        evidence_scope.text(cursor, "cursor", 128)
    with principal.transaction(store, who) as (db, actor):
        scoped = "" if actor["allowed_indexes"] == ["*"] else " AND NOT EXISTS(SELECT 1 FROM json_each(indexes) x WHERE x.value NOT IN (SELECT value FROM json_each(?)))"
        args = [actor["tenant"], cursor or ""] + ([] if not scoped else [encode(actor["allowed_indexes"])]) + [count+1]
        rows = db.execute("SELECT id,indexes,created,start,end,snapshot_digest,result_digest FROM shadow_compare_runs WHERE tenant=? AND id>?" + scoped + " ORDER BY id LIMIT ?", args).fetchall()
        visible = [{**dict(row), "indexes": json.loads(row["indexes"])} for row in rows[:count]]
        return {"items": visible, "next_cursor": rows[count-1]["id"] if len(rows)>count else None, "live_effects": False}


def replay(store, who, identifier):
    with principal.transaction(store, who, ("admin", "analyst")) as (db, actor):
        row, snapshot = _visible(db, actor, identifier)
    if _engine() != snapshot["engine"]:
        raise ConflictError("Pinned evaluator implementation changed; create a new comparison")
    result = _compare(store, snapshot)
    result_digest = release_manifest.digest(result)
    replay_id = uuid.uuid4().hex
    with principal.transaction(store, actor, ("admin", "analyst"), write=True) as (db, fresh):
        original, _ = _visible(db, fresh, identifier)
        if fresh != actor or original["snapshot_digest"] != row["snapshot_digest"] or _engine() != snapshot["engine"]:
            raise ConflictError("Shadow replay authority/engine changed")
        db.execute("INSERT INTO shadow_compare_replays VALUES(?,?,?,?,?,?,?,?)", (replay_id, identifier, actor["tenant"], actor["name"], time.time(), row["snapshot_digest"], result_digest, int(result_digest==row["result_digest"])))
    return {"id": identifier, "replay_id": replay_id, "snapshot_digest": row["snapshot_digest"], "result_digest": result_digest,
            "identical": result_digest==row["result_digest"], "live_effects": False}


def register(app, store, runtime, who, body):
    from fastapi import Request
    from starlette.concurrency import run_in_threadpool

    @app.get("/api/v3/shadow/context")
    async def context(request: Request):
        return await run_in_threadpool(context_status, store, who(request), request.query_params.getlist("index"))

    @app.post("/api/v3/shadow/compare", status_code=201)
    async def compare(request: Request):
        return await run_in_threadpool(run_compare, store, who(request, ("admin", "analyst")), await body(request))

    @app.get("/api/v3/shadow/runs")
    async def runs(request: Request):
        return await run_in_threadpool(listing, store, who(request), request.query_params.get("cursor"), int(request.query_params.get("count", "50")))

    @app.get("/api/v3/shadow/runs/{identifier}")
    async def details(identifier: str, request: Request):
        return await run_in_threadpool(get, store, who(request), identifier)

    @app.post("/api/v3/shadow/runs/{identifier}/replay")
    async def rerun(identifier: str, request: Request):
        return await run_in_threadpool(replay, store, who(request, ("admin", "analyst")), identifier)

    @app.get("/api/v3/ocsf/events/{event_id}")
    async def ocsf(event_id: str, request: Request):
        actor = who(request)
        records = await run_in_threadpool(evidence_scope.originals, store, actor, [event_id])
        with principal.transaction(store, actor) as (db, current):
            evidence_scope.recheck(db, current, records)
            row = db.execute("SELECT projection FROM event_projections WHERE tenant=? AND event_id=? ORDER BY seq DESC LIMIT 1", (current["tenant"], event_id)).fetchone()
            if not row:
                raise KeyError("Registered projection not found")
            projected = json.loads(row[0])
            from . import ocsf_mapping
            return {"event_id": event_id, "projection_version": projected["version"], "projection_digest": projected["projection_digest"],
                    "ocsf": projected.get("ocsf") or ocsf_mapping.project(projected), "original_unchanged": True}
