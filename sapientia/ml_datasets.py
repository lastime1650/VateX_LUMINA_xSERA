"""Scoped, revisioned CPU datasets; templates require explicit source admission.

Labels and split metadata are external manifests, never model input telemetry.
Removing a dataset releases only its own references and changes no model.
"""
import copy
import json
import threading
import time
import uuid
from datetime import datetime
from itertools import pairwise

from . import (
    connector_runtime,
    cpu_ml,
    cpu_sequence,
    evidence_scope,
    migrations,
    principal,
    source_registry,
)
from .storage import CapacityError, ConflictError, encode

EDITORS = ("admin", "analyst")
KINDS = {"autoencoder", "sequence"}
SPLITS = {"training", "calibration", "holdout"}
MAX_SAMPLES = 4096
TRAIN_LEASE_SECONDS = 600
_ACTIVE_TRAINING = set()
_TRAINING_LOCK = threading.Lock()
BUNDLES = {
    "autoencoder_demo24": {"name": "CPU 정상 이벤트 예제 24개", "kind": "autoencoder", "variants": 4, "samples": 24, "event_count": 24},
    "sequence_demo96": {"name": "CPU 행동 순서 예제 96개", "kind": "sequence", "variants": 4, "samples": 96, "event_count": 1152},
    "sequence_research1536": {"name": "CPU 행동 순서 연구 예제 1,536개", "kind": "sequence", "variants": 64, "samples": 1536, "event_count": 18432},
}


def initialize(store):
    migrations.apply_store(store, "ml_datasets", [
        "CREATE TABLE IF NOT EXISTS ml_datasets(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,name TEXT NOT NULL,description TEXT NOT NULL,kind TEXT NOT NULL,indexes TEXT NOT NULL,version INTEGER NOT NULL,state TEXT NOT NULL,created REAL NOT NULL,updated REAL NOT NULL)",
        "CREATE INDEX IF NOT EXISTS ml_datasets_scope ON ml_datasets(tenant,state,updated,id)",
        "CREATE TABLE IF NOT EXISTS ml_dataset_revisions(dataset_id TEXT NOT NULL,revision INTEGER NOT NULL,tenant TEXT NOT NULL,actor TEXT NOT NULL,created REAL NOT NULL,digest TEXT NOT NULL,summary TEXT NOT NULL,state TEXT NOT NULL,PRIMARY KEY(dataset_id,revision))",
        "CREATE TABLE IF NOT EXISTS ml_dataset_sample_versions(id TEXT PRIMARY KEY,dataset_id TEXT NOT NULL,tenant TEXT NOT NULL,sample_id TEXT NOT NULL,created REAL NOT NULL,actor TEXT NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS ml_dataset_revision_samples(dataset_id TEXT NOT NULL,revision INTEGER NOT NULL,sample_id TEXT NOT NULL,sample_version_id TEXT NOT NULL,PRIMARY KEY(dataset_id,revision,sample_id))",
        "CREATE TABLE IF NOT EXISTS ml_dataset_validations(id TEXT PRIMARY KEY,dataset_id TEXT NOT NULL,revision INTEGER NOT NULL,tenant TEXT NOT NULL,actor TEXT NOT NULL,created REAL NOT NULL,digest TEXT NOT NULL,result TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS ml_dataset_model_links(dataset_id TEXT NOT NULL,revision INTEGER NOT NULL,tenant TEXT NOT NULL,model_family TEXT NOT NULL,model_id TEXT NOT NULL,dataset_digest TEXT NOT NULL,actor TEXT NOT NULL,created REAL NOT NULL,PRIMARY KEY(model_family,model_id))",
        "CREATE TABLE IF NOT EXISTS ml_dataset_model_sources(tenant TEXT NOT NULL,model_id TEXT NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL,PRIMARY KEY(tenant,model_id))",
        "CREATE TABLE IF NOT EXISTS ml_dataset_materializations(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,dataset_id TEXT NOT NULL,base_revision INTEGER NOT NULL,current_revision INTEGER NOT NULL,input_digest TEXT NOT NULL,owner TEXT NOT NULL,state TEXT NOT NULL,items TEXT NOT NULL,position INTEGER NOT NULL,claim TEXT,created REAL NOT NULL,updated REAL NOT NULL,error TEXT)",
        "CREATE TABLE IF NOT EXISTS ml_dataset_materialized_samples(materialization_id TEXT NOT NULL,sample_id TEXT NOT NULL,source_id TEXT,original_ids TEXT,state TEXT NOT NULL,PRIMARY KEY(materialization_id,sample_id))",
    ])
    migrations.apply_store(store, "ml_datasets", [
        "CREATE TABLE IF NOT EXISTS ml_dataset_training_claims(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,dataset_id TEXT NOT NULL,revision INTEGER NOT NULL,digest TEXT NOT NULL,owner TEXT NOT NULL,token TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,state TEXT NOT NULL,model_family TEXT NOT NULL,model_id TEXT,error TEXT,pins_released INTEGER NOT NULL DEFAULT 0)",
        "CREATE INDEX IF NOT EXISTS ml_dataset_training_claims_expiry ON ml_dataset_training_claims(pins_released,expires,id)",
    ], version=2)
    run_due(store)


def _training_key(store, identifier):
    return str(store.settings.data.resolve()), identifier


def run_due(store, now=None, cancel=None, budget=.25, max_runs=64):
    """Recover expired abandoned claims; an in-process operation retains pins."""
    now = time.time() if now is None else evidence_scope.number(now, "training recovery time")
    maximum = evidence_scope.integer(max_runs, "training recovery batch", 1, 64)
    deadline = time.monotonic() + min(.25, evidence_scope.number(budget, "training recovery budget", 0, .25))
    recovered = 0
    with store.write_lock, store.control() as db:
        db.execute("BEGIN IMMEDIATE")
        with _TRAINING_LOCK:
            active_ids = sorted(identifier for path, identifier in _ACTIVE_TRAINING if path == str(store.settings.data.resolve()))
        rows = db.execute("SELECT * FROM ml_dataset_training_claims WHERE pins_released=0 AND expires<=? AND id NOT IN (SELECT value FROM json_each(?)) ORDER BY expires,id LIMIT ?", (now, encode(active_ids), maximum)).fetchall()
        for row in rows:
            if time.monotonic() >= deadline or cancel is not None and cancel.is_set():
                break
            with _TRAINING_LOCK:
                active = _training_key(store, row["id"]) in _ACTIVE_TRAINING
            if active:
                continue
            # A Store owns its data directory's process lock. After a crash,
            # a new Store's process has no matching active invocation. The
            # exact persisted token, tenant, state and expiry are checked
            # before releasing only that invocation's transient references.
            changed = db.execute("UPDATE ml_dataset_training_claims SET state=CASE WHEN state='running' THEN 'expired' ELSE state END,error=CASE WHEN state='running' THEN 'abandoned training lease expired' ELSE error END,pins_released=1 WHERE id=? AND tenant=? AND token=? AND state=? AND pins_released=0 AND expires<=?", (row["id"], row["tenant"], row["token"], row["state"], now)).rowcount
            if not changed:
                continue
            db.execute("DELETE FROM record_case_evidence_refs WHERE tenant=? AND kind='ml_dataset_train' AND record_id=?", (row["tenant"], row["id"]))
            store.audit(db, row["tenant"], "system", "ml.dataset.train.expire", {"dataset_id": row["dataset_id"], "revision": row["revision"], "claim_id": row["id"], "model_id": row["model_id"]})
            recovered += 1
    return {"expired_training_claims": recovered, "lease_seconds": TRAIN_LEASE_SECONDS}


def _digest(value):
    return cpu_sequence._digest(value)


def _indexes(value):
    return evidence_scope.indexes(value)


def _expected(data, current):
    if not isinstance(data, dict) or type(data.get("expected_revision")) is not int or data["expected_revision"] != current:
        raise ConflictError("Dataset revision changed; reload before editing")


def _head(db, actor, identifier, active=True):
    row = db.execute("SELECT * FROM ml_datasets WHERE tenant=? AND id=?", (actor["tenant"], identifier)).fetchone()
    if not row or not principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
        raise KeyError("Dataset not found in complete current index scope")
    if active and row["state"] == "deleted":
        raise ConflictError("Removed dataset cannot be edited, admitted or trained")
    return row


def _items(db, identifier, revision):
    return {row["sample_id"]: row["sample_version_id"] for row in db.execute(
        "SELECT sample_id,sample_version_id FROM ml_dataset_revision_samples WHERE dataset_id=? AND revision=? ORDER BY sample_id", (identifier, revision))}


def _bodies(db, items):
    found = {row["id"]: row for row in db.execute("SELECT * FROM ml_dataset_sample_versions WHERE id IN (SELECT value FROM json_each(?))", (encode(list(items.values())),))}
    if set(found) != set(items.values()):
        raise ConflictError("Immutable dataset sample version disappeared")
    answer = {}
    for sample_id, version_id in items.items():
        row = found[version_id]
        body = json.loads(row["body"])
        if row["sample_id"] != sample_id or _digest(body) != row["digest"]:
            raise ConflictError("Immutable dataset sample hash mismatch")
        answer[sample_id] = body
    return answer


def _counts(bodies):
    counts = {name: 0 for name in ("samples", "originals", "training", "calibration", "holdout", "normal", "attack", "templates", "materialized")}
    ids = set()
    for body in bodies.values():
        counts["samples"] += 1
        counts[body["split"]] += 1
        counts[body["label"]] += 1
        counts["templates" if body["mode"] == "template" else "materialized"] += 1
        ids.update(body.get("event_ids", []))
    counts["originals"] = len(ids)
    counts["validation"] = counts["calibration"]
    return counts


def _revision(db, head):
    row = db.execute("SELECT * FROM ml_dataset_revisions WHERE dataset_id=? AND revision=?", (head["id"], head["version"])).fetchone()
    if not row:
        raise ConflictError("Dataset revision history unavailable")
    return row


def _public(db, actor, head):
    revision = _revision(db, head)
    summary = json.loads(revision["summary"])
    counts = summary["counts"]
    last = db.execute("SELECT result FROM ml_dataset_validations WHERE dataset_id=? AND revision=? ORDER BY created DESC LIMIT 1", (head["id"], head["version"])).fetchone()
    last = json.loads(last[0]) if last else None
    editor = actor["role"] in EDITORS and head["state"] != "deleted"
    synthetic_scope = all(index.startswith("ml_synthetic_") for index in json.loads(head["indexes"]))
    models = []
    for link in db.execute("SELECT * FROM ml_dataset_model_links WHERE dataset_id=? AND tenant=? ORDER BY created", (head["id"], actor["tenant"])):
        prefix = "cpu_sequence" if link["model_family"] == "sequence" else "cpu_ml"
        row = db.execute("SELECT id,name,revision,indexes FROM "+prefix+"_models WHERE tenant=? AND id=?", (actor["tenant"], link["model_id"])).fetchone()
        if row and principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
            active = db.execute("SELECT 1 FROM "+prefix+"_active WHERE tenant=? AND model_id=?", (actor["tenant"], row["id"])).fetchone() is not None
            models.append({"id": row["id"], "name": row["name"], "family": link["model_family"], "revision": row["revision"], "active": active, "dataset_revision": link["revision"]})
    state = "deleted" if head["state"] == "deleted" else "templates" if counts["templates"] else "validated" if last and last["ready"] else "draft"
    issues = last["issues"] if last else [{"code": "validation_required", "message": "현재 원본·출처·분리 조건 검증이 필요합니다."}]
    materializations = []
    for row in db.execute("SELECT id,state,owner,position,json_array_length(items) AS total,current_revision,updated FROM ml_dataset_materializations WHERE tenant=? AND dataset_id=? ORDER BY updated DESC,id LIMIT 10", (actor["tenant"], head["id"])):
        idle = max(0., time.time()-row["updated"])
        materializations.append({**dict(row), "resumable": bool(editor and actor["role"] == "admin" and synthetic_scope and row["owner"] == actor["name"] and row["current_revision"] == head["version"] and (
            row["state"] == "pending" or row["state"] == "running" and idle >= 120)),
            "lease_seconds": 120, "lease_remaining_seconds": max(0., 120-idle) if row["state"] == "running" else 0.})
    return {"id": head["id"], "name": head["name"], "description": head["description"], "kind": head["kind"], "family": head["kind"],
            "indexes": json.loads(head["indexes"]), "revision": head["version"], "version": head["version"], "digest": revision["digest"],
            "state": head["state"], "owner": head["owner"], "created": head["created"], "updated": head["updated"], "counts": counts,
            "allowed_actions": {name: editor for name in ("edit", "remove", "add_sample", "edit_sample", "remove_sample", "validate", "train")} | {
                "materialize": editor and actor["role"] == "admin" and synthetic_scope and counts["templates"] > 0},
            "readiness": {"ready": bool(last and last["ready"] and state == "validated"), "state": state, "issues": issues,
                          "requires_current_validation": True, "authority_rechecked": False},
            "usage": {"models": models, "materializations": materializations, "training_runs": [dict(row) for row in db.execute("SELECT id,revision,created,expires,state,model_family,model_id,error,pins_released FROM ml_dataset_training_claims WHERE tenant=? AND dataset_id=? ORDER BY created DESC LIMIT 10", (actor["tenant"], head["id"]))]},
            "last_validation": last}


def _append_revision(store, db, actor, head, items, *, name=None, description=None, indexes=None, state=None, materialization_id=None):
    if len(items) > MAX_SAMPLES:
        raise CapacityError("Dataset exceeds 4096 samples")
    bodies = _bodies(db, items)
    used, scenarios = set(), set()
    for body in bodies.values():
        if body["scenario_id"] in scenarios:
            raise ValueError("Scenario IDs must be distinct across dataset samples")
        scenarios.add(body["scenario_id"])
        if used.intersection(body["event_ids"]):
            raise ValueError("Original IDs cannot occur in multiple dataset samples")
        used.update(body["event_ids"])
    if len(used)*len(cpu_sequence.FEATURES) > 2_000_000 and head["kind"] == "sequence":
        raise CapacityError("Dataset exceeds the sequence feature budget")
    next_revision = head["version"]+1
    values = {"name": head["name"] if name is None else name, "description": head["description"] if description is None else description,
              "indexes": json.loads(head["indexes"]) if indexes is None else indexes, "kind": head["kind"], "state": state or head["state"]}
    samples = [{"id": sid, "version_id": vid, "digest": db.execute("SELECT digest FROM ml_dataset_sample_versions WHERE id=?", (vid,)).fetchone()[0]} for sid, vid in sorted(items.items())]
    counts = _counts(bodies)
    digest = _digest({"dataset_id": head["id"], "revision": next_revision, **values, "samples": samples})
    now = time.time()
    db.execute("UPDATE ml_datasets SET name=?,description=?,indexes=?,version=?,state=?,updated=? WHERE id=? AND version=?",
               (values["name"], values["description"], encode(values["indexes"]), next_revision, values["state"], now, head["id"], head["version"]))
    if db.execute("SELECT changes()").fetchone()[0] != 1:
        raise ConflictError("Dataset revision changed")
    db.execute("INSERT INTO ml_dataset_revisions VALUES(?,?,?,?,?,?,?,?)", (head["id"], next_revision, actor["tenant"], actor["name"], now, digest, encode({"counts": counts, **values}), values["state"]))
    db.executemany("INSERT INTO ml_dataset_revision_samples VALUES(?,?,?,?)", [(head["id"], next_revision, sid, vid) for sid, vid in items.items()])
    # Only the current dataset head pins originals. Models own their separate
    # training references; old revision JSON/history is retained permanently.
    db.execute("DELETE FROM record_case_evidence_refs WHERE tenant=? AND kind='ml_dataset' AND record_id=?", (actor["tenant"], head["id"]))
    db.executemany("INSERT OR IGNORE INTO record_case_evidence_refs VALUES(?,?,?,?)", [(actor["tenant"], eid, "ml_dataset", head["id"]) for eid in used])
    # An ordinary edit supersedes any resumable job bound to the old head.
    # Completed admissions remain originals; only the cancelled job's pins
    # are released. A committing job is explicitly exempted from cancellation.
    cancelled = [r[0] for r in db.execute("SELECT id FROM ml_dataset_materializations WHERE dataset_id=? AND state IN ('pending','running') AND id!=?", (head["id"], materialization_id or ""))]
    if cancelled:
        db.execute("UPDATE ml_dataset_materializations SET state='cancelled',claim=NULL,error='dataset revision changed' WHERE id IN (SELECT value FROM json_each(?))", (encode(cancelled),))
        db.execute("DELETE FROM record_case_evidence_refs WHERE tenant=? AND kind='ml_dataset_materialize' AND record_id IN (SELECT value FROM json_each(?))", (actor["tenant"], encode(cancelled)))
    store.audit(db, actor["tenant"], actor["name"], "ml.dataset.revision", {"dataset_id": head["id"], "revision": next_revision, "digest": digest, "counts": counts, "state": values["state"]})
    return db.execute("SELECT * FROM ml_datasets WHERE id=?", (head["id"],)).fetchone()


def _create(db, actor, data, *, identifier=None):
    if not isinstance(data, dict) or set(data)-{"expected_revision", "name", "description", "kind", "indexes"}:
        raise ValueError("Exact dataset name, kind and index scope required")
    _expected(data, 0)
    kind = data.get("kind")
    if kind not in KINDS:
        raise ValueError("Dataset kind must be sequence or autoencoder")
    indexes = _indexes(data.get("indexes"))
    if not principal.contains(actor["allowed_indexes"], indexes):
        raise PermissionError("Dataset index scope exceeds current permissions")
    identifier, now = identifier or str(uuid.uuid4()), time.time()
    name = evidence_scope.text(data.get("name"), "dataset name", 128)
    description = evidence_scope.text(data.get("description", ""), "dataset description", 2000, empty=True)
    db.execute("INSERT INTO ml_datasets VALUES(?,?,?,?,?,?,?,0,'draft',?,?)", (identifier, actor["tenant"], actor["name"], name, description, kind, encode(indexes), now, now))
    return db.execute("SELECT * FROM ml_datasets WHERE id=?", (identifier,)).fetchone()


def create(store, who, data):
    with principal.transaction(store, who, EDITORS, write=True) as (db, actor):
        head = _append_revision(store, db, actor, _create(db, actor, data), {})
        return _public(db, actor, head)


def listing(store, who, cursor=0, count=25):
    cursor = evidence_scope.integer(cursor, "dataset cursor", 0, 10_000_000)
    count = evidence_scope.integer(count, "dataset page size", 1, 100)
    with principal.transaction(store, who) as (db, actor):
        scope = "" if actor["allowed_indexes"] == ["*"] else " AND NOT EXISTS(SELECT 1 FROM json_each(d.indexes) i WHERE i.value NOT IN (SELECT value FROM json_each(?)))"
        args = [actor["tenant"]] + ([] if not scope else [encode(actor["allowed_indexes"])])
        total = db.execute("SELECT count(*) FROM ml_datasets d WHERE d.tenant=? AND d.state!='deleted'"+scope, args).fetchone()[0]
        rows = db.execute("SELECT d.* FROM ml_datasets d WHERE d.tenant=? AND d.state!='deleted'"+scope+" ORDER BY d.updated DESC,d.id LIMIT ? OFFSET ?", [*args, count+1, cursor]).fetchall()
        return {"items": [_public(db, actor, row) for row in rows[:count]], "total": total, "next_cursor": cursor+count if len(rows)>count else None}


def get(store, who, identifier):
    with principal.transaction(store, who) as (db, actor):
        return _public(db, actor, _head(db, actor, identifier, False))


def update(store, who, identifier, data):
    if not isinstance(data, dict) or set(data)-{"expected_revision", "name", "description", "indexes"}:
        raise ValueError("Exact editable dataset fields required")
    with principal.transaction(store, who, EDITORS, write=True) as (db, actor):
        head = _head(db, actor, identifier)
        _expected(data, head["version"])
        indexes = _indexes(data.get("indexes", json.loads(head["indexes"])))
        if not principal.contains(actor["allowed_indexes"], indexes):
            raise PermissionError("New dataset scope exceeds current permissions")
        bodies = _bodies(db, _items(db, identifier, head["version"]))
        if indexes != json.loads(head["indexes"]) and any(body["event_ids"] for body in bodies.values()):
            raise ConflictError("Materialized/original sample scope cannot be moved; create a new dataset")
        changed = _append_revision(store, db, actor, head, _items(db, identifier, head["version"]),
            name=evidence_scope.text(data.get("name", head["name"]), "dataset name", 128),
            description=evidence_scope.text(data.get("description", head["description"]), "dataset description", 2000, empty=True), indexes=indexes)
        return {"dataset": _public(db, actor, changed), "revision": changed["version"], "version": changed["version"]}


def remove(store, who, identifier, data):
    if not isinstance(data, dict) or set(data)-{"expected_revision", "notes"}:
        raise ValueError("Expected dataset revision and removal notes required")
    with principal.transaction(store, who, EDITORS, write=True) as (db, actor):
        head = _head(db, actor, identifier)
        _expected(data, head["version"])
        notes = evidence_scope.text(data.get("notes", "Explicit dataset removal"), "removal notes", 2000)
        changed = _append_revision(store, db, actor, head, {}, state="deleted")
        db.execute("UPDATE ml_dataset_materializations SET state='cancelled',claim=NULL,error=? WHERE dataset_id=? AND state IN ('pending','running')", (notes, identifier))
        db.execute("DELETE FROM record_case_evidence_refs WHERE tenant=? AND kind='ml_dataset_materialize' AND record_id IN (SELECT id FROM ml_dataset_materializations WHERE dataset_id=?)", (actor["tenant"], identifier))
        return {"dataset": _public(db, actor, changed), "revision": changed["version"], "version": changed["version"], "originals_deleted": False, "models_changed": False}


def _no_truth(value):
    if isinstance(value, dict):
        if set(value) & {"label", "truth", "family", "scenario_id", "split"}:
            raise ValueError("Labels, family and scenario truth belong only to the external manifest")
        for item in value.values():
            _no_truth(item)
    elif isinstance(value, list):
        for item in value:
            _no_truth(item)


def _sample(data, kind, previous=None):
    allowed = {"scenario_id", "split", "label", "family", "host_group", "event_ids", "template_events", "mode"}
    if not isinstance(data, dict) or set(data)-allowed:
        raise ValueError("Exact typed dataset sample fields required")
    value = {**(previous or {}), **copy.deepcopy(data)}
    result = {key: evidence_scope.text(value.get(key), key, 128 if key in {"scenario_id", "family"} else 256) for key in ("scenario_id", "family", "host_group")}
    if value.get("split") not in SPLITS or kind == "autoencoder" and value["split"] == "holdout":
        raise ValueError("Use training/calibration/holdout; autoencoder uses training/calibration")
    if value.get("label") not in {"normal", "attack"} or kind == "autoencoder" and value["label"] != "normal":
        raise ValueError("External label must be normal/attack; autoencoder samples must be normal")
    mode = value.get("mode", "originals" if value.get("event_ids") else "template")
    if mode not in {"originals", "template"}:
        raise ValueError("Sample mode must be originals or template")
    result.update(split=value["split"], label=value["label"], mode=mode, event_ids=[])
    if mode == "originals":
        ids = value.get("event_ids")
        minimum, maximum = (1, 1) if kind == "autoencoder" else (2, 32)
        if not isinstance(ids, list) or not minimum <= len(ids) <= maximum:
            raise ValueError(f"Sample requires {minimum}..{maximum} authenticated original IDs")
        result["event_ids"] = [evidence_scope.text(item, "original ID") for item in ids]
        if len(set(ids)) != len(ids):
            raise ValueError("Sample original IDs must be unique")
    else:
        events = value.get("template_events")
        minimum, maximum = (1, 1) if kind == "autoencoder" else (2, 32)
        if not isinstance(events, list) or not minimum <= len(events) <= maximum:
            raise ValueError(f"Synthetic template requires {minimum}..{maximum} events")
        result["template_events"] = []
        for event in events:
            if not isinstance(event, dict) or set(event) != {"event_time", "host", "raw"} or event["host"] != result["host_group"] or not isinstance(event["raw"], dict):
                raise ValueError("Template needs exact event_time/host/raw matching its host group")
            evidence_scope.number(event["event_time"], "template event time")
            _no_truth(event["raw"])
            if kind == "sequence":
                data = cpu_sequence.features.get(event["raw"], "xdr.data") or {}
                host = data.get("host") if isinstance(data, dict) else None
                if not isinstance(host, dict) or not host.get("id") or not host.get("boot_id"):
                    raise ValueError("Sequence template requires reported host/boot identity")
            result["template_events"].append(copy.deepcopy(event))
        times = [event["event_time"] for event in result["template_events"]]
        if any(b <= a for a, b in pairwise(times)):
            raise ValueError("Template source times must be strictly increasing")
    if previous and previous.get("template_origin"):
        result["template_origin"] = previous["template_origin"]
    if len(encode(result).encode()) > 128*1024:
        raise CapacityError("Sample exceeds 128 KiB; use bounded sample operations")
    return result


def _verify_original_sample(store, actor, head, body):
    if body["mode"] == "template":
        return []
    indexes = json.loads(head["indexes"])
    if head["kind"] == "sequence":
        window = cpu_sequence.inspect_sequences(store, actor, [body], indexes)[0]
        if window["host"] != body["host_group"]:
            raise ValueError("Sample host group must equal authenticated originals' actual host")
        return [window]
    else:
        rows, _ = cpu_sequence._fetch(store, actor, body["event_ids"], indexes)
        if rows[body["event_ids"][0]]["host"] != body["host_group"]:
            raise ValueError("Sample host group must equal its actual original host")
        return _receipt_windows(rows)


def _receipt_windows(rows):
    return [{"provenance": [evidence_scope.reference(row)], "source_context": row["source_context"]} for row in rows.values()]


def _recheck(db, actor, windows):
    cpu_sequence._recheck(db, actor, windows, [])
    expected = {p["event_id"]: (p, w["source_context"]) for w in windows for p in w["provenance"]}
    ids = list(expected)
    for start in range(0, len(ids), 1000):
        selected = ids[start:start+1000]
        found = {r["event_id"]: r for r in db.execute("SELECT * FROM source_event_receipts WHERE tenant=? AND event_id IN (SELECT value FROM json_each(?))", (actor["tenant"], encode(selected)))}
        if set(found) != set(selected):
            raise ConflictError("Dataset original registered-source proof disappeared")
        for eid, row in found.items():
            provenance, context = expected[eid]
            if row["source_id"] != context["id"] or row["source_version"] != context["version"] or row["index_name"] != provenance["index_name"] or row["receipt_digest"] != provenance["admission_digest"] or row["received"] != provenance["received"]:
                raise ConflictError("Dataset original registered-source proof changed")


def validate_model_sources(db, actor, model_id, guard):
    """Dataset AE extension; immutable provenance outlives dataset removal."""
    row = db.execute("SELECT body,digest FROM ml_dataset_model_sources WHERE tenant=? AND model_id=?", (actor["tenant"], model_id)).fetchone()
    if row is None:
        raise ConflictError("Dataset model source provenance disappeared")
    body = json.loads(row["body"])
    if guard != {"schema": "xsera.dataset-model-sources.v1", "digest": row["digest"]} or _digest(body) != row["digest"] or body["model_id"] != model_id or body["tenant"] != actor["tenant"]:
        raise ConflictError("Immutable dataset model source provenance changed")
    if not principal.contains(actor["allowed_indexes"], body["indexes"]):
        raise PermissionError("Dataset model source scope exceeds current permissions")
    validate_model_binding(db, actor, model_id, "autoencoder", {key: body[key] for key in ("dataset_id", "dataset_revision", "dataset_digest")})
    _recheck(db, actor, body["windows"])


def validate_model_binding(db, actor, model_id, family, binding):
    if not isinstance(binding, dict) or set(binding) != {"dataset_id", "dataset_revision", "dataset_digest"}:
        raise ConflictError("Immutable dataset model binding is invalid")
    row = db.execute("SELECT * FROM ml_dataset_model_links WHERE tenant=? AND model_family=? AND model_id=?", (actor["tenant"], family, model_id)).fetchone()
    if not row or row["dataset_id"] != binding["dataset_id"] or row["revision"] != binding["dataset_revision"] or row["dataset_digest"] != binding["dataset_digest"]:
        raise ConflictError("Immutable dataset model binding disappeared or changed")


def _new_sample(db, actor, identifier, sid, body):
    version_id = str(uuid.uuid4())
    db.execute("INSERT INTO ml_dataset_sample_versions VALUES(?,?,?,?,?,?,?,?)", (version_id, identifier, actor["tenant"], sid, time.time(), actor["name"], encode(body), _digest(body)))
    return version_id


def _sample_public(sid, body, detail=False):
    result = {"id": sid, **{key: body[key] for key in ("scenario_id", "split", "label", "family", "host_group", "mode", "event_ids")},
              "materialized": body["mode"] == "originals", "event_count": len(body.get("template_events", body["event_ids"]))}
    if detail and body["mode"] == "template":
        result["template_events"] = body["template_events"]
    if body.get("template_origin"):
        result["template_origin"] = body["template_origin"]
    return result


def save_sample(store, who, identifier, data, sid=None):
    if not isinstance(data, dict) or set(data) != {"expected_revision", "sample"}:
        raise ValueError("Expected dataset revision and typed sample required")
    with principal.transaction(store, who, EDITORS) as (db, actor):
        head = dict(_head(db, actor, identifier))
        _expected(data, head["version"])
        items = _items(db, identifier, head["version"])
        if sid and sid not in items:
            raise KeyError("Dataset sample not found")
        previous = _bodies(db, {sid: items[sid]})[sid] if sid else None
    body = _sample(data["sample"], head["kind"], previous)
    windows = _verify_original_sample(store, actor, head, body)
    with principal.transaction(store, actor, EDITORS, write=True) as (db, fresh):
        current = _head(db, fresh, identifier)
        _expected(data, current["version"])
        _recheck(db, fresh, windows)
        sid = sid or str(uuid.uuid4())
        items[sid] = _new_sample(db, fresh, identifier, sid, body)
        changed = _append_revision(store, db, fresh, current, items)
        return {"dataset": _public(db, fresh, changed), "sample": _sample_public(sid, body, True), "revision": changed["version"], "version": changed["version"]}


def remove_sample(store, who, identifier, sid, data):
    if not isinstance(data, dict) or set(data) != {"expected_revision"}:
        raise ValueError("Expected dataset revision required")
    with principal.transaction(store, who, EDITORS, write=True) as (db, actor):
        head = _head(db, actor, identifier)
        _expected(data, head["version"])
        items = _items(db, identifier, head["version"])
        if sid not in items:
            raise KeyError("Dataset sample not found")
        del items[sid]
        changed = _append_revision(store, db, actor, head, items)
        return {"dataset": _public(db, actor, changed), "revision": changed["version"], "version": changed["version"], "originals_deleted": False}


def samples(store, who, identifier, cursor=0, count=25, sid=None):
    cursor = evidence_scope.integer(cursor, "sample cursor", 0, MAX_SAMPLES)
    count = evidence_scope.integer(count, "sample page size", 1, 100)
    with principal.transaction(store, who) as (db, actor):
        head = _head(db, actor, identifier)
        items = _items(db, identifier, head["version"])
        if sid:
            if sid not in items:
                raise KeyError("Dataset sample not found")
            body = _bodies(db, {sid: items[sid]})[sid]
            return {"sample": _sample_public(sid, body, True), "revision": head["version"]}
        selected = list(items)[cursor:cursor+count+1]
        bodies = _bodies(db, {key: items[key] for key in selected[:count]})
        return {"items": [_sample_public(key, bodies[key]) for key in selected[:count]], "total": len(items), "revision": head["version"], "next_cursor": cursor+count if len(selected)>count else None}


def revisions(store, who, identifier, cursor=0, count=25):
    cursor = evidence_scope.integer(cursor, "revision cursor", 0, 10_000_000)
    count = evidence_scope.integer(count, "revision page size", 1, 100)
    with principal.transaction(store, who) as (db, actor):
        head = _head(db, actor, identifier, False)
        rows = db.execute("SELECT * FROM ml_dataset_revisions WHERE dataset_id=? ORDER BY revision DESC LIMIT ? OFFSET ?", (identifier, count+1, cursor)).fetchall()
        items = [{"revision": row["revision"], "version": row["revision"], "digest": row["digest"], "created": row["created"], "actor": row["actor"], "state": row["state"], "counts": json.loads(row["summary"])["counts"]} for row in rows[:count]]
        total = db.execute("SELECT count(*) FROM ml_dataset_revisions WHERE dataset_id=?", (identifier,)).fetchone()[0]
        return {"items": items, "total": total, "current_revision": head["version"], "next_cursor": cursor+count if len(rows)>count else None}


def _frozen(db, head):
    revision = _revision(db, head)
    items = _items(db, head["id"], head["version"])
    bodies = _bodies(db, items)
    summary = json.loads(revision["summary"])
    values = {key: summary[key] for key in ("name", "description", "indexes", "kind", "state")}
    if any(values[key] != (json.loads(head["indexes"]) if key == "indexes" else head[key]) for key in values):
        raise ConflictError("Dataset head differs from its immutable revision")
    samples = [{"id": sid, "version_id": vid, "digest": _digest(bodies[sid])} for sid, vid in sorted(items.items())]
    if _digest({"dataset_id": head["id"], "revision": head["version"], **values, "samples": samples}) != revision["digest"] or _counts(bodies) != summary["counts"]:
        raise ConflictError("Immutable dataset revision hash mismatch")
    return revision, items, bodies


def bundle_catalog(store, who):
    with principal.transaction(store, who) as (db, actor):
        # Installed count means currently stored editable samples, not the
        # historical generator size, admitted event count or trained models.
        installed = {"samples": 0, "templates": 0, "materialized": 0}
        for head in db.execute("SELECT * FROM ml_datasets WHERE tenant=? AND state!='deleted'", (actor["tenant"],)):
            if principal.contains(actor["allowed_indexes"], json.loads(head["indexes"])):
                counts = json.loads(_revision(db, head)["summary"])["counts"]
                for key in installed:
                    installed[key] += counts[key]
        items = []
        for identifier, bundle in BUNDLES.items():
            counts = {"training": 16, "calibration": 8, "holdout": 0} if bundle["kind"] == "autoencoder" else {
                "training": 16*bundle["variants"], "calibration": 4*bundle["variants"], "holdout": 4*bundle["variants"]}
            items.append({"id": identifier, **{k: bundle[k] for k in ("name", "kind", "samples", "event_count")},
                          "counts": counts, "synthetic": True, "native_sensor_collected": False, "import_mode": "editable_template_draft"})
        return {"items": items, "installed_sample_counts": installed, "automatic_admission": False}


def _namespace_template(event, dataset_id, old_host, new_host):
    raw = copy.deepcopy(event["raw"])
    def rewrite(value):
        if isinstance(value, dict):
            return {key: rewrite(item) for key, item in value.items()}
        if isinstance(value, list):
            return [rewrite(item) for item in value]
        return value.replace(old_host, new_host) if isinstance(value, str) else value
    raw = rewrite(raw)
    data = cpu_sequence.features.get(raw, "xdr.data")
    if isinstance(data, dict):
        for obj, keys in ((data.get("process"), ("guid", "start_identity")), ((data.get("process") or {}).get("parent"), ("guid", "start_identity"))):
            if isinstance(obj, dict):
                for key in keys:
                    if key in obj:
                        obj[key] = _digest([dataset_id, obj[key]])
    return {"event_time": event["event_time"], "host": new_host, "raw": _mark_synthetic(raw)}


def _mark_synthetic(raw):
    raw = copy.deepcopy(raw)
    data = cpu_sequence.features.get(raw, "xdr.data")
    if isinstance(data, dict):
        data["agent"] = dict(data["agent"]) if isinstance(data.get("agent"), dict) else {}
        data["agent"].update(simulation=True, native_sensor_collected=False, dataset_template=True)
    raw["agent"] = dict(raw["agent"]) if isinstance(raw.get("agent"), dict) else {}
    raw["agent"].update(simulation=True, native_sensor_collected=False, dataset_template=True)
    return raw


def import_bundle(store, who, bundle_id, data):
    if bundle_id not in BUNDLES:
        raise KeyError("Packaged dataset bundle not found")
    if not isinstance(data, dict) or set(data)-{"expected_revision", "name", "description", "indexes"}:
        raise ValueError("Expected new revision, bundle name and index scope required")
    _expected(data, 0)
    bundle = BUNDLES[bundle_id]
    with principal.transaction(store, who, EDITORS) as (_, actor):
        indexes = _indexes(data.get("indexes"))
        if not principal.contains(actor["allowed_indexes"], indexes):
            raise PermissionError("Bundle scope exceeds current permissions")
    from .sequence_samples import generate
    scenarios = generate(variants_per_family=bundle["variants"], base_time=int(time.time()))
    if bundle["kind"] == "autoencoder":
        train = [s for s in scenarios if s["split"] == "train" and s["label"] == "normal"][:16]
        calibration = [s for s in scenarios if s["split"] == "validation" and s["label"] == "normal"][:8]
        scenarios = train + calibration
    identifier, now = str(uuid.uuid4()), time.time()
    values = {"name": evidence_scope.text(data.get("name", bundle["name"]), "dataset name", 128),
              "description": evidence_scope.text(data.get("description", "명시적 생성과 검증이 필요한 가상 학습 예제"), "dataset description", 2000, empty=True),
              "indexes": indexes, "kind": bundle["kind"], "state": "draft"}
    # Prepare bounded, generated immutable content outside the three-second
    # reserved transaction. Only exact local encoded rows enter its bulk INSERT;
    # grants are read again immediately before persistence.
    prepared, pointers, bodies = [], [], {}
    for scenario in scenarios:
        sid, vid = str(uuid.uuid4()), str(uuid.uuid4())
        host = "ml-" + identifier[:16] + "-" + scenario["host_group"]
        events = scenario["events"] if bundle["kind"] == "sequence" else scenario["events"][:1]
        templates = []
        for event in events:
            canonical = {"event_time": datetime.fromisoformat(event["data"]["@timestamp"]).timestamp(), "host": scenario["host_group"], "raw": {"xdr": {"data": event["data"]}}}
            templates.append(_namespace_template(canonical, identifier, scenario["host_group"], host))
        body = _sample({"scenario_id": identifier[:16] + ":" + scenario["scenario_id"],
            "split": {"train": "training", "validation": "calibration", "heldout": "holdout"}[scenario["split"]],
            "label": scenario["label"], "family": scenario["family"], "host_group": host, "mode": "template", "template_events": templates}, bundle["kind"])
        body["template_origin"] = {"bundle_id": bundle_id, "schema": "xsera.synthetic-sequence-dataset.v1", "synthetic": True, "native_sensor_collected": False}
        encoded, digest = encode(body), _digest(body)
        prepared.append((vid, identifier, actor["tenant"], sid, now, actor["name"], encoded, digest))
        pointers.append({"id": sid, "version_id": vid, "digest": digest})
        bodies[sid] = body
    counts = _counts(bodies)
    digest = _digest({"dataset_id": identifier, "revision": 1, **values, "samples": sorted(pointers, key=lambda p: p["id"])})
    summary = encode({"counts": counts, **values})
    with principal.transaction(store, actor, EDITORS, write=True) as (db, fresh):
        if fresh != actor:
            raise PermissionError("Bundle import permissions changed")
        _create(db, fresh, {**data, "name": values["name"], "description": values["description"], "kind": bundle["kind"]}, identifier=identifier)
        db.executemany("INSERT INTO ml_dataset_sample_versions VALUES(?,?,?,?,?,?,?,?)", prepared)
        db.executemany("INSERT INTO ml_dataset_revision_samples VALUES(?,?,?,?)", [(identifier, 1, p["id"], p["version_id"]) for p in pointers])
        db.execute("UPDATE ml_datasets SET version=1 WHERE id=?", (identifier,))
        db.execute("INSERT INTO ml_dataset_revisions VALUES(?,?,?,?,?,?,?,?)", (identifier, 1, fresh["tenant"], fresh["name"], now, digest, summary, "draft"))
        store.audit(db, fresh["tenant"], fresh["name"], "ml.dataset.revision", {"dataset_id": identifier, "revision": 1, "digest": digest, "counts": counts, "state": "draft", "bundle_id": bundle_id})
        return _public(db, fresh, db.execute("SELECT * FROM ml_datasets WHERE id=?", (identifier,)).fetchone())


def _materialization_guard(db, actor, identifier, job_id, claim=None):
    head = _head(db, actor, identifier)
    job = db.execute("SELECT * FROM ml_dataset_materializations WHERE id=? AND tenant=? AND dataset_id=?", (job_id, actor["tenant"], identifier)).fetchone()
    if not job or job["owner"] != actor["name"] or job["state"] not in {"pending", "running", "completed"}:
        raise ConflictError("Materialization is unavailable or cancelled")
    if job["current_revision"] != head["version"] or claim is not None and (job["claim"] != claim or job["state"] != "running"):
        raise ConflictError("Dataset changed or materialization claim was superseded")
    revision = _revision(db, head)
    summary = json.loads(revision["summary"])
    if revision["digest"] != job["input_digest"] or any(summary[key] != (json.loads(head["indexes"]) if key == "indexes" else head[key]) for key in ("name", "description", "indexes", "kind", "state")):
        raise ConflictError("Materialization's exact revision metadata changed")
    # The whole immutable revision is checked once at batch claim and again
    # at commit. Per-sample steps hash only their captured immutable sample
    # version, while rechecking current head/lease/actor/source each time.
    return head, job


def materialize(store, who, identifier, data):
    allowed = {"expected_revision", "confirmed_synthetic", "batch_size", "materialization_id"}
    if not isinstance(data, dict) or set(data)-allowed or data.get("confirmed_synthetic") is not True:
        raise ValueError("Explicit synthetic-only admission confirmation required")
    size = evidence_scope.integer(data.get("batch_size", 8), "materialization batch", 1, 16)
    claim, now = uuid.uuid4().hex, time.time()
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        head = _head(db, actor, identifier)
        _expected(data, head["version"])
        indexes = json.loads(head["indexes"])
        if not all(index.startswith("ml_synthetic_") for index in indexes):
            raise PermissionError("Explicit synthetic-only ml_synthetic_ index scope required")
        revision, items, bodies = _frozen(db, head)
        job_id = data.get("materialization_id")
        if job_id:
            head, job = _materialization_guard(db, actor, identifier, job_id)
            if job["state"] == "running" and now-job["updated"] < 120:
                raise ConflictError("Another request owns this materialization batch")
        else:
            if db.execute("SELECT 1 FROM ml_dataset_materializations WHERE dataset_id=? AND current_revision=? AND state IN ('pending','running')", (identifier, head["version"])).fetchone():
                raise ConflictError("Resume the existing materialization instead of starting a duplicate")
            pending = [{"sample_id": sid, "version_id": items[sid]} for sid, body in bodies.items() if body["mode"] == "template"]
            if not pending:
                raise ValueError("Dataset has no templates to materialize")
            job_id = str(uuid.uuid4())
            db.execute("INSERT INTO ml_dataset_materializations VALUES(?,?,?,?,?,?,?,?,?,0,NULL,?,?,NULL)", (job_id, actor["tenant"], identifier, head["version"], head["version"], revision["digest"], actor["name"], "pending", encode(pending), now, now))
            job = db.execute("SELECT * FROM ml_dataset_materializations WHERE id=?", (job_id,)).fetchone()
        if job["state"] == "completed":
            return _materialization_result(db, actor, head, job, 0)
        pending = json.loads(job["items"])
        selected = pending[job["position"]:job["position"]+size]
        db.execute("UPDATE ml_dataset_materializations SET state='running',claim=?,updated=?,error=NULL WHERE id=?", (claim, now, job_id))
        for item in selected:
            db.execute("INSERT OR IGNORE INTO ml_dataset_materialized_samples VALUES(?,?,NULL,NULL,'pending')", (job_id, item["sample_id"]))
    try:
        admitted = []
        for item in selected:
            sid = item["sample_id"]
            with principal.transaction(store, actor, ("admin",)) as (db, fresh):
                current, _ = _materialization_guard(db, fresh, identifier, job_id, claim)
                body = _bodies(db, {sid: item["version_id"]})[sid]
                receipt = db.execute("SELECT * FROM ml_dataset_materialized_samples WHERE materialization_id=? AND sample_id=?", (job_id, sid)).fetchone()
                source_id = receipt["source_id"]
            if not source_id:
                # Source registration itself requires a current administrator;
                # no credential is read, connector is contacted or code run.
                source = source_registry.save(store, actor, {"index": json.loads(current["indexes"])[0], "product": "json", "account": body["host_group"], "realm": "ml-synthetic:"+identifier, "credential_ref": "env:SAPIENTIA_CONNECTOR_ML_DATASET", "version": 0})
                source_id = source["id"]
                with principal.transaction(store, actor, ("admin",), write=True) as (db, fresh):
                    _materialization_guard(db, fresh, identifier, job_id, claim)
                    db.execute("UPDATE ml_dataset_materialized_samples SET source_id=? WHERE materialization_id=? AND sample_id=? AND source_id IS NULL", (source_id, job_id, sid))
                    source_id = db.execute("SELECT source_id FROM ml_dataset_materialized_samples WHERE materialization_id=? AND sample_id=?", (job_id, sid)).fetchone()[0]
            records = [{**event, "raw": _mark_synthetic(event["raw"]), "event_id": _digest(["ml-dataset-wire", identifier, job_id, item["version_id"], n]), "source": "ml-dataset-template", "sourcetype": "synthetic_ml_template"} for n, event in enumerate(body["template_events"])]
            result = connector_runtime.intake(store, actor, source_id, {"version": 1, "events": records, "cursor": _digest([job_id, sid, item["version_id"]]), "checkpoint_version": 0})
            ids = result["event_ids"]
            with principal.transaction(store, actor, ("admin",), write=True) as (db, fresh):
                _materialization_guard(db, fresh, identifier, job_id, claim)
                context = cpu_sequence._source_context(db, fresh, source_id)
                if context["version"] != 1:
                    raise ConflictError("Synthetic source changed during admission")
                db.execute("UPDATE ml_dataset_materialized_samples SET original_ids=?,state='admitted' WHERE materialization_id=? AND sample_id=?", (encode(ids), job_id, sid))
                db.execute("UPDATE ml_dataset_materializations SET updated=? WHERE id=? AND claim=? AND state='running'", (time.time(), job_id, claim))
                db.executemany("INSERT OR IGNORE INTO record_case_evidence_refs VALUES(?,?,?,?)", [(actor["tenant"], eid, "ml_dataset_materialize", job_id) for eid in ids])
            admitted.append((sid, body, ids))
        with principal.transaction(store, actor, ("admin",), write=True) as (db, fresh):
            current, job = _materialization_guard(db, fresh, identifier, job_id, claim)
            items = _items(db, identifier, current["version"])
            for sid, body, ids in admitted:
                receipt = db.execute("SELECT * FROM ml_dataset_materialized_samples WHERE materialization_id=? AND sample_id=?", (job_id, sid)).fetchone()
                context = cpu_sequence._source_context(db, fresh, receipt["source_id"])
                proofs = list(db.execute("SELECT p.*,r.digest AS current_digest FROM source_event_receipts p JOIN receipts r ON r.tenant=p.tenant AND r.event_id=p.event_id WHERE p.tenant=? AND p.event_id IN (SELECT value FROM json_each(?))", (fresh["tenant"], encode(ids))))
                if len(proofs) != len(ids) or any(p["source_id"] != context["id"] or p["source_version"] != context["version"] or p["receipt_digest"] != p["current_digest"] for p in proofs):
                    raise ConflictError("Synthetic originals or source authority changed")
                converted = {key: value for key, value in body.items() if key != "template_events"}
                converted.update(mode="originals", event_ids=ids)
                items[sid] = _new_sample(db, fresh, identifier, sid, converted)
            changed = _append_revision(store, db, fresh, current, items, materialization_id=job_id)
            position = job["position"] + len(admitted)
            db.execute("UPDATE ml_dataset_materializations SET current_revision=?,input_digest=?,position=?,state=?,claim=NULL,updated=? WHERE id=?", (changed["version"], _revision(db, changed)["digest"], position, "completed" if position == len(pending) else "pending", time.time(), job_id))
            db.execute("DELETE FROM record_case_evidence_refs WHERE tenant=? AND kind='ml_dataset_materialize' AND record_id=?", (fresh["tenant"], job_id))
            final = db.execute("SELECT * FROM ml_dataset_materializations WHERE id=?", (job_id,)).fetchone()
            return _materialization_result(db, fresh, changed, final, sum(len(ids) for _, _, ids in admitted))
    except Exception as exc:
        # Keep resumable receipts and only this job's temporary references.
        # A changed/deleted dataset is never silently rebound to a new head.
        with store.write_lock, store.control() as db:
            db.execute("UPDATE ml_dataset_materializations SET state=CASE WHEN state='running' THEN 'pending' ELSE state END,claim=NULL,error=?,updated=? WHERE id=? AND claim=?", (type(exc).__name__, time.time(), job_id, claim))
        raise


def _materialization_result(db, actor, head, job, accepted):
    total = db.execute("SELECT coalesce(sum(json_array_length(original_ids)),0) FROM ml_dataset_materialized_samples WHERE materialization_id=? AND state='admitted'", (job["id"],)).fetchone()[0]
    return {"dataset": _public(db, actor, head), "revision": head["version"], "version": head["version"],
            "materialization_id": job["id"], "completed": job["state"] == "completed", "remaining": len(json.loads(job["items"]))-job["position"],
            "accepted_originals": total, "batch_accepted_originals": accepted, "indexing_required": True,
            "synthetic": True, "native_effects": False, "automatic_model_activation": False, "live_policy_isolation_guaranteed": False}


def _manifest(head, bodies):
    if any(body["mode"] != "originals" for body in bodies.values()):
        raise ValueError("Template drafts cannot train; explicitly materialize and index their originals first")
    manifest = {split: [] for split in ("training", "calibration", "holdout")}
    for body in bodies.values():
        manifest[body["split"]].append({key: body[key] for key in ("scenario_id", "event_ids", "label", "family", "host_group")})
    if head["kind"] == "sequence":
        cpu_sequence._dataset(manifest)
    else:
        for split, minimum in (("training", 16), ("calibration", 8)):
            if len(manifest[split]) < minimum or any(item["label"] != "normal" or len(item["event_ids"]) != 1 for item in manifest[split]):
                raise ValueError("Autoencoder requires at least 16 training and 8 independent normal calibration originals")
            cpu_ml._ids([item["event_ids"][0] for item in manifest[split]], minimum)
        if manifest["holdout"]:
            raise ValueError("Autoencoder uses its separate normal calibration partition")
        for key in ("family", "host_group"):
            if {item[key] for item in manifest["training"]} & {item[key] for item in manifest["calibration"]}:
                raise ValueError("Dataset family and host groups must be disjoint across partitions")
    return manifest


def _inspect_dataset(store, actor, head, bodies):
    manifest = _manifest(head, bodies)
    indexes = json.loads(head["indexes"])
    items = [item for group in manifest.values() for item in group]
    if head["kind"] == "sequence":
        windows = cpu_sequence.inspect_sequences(store, actor, items, indexes)
        if any(w["host"] != item["host_group"] for w, item in zip(windows, items)):
            raise ValueError("Manifest host group must equal each original's actual host")
    else:
        rows, _ = cpu_sequence._fetch(store, actor, [item["event_ids"][0] for item in items], indexes)
        if any(rows[item["event_ids"][0]]["host"] != item["host_group"] for item in items):
            raise ValueError("Manifest host group must equal each original's actual host")
        windows = []
        for item in items:
            row = rows[item["event_ids"][0]]
            windows.append({**_receipt_windows({row["event_id"]: row})[0], "start": row["event_time"], "end": row["event_time"]})
    by_split, position = {}, 0
    for split, group in manifest.items():
        by_split[split] = windows[position:position+len(group)]
        position += len(group)
    pairs = [("training", "calibration")] + ([("calibration", "holdout")] if head["kind"] == "sequence" else [])
    if any(max(w["end"] for w in by_split[left]) >= min(w["start"] for w in by_split[right]) for left, right in pairs):
        raise ValueError("Training, calibration and holdout source times must be strictly disjoint and ordered")
    return manifest, windows


def validate(store, who, identifier, data):
    if not isinstance(data, dict) or set(data) != {"expected_revision"}:
        raise ValueError("Exact expected dataset revision required")
    with principal.transaction(store, who, EDITORS) as (db, actor):
        head = dict(_head(db, actor, identifier))
        _expected(data, head["version"])
        revision, _, bodies = _frozen(db, head)
        digest = revision["digest"]
    issues, windows = [], []
    try:
        _, windows = _inspect_dataset(store, actor, head, bodies)
    except (ValueError, KeyError, PermissionError, ConflictError, CapacityError) as exc:
        issues.append({"code": "templates_require_materialization" if any(b["mode"] == "template" for b in bodies.values()) else "dataset_not_ready", "message": str(exc)})
    result = {"revision": head["version"], "digest": digest, "ready": not issues, "issues": issues, "counts": _counts(bodies),
              "authority_rechecked": True, "split_names": ["training", "calibration", "holdout"] if head["kind"] == "sequence" else ["training", "calibration"],
              "labels_external": True, "model_input_from_authenticated_originals_only": True, "automatic_model_activation": False}
    with principal.transaction(store, actor, EDITORS, write=True) as (db, fresh):
        current = _head(db, fresh, identifier)
        _expected(data, current["version"])
        if _frozen(db, current)[0]["digest"] != digest:
            raise ConflictError("Dataset revision changed during validation")
        if not issues:
            _recheck(db, fresh, windows)
        db.execute("INSERT INTO ml_dataset_validations VALUES(?,?,?,?,?,?,?,?)", (str(uuid.uuid4()), identifier, current["version"], fresh["tenant"], fresh["name"], time.time(), digest, encode(result)))
        store.audit(db, fresh["tenant"], fresh["name"], "ml.dataset.validate", {"dataset_id": identifier, "revision": current["version"], "digest": digest, "ready": not issues})
    return result


def train(store, who, identifier, data):
    allowed = {"expected_revision", "name", "epochs", "reviewed_dataset", "normal_training_confirmed"}
    if not isinstance(data, dict) or set(data)-allowed or data.get("reviewed_dataset") is not True:
        raise ValueError("Explicit external dataset review acknowledgement and exact revision required")
    name = evidence_scope.text(data.get("name"), "model name", 128)
    with principal.transaction(store, who, EDITORS) as (db, actor):
        head = dict(_head(db, actor, identifier))
        _expected(data, head["version"])
        revision, _, bodies = _frozen(db, head)
        digest = revision["digest"]
    epochs = evidence_scope.integer(data.get("epochs", 30), "CPU epochs", 1, 60 if head["kind"] == "sequence" else 120)
    if head["kind"] == "autoencoder" and data.get("normal_training_confirmed") is not True:
        raise ValueError("Explicit normal autoencoder training acknowledgement required")
    manifest, windows = _inspect_dataset(store, actor, head, bodies)
    pin_id, claim_token = str(uuid.uuid4()), uuid.uuid4().hex
    with principal.transaction(store, actor, EDITORS, write=True) as (db, fresh):
        current = _head(db, fresh, identifier)
        _expected(data, current["version"])
        if _frozen(db, current)[0]["digest"] != digest:
            raise ConflictError("Dataset training snapshot changed")
        _recheck(db, fresh, windows)
        began = time.time()
        db.execute("INSERT INTO ml_dataset_training_claims VALUES(?,?,?,?,?,?,?,?,?,'running',?,NULL,NULL,0)", (pin_id, fresh["tenant"], identifier, head["version"], digest, fresh["name"], claim_token, began, began+TRAIN_LEASE_SECONDS, head["kind"]))
        db.executemany("INSERT OR IGNORE INTO record_case_evidence_refs VALUES(?,?,?,?)", [(actor["tenant"], p["event_id"], "ml_dataset_train", pin_id) for w in windows for p in w["provenance"]])
        store.audit(db, fresh["tenant"], fresh["name"], "ml.dataset.train.begin", {"dataset_id": identifier, "revision": head["version"], "digest": digest, "pin_id": pin_id})
    with _TRAINING_LOCK:
        _ACTIVE_TRAINING.add(_training_key(store, pin_id))
    try:
        def publication_check(db, fresh, model_id):
            # Exact immutable revision is allowed to finish after a later
            # ordinary edit/removal; current actor/source/receipt authority
            # is always checked inside the model's publication transaction.
            _recheck(db, fresh, windows)
            claimed = db.execute("SELECT * FROM ml_dataset_training_claims WHERE tenant=? AND id=? AND token=? AND state='running' AND pins_released=0", (fresh["tenant"], pin_id, claim_token)).fetchone()
            if not claimed or claimed["dataset_id"] != identifier or claimed["revision"] != head["version"] or claimed["digest"] != digest or claimed["owner"] != fresh["name"]:
                raise ConflictError("Dataset training invocation expired or was superseded")
            db.execute("UPDATE ml_dataset_training_claims SET state='completed',model_id=?,expires=? WHERE tenant=? AND id=? AND token=? AND state='running'", (model_id, time.time()+TRAIN_LEASE_SECONDS, fresh["tenant"], pin_id, claim_token))
            binding = {"dataset_id": identifier, "dataset_revision": head["version"], "dataset_digest": digest}
            db.execute("INSERT INTO ml_dataset_model_links VALUES(?,?,?,?,?,?,?,?)", (identifier, head["version"], fresh["tenant"], head["kind"], model_id, digest, fresh["name"], time.time()))
            store.audit(db, fresh["tenant"], fresh["name"], "ml.dataset.train.link", {**binding, "model_id": model_id})
            if head["kind"] == "sequence":
                return binding
            source_body = {"tenant": fresh["tenant"], "model_id": model_id, "dataset_id": identifier,
                "dataset_revision": head["version"], "dataset_digest": digest, "indexes": json.loads(head["indexes"]), "windows": windows}
            source_digest = _digest(source_body)
            db.execute("INSERT INTO ml_dataset_model_sources VALUES(?,?,?,?)", (fresh["tenant"], model_id, encode(source_body), source_digest))
            return {"schema": "xsera.dataset-model-sources.v1", "digest": source_digest}
        if head["kind"] == "sequence":
            model = cpu_sequence.train(store, actor, {"name": name, "indexes": json.loads(head["indexes"]), **manifest, "epochs": epochs, "reviewed_dataset": True}, _publication_check=publication_check)
        else:
            model = cpu_ml.train(store, actor, {"name": name, "indexes": json.loads(head["indexes"]),
                "training_ids": [item["event_ids"][0] for item in manifest["training"]],
                "validation_ids": [item["event_ids"][0] for item in manifest["calibration"]], "epochs": epochs,
                "normal_training_confirmed": True}, _publication_check=publication_check)
        if model.get("status") != "completed":
            return {**model, "dataset_id": identifier, "dataset_revision": head["version"], "dataset_digest": digest, "model_family": head["kind"]}
        head_changed = None
        try:
            with principal.transaction(store, actor, EDITORS) as (db, fresh):
                head_changed = _head(db, fresh, identifier, False)["version"] != head["version"]
        except (PermissionError, KeyError, ConflictError, CapacityError):
            # Publishing and the immutable dataset/model link already
            # committed together. A best-effort display check cannot turn
            # that successful candidate into an API error.
            pass
        return {"status": "completed", "model": model, "dataset_id": identifier, "dataset_revision": head["version"],
                "dataset_digest": digest, "model_family": head["kind"], "head_changed": head_changed,
                "automatic_model_activation": False}
    finally:
        # Release only this training invocation's temporary pins; candidate,
        # Case/anomaly/queue and other dataset/model ownership is untouched.
        try:
            with store.write_lock, store.control() as db:
                db.execute("DELETE FROM record_case_evidence_refs WHERE tenant=? AND kind='ml_dataset_train' AND record_id=?", (actor["tenant"], pin_id))
                db.execute("UPDATE ml_dataset_training_claims SET state=CASE WHEN state='running' THEN 'failed' ELSE state END,error=CASE WHEN state='running' THEN 'training did not publish' ELSE error END,pins_released=1 WHERE tenant=? AND id=? AND token=?", (actor["tenant"], pin_id, claim_token))
        finally:
            with _TRAINING_LOCK:
                _ACTIVE_TRAINING.discard(_training_key(store, pin_id))


def register(app, store, runtime, who, body):
    from fastapi import Request
    from starlette.concurrency import run_in_threadpool

    @app.get("/api/v3/ml/dataset-bundles")
    def catalog(request: Request):
        return bundle_catalog(store, who(request))

    @app.post("/api/v3/ml/dataset-bundles/{bundle_id}/import", status_code=201)
    async def importing(bundle_id: str, request: Request):
        return await run_in_threadpool(import_bundle, store, who(request, EDITORS), bundle_id, await body(request))

    @app.get("/api/v3/ml/datasets")
    def datasets(request: Request, cursor: int = 0, count: int = 25):
        return listing(store, who(request), cursor, count)

    @app.post("/api/v3/ml/datasets", status_code=201)
    async def creating(request: Request):
        return create(store, who(request, EDITORS), await body(request))

    @app.get("/api/v3/ml/datasets/{dataset_id}")
    def detail(dataset_id: str, request: Request):
        return get(store, who(request), dataset_id)

    @app.put("/api/v3/ml/datasets/{dataset_id}")
    async def editing(dataset_id: str, request: Request):
        return update(store, who(request, EDITORS), dataset_id, await body(request))

    @app.delete("/api/v3/ml/datasets/{dataset_id}")
    async def removing(dataset_id: str, request: Request):
        return remove(store, who(request, EDITORS), dataset_id, await body(request))

    @app.get("/api/v3/ml/datasets/{dataset_id}/revisions")
    def history(dataset_id: str, request: Request, cursor: int = 0, count: int = 25):
        return revisions(store, who(request), dataset_id, cursor, count)

    @app.get("/api/v3/ml/datasets/{dataset_id}/samples")
    def page(dataset_id: str, request: Request, cursor: int = 0, count: int = 25):
        return samples(store, who(request), dataset_id, cursor, count)

    @app.get("/api/v3/ml/datasets/{dataset_id}/samples/{sample_id}")
    def sample_detail(dataset_id: str, sample_id: str, request: Request):
        return samples(store, who(request), dataset_id, sid=sample_id)

    @app.post("/api/v3/ml/datasets/{dataset_id}/samples", status_code=201)
    async def adding(dataset_id: str, request: Request):
        return await run_in_threadpool(save_sample, store, who(request, EDITORS), dataset_id, await body(request))

    @app.put("/api/v3/ml/datasets/{dataset_id}/samples/{sample_id}")
    async def changing(dataset_id: str, sample_id: str, request: Request):
        return await run_in_threadpool(save_sample, store, who(request, EDITORS), dataset_id, await body(request), sample_id)

    @app.delete("/api/v3/ml/datasets/{dataset_id}/samples/{sample_id}")
    async def deleting(dataset_id: str, sample_id: str, request: Request):
        return remove_sample(store, who(request, EDITORS), dataset_id, sample_id, await body(request))

    @app.post("/api/v3/ml/datasets/{dataset_id}/materialize")
    async def admitting(dataset_id: str, request: Request):
        return await run_in_threadpool(materialize, store, who(request, ("admin",)), dataset_id, await body(request))

    @app.post("/api/v3/ml/datasets/{dataset_id}/validate")
    async def validating(dataset_id: str, request: Request):
        return await run_in_threadpool(validate, store, who(request, EDITORS), dataset_id, await body(request))

    @app.post("/api/v3/ml/datasets/{dataset_id}/train")
    async def training(dataset_id: str, request: Request):
        return await run_in_threadpool(train, store, who(request, EDITORS), dataset_id, await body(request))
