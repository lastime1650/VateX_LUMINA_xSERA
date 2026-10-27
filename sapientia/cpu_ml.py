"""Scoped, reviewed CPU autoencoder; anomaly evidence is never attack probability.

Training uses immutable snapshots of persisted originals selected by event ID.
Inference refetches originals, verifies hashes, and rechecks both model owner and
reviewer's current grants. Model execution is confined to a bounded CPU child.
"""

import hashlib
import ipaddress
import json
import math
import os
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from . import migrations, principal
from .entities import exact_indexes
from .storage import CapacityError, ConflictError, encode

EDITORS = ("admin", "analyst")
FEATURE_SCHEMA = "xsera.cpu-features.v1"
MODEL_SCHEMA = "xsera.cpu-autoencoder.v1"
FEATURES = ("hour_sin", "hour_cos", "remote_port_scaled", "command_length_scaled",
            "network_external", "process_depth", "file_activity")
FEATURE_CONTRACT_DIGEST = hashlib.sha256(encode({
    "schema": FEATURE_SCHEMA, "fields": FEATURES, "time_basis": "UTC event_time",
    "bounded_scales": {"dest_port": 65535, "command_length": 8192, "explicit_process_depth": 32},
    "source_priority": ["raw.security", "raw structured vendor fields", "raw.xdr.data"],
    "endpoint_paths": ["destination.port", "destination.ip", "process.command_line", "process.depth", "process.process_depth", "file.path", "event.action"],
    "missing_optional": "zero with explicit missing_source_features", "ancestry_inferred": False,
}).encode()).hexdigest()
MAX_EVENTS = 1000
STATUS_PROBE_TIMEOUT_SECONDS = 30
STATUS_NEGATIVE_TTL_SECONDS = 5
_status_cache = None
_status_retry_at = 0.0
_status_lock = threading.Lock()


def initialize(store):
    migrations.apply_store(store, "cpu_ml", [
        "CREATE TABLE IF NOT EXISTS cpu_ml_models(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,name TEXT NOT NULL,revision INTEGER NOT NULL,indexes TEXT NOT NULL,created REAL NOT NULL,definition TEXT NOT NULL,snapshot TEXT NOT NULL,digest TEXT NOT NULL,metrics TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS cpu_ml_models_scope ON cpu_ml_models(tenant,name,revision)",
        "CREATE TABLE IF NOT EXISTS cpu_ml_reviews(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,model_id TEXT NOT NULL,reviewer TEXT NOT NULL,at REAL NOT NULL,notes TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS cpu_ml_active(tenant TEXT NOT NULL,name TEXT NOT NULL,model_id TEXT NOT NULL,review_id TEXT NOT NULL,updated REAL NOT NULL,PRIMARY KEY(tenant,name))",
        "CREATE TABLE IF NOT EXISTS cpu_ml_runs(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,model_id TEXT NOT NULL,indexes TEXT NOT NULL,created REAL NOT NULL,shadow INTEGER NOT NULL,result TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS cpu_ml_runs_tenant ON cpu_ml_runs(tenant,created)",
    ])
    from . import cpu_ml_lifecycle
    cpu_ml_lifecycle.initialize(store)


def _worker(payload, timeout=20):
    text = encode(payload)
    if len(text.encode()) > 2 * 1024 * 1024:
        raise CapacityError("CPU worker request exceeds 2 MiB")
    from .cpu_ml_runtime import request
    return request(payload, timeout)


def runtime_status(force=False):
    global _status_cache, _status_retry_at
    # Serialize cold starts and recheck the cache after another probe completes.
    with _status_lock:
        if _status_cache is not None and not force:
            if _status_cache.get("available") is True or time.monotonic() < _status_retry_at:
                return dict(_status_cache)
        try:
            value = _worker({"operation": "status"}, timeout=STATUS_PROBE_TIMEOUT_SECONDS)
        except CapacityError as exc:
            value = {"worker_error": "Deadline", "reason": str(exc)}
        if value.get("worker_error"):
            value = {"available": False, "status": "시스템에서 호환되지 않음", "reason": value["reason"],
                     "framework": "pytorch", "device": "cpu", "simulation_continues": True}
        _status_cache = value
        # Start the retry interval after the bounded handshake, including timeout.
        _status_retry_at = (0.0 if value.get("available") is True else
                            time.monotonic() + STATUS_NEGATIVE_TTL_SECONDS)
        return dict(value)


def _number(value, default=0):
    if type(value) not in (int, float) or not math.isfinite(value):
        return default
    return value


def _feature_inputs(event):
    raw = event.get("raw", {})
    if isinstance(raw, str):
        raw = json.loads(raw)
    if not isinstance(raw, dict):
        raw = {}
    security = raw.get("security", {}) if isinstance(raw, dict) else {}
    if not isinstance(security, dict):
        security = {}
    endpoint = raw.get("xdr", {}).get("data", {}) if isinstance(raw.get("xdr"), dict) else {}
    if not isinstance(endpoint, dict):
        endpoint = {}
    process = endpoint.get("process", {}) if isinstance(endpoint.get("process"), dict) else {}
    destination = endpoint.get("destination", {}) if isinstance(endpoint.get("destination"), dict) else {}
    file = endpoint.get("file", {}) if isinstance(endpoint.get("file"), dict) else {}
    observed = endpoint.get("event", {}) if isinstance(endpoint.get("event"), dict) else {}
    def pick(*values):
        return next((value for value in values if value is not None), None)
    return {"port": pick(security.get("dest_port"), raw.get("dest_port"), raw.get("dport"), destination.get("port")),
            "command": pick(security.get("command_line"), raw.get("command_line"), raw.get("CommandLine"), process.get("command_line")),
            "address": pick(security.get("dest_ip"), raw.get("dest_ip"), raw.get("dstip"), destination.get("ip")),
            "action": pick(security.get("action"), raw.get("action"), observed.get("action")),
            "file": pick(security.get("file_path"), raw.get("file_path"), file.get("path")),
            "depth": pick(security.get("process_depth"), raw.get("process_depth"), process.get("depth"), process.get("process_depth"))}


def extract_features(event):
    inputs = _feature_inputs(event)
    phase = (float(event["event_time"]) % 86400) / 86400 * 2 * math.pi
    port = inputs["port"]
    try:
        port = float(port)
    except (ValueError, TypeError):
        port = 0
    command = inputs["command"]
    if not isinstance(command, str):
        command = ""
    address = inputs["address"]
    try:
        external = float(ipaddress.ip_address(address).is_global)
    except (ValueError, TypeError):
        external = 0.0
    action = inputs["action"]
    file_activity = bool(inputs["file"] or
                         (isinstance(action, str) and action.startswith("file_")))
    depth = inputs["depth"]
    values = [(math.sin(phase)+1)/2, (math.cos(phase)+1)/2,
              min(65535, max(0, _number(port))) / 65535,
              min(len(command), 8192)/8192, external,
              min(32, max(0, _number(depth))) / 32, float(file_activity)]
    return dict(zip(FEATURES, values))


def _ids(value, minimum=1):
    if not isinstance(value, list) or not minimum <= len(value) <= MAX_EVENTS:
        raise ValueError(f"{minimum}..{MAX_EVENTS} explicit original event IDs required")
    if any(not isinstance(x, str) or not x or len(x) > 256 for x in value) or len(set(value)) != len(value):
        raise ValueError("Original event IDs must be unique bounded strings")
    return sorted(value)


def _originals(store, actor, ids, indexes):
    if not principal.contains(actor["allowed_indexes"], indexes):
        raise PermissionError("ML indexes exceed current permissions")
    result = store.analytics_query(
        "SELECT event_id,event_time,source,sourcetype,host,severity,message,raw,index_name FROM events_all WHERE tenant=? AND event_id IN (SELECT unnest(?)) AND index_name IN (SELECT unnest(?)) ORDER BY event_id",
        [actor["tenant"], ids, indexes], max_rows=len(ids), timeout=10)["rows"]
    if {r["event_id"] for r in result} != set(ids):
        raise KeyError("Original ML event not found in the authorized indexes")
    with store.control() as db:
        receipts = {r["event_id"]: r["digest"] for r in db.execute(
            "SELECT event_id,digest FROM receipts WHERE tenant=? AND event_id IN (SELECT value FROM json_each(?))",
            (actor["tenant"], encode(ids)))}
    if set(receipts) != set(ids):
        raise ConflictError("Original ML receipt is unavailable")
    records = []
    for event in result:
        event["raw"] = json.loads(event["raw"]) if isinstance(event["raw"], str) else event["raw"]
        features = extract_features(event)
        provenance = {"event_id": event["event_id"], "index": event["index_name"],
                      "receipt_digest": receipts[event["event_id"]],
                      "event_digest": hashlib.sha256(encode(event).encode()).hexdigest(),
                      "feature_schema": FEATURE_SCHEMA,
                      "mapping_version": event["raw"].get("security", {}).get("version") if isinstance(event["raw"].get("security"), dict) else None,
                      "missing_values_encoded_as_zero": True,
                      "missing_source_features": sorted(key for key, value in _feature_inputs(event).items() if value is None),
                      "feature_digest": hashlib.sha256(encode(features).encode()).hexdigest()}
        records.append({"features": features, "provenance": provenance})
    return records


def _load(db, actor, identifier, require_review=False):
    row = db.execute("SELECT * FROM cpu_ml_models WHERE id=? AND tenant=?", (identifier, actor["tenant"])).fetchone()
    if not row or not principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
        raise KeyError("CPU ML model not found")
    from . import cpu_ml_lifecycle
    cpu_ml_lifecycle.assert_not_retired(db, actor["tenant"], "autoencoder", identifier)
    owner = principal.current(db, {"name": row["owner"], "tenant": row["tenant"], "role": "analyst"}, EDITORS)
    if not principal.contains(owner["allowed_indexes"], json.loads(row["indexes"])):
        raise PermissionError("Model owner no longer has the model's full index scope")
    definition, snapshot = json.loads(row["definition"]), json.loads(row["snapshot"])
    if hashlib.sha256(encode({"definition": definition, "snapshot": snapshot}).encode()).hexdigest() != row["digest"]:
        raise ConflictError("Immutable CPU model hash mismatch")
    if snapshot["schema"] != MODEL_SCHEMA or snapshot["feature_schema"] != FEATURE_SCHEMA:
        raise ConflictError("CPU model schema is unsupported")
    if (definition.get("architecture") != [7, 6, 3, 6, 7]
            or definition.get("feature_contract_digest") != FEATURE_CONTRACT_DIGEST
            or definition.get("optimizer") != "Adam" or definition.get("seed") != 81213
            or type(definition.get("epochs")) is not int or not 1 <= definition["epochs"] <= 120
            or type(snapshot.get("threshold")) not in (int, float)
            or not math.isfinite(snapshot["threshold"]) or snapshot["threshold"] <= 0):
        raise ConflictError("CPU model feature/architecture contract is unsupported")
    if "dataset_source_guard" in definition:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ml_dataset_model_sources'").fetchone():
            raise ConflictError("Dataset model source guard storage unavailable")
        from .ml_datasets import validate_model_sources
        validate_model_sources(db, actor, identifier, definition["dataset_source_guard"])
    if require_review:
        review = db.execute("SELECT r.* FROM cpu_ml_active a JOIN cpu_ml_reviews r ON r.id=a.review_id WHERE a.tenant=? AND a.model_id=?",
                            (actor["tenant"], identifier)).fetchone()
        if not review or review["reviewer"] == row["owner"]:
            raise PermissionError("Independent active CPU model approval required")
        reviewer = principal.current(db, {"name": review["reviewer"], "tenant": row["tenant"], "role": "analyst"}, EDITORS)
        if not principal.contains(reviewer["allowed_indexes"], json.loads(row["indexes"])):
            raise PermissionError("Model reviewer no longer has the model's full index scope")
    return row, definition, snapshot


def _public(db, row):
    active = bool(db.execute("SELECT 1 FROM cpu_ml_active WHERE tenant=? AND model_id=?", (row["tenant"], row["id"])).fetchone())
    snapshot = json.loads(row["snapshot"])
    from . import cpu_ml_lifecycle
    retired = cpu_ml_lifecycle.retirement(db, row["tenant"], "autoencoder", row["id"])
    return {"id": row["id"], "model_id": row["id"], "model_family": "autoencoder", "retired": retired is not None, "retirement": retired, "name": row["name"], "revision": row["revision"],
            "owner": row["owner"], "indexes": json.loads(row["indexes"]), "created": row["created"],
            "digest": row["digest"], "active": active, "device": "cpu", "framework": "pytorch",
            "feature_schema": FEATURE_SCHEMA, "features": list(FEATURES), "threshold": snapshot["threshold"],
            "metrics": json.loads(row["metrics"]), "malicious_probability": False}


def train(store, who, data, *, _publication_check=None):
    fields = {"name", "indexes", "training_ids", "validation_ids", "epochs", "normal_training_confirmed"}
    if not isinstance(data, dict) or set(data)-fields or not {"name", "indexes", "training_ids", "validation_ids"} <= set(data):
        raise ValueError("Expected CPU model name, indexes, training_ids and validation_ids")
    name = data["name"]
    if not isinstance(name, str) or not name.strip() or len(name) > 128:
        raise ValueError("CPU model name requires 1..128 characters")
    if data.get("normal_training_confirmed") is not True:
        raise ValueError("Explicit normal-training review acknowledgement required")
    indexes = exact_indexes(data["indexes"])
    train_ids, valid_ids = _ids(data["training_ids"], 16), _ids(data["validation_ids"], 8)
    if set(train_ids) & set(valid_ids):
        raise ValueError("Training and holdout original IDs must be disjoint")
    epochs = data.get("epochs", 60)
    if type(epochs) is not int or not 1 <= epochs <= 120:
        raise ValueError("CPU model epochs must be 1..120")
    with principal.transaction(store, who, EDITORS) as (_, actor):
        if not principal.contains(actor["allowed_indexes"], indexes):
            raise PermissionError("Training scope exceeds current permissions")
    if not runtime_status()["available"]:
        return {**runtime_status(), "status": "unavailable", "compatibility": "시스템에서 호환되지 않음"}
    training, validation = _originals(store, actor, train_ids, indexes), _originals(store, actor, valid_ids, indexes)
    output = _worker({"operation": "train", "training": [list(r["features"].values()) for r in training],
                      "validation": [list(r["features"].values()) for r in validation], "epochs": epochs}, timeout=25)
    if output.get("worker_error"):
        return {"status": "unavailable", "available": False, "reason": output["reason"], "compatibility": "시스템에서 호환되지 않음"}
    output["metrics"]["worker_wall_ms"] = output["worker_wall_ms"]
    definition = {"name": name, "indexes": indexes, "epochs": epochs, "normal_training_confirmed": True,
                  "architecture": [7, 6, 3, 6, 7], "optimizer": "Adam", "seed": 81213,
                  "feature_contract_digest": FEATURE_CONTRACT_DIGEST,
                  "framework_version": output["framework_version"]}
    snapshot = {"schema": MODEL_SCHEMA, "feature_schema": FEATURE_SCHEMA, "weights": output["weights"],
                "threshold": output["threshold"], "training": training, "validation": validation}
    digest = hashlib.sha256(encode({"definition": definition, "snapshot": snapshot}).encode()).hexdigest()
    with principal.transaction(store, actor, EDITORS, write=True) as (db, fresh):
        if actor != fresh or not principal.contains(fresh["allowed_indexes"], indexes):
            raise PermissionError("ML training permissions changed; retry")
        receipts = {r["event_id"]: r["digest"] for r in db.execute(
            "SELECT event_id,digest FROM receipts WHERE tenant=? AND event_id IN (SELECT value FROM json_each(?))",
            (fresh["tenant"], encode(train_ids+valid_ids)))}
        if any(receipts.get(record["provenance"]["event_id"]) != record["provenance"]["receipt_digest"] for record in training+validation):
            raise ConflictError("ML originals changed or were retired during training")
        revision = db.execute("SELECT coalesce(max(revision),0)+1 FROM cpu_ml_models WHERE tenant=? AND name=?", (fresh["tenant"], name)).fetchone()[0]
        identifier = str(uuid.uuid4())
        if _publication_check is not None:
            definition["dataset_source_guard"] = _publication_check(db, fresh, identifier)
            digest = hashlib.sha256(encode({"definition": definition, "snapshot": snapshot}).encode()).hexdigest()
        db.execute("INSERT INTO cpu_ml_models VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                   (identifier, fresh["tenant"], fresh["name"], name, revision, encode(indexes), time.time(), encode(definition), encode(snapshot), digest, encode(output["metrics"])))
        db.executemany("INSERT OR IGNORE INTO record_case_evidence_refs VALUES(?,?,?,?)",
                       [(fresh["tenant"], event_id, "cpu_ml_model", identifier) for event_id in train_ids+valid_ids])
        store.audit(db, fresh["tenant"], fresh["name"], "cpu_ml.train", {"id": identifier, "digest": digest, "revision": revision, "indexes": indexes})
        return {"status": "completed", **_public(db, db.execute("SELECT * FROM cpu_ml_models WHERE id=?", (identifier,)).fetchone())}


def activate(store, who, model_id, notes):
    if not isinstance(notes, str) or not 8 <= len(notes.strip()) <= 2000:
        raise ValueError("Independent review notes require 8..2000 characters")
    with principal.transaction(store, who, EDITORS, write=True) as (db, actor):
        row, _, _ = _load(db, actor, model_id)
        if actor["name"] == row["owner"]:
            raise PermissionError("Model creator cannot approve their own model")
        review_id = str(uuid.uuid4())
        db.execute("INSERT INTO cpu_ml_reviews VALUES(?,?,?,?,?,?)", (review_id, actor["tenant"], model_id, actor["name"], time.time(), notes))
        db.execute("INSERT INTO cpu_ml_active VALUES(?,?,?,?,?) ON CONFLICT(tenant,name) DO UPDATE SET model_id=excluded.model_id,review_id=excluded.review_id,updated=excluded.updated",
                   (actor["tenant"], row["name"], model_id, review_id, time.time()))
        store.audit(db, actor["tenant"], actor["name"], "cpu_ml.activate", {"model_id": model_id, "digest": row["digest"], "review_id": review_id})
        return _public(db, row)


def rollback(store, who, model_id, notes):
    # A rollback is an explicit, freshly peer-approved activation of an older
    # immutable version; it never trusts a stale review or the model's filename.
    return activate(store, who, model_id, notes)


def disable(store, who, model_id):
    with principal.transaction(store, who, EDITORS, write=True) as (db, actor):
        row, _, _ = _load(db, actor, model_id)
        db.execute("DELETE FROM cpu_ml_active WHERE tenant=? AND model_id=?", (actor["tenant"], model_id))
        store.audit(db, actor["tenant"], actor["name"], "cpu_ml.disable", {"model_id": model_id})
        return {"model_id": model_id, "active": False}


def list_models(store, who):
    with principal.transaction(store, who) as (db, actor):
        result = []
        for row in db.execute("SELECT * FROM cpu_ml_models WHERE tenant=? ORDER BY created DESC", (actor["tenant"],)):
            try:
                from . import cpu_ml_lifecycle
                if principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])) and cpu_ml_lifecycle.retirement(db, actor["tenant"], "autoencoder", row["id"]):
                    result.append(_public(db, row))
                    continue
                visible, _, _ = _load(db, actor, row["id"])
                result.append(_public(db, visible))
            except (KeyError, PermissionError):
                continue
        return result


def validate_publication(store, db, actor, model_id, digest, revision):
    """Validate a prediction's authority inside the Signal write transaction."""
    if not db.in_transaction:
        raise ConflictError("CPU ML publication requires the caller's reserved transaction")
    fresh = principal.current(db, actor, EDITORS)
    if type(revision) is not int or revision < 1 or not isinstance(digest, str) or len(digest) != 64:
        raise ValueError("Exact CPU model revision and SHA-256 digest required")
    row, _, _ = _load(db, fresh, model_id, require_review=True)
    if row["digest"] != digest or row["revision"] != revision:
        raise ConflictError("CPU ML prediction belongs to a different immutable model revision")
    return _public(db, row)


def compatible_models(store, who, indexes):
    """Return reviewed active models covering all requested exact indexes."""
    indexes = exact_indexes(indexes)
    with principal.transaction(store, who) as (db, actor):
        if not principal.contains(actor["allowed_indexes"], indexes):
            raise PermissionError("ML selection scope exceeds current permissions")
        result = []
        for pointer in db.execute("SELECT model_id FROM cpu_ml_active WHERE tenant=? ORDER BY updated DESC,name", (actor["tenant"],)).fetchall():
            try:
                row, _, _ = _load(db, actor, pointer["model_id"], require_review=True)
            except (KeyError, PermissionError):
                continue
            if principal.contains(json.loads(row["indexes"]), indexes):
                result.append(_public(db, row))
        return result


def infer_events(store, who, events, *, model_id=None, shadow=False):
    if type(shadow) is not bool:
        raise ValueError("ML shadow must be a boolean")
    ids = _ids([event["event_id"] for event in events])
    with principal.transaction(store, who) as (db, actor):
        if model_id is None:
            candidates = db.execute("SELECT model_id FROM cpu_ml_active WHERE tenant=? ORDER BY updated DESC", (actor["tenant"],)).fetchall()
            for candidate in candidates:
                try:
                    row, definition, snapshot = _load(db, actor, candidate[0], True)
                    model_id = row["id"]
                    break
                except (KeyError, PermissionError):
                    continue
            else:
                return {"status": "no_active_model", "results": []}
        else:
            row, definition, snapshot = _load(db, actor, model_id, not shadow)
    if not runtime_status()["available"]:
        return {**runtime_status(), "status": "unavailable", "results": [], "compatibility": "시스템에서 호환되지 않음"}
    records = _originals(store, actor, ids, json.loads(row["indexes"]))
    output = _worker({"operation": "infer", "weights": snapshot["weights"],
                      "features": [list(record["features"].values()) for record in records]}, timeout=15)
    if output.get("worker_error"):
        return {"status": "unavailable", "results": [], "reason": output["reason"], "compatibility": "시스템에서 호환되지 않음"}
    results = []
    for record, score, errors in zip(records, output["scores"], output["feature_errors"]):
        provenance = record["provenance"]
        results.append({"event_id": provenance["event_id"], "event_ids": [provenance["event_id"]],
                        "model_id": model_id, "revision": row["revision"], "digest": row["digest"],
                        "features": record["features"], "provenance": provenance,
                        "feature_error": dict(zip(FEATURES, errors)), "score": score,
                        "threshold": snapshot["threshold"], "anomaly": score > snapshot["threshold"],
                        "malicious_probability": False, "shadow": shadow})
    answer = {"status": "completed", "results": results, "duration_ms": output["duration_ms"],
              "worker_wall_ms": output["worker_wall_ms"], "device": "cpu", "model_id": model_id,
              "digest": row["digest"], "shadow": shadow}
    with principal.transaction(store, actor, write=True) as (db, fresh):
        if fresh != actor:
            raise PermissionError("ML inference permissions changed; retry")
        current, _, _ = _load(db, fresh, model_id, not shadow)
        if current["digest"] != row["digest"]:
            raise ConflictError("CPU model changed during inference")
        receipts = {r["event_id"]: r["digest"] for r in db.execute(
            "SELECT event_id,digest FROM receipts WHERE tenant=? AND event_id IN (SELECT value FROM json_each(?))",
            (fresh["tenant"], encode(ids)))}
        if any(receipts.get(record["provenance"]["event_id"]) != record["provenance"]["receipt_digest"] for record in records):
            raise ConflictError("ML originals changed or were retired during inference")
        answer["run_id"] = str(uuid.uuid4())
        db.execute("INSERT INTO cpu_ml_runs VALUES(?,?,?,?,?,?,?,?)", (answer["run_id"], actor["tenant"], actor["name"], model_id, row["indexes"], time.time(), int(shadow), encode(answer)))
        from . import cpu_ml_lifecycle
        cpu_ml_lifecycle.record_run(db, actor, "autoencoder", answer["run_id"], answer)
        store.audit(db, actor["tenant"], actor["name"], "cpu_ml.infer", {"run_id": answer["run_id"], "model_id": model_id, "shadow": shadow, "events": len(ids), "anomalies": sum(r["anomaly"] for r in results)})
    return answer


def run_due(store, now=None):
    # Training requires explicit normal-cohort acknowledgement and peer review.
    # Unified-signal worker calls infer_events on its own durable batches.
    with store.control() as db:
        count = db.execute("SELECT count(*) FROM cpu_ml_active").fetchone()[0]
    return {"active_models": count, "automatic_training": False, "device": "cpu"}


def register(app, store, runtime, who, body):
    from fastapi import Request
    from starlette.concurrency import run_in_threadpool
    from . import cpu_ml_lifecycle
    cpu_ml_lifecycle.register(app, store, runtime, who, body)

    @app.get("/api/v3/ml/status")
    async def status(request: Request):
        with principal.transaction(store, who(request)):
            pass
        return await run_in_threadpool(runtime_status)

    @app.get("/api/v3/ml/models")
    def models(request: Request):
        return list_models(store, who(request))

    @app.post("/api/v3/ml/models", status_code=201)
    async def training(request: Request):
        return await run_in_threadpool(train, store, who(request, EDITORS), await body(request))

    @app.post("/api/v3/ml/models/{model_id}/activate")
    async def approval(model_id: str, request: Request):
        data = await body(request)
        if set(data) != {"notes"}:
            raise ValueError("Expected independent review notes")
        return activate(store, who(request, EDITORS), model_id, data["notes"])

    @app.post("/api/v3/ml/models/{model_id}/rollback")
    async def reverting(model_id: str, request: Request):
        data = await body(request)
        if set(data) != {"notes"}:
            raise ValueError("Expected independent rollback review notes")
        return rollback(store, who(request, EDITORS), model_id, data["notes"])

    @app.post("/api/v3/ml/models/{model_id}/disable")
    def disabling(model_id: str, request: Request):
        return disable(store, who(request, EDITORS), model_id)

    @app.post("/api/v3/ml/models/{model_id}/infer")
    async def inference(model_id: str, request: Request):
        data = await body(request)
        if set(data)-{"event_ids", "shadow"} or "event_ids" not in data:
            raise ValueError("Expected original event_ids and optional shadow boolean")
        ids = _ids(data["event_ids"])
        return await run_in_threadpool(infer_events, store, who(request), [{"event_id": eid} for eid in ids], model_id=model_id, shadow=data.get("shadow", False))
