"""Archive normal ML payloads without deleting permanent run/audit history.

Only a run's temporary normal/shadow references are released. Model training,
live anomaly, Case, hold and queued-work references remain separate and intact.
Original telemetry is removed only by the existing capacity cleanup policy.
"""
import hashlib
import json
import time

from . import evidence_scope, migrations, principal
from .storage import ConflictError, encode

TABLES = {"autoencoder": "cpu_ml_runs", "sequence": "cpu_sequence_runs"}
PREFIX = {"autoencoder": "cpu_ml", "sequence": "cpu_sequence"}
NORMAL_PAYLOAD_SECONDS = 86400
NORMAL_PAYLOADS_PER_MODEL = 128


def digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def initialize(store):
    migrations.apply_store(store, "cpu_ml_lifecycle", [
        "CREATE TABLE IF NOT EXISTS cpu_ml_run_retention(family TEXT NOT NULL,run_id TEXT NOT NULL,tenant TEXT NOT NULL,owner TEXT NOT NULL,indexes TEXT NOT NULL,model_id TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,state TEXT NOT NULL,input_digest TEXT NOT NULL,archived REAL,summary TEXT NOT NULL,PRIMARY KEY(family,run_id))",
        "CREATE INDEX IF NOT EXISTS cpu_ml_normal_payload_age ON cpu_ml_run_retention(tenant,family,model_id,state,created)",
        "CREATE INDEX IF NOT EXISTS cpu_ml_retention_expiry ON cpu_ml_run_retention(state,expires)",
    ])
    migrations.apply_store(store, "cpu_ml_lifecycle", [
        "CREATE TABLE IF NOT EXISTS cpu_ml_retired_models(family TEXT NOT NULL,model_id TEXT NOT NULL,tenant TEXT NOT NULL,retired_by TEXT NOT NULL,retired_at REAL NOT NULL,indexes TEXT NOT NULL,model_digest TEXT NOT NULL,summary TEXT NOT NULL,PRIMARY KEY(family,model_id))",
        "CREATE INDEX IF NOT EXISTS cpu_ml_retirement_scope ON cpu_ml_retired_models(tenant,family,retired_at)",
    ], version=2)


def retirement(db, tenant, family, model_id):
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='cpu_ml_retired_models'").fetchone():
        return None
    row = db.execute("SELECT summary FROM cpu_ml_retired_models WHERE tenant=? AND family=? AND model_id=?", (tenant, family, model_id)).fetchone()
    return json.loads(row[0]) if row else None


def assert_not_retired(db, tenant, family, model_id):
    if retirement(db, tenant, family, model_id):
        raise ConflictError("Retired CPU model cannot be activated or inferred")


def retire_model(store, who, family, model_id, notes):
    if family not in TABLES:
        raise ValueError("Supported CPU model family required")
    model_id = evidence_scope.text(model_id, "retired model ID")
    notes = evidence_scope.text(notes, "independent retirement review notes", 2000)
    prefix = PREFIX[family]
    with principal.transaction(store, who, ("admin", "analyst"), write=True) as (db, actor):
        row = db.execute("SELECT * FROM "+prefix+"_models WHERE tenant=? AND id=?", (actor["tenant"], model_id)).fetchone()
        if not row or not principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
            raise KeyError("Retirement requires complete current model scope")
        if actor["name"] == row["owner"]:
            raise PermissionError("Model creator cannot approve their own retirement")
        old = retirement(db, actor["tenant"], family, model_id)
        if old is not None:
            return old
        if db.execute("SELECT 1 FROM "+prefix+"_active WHERE tenant=? AND model_id=?", (actor["tenant"], model_id)).fetchone():
            raise ConflictError("Active model must be disabled before explicit retirement")
        definition, snapshot = json.loads(row["definition"]), json.loads(row["snapshot"])
        if digest({"definition": definition, "snapshot": snapshot}) != row["digest"]:
            raise ConflictError("Immutable model changed before retirement")
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if family == "sequence":
            if "intelligence_sequence_jobs" in tables and db.execute("SELECT 1 FROM intelligence_sequence_jobs WHERE tenant=? AND model_id=? AND state IN ('pending','running') LIMIT 1", (actor["tenant"], model_id)).fetchone():
                raise ConflictError("Pending sequence work must finish or be explicitly excluded before retirement")
            if "intelligence_sequence_buffers" in tables and db.execute("SELECT 1 FROM intelligence_sequence_buffers WHERE tenant=? AND model_id=? LIMIT 1", (actor["tenant"], model_id)).fetchone():
                raise ConflictError("Buffered sequence work must finish or be explicitly excluded before retirement")
        elif "intelligence_ml_jobs" in tables and db.execute("SELECT 1 FROM intelligence_ml_jobs WHERE tenant=? AND owner=? AND state='pending' AND index_name IN (SELECT value FROM json_each(?)) LIMIT 1", (actor["tenant"], row["owner"], row["indexes"])).fetchone():
            raise ConflictError("Pending scoped CPU work must finish before retirement")
        model_kind = prefix+"_model"
        identifiers = [r[0] for r in db.execute("SELECT event_id FROM record_case_evidence_refs WHERE tenant=? AND kind=? AND record_id=?", (actor["tenant"], model_kind, model_id))]
        other = db.execute(
            "SELECT count(DISTINCT other.event_id) FROM record_case_evidence_refs own JOIN record_case_evidence_refs other "
            "ON own.tenant=other.tenant AND own.event_id=other.event_id WHERE own.tenant=? AND own.kind=? AND own.record_id=? "
            "AND NOT(other.kind=own.kind AND other.record_id=own.record_id)", (actor["tenant"], model_kind, model_id)).fetchone()[0]
        summary = {"family": family, "model_id": model_id, "model_digest": row["digest"], "revision": row["revision"],
                   "retired": True, "retired_by": actor["name"], "retired_at": time.time(),
                   "training_reference_count_released": len(identifiers), "training_original_set_digest": digest(sorted(identifiers)),
                   "other_protected_original_count": other, "model_weights_provenance_row_retained": True,
                   "case_anomaly_other_model_queue_refs_modified": False, "originals_physically_deleted": False,
                   "infer_activate_disabled": True, "notes": notes}
        db.execute("INSERT INTO cpu_ml_retired_models VALUES(?,?,?,?,?,?,?,?)",
                   (family, model_id, actor["tenant"], actor["name"], summary["retired_at"], row["indexes"], row["digest"], encode(summary)))
        db.execute("DELETE FROM record_case_evidence_refs WHERE tenant=? AND kind=? AND record_id=?", (actor["tenant"], model_kind, model_id))
        store.audit(db, actor["tenant"], actor["name"], "cpu_ml.model.retire", summary)
        return summary


def record_run(db, actor, family, run_id, answer):
    if family not in TABLES:
        raise ValueError("Supported CPU model family required")
    row = db.execute("SELECT * FROM "+TABLES[family]+" WHERE tenant=? AND id=?", (actor["tenant"], run_id)).fetchone()
    if not row or not principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
        raise KeyError("ML run unavailable in complete current scope")
    original = digest(answer)
    db.execute("INSERT OR IGNORE INTO cpu_ml_run_retention VALUES(?,?,?,?,?,?,?,?,?,?,NULL,'{}')",
               (family, run_id, actor["tenant"], row["owner"], row["indexes"], row["model_id"], row["created"], row["created"]+NORMAL_PAYLOAD_SECONDS, "payload", original))
    prefix = PREFIX[family]
    for prediction in answer.get("results", []):
        ids = prediction.get("event_ids") or [prediction["event_id"]]
        kind = prefix+"_anomaly" if prediction.get("anomaly") and not answer.get("shadow") else prefix+"_run"
        db.executemany("INSERT OR IGNORE INTO record_case_evidence_refs VALUES(?,?,?,?)", [(actor["tenant"], event_id, kind, run_id) for event_id in ids])


def _archive_one(store, db, actor, family, identifier, notes):
    table = TABLES[family]
    row = db.execute("SELECT * FROM "+table+" WHERE tenant=? AND id=?", (actor["tenant"], identifier)).fetchone()
    if not row or not principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
        raise KeyError("ML archive requires complete current run scope")
    state = db.execute("SELECT * FROM cpu_ml_run_retention WHERE tenant=? AND family=? AND run_id=?", (actor["tenant"], family, identifier)).fetchone()
    answer = json.loads(row["result"])
    if state is None:
        record_run(db, actor, family, identifier, answer)
        state = db.execute("SELECT * FROM cpu_ml_run_retention WHERE family=? AND run_id=?", (family, identifier)).fetchone()
    if state["state"] != "payload":
        return json.loads(state["summary"])
    if digest(answer) != state["input_digest"]:
        raise ConflictError("Immutable ML run payload changed before archival")
    retained, normal, normal_ids, anomaly_ids = [], [], set(), set()
    for prediction in answer.get("results", []):
        ids = prediction.get("event_ids") or [prediction["event_id"]]
        if prediction.get("anomaly") and not answer.get("shadow"):
            retained.append(prediction)
            anomaly_ids.update(ids)
        else:
            normal.append(prediction)
            normal_ids.update(ids)
    # Preserve an original when overlapping windows include any live anomaly.
    normal_ids -= anomaly_ids
    prefix = PREFIX[family]
    db.executemany("INSERT OR IGNORE INTO record_case_evidence_refs VALUES(?,?,?,?)", [(actor["tenant"], eid, prefix+"_anomaly", identifier) for eid in anomaly_ids])
    db.executemany("DELETE FROM record_case_evidence_refs WHERE tenant=? AND event_id=? AND kind=? AND record_id=?",
                   [(actor["tenant"], eid, prefix+"_run", identifier) for eid in normal_ids | anomaly_ids])
    summary = {"family": family, "run_id": identifier, "model_id": row["model_id"], "original_payload_digest": state["input_digest"],
               "normal_result_count_archived": len(normal), "normal_original_count_ref_released": len(normal_ids),
               "normal_result_digest": digest(normal), "normal_original_set_digest": digest(sorted(normal_ids)),
               "live_anomaly_result_count_retained": len(retained), "shadow": bool(row["shadow"]),
               "permanent_run_row_retained": True, "case_model_anomaly_queue_refs_modified": False,
               "originals_physically_deleted": False, "archived_at": time.time()}
    answer["results"] = retained
    answer["archive"] = summary
    db.execute("UPDATE "+table+" SET result=? WHERE tenant=? AND id=?", (encode(answer), actor["tenant"], identifier))
    db.execute("UPDATE cpu_ml_run_retention SET state=?,archived=?,summary=? WHERE tenant=? AND family=? AND run_id=?", ("anomaly_only" if retained else "archived", summary["archived_at"], encode(summary), actor["tenant"], family, identifier))
    store.audit(db, actor["tenant"], actor["name"], "cpu_ml.run.archive", {**summary, "notes": notes})
    return summary


def archive_runs(store, who, family, run_ids, notes):
    if family not in TABLES or not isinstance(run_ids, list) or not 1 <= len(run_ids) <= 64 or len(set(run_ids)) != len(run_ids):
        raise ValueError("Supported model family and 1..64 exact unique run IDs required")
    run_ids = [evidence_scope.text(identifier, "ML run ID") for identifier in run_ids]
    notes = evidence_scope.text(notes, "archive notes", 2000)
    # No DuckDB reads are needed. Current grants and immutable payload/reference
    # checks are reserved in the same transaction as the archival decision.
    with principal.transaction(store, who, ("admin", "analyst"), write=True) as (db, actor):
        return {"status": "completed", "archives": [_archive_one(store, db, actor, family, identifier, notes) for identifier in run_ids]}


def run_due(store, now=None, cancel=None, budget=.25, max_runs=16):
    now = time.time() if now is None else now
    deadline = time.monotonic()+max(.01, min(float(budget), 3))
    archived = excluded = 0
    # Existing 0.13 rows are lazily registered without changing immutable
    # migration checksums, and with the current full scope of their owner.
    with store.control() as db:
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        candidates = []
        for family, table in TABLES.items():
            if table not in tables:
                continue
            candidates.extend((family, dict(row)) for row in db.execute("SELECT r.* FROM "+table+" r WHERE NOT EXISTS(SELECT 1 FROM cpu_ml_run_retention t WHERE t.family=? AND t.run_id=r.id) ORDER BY r.created LIMIT ?", (family, min(16, max_runs))).fetchall())
    for family, row in candidates:
        if time.monotonic() >= deadline or cancel is not None and cancel.is_set():
            break
        try:
            with principal.transaction(store, {"tenant": row["tenant"], "name": row["owner"], "role": "analyst"}, ("admin", "analyst"), write=True) as (db, actor):
                fresh = db.execute("SELECT * FROM "+TABLES[family]+" WHERE tenant=? AND id=?", (actor["tenant"], row["id"])).fetchone()
                record_run(db, actor, family, row["id"], json.loads(fresh["result"]))
        except (PermissionError, KeyError, ConflictError):
            excluded += 1
    with store.control() as db:
        eligible = [dict(row) for row in db.execute("SELECT r.* FROM cpu_ml_run_retention r WHERE state='payload' AND (expires<=? OR (SELECT count(*) FROM cpu_ml_run_retention n WHERE n.tenant=r.tenant AND n.family=r.family AND n.model_id=r.model_id AND n.state='payload' AND n.created>r.created)>=?) ORDER BY r.created LIMIT ?", (now, NORMAL_PAYLOADS_PER_MODEL, min(64, max_runs))).fetchall()]
    for row in eligible:
        if time.monotonic() >= deadline or cancel is not None and cancel.is_set():
            break
        try:
            archive_runs(store, {"tenant": row["tenant"], "name": row["owner"], "role": "analyst"}, row["family"], [row["run_id"]], "Bounded normal payload archival; permanent digest/run history retained")
            archived += 1
        except (PermissionError, KeyError, ConflictError):
            excluded += 1
    return {"archived": archived, "excluded": excluded, "normal_payload_seconds": NORMAL_PAYLOAD_SECONDS,
            "normal_payloads_per_model": NORMAL_PAYLOADS_PER_MODEL, "permanent_run_history": True}


def register(app, store, runtime, who, body):
    from fastapi import Request

    @app.post("/api/v3/ml/runs/archive")
    async def archiving(request: Request):
        data = await body(request)
        if not isinstance(data, dict) or set(data) != {"family", "run_ids", "notes"}:
            raise ValueError("Model family, exact run IDs and archive notes required")
        return archive_runs(store, who(request, ("admin", "analyst")), data["family"], data["run_ids"], data["notes"])

    @app.post("/api/v3/ml/models/{family}/{model_id}/retire")
    async def retiring(family: str, model_id: str, request: Request):
        data = await body(request)
        if not isinstance(data, dict) or set(data) != {"notes"}:
            raise ValueError("Explicit independent model retirement notes required")
        return retire_model(store, who(request, ("admin", "analyst")), family, model_id, data["notes"])
