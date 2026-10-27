"""Durable source-scoped sequence windows and reviewed CPU inference publication.

No inference in admission transactions; labels and synthetic truth are never
accepted here. Only exact source/device/boot/session identities define a window.
"""

import json
import time

from . import (
    cpu_sequence,
    evidence_scope,
    intelligence,
    migrations,
    principal,
    release_manifest,
)
from .storage import ConflictError, encode

WINDOW = 12


def initialize(store):
    migrations.apply_store(
        store,
        "intelligence_sequence",
        [
            "CREATE TABLE IF NOT EXISTS intelligence_sequence_state(model_id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,digest TEXT NOT NULL,cursor INTEGER NOT NULL,updated REAL NOT NULL,error TEXT)",
            "CREATE TABLE IF NOT EXISTS intelligence_sequence_buffers(model_id TEXT NOT NULL,entity TEXT NOT NULL,tenant TEXT NOT NULL,index_name TEXT NOT NULL,event_ids TEXT NOT NULL,source_times TEXT NOT NULL,updated REAL NOT NULL,PRIMARY KEY(model_id,entity))",
            "CREATE TABLE IF NOT EXISTS intelligence_sequence_jobs(id TEXT PRIMARY KEY,model_id TEXT NOT NULL,tenant TEXT NOT NULL,owner TEXT NOT NULL,indexes TEXT NOT NULL,event_ids TEXT NOT NULL,created REAL NOT NULL,state TEXT NOT NULL,started REAL,finished REAL,result TEXT,error TEXT)",
            "CREATE INDEX IF NOT EXISTS intelligence_sequence_due ON intelligence_sequence_jobs(state,model_id,created)",
            "CREATE TABLE IF NOT EXISTS intelligence_sequence_diagnostics(seq INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT NOT NULL,model_id TEXT NOT NULL,event_id TEXT,reason TEXT NOT NULL,at REAL NOT NULL)",
        ],
    )


def activate_model(db, model):
    """Called only inside freshly reviewed model activation's write transaction."""
    stop_model(db, model["id"], "fresh activation supersedes queued previous review")
    cursor = db.execute(
        "SELECT coalesce(max(seq),0) FROM intelligence_event_outbox"
    ).fetchone()[0]
    db.execute(
        "INSERT INTO intelligence_sequence_state VALUES(?,?,?,?,?,?,NULL) ON CONFLICT(model_id) DO UPDATE SET digest=excluded.digest,cursor=excluded.cursor,updated=excluded.updated,error=NULL",
        (
            model["id"],
            model["tenant"],
            model["owner"],
            model["digest"],
            cursor,
            time.time(),
        ),
    )
    db.execute(
        "DELETE FROM intelligence_sequence_buffers WHERE model_id=?", (model["id"],)
    )


def stop_model(db, model_id, reason="model explicitly disabled"):
    """Only called inside a freshly authorized model mutation transaction."""
    for row in db.execute(
        "SELECT tenant,id FROM intelligence_sequence_jobs WHERE model_id=? AND state IN ('pending','running')",
        (model_id,),
    ).fetchall():
        _diagnostic(db, row["tenant"], model_id, None, reason)
    db.execute(
        "UPDATE intelligence_sequence_jobs SET state='excluded',finished=?,error=? WHERE model_id=? AND state IN ('pending','running')",
        (time.time(), reason[:400], model_id),
    )
    db.execute(
        "DELETE FROM intelligence_sequence_buffers WHERE model_id=?", (model_id,)
    )
    from . import sequence_event_time

    sequence_event_time.suspend(db, model_id, reason)


def protected_ids(db, tenant, ids, now=None):
    if (
        not ids
        or not db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='intelligence_sequence_jobs'"
        ).fetchone()
    ):
        return set()
    encoded = encode(ids)
    guard = (
        " AND NOT EXISTS(SELECT 1 FROM sequence_event_time_config v WHERE v.model_id=m.id AND v.state<>'disabled')"
        if db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='sequence_event_time_config'"
        ).fetchone()
        else ""
    )
    return {
        r[0]
        for r in db.execute(
            "SELECT DISTINCT j.value FROM intelligence_sequence_jobs q,json_each(q.event_ids) j WHERE q.tenant=? AND q.state IN ('pending','running') AND j.value IN (SELECT value FROM json_each(?)) UNION SELECT DISTINCT j.value FROM intelligence_sequence_buffers b,json_each(b.event_ids) j WHERE b.tenant=? AND j.value IN (SELECT value FROM json_each(?)) UNION SELECT DISTINCT e.event_id FROM intelligence_event_outbox e JOIN intelligence_sequence_state s ON s.tenant=e.tenant AND e.seq>s.cursor JOIN cpu_sequence_active a ON a.model_id=s.model_id JOIN cpu_sequence_models m ON m.id=s.model_id WHERE e.tenant=? AND e.event_id IN (SELECT value FROM json_each(?)) AND e.index_name IN (SELECT value FROM json_each(m.indexes))"
            + guard,
            (tenant, encoded, tenant, encoded, tenant, encoded),
        )
    }


def _diagnostic(db, tenant, model, event, reason):
    if db.execute(
        "SELECT 1 FROM intelligence_sequence_diagnostics WHERE tenant=? AND model_id=? AND event_id IS ? AND reason=? ORDER BY seq DESC LIMIT 1",
        (tenant, model, event, reason[:400]),
    ).fetchone():
        return
    db.execute(
        "INSERT INTO intelligence_sequence_diagnostics(tenant,model_id,event_id,reason,at) VALUES(?,?,?,?,?)",
        (tenant, model, event, reason[:400], time.time()),
    )


def _job(db, model, actor, index, ids, *, stream_context=None):
    identity = ["sequence-job", model["id"], model["digest"], ids]
    if stream_context is not None:
        identity.append(stream_context)
    identifier = release_manifest.digest(identity)
    db.execute(
        "INSERT OR IGNORE INTO intelligence_sequence_jobs VALUES(?,?,?,?,?,?,?,'pending',NULL,NULL,?,NULL)",
        (
            identifier,
            model["id"],
            actor["tenant"],
            actor["name"],
            encode([index]),
            encode(ids),
            time.time(),
            encode({"stream_context": stream_context})
            if stream_context is not None
            else None,
        ),
    )
    intelligence._phase(db, actor["tenant"], ids, sequence_queued_at=time.time())


def _job_profile(store, db, actor, job):
    from . import sequence_event_time

    payload = json.loads(job["result"]) if job.get("result") else {}
    if not isinstance(payload, dict):
        raise ConflictError("Invalid queued sequence stream context")
    context = payload.get("stream_context")
    if context is not None:
        sequence_event_time.validate_job(store, db, actor, job["model_id"], context)
    elif sequence_event_time.managed(db, job["model_id"]):
        raise ConflictError(
            "Legacy job cannot bypass a managed or paused stream profile"
        )
    return context


def _models(store):
    from . import sequence_event_time

    with store.control() as db:
        return [
            dict(r)
            for r in db.execute(
                "SELECT m.* FROM cpu_sequence_models m JOIN cpu_sequence_active a ON a.model_id=m.id AND a.tenant=m.tenant ORDER BY a.updated,m.id"
            )
            if not sequence_event_time.managed(db, r["id"])
        ]


def enqueue(store, maximum=128, cancel=None):
    scheduled = 0
    # Disabling an approved model releases only its queue/buffer protection;
    # original/model/anomaly/Case retention remains governed independently.
    with store.write_lock, store.control(local=True) as db:
        db.execute(
            "UPDATE intelligence_sequence_jobs SET state='pending',started=NULL,error='expired execution lease; retry immutable originals' WHERE state='running' AND started<?",
            (time.time() - 120,),
        )
        inactive = [
            r[0]
            for r in db.execute(
                "SELECT DISTINCT q.model_id FROM intelligence_sequence_jobs q LEFT JOIN cpu_sequence_active a ON a.model_id=q.model_id WHERE q.state IN ('pending','running') AND a.model_id IS NULL UNION SELECT DISTINCT b.model_id FROM intelligence_sequence_buffers b LEFT JOIN cpu_sequence_active a ON a.model_id=b.model_id WHERE a.model_id IS NULL"
            )
        ]
        for identifier in inactive:
            db.execute(
                "UPDATE intelligence_sequence_jobs SET state='excluded',finished=?,error='model disabled before execution' WHERE model_id=? AND state IN ('pending','running')",
                (time.time(), identifier),
            )
            db.execute(
                "DELETE FROM intelligence_sequence_buffers WHERE model_id=?",
                (identifier,),
            )
    for model in _models(store):
        if cancel is not None and cancel.is_set():
            break
        who = {"name": model["owner"], "tenant": model["tenant"], "role": "analyst"}
        try:
            with principal.transaction(store, who) as (db, actor):
                cpu_sequence.validate_publication(
                    store, db, actor, model["id"], model["digest"], model["revision"]
                )
                state = db.execute(
                    "SELECT * FROM intelligence_sequence_state WHERE model_id=?",
                    (model["id"],),
                ).fetchone()
                if not state:
                    # Old upgraded models have no historical end-to-end timing.
                    cursor = db.execute(
                        "SELECT coalesce(max(seq),0) FROM intelligence_event_outbox WHERE received<=?",
                        (model["created"],),
                    ).fetchone()[0]
                else:
                    cursor = state["cursor"]
                pending = [
                    dict(r)
                    for r in db.execute(
                        "SELECT * FROM intelligence_event_outbox WHERE tenant=? AND seq>? AND index_name IN (SELECT value FROM json_each(?)) ORDER BY seq LIMIT ?",
                        (actor["tenant"], cursor, model["indexes"], maximum),
                    )
                ]
                newest = db.execute(
                    "SELECT coalesce(max(seq),0) FROM intelligence_event_outbox WHERE tenant=?",
                    (actor["tenant"],),
                ).fetchone()[0]
            records, unavailable = {}, {}
            if pending:
                with store.segment_lock.read(deadline=time.monotonic() + 10):
                    for offset in range(0, len(pending), 32):
                        group = pending[offset : offset + 32]
                        try:
                            records.update(
                                evidence_scope.originals(
                                    store, actor, [r["event_id"] for r in group]
                                )
                            )
                        except (KeyError, ConflictError):
                            # One unavailable original cannot starve the later
                            # valid source records or another device's window.
                            for row in group:
                                try:
                                    records.update(
                                        evidence_scope.originals(
                                            store, actor, [row["event_id"]]
                                        )
                                    )
                                except (KeyError, ConflictError) as exc:
                                    unavailable[row["event_id"]] = type(exc).__name__
            with (
                store.segment_lock.read(deadline=time.monotonic() + 10),
                principal.transaction(store, actor, write=True) as (db, fresh),
            ):
                cpu_sequence.validate_publication(
                    store, db, fresh, model["id"], model["digest"], model["revision"]
                )
                evidence_scope.recheck(db, fresh, records)
                for item in pending:
                    if item["event_id"] in unavailable:
                        _diagnostic(
                            db,
                            fresh["tenant"],
                            model["id"],
                            item["event_id"],
                            unavailable[item["event_id"]]
                            + ": original unavailable, cursor continues",
                        )
                        continue
                    record = records[item["event_id"]]
                    if (
                        record["received"] != item["received"]
                        or record["index_name"] != item["index_name"]
                    ):
                        _diagnostic(
                            db,
                            fresh["tenant"],
                            model["id"],
                            item["event_id"],
                            "original admission generation differs; cursor continues",
                        )
                        continue
                    xdr = record["raw"].get("xdr", {})
                    data = xdr.get("data", {}) if isinstance(xdr, dict) else {}
                    data = data if isinstance(data, dict) else {}

                    def obj(key, data=data):
                        value = data.get(key, {})
                        return value if isinstance(value, dict) else {}

                    host, user, authentication, container = (
                        obj("host"),
                        obj("user"),
                        obj("authentication"),
                        obj("container"),
                    )
                    proof = db.execute(
                        "SELECT source_id,source_version FROM source_event_receipts WHERE tenant=? AND event_id=?",
                        (fresh["tenant"], item["event_id"]),
                    ).fetchone()
                    from .identity_resolver import identity_text

                    session = user.get("session_id")
                    if session is None:
                        session = authentication.get("session_id")
                    optional_identity = (
                        user.get("id"),
                        session,
                        container.get("id"),
                        container.get("namespace"),
                    )
                    if (
                        not proof
                        or not identity_text(host.get("id"))
                        or not identity_text(host.get("boot_id"))
                        or any(
                            v is not None and not identity_text(v)
                            for v in optional_identity
                        )
                    ):
                        _diagnostic(
                            db,
                            fresh["tenant"],
                            model["id"],
                            item["event_id"],
                            "exact source/device/boot missing; sequence excluded",
                        )
                        continue
                    entity = release_manifest.digest(
                        [
                            fresh["tenant"],
                            item["index_name"],
                            proof["source_id"],
                            proof["source_version"],
                            record["host"],
                            host["id"],
                            host["boot_id"],
                            *optional_identity,
                        ]
                    )
                    old = db.execute(
                        "SELECT * FROM intelligence_sequence_buffers WHERE model_id=? AND entity=?",
                        (model["id"], entity),
                    ).fetchone()
                    ids = json.loads(old["event_ids"]) if old else []
                    times = json.loads(old["source_times"]) if old else []
                    instant = record["event_time"]
                    if times and instant <= times[-1]:
                        _diagnostic(
                            db,
                            fresh["tenant"],
                            model["id"],
                            item["event_id"],
                            "late/ambiguous source order; sequence excluded, original retained",
                        )
                        continue
                    ids.append(item["event_id"])
                    times.append(instant)
                    if len(ids) == WINDOW:
                        _job(db, model, fresh, item["index_name"], ids)
                        scheduled += 1
                        db.execute(
                            "DELETE FROM intelligence_sequence_buffers WHERE model_id=? AND entity=?",
                            (model["id"], entity),
                        )
                    else:
                        db.execute(
                            "INSERT INTO intelligence_sequence_buffers VALUES(?,?,?,?,?,?,?) ON CONFLICT(model_id,entity) DO UPDATE SET event_ids=excluded.event_ids,source_times=excluded.source_times,updated=excluded.updated",
                            (
                                model["id"],
                                entity,
                                fresh["tenant"],
                                item["index_name"],
                                encode(ids),
                                encode(times),
                                time.time(),
                            ),
                        )
                # Partial windows stay protected until idle finalization. They
                # are labeled partial, never promoted as complete causal chains.
                for row in db.execute(
                    "SELECT * FROM intelligence_sequence_buffers WHERE model_id=? AND updated<? ORDER BY updated LIMIT 32",
                    (model["id"], time.time() - 5),
                ).fetchall():
                    ids = json.loads(row["event_ids"])
                    if len(ids) >= 3:
                        _job(db, model, fresh, row["index_name"], ids)
                        scheduled += 1
                    else:
                        for eid in ids:
                            _diagnostic(
                                db,
                                fresh["tenant"],
                                model["id"],
                                eid,
                                "idle window too short; sequence excluded",
                            )
                    db.execute(
                        "DELETE FROM intelligence_sequence_buffers WHERE model_id=? AND entity=?",
                        (model["id"], row["entity"]),
                    )
                final_cursor = pending[-1]["seq"] if pending else newest
                db.execute(
                    "INSERT INTO intelligence_sequence_state VALUES(?,?,?,?,?,?,NULL) ON CONFLICT(model_id) DO UPDATE SET cursor=excluded.cursor,updated=excluded.updated,error=NULL",
                    (
                        model["id"],
                        fresh["tenant"],
                        fresh["name"],
                        model["digest"],
                        final_cursor,
                        time.time(),
                    ),
                )
        except (KeyError, PermissionError, ConflictError, ValueError) as exc:
            with store.write_lock, store.control(local=True) as db:
                _diagnostic(
                    db,
                    model["tenant"],
                    model["id"],
                    None,
                    type(exc).__name__ + ": " + str(exc),
                )
                db.execute(
                    "DELETE FROM intelligence_sequence_buffers WHERE model_id=?",
                    (model["id"],),
                )
                db.execute(
                    "UPDATE intelligence_sequence_jobs SET state='excluded',finished=?,error=? WHERE model_id=? AND state IN ('pending','running')",
                    (time.time(), type(exc).__name__, model["id"]),
                )
                newest = db.execute(
                    "SELECT coalesce(max(seq),0) FROM intelligence_event_outbox WHERE tenant=?",
                    (model["tenant"],),
                ).fetchone()[0]
                db.execute(
                    "UPDATE intelligence_sequence_state SET cursor=?,updated=?,error=? WHERE model_id=?",
                    (newest, time.time(), type(exc).__name__, model["id"]),
                )
    return scheduled


def _association(store, db, actor, original_ids, fallback):
    records = evidence_scope.originals(store, actor, original_ids)
    # Exact reported five-tuple is association only. Identity grouping always
    # remains source/device scoped; a network match never authorizes a response.
    for record in sorted(
        records.values(), key=lambda r: (r["event_time"], r["event_id"]), reverse=True
    ):
        projection = intelligence._projection(db, actor["tenant"], record)
        if projection and projection.get("flow"):
            from . import identity_resolver

            key = identity_resolver.relation_key(store, actor, projection, "flow")
            if key:
                return key
    return fallback


def run_due(store, now=None, cancel=None, budget=0.25, max_runs=32):
    enqueue(store, maximum=128, cancel=cancel)
    from . import sequence_event_time

    sequence_event_time.enqueue(store, maximum=128, cancel=cancel, now=now)
    with store.control() as db:
        first = db.execute(
            "SELECT * FROM intelligence_sequence_jobs WHERE state='pending' ORDER BY created,id LIMIT 1"
        ).fetchone()
        jobs = (
            [
                dict(r)
                for r in db.execute(
                    "SELECT * FROM intelligence_sequence_jobs WHERE state='pending' AND model_id=? AND owner=? AND indexes=? ORDER BY created,id LIMIT ?",
                    (
                        first["model_id"],
                        first["owner"],
                        first["indexes"],
                        min(32, max_runs),
                    ),
                )
            ]
            if first
            else []
        )
    if not jobs:
        return {"completed": 0, "signals": 0}
    who = {"name": jobs[0]["owner"], "tenant": jobs[0]["tenant"], "role": "analyst"}
    ids = [eid for j in jobs for eid in json.loads(j["event_ids"])]
    try:
        with principal.transaction(store, who, write=True) as (db, actor):
            expected_model = cpu_sequence.model_pin(
                store, db, actor, jobs[0]["model_id"]
            )
            claimed = []
            for job in jobs:
                _job_profile(store, db, actor, job)
                started = time.time()
                changed = db.execute(
                    "UPDATE intelligence_sequence_jobs SET state='running',started=? WHERE id=? AND state='pending'",
                    (started, job["id"]),
                ).rowcount
                if changed:
                    job["started"] = started
                    claimed.append(job)
            jobs = claimed
            if not jobs:
                return {"completed": 0, "signals": 0}
            intelligence._phase(
                db, actor["tenant"], ids, sequence_started_at=time.time()
            )
        answer = cpu_sequence.infer_sequences(
            store,
            who,
            [{"event_ids": json.loads(j["event_ids"])} for j in jobs],
            model_id=jobs[0]["model_id"],
            shadow=False,
        )
        if answer.get("status") != "completed":
            with store.write_lock, store.control(local=True) as db:
                for job in jobs:
                    db.execute(
                        "UPDATE intelligence_sequence_jobs SET state='excluded',finished=?,error=? WHERE id=? AND state='running' AND started=?",
                        (
                            time.time(),
                            answer.get("compatibility", "sequence unavailable"),
                            job["id"],
                            job["started"],
                        ),
                    )
                    _diagnostic(
                        db,
                        job["tenant"],
                        job["model_id"],
                        None,
                        answer.get("compatibility", "sequence unavailable"),
                    )
            return {
                "completed": 0,
                "excluded": len(jobs),
                "compatibility": answer.get("compatibility", "sequence unavailable"),
                "core_continues": True,
            }
        if len(answer.get("results", [])) != len(jobs):
            raise ConflictError("Sequence worker returned an incomplete job batch")
        emitted = 0
        with (
            store.segment_lock.read(deadline=time.monotonic() + 10),
            principal.transaction(store, who, write=True) as (db, actor),
        ):
            cpu_sequence.validate_publication(
                store,
                db,
                actor,
                expected_model["id"],
                expected_model["digest"],
                expected_model["revision"],
            )
            for job, result in zip(jobs, answer["results"]):
                stream_context = _job_profile(store, db, actor, job)
                current = db.execute(
                    "SELECT state,started FROM intelligence_sequence_jobs WHERE id=?",
                    (job["id"],),
                ).fetchone()
                if (
                    not current
                    or current["state"] != "running"
                    or current["started"] != job["started"]
                ):
                    raise ConflictError(
                        "Sequence execution lease changed before publication"
                    )
                if (
                    result["event_ids"] != json.loads(job["event_ids"])
                    or result["model_id"] != expected_model["id"]
                    or result["digest"] != expected_model["digest"]
                    or result["revision"] != expected_model["revision"]
                ):
                    raise ConflictError(
                        "Sequence result differs from its exact claimed originals/model"
                    )
                if result["anomaly"]:
                    model_id = result.get("model_id", jobs[0]["model_id"])
                    signal = intelligence.publish_in_transaction(
                        store,
                        db,
                        actor,
                        {
                            "event_ids": result["event_ids"],
                            "kind": "ml",
                            "rule_id": "ml:sequence:" + model_id,
                            "rule_revision": result["revision"],
                            "model_digest": result["digest"],
                            "entity_key": _association(
                                store,
                                db,
                                actor,
                                result["event_ids"],
                                result["entity_key"],
                            ),
                            "features": {
                                "model_family": "sequence",
                                "sequence_score": result["score"],
                                "threshold": result["threshold"],
                                "sequence_length": len(result["event_ids"]),
                                "probability_calibrated": False,
                            },
                            "severity": "high",
                            "confidence_grade": "reviewed_sequence_model_hypothesis",
                            "metadata": {
                                "model_id": model_id,
                                "model_family": "sequence",
                                "run_id": answer.get("run_id"),
                                "source_entity_key": result["entity_key"],
                                "partial_window": len(result["event_ids"])
                                < (
                                    stream_context["window"]
                                    if stream_context
                                    else WINDOW
                                ),
                                "native_capture_proven": False,
                                **(
                                    {"stream_context": stream_context}
                                    if stream_context
                                    else {}
                                ),
                            },
                            "window": 900,
                        },
                    )
                    emitted += int(not signal["duplicate"])
                db.execute(
                    "UPDATE intelligence_sequence_jobs SET state='completed',finished=?,result=? WHERE id=? AND state='running' AND started=?",
                    (
                        time.time(),
                        encode(
                            {
                                "run_id": answer.get("run_id"),
                                "score": result["score"],
                                "anomaly": result["anomaly"],
                                **(
                                    {"stream_context": stream_context}
                                    if stream_context
                                    else {}
                                ),
                            }
                        ),
                        job["id"],
                        job["started"],
                    ),
                )
                intelligence._phase(
                    db,
                    actor["tenant"],
                    result["event_ids"],
                    sequence_finished_at=time.time(),
                )
        return {
            "completed": len(jobs),
            "signals": emitted,
            "duration_ms": answer.get("duration_ms"),
            "worker_wall_ms": answer.get("worker_wall_ms"),
        }
    except (KeyError, PermissionError, ConflictError, ValueError) as exc:
        with store.write_lock, store.control(local=True) as db:
            for job in jobs:
                db.execute(
                    "UPDATE intelligence_sequence_jobs SET state='excluded',finished=?,error=? WHERE id=? AND state='running' AND started=?",
                    (time.time(), type(exc).__name__, job["id"], job.get("started")),
                )
                _diagnostic(
                    db,
                    job["tenant"],
                    job["model_id"],
                    None,
                    type(exc).__name__ + ": " + str(exc),
                )
        return {"completed": 0, "excluded": len(jobs), "error": type(exc).__name__}


def register(app, store, runtime, who, body):
    from fastapi import Request

    @app.get("/api/v3/ml/sequences/stream")
    def stream_status(request: Request):
        with principal.transaction(store, who(request)) as (db, actor):
            visible = []
            for row in db.execute(
                "SELECT s.*,m.indexes,m.digest AS current_digest,m.revision FROM intelligence_sequence_state s JOIN cpu_sequence_models m ON m.id=s.model_id WHERE s.tenant=?",
                (actor["tenant"],),
            ).fetchall():
                if not principal.contains(
                    actor["allowed_indexes"], json.loads(row["indexes"])
                ):
                    continue
                try:
                    cpu_sequence.validate_publication(
                        store,
                        db,
                        actor,
                        row["model_id"],
                        row["current_digest"],
                        row["revision"],
                    )
                except (KeyError, PermissionError, ConflictError):
                    continue
                counts = dict(
                    db.execute(
                        "SELECT state,count(*) FROM intelligence_sequence_jobs WHERE model_id=? GROUP BY state",
                        (row["model_id"],),
                    ).fetchall()
                )
                profile = db.execute(
                    "SELECT state,definition,reason FROM sequence_event_time_config WHERE model_id=?",
                    (row["model_id"],),
                ).fetchone()
                definition = json.loads(profile["definition"]) if profile else {}
                event_state = (
                    db.execute(
                        "SELECT cursor,updated FROM sequence_event_time_state WHERE model_id=?",
                        (row["model_id"],),
                    ).fetchone()
                    if profile
                    else None
                )
                processing = (
                    "event_time"
                    if profile and profile["state"] == "active"
                    else "paused"
                    if profile and profile["state"] != "disabled"
                    else "legacy"
                )
                visible.append(
                    {
                        "model_id": row["model_id"],
                        "cursor": event_state["cursor"]
                        if processing == "event_time" and event_state
                        else row["cursor"],
                        "updated": event_state["updated"]
                        if processing == "event_time" and event_state
                        else row["updated"],
                        "error": profile["reason"]
                        if processing == "paused"
                        else row["error"],
                        "jobs": counts,
                        "authority_rechecked": True,
                        "processing_profile": processing,
                        "window_events": definition.get("window", WINDOW)
                        if processing == "event_time"
                        else WINDOW,
                        "idle_seconds": definition.get("idle_seconds", 5)
                        if processing == "event_time"
                        else 5,
                        "stream_epoch": definition.get("stream_epoch")
                        if profile
                        else None,
                        "model_review_id": definition.get("model_review_id")
                        if profile
                        else None,
                    }
                )
            return {
                "states": visible,
                "window_events": WINDOW,
                "idle_seconds": 5,
                "defaults_apply_to": "legacy only; per-model fields describe reviewed event-time profiles or paused processing",
                "no_native_effects": True,
            }
