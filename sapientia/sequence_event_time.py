"""Reviewed, bounded event-time overlap for existing CPU sequence models.

Never-configured models retain legacy processing. Saving a managed profile
pauses its stream until independent review; suspension never silently replays
legacy data. A reviewed disabled profile resumes legacy at a fresh cursor.
Model activation and entity coverage epochs are explicit. Watermarks never
rewrite originals or claim ordering for equal timestamps.
"""

import json
import math
import time
import uuid

from . import (
    cpu_sequence,
    evidence_scope,
    intelligence,
    migrations,
    principal,
    release_manifest,
)
from .storage import ConflictError, encode

MAX_BUFFER = 128
MAX_ENTITIES = 4096


def initialize(store):
    migrations.apply_store(
        store,
        "sequence_event_time",
        [
            "CREATE TABLE IF NOT EXISTS sequence_event_time_config(model_id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,indexes TEXT NOT NULL,revision INTEGER NOT NULL,definition TEXT NOT NULL,state TEXT NOT NULL,reviewer TEXT,reason TEXT,updated REAL NOT NULL)",
            "CREATE TABLE IF NOT EXISTS sequence_event_time_state(model_id TEXT PRIMARY KEY,cursor INTEGER NOT NULL,updated REAL NOT NULL)",
            "CREATE TABLE IF NOT EXISTS sequence_event_time_buffers(model_id TEXT NOT NULL,entity TEXT NOT NULL,tenant TEXT NOT NULL,index_name TEXT NOT NULL,items TEXT NOT NULL,max_time REAL NOT NULL,emitted_time REAL,updated REAL NOT NULL,PRIMARY KEY(model_id,entity))",
        ],
    )
    migrations.apply_store(
        store,
        "sequence_event_time",
        [
            "ALTER TABLE sequence_event_time_buffers ADD COLUMN epoch TEXT NOT NULL DEFAULT 'legacy-unqualified'",
        ],
        version=2,
    )


def _model(db, actor, identifier):
    model = db.execute(
        "SELECT * FROM cpu_sequence_models WHERE tenant=? AND id=?",
        (actor["tenant"], identifier),
    ).fetchone()
    if not model or not principal.contains(
        actor["allowed_indexes"], json.loads(model["indexes"])
    ):
        raise KeyError("Sequence model not found")
    return model


def _review_pin(db, tenant, model_id):
    row = db.execute(
        "SELECT review_id FROM cpu_sequence_active WHERE tenant=? AND model_id=?",
        (tenant, model_id),
    ).fetchone()
    if not row:
        raise PermissionError("An actively reviewed sequence model is required")
    return row["review_id"]


def managed(db, model_id):
    """A configured pending/suspended profile pauses instead of replaying legacy."""
    return bool(
        db.execute(
            "SELECT 1 FROM sequence_event_time_config WHERE model_id=? AND state<>'disabled'",
            (model_id,),
        ).fetchone()
    )


def suspend(db, model_id, reason):
    """Model mutation hook, inside its existing reserved write transaction."""
    if not db.execute(
        "SELECT 1 FROM sqlite_master WHERE name='sequence_event_time_config'"
    ).fetchone():
        return
    db.execute(
        "UPDATE sequence_event_time_config SET state='suspended',reason=?,updated=? WHERE model_id=?",
        (reason[:1000], time.time(), model_id),
    )
    db.execute("DELETE FROM sequence_event_time_buffers WHERE model_id=?", (model_id,))


def _cancel_work(db, model_id, reason):
    db.execute(
        "UPDATE intelligence_sequence_jobs SET state='excluded',finished=?,error=? WHERE model_id=? AND state IN ('pending','running')",
        (time.time(), reason[:400], model_id),
    )
    db.execute(
        "DELETE FROM intelligence_sequence_buffers WHERE model_id=?", (model_id,)
    )
    db.execute("DELETE FROM sequence_event_time_buffers WHERE model_id=?", (model_id,))


def save(store, who, identifier, data):
    if not isinstance(data, dict) or set(data) != {
        "expected_revision",
        "lateness_seconds",
        "window",
        "stride",
        "idle_seconds",
        "enabled",
    }:
        raise ValueError("Exact event-time stream configuration required")
    for key, lower, upper in [
        ("expected_revision", 0, 10**9),
        ("lateness_seconds", 0, 300),
        ("window", 3, 32),
        ("stride", 1, 32),
        ("idle_seconds", 1, 300),
    ]:
        if type(data[key]) is not int or not lower <= data[key] <= upper:
            raise ValueError("Invalid " + key)
    if type(data["enabled"]) is not bool or data["stride"] > data["window"]:
        raise ValueError("Boolean enabled and stride <= window required")
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        model = _model(db, actor, identifier)
        cpu_sequence.validate_publication(
            store, db, actor, identifier, model["digest"], model["revision"]
        )
        model_review_id = _review_pin(db, actor["tenant"], identifier)
        old = db.execute(
            "SELECT * FROM sequence_event_time_config WHERE model_id=?", (identifier,)
        ).fetchone()
        revision = old["revision"] if old else 0
        if data["expected_revision"] != revision:
            raise ConflictError("Stream revision changed")
        definition = {k: v for k, v in data.items() if k != "expected_revision"}
        definition.update(
            model_digest=model["digest"],
            model_revision=model["revision"],
            model_review_id=model_review_id,
            stream_epoch=uuid.uuid4().hex,
            profile="event-time-overlap-v2",
        )
        db.execute(
            "INSERT INTO sequence_event_time_config VALUES(?,?,?,?,?,?,?,NULL,NULL,?) ON CONFLICT(model_id) DO UPDATE SET owner=excluded.owner,indexes=excluded.indexes,revision=excluded.revision,definition=excluded.definition,state=excluded.state,reviewer=NULL,reason=NULL,updated=excluded.updated",
            (
                identifier,
                actor["tenant"],
                actor["name"],
                model["indexes"],
                revision + 1,
                encode(definition),
                "pending_review",
                time.time(),
            ),
        )
        _cancel_work(
            db,
            identifier,
            "stream profile revision pending independent review; analysis paused",
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "sequence.event_time.save",
            {"id": identifier, "revision": revision + 1},
        )
        return {
            "model_id": identifier,
            "revision": revision + 1,
            "state": "pending_review",
            "definition": definition,
        }


def review(store, who, identifier, data):
    if (
        not isinstance(data, dict)
        or set(data) != {"expected_revision", "approve", "reason"}
        or type(data["approve"]) is not bool
        or not isinstance(data["reason"], str)
        or not 5 <= len(data["reason"]) <= 1000
    ):
        raise ValueError("Revision, independent review and reason required")
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        row = db.execute(
            "SELECT * FROM sequence_event_time_config WHERE tenant=? AND model_id=?",
            (actor["tenant"], identifier),
        ).fetchone()
        if not row:
            raise KeyError("Stream profile not found")
        model = _model(db, actor, identifier)
        if (
            type(data["expected_revision"]) is not int
            or row["revision"] != data["expected_revision"]
        ):
            raise ConflictError("Stream revision changed")
        if row["owner"] == actor["name"]:
            raise PermissionError("Independent stream reviewer required")
        owner = principal.current(
            db,
            {"name": row["owner"], "tenant": row["tenant"], "role": "admin"},
            ("admin",),
        )
        if not principal.contains(owner["allowed_indexes"], json.loads(row["indexes"])):
            raise PermissionError("Stream profile owner scope revoked")
        definition = json.loads(row["definition"])
        cpu_sequence.validate_publication(
            store,
            db,
            actor,
            identifier,
            definition["model_digest"],
            definition["model_revision"],
        )
        if definition.get("model_review_id") != _review_pin(
            db, actor["tenant"], identifier
        ):
            raise ConflictError(
                "Model activation review changed; save a new stream profile revision"
            )
        state = "active" if data["approve"] and definition["enabled"] else "disabled"
        if row["state"] != "pending_review":
            if row["state"] == state and row["reviewer"] == actor["name"]:
                return {
                    "model_id": identifier,
                    "revision": row["revision"],
                    "state": state,
                    "duplicate": True,
                }
            raise ConflictError(
                "Save a new stream profile revision before reviewing again"
            )
        db.execute(
            "UPDATE sequence_event_time_config SET state=?,reviewer=?,reason=?,updated=? WHERE model_id=?",
            (state, actor["name"], data["reason"], time.time(), identifier),
        )
        cursor = db.execute(
            "SELECT coalesce(max(seq),0) FROM intelligence_event_outbox"
        ).fetchone()[0]
        previous = db.execute(
            "SELECT cursor FROM sequence_event_time_state WHERE model_id=?",
            (identifier,),
        ).fetchone()
        if previous and previous["cursor"] < cursor:
            from .intelligence_sequence import _diagnostic

            skipped = db.execute(
                "SELECT count(*) FROM intelligence_event_outbox WHERE tenant=? AND seq>? AND seq<=? AND index_name IN (SELECT value FROM json_each(?))",
                (actor["tenant"], previous["cursor"], cursor, row["indexes"]),
            ).fetchone()[0]
            if skipped:
                _diagnostic(
                    db,
                    actor["tenant"],
                    identifier,
                    None,
                    f"profile review starts a fresh coverage epoch; {skipped} paused originals retained but not replayed",
                )
        db.execute(
            "INSERT INTO sequence_event_time_state VALUES(?,?,?) ON CONFLICT(model_id) DO UPDATE SET cursor=excluded.cursor,updated=excluded.updated",
            (identifier, cursor, time.time()),
        )
        _cancel_work(db, identifier, "reviewed stream profile changed")
        # Explicitly approved disabled profiles resume legacy at this boundary,
        # never at its old, pre-v2 cursor. Pending/suspended profiles stay paused.
        db.execute(
            "INSERT INTO intelligence_sequence_state VALUES(?,?,?,?,?,?,NULL) ON CONFLICT(model_id) DO UPDATE SET owner=excluded.owner,digest=excluded.digest,cursor=excluded.cursor,updated=excluded.updated,error=NULL",
            (
                identifier,
                actor["tenant"],
                model["owner"],
                model["digest"],
                cursor,
                time.time(),
            ),
        )
        # A profile switch cannot leave a claimed job from the preceding stream.
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "sequence.event_time.review",
            {"id": identifier, "state": state, "revision": row["revision"]},
        )
        return {"model_id": identifier, "revision": row["revision"], "state": state}


def enabled(db, model_id):
    return bool(
        db.execute(
            "SELECT 1 FROM sequence_event_time_config WHERE model_id=? AND state='active'",
            (model_id,),
        ).fetchone()
    )


def _authority(store, db, row):
    who = {"name": row["owner"], "tenant": row["tenant"], "role": "admin"}
    actor = principal.current(db, who, ("admin",))
    reviewer = principal.current(
        db,
        {"name": row["reviewer"], "tenant": row["tenant"], "role": "admin"},
        ("admin",),
    )
    scope = json.loads(row["indexes"])
    if actor["name"] == reviewer["name"] or not all(
        principal.contains(p["allowed_indexes"], scope) for p in (actor, reviewer)
    ):
        raise PermissionError("Stream review scope revoked")
    definition = json.loads(row["definition"])
    cpu_sequence.validate_publication(
        store,
        db,
        actor,
        row["model_id"],
        definition["model_digest"],
        definition["model_revision"],
    )
    if definition.get("model_review_id") != _review_pin(
        db, actor["tenant"], row["model_id"]
    ):
        raise PermissionError("Stream belongs to a superseded model activation review")
    if (
        not isinstance(definition.get("stream_epoch"), str)
        or not definition["stream_epoch"]
    ):
        raise PermissionError(
            "Legacy stream profile requires a fresh pinned independent review"
        )
    return actor, definition


def validate_job(store, db, actor, model_id, context):
    row = db.execute(
        "SELECT * FROM sequence_event_time_config WHERE tenant=? AND model_id=?",
        (actor["tenant"], model_id),
    ).fetchone()
    if not row or row["state"] != "active" or not isinstance(context, dict):
        raise PermissionError("Queued event-time profile is no longer active")
    _, definition = _authority(store, db, row)
    if any(
        context.get(key) != value
        for key, value in {
            "profile_revision": row["revision"],
            "stream_epoch": definition["stream_epoch"],
            "model_review_id": definition["model_review_id"],
            "window": definition["window"],
            "stride": definition["stride"],
            "lateness_seconds": definition["lateness_seconds"],
        }.items()
    ):
        raise ConflictError("Queued event-time profile/activation epoch changed")
    if (
        not isinstance(context.get("coverage_epoch"), str)
        or not context["coverage_epoch"]
    ):
        raise ConflictError("Queued event-time coverage epoch missing")
    return definition


def _make_room(db, configuration):
    """Discard only a completed watermark, never pending original references."""
    model_id = configuration["model_id"]
    if (
        db.execute(
            "SELECT count(*) FROM sequence_event_time_buffers WHERE model_id=?",
            (model_id,),
        ).fetchone()[0]
        < MAX_ENTITIES
    ):
        return True
    old = db.execute(
        "SELECT entity,epoch,max_time,emitted_time FROM sequence_event_time_buffers WHERE model_id=? AND items='[]' ORDER BY updated,entity LIMIT 1",
        (model_id,),
    ).fetchone()
    if not old:
        return False
    db.execute(
        "DELETE FROM sequence_event_time_buffers WHERE model_id=? AND entity=? AND items='[]'",
        (model_id, old["entity"]),
    )
    from .intelligence_sequence import _diagnostic

    _diagnostic(
        db,
        configuration["tenant"],
        model_id,
        None,
        f"empty watermark evicted at entity capacity; previous coverage epoch {old['epoch']}; continuity for that entity is no longer retained",
    )
    return True


def _entity(db, actor, record):
    projection = intelligence._projection(db, actor["tenant"], record)
    if not projection:
        return None
    data = record["raw"].get("xdr", {}).get("data", {})
    if not isinstance(data, dict):
        return None
    from .identity_resolver import identity_text

    host = data.get("host", {})
    user = data.get("user", {})
    container = data.get("container", {})
    if not all(isinstance(o, dict) for o in (host, user, container)):
        return None
    session = user.get("session_id")
    if session is None:
        authentication = data.get("authentication", {})
        session = (
            authentication.get("session_id")
            if isinstance(authentication, dict)
            else None
        )
    optional = [
        user.get("id"),
        session,
        container.get("id"),
        container.get("namespace"),
    ]
    if (
        not identity_text(host.get("id"))
        or not identity_text(host.get("boot_id"))
        or any(v is not None and not identity_text(v) for v in optional)
    ):
        return None
    return release_manifest.digest(
        [
            actor["tenant"],
            record["index_name"],
            projection["source_id"],
            projection["source_version"],
            record["host"],
            host["id"],
            host["boot_id"],
            *optional,
        ]
    )


def advance(
    items,
    new_items,
    *,
    maximum_time=None,
    emitted_time=None,
    lateness=5,
    window=12,
    stride=6,
    finalize=False,
):
    """Pure bounded watermark transition; equal timestamps have no causal order."""
    all_items = {x["id"]: dict(x) for x in items}
    diagnostics = []
    maximum_time = max(
        [x["time"] for x in items]
        + ([maximum_time] if maximum_time is not None else []),
        default=None,
    )
    for item in new_items:
        instant = item["time"]
        if type(instant) not in (int, float) or not math.isfinite(instant):
            raise ValueError("Finite event time required")
        if (
            emitted_time is not None
            and instant <= emitted_time
            or maximum_time is not None
            and instant < maximum_time - lateness
        ):
            diagnostics.append(
                (item["id"], "outside event-time watermark; original retained")
            )
            continue
        maximum_time = (
            max(instant, maximum_time) if maximum_time is not None else instant
        )
        all_items[item["id"]] = dict(item)
    ordered = sorted(all_items.values(), key=lambda x: (x["time"], x["id"]))
    if len(ordered) > MAX_BUFFER:
        raise ValueError("Event-time buffer capacity exceeded")
    tied = {
        x["time"]
        for i, x in enumerate(ordered)
        if i and x["time"] == ordered[i - 1]["time"]
    }
    for item in ordered:
        if item["time"] in tied:
            diagnostics.append(
                (item["id"], "equal source timestamps; causal order unknown")
            )
    ordered = [x for x in ordered if x["time"] not in tied]
    watermark = (
        maximum_time
        if finalize
        else maximum_time - lateness
        if maximum_time is not None
        else -math.inf
    )
    eligible = [x for x in ordered if x["time"] <= watermark]
    jobs = []
    while len(eligible) >= window:
        selected = eligible[:window]
        jobs.append([x["id"] for x in selected])
        consumed = eligible[:stride]
        # Preserve overlapping suffix but never accept a newly late record
        # into an already emitted inference window.
        emitted_time = selected[-1]["time"]
        discarded = {x["id"] for x in consumed}
        ordered = [x for x in ordered if x["id"] not in discarded]
        eligible = eligible[stride:]
    if finalize:
        fresh = [x for x in ordered if emitted_time is None or x["time"] > emitted_time]
        if len(fresh) >= 3:
            selected = ordered[:32]
            jobs.append([x["id"] for x in selected])
            emitted_time = selected[-1]["time"]
        elif fresh:
            diagnostics.extend(
                (x["id"], "idle window too short; original retained") for x in fresh
            )
        ordered = []
    return {
        "items": ordered,
        "max_time": maximum_time,
        "emitted_time": emitted_time,
        "jobs": jobs,
        "diagnostics": diagnostics,
        "watermark": watermark,
    }


def enqueue(store, maximum=128, cancel=None, now=None):
    now = time.time() if now is None else now
    from . import intelligence_sequence as stream

    with store.control() as db:
        configurations = [
            dict(r)
            for r in db.execute(
                "SELECT c.* FROM sequence_event_time_config c LEFT JOIN sequence_event_time_state s ON s.model_id=c.model_id WHERE c.state='active' ORDER BY coalesce(s.updated,c.updated),c.model_id LIMIT 32"
            )
        ]
    total = 0
    for configuration in configurations:
        if cancel is not None and cancel.is_set():
            break
        try:
            with principal.transaction(
                store,
                {
                    "name": configuration["owner"],
                    "tenant": configuration["tenant"],
                    "role": "admin",
                },
            ) as (db, _):
                actor, definition = _authority(store, db, configuration)
                model = dict(_model(db, actor, configuration["model_id"]))
                state = db.execute(
                    "SELECT cursor FROM sequence_event_time_state WHERE model_id=?",
                    (model["id"],),
                ).fetchone()
                cursor = state[0] if state else 0
                pending = [
                    dict(r)
                    for r in db.execute(
                        "SELECT * FROM intelligence_event_outbox WHERE tenant=? AND seq>? AND index_name IN (SELECT value FROM json_each(?)) ORDER BY seq LIMIT ?",
                        (
                            actor["tenant"],
                            cursor,
                            configuration["indexes"],
                            min(128, maximum),
                        ),
                    )
                ]
            records = {}
            for offset in range(0, len(pending), 32):
                for item in pending[offset : offset + 32]:
                    try:
                        records.update(
                            evidence_scope.originals(store, actor, [item["event_id"]])
                        )
                    except (KeyError, ConflictError):
                        pass
            with (
                store.segment_lock.read(deadline=time.monotonic() + 10),
                principal.transaction(store, actor, write=True) as (db, actor),
            ):
                fresh = db.execute(
                    "SELECT * FROM sequence_event_time_config WHERE model_id=?",
                    (model["id"],),
                ).fetchone()
                if (
                    not fresh
                    or fresh["revision"] != configuration["revision"]
                    or fresh["state"] != "active"
                ):
                    raise ConflictError("Stream configuration changed")
                _authority(store, db, fresh)
                evidence_scope.recheck(db, actor, records)
                grouped = {}
                for item in pending:
                    record = records.get(item["event_id"])
                    if not record or record["received"] != item["received"]:
                        stream._diagnostic(
                            db,
                            actor["tenant"],
                            model["id"],
                            item["event_id"],
                            "event-time original unavailable",
                        )
                        continue
                    entity = _entity(db, actor, record)
                    if not entity:
                        stream._diagnostic(
                            db,
                            actor["tenant"],
                            model["id"],
                            item["event_id"],
                            "exact source/device/boot missing; event-time excluded",
                        )
                        continue
                    grouped.setdefault((entity, item["index_name"]), []).append(
                        {"id": item["event_id"], "time": record["event_time"]}
                    )
                for row in db.execute(
                    "SELECT entity,index_name FROM sequence_event_time_buffers WHERE model_id=? AND updated<? AND items!='[]' ORDER BY updated LIMIT 32",
                    (model["id"], now - definition["idle_seconds"]),
                ):
                    grouped.setdefault((row["entity"], row["index_name"]), [])
                for (entity, index), items in grouped.items():
                    old = db.execute(
                        "SELECT * FROM sequence_event_time_buffers WHERE model_id=? AND entity=?",
                        (model["id"], entity),
                    ).fetchone()
                    if not old and not _make_room(db, configuration):
                        for item in items:
                            stream._diagnostic(
                                db,
                                actor["tenant"],
                                model["id"],
                                item["id"],
                                "event-time entity capacity reached",
                            )
                        continue
                    coverage_epoch = old["epoch"] if old else uuid.uuid4().hex
                    result = advance(
                        json.loads(old["items"]) if old else [],
                        items,
                        maximum_time=old["max_time"] if old else None,
                        emitted_time=old["emitted_time"] if old else None,
                        lateness=definition["lateness_seconds"],
                        window=definition["window"],
                        stride=definition["stride"],
                        finalize=not items and old is not None,
                    )
                    for identifier, reason in result["diagnostics"]:
                        stream._diagnostic(
                            db, actor["tenant"], model["id"], identifier, reason
                        )
                    for ids in result["jobs"]:
                        stream._job(
                            db,
                            model,
                            actor,
                            index,
                            ids,
                            stream_context={
                                "profile_revision": fresh["revision"],
                                "stream_epoch": definition["stream_epoch"],
                                "model_review_id": definition["model_review_id"],
                                "coverage_epoch": coverage_epoch,
                                "window": definition["window"],
                                "stride": definition["stride"],
                                "lateness_seconds": definition["lateness_seconds"],
                            },
                        )
                        total += 1
                    # Empty bounded tombstones preserve the watermark after an
                    # idle flush; delayed records cannot restart a past window.
                    db.execute(
                        "INSERT INTO sequence_event_time_buffers(model_id,entity,tenant,index_name,items,max_time,emitted_time,updated,epoch) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(model_id,entity) DO UPDATE SET items=excluded.items,max_time=excluded.max_time,emitted_time=excluded.emitted_time,updated=excluded.updated,epoch=excluded.epoch",
                        (
                            model["id"],
                            entity,
                            actor["tenant"],
                            index,
                            encode(result["items"]),
                            result["max_time"],
                            result["emitted_time"],
                            now,
                            coverage_epoch,
                        ),
                    )
                final = pending[-1]["seq"] if pending else cursor
                db.execute(
                    "INSERT INTO sequence_event_time_state VALUES(?,?,?) ON CONFLICT(model_id) DO UPDATE SET cursor=excluded.cursor,updated=excluded.updated",
                    (model["id"], final, now),
                )
        except (KeyError, PermissionError, ConflictError, ValueError) as exc:
            with store.write_lock, store.control() as db:
                stream._diagnostic(
                    db,
                    configuration["tenant"],
                    configuration["model_id"],
                    None,
                    "event-time: " + str(exc),
                )
                fresh = db.execute(
                    "SELECT revision,state FROM sequence_event_time_config WHERE model_id=?",
                    (configuration["model_id"],),
                ).fetchone()
                if (
                    isinstance(exc, (PermissionError, ConflictError))
                    and fresh
                    and fresh["revision"] == configuration["revision"]
                    and fresh["state"] == "active"
                ):
                    suspend(db, configuration["model_id"], str(exc))
                    _cancel_work(
                        db,
                        configuration["model_id"],
                        "event-time authority or activation changed; analysis paused",
                    )
    return total


def protected_ids(db, tenant, ids):
    if (
        not ids
        or not db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='sequence_event_time_config'"
        ).fetchone()
    ):
        return set()
    buffered = {
        json.loads(r[0])["id"]
        for r in db.execute(
            "SELECT j.value FROM sequence_event_time_buffers b JOIN sequence_event_time_config c ON c.model_id=b.model_id AND c.state='active',json_each(b.items) j WHERE b.tenant=? AND c.tenant=b.tenant AND json_extract(j.value,'$.id') IN (SELECT value FROM json_each(?))",
            (tenant, encode(ids)),
        )
    }
    pending = {
        r[0]
        for r in db.execute(
            "SELECT e.event_id FROM intelligence_event_outbox e JOIN sequence_event_time_state s ON e.seq>s.cursor JOIN sequence_event_time_config c ON c.model_id=s.model_id WHERE e.tenant=? AND c.tenant=e.tenant AND c.state='active' AND e.event_id IN (SELECT value FROM json_each(?)) AND e.index_name IN (SELECT value FROM json_each(c.indexes))",
            (tenant, encode(ids)),
        )
    }
    return buffered | pending


def status(store, who):
    with principal.transaction(store, who) as (db, actor):
        return {
            "profiles": [
                {
                    "model_id": r["model_id"],
                    "owner": r["owner"],
                    "revision": r["revision"],
                    "state": r["state"],
                    "reviewer": r["reviewer"],
                    "reason": r["reason"],
                    "definition": json.loads(r["definition"]),
                    "processing": "event_time"
                    if r["state"] == "active"
                    else "legacy_from_review_boundary"
                    if r["state"] == "disabled"
                    else "paused",
                }
                for r in db.execute(
                    "SELECT * FROM sequence_event_time_config WHERE tenant=? ORDER BY updated DESC",
                    (actor["tenant"],),
                )
                if principal.contains(
                    actor["allowed_indexes"], json.loads(r["indexes"])
                )
            ],
            "default_profile": "legacy-only-when-never-configured-or-independently-disabled",
            "pending_or_suspended": "paused; no implicit legacy fallback",
            "reactivation": "new model review requires a fresh stream profile revision and peer review",
            "empty_watermark_eviction": "oldest completed entity only; new coverage epoch, no continuity claim",
            "max_buffer": MAX_BUFFER,
            "max_entities": MAX_ENTITIES,
        }


def register(app, store, runtime, who, body):
    from fastapi import Request
    from starlette.concurrency import run_in_threadpool

    @app.get("/api/v3/ml/sequences/event-time")
    async def get_status(request: Request):
        return await run_in_threadpool(status, store, who(request))

    @app.put("/api/v3/ml/sequences/{identifier}/event-time")
    async def put(identifier: str, request: Request):
        return await run_in_threadpool(
            save, store, who(request, ("admin",)), identifier, await body(request)
        )

    @app.post("/api/v3/ml/sequences/{identifier}/event-time/review")
    async def approve(identifier: str, request: Request):
        return await run_in_threadpool(
            review, store, who(request, ("admin",)), identifier, await body(request)
        )
