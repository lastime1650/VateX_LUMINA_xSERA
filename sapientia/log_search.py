"""Authorized disk-backed point-in-time exports and node-local FTS5 indexing.

The search API never accepts SQL. Complete results are spooled to a private
SQLite snapshot, then paged without an OFFSET scan of the analytical store.
Disk and duration budgets fail the whole build rather than silently truncating.
"""

import hashlib
import json
import os
import re
import shutil
import sqlite3
import threading
import time
import uuid
from contextlib import closing, contextmanager, nullcontext

from . import principal
from .query import FIELDS, Query
from .storage import CapacityError, ConflictError, encode

ID = re.compile(r"[0-9a-f]{32}\Z")
MAX_SNAPSHOT_BYTES = 2 * 1024**3
MAX_TENANT_BYTES = 8 * 1024**3
TTL = 3600
FTS_FORMAT = 3
MAX_PENDING_DOCUMENTS = 100000
MAX_PENDING_BYTES = 512 * 1024**2
FTS_CHECK_DOCUMENTS = 128
FTS_CHECK_BYTES = 1024**2
FTS_NATIVE_SECONDS = 1.0
FTS_CHECKPOINT_NATIVE_SECONDS = 5.0
_lock_guard = threading.Lock()
_locks = {}


def initialize(store):
    root = store.path / "log-search"
    if getattr(store, "_log_search_initialized", False):
        return root
    root.mkdir(exist_ok=True)
    if root.is_symlink() or root.resolve() != root:
        raise ValueError("Search snapshots require a local managed directory")
    if os.name != "nt":
        root.chmod(0o700)
    with store.control(local=True) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS log_snapshots(
            id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,
            scope TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,
            row_count INTEGER NOT NULL,bytes INTEGER NOT NULL,digest TEXT NOT NULL,
            query TEXT NOT NULL)""")
        if "purge_generation" not in {
            r[1] for r in db.execute("PRAGMA table_info(log_snapshots)")
        }:
            db.execute(
                "ALTER TABLE log_snapshots ADD COLUMN purge_generation INTEGER NOT NULL DEFAULT 0"
            )
        if "ndjson_bytes" not in {
            r[1] for r in db.execute("PRAGMA table_info(log_snapshots)")
        }:
            db.execute("ALTER TABLE log_snapshots ADD COLUMN ndjson_bytes INTEGER")
        db.execute(
            "CREATE TABLE IF NOT EXISTS log_search_generation(singleton INTEGER PRIMARY KEY,purges INTEGER NOT NULL)"
        )
        db.execute(
            "INSERT OR IGNORE INTO log_search_generation VALUES(1,?)",
            (getattr(store, "purge_generation", 0),),
        )
        db.executescript("""CREATE TABLE IF NOT EXISTS log_fts_journal(
            seq INTEGER PRIMARY KEY AUTOINCREMENT,op TEXT NOT NULL,tenant TEXT NOT NULL,
            event_id TEXT NOT NULL,index_name TEXT,message TEXT,raw TEXT,digest TEXT,
            weight INTEGER NOT NULL,created REAL NOT NULL,generation INTEGER NOT NULL,purges INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS log_fts_state(singleton INTEGER PRIMARY KEY,
            bootstrap_required INTEGER NOT NULL,applied_sequence INTEGER NOT NULL,
            generation INTEGER NOT NULL,purges INTEGER NOT NULL,pending_documents INTEGER NOT NULL,
            pending_bytes INTEGER NOT NULL,indexed_documents INTEGER NOT NULL,last_error TEXT);
            CREATE TABLE IF NOT EXISTS log_fts_inflight(seq INTEGER PRIMARY KEY);
        """)
        if (
            db.execute("SELECT 1 FROM log_fts_state WHERE singleton=1").fetchone()
            is None
        ):
            with closing(store.analytics.cursor()) as con:
                existing = bool(
                    con.execute(
                        "SELECT 1 FROM " + _relation(store) + " LIMIT 1"
                    ).fetchone()
                )
            db.execute(
                "INSERT INTO log_fts_state VALUES(1,?,0,?,?,0,0,0,NULL)",
                (
                    int(existing),
                    getattr(store, "content_generation", 0),
                    getattr(store, "purge_generation", 0),
                ),
            )
            db.execute("INSERT OR IGNORE INTO log_fts_inflight SELECT seq FROM queue")
    store._log_search_initialized = True
    return root


def journal_begin(store, db, rows):
    """Durably fence a source commit before its separately committed FTS handoff."""
    db.executemany(
        "INSERT OR IGNORE INTO log_fts_inflight VALUES(?)",
        [(row["seq"],) for row in rows],
    )


def journal_preflight(store, db, rows):
    """Reject a full handoff before source I/O; append checks remain authoritative.

    The normalized queue payload contains the message, canonical raw body and
    event ID, so its encoded size plus overhead bounds their journal weight.
    This read-only estimate may conservatively defer a batch near the byte cap.
    It neither reserves capacity nor clears the durable source-commit fence.
    """
    if not rows:
        return
    state = db.execute(
        "SELECT pending_documents,pending_bytes FROM log_fts_state WHERE singleton=1"
    ).fetchone()
    if state is None:
        raise ConflictError("Full-text journal initialization required")
    if state[0] + len(rows) > MAX_PENDING_DOCUMENTS:
        raise CapacityError(
            "Full-text pending journal full; indexing must catch up before source acknowledgement"
        )
    weight = sum(len(row["payload"].encode()) + 256 for row in rows)
    if state[1] + weight > MAX_PENDING_BYTES:
        raise CapacityError(
            "Full-text pending journal full; indexing must catch up before source acknowledgement"
        )
    if shutil.disk_usage(store.path).free < store.settings.min_free_bytes + weight:
        raise CapacityError("Full-text journal disk reserve reached")


def journal_prefix(store, db, rows, *, sealed_keys=()):
    """Fit an ordered queue prefix without reserving or relaxing journal bounds.

    The caller may exempt completed sealed replays only; a prior source-commit
    fence still requires a journal handoff. A charged row that cannot fit stops
    the prefix, including later exempt rows, so source queue order is preserved.
    Existing preflight and authoritative append must still run after selection;
    this helper performs no filesystem or source reads.
    """
    if not rows:
        return 0
    state = db.execute(
        "SELECT pending_documents,pending_bytes FROM log_fts_state WHERE singleton=1"
    ).fetchone()
    if state is None:
        raise ConflictError("Full-text journal initialization required")
    documents, weight = state
    if documents < 0 or weight < 0:
        raise ConflictError("Full-text journal counters are inconsistent")
    sealed = set(sealed_keys)
    prefix = 0
    for row in rows:
        if (row["tenant"], row["event_id"]) not in sealed:
            extra = len(row["payload"].encode()) + 256
            if (
                documents + 1 > MAX_PENDING_DOCUMENTS
                or weight + extra > MAX_PENDING_BYTES
            ):
                break
            documents += 1
            weight += extra
        prefix += 1
    if not prefix:
        raise CapacityError(
            "Full-text pending journal full; indexing must catch up before source acknowledgement"
        )
    return prefix


def journal_complete(store, db, rows):
    """Clear the fence only in the same transaction as outbox + queue ACK."""
    db.executemany(
        "DELETE FROM log_fts_inflight WHERE seq=?", [(row["seq"],) for row in rows]
    )


def _journal_generation(db):
    row = db.execute(
        "SELECT content,purges FROM log_event_generation WHERE singleton=1"
    ).fetchone()
    return tuple(row)


def _append_journal(store, db, values):
    """Called only inside the source control transaction, never takes FTS locks."""
    state = db.execute(
        "SELECT pending_documents,pending_bytes FROM log_fts_state WHERE singleton=1"
    ).fetchone()
    if state is None:
        raise ConflictError("Full-text journal initialization required")
    weight = sum(row[7] for row in values)
    if (
        state[0] + len(values) > MAX_PENDING_DOCUMENTS
        or state[1] + weight > MAX_PENDING_BYTES
    ):
        raise CapacityError(
            "Full-text pending journal full; indexing must catch up before source acknowledgement"
        )
    if shutil.disk_usage(store.path).free < store.settings.min_free_bytes + weight:
        raise CapacityError("Full-text journal disk reserve reached")
    db.executemany(
        "INSERT INTO log_fts_journal(op,tenant,event_id,index_name,message,raw,digest,weight,created,generation,purges) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        values,
    )
    db.execute(
        "UPDATE log_fts_state SET pending_documents=pending_documents+?,pending_bytes=pending_bytes+? WHERE singleton=1",
        (len(values), weight),
    )


def journal_indexed(store, db, rows):
    """Durable source→FTS handoff; source commit replay retains immutable bodies."""
    generation, purges = _journal_generation(db)
    values = []
    for row in rows:
        event = json.loads(row["payload"])
        if event.get("event_id") != row["event_id"]:
            raise ConflictError("Full-text journal event identity mismatch")
        message, raw = event["message"], encode(event["raw"])
        digest = hashlib.sha256(encode([message, raw]).encode()).hexdigest()
        weight = (
            len(message.encode())
            + len(raw.encode())
            + len(row["event_id"].encode())
            + 256
        )
        values.append(
            (
                "put",
                row["tenant"],
                row["event_id"],
                event.get("index", "main"),
                message,
                raw,
                digest,
                weight,
                time.time(),
                generation,
                purges,
            )
        )
    _append_journal(store, db, values)


def journal_purged(store, db, tenant, event_ids):
    """Ordered tombstones precede any permitted reuse of a purged event ID."""
    generation, purges = _journal_generation(db)
    values = [
        (
            "delete",
            tenant,
            event_id,
            None,
            None,
            None,
            None,
            len(event_id.encode()) + 256,
            time.time(),
            generation,
            purges,
        )
        for event_id in event_ids
    ]
    _append_journal(store, db, values)


def _read_gate(store, deadline=None):
    gate = getattr(store, "segment_lock", None)
    return gate.read(deadline=deadline) if gate else nullcontext()


class _FTSLockDeferred(CapacityError):
    """Expected background-only FTS mutex contention."""


@contextmanager
def _budget_lock(lock, deadline=None, *, busy_error=CapacityError):
    acquired = (
        lock.acquire()
        if deadline is None
        else lock.acquire(timeout=max(0, deadline - time.monotonic()))
    )
    if not acquired:
        raise busy_error("Log search deadline exceeded while waiting for storage")
    try:
        yield
    finally:
        lock.release()


def _pending_retention(store, db=None):
    if db is None:
        with store.control(local=True) as connection:
            return _pending_retention(store, connection)
    return bool(
        db.execute(
            "SELECT 1 FROM retention_intents i LEFT JOIN retention_applied a ON a.id=i.id WHERE a.id IS NULL LIMIT 1"
        ).fetchone()
    )


def _require_retained_source(store):
    if _pending_retention(store):
        raise ConflictError(
            "Retention deletion is pending; search copies remain unavailable until recovery completes"
        )


def _relation(store):
    return "events_all" if getattr(store, "segments", None) else "events"


def _generation(store):
    generation = getattr(store, "event_generation", None)
    if generation is not None:
        return str(generation() if callable(generation) else generation)
    with closing(store.analytics.cursor()) as con:
        return encode(
            con.execute("SELECT count(*),max(received) FROM events").fetchone()
        )


def _fts_lock(store):
    key = str(store.path)
    with _lock_guard:
        return _locks.setdefault(key, threading.Lock())


def _fts_budget(store):
    return int(getattr(store.settings, "fts_max_bytes", 8 * 1024**3))


def _open_terms(path):
    db = sqlite3.connect(path, timeout=0.25)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=DELETE")
    db.execute("PRAGMA synchronous=FULL")
    db.execute("PRAGMA cache_size=-8192")
    return db


def _new_terms(db, generation, purges, sequence=0):
    db.executescript("""CREATE TABLE metadata(format_version INTEGER NOT NULL,
        applied_sequence INTEGER NOT NULL,generation INTEGER NOT NULL,purges INTEGER NOT NULL,documents INTEGER NOT NULL);
        CREATE TABLE registry(tenant TEXT NOT NULL,event_id TEXT NOT NULL,term_rowid INTEGER NOT NULL UNIQUE,
        digest TEXT NOT NULL,index_name TEXT NOT NULL,PRIMARY KEY(tenant,event_id)) WITHOUT ROWID;
        CREATE VIRTUAL TABLE terms USING fts5(tenant UNINDEXED,event_id UNINDEXED,message,raw,
        tokenize='unicode61 remove_diacritics 2');""")
    db.execute(
        "INSERT INTO metadata VALUES(?,?,?,?,0)",
        (FTS_FORMAT, sequence, generation, purges),
    )
    db.commit()


def _cache_metadata(db):
    required = {
        "format_version",
        "applied_sequence",
        "generation",
        "purges",
        "documents",
    }
    columns = {row[1] for row in db.execute("PRAGMA table_info(metadata)")}
    registry = {row[1] for row in db.execute("PRAGMA table_info(registry)")}
    if (
        not required <= columns
        or not {"tenant", "event_id", "term_rowid", "digest", "index_name"} <= registry
        or not db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='terms' AND type='table'"
        ).fetchone()
    ):
        raise ConflictError("Full-text cache version/schema requires offline rebuild")
    row = db.execute("SELECT * FROM metadata").fetchone()
    if row is None:
        raise ConflictError("Full-text cache checkpoint requires offline rebuild")
    return dict(row)


def _check_fts_budget(store, db, path, deadline, extra=0):
    if time.monotonic() >= deadline:
        raise CapacityError("Full-text indexing deadline exceeded")
    weight = (
        db.execute("PRAGMA page_count").fetchone()[0]
        * db.execute("PRAGMA page_size").fetchone()[0]
    )
    journal = path.with_name(path.name + "-journal")
    weight += journal.stat().st_size if journal.exists() else 0
    if weight + extra > _fts_budget(store):
        raise CapacityError("Full-text configured disk budget exceeded")
    if shutil.disk_usage(path.parent).free < store.settings.min_free_bytes + extra:
        raise CapacityError("Full-text disk reserve reached")


def error_code(exc):
    """Stable diagnostics contain no event bodies, SQL parameters or secrets."""
    if isinstance(exc, sqlite3.DatabaseError):
        code = getattr(exc, "sqlite_errorcode", None)
        if code == sqlite3.SQLITE_INTERRUPT:
            return "sqlite_interrupted"
        if code in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
            return "sqlite_busy"
        return "sqlite_error"
    if isinstance(exc, CapacityError):
        message = str(exc).lower()
        if "disk budget" in message:
            return "disk_quota"
        if "disk reserve" in message:
            return "disk_reserve"
        if "journal full" in message:
            return "journal_capacity"
        if "deadline" in message:
            return "deadline"
        return "capacity_error"
    if isinstance(exc, ConflictError):
        return "cache_conflict"
    return "error"


def _record_fts_error(store, exc):
    code = error_code(exc)
    with store.write_lock, store.control(local=True) as db:
        db.execute("UPDATE log_fts_state SET last_error=? WHERE singleton=1", (code,))


def drain(
    store,
    budget=0.25,
    max_documents=500,
    cancel=None,
    after_commit=None,
    hard_deadline=None,
    defer_lock=False,
):
    """Bounded durable outbox consumer; never scans source IDs or holds flush_lock.

    FTS commit precedes control ACK. Replaying a committed batch verifies the
    immutable digest and uses its stored sequence, so crashes cannot duplicate
    terms or resurrect a tombstone before a newer put operation. The batch
    budget is cooperative between documents. Each document has a one-second
    native VM guard. The checkpoint has a separate five-second guard because
    SQLite may flush pending FTS terms and merge index segments at a statement
    savepoint. Both guards are constrained by an interactive caller's hard
    deadline. SQLite busy waits and filesystem I/O are separate;
    the progress callback is not a hard wall-clock execution guarantee.
    Runtime may defer FTS mutex contention without changing durable error state;
    interactive callers retain the default acquisition failure.
    """
    deadline = time.monotonic() + max(0.001, float(budget))
    if hard_deadline is not None:
        deadline = min(deadline, hard_deadline)
    cancelled_now = (
        cancel if callable(cancel) else cancel.is_set if cancel else lambda: False
    )
    root = initialize(store)
    path = root / "terms.sqlite3"
    try:
        with _budget_lock(
            _fts_lock(store),
            deadline,
            busy_error=_FTSLockDeferred if defer_lock else CapacityError,
        ):
            if cancelled_now():
                return {"processed": 0, "cancelled": True}
            with store.control(local=True) as control:
                state = dict(
                    control.execute(
                        "SELECT * FROM log_fts_state WHERE singleton=1"
                    ).fetchone()
                )
                if state["bootstrap_required"]:
                    return {"processed": 0, "bootstrap_required": True}
                rows = [
                    dict(r)
                    for r in control.execute(
                        "SELECT * FROM log_fts_journal ORDER BY seq LIMIT ?",
                        (max_documents,),
                    )
                ]
            if not path.exists() and (
                state["indexed_documents"] or state["applied_sequence"]
            ):
                with store.write_lock, store.control(local=True) as control:
                    control.execute(
                        "UPDATE log_fts_state SET bootstrap_required=1,last_error='missing_cache' WHERE singleton=1"
                    )
                raise ConflictError("Full-text cache missing; offline rebuild required")
            with closing(_open_terms(path)) as db:
                if not db.execute(
                    "SELECT 1 FROM sqlite_master WHERE name='metadata'"
                ).fetchone():
                    if state["indexed_documents"] or state["applied_sequence"]:
                        with store.write_lock, store.control(local=True) as control:
                            control.execute(
                                "UPDATE log_fts_state SET bootstrap_required=1,last_error='incomplete_cache' WHERE singleton=1"
                            )
                        raise ConflictError(
                            "Full-text acknowledged cache is incomplete; offline rebuild required"
                        )
                    _new_terms(
                        db,
                        state["generation"],
                        state["purges"],
                        state["applied_sequence"],
                    )
                try:
                    meta = _cache_metadata(db)
                except ConflictError:
                    with store.write_lock, store.control(local=True) as control:
                        control.execute(
                            "UPDATE log_fts_state SET bootstrap_required=1,last_error='incompatible_cache' WHERE singleton=1"
                        )
                    raise
                if meta["format_version"] != FTS_FORMAT:
                    raise ConflictError(
                        "Full-text cache version requires offline rebuild"
                    )
                if meta["applied_sequence"] < state["applied_sequence"] or (
                    meta["applied_sequence"] == state["applied_sequence"]
                    and meta["documents"] != state["indexed_documents"]
                ):
                    with store.write_lock, store.control(local=True) as control:
                        control.execute(
                            "UPDATE log_fts_state SET bootstrap_required=1,last_error='incomplete_cache' WHERE singleton=1"
                        )
                    raise ConflictError(
                        "Full-text acknowledged cache checkpoint is inconsistent; offline rebuild required"
                    )
                if meta["applied_sequence"] > state["applied_sequence"] and (
                    not rows or rows[0]["seq"] > meta["applied_sequence"]
                ):
                    with store.write_lock, store.control(local=True) as control:
                        control.execute(
                            "UPDATE log_fts_state SET bootstrap_required=1,last_error='incomplete_cache' WHERE singleton=1"
                        )
                    raise ConflictError(
                        "Full-text cache checkpoint has no recovery journal; offline rebuild required"
                    )
                if not rows:
                    # A logical purge may ultimately delete no held originals.
                    # Once its pending fence clears, a content-identical cache
                    # can advance the privacy epoch without rescanning bodies.
                    generation = getattr(store, "content_generation", 0)
                    purges = getattr(store, "purge_generation", 0)
                    if state["generation"] == generation and not _pending_retention(
                        store
                    ):
                        if meta["purges"] != purges:
                            db.execute("UPDATE metadata SET purges=?", (purges,))
                            db.commit()
                        if state["purges"] != purges or state["last_error"] is not None:
                            with store.write_lock, store.control(local=True) as control:
                                control.execute(
                                    "UPDATE log_fts_state SET purges=?,last_error=NULL WHERE singleton=1 AND generation=? AND pending_documents=0",
                                    (purges, generation),
                                )
                    return {"processed": 0}
                native_deadline = float("inf")
                native_cancel = True

                def native_interrupted():
                    return int(
                        time.monotonic() >= native_deadline
                        or (native_cancel and cancelled_now())
                    )

                db.set_progress_handler(native_interrupted, 1000)
                db.execute("BEGIN IMMEDIATE")
                try:
                    checked_documents = 0
                    cancelled = False
                    for position, row in enumerate(rows):
                        if row["seq"] <= meta["applied_sequence"]:
                            continue
                        if cancelled_now():
                            cancelled = True
                            break
                        if time.monotonic() >= deadline - 0.02:
                            break
                        if not checked_documents:
                            # Filesystem/SQLite size probes are expensive on Windows.
                            # Bound the unchecked work by documents AND input bytes;
                            # retain the actual precommit check and rollback below.
                            checked_weight = 0
                            for upcoming in rows[
                                position : position + FTS_CHECK_DOCUMENTS
                            ]:
                                if (
                                    checked_documents
                                    and checked_weight + upcoming["weight"]
                                    > FTS_CHECK_BYTES
                                ):
                                    break
                                checked_weight += upcoming["weight"]
                                checked_documents += 1
                            _check_fts_budget(
                                store, db, path, float("inf"), checked_weight * 3
                            )
                            if time.monotonic() >= deadline - 0.02:
                                break
                        native_deadline = min(
                            time.monotonic() + FTS_NATIVE_SECONDS,
                            hard_deadline
                            if hard_deadline is not None
                            else float("inf"),
                        )
                        existing = db.execute(
                            "SELECT term_rowid,digest FROM registry WHERE tenant=? AND event_id=?",
                            (row["tenant"], row["event_id"]),
                        ).fetchone()
                        if row["op"] == "delete":
                            if existing:
                                db.execute(
                                    "DELETE FROM terms WHERE rowid=?", (existing[0],)
                                )
                                db.execute(
                                    "DELETE FROM registry WHERE tenant=? AND event_id=?",
                                    (row["tenant"], row["event_id"]),
                                )
                                meta["documents"] -= 1
                        elif row["op"] == "put":
                            if existing and existing[1] != row["digest"]:
                                raise ConflictError(
                                    "Full-text immutable identity digest conflict"
                                )
                            if not existing:
                                result = db.execute(
                                    "INSERT INTO terms(tenant,event_id,message,raw) VALUES(?,?,?,?)",
                                    (
                                        row["tenant"],
                                        row["event_id"],
                                        row["message"],
                                        row["raw"],
                                    ),
                                )
                                db.execute(
                                    "INSERT INTO registry VALUES(?,?,?,?,?)",
                                    (
                                        row["tenant"],
                                        row["event_id"],
                                        result.lastrowid,
                                        row["digest"],
                                        row["index_name"],
                                    ),
                                )
                                meta["documents"] += 1
                        else:
                            raise ConflictError("Invalid full-text journal operation")
                        if time.monotonic() >= native_deadline:
                            raise CapacityError(
                                "Full-text atomic work deadline exceeded"
                            )
                        meta.update(
                            applied_sequence=row["seq"],
                            generation=row["generation"],
                            purges=row["purges"],
                        )
                        checked_documents -= 1
                    # A fresh native guard completes the prefix independently
                    # of the cooperative slice. Cancellation observed between
                    # documents commits finished work; mid-document VM cancel
                    # still interrupts and replays the unacknowledged batch.
                    native_cancel = False
                    native_deadline = min(
                        time.monotonic() + FTS_CHECKPOINT_NATIVE_SECONDS,
                        hard_deadline if hard_deadline is not None else float("inf"),
                    )
                    db.execute(
                        "UPDATE metadata SET applied_sequence=?,generation=?,purges=?,documents=?",
                        (
                            meta["applied_sequence"],
                            meta["generation"],
                            meta["purges"],
                            meta["documents"],
                        ),
                    )
                    # The cooperative budget bounds processing, then commits
                    # the completed prefix instead of rolling all progress back.
                    _check_fts_budget(store, db, path, float("inf"))
                    if time.monotonic() >= native_deadline:
                        raise CapacityError("Full-text atomic work deadline exceeded")
                    db.commit()
                except Exception:
                    db.rollback()
                    raise
                finally:
                    db.set_progress_handler(None, 0)
                if path.stat().st_size > _fts_budget(store):
                    raise CapacityError(
                        "Full-text configured disk budget exceeded after commit"
                    )
            # A crash at this seam replays the same sequences without side effects.
            if after_commit:
                after_commit()
            with store.write_lock, store.control(local=True) as control:
                control.execute("BEGIN IMMEDIATE")
                amount, weight = control.execute(
                    "SELECT count(*),COALESCE(sum(weight),0) FROM log_fts_journal WHERE seq<=?",
                    (meta["applied_sequence"],),
                ).fetchone()
                control.execute(
                    "DELETE FROM log_fts_journal WHERE seq<=?",
                    (meta["applied_sequence"],),
                )
                control.execute(
                    "UPDATE log_fts_state SET applied_sequence=?,generation=?,purges=?,indexed_documents=?,pending_documents=pending_documents-?,pending_bytes=pending_bytes-?,last_error=NULL WHERE singleton=1",
                    (
                        meta["applied_sequence"],
                        meta["generation"],
                        meta["purges"],
                        meta["documents"],
                        amount,
                        weight,
                    ),
                )
            return {"processed": amount, **({"cancelled": True} if cancelled else {})}
    except _FTSLockDeferred:
        return {"processed": 0, "deferred": "fts_lock"}
    except Exception as exc:
        _record_fts_error(store, exc)
        raise


def _fts(store, deadline):
    """Interactive reads may drain a small batch, never bootstrap all sources."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise CapacityError("Full-text search deadline exceeded")
    drain(store, budget=min(0.25, remaining), hard_deadline=deadline)
    with store.control(local=True) as db:
        state = db.execute("SELECT * FROM log_fts_state WHERE singleton=1").fetchone()
        inflight = bool(db.execute("SELECT 1 FROM log_fts_inflight LIMIT 1").fetchone())
    if state["bootstrap_required"]:
        raise ConflictError(
            "Full-text existing-data bootstrap required; run offline rebuild-fts"
        )
    if (
        inflight
        or state["pending_documents"]
        or state["generation"] != getattr(store, "content_generation", 0)
        or state["purges"] != getattr(store, "purge_generation", 0)
    ):
        raise CapacityError(
            "Full-text indexing in progress; structured search remains available"
        )
    path = initialize(store) / "terms.sqlite3"
    if not path.exists() or path.stat().st_size > _fts_budget(store):
        raise CapacityError(
            "Full-text cache unavailable or configured disk budget exceeded"
        )
    _require_retained_source(store)
    return path


def rebuild(store, deadline):
    """Explicit offline full bootstrap; private, exact, atomic publication.

    Caller owns the Store process lock, normally through the offline CLI. The
    deadline is independent from the interactive query limit. No partial cache
    is published, and pre-existing valid cache remains intact on failure.
    """
    started = time.monotonic()
    root = initialize(store)
    path, pending = root / "terms.sqlite3", root / (uuid.uuid4().hex + ".fts.pending")
    timer = None
    try:
        with (
            _budget_lock(store.flush_lock, deadline),
            _read_gate(store, deadline),
            _budget_lock(_fts_lock(store), deadline),
        ):
            if getattr(store, "segments", None):
                store.segments.ensure_readable(deadline=deadline)
            _require_retained_source(store)
            generation, purges = (
                getattr(store, "content_generation", 0),
                getattr(store, "purge_generation", 0),
            )
            with store.control(local=True) as control:
                sequence = control.execute(
                    "SELECT max(COALESCE((SELECT max(seq) FROM log_fts_journal),0),applied_sequence) FROM log_fts_state WHERE singleton=1"
                ).fetchone()[0]
            with (
                closing(_open_terms(pending)) as db,
                closing(store.analytics.cursor()) as con,
            ):
                _new_terms(db, generation, purges, sequence)
                timer = threading.Timer(
                    max(0.001, deadline - time.monotonic()), con.interrupt
                )
                timer.daemon = True
                timer.start()
                db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
                db.execute("BEGIN IMMEDIATE")
                con.execute(
                    "SELECT tenant,event_id,message,raw,index_name FROM "
                    + _relation(store)
                )
                documents = 0
                while rows := con.fetchmany(128):
                    _check_fts_budget(
                        store,
                        db,
                        pending,
                        deadline,
                        sum(
                            len((r[2] or "").encode()) + len((r[3] or "").encode())
                            for r in rows
                        )
                        * 3,
                    )
                    values, keys = [], []
                    for tenant, event_id, message, raw, index_name in rows:
                        documents += 1
                        digest = hashlib.sha256(
                            encode([message, raw]).encode()
                        ).hexdigest()
                        values.append((documents, tenant, event_id, message, raw))
                        keys.append((tenant, event_id, documents, digest, index_name))
                    db.executemany(
                        "INSERT INTO terms(rowid,tenant,event_id,message,raw) VALUES(?,?,?,?,?)",
                        values,
                    )
                    db.executemany("INSERT INTO registry VALUES(?,?,?,?,?)", keys)
                if generation != getattr(
                    store, "content_generation", 0
                ) or purges != getattr(store, "purge_generation", 0):
                    raise ConflictError(
                        "Full-text source changed during offline rebuild"
                    )
                _require_retained_source(store)
                db.execute("UPDATE metadata SET documents=?", (documents,))
                _check_fts_budget(store, db, pending, deadline)
                db.commit()
                timer.cancel()
                timer.join()
            if pending.stat().st_size > _fts_budget(store):
                raise CapacityError(
                    "Full-text configured disk budget exceeded after rebuild"
                )
            os.replace(pending, path)
            with store.write_lock, store.control(local=True) as control:
                control.execute("BEGIN IMMEDIATE")
                control.execute("DELETE FROM log_fts_journal WHERE seq<=?", (sequence,))
                control.execute("DELETE FROM log_fts_inflight")
                amount, weight = control.execute(
                    "SELECT count(*),COALESCE(sum(weight),0) FROM log_fts_journal"
                ).fetchone()
                control.execute(
                    "UPDATE log_fts_state SET bootstrap_required=0,applied_sequence=?,generation=?,purges=?,pending_documents=?,pending_bytes=?,indexed_documents=?,last_error=NULL WHERE singleton=1",
                    (sequence, generation, purges, amount, weight, documents),
                )
            return {
                "documents": documents,
                "bytes": path.stat().st_size,
                "duration_seconds": time.monotonic() - started,
                "current": True,
                "rebuilt": True,
            }
    except Exception as exc:
        _record_fts_error(store, exc)
        if time.monotonic() >= deadline and not isinstance(
            exc, (CapacityError, ConflictError)
        ):
            raise CapacityError("Full-text offline rebuild deadline exceeded") from None
        raise
    finally:
        if timer:
            timer.cancel()
            timer.join()
        pending.unlink(missing_ok=True)


def _query(payload, tenant, allowed):
    if not isinstance(payload, dict) or set(payload) - {
        "query",
        "fulltext",
        "ttl_seconds",
    }:
        raise ValueError("Expected query, optional fulltext and ttl_seconds")
    supplied = payload.get("query", {})
    if not isinstance(supplied, dict) or supplied.get("language", "json") != "json":
        raise ValueError("Complete log snapshots require a structured JSON event query")
    supplied = {**supplied, "language": "json", "limit": 1000}
    supplied.setdefault("earliest", 0)
    supplied.setdefault("latest", time.time() + 86401)
    body = supplied.setdefault("query", {})
    if not isinstance(body, dict) or body.get("group_by") is not None:
        raise ValueError("Snapshot query must select events, not aggregate groups")
    supplied["query"] = {
        **body,
        "fields": sorted(FIELDS),
        "sort": "received",
        "descending": False,
    }
    q = Query.parse(supplied)
    sql, args = q.compile(tenant, allowed_indexes=allowed)
    # The compiler produces a final ORDER BY/LIMIT. The snapshot supplies its
    # own received/event_id ordering after the optional full-text join.
    sql = sql.rsplit(" ORDER BY ", 1)[0]
    return sql, args[:-1]


def _snapshot_json(sql):
    # Identifiers and JSON keys come only from the server's fixed field set.
    # Native JSON preserves nested raw numbers without a Python object per row.
    fields = []
    for name in sorted(FIELDS):
        value = "CAST(selected.raw AS JSON)" if name == "raw" else "selected." + name
        fields.extend(("'" + name + "'", value))
    return (
        "SELECT json_object("
        + ",".join(fields)
        + ") AS payload FROM ("
        + sql
        + ") selected ORDER BY selected.received,selected.event_id"
    )


def create(store, who, payload):
    deadline = time.monotonic() + min(120, max(15, store.settings.query_timeout))
    root = initialize(store)
    with principal.transaction(store, who) as (_, actor):
        scope = actor["allowed_indexes"]
    sql, args = _query(payload, actor["tenant"], scope)
    fulltext = payload.get("fulltext", "")
    if not isinstance(fulltext, str) or len(fulltext) > 1024:
        raise ValueError("Fulltext must be at most 1024 characters")
    ttl = payload.get("ttl_seconds", TTL)
    if type(ttl) is not int or not 60 <= ttl <= 86400:
        raise ValueError("Snapshot TTL must be 60..86400 seconds")
    maintenance(store, deadline=deadline)
    with store.control(local=True) as db:
        count, used = db.execute(
            "SELECT count(*),COALESCE(sum(bytes),0) FROM log_snapshots WHERE tenant=?",
            (actor["tenant"],),
        ).fetchone()
    if count >= 32 or used >= MAX_TENANT_BYTES:
        raise CapacityError("Tenant snapshot quota exhausted; close expired searches")
    if not store.query_slots.acquire(blocking=False):
        raise CapacityError("Search concurrency exhausted; retry later")
    snapshot_id = uuid.uuid4().hex
    pending, destination = (
        root / (snapshot_id + ".pending"),
        root / (snapshot_id + ".sqlite3"),
    )
    digest, count, total = hashlib.sha256(), 0, 0
    con, timer = None, None
    try:
        with (
            _budget_lock(store.flush_lock, deadline),
            _read_gate(store, deadline),
            closing(sqlite3.connect(pending)) as spool,
        ):
            if getattr(store, "segments", None):
                store.segments.ensure_readable(deadline=deadline)
            _require_retained_source(store)
            purge_epoch = getattr(store, "purge_generation", 0)
            con = store.analytics.cursor()
            timer = threading.Timer(
                max(0.01, deadline - time.monotonic()), con.interrupt
            )
            timer.daemon = True
            timer.start()
            spool.execute(
                "CREATE TABLE rows(position INTEGER PRIMARY KEY,payload TEXT NOT NULL)"
            )
            if fulltext:
                terms = _fts(store, deadline)
                con.execute(
                    "CREATE TEMP TABLE log_fts_candidates(tenant VARCHAR,event_id VARCHAR)"
                )
                with closing(sqlite3.connect(terms)) as fts:
                    fts.set_progress_handler(
                        lambda: int(time.monotonic() >= deadline), 1000
                    )
                    try:
                        found = fts.execute(
                            "SELECT tenant,event_id FROM terms WHERE terms MATCH ? AND tenant=?",
                            (fulltext, actor["tenant"]),
                        )
                        while candidates := found.fetchmany(500):
                            con.executemany(
                                "INSERT INTO log_fts_candidates VALUES(?,?)", candidates
                            )
                    except sqlite3.OperationalError:
                        if time.monotonic() >= deadline:
                            raise CapacityError(
                                "Full-text search deadline exceeded"
                            ) from None
                        raise ValueError(
                            "Invalid full-text term, phrase or boolean expression"
                        ) from None
                sql = (
                    "SELECT selected.* FROM ("
                    + sql
                    + ") selected JOIN log_fts_candidates candidates USING(event_id) WHERE candidates.tenant=?"
                )
                args = [*args, actor["tenant"]]
            con.execute(_snapshot_json(sql), args)
            while chunk := con.fetchmany(250):
                if time.monotonic() > deadline:
                    raise CapacityError(
                        "Log snapshot deadline exceeded; narrow the time range"
                    )
                values = []
                for (encoded,) in chunk:
                    line = (encoded + "\n").encode()
                    count += 1
                    total += len(line)
                    digest.update(line)
                    values.append((count, encoded))
                if total > MAX_SNAPSHOT_BYTES or total + used > MAX_TENANT_BYTES:
                    raise CapacityError(
                        "Snapshot disk budget exceeded; narrow the time range"
                    )
                if (
                    shutil.disk_usage(root).free
                    < store.settings.min_free_bytes + len(values) * 65536
                ):
                    raise CapacityError("Snapshot disk reserve reached")
                spool.executemany("INSERT INTO rows VALUES(?,?)", values)
            spool.commit()
            timer.cancel()
            timer.join()
            con.close()
            con = None
        principal.recheck(store, actor)
        _require_retained_source(store)
        if purge_epoch != getattr(store, "purge_generation", 0):
            raise ConflictError("Retention changed during snapshot creation; retry")
        os.replace(pending, destination)
        if os.name != "nt":
            destination.chmod(0o600)
        now = time.time()
        with principal.transaction(store, actor, write=True) as (db, fresh):
            store.audit(
                db,
                fresh["tenant"],
                fresh["name"],
                "logs.snapshot.create",
                {
                    "id": snapshot_id,
                    "rows": count,
                    "sha256": digest.hexdigest(),
                    "fulltext": bool(fulltext),
                },
            )
        with store.control(local=True) as db:
            db.execute("BEGIN IMMEDIATE")
            if purge_epoch != getattr(store, "purge_generation", 0):
                raise ConflictError(
                    "Retention changed during snapshot publication; retry"
                )
            current_count, current_bytes = db.execute(
                "SELECT count(*),COALESCE(sum(bytes),0) FROM log_snapshots WHERE tenant=?",
                (actor["tenant"],),
            ).fetchone()
            if (
                current_count >= 32
                or current_bytes + destination.stat().st_size > MAX_TENANT_BYTES
            ):
                raise CapacityError(
                    "Tenant snapshot quota exhausted during publication"
                )
            db.execute(
                "INSERT INTO log_snapshots(id,tenant,owner,scope,created,expires,row_count,bytes,digest,query,purge_generation,ndjson_bytes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    snapshot_id,
                    actor["tenant"],
                    actor["name"],
                    encode(scope),
                    now,
                    now + ttl,
                    count,
                    destination.stat().st_size,
                    digest.hexdigest(),
                    encode(payload),
                    purge_epoch,
                    total,
                ),
            )
        return {
            "id": snapshot_id,
            "rows": count,
            "expires": now + ttl,
            "sha256_ndjson": digest.hexdigest(),
            "snapshot": True,
            "truncated": False,
        }
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        if timer:
            timer.cancel()
            timer.join()
        if con:
            con.close()
        pending.unlink(missing_ok=True)
        store.query_slots.release()


def _authorize(store, who, snapshot_id):
    if not isinstance(snapshot_id, str) or not ID.fullmatch(snapshot_id):
        raise KeyError("Snapshot not found")
    with (
        principal.transaction(store, who) as (_, actor),
        store.control(local=True) as db,
    ):
        row = db.execute(
            "SELECT * FROM log_snapshots WHERE id=? AND tenant=? AND owner=?",
            (snapshot_id, actor["tenant"], actor["name"]),
        ).fetchone()
    if not row:
        raise KeyError("Snapshot not found")
    _require_retained_source(store)
    if row["expires"] <= time.time():
        raise ConflictError("Snapshot expired; create a new search")
    if row["purge_generation"] != getattr(store, "purge_generation", 0):
        raise ConflictError("Log retention changed the source; snapshot invalidated")
    if actor["allowed_indexes"] != json.loads(row["scope"]):
        raise PermissionError("Index permissions changed; create a new search")
    return dict(row), actor


def _page_payloads(store, who, snapshot_id, after=0, limit=500):
    if (
        type(after) is not int
        or after < 0
        or type(limit) is not int
        or not 1 <= limit <= 5000
    ):
        raise ValueError("Page position >=0 and limit 1..5000 required")
    deadline = time.monotonic() + min(120, max(15, store.settings.query_timeout))
    with _budget_lock(_fts_lock(store), deadline):
        metadata, actor = _authorize(store, who, snapshot_id)
        path = initialize(store) / (snapshot_id + ".sqlite3")
        if not path.is_file():
            raise KeyError("Snapshot data no longer available")
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
            db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
            values, payloads, size, position = [], [], 0, after
            for row in db.execute(
                "SELECT position,payload FROM rows WHERE position>? ORDER BY position LIMIT ?",
                (after, limit),
            ):
                weight = len(row[1].encode())
                if size + weight > 2 * 1024 * 1024 and values:
                    break
                values.append(json.loads(row[1]))
                payloads.append(row[1])
                size += weight
                position = row[0]
    principal.recheck(store, actor)
    _require_retained_source(store)
    if metadata["purge_generation"] != getattr(store, "purge_generation", 0):
        raise ConflictError("Retention invalidated this snapshot during the read")
    return {
        "id": snapshot_id,
        "rows": values,
        "returned": len(values),
        "total": metadata["row_count"],
        "next_after": position if position < metadata["row_count"] else None,
        "snapshot": True,
        "sha256_ndjson": metadata["digest"],
    }, payloads


def page(store, who, snapshot_id, after=0, limit=500):
    return _page_payloads(store, who, snapshot_id, after, limit)[0]


def ndjson(store, who, snapshot_id, after=0, limit=1000):
    result, payloads = _page_payloads(store, who, snapshot_id, after, limit)
    # Send the frozen bytes, including native float/string spelling. Re-encoding
    # parsed page objects could change SHA256 and the advertised Content-Length.
    return result, "".join(value + "\n" for value in payloads)


def download_info(store, who, snapshot_id):
    """An exact byte length lets the browser detect an interrupted full export."""
    deadline = time.monotonic() + min(120, max(15, store.settings.query_timeout))
    with _budget_lock(_fts_lock(store), deadline):
        metadata, actor = _authorize(store, who, snapshot_id)
        path = initialize(store) / (snapshot_id + ".sqlite3")
        if not path.is_file():
            raise KeyError("Snapshot data no longer available")
        size = metadata["ndjson_bytes"]
        if size is None:  # Older local derived copies are migrated on demand.
            with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
                db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
                size = db.execute(
                    "SELECT COALESCE(sum(length(CAST(payload AS BLOB))+1),0) FROM rows"
                ).fetchone()[0]
    principal.recheck(store, actor)
    _require_retained_source(store)
    return {"bytes": size, "rows": metadata["row_count"], "sha256": metadata["digest"]}


def close(store, who, snapshot_id):
    with _budget_lock(_fts_lock(store), time.monotonic() + 15):
        _metadata, actor = _authorize(store, who, snapshot_id)
        with store.control(local=True) as db:
            db.execute("DELETE FROM log_snapshots WHERE id=?", (snapshot_id,))
        (initialize(store) / (snapshot_id + ".sqlite3")).unlink(missing_ok=True)
    with principal.transaction(store, actor, write=True) as (db, fresh):
        store.audit(
            db,
            fresh["tenant"],
            fresh["name"],
            "logs.snapshot.close",
            {"id": snapshot_id},
        )
    return {"closed": True}


def maintenance(store, deadline=None):
    root = initialize(store)
    with (
        _budget_lock(store.flush_lock, deadline),
        _budget_lock(_fts_lock(store), deadline),
        store.control(local=True) as db,
    ):
        purges = getattr(store, "purge_generation", 0)
        pending = _pending_retention(store, db)
        ids = [
            r[0]
            for r in db.execute(
                "SELECT id FROM log_snapshots WHERE expires<=? OR purge_generation<>? OR ?",
                (time.time(), purges, pending),
            )
        ]
        db.execute(
            "DELETE FROM log_snapshots WHERE expires<=? OR purge_generation<>? OR ?",
            (time.time(), purges, pending),
        )
        db.execute(
            "UPDATE log_search_generation SET purges=? WHERE singleton=1", (purges,)
        )
        for snapshot_id in ids:
            (root / (snapshot_id + ".sqlite3")).unlink(missing_ok=True)
        # FTS tombstones are applied through the durable local outbox. Deleting
        # its cache here would force an unnecessary full-source bootstrap.
        known = {r[0] for r in db.execute("SELECT id FROM log_snapshots")}
        cutoff = time.time() - 86400
        orphans = 0
        for file in root.iterdir():
            if (
                re.fullmatch(
                    r"[0-9a-f]{32}(?:\.fts)?\.(?:pending|sqlite3)(?:-journal)?",
                    file.name,
                )
                and file.name[:32] not in known
                and file.is_file()
                and file.stat().st_mtime < cutoff
            ):
                file.unlink(missing_ok=True)
                orphans += 1
    return {"expired": len(ids), "orphan_files_removed": orphans}


def status(store, who):
    from .query import index_predicate

    with (
        principal.transaction(store, who) as (_, actor),
        store.control(local=True) as db,
    ):
        rows = [
            dict(r)
            for r in db.execute(
                "SELECT id,created,expires,row_count,bytes,digest FROM log_snapshots WHERE tenant=? AND owner=? ORDER BY created DESC",
                (actor["tenant"], actor["name"]),
            )
        ]
        state = db.execute("SELECT * FROM log_fts_state WHERE singleton=1").fetchone()
        fenced = bool(
            db.execute("SELECT 1 FROM log_fts_inflight LIMIT 1").fetchone()
        ) or _pending_retention(store, db)
        predicate, args = index_predicate(actor["allowed_indexes"])
        pending, weight, oldest = db.execute(
            "SELECT count(*),COALESCE(sum(weight),0),min(created) FROM log_fts_journal WHERE tenant=? AND "
            + predicate,
            (actor["tenant"], *args),
        ).fetchone()
    ready = (
        not state["bootstrap_required"]
        and not fenced
        and not state["pending_documents"]
        and state["generation"] == getattr(store, "content_generation", 0)
        and state["purges"] == getattr(store, "purge_generation", 0)
    )
    cache = store.path / "log-search" / "terms.sqlite3"
    bootstrap = state["bootstrap_required"] or (
        not cache.is_file()
        and (state["indexed_documents"] or state["applied_sequence"])
    )
    # Only availability and configured budget are global; no cross-tenant counts.
    capacity = cache.exists() and cache.stat().st_size > _fts_budget(store)
    error = "capacity_error" if capacity else state["last_error"]
    ready = ready and cache.is_file()
    if cache.is_file() and not bootstrap:
        try:
            with closing(
                sqlite3.connect(cache.as_uri() + "?mode=ro", uri=True, timeout=0.05)
            ) as terms:
                terms.row_factory = sqlite3.Row
                metadata = _cache_metadata(terms)
            if metadata["format_version"] != FTS_FORMAT:
                error, ready = "incompatible_cache", False
            elif metadata["applied_sequence"] < state["applied_sequence"] or (
                metadata["applied_sequence"] == state["applied_sequence"]
                and metadata["documents"] != state["indexed_documents"]
            ):
                error, ready = "incomplete_cache", False
            elif (metadata["generation"], metadata["purges"]) != (
                state["generation"],
                state["purges"],
            ) or metadata["applied_sequence"] != state["applied_sequence"]:
                ready = False
        except ConflictError:
            error, ready = "incompatible_cache", False
        except sqlite3.OperationalError as exc:
            ready = False
            if "locked" not in str(exc).lower():
                error = "incompatible_cache"
        except sqlite3.DatabaseError:
            error, ready = "incompatible_cache", False
    mode = (
        "bootstrap_required"
        if bootstrap
        else "capacity_error"
        if error in {"capacity_error", "disk_quota", "disk_reserve", "journal_capacity"}
        else "error"
        if error
        else "ready"
        if ready
        else "indexing"
    )
    fulltext = {
        "state": mode,
        "ready": ready and not error,
        "pending_documents": pending,
        "pending_bytes": weight,
        "lag_seconds": max(0, time.time() - oldest) if oldest is not None else 0,
        "budget_bytes": _fts_budget(store),
        "error": error,
    }
    return {
        "snapshots": rows,
        "fulltext": fulltext,
        "fulltext_engine": "SQLite FTS5 unicode61",
        "max_snapshot_bytes": MAX_SNAPSHOT_BYTES,
        "max_tenant_bytes": MAX_TENANT_BYTES,
        "default_ttl_seconds": TTL,
        "result_total_cap": None,
    }
