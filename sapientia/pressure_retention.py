"""Capacity-triggered FIFO log retention; never delete Case/control history.

Intents use the existing journal, read fence, receipt/projection retirement and
segment writer contract. Progress and physical measurements survive restart.
Only Runtime's dedicated worker performs cleanup; API reads have no side effect.
"""

import heapq
import json
import shutil
import time
import uuid

from . import migrations
from .storage import ConflictError, encode

# Stop visibly if repeated logical deletion fails to recover physical space.
# This is an operational circuit breaker, not a total history quota.
NO_RECLAIM_BATCHES = 32


def initialize(store):
    statements = [
        "CREATE TABLE IF NOT EXISTS capacity_retention_intents(intent_id TEXT PRIMARY KEY,cycle_id TEXT NOT NULL,policy_version INTEGER NOT NULL,protect_case_evidence INTEGER NOT NULL,created REAL NOT NULL)",
        "CREATE TABLE IF NOT EXISTS record_capacity_cleanup_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1),definition TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS record_capacity_cleanup_history(id INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT NOT NULL,cycle_id TEXT NOT NULL,state TEXT NOT NULL,definition TEXT NOT NULL,at REAL NOT NULL)",
        "CREATE TABLE IF NOT EXISTS record_case_evidence_refs(tenant TEXT NOT NULL,event_id TEXT NOT NULL,kind TEXT NOT NULL,record_id TEXT NOT NULL,PRIMARY KEY(tenant,event_id,kind,record_id)) WITHOUT ROWID",
        "CREATE INDEX IF NOT EXISTS record_case_evidence_origin ON record_case_evidence_refs(kind,record_id)",
        "CREATE INDEX IF NOT EXISTS capacity_quarantine_fifo ON ingest_quarantine(received,tenant,event_id)",
    ]
    # Indexed reference rows make protection independent of Case age/status and
    # avoid a full JSON evidence scan for every cleanup batch. They are updated
    # by the same SQLite transaction that records the original Case evidence.
    for table, kind, expression in (
        ("risk_contributions", "contribution", "SELECT NEW.tenant,CAST(j.value AS TEXT),'contribution',NEW.id FROM json_each(NEW.evidence,'$.event_ids') j WHERE j.type='text'"),
        ("case_bookmarks", "bookmark", "SELECT NEW.tenant,NEW.event_id,'bookmark',NEW.id"),
    ):
        statements.extend([
            "CREATE TRIGGER IF NOT EXISTS capacity_"+kind+"_insert AFTER INSERT ON "+table+" BEGIN INSERT OR IGNORE INTO record_case_evidence_refs "+expression+"; END",
            "CREATE TRIGGER IF NOT EXISTS capacity_"+kind+"_update AFTER UPDATE ON "+table+" BEGIN DELETE FROM record_case_evidence_refs WHERE kind='"+kind+"' AND record_id=OLD.id; INSERT OR IGNORE INTO record_case_evidence_refs "+expression+"; END",
            "CREATE TRIGGER IF NOT EXISTS capacity_"+kind+"_delete AFTER DELETE ON "+table+" BEGIN DELETE FROM record_case_evidence_refs WHERE kind='"+kind+"' AND record_id=OLD.id; END",
        ])
    statements.extend([
        "INSERT OR IGNORE INTO record_case_evidence_refs SELECT r.tenant,CAST(j.value AS TEXT),'contribution',r.id FROM risk_contributions r,json_each(r.evidence,'$.event_ids') j WHERE j.type='text'",
        "INSERT OR IGNORE INTO record_case_evidence_refs SELECT tenant,event_id,'bookmark',id FROM case_bookmarks",
    ])
    migrations.apply_store(store, "record_governance", statements, version=2)


def protected_ids(store, db, tenant, ids, now=None, protect_case=True):
    from . import detector_ops

    protected = store.segments.held_ids(db, tenant, ids, now)
    protected.update(detector_ops.protected_ids(db,tenant,ids,now,store))
    from . import intelligence

    protected.update(intelligence.protected_ids(db, tenant, ids, now))
    if protect_case and ids:
        protected.update(row[0] for row in db.execute(
            "SELECT DISTINCT event_id FROM record_case_evidence_refs WHERE tenant=? AND event_id IN (SELECT value FROM json_each(?))",
            (tenant, encode(ids)),
        ))
    return protected


def reserve_bytes(store, disk, policy=None):
    policy = getattr(store, "record_policy", {}) if policy is None else policy
    # Percentage reserve also applies when cleanup is disabled; disabling a
    # worker is not authorization to fill the filesystem with new admissions.
    percentage = policy.get("min_free_percent", 20)
    return max(store.settings.min_free_bytes, (disk.total*percentage+99)//100)


def _persist(store, state, transition=False):
    with store.control(local=True) as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("INSERT INTO record_capacity_cleanup_state VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET definition=excluded.definition", (encode(state),))
        if transition:
            db.execute("INSERT INTO record_capacity_cleanup_history(tenant,cycle_id,state,definition,at) VALUES('default',?,?,?,?)", (state.get("cycle_id",""), state["state"], encode(state), time.time()))
            store.audit(db, "default", "system", "record.capacity.cleanup."+state["state"], state)


def _finish(store, state, status, reason=None):
    state.update(state=status, reason=reason, updated=time.time())
    _persist(store, state, transition=True)
    return state


def _measure(state, disk):
    state.update(free_bytes=disk.free, free_percent=100*disk.free/disk.total if disk.total else 0,
                 volume_bytes=disk.total, net_free_delta_bytes=disk.free-state["start_free_bytes"], updated=time.time())


def _checkpoint(store, state):
    con = store.analytics.cursor()
    try:
        # CHECKPOINT has partial physical reclamation semantics. VACUUM does
        # not compact deleted DuckDB data. Never infer bytes from row count.
        con.execute("CHECKPOINT")
        state["checkpoint_error"] = None
    except Exception as exc:
        state["checkpoint_error"] = type(exc).__name__
    finally:
        con.close()
    with store.control(local=True) as db:
        db.execute("PRAGMA wal_checkpoint(PASSIVE)")


def _candidates(store, state, size):
    after = state.get("after")
    frontier = ""
    args = [state["cutoff"]]
    if after:
        frontier = " AND (received>? OR (received=? AND tenant>?) OR (received=? AND tenant=? AND event_id>?))"
        args.extend([after[0],after[0],after[1],after[0],after[1],after[2]])
    sql = "SELECT received,tenant,event_id FROM {} WHERE received<?"+frontier+" ORDER BY received,tenant,event_id LIMIT ?"
    con = store.analytics.cursor()
    try:
        originals = con.execute(sql.format("events_all"), [*args,size]).fetchall()
    finally:
        con.close()
    with store.control(local=True) as db:
        quarantine = [tuple(r) for r in db.execute(sql.format("ingest_quarantine"), [*args,size])]
    # Each source is bounded by the transfer batch; the merged scan has no
    # lifetime ceiling. Server received time, not device time, orders eviction.
    return list(heapq.merge(originals, quarantine))[:size]


def _plan(store, state, rows, policy):
    groups = {}
    for _,tenant,ident in rows:
        groups.setdefault(tenant, []).append(ident)
    planned = 0
    # This is the replicated logical deletion transaction. Keep the intent and
    # its capacity tag atomic so a restart cannot mistake it for age expiry.
    with store.control() as db:
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT version FROM record_management_policy WHERE singleton=1").fetchone()[0] != state["policy_version"]:
            raise ConflictError("Capacity policy changed before intent commit; retry")
        for tenant, ids in groups.items():
            held = protected_ids(store, db, tenant, ids, protect_case=policy["protect_case_evidence"])
            state["protected_scanned"] += len(held)
            eligible = [ident for ident in ids if ident not in held]
            if not eligible:
                continue
            ident = str(uuid.uuid4())
            db.execute("INSERT INTO retention_intents VALUES(?,?,?,?,?)", (ident,tenant,state["cutoff"],encode(eligible),time.time()))
            db.execute("INSERT INTO capacity_retention_intents VALUES(?,?,?,?,?)", (ident,state["cycle_id"],state["policy_version"],int(policy["protect_case_evidence"]),time.time()))
            store.segments.bump(db,purge=True,content=False)
            store.audit(db,tenant,"system","retention.capacity.plan",{"intent_id":ident,"cycle_id":state["cycle_id"],"events":len(eligible),"receipt_cutoff":state["cutoff"],"minimum_free_percent":policy["min_free_percent"]})
            planned += len(eligible)
    # If a crash precedes saving the cursor, pending intent replay completes
    # first. Re-scanning surviving protected rows is harmless.
    state["after"] = list(rows[-1])
    state["scanned"] += len(rows)
    return planned


def step(store, cancel=None):
    """One cooperative batch. Does not open the Store or start any workers."""
    if cancel is not None and cancel.is_set():
        return {"state":"cancelled"}
    if not store.capacity_worker_lock.acquire(blocking=False):
        return {"state":"busy"}
    try:
        # Match existing flush -> segment writer -> control write lock order.
        # Case mutations, admission, export and segment publication cannot race
        # protection checks or physical deletion inside this lease.
        with store.flush_lock, store.segment_lock.write(), store.write_lock:
            if cancel is not None and cancel.is_set():
                return {"state":"cancelled"}
            disk = shutil.disk_usage(store.path)
            with store.control(local=True) as db:
                row = db.execute("SELECT definition FROM record_capacity_cleanup_state WHERE singleton=1").fetchone()
                state = json.loads(row[0]) if row else {"state":"idle"}
                saved_policy = db.execute("SELECT version,definition FROM record_management_policy WHERE singleton=1").fetchone()
                version = saved_policy["version"]
                from .record_governance import DEFAULT

                policy = {**DEFAULT, **json.loads(saved_policy["definition"])}
                store.record_policy = policy
                pending = db.execute("SELECT count(*) FROM retention_intents i JOIN capacity_retention_intents c ON c.intent_id=i.id LEFT JOIN retention_applied a ON a.id=i.id WHERE a.id IS NULL").fetchone()[0]
            # Logical expiry already committed must recover even if the worker
            # was disabled in a subsequent policy revision.
            if pending:
                removed = store._apply_retention_segments_locked()
                state["recovered_pending_rows"] = state.get("recovered_pending_rows",0)+removed
                state.setdefault("start_free_bytes",disk.free)
                _checkpoint(store,state)
                disk = shutil.disk_usage(store.path)
                _measure(state,disk)
                _persist(store,state)
                return {**state,"state":"recovering"}
            if not policy["capacity_cleanup_enabled"]:
                if state["state"] != "disabled":
                    _finish(store,state,"disabled","capacity cleanup disabled by policy")
                return {**state,"state":"disabled"}
            free = 100*disk.free/disk.total if disk.total else 0
            target = policy["min_free_percent"]+policy["cleanup_hysteresis_percent"]
            absolute_target = max(reserve_bytes(store,disk), (disk.total*target+99)//100)
            active = state["state"] == "reclaiming" and state.get("policy_version") == version
            if not active:
                if free > policy["min_free_percent"] and disk.free > reserve_bytes(store,disk):
                    if state["state"] in {"blocked","disabled","error","reclaiming"}:
                        state.setdefault("start_free_bytes",disk.free)
                        _measure(state,disk)
                        _finish(store,state,"ready")
                    return {**state,"state":"idle"}
                if state.get("block_kind") == "no_physical_reclaim" and state.get("policy_version") == version:
                    # Do not repeat another 32 destructive batches every minute.
                    # A policy revision or a material external free-space gain
                    # is required before this particular breaker can retry.
                    gain = max(1024*1024,disk.total//1000)
                    if disk.free <= state.get("free_bytes",disk.free)+gain:
                        return state
                # Blocked/error cycles retry periodically, including when a
                # hold is released without a policy change. A cursor reset also
                # reconsiders protected rows under the current policy.
                state = {"cycle_id":str(uuid.uuid4()),"state":"reclaiming","policy_version":version,
                         "cutoff":time.time(),"started":time.time(),"after":None,"scanned":0,
                         "protected_scanned":0,"deleted_rows":0,"no_reclaim_batches":0,
                         "start_free_bytes":disk.free,"target_free_percent":target,
                         "target_free_bytes":absolute_target,"minimum_free_percent":policy["min_free_percent"],
                         "order":"server received, tenant, event_id","scope":"indexed originals and ingest quarantine; exclude Case/control history"}
                _measure(state,disk)
                _persist(store,state,transition=True)
            if disk.free >= absolute_target:
                _measure(state,disk)
                return _finish(store,state,"recovered")
            if state.get("no_reclaim_batches",0) >= NO_RECLAIM_BATCHES:
                _measure(state,disk)
                state["block_kind"] = "no_physical_reclaim"
                return _finish(store,state,"blocked","logical deletion did not recover physical bytes; compact/expand storage or remove unrelated files")
            store.segments.ensure_readable()
            rows = _candidates(store,state,policy["cleanup_batch_rows"])
            if not rows:
                _measure(state,disk)
                state["block_kind"] = "no_physical_reclaim" if state.get("deleted_rows",0) and disk.free <= state["start_free_bytes"] else "scan_exhausted"
                return _finish(store,state,"blocked","eligible log scan exhausted; protected data/control history or other files prevent target")
            planned = _plan(store,state,rows,policy)
            removed = store._apply_retention_segments_locked() if planned else 0
            state["deleted_rows"] += removed
            if planned:
                _checkpoint(store,state)
            after_disk = shutil.disk_usage(store.path)
            if removed:
                state["no_reclaim_batches"] = 0 if after_disk.free > disk.free else state.get("no_reclaim_batches",0)+1
            _measure(state,after_disk)
            _persist(store,state)
            if after_disk.free >= absolute_target:
                return _finish(store,state,"recovered")
            return state
    finally:
        store.capacity_worker_lock.release()


def record_error(store, exc):
    """Keep a visible memory error even when a full disk prevents persistence."""
    store.capacity_worker_error = type(exc).__name__
    with store.write_lock:
        with store.control(local=True) as db:
            row = db.execute("SELECT definition FROM record_capacity_cleanup_state WHERE singleton=1").fetchone()
        state = json.loads(row[0]) if row else {"state":"idle"}
        state["error_class"] = type(exc).__name__
        return _finish(store,state,"error",type(exc).__name__)
