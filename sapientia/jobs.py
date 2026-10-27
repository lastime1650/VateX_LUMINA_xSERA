"""Durable bounded search jobs, cancellation, ownership and result pagination."""

import json
import logging
import threading
import time
import uuid

from .query import Query
from .storage import CapacityError, ConflictError, encode

LOG = logging.getLogger("sapientia.jobs")
TERMINAL = {"done", "failed", "cancelled"}


def initialize(store):
    with store.control(local=True) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS search_jobs(
            id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,
            query TEXT NOT NULL,state TEXT NOT NULL,created REAL NOT NULL,
            started REAL,finished REAL,lease REAL,result TEXT,error TEXT,expires REAL NOT NULL);
        CREATE INDEX IF NOT EXISTS jobs_ready ON search_jobs(state,created);
        CREATE INDEX IF NOT EXISTS jobs_tenant ON search_jobs(tenant,owner,created);
        CREATE TABLE IF NOT EXISTS search_job_access(job_id TEXT PRIMARY KEY,allowed_indexes TEXT NOT NULL);
        CREATE TRIGGER IF NOT EXISTS search_job_access_delete AFTER DELETE ON search_jobs
        BEGIN DELETE FROM search_job_access WHERE job_id=OLD.id; END;
        """)
    from .runtime import initialize as initialize_rules

    initialize_rules(store)


def submit(store, who, query):
    Query.parse(query)
    now = time.time()
    job_id = str(uuid.uuid4())
    with store.write_lock, store.control() as db:
        db.execute("BEGIN IMMEDIATE")
        count = db.execute(
            "SELECT count(*) FROM search_jobs WHERE state NOT IN ('done','failed','cancelled')"
        ).fetchone()[0]
        own = db.execute(
            "SELECT count(*) FROM search_jobs WHERE tenant=? AND state NOT IN ('done','failed','cancelled')",
            (who["tenant"],),
        ).fetchone()[0]
        if count >= 200 or own >= 20:
            raise CapacityError("Search job queue is full for this tenant")
        db.execute(
            "INSERT INTO search_jobs(id,tenant,owner,query,state,created,expires) VALUES(?,?,?,?,?,?,?)",
            (
                job_id,
                who["tenant"],
                who["name"],
                encode(query),
                "queued",
                now,
                now + 86400,
            ),
        )
        store.audit(
            db,
            who["tenant"],
            who["name"],
            "search.submit",
            {"id": job_id, "language": query.get("language", "spl")},
        )
    return job_id


def owned(store, who, job_id):
    with store.control() as db:
        row = db.execute(
            "SELECT * FROM search_jobs WHERE id=? AND tenant=?", (job_id, who["tenant"])
        ).fetchone()
    if not row or (row["owner"] != who["name"] and who["role"] != "admin"):
        raise KeyError("Search job not found")
    if row["expires"] < time.time():
        raise KeyError("Search job expired")
    return dict(row)


def status(store, who, job_id):
    row = owned(store, who, job_id)
    return {
        k: row[k]
        for k in (
            "id",
            "owner",
            "state",
            "created",
            "started",
            "finished",
            "expires",
            "error",
        )
    }


def result(store, who, job_id, offset=0, count=100):
    if (
        type(offset) is not int
        or type(count) is not int
        or not 0 <= offset <= 1000
        or not 1 <= count <= 1000
    ):
        raise ValueError("Result offset 0..1000 and count 1..1000 required")
    row = owned(store, who, job_id)
    if row["state"] != "done":
        raise ConflictError("Search job has not completed successfully")
    from .runtime import owner_indexes

    owner_grants = owner_indexes(store, row["owner"], row["tenant"])
    requester_grants = owner_indexes(store, who["name"], who["tenant"])
    with store.control() as db:
        grants = db.execute(
            "SELECT allowed_indexes FROM search_job_access WHERE job_id=?", (job_id,)
        ).fetchone()
    execution_grants = json.loads(grants[0]) if grants else ["*"]
    if not all(
        current == ["*"]
        or (execution_grants != ["*"] and set(execution_grants) <= set(current))
        for current in (owner_grants, requester_grants)
    ):
        raise PermissionError(
            "Search result permissions changed; submit the search again"
        )
    data = json.loads(row["result"])
    total = len(data["rows"])
    data["rows"] = data["rows"][offset : offset + count]
    data.update(
        offset=offset,
        page_returned=len(data["rows"]),
        total_materialized=total,
        next_offset=offset + count if offset + count < total else None,
    )
    return data


def cancel(store, who, job_id):
    owned(store, who, job_id)
    with store.write_lock, store.control() as db:
        db.execute(
            "UPDATE search_jobs SET state=CASE WHEN state='queued' THEN 'cancelled' ELSE 'cancel_requested' END WHERE id=? AND state IN ('queued','running')",
            (job_id,),
        )
        store.audit(db, who["tenant"], who["name"], "search.cancel", {"id": job_id})
    return status(store, who, job_id)


class JobManager:
    def __init__(self, store):
        self.store = store
        self.stop = threading.Event()
        self.threads = []
        self.last_tenant = None
        self.claim_lock = threading.Lock()

    def start(self):
        self.threads = [
            threading.Thread(
                target=self.loop, name=f"sapientia-search-{i}", daemon=True
            )
            for i in range(self.store.settings.workers)
        ]
        for thread in self.threads:
            thread.start()

    def claim(self):
        now = time.time()
        with self.claim_lock, self.store.write_lock, self.store.control() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT * FROM search_jobs
                WHERE state='queued' OR (state IN ('running','cancel_requested') AND lease<?)
                ORDER BY CASE WHEN tenant=? THEN 1 ELSE 0 END,created LIMIT 1""",
                (now, self.last_tenant or ""),
            ).fetchone()
            if not row:
                return None
            if row["state"] == "cancel_requested":
                db.execute(
                    "UPDATE search_jobs SET state='cancelled',finished=? WHERE id=?",
                    (now, row["id"]),
                )
                return None
            db.execute(
                "UPDATE search_jobs SET state='running',started=?,lease=?,error=NULL WHERE id=?",
                (now, now + 60, row["id"]),
            )
            self.last_tenant = row["tenant"]
            return dict(row)

    def execute(self, job):
        def cancelled():
            if self.stop.is_set():
                return True
            with self.store.control(local=True) as db:
                row = db.execute(
                    "SELECT state FROM search_jobs WHERE id=?", (job["id"],)
                ).fetchone()
            return not row or row[0] == "cancel_requested"

        result_value, error = None, None
        try:
            from .runtime import owner_indexes

            allowed = owner_indexes(self.store, job["owner"], job["tenant"])
            result_value = self.store.search(
                job["tenant"],
                json.loads(job["query"]),
                cancel=cancelled,
                allowed_indexes=allowed,
            )
            if owner_indexes(self.store, job["owner"], job["tenant"]) != allowed:
                raise PermissionError("Search permissions changed during execution")
            state = "done"
        except Exception as exc:
            state = "cancelled" if cancelled() else "failed"
            error = (
                "Search cancelled"
                if state == "cancelled"
                else type(exc).__name__ + ": " + str(exc)[:400]
            )
        with self.store.write_lock, self.store.control() as db:
            prior = db.execute(
                "SELECT state FROM search_jobs WHERE id=?", (job["id"],)
            ).fetchone()
            if prior and prior[0] == "cancel_requested":
                state, result_value, error = "cancelled", None, "Search cancelled"
            if state == "done":
                db.execute(
                    "INSERT OR REPLACE INTO search_job_access(job_id,allowed_indexes) VALUES(?,?)",
                    (job["id"], encode(allowed)),
                )
            db.execute(
                "UPDATE search_jobs SET state=?,finished=?,lease=NULL,result=?,error=? WHERE id=? AND state IN ('running','cancel_requested')",
                (
                    state,
                    time.time(),
                    encode(result_value) if result_value else None,
                    error,
                    job["id"],
                ),
            )
            self.store.audit(
                db,
                job["tenant"],
                job["owner"],
                "search.finish",
                {"id": job["id"], "state": state},
            )

    def loop(self):
        while not self.stop.wait(0.2):
            try:
                job = self.claim()
                if job:
                    self.execute(job)
            except ConflictError:
                pass  # Another application node claimed this state revision.
            except Exception as exc:
                LOG.warning(
                    "Search worker will retry persisted state: %s", type(exc).__name__
                )

    def close(self):
        self.stop.set()
        for thread in self.threads:
            thread.join(25)
            if thread.is_alive():
                raise RuntimeError("Search worker is still running")
