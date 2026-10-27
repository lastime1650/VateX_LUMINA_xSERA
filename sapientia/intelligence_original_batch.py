"""Contiguous original turns: one bounded write commit and raw fetch per owner.

The reserved transaction serializes current authority with durable signals,
exclusions, ML jobs and the input cursor. Owner savepoints retain the existing
partial-owner semantics; a crash before the commit replays the whole turn.
"""

import json
import sqlite3
import time

from . import evidence_scope, principal
from .storage import CapacityError, ConflictError


def run(store, core, cancel=None, maximum=16, deadline=None, legacy=None):
    if (
        cancel is not None
        and cancel.is_set()
        or deadline
        and time.monotonic() >= deadline
    ):
        return 0
    maximum = max(1, min(32, maximum))
    with store.control() as db:
        cursor = db.execute(
            "SELECT cursor FROM intelligence_cursors WHERE worker='events'"
        ).fetchone()[0]
        rows = [
            dict(r)
            for r in db.execute(
                "SELECT * FROM intelligence_event_outbox WHERE seq>? ORDER BY seq LIMIT ?",
                (cursor, maximum),
            )
        ]
        declared = {
            tenant: [
                dict(r)
                for r in db.execute(
                    "SELECT * FROM intelligence_policies WHERE tenant=? AND state='active' ORDER BY id",
                    (tenant,),
                )
            ]
            for tenant in {r["tenant"] for r in rows}
        }
    if not rows:
        return 0
    owners = {
        (r["tenant"], p["owner"])
        for r in rows
        for p in declared[r["tenant"]]
        if r["index_name"] in json.loads(p["indexes"])
    }
    # Multi-owner/tenant turns keep the established independent transaction
    # behavior. The common single-owner path batches all contiguous originals.
    if len(owners) != 1 or len({r["tenant"] for r in rows}) != 1:
        return legacy()
    tenant, owner = next(iter(owners))
    try:
        return _single(
            store,
            core,
            rows,
            declared,
            cursor,
            {"name": owner, "tenant": tenant, "role": "analyst"},
            cancel,
            deadline,
        )
    except (PermissionError, KeyError, ConflictError, ValueError):
        return legacy()


def _single(store, core, rows, declared, cursor, who, cancel, deadline):
    limit = time.monotonic() + 2.5
    completed = 0
    with (
        store.segment_lock.read(deadline=limit),
        principal.transaction(store, who, ("admin", "analyst"), write=True) as (db, _),
    ):
        db.execute("PRAGMA busy_timeout=1000")
        db.set_progress_handler(lambda: int(time.monotonic() >= limit), 1000)
        try:
            fresh_cursor = db.execute(
                "SELECT cursor FROM intelligence_cursors WHERE worker='events'"
            ).fetchone()[0]
            if fresh_cursor != cursor:
                return 0
            if (
                cancel is not None
                and cancel.is_set()
                or deadline
                and time.monotonic() >= deadline
            ):
                return 0
            prefetch = []
            for tenant in {r["tenant"] for r in rows}:
                for owner in {r["owner"] for r in declared[tenant]}:
                    try:
                        actor = principal.current(
                            db,
                            {"name": owner, "tenant": tenant, "role": "analyst"},
                            ("admin", "analyst"),
                        )
                        scoped = {
                            index
                            for p in declared[tenant]
                            if p["owner"] == owner
                            for index in json.loads(p["indexes"])
                        }
                        identifiers = [
                            r["event_id"]
                            for r in rows
                            if r["tenant"] == tenant
                            and r["index_name"] in scoped
                            and principal.contains(
                                actor["allowed_indexes"], [r["index_name"]]
                            )
                        ]
                        prefetch.append((actor, identifiers))
                    except (PermissionError, KeyError, ConflictError, ValueError):
                        continue
            with evidence_scope.prefetch_transaction(store, db, prefetch):
                for item in rows:
                    if (
                        cancel is not None
                        and cancel.is_set()
                        or deadline
                        and time.monotonic() >= deadline
                        or time.monotonic() >= limit - 0.1
                    ):
                        break
                    core._phase(
                        db,
                        item["tenant"],
                        [item["event_id"]],
                        analysis_started_at=time.time(),
                    )
                    owners = {}
                    for policy in declared[item["tenant"]]:
                        if item["index_name"] in json.loads(policy["indexes"]):
                            owners.setdefault(policy["owner"], []).append(policy)
                    processed, job_owner = False, None
                    for owner, owned in owners.items():
                        db.execute("SAVEPOINT original_owner")
                        try:
                            actor = principal.current(
                                db,
                                {
                                    "name": owner,
                                    "tenant": item["tenant"],
                                    "role": "analyst",
                                },
                                ("admin", "analyst"),
                            )
                            authorized = []
                            for policy in owned:
                                fresh = db.execute(
                                    "SELECT * FROM intelligence_policies WHERE tenant=? AND id=?",
                                    (item["tenant"], policy["id"]),
                                ).fetchone()
                                try:
                                    if fresh is not None and fresh["owner"] != owner:
                                        raise PermissionError(
                                            "Policy owner changed during the declared turn"
                                        )
                                    checked, definition = core._authority(
                                        db,
                                        fresh,
                                        include_parents=fresh is not None
                                        and fresh["kind"] == "atomic",
                                    )
                                    if checked != actor:
                                        raise PermissionError(
                                            "Policy principal changed during original processing"
                                        )
                                    if item["index_name"] in definition["indexes"]:
                                        authorized.append((fresh, definition))
                                except (
                                    PermissionError,
                                    KeyError,
                                    ConflictError,
                                    ValueError,
                                ) as exc:
                                    core._decision(
                                        db,
                                        policy,
                                        None,
                                        None,
                                        "original_excluded",
                                        {
                                            "event_id": item["event_id"],
                                            "reason": type(exc).__name__,
                                        },
                                    )
                            if authorized:
                                record = evidence_scope.originals(
                                    store, actor, [item["event_id"]]
                                )[item["event_id"]]
                                projection = core._projection(
                                    db, actor["tenant"], record
                                )
                                core.publish_in_transaction(
                                    store,
                                    db,
                                    actor,
                                    {
                                        "event_ids": [item["event_id"]],
                                        "kind": "observation",
                                        "rule_id": "indexed-observation",
                                        "rule_revision": 1,
                                        "features": {},
                                        "severity": "info",
                                        "confidence_grade": "authenticated_source_assertion"
                                        if projection
                                        else "admitted_original",
                                        "window": max(
                                            definition["window"]
                                            for _, definition in authorized
                                        ),
                                    },
                                )
                                for fresh, definition in authorized:
                                    if fresh["kind"] != "atomic":
                                        continue
                                    try:
                                        matched = core._atomic_matches(
                                            {
                                                "event": record,
                                                "raw": record["raw"],
                                                "projection": projection or {},
                                            },
                                            definition,
                                        )
                                    except ValueError as exc:
                                        core._decision(
                                            db,
                                            fresh,
                                            actor,
                                            None,
                                            "predicate_excluded",
                                            {
                                                "event_id": item["event_id"],
                                                "reason": str(exc)[:500],
                                            },
                                        )
                                        continue
                                    if matched:
                                        signal = core.publish_in_transaction(
                                            store,
                                            db,
                                            actor,
                                            {
                                                "event_ids": [item["event_id"]],
                                                "kind": "atomic",
                                                "rule_id": fresh["id"],
                                                "rule_revision": fresh["version"],
                                                "features": {},
                                                "severity": definition["severity"],
                                                "confidence_grade": definition[
                                                    "confidence_grade"
                                                ],
                                                "window": definition["window"],
                                                "definition_digest": core.release_manifest.digest(
                                                    definition
                                                ),
                                            },
                                        )
                                        outcome = core._case(
                                            store, db, actor, fresh, definition, signal
                                        )
                                        if not signal["duplicate"]:
                                            core._decision(
                                                db,
                                                fresh,
                                                actor,
                                                signal["id"],
                                                "matched",
                                                {"case_emission": outcome},
                                            )
                                processed, job_owner = True, actor["name"]
                            db.execute("RELEASE original_owner")
                        except (
                            PermissionError,
                            KeyError,
                            ConflictError,
                            ValueError,
                        ) as exc:
                            db.execute("ROLLBACK TO original_owner")
                            db.execute("RELEASE original_owner")
                            for policy in owned:
                                core._decision(
                                    db,
                                    policy,
                                    None,
                                    None,
                                    "original_excluded",
                                    {
                                        "event_id": item["event_id"],
                                        "reason": type(exc).__name__,
                                    },
                                )
                    if processed:
                        db.execute(
                            "INSERT OR IGNORE INTO intelligence_ml_jobs VALUES(?,?,?,?,?,'pending',0,NULL,0,?,NULL)",
                            (
                                item["id"],
                                item["tenant"],
                                item["event_id"],
                                job_owner,
                                item["index_name"],
                                time.time(),
                            ),
                        )
                        core._phase(
                            db,
                            item["tenant"],
                            [item["event_id"]],
                            ml_queued_at=time.time(),
                        )
                    db.execute(
                        "UPDATE intelligence_cursors SET cursor=? WHERE worker='events'",
                        (item["seq"],),
                    )
                    core._phase(
                        db,
                        item["tenant"],
                        [item["event_id"]],
                        analysis_completed_at=time.time(),
                        outcome="processed" if processed else "excluded",
                    )
                    completed += 1
        except sqlite3.OperationalError as exc:
            if "interrupted" in str(exc).lower():
                raise CapacityError(
                    "Original batch exceeded its bounded transaction budget"
                ) from None
            raise
        finally:
            db.set_progress_handler(None, 0)
    return completed
