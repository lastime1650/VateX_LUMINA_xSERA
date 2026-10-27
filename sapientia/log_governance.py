"""Explicit original-event holds for a versioned case evidence snapshot.

These local retention guards are not WORM. New case evidence is not silently
covered: status reports unheld originals and an administrator must refresh the
snapshot. SQLite receipts and the hot/Parquet originals must both still exist.
"""

import json
import time

from . import principal
from .storage import ConflictError

ROLES = ("admin", "analyst", "viewer")


def _request(data):
    if not isinstance(data, dict) or set(data) != {"version", "reason"}:
        raise ValueError("Case hold requires version and reason only")
    if type(data["version"]) is not int or data["version"] < 1:
        raise ValueError("A positive current case version is required")
    reason = data["reason"]
    if (
        not isinstance(reason, str)
        or not reason.strip()
        or len(reason) > 1000
        or "\x00" in reason
    ):
        raise ValueError("Hold reason requires 1..1000 characters")
    try:
        reason.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("Hold reason contains invalid Unicode") from None
    return data["version"], reason.strip()


def _case(db, actor, case_id):
    if not isinstance(case_id, str) or not 1 <= len(case_id) <= 128:
        raise ValueError("A case identifier is required")
    incident = principal.incident(db, actor, case_id)
    # A case's historical held scope remains private even if a later upgrade or
    # local data repair removed the contribution that originally referenced it.
    indexes = [
        row[0]
        for row in db.execute(
            "SELECT DISTINCT index_name FROM log_evidence_holds WHERE tenant=? AND case_id=?",
            (actor["tenant"], case_id),
        )
    ]
    if not principal.contains(actor["allowed_indexes"], indexes):
        raise KeyError("Incident not found")
    return incident


def _evidence_ids(db, tenant, case_id):
    # DISTINCT spans all contributions and bookmarks. There is no lifetime
    # evidence ceiling and no partially successful hold.
    rows = db.execute(
        "SELECT event_id FROM (SELECT j.value AS event_id FROM risk_contributions r JOIN json_each(r.evidence,'$.event_ids') j WHERE r.tenant=? AND r.incident_id=? UNION SELECT event_id FROM case_bookmarks WHERE tenant=? AND incident_id=?) ORDER BY event_id",
        (tenant, case_id, tenant, case_id),
    ).fetchall()
    ids = [row[0] for row in rows]
    if any(not isinstance(item, str) or not 1 <= len(item) <= 256 for item in ids):
        raise ConflictError(
            "Case evidence contains an invalid original event identifier"
        )
    return ids


def _originals(store, db, actor, ids):
    if not ids:
        return {}, set()
    rows = []
    for start in range(0, len(ids), 1000):
        batch = ids[start:start+1000]
        rows.extend(store.analytics_query(
            "SELECT event_id,index_name FROM events_all WHERE tenant=? AND event_id IN (SELECT json_extract_string(value,'$') FROM json_each(?)) ORDER BY event_id",
            [actor["tenant"], json.dumps(batch)], max_rows=len(batch), timeout=2)["rows"])
    found = {row["event_id"]: row["index_name"] for row in rows}
    if not principal.contains(actor["allowed_indexes"], sorted(set(found.values()))):
        raise KeyError("Incident not found")
    receipts = {
        row[0]
        for row in db.execute(
            "SELECT event_id FROM receipts WHERE tenant=? AND event_id IN (SELECT value FROM json_each(?))",
            (actor["tenant"], json.dumps(ids)),
        )
    }
    return found, receipts


def _status(db, actor, incident, ids, originals, receipts):
    rows = db.execute(
        "SELECT event_id,index_name,created,expires FROM log_evidence_holds WHERE tenant=? AND case_id=? AND (expires IS NULL OR expires>?) ORDER BY event_id",
        (actor["tenant"], incident["id"], time.time()),
    ).fetchall()
    held = {row["event_id"] for row in rows}
    missing = set(ids) - (set(originals) & receipts)
    by_index = {}
    for row in rows:
        by_index[row["index_name"]] = by_index.get(row["index_name"], 0) + 1
    current_held = len(set(ids) & held)
    return {
        "case_id": incident["id"],
        "version": incident["version"],
        "evidence_count": len(ids),
        "originals_available": len(ids) - len(missing),
        "originals_present": len(set(ids) & set(originals)),
        "missing_originals": len(set(ids) - set(originals)),
        "missing_receipts": len(set(ids) - receipts),
        "unavailable_originals": len(missing),
        "missing_event_ids": sorted(missing),
        "missing_event_ids_truncated": False,
        "held_count": len(held),
        "held_current_evidence": current_held,
        "unheld_current_evidence": len(ids) - current_held,
        "indexes": [
            {"index": name, "held": count} for name, count in sorted(by_index.items())
        ],
        "active": bool(held),
        "complete": bool(ids) and current_held == len(ids) and not missing,
        "limit": None,
        "scope": "explicit_current_case_evidence_snapshot",
        "protects_future_evidence": False,
        "immutable": False,
    }


def get_case_hold(store, who, case_id):
    deadline = time.monotonic() + 5
    with (
        store.segment_lock.read(deadline=deadline),
        principal.transaction(store, who, ROLES) as (db, actor),
    ):
        incident = _case(db, actor, case_id)
        ids = _evidence_ids(db, actor["tenant"], case_id)
        originals, receipts = _originals(store, db, actor, ids)
        return _status(db, actor, incident, ids, originals, receipts)


def hold_case(store, who, case_id, data):
    version, reason = _request(data)
    deadline = time.monotonic() + 5
    # Same order as retention: segment read prevents delete/publication, then
    # write lock and BEGIN IMMEDIATE make receipts, case version and scope stable.
    with (
        store.segment_lock.read(deadline=deadline),
        principal.transaction(store, who, ("admin",), write=True) as (db, actor),
    ):
        incident = _case(db, actor, case_id)
        if incident["version"] != version:
            raise ConflictError(
                "Case changed; review its current evidence before holding"
            )
        ids = _evidence_ids(db, actor["tenant"], case_id)
        if not ids:
            raise ConflictError("Case has no referenced original events")
        originals, receipts = _originals(store, db, actor, ids)
        if set(ids) != set(originals) or set(ids) != receipts:
            raise ConflictError(
                "Some original events or admission receipts are unavailable; no partial hold was applied"
            )
        old = {
            row[0]
            for row in db.execute(
                "SELECT event_id FROM log_evidence_holds WHERE tenant=? AND case_id=? AND (expires IS NULL OR expires>?)",
                (actor["tenant"], case_id, time.time()),
            )
        }
        bookmarks = db.execute(
            "SELECT event_id,index_name FROM case_bookmarks WHERE tenant=? AND incident_id=?",
            (actor["tenant"], case_id),
        )
        if any(originals[row["event_id"]] != row["index_name"] for row in bookmarks):
            raise ConflictError(
                "Bookmarked event index differs from the original event"
            )
        now = time.time()
        db.executemany(
            "INSERT INTO log_evidence_holds(tenant,index_name,event_id,case_id,created,expires,reason) VALUES(?,?,?,?,?,NULL,?) ON CONFLICT(tenant,event_id,case_id) DO UPDATE SET index_name=excluded.index_name,expires=NULL,reason=excluded.reason",
            [
                (actor["tenant"], originals[event_id], event_id, case_id, now, reason)
                for event_id in ids
            ],
        )
        db.execute(
            "UPDATE incidents SET version=version+1,updated=? WHERE id=? AND tenant=? AND version=?",
            (now, case_id, actor["tenant"], version),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "logs.case.hold",
            {
                "case_id": case_id,
                "case_version": version,
                "new_version": version + 1,
                "events": len(ids),
                "indexes": sorted(set(originals.values())),
                "reason": reason,
                "snapshot": True,
            },
        )
        return _status(
            db,
            actor,
            {**dict(incident), "version": version + 1},
            ids,
            originals,
            receipts,
        )


def release_case_hold(store, who, case_id, data):
    version, reason = _request(data)
    deadline = time.monotonic() + 5
    with (
        store.segment_lock.read(deadline=deadline),
        principal.transaction(store, who, ("admin",), write=True) as (db, actor),
    ):
        incident = _case(db, actor, case_id)
        if incident["version"] != version:
            raise ConflictError(
                "Case changed; review its current hold before releasing"
            )
        now = time.time()
        changed = db.execute(
            "UPDATE log_evidence_holds SET expires=? WHERE tenant=? AND case_id=? AND (expires IS NULL OR expires>?)",
            (now, actor["tenant"], case_id, now),
        ).rowcount
        db.execute(
            "UPDATE incidents SET version=version+1,updated=? WHERE id=? AND tenant=? AND version=?",
            (now, case_id, actor["tenant"], version),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "logs.case.hold.release",
            {
                "case_id": case_id,
                "case_version": version,
                "new_version": version + 1,
                "events": changed,
                "reason": reason,
            },
        )
        return {
            "case_id": case_id,
            "version": version + 1,
            "released": changed,
            "active": False,
            "note": "Other case, tenant or index holds may still protect these originals",
        }
