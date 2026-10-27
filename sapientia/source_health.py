"""Persisted, index-scoped source silence, field presence and arrival-lag monitors."""

import hashlib
import json
import math
import time
import uuid

from . import access, principal
from .query import column, index_predicate
from .storage import CapacityError, ConflictError, encode


def initialize(store):
    with store.control(local=True) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS source_monitors(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,name TEXT NOT NULL,
          definition TEXT NOT NULL,version INTEGER NOT NULL,enabled INTEGER NOT NULL,
          next_run REAL NOT NULL,last_run REAL,result TEXT);
        CREATE INDEX IF NOT EXISTS source_monitors_due ON source_monitors(enabled,next_run);
        CREATE TABLE IF NOT EXISTS source_monitor_runs(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,monitor_id TEXT NOT NULL,at REAL NOT NULL,
          result TEXT NOT NULL,digest TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS source_runs_recent ON source_monitor_runs(tenant,monitor_id,at DESC,id DESC);
        """)


def validate(data):
    if not isinstance(data, dict) or set(data) - {
        "name",
        "source",
        "indexes",
        "max_silence",
        "max_lag",
        "required_fields",
        "window",
        "interval",
        "enabled",
    }:
        raise ValueError("Unknown source monitor property")
    result = {
        "name": data.get("name"),
        "source": data.get("source"),
        "indexes": access.validate(data.get("indexes", [])),
        "required_fields": data.get("required_fields", []),
        "enabled": data.get("enabled", True),
    }
    for key in ("name", "source"):
        if not isinstance(result[key], str) or not 1 <= len(result[key]) <= (
            120 if key == "name" else 256
        ):
            raise ValueError("Monitor requires a name and an exact source")
    if (
        not result["indexes"]
        or result["indexes"] == ["*"]
        or len(result["indexes"]) > 16
        or type(result["enabled"]) is not bool
    ):
        raise ValueError("Monitor requires 1..16 concrete indexes and boolean enabled")
    for key, default, low, high in [
        ("max_silence", 300, 30, 604800),
        ("max_lag", 300, 1, 604800),
        ("window", 3600, 60, 604800),
        ("interval", 60, 30, 86400),
    ]:
        value = data.get(key, default)
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f"{key} must be in {low}..{high}")
        result[key] = value
    fields = result["required_fields"]
    if (
        not isinstance(fields, list)
        or len(fields) > 16
        or any(not isinstance(f, str) for f in fields)
        or len(set(fields)) != len(fields)
    ):
        raise ValueError("At most 16 unique required field names are supported")
    for field in fields:
        if field == "raw":
            raise ValueError("Choose scalar required fields")
        column(field)
    return result


def save(store, who, data, monitor_id=None):
    if (
        not isinstance(data, dict)
        or set(data) != {"version", "definition"}
        or type(data["version"]) is not int
        or data["version"] < 0
    ):
        raise ValueError("Expected definition and nonnegative version")
    definition = validate(data["definition"])
    with principal.transaction(store, who, ("admin", "analyst"), write=True) as (
        db,
        actor,
    ):
        if not principal.contains(actor["allowed_indexes"], definition["indexes"]):
            raise PermissionError("Monitor indexes exceed current permissions")
        old = (
            db.execute(
                "SELECT * FROM source_monitors WHERE id=? AND tenant=?",
                (monitor_id, actor["tenant"]),
            ).fetchone()
            if monitor_id
            else None
        )
        if monitor_id and not old:
            raise KeyError("Monitor not found")
        if old and (old["owner"] != actor["name"] and actor["role"] != "admin"):
            raise PermissionError(
                "Only the owner or tenant administrator may edit this monitor"
            )
        if old and not principal.contains(
            actor["allowed_indexes"], json.loads(old["definition"])["indexes"]
        ):
            raise KeyError("Monitor not found")
        if (old["version"] if old else 0) != data["version"]:
            raise ConflictError("Monitor version changed")
        # Durable inventory/history has no lifetime record-count ceiling.
        monitor_id, version = monitor_id or str(uuid.uuid4()), data["version"] + 1
        db.execute(
            "INSERT INTO source_monitors VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET owner=excluded.owner,name=excluded.name,definition=excluded.definition,version=excluded.version,enabled=excluded.enabled,next_run=excluded.next_run,last_run=NULL,result=NULL",
            (
                monitor_id,
                actor["tenant"],
                actor["name"],
                definition["name"],
                encode(definition),
                version,
                int(definition["enabled"]),
                time.time(),
                None,
                None,
            ),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "source_monitor.save",
            {"id": monitor_id, "version": version, "indexes": definition["indexes"]},
        )
        return {"id": monitor_id, "version": version, "definition": definition}


def list_for(store, who):
    with principal.transaction(store, who, ("admin", "analyst")) as (db, actor):
        result = []
        for row in db.execute(
            "SELECT * FROM source_monitors WHERE tenant=? ORDER BY name,id",
            (actor["tenant"],),
        ):
            definition = json.loads(row["definition"])
            if principal.contains(actor["allowed_indexes"], definition["indexes"]):
                result.append(
                    {
                        **dict(row),
                        "definition": definition,
                        "result": json.loads(row["result"]) if row["result"] else None,
                    }
                )
        return result


def _measure(store, actor, definition, now, cancel=None):
    predicate, grants = index_predicate(definition["indexes"])
    fields = []
    for position, field in enumerate(definition["required_fields"]):
        fields.append(
            f"sum(CASE WHEN received>=? AND ({column(field)} IS NULL OR CAST({column(field)} AS VARCHAR)='') THEN 1 ELSE 0 END) AS missing_{position}"
        )
    extras = ("," + ",".join(fields)) if fields else ""
    start = now - definition["window"]
    sql = (
        "SELECT max(received) AS last_seen,count(*) FILTER(WHERE received>=?) AS recent_events,max(greatest(received-event_time,0)) FILTER(WHERE received>=?) AS max_lag,quantile_cont(greatest(received-event_time,0),0.95) FILTER(WHERE received>=?) AS lag_p95,count(*) FILTER(WHERE received>=? AND event_time>received) AS future_events"
        + extras
        + " FROM events_all WHERE tenant=? AND source=? AND received<=? AND "
        + predicate
    )
    args = [
        start,
        start,
        start,
        start,
        *([start] * len(fields)),
        actor["tenant"],
        definition["source"],
        now,
        *grants,
    ]
    row = store.analytics_query(sql, args, cancel=cancel, timeout=2, max_rows=1)[
        "rows"
    ][0]
    principal.recheck(store, actor, ("admin", "analyst"))
    issues = []
    if row["last_seen"] is None or now - row["last_seen"] > definition["max_silence"]:
        issues.append("silent")
    if row["max_lag"] is not None and row["max_lag"] > definition["max_lag"]:
        issues.append("lagging")
    missing = {
        field: int(row[f"missing_{i}"] or 0)
        for i, field in enumerate(definition["required_fields"])
    }
    if any(missing.values()):
        issues.append("incomplete")
    if row["future_events"]:
        issues.append("future_timestamps")
    return {
        "status": "degraded" if issues else "healthy",
        "issues": issues,
        "last_seen": row["last_seen"],
        "silence_seconds": now - row["last_seen"]
        if row["last_seen"] is not None
        else None,
        "recent_events": row["recent_events"],
        "max_arrival_lag_seconds": row["max_lag"],
        "arrival_lag_p95_seconds": row["lag_p95"],
        "future_timestamp_events": row["future_events"],
        "missing_fields": missing,
        "window_start": start,
        "window_end": now,
        "indexes": definition["indexes"],
        "population": "all authorized events received within the window",
        "operational_monitor": True,
    }


def evaluate(store, who, monitor_id, now=None, cancel=None):
    now = time.time() if now is None else now
    if (
        isinstance(now, bool)
        or not isinstance(now, (int, float))
        or not math.isfinite(now)
        or now < 0
    ):
        raise ValueError("Invalid evaluation time")
    with principal.transaction(store, who, ("admin", "analyst")) as (db, actor):
        row = db.execute(
            "SELECT * FROM source_monitors WHERE id=? AND tenant=?",
            (monitor_id, actor["tenant"]),
        ).fetchone()
        if not row:
            raise KeyError("Monitor not found")
        definition = json.loads(row["definition"])
        if not principal.contains(actor["allowed_indexes"], definition["indexes"]):
            raise KeyError("Monitor not found")
        owner = principal.current(
            db,
            {"name": row["owner"], "tenant": row["tenant"], "role": "analyst"},
            ("admin", "analyst"),
        )
        if not principal.contains(owner["allowed_indexes"], definition["indexes"]):
            raise PermissionError(
                "Monitor owner no longer has its declared index scope"
            )
    result = _measure(store, actor, definition, now, cancel=cancel)
    with principal.transaction(store, actor, ("admin", "analyst"), write=True) as (
        db,
        fresh,
    ):
        latest = db.execute(
            "SELECT version FROM source_monitors WHERE id=? AND tenant=?",
            (monitor_id, fresh["tenant"]),
        ).fetchone()
        if (
            not latest
            or latest[0] != row["version"]
            or not principal.contains(fresh["allowed_indexes"], definition["indexes"])
        ):
            raise ConflictError("Monitor configuration or permissions changed")
        current_owner = principal.current(db, owner, ("admin", "analyst"))
        if not principal.contains(
            current_owner["allowed_indexes"], definition["indexes"]
        ):
            raise PermissionError("Monitor owner permissions changed")
        encoded = encode(result)
        db.execute(
            "UPDATE source_monitors SET last_run=?,next_run=?,result=? WHERE id=?",
            (now, now + definition["interval"], encoded, monitor_id),
        )
        db.execute(
            "INSERT INTO source_monitor_runs VALUES(?,?,?,?,?,?)",
            (
                str(uuid.uuid4()),
                fresh["tenant"],
                monitor_id,
                now,
                encoded,
                hashlib.sha256(encoded.encode()).hexdigest(),
            ),
        )
        # Every source-health evaluation remains in permanent history.
        store.audit(
            db,
            fresh["tenant"],
            fresh["name"],
            "source_monitor.evaluate",
            {"id": monitor_id, "status": result["status"], "issues": result["issues"]},
        )
    return result


def run_due(store, now=None, cancel=None, budget=0.25, max_runs=2):
    now, started, count = time.time() if now is None else now, time.monotonic(), 0
    with store.control() as db:
        rows = [
            dict(r)
            for r in db.execute(
                "SELECT * FROM source_monitors WHERE enabled=1 AND next_run<=? ORDER BY next_run,tenant,id LIMIT ?",
                (now, max_runs),
            )
        ]
    for row in rows:
        if time.monotonic() - started >= budget or (cancel and cancel.is_set()):
            break
        try:
            evaluate(
                store,
                {"name": row["owner"], "tenant": row["tenant"], "role": "analyst"},
                row["id"],
                now,
                cancel=cancel,
            )
        except Exception as exc:  # noqa: BLE001 - Persist operational failure type without hidden data; retry later.
            # Do not persist exception text, SQL parameters or hidden event data.
            error = {
                "status": "error",
                "error": type(exc).__name__,
                "operational_monitor": True,
            }
            with store.write_lock, store.control() as db:
                db.execute(
                    "UPDATE source_monitors SET next_run=?,last_run=?,result=? WHERE id=? AND version=?",
                    (now + 60, now, encode(error), row["id"], row["version"]),
                )
        count += 1
    return count
