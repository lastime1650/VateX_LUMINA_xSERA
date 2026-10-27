"""Stored dashboards use validated queries; panels cannot inject HTML or scripts."""

import json
import time
import uuid

from .query import Query
from .storage import ConflictError, encode


def initialize(store):
    with store.control(local=True) as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS dashboards(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,name TEXT NOT NULL,panels TEXT NOT NULL,shared INTEGER NOT NULL,version INTEGER NOT NULL,updated REAL NOT NULL)"
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS dashboards_tenant ON dashboards(tenant,owner)"
        )


def validate(data):
    if set(data) - {"name", "panels", "shared", "version"}:
        raise ValueError("Unknown dashboard property")
    name, panels, shared = (
        data.get("name"),
        data.get("panels"),
        data.get("shared", False),
    )
    if (
        not isinstance(name, str)
        or not 1 <= len(name) <= 120
        or type(shared) is not bool
    ):
        raise ValueError("Dashboard name and shared boolean required")
    if not isinstance(panels, list) or not 1 <= len(panels) <= 12:
        raise ValueError("Dashboard requires 1..12 panels")
    for panel in panels:
        if not isinstance(panel, dict) or set(panel) != {"title", "query", "display"}:
            raise ValueError("Panel requires title, query, display")
        if (
            not isinstance(panel["title"], str)
            or not 1 <= len(panel["title"]) <= 120
            or panel["display"] not in {"table", "number", "bar"}
        ):
            raise ValueError("Invalid panel title/display")
        Query.parse(panel["query"])
    if len(encode(data).encode()) > 128 * 1024:
        raise ValueError("Dashboard exceeds 128 KiB")
    return name, panels, shared


def list_for(store, who):
    with store.control() as db:
        rows = db.execute(
            "SELECT * FROM dashboards WHERE tenant=? AND (owner=? OR shared=1 OR ?='admin') ORDER BY name",
            (who["tenant"], who["name"], who["role"]),
        ).fetchall()
    return [{**dict(row), "panels": json.loads(row["panels"])} for row in rows]


def save(store, who, data, dashboard_id=None):
    if who["role"] not in {"admin", "analyst"}:
        raise PermissionError("Dashboard editing requires analyst or administrator")
    name, panels, shared = validate(data)
    with store.write_lock, store.control() as db:
        if dashboard_id:
            row = db.execute(
                "SELECT * FROM dashboards WHERE id=? AND tenant=?",
                (dashboard_id, who["tenant"]),
            ).fetchone()
            if not row or (row["owner"] != who["name"] and who["role"] != "admin"):
                raise KeyError("Dashboard not found")
            if data.get("version") != row["version"]:
                raise ConflictError("Dashboard changed; refresh before saving")
            db.execute(
                "UPDATE dashboards SET name=?,panels=?,shared=?,version=version+1,updated=? WHERE id=?",
                (name, encode(panels), int(shared), time.time(), dashboard_id),
            )
        else:
            count = db.execute(
                "SELECT count(*) FROM dashboards WHERE tenant=?", (who["tenant"],)
            ).fetchone()[0]
            # Durable inventory/history has no lifetime record-count ceiling.
            dashboard_id = str(uuid.uuid4())
            db.execute(
                "INSERT INTO dashboards VALUES(?,?,?,?,?,?,?,?)",
                (
                    dashboard_id,
                    who["tenant"],
                    who["name"],
                    name,
                    encode(panels),
                    int(shared),
                    1,
                    time.time(),
                ),
            )
        store.audit(
            db,
            who["tenant"],
            who["name"],
            "dashboard.save",
            {"id": dashboard_id, "panels": len(panels)},
        )
    return dashboard_id
