"""Incident tasks, collaboration and complete bounded evidence exports.

All state is tenant-bound and protected by the incident's complete index scope.
Local response actions share the same transaction as their idempotency receipt.
"""

import hashlib
import json
import math
import re
import time
import uuid

from . import access, principal
from .storage import CapacityError, ConflictError, encode

EDITORS = ("admin", "analyst")
SOAR_ACTION_KEY = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}:[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z"
)


def initialize(store):
    with store.control(local=True) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS case_workspaces(
          tenant TEXT NOT NULL,incident_id TEXT PRIMARY KEY,priority TEXT NOT NULL,
          due_at REAL,tags TEXT NOT NULL,version INTEGER NOT NULL,updated REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS case_tasks(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,incident_id TEXT NOT NULL,
          title TEXT NOT NULL,description TEXT NOT NULL,status TEXT NOT NULL,
          assignee TEXT NOT NULL,mandatory INTEGER NOT NULL,due_at REAL,
          created REAL NOT NULL,updated REAL NOT NULL,version INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS case_tasks_incident ON case_tasks(tenant,incident_id,created,id);
        CREATE TABLE IF NOT EXISTS case_notes(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,incident_id TEXT NOT NULL,
          actor TEXT NOT NULL,at REAL NOT NULL,note TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS case_notes_incident ON case_notes(tenant,incident_id,at,id);
        CREATE TABLE IF NOT EXISTS case_bookmarks(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,incident_id TEXT NOT NULL,
          event_id TEXT NOT NULL,index_name TEXT NOT NULL,label TEXT NOT NULL,
          actor TEXT NOT NULL,at REAL NOT NULL,event TEXT NOT NULL,
          UNIQUE(tenant,incident_id,event_id));
        CREATE TABLE IF NOT EXISTS case_action_receipts(
          tenant TEXT NOT NULL,action_key TEXT NOT NULL,incident_id TEXT NOT NULL,
          digest TEXT NOT NULL,result TEXT NOT NULL,at REAL NOT NULL,
          PRIMARY KEY(tenant,action_key));
        """)


def _text(value, name, maximum, *, empty=False):
    if (
        not isinstance(value, str)
        or (not empty and not value.strip())
        or len(value) > maximum
    ):
        raise ValueError(
            f"{name} requires {'0' if empty else '1'}..{maximum} characters"
        )
    return value


def _version(value):
    if type(value) is not int or value < 0:
        raise ValueError("A nonnegative integer version is required")
    return value


def _due(value):
    if value is not None and (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not 0 <= value <= time.time() + 366 * 86400
    ):
        raise ValueError("due_at must be null or epoch seconds within the next year")
    return value


def _assignee(db, actor, incident_id, name):
    name = _text(name, "assignee", 64, empty=True)
    if not name:
        return ""
    row = db.execute(
        "SELECT name,tenant,role,disabled,must_change FROM users WHERE name=? AND tenant=?",
        (name, actor["tenant"]),
    ).fetchone()
    if not row or row["disabled"] or row["must_change"] or row["role"] not in EDITORS:
        raise ValueError("Assignee must be an active analyst in the same tenant")
    principal.incident(
        db,
        {**dict(row), "allowed_indexes": access._get(db, name, actor["tenant"])},
        incident_id,
    )
    return name


def require_resolution(db, actor, incident_id):
    from . import contribution_verdicts

    contribution_verdicts.require_resolution(db, actor, incident_id)
    if db.execute(
        "SELECT 1 FROM case_tasks WHERE tenant=? AND incident_id=? AND mandatory=1 AND status!='done' LIMIT 1",
        (actor["tenant"], incident_id),
    ).fetchone():
        raise ConflictError("Complete all required incident tasks before resolving")


def apply_action(db, store, actor, incident_id, action, action_key):
    """Execute one idempotent local action in the caller's write transaction."""
    actor = principal.current(db, actor, EDITORS)
    incident = principal.incident(db, actor, incident_id)
    _text(action_key, "action_key", 128)
    if not isinstance(action, dict):
        raise ValueError("A typed action object is required")  # noqa: TRY004 - JSON validation is HTTP 400.
    digest = hashlib.sha256(encode(action).encode()).hexdigest()
    receipt = db.execute(
        "SELECT * FROM case_action_receipts WHERE tenant=? AND action_key=?",
        (actor["tenant"], action_key),
    ).fetchone()
    if receipt:
        if receipt["incident_id"] != incident_id or receipt["digest"] != digest:
            raise ConflictError("Action key already used with different content")
        return {**json.loads(receipt["result"]), "duplicate": True}
    now, kind = time.time(), action.get("type")
    result = {"type": kind, "incident_id": incident_id, "duplicate": False}
    if kind == "add_note":
        if set(action) != {"type", "note"}:
            raise ValueError("add_note accepts type and note")
        note = _text(action["note"], "note", 8000)
        # Durable inventory/history has no lifetime record-count ceiling.
        item_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO case_notes VALUES(?,?,?,?,?,?)",
            (item_id, actor["tenant"], incident_id, actor["name"], now, note),
        )
        result["id"] = item_id
    elif kind == "add_task":
        if set(action) - {
            "type",
            "title",
            "description",
            "assignee",
            "mandatory",
            "due_at",
        }:
            raise ValueError("Unknown task property")
        title = _text(action.get("title"), "title", 200)
        description = _text(
            action.get("description", ""), "description", 4000, empty=True
        )
        mandatory = action.get("mandatory", False)
        if type(mandatory) is not bool:
            raise ValueError("mandatory must be boolean")
        if mandatory and incident["status"] in {"resolved", "false_positive"}:
            raise ConflictError("Reopen the closed case before adding required work")
        due = _due(action.get("due_at"))
        assignee = _assignee(db, actor, incident_id, action.get("assignee", ""))
        # Durable inventory/history has no lifetime record-count ceiling.
        item_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO case_tasks VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                item_id,
                actor["tenant"],
                incident_id,
                title,
                description,
                "open",
                assignee,
                int(mandatory),
                due,
                now,
                now,
                1,
            ),
        )
        result.update({"id": item_id, "version": 1})
    elif kind == "assign":
        if set(action) != {"type", "assignee"}:
            raise ValueError("assign accepts type and assignee")
        assignee = _assignee(db, actor, incident_id, action["assignee"])
        db.execute(
            "UPDATE incidents SET owner=?,updated=?,version=version+1 WHERE id=? AND tenant=?",
            (assignee, now, incident_id, actor["tenant"]),
        )
        result["assignee"] = assignee
    elif kind == "set_status":
        if (
            set(action) != {"type", "status", "note"}
            or not isinstance(action["status"], str)
            or action["status"] not in {"new", "triage", "resolved"}
        ):
            raise ValueError(
                "set_status requires new/triage/resolved and an explanation"
            )
        note = _text(action["note"], "note", 4000)
        if action["status"] == "resolved":
            require_resolution(db, actor, incident_id)
        db.execute(
            "UPDATE incidents SET status=?,updated=?,version=version+1 WHERE id=? AND tenant=?",
            (action["status"], now, incident_id, actor["tenant"]),
        )
        db.execute(
            "INSERT INTO incident_feedback(tenant,incident_id,actor,at,status,note) VALUES(?,?,?,?,?,?)",
            (actor["tenant"], incident_id, actor["name"], now, action["status"], note),
        )
        result["status"] = action["status"]
    else:
        raise ValueError("Unsupported local response action")
    db.execute(
        "INSERT INTO case_action_receipts VALUES(?,?,?,?,?,?)",
        (actor["tenant"], action_key, incident_id, digest, encode(result), now),
    )
    store.audit(
        db,
        actor["tenant"],
        actor["name"],
        "case.action",
        {
            "incident_id": incident_id,
            "action": kind,
            "action_key": action_key,
            "result_id": result.get("id"),
            "previous_status": incident["status"],
        },
    )
    return result


def act(store, who, incident_id, data):
    if not isinstance(data, dict) or set(data) != {"action", "request_id"}:
        raise ValueError("Expected action and stable request_id")
    request_id = _text(data["request_id"], "request_id", 128)
    if SOAR_ACTION_KEY.fullmatch(request_id):
        raise ValueError("This request_id namespace is reserved for approved workflows")
    with principal.transaction(store, who, EDITORS, write=True) as (db, actor):
        return apply_action(
            db, store, actor, incident_id, data["action"], data["request_id"]
        )


def workspace(store, who, incident_id):
    with principal.transaction(store, who) as (db, actor):
        incident = principal.incident(db, actor, incident_id)
        row = db.execute(
            "SELECT * FROM case_workspaces WHERE tenant=? AND incident_id=?",
            (actor["tenant"], incident_id),
        ).fetchone()
        metadata = (
            dict(row)
            if row
            else {"priority": "medium", "due_at": None, "tags": "[]", "version": 0}
        )
        metadata["tags"] = json.loads(metadata["tags"])
        metadata["overdue"] = (
            metadata["due_at"] is not None
            and metadata["due_at"] < time.time()
            and incident["status"] not in {"resolved", "false_positive"}
        )
        tasks = [
            dict(r)
            for r in db.execute(
                "SELECT * FROM case_tasks WHERE tenant=? AND incident_id=? ORDER BY created,id",
                (actor["tenant"], incident_id),
            )
        ]
        notes = [
            dict(r)
            for r in db.execute(
                "SELECT * FROM case_notes WHERE tenant=? AND incident_id=? ORDER BY at DESC,id DESC",
                (actor["tenant"], incident_id),
            )
        ]
        total_notes = db.execute(
            "SELECT count(*) FROM case_notes WHERE tenant=? AND incident_id=?",
            (actor["tenant"], incident_id),
        ).fetchone()[0]
        bookmarks = [
            dict(r)
            for r in db.execute(
                "SELECT id,event_id,index_name,label,actor,at FROM case_bookmarks WHERE tenant=? AND incident_id=? ORDER BY at,id",
                (actor["tenant"], incident_id),
            )
        ]
        result = {
            "incident": incident,
            "workspace": metadata,
            "tasks": tasks,
            "notes": notes,
            "notes_total": total_notes,
            "notes_truncated": total_notes > len(notes),
            "bookmarks": bookmarks,
        }
        return result


def configure(store, who, incident_id, data):
    if not isinstance(data, dict) or set(data) != {
        "version",
        "priority",
        "due_at",
        "tags",
    }:
        raise ValueError("Expected version, priority, due_at and tags")
    version, due = _version(data["version"]), _due(data["due_at"])
    priority, tags = data["priority"], data["tags"]
    if (
        not isinstance(priority, str)
        or priority not in {"critical", "high", "medium", "low"}
        or not isinstance(tags, list)
        or len(tags) > 16
    ):
        raise ValueError("Invalid priority or tags")
    tags = sorted({_text(tag, "tag", 64) for tag in tags})
    with principal.transaction(store, who, EDITORS, write=True) as (db, actor):
        principal.incident(db, actor, incident_id)
        old = db.execute(
            "SELECT version FROM case_workspaces WHERE tenant=? AND incident_id=?",
            (actor["tenant"], incident_id),
        ).fetchone()
        if (old[0] if old else 0) != version:
            raise ConflictError("Case workspace version changed")
        db.execute(
            "INSERT INTO case_workspaces VALUES(?,?,?,?,?,?,?) ON CONFLICT(incident_id) DO UPDATE SET priority=excluded.priority,due_at=excluded.due_at,tags=excluded.tags,version=excluded.version,updated=excluded.updated",
            (
                actor["tenant"],
                incident_id,
                priority,
                due,
                encode(tags),
                version + 1,
                time.time(),
            ),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "case.configure",
            {"incident_id": incident_id, "version": version + 1},
        )
    return {"version": version + 1}


def update_task(store, who, incident_id, task_id, data):
    if not isinstance(data, dict) or set(data) != {
        "version",
        "status",
        "assignee",
        "due_at",
    }:
        raise ValueError("Expected version, status, assignee and due_at")
    version, due = _version(data["version"]), _due(data["due_at"])
    if not isinstance(data["status"], str) or data["status"] not in {
        "open",
        "done",
        "cancelled",
    }:
        raise ValueError("Invalid task status")
    with principal.transaction(store, who, EDITORS, write=True) as (db, actor):
        incident = principal.incident(db, actor, incident_id)
        row = db.execute(
            "SELECT * FROM case_tasks WHERE id=? AND tenant=? AND incident_id=?",
            (task_id, actor["tenant"], incident_id),
        ).fetchone()
        if not row:
            raise KeyError("Task not found")
        if row["version"] != version:
            raise ConflictError("Task version changed")
        if row["mandatory"] and data["status"] == "cancelled":
            raise ConflictError("A required task must be completed")
        if (
            row["mandatory"]
            and data["status"] != "done"
            and incident["status"] in {"resolved", "false_positive"}
        ):
            raise ConflictError("Reopen the closed case before reopening required work")
        assignee = _assignee(db, actor, incident_id, data["assignee"])
        db.execute(
            "UPDATE case_tasks SET status=?,assignee=?,due_at=?,updated=?,version=version+1 WHERE id=?",
            (data["status"], assignee, due, time.time(), task_id),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "case.task_update",
            {
                "incident_id": incident_id,
                "task_id": task_id,
                "status": data["status"],
                "version": version + 1,
            },
        )
    return {"id": task_id, "version": version + 1, "status": data["status"]}


def bookmark(store, who, incident_id, data):
    if not isinstance(data, dict) or set(data) != {"event_id", "label"}:
        raise ValueError("Expected event_id and label")
    event_id = _text(data["event_id"], "event_id", 256)
    label = _text(data["label"], "label", 200)
    with principal.transaction(store, who, EDITORS) as (db, actor):
        principal.incident(db, actor, incident_id)
    result = store.search(
        actor["tenant"],
        {
            "language": "json",
            "query": {
                "filters": [{"field": "event_id", "op": "eq", "value": event_id}],
                "fields": [
                    "event_id",
                    "event_time",
                    "index_name",
                    "host",
                    "source",
                    "message",
                    "raw",
                ],
            },
            "limit": 2,
        },
        allowed_indexes=actor["allowed_indexes"],
    )
    if len(result["rows"]) != 1:
        raise KeyError("Event not found")
    event = result["rows"][0]
    with principal.transaction(store, actor, EDITORS, write=True) as (db, fresh):
        principal.incident(db, fresh, incident_id)
        if not principal.contains(fresh["allowed_indexes"], [event["index_name"]]):
            raise KeyError("Event not found")
        existing = db.execute(
            "SELECT id FROM case_bookmarks WHERE tenant=? AND incident_id=? AND event_id=?",
            (fresh["tenant"], incident_id, event_id),
        ).fetchone()
        if existing:
            return {"id": existing[0], "duplicate": True}
        # Durable inventory/history has no lifetime record-count ceiling.
        item_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO case_bookmarks VALUES(?,?,?,?,?,?,?,?,?)",
            (
                item_id,
                fresh["tenant"],
                incident_id,
                event_id,
                event["index_name"],
                label,
                fresh["name"],
                time.time(),
                encode(event),
            ),
        )
        store.audit(
            db,
            fresh["tenant"],
            fresh["name"],
            "case.bookmark",
            {
                "incident_id": incident_id,
                "event_id": event_id,
                "index": event["index_name"],
            },
        )
        return {"id": item_id, "duplicate": False}


def export_case(store, who, incident_id):
    with principal.transaction(store, who) as (db, actor):
        incident = principal.incident(db, actor, incident_id)
        result = {
            "schema": "sapientia.case.v1",
            "created": time.time(),
            "incident": incident,
        }
        queries = {
            "workspace": "SELECT * FROM case_workspaces WHERE tenant=? AND incident_id=?",
            "tasks": "SELECT * FROM case_tasks WHERE tenant=? AND incident_id=? ORDER BY created,id",
            "notes": "SELECT * FROM case_notes WHERE tenant=? AND incident_id=? ORDER BY at,id",
            "bookmarks": "SELECT * FROM case_bookmarks WHERE tenant=? AND incident_id=? ORDER BY at,id",
            "contributions": "SELECT * FROM risk_contributions WHERE tenant=? AND incident_id=? ORDER BY at,id",
            "feedback": "SELECT * FROM incident_feedback WHERE tenant=? AND incident_id=? ORDER BY at,id",
        }
        total = len(encode(result).encode())
        for name, query in queries.items():
            items = []
            for row in db.execute(query, (actor["tenant"], incident_id)):
                item = dict(row)
                if name == "bookmarks" and not principal.contains(
                    actor["allowed_indexes"], [item["index_name"]]
                ):
                    raise KeyError("Incident not found")
                total += len(encode(item).encode()) + 32
                items.append(item)
            result[name] = items
        from . import content_notices
        result["content_notices"] = content_notices.for_case(db, actor, incident_id, result["contributions"])
        result["sha256"] = hashlib.sha256(encode(result).encode()).hexdigest()
        result["integrity_note"] = (
            "Digest covers canonical JSON before sha256/integrity_note; not an independent WORM proof"
        )
        return result
