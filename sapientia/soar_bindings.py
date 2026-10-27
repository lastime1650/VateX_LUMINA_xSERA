"""Explicit policy-to-case proposals. Binding never grants or skips approval."""

import json
import time
import uuid

from . import principal, soar
from .storage import CapacityError, ConflictError, encode


def save(store, who, data):
    if (
        not isinstance(data, dict)
        or set(data) != {"policy_id", "playbook_id", "enabled", "version"}
        or type(data["enabled"]) is not bool
        or type(data["version"]) is not int
        or data["version"] < 0
    ):
        raise ValueError("Binding requires policy_id,playbook_id,enabled,version")
    soar._text(data["policy_id"], "policy_id", 256)
    soar._text(data["playbook_id"], "playbook_id", 256)
    with principal.transaction(store, who, soar.EDITORS, write=True) as (db, actor):
        policy = db.execute(
            "SELECT * FROM correlation_policies WHERE tenant=? AND id=?",
            (actor["tenant"], data["policy_id"]),
        ).fetchone()
        book = db.execute(
            "SELECT * FROM soar_playbooks WHERE tenant=? AND id=?",
            (actor["tenant"], data["playbook_id"]),
        ).fetchone()
        if not policy or not book:
            raise KeyError("Policy or playbook not found")
        book_scope = soar._playbook_guard(db, actor, book["id"], book["version"])
        if actor["role"] != "admin" and (
            policy["owner"] != actor["name"] or book["owner"] != actor["name"]
        ):
            raise PermissionError("Binding requires ownership or tenant administrator")
        indexes = json.loads(policy["definition"]).get("indexes", ["*"])
        if not principal.contains(actor["allowed_indexes"], indexes):
            raise PermissionError("Binding scope must cover the policy's indexes")
        required_scope = (
            ["*"]
            if "*" in indexes or "*" in book_scope
            else sorted(set(indexes) | set(book_scope))
        )
        old = db.execute(
            "SELECT * FROM soar_bindings WHERE tenant=? AND policy_id=?",
            (actor["tenant"], policy["id"]),
        ).fetchone()
        if (old["version"] if old else 0) != data["version"]:
            raise ConflictError("Binding version changed")
        # Durable inventory/history has no lifetime record-count ceiling.
        if old and old["owner"] != actor["name"] and actor["role"] != "admin":
            raise PermissionError("Only binding owner or administrator may edit")
        identifier = old["id"] if old else "BIND-" + uuid.uuid4().hex
        # New/reconfigured bindings are prospective, never import old cases.
        cursor = db.execute(
            "SELECT coalesce(max(rowid),0) FROM risk_contributions WHERE tenant=?",
            (actor["tenant"],),
        ).fetchone()[0]
        db.execute(
            "INSERT INTO soar_bindings VALUES(?,?,?,?,?,?,?,?,?,?,?,NULL) ON CONFLICT(id) DO UPDATE SET owner=excluded.owner,scope=excluded.scope,playbook_id=excluded.playbook_id,revision=excluded.revision,version=excluded.version,enabled=excluded.enabled,cursor=excluded.cursor,updated=excluded.updated,error=NULL",
            (
                identifier,
                actor["tenant"],
                actor["name"],
                encode(required_scope),
                policy["id"],
                book["id"],
                book["version"],
                data["version"] + 1,
                int(data["enabled"]),
                cursor,
                time.time(),
            ),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "soar.binding_save",
            {
                "id": identifier,
                "enabled": data["enabled"],
                "policy_id": policy["id"],
                "approval": "independent_approval_still_required",
            },
        )
        return {
            "id": identifier,
            "version": data["version"] + 1,
            "enabled": data["enabled"],
            "prospective_only": True,
            "approval_required": True,
        }


def listing(store, who):
    with principal.transaction(store, who, soar.EDITORS) as (db, actor):
        rows = db.execute(
            "SELECT * FROM soar_bindings WHERE tenant=? ORDER BY id",
            (actor["tenant"],),
        ).fetchall()
        visible = []
        for row in rows:
            if not principal.contains(
                actor["allowed_indexes"], json.loads(row["scope"])
            ):
                continue
            try:
                soar._playbook_guard(db, actor, row["playbook_id"], row["revision"])
            except KeyError:
                continue
            visible.append(row)
        return {
            "bindings": [
                {
                    key: row[key]
                    for key in (
                        "id",
                        "owner",
                        "policy_id",
                        "playbook_id",
                        "revision",
                        "version",
                        "enabled",
                        "updated",
                        "error",
                    )
                }
                for row in visible
            ],
            "approval_required": True,
            "prospective_only": True,
        }


def run_due(store, deadline, maximum=20):
    processed = 0
    with store.control() as db:
        bindings = db.execute(
            "SELECT * FROM soar_bindings WHERE enabled=1 ORDER BY updated,id"
        ).fetchall()
    for binding in bindings:
        if processed >= maximum or time.monotonic() >= deadline:
            break
        with store.control() as db:
            candidate = db.execute(
                "SELECT rowid,incident_id FROM risk_contributions WHERE tenant=? AND policy_id=? AND rowid>? ORDER BY rowid LIMIT 1",
                (binding["tenant"], binding["policy_id"], binding["cursor"]),
            ).fetchone()
            if not candidate:
                continue
            try:
                actor = principal.current(
                    db,
                    {
                        "name": binding["owner"],
                        "tenant": binding["tenant"],
                        "role": "analyst",
                        "allowed_indexes": json.loads(binding["scope"]),
                    },
                    soar.EDITORS,
                )
                book = db.execute(
                    "SELECT version FROM soar_playbooks WHERE tenant=? AND id=?",
                    (binding["tenant"], binding["playbook_id"]),
                ).fetchone()
                if not book or book["version"] != binding["revision"]:
                    raise ConflictError("Bound playbook revision changed")
                principal.incident(db, actor, candidate["incident_id"])
                error = None
            except (PermissionError, KeyError, ConflictError):
                actor, error = None, "binding_scope_or_revision_unavailable"
        if actor is not None:
            try:
                soar.start_run(
                    store,
                    actor,
                    binding["playbook_id"],
                    candidate["incident_id"],
                    "binding-"
                    + soar._digest(
                        [binding["id"], binding["version"], candidate["incident_id"]]
                    )[:48],
                    binding=(binding["id"], binding["version"]),
                )
            except (PermissionError, KeyError, ConflictError, CapacityError):
                error = "binding_proposal_unavailable"
        with store.write_lock, store.control() as db:
            if error is None:
                db.execute(
                    "UPDATE soar_bindings SET cursor=?,error=NULL WHERE id=? AND version=? AND enabled=1",
                    (candidate["rowid"], binding["id"], binding["version"]),
                )
            else:
                db.execute(
                    "UPDATE soar_bindings SET error=?,enabled=0 WHERE id=? AND version=?",
                    (error, binding["id"], binding["version"]),
                )
            store.audit(
                db,
                binding["tenant"],
                binding["owner"],
                "soar.binding_proposal",
                {
                    "id": binding["id"],
                    "incident_id": candidate["incident_id"],
                    "error": error,
                    "approval_required": True,
                },
            )
        processed += 1
    return processed
