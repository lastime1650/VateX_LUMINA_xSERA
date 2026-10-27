"""Resolve current tenant principals in the same transaction as protected state."""

import sqlite3
import time
from contextlib import contextmanager, nullcontext

from . import access
from .storage import CapacityError


def intersection(left, right):
    left, right = access.validate(left), access.validate(right)
    if left == ["*"]:
        return right
    if right == ["*"]:
        return left
    return sorted(set(left) & set(right))


def current(db, who, roles=("admin", "analyst", "viewer")):
    if (
        not isinstance(who, dict)
        or who.get("kind") == "token"
        or who.get("role") not in roles
    ):
        raise PermissionError("An active local user with the required role is required")
    row = db.execute(
        "SELECT name,tenant,role,disabled,must_change FROM users WHERE name=? AND tenant=?",
        (who.get("name"), who.get("tenant")),
    ).fetchone()
    if not row or row["disabled"] or row["must_change"] or row["role"] not in roles:
        raise PermissionError("User permissions changed or the account is unavailable")
    granted = access._get(db, row["name"], row["tenant"])
    return {
        "name": row["name"],
        "tenant": row["tenant"],
        "role": row["role"],
        "allowed_indexes": intersection(granted, who.get("allowed_indexes", granted)),
    }


@contextmanager
def transaction(store, who, roles=("admin", "analyst", "viewer"), *, write=False):
    with store.write_lock if write else nullcontext(), store.control() as db:
        deadline = time.monotonic() + 3
        db.execute("PRAGMA busy_timeout=1000")
        db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        try:
            if not db.in_transaction:
                db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield db, current(db, who, roles)
        except sqlite3.OperationalError as exc:
            if "interrupted" in str(exc).lower():
                raise CapacityError(
                    "Operation deadline exceeded; narrow the request"
                ) from None
            raise
        finally:
            db.set_progress_handler(None, 0)


def recheck(store, actor, roles=("admin", "analyst", "viewer")):
    with store.control() as db:
        fresh = current(db, actor, roles)
    if fresh != actor:
        raise PermissionError("Permissions changed during the operation; retry")
    return fresh


def incident(db, actor, incident_id):
    from .detections import _authorize_incident

    result = _authorize_incident(db, actor, incident_id)[0]
    scope = actor["allowed_indexes"]
    if scope != ["*"]:
        slots = ",".join("?" for _ in scope) or "NULL"
        if db.execute(
            "SELECT 1 FROM case_bookmarks WHERE tenant=? AND incident_id=? AND index_name NOT IN ("
            + slots
            + ") LIMIT 1",
            [actor["tenant"], incident_id, *scope],
        ).fetchone():
            raise KeyError("Incident not found")
    return result


def contains(scope, indexes):
    scope = access.validate(scope)
    indexes = access.validate(indexes)
    return scope == ["*"] or (indexes != ["*"] and set(indexes) <= set(scope))
