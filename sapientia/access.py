"""Tenant-bound, exact logical-index grants for searchable user principals."""

import json
import re


def initialize(store):
    with store.control(local=True) as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS user_index_access(tenant TEXT NOT NULL,name TEXT NOT NULL,allowed_indexes TEXT NOT NULL,PRIMARY KEY(tenant,name))"
        )
    from .auth import initialize as initialize_collectors

    initialize_collectors(store)


def validate(indexes):
    if not isinstance(indexes, list) or len(indexes) > 256:
        raise ValueError(
            "allowed_indexes must be a list of at most 256 exact index names"
        )
    if indexes == ["*"]:
        return ["*"]
    if any(
        not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name)
        for name in indexes
    ):
        raise ValueError("Use exact index names, ['*'] for all, or [] to deny all")
    if len(set(indexes)) != len(indexes):
        raise ValueError("Duplicate index grants are not allowed")
    return sorted(indexes)


def _get(db, name, tenant):
    user = db.execute(
        "SELECT disabled FROM users WHERE name=? AND tenant=?", (name, tenant)
    ).fetchone()
    if not user or user["disabled"]:
        return []
    row = db.execute(
        "SELECT allowed_indexes FROM user_index_access WHERE tenant=? AND name=?",
        (tenant, name),
    ).fetchone()
    # Existing enabled principals retain their former access until an admin sets
    # an explicit grant. A stored empty list must never be treated as this default.
    return validate(json.loads(row[0])) if row else ["*"]


def get_for_user(store, name, tenant=None):
    if isinstance(name, dict):
        tenant, name = name["tenant"], name["name"]
    if not isinstance(name, str) or not isinstance(tenant, str):
        raise ValueError("User and tenant are required")  # noqa: TRY004 - API validation uses ValueError.
    with store.control() as db:
        return _get(db, name, tenant)


def require_full_admin(db, who):
    """Account administration can grant any role, so it requires full index scope."""
    from . import principal

    actor = principal.current(db, who, ("admin",))
    if actor["allowed_indexes"] != ["*"]:
        raise PermissionError(
            "Account administration requires an unrestricted tenant administrator"
        )
    return actor


def set_for_user(store, actor, name, indexes):
    from . import principal

    indexes = validate(indexes)
    with principal.transaction(store, actor, ("admin",), write=True) as (db, current):
        tenant = current["tenant"]
        if not db.execute(
            "SELECT 1 FROM users WHERE name=? AND tenant=?", (name, tenant)
        ).fetchone():
            raise KeyError("User not found")
        row = db.execute(
            "SELECT allowed_indexes FROM user_index_access WHERE tenant=? AND name=?",
            (tenant, name),
        ).fetchone()
        # Read configured grants even for a disabled target. Disabled status must
        # not make an unrestricted account appear manageable by a scoped admin.
        previous = validate(json.loads(row[0])) if row else ["*"]
        if not principal.contains(
            current["allowed_indexes"], previous
        ) or not principal.contains(current["allowed_indexes"], indexes):
            raise PermissionError(
                "Index administration cannot exceed the administrator's current scope"
            )
        db.execute(
            "INSERT INTO user_index_access(tenant,name,allowed_indexes) VALUES(?,?,?) ON CONFLICT(tenant,name) DO UPDATE SET allowed_indexes=excluded.allowed_indexes",
            (tenant, name, json.dumps(indexes, separators=(",", ":"))),
        )
        db.execute("DELETE FROM sessions WHERE name=?", (name,))
        store.audit(
            db,
            tenant,
            current["name"],
            "user.index_access",
            {"name": name, "allowed_indexes": indexes, "sessions_revoked": True},
        )
    return {"name": name, "allowed_indexes": indexes, "sessions_revoked": True}
