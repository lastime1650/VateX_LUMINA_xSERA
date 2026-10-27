import hashlib
import json
import re
import secrets
import time

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

PASSWORDS = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
DUMMY = PASSWORDS.hash(secrets.token_urlsafe(24))


def initialize(store):
    """Old unbound tokens cannot be attributed safely: require explicit rotation."""
    with store.control(local=True) as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS collector_access(digest TEXT PRIMARY KEY,tenant TEXT NOT NULL,issued_by TEXT,allowed_indexes TEXT NOT NULL,legacy INTEGER NOT NULL DEFAULT 0)"
        )
        db.execute(
            "INSERT OR IGNORE INTO collector_access(digest,tenant,issued_by,allowed_indexes,legacy) SELECT digest,tenant,NULL,'[]',1 FROM tokens"
        )


def _token_identity(db, token_digest):
    from . import access, principal

    row = db.execute(
        "SELECT t.*,c.issued_by,c.allowed_indexes,c.legacy FROM tokens t JOIN collector_access c ON c.digest=t.digest AND c.tenant=t.tenant WHERE t.digest=?",
        (token_digest,),
    ).fetchone()
    if (
        not row
        or row["scope"] != "ingest"
        or row["legacy"]
        or not row["issued_by"]
        or row["expires"] is None
        or row["expires"] <= time.time()
    ):
        return None
    try:
        owner = principal.current(
            db,
            {"name": row["issued_by"], "tenant": row["tenant"], "role": "admin"},
            ("admin",),
        )
        scope = principal.intersection(
            access.validate(json.loads(row["allowed_indexes"])),
            owner["allowed_indexes"],
        )
    except (PermissionError, ValueError, TypeError):
        return None
    if not scope:
        return None
    return {
        "name": row["name"],
        "tenant": row["tenant"],
        "role": "ingest",
        "kind": "token",
        "allowed_indexes": scope,
        "issued_by": row["issued_by"],
        "credential_id": token_digest,
    }


def ingest_scope(db, who):
    """Resolve intake authority in Store's admission transaction, before writes."""
    from . import principal

    if who.get("kind") == "token":
        fresh = _token_identity(db, who.get("credential_id"))
        if (
            not fresh
            or fresh["tenant"] != who.get("tenant")
            or fresh["name"] != who.get("name")
        ):
            raise PermissionError(
                "Collector token is unavailable or issuer permissions changed"
            )
        return principal.intersection(
            fresh["allowed_indexes"], who.get("allowed_indexes", [])
        )
    actor = principal.current(db, who, ("admin",))
    return actor["allowed_indexes"]


def ingest_authorized(store, who, events):
    return store.ingest(
        who["tenant"],
        events,
        who["name"],
        allowed_indexes=who["allowed_indexes"],
        authorization=lambda db: ingest_scope(db, who),
    )


def digest(value):
    try:
        return hashlib.sha256(value.encode()).hexdigest()
    except UnicodeEncodeError:
        raise ValueError("Invalid Unicode credential") from None


def check_password(encoded, password):
    if not isinstance(password, str) or len(password) > 128:
        return False
    try:
        return PASSWORDS.verify(encoded, password)
    except (VerificationError, InvalidHashError, UnicodeError):
        return False


def password_policy(password):
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        raise ValueError("Password must be 12..128 characters")
    try:
        password.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("Password contains invalid Unicode") from None


def create_user(
    store,
    name,
    password,
    role="admin",
    tenant="default",
    first=False,
    actor="bootstrap",
    must_change=False,
    authorization=None,
):
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", name):
        raise ValueError(
            "Username must be 3..64 letters, digits, dots, underscores or hyphens"
        )
    password_policy(password)
    if (
        not isinstance(role, str)
        or role not in {"admin", "analyst", "viewer"}
        or not isinstance(tenant, str)
        or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", tenant)
    ):
        raise ValueError("Invalid role or tenant")
    password_hash = PASSWORDS.hash(password)
    with store.write_lock, store.control() as db:
        db.execute("BEGIN IMMEDIATE")
        if authorization is not None:
            current = authorization(db)
            if current["tenant"] != tenant or current["name"] != actor:
                raise PermissionError("Account administration identity changed")
        if first and db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            raise ValueError("Initial setup already completed")
        db.execute(
            "INSERT INTO users(name,password,role,tenant,password_changed,must_change) VALUES(?,?,?,?,?,?)",
            (name, password_hash, role, tenant, time.time(), int(must_change)),
        )
        store.audit(db, tenant, actor, "user.create", {"name": name, "role": role})


def login(store, name, password, otp=None):
    if not isinstance(name, str):
        raise ValueError("Invalid username format")  # noqa: TRY004 - API validation uses ValueError.
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("Invalid username format") from None
    with store.control() as db:
        user = db.execute("SELECT * FROM users WHERE name=?", (name,)).fetchone()
    valid = check_password(user["password"] if user else DUMMY, password)
    if not valid or not user:
        return None
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    with store.write_lock, store.control() as db:
        current = db.execute("SELECT * FROM users WHERE name=?", (name,)).fetchone()
        if (
            not current
            or current["disabled"]
            or current["password"] != user["password"]
        ):
            return None
        user = current
        if user["mfa_secret"]:
            from . import mfa

            counter = mfa.verify(
                mfa.decrypt(store, name, user["mfa_secret"]), otp, user["mfa_counter"]
            )
            if counter is None:
                return None
            db.execute("UPDATE users SET mfa_counter=? WHERE name=?", (counter, name))
        db.execute(
            "INSERT INTO sessions VALUES(?,?,?,?)",
            (digest(token), name, time.time() + 28800, csrf),
        )
        store.audit(db, user["tenant"], name, "login", {})
    return {
        "token": token,
        "csrf": csrf,
        "name": name,
        "role": user["role"],
        "tenant": user["tenant"],
        "must_change": bool(user["must_change"]),
        "mfa_enabled": bool(user["mfa_secret"]),
    }


def identity(store, cookie=None, bearer=None):
    from . import access

    credential = bearer or cookie
    if credential and (
        not isinstance(credential, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", credential)
    ):
        return None
    with store.control() as db:
        if bearer:
            return _token_identity(db, digest(bearer))
        if cookie:
            row = db.execute(
                "SELECT u.name,u.role,u.tenant,s.csrf,u.must_change,u.mfa_secret IS NOT NULL AS mfa_enabled FROM sessions s JOIN users u ON u.name=s.name WHERE s.digest=? AND s.expires>? AND u.disabled=0",
                (digest(cookie), time.time()),
            ).fetchone()
            return (
                {
                    **dict(row),
                    "kind": "session",
                    "allowed_indexes": access._get(db, row["name"], row["tenant"]),
                }
                if row
                else None
            )
    return None


def issue_token(store, who, name, lifetime_days=90, allowed_indexes=None):
    from . import access, principal

    if not isinstance(name, str) or not 1 <= len(name) <= 80:
        raise ValueError("Collector name required (1..80 characters)")
    if type(lifetime_days) is not int or not 1 <= lifetime_days <= 365:
        raise ValueError("Collector token lifetime must be 1..365 days")
    indexes = access.validate(["main"] if allowed_indexes is None else allowed_indexes)
    if not indexes or indexes == ["*"]:
        raise ValueError(
            "Collector write access requires 1..256 exact index names; wildcards are forbidden"
        )
    token = secrets.token_urlsafe(32)
    with store.write_lock, store.control() as db:
        db.execute("BEGIN IMMEDIATE")
        actor = principal.current(
            db, {**who, "role": who.get("role", "admin")}, ("admin",)
        )
        if not principal.contains(actor["allowed_indexes"], indexes):
            raise PermissionError(
                "Collector write indexes exceed issuer's current grants"
            )
        # Durable inventory/history has no lifetime record-count ceiling.
        db.execute(
            "INSERT INTO tokens(digest,name,tenant,scope,created,expires) VALUES(?,?,?,?,?,?)",
            (
                digest(token),
                name,
                who["tenant"],
                "ingest",
                time.time(),
                time.time() + lifetime_days * 86400,
            ),
        )
        db.execute(
            "INSERT INTO collector_access VALUES(?,?,?,?,0)",
            (
                digest(token),
                actor["tenant"],
                actor["name"],
                json.dumps(indexes, separators=(",", ":")),
            ),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "token.create",
            {
                "collector": name,
                "allowed_indexes": indexes,
                "expires_in_days": lifetime_days,
                "issued_by": actor["name"],
            },
        )
    return token


def list_tokens(store, who):
    from . import principal

    with principal.transaction(store, who, ("admin",)) as (db, actor):
        result = []
        for row in db.execute(
            "SELECT t.digest AS id,t.name,t.scope,t.created,t.expires,c.issued_by,c.allowed_indexes,c.legacy FROM tokens t LEFT JOIN collector_access c ON c.digest=t.digest WHERE t.tenant=? ORDER BY t.created DESC",
            (actor["tenant"],),
        ):
            item = dict(row)
            item["allowed_indexes"] = json.loads(item["allowed_indexes"] or "[]")
            item["status"] = (
                "legacy_requires_rotation"
                if item["legacy"] or not item["issued_by"]
                else "expired"
                if item["expires"] is None or item["expires"] <= time.time()
                else "active"
                if _token_identity(db, item["id"])
                else "issuer_unavailable_or_scope_revoked"
            )
            result.append(item)
        return result


def revoke_token(store, who, token_id):
    from . import principal

    if not isinstance(token_id, str) or not re.fullmatch(r"[a-f0-9]{64}", token_id):
        raise ValueError("Invalid collector token identifier")
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        db.execute(
            "DELETE FROM tokens WHERE digest=? AND tenant=?",
            (token_id, actor["tenant"]),
        )
        db.execute(
            "DELETE FROM collector_access WHERE digest=? AND tenant=?",
            (token_id, actor["tenant"]),
        )
        store.audit(
            db, actor["tenant"], actor["name"], "token.revoke", {"id": token_id}
        )
    return {"ok": True}


def verified_session(store, name, otp=None, detail=None):
    """Issue a session only after a trusted authentication adapter verified identity.

    This is an internal helper, never an endpoint accepting an asserted username.
    Local account state and a configured local second factor still apply.
    """
    from . import access, mfa

    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    with store.write_lock, store.control() as db:
        db.execute("BEGIN IMMEDIATE")
        user = db.execute("SELECT * FROM users WHERE name=?", (name,)).fetchone()
        if (
            not user
            or user["disabled"]
            or user["role"] not in {"admin", "analyst", "viewer"}
        ):
            raise PermissionError("Mapped local account is unavailable")
        if user["mfa_secret"]:
            counter = mfa.verify(
                mfa.decrypt(store, name, user["mfa_secret"]), otp, user["mfa_counter"]
            )
            if counter is None:
                raise PermissionError("Local authenticator verification required")
            db.execute("UPDATE users SET mfa_counter=? WHERE name=?", (counter, name))
        db.execute(
            "INSERT INTO sessions VALUES(?,?,?,?)",
            (digest(token), name, time.time() + 28800, csrf),
        )
        store.audit(db, user["tenant"], name, "sso.login", detail or {})
        indexes = access._get(db, name, user["tenant"])
    return {
        "token": token,
        "csrf": csrf,
        "name": name,
        "role": user["role"],
        "tenant": user["tenant"],
        "must_change": bool(user["must_change"]),
        "mfa_enabled": bool(user["mfa_secret"]),
        "allowed_indexes": indexes,
    }


def change_password(store, who, current, new, otp=None):
    password_policy(new)
    if current == new:
        raise ValueError("Choose a different new password")
    new_hash = PASSWORDS.hash(new)
    with store.write_lock, store.control() as db:
        user = db.execute(
            "SELECT * FROM users WHERE name=? AND tenant=?",
            (who["name"], who["tenant"]),
        ).fetchone()
        if not user or not check_password(user["password"], current):
            raise ValueError("Current password verification failed")
        if user["mfa_secret"]:
            from . import mfa

            counter = mfa.verify(
                mfa.decrypt(store, who["name"], user["mfa_secret"]),
                otp,
                user["mfa_counter"],
            )
            if counter is None:
                raise ValueError(
                    "Current authenticator code is invalid or already used"
                )
            db.execute(
                "UPDATE users SET mfa_counter=? WHERE name=?", (counter, who["name"])
            )
        db.execute(
            "UPDATE users SET password=?,must_change=0,password_changed=? WHERE name=?",
            (new_hash, time.time(), who["name"]),
        )
        db.execute("DELETE FROM sessions WHERE name=?", (who["name"],))
        store.audit(
            db,
            who["tenant"],
            who["name"],
            "password.changed",
            {"sessions_revoked": True},
        )
    return {"changed": True, "sessions_revoked": True}
