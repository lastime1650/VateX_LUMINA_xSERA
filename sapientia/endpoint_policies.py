"""Independent signed, peer-approved per-endpoint offline defense policies."""

import hashlib
import json
import os
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import mfa, principal
from .endpoint_agent.Agent.defense import SCHEMA, canonical, validate
from .storage import ConflictError, encode

BLOCKED_REASON = "This CPU observation deployment blocks native defense policy delivery"


def _deployment_blocked():
    return os.environ.get("SAPIENTIA_BLOCK_NATIVE_RESPONSE") == "1"


def _release_guard():
    if _deployment_blocked():
        raise PermissionError(BLOCKED_REASON)


def initialize(store):
    if getattr(store, "_endpoint_defense_schema_ready", False):
        return
    with store.control(local=True) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS endpoint_defense_signers(tenant TEXT PRIMARY KEY,public_key TEXT NOT NULL,private_cipher TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS endpoint_defense_policies(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,agent_id TEXT NOT NULL,owner TEXT NOT NULL,approver TEXT,
          request_id TEXT NOT NULL,request_digest TEXT NOT NULL,revision INTEGER NOT NULL,
          document TEXT NOT NULL,digest TEXT NOT NULL,signature TEXT,status TEXT NOT NULL,created REAL NOT NULL,
          UNIQUE(tenant,owner,request_id),UNIQUE(tenant,agent_id,revision));
        CREATE INDEX IF NOT EXISTS endpoint_defense_agent ON endpoint_defense_policies(tenant,agent_id,revision DESC);
        """)
    store._endpoint_defense_schema_ready = True


def _signer(store, db, tenant):
    row = db.execute(
        "SELECT * FROM endpoint_defense_signers WHERE tenant=?", (tenant,)
    ).fetchone()
    if row:
        return row
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw().hex()
    cipher = mfa.encrypt(
        store, "endpoint-defense-release:" + tenant, key.private_bytes_raw().hex()
    )
    db.execute(
        "INSERT INTO endpoint_defense_signers VALUES(?,?,?)", (tenant, public, cipher)
    )
    return {"public_key": public, "private_cipher": cipher}


def public_key(store, tenant):
    initialize(store)
    with store.write_lock, store.control() as db:
        db.execute("BEGIN IMMEDIATE")
        return _signer(store, db, tenant)["public_key"]


def _agent(db, actor, agent_id):
    row = db.execute(
        "SELECT * FROM endpoint_agents WHERE id=? AND tenant=?",
        (agent_id, actor["tenant"]),
    ).fetchone()
    if (
        not row
        or row["revoked"]
        or row["expires"] <= time.time()
        or not principal.contains(actor["allowed_indexes"], [row["index_name"]])
    ):
        raise KeyError("Endpoint not found")
    return row


def _publisher(db, row, agent):
    for name in [row["owner"], row["approver"]]:
        if not name:
            raise PermissionError("Independent release approval required")
        actor = principal.current(
            db,
            {
                "name": name,
                "tenant": row["tenant"],
                "role": "admin",
                "allowed_indexes": [agent["index_name"]],
            },
            ("admin",),
        )
        if not principal.contains(actor["allowed_indexes"], [agent["index_name"]]):
            raise PermissionError("Release publisher/approver grant changed")


def _public(row):
    return {
        key: row[key]
        for key in [
            "id",
            "tenant",
            "agent_id",
            "owner",
            "approver",
            "revision",
            "digest",
            "status",
            "created",
        ]
    } | {"document": json.loads(row["document"])}


def save(store, who, data):
    if (
        not isinstance(data, dict)
        or set(data) - {"agent_id", "request_id", "rules", "lifetime_hours"}
        or not {"agent_id", "request_id", "rules"} <= set(data)
    ):
        raise ValueError("Agent, stable request ID and rules required")
    request = data["request_id"]
    if not isinstance(data["agent_id"], str) or not 1 <= len(data["agent_id"]) <= 120:
        raise ValueError("Bounded endpoint ID required")
    if not isinstance(request, str) or not 1 <= len(request) <= 120:
        raise ValueError("Bounded stable request ID required")
    hours = data.get("lifetime_hours", 24)
    if type(hours) is not int or not 1 <= hours <= 72:
        raise ValueError("Policy lifetime 1..72 hours")
    initialize(store)
    request_digest = hashlib.sha256(canonical(data)).hexdigest()
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        agent = _agent(db, actor, data["agent_id"])
        old = db.execute(
            "SELECT * FROM endpoint_defense_policies WHERE tenant=? AND owner=? AND request_id=?",
            (actor["tenant"], actor["name"], request),
        ).fetchone()
        if old:
            if old["request_digest"] != request_digest:
                raise ConflictError("Defense policy request ID content conflict")
            return _public(old)
        # Permanent execution/investigation history has no lifetime count ceiling.
        revision = db.execute(
            "SELECT coalesce(max(revision),0)+1 FROM endpoint_defense_policies WHERE tenant=? AND agent_id=?",
            (actor["tenant"], agent["id"]),
        ).fetchone()[0]
        now = time.time()
        document = {
            "schema": SCHEMA,
            "tenant": actor["tenant"],
            "host": agent["host"],
            "agent_id": agent["id"],
            "index": agent["index_name"],
            "revision": revision,
            "issued_at": now,
            "expires_at": now + hours * 3600,
            "rules": data["rules"],
        }
        validate(
            document,
            {
                "tenant": actor["tenant"],
                "host": agent["host"],
                "agent_id": agent["id"],
                "index": agent["index_name"],
            },
            now,
        )
        digest, identifier = (
            hashlib.sha256(canonical(document)).hexdigest(),
            str(uuid.uuid4()),
        )
        db.execute(
            "INSERT INTO endpoint_defense_policies VALUES(?,?,?,?,?,?,?,?,?,?,?,'pending_approval',?)",
            (
                identifier,
                actor["tenant"],
                agent["id"],
                actor["name"],
                None,
                request,
                request_digest,
                revision,
                encode(document),
                digest,
                None,
                now,
            ),
        )
        _signer(store, db, actor["tenant"])
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "endpoint.defense.request",
            {
                "id": identifier,
                "agent_id": agent["id"],
                "revision": revision,
                "digest": digest,
            },
        )
        return _public(
            db.execute(
                "SELECT * FROM endpoint_defense_policies WHERE id=?", (identifier,)
            ).fetchone()
        )


def approve(store, who, identifier):
    initialize(store)
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        _release_guard()
        row = db.execute(
            "SELECT * FROM endpoint_defense_policies WHERE id=? AND tenant=?",
            (identifier, actor["tenant"]),
        ).fetchone()
        if not row:
            raise KeyError("Defense policy not found")
        if row["owner"] == actor["name"]:
            raise PermissionError("Defense release cannot be self approved")
        agent = _agent(db, actor, row["agent_id"])
        owner = principal.current(
            db,
            {
                "name": row["owner"],
                "tenant": row["tenant"],
                "role": "admin",
                "allowed_indexes": [agent["index_name"]],
            },
            ("admin",),
        )
        if not principal.contains(owner["allowed_indexes"], [agent["index_name"]]):
            raise PermissionError("Release owner grant changed")
        if row["status"] == "active" and row["approver"] == actor["name"]:
            return _public(row)
        if row["status"] != "pending_approval":
            raise ConflictError("Release is not awaiting approval")
        doc = json.loads(row["document"])
        validate(
            doc,
            {
                "tenant": row["tenant"],
                "host": agent["host"],
                "agent_id": agent["id"],
                "index": agent["index_name"],
            },
            time.time(),
        )
        newer = db.execute(
            "SELECT 1 FROM endpoint_defense_policies WHERE tenant=? AND agent_id=? AND revision>? AND status='active'",
            (row["tenant"], row["agent_id"], row["revision"]),
        ).fetchone()
        if newer:
            raise ConflictError(
                "Newer approved policy exists; rollback requires a new revision"
            )
        signer = _signer(store, db, row["tenant"])
        private = mfa.decrypt(
            store, "endpoint-defense-release:" + row["tenant"], signer["private_cipher"]
        )
        signature = (
            Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private))
            .sign(canonical(doc))
            .hex()
        )
        db.execute(
            "UPDATE endpoint_defense_policies SET status='superseded' WHERE tenant=? AND agent_id=? AND status='active'",
            (row["tenant"], row["agent_id"]),
        )
        db.execute(
            "UPDATE endpoint_defense_policies SET approver=?,signature=?,status='active' WHERE id=?",
            (actor["name"], signature, identifier),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "endpoint.defense.approve",
            {
                "id": identifier,
                "agent_id": agent["id"],
                "revision": row["revision"],
                "digest": row["digest"],
            },
        )
        return _public(
            db.execute(
                "SELECT * FROM endpoint_defense_policies WHERE id=?", (identifier,)
            ).fetchone()
        )


def listing(store, who):
    initialize(store)
    with principal.transaction(store, who, ("admin", "analyst")) as (db, actor):
        args = [actor["tenant"]]
        scope = ""
        if actor["allowed_indexes"] != ["*"]:
            scope = (
                " AND a.index_name IN ("
                + (",".join("?" for _ in actor["allowed_indexes"]) or "NULL")
                + ")"
            )
            args.extend(actor["allowed_indexes"])
        rows = db.execute(
            "SELECT p.*,a.index_name FROM endpoint_defense_policies p JOIN endpoint_agents a ON a.id=p.agent_id AND a.tenant=p.tenant WHERE p.tenant=?"
            + scope
            + " ORDER BY p.created DESC",
            args,
        ).fetchall()
        items = [
            _public(r)
            for r in rows
            if principal.contains(actor["allowed_indexes"], [r["index_name"]])
        ]
        signer = db.execute(
            "SELECT public_key FROM endpoint_defense_signers WHERE tenant=?",
            (actor["tenant"],),
        ).fetchone()
        return {
            "policies": items,
            "public_key": signer["public_key"] if signer else None,
            "limit": 1000,
            "truncated": len(rows) == 1000,
            "offline_revocation": "An already cached policy remains valid until signed expiry; no instantaneous offline revocation",
        }


def bundle(store, who, identifier):
    initialize(store)
    with principal.transaction(store, who, ("admin", "analyst")) as (db, actor):
        _release_guard()
        row = db.execute(
            "SELECT * FROM endpoint_defense_policies WHERE id=? AND tenant=?",
            (identifier, actor["tenant"]),
        ).fetchone()
        if not row or row["status"] != "active":
            raise KeyError("Active signed policy not found")
        agent = _agent(db, actor, row["agent_id"])
        _publisher(db, row, agent)
        doc = json.loads(row["document"])
        validate(
            doc,
            {
                "tenant": row["tenant"],
                "host": agent["host"],
                "agent_id": agent["id"],
                "index": agent["index_name"],
            },
            time.time(),
        )
        return {"document": doc, "signature": row["signature"]}


def fetch(store, service, credential, data):
    if data != {}:
        raise ValueError("Defense fetch body must be empty")
    initialize(store)
    with store.control() as db:
        agent = service._agent(db, credential)
        if _deployment_blocked():
            return {"bundle": None, "blocked": True, "reason": BLOCKED_REASON}
        row = db.execute(
            "SELECT * FROM endpoint_defense_policies WHERE tenant=? AND agent_id=? AND status='active' ORDER BY revision DESC LIMIT 1",
            (agent["tenant"], agent["id"]),
        ).fetchone()
        if not row:
            return {"bundle": None}
        _publisher(db, row, agent)
        doc = json.loads(row["document"])
        validate(
            doc,
            {
                "tenant": agent["tenant"],
                "host": agent["host"],
                "agent_id": agent["id"],
                "index": agent["index_name"],
            },
            time.time(),
        )
        return {"bundle": {"document": doc, "signature": row["signature"]}}
