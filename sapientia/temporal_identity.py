"""Evidence-bound temporal identity and exact NAT five-tuple resolution.

Bindings are explicit observations approved by an analyst, not IP attribution.
An overlap never selects a convenient candidate. Source endpoint authorization
continues to use the enrolled agent's receipt, GUID and process start identity.
"""

import ipaddress
import json
import time
import uuid

from . import entities, principal
from . import evidence_scope as evidence
from .storage import CapacityError, ConflictError, encode


def initialize(store):
    with store.control(local=True) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS temporal_identity_bindings(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,kind TEXT NOT NULL,
          lookup_key TEXT NOT NULL,entity_id TEXT NOT NULL,session_id TEXT NOT NULL,
          valid_from REAL NOT NULL,valid_until REAL NOT NULL,indexes TEXT NOT NULL,
          definition TEXT NOT NULL,version INTEGER NOT NULL,state TEXT NOT NULL,
          owner TEXT NOT NULL,updated REAL NOT NULL);
        CREATE INDEX IF NOT EXISTS temporal_identity_lookup ON
          temporal_identity_bindings(tenant,kind,lookup_key,valid_from,valid_until);
        CREATE TABLE IF NOT EXISTS temporal_identity_history(
          id TEXT NOT NULL,tenant TEXT NOT NULL,version INTEGER NOT NULL,
          actor TEXT NOT NULL,at REAL NOT NULL,record TEXT NOT NULL,
          PRIMARY KEY(tenant,id,version));
        """)


def lookup(kind, value):
    if kind == "ip":
        if not isinstance(value, str):
            raise ValueError("IP lookup requires an IP address")
        return str(ipaddress.ip_address(value))
    if kind == "user":
        return evidence.text(value, "user identity")
    if kind == "nat":
        if not isinstance(value, dict) or set(value) != {
            "src_ip",
            "src_port",
            "dest_ip",
            "dest_port",
            "protocol",
        }:
            raise ValueError(
                "NAT requires the complete src/dest IP+port+protocol tuple"
            )
        evidence.choice(value["protocol"], {"tcp", "udp"}, "NAT protocol")
        return {
            "src_ip": lookup("ip", value["src_ip"]),
            "src_port": evidence.integer(value["src_port"], "src_port", 1, 65535),
            "dest_ip": lookup("ip", value["dest_ip"]),
            "dest_port": evidence.integer(value["dest_port"], "dest_port", 1, 65535),
            "protocol": value["protocol"],
        }
    raise ValueError("Identity lookup kind must be ip, user or nat")


def _row(row):
    result = json.loads(row["definition"])
    return {
        **result,
        "id": row["id"],
        "version": row["version"],
        "state": row["state"],
        "indexes": json.loads(row["indexes"]),
        "owner": row["owner"],
        "updated": row["updated"],
        "attribution": "explicit evidence-backed observation; not endpoint authorization",
    }


def _visible(db, actor, identifier):
    row = db.execute(
        "SELECT * FROM temporal_identity_bindings WHERE tenant=? AND id=?",
        (actor["tenant"], identifier),
    ).fetchone()
    if not row or not principal.contains(
        actor["allowed_indexes"], json.loads(row["indexes"])
    ):
        raise KeyError("Identity binding not found")
    return row


def save(store, who, data, identifier=None):
    allowed = {
        "kind",
        "lookup",
        "entity_id",
        "session_id",
        "valid_from",
        "valid_until",
        "evidence",
        "reason",
        "version",
        "translated",
    }
    if not isinstance(data, dict) or set(data) - allowed:
        raise ValueError("Unknown temporal identity property")
    kind = data.get("kind")
    value = lookup(kind, data.get("lookup"))
    start = evidence.number(data.get("valid_from"), "valid_from")
    end = evidence.number(data.get("valid_until"), "valid_until")
    if not start < end or end - start > 31 * 86400:
        raise ValueError("Identity validity must be positive and at most 31 days")
    entity_id = evidence.text(data.get("entity_id"), "entity_id")
    session = evidence.text(data.get("session_id", ""), "session_id", empty=True)
    reason = evidence.text(data.get("reason"), "reason", 2000)
    version = evidence.integer(data.get("version", 0), "version", 0, 2**31 - 1)
    translated = None
    if "translated" in data:
        if kind != "nat":
            raise ValueError("Translated tuples belong to NAT bindings only")
        translated = lookup("nat", data["translated"])
    refs = data.get("evidence")
    if not isinstance(refs, list) or not 1 <= len(refs) <= 32:
        raise ValueError("1..32 exact evidence observations are required")
    for ref in refs:
        if not isinstance(ref, dict) or set(ref) != {"event_id", "fields"}:
            raise ValueError("Evidence requires event_id and exact observed fields")
        if not isinstance(ref["fields"], dict) or not 1 <= len(ref["fields"]) <= 12:
            raise ValueError("Evidence requires 1..12 exact fields")
        evidence.text(ref["event_id"], "event_id")
    with principal.transaction(store, who, ("admin", "analyst")) as (db, actor):
        entity = entities._visible(db, actor, entity_id)
        if identifier:
            _visible(db, actor, identifier)
    records = evidence.originals(
        store, actor, list(dict.fromkeys(ref["event_id"] for ref in refs))
    )
    values = set(value.values()) if isinstance(value, dict) else {value}
    observed = set()
    snapshots = []
    for ref in refs:
        record = records[ref["event_id"]]
        if not start <= record["event_time"] < end:
            raise ValueError("Binding evidence must fall inside its validity interval")
        for path, expected in ref["fields"].items():
            actual = evidence.field(record, path)
            if (
                type(expected) not in (str, int, float, bool)
                or type(expected) is not type(actual)
                or actual != expected
            ):
                raise ValueError(
                    "Binding field claim does not match the original typed scalar"
                )
            observed.add(actual)
        snapshots.append({**evidence.reference(record), "fields": ref["fields"]})
    if not values <= observed:
        raise ValueError(
            "Every lookup tuple component must be present in original evidence"
        )
    if translated and not set(translated.values()) <= observed:
        raise ValueError(
            "Every translated tuple component must be present in original evidence"
        )
    anchor_fields = {
        "hostname": ("host", "raw.host.hostname", "raw.agent.hostname"),
        "device_id": ("raw.security.device_id", "raw.agent.id", "raw.device.id"),
        "username": ("raw.security.user", "raw.user", "raw.user.name"),
        "email": ("raw.security.user", "raw.user", "raw.user.email"),
        "ip": ("raw.security.src_ip", "raw.security.dest_ip", "raw.ip"),
    }
    if not any(
        evidence.field(record, path) == alias["value"]
        for record in records.values()
        for alias in entity["aliases"]
        for path in anchor_fields.get(alias["type"], ())
    ):
        raise ValueError(
            "Binding requires an original source observation of an explicit asset alias"
        )
    scope = sorted(
        set(entity["indexes"]) | {row["index_name"] for row in records.values()}
    )
    definition = {
        "kind": kind,
        "lookup": value,
        "entity_id": entity_id,
        "entity_version": entity["version"],
        "session_id": session,
        "valid_from": start,
        "valid_until": end,
        "evidence": snapshots,
        "reason": reason,
    }
    if translated:
        definition["translated"] = translated
    with principal.transaction(store, actor, ("admin", "analyst"), write=True) as (
        db,
        fresh,
    ):
        evidence.recheck(db, fresh, records)
        current_entity = entities._visible(db, fresh, entity_id)
        if current_entity["version"] != entity["version"]:
            raise ConflictError("Asset revision changed during source inspection")
        if not principal.contains(fresh["allowed_indexes"], scope):
            raise PermissionError(
                "Binding requires the complete asset and source index scope"
            )
        old = _visible(db, fresh, identifier) if identifier else None
        if (old["version"] if old else 0) != version:
            raise ConflictError("Identity binding version changed")
        # Durable inventory/history has no lifetime record-count ceiling.
        identifier = identifier or str(uuid.uuid4())
        now = time.time()
        db.execute(
            "INSERT INTO temporal_identity_bindings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET kind=excluded.kind,lookup_key=excluded.lookup_key,"
            "entity_id=excluded.entity_id,session_id=excluded.session_id,valid_from=excluded.valid_from,"
            "valid_until=excluded.valid_until,indexes=excluded.indexes,definition=excluded.definition,"
            "version=excluded.version,state=excluded.state,owner=excluded.owner,updated=excluded.updated",
            (
                identifier,
                fresh["tenant"],
                kind,
                encode(value),
                entity_id,
                session,
                start,
                end,
                encode(scope),
                encode(definition),
                version + 1,
                "active",
                fresh["name"],
                now,
            ),
        )
        row = _visible(db, fresh, identifier)
        db.execute(
            "INSERT INTO temporal_identity_history VALUES(?,?,?,?,?,?)",
            (
                identifier,
                fresh["tenant"],
                version + 1,
                fresh["name"],
                now,
                encode(_row(row)),
            ),
        )
        store.audit(
            db,
            fresh["tenant"],
            fresh["name"],
            "identity.binding.save",
            {"id": identifier, "version": version + 1, "kind": kind, "indexes": scope},
        )
        return _row(row)


def revoke(store, who, identifier, version, reason):
    version = evidence.integer(version, "version", 1, 2**31 - 1)
    reason = evidence.text(reason, "revocation reason", 2000)
    with principal.transaction(store, who, ("admin", "analyst"), write=True) as (
        db,
        actor,
    ):
        row = _visible(db, actor, identifier)
        if row["version"] != version:
            raise ConflictError("Identity binding version changed")
        if row["state"] == "revoked":
            raise ConflictError("Identity binding is already revoked")
        now = time.time()
        db.execute(
            "UPDATE temporal_identity_bindings SET state='revoked',version=version+1,updated=? WHERE id=?",
            (now, identifier),
        )
        result = _row(_visible(db, actor, identifier))
        db.execute(
            "INSERT INTO temporal_identity_history VALUES(?,?,?,?,?,?)",
            (
                identifier,
                actor["tenant"],
                version + 1,
                actor["name"],
                now,
                encode({**result, "revocation_reason": reason}),
            ),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "identity.binding.revoke",
            {"id": identifier, "version": version + 1, "reason": reason},
        )
        return result


def resolve(store, who, kind, value, at, session_id=None):
    value = lookup(kind, value)
    at = evidence.number(at, "at")
    if session_id is not None:
        session_id = evidence.text(session_id, "session_id")
    with principal.transaction(store, who) as (db, actor):
        rows = db.execute(
            "SELECT * FROM temporal_identity_bindings WHERE tenant=? AND kind=? AND lookup_key=? "
            "AND state='active' AND valid_from<=? AND valid_until>? ORDER BY entity_id,id",
            (actor["tenant"], kind, encode(value), at, at),
        ).fetchall()
        rows = [
            row for row in rows if session_id is None or row["session_id"] == session_id
        ]
        candidates = []
        unavailable = False
        for row in rows:
            if not principal.contains(
                actor["allowed_indexes"], json.loads(row["indexes"])
            ):
                unavailable = True
                continue
            try:
                entity = entities._visible(db, actor, row["entity_id"])
            except KeyError:
                unavailable = True
                continue
            if json.loads(row["definition"]).get("entity_version") != entity["version"]:
                unavailable = True
                continue
            candidates.append({"binding": _row(row), "entity": entity})
        unique = {row["entity"]["id"] for row in candidates}
        status = (
            "unresolved"
            if unavailable or not candidates
            else ("ambiguous" if len(unique) > 1 else "resolved")
        )
        return {
            "kind": kind,
            "lookup": value,
            "at": at,
            "session_id": session_id,
            "status": status,
            "entity_id": next(iter(unique)) if status == "resolved" else None,
            "candidates": candidates,
            "automatic_attribution": False,
            "meaning": "Exact time-bounded observations; unresolved requires more authorized evidence, ambiguity requires analyst review",
        }


def list_bindings(store, who, *, limit=100):
    evidence.integer(limit, "limit", 1, 500)
    with principal.transaction(store, who) as (db, actor):
        rows = db.execute(
            "SELECT * FROM temporal_identity_bindings WHERE tenant=? ORDER BY updated DESC,id",
            (actor["tenant"],),
        ).fetchall()
        # Durable inventory/history has no lifetime record-count ceiling.
        visible = [
            _row(row)
            for row in rows
            if principal.contains(actor["allowed_indexes"], json.loads(row["indexes"]))
        ]
        return {
            "items": visible,
            "total_visible": len(visible),
            "truncated": False,
        }


def history(store, who, identifier):
    with principal.transaction(store, who) as (db, actor):
        _visible(db, actor, identifier)
        rows = db.execute(
            "SELECT * FROM temporal_identity_history WHERE tenant=? AND id=? ORDER BY version",
            (actor["tenant"], identifier),
        ).fetchall()
        # Permanent execution/investigation history has no lifetime count ceiling.
        return [
            {**dict(row), "record": json.loads(row["record"])}
            for row in rows
            if principal.contains(
                actor["allowed_indexes"], json.loads(row["record"])["indexes"]
            )
        ]
