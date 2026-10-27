"""Explicit entity inventory and event-backed co-observation, never attribution guesses."""

import hashlib
import ipaddress
import json
import math
import time
import uuid

from . import access, principal
from .query import index_predicate
from .storage import CapacityError, ConflictError, encode

EDITORS = ("admin", "analyst")
ALIAS_TYPES = {
    "user": {"username", "email"},
    "host": {"hostname", "ip", "device_id"},
    "ip": {"ip"},
    "device": {"device_id", "hostname", "ip"},
}
FIELDS = {
    "username": ["json_extract_string(raw,'$.security.user')"],
    "email": ["json_extract_string(raw,'$.security.user')"],
    "hostname": ["host"],
    "ip": [
        "json_extract_string(raw,'$.security.src_ip')",
        "json_extract_string(raw,'$.security.dest_ip')",
    ],
    "device_id": ["json_extract_string(raw,'$.security.device_id')"],
}


def initialize(store):
    with store.control(local=True) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS entity_inventory(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,kind TEXT NOT NULL,
          name TEXT NOT NULL,indexes TEXT NOT NULL,criticality INTEGER NOT NULL,
          tags TEXT NOT NULL,version INTEGER NOT NULL,created REAL NOT NULL,updated REAL NOT NULL);
        CREATE INDEX IF NOT EXISTS entity_inventory_tenant ON entity_inventory(tenant,id);
        CREATE TABLE IF NOT EXISTS entity_aliases(
          tenant TEXT NOT NULL,type TEXT NOT NULL,value TEXT NOT NULL,entity_id TEXT NOT NULL,
          PRIMARY KEY(tenant,type,value));
        CREATE INDEX IF NOT EXISTS entity_alias_entity ON entity_aliases(tenant,entity_id);
        """)


def _text(value, label, maximum=256):
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > maximum
        or any(ord(c) < 32 for c in value)
    ):
        raise ValueError(f"{label} requires 1..{maximum} visible characters")
    return value


def exact_indexes(value):
    result = access.validate(value)
    if not result or result == ["*"] or len(result) > 64:
        raise ValueError("Explicit 1..64 exact indexes are required")
    return sorted(set(result))


def window(start, end):
    for item in (start, end):
        if (
            isinstance(item, bool)
            or not isinstance(item, (int, float))
            or not math.isfinite(item)
            or not 0 <= item <= 253402300799
        ):
            raise ValueError("Window requires finite nonnegative epoch seconds")
    if not start < end or end - start > 366 * 86400:
        raise ValueError("Window must be positive and at most 366 days")
    return float(start), float(end)


def deadline(store):
    return time.monotonic() + min(10, store.settings.query_timeout)


def query(store, sql, args, until, max_rows=1000, cancel=None):
    remaining = until - time.monotonic()
    if remaining <= 0:
        raise CapacityError("Entity/behavior operation deadline exceeded")
    return store.analytics_query(
        sql, args, timeout=remaining, max_rows=max_rows, cancel=cancel
    )


def _aliases(db, tenant, entity_id):
    return [
        dict(row)
        for row in db.execute(
            "SELECT type,value FROM entity_aliases WHERE tenant=? AND entity_id=? ORDER BY type,value",
            (tenant, entity_id),
        )
    ]


def _visible(db, actor, entity_id):
    row = db.execute(
        "SELECT * FROM entity_inventory WHERE tenant=? AND id=?",
        (actor["tenant"], entity_id),
    ).fetchone()
    if not row or not principal.contains(
        actor["allowed_indexes"], json.loads(row["indexes"])
    ):
        raise KeyError("Entity not found")
    result = dict(row)
    result["indexes"], result["tags"] = (
        json.loads(result["indexes"]),
        json.loads(result["tags"]),
    )
    result["aliases"] = _aliases(db, actor["tenant"], entity_id)
    return result


def save(store, who, data, entity_id=None):
    if not isinstance(data, dict) or set(data) - {
        "kind",
        "name",
        "indexes",
        "criticality",
        "tags",
        "aliases",
        "version",
    }:
        raise ValueError("Unknown entity property")
    kind = data.get("kind")
    if not isinstance(kind, str) or kind not in ALIAS_TYPES:
        raise ValueError("Entity kind must be user, host, ip or device")
    name, indexes = _text(data.get("name"), "name"), exact_indexes(data.get("indexes"))
    criticality, version = data.get("criticality", 3), data.get("version", 0)
    if (
        type(criticality) is not int
        or not 1 <= criticality <= 5
        or type(version) is not int
        or version < 0
    ):
        raise ValueError("Criticality must be 1..5 and version nonnegative integers")
    tags = data.get("tags", [])
    if not isinstance(tags, list) or len(tags) > 20:
        raise ValueError("At most 20 tags are allowed")
    tags = sorted({_text(tag, "tag", 64) for tag in tags})
    aliases = data.get("aliases")
    if not isinstance(aliases, list) or not 1 <= len(aliases) <= 32:
        raise ValueError("1..32 explicitly typed aliases are required")
    checked = set()
    for alias in aliases:
        if (
            not isinstance(alias, dict)
            or set(alias) != {"type", "value"}
            or not isinstance(alias["type"], str)
            or alias["type"] not in ALIAS_TYPES[kind]
        ):
            raise ValueError("Alias type is not valid for this entity kind")
        value = _text(alias["value"], "alias")
        if alias["type"] == "ip":
            value = str(ipaddress.ip_address(value))
        checked.add((alias["type"], value))
    now = time.time()
    with principal.transaction(store, who, EDITORS, write=True) as (db, actor):
        if not principal.contains(actor["allowed_indexes"], indexes):
            raise PermissionError("Entity indexes exceed current permissions")
        old = _visible(db, actor, entity_id) if entity_id else None
        if version != (old["version"] if old else 0):
            raise ConflictError("Entity changed; refresh before saving")
        if old and old["kind"] != kind:
            raise ValueError("Entity kind is immutable")
        # Durable inventory/history has no lifetime record-count ceiling.
        entity_id = entity_id or str(uuid.uuid4())
        for alias_type, value in checked:
            # security.user carries an explicit identity but no email/username subtype.
            # Reject cross-subtype ambiguity instead of guessing which user it denotes.
            types = (
                ("username", "email")
                if alias_type in ("username", "email")
                else (alias_type,)
            )
            found = db.execute(
                "SELECT entity_id FROM entity_aliases WHERE tenant=? AND value=? AND type IN ("
                + ",".join("?" for _ in types)
                + ")",
                (actor["tenant"], value, *types),
            ).fetchall()
            if any(row[0] != entity_id for row in found):
                raise ConflictError(
                    "Alias is ambiguous; resolve the existing mapping first"
                )
        db.execute(
            "INSERT INTO entity_inventory VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,indexes=excluded.indexes,criticality=excluded.criticality,tags=excluded.tags,version=excluded.version,updated=excluded.updated",
            (
                entity_id,
                actor["tenant"],
                old["owner"] if old else actor["name"],
                kind,
                name,
                encode(indexes),
                criticality,
                encode(tags),
                version + 1,
                old["created"] if old else now,
                now,
            ),
        )
        db.execute(
            "DELETE FROM entity_aliases WHERE tenant=? AND entity_id=?",
            (actor["tenant"], entity_id),
        )
        db.executemany(
            "INSERT INTO entity_aliases VALUES(?,?,?,?)",
            [
                (actor["tenant"], key, value, entity_id)
                for key, value in sorted(checked)
            ],
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "entity.save",
            {"id": entity_id, "version": version + 1, "indexes": indexes},
        )
        return _visible(db, actor, entity_id)


def get(store, who, entity_id):
    with principal.transaction(store, who) as (db, actor):
        return _visible(db, actor, entity_id)


def list_entities(store, who):
    with principal.transaction(store, who) as (db, actor):
        ids = db.execute(
            "SELECT id,indexes FROM entity_inventory WHERE tenant=? ORDER BY name,id",
            (actor["tenant"],),
        ).fetchall()
        # Durable inventory/history has no lifetime record-count ceiling.
        return [
            _visible(db, actor, row["id"])
            for row in ids
            if principal.contains(actor["allowed_indexes"], json.loads(row["indexes"]))
        ]


def resolve(store, who, alias_type, value):
    if not isinstance(alias_type, str) or alias_type not in FIELDS:
        raise ValueError("Unsupported alias type")
    value = _text(value, "alias")
    if alias_type == "ip":
        value = str(ipaddress.ip_address(value))
    with principal.transaction(store, who) as (db, actor):
        row = db.execute(
            "SELECT entity_id FROM entity_aliases WHERE tenant=? AND type=? AND value=?",
            (actor["tenant"], alias_type, value),
        ).fetchone()
        if not row:
            raise KeyError("Entity not found")
        return _visible(db, actor, row[0])


def priority_context(store, who, entity_field, entity, evidence_score):
    """Explicit inventory criticality overlay; never a threat probability."""
    alias = {
        "host": "hostname",
        "raw.security.user": "username",
        "raw.security.src_ip": "ip",
        "raw.security.dest_ip": "ip",
    }.get(entity_field)
    if alias is None:
        return None
    try:
        registered = resolve(store, who, alias, entity)
    except KeyError:
        return None
    criticality = registered["criticality"]
    return {
        "inventory_id": registered["id"],
        "criticality": criticality,
        "source": "explicit_authorized_entity_inventory",
        "evidence_score": evidence_score,
        "operational_priority": round(
            min(100, max(0, evidence_score * (1 + 0.1 * (criticality - 3)))), 2
        ),
        "formula": "min(100,max(0,evidence_score*(1+0.1*(criticality-3))))",
        "meaning": "Configured asset importance overlay; separate from case evidence score and probability",
    }


def timeline(store, who, entity_id, start, end, limit=100, cancel=None):
    start, end = window(start, end)
    if type(limit) is not int or not 1 <= limit <= 500:
        raise ValueError("Timeline limit must be 1..500")
    with principal.transaction(store, who) as (db, actor):
        entity = _visible(db, actor, entity_id)
    until, conditions, values = deadline(store), [], []
    for alias in entity["aliases"]:
        for field in FIELDS[alias["type"]]:
            conditions.append(field + "=?")
            values.append(alias["value"])
    predicate, indexes = index_predicate(entity["indexes"])
    where = (
        "tenant=? AND event_time>=? AND event_time<? AND "
        + predicate
        + " AND ("
        + " OR ".join(conditions)
        + ")"
    )
    args = [actor["tenant"], start, end, *indexes, *values]
    rows = query(
        store,
        "SELECT event_id,event_time,index_name,source,host,severity,substr(message,1,512) AS message,count(*) OVER() AS window_total FROM events_all WHERE "
        + where
        + " ORDER BY event_time,event_id LIMIT ?",
        [*args, limit],
        until,
        limit,
        cancel,
    )["rows"]
    total = rows[0]["window_total"] if rows else 0
    for row in rows:
        row.pop("window_total")
    principal.recheck(store, actor)
    return {
        "entity": entity,
        "start": start,
        "end": end,
        "total": total,
        "events": rows,
        "truncated": total > len(rows),
        "evidence_limit": limit,
    }


def graph(store, who, start, end, limit=100, cancel=None):
    """Count exact co-observation in a bounded authorized window; not network flow."""
    start, end = window(start, end)
    if type(limit) is not int or not 1 <= limit <= 500:
        raise ValueError("Graph node limit must be 1..500")
    with principal.transaction(store, who) as (db, actor):
        inventory = {}
        entries = db.execute(
            "SELECT id,indexes FROM entity_inventory WHERE tenant=?",
            (actor["tenant"],),
        ).fetchall()
        # Durable inventory/history has no lifetime record-count ceiling.
        for row in entries:
            if principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
                entry = _visible(db, actor, row["id"])
                for alias in entry["aliases"]:
                    inventory[(alias["type"], alias["value"])] = entry
    predicate, indexes = index_predicate(actor["allowed_indexes"])
    until = deadline(store)
    result = query(
        store,
        "SELECT event_id,event_time,index_name,host,json_extract_string(raw,'$.security.user') AS username,json_extract_string(raw,'$.security.src_ip') AS src_ip,json_extract_string(raw,'$.security.dest_ip') AS dest_ip,json_extract_string(raw,'$.security.device_id') AS device_id FROM events_all WHERE tenant=? AND event_time>=? AND event_time<? AND "
        + predicate
        + " ORDER BY event_time,event_id",
        [actor["tenant"], start, end, *indexes],
        until,
        10000,
        cancel,
    )
    nodes, edges = {}, {}
    for event in result["rows"]:
        if time.monotonic() >= until or (
            cancel and (cancel() if callable(cancel) else cancel.is_set())
        ):
            raise CapacityError("Graph cancelled or deadline exceeded")
        present = set()
        observations = [
            ("hostname", event["host"]),
            ("username", event["username"]),
            ("ip", event["src_ip"]),
            ("ip", event["dest_ip"]),
            ("device_id", event["device_id"]),
        ]
        for alias_type, value in observations:
            if not value or (alias_type == "hostname" and value == "unknown"):
                continue
            _text(value, "observed identity")
            if alias_type == "ip":
                try:
                    value = str(ipaddress.ip_address(value))
                except ValueError:
                    continue
            entry = inventory.get((alias_type, value))
            if alias_type == "username":
                email = inventory.get(("email", value))
                if entry and email and entry["id"] != email["id"]:
                    raise ConflictError("Observed identity has ambiguous aliases")
                entry = entry or email
            if entry and event["index_name"] not in entry["indexes"]:
                entry = None
            node_id = (
                entry["id"]
                if entry
                else "observed:"
                + hashlib.sha256(encode([alias_type, value]).encode()).hexdigest()
            )
            nodes.setdefault(
                node_id,
                {
                    "id": node_id,
                    "type": entry["kind"] if entry else alias_type,
                    "name": entry["name"] if entry else value,
                    "registered": bool(entry),
                    "criticality": entry["criticality"] if entry else None,
                    "tags": entry["tags"] if entry else [],
                },
            )
            present.add(node_id)
        if len(nodes) > limit:
            raise CapacityError("Graph node bound exceeded; narrow the window")
        ordered = sorted(present)
        for i, left in enumerate(ordered):
            for right in ordered[i + 1 :]:
                item = edges.setdefault(
                    (left, right),
                    {
                        "source": left,
                        "target": right,
                        "relation": "co_observed",
                        "count": 0,
                        "first": event["event_time"],
                        "last": event["event_time"],
                        "evidence": [],
                    },
                )
                item["count"] += 1
                item["last"] = event["event_time"]
                if len(item["evidence"]) < 5:
                    item["evidence"].append(
                        {
                            "event_id": event["event_id"],
                            "index": event["index_name"],
                            "event_time": event["event_time"],
                        }
                    )
        if len(edges) > 1000:
            raise CapacityError("Graph edge bound exceeded; narrow the window")
    principal.recheck(store, actor)
    return {
        "start": start,
        "end": end,
        "matched_events": result["returned"],
        "nodes": list(nodes.values()),
        "edges": list(edges.values()),
        "relation_semantics": "Explicit fields co-observed in the same event; no ownership, causation or network connection inferred",
        "event_bound": 10000,
        "evidence_limit_per_edge": 5,
        "complete_counts": True,
    }
