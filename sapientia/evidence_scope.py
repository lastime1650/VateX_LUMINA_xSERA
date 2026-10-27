"""Shared bounded, immutable source references for operational analytics.

These proofs describe admitted telemetry. They do not authenticate the truth of
an upstream claim or authorize an endpoint command.
"""

import hashlib
import json
import math
import re
from contextlib import contextmanager, nullcontext
from contextvars import ContextVar
from copy import deepcopy

from . import access, principal
from .query import index_predicate
from .storage import ConflictError, encode

_ORIGINAL_TURN = ContextVar("xsera_original_turn", default=None)


def _actor_key(actor):
    return (
        actor["tenant"],
        actor["name"],
        actor["role"],
        tuple(actor["allowed_indexes"]),
    )


@contextmanager
def prefetch_transaction(store, db, actors_and_ids):
    """Internal immutable raw reuse for one reserved write/segment-read turn.

    Authority is never cached: every hit rechecks the caller, admission receipt,
    pinned source receipt and current source owner. The context is reset before
    leaving the transaction. Up to 1,056 unique originals per actor are loaded
    in one bounded query, or 32-record chunks only on the analytics result-size
    limit. An unavailable batch falls back to individual reads so one expired
    original cannot prevent later valid originals progressing.
    """
    if not db.in_transaction:
        raise ConflictError("Original prefetch requires a reserved transaction")
    token = _ORIGINAL_TURN.set(None)
    cache = {"store": store, "db": db, "actors": {}}
    try:
        for actor, event_ids in actors_and_ids:
            if not event_ids:
                continue
            event_ids = list(dict.fromkeys(event_ids))
            if len(event_ids) > 1056:
                raise ValueError("Transaction prefetch permits at most 1056 originals")
            try:
                try:
                    records = _load_originals(
                        store, actor, event_ids, db=db, maximum=1056
                    )
                except ValueError as exc:
                    if (
                        len(event_ids) <= 32
                        or str(exc) != "Result exceeds 2 MiB; reduce fields or limit"
                    ):
                        raise
                    records = {}
                    for offset in range(0, len(event_ids), 32):
                        records.update(
                            originals(
                                store, actor, event_ids[offset : offset + 32], db=db
                            )
                        )
                received = _source_receipts(db, actor, records)
                sources = {
                    identifier: dict(received[identifier])
                    if identifier in received
                    else None
                    for identifier in records
                }
                cache["actors"][_actor_key(actor)] = {
                    "records": records,
                    "sources": sources,
                }
            except (PermissionError, KeyError, ConflictError, ValueError):
                continue
        _ORIGINAL_TURN.set(cache)
        yield
    finally:
        _ORIGINAL_TURN.reset(token)


def _source_receipts(db, actor, event_ids):
    return {
        row["event_id"]: row
        for row in db.execute(
            "SELECT * FROM source_event_receipts WHERE tenant=? AND event_id IN "
            "(SELECT value FROM json_each(?))",
            (actor["tenant"], encode(list(event_ids))),
        ).fetchall()
    }


def _admission_receipts(db, actor, event_ids):
    return {
        row["event_id"]: row
        for row in db.execute(
            "SELECT event_id,digest,received FROM receipts WHERE tenant=? AND event_id IN "
            "(SELECT value FROM json_each(?))",
            (actor["tenant"], encode(list(event_ids))),
        ).fetchall()
    }


def _prefetched_records(store, actor, event_ids, *, db=None):
    cache = _ORIGINAL_TURN.get()
    if not cache or cache["store"] is not store:
        return None
    if db is not None and db is not cache["db"]:
        return None
    db = cache["db"]
    if not db.in_transaction:
        raise ConflictError("Original prefetch outlived its transaction")
    entry = cache["actors"].get(_actor_key(actor))
    if not entry or not set(event_ids) <= set(entry["records"]):
        return None
    if principal.current(db, actor) != actor:
        raise PermissionError("Permissions changed during prefetched source inspection")
    result = {identifier: entry["records"][identifier] for identifier in event_ids}
    recheck(db, actor, result)
    receipts = _source_receipts(db, actor, event_ids)
    source_ids = {row["source_id"] for row in receipts.values()}
    sources = (
        {
            row["id"]: row
            for row in db.execute(
                "SELECT * FROM source_registry WHERE tenant=? AND id IN "
                "(SELECT value FROM json_each(?))",
                (actor["tenant"], encode(sorted(source_ids))),
            ).fetchall()
        }
        if source_ids
        else {}
    )
    owners = {}
    for identifier in event_ids:
        current = receipts.get(identifier)
        expected = entry["sources"][identifier]
        if (dict(current) if current else None) != expected:
            raise ConflictError("Prefetched source receipt changed")
        if current is not None:
            source = sources.get(current["source_id"])
            if (
                not source
                or source["state"] != "active"
                or source["version"] != current["source_version"]
                or source["index_name"] != current["index_name"]
            ):
                raise ConflictError("Prefetched source authority changed")
            if source["owner"] not in owners:
                owners[source["owner"]] = principal.current(
                    db,
                    {
                        "name": source["owner"],
                        "tenant": source["tenant"],
                        "role": "analyst",
                    },
                    ("admin", "analyst"),
                )
            owner = owners[source["owner"]]
            if not principal.contains(owner["allowed_indexes"], [source["index_name"]]):
                raise PermissionError("Prefetched source owner scope changed")
    return result, cache


def _prefetched(store, actor, event_ids, *, db=None):
    value = _prefetched_records(store, actor, event_ids, db=db)
    return _copy_facts(value[0]) if value is not None else None


def _prefetched_reference_guard(store, db, actor, proofs):
    """Private fresh authority guard for an already replayed immutable raw turn.

    This returns only an opaque transaction binding, never borrowed raw facts.
    Every invocation executes the same principal/admission/source/owner checks
    as a normal prefetch hit. Exact raw reference hashes must still match.
    """
    ids = [proof["event_id"] for proof in proofs]
    if not ids or len(ids) > 1056 or len(set(ids)) != len(ids):
        raise ValueError("Bounded unique replay proofs required")
    value = _prefetched_records(store, actor, ids, db=db)
    if value is None:
        return None
    records, binding = value
    for proof in proofs:
        if any(proof.get(key) != item for key, item in reference(records[proof["event_id"]]).items()):
            raise ConflictError("Replayed raw reference changed within its transaction")
    return binding


def _copy_facts(value):
    """Copy actual JSON facts quickly without normalizing internal odd types."""
    pending, containers = [value], set()
    while pending:
        item = pending.pop()
        kind = type(item)
        if kind in (dict, list):
            if id(item) in containers:
                return deepcopy(value)
            containers.add(id(item))
        if kind is dict:
            if any(type(key) is not str for key in item):
                return deepcopy(value)
            pending.extend(item.values())
        elif kind is list:
            pending.extend(item)
        elif kind is float and not math.isfinite(item) or kind not in (str, int, float, bool, type(None)):
            return deepcopy(value)
    return json.loads(encode(value))


def text(value, label, maximum=256, *, empty=False):
    if (
        not isinstance(value, str)
        or (not empty and not value.strip())
        or len(value) > maximum
        or any(ord(c) < 32 for c in value)
    ):
        raise ValueError(f"{label} requires visible text, at most {maximum} characters")
    return value


def number(value, label, lower=0, upper=253402300799):
    if (
        type(value) not in (int, float)
        or not math.isfinite(value)
        or not lower <= value <= upper
    ):
        raise ValueError(f"{label} must be finite, within {lower}..{upper}")
    return float(value)


def integer(value, label, lower=0, upper=100):
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError(f"{label} must be an integer within {lower}..{upper}")
    return value


def choice(value, choices, label):
    if not isinstance(value, str) or value not in choices:
        raise ValueError(f"Unsupported {label}")
    return value


def indexes(value):
    result = access.validate(value)
    if not result or result == ["*"] or len(result) > 64:
        raise ValueError("Explicit 1..64 exact indexes are required")
    return result


def field(record, path):
    if not isinstance(path, str) or not re.fullmatch(
        r"(?:event_id|event_time|host|source|sourcetype|severity|message|index_name|raw(?:\.[A-Za-z_][A-Za-z0-9_]{0,63}){1,8})",
        path,
    ):
        raise ValueError("An exact bounded scalar event field is required")
    current = record
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return (
        current if type(current) in (str, int, float, bool) or current is None else None
    )


def originals(store, actor, event_ids, *, db=None):
    """Read raw facts and verify current admissions, optionally in a caller TX.

    A supplied connection must already hold a transaction. No authority result
    escapes this call; receipts and principals are read again on every reuse.
    """
    if not isinstance(event_ids, list) or not 1 <= len(event_ids) <= 32:
        raise ValueError("1..32 unique source event IDs are required")
    return _load_originals(store, actor, event_ids, db=db)


def originals_many(store, actor, event_ids, *, db=None):
    """Internal bulk facts, with the same fresh authority contract as originals.

    This does not extend the public 32-original signal contract. Large raw
    results fall back only on the analytics byte ceiling, never on authority
    errors. Every cache hit rechecks current receipts, callers and sources.
    """
    try:
        return _load_originals(store, actor, event_ids, db=db, maximum=1056)
    except ValueError as exc:
        if str(exc)!="Result exceeds 2 MiB; reduce fields or limit" or len(event_ids)<=32:
            raise
        records={}
        for offset in range(0,len(event_ids),32):
            records.update(originals(store,actor,event_ids[offset:offset+32],db=db))
        return records


def _load_originals(store, actor, event_ids, *, db=None, maximum=32):
    """Private bounded raw-fact load; public calls retain their 32-ID contract."""
    if not isinstance(event_ids, list) or not 1 <= len(event_ids) <= maximum <= 1056:
        raise ValueError("Internal raw load requires 1..1056 bounded original IDs")
    for item in event_ids:
        text(item, "event_id")
    if len(set(event_ids)) != len(event_ids):
        raise ValueError("Source event IDs must be unique")
    turn = _ORIGINAL_TURN.get()
    if db is None and turn and turn["store"] is store:
        # A failed prefetch must not inspect authority through another control
        # connection that cannot see mutations in this reserved transaction.
        db = turn["db"]
    if db is not None and not db.in_transaction:
        raise ConflictError("Source inspection requires a reserved transaction")
    cached = _prefetched(store, actor, event_ids, db=db)
    if cached is not None:
        return cached
    scope, args = index_predicate(actor["allowed_indexes"])
    result = store.analytics_query(
        "SELECT event_id,event_time,source,sourcetype,host,severity,message,index_name,raw,received "
        "FROM events_all WHERE tenant=? AND "
        + scope
        + " AND event_id IN (SELECT value->>'$' FROM json_each(?)) ORDER BY event_id",
        [actor["tenant"], *args, encode(event_ids)],
        timeout=min(5, store.settings.query_timeout),
        max_rows=maximum,
    )
    if len(result["rows"]) != len(event_ids):
        raise KeyError("Source evidence unavailable in the current index scope")
    records = {}
    with nullcontext(db) if db is not None else store.control() as connection:
        fresh = principal.current(connection, actor)
        if fresh != actor:
            raise PermissionError("Permissions changed during source inspection")
        proofs = _admission_receipts(connection, actor, event_ids)
        for row in result["rows"]:
            proof = proofs.get(row["event_id"])
            if not proof or proof["received"] != row["received"]:
                raise ConflictError("Source admission receipt unavailable or changed")
            record = dict(row)
            record["raw"] = (
                json.loads(record["raw"])
                if isinstance(record["raw"], str)
                else record["raw"]
            )
            record["admission_digest"] = proof["digest"]
            record["record_digest"] = hashlib.sha256(encode(row).encode()).hexdigest()
            records[row["event_id"]] = record
    return records


def recheck(db, actor, records):
    proofs = _admission_receipts(db, actor, records)
    for item in records.values():
        if not principal.contains(actor["allowed_indexes"], [item["index_name"]]):
            raise PermissionError("Source index permission changed")
        proof = proofs.get(item["event_id"])
        if (
            not proof
            or proof["digest"] != item["admission_digest"]
            or proof["received"] != item["received"]
        ):
            raise ConflictError(
                "Source evidence expired or changed during the operation"
            )


def reference(record):
    return {
        key: record[key]
        for key in (
            "event_id",
            "event_time",
            "index_name",
            "received",
            "admission_digest",
            "record_digest",
        )
    }
