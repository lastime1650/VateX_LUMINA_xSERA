"""Managed tenant lookup snapshots and explicit, local threat-intel enrichment.

No file paths, URLs, feed fetches or executable lookup definitions are accepted.
Tables have unique string keys so an enrichment cannot multiply event rows.
"""

import copy
import ipaddress
import json
import math
import re
import time

from .query import QueryError
from .storage import ConflictError, encode

NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
KINDS = {"lookup", "ip", "domain", "hash"}


def name_checked(name):
    if (
        not isinstance(name, str)
        or not NAME.fullmatch(name)
        or name.startswith("__")
        or name.lower() == "tenant"
    ):
        raise ValueError(
            "Lookup names and columns must be simple, nonreserved identifiers"
        )
    return name


def normalize_indicator(kind, value):
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError("Indicator must be a nonempty string")
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("Invalid IP indicator") from exc
    if kind == "domain":
        try:
            domain = value.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("Invalid domain indicator") from exc
        if len(domain) > 253 or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in domain.split(".")
        ):
            raise ValueError("Invalid domain indicator")
        return domain
    if kind == "hash":
        if not re.fullmatch(
            r"(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})", value
        ):
            raise ValueError("Hash indicator must be MD5, SHA1 or SHA256 hex")
        return value.lower()
    if kind == "lookup":
        return value
    raise ValueError("Unknown threat-intel indicator kind")


def validate_rows(key, rows, columns=None, kind="lookup", provenance=""):
    name_checked(key)
    if not isinstance(kind, str) or kind not in KINDS:
        raise ValueError("Invalid lookup kind")
    if not isinstance(rows, list) or len(rows) > 10000:
        raise ValueError("Lookup must contain at most 10000 rows")
    if (
        not isinstance(provenance, str)
        or len(provenance) > 512
        or (kind != "lookup" and not provenance)
    ):
        raise ValueError("Threat-intel requires provenance of 1..512 characters")
    cleaned, seen = [], set()
    for row in rows:
        if not isinstance(row, dict) or key not in row or not 1 <= len(row) <= 20:
            raise ValueError("Every lookup row requires its key and at most 20 columns")
        row = dict(row)
        row[key] = normalize_indicator(kind, row[key])
        if row[key] in seen:
            raise ValueError("Lookup key values must be unique")
        seen.add(row[key])
        if kind != "lookup":
            confidence = row.get("confidence")
            if (
                isinstance(confidence, bool)
                or not isinstance(confidence, (int, float))
                or not 0 <= confidence <= 100
                or not math.isfinite(confidence)
            ):
                raise ValueError("Threat-intel confidence must be in 0..100")
            row.setdefault("provenance", provenance)
            if (
                not isinstance(row["provenance"], str)
                or not 1 <= len(row["provenance"]) <= 512
            ):
                raise ValueError("Invalid threat-intel row provenance")
        for column, value in row.items():
            name_checked(column)
            if not isinstance(value, (str, int, float, bool, type(None))):
                raise ValueError("Lookup cells must be scalar JSON values")  # noqa: TRY004 - invalid request data.
            if isinstance(value, str) and len(value) > 4096:
                raise ValueError("Lookup strings exceed 4096 characters")
            if (
                isinstance(value, (int, float))
                and not isinstance(value, bool)
                and (abs(value) > 1e100 or not math.isfinite(value))
            ):
                raise ValueError("Lookup numeric value outside supported range")
        cleaned.append(row)
    actual = {key, *(column for row in cleaned for column in row)}
    if columns is None:
        columns = [key, *sorted(actual - {key})]
    if not isinstance(columns, list) or not 1 <= len(columns) <= 20:
        raise ValueError("Lookup requires 1..20 unique scalar columns")
    for column in columns:
        name_checked(column)
    if len(set(columns)) != len(columns):
        raise ValueError("Lookup requires unique columns")
    if not actual <= set(columns):
        raise ValueError("Lookup row contains a column outside its schema")
    if (
        len(encode({"key": key, "columns": columns, "rows": cleaned}).encode("utf-8"))
        > 2 * 1024 * 1024
    ):
        raise ValueError("Lookup table exceeds 2 MiB")
    return cleaned, list(columns)


def validated_snapshot(table, now=None):
    if not isinstance(table, dict):
        raise ValueError("Lookup snapshot must be an object")  # noqa: TRY004 - invalid request data.
    now = time.time() if now is None else now
    expires = table.get("expires")
    kind = table.get("kind", "lookup")
    if expires is not None and (
        isinstance(expires, bool)
        or not isinstance(expires, (int, float))
        or abs(expires) > 1e100
        or not math.isfinite(expires)
    ):
        raise ValueError("Invalid lookup expiry")
    if (expires is not None and expires <= now) or (
        kind != "lookup" and expires is None
    ):
        raise QueryError("Managed lookup snapshot expired or has no expiry")
    return validate_rows(
        table.get("key"),
        table.get("rows"),
        table.get("columns"),
        kind,
        table.get("provenance", ""),
    )


def initialize(store):
    with store.control(local=True) as db:
        db.execute(
            """CREATE TABLE IF NOT EXISTS managed_lookups(
            tenant TEXT NOT NULL,name TEXT NOT NULL,owner TEXT NOT NULL,
            version INTEGER NOT NULL,lookup_key TEXT NOT NULL,columns TEXT NOT NULL,
            rows TEXT NOT NULL,kind TEXT NOT NULL,provenance TEXT NOT NULL,
            expires REAL,created REAL NOT NULL,updated REAL NOT NULL,
            PRIMARY KEY(tenant,name))"""
        )


def save(store, who, name, data):
    if who.get("role") != "admin":
        raise PermissionError("Lookup editing requires administrator")
    name_checked(name)
    if not isinstance(data, dict) or set(data) - {
        "key",
        "rows",
        "columns",
        "version",
        "expires",
        "kind",
        "provenance",
    }:
        raise ValueError("Unknown lookup property")
    version = data.get("version", 0)
    if type(version) is not int or version < 0:
        raise ValueError("Lookup version must be a nonnegative integer")
    kind, provenance = data.get("kind", "lookup"), data.get("provenance", "")
    rows, columns = validate_rows(
        data.get("key"), data.get("rows"), data.get("columns"), kind, provenance
    )
    now, expires = time.time(), data.get("expires")
    if expires is not None and (
        isinstance(expires, bool)
        or not isinstance(expires, (int, float))
        or abs(expires) > 1e100
        or not math.isfinite(expires)
        or expires <= now
    ):
        raise ValueError("Lookup expiry must be a finite future epoch timestamp")
    if kind != "lookup" and expires is None:
        raise ValueError("Threat-intel requires an explicit expiry")
    with store.write_lock, store.control() as db:
        db.execute("BEGIN IMMEDIATE")
        old = db.execute(
            "SELECT owner,version,created FROM managed_lookups WHERE tenant=? AND name=?",
            (who["tenant"], name),
        ).fetchone()
        if version != (old["version"] if old else 0):
            raise ConflictError("Lookup changed; refresh before saving")
        # Durable inventory/history has no lifetime record-count ceiling.
        db.execute(
            "INSERT INTO managed_lookups VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant,name) DO UPDATE SET version=excluded.version,lookup_key=excluded.lookup_key,columns=excluded.columns,rows=excluded.rows,kind=excluded.kind,provenance=excluded.provenance,expires=excluded.expires,updated=excluded.updated",
            (
                who["tenant"],
                name,
                old["owner"] if old else who["name"],
                version + 1,
                data["key"],
                encode(columns),
                encode(rows),
                kind,
                provenance,
                expires,
                old["created"] if old else now,
                now,
            ),
        )
        store.audit(
            db,
            who["tenant"],
            who["name"],
            "lookup.save",
            {"name": name, "version": version + 1, "rows": len(rows), "kind": kind},
        )
    return get(store, who["tenant"], name)


def _decoded(row):
    result = dict(row)
    result["key"] = result.pop("lookup_key")
    result["rows"] = json.loads(result["rows"])
    result["columns"] = json.loads(result["columns"])
    result["expired"] = (
        result["expires"] is not None and result["expires"] <= time.time()
    )
    return result


def get(store, tenant, name):
    name_checked(name)
    with store.control() as db:
        row = db.execute(
            "SELECT * FROM managed_lookups WHERE tenant=? AND name=?", (tenant, name)
        ).fetchone()
    if not row:
        raise KeyError("Lookup not found")
    return _decoded(row)


def list_for(store, who):
    with store.control() as db:
        rows = db.execute(
            "SELECT * FROM managed_lookups WHERE tenant=? ORDER BY name",
            (who["tenant"],),
        ).fetchall()
    result = []
    for row in rows:
        decoded = _decoded(row)
        decoded["row_count"] = len(decoded.pop("rows"))
        result.append(decoded)
    return result


def for_query(store, tenant, querybody):
    if isinstance(querybody, dict):
        if querybody.get("language", "spl") != "spl":
            return {}
        querybody = querybody.get("query", "")
    if not isinstance(querybody, str):
        return {}
    from .query import Query
    from .spl import lookup_spec

    query = Query.parse({"query": querybody})
    names = {lookup_spec(rest)[0] for cmd, rest in query.commands if cmd == "lookup"}
    tables = {}
    for name in sorted(names):
        try:
            table = get(store, tenant, name)
        except KeyError as exc:
            raise QueryError("Managed lookup unavailable: " + name) from exc
        if table["expired"]:
            raise QueryError("Managed lookup expired: " + name)
        tables[name] = table
    return tables


def threat_intel(kind, indicators, provenance, expires, confidence=80):
    if kind not in {"ip", "domain", "hash"} or not isinstance(indicators, list):
        raise ValueError("Threat-intel requires typed indicators")
    data = {
        "key": "indicator",
        "kind": kind,
        "provenance": provenance,
        "expires": expires,
        "rows": [
            {"indicator": value, "confidence": confidence, "provenance": provenance}
            for value in indicators
        ],
    }
    validate_rows(data["key"], data["rows"], kind=kind, provenance=provenance)
    return data


def prepare_threat_tables(tables, now=None):
    now = time.time() if now is None else now
    prepared = []
    for name, table in tables.items():
        if table.get("kind", "lookup") == "lookup":
            continue
        rows, _ = validated_snapshot(table, now)
        prepared.append(
            {
                "name": name,
                "kind": table["kind"],
                "expires": table["expires"],
                "indexed": {row[table["key"]]: row for row in rows},
            }
        )
    return prepared


def enrich_event(event, tables, fields=None, now=None, *, _prepared=None):
    """Return a copy with matched local indicators; never mutate source evidence."""
    now = time.time() if now is None else now
    fields = fields or {
        "ip": [
            "src_ip",
            "dest_ip",
            "ip",
            "raw.security.src_ip",
            "raw.security.dest_ip",
            "raw.xdr.data.source.ip",
            "raw.xdr.data.destination.ip",
        ],
        "domain": ["domain", "raw.xdr.data.dns.question.name"],
        "hash": ["hash", "file_hash", "raw.xdr.data.file.hash.sha256"],
    }
    result, matches = copy.deepcopy(event), []
    raw = result.get("raw", {})
    if not isinstance(raw, dict):
        raise ValueError("Threat enrichment requires object raw evidence")  # noqa: TRY004 - invalid event data.
    if "threat_intel" in raw:
        raise ValueError(
            "Threat enrichment must not overwrite original threat_intel evidence"
        )
    for prepared in (
        prepare_threat_tables(tables, now) if _prepared is None else _prepared
    ):
        name, kind, indexed = prepared["name"], prepared["kind"], prepared["indexed"]
        if prepared["expires"] <= now:
            raise QueryError("Prepared managed IOC feed expired")
        for field in fields.get(kind, []):
            if field.startswith("raw."):
                value = event
                for component in field.split("."):
                    value = value.get(component) if isinstance(value, dict) else None
            else:
                value = event.get(field, raw.get(field))
            if value is None:
                continue
            try:
                indicator = normalize_indicator(kind, value)
            except ValueError:
                continue
            row = indexed.get(indicator)
            if row:
                matches.append(
                    {
                        "lookup": name,
                        "kind": kind,
                        "indicator": indicator,
                        "field": field,
                        "confidence": row["confidence"],
                        "provenance": row["provenance"],
                        "expires": prepared["expires"],
                    }
                )
    raw["threat_intel"] = matches
    result["raw"] = raw
    return result
