"""Versioned JSON mappings, explicit redaction and durable failure quarantine.

This is a bounded mapping language, not arbitrary code, regex or vendor parsers.
Receipt identity is computed from the original collector content by Store.
"""

import copy
import hashlib
import json
import re
import shutil
import time

from . import normalization, principal
from .storage import CapacityError, ConflictError, encode, normalize

MAX_QUARANTINE_EVENTS = 1000
MAX_QUARANTINE_BYTES = 32 * 1024 * 1024
PATH = re.compile(r"raw(?:\.[A-Za-z_][A-Za-z0-9_]{0,63}){1,5}\Z")


def initialize(store):
    with store.control(local=True) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS parser_policies(
          tenant TEXT NOT NULL,name TEXT NOT NULL,owner TEXT NOT NULL,source TEXT NOT NULL,
          definition TEXT NOT NULL,enabled INTEGER NOT NULL,version INTEGER NOT NULL,
          digest TEXT NOT NULL,updated REAL NOT NULL,PRIMARY KEY(tenant,name));
        CREATE UNIQUE INDEX IF NOT EXISTS parser_source ON parser_policies(tenant,source) WHERE enabled=1;
        CREATE TABLE IF NOT EXISTS parser_revisions(
          tenant TEXT NOT NULL,name TEXT NOT NULL,version INTEGER NOT NULL,
          definition TEXT NOT NULL,digest TEXT NOT NULL,actor TEXT NOT NULL,at REAL NOT NULL,
          PRIMARY KEY(tenant,name,version));
        CREATE TABLE IF NOT EXISTS ingest_quarantine(
          tenant TEXT NOT NULL,event_id TEXT NOT NULL,index_name TEXT NOT NULL,
          source TEXT NOT NULL,payload TEXT NOT NULL,received REAL NOT NULL,
          policy_name TEXT NOT NULL,policy_version INTEGER NOT NULL,reason TEXT NOT NULL,
          attempts INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(tenant,event_id));
        CREATE INDEX IF NOT EXISTS quarantine_recent ON ingest_quarantine(tenant,received,event_id);
        """)


def _full(actor):
    if actor["allowed_indexes"] != ["*"]:
        raise PermissionError(
            "Ingestion configuration requires full tenant index access"
        )


def _path(value):
    if value != "message" and (not isinstance(value, str) or not PATH.fullmatch(value)):
        raise ValueError(
            "Mapping paths must be message or a raw scalar path of depth 1..5"
        )
    return value


def _value(record, path):
    value = record
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _set(record, path, value, *, overwrite):
    parts, cursor = path.split("."), record
    for part in parts[:-1]:
        if part not in cursor:
            cursor[part] = {}
        if not isinstance(cursor[part], dict):
            raise ValueError("Mapping target conflicts with an existing scalar")  # noqa: TRY004 - Invalid JSON mapping is HTTP 400.
        cursor = cursor[part]
    if overwrite or parts[-1] not in cursor:
        cursor[parts[-1]] = copy.deepcopy(value)


def validate(data):
    allowed = {
        "source",
        "sourcetype",
        "route_index",
        "mappings",
        "redact_fields",
        "required_fields",
        "decode_message_json",
        "on_failure",
        "enabled",
    }
    if not isinstance(data, dict) or set(data) - allowed:
        raise ValueError("Unknown parser policy property")
    source = data.get("source")
    if not isinstance(source, str) or not 1 <= len(source) <= 256:
        raise ValueError("An exact source name is required")
    result = {
        "source": source,
        "sourcetype": data.get("sourcetype"),
        "route_index": data.get("route_index"),
        "mappings": data.get("mappings", {}),
        "redact_fields": data.get("redact_fields", []),
        "required_fields": data.get("required_fields", []),
        "decode_message_json": data.get("decode_message_json", False),
        "on_failure": data.get("on_failure", "quarantine"),
        "enabled": data.get("enabled", True),
    }
    if result["sourcetype"] is not None and (
        not isinstance(result["sourcetype"], str)
        or not 1 <= len(result["sourcetype"]) <= 256
    ):
        raise ValueError("Invalid exact sourcetype")
    if result["route_index"] is not None and (
        not isinstance(result["route_index"], str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", result["route_index"])
    ):
        raise ValueError("Invalid route_index")
    if (
        type(result["enabled"]) is not bool
        or type(result["decode_message_json"]) is not bool
        or not isinstance(result["on_failure"], str)
        or result["on_failure"] not in {"quarantine", "reject"}
    ):
        raise ValueError("Invalid enabled/decode flag or on_failure")
    if not isinstance(result["mappings"], dict) or len(result["mappings"]) > 32:
        raise ValueError("At most 32 field mappings are supported")
    for target, origin in result["mappings"].items():
        _path(target)
        _path(origin)
        if target == "message" or target.startswith("raw._sapientia_pipeline"):
            raise ValueError(
                "Mapping targets must be raw fields outside pipeline provenance"
            )
    for name in ("redact_fields", "required_fields"):
        if (
            not isinstance(result[name], list)
            or len(result[name]) > 32
            or any(not isinstance(path, str) for path in result[name])
            or len(set(result[name])) != len(result[name])
        ):
            raise ValueError(f"{name} must contain at most 32 unique paths")
        for path in result[name]:
            _path(path)
    if len(encode(result).encode()) > 16384:
        raise ValueError("Parser policy exceeds 16 KiB")
    return result


def save(store, who, name, data):
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name):
        raise ValueError("Invalid parser policy name")
    if (
        not isinstance(data, dict)
        or set(data) != {"version", "definition"}
        or type(data["version"]) is not int
        or data["version"] < 0
    ):
        raise ValueError("Expected nonnegative version and definition")
    definition = validate(data["definition"])
    digest = hashlib.sha256(encode(definition).encode()).hexdigest()
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        _full(actor)
        old = db.execute(
            "SELECT version FROM parser_policies WHERE tenant=? AND name=?",
            (actor["tenant"], name),
        ).fetchone()
        if (old[0] if old else 0) != data["version"]:
            raise ConflictError("Parser policy version changed")
        # Durable inventory/history has no lifetime record-count ceiling.
        if (
            definition["enabled"]
            and db.execute(
                "SELECT 1 FROM parser_policies WHERE tenant=? AND source=? AND enabled=1 AND name!=?",
                (actor["tenant"], definition["source"], name),
            ).fetchone()
        ):
            raise ConflictError(
                "Only one enabled parser policy per exact source is allowed"
            )
        version, now = data["version"] + 1, time.time()
        db.execute(
            "INSERT INTO parser_policies VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant,name) DO UPDATE SET owner=excluded.owner,source=excluded.source,definition=excluded.definition,enabled=excluded.enabled,version=excluded.version,digest=excluded.digest,updated=excluded.updated",
            (
                actor["tenant"],
                name,
                actor["name"],
                definition["source"],
                encode(definition),
                int(definition["enabled"]),
                version,
                digest,
                now,
            ),
        )
        db.execute(
            "INSERT INTO parser_revisions VALUES(?,?,?,?,?,?,?)",
            (
                actor["tenant"],
                name,
                version,
                encode(definition),
                digest,
                actor["name"],
                now,
            ),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "parser.save",
            {"name": name, "version": version, "digest": digest},
        )
    return {
        "name": name,
        "version": version,
        "digest": digest,
        "definition": definition,
    }


def list_for(store, who):
    with principal.transaction(store, who, ("admin", "analyst")) as (db, actor):
        _full(actor)
        return [
            {**dict(row), "definition": json.loads(row["definition"])}
            for row in db.execute(
                "SELECT * FROM parser_policies WHERE tenant=? ORDER BY name",
                (actor["tenant"],),
            )
        ]


def for_ingest(db, tenant):
    return {
        row["source"]: {
            "name": row["name"],
            "version": row["version"],
            "digest": row["digest"],
            "definition": json.loads(row["definition"]),
        }
        for row in db.execute(
            "SELECT * FROM parser_policies WHERE tenant=? AND enabled=1 ORDER BY name",
            (tenant,),
        )
    }


def _sensitive_values(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from _sensitive_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _sensitive_values(item)
    elif value is not None and value != "[REDACTED]":
        yield value


def _sanitize_duplicates(value, secrets, replacements, encoded_depth=0):
    if isinstance(value, dict):
        return {
            _sanitize_duplicates(
                key, [], replacements, encoded_depth
            ): _sanitize_duplicates(item, secrets, replacements, encoded_depth)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            _sanitize_duplicates(item, secrets, replacements, encoded_depth)
            for item in value
        ]
    if any(type(value) is type(secret) and value == secret for secret in secrets):
        return "[REDACTED]"
    if isinstance(value, str) and replacements is not None:
        # JSON permits many spellings of the same scalar (mixed Unicode escapes,
        # escaped slashes and nested JSON strings). Scrub decoded quoted spans
        # even inside a syslog prefix; literal replacement alone misses these.
        if '"' in value:
            if encoded_depth >= 8:
                return "[REDACTED]"
            decoder, parts, offset, inspected = json.JSONDecoder(), [], 0, 0
            while (start := value.find('"', offset)) >= 0:
                inspected += 1
                if inspected > 2048:
                    return (
                        "[REDACTED]"  # Bound work without leaving an unchecked suffix.
                    )
                try:
                    decoded, end = decoder.raw_decode(value, start)
                except (ValueError, RecursionError):
                    parts.append(value[offset : start + 1])
                    offset = start + 1
                    continue
                sanitized = _sanitize_duplicates(
                    decoded, secrets, replacements, encoded_depth + 1
                )
                parts.append(value[offset:start])
                parts.append(
                    json.dumps(sanitized, ensure_ascii=False)
                    if sanitized != decoded
                    else value[start:end]
                )
                offset = end
            parts.append(value[offset:])
            value = "".join(parts)
        value = replacements.sub("[REDACTED]", value)
    return value


def _redact(record, paths):
    """Redact selected values and their raw/message copies, including JSON escapes.

    This is explicit value redaction, not automatic PII classification. Original
    receipt hashes remain independent; neither they nor envelope routing change.
    """
    secrets = [
        item for path in paths for item in _sensitive_values(_value(record, path))
    ]
    if "message" in paths:
        try:
            decoded = json.loads(record["message"].removeprefix("- "))
        except (ValueError, RecursionError):
            decoded = None
        secrets.extend(_sensitive_values(decoded))
    replacements = set()
    for value in secrets:
        if isinstance(value, str):
            if value:
                replacements.add(value)
                replacements.add(json.dumps(value, ensure_ascii=True)[1:-1])
                replacements.add(json.dumps(value, ensure_ascii=False)[1:-1])
        elif type(value) in (int, float, bool):
            replacements.add(json.dumps(value))
    replacements = sorted(
        (item for item in replacements if item), key=lambda item: (-len(item), item)
    )
    replacements = (
        re.compile("|".join([*(re.escape(item) for item in replacements), r"\[REDACTED\]"]))
        if replacements
        else None
    )
    record["raw"] = _sanitize_duplicates(record["raw"], secrets, replacements)
    record["message"] = _sanitize_duplicates(record["message"], secrets, replacements)
    for path in paths:
        if _value(record, path) is not None:
            _set(record, path, "[REDACTED]", overwrite=True)


def _clear_derived_security(record):
    security = record["raw"].get("security")
    if not isinstance(security, dict):
        return
    # Store normalized this object before policies ran. Drop calculated fields
    # before remapping so overwrite=False cannot silently retain stale identity.
    keep = {
        name: security[name]
        for name in security.get("unverified_fields", [])
        if name in security
    }
    if keep:
        record["raw"]["security"] = keep
    else:
        record["raw"].pop("security", None)


def apply(record, policy):
    """Return sanitized record and explicit failures; do not write any state."""
    if not policy or (
        policy["definition"]["sourcetype"] is not None
        and record["sourcetype"] != policy["definition"]["sourcetype"]
    ):
        return record, []
    result, definition, errors = copy.deepcopy(record), policy["definition"], []
    if not isinstance(result["raw"], dict):
        raise ValueError("Managed parser policies require a JSON object in raw")  # noqa: TRY004 - Invalid event input is HTTP 400.
    # Decode only in memory before erasing serialized copies. Redaction then
    # covers both decoded fields and all derived/raw/message copies, including
    # quarantine failures. No original payload copy is stored in that path.
    if definition["decode_message_json"]:
        try:
            decoded = json.loads(result["message"])
            if not isinstance(decoded, dict):
                raise ValueError()  # noqa: TRY004 - Common parser failure becomes a quarantined event.
            _set(result, "raw.parsed", decoded, overwrite=False)
        except (ValueError, RecursionError):
            errors.append("message is not a bounded JSON object")
    _redact(result, definition["redact_fields"])
    _clear_derived_security(result)
    canonical_paths = {}
    for target, origin in definition["mappings"].items():
        value = _value(result, origin)
        if value is not None and not isinstance(value, (dict, list)):
            _set(result, target, value, overwrite=False)
            if target.startswith("raw.security.") and target.count(".") == 2:
                canonical_paths[target.rsplit(".", 1)[1]] = [origin]
    _redact(result, definition["redact_fields"])
    if canonical_paths and isinstance(result["raw"].get("security"), dict):
        result["raw"]["security"].update(
            {
                "schema": normalization.SCHEMA,
                "version": normalization.VERSION,
                "mapping": "managed-parser-v1",
                "provenance": canonical_paths,
            }
        )
    if definition["route_index"] is not None:
        result["index"] = definition["route_index"]
    for path in definition["required_fields"]:
        value = _value(result, path)
        if value is None or value == "" or isinstance(value, (dict, list)):
            errors.append("missing scalar: " + path)
    result["raw"]["_sapientia_pipeline"] = {
        "name": policy["name"],
        "version": policy["version"],
        "digest": policy["digest"],
        "status": "quarantined" if errors else "mapped",
    }
    result = normalize(result)
    if errors and definition["on_failure"] == "reject":
        raise ValueError("Parser policy rejected event: " + "; ".join(errors))
    return result, errors


def preview(store, who, data):
    if not isinstance(data, dict) or set(data) != {"definition", "event"}:
        raise ValueError("Expected definition and sample event")
    with principal.transaction(store, who, ("admin", "analyst")) as (_, actor):
        _full(actor)
    definition = validate(data["definition"])
    record = normalize(data["event"])
    if record["source"] != definition["source"]:
        raise ValueError("Sample source does not match the parser policy")
    result, errors = apply(
        record,
        {
            "name": "preview",
            "version": 0,
            "digest": hashlib.sha256(encode(definition).encode()).hexdigest(),
            "definition": definition,
        },
    )
    return {
        "event": result,
        "errors": errors,
        "persisted": False,
        "searchable": not errors,
    }


def admit_quarantine(db, records):
    if not records:
        return
    tenant = records[0][0]
    count, size = db.execute(
        "SELECT count(*),coalesce(sum(length(CAST(payload AS BLOB))),0) FROM ingest_quarantine WHERE tenant=?",
        (tenant,),
    ).fetchone()
    # Failed parsing preserves every admitted record; no lifetime quarantine cap.
    db.executemany(
        "INSERT INTO ingest_quarantine(tenant,event_id,index_name,source,payload,received,policy_name,policy_version,reason) VALUES(?,?,?,?,?,?,?,?,?)",
        records,
    )


def quarantine(store, who, offset=0, count=10):
    if (
        type(offset) is not int
        or not 0 <= offset
        or type(count) is not int
        or not 1 <= count <= 20
    ):
        raise ValueError("Quarantine offset/count outside supported bounds")
    from .query import index_predicate

    with principal.transaction(store, who, ("admin", "analyst")) as (db, actor):
        predicate, grants = index_predicate(actor["allowed_indexes"])
        where, params = "tenant=? AND " + predicate, [actor["tenant"], *grants]
        total = db.execute(
            "SELECT count(*) FROM ingest_quarantine WHERE " + where, params
        ).fetchone()[0]
        rows = [
            {**dict(r), "payload": json.loads(r["payload"])}
            for r in db.execute(
                "SELECT * FROM ingest_quarantine WHERE "
                + where
                + " ORDER BY received,event_id LIMIT ? OFFSET ?",
                [*params, count, offset],
            )
        ]
        return {
            "rows": rows,
            "total_count": total,
            "offset": offset,
            "next_offset": offset + len(rows) if offset + len(rows) < total else None,
        }


def replay(store, who, data):
    if (
        not isinstance(data, dict)
        or set(data) != {"event_ids"}
        or not isinstance(data["event_ids"], list)
        or not 1 <= len(data["event_ids"]) <= 100
        or any(
            not isinstance(x, str) or not 1 <= len(x) <= 256 for x in data["event_ids"]
        )
        or len(set(data["event_ids"])) != len(data["event_ids"])
    ):
        raise ValueError("Expected 1..100 unique event_ids")
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        _full(actor)
        policies = for_ingest(db, actor["tenant"])
        queued, failed, now = [], [], time.time()
        for event_id in data["event_ids"]:
            row = db.execute(
                "SELECT * FROM ingest_quarantine WHERE tenant=? AND event_id=?",
                (actor["tenant"], event_id),
            ).fetchone()
            if not row:
                raise KeyError("Quarantined event not found")
            record = json.loads(row["payload"])
            record["raw"].pop("_sapientia_pipeline", None)
            record, errors = apply(record, policies.get(record["source"]))
            if errors:
                db.execute(
                    "UPDATE ingest_quarantine SET attempts=attempts+1,reason=? WHERE tenant=? AND event_id=?",
                    ("; ".join(errors), actor["tenant"], event_id),
                )
                failed.append({"event_id": event_id, "errors": errors})
            else:
                queued.append((actor["tenant"], event_id, encode(record), now))
        pending = db.execute("SELECT count(*) FROM queue").fetchone()[0]
        tenant_pending = db.execute(
            "SELECT count(*) FROM queue WHERE tenant=?", (actor["tenant"],)
        ).fetchone()[0]
        if (
            pending + len(queued) > store.settings.max_queue
            or tenant_pending + len(queued) > store.settings.max_tenant_queue
        ):
            raise CapacityError("Admission capacity exhausted; quarantine was retained")
        if queued and shutil.disk_usage(
            store.path
        ).free < store.settings.min_free_bytes + sum(
            len(r[2].encode()) * 3 for r in queued
        ):
            raise CapacityError("Disk reserve reached; quarantine was retained")
        db.executemany(
            "INSERT INTO queue(tenant,event_id,payload,received) VALUES(?,?,?,?)",
            queued,
        )
        db.executemany(
            "DELETE FROM ingest_quarantine WHERE tenant=? AND event_id=?",
            [(r[0], r[1]) for r in queued],
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "quarantine.replay",
            {"queued": len(queued), "still_quarantined": len(failed)},
        )
        return {"queued": len(queued), "still_quarantined": failed, "searchable": False}
