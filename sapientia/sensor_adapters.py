"""Bounded, source-bound external sensor JSON adapters; no packet capture or effects.

The registered connector receives observations from an operator-managed sensor.
Authentication proves which connector submitted bytes, not kernel capture or
truthfulness. Replay is permanently marked and never promoted to live coverage.
"""

import copy
import hashlib
import ipaddress
import json
import math
import re
import shutil
import time
import uuid
from datetime import datetime

from . import (
    connector_runtime,
    intelligence,
    migrations,
    normalization,
    principal,
    source_registry,
)
from .storage import ConflictError, encode, normalize

SENSORS = ("suricata", "zeek", "falco", "tetragon", "osquery")
SCHEMA = "xsera.external-sensor.v1"
CATALOG = (
    {
        "id": "suricata",
        "name": "Suricata EVE",
        "license": "GPL-2.0",
        "url": "https://docs.suricata.io/en/latest/output/eve/eve-json-format.html",
        "scope": "External EVE alert, flow, DNS, HTTP and TLS observations",
    },
    {
        "id": "zeek",
        "name": "Zeek JSON",
        "license": "BSD-3-Clause",
        "url": "https://docs.zeek.org/en/current/log-formats.html",
        "scope": "External conn, dns, http, ssl and notice logs",
    },
    {
        "id": "falco",
        "name": "Falco JSON",
        "license": "Apache-2.0",
        "url": "https://falco.org/docs/outputs/",
        "scope": "External rule alerts and explicit syscall fields",
    },
    {
        "id": "tetragon",
        "name": "Tetragon JSON",
        "license": "Apache-2.0",
        "url": "https://tetragon.io/docs/concepts/events/",
        "scope": "External process_exec, process_exit and process_kprobe observations",
    },
    {
        "id": "osquery",
        "name": "osquery differential JSON",
        "license": "Apache-2.0",
        "url": "https://osquery.readthedocs.io/en/stable/deployment/logging/",
        "scope": "External differential query results; only reviewed query names alert",
    },
)


def initialize(store):
    migrations.apply_store(
        store,
        "sensor_adapters",
        [
            "CREATE TABLE IF NOT EXISTS analysis_sensor_sources(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,source_id TEXT NOT NULL,policy_id TEXT NOT NULL,definition TEXT NOT NULL,version INTEGER NOT NULL,state TEXT NOT NULL,reviewer TEXT,created REAL NOT NULL,updated REAL NOT NULL)",
            "CREATE TABLE IF NOT EXISTS analysis_sensor_health(id INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT NOT NULL,binding_id TEXT NOT NULL,actor TEXT NOT NULL,body TEXT NOT NULL,created REAL NOT NULL)",
            "CREATE INDEX IF NOT EXISTS analysis_sensor_scope ON analysis_sensor_sources(tenant,source_id)",
        ],
    )


def _text(value, name, maximum=1024, optional=False):
    if optional and value is None:
        return None
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or any(ord(c) < 32 for c in value)
    ):
        raise ValueError("Bounded sensor text required: " + name)
    return value


def _number(value, name, maximum=2**63 - 1):
    if (
        type(value) not in (int, float)
        or not math.isfinite(value)
        or not 0 <= value <= maximum
    ):
        raise ValueError("Finite sensor number required: " + name)
    return value


def _stamp(value):
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
            if parsed.utcoffset() is None:
                raise ValueError("Sensor timestamp requires an explicit timezone")
            value = parsed.timestamp()
        except (ValueError, OverflowError):
            raise ValueError(
                "Sensor timestamp requires epoch seconds or timezone ISO8601"
            ) from None
    return _number(value, "timestamp", time.time() + 86400)


def _obj(value, name):
    if not isinstance(value, dict):
        raise ValueError("Sensor object required: " + name)  # noqa: TRY004 - HTTP input validation returns 400.
    return value


def _ip(value):
    return str(ipaddress.ip_address(value)) if value is not None else None


def _port(value):
    if value is None:
        return None
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError("Sensor port requires an integer in 1..65535")
    return value


def _definition_from_source(source):
    definition = (
        source.get("definition") if isinstance(source, dict) else source["definition"]
    )
    definition = json.loads(definition) if isinstance(definition, str) else definition
    return definition.get("sensor_adapter", {}) if isinstance(definition, dict) else {}


def decode(item, source):
    """Convert one actual sensor JSON record into an immutable admitted original."""
    if (
        not isinstance(item, dict)
        or not {"id", "log"} <= set(item)
        or set(item) - {"id", "log", "kind"}
    ):
        raise ValueError("Sensor record requires id,log and optional Zeek kind")
    _text(item["id"], "original ID", 256)
    log = copy.deepcopy(_obj(item["log"], "log"))
    if len(encode(log).encode()) > 48 * 1024:
        raise ValueError("Sensor log exceeds 48 KiB")
    sensor = source["product"]
    if sensor not in SENSORS:
        raise ValueError("Unsupported sensor")
    config = _definition_from_source(source)
    if not config or config.get("schema") != SCHEMA:
        raise PermissionError(
            "Use a reviewed sensor binding; generic source registration is insufficient"
        )
    mode = config["mode"]
    account = source["account"]
    security, data = (
        {},
        {"host": {"id": account}, "agent": {"simulation": mode == "replay"}},
    )
    suspicious, severity, rule, action = False, "info", None, "sensor_observation"
    kind = item.get("kind")
    if sensor == "suricata":
        at, kind = (
            _stamp(log.get("timestamp")),
            _text(log.get("event_type"), "event_type", 64),
        )
        if kind not in {"alert", "flow", "dns", "http", "tls", "stats", "fileinfo"}:
            raise ValueError("Unsupported EVE event_type")
        for field, name in (("src_ip", "src_ip"), ("dest_ip", "dest_ip")):
            if log.get(field) is not None:
                security[name] = _ip(log[field])
        for field in ("src_port", "dest_port"):
            if log.get(field) is not None:
                security[field] = _port(log[field])
        if log.get("proto") is not None:
            security["protocol"] = _text(log["proto"], "proto", 16).lower()
        if kind == "alert":
            alert = _obj(log.get("alert"), "alert")
            rule = _text(alert.get("signature"), "signature", 2048)
            _number(alert.get("signature_id"), "signature_id")
            level = _number(alert.get("severity", 3), "severity", 255)
            severity, suspicious = (
                ("critical" if level <= 1 else "high" if level <= 2 else "medium"),
                True,
            )
        action = (
            "dns_query"
            if kind == "dns"
            else "network_connection"
            if kind in {"flow", "alert", "http", "tls"}
            else "sensor_observation"
        )
        if kind == "dns":
            query = _obj(log.get("dns", {}), "dns").get("rrname")
            if isinstance(query, str):
                data["dns"] = {"query": query[:253]}
    elif sensor == "zeek":
        at, kind = (
            _stamp(log.get("ts")),
            _text(kind or log.get("_path", "conn"), "Zeek kind", 32),
        )
        if kind not in {"conn", "dns", "http", "ssl", "notice"}:
            raise ValueError("Unsupported Zeek log kind")
        for field, name in (("id.orig_h", "src_ip"), ("id.resp_h", "dest_ip")):
            if log.get(field) is not None:
                security[name] = _ip(log[field])
        for field, name in (("id.orig_p", "src_port"), ("id.resp_p", "dest_port")):
            if log.get(field) is not None:
                security[name] = _port(log[field])
        if log.get("proto"):
            security["protocol"] = _text(log["proto"], "proto", 16).lower()
        if kind == "notice":
            rule, suspicious, severity = (
                _text(log.get("note"), "note", 256),
                True,
                "medium",
            )
        action = "dns_query" if kind == "dns" else "network_connection"
        if kind == "dns" and log.get("query"):
            data["dns"] = {"query": _text(log["query"], "query", 253)}
        if kind == "conn":
            data["network"] = {"protocol": security.get("protocol")}
            for key, field in (("bytes_out", "orig_bytes"), ("bytes_in", "resp_bytes")):
                if log.get(field) is not None:
                    data["network"][key] = _number(log[field], field)
    elif sensor == "falco":
        at = _stamp(log.get("time"))
        fields = _obj(log.get("output_fields"), "output_fields")
        if log.get("hostname") is not None and log["hostname"] != account:
            raise PermissionError(
                "Falco hostname differs from registered sensor account"
            )
        rule = _text(log.get("rule"), "rule", 256)
        priority = _text(log.get("priority"), "priority", 32).lower()
        if priority not in {
            "emergency",
            "alert",
            "critical",
            "error",
            "warning",
            "notice",
            "informational",
            "debug",
        }:
            raise ValueError("Unknown Falco priority")
        suspicious = priority in {"emergency", "alert", "critical", "error", "warning"}
        severity = (
            "critical"
            if priority in {"emergency", "alert", "critical"}
            else "high"
            if priority == "error"
            else "medium"
            if suspicious
            else "info"
        )
        data["process"] = {}
        for src, dst in (
            ("proc.pid", "pid"),
            ("proc.name", "name"),
            ("proc.cmdline", "command_line"),
            ("proc.exepath", "executable"),
        ):
            if fields.get(src) is not None:
                value = fields[src]
                if dst == "pid" and type(value) is not int:
                    raise ValueError("Falco PID requires an integer")
                data["process"][dst] = (
                    _number(value, src, 2**32 - 1)
                    if dst == "pid"
                    else _text(value, src, 8192)
                )
        action, kind = "sensor_rule_alert", "rule"
    elif sensor == "tetragon":
        at = _stamp(log.get("time"))
        kinds = [
            key
            for key in ("process_exec", "process_exit", "process_kprobe")
            if key in log
        ]
        if len(kinds) != 1:
            raise ValueError("Exactly one supported Tetragon event required")
        kind, event = kinds[0], _obj(log[kinds[0]], "Tetragon event")
        process = _obj(event.get("process"), "process")
        data["process"] = {}
        for src, dst in (
            ("exec_id", "guid"),
            ("pid", "pid"),
            ("binary", "executable"),
            ("arguments", "command_line"),
            ("start_time", "start_identity"),
        ):
            if process.get(src) is not None:
                value = process[src]
                if dst == "pid" and type(value) is not int:
                    raise ValueError("Tetragon PID requires an integer")
                data["process"][dst] = (
                    _number(value, src, 2**32 - 1)
                    if dst == "pid"
                    else _text(value, src, 8192)
                )
        parent = event.get("parent", {})
        _obj(parent, "parent")
        reported_parent = process.get("parent_exec_id") or parent.get("exec_id")
        if (
            process.get("parent_exec_id")
            and parent.get("exec_id")
            and process["parent_exec_id"] != parent["exec_id"]
        ):
            raise ValueError("Conflicting explicit Tetragon parent identities")
        if reported_parent:
            data["process"]["parent"] = {
                "guid": _text(reported_parent, "parent_exec_id", 1024)
            }
        pod = process.get("pod", {})
        _obj(pod, "pod")
        container = _obj(pod.get("container", {}), "container")
        if container.get("id"):
            data["container"] = {"id": _text(container["id"], "container ID", 1024)}
            if pod.get("namespace"):
                data["container"]["namespace"] = _text(
                    pod["namespace"], "namespace", 256
                )
        if log.get("node_name") is not None and log["node_name"] != account:
            raise PermissionError(
                "Tetragon node differs from registered sensor account"
            )
        rule = event.get("policy_name") or log.get("policy_name")
        if rule is not None:
            _text(rule, "policy_name", 256)
        suspicious, severity = rule in config.get("alert_queries", []), "medium"
        action = (
            "process_created"
            if kind == "process_exec"
            else "process_terminated"
            if kind == "process_exit"
            else "sensor_syscall_observation"
        )
    else:
        reported_time = log.get("unixTime")
        # The official logger defaults numerics=false and emits unixTime as a
        # decimal string. Only this documented field permits that conversion.
        if isinstance(reported_time, str) and re.fullmatch(
            r"[0-9]{1,12}", reported_time
        ):
            reported_time = int(reported_time)
        at = _stamp(reported_time)
        if log.get("hostIdentifier", log.get("hostname")) != account:
            raise PermissionError(
                "osquery hostIdentifier differs from registered sensor account"
            )
        rule = _text(log.get("name"), "query name", 256)
        kind = _text(log.get("action"), "query action", 32)
        if kind not in {"added", "removed"}:
            raise ValueError("Only osquery differential results supported")
        _obj(log.get("columns"), "columns")
        suspicious, severity = (
            rule in config.get("alert_queries", []) and kind == "added",
            "medium",
        )
        action = "sensor_query_observation"
    # Canonical fields use the same alias map as ingestion normalization; the
    # reported process action remains intact in xdr.data and sensor_original.
    security.update(
        action=normalization.OTHER_ACTIONS.get(action, action), outcome="observed"
    )
    if security.get("src_ip"):
        data["source"] = {"ip": security["src_ip"], "port": security.get("src_port")}
    if security.get("dest_ip"):
        data["destination"] = {
            "ip": security["dest_ip"],
            "port": security.get("dest_port"),
        }
    data.setdefault("network", {})["protocol"] = security.get("protocol")
    data["event"] = {
        "action": action,
        "category": "network" if sensor in {"suricata", "zeek"} else "process",
        "kind": "alert" if suspicious else "event",
    }
    metadata = {
        "schema": SCHEMA,
        "engine": sensor,
        "kind": kind,
        "mode": mode,
        "suspicious": suspicious,
        "rule": rule,
        "source_asserted": True,
        "native_capture_proven": False,
        "packet_inspection_performed_by_xsera": False,
        "source_payload_sha256": hashlib.sha256(encode(log).encode()).hexdigest(),
    }
    return normalize(
        {
            "event_id": item["id"],
            "event_time": at,
            "host": account,
            "index": source["index_name"],
            "source": sensor,
            "sourcetype": sensor + ":json",
            "severity": severity,
            "message": (rule or sensor + " " + kind)[:2048],
            "raw": {
                "sensor_original": log,
                "sensor_analysis": metadata,
                "security": security,
                "xdr": {"data": data},
            },
        }
    )


def _visible(db, actor, identifier):
    row = db.execute(
        "SELECT * FROM analysis_sensor_sources WHERE id=? AND tenant=?",
        (identifier, actor["tenant"]),
    ).fetchone()
    if not row or not principal.contains(
        actor["allowed_indexes"], [json.loads(row["definition"])["index"]]
    ):
        raise KeyError("Sensor binding not found")
    return row


def _public(row):
    return {
        "id": row["id"],
        "source_id": row["source_id"],
        "policy_id": row["policy_id"],
        "version": row["version"],
        "state": row["state"],
        "owner": row["owner"],
        "reviewer": row["reviewer"],
        **json.loads(row["definition"]),
    }


def save(store, who, data):
    fields = {
        "name",
        "sensor",
        "index",
        "account",
        "realm",
        "credential_ref",
        "mode",
        "create_case",
        "alert_queries",
    }
    if (
        not isinstance(data, dict)
        or set(data) != fields
        or data["sensor"] not in SENSORS
        or not isinstance(data["mode"], str)
        or data["mode"] not in {"live", "replay"}
        or type(data["create_case"]) is not bool
    ):
        raise ValueError("Exact sensor binding fields required")
    _text(data["name"], "name", 120)
    queries = data["alert_queries"]
    if (
        not isinstance(queries, list)
        or len(queries) > 32
        or any(not isinstance(q, str) for q in queries)
        or len(set(queries)) != len(queries)
    ):
        raise ValueError("At most 32 unique reviewed query/policy names")
    for query in queries:
        _text(query, "alert query/policy", 256)
    if data["mode"] == "replay" and data["realm"] != "virtual-lab":
        raise ValueError("Replay sources require the explicit virtual-lab realm")
    with store.write_lock:
        with principal.transaction(store, who, ("admin",)) as (db, actor):
            if not principal.contains(actor["allowed_indexes"], [data["index"]]):
                raise PermissionError("Sensor index outside scope")
        source = source_registry.save(
            store,
            actor,
            {k: data[k] for k in ("index", "account", "realm", "credential_ref")}
            | {"product": data["sensor"], "version": 0},
        )
        # This immutable parser contract is part of the source snapshot. All
        # connector paths invoke decode; callers cannot select a generic decoder.
        with principal.transaction(store, actor, ("admin",), write=True) as (db, fresh):
            row = source_registry.visible(db, fresh, source["id"])
            definition = json.loads(row["definition"])
            definition["sensor_adapter"] = {
                "schema": SCHEMA,
                "mode": data["mode"],
                "alert_queries": queries,
            }
            db.execute(
                "UPDATE source_registry SET definition=? WHERE id=?",
                (encode(definition), source["id"]),
            )
        policy = intelligence.save_policy(
            store,
            actor,
            {
                "name": data["name"][:100] + " · sensor alerts",
                "kind": "atomic",
                "indexes": [data["index"]],
                "enabled": True,
                "severity": "high",
                "confidence_grade": "external_sensor_reported_alert"
                if data["mode"] == "live"
                else "replayed_sensor_alert_fixture",
                "filters": [
                    {
                        "field": "projection.source_id",
                        "op": "eq",
                        "value": source["id"],
                    },
                    {
                        "field": "raw.sensor_analysis.suspicious",
                        "op": "eq",
                        "value": True,
                    },
                    {
                        "field": "raw.sensor_analysis.mode",
                        "op": "eq",
                        "value": data["mode"],
                    },
                ],
                "case_adapter": {
                    "entity_field": "host",
                    "risk_score": 50,
                    "severity": "high",
                    "mitre": [],
                    "cooldown": 300,
                }
                if data["create_case"]
                else None,
            },
        )
        identifier, now = "SENSOR-" + uuid.uuid4().hex, time.time()
        with principal.transaction(store, actor, ("admin",), write=True) as (db, fresh):
            db.execute(
                "INSERT INTO analysis_sensor_sources VALUES(?,?,?,?,?,?,1,'pending',NULL,?,?)",
                (
                    identifier,
                    fresh["tenant"],
                    fresh["name"],
                    source["id"],
                    policy["id"],
                    encode(data),
                    now,
                    now,
                ),
            )
            store.audit(
                db,
                fresh["tenant"],
                fresh["name"],
                "sensor.binding.create",
                {
                    "id": identifier,
                    "source_id": source["id"],
                    "policy_id": policy["id"],
                    "mode": data["mode"],
                },
            )
            return _public(_visible(db, fresh, identifier))


def review(store, who, identifier, data):
    if (
        not isinstance(data, dict)
        or set(data) != {"version", "approve", "reason"}
        or type(data["approve"]) is not bool
        or type(data["version"]) is not int
    ):
        raise ValueError("Review requires integer version,approve,reason")
    _text(data["reason"], "review reason", 2000)
    with store.write_lock:
        with principal.transaction(store, who, ("admin",)) as (db, actor):
            row = dict(_visible(db, actor, identifier))
            if row["version"] != data["version"] or row["state"] != "pending":
                raise ConflictError("Sensor draft revision changed")
            if row["owner"] == actor["name"]:
                raise PermissionError("Independent sensor review required")
        intelligence.review_policy(
            store,
            actor,
            row["policy_id"],
            {"version": 1, "approve": data["approve"], "reason": data["reason"]},
        )
        with principal.transaction(store, actor, ("admin",), write=True) as (db, fresh):
            db.execute(
                "UPDATE analysis_sensor_sources SET state=?,reviewer=?,updated=? WHERE id=?",
                (
                    "active" if data["approve"] else "rejected",
                    fresh["name"],
                    time.time(),
                    identifier,
                ),
            )
            store.audit(
                db,
                fresh["tenant"],
                fresh["name"],
                "sensor.binding.review",
                {"id": identifier, **data},
            )
            return _public(_visible(db, fresh, identifier))


def _active(db, actor, identifier, version):
    if type(version) is not int:
        raise ValueError("Sensor binding revision requires an integer")
    row = _visible(db, actor, identifier)
    if row["state"] != "active" or row["version"] != version:
        raise ConflictError("Sensor binding unavailable or revision changed")
    source = source_registry.visible(db, actor, row["source_id"])
    if source["state"] != "active" or source["version"] != 1:
        raise ConflictError("Sensor source changed; create and review a new binding")
    policy = db.execute(
        "SELECT * FROM intelligence_policies WHERE id=? AND tenant=?",
        (row["policy_id"], actor["tenant"]),
    ).fetchone()
    if (
        not policy
        or policy["version"] != 1
        or policy["owner"] != row["owner"]
        or policy["approver"] != row["reviewer"]
    ):
        raise ConflictError(
            "Bound sensor policy changed; create and review a new binding"
        )
    intelligence._authority(db, policy)
    return row, source


def intake(store, who, identifier, data):
    if not isinstance(data, dict) or set(data) != {
        "version",
        "events",
        "cursor",
        "checkpoint_version",
    }:
        raise ValueError("Exact sensor intake fields required")
    with store.write_lock:
        with principal.transaction(store, who, ("admin", "analyst")) as (db, actor):
            row, source = _active(db, actor, identifier, data["version"])
            source_id, version, mode = (
                row["source_id"],
                source["version"],
                json.loads(row["definition"])["mode"],
            )
        result = connector_runtime.intake(
            store, actor, source_id, {**data, "version": version}
        )
        return {
            **result,
            "binding_id": identifier,
            "mode": mode,
            "packet_inspection_performed_by_xsera": False,
            "sensor_installation_verified": False,
        }


def revoke(store, who, identifier, data):
    if (
        not isinstance(data, dict)
        or set(data) != {"version", "reason"}
        or type(data["version"]) is not int
    ):
        raise ValueError("Revocation requires integer version,reason")
    _text(data["reason"], "reason", 2000)
    with store.write_lock:
        with principal.transaction(store, who, ("admin",)) as (db, actor):
            row = dict(_visible(db, actor, identifier))
            if row["version"] != data["version"]:
                raise ConflictError("Sensor binding revision changed")
            source = dict(source_registry.visible(db, actor, row["source_id"]))
        source_registry.revoke(store, actor, source["id"], source["version"])
        with principal.transaction(store, actor, ("admin",), write=True) as (db, fresh):
            db.execute(
                "UPDATE analysis_sensor_sources SET state='revoked',version=version+1,updated=? WHERE id=?",
                (time.time(), identifier),
            )
            store.audit(
                db,
                fresh["tenant"],
                fresh["name"],
                "sensor.binding.revoke",
                {"id": identifier, "reason": data["reason"]},
            )
            return _public(_visible(db, fresh, identifier))


def health_report(store, who, identifier, data):
    fields = {"version", "state", "captured", "dropped", "sensor_version"}
    if (
        not isinstance(data, dict)
        or set(data) != fields
        or not isinstance(data["state"], str)
        or data["state"] not in {"ok", "degraded", "unavailable"}
    ):
        raise ValueError("Exact reported sensor health fields required")
    for key in ("captured", "dropped"):
        if type(data[key]) is not int:
            raise ValueError("Health counters require nonnegative integers")
        _number(data[key], key)
    _text(data["sensor_version"], "sensor_version", 128)
    with principal.transaction(store, who, ("admin", "analyst"), write=True) as (
        db,
        actor,
    ):
        row, _ = _active(db, actor, identifier, data["version"])
        result = {
            **data,
            "reported_not_independently_verified": True,
            "mode": json.loads(row["definition"])["mode"],
            "effective_reported_state": "degraded"
            if data["dropped"] > 0 and data["state"] == "ok"
            else data["state"],
        }
        db.execute(
            "INSERT INTO analysis_sensor_health(tenant,binding_id,actor,body,created) VALUES(?,?,?,?,?)",
            (actor["tenant"], identifier, actor["name"], encode(result), time.time()),
        )
        return result


def listing(store, who):
    with principal.transaction(store, who) as (db, actor):
        items = []
        for row in db.execute(
            "SELECT * FROM analysis_sensor_sources WHERE tenant=? ORDER BY created DESC",
            (actor["tenant"],),
        ).fetchall():
            if not principal.contains(
                actor["allowed_indexes"], [json.loads(row["definition"])["index"]]
            ):
                continue
            item = _public(row)
            source = source_registry.visible(db, actor, row["source_id"])
            item["source_state"], item["source_version"] = (
                source["state"],
                source["version"],
            )
            counts = db.execute(
                "SELECT count(*),max(received) FROM source_event_receipts WHERE tenant=? AND source_id=?",
                (actor["tenant"], row["source_id"]),
            ).fetchone()
            item["received_originals"], item["last_received"] = counts[0], counts[1]
            checkpoint = db.execute(
                "SELECT cursor,version FROM connector_checkpoints WHERE source_id=?",
                (row["source_id"],),
            ).fetchone()
            item["checkpoint_version"] = checkpoint["version"] if checkpoint else 0
            item["checkpoint_cursor"] = checkpoint["cursor"] if checkpoint else None
            health = db.execute(
                "SELECT body,created FROM analysis_sensor_health WHERE tenant=? AND binding_id=? ORDER BY id DESC LIMIT 1",
                (actor["tenant"], row["id"]),
            ).fetchone()
            item["reported_health"] = (
                {**json.loads(health["body"]), "received": health["created"]}
                if health
                else None
            )
            item["effective_state"] = row["state"]
            if row["state"] == "active":
                try:
                    _active(db, actor, row["id"], row["version"])
                except (PermissionError, KeyError, ConflictError, ValueError):
                    item["effective_state"] = "authority_changed"
            item["coverage"] = (
                "replay_fixture"
                if item["mode"] == "replay"
                else "external_reported_observations"
                if counts[0]
                else "unavailable_no_observations"
            )
            item["installation_verified"] = False
            items.append(item)
        return {"items": items, "total": len(items)}


def catalog():
    return {
        "items": [
            {
                **item,
                "adapter_available": True,
                "local_executable_found": bool(shutil.which(item["id"])),
                "local_runtime_status": "unavailable"
                if not shutil.which(item["id"])
                else "executable_found_not_qualified",
                "installation_verified": False,
            }
            for item in CATALOG
        ],
        "packet_inspection_performed_by_xsera": False,
        "host_effects": False,
        "limits": {
            "event_bytes": 48 * 1024,
            "batch_events": 1000,
            "format": "JSON only; no pcap or kernel execution",
        },
    }
