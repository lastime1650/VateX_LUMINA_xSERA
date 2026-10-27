"""Evidence-bound manual endpoint response with durable, non-replaying leases.

An agent credential authenticates reports, not hardware attestation. Completion
is a signed-in agent's reported OS result; no case is automatically resolved.
"""

import hashlib
import hmac
import json
import ntpath
import os
import posixpath
import re
import secrets
import time
import uuid

from . import principal
from .query import index_predicate
from .storage import CapacityError, ConflictError, encode

EDIT = ("admin", "analyst")
TERMINAL = {"succeeded", "failed", "unknown", "expired", "cancelled"}
TTL = 300
LEASE = 30
READ_ACTIONS = {"inspect_process", "inspect_file", "collect_artifact"}
ACTIONS = {
    "terminate_process",
    "delete_file",
    "quarantine_file",
    "restore_file",
    "isolate_host",
    "release_host",
    *READ_ACTIONS,
}


def _deployment_guard(target):
    """The signed CPU observation release never authorizes OS mutation."""
    if os.environ.get("SAPIENTIA_BLOCK_NATIVE_RESPONSE") == "1" and target.get("type") not in READ_ACTIONS:
        raise PermissionError("This CPU observation deployment blocks native host response")


def initialize(store):
    with store.control(local=True) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS endpoint_responses(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,incident_id TEXT NOT NULL,
          agent_id TEXT NOT NULL,host TEXT NOT NULL,index_name TEXT NOT NULL,
          requester TEXT NOT NULL,scope TEXT NOT NULL,request_id TEXT NOT NULL,
          request_digest TEXT NOT NULL,evidence_event_id TEXT NOT NULL,
          case_version INTEGER NOT NULL,action TEXT NOT NULL,reason TEXT NOT NULL,
          state TEXT NOT NULL,created REAL NOT NULL,expires REAL NOT NULL,
          lease_digest TEXT,lease_until REAL,execution_id TEXT,started REAL,
          result TEXT,finished REAL,error TEXT,
          UNIQUE(tenant,requester,request_id));
        CREATE INDEX IF NOT EXISTS endpoint_response_due ON endpoint_responses(agent_id,state,created);
        CREATE INDEX IF NOT EXISTS endpoint_response_case ON endpoint_responses(tenant,incident_id,created DESC);
        CREATE TABLE IF NOT EXISTS endpoint_response_workflow(
          response_id TEXT PRIMARY KEY,run_id TEXT NOT NULL,position INTEGER NOT NULL,
          UNIQUE(run_id,position));
        CREATE TABLE IF NOT EXISTS endpoint_response_evidence_binding(
          response_id TEXT PRIMARY KEY,tenant TEXT NOT NULL,event_id TEXT NOT NULL,
          agent_id TEXT NOT NULL,index_name TEXT NOT NULL,payload_digest TEXT NOT NULL,
          receipt_digest TEXT NOT NULL,received REAL NOT NULL);
        """)
        from . import endpoint_artifacts

        endpoint_artifacts.initialize(db)


def _text(value, name, limit):
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > limit
        or any(ord(c) < 32 for c in value)
    ):
        raise ValueError(
            name + " must be bounded nonempty text without control characters"
        )
    return value


def _digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def _secret(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", value):
        raise PermissionError("Invalid command lease")
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def action(value, platform):
    if not isinstance(value, dict):
        raise ValueError("A typed response action is required")  # noqa: TRY004 -- API validation is HTTP 400.
    if not isinstance(value.get("type"), str):
        raise ValueError("Response action type must be text")  # noqa: TRY004 -- API malformed JSON is HTTP 400.
    if value.get("type") == "collect_artifact" and value.get("source") == "process_executable":
        fields = {"type", "source", "process_guid", "pid", "start_identity", "path", "sha256"}
        if set(value) - fields - {"max_bytes"} or not fields <= set(value):
            raise ValueError("Process executable collection requires the exact original process/path/hash")
        process = action({key: value[key] for key in ("process_guid", "pid", "start_identity")} | {"type": "inspect_process"}, platform)
        file = action({key: value[key] for key in ("type", "path", "sha256")}, platform)
        from .endpoint_artifacts import PROCESS_MAX_BYTES
        maximum = value.get("max_bytes", PROCESS_MAX_BYTES)
        if type(maximum) is not int or not 1 <= maximum <= PROCESS_MAX_BYTES:
            raise ValueError("Process executable collection is limited to 32 MiB")
        return {**file, "source": "process_executable", **{key: process[key] for key in ("process_guid", "pid", "start_identity")}, "max_bytes": maximum}
    if value.get("type") in {"terminate_process", "inspect_process"}:
        capture = value.get("type") == "inspect_process" and value.get("capture_executable_evidence") is True
        if (
            set(value) != {"type", "process_guid", "pid", "start_identity"} | ({"capture_executable_evidence", "path"} if capture else set())
            or type(value["pid"]) is not int
            or not 4 < value["pid"] < 2**32
        ):
            raise ValueError(
                "Process termination requires GUID, PID >4 and start identity"
            )
        _text(value["process_guid"], "process_guid", 256)
        identity = _text(value["start_identity"], "start_identity", 128)
        pattern = (
            r"windows:[1-9][0-9]{0,19}"
            if platform == "windows"
            else r"linux:[0-9a-fA-F-]{36}:[1-9][0-9]{0,19}"
        )
        if not re.fullmatch(pattern, identity):
            raise ValueError(
                "Process start identity differs from the enrolled OS format"
            )
        result = dict(value)
        if capture:
            result["path"] = action({"type": "inspect_file", "path": value["path"], "sha256": "0" * 64}, platform)["path"]
        return result
    if value.get("type") in {
        "delete_file",
        "quarantine_file",
        "restore_file",
        "inspect_file",
        "collect_artifact",
    }:
        fields = {"type", "path", "sha256"} | (
            {"quarantine_id"} if value["type"] == "restore_file" else set()
        )
        if set(value) != fields:
            raise ValueError("File deletion requires absolute path and expected SHA256")
        path = _text(value["path"], "file path", 512)
        module = ntpath if platform == "windows" else posixpath
        if (
            not module.isabs(path)
            or path.startswith(("\\\\", "//"))
            or ".." in re.split(r"[/\\]", path)
            or (
                platform == "windows"
                and (
                    not re.fullmatch(r"[A-Za-z]:", ntpath.splitdrive(path)[0])
                    or ":" in path[2:]
                )
            )
        ):
            raise ValueError("A local canonical absolute file path is required")
        sha = value["sha256"]
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", sha):
            raise ValueError("Expected SHA256 requires 64 hexadecimal digits")
        if value["type"] == "restore_file" and not re.fullmatch(
            r"Q-[0-9a-f]{32}", str(value["quarantine_id"])
        ):
            raise ValueError("An exact quarantine receipt ID is required")
        return {
            **value,
            "path": module.normpath(path),
            "sha256": sha.lower(),
        }
    if value.get("type") in {"isolate_host", "release_host"}:
        fields = {"type", "management_allowlist_digest"} | (
            {"isolation_id"} if value["type"] == "release_host" else set()
        )
        if set(value) != fields or not re.fullmatch(
            r"[0-9a-f]{64}", str(value.get("management_allowlist_digest"))
        ):
            raise ValueError("Exact management allowlist digest is required")
        if value["type"] == "release_host" and not re.fullmatch(
            r"[0-9a-f]{32}", str(value["isolation_id"])
        ):
            raise ValueError("An exact isolation receipt ID is required")
        return dict(value)
    raise ValueError("Unsupported typed endpoint response action")


def _member(db, actor, incident_id, event_id):
    return bool(
        db.execute(
            """SELECT 1 FROM case_bookmarks WHERE tenant=? AND incident_id=? AND event_id=?
        UNION ALL SELECT 1 FROM risk_contributions r,json_each(r.evidence,'$.event_ids') e
        WHERE r.tenant=? AND r.incident_id=? AND e.value=? LIMIT 1""",
            (
                actor["tenant"],
                incident_id,
                event_id,
                actor["tenant"],
                incident_id,
                event_id,
            ),
        ).fetchone()
    )


def _events(store, actor, identifiers):
    if not identifiers:
        return []
    predicate, indexes = index_predicate(actor["allowed_indexes"])
    found = store.analytics_query(
        "SELECT event_id,event_time,source,sourcetype,host,severity,message,index_name,raw,received FROM events_all WHERE tenant=? AND "
        + predicate
        + " AND event_id IN ("
        + ",".join("?" for _ in identifiers)
        + ") ORDER BY event_time DESC,event_id",
        [actor["tenant"], *indexes, *identifiers],
        max_rows=len(identifiers),
        timeout=2,
    )["rows"]
    with store.control() as db:
        proofs = {
            identifier: _proof(db, actor["tenant"], identifier)
            for identifier in identifiers
        }
    result = []
    for row in found:
        raw = json.loads(row.pop("raw"))
        if not isinstance(raw, dict):
            continue
        payload = {
            key: row[key]
            for key in (
                "event_id",
                "event_time",
                "source",
                "sourcetype",
                "host",
                "severity",
                "message",
            )
        }
        payload.update(index=row["index_name"], raw=raw)
        proof = proofs.get(row["event_id"])
        verified = bool(
            proof
            and proof["index_name"] == row["index_name"]
            and proof["received"] == row["received"]
            and proof["payload_digest"] == _digest(payload)
        )
        row["response_eligible"] = verified
        row["provenance"] = "registered_endpoint" if verified else "unverified"
        row["verified_agent_id"] = proof["agent_id"] if verified else None
        row["verified_body_digest"] = proof["payload_digest"] if verified else None
        row["verified_receipt_digest"] = proof["receipt_digest"] if verified else None
        xdr = raw.get("xdr")
        if not isinstance(xdr, dict) or xdr.get("schema") != "aegis.endpoint.v1":
            continue
        data = xdr.get("data")
        if (
            not isinstance(data, dict)
            or not isinstance(data.get("host"), dict)
            or data["host"].get("id") != row["host"]
        ):
            continue
        process, file = data.get("process", {}), data.get("file", {})
        process = process if isinstance(process, dict) else {}
        file = file if isinstance(file, dict) else {}
        row["process"] = {
            key: process.get(key)
            for key in ("guid", "pid", "start_identity", "name", "executable")
        }
        row["process"]["sha256"] = process.get("hash", {}).get("sha256") if isinstance(process.get("hash"), dict) else None
        row["file"] = {
            "path": file.get("path"),
            "sha256": file.get("hash", {}).get("sha256")
            if isinstance(file.get("hash"), dict)
            else None,
        }
        result.append(row)
    return result


def _proof(db, tenant, event_id):
    if not db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='endpoint_event_receipts'"
    ).fetchone():
        return None
    row = db.execute(
        "SELECT e.* FROM endpoint_event_receipts e JOIN receipts r ON r.tenant=e.tenant AND r.event_id=e.event_id AND r.digest=e.receipt_digest AND r.received=e.received WHERE e.tenant=? AND e.event_id=?",
        (tenant, event_id),
    ).fetchone()
    return dict(row) if row else None


def _target(event, target, platform):
    if target["type"] in {"isolate_host", "release_host"}:
        return True  # Enrollment host/index and authorized case event are checked separately.
    process_image = target["type"] == "collect_artifact" and target.get("source") == "process_executable"
    if target["type"] in {"terminate_process", "inspect_process"} or process_image:
        actual = event["process"]
        matches = all(
            actual.get(key) == target[out]
            for key, out in (
                ("guid", "process_guid"),
                ("pid", "pid"),
                ("start_identity", "start_identity"),
            )
        )
        if process_image or target.get("capture_executable_evidence") is True:
            module = ntpath if platform == "windows" else posixpath
            matches = matches and isinstance(actual.get("executable"), str) and module.normcase(module.normpath(actual["executable"])) == module.normcase(target["path"])
        if process_image:
            matches = matches and isinstance(actual.get("sha256"), str) and actual["sha256"].lower() == target["sha256"]
        return matches
    actual = event["file"]
    module = ntpath if platform == "windows" else posixpath
    return (
        isinstance(actual.get("path"), str)
        and module.normcase(module.normpath(actual["path"]))
        == module.normcase(target["path"])
        and isinstance(actual.get("sha256"), str)
        and actual["sha256"].lower() == target["sha256"]
    )


def _agent(db, actor, agent_id):
    row = db.execute(
        "SELECT * FROM endpoint_agents WHERE tenant=? AND id=?",
        (actor["tenant"], agent_id),
    ).fetchone()
    if (
        not row
        or row["revoked"]
        or row["expires"] <= time.time()
        or not principal.contains(actor["allowed_indexes"], [row["index_name"]])
    ):
        raise KeyError("Eligible agent not found")
    owner = principal.current(
        db, {"name": row["owner"], "tenant": row["tenant"], "role": "admin"}, ("admin",)
    )
    if not principal.contains(owner["allowed_indexes"], [row["index_name"]]):
        raise PermissionError("Agent enrollment owner permissions changed")
    return row


def _guard(db, row):
    _deployment_guard(json.loads(row["action"]))
    actor = principal.current(
        db,
        {
            "name": row["requester"],
            "tenant": row["tenant"],
            "role": "analyst",
            "allowed_indexes": json.loads(row["scope"]),
        },
        EDIT,
    )
    incident = principal.incident(db, actor, row["incident_id"])
    if incident["version"] != row["case_version"]:
        raise ConflictError("Case changed since the response was requested")
    agent = _agent(db, actor, row["agent_id"])
    if (
        agent["host"] != row["host"]
        or agent["index_name"] != row["index_name"]
        or not _member(db, actor, row["incident_id"], row["evidence_event_id"])
    ):
        raise ConflictError("Agent or case evidence changed")
    binding = db.execute(
        "SELECT * FROM endpoint_response_evidence_binding WHERE response_id=?",
        (row["id"],),
    ).fetchone()
    proof = _proof(db, row["tenant"], row["evidence_event_id"])
    if (
        not binding
        or not proof
        or proof["agent_id"] != row["agent_id"]
        or any(
            binding[key] != proof[key]
            for key in (
                "tenant",
                "event_id",
                "agent_id",
                "index_name",
                "payload_digest",
                "receipt_digest",
                "received",
            )
        )
    ):
        raise ConflictError(
            "Registered endpoint evidence provenance is unavailable or changed"
        )
    binding = db.execute(
        "SELECT * FROM endpoint_response_workflow WHERE response_id=?", (row["id"],)
    ).fetchone()
    if binding:
        from . import soar

        run = db.execute(
            "SELECT * FROM soar_runs WHERE id=?", (binding["run_id"],)
        ).fetchone()
        if not run or run["state"] != "waiting" or run["cancel_requested"]:
            raise ConflictError(
                "Approved workflow is no longer awaiting this endpoint result"
            )
        soar._executor(db, run)
    return actor


def _public(row):
    result = {
        key: row[key]
        for key in (
            "id",
            "incident_id",
            "agent_id",
            "host",
            "index_name",
            "requester",
            "request_id",
            "evidence_event_id",
            "case_version",
            "reason",
            "state",
            "created",
            "expires",
            "started",
            "finished",
            "error",
        )
    }
    result["action"] = json.loads(row["action"])
    result["result"] = json.loads(row["result"]) if row["result"] else None
    return result


def create(store, who, incident_id, data, *, workflow=None):
    if not isinstance(data, dict) or set(data) != {
        "agent_id",
        "evidence_event_id",
        "case_version",
        "request_id",
        "reason",
        "action",
    }:
        raise ValueError(
            "Expected agent_id,evidence_event_id,case_version,request_id,reason,action"
        )
    if (
        type(data["case_version"]) is not int
        or data["case_version"] < 1
        or not isinstance(data["request_id"], str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", data["request_id"])
    ):
        raise ValueError(
            "Positive case_version and stable 1..64 ASCII request_id required"
        )
    reason = _text(data["reason"], "reason", 1000)
    _text(data["evidence_event_id"], "evidence_event_id", 256)
    with principal.transaction(store, who, EDIT) as (db, actor):
        incident = principal.incident(db, actor, incident_id)
        agent = _agent(db, actor, data["agent_id"])
        target = action(data["action"], agent["platform"])
        _deployment_guard(target)
        if not _member(db, actor, incident_id, data["evidence_event_id"]):
            raise KeyError("Case evidence not found")
    records = _events(store, actor, [data["evidence_event_id"]])
    if (
        len(records) != 1
        or not records[0]["response_eligible"]
        or records[0]["verified_agent_id"] != agent["id"]
        or records[0]["host"] != agent["host"]
        or records[0]["index_name"] != agent["index_name"]
        or not _target(records[0], target, agent["platform"])
    ):
        raise ValueError("Exact enrolled host/index and evidence target must match")
    digest = _digest({**data, "incident_id": incident_id, "action": target})
    with principal.transaction(store, actor, EDIT, write=True) as (db, fresh):
        incident = principal.incident(db, fresh, incident_id)
        current = _agent(db, fresh, agent["id"])
        proof = _proof(db, fresh["tenant"], data["evidence_event_id"])
        if (
            not proof
            or proof["agent_id"] != agent["id"]
            or proof["payload_digest"] != records[0]["verified_body_digest"]
            or proof["receipt_digest"] != records[0]["verified_receipt_digest"]
            or proof["received"] != records[0]["received"]
        ):
            raise ConflictError(
                "Registered endpoint evidence changed during target lookup"
            )
        if workflow is not None:
            from . import soar

            run_id, position = workflow
            run = db.execute("SELECT * FROM soar_runs WHERE id=?", (run_id,)).fetchone()
            if (
                not run
                or run["state"] not in {"queued", "retry"}
                or run["incident_id"] != incident_id
                or run["requested_by"] != fresh["name"]
                or run["cancel_requested"]
            ):
                raise ConflictError(
                    "Approved workflow changed before endpoint queueing"
                )
            soar._executor(db, run)
            step = db.execute(
                "SELECT * FROM soar_steps WHERE run_id=? AND position=?",
                (run_id, position),
            ).fetchone()
            if (
                not step
                or step["state"] not in {"pending", "retry"}
                or json.loads(step["action"])["type"] != "endpoint_response"
            ):
                raise ConflictError("Endpoint workflow step is unavailable")
            approved = soar.resolve_endpoint_action(
                db, run_id, json.loads(step["action"])
            )
            if any(
                approved[key] != data[key]
                for key in ("agent_id", "evidence_event_id", "action", "reason")
            ):
                raise ConflictError(
                    "Queued endpoint target differs from approved workflow"
                )
        old = db.execute(
            "SELECT * FROM endpoint_responses WHERE tenant=? AND requester=? AND request_id=?",
            (fresh["tenant"], fresh["name"], data["request_id"]),
        ).fetchone()
        if old:
            if old["request_digest"] != digest:
                raise ConflictError(
                    "Response request_id already used with different content"
                )
            if workflow is not None:
                link = db.execute(
                    "SELECT run_id,position FROM endpoint_response_workflow WHERE response_id=?",
                    (old["id"],),
                ).fetchone()
                if not link or tuple(link) != (run_id, position):
                    raise ConflictError(
                        "Existing manual command cannot be adopted by an approved workflow"
                    )
                db.execute(
                    "UPDATE soar_steps SET state='waiting',result=? WHERE run_id=? AND position=?",
                    (encode({"command_id": old["id"]}), run_id, position),
                )
                db.execute(
                    "UPDATE soar_runs SET state='waiting',updated=?,next_run=? WHERE id=?",
                    (time.time(), time.time() + 1, run_id),
                )
            return {**_public(old), "duplicate": True}
        if (
            incident["version"] != data["case_version"]
            or current["host"] != agent["host"]
            or current["index_name"] != agent["index_name"]
            or not _member(db, fresh, incident_id, data["evidence_event_id"])
        ):
            raise ConflictError(
                "Case/agent/evidence changed; reload before manual response"
            )
        if (
            db.execute(
                "SELECT count(*) FROM endpoint_responses WHERE agent_id=? AND state IN ('queued','claimed','started')",
                (agent["id"],),
            ).fetchone()[0]
            >= 32
        ):
            raise CapacityError(
                "32 concurrent pending commands per agent; permanent response history has no count limit"
            )
        identifier, now = "RSP-" + uuid.uuid4().hex, time.time()
        db.execute(
            "INSERT INTO endpoint_responses(id,tenant,incident_id,agent_id,host,index_name,requester,scope,request_id,request_digest,evidence_event_id,case_version,action,reason,state,created,expires) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'queued',?,?)",
            (
                identifier,
                fresh["tenant"],
                incident_id,
                agent["id"],
                agent["host"],
                agent["index_name"],
                fresh["name"],
                encode(fresh["allowed_indexes"]),
                data["request_id"],
                digest,
                data["evidence_event_id"],
                data["case_version"],
                encode(target),
                reason,
                now,
                now + TTL,
            ),
        )
        if workflow is not None:
            db.execute(
                "INSERT INTO endpoint_response_workflow VALUES(?,?,?)",
                (identifier, run_id, position),
            )
            db.execute(
                "UPDATE soar_steps SET state='waiting',attempts=attempts+1,result=? WHERE run_id=? AND position=?",
                (encode({"command_id": identifier}), run_id, position),
            )
            db.execute(
                "UPDATE soar_runs SET state='waiting',updated=?,next_run=? WHERE id=?",
                (now, now + 1, run_id),
            )
        db.execute(
            "INSERT INTO endpoint_response_evidence_binding VALUES(?,?,?,?,?,?,?,?)",
            (
                identifier,
                fresh["tenant"],
                data["evidence_event_id"],
                agent["id"],
                agent["index_name"],
                proof["payload_digest"],
                proof["receipt_digest"],
                proof["received"],
            ),
        )
        store.audit(
            db,
            fresh["tenant"],
            fresh["name"],
            "endpoint.response.request",
            {
                "id": identifier,
                "incident_id": incident_id,
                "agent_id": agent["id"],
                "action": target,
                "evidence_event_id": data["evidence_event_id"],
                "reason": reason,
            },
        )
        return {
            **_public(
                db.execute(
                    "SELECT * FROM endpoint_responses WHERE id=?", (identifier,)
                ).fetchone()
            ),
            "duplicate": False,
        }


def get(store, who, identifier):
    with principal.transaction(store, who, EDIT) as (db, actor):
        row = db.execute(
            "SELECT * FROM endpoint_responses WHERE tenant=? AND id=?",
            (actor["tenant"], identifier),
        ).fetchone()
        if not row:
            raise KeyError("Response not found")
        principal.incident(db, actor, row["incident_id"])
        if not principal.contains(actor["allowed_indexes"], [row["index_name"]]):
            raise KeyError("Response not found")
        return _public(row)


def listing(store, who, incident_id):
    with principal.transaction(store, who, EDIT) as (db, actor):
        incident = principal.incident(db, actor, incident_id)
        ids = [
            r[0]
            for r in db.execute(
                "SELECT event_id FROM case_bookmarks WHERE tenant=? AND incident_id=? UNION SELECT e.value FROM risk_contributions r,json_each(r.evidence,'$.event_ids') e WHERE r.tenant=? AND r.incident_id=?",
                (actor["tenant"], incident_id, actor["tenant"], incident_id),
            )
        ]
        predicate, indexes = index_predicate(actor["allowed_indexes"])
        commands = db.execute(
            "SELECT * FROM endpoint_responses WHERE tenant=? AND incident_id=? AND "
            + predicate
            + " ORDER BY created DESC,id",
            (actor["tenant"], incident_id, *indexes),
        ).fetchall()
    events = []
    for start in range(0, len(ids), 1000):
        events.extend(_events(store, actor, ids[start:start+1000]))
    with principal.transaction(store, actor, EDIT) as (db, fresh):
        current = principal.incident(db, fresh, incident_id)
        if current["version"] != incident["version"]:
            raise ConflictError("Case changed during target lookup; reload")
        agents = []
        pairs = {(e["host"], e["index_name"]) for e in events}
        for row in db.execute(
            "SELECT * FROM endpoint_agents WHERE tenant=? AND revoked=0 AND expires>? ORDER BY host,id",
            (fresh["tenant"], time.time()),
        ):
            if (row["host"], row["index_name"]) not in pairs:
                continue
            try:
                _agent(db, fresh, row["id"])
            except (KeyError, PermissionError):
                continue
            response = json.loads(row["health"]).get("response", {})
            agents.append(
                {
                    "id": row["id"],
                    "host": row["host"],
                    "index": row["index_name"],
                    "platform": row["platform"],
                    "last_seen": row["last_seen"],
                    "response_reported": response if isinstance(response, dict) else {},
                    "capability_source": "agent-reported local opt-in; execution can still reject target",
                }
            )
    principal.recheck(store, fresh, EDIT)
    commands = [
        r
        for r in commands
        if principal.contains(fresh["allowed_indexes"], [r["index_name"]])
    ]
    return {
        "case_version": incident["version"],
        "agents": agents,
        "events": events,
        "events_limit": None,
        "events_truncated": False,
        "commands": [_public(r) for r in commands],
        "commands_limit": None,
        "commands_truncated": False,
        "actions": sorted(ACTIONS),
        "ttl_seconds": TTL,
        "semantics": "Typed investigation, one-time effects, reversible quarantine and explicit local-opt-in isolation with management verification. No arbitrary shell or permanent execution block. Cancellation/permission changes after execution ACK cannot undo an in-flight effect.",
    }


def cancel(store, who, identifier):
    with principal.transaction(store, who, EDIT, write=True) as (db, actor):
        row = db.execute(
            "SELECT * FROM endpoint_responses WHERE tenant=? AND id=?",
            (actor["tenant"], identifier),
        ).fetchone()
        if not row:
            raise KeyError("Response not found")
        principal.incident(db, actor, row["incident_id"])
        if not principal.contains(actor["allowed_indexes"], [row["index_name"]]):
            raise KeyError("Response not found")
        if row["state"] == "started":
            raise ConflictError(
                "Execution ACK already issued; in-flight OS effect cannot be cancelled"
            )
        if row["state"] not in TERMINAL:
            db.execute(
                "UPDATE endpoint_responses SET state='cancelled',finished=? WHERE id=?",
                (time.time(), identifier),
            )
            store.audit(
                db,
                actor["tenant"],
                actor["name"],
                "endpoint.response.cancel",
                {"id": identifier},
            )
        return _public(
            db.execute(
                "SELECT * FROM endpoint_responses WHERE id=?", (identifier,)
            ).fetchone()
        )


def _fail(db, store, row, state, code):
    db.execute(
        "UPDATE endpoint_artifacts SET state='unknown',updated=? WHERE command_id=? AND state!='complete'",
        (time.time(), row["id"]),
    )
    db.execute(
        "UPDATE endpoint_responses SET state=?,error=?,finished=? WHERE id=?",
        (state, code, time.time(), row["id"]),
    )
    store.audit(
        db,
        row["tenant"],
        row["agent_id"],
        "endpoint.response." + state,
        {"id": row["id"], "code": code},
    )


def poll(store, service, credential, data):
    if data != {}:
        raise ValueError("Poll body must be empty")
    with store.write_lock, store.control() as db:
        db.execute("BEGIN IMMEDIATE")
        agent = service._agent(db, credential)
        reported = json.loads(agent["health"]).get("response", {})
        enabled = (
            reported.get("actions", [])
            if isinstance(reported, dict) and reported.get("enabled") is True
            else []
        )
        capabilities = sorted(kind for kind in ACTIONS if kind in enabled)
        if os.environ.get("SAPIENTIA_BLOCK_NATIVE_RESPONSE") == "1":
            capabilities = [kind for kind in capabilities if kind in READ_ACTIONS]
        now = time.time()
        rows = db.execute(
            "SELECT * FROM endpoint_responses WHERE agent_id=? AND state IN ('queued','claimed','started') ORDER BY created,id LIMIT 32",
            (agent["id"],),
        ).fetchall()
        for row in rows:
            if row["expires"] <= now:
                _fail(
                    db,
                    store,
                    row,
                    "unknown" if row["state"] == "started" else "expired",
                    "execution_outcome_unreported"
                    if row["state"] == "started"
                    else "expired_before_execution",
                )
                continue
            if row["state"] == "started" or (
                row["state"] == "claimed" and row["lease_until"] > now
            ):
                continue
            try:
                _guard(db, row)
            except (PermissionError, KeyError, ConflictError):
                _fail(db, store, row, "failed", "case_or_principal_permissions_changed")
                continue
            lease = secrets.token_urlsafe(32)
            until = min(now + LEASE, row["expires"])
            db.execute(
                "UPDATE endpoint_responses SET state='claimed',lease_digest=?,lease_until=?,execution_id=NULL WHERE id=?",
                (_secret(lease), until, row["id"]),
            )
            command = {
                "id": row["id"],
                "agent_id": agent["id"],
                "tenant": row["tenant"],
                "host": row["host"],
                "index": row["index_name"],
                "incident_id": row["incident_id"],
                "case_version": row["case_version"],
                "action": json.loads(row["action"]),
                "expires_at": row["expires"],
                "lease_until": until,
                "lease_token": lease,
            }
            signature = hmac.new(
                credential.encode("ascii"), encode(command).encode(), hashlib.sha256
            ).hexdigest()
            return {
                "command": command,
                "signature": signature,
                "poll_after_seconds": 2,
                "capabilities": capabilities,
            }
    return {"command": None, "poll_after_seconds": 5, "capabilities": capabilities}


def _leased(db, service, credential, data):
    agent = service._agent(db, credential)
    row = db.execute(
        "SELECT * FROM endpoint_responses WHERE id=? AND agent_id=?",
        (data.get("command_id"), agent["id"]),
    ).fetchone()
    if (
        not row
        or not row["lease_digest"]
        or not hmac.compare_digest(
            row["lease_digest"], _secret(data.get("lease_token"))
        )
    ):
        raise PermissionError("Invalid command lease")
    execution = data.get("execution_id")
    if not isinstance(execution, str) or not re.fullmatch(r"[0-9a-f]{32}", execution):
        raise ValueError("A durable 32-hex execution_id is required")
    if row["execution_id"] and row["execution_id"] != execution:
        raise ConflictError("Command already bound to a different execution identity")
    return row, execution


def ack(store, service, credential, data):
    if not isinstance(data, dict) or set(data) != {
        "command_id",
        "lease_token",
        "execution_id",
    }:
        raise ValueError("Expected command_id,lease_token,execution_id")
    with store.write_lock, store.control() as db:
        db.execute("BEGIN IMMEDIATE")
        row, execution = _leased(db, service, credential, data)
        if (
            row["state"] not in {"claimed", "started"}
            or row["lease_until"] <= time.time()
            or row["expires"] <= time.time()
        ):
            return {"execute": False, "state": row["state"]}
        try:
            _guard(db, row)
        except (PermissionError, KeyError, ConflictError):
            _fail(db, store, row, "failed", "case_or_principal_permissions_changed")
            return {"execute": False, "state": "failed"}
        if row["state"] == "claimed":
            db.execute(
                "UPDATE endpoint_responses SET state='started',execution_id=?,started=? WHERE id=?",
                (execution, time.time(), row["id"]),
            )
            store.audit(
                db,
                row["tenant"],
                row["agent_id"],
                "endpoint.response.execution_ack",
                {"id": row["id"], "execution_id": execution},
            )
        return {
            "execute": True,
            "state": "started",
            "command_id": row["id"],
            "execution_id": execution,
            "execute_until": min(row["expires"], row["lease_until"]),
        }


def result(store, service, credential, data):
    if not isinstance(data, dict) or set(data) != {
        "command_id",
        "lease_token",
        "execution_id",
        "result",
    }:
        raise ValueError("Expected command lease,execution_id,result")
    outcome = data["result"]
    if (
        not isinstance(outcome, dict)
        or not {"success", "executed", "type", "code", "detail"} <= set(outcome)
        or set(outcome) - {"success", "executed", "type", "code", "detail", "data"}
        or (
            "data" in outcome
            and (
                not isinstance(outcome["data"], dict)
                or len(encode(outcome["data"]).encode()) > 4096
            )
        )
        or type(outcome["success"]) is not bool
        or (outcome["executed"] is not None and type(outcome["executed"]) is not bool)
        or len(encode(outcome).encode()) > 8192
    ):
        raise ValueError("Bounded typed execution result required")
    _text(outcome["code"], "result code", 80)
    _text(outcome["detail"], "result detail", 2000)
    proof = outcome.get("data", {})
    if proof.get("mode") == "virtual" or proof.get("synthetic_hardware_effect") is True or proof.get("simulation") is True:
        raise ValueError("Virtual device results belong to the simulation effect protocol and cannot qualify an endpoint OS effect")
    with store.write_lock, store.control() as db:
        db.execute("BEGIN IMMEDIATE")
        row, execution = _leased(db, service, credential, data)
        if (
            row["execution_id"] != execution
            or outcome["type"] != json.loads(row["action"])["type"]
            or row["state"] not in {"started", "unknown", "succeeded", "failed"}
        ):
            raise ConflictError("Command is not awaiting this execution result")
        if row["result"]:
            if json.loads(row["result"]) != outcome:
                raise ConflictError(
                    "Conflicting execution result; original receipt preserved"
                )
            return {"id": row["id"], "state": row["state"], "duplicate": True}
        target = json.loads(row["action"])
        if target.get("source") == "process_executable" and outcome["success"]:
            _guard(db, row)
            if row["expires"] <= time.time():
                raise ConflictError("Process executable collection expired before its final receipt")
        if target["type"] == "inspect_process" and target.get("capture_executable_evidence") is True and outcome["success"]:
            _guard(db, row)
            if row["expires"] <= time.time():
                raise ConflictError("Process executable inspection expired before its evidence receipt")
            _verify_prepared_evidence(db, row, target, outcome)
        if outcome["type"] == "collect_artifact" and outcome["success"]:
            artifact = db.execute(
                "SELECT id FROM endpoint_artifacts WHERE command_id=? AND state='complete'",
                (row["id"],),
            ).fetchone()
            if (
                not artifact
                or outcome.get("data", {}).get("server_artifact_id") != artifact["id"]
            ):
                raise ConflictError(
                    "Artifact success requires completed evidence-bound remote transfer"
                )
        state = (
            "succeeded"
            if outcome["success"]
            and (
                outcome["executed"] is True
                or (outcome["type"] in READ_ACTIONS and outcome["executed"] is False)
            )
            else "unknown"
            if outcome["executed"] is None or outcome["executed"] is True
            else "failed"
        )
        if outcome["success"] and state != "succeeded":
            raise ValueError(
                "Success requires confirmed OS effect or typed read-only investigation"
            )
        db.execute(
            "UPDATE endpoint_responses SET state=?,result=?,finished=?,error=? WHERE id=?",
            (
                state,
                encode(outcome),
                time.time(),
                None if state == "succeeded" else outcome["code"],
                row["id"],
            ),
        )
        if outcome["type"] == "collect_artifact" and not outcome["success"]:
            db.execute(
                "UPDATE endpoint_artifacts SET state='unknown',updated=? WHERE command_id=? AND state!='complete'",
                (time.time(), row["id"]),
            )
        store.audit(
            db,
            row["tenant"],
            row["agent_id"],
            "endpoint.response.result",
            {"id": row["id"], "state": state, "result": outcome},
        )
        return {"id": row["id"], "state": state, "duplicate": False}


def artifact_upload(store, service, credential, command_id, data):
    from . import endpoint_artifacts

    return endpoint_artifacts.upload(store, service, credential, command_id, data)


def _verify_prepared_evidence(db, row, target, outcome):
    """Bind new inspection metadata to its admitted original and source command."""
    from . import pipeline, xdr_bridge
    from .storage import normalize
    result = outcome.get("data", {})
    record = result.get("process_evidence_record")
    if not isinstance(record, dict) or result.get("source_response_command_id") != row["id"]:
        raise ConflictError("Process inspection requires its newly admitted original")
    parsed = normalize(xdr_bridge.parse_event(record, "agent", row["index_name"], expected_host=row["host"]))
    parsed, errors = pipeline.apply(parsed, pipeline.for_ingest(db, row["tenant"]).get(parsed["source"]))
    metadata = record.get("data", {})
    process = metadata.get("process", {})
    sha = process.get("hash", {}).get("sha256") if isinstance(process.get("hash"), dict) else None
    proof = _proof(db, row["tenant"], parsed["event_id"])
    if (errors or parsed["event_id"] != result.get("process_evidence_event_id")
            or metadata.get("agent", {}).get("source_response_command_id") != row["id"]
            or metadata.get("event", {}).get("action") != "process_image_observed"
            or any(process.get(key) != target[name] for key, name in (("guid", "process_guid"), ("pid", "pid"), ("start_identity", "start_identity")))
            or process.get("executable") != target["path"]
            or not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha)
            or not proof or proof["agent_id"] != row["agent_id"] or proof["index_name"] != row["index_name"]
            or proof["payload_digest"] != _digest(parsed)):
        raise ConflictError("New process executable evidence differs from its exact command or receipt")


def artifact_download(store, who, artifact_id):
    from . import endpoint_artifacts

    return endpoint_artifacts.download(store, who, artifact_id)
