"""Approval-gated durable response workflows; local actions are transactional.

No endpoint containment is implied. Outbound HTTPS requires server-only explicit
configuration; uncertain remote outcomes never replay without an operator's
configured peer idempotency guarantee. No credentials are stored in workflows.
"""

import hashlib
import http.client
import ipaddress
import json
import math
import os
import queue
import re
import socket
import sqlite3
import ssl
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from . import access, casework, principal, workflow_graph
from .storage import CapacityError, ConflictError, encode

EDITORS = ("admin", "analyst")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
MAX_BYTES = 64 * 1024
TERMINAL = {"completed", "cancelled", "failed", "unknown"}


class _RecoverRemote(Exception):
    pass


class _QueueEndpoint(Exception):
    def __init__(self, actor, data, workflow):
        self.actor, self.data, self.workflow = actor, data, workflow


class _EndpointUnknown(Exception):
    pass


def _digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def _name(value, label):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise ValueError(f"{label} requires 1..64 ASCII identifier characters")
    return value


def _text(value, label, maximum, empty=False):
    return casework._text(value, label, maximum, empty=empty)


def _number(value, label, low, high, integer=False):
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not low <= value <= high
        or (integer and type(value) is not int)
    ):
        raise ValueError(f"Invalid {label}")
    return value


class Webhooks:
    """Trusted deployment settings, never accepted from a workflow HTTP body."""

    def __init__(self, config=None, *, allow_loopback=False, context=None):
        config = config or {"allow_hosts": [], "destinations": {}}
        if not isinstance(config, dict) or set(config) != {
            "allow_hosts",
            "destinations",
        }:
            raise ValueError(
                "Webhook configuration requires allow_hosts and destinations"
            )
        hosts, destinations = config["allow_hosts"], config["destinations"]
        if (
            not isinstance(hosts, list)
            or len(hosts) > 16
            or not all(isinstance(h, str) and h and len(h) <= 253 for h in hosts)
        ):
            raise ValueError(
                "Webhook allow_hosts must contain at most 16 exact hostnames"
            )
        if not isinstance(destinations, dict) or len(destinations) > 16:
            raise ValueError("At most 16 webhook destinations are supported")
        self.destinations, self.allow_loopback = {}, allow_loopback
        for name, definition in destinations.items():
            _name(name, "destination")
            if not isinstance(definition, dict) or set(definition) != {
                "url",
                "secret_env",
                "idempotency_guaranteed",
            }:
                raise ValueError(
                    "Destination requires url, secret_env, idempotency_guaranteed"
                )
            url = definition["url"]
            if not isinstance(url, str) or len(url) > 2048:
                raise ValueError("Invalid destination URL")
            parts = urlsplit(url)
            if (
                parts.scheme != "https"
                or not parts.hostname
                or parts.hostname not in hosts
                or parts.username
                or parts.password
                or parts.fragment
                or parts.query
            ):
                raise ValueError(
                    "Destination must be allowlisted HTTPS without credentials, query or fragment"
                )
            if (
                type(definition["idempotency_guaranteed"]) is not bool
                or not isinstance(definition["secret_env"], str)
                or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", definition["secret_env"])
            ):
                raise ValueError(
                    "Invalid secret environment name or idempotency guarantee"
                )
            try:
                port = parts.port or 443
            except ValueError:
                raise ValueError("Invalid webhook port") from None
            if not 1 <= port <= 65535:
                raise ValueError("Invalid webhook port")
            self.destinations[name] = {
                **definition,
                "host": parts.hostname,
                "port": port,
                "path": parts.path or "/",
            }
        self.context = context or ssl.create_default_context()
        if (
            not self.context.check_hostname
            or self.context.verify_mode != ssl.CERT_REQUIRED
        ):
            raise ValueError(
                "Webhook TLS requires certificate and hostname verification"
            )
        self.context.minimum_version = max(
            self.context.minimum_version, ssl.TLSVersion.TLSv1_2
        )
        self.fingerprint = _digest(config)
        self.slots = threading.BoundedSemaphore(2)
        self.resolvers = threading.BoundedSemaphore(2)

    def guaranteed(self, destination):
        return self.destinations[destination]["idempotency_guaranteed"]

    def send(self, destination, payload, action_key, timeout):
        """Return only bounded status metadata; response content is never persisted."""
        entry = self.destinations[destination]
        secret = os.environ.get(entry["secret_env"], "")
        if not 32 <= len(secret) <= 512 or any(
            not 32 <= ord(ch) <= 126 for ch in secret
        ):
            raise ValueError("Webhook secret unavailable or invalid")
        if len(payload) > MAX_BYTES:
            raise ValueError("Webhook payload exceeds 64 KiB")
        if not self.slots.acquire(blocking=False):
            raise CapacityError("Webhook connection quota reached")
        connection = None
        timer = None
        try:
            deadline = time.monotonic() + min(5.0, timeout)
            resolved = queue.Queue(maxsize=1)

            if not self.resolvers.acquire(blocking=False):
                raise CapacityError("Webhook DNS quota reached")

            def resolve():
                try:
                    resolved.put(
                        socket.getaddrinfo(
                            entry["host"], entry["port"], type=socket.SOCK_STREAM
                        )
                    )
                except OSError:
                    resolved.put(None)
                finally:
                    self.resolvers.release()

            threading.Thread(target=resolve, daemon=True).start()
            addresses = resolved.get(timeout=max(0.01, deadline - time.monotonic()))
            if not addresses:
                raise OSError("Webhook DNS unavailable")
            for address in addresses:
                ip = ipaddress.ip_address(address[4][0])
                if not ip.is_global and not (self.allow_loopback and ip.is_loopback):
                    raise ValueError("Webhook resolves to an excluded network")
            address = addresses[0][4]
            connection = http.client.HTTPSConnection(
                entry["host"],
                entry["port"],
                timeout=max(0.01, deadline - time.monotonic()),
                context=self.context,
            )

            def connect_address(unused_address, timeout=None, source_address=None):
                result = socket.create_connection(
                    (address[0], address[1]), timeout, source_address
                )
                result.settimeout(max(0.001, deadline - time.monotonic()))
                return result

            connection._create_connection = connect_address
            connection.connect()
            wire_socket = connection.sock

            def expire():
                try:
                    wire_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            timer = threading.Timer(max(0.001, deadline - time.monotonic()), expire)
            timer.daemon = True
            timer.start()
            connection.request(
                "POST",
                entry["path"],
                body=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + secret,
                    "Idempotency-Key": action_key,
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            if len(response.read(MAX_BYTES + 1)) > MAX_BYTES:
                raise OSError("Webhook response exceeded limit")
            if time.monotonic() >= deadline:
                raise TimeoutError("Webhook deadline exceeded")
            # Redirects are never followed. Every non-2xx may already have had
            # a remote side effect, so the caller conservatively marks unknown.
            if not 200 <= response.status < 300:
                raise OSError("Webhook did not acknowledge the action")
            return {
                "type": "webhook",
                "destination": destination,
                "status_code": response.status,
                "outcome": "acknowledged",
            }
        finally:
            if timer:
                timer.cancel()
            if connection:
                connection.close()
            self.slots.release()


def load_config(path=None):
    path = path or os.environ.get("SAPIENTIA_SOAR_CONFIG")
    if not path:
        return Webhooks()
    path = Path(path)
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("Webhook configuration must be a file no larger than 64 KiB")
    return Webhooks(json.loads(path.read_text(encoding="utf-8-sig")))


def initialize(store):
    with store.control(local=True) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS soar_playbooks(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,name TEXT NOT NULL,owner TEXT NOT NULL,
          version INTEGER NOT NULL,updated REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS soar_revisions(
          playbook_id TEXT NOT NULL,version INTEGER NOT NULL,definition TEXT NOT NULL,
          digest TEXT NOT NULL,actor TEXT NOT NULL,at REAL NOT NULL,
          PRIMARY KEY(playbook_id,version));
        CREATE TABLE IF NOT EXISTS soar_playbook_scopes(
          playbook_id TEXT NOT NULL,version INTEGER NOT NULL,indexes TEXT NOT NULL,
          PRIMARY KEY(playbook_id,version));
        CREATE TABLE IF NOT EXISTS soar_runs(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,playbook_id TEXT NOT NULL,
          revision INTEGER NOT NULL,definition TEXT NOT NULL,revision_digest TEXT NOT NULL,
          incident_id TEXT NOT NULL,requested_by TEXT NOT NULL,request_id TEXT NOT NULL,
          requested_scope TEXT NOT NULL,snapshot TEXT NOT NULL,snapshot_digest TEXT NOT NULL,
          config_digest TEXT NOT NULL,approved_by TEXT,approved_scope TEXT,approval_digest TEXT,
          state TEXT NOT NULL,expected_incident_version INTEGER NOT NULL,
          created REAL NOT NULL,updated REAL NOT NULL,next_run REAL NOT NULL,
          cancel_requested INTEGER NOT NULL DEFAULT 0,error TEXT,
          UNIQUE(tenant,requested_by,request_id));
        CREATE INDEX IF NOT EXISTS soar_run_due ON soar_runs(state,next_run);
        CREATE INDEX IF NOT EXISTS soar_run_incident ON soar_runs(tenant,incident_id,created DESC);
        CREATE TABLE IF NOT EXISTS soar_steps(
          run_id TEXT NOT NULL,position INTEGER NOT NULL,step_id TEXT NOT NULL,
          action TEXT NOT NULL,state TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,
          result TEXT,error TEXT,lease_until REAL,attempt_token TEXT,
          PRIMARY KEY(run_id,position));
        CREATE TABLE IF NOT EXISTS soar_bindings(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,scope TEXT NOT NULL,
          policy_id TEXT NOT NULL,playbook_id TEXT NOT NULL,revision INTEGER NOT NULL,
          version INTEGER NOT NULL,enabled INTEGER NOT NULL,cursor INTEGER NOT NULL,
          updated REAL NOT NULL,error TEXT,UNIQUE(tenant,policy_id));
        """)
    if not hasattr(store, "soar_webhooks"):
        store.soar_webhooks = load_config()


def _literal_endpoint_target(target):
    result = dict(target)
    for key, prefix in (("quarantine_id", "Q-"), ("isolation_id", "")):
        if isinstance(result.get(key), dict):
            reference = result[key]
            if (
                set(reference) != {"from_step", "field"}
                or reference["field"] != "data." + key
            ):
                raise ValueError("Only a typed receipt reference is allowed")
            _name(reference["from_step"], "receipt source step")
            result[key] = prefix + "0" * 32
    return result


def resolve_endpoint_action(db, run_id, action):
    result = {
        key: action[key]
        for key in ("agent_id", "evidence_event_id", "action", "reason")
    }
    result["action"] = dict(result["action"])
    for key in ("quarantine_id", "isolation_id"):
        if isinstance(result["action"].get(key), dict):
            reference = result["action"][key]
            row = db.execute(
                "SELECT state,result FROM soar_steps WHERE run_id=? AND step_id=?",
                (run_id, reference["from_step"]),
            ).fetchone()
            if not row or row["state"] != "completed" or not row["result"]:
                raise ConflictError("Typed receipt dependency is not complete")
            receipt = json.loads(row["result"]).get("data", {}).get(key)
            if not isinstance(receipt, str):
                raise ConflictError("Typed receipt output is unavailable")
            result["action"][key] = receipt
    return result


def _action(action):
    if not isinstance(action, dict):
        raise ValueError("A typed action is required")  # noqa: TRY004 - JSON validation uses HTTP 400 ValueError.
    kind = action.get("type")
    if kind == "endpoint_response":
        if set(action) != {
            "type",
            "agent_id",
            "evidence_event_id",
            "action",
            "reason",
        } or not isinstance(action["action"], dict):
            raise ValueError(
                "Endpoint action requires agent_id,evidence_event_id,action,reason"
            )
        _text(action["agent_id"], "agent_id", 256)
        _text(action["evidence_event_id"], "evidence_event_id", 256)
        _text(action["reason"], "reason", 1000)
        from . import endpoint_response

        # Enrolled platform and exact target are checked again when queued.
        try:
            endpoint_response.action(
                _literal_endpoint_target(action["action"]), "windows"
            )
        except ValueError:
            endpoint_response.action(
                _literal_endpoint_target(action["action"]), "linux"
            )
    elif kind == "add_note":
        if set(action) != {"type", "note"}:
            raise ValueError("Invalid add_note fields")
        _text(action["note"], "note", 8000)
    elif kind == "add_task":
        if set(action) - {
            "type",
            "title",
            "description",
            "assignee",
            "mandatory",
            "due_at",
        }:
            raise ValueError("Invalid add_task fields")
        _text(action.get("title"), "title", 200)
        _text(action.get("description", ""), "description", 4000, empty=True)
        _text(action.get("assignee", ""), "assignee", 64, empty=True)
        if type(action.get("mandatory", False)) is not bool:
            raise ValueError("Invalid task mandatory flag")
        casework._due(action.get("due_at"))
    elif kind == "assign":
        if set(action) != {"type", "assignee"}:
            raise ValueError("Invalid assign fields")
        _text(action["assignee"], "assignee", 64)
    elif kind == "set_status":
        if (
            set(action) != {"type", "status", "note"}
            or not isinstance(action["status"], str)
            or action["status"]
            not in {
                "new",
                "triage",
                "resolved",
            }
        ):
            raise ValueError("Invalid status action")
        _text(action["note"], "note", 4000)
    elif kind == "webhook":
        if set(action) != {"type", "destination", "payload"} or not isinstance(
            action["payload"], dict
        ):
            raise ValueError("Webhook requires destination and literal JSON payload")
        _name(action["destination"], "destination")
        pending, elements = [(action["payload"], 0)], 0
        while pending:
            item, depth = pending.pop()
            elements += 1
            if depth > 8 or elements > 4096:
                raise ValueError("Webhook JSON exceeds depth or element limit")
            if isinstance(item, dict):
                if not all(isinstance(key, str) and len(key) <= 200 for key in item):
                    raise ValueError("Invalid webhook payload key")
                pending.extend((value, depth + 1) for value in item.values())
            elif isinstance(item, list):
                pending.extend((value, depth + 1) for value in item)
            elif item is not None and not isinstance(item, (str, int, float, bool)):
                raise ValueError("Webhook payload must be JSON")
    else:
        raise ValueError("Unsupported response action")
    if len(encode(action).encode()) > MAX_BYTES - 1024:
        raise ValueError("Action exceeds payload limit")
    return json.loads(encode(action))


def validate(data):
    if not isinstance(data, dict) or set(data) != {"name", "version", "steps"}:
        raise ValueError("Playbook requires name, version and steps")
    _text(data["name"], "name", 160)
    _number(data["version"], "version", 0, 100, True)
    if not isinstance(data["steps"], list) or not 1 <= len(data["steps"]) <= 16:
        raise ValueError("Playbook requires 1..16 sequential steps")
    steps, seen = [], set()
    for step in data["steps"]:
        if not isinstance(step, dict) or set(step) - {
            "id",
            "action",
            "max_attempts",
            "retry_base",
            "depends_on",
            "when",
        }:
            raise ValueError("Invalid playbook step")
        identifier = _name(step.get("id"), "step id")
        if identifier in seen:
            raise ValueError("Step IDs must be unique")
        seen.add(identifier)
        steps.append(
            {
                "id": identifier,
                "action": _action(step.get("action")),
                "max_attempts": _number(
                    step.get("max_attempts", 3), "max_attempts", 1, 5, True
                ),
                "retry_base": _number(
                    step.get("retry_base", 5), "retry_base", 1, 300, True
                ),
                **({"depends_on": step["depends_on"]} if "depends_on" in step else {}),
                **({"when": step["when"]} if "when" in step else {}),
            }
        )
    definition = {"name": data["name"], "steps": workflow_graph.order(steps)}
    if len(encode(definition).encode()) > MAX_BYTES:
        raise ValueError("Playbook exceeds 64 KiB")
    return definition


def _endpoint_scope(db, actor, definition):
    """Freeze real enrollment/evidence indexes, never client origin labels."""
    from . import endpoint_response

    indexes = set()
    for step in definition["steps"]:
        action = step["action"]
        if action["type"] != "endpoint_response":
            continue
        agent = endpoint_response._agent(db, actor, action["agent_id"])
        proof = endpoint_response._proof(
            db, actor["tenant"], action["evidence_event_id"]
        )
        if (
            not proof
            or proof["agent_id"] != agent["id"]
            or proof["index_name"] != agent["index_name"]
            or not principal.contains(actor["allowed_indexes"], [proof["index_name"]])
        ):
            raise KeyError("Eligible endpoint evidence not found")
        indexes.update((agent["index_name"], proof["index_name"]))
    return access.validate(sorted(indexes))


def _playbook_scope(db, playbook_id, version, definition=None):
    row = db.execute(
        "SELECT indexes FROM soar_playbook_scopes WHERE playbook_id=? AND version=?",
        (playbook_id, version),
    ).fetchone()
    if row:
        return access.validate(json.loads(row[0]))
    if definition is None:
        revision = db.execute(
            "SELECT definition FROM soar_revisions WHERE playbook_id=? AND version=?",
            (playbook_id, version),
        ).fetchone()
        if not revision:
            raise KeyError("Playbook not found")
        definition = json.loads(revision[0])
    # Legacy generic books keep their tenant visibility. Unscoped endpoint
    # revisions require wildcard access until an authorized author saves anew.
    return (
        ["*"]
        if any(
            step["action"]["type"] == "endpoint_response"
            for step in definition["steps"]
        )
        else []
    )


def _playbook_guard(db, actor, playbook_id, version, definition=None):
    indexes = _playbook_scope(db, playbook_id, version, definition)
    if not principal.contains(actor["allowed_indexes"], indexes):
        raise KeyError("Playbook not found")
    return indexes


def save(store, who, data, playbook_id=None):
    definition = validate(data)
    now = time.time()
    with principal.transaction(store, who, EDITORS, write=True) as (db, actor):
        old = (
            db.execute(
                "SELECT * FROM soar_playbooks WHERE tenant=? AND id=?",
                (actor["tenant"], playbook_id),
            ).fetchone()
            if playbook_id
            else None
        )
        if playbook_id and not old:
            raise KeyError("Playbook not found")
        if old:
            _playbook_guard(db, actor, old["id"], old["version"])
        if old and old["owner"] != actor["name"] and actor["role"] != "admin":
            raise PermissionError(
                "Only playbook owner or tenant administrator may edit"
            )
        if (old["version"] if old else 0) != data["version"]:
            raise ConflictError("Playbook version changed")
        # Durable inventory/history has no lifetime record-count ceiling.
        # Durable inventory/history has no lifetime record-count ceiling.
        indexes = _endpoint_scope(db, actor, definition)
        playbook_id = playbook_id or str(uuid.uuid4())
        version = data["version"] + 1
        db.execute(
            "INSERT INTO soar_playbooks VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,version=excluded.version,updated=excluded.updated",
            (
                playbook_id,
                actor["tenant"],
                definition["name"],
                actor["name"],
                version,
                now,
            ),
        )
        digest = _digest(definition)
        db.execute(
            "INSERT INTO soar_revisions VALUES(?,?,?,?,?,?)",
            (playbook_id, version, encode(definition), digest, actor["name"], now),
        )
        db.execute(
            "INSERT INTO soar_playbook_scopes VALUES(?,?,?)",
            (playbook_id, version, encode(indexes)),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "soar.playbook_save",
            {"playbook_id": playbook_id, "version": version, "digest": digest},
        )
    return {"id": playbook_id, "version": version, "digest": digest}


def list_playbooks(store, who):
    with principal.transaction(store, who) as (db, actor):
        result = []
        for row in db.execute(
            "SELECT p.*,r.definition FROM soar_playbooks p JOIN soar_revisions r ON r.playbook_id=p.id AND r.version=p.version WHERE p.tenant=? ORDER BY p.updated DESC,p.id",
            (actor["tenant"],),
        ):
            try:
                _playbook_guard(
                    db, actor, row["id"], row["version"], json.loads(row["definition"])
                )
            except KeyError:
                continue
            result.append(
                {
                    key: row[key]
                    for key in ("id", "tenant", "name", "owner", "version", "updated")
                }
            )
        return result


def get_playbook(store, who, playbook_id):
    with principal.transaction(store, who) as (db, actor):
        row = db.execute(
            "SELECT p.*,r.definition,r.digest FROM soar_playbooks p JOIN soar_revisions r ON r.playbook_id=p.id AND r.version=p.version WHERE p.tenant=? AND p.id=?",
            (actor["tenant"], playbook_id),
        ).fetchone()
        if not row:
            raise KeyError("Playbook not found")
        _playbook_guard(
            db, actor, row["id"], row["version"], json.loads(row["definition"])
        )
        return {**dict(row), "definition": json.loads(row["definition"])}


def _evidence(db, actor, incident_id):
    from . import contribution_verdicts

    incident = principal.incident(db, actor, incident_id)
    digest, indexes, count, size = hashlib.sha256(), set(), 0, 0
    inactive, uncertain = 0, 0
    deadline = time.monotonic() + 1
    for table, order in (("risk_contributions", "id"), ("case_bookmarks", "id")):
        digest.update(table.encode())
        for row in db.execute(
            "SELECT * FROM "
            + table
            + " WHERE tenant=? AND incident_id=? ORDER BY "
            + order,
            (actor["tenant"], incident_id),
        ):
            count += 1
            if count > 10000 or time.monotonic() >= deadline:
                raise CapacityError(
                    "SOAR evidence snapshot exceeds record or time limit"
                )
            material = dict(row)
            if table == "risk_contributions":
                verdict = contribution_verdicts.classification(db, material)
                material["current_adjudication"] = verdict
                inactive += int(not verdict["active"])
                uncertain += int(json.loads(row["evidence"]).get("temporal", {}).get("automation_eligible") is False)
            body = encode(material).encode()
            size += len(body)
            if size > 8 * 1024 * 1024:
                raise CapacityError("SOAR evidence snapshot exceeds 8 MiB")
            digest.update(body)
            indexes.update(
                json.loads(row["indexes"])
                if table == "risk_contributions"
                else [row["index_name"]]
            )
    indexes = access.validate(sorted(indexes))
    return incident, {"digest": digest.hexdigest(), "count": count, "indexes": indexes,
                      "inactive_adjudicated_contributions": inactive,
                      "temporally_uncertain_contributions": uncertain,
                      "independent_approval_required": True,
                      "decision_basis": "Current complete evidence and individual judgements; risk score is not malicious probability"}


def start_run(store, who, playbook_id, incident_id, request_id, *, binding=None):
    _name(request_id, "request_id")
    now = time.time()
    with principal.transaction(store, who, EDITORS, write=True) as (db, actor):
        if binding is not None:
            bound = db.execute(
                "SELECT * FROM soar_bindings WHERE id=? AND tenant=?",
                (binding[0], actor["tenant"]),
            ).fetchone()
            book_version = db.execute(
                "SELECT version FROM soar_playbooks WHERE id=? AND tenant=?",
                (playbook_id, actor["tenant"]),
            ).fetchone()
            if (
                not bound
                or not bound["enabled"]
                or bound["version"] != binding[1]
                or bound["owner"] != actor["name"]
                or bound["playbook_id"] != playbook_id
                or not book_version
                or bound["revision"] != book_version[0]
                or not principal.contains(
                    actor["allowed_indexes"], json.loads(bound["scope"])
                )
            ):
                raise ConflictError("Prospective binding changed before proposal")
        old = db.execute(
            "SELECT * FROM soar_runs WHERE tenant=? AND requested_by=? AND request_id=?",
            (actor["tenant"], actor["name"], request_id),
        ).fetchone()
        if old:
            _read_guard(db, actor, old)
            if old["playbook_id"] != playbook_id or old["incident_id"] != incident_id:
                raise ConflictError(
                    "Run request_id already used with different content"
                )
            return {"id": old["id"], "state": old["state"], "duplicate": True}
        book = db.execute(
            "SELECT p.*,r.definition,r.digest FROM soar_playbooks p JOIN soar_revisions r ON p.id=r.playbook_id AND p.version=r.version WHERE p.tenant=? AND p.id=?",
            (actor["tenant"], playbook_id),
        ).fetchone()
        if not book:
            raise KeyError("Playbook not found")
        definition = json.loads(book["definition"])
        _playbook_guard(db, actor, book["id"], book["version"], definition)
        for step in definition["steps"]:
            if (
                step["action"]["type"] == "webhook"
                and step["action"]["destination"]
                not in store.soar_webhooks.destinations
            ):
                raise ValueError(
                    "Webhook destination is not enabled by server configuration"
                )
        incident, evidence = _evidence(db, actor, incident_id)
        snapshot = {"incident": incident, "evidence": evidence}
        # Durable inventory/history has no lifetime record-count ceiling.
        run_id = str(uuid.uuid4())
        db.execute(
            """INSERT INTO soar_runs(id,tenant,playbook_id,revision,definition,revision_digest,incident_id,requested_by,request_id,requested_scope,snapshot,snapshot_digest,config_digest,state,expected_incident_version,created,updated,next_run)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'pending_approval',?,?,?,?)""",
            (
                run_id,
                actor["tenant"],
                playbook_id,
                book["version"],
                book["definition"],
                book["digest"],
                incident_id,
                actor["name"],
                request_id,
                encode(actor["allowed_indexes"]),
                encode(snapshot),
                _digest(snapshot),
                store.soar_webhooks.fingerprint,
                incident["version"],
                now,
                now,
                now,
            ),
        )
        for position, step in enumerate(definition["steps"]):
            db.execute(
                "INSERT INTO soar_steps(run_id,position,step_id,action,state) VALUES(?,?,?,?,'pending')",
                (run_id, position, step["id"], encode(step["action"])),
            )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "soar.run_request",
            {
                "run_id": run_id,
                "revision_digest": book["digest"],
                "snapshot_digest": _digest(snapshot),
                "incident_id": incident_id,
            },
        )
    return {"id": run_id, "state": "pending_approval", "duplicate": False}


def _read_guard(db, actor, run):
    _playbook_guard(
        db, actor, run["playbook_id"], run["revision"], json.loads(run["definition"])
    )
    principal.incident(db, actor, run["incident_id"])
    if not principal.contains(
        actor["allowed_indexes"], json.loads(run["snapshot"])["evidence"]["indexes"]
    ):
        raise KeyError("Run not found")


def _run(db, actor, run_id):
    run = db.execute(
        "SELECT * FROM soar_runs WHERE id=? AND tenant=?", (run_id, actor["tenant"])
    ).fetchone()
    if not run:
        raise KeyError("Run not found")
    _read_guard(db, actor, run)
    return run


def get_run(store, who, run_id):
    with principal.transaction(store, who) as (db, actor):
        run = _run(db, actor, run_id)
        result = dict(run)
        for key in ("definition", "requested_scope", "snapshot", "approved_scope"):
            result[key] = json.loads(result[key]) if result[key] is not None else None
        result["steps"] = []
        for step in db.execute(
            "SELECT * FROM soar_steps WHERE run_id=? ORDER BY position", (run_id,)
        ):
            item = dict(step)
            item.pop("attempt_token")
            item["action"] = json.loads(item["action"])
            item["result"] = json.loads(item["result"]) if item["result"] else None
            result["steps"].append(item)
        return result


def list_runs(store, who, incident_id=None):
    with principal.transaction(store, who) as (db, actor):
        if incident_id:
            principal.incident(db, actor, incident_id)
        where = "tenant=?" + (" AND incident_id=?" if incident_id else "")
        args = [actor["tenant"]] + ([incident_id] if incident_id else [])
        result = []
        # All candidates authorized before returning metadata; 10000 is the
        # documented per-tenant run quota, not a silent visibility ceiling.
        for row in db.execute(
            "SELECT * FROM soar_runs WHERE "
            + where
            + " ORDER BY created DESC,id",
            args,
        ):
            try:
                _read_guard(db, actor, row)
            except KeyError:
                continue
            result.append(
                {
                    key: row[key]
                    for key in (
                        "id",
                        "playbook_id",
                        "revision",
                        "incident_id",
                        "requested_by",
                        "approved_by",
                        "state",
                        "created",
                        "updated",
                        "error",
                    )
                }
            )
        return {
            "runs": result,
            "limit": None,
            "truncated": False,
            "listing": "complete_authorized_history",
        }


def approve(store, who, run_id):
    with principal.transaction(store, who, EDITORS, write=True) as (db, actor):
        run = _run(db, actor, run_id)
        if run["requested_by"] == actor["name"]:
            raise PermissionError("An independent active analyst must approve the run")
        if run["state"] != "pending_approval":
            raise ConflictError("Run is not awaiting approval")
        creator = principal.current(
            db,
            {
                "name": run["requested_by"],
                "tenant": run["tenant"],
                "role": "analyst",
                "allowed_indexes": json.loads(run["requested_scope"]),
            },
            EDITORS,
        )
        _read_guard(db, creator, run)
        incident, evidence = _evidence(db, creator, run["incident_id"])
        snapshot = json.loads(run["snapshot"])
        if (
            evidence != snapshot["evidence"]
            or incident["version"] != run["expected_incident_version"]
        ):
            raise ConflictError(
                "Incident/evidence changed; request a new run for fresh approval"
            )
        approval_digest = _digest(
            {
                "revision": run["revision_digest"],
                "snapshot": run["snapshot_digest"],
                "run_id": run_id,
            }
        )
        db.execute(
            "UPDATE soar_runs SET approved_by=?,approved_scope=?,approval_digest=?,state='queued',updated=? WHERE id=?",
            (
                actor["name"],
                encode(actor["allowed_indexes"]),
                approval_digest,
                time.time(),
                run_id,
            ),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "soar.approve",
            {"run_id": run_id, "approval_digest": approval_digest},
        )
    return {"id": run_id, "state": "queued", "approval_digest": approval_digest}


def cancel_run(store, who, run_id):
    with principal.transaction(store, who, EDITORS, write=True) as (db, actor):
        run = _run(db, actor, run_id)
        if run["state"] in TERMINAL:
            return {"id": run_id, "state": run["state"], "already_terminal": True}
        state = run["state"] if run["state"] == "sending" else "cancelled"
        db.execute(
            "UPDATE soar_runs SET cancel_requested=1,state=?,updated=? WHERE id=?",
            (state, time.time(), run_id),
        )
        if state == "cancelled":
            db.execute(
                "UPDATE soar_steps SET state='cancelled' WHERE run_id=? AND state!='completed'",
                (run_id,),
            )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "soar.cancel",
            {"run_id": run_id, "remote_in_flight": state == "sending"},
        )
    return {"id": run_id, "state": state, "cancel_requested": True}


def _executor(db, run):
    actor = principal.current(
        db,
        {
            "name": run["requested_by"],
            "tenant": run["tenant"],
            "role": "analyst",
            "allowed_indexes": json.loads(run["requested_scope"]),
        },
        EDITORS,
    )
    approver = principal.current(
        db,
        {
            "name": run["approved_by"],
            "tenant": run["tenant"],
            "role": "analyst",
            "allowed_indexes": json.loads(run["approved_scope"] or "[]"),
        },
        EDITORS,
    )
    if actor["name"] == approver["name"]:
        raise PermissionError("Independent approval is required")
    _read_guard(db, actor, run)
    _read_guard(db, approver, run)
    incident, evidence = _evidence(db, actor, run["incident_id"])
    if (
        evidence != json.loads(run["snapshot"])["evidence"]
        or incident["version"] != run["expected_incident_version"]
    ):
        raise ConflictError("Approved evidence or incident changed")
    expected = _digest(
        {
            "revision": run["revision_digest"],
            "snapshot": run["snapshot_digest"],
            "run_id": run["id"],
        }
    )
    if (
        _digest(json.loads(run["definition"])) != run["revision_digest"]
        or _digest(json.loads(run["snapshot"])) != run["snapshot_digest"]
        or run["approval_digest"] != expected
    ):
        raise ConflictError("Run approval integrity check failed")
    return actor


def _finish(db, store, run, step, result, now):
    db.execute(
        "UPDATE soar_steps SET state='completed',attempts=attempts+CASE WHEN state IN ('sending','waiting') THEN 0 ELSE 1 END,result=?,error=NULL,lease_until=NULL,attempt_token=NULL WHERE run_id=? AND position=?",
        (encode(result), run["id"], step["position"]),
    )
    pending = db.execute(
        "SELECT 1 FROM soar_steps WHERE run_id=? AND state NOT IN ('completed','skipped') LIMIT 1",
        (run["id"],),
    ).fetchone()
    if json.loads(step["action"])["type"] in {"webhook", "endpoint_response"}:
        # An acknowledgement proves only the remote action's result. Adopting
        # the current case version here would silently approve an analyst's
        # concurrent status/owner change while the request was in transit.
        # Preserve the approved version so the next step rechecks its CAS.
        version = run["expected_incident_version"]
    else:
        # Local actions and this checkpoint share one writer transaction, so
        # their own changes can safely advance the version for the next step.
        version = db.execute(
            "SELECT version FROM incidents WHERE id=? AND tenant=?",
            (run["incident_id"], run["tenant"]),
        ).fetchone()[0]
    state = (
        "cancelled"
        if run["cancel_requested"]
        else ("queued" if pending else "completed")
    )
    db.execute(
        "UPDATE soar_runs SET state=?,expected_incident_version=?,updated=?,next_run=?,error=NULL WHERE id=?",
        (state, version, now, now, run["id"]),
    )
    if state == "cancelled":
        db.execute(
            "UPDATE soar_steps SET state='cancelled' WHERE run_id=? AND state!='completed'",
            (run["id"],),
        )
    store.audit(
        db,
        run["tenant"],
        run["requested_by"],
        "soar.step_complete",
        {"run_id": run["id"], "step_id": step["step_id"], "state": state},
    )


def _failure(
    store,
    run_id,
    step_position,
    now,
    code,
    *,
    transient=False,
    unknown=False,
    token=None,
):
    with store.write_lock, store.control() as db:
        db.execute("BEGIN IMMEDIATE")
        run = db.execute("SELECT * FROM soar_runs WHERE id=?", (run_id,)).fetchone()
        if not run or run["state"] in TERMINAL:
            return
        step = db.execute(
            "SELECT * FROM soar_steps WHERE run_id=? AND position=?",
            (run_id, step_position),
        ).fetchone()
        if not step or (token is not None and step["attempt_token"] != token):
            return
        if step["state"] == "completed":
            return
        definition = json.loads(run["definition"])["steps"][step_position]
        attempts = step["attempts"] + (
            0 if step["state"] in {"sending", "waiting"} else 1
        )
        retry = (
            transient
            and attempts < definition["max_attempts"]
            and not run["cancel_requested"]
        )
        state = (
            "retry"
            if retry
            else (
                "unknown"
                if unknown
                else ("cancelled" if run["cancel_requested"] else "failed")
            )
        )
        db.execute(
            "UPDATE soar_steps SET state=?,attempts=?,error=?,lease_until=NULL,attempt_token=NULL WHERE run_id=? AND position=?",
            (state, attempts, code, run_id, step_position),
        )
        db.execute(
            "UPDATE soar_runs SET state=?,updated=?,next_run=?,error=? WHERE id=?",
            (
                state,
                now,
                now + min(3600, definition["retry_base"] * 2 ** max(0, attempts - 1)),
                code,
                run_id,
            ),
        )
        store.audit(
            db,
            run["tenant"],
            "system",
            "soar.step_failure",
            {
                "run_id": run_id,
                "step_id": step["step_id"],
                "state": state,
                "code": code,
                "attempts": attempts,
            },
        )


def run_due(store, now=None, cancel=None, budget=1.0, max_runs=20):
    """Bounded scheduler pass; return attempted steps, never auto-approve runs."""
    _number(budget, "budget", 0.01, 5)
    _number(max_runs, "max_runs", 1, 100, True)
    now = time.time() if now is None else _number(now, "now", 0, 1e12)
    deadline = time.monotonic() + budget
    processed = 0
    if cancel is None or not cancel.is_set():
        from . import soar_bindings

        soar_bindings.run_due(store, deadline, max_runs)
    with store.control() as db:
        db.execute("PRAGMA busy_timeout=100")
        ids = [
            r[0]
            for r in db.execute(
                "SELECT id FROM soar_runs WHERE (state IN ('queued','retry','waiting') AND next_run<=?) OR (state='sending' AND next_run<=?) ORDER BY next_run,id LIMIT ?",
                (now, now, max_runs),
            )
        ]
    for run_id in ids:
        if time.monotonic() >= deadline or (cancel is not None and cancel.is_set()):
            break
        position, token, external = None, None, None
        try:
            with store.write_lock, store.control() as db:
                db.execute("PRAGMA busy_timeout=100")
                db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
                db.execute("BEGIN IMMEDIATE")
                run = db.execute(
                    "SELECT * FROM soar_runs WHERE id=?", (run_id,)
                ).fetchone()
                if (
                    run["state"] not in {"queued", "retry", "sending", "waiting"}
                    or run["next_run"] > now
                ):
                    continue
                step = db.execute(
                    "SELECT * FROM soar_steps WHERE run_id=? AND state NOT IN ('completed','skipped') ORDER BY position LIMIT 1",
                    (run_id,),
                ).fetchone()
                if not step:
                    raise ConflictError("Run has no pending step")
                position = step["position"]
                if run["state"] == "sending":
                    # A previous process may have transmitted before crashing.
                    external = json.loads(step["action"])
                    safe = (
                        run["config_digest"] == store.soar_webhooks.fingerprint
                        and external["destination"] in store.soar_webhooks.destinations
                        and store.soar_webhooks.guaranteed(external["destination"])
                    )
                    token = step["attempt_token"]
                    raise _RecoverRemote()
                if run["cancel_requested"]:
                    db.execute(
                        "UPDATE soar_runs SET state='cancelled',updated=? WHERE id=?",
                        (now, run_id),
                    )
                    continue
                actor = _executor(db, run)
                action = json.loads(step["action"])
                definition = json.loads(run["definition"])["steps"][position]
                if (
                    action != definition["action"]
                    or step["step_id"] != definition["id"]
                ):
                    raise ConflictError("Step integrity check failed")
                if run["state"] == "waiting":
                    command_id = json.loads(step["result"])["command_id"]
                    command = db.execute(
                        "SELECT r.* FROM endpoint_responses r JOIN endpoint_response_workflow w ON w.response_id=r.id WHERE r.id=? AND w.run_id=? AND w.position=?",
                        (command_id, run_id, position),
                    ).fetchone()
                    if not command:
                        raise ConflictError("Endpoint result binding disappeared")
                    state = command["state"]
                    if state not in {
                        "succeeded",
                        "failed",
                        "unknown",
                        "expired",
                        "cancelled",
                    }:
                        if command["expires"] > now:
                            db.execute(
                                "UPDATE soar_runs SET next_run=?,updated=? WHERE id=?",
                                (now + 1, now, run_id),
                            )
                            continue
                        if state == "started":
                            raise _EndpointUnknown()
                        raise ConflictError("Endpoint command expired before execution")
                    if state == "unknown":
                        raise _EndpointUnknown()
                    if state != "succeeded":
                        raise ConflictError(
                            "Endpoint did not confirm successful result"
                        )
                    result = json.loads(command["result"])
                    _finish(db, store, run, step, result, now)
                    processed += 1
                    continue
                all_steps = db.execute(
                    "SELECT step_id,state,result FROM soar_steps WHERE run_id=?",
                    (run_id,),
                ).fetchall()
                states = {row["step_id"]: row["state"] for row in all_steps}
                depends = definition.get(
                    "depends_on",
                    []
                    if position == 0
                    else [json.loads(run["definition"])["steps"][position - 1]["id"]],
                )
                if any(
                    states.get(name) not in {"completed", "skipped"} for name in depends
                ):
                    raise ConflictError("Workflow dependency is not complete")
                results = {
                    row["step_id"]: json.loads(row["result"]) if row["result"] else {}
                    for row in all_steps
                }
                if not workflow_graph.matches(definition.get("when"), results):
                    _finish(
                        db,
                        store,
                        run,
                        step,
                        {"skipped": True, "reason": "condition_false"},
                        now,
                    )
                    db.execute(
                        "UPDATE soar_steps SET state='skipped' WHERE run_id=? AND position=?",
                        (run_id, position),
                    )
                    processed += 1
                    continue
                if action["type"] == "endpoint_response":
                    target = resolve_endpoint_action(db, run_id, action)
                    raise _QueueEndpoint(
                        actor,
                        target
                        | {
                            "case_version": run["expected_incident_version"],
                            "request_id": "soar-"
                            + _digest([run_id, step["step_id"]])[:50],
                        },
                        (run_id, position),
                    )
                if action["type"] != "webhook":
                    if time.monotonic() >= deadline or (
                        cancel is not None and cancel.is_set()
                    ):
                        break
                    action_key = run_id + ":" + step["step_id"]
                    if db.execute(
                        "SELECT 1 FROM case_action_receipts WHERE tenant=? AND action_key=?",
                        (actor["tenant"], action_key),
                    ).fetchone():
                        # A local step and its receipt/checkpoint commit in one
                        # transaction. A pending step cannot legitimately have
                        # a prior receipt; it may be an old public-key collision.
                        raise ConflictError(
                            "Unexpected existing workflow action receipt"
                        )
                    result = casework.apply_action(
                        db,
                        store,
                        actor,
                        run["incident_id"],
                        action,
                        action_key,
                    )
                    _finish(db, store, run, step, result, now)
                    processed += 1
                    continue
                if (
                    run["config_digest"] != store.soar_webhooks.fingerprint
                    or action["destination"] not in store.soar_webhooks.destinations
                ):
                    raise ConflictError("Approved webhook configuration changed")
                if time.monotonic() >= deadline or (
                    cancel is not None and cancel.is_set()
                ):
                    break
                token = str(uuid.uuid4())
                lease = now + 15
                db.execute(
                    "UPDATE soar_steps SET state='sending',attempts=attempts+1,lease_until=?,attempt_token=? WHERE run_id=? AND position=?",
                    (lease, token, run_id, position),
                )
                db.execute(
                    "UPDATE soar_runs SET state='sending',next_run=?,updated=? WHERE id=?",
                    (lease, now, run_id),
                )
                store.audit(
                    db,
                    run["tenant"],
                    actor["name"],
                    "soar.webhook_begin",
                    {
                        "run_id": run_id,
                        "step_id": step["step_id"],
                        "destination": action["destination"],
                        "action_key": run_id + ":" + step["step_id"],
                    },
                )
                external = action
            # No SQLite transaction or write lock is held across a network call.
            # Repeat current actor, independent approver, complete incident and
            # evidence checks immediately before dispatch. A remote side effect
            # cannot be atomically rolled back with later local revocation.
            with store.control() as db:
                db.execute("BEGIN")
                fresh = db.execute(
                    "SELECT * FROM soar_runs WHERE id=?", (run_id,)
                ).fetchone()
                pending_step = db.execute(
                    "SELECT attempt_token FROM soar_steps WHERE run_id=? AND position=?",
                    (run_id, position),
                ).fetchone()
                if (
                    fresh["state"] != "sending"
                    or pending_step["attempt_token"] != token
                ):
                    continue
                if fresh["cancel_requested"]:
                    raise PermissionError("Run was cancelled before dispatch")
                actor = _executor(db, fresh)
            payload = encode(
                {
                    "schema": "sapientia.soar.webhook.v1",
                    "run_id": run_id,
                    "step_id": step["step_id"],
                    "incident_id": run["incident_id"],
                    "payload": external["payload"],
                }
            ).encode()
            result = store.soar_webhooks.send(
                external["destination"],
                payload,
                run_id + ":" + step["step_id"],
                max(0.01, deadline - time.monotonic()),
            )
            with store.write_lock, store.control() as db:
                db.execute("BEGIN IMMEDIATE")
                fresh = db.execute(
                    "SELECT * FROM soar_runs WHERE id=?", (run_id,)
                ).fetchone()
                current_step = db.execute(
                    "SELECT * FROM soar_steps WHERE run_id=? AND position=?",
                    (run_id, position),
                ).fetchone()
                if (
                    current_step["attempt_token"] == token
                    and fresh["state"] == "sending"
                ):
                    # Retain acknowledgement even if privileges changed during
                    # transit, then stop all subsequent steps on the next check.
                    _finish(db, store, fresh, current_step, result, now)
            processed += 1
        except _QueueEndpoint as queued:
            from . import endpoint_response

            try:
                if time.monotonic() >= deadline or (
                    cancel is not None and cancel.is_set()
                ):
                    break
                endpoint_response.create(
                    store,
                    queued.actor,
                    run["incident_id"],
                    queued.data,
                    workflow=queued.workflow,
                )
                processed += 1
            except (PermissionError, KeyError, ValueError, ConflictError):
                _failure(
                    store,
                    run_id,
                    position,
                    now,
                    "endpoint_target_or_authorization_unavailable",
                )
                processed += 1
            except (CapacityError, sqlite3.OperationalError):
                _failure(
                    store,
                    run_id,
                    position,
                    now,
                    "endpoint_queue_capacity_unavailable",
                    transient=True,
                )
                processed += 1
        except _EndpointUnknown:
            _failure(
                store, run_id, position, now, "endpoint_outcome_unknown", unknown=True
            )
            processed += 1
        except _RecoverRemote:
            _failure(
                store,
                run_id,
                position,
                now,
                "remote_outcome_unknown_after_restart",
                transient=safe,
                unknown=True,
                token=token,
            )
            processed += 1
        except (PermissionError, KeyError):
            if position is not None:
                _failure(
                    store,
                    run_id,
                    position,
                    now,
                    "authorization_unavailable",
                    token=token,
                )
                processed += 1
        except (ValueError, ConflictError):
            if position is not None:
                _failure(
                    store,
                    run_id,
                    position,
                    now,
                    "approved_state_or_action_unavailable",
                    token=token,
                )
                processed += 1
        except (OSError, TimeoutError, queue.Empty):
            if position is not None:
                safe = external is not None and store.soar_webhooks.guaranteed(
                    external["destination"]
                )
                _failure(
                    store,
                    run_id,
                    position,
                    now,
                    "remote_outcome_unknown",
                    transient=safe,
                    unknown=True,
                    token=token,
                )
                processed += 1
        except CapacityError:
            if position is not None:
                _failure(
                    store,
                    run_id,
                    position,
                    now,
                    "capacity_unavailable",
                    transient=True,
                    token=token,
                )
                processed += 1
        except sqlite3.OperationalError:
            if position is not None:
                _failure(
                    store,
                    run_id,
                    position,
                    now,
                    "control_storage_unavailable",
                    transient=True,
                    token=token,
                )
                processed += 1
    return processed
