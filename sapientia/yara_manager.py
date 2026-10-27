"""Managed release rules, scoped revisions and evidence-bound offline YARA runs."""

import base64
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

from . import access, content_notices, endpoint_artifacts, principal, release_manifest
from . import evidence_scope as evidence
from .storage import CapacityError, ConflictError, encode
from .yara_runtime import isolated_command

MAX_SOURCE = 32768
MAX_SOURCES_BYTES = 16 * 1024 * 1024
MAX_SAMPLE = 32 * 1024 * 1024
SCAN_SECONDS = 15
_gate = threading.BoundedSemaphore(1)


class _SourceBudgetError(CapacityError):
    """An unchanged source selection cannot fit by retrying it."""


def initialize(store):
    with store.control(local=True) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS yara_rules(
          tenant TEXT NOT NULL,id TEXT NOT NULL,revision INTEGER NOT NULL,
          definition TEXT NOT NULL,state TEXT NOT NULL,requester TEXT NOT NULL,
          approver TEXT,updated REAL NOT NULL,PRIMARY KEY(tenant,id));
        CREATE TABLE IF NOT EXISTS yara_rule_history(
          seq INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT NOT NULL,id TEXT NOT NULL,
          revision INTEGER NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,
          created REAL NOT NULL,body TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS yara_rule_epochs(tenant TEXT PRIMARY KEY,epoch INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS yara_runs(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,incident_id TEXT NOT NULL,
          artifact_id TEXT NOT NULL,index_name TEXT NOT NULL,actor TEXT NOT NULL,
          created REAL NOT NULL,body TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS yara_runs_case ON yara_runs(tenant,incident_id,created);
        CREATE TABLE IF NOT EXISTS yara_auto_jobs(
          artifact_id TEXT PRIMARY KEY,tenant TEXT NOT NULL,actor TEXT NOT NULL,
          state TEXT NOT NULL,updated REAL NOT NULL,result_id TEXT,error TEXT);
        """)


def _source(value):
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.encode("utf-8")) > MAX_SOURCE
        or any(ord(c) < 32 and c not in "\n\r\t" for c in value)
    ):
        raise ValueError("YARA source must be UTF-8 text within 32 KiB")
    if re.search(r"\b(?:include|import)\b", value):
        raise ValueError(
            "Managed YARA disables include directives and imported modules"
        )
    return value


def _worker(sources, *, body=None, timeout=None):
    if importlib.util.find_spec("yara") is None:
        return {
            "status": "unavailable",
            "matches": [],
            "error": "Install the pinned analysis extra in the server Python environment",
        }
    if (
        not sources
        or len(sources) > 4096
        or sum(len(s.encode("utf-8")) for s in sources.values()) > MAX_SOURCES_BYTES
    ):
        raise _SourceBudgetError(
            "Choose fewer YARA rule files; source budget is 4096 files / 16 MiB"
        )
    request = {"operation": "validate" if body is None else "scan", "sources": sources}
    if body is not None:
        if not isinstance(body, bytes) or len(body) > MAX_SAMPLE:
            raise ValueError("Immutable sample bytes must fit the 32 MiB scan limit")
        request["body"] = base64.b64encode(body).decode("ascii")
    if not _gate.acquire(blocking=False):
        raise CapacityError("Another YARA compile or scan is running; retry shortly")
    try:
        script = Path(__file__).with_name("yara_worker.py").read_text(encoding="utf-8")
        try:
            child = subprocess.run(
                isolated_command(script),
                input=encode(request),
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=timeout or SCAN_SECONDS,
                creationflags=subprocess.CREATE_NO_WINDOW
                if sys.platform == "win32"
                else 0,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "matches": [],
                "error": "YARA isolated worker wall deadline exceeded",
            }
        if child.returncode or len(child.stdout.encode("utf-8")) > 256 * 1024:
            return {
                "status": "failed",
                "matches": [],
                "error": "YARA isolated worker failed or exceeded its output budget",
            }
        try:
            result = json.loads(child.stdout)
        except (ValueError, TypeError):
            result = None
        if (
            not isinstance(result, dict)
            or result.get("status")
            not in {"completed", "failed", "timeout", "unavailable"}
            or not isinstance(result.get("matches"), list)
            or len(result["matches"]) > 256
            or any(
                not isinstance(m, dict)
                or m.get("namespace") not in sources
                or not isinstance(m.get("rule"), str)
                or len(m["rule"]) > 128
                for m in result["matches"]
            )
        ):
            return {
                "status": "failed",
                "matches": [],
                "error": "YARA child result failed validation",
            }
        return result
    finally:
        _gate.release()


def validate(source):
    return _worker({"validation": _source(source)}, timeout=5)


def build_rule(data):
    required = {"name", "strings", "match", "format", "max_bytes"}
    if (
        not isinstance(data, dict)
        or not required <= set(data)
        or set(data) - required - {"description"}
    ):
        raise ValueError(
            "Expected name,strings,match,format,max_bytes and optional description"
        )
    name = data["name"]
    if not isinstance(name, str) or not re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]{0,127}", name
    ):
        raise ValueError(
            "Rule identifier requires 1..128 ASCII letters, digits or underscores, starting with a letter/underscore"
        )
    strings = data["strings"]
    if not isinstance(strings, list) or not 1 <= len(strings) <= 32:
        raise ValueError("Provide 1..32 text or hexadecimal patterns")
    patterns = []
    for i, item in enumerate(strings):
        if (
            not isinstance(item, dict)
            or set(item) - {"kind", "value", "nocase", "wide"}
            or not {"kind", "value"} <= set(item)
        ):
            raise ValueError(
                "Pattern requires kind,value and optional boolean modifiers"
            )
        for modifier in ("nocase", "wide"):
            if modifier in item and type(item[modifier]) is not bool:
                raise ValueError("Pattern modifiers must be boolean")
        value = item["value"]
        if not isinstance(value, str) or not 1 <= len(value) <= 1024:
            raise ValueError("Pattern length must be 1..1024 characters")
        if item["kind"] == "text":
            if (
                any(ord(c) < 32 for c in value)
                or item.get("wide")
                and any(ord(c) > 126 for c in value)
            ):
                raise ValueError(
                    "Text patterns require visible UTF-8; wide modifiers require ASCII (use hex for exact UTF-16 bytes)"
                )
            encoded = json.dumps(value, ensure_ascii=False)
            modifiers = (
                " ascii"
                + (" wide" if item.get("wide") else "")
                + (" nocase" if item.get("nocase") else "")
            )
        elif item["kind"] == "hex":
            if (
                item.get("wide")
                or item.get("nocase")
                or not re.fullmatch(
                    r"(?:[0-9a-fA-F?]{2})(?:\s+[0-9a-fA-F?]{2})*", value.strip()
                )
            ):
                raise ValueError(
                    "Hex patterns use space-separated bytes or ?? wildcards without text modifiers"
                )
            if not re.search(r"[0-9a-fA-F]", value):
                raise ValueError("Hex patterns must contain a fixed nibble")
            encoded, modifiers = "{ " + value.strip().upper() + " }", ""
        else:
            raise ValueError("Pattern kind must be text or hex")
        patterns.append(f"    $s{i + 1} = {encoded}{modifiers}")
    match = evidence.choice(data["match"], {"all", "any"}, "pattern match")
    form = evidence.choice(data["format"], {"any", "pe", "elf"}, "file format")
    maximum = evidence.integer(data["max_bytes"], "max_bytes", 1, MAX_SAMPLE)
    description = evidence.text(
        data.get("description", ""), "description", 1000, empty=True
    )
    conditions = [f"filesize <= {maximum}"]
    if form == "pe":
        conditions += [
            "filesize >= 64",
            "uint16(0) == 0x5a4d",
            "uint32(uint32(0x3c)) == 0x00004550",
        ]
    elif form == "elf":
        conditions.append("uint32(0) == 0x464c457f")
    conditions.append(f"{match} of ($s*)")
    source = (
        f"rule {name} {{\n  meta:\n    description = {json.dumps(description, ensure_ascii=False)}\n  strings:\n"
        + "\n".join(patterns)
        + "\n  condition:\n    "
        + " and ".join(conditions)
        + "\n}\n"
    )
    return {"source": source, "validation": validate(source)}


def _builtin(item):
    authors = item.get("authors", item.get("author", ""))
    author_text = "; ".join(authors) if isinstance(authors, list) else authors
    return {
        **item,
        "revision": 1,
        "indexes": ["*"],
        "enabled": True,
        "origin": "builtin",
        "state": "active",
        "effective_state": "active",
        "requester": "release",
        "approver": "release",
        "author": author_text
        or "원본 저자 미표기 · " + item.get("repository", "upstream"),
        "rule_count": item.get("rule_count", 1),
    }


def _effective(db, row):
    item = {
        **json.loads(row["definition"]),
        "id": row["id"],
        "revision": row["revision"],
        "state": row["state"],
        "requester": row["requester"],
        "approver": row["approver"],
        "updated": row["updated"],
    }
    state = item["state"]
    release_copy = (
        item["origin"] == "builtin"
        and row["requester"] == "release"
        and row["approver"] == "release"
    )
    if state == "active" and release_copy:
        from . import yara_catalog

        original = yara_catalog.get(row["id"])
        if (
            item["sha256"] != original["sha256"]
            or item["source"] != original["source"]
            or item["indexes"] != ["*"]
        ):
            state = "authority_changed"
    elif state == "active":
        if not row["approver"] or row["approver"] == row["requester"]:
            state = "authority_changed"
        else:
            for name in (row["requester"], row["approver"]):
                try:
                    person = principal.current(
                        db,
                        {"name": name, "tenant": row["tenant"], "role": "admin"},
                        ("admin",),
                    )
                    if not principal.contains(
                        person["allowed_indexes"], item["indexes"]
                    ):
                        state = "authority_changed"
                except PermissionError:
                    state = "authority_changed"
    item["effective_state"] = (
        state if not (state == "active" and not item["enabled"]) else "disabled"
    )
    return item


def _inventory(db, actor):
    from . import yara_catalog

    items = {v["id"]: _builtin(v) for v in yara_catalog.inventory()}
    for row in db.execute(
        "SELECT * FROM yara_rules WHERE tenant=?", (actor["tenant"],)
    ):
        item = _effective(db, row)
        if principal.contains(actor["allowed_indexes"], item["indexes"]):
            items[row["id"]] = item
        else:
            items.pop(row["id"], None)
    return items


def _rule(db, actor, identifier):
    from . import yara_catalog

    row = db.execute(
        "SELECT * FROM yara_rules WHERE tenant=? AND id=?",
        (actor["tenant"], identifier),
    ).fetchone()
    if row:
        item = _effective(db, row)
        if not principal.contains(actor["allowed_indexes"], item["indexes"]):
            raise KeyError("YARA rule not found")
        return item
    return _builtin(yara_catalog.get(identifier))


def list_rules(store, who, *, q="", offset=0, limit=100, origin="all", state="all"):
    evidence.text(q, "search", 200, empty=True)
    evidence.integer(offset, "offset", 0, 2**31 - 1)
    evidence.integer(limit, "limit", 1, 200)
    evidence.choice(origin, {"all", "builtin", "custom"}, "origin")
    evidence.choice(
        state,
        {
            "all",
            "active",
            "pending",
            "deleted",
            "disabled",
            "rejected",
            "authority_changed",
        },
        "state",
    )
    with principal.transaction(store, who) as (db, actor):
        items = [
            v
            for v in _inventory(db, actor).values()
            if (origin == "all" or v["origin"] == origin)
            and (state == "all" or v["effective_state"] == state)
            and (
                not q
                or q.casefold()
                in " ".join(
                    str(v.get(k, ""))
                    for k in ("name", "description", "author", "license", "id")
                ).casefold()
            )
        ]
        items.sort(
            key=lambda v: (v["origin"] == "builtin", v["name"].casefold(), v["id"])
        )
        return {
            "items": [
                {k: v for k, v in item.items() if k != "source"}
                for item in items[offset : offset + limit]
            ],
            "total": len(items),
            "offset": offset,
            "limit": limit,
        }


def get_rule(store, who, identifier):
    with principal.transaction(store, who) as (db, actor):
        return _rule(db, actor, identifier)


def _changed(store, db, actor, identifier, revision, action, item):
    db.execute(
        "INSERT INTO yara_rule_epochs VALUES(?,1) ON CONFLICT(tenant) DO UPDATE SET epoch=epoch+1",
        (actor["tenant"],),
    )
    db.execute(
        "INSERT INTO yara_rule_history(tenant,id,revision,actor,action,created,body) VALUES(?,?,?,?,?,?,?)",
        (
            actor["tenant"],
            identifier,
            revision,
            actor["name"],
            action,
            time.time(),
            encode(item),
        ),
    )
    store.audit(
        db,
        actor["tenant"],
        actor["name"],
        "yara.rule." + action,
        {"id": identifier, "revision": revision, "sha256": item.get("sha256")},
    )


def save_rule(store, who, data, identifier=None):
    required = {"name", "source", "indexes", "enabled"}
    allowed = (
        required | {"description"} | ({"expected_revision"} if identifier else set())
    )
    if not isinstance(data, dict) or not required <= set(data) or set(data) - allowed:
        raise ValueError(
            "Expected name,source,indexes,enabled,description and update expected_revision"
        )
    name = evidence.text(data["name"], "name", 160)
    description = evidence.text(
        data.get("description", ""), "description", 2000, empty=True
    )
    source = _source(data["source"])
    if type(data["enabled"]) is not bool:
        raise ValueError("enabled must be boolean")
    if identifier:
        evidence.integer(
            data.get("expected_revision"), "expected_revision", 1, 2**31 - 1
        )
    with principal.transaction(store, who, ("admin",)) as (db, actor):
        old = _rule(db, actor, identifier) if identifier else None
        if old and old["origin"] == "builtin":
            access.require_full_admin(db, actor)
            if data["indexes"] != ["*"]:
                raise ValueError(
                    "Built-in overrides retain the tenant-wide scope; clone for scoped custom rules"
                )
            indexes = ["*"]
        else:
            indexes = evidence.indexes(data["indexes"])
        if not principal.contains(actor["allowed_indexes"], indexes):
            raise PermissionError("YARA scope exceeds current permissions")
        if old and data.get("expected_revision") != old["revision"]:
            raise ConflictError("YARA rule revision changed; refresh first")
    validation = validate(source)
    if validation["status"] == "failed" or validation["status"] == "timeout":
        raise ValueError(
            "YARA compilation failed: " + validation.get("error", validation["status"])
        )
    identifier = identifier or "YR-" + uuid.uuid4().hex
    with principal.transaction(store, actor, ("admin",), write=True) as (db, fresh):
        if old:
            current = _rule(db, fresh, identifier)
            if current["revision"] != old["revision"]:
                raise ConflictError("YARA rule changed during compilation")
        if not principal.contains(fresh["allowed_indexes"], indexes):
            raise PermissionError("YARA scope changed during compilation")
        revision = old["revision"] + 1 if old else 1
        item = {
            "name": name,
            "source": source,
            "description": description,
            "indexes": indexes,
            "enabled": data["enabled"],
            "origin": old["origin"] if old else "custom",
            "sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
            "author": old.get("author", fresh["name"]) if old else fresh["name"],
            "modified_by": fresh["name"],
            "rule_count": validation.get("rule_count"),
            "validation": validation,
            "license": old.get("license", "Local rule") if old else "Local rule",
            "upstream_url": old.get("upstream_url", "") if old else "",
        }
        if old:
            for key in (
                "authors",
                "license_url",
                "repository",
                "commit",
                "upstream_path",
                "file_path",
            ):
                if key in old:
                    item[key] = old[key]
        db.execute(
            "INSERT INTO yara_rules VALUES(?,?,?,?,'pending',?,NULL,?) ON CONFLICT(tenant,id) DO UPDATE SET revision=excluded.revision,definition=excluded.definition,state='pending',requester=excluded.requester,approver=NULL,updated=excluded.updated",
            (
                fresh["tenant"],
                identifier,
                revision,
                encode(item),
                fresh["name"],
                time.time(),
            ),
        )
        _changed(store, db, fresh, identifier, revision, "save", item)
        return _effective(
            db,
            db.execute(
                "SELECT * FROM yara_rules WHERE tenant=? AND id=?",
                (fresh["tenant"], identifier),
            ).fetchone(),
        )


def review_rule(store, who, identifier, expected_revision, approve, reason):
    evidence.integer(expected_revision, "expected_revision", 1, 2**31 - 1)
    evidence.text(reason, "review reason", 2000)
    if type(approve) is not bool:
        raise ValueError("approve must be boolean")
    with principal.transaction(store, who, ("admin",)) as (db, actor):
        item = _rule(db, actor, identifier)
        if item["revision"] != expected_revision or item["state"] != "pending":
            raise ConflictError("YARA revision is not pending or changed")
        if item["requester"] == actor["name"]:
            raise PermissionError(
                "A different administrator must approve YARA rule changes"
            )
    checked = validate(item["source"]) if approve else {"status": "completed"}
    if checked["status"] != "completed":
        raise ConflictError(
            "Real YARA compilation must succeed before activation: " + checked["status"]
        )
    with principal.transaction(store, actor, ("admin",), write=True) as (db, fresh):
        current = _rule(db, fresh, identifier)
        if current["revision"] != expected_revision or current["state"] != "pending":
            raise ConflictError("YARA rule changed during review")
        requester = principal.current(
            db,
            {"name": current["requester"], "tenant": fresh["tenant"], "role": "admin"},
            ("admin",),
        )
        if not principal.contains(requester["allowed_indexes"], current["indexes"]):
            raise PermissionError("YARA requester scope changed")
        definition = {
            k: v
            for k, v in current.items()
            if k
            not in {
                "id",
                "revision",
                "state",
                "effective_state",
                "requester",
                "approver",
                "updated",
            }
        }
        if approve:
            definition.update(rule_count=checked["rule_count"], validation=checked)
        db.execute(
            "UPDATE yara_rules SET state=?,approver=?,updated=?,definition=? WHERE tenant=? AND id=?",
            (
                "active" if approve else "rejected",
                fresh["name"],
                time.time(),
                encode(definition),
                fresh["tenant"],
                identifier,
            ),
        )
        _changed(
            store,
            db,
            fresh,
            identifier,
            expected_revision,
            "approve" if approve else "reject",
            {**current, "review_reason": reason},
        )
        return _rule(db, fresh, identifier)


def delete_rule(store, who, identifier, expected_revision, reason):
    evidence.integer(expected_revision, "expected_revision", 1, 2**31 - 1)
    evidence.text(reason, "deletion reason", 2000)
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        item = _rule(db, actor, identifier)
        if item["revision"] != expected_revision or item["state"] == "deleted":
            raise ConflictError("YARA rule changed or was already deleted")
        if item["origin"] == "builtin":
            access.require_full_admin(db, actor)
        revision = expected_revision + 1
        definition = {
            k: v
            for k, v in item.items()
            if k
            not in {
                "id",
                "revision",
                "state",
                "effective_state",
                "requester",
                "approver",
                "updated",
            }
        }
        db.execute(
            "INSERT INTO yara_rules VALUES(?,?,?,?,'deleted',?,NULL,?) ON CONFLICT(tenant,id) DO UPDATE SET revision=excluded.revision,definition=excluded.definition,state='deleted',requester=excluded.requester,approver=NULL,updated=excluded.updated",
            (
                actor["tenant"],
                identifier,
                revision,
                encode(definition),
                actor["name"],
                time.time(),
            ),
        )
        _changed(
            store, db, actor, identifier, revision, "delete", {**item, "reason": reason}
        )
        return _rule(db, actor, identifier)


def restore_rule(store, who, identifier, expected_revision):
    from . import yara_catalog

    evidence.integer(expected_revision, "expected_revision", 1, 2**31 - 1)
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        item = _rule(db, actor, identifier)
        if not db.execute(
            "SELECT 1 FROM yara_rules WHERE tenant=? AND id=?",
            (actor["tenant"], identifier),
        ).fetchone():
            raise ConflictError("The built-in rule has no local override to restore")
        if item["revision"] != expected_revision:
            raise ConflictError("YARA rule revision changed")
        revision = expected_revision + 1
        if item["origin"] == "builtin":
            access.require_full_admin(db, actor)
            original = _builtin(yara_catalog.get(identifier))
            requester, approver, state = "release", "release", "active"
        else:
            original = item
            requester, approver, state = actor["name"], None, "pending"
        definition = {
            k: v
            for k, v in original.items()
            if k
            not in {
                "id",
                "revision",
                "state",
                "effective_state",
                "requester",
                "approver",
                "updated",
            }
        }
        db.execute(
            "UPDATE yara_rules SET revision=?,definition=?,state=?,requester=?,approver=?,updated=? WHERE tenant=? AND id=?",
            (
                revision,
                encode(definition),
                state,
                requester,
                approver,
                time.time(),
                actor["tenant"],
                identifier,
            ),
        )
        _changed(store, db, actor, identifier, revision, "restore", original)
        return _rule(db, actor, identifier)


def status(store, who):
    from . import yara_catalog

    with principal.transaction(store, who) as (db, actor):
        items = _inventory(db, actor)
        return {
            "runtime_available": importlib.util.find_spec("yara") is not None,
            "catalog": yara_catalog.summary(),
            "rules": {
                "total": len(items),
                "active": sum(i["effective_state"] == "active" for i in items.values()),
            },
            "max_artifact_bytes": MAX_SAMPLE,
            "sample_execution": False,
            "process_memory_scan": False,
            "automatic_process_artifact_scan": True,
            "custom_rule_peer_review": True,
            "no_match_verdict": "unknown",
            "imports": False,
            "includes": False,
        }


def list_artifacts(store, who, *, incident_id=None):
    with principal.transaction(store, who) as (db, actor):
        if incident_id:
            principal.incident(db, actor, incident_id)
        rows = db.execute(
            "SELECT a.*,r.action,r.evidence_event_id,j.state AS yara_job_state,j.error AS yara_job_error,j.result_id AS yara_run_id FROM endpoint_artifacts a JOIN endpoint_responses r ON r.id=a.command_id LEFT JOIN yara_auto_jobs j ON j.artifact_id=a.id WHERE a.tenant=? ORDER BY a.updated DESC",
            (actor["tenant"],),
        )
        items = []
        for row in rows:
            if (
                incident_id
                and row["incident_id"] != incident_id
                or not principal.contains(actor["allowed_indexes"], [row["index_name"]])
            ):
                continue
            try:
                principal.incident(db, actor, row["incident_id"])
            except (KeyError, PermissionError):
                continue
            item = dict(row)
            item["action"] = json.loads(item["action"])
            items.append(item)
            if len(items) >= 200:
                break
        return {"items": items, "total": len(items), "limit": 200}


def _epoch(db, tenant):
    row = db.execute(
        "SELECT epoch FROM yara_rule_epochs WHERE tenant=?", (tenant,)
    ).fetchone()
    return row[0] if row else 0


def scan_artifact(store, who, artifact_id, *, rule_ids=None, emit_signal=True):
    if type(emit_signal) is not bool:
        raise ValueError("emit_signal must be boolean")
    if rule_ids is not None and (
        not isinstance(rule_ids, list)
        or not 1 <= len(rule_ids) <= 4096
        or any(not isinstance(i, str) for i in rule_ids)
        or len(set(rule_ids)) != len(rule_ids)
    ):
        raise ValueError(
            "Select 1..4096 unique YARA rule file IDs or omit the selection"
        )
    with principal.transaction(store, who, ("admin", "analyst")) as (_, actor):
        pass
    body, _, sha = endpoint_artifacts.download(store, actor, artifact_id)
    with principal.transaction(store, actor, ("admin", "analyst")) as (db, fresh):
        artifact = db.execute(
            "SELECT * FROM endpoint_artifacts WHERE tenant=? AND id=?",
            (fresh["tenant"], artifact_id),
        ).fetchone()
        principal.incident(db, fresh, artifact["incident_id"])
        inventory = _inventory(db, fresh)
        selected = [
            item
            for item in inventory.values()
            if item["effective_state"] == "active"
            and (item["indexes"] == ["*"] or artifact["index_name"] in item["indexes"])
            and (rule_ids is None or item["id"] in rule_ids)
        ]
        if rule_ids is not None and {i["id"] for i in selected} != set(rule_ids):
            raise ConflictError(
                "A selected rule is unavailable, unapproved, disabled, deleted or outside the artifact scope"
            )
        if not selected:
            raise ConflictError(
                "No active YARA rules are available in this artifact scope"
            )
        epoch = _epoch(db, fresh["tenant"])
        command = db.execute(
            "SELECT * FROM endpoint_responses WHERE tenant=? AND id=?",
            (fresh["tenant"], artifact["command_id"]),
        ).fetchone()
        if not command:
            raise ConflictError("Original collection command is unavailable")
        source_event_id = command["evidence_event_id"]
    originals = evidence.originals(store, actor, [source_event_id])
    # Independent namespaces preserve exact upstream sources and their intra-file dependencies.
    mapped = {"r_" + str(i): item for i, item in enumerate(selected)}
    began = time.perf_counter()
    result = _worker(
        {key: _source(item["source"]) for key, item in mapped.items()}, body=body
    )
    matches = [
        {
            **m,
            "rule_id": mapped[m["namespace"]]["id"],
            "revision": mapped[m["namespace"]]["revision"],
            "author": mapped[m["namespace"]].get("author", "") if mapped[m["namespace"]].get("origin") == "builtin" else m.get("author") or mapped[m["namespace"]].get("author", ""),
            "authors": list(dict.fromkeys([*mapped[m["namespace"]].get("authors", []), *([m["author"]] if isinstance(m.get("author"), str) and m["author"] else [])])),
            "license": (m.get("license") if mapped[m["namespace"]].get("origin") == "custom" else None) or mapped[m["namespace"]].get("license", ""),
            "license_url": (m.get("license_url") if mapped[m["namespace"]].get("origin") == "custom" else None) or mapped[m["namespace"]].get("license_url", ""),
            "license_file": mapped[m["namespace"]].get("license_file", ""),
            "repository": mapped[m["namespace"]].get("repository", ""),
            "commit": mapped[m["namespace"]].get("commit", ""),
            "upstream_url": (m.get("source_url") if mapped[m["namespace"]].get("origin") == "custom" else None) or mapped[m["namespace"]].get("upstream_url", ""),
            "source_sha256": mapped[m["namespace"]]["sha256"],
        }
        for m in result["matches"]
    ]
    finished = time.time()
    run_id = "YR-RUN-" + uuid.uuid4().hex
    result = {
        **result,
        "id": run_id,
        "artifact_id": artifact_id,
        "incident_id": artifact["incident_id"],
        "sha256": sha,
        "matches": matches,
        "selected_file_count": len(selected),
        "selected_rule_count": sum(i.get("rule_count") or 0 for i in selected),
        "verdict": "suspicious" if matches else "unknown",
        "coverage_complete": result["status"] == "completed"
        and not result.get("matches_truncated", False),
        "sample_executed": False,
        "process_memory_scanned": False,
        "duration_ms": round((time.perf_counter() - began) * 1000, 3),
        "created": finished,
        "event_ids": [source_event_id],
        "signal_id": None,
        "rules_digest": release_manifest.digest(
            [[i["id"], i["revision"], i["sha256"]] for i in selected]
        ),
        "meaning": "Static disk executable rule match; no match is unknown, not clean. Matching is not a calibrated malware probability.",
        "rules": [
            {"id": i["id"], "revision": i["revision"], "sha256": i["sha256"]}
            for i in selected
        ],
    }
    result["content_notices"] = content_notices.yara_matches(matches, complete=not result.get("matches_truncated", False))
    with (
        store.segment_lock.read(deadline=time.monotonic() + 3),
        principal.transaction(store, actor, ("admin", "analyst"), write=True) as (
            db,
            fresh,
        ),
    ):
        principal.incident(db, fresh, artifact["incident_id"])
        evidence.recheck(db, fresh, originals)
        current = db.execute(
            "SELECT * FROM endpoint_artifacts WHERE tenant=? AND id=?",
            (fresh["tenant"], artifact_id),
        ).fetchone()
        if (
            not current
            or current["state"] != "complete"
            or current["sha256"] != sha
            or current["total_bytes"] != len(body)
        ):
            raise ConflictError("Artifact changed during YARA analysis")
        if epoch != _epoch(db, fresh["tenant"]):
            raise ConflictError(
                "YARA rules changed during analysis; rerun with the current revisions"
            )
        current_rules = _inventory(db, fresh)
        for item in selected:
            latest = current_rules.get(item["id"])
            if (
                not latest
                or latest["effective_state"] != "active"
                or latest["revision"] != item["revision"]
                or latest["sha256"] != item["sha256"]
            ):
                raise ConflictError(
                    "YARA rule scope, authority or content changed during analysis"
                )
        if matches and emit_signal:
            from . import intelligence

            signal = intelligence.publish_in_transaction(
                store,
                db,
                fresh,
                {
                    "event_ids": [source_event_id],
                    "kind": "finding",
                    "rule_id": "yara:binary",
                    "rule_revision": 1,
                    "features": {
                        "yara_match_count": result.get("match_count", len(matches)),
                        "artifact_sha256": sha,
                    },
                    "severity": "high",
                    "confidence_grade": "managed_static_binary_signature_match",
                    "context_digest": release_manifest.digest(
                        [sha, result["rules_digest"]]
                    ),
                    "metadata": {
                        "yara_run_id": run_id,
                        "artifact_id": artifact_id,
                        "sample_executed": False,
                        "matched_rules": [
                            {
                                k: m[k]
                                for k in ("rule_id", "rule", "author", "authors", "license", "license_url", "license_file", "upstream_url", "repository", "commit", "source_sha256")
                            }
                            for m in matches[:32]
                        ],
                        "matches_truncated": len(matches) > 32
                        or result.get("matches_truncated", False),
                        "content_notices": result["content_notices"],
                    },
                },
            )
            result["signal_id"] = signal["id"]
        db.execute(
            "INSERT INTO yara_runs VALUES(?,?,?,?,?,?,?,?)",
            (
                run_id,
                fresh["tenant"],
                artifact["incident_id"],
                artifact_id,
                artifact["index_name"],
                fresh["name"],
                finished,
                encode(result),
            ),
        )
        store.audit(
            db,
            fresh["tenant"],
            fresh["name"],
            "yara.artifact.scan",
            {
                "id": run_id,
                "artifact_id": artifact_id,
                "sha256": sha,
                "status": result["status"],
                "match_count": len(matches),
                "signal_id": result["signal_id"],
                "sample_executed": False,
            },
        )
    return result


def get_run(store, who, identifier):
    with principal.transaction(store, who) as (db, actor):
        row = db.execute(
            "SELECT * FROM yara_runs WHERE tenant=? AND id=?",
            (actor["tenant"], identifier),
        ).fetchone()
        if not row or not principal.contains(
            actor["allowed_indexes"], [row["index_name"]]
        ):
            raise KeyError("YARA run not found")
        principal.incident(db, actor, row["incident_id"])
        return json.loads(row["body"])


def list_runs(store, who, *, incident_id=None):
    with principal.transaction(store, who) as (db, actor):
        if incident_id:
            principal.incident(db, actor, incident_id)
        items = []
        for row in db.execute(
            "SELECT * FROM yara_runs WHERE tenant=? ORDER BY created DESC",
            (actor["tenant"],),
        ):
            if (
                incident_id
                and row["incident_id"] != incident_id
                or not principal.contains(actor["allowed_indexes"], [row["index_name"]])
            ):
                continue
            try:
                principal.incident(db, actor, row["incident_id"])
            except (KeyError, PermissionError):
                continue
            item = json.loads(row["body"])
            item.pop("rules", None)
            items.append(item)
            if len(items) >= 100:
                break
        return {"items": items, "total": len(items), "limit": 100}


def run_due(store, cancel=None):
    """Automatic scan only for explicitly requested process-executable collections."""
    if cancel is not None and cancel.is_set():
        return 0
    with store.write_lock, store.control(local=True) as db:
        db.execute(
            "UPDATE yara_auto_jobs SET state='pending',updated=? WHERE state='running' AND updated<?",
            (time.time(), time.time() - 120),
        )
        rows = db.execute(
            "SELECT a.id,a.tenant,r.requester FROM endpoint_artifacts a JOIN endpoint_responses r ON r.id=a.command_id LEFT JOIN yara_auto_jobs j ON j.artifact_id=a.id WHERE a.state='complete' AND json_extract(r.action,'$.source')='process_executable' AND j.artifact_id IS NULL ORDER BY a.updated LIMIT 8"
        ).fetchall()
        for row in rows:
            db.execute(
                "INSERT OR IGNORE INTO yara_auto_jobs VALUES(?,?,?,'pending',?,NULL,NULL)",
                (row["id"], row["tenant"], row["requester"], time.time()),
            )
        job = db.execute(
            "SELECT * FROM yara_auto_jobs WHERE state='pending' ORDER BY updated LIMIT 1"
        ).fetchone()
        if not job:
            return 0
        db.execute(
            "UPDATE yara_auto_jobs SET state='running',updated=? WHERE artifact_id=?",
            (time.time(), job["artifact_id"]),
        )
    try:
        result = scan_artifact(
            store,
            {"name": job["actor"], "tenant": job["tenant"], "role": "admin"},
            job["artifact_id"],
        )
        state, identifier = result["status"], result["id"]
        error = (
            None
            if state == "completed"
            else result.get("error") or "YARA inspection " + state
        )
    except _SourceBudgetError as exc:
        state, error, identifier = "excluded", str(exc)[:1000], None
    except CapacityError as exc:
        state, error, identifier = "pending", str(exc)[:1000], None
    except (ValueError, KeyError, PermissionError, OSError) as exc:
        state, error, identifier = "excluded", str(exc)[:1000], None
    with store.write_lock, store.control(local=True) as db:
        db.execute(
            "UPDATE yara_auto_jobs SET state=?,updated=?,result_id=?,error=? WHERE artifact_id=?",
            (state, time.time(), identifier, error, job["artifact_id"]),
        )
    return int(state == "completed")
