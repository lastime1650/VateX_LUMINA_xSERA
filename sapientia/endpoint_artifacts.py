"""Credential/lease/evidence-bound chunk transfer; incomplete objects are private."""

import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import time
import uuid
from pathlib import Path

from . import principal
from .storage import CapacityError, ConflictError

MAX_BYTES = 2 * 1024 * 1024
PROCESS_MAX_BYTES = 32 * 1024 * 1024
CHUNK_BYTES = 32 * 1024


def command_limit(target):
    """The larger cap belongs only to a frozen process-image collection target."""
    if target.get("type") == "collect_artifact" and target.get("source") == "process_executable":
        maximum = target.get("max_bytes", PROCESS_MAX_BYTES)
        if type(maximum) is not int or not 1 <= maximum <= PROCESS_MAX_BYTES:
            raise ValueError("Invalid frozen process executable byte limit")
        return maximum
    return MAX_BYTES


def artifact_limit(db, artifact):
    """Larger retained objects require the original exact command binding."""
    command = db.execute("SELECT * FROM endpoint_responses WHERE id=?", (artifact["command_id"],)).fetchone()
    if command is None:
        if artifact["total_bytes"] > MAX_BYTES:
            raise ConflictError("Large process artifact has no exact collection command")
        return MAX_BYTES  # Preserve old <=2MiB artifact history/backup contracts.
    target = json.loads(command["action"])
    if any(command[key] != artifact[key] for key in ("tenant", "incident_id", "index_name", "agent_id")) or target.get("type") != "collect_artifact" or target.get("sha256") != artifact["sha256"]:
        raise ConflictError("Artifact differs from its frozen collection command")
    if target.get("source") == "process_executable":
        from . import endpoint_response
        identity = target.get("start_identity", "")
        platform = "windows" if isinstance(identity, str) and identity.startswith("windows:") else "linux"
        if endpoint_response.action(target, platform) != target:
            raise ConflictError("Process artifact lacks a canonical exact executable command")
    return command_limit(target)


def initialize(db):
    db.executescript("""
    CREATE TABLE IF NOT EXISTS endpoint_artifacts(
      id TEXT PRIMARY KEY,command_id TEXT NOT NULL UNIQUE,tenant TEXT NOT NULL,
      incident_id TEXT NOT NULL,index_name TEXT NOT NULL,agent_id TEXT NOT NULL,
      sha256 TEXT NOT NULL,total_bytes INTEGER NOT NULL,received INTEGER NOT NULL,
      state TEXT NOT NULL,created REAL NOT NULL,updated REAL NOT NULL);
    """)


def _directory(store):
    from .backup import _private_directory

    root = Path(store.path) / "response-artifacts"
    if root.is_symlink():
        raise PermissionError("Artifact directory must not be a link")
    if root.exists() and not root.is_dir():
        raise ConflictError("Artifact directory is unavailable")
    try:
        root.mkdir(mode=0o700)
    except FileExistsError:
        created = False
    else:
        created = True
    if getattr(root.lstat(), "st_file_attributes", 0) & 0x400:
        raise PermissionError("Artifact directory must not be a reparse point")
    _private_directory(root, created=created)
    return root


def upload(store, service, credential, command_id, data):
    from . import endpoint_response as response

    fields = {
        "lease_token",
        "execution_id",
        "offset",
        "total_bytes",
        "sha256",
        "chunk_sha256",
        "body_base64",
    }
    if (
        not isinstance(data, dict)
        or set(data) != fields
        or type(data["offset"]) is not int
        or type(data["total_bytes"]) is not int
        or not 0 <= data["offset"] <= data["total_bytes"] <= PROCESS_MAX_BYTES
    ):
        raise ValueError("Bounded artifact chunk fields/offset/total required")
    if (
        not all(
            isinstance(data[key], str) and re.fullmatch(r"[0-9a-f]{64}", data[key])
            for key in ("sha256", "chunk_sha256")
        )
        or not isinstance(data["body_base64"], str)
        or len(data["body_base64"]) > 44000
    ):
        raise ValueError("Artifact hashes and bounded Base64 chunk required")
    try:
        chunk = base64.b64decode(data["body_base64"], validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("Invalid artifact Base64") from None
    if (
        len(chunk) > CHUNK_BYTES
        or (not chunk and data["total_bytes"] != 0)
        or data["offset"] + len(chunk) > data["total_bytes"]
        or hashlib.sha256(chunk).hexdigest() != data["chunk_sha256"]
    ):
        raise ValueError("Artifact chunk size or digest mismatch")
    with store.write_lock, store.control() as db:
        db.execute("BEGIN IMMEDIATE")
        command, execution = response._leased(
            db,
            service,
            credential,
            {
                "command_id": command_id,
                "lease_token": data["lease_token"],
                "execution_id": data["execution_id"],
            },
        )
        target = json.loads(command["action"])
        maximum = command_limit(target)
        if data["total_bytes"] > maximum:
            raise ValueError("Artifact exceeds the exact command's byte limit")
        if (
            command["state"] != "started"
            or command["execution_id"] != execution
            or command["expires"] <= time.time()
            or target["type"] != "collect_artifact"
            or target["sha256"] != data["sha256"]
        ):
            raise ConflictError(
                "Artifact requires an active exact collect_artifact execution"
            )
        response._guard(db, command)
        row = db.execute(
            "SELECT * FROM endpoint_artifacts WHERE command_id=?", (command_id,)
        ).fetchone()
        if row is None:
            if data["offset"] != 0:
                raise ConflictError("Artifact must begin at offset zero")
            # Durable inventory/history has no lifetime record-count ceiling.
            identifier, now = "ART-" + uuid.uuid4().hex, time.time()
            db.execute(
                "INSERT INTO endpoint_artifacts VALUES(?,?,?,?,?,?,?,?,0,'receiving',?,?)",
                (
                    identifier,
                    command_id,
                    command["tenant"],
                    command["incident_id"],
                    command["index_name"],
                    command["agent_id"],
                    data["sha256"],
                    data["total_bytes"],
                    now,
                    now,
                ),
            )
            row = db.execute(
                "SELECT * FROM endpoint_artifacts WHERE id=?", (identifier,)
            ).fetchone()
        if (
            row["sha256"] != data["sha256"]
            or row["total_bytes"] != data["total_bytes"]
            or data["offset"] > row["received"]
        ):
            raise ConflictError("Artifact transfer identity or offset changed")
        if row["state"] not in {"receiving", "complete"}:
            raise ConflictError("Artifact transfer is unknown and cannot resume")
        directory = _directory(store)
        part, final = (
            directory / (row["id"] + ".part"),
            directory / (row["id"] + ".bin"),
        )
        for path in (part, final):
            if path.is_symlink() or (
                path.exists() and getattr(path.lstat(), "st_file_attributes", 0) & 0x400
            ):
                raise PermissionError("Artifact object link rejected")
        # A completed rename may precede its SQLite commit during a crash.
        if final.exists() and row["state"] != "complete":
            if (
                final.stat().st_size != row["total_bytes"]
                or final.stat().st_size > maximum
            ):
                raise ConflictError("Artifact recovery object size mismatch")
            with final.open("rb") as stream:
                content = stream.read(maximum + 1)
            if (
                len(content) != row["total_bytes"]
                or hashlib.sha256(content).hexdigest() != row["sha256"]
            ):
                raise ConflictError("Artifact recovery object is corrupt")
            db.execute(
                "UPDATE endpoint_artifacts SET received=total_bytes,state='complete',updated=? WHERE id=?",
                (time.time(), row["id"]),
            )
            row = db.execute(
                "SELECT * FROM endpoint_artifacts WHERE id=?", (row["id"],)
            ).fetchone()
        if data["offset"] < row["received"] or row["state"] == "complete":
            existing = final if row["state"] == "complete" else part
            with existing.open("rb") as stream:
                stream.seek(data["offset"])
                if (
                    stream.read(len(chunk)) != chunk
                    or data["offset"] + len(chunk) > row["received"]
                ):
                    raise ConflictError("Conflicting artifact chunk retry")
            return {
                "artifact_id": row["id"],
                "received": row["received"],
                "complete": row["state"] == "complete",
                "sha256": row["sha256"],
                "duplicate": True,
            }
        if not part.exists() and row["received"]:
            raise ConflictError(
                "Artifact prefix disappeared; transfer remains incomplete"
            )
        if shutil.disk_usage(directory).free < getattr(
            store.settings, "min_free_bytes", 0
        ) + len(chunk):
            raise CapacityError("Artifact transfer disk reserve reached")
        with part.open("r+b" if part.exists() else "x+b") as stream:
            if stream.seek(0, 2) < row["received"]:
                raise ConflictError("Artifact prefix was truncated")
            stream.truncate(row["received"])
            stream.seek(row["received"])
            stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        received, complete = (
            data["offset"] + len(chunk),
            data["offset"] + len(chunk) == row["total_bytes"],
        )
        if complete:
            body = part.read_bytes()
            if (
                len(body) != row["total_bytes"]
                or hashlib.sha256(body).hexdigest() != row["sha256"]
            ):
                part.unlink(missing_ok=True)
                raise ConflictError("Complete artifact digest mismatch")
            os.replace(part, final)
        db.execute(
            "UPDATE endpoint_artifacts SET received=?,state=?,updated=? WHERE id=?",
            (received, "complete" if complete else "receiving", time.time(), row["id"]),
        )
        if complete:
            store.audit(
                db,
                command["tenant"],
                command["agent_id"],
                "endpoint.artifact_received",
                {
                    "artifact_id": row["id"],
                    "command_id": command_id,
                    "sha256": row["sha256"],
                    "bytes": received,
                },
            )
        return {
            "artifact_id": row["id"],
            "received": received,
            "complete": complete,
            "sha256": row["sha256"],
            "duplicate": False,
        }


def download(store, who, identifier):
    if not isinstance(identifier, str) or not re.fullmatch(
        r"ART-[0-9a-f]{32}", identifier
    ):
        raise KeyError("Artifact not found")
    with principal.transaction(store, who, write=True) as (db, actor):
        row = db.execute(
            "SELECT * FROM endpoint_artifacts WHERE id=? AND tenant=?",
            (identifier, actor["tenant"]),
        ).fetchone()
        if not row or not principal.contains(
            actor["allowed_indexes"], [row["index_name"]]
        ):
            raise KeyError("Artifact not found")
        principal.incident(db, actor, row["incident_id"])
        if row["state"] != "complete":
            raise ConflictError("Artifact transfer incomplete or unknown")
        maximum = artifact_limit(db, row)
        path = _directory(store) / (identifier + ".bin")
        if not path.exists():
            raise ConflictError("Artifact object disappeared")
        if (
            path.is_symlink()
            or getattr(path.lstat(), "st_file_attributes", 0) & 0x400
            or path.stat().st_size != row["total_bytes"]
            or row["total_bytes"] > maximum
        ):
            raise ConflictError("Artifact object unavailable or corrupt")
        with path.open("rb") as stream:
            body = stream.read(maximum + 1)
        if (
            len(body) != row["total_bytes"]
            or hashlib.sha256(body).hexdigest() != row["sha256"]
        ):
            raise ConflictError("Artifact content digest mismatch")
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "endpoint.artifact_download",
            {"artifact_id": identifier, "sha256": row["sha256"], "bytes": len(body)},
        )
        return body, identifier + ".bin", row["sha256"]
