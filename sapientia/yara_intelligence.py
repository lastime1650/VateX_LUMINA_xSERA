"""Current, evidence-bound YARA finding parents for composite detection.

Historical runs remain readable after a rule is retired. Their use in a new
composite still requires an exact persisted signal, an intact collected file,
current Case/source authority and at least one unchanged active matched rule.
"""

import hashlib
import json
import os
import re
import stat
from pathlib import Path

from . import endpoint_artifacts, evidence_scope, principal, release_manifest
from .storage import ConflictError

EDITORS = ("admin", "analyst")


def _signature(value):
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _regular(value):
    return stat.S_ISREG(value.st_mode) and not (
        getattr(value, "st_file_attributes", 0) & 0x400
    )


def _intact(store, db, artifact, memo):
    """Hash at most 32 MiB; reuse only this transaction's same-stat proof."""
    if not re.fullmatch(r"ART-[0-9a-f]{32}", artifact["id"]):
        return False
    maximum = endpoint_artifacts.artifact_limit(db, artifact)
    if not 0 <= artifact["total_bytes"] <= min(
        maximum, endpoint_artifacts.PROCESS_MAX_BYTES
    ):
        return False
    directory = Path(store.path) / "response-artifacts"
    directory_stat = directory.lstat()
    if not stat.S_ISDIR(directory_stat.st_mode) or (
        getattr(directory_stat, "st_file_attributes", 0) & 0x400
    ):
        return False
    path = directory / (artifact["id"] + ".bin")
    before = path.lstat()
    if not _regular(before) or before.st_size != artifact["total_bytes"]:
        return False
    key = (str(path), artifact["sha256"], _signature(before))
    cache = None
    if memo is not None and db.in_transaction:
        entry = memo.get("yara_files")
        if not isinstance(entry, dict) or entry.get("db") is not db:
            entry = memo["yara_files"] = {"db": db, "hashes": {}}
        cache = entry["hashes"]
        if key in cache:
            return cache[key]
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        # Windows path-stat and handle-stat expose different historical ctime
        # semantics. Compare identity/size/mtime across the open handle; the
        # complete path signature (including ctime) is checked again below.
        if _signature(os.fstat(stream.fileno()))[:-1] != _signature(before)[:-1]:
            return False
        remaining = artifact["total_bytes"]
        while remaining:
            part = stream.read(min(65536, remaining))
            if not part:
                return False
            digest.update(part)
            remaining -= len(part)
        if stream.read(1) or _signature(os.fstat(stream.fileno()))[:-1] != _signature(
            before
        )[:-1]:
            return False
    after = path.lstat()
    intact = (
        _regular(after)
        and _signature(after) == _signature(before)
        and digest.hexdigest() == artifact["sha256"]
    )
    if cache is not None:
        if len(cache) >= 256:
            cache.pop(next(iter(cache)))
        cache[key] = intact
    return intact


def validate_parent(store, db, actor, body, memo=None):
    """Fail closed without granting endpoint effects or inventing ancestry."""
    from . import yara_manager

    try:
        actor = principal.current(db, actor, EDITORS)
        if (
            not isinstance(body, dict)
            or body.get("kind") != "finding"
            or body.get("rule_id") != "yara:binary"
        ):
            return False
        metadata = body.get("metadata", {})
        if not isinstance(metadata, dict):
            return False
        row = db.execute(
            "SELECT * FROM yara_runs WHERE tenant=? AND id=?",
            (actor["tenant"], metadata.get("yara_run_id")),
        ).fetchone()
        stored = db.execute(
            "SELECT body FROM intelligence_signals WHERE tenant=? AND id=?",
            (actor["tenant"], body.get("id")),
        ).fetchone()
        if not row or not stored:
            return False
        # Story reconciliation can replace only a recorded story association.
        # Every other identity, feature, receipt and provenance field is exact.
        saved = json.loads(stored["body"])
        if not isinstance(saved, dict):
            return False
        if {k: v for k, v in saved.items() if k != "story_id"} != {
            k: v for k, v in body.items() if k != "story_id"
        }:
            return False
        run = json.loads(row["body"])
        sha = run["sha256"]
        rule_snapshots = run["rules"]
        if (
            run["id"] != row["id"]
            or run["signal_id"] != body["id"]
            or run["status"] != "completed"
            or not run["matches"]
            or run["artifact_id"] != row["artifact_id"]
            or metadata.get("artifact_id") != row["artifact_id"]
            or run["incident_id"] != row["incident_id"]
            or run["event_ids"] != body["event_ids"]
            or len(run["event_ids"]) != 1
            or body.get("mode") != "live"
            or body.get("features")
            != {
                "artifact_sha256": sha,
                "yara_match_count": run.get("match_count", len(run["matches"])),
            }
            or body.get("context_digest")
            != release_manifest.digest([sha, run["rules_digest"]])
            or run["rules_digest"]
            != release_manifest.digest(
                [[r["id"], r["revision"], r["sha256"]] for r in rule_snapshots]
            )
            or not principal.contains(actor["allowed_indexes"], [row["index_name"]])
        ):
            return False
        case = principal.incident(db, actor, row["incident_id"])
        if case["status"] == "false_positive":
            return False
        author = principal.current(
            db,
            {"name": row["actor"], "tenant": actor["tenant"], "role": "analyst"},
            EDITORS,
        )
        if not principal.contains(author["allowed_indexes"], [row["index_name"]]):
            return False
        principal.incident(db, author, row["incident_id"])
        artifact = db.execute(
            "SELECT * FROM endpoint_artifacts WHERE tenant=? AND id=?",
            (actor["tenant"], row["artifact_id"]),
        ).fetchone()
        if (
            not artifact
            or artifact["state"] != "complete"
            or artifact["incident_id"] != row["incident_id"]
            or artifact["index_name"] != row["index_name"]
            or body["indexes"] != [row["index_name"]]
            or artifact["sha256"] != sha
        ):
            return False
        command = db.execute(
            "SELECT * FROM endpoint_responses WHERE tenant=? AND id=?",
            (actor["tenant"], artifact["command_id"]),
        ).fetchone()
        if (
            not command
            or command["incident_id"] != row["incident_id"]
            or command["index_name"] != row["index_name"]
            or command["agent_id"] != artifact["agent_id"]
            or [command["evidence_event_id"]] != body["event_ids"]
        ):
            return False
        evidence_scope.recheck(
            db, actor, {item["event_id"]: item for item in body["originals"]}
        )
        source = db.execute(
            "SELECT s.source_version,r.version,r.state FROM source_event_receipts s "
            "LEFT JOIN source_registry r ON r.tenant=s.tenant AND r.id=s.source_id "
            "WHERE s.tenant=? AND s.event_id=?",
            (actor["tenant"], command["evidence_event_id"]),
        ).fetchone()
        if source and (
            source["state"] != "active" or source["version"] != source["source_version"]
        ):
            return False
        if not _intact(store, db, artifact, memo):
            return False
        snapshots = {
            (r["id"], r["revision"], r["sha256"]) for r in rule_snapshots
        }
        for match in run["matches"]:
            pin = (match["rule_id"], match["revision"], match["source_sha256"])
            if pin not in snapshots:
                continue
            try:
                current = yara_manager._rule(db, actor, match["rule_id"])
                if (
                    current["effective_state"] == "active"
                    and current["revision"] == match["revision"]
                    and current["sha256"] == match["source_sha256"]
                    and hashlib.sha256(current["source"].encode("utf-8")).hexdigest()
                    == match["source_sha256"]
                ):
                    return True
            except (KeyError, PermissionError, ConflictError):
                continue
        return False
    except (KeyError, PermissionError, ValueError, TypeError, AttributeError, OSError):
        return False
