"""Verify the local audit chain and compare it with an operator-held checkpoint.

A checkpoint is evidence only while it is protected independently of the data
directory. These helpers do not provide an immutable or WORM storage service.
"""

import hashlib
import hmac
import json
import os
import re
import tempfile
import time
from pathlib import Path

from .storage import encode

ZERO = "0" * 64


def _checkpoint(value):
    if (
        not isinstance(value, dict)
        or value.get("schema") != 1
        or type(value.get("sequence")) is not int
        or value["sequence"] < 0
        or not isinstance(value.get("digest"), str)
        or not re.fullmatch(r"[a-f0-9]{64}", value["digest"])
        or (value["sequence"] == 0 and value["digest"] != ZERO)
    ):
        raise ValueError("Invalid audit checkpoint")
    return value


def read_checkpoint(path):
    return _checkpoint(json.loads(Path(path).read_text(encoding="utf-8")))


def verify(store, checkpoint=None):
    if checkpoint is not None:
        checkpoint = (
            read_checkpoint(checkpoint)
            if isinstance(checkpoint, (str, Path))
            else _checkpoint(checkpoint)
        )
    errors, previous, sequence, count = [], ZERO, 0, 0
    anchored = checkpoint is None or checkpoint["sequence"] == 0
    with store.control() as db:
        for row in db.execute("SELECT * FROM audit ORDER BY seq"):
            count += 1
            reason = []
            if row["seq"] != sequence + 1:
                reason.append("sequence discontinuity")
            if row["previous"] != previous:
                reason.append("previous digest mismatch")
            expected = hashlib.sha256(
                encode(
                    [
                        row["at"],
                        row["tenant"],
                        row["actor"],
                        row["action"],
                        row["detail"],
                        row["previous"],
                    ]
                ).encode()
            ).hexdigest()
            digest_valid = isinstance(row["digest"], str) and re.fullmatch(
                r"[a-f0-9]{64}", row["digest"]
            )
            if not digest_valid or not hmac.compare_digest(row["digest"], expected):
                reason.append("row digest mismatch")
            if checkpoint is not None and row["seq"] == checkpoint["sequence"]:
                anchored = bool(digest_valid) and hmac.compare_digest(
                    row["digest"], checkpoint["digest"]
                )
                if not anchored:
                    reason.append("checkpoint digest mismatch")
            if reason and len(errors) < 20:
                errors.append({"sequence": row["seq"], "reason": "; ".join(reason)})
            sequence, previous = row["seq"], row["digest"]
    if not anchored:
        errors.append(
            {
                "sequence": checkpoint["sequence"],
                "reason": "checkpoint missing or chain truncated",
            }
        )
    return {
        "valid": not errors,
        "count": count,
        "sequence": sequence,
        "digest": previous,
        "checkpoint_verified": checkpoint is not None and anchored,
        "errors": errors,
        "assurance": "Local hash chain; protect checkpoints independently. No WORM guarantee.",
    }


def create_checkpoint(store):
    result = verify(store)
    if not result["valid"]:
        raise ValueError("Audit chain verification failed; checkpoint refused")
    return {
        "schema": 1,
        "sequence": result["sequence"],
        "digest": result["digest"],
        "created": time.time(),
    }


def write_checkpoint(store, path):
    path = Path(path).resolve()
    if path == store.path or store.path in path.parents:
        raise ValueError("Store audit checkpoints outside the data directory")
    with store.write_lock:
        value = create_checkpoint(store)
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            prefix=".audit-checkpoint-", dir=path.parent
        )
        try:
            if os.name != "nt":
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(encode(value))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return value
