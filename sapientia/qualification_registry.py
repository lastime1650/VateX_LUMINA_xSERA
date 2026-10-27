"""Pinned, source/config-bound signed qualification receipts; assertions are not proof."""

import base64
import json
import math
import re
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import migrations, principal, release_manifest
from .storage import encode

HEX = re.compile(r"[0-9a-f]{64}\Z")
SCHEMA = "xsera.qualification.v1"
FIELDS = {"schema", "signer", "tenant", "indexes", "source_digest", "package_digest", "config_digest", "tool_digest", "platform", "capability", "native", "passed", "checks", "created", "expires"}


def initialize(store):
    migrations.apply_store(store, "qualification", [
        "CREATE TABLE IF NOT EXISTS qualification_manifests(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,indexes TEXT NOT NULL,signer TEXT NOT NULL,document TEXT NOT NULL,signature TEXT NOT NULL,source_digest TEXT NOT NULL,config_digest TEXT NOT NULL,capability TEXT NOT NULL,platform TEXT NOT NULL,expires REAL NOT NULL,created REAL NOT NULL)"])


def keys(store):
    path = getattr(store.settings, "qualification_keys", None)
    if path is None:
        return {}
    from pathlib import Path
    path = Path(path)
    if path.is_symlink() or path.stat().st_size > 65536:
        raise ValueError("Bounded ordinary qualification key file required")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or len(value) > 64 or any(not isinstance(k, str) or not isinstance(v, str) for k, v in value.items()):
        raise ValueError("Pinned qualification public keys required")
    return value


def verify(envelope, trusted_keys, now=None):
    now = time.time() if now is None else now
    if not isinstance(envelope, dict) or set(envelope) != {"document", "signature"}:
        raise ValueError("Exact signed qualification envelope required")
    doc = envelope["document"]
    if not isinstance(doc, dict) or set(doc) != FIELDS or doc["schema"] != SCHEMA:
        raise ValueError("Exact qualification document required")
    if len(release_manifest.canonical(doc)) > 65536:
        raise ValueError("Qualification budget exceeded")
    for field in ("source_digest", "package_digest", "config_digest", "tool_digest"):
        if not isinstance(doc[field], str) or not HEX.fullmatch(doc[field]):
            raise ValueError("Qualification hash required")
    for field in ("created", "expires"):
        if type(doc[field]) not in (int, float) or not math.isfinite(doc[field]):
            raise ValueError("Finite qualification time required")
    if not doc["created"] <= now < doc["expires"] or doc["expires"] - doc["created"] > 31 * 86400:
        raise ValueError("Qualification expired or future-dated")
    if type(doc["native"]) is not bool or type(doc["passed"]) is not bool:
        raise ValueError("Typed qualification provenance required")
    for field in ("signer", "tenant", "platform", "capability"):
        if not isinstance(doc[field], str) or not 1 <= len(doc[field]) <= 256:
            raise ValueError("Bounded qualification identity required")
    if not isinstance(doc["checks"], list) or not 1 <= len(doc["checks"]) <= 256 or any(not isinstance(c, dict) or set(c) != {"name", "passed", "artifact_digest"} or not isinstance(c["name"], str) or not 1 <= len(c["name"]) <= 256 or type(c["passed"]) is not bool or not isinstance(c["artifact_digest"], str) or not HEX.fullmatch(c["artifact_digest"]) for c in doc["checks"]):
        raise ValueError("Exact independently recorded checks required")
    if len({c["name"] for c in doc["checks"]}) != len(doc["checks"]) or doc["passed"] != all(c["passed"] for c in doc["checks"]):
        raise ValueError("Qualification check summary differs")
    try:
        key = base64.b64decode(trusted_keys[doc["signer"]], validate=True)
        signature = base64.b64decode(envelope["signature"], validate=True)
        Ed25519PublicKey.from_public_bytes(key).verify(signature, release_manifest.canonical(doc))
    except (KeyError, ValueError, TypeError, InvalidSignature) as exc:
        raise PermissionError("Qualification signer/signature unavailable") from exc
    if doc["native"] and (doc["platform"].lower().startswith(("virtual", "synthetic", "simulation")) or doc["capability"].lower().startswith(("virtual", "synthetic", "simulation"))):
        raise ValueError("Explicit virtual qualification cannot claim native hardware effectiveness")
    return dict(doc)


def record(store, who, envelope):
    doc = verify(envelope, keys(store))
    source = release_manifest.current_identity()["source_digest"]
    if doc["source_digest"] != source:
        raise ValueError("Qualification belongs to another source release")
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        from .access import validate
        indexes = validate(doc["indexes"])
        if not indexes or indexes == ["*"] or doc["tenant"] != actor["tenant"] or not principal.contains(actor["allowed_indexes"], indexes):
            raise PermissionError("Qualification outside current scope")
        identifier = release_manifest.digest(doc)
        db.execute("INSERT OR IGNORE INTO qualification_manifests VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                   (identifier, actor["tenant"], encode(indexes), doc["signer"], encode(doc), envelope["signature"], source, doc["config_digest"], doc["capability"], doc["platform"], doc["expires"], doc["created"]))
        store.audit(db, actor["tenant"], actor["name"], "qualification.record", {"id": identifier, "native": doc["native"], "passed": doc["passed"]})
        return {"id": identifier, "native": doc["native"], "passed": doc["passed"]}


def check(store, who, *, capability, platform, config_digest, source_digest, package_digest):
    trusted = keys(store)
    with principal.transaction(store, who) as (db, actor):
        rows = db.execute("SELECT * FROM qualification_manifests WHERE tenant=? AND capability=? AND platform=? AND config_digest=? AND source_digest=? AND expires>? ORDER BY created DESC", (actor["tenant"], capability, platform, config_digest, source_digest, time.time())).fetchall()
        for row in rows:
            if not principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
                continue
            try:
                doc = verify({"document": json.loads(row["document"]), "signature": row["signature"]}, trusted)
            except (PermissionError, ValueError):
                continue
            if doc["native"] and doc["passed"] and doc["package_digest"] == package_digest:
                return {"qualified": True, "receipt_id": row["id"], "scope": doc["indexes"], "expires": doc["expires"]}
    return {"qualified": False, "reason": "no_current_matching_pinned_native_receipt"}
