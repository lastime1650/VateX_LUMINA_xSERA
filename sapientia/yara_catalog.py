"""Pinned, immutable-source public YARA inventory; no scanning or activation.

Each entry is a complete upstream file. Namespaces preserve both duplicate rule
identifiers and the scope of global/private helper rules. Source and license
bytes are checked on every load; callers receive independent mutable copies.
"""
import hashlib
import json
import re
import subprocess
import sys
from importlib import resources
from pathlib import PurePosixPath

from .yara_runtime import isolated_command

SCHEMA = "xsera.yara-catalog.v1"
MANIFEST_SHA256 = "8fab59933420f358e88e3613a618e7eaa273b22deb8d2c4416d9db209cdbf28e"
MAX_SOURCE_BYTES = 32768
MAX_TOTAL_BYTES = 16 * 1024 * 1024
_FORBIDDEN = re.compile(r"\b(?:include|import)\b")
_ID = re.compile(r"YC-[0-9a-f]{24}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


class CatalogIntegrityError(ValueError):
    pass


def _root():
    return resources.files("sapientia").joinpath("catalogs", "yara")


def _path(value):
    if not isinstance(value, str):
        raise CatalogIntegrityError("Catalog path must be text")
    path = PurePosixPath(value)
    if path.is_absolute() or not value or "\\" in value or any(part in {"", ".", ".."} or ":" in part for part in path.parts):
        raise CatalogIntegrityError("Catalog path escapes package boundary")
    return path


def _bytes(path):
    try:
        return _root().joinpath(*_path(path).parts).read_bytes()
    except (OSError, ValueError) as exc:
        raise CatalogIntegrityError("Catalog package file unavailable: "+str(path)) from exc


def _digest(body):
    return hashlib.sha256(body).hexdigest()


def _manifest():
    body = _bytes("manifest.json")
    if len(body) > MAX_TOTAL_BYTES or _digest(body) != MANIFEST_SHA256:
        raise CatalogIntegrityError("Pinned YARA catalog manifest hash mismatch")
    try:
        manifest = json.loads(body)
    except (ValueError, UnicodeError) as exc:
        raise CatalogIntegrityError("Invalid catalog manifest JSON") from exc
    entries, sources = manifest.get("entries"), manifest.get("sources")
    if manifest.get("schema") != SCHEMA or not isinstance(entries, list) or not 1 <= len(entries) <= 4096 or not isinstance(sources, list):
        raise CatalogIntegrityError("Unsupported catalog manifest schema")
    identifiers = [e.get("id") for e in entries]
    if any(not isinstance(value, str) or not _ID.fullmatch(value) for value in identifiers) or len(set(identifiers)) != len(identifiers):
        raise CatalogIntegrityError("Catalog entry IDs are invalid or duplicated")
    if (manifest.get("file_count") != len(entries) or manifest.get("rule_count") != sum(e["rule_count"] for e in entries)
            or manifest.get("public_rule_count") != sum(e["public_rule_count"] for e in entries)
            or sum(e["bytes"] for e in entries) > MAX_TOTAL_BYTES):
        raise CatalogIntegrityError("Catalog count or source byte bound mismatch")
    expected_sources = {s["id"]: s for s in sources}
    for entry in entries:
        source = expected_sources.get(entry.get("source_id"))
        if (not source or entry.get("repository") != source["repository"] or entry.get("commit") != source["commit"]
                or entry.get("license") != source["license"] or entry.get("license_file") != source["license_file"]
                or not entry.get("license_review", {}).get("accepted") or not entry.get("quality_review", {}).get("accepted")
                or not _SHA.fullmatch(entry.get("sha256", "")) or entry.get("rule_count") != len(entry.get("rules", []))
                or entry.get("public_rule_count") != sum(not rule["private"] for rule in entry["rules"])
                or not 1 <= entry.get("bytes", 0) <= MAX_SOURCE_BYTES):
            raise CatalogIntegrityError("Catalog provenance, quality or rule count mismatch")
        if _path(entry["file_path"]).parts[:2] != ("rules", entry["source_id"]):
            raise CatalogIntegrityError("Catalog source path differs from its upstream scope")
    for source in sources:
        notice = _bytes(source["license_file"])
        if _digest(notice) != source["license_sha256"]:
            raise CatalogIntegrityError("Catalog license notice hash mismatch")
        selected = [entry for entry in entries if entry["source_id"] == source["id"]]
        if source["included_files"] != len(selected) or source["rule_count"] != sum(e["rule_count"] for e in selected) or source["public_rule_count"] != sum(e["public_rule_count"] for e in selected):
            raise CatalogIntegrityError("Catalog upstream totals mismatch")
    return manifest


def _entry(entry, include_source):
    body = _bytes(entry["file_path"])
    if len(body) != entry["bytes"] or _digest(body) != entry["sha256"]:
        raise CatalogIntegrityError("Immutable YARA source hash mismatch: "+entry["id"])
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CatalogIntegrityError("Catalog source encoding changed") from exc
    if _FORBIDDEN.search(text) or any(ord(character)<32 and character not in "\t\r\n" for character in text):
        raise CatalogIntegrityError("Catalog source exceeds module/include/text policy")
    # The manifest was decoded for this call, so no mutable object escapes
    # into another caller or shared cache.
    result = dict(entry)
    if include_source:
        result["source"] = text
    return result


def inventory(*, include_source=True):
    """List checked independent entries; source means unchanged YARA text."""
    if type(include_source) is not bool:
        raise ValueError("include_source must be boolean")
    return [_entry(entry, include_source) for entry in _manifest()["entries"]]


def get(identifier):
    if not isinstance(identifier, str) or not _ID.fullmatch(identifier):
        raise KeyError("YARA catalog entry not found")
    for entry in _manifest()["entries"]:
        if entry["id"] == identifier:
            return _entry(entry, True)
    raise KeyError("YARA catalog entry not found")


def summary():
    manifest = _manifest()
    for entry in manifest["entries"]:
        _entry(entry, False)
    return {"schema": SCHEMA, "revision": manifest["revision"], "manifest_sha256": MANIFEST_SHA256,
            "captured_utc": manifest["captured_utc"], "file_count": manifest["file_count"], "rule_count": manifest["rule_count"],
            "public_rule_count": manifest["public_rule_count"], "private_helper_count": manifest["rule_count"]-manifest["public_rule_count"],
            "source_bytes": sum(e["bytes"] for e in manifest["entries"]), "sources": manifest["sources"],
            "excluded_file_count": len(manifest["excluded"]), "constraints": manifest["constraints"],
            "integrity_verified": True, "automatic_response": False, "malware_accuracy_measured": False}


_COMPILE_CHILD = r"""
import json,sys
request=json.load(sys.stdin)
try:
 import yara
 rules=yara.compile(sources=request["sources"],includes=False,error_on_warning=True)
 rows=list(rules)
 matches=rules.match(data=b"xSERA harmless compatibility probe. No executable or malware is loaded.",timeout=1)
 print(json.dumps({"status":"completed","version":yara.__version__,"rule_count":len(rows),
  "public_rule_count":sum(not r.is_private for r in rows),"harmless_matches":[{"rule":m.rule,"namespace":m.namespace,"author":m.meta.get("author")} for m in matches]},allow_nan=False))
except Exception as exc:
 print(json.dumps({"status":"failed","reason":type(exc).__name__+": "+str(exc)[:400]}))
"""


def verify(*, compile_rules=False):
    """Optional offline real compile/probe; never reads a local sample."""
    if type(compile_rules) is not bool:
        raise ValueError("compile_rules must be boolean")
    result = summary()
    if not compile_rules:
        return result
    entries = inventory()
    payload = json.dumps({"sources": {e["id"].replace("-", "_"):e["source"] for e in entries}}, ensure_ascii=False)
    try:
        child = subprocess.run(isolated_command(_COMPILE_CHILD), input=payload, capture_output=True,
            text=True, encoding="utf-8", timeout=3, check=False,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
    except subprocess.TimeoutExpired:
        result["compilation"] = {"status": "timeout", "outer_deadline_seconds": 3}
        return result
    if child.returncode or len(child.stdout.encode()) > 32768:
        result["compilation"] = {"status": "failed", "reason": "validator child/output bound"}
        return result
    try:
        compilation = json.loads(child.stdout)
    except ValueError:
        compilation = {"status": "failed", "reason": "validator returned invalid JSON"}
    if compilation.get("status") == "completed" and (compilation.get("rule_count") != result["rule_count"] or compilation.get("public_rule_count") != result["public_rule_count"]):
        raise CatalogIntegrityError("Actual compiled rule count differs from catalog")
    result["compilation"] = compilation
    return result
