"""Reproducible release identity; no production data or credential discovery."""

import base64
import hashlib
import importlib.metadata
import json
import os
import re
import stat
import sysconfig
import tomllib
from pathlib import Path, PurePosixPath

from . import __version__

SCHEMA = "xsera.release-manifest.v1"
WIRE_VERSION = 1
CONTROL_VERSION = 1
RELEASE_ROOTS = ("sapientia", "tests", "tools", "docs", "deploy", "yocto")
ROOT_FILES = ("pyproject.toml", "requirements-lock.txt", "README.md", "LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md", "SECURITY.md", "MANIFEST.in", "setup.py")
EXCLUDED = {"__pycache__", ".pytest_cache", ".ruff_cache", ".git", "node_modules"}
EXTENSIONS = {".py", ".json", ".toml", ".txt", ".md", ".js", ".cjs", ".css", ".html", ".ps1", ".sh", ".c", ".h", ".rs", ".bb", ".bbappend", ".conf", ".service", ".yar", ".yara", ".yaml", ".yml", ".zeek", ".cfg", ".rules", ".jsonl"}
MAX_FILES = 10000
MAX_BYTES = 128 * 1024 * 1024
INSTALLED_MANIFEST = "xsera-source-manifest.json"
MAX_INSTALLED_MANIFEST_BYTES = 4 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def hash_file(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400:
        raise ValueError("Release inputs must be ordinary files")
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("Release file budget exceeded")
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def build(root=None):
    root = Path(root or Path(__file__).resolve().parents[1]).resolve(strict=True)
    files = {}
    total = 0
    candidates = [root / name for name in ROOT_FILES if (root / name).is_file()]
    for directory in RELEASE_ROOTS:
        base = root / directory
        if not base.exists():
            continue
        if base.is_symlink():
            raise ValueError("Release directories must not be links")
        for parent, dirs, names in os.walk(base, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in EXCLUDED)
            for child in dirs:
                p = Path(parent) / child
                if p.is_symlink() or getattr(p.lstat(), "st_file_attributes", 0) & 0x400:
                    raise ValueError("Release directories must not be links")
            for name in sorted(names):
                p = Path(parent) / name
                if p.suffix.lower() in EXTENSIONS:
                    candidates.append(p)
    for path in sorted(candidates):
        relative = path.relative_to(root).as_posix()
        if any(part in EXCLUDED for part in path.parts):
            continue
        total += path.stat().st_size
        if len(files) >= MAX_FILES or total > MAX_BYTES:
            raise ValueError("Release source budget exceeded")
        files[relative] = hash_file(path)
    package = (root / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^\"]+)"', package, re.MULTILINE)
    if not match or match[1] != __version__:
        raise ValueError("Package/module release versions differ")
    identity = {"schema": SCHEMA, "release": __version__, "wire_version": WIRE_VERSION,
                "control_version": CONTROL_VERSION, "files": files}
    return {**identity, "source_digest": digest(identity), "source_bytes": total,
            "native_qualified": False, "code_signed": False}


def verify(manifest, root=None):
    actual = build(root)
    return {"matches": actual["source_digest"] == manifest.get("source_digest"),
            "expected_digest": manifest.get("source_digest"), "actual_digest": actual["source_digest"],
            "changed": sorted(p for p in set(actual["files"]) | set(manifest.get("files", {}))
                              if actual["files"].get(p) != manifest.get("files", {}).get(p))}


def _plain_file(path):
    """No link aliases or shared file identities in an installed authority."""
    path = Path(os.path.abspath(path))
    for parent in (*path.parents, path):
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Installed identity paths must not contain links")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("Installed identity requires ordinary unshared files")
    return path


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate installed identity JSON key")
        result[key] = value
    return result


def _nonfinite(value):
    raise ValueError("Nonfinite installed identity JSON value")


def _installed_document(raw):
    if not raw or len(raw) > MAX_INSTALLED_MANIFEST_BYTES:
        raise ValueError("Bounded installed source inventory required")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                              parse_constant=_nonfinite)
    except (UnicodeError, RecursionError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid installed source inventory JSON") from exc
    identity_fields = {"schema", "release", "wire_version", "control_version", "files"}
    if not isinstance(document, dict) or set(document) != identity_fields | {
        "source_digest", "source_bytes", "native_qualified", "code_signed"
    }:
        raise ValueError("Exact complete installed source inventory required")
    if (document["schema"] != SCHEMA or document["release"] != __version__
            or type(document["wire_version"]) is not int or document["wire_version"] != WIRE_VERSION
            or type(document["control_version"]) is not int or document["control_version"] != CONTROL_VERSION
            or type(document["source_bytes"]) is not int or not 0 <= document["source_bytes"] <= MAX_BYTES
            or document["native_qualified"] is not False or document["code_signed"] is not False):
        raise ValueError("Installed inventory version or provenance differs")
    files = document["files"]
    if not isinstance(files, dict) or not 1 <= len(files) <= MAX_FILES:
        raise ValueError("Bounded installed inventory files required")
    if not {"pyproject.toml", "setup.py", "sapientia/__init__.py", "sapientia/release_manifest.py"} <= set(files):
        raise ValueError("Complete source identity roots are required")
    for name, expected in files.items():
        if (not isinstance(name, str) or not 1 <= len(name) <= 1024 or "\\" in name or ":" in name
                or any(ord(character) < 32 for character in name)):
            raise ValueError("Invalid installed inventory path")
        parts = name.split("/")
        if any(part in {"", ".", ".."} or part in EXCLUDED for part in parts):
            raise ValueError("Invalid installed inventory path")
        if name not in ROOT_FILES and (len(parts) < 2 or parts[0] not in RELEASE_ROOTS):
            raise ValueError("Installed inventory path is outside release roots")
        if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            raise ValueError("Installed inventory SHA-256 required")
    identity = {key: document[key] for key in identity_fields}
    if (not isinstance(document["source_digest"], str)
            or document["source_digest"] != digest(identity)):
        raise ValueError("Installed source inventory digest differs")
    return document


def _installed_identity(distribution, root):
    if distribution is None or distribution.version != __version__:
        raise ValueError("Current installed application distribution is unavailable")
    package = Path(os.path.abspath(distribution.locate_file("sapientia")))
    if package != root / "sapientia" or _plain_file(package / "release_manifest.py") != _plain_file(__file__):
        raise ValueError("Installed inventory distribution does not own the imported application")
    entries = distribution.files
    if entries is None:
        raise ValueError("Installed application RECORD is unavailable")
    markers = [item for item in entries if len(PurePosixPath(str(item)).parts) == 2
               and PurePosixPath(str(item)).parts[0].endswith(".dist-info")
               and PurePosixPath(str(item)).name == INSTALLED_MANIFEST]
    if len(markers) != 1:
        raise ValueError("One installed source inventory is required")
    marker_entry = markers[0]
    marker = _plain_file(distribution.locate_file(marker_entry))
    if marker.parent.parent != root or marker.stat().st_size > MAX_INSTALLED_MANIFEST_BYTES:
        raise ValueError("Installed source inventory is outside its distribution")
    raw = marker.read_bytes()
    record_hash = marker_entry.hash
    if (record_hash is None or record_hash.mode != "sha256"
            or record_hash.value != base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")):
        raise ValueError("Installed source inventory differs from wheel RECORD")
    document = _installed_document(raw)
    expected = {name: value for name, value in document["files"].items() if name.startswith("sapientia/")}
    recorded = {str(item) for item in entries if str(item).startswith("sapientia/")}
    if not expected or recorded != set(expected):
        raise ValueError("Installed application RECORD runtime file set differs")
    actual = set()
    total = 0
    for parent, dirs, names in os.walk(package, followlinks=False):
        for name in dirs:
            candidate = Path(parent) / name
            info = candidate.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("Installed runtime directory must not be a link")
        for name in names:
            candidate = _plain_file(Path(parent) / name)
            relative = candidate.relative_to(root).as_posix()
            actual.add(relative)
            total += candidate.stat().st_size
            if len(actual) > MAX_FILES or total > MAX_BYTES or relative not in expected:
                raise ValueError("Installed runtime has an unexpected file or exceeds its budget")
            if hash_file(candidate) != expected[relative]:
                raise ValueError("Installed runtime file differs from source inventory")
    if actual != set(expected):
        raise ValueError("Installed runtime source file is missing")
    return document


def current_identity():
    """Bind qualification to actual runtime bytes, without changing build().

    A wheel inventory is not a publisher signature. The signed installer and
    protected package establish installation integrity; record() additionally
    verifies an independent qualification signature over this complete digest.
    Every call rechecks files. Missing wheel metadata never becomes a source
    checkout or a version-only/environment-provided identity.
    """
    root = Path(os.path.abspath(__file__)).parents[1]
    try:
        distribution = importlib.metadata.distribution("vatex-lumina-xsera")
    except importlib.metadata.PackageNotFoundError:
        distribution = None
    wheel_record = distribution is not None and any(
        PurePosixPath(str(item)).parts
        and PurePosixPath(str(item)).parts[0].endswith(".dist-info")
        for item in distribution.files or []
    )
    owned = wheel_record and Path(os.path.abspath(distribution.locate_file("sapientia"))) == root / "sapientia"
    libraries = {Path(os.path.abspath(sysconfig.get_path(kind))) for kind in ("purelib", "platlib")}
    if owned or root in libraries or root.name in {"site-packages", "dist-packages"}:
        return _installed_identity(distribution, root)
    project = root / "pyproject.toml"
    if not project.is_file():
        raise ValueError("Genuine source checkout or verified installed inventory required")
    metadata = tomllib.loads(_plain_file(project).read_text(encoding="utf-8"))
    if (metadata.get("project", {}).get("name") != "vatex-lumina-xsera"
            or metadata["project"].get("version") != __version__):
        raise ValueError("Source checkout project identity differs")
    return build(root)
