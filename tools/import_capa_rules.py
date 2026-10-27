"""Import only Apache-2.0 text rules from an exact official capa-rules commit.

No samples or upstream Python are extracted. An existing different destination
is refused so an update cannot silently replace the release pack.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import urllib.request
import zipfile


def import_pack(destination, commit):
    if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
        raise ValueError("Require exact lowercase Git commit SHA")
    destination = Path(destination)
    if destination.exists():
        raise ValueError("Destination already exists; review an update in a new directory")
    url = "https://codeload.github.com/mandiant/capa-rules/zip/" + commit
    with urllib.request.urlopen(url, timeout=30) as response:
        body = response.read(16 * 1024 * 1024 + 1)
    if len(body) > 16 * 1024 * 1024:
        raise ValueError("Archive download exceeds budget")
    archive = zipfile.ZipFile(io.BytesIO(body))
    files, total = [], 0
    for entry in archive.infolist():
        parts = PurePosixPath(entry.filename).parts
        if len(parts) < 2 or any(p in {".", ".."} for p in parts) or entry.flag_bits & 1:
            continue
        relative = PurePosixPath(*parts[1:])
        if str(relative) != "LICENSE.txt" and relative.suffix not in {".yml", ".yaml"}:
            continue
        if str(relative).startswith(".github/"):
            continue
        if entry.file_size > 1024 * 1024 or len(files) >= 20000:
            raise ValueError("Archive text member budget exceeded")
        content = archive.read(entry)
        content.decode("utf-8")
        total += len(content)
        if total > 32 * 1024 * 1024:
            raise ValueError("Archive expanded text budget exceeded")
        files.append((relative, content))
    license_text = next(content for path, content in files if str(path) == "LICENSE.txt")
    if b"Apache License" not in license_text or b"Version 2.0" not in license_text:
        raise ValueError("Expected upstream Apache-2.0 license is absent")
    records = []
    for relative, content in files:
        path = destination / ("rules" if str(relative) != "LICENSE.txt" else "") / str(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        records.append({"path": path.relative_to(destination).as_posix(), "sha256": hashlib.sha256(content).hexdigest(), "bytes": len(content)})
    manifest = {"schema": "xsera.capa.release.v1", "upstream": "https://github.com/mandiant/capa-rules", "commit": commit, "license": "Apache-2.0", "archive_sha256": hashlib.sha256(body).hexdigest(), "rule_files": len(files) - 1, "files": records}
    (destination / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("destination")
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    result = import_pack(args.destination, args.commit)
    print(json.dumps({k: v for k, v in result.items() if k != "files"}))
