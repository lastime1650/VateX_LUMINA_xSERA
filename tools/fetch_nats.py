"""Fetch pinned upstream NATS binaries and verify their published checksums."""

import argparse
import hashlib
import json
from pathlib import Path
import urllib.request
import zipfile

VERSION = "2.15.0"
BASE = f"https://github.com/nats-io/nats-server/releases/download/v{VERSION}/"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", type=Path, default=Path("vendor/nats"))
    args = parser.parse_args()
    args.destination.mkdir(parents=True, exist_ok=True)
    checksums = urllib.request.urlopen(BASE + "SHA256SUMS", timeout=30).read().decode()
    expected = {
        line.split()[-1].lstrip("*"): line.split()[0]
        for line in checksums.splitlines()
        if line.strip()
    }
    report = {"version": VERSION, "upstream": BASE, "files": {}}
    for suffix in ("windows-amd64.zip", "linux-amd64.tar.gz"):
        name = f"nats-server-v{VERSION}-" + suffix
        path = args.destination / name
        if (
            not path.exists()
            or hashlib.sha256(path.read_bytes()).hexdigest() != expected[name]
        ):
            urllib.request.urlretrieve(BASE + name, path)
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected[name]:
            raise RuntimeError("Upstream checksum mismatch: " + name)
        report["files"][name] = {"sha256": actual, "bytes": path.stat().st_size}
        if suffix.endswith(".zip"):
            with zipfile.ZipFile(path) as archive:
                for member in archive.infolist():
                    if Path(member.filename).name in {
                        "nats-server.exe",
                        "LICENSE",
                        "README.md",
                    }:
                        target = args.destination / Path(member.filename).name
                        target.write_bytes(archive.read(member))
    (args.destination / "upstream-sha256.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
