"""Build secret-free source agent archives without touching the original XDR."""

import argparse
import json
from pathlib import Path

from sapientia.agent_distribution import PLATFORMS, package


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for platform in PLATFORMS:
        blob, digest, filename = package(platform)
        target = args.output_dir / filename
        target.write_bytes(blob)
        target.with_suffix(target.suffix + ".sha256").write_text(
            digest + "  " + filename + "\n", encoding="ascii"
        )
        results.append(
            {
                "platform": platform,
                "filename": filename,
                "sha256": digest,
                "size": len(blob),
                "format": "python-source-zip",
                "python_minimum": "3.10",
                "secrets": False,
            }
        )
    (args.output_dir / "packages.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )
    print(json.dumps(results))


if __name__ == "__main__":
    main()
