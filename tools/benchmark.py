"""Repeatable synthetic local baseline. Not an enterprise-scale performance claim."""

import argparse
import json
import platform
from pathlib import Path
import statistics
import tempfile
import time
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sapientia.storage import Store, Settings

parser = argparse.ArgumentParser()
parser.add_argument("--count", type=int, default=10000)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
if not 1 <= args.count <= 1_000_000:
    parser.error("count must be 1..1000000")
with tempfile.TemporaryDirectory(prefix="sapientia-bench-") as directory:
    # This offline storage baseline queues its full workload before flushing.
    # Provision only this disposable benchmark, leaving service quotas intact.
    capacity = max(100000, args.count)
    store = Store(
        Settings(
            Path(directory),
            min_free_bytes=0,
            max_queue=capacity,
            max_tenant_queue=capacity,
        )
    )
    now = time.time()
    started = time.perf_counter()
    for base in range(0, args.count, 1000):
        batch = [
            {
                "event_id": str(i),
                "event_time": now - i % 3600,
                "source": ["firewall", "edr", "identity", "cloud"][i % 4],
                "host": f"host-{i % 100}",
                "severity": "high" if i % 7 == 0 else "info",
                "message": f"Synthetic security event {i} {'denied' if i % 7 == 0 else 'allowed'}",
                "raw": {"test": True, "bytes": i % 4096},
            }
            for i in range(base, min(args.count, base + 1000))
        ]
        store.ingest("benchmark", batch)
    admission = time.perf_counter() - started
    started = time.perf_counter()
    while store.flush():
        pass
    indexing = time.perf_counter() - started
    samples = []
    for _ in range(20):
        started = time.perf_counter()
        result = store.search(
            "benchmark",
            {
                "query": "search * | stats count by source",
                "earliest": now - 7200,
                "latest": now + 1,
            },
        )
        samples.append((time.perf_counter() - started) * 1000)
        assert sum(x["count"] for x in result["rows"]) == args.count
    health = store.health("benchmark")
    store.close()
    report = {
        "events": args.count,
        "admission_seconds": round(admission, 3),
        "admission_eps": round(args.count / admission, 1),
        "indexing_seconds": round(indexing, 3),
        "indexing_eps": round(args.count / indexing, 1),
        "aggregate_median_ms": round(statistics.median(samples), 2),
        "aggregate_p95_ms": round(sorted(samples)[18], 2),
        "indexed": health["indexed"],
        "pending": health["pending"],
        "storage_bytes": health["storage_bytes"],
        "platform": platform.platform(),
        "python": platform.python_version(),
        "time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "limits": "Synthetic single-node local test, 100 hosts/4 sources; no sustained load or distributed/Splunk comparison.",
    }
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
print(json.dumps(report, indent=2))
