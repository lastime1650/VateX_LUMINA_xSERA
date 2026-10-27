"""Fresh, marked, loopback TLS qualification; never accepts a live URL or store.

Synthetic log contents and temporary credentials stay in the private QA store.
The JSON report contains measurements and assertions, never event payloads.
Lifecycle time is advanced explicitly; no performance or WORM claim is implied.
"""

import argparse
import asyncio
import hashlib
import json
import os
import platform
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx
import uvicorn

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT.parent
sys.path.insert(0, str(ROOT))

from sapientia import (
    __version__,
    access,
    audit_integrity,
    auth,
    casework,
    detections,
    log_governance,
)
from sapientia.api import create_app
from sapientia.backup import _private_directory
from sapientia.backup_stream import restore_bundle
from sapientia.log_segments import SegmentError
from sapientia.storage import Settings, Store
from tools import log_qualification_diagnostics as diagnostics
from tools.qualification import certificate, correctness, distribution

INDEXES = ("main", "endpoint", "firewall")
DISK_RESERVE = 10 * 1024**3
SEAL_BUDGET = 600
SEAL_SEGMENTS = 10000
FTS_BUDGET = 8 * 1024**3
FTS_READINESS_BUDGET = 600
_probe = None
STATS = "search * | stats count AS n, dc(event_id) AS distinct_ids, sum(raw.sequence) AS sequence_sum"
ADMIN = {
    "name": "qa_admin",
    "tenant": "default",
    "role": "admin",
    "allowed_indexes": ["*"],
}


class CheckFailure(RuntimeError):
    pass


def check(value, message):
    if not value:
        raise CheckFailure(message)


def settings_for(directory, query_timeout):
    check(
        type(query_timeout) is int and query_timeout in (15, 120),
        "Unsupported query timeout profile",
    )
    return Settings(
        directory / "data",
        min_free_bytes=DISK_RESERVE,
        max_queue=150000,
        max_tenant_queue=150000,
        query_timeout=query_timeout,
        indexing_batch=5000,
        indexing_budget=0.25,
        fts_max_bytes=FTS_BUDGET,
    )


def process_memory():
    """Same process hosts both server and client; DuckDB's limit is separate."""
    if os.name != "nt":
        import resource

        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return {
            "rss_bytes": None,
            "peak_rss_bytes": int(peak if sys.platform == "darwin" else peak * 1024),
        }
    import ctypes
    from ctypes import wintypes

    class Counters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("page_faults", wintypes.DWORD)] + [
            (name, ctypes.c_size_t)
            for name in (
                "peak_rss",
                "rss",
                "peak_paged",
                "paged",
                "peak_nonpaged",
                "nonpaged",
                "pagefile",
                "peak_pagefile",
            )
        ]

    kernel, psapi = (
        ctypes.WinDLL("kernel32", use_last_error=True),
        ctypes.WinDLL("psapi", use_last_error=True),
    )
    kernel.GetCurrentProcess.argtypes, kernel.GetCurrentProcess.restype = (
        [],
        wintypes.HANDLE,
    )
    psapi.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(Counters),
        wintypes.DWORD,
    ]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    value = Counters()
    value.cb = ctypes.sizeof(value)
    if not psapi.GetProcessMemoryInfo(
        kernel.GetCurrentProcess(), ctypes.byref(value), value.cb
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return {"rss_bytes": value.rss, "peak_rss_bytes": value.peak_rss}


class ResourceProbe:
    def __init__(self, report):
        self.report = report
        self.lock, self.started, self.last = threading.Lock(), time.monotonic(), 0
        self.values = {
            "minimum_free_bytes": None,
            "peak_rss_bytes": None,
            "samples": [],
            "scope": "combined QA client/server process; host CPU/I/O not reserved",
        }
        report["resources"] = self.values
        self.http = {"observations": [], "dropped": 0, "limit": 256}
        report["http_requests"] = self.http

    def request(
        self,
        method,
        path,
        status,
        elapsed,
        transport_error=None,
        fulltext=False,
        detail_code=None,
    ):
        with self.lock:
            rows = self.http["observations"]
            if len(rows) >= self.http["limit"]:
                rows.pop(0)
                self.http["dropped"] += 1
            rows.append(
                {
                    "stage": self.report.get("stage"),
                    "method": method,
                    "path": path.split("?")[0],
                    "status": status,
                    "elapsed_seconds": elapsed,
                    "transport_error": transport_error,
                    "fulltext_snapshot": fulltext,
                    "detail_code": detail_code,
                }
            )

    def sample(self, stage, force=False):
        with self.lock:
            free = shutil.disk_usage(WORK).free
            previous = self.values["minimum_free_bytes"]
            self.values["minimum_free_bytes"] = (
                min(free, previous) if previous is not None else free
            )
            check(
                free >= DISK_RESERVE,
                "QA disk free space fell below the mandatory 10 GiB reserve",
            )
            if force or time.monotonic() - self.last >= 15:
                try:
                    memory = process_memory()
                except (OSError, AttributeError):
                    memory = {
                        "rss_bytes": None,
                        "peak_rss_bytes": None,
                        "memory_measurement_unavailable": True,
                    }
                if memory["peak_rss_bytes"] is not None:
                    self.values["peak_rss_bytes"] = max(
                        self.values["peak_rss_bytes"] or 0, memory["peak_rss_bytes"]
                    )
                value = {
                    "stage": stage,
                    "elapsed_seconds": time.monotonic() - self.started,
                    "disk_free_bytes": free,
                    **memory,
                }
                self.values["samples"].append(value)
                print(json.dumps({"resource_sample": value}), flush=True)
                self.last = time.monotonic()


def monitor(stage, force=False):
    if _probe is not None:
        _probe.sample(stage, force)


def seal_complete(store, now, expected, budget=SEAL_BUDGET, max_segments=SEAL_SEGMENTS):
    """Cooperative bounds between native seal calls, never an unbounded loop."""
    started, passes = time.monotonic(), 0
    while True:
        status = store.segments.status("default", ["*"])
        check(
            len(status["segments"]) <= max_segments,
            "Seal segment-file safety limit exceeded",
        )
        hot = status["tiers"]["hot"]["events"]
        if hot == 0:
            check(
                status["tiers"]["warm"]["events"] == expected,
                "Warm sealing population mismatch",
            )
            return status, {
                "seal_passes": passes,
                "seal_seconds": time.monotonic() - started,
                "seal_budget_seconds": budget,
                "seal_segment_limit": max_segments,
            }
        check(
            time.monotonic() - started < budget,
            "Seal wall-clock budget exhausted with remaining hot events",
        )
        check(
            len(status["segments"]) < max_segments,
            "Seal segment-file safety limit reached with remaining hot events",
        )
        monitor("seal-hot-backlog")
        result = store.segments.seal(now=now, batch=5000)
        check(
            result["sealed_events"] > 0,
            "Sealing made no progress despite eligible hot backlog",
        )
        passes += 1


class DelayedAdmissionResponse:
    """Only this QA wrapper delays an ACK *after* the application's commit."""

    def __init__(self, app):
        self.app = app
        self.committed = threading.Event()

    async def __call__(self, scope, receive, send):
        delayed = (
            scope["type"] == "http"
            and scope.get("path") == "/api/v1/events"
            and (b"x-qa-delay-response", b"1") in scope.get("headers", [])
        )

        async def emit(message):
            if delayed and message["type"] == "http.response.start":
                self.committed.set()
                await asyncio.sleep(0.3)
            await send(message)

        await self.app(scope, receive, emit)


class Service:
    def __init__(self, directory, query_timeout):
        self.directory = directory
        settings = settings_for(directory, query_timeout)
        self.app = create_app(settings, background=True)
        self.store = self.app.state.store
        self.password = secrets.token_urlsafe(32)
        for name, tenant, role in (
            ("qa_admin", "default", "admin"),
            ("qa_main", "default", "analyst"),
            ("qa_other", "other", "analyst"),
        ):
            auth.create_user(self.store, name, self.password, role, tenant)
        access.set_for_user(self.store, ADMIN, "qa_main", ["main"])
        cert, key = certificate(directory)
        self.verify = ssl.create_default_context(cafile=str(cert))
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(("127.0.0.1", 0))
        self.port = self.socket.getsockname()[1]
        check(
            self.port not in (8787, 8788, 8790, 8791),
            "QA must use a fresh ephemeral port",
        )
        self.base = f"https://127.0.0.1:{self.port}"
        self.delayed_app = DelayedAdmissionResponse(self.app)
        self.server = uvicorn.Server(
            uvicorn.Config(
                self.delayed_app,
                host="127.0.0.1",
                port=self.port,
                ssl_certfile=str(cert),
                ssl_keyfile=str(key),
                log_level="error",
                access_log=False,
                timeout_graceful_shutdown=20,
            )
        )
        self.thread = threading.Thread(
            target=self.server.run, kwargs={"sockets": [self.socket]}, daemon=True
        )
        self.thread.start()
        deadline = time.monotonic() + 30
        while (
            not self.server.started
            and self.thread.is_alive()
            and time.monotonic() < deadline
        ):
            time.sleep(0.05)
        check(self.server.started, "Isolated TLS server did not start")
        self.clients = []

    def client(self, name=None, token=None):
        client = httpx.Client(
            base_url=self.base,
            verify=self.verify,
            trust_env=False,
            timeout=httpx.Timeout(180, connect=5),
            follow_redirects=False,
        )
        self.clients.append(client)
        if name:
            response = client.post(
                "/api/login", json={"name": name, "password": self.password}
            )
            check(response.status_code == 200, "Synthetic local login failed")
            client.headers["X-CSRF-Token"] = response.json()["csrf"]
        if token:
            client.headers["Authorization"] = "Bearer " + token
        return client

    def close(self):
        for client in self.clients:
            client.close()
        self.server.should_exit = True
        self.thread.join(30)
        self.socket.close()
        check(not self.thread.is_alive(), "Isolated service did not shut down cleanly")


def request(client, method, path, *, expected=200, **kwargs):
    monitor(path.split("?")[0])
    started = time.monotonic()
    fulltext = bool(kwargs.get("json", {}).get("fulltext"))
    try:
        response = client.request(method, path, **kwargs)
    except httpx.TransportError as exc:
        if _probe is not None:
            _probe.request(
                method,
                path,
                None,
                time.monotonic() - started,
                type(exc).__name__,
                fulltext,
            )
        raise
    if _probe is not None:
        _probe.request(
            method,
            path,
            response.status_code,
            time.monotonic() - started,
            fulltext=fulltext,
            detail_code=diagnostics.http_evidence(response)["detail_code"]
            if response.status_code != expected
            else None,
        )
    check(
        response.status_code == expected,
        f"HTTP {response.status_code} instead of {expected} at {path.split('?')[0]}",
    )
    return response


def events(start, stop, base):
    for seq in range(start, stop):
        index = INDEXES[seq % len(INDEXES)]
        yield {
            "event_id": f"synthetic-log-{seq:08d}",
            "event_time": base + seq % 3600,
            "index": index,
            "source": "synthetic-" + index,
            "sourcetype": {
                "main": "qa:service",
                "endpoint": "qa:windows-linux",
                "firewall": "qa:fortigate",
            }[index],
            "host": "QA-LOG-" + str(seq % 12),
            "severity": "high" if seq % 997 == 0 else "info",
            "message": "synthetic credential access alert"
            if seq % 997 == 0
            else "synthetic routine health heartbeat",
            "raw": {
                "sequence": seq,
                "synthetic": True,
                "platform": "windows" if seq % 2 else "linux",
            },
        }


def admit(client, batch, metrics, evidence=None):
    started = time.monotonic()
    context = None
    for attempt in range(8):
        monitor("durable-http-admission")
        request_started = time.monotonic()
        try:
            response = client.post("/api/v1/events", json={"events": batch})
        except httpx.TransportError as exc:
            metrics["transport_retries"] += 1
            if evidence is not None:
                context = context or diagnostics.batch_summary(
                    batch, metrics["accepted_acks"]
                )
                evidence.observe(
                    None, context, attempt, time.monotonic() - request_started, exc
                )
        else:
            if response.status_code == 202:
                result = response.json()
                check(result["durable"] is True, "Admission ACK was not durable")
                check(
                    result["accepted"] + result["duplicate"] == len(batch),
                    "Admission ACK count mismatch",
                )
                metrics["accepted_acks"] += result["accepted"]
                metrics["duplicate_acks"] += result["duplicate"]
                metrics["request_seconds"].append(time.monotonic() - started)
                return result
            if evidence is not None:
                context = context or diagnostics.batch_summary(
                    batch, metrics["accepted_acks"]
                )
                evidence.observe(
                    response, context, attempt, time.monotonic() - request_started
                )
                evidence.capture(
                    "first_capacity"
                    if response.status_code in (429, 503)
                    else "admission_failed",
                    context,
                )
            check(
                response.status_code in (429, 503),
                f"Unexpected ingestion HTTP {response.status_code}",
            )
            metrics["capacity_retries"] += 1
        time.sleep(min(1.0, 0.05 * 2**attempt))
    if evidence is not None:
        evidence.capture(
            "admission_failed",
            context or diagnostics.batch_summary(batch, metrics["accepted_acks"]),
        )
    raise CheckFailure("Admission retry budget exhausted")


def aggregate(client):
    result = request(
        client,
        "POST",
        "/api/search",
        json={
            "language": "spl",
            "query": STATS,
            "earliest": 0,
            "latest": time.time() + 86400,
        },
    ).json()
    return result["rows"]


def drain(client, expected, timeout=600):
    started, last_progress = time.monotonic(), 0
    samples = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        health = request(client, "GET", "/api/health").json()
        if time.monotonic() - last_progress >= 15:
            indexer = request(client, "GET", "/api/operations").json()["indexer"]
            sample = {
                "indexed": health["indexed"],
                "pending": health["pending"],
                "elapsed_seconds": time.monotonic() - started,
                "oldest_pending_seconds": health["oldest_pending_seconds"],
                "indexer": {
                    name: indexer.get(name)
                    for name in (
                        "indexed_eps",
                        "indexing_active_eps",
                        "indexed_total",
                        "last_indexed",
                        "last_batches",
                        "oldest_pending_seconds",
                        "error",
                    )
                },
            }
            samples.append(sample)
            print(
                json.dumps(
                    {
                        "stage": "incremental-indexing",
                        **sample,
                        "expected": expected,
                        "elapsed_seconds": time.monotonic() - started,
                    }
                ),
                flush=True,
            )
            last_progress = time.monotonic()
        if health["pending"] == 0 and health["indexed"] == expected:
            result = correctness(aggregate(client), expected)
            check(result["passed"], "Count/distinct/sequence checksum mismatch")
            return {
                **result,
                "indexing_wait_seconds": time.monotonic() - started,
                "wait_budget_seconds": timeout,
                "progress_samples": samples,
            }
        time.sleep(0.15)
    raise CheckFailure(
        "Incremental indexing did not reach the exact expected population"
    )


def source_identity():
    digest = hashlib.sha256()
    count = 0
    for path in sorted((ROOT / "sapientia").rglob("*")):
        if path.is_file() and path.suffix in {".py", ".js", ".css", ".html"}:
            digest.update(path.relative_to(ROOT).as_posix().encode())
            digest.update(b"\0")
            digest.update(path.read_bytes())
            count += 1
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        "version": __version__,
        "product_source_sha256": digest.hexdigest(),
        "files": count,
        "git_head": head.stdout.strip() if head.returncode == 0 else None,
        "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "diagnostics_helper_sha256": diagnostics.helper_identity(),
    }


def hold_qualification(directory, query_timeout):
    """Small separate expiry store avoids disguising 100k rewrites as measured."""
    store = Store(
        Settings(
            directory / "hold-data",
            min_free_bytes=DISK_RESERVE,
            query_timeout=query_timeout,
        )
    )
    try:
        auth.create_user(store, ADMIN["name"], secrets.token_urlsafe(32))
        now = time.time()
        store.ingest(
            "default",
            [
                {
                    "event_id": "synthetic-held-original",
                    "event_time": now - 2,
                    "message": "synthetic preservation",
                    "raw": {"user": "synthetic-subject"},
                },
                {
                    "event_id": "synthetic-bookmarked-original",
                    "event_time": now - 1,
                    "message": "synthetic supporting original",
                },
            ],
        )
        store.flush()
        detections.save(
            store,
            ADMIN,
            {
                "name": "Synthetic preservation policy",
                "entity_field": "raw.user",
                "window": 300,
                "steps": [
                    {
                        "filters": [
                            {
                                "field": "event_id",
                                "op": "eq",
                                "value": "synthetic-held-original",
                            }
                        ]
                    }
                ],
            },
        )
        check(
            detections.run_due(store, now + 1, budget=5) == 1,
            "Small hold fixture did not create an incident",
        )
        incident = detections.incident_list(store, ADMIN)[0]["id"]
        casework.bookmark(
            store,
            ADMIN,
            incident,
            {
                "event_id": "synthetic-bookmarked-original",
                "label": "Synthetic original",
            },
        )
        status = log_governance.get_case_hold(store, ADMIN, incident)
        check(
            status["evidence_count"] == status["originals_available"] == 2,
            "Hold fixture must have two originals",
        )
        held = log_governance.hold_case(
            store,
            ADMIN,
            incident,
            {"version": status["version"], "reason": "Synthetic QA preservation"},
        )
        store.segments.seal(now=now + 2 * 86400)
        check(
            store.retain(now + 100 * 86400) == 0, "Case hold did not protect originals"
        )
        log_governance.release_case_hold(
            store,
            ADMIN,
            incident,
            {"version": held["version"], "reason": "Synthetic QA release"},
        )
        deleted = store.retain(now + 100 * 86400)
        check(deleted == 2, "Released originals did not expire")
        check(
            len(casework.export_case(store, ADMIN, incident)["bookmarks"]) == 1,
            "Case evidence copy unexpectedly disappeared",
        )
        return {
            "passed": True,
            "population": 2,
            "held_originals": 2,
            "deleted_after_release": deleted,
            "bookmark_copies_remain": 1,
            "scope": "separate small expiry store",
        }
    finally:
        store.close()


def qualify(report, count, query_timeout):
    global _probe

    _probe = ResourceProbe(report)
    monitor("preflight", force=True)
    directory = WORK / ("log-platform-qa-" + uuid.uuid4().hex)
    directory.mkdir()
    _private_directory(directory, created=True)
    (directory / ".isolated-log-platform-qa.json").write_text(
        json.dumps(
            {
                "synthetic": True,
                "version": __version__,
                "created": time.time(),
                "purpose": "isolated log platform qualification",
            }
        ),
        encoding="utf-8",
    )
    report.update(
        source=source_identity(),
        platform=platform.platform(),
        synthetic=True,
        initial_population=count,
        concurrent_population=2000,
        tls_verified=True,
        isolation="Fresh private marked directory, loopback ephemeral TLS, no production URL accepted",
        settings={
            "query_deadline_seconds": query_timeout,
            "query_workers": 4,
            "max_queue": 150000,
            "max_tenant_queue": 150000,
            "min_free_bytes": DISK_RESERVE,
            "indexing_batch": 5000,
            "indexing_budget_seconds": 0.25,
            "memory_limit": "512MB",
            "indexing_wait_budget_seconds": 600,
            "seal_budget_seconds": SEAL_BUDGET,
            "seal_segment_limit": SEAL_SEGMENTS,
            "snapshot_maximum_bytes": 2 * 1024**3,
            "snapshot_tenant_maximum_bytes": 8 * 1024**3,
            "fts_max_bytes": FTS_BUDGET,
            "fts_readiness_wait_budget_seconds": FTS_READINESS_BUDGET,
        },
        limits=[
            "Single Windows host, CPU and disk not reserved; no distributed HA or sustained EPS claim.",
            "HTTP synthetic Windows/Linux/firewall event envelopes; no native agent or OS response exercised here.",
            "Archive means local searchable verified Parquet; external Object Lock is not exercised.",
            "Expiry and case-hold test uses two originals in a separate store; no full-population retention rewrite measured.",
            "Client ACK timeout is deliberately injected by this harness after commit, not an observed product latency defect.",
            "Backup actual size is reported; no >64GiB or multi-terabyte throughput claim.",
            "Complete HTTP download is verified by a streaming client; native browser file-save completion is not exercised.",
        ],
    )
    service, evidence = None, None
    admission = {
        "accepted_acks": 0,
        "duplicate_acks": 0,
        "capacity_retries": 0,
        "transport_retries": 0,
        "request_seconds": [],
    }
    try:
        report["stage"] = "TLS service and scoped collectors"
        service = Service(directory, query_timeout)
        check(
            service.store.settings.fts_max_bytes == report["settings"]["fts_max_bytes"],
            "Reported FTS budget differs from actual service settings",
        )
        admin, main, other = (
            service.client("qa_admin"),
            service.client("qa_main"),
            service.client("qa_other"),
        )
        report["admission_diagnostics"] = {}
        evidence = diagnostics.AdmissionEvidence(
            report["admission_diagnostics"],
            lambda deadline, context: diagnostics.combined_snapshot(
                service.store, service.app.state.runtime, admin, deadline
            ),
        )
        issued = request(
            admin,
            "POST",
            "/api/tokens",
            json={"name": "qa-mixed", "allowed_indexes": list(INDEXES)},
        ).json()
        collector = service.client(token=issued["token"])
        limited_token = request(
            admin,
            "POST",
            "/api/tokens",
            json={"name": "qa-main", "allowed_indexes": ["main"]},
        ).json()["token"]
        limited = service.client(token=limited_token)
        base = time.time() - 5 * 86400
        rejected = [
            {"event_id": "synthetic-denied-main", "index": "main"},
            {"event_id": "synthetic-denied-firewall", "index": "firewall"},
        ]
        request(
            limited, "POST", "/api/v1/events", expected=403, json={"events": rejected}
        )
        with service.store.control() as db:
            check(
                db.execute(
                    "SELECT count(*) FROM receipts WHERE event_id LIKE 'synthetic-denied-%'"
                ).fetchone()[0]
                == 0,
                "Cross-index batch was partially admitted",
            )
        report["atomic_scope_rejection"] = {"http": 403, "admitted": 0}

        report["stage"] = f"Initial {count:,} bounded durable HTTP admission"
        started = time.monotonic()
        for start in range(0, count, 1000):
            admit(
                collector,
                list(events(start, min(start + 1000, count), base)),
                admission,
                evidence,
            )
            if start % 10000 == 0:
                print(
                    json.dumps(
                        {
                            "stage": "initial-admission",
                            "rows_acknowledged": min(start + 1000, count),
                        }
                    ),
                    flush=True,
                )
        replay = admit(collector, list(events(0, 1000, base)), admission, evidence)
        check(
            replay["accepted"] == 0 and replay["duplicate"] == 1000,
            "Stable replay was not deduplicated",
        )
        report["initial_ingest_seconds"] = time.monotonic() - started
        report["initial_integrity"] = drain(admin, count)

        report["stage"] = "Full-text background readiness before interactive query"
        readiness = {
            "passed": False,
            "budget_seconds": FTS_READINESS_BUDGET,
            "seconds": 0,
            "last_state": None,
        }
        report["fts_readiness"] = readiness
        readiness_started = time.monotonic()
        while True:
            state = request(admin, "GET", "/api/logs/status").json()["search"][
                "fulltext"
            ]
            check(
                state["budget_bytes"] == report["settings"]["fts_max_bytes"],
                "Full-text status budget differs from qualification settings",
            )
            readiness["seconds"] = time.monotonic() - readiness_started
            readiness["last_state"] = state
            if state["ready"]:
                readiness["passed"] = True
                break
            check(
                state["state"] not in {"capacity_error", "bootstrap_required"},
                "Full-text readiness blocked by configured capacity or required offline bootstrap",
            )
            check(
                readiness["seconds"] < readiness["budget_seconds"],
                "Full-text background readiness budget exceeded",
            )
            if readiness["seconds"] % 15 < 0.3:
                print(
                    json.dumps({"stage": "fulltext-readiness", **readiness}), flush=True
                )
            time.sleep(0.25)

        report["stage"] = "FTS phrase, structured filter, tenant and index scopes"
        query = {
            "query": {
                "query": {
                    "filters": [{"field": "raw.sequence", "op": "lt", "value": count}]
                }
            },
            "fulltext": '"credential access"',
        }
        fts_started = time.monotonic()
        fts = request(
            admin, "POST", "/api/logs/snapshots", expected=201, json=query
        ).json()
        scoped = request(
            main, "POST", "/api/logs/snapshots", expected=201, json=query
        ).json()
        foreign = request(
            other, "POST", "/api/logs/snapshots", expected=201, json=query
        ).json()
        all_hits = (count - 1) // 997 + 1
        main_hits = len(range(0, (count - 1) // 997 + 1, 3))
        check(
            (fts["rows"], scoped["rows"], foreign["rows"]) == (all_hits, main_hits, 0),
            "FTS structured/tenant/index scope mismatch",
        )
        report["fts"] = {
            "passed": True,
            "total": fts["rows"],
            "main_only": scoped["rows"],
            "other_tenant": foreign["rows"],
            "seconds": time.monotonic() - fts_started,
        }

        report["stage"] = (
            "Complete point-in-time NDJSON during concurrent admission/read"
        )
        snapshot = request(
            admin, "POST", "/api/logs/snapshots", expected=201, json={"query": {}}
        ).json()
        check(
            snapshot["rows"] == count and not snapshot["truncated"],
            "Complete initial snapshot was truncated",
        )
        reader_seconds, reader_counts = [], []
        writer_done = threading.Event()
        writer_client, reader_client = (
            service.client(token=issued["token"]),
            service.client("qa_admin"),
        )

        def writer():
            first = list(events(count, count + 100, base))
            timeout_seen = False
            try:
                writer_client.post(
                    "/api/v1/events",
                    json={"events": first},
                    headers={"X-QA-Delay-Response": "1"},
                    timeout=httpx.Timeout(0.03, connect=5, write=5),
                )
            except httpx.ReadTimeout:
                timeout_seen = True
            check(timeout_seen, "Injected post-commit ACK timeout was not observed")
            check(
                service.delayed_app.committed.wait(5),
                "Delayed original request did not reach its committed response",
            )
            retry = admit(writer_client, first, admission, evidence)
            check(
                retry["accepted"] == 0 and retry["duplicate"] == 100,
                "Ambiguous committed ACK replay duplicated admission",
            )
            report["ambiguous_ack_retry"] = {
                "injected_read_timeout": True,
                "retry_duplicate": retry["duplicate"],
                "retry_accepted": retry["accepted"],
            }
            try:
                for start in range(count + 100, count + 2000, 250):
                    admit(
                        writer_client,
                        list(events(start, min(start + 250, count + 2000), base)),
                        admission,
                        evidence,
                    )
            finally:
                writer_done.set()

        def reader():
            for _ in range(40):
                began = time.monotonic()
                result = aggregate(reader_client)
                reader_seconds.append(time.monotonic() - began)
                value = int(result[0]["n"])
                reader_counts.append(value)
                check(
                    count <= value <= count + 2000,
                    "Concurrent reader observed an impossible count",
                )
                if writer_done.is_set() and value == count + 2000:
                    return
                time.sleep(0.05)

        export_started = time.monotonic()
        with ThreadPoolExecutor(max_workers=2) as pool:
            writer_future, reader_future = pool.submit(writer), pool.submit(reader)
            digest, seen, seqsum, position, pages, export_bytes = (
                hashlib.sha256(),
                bytearray((count + 7) // 8),
                0,
                0,
                0,
                0,
            )
            unique_count = 0
            while True:
                response = request(
                    admin,
                    "GET",
                    f"/api/logs/snapshots/{snapshot['id']}/export?after={position}&limit=5000",
                )
                check(
                    int(response.headers["X-Total-Rows"]) == count,
                    "Paged snapshot total changed during ingestion",
                )
                check(
                    response.headers["X-Snapshot-SHA256"] == snapshot["sha256_ndjson"],
                    "Snapshot page digest metadata changed",
                )
                digest.update(response.content)
                export_bytes += len(response.content)
                for line in response.content.splitlines():
                    row = json.loads(line)
                    sequence = row["raw"]["sequence"]
                    check(
                        type(sequence) is int and 0 <= sequence < count,
                        "Snapshot sequence is outside the frozen population",
                    )
                    check(
                        row["event_id"] == f"synthetic-log-{sequence:08d}",
                        "Snapshot event identity does not match its sequence",
                    )
                    offset, mask = sequence // 8, 1 << (sequence % 8)
                    check(not seen[offset] & mask, "Snapshot export repeated an event")
                    seen[offset] |= mask
                    unique_count += 1
                    seqsum += sequence
                pages += 1
                next_position = response.headers["X-Next-After"]
                if not next_position:
                    break
                check(
                    int(next_position) > position,
                    "Snapshot export cursor did not advance",
                )
                position = int(next_position)
            writer_future.result()
            reader_future.result()
        check(
            unique_count == count and seqsum == count * (count - 1) // 2,
            "Complete export identity/sequence mismatch",
        )
        check(
            digest.hexdigest() == snapshot["sha256_ndjson"],
            "Complete NDJSON SHA256 mismatch",
        )
        check(
            reader_counts == sorted(reader_counts),
            "Concurrent indexed counts moved backwards",
        )
        report["complete_export"] = {
            "passed": True,
            "rows": unique_count,
            "unique_ids": unique_count,
            "identity_bitmap_bytes": len(seen),
            "sequence_sum": seqsum,
            "sha256": digest.hexdigest(),
            "bytes": export_bytes,
            "pages": pages,
            "seconds": time.monotonic() - export_started,
            "point_in_time_population": count,
            "final_live_population": count + 2000,
        }
        download_started = time.monotonic()
        stream_digest, stream_bytes, stream_lines = hashlib.sha256(), 0, 0
        with admin.stream(
            "GET",
            f"/api/logs/snapshots/{snapshot['id']}/download",
            headers={"Accept-Encoding": "identity"},
        ) as response:
            check(response.status_code == 200, "Complete HTTP stream download failed")
            check(
                response.headers.get("Content-Encoding", "identity") == "identity",
                "Unexpected compression in complete download",
            )
            declared_bytes = int(response.headers["Content-Length"])
            check(
                int(response.headers["X-Total-Rows"]) == count,
                "Complete download total differs from frozen snapshot",
            )
            check(
                response.headers["X-Snapshot-SHA256"] == snapshot["sha256_ndjson"],
                "Complete download digest metadata changed",
            )
            for chunk in response.iter_bytes(chunk_size=64 * 1024):
                monitor("complete-http-download")
                stream_digest.update(chunk)
                stream_bytes += len(chunk)
                stream_lines += chunk.count(b"\n")
        check(
            stream_bytes == declared_bytes == export_bytes,
            "Complete HTTP stream byte length mismatch",
        )
        check(stream_lines == count, "Complete HTTP stream line count mismatch")
        check(
            stream_digest.hexdigest()
            == snapshot["sha256_ndjson"]
            == digest.hexdigest(),
            "Paged and streamed complete export SHA256 mismatch",
        )
        report["complete_download"] = {
            "passed": True,
            "rows": stream_lines,
            "bytes": stream_bytes,
            "content_length": declared_bytes,
            "sha256": stream_digest.hexdigest(),
            "chunk_bytes": 65536,
            "seconds": time.monotonic() - download_started,
            "native_browser_file_save_verified": False,
        }
        report["concurrent_reads"] = {
            "passed": True,
            "latency_seconds": distribution(reader_seconds),
            "minimum_count": min(reader_counts),
            "maximum_count": max(reader_counts),
        }
        report["final_integrity"] = drain(admin, count + 2000)

        report["stage"] = "Parquet warm/cold/archive integrated exact population"
        print(json.dumps({"stage": report["stage"]}), flush=True)
        for index in INDEXES:
            request(
                admin,
                "PUT",
                f"/api/logs/indexes/{index}/lifecycle",
                json={
                    "hot_days": 1,
                    "warm_days": 2,
                    "cold_days": 3,
                    "retention_days": 30,
                    "hold": False,
                    "version": 0,
                },
            )
        lifecycle_started, simulated_now = time.monotonic(), time.time()
        warm, seal_metrics = seal_complete(
            service.store, simulated_now + 1.5 * 86400, count + 2000
        )
        check(
            warm["tiers"]["hot"]["events"] == 0
            and warm["tiers"]["warm"]["events"] == count + 2000,
            "Warm sealing population mismatch",
        )
        check(
            correctness(aggregate(admin), count + 2000)["passed"],
            "Warm full-population search mismatch",
        )
        service.store.segments.maintenance(now=simulated_now + 2.5 * 86400)
        monitor("cold-tier-movement", force=True)
        cold = service.store.segments.status("default", ["*"])
        check(
            cold["tiers"]["cold"]["events"] == count + 2000,
            "Cold movement population mismatch",
        )
        check(
            correctness(aggregate(admin), count + 2000)["passed"],
            "Cold full-population search mismatch",
        )
        service.store.segments.maintenance(now=simulated_now + 3.5 * 86400)
        monitor("archive-tier-movement", force=True)
        archived = service.store.segments.status("default", ["*"])
        check(
            archived["tiers"]["archive"]["events"] == count + 2000,
            "Archive movement population mismatch",
        )
        check(
            correctness(aggregate(admin), count + 2000)["passed"],
            "Archive full-population search mismatch",
        )
        report["lifecycle"] = {
            "passed": True,
            "clock": "received, explicit simulated future epochs",
            "warm_events": warm["tiers"]["warm"]["events"],
            "cold_events": cold["tiers"]["cold"]["events"],
            "archive_events": archived["tiers"]["archive"]["events"],
            "segments": len(archived["segments"]),
            "seconds": time.monotonic() - lifecycle_started,
            **seal_metrics,
        }

        report["stage"] = "Online consistent snapshot and format2 authenticated restore"
        print(json.dumps({"stage": report["stage"]}), flush=True)
        backup_started = time.monotonic()
        passphrase = secrets.token_urlsafe(40)
        old_cookie = admin.cookies.get(service.app.state.cookie_name)
        bundle = request(
            admin,
            "POST",
            "/api/logs/backups",
            expected=201,
            json={"passphrase": passphrase},
        ).json()
        check(
            bundle["format"] == 2 and bundle["online"] and bundle["encrypted"],
            "Online backup did not use authenticated format2",
        )
        bundle_path = service.store.path / "private" / "online-backups" / bundle["id"]
        restored_path = directory / "different-path-restored"
        restored_result = restore_bundle(bundle_path, restored_path, passphrase)
        monitor("restore-bundle", force=True)
        restored = Store(
            Settings(
                restored_path, min_free_bytes=DISK_RESERVE, query_timeout=query_timeout
            )
        )
        try:
            integrity = correctness(
                restored.search(
                    "default",
                    {
                        "language": "spl",
                        "query": STATS,
                        "earliest": 0,
                        "latest": time.time() + 86400,
                    },
                    allowed_indexes=["*"],
                )["rows"],
                count + 2000,
            )
            check(integrity["passed"], "Restored full-population integrity mismatch")
            restored_segments = restored.segments.status("default", ["*"])
            check(
                restored_segments["tiers"]["archive"]["events"] == count + 2000,
                "Restored archive population mismatch",
            )
            audit = audit_integrity.verify(restored)
            check(audit["valid"], "Restored audit chain is invalid")
            check(
                auth.identity(restored, cookie=old_cookie) is None,
                "Backup restore retained an old browser session",
            )
            with restored.control() as db:
                sessions = db.execute("SELECT count(*) FROM sessions").fetchone()[0]
            check(sessions == 0, "Restored session table is not empty")
            report["backup_restore"] = {
                "passed": True,
                "format": 2,
                "online": True,
                "files": bundle["files"],
                "plaintext_bytes": bundle["bytes"],
                "chunks": bundle["chunks"],
                "sessions_revoked": restored_result["sessions_revoked"],
                "remaining_sessions": sessions,
                "audit_valid": audit["valid"],
                "audit_sequence": audit["sequence"],
                "integrity": integrity,
                "restored_archive_events": restored_segments["tiers"]["archive"][
                    "events"
                ],
                "seconds": time.monotonic() - backup_started,
            }
            segment_path = (
                restored.segments.root / restored_segments["segments"][0]["path"]
            )
        finally:
            restored.close()
        # Deliberately damage only the restored private QA copy, after closing it.
        with segment_path.open("r+b") as stream:
            stream.seek(16)
            value = stream.read(1)
            check(bool(value), "Restored QA segment unexpectedly empty")
            stream.seek(16)
            stream.write(bytes([value[0] ^ 1]))
        damaged = None
        try:
            damaged = Store(
                Settings(
                    restored_path,
                    min_free_bytes=DISK_RESERVE,
                    query_timeout=query_timeout,
                )
            )
        except SegmentError:
            report["damaged_restore"] = {
                "passed": True,
                "startup_rejected": True,
                "exception": "SegmentError",
            }
        else:
            raise CheckFailure("Damaged restored Parquet was not rejected")
        finally:
            if damaged:
                damaged.close()
        report["stage"] = "Separate case original hold and release expiry"
        report["case_hold"] = hold_qualification(directory, query_timeout)
        report["passed"] = True
        report["stage"] = "complete"
        monitor("complete", force=True)
    finally:
        report["qa_service_closed"] = service is None
        try:
            if evidence is not None and not evidence.finish():
                report["passed"] = False
                report["diagnostic_cleanup_failure"] = (
                    "Owned diagnostic worker did not finish within its bounded cleanup deadline"
                )
            if service:
                service.close()
            report["qa_service_closed"] = True
        finally:
            # Failed queries still need source, admission and cleanup evidence.
            report["admission"] = {
                **{
                    key: value
                    for key, value in admission.items()
                    if key != "request_seconds"
                },
                "request_latency_seconds": distribution(admission["request_seconds"]),
            }
            final_identity = source_identity()
            report["source_unchanged_during_run"] = (
                final_identity["product_source_sha256"]
                == report["source"]["product_source_sha256"]
            )
            report["harness_unchanged_during_run"] = all(
                final_identity[key] == report["source"][key]
                for key in ("harness_sha256", "diagnostics_helper_sha256")
            )
            monitor("cleanup", force=True)
            check(
                report["source_unchanged_during_run"],
                "Product source changed during qualification",
            )
            check(
                report["harness_unchanged_during_run"],
                "Qualification harness or diagnostic helper changed during qualification",
            )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, choices=[100000, 1000000], default=100000)
    parser.add_argument("--query-timeout", type=int, choices=[15, 120], default=15)
    parser.add_argument(
        "--report",
        type=Path,
        required=True,
        help="New JSON file under this task's work/ or outputs/; never overwritten",
    )
    args = parser.parse_args()
    target = Path(os.path.abspath(args.report))
    resolved = target.resolve()
    if (
        target != resolved
        or target.suffix.lower() != ".json"
        or not (
            target.is_relative_to(WORK)
            or target.is_relative_to(WORK.parent / "outputs")
        )
        or target.is_relative_to(ROOT)
        or target.exists()
    ):
        parser.error(
            "Report must be a new, non-linked JSON path under task work/ or outputs/, outside the source repository"
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    # This process must not inherit a production identity-provider or endpoint
    # deployment configuration. No external integration is used in this test.
    for key in (
        "SAPIENTIA_OIDC_CONFIG",
        "SAPIENTIA_AGENT_ENDPOINT_URL",
        "SAPIENTIA_AGENT_CA_FILE",
    ):
        os.environ.pop(key, None)
    report = {"passed": False, "started_at_epoch": time.time()}
    started = time.monotonic()
    try:
        qualify(report, args.events, args.query_timeout)
    except Exception as exc:  # noqa: BLE001 - Always save a sanitized failed qualification, without credentials.
        report["passed"] = False
        report["failure"] = {
            "type": type(exc).__name__,
            "stage": report.get("stage"),
            "reason": str(exc)
            if isinstance(exc, CheckFailure)
            else "Operation failed; inspect isolated qualification locally",
        }
    finally:
        report["elapsed_seconds"] = time.monotonic() - started
        with target.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        print(
            json.dumps(
                {
                    "passed": report["passed"],
                    "stage": report.get("stage"),
                    "elapsed_seconds": report["elapsed_seconds"],
                    "report": str(target),
                },
                ensure_ascii=False,
            ),
            flush=True,
        )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
