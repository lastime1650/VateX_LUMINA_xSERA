"""Isolated HTTP/TLS qualification harness. Never accepts a production URL or data path."""

import argparse
import ctypes
import ipaddress
import json
import math
import platform
import secrets
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx


def percentile(samples, fraction):
    if not 0 < fraction <= 1:
        raise ValueError("Percentile fraction must be in (0,1]")
    values = sorted(samples)
    return values[max(0, math.ceil(len(values) * fraction) - 1)] if values else None


def distribution(samples):
    return {
        "samples": len(samples),
        "p50": percentile(samples, 0.5),
        "p95": percentile(samples, 0.95),
        "max": max(samples) if samples else None,
        "method": "nearest-rank",
    }


def correctness(rows, expected):
    row = rows[0] if rows else {}
    actual = {
        "count": int(row.get("n", 0)),
        "distinct_event_ids": int(row.get("distinct_ids", 0)),
        "sequence_sum": int(float(row.get("sequence_sum", 0) or 0)),
    }
    wanted = {
        "count": expected,
        "distinct_event_ids": expected,
        "sequence_sum": expected * (expected - 1) // 2,
    }
    return {
        "passed": actual == wanted,
        "actual": actual,
        "expected": wanted,
        "checksum_kind": "arithmetic sequence sum, not a cryptographic content hash",
    }


def certificate(directory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "LUMINA isolated qualification")]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "test-cert.pem", directory / "test-key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


class IsolatedService:
    def __init__(self, directory, transport, timeout, query_workers=4):
        self.directory, self.timeout = directory, timeout
        self.query_workers = query_workers
        with socket.socket() as bound:
            bound.bind(("127.0.0.1", 0))
            self.port = bound.getsockname()[1]
        if self.port == 8787:
            raise RuntimeError("Reserved production port cannot be used")
        self.base = f"{transport}://127.0.0.1:{self.port}"
        self.verify, self.tls = True, []
        if transport == "https":
            cert, key = certificate(directory)
            self.verify = ssl.create_default_context(cafile=str(cert))
            self.tls = ["--cert", str(cert), "--key", str(key)]
        self.process = self.log = None
        self.stop_checks = []
        self.generation = 0
        self.report = None
        self.child_handles = []
        self.stop_method = "owned process termination"

    def client(self):
        return httpx.Client(
            base_url=self.base,
            verify=self.verify,
            trust_env=False,
            timeout=self.timeout,
        )

    def start(self):
        self.generation += 1
        self.log = (self.directory / "isolated-server.log").open("ab")
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "sapientia",
                "--data",
                str(self.directory / "data"),
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
                "--query-workers",
                str(self.query_workers),
                *self.tls,
            ],
            cwd=Path(__file__).resolve().parents[1],
            stdout=self.log,
            stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        deadline = time.monotonic() + self.timeout
        with self.client() as client:
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError("Isolated server exited during startup")
                try:
                    if client.get("/api/bootstrap").status_code == 200:
                        if sys.platform == "win32":
                            self._capture_windows_children()
                        return
                except httpx.TransportError:
                    pass
                time.sleep(0.05)
        raise TimeoutError("Isolated server startup deadline exceeded")

    def _capture_windows_children(self):
        from ctypes import wintypes

        class Entry(ctypes.Structure):
            _fields_ = [
                ("size", wintypes.DWORD),
                ("usage", wintypes.DWORD),
                ("pid", wintypes.DWORD),
                ("heap", ctypes.c_size_t),
                ("module", wintypes.DWORD),
                ("threads", wintypes.DWORD),
                ("parent", wintypes.DWORD),
                ("priority", wintypes.LONG),
                ("flags", wintypes.DWORD),
                ("name", wintypes.WCHAR * 260),
            ]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
        kernel.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            raise OSError(ctypes.get_last_error(), "Cannot inspect owned process tree")
        entries, entry = {}, Entry()
        entry.size = ctypes.sizeof(entry)
        try:
            available = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
            while available:
                entries[entry.pid] = (entry.parent, entry.name)
                available = kernel.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            kernel.CloseHandle(snapshot)
        owned, pending = {self.process.pid}, [self.process.pid]
        while pending:
            parent = pending.pop(0)
            for pid, (ancestor, name) in entries.items():
                if ancestor == parent and pid not in owned:
                    if name.lower() == "conhost.exe":
                        # Windows console helper is not the server process.
                        continue
                    if name.lower() not in {"python.exe", "pythonw.exe"}:
                        raise RuntimeError(
                            "Unexpected executable in owned Python process tree: "
                            + name
                        )
                    handle = kernel.OpenProcess(0x100001, False, pid)
                    if not handle:
                        raise OSError(
                            ctypes.get_last_error(), "Cannot retain owned child handle"
                        )
                    # A retained kernel handle identifies this actual process,
                    # even if its numeric PID is later reused.
                    self.child_handles.append(handle)
                    owned.add(pid)
                    pending.append(pid)

    def _stop_windows_tree(self):
        from ctypes import wintypes

        if not self.child_handles:
            subprocess.run(
                ["taskkill", "/PID", str(self.process.pid), "/T", "/F"],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                timeout=10,
            )
            self.stop_method = "owned PID tree termination"
            return
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel.TerminateProcess.restype = wintypes.BOOL
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        try:
            for handle in reversed(self.child_handles):
                if kernel.WaitForSingleObject(handle, 0) != 0:
                    if not kernel.TerminateProcess(handle, 1):
                        raise OSError(
                            ctypes.get_last_error(), "Cannot stop owned Python child"
                        )
                    if kernel.WaitForSingleObject(handle, 10000) != 0:
                        raise TimeoutError("Owned Python child did not exit")
        finally:
            for handle in self.child_handles:
                kernel.CloseHandle(handle)
            self.child_handles.clear()
        if self.process.poll() is None:
            self.process.kill()
        self.stop_method = "owned captured process tree handles"

    def stop(self):
        if self.process is None:
            return
        try:
            if sys.platform == "win32" and self.child_handles:
                self._stop_windows_tree()
                self.process.wait(timeout=10)
            elif self.process.poll() is None:
                if sys.platform == "win32":
                    # A Windows virtualenv launcher can own a second Python
                    # process. Kill only this harness-owned PID and its tree.
                    self._stop_windows_tree()
                else:
                    self.process.kill()
                self.process.wait(timeout=10)
            self.stop_checks.append(self._verify_stopped())
        finally:
            if self.log:
                self.log.close()
            self.log = None
        self.process = None

    def _verify_stopped(self):
        deadline = time.monotonic() + 10
        listener_closed = database_released = False
        path = self.directory / "data" / "control.sqlite3"
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.1):
                    listener_closed = False
            except OSError:
                listener_closed = True
            database_released = True
            if sys.platform == "win32" and path.exists():
                # No sharing: successful open proves the actual SQLite owner
                # has released its handle before queue inspection or restart.
                from ctypes import wintypes

                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.CreateFileW.argtypes = [
                    wintypes.LPCWSTR,
                    wintypes.DWORD,
                    wintypes.DWORD,
                    ctypes.c_void_p,
                    wintypes.DWORD,
                    wintypes.DWORD,
                    wintypes.HANDLE,
                ]
                kernel.CreateFileW.restype = wintypes.HANDLE
                kernel.CloseHandle.argtypes = [wintypes.HANDLE]
                kernel.CloseHandle.restype = wintypes.BOOL
                handle = kernel.CreateFileW(
                    str(path), 0x80000000, 0, None, 3, 128, None
                )
                database_released = handle != ctypes.c_void_p(-1).value
                if database_released:
                    kernel.CloseHandle(handle)
            if listener_closed and database_released:
                return {
                    "generation": self.generation,
                    "owned_process_exited": self.process.poll() is not None,
                    "listener_closed": True,
                    "database_handle_released": True
                    if sys.platform == "win32"
                    else None,
                    "method": self.stop_method,
                }
            time.sleep(0.05)
        raise RuntimeError("Owned temporary server listener or database remains open")


def request(client, method, path, **kwargs):
    response = client.request(method, path, **kwargs)
    response.raise_for_status()
    return response.json()


def login(client, name, password):
    value = request(
        client, "POST", "/api/login", json={"name": name, "password": password}
    )
    client.headers["x-csrf-token"] = value["csrf"]
    return value


AGGREGATE = "search * | stats count AS n, dc(event_id) AS distinct_ids, sum(raw.sequence) AS sequence_sum"


def aggregate(client):
    return request(
        client, "POST", "/api/search", json={"query": AGGREGATE, "limit": 10}
    )["rows"]


def wait_count(client, expected, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows = aggregate(client)
        if rows and int(rows[0]["n"]) == expected:
            return rows
        time.sleep(0.01)
    raise TimeoutError("Acknowledged events did not become searchable before deadline")


def event(number):
    return {
        "event_id": f"qualification-{number}",
        "message": f"Synthetic qualification {number}",
        "source": f"source-{number % 4}",
        "host": f"host-{number % 100}",
        "raw": {"sequence": number, "synthetic": True},
    }


def qualify(service, args):
    admin = service.client()
    clients = []
    password = secrets.token_urlsafe(32)
    report = {
        "scope": "isolated temporary single-node service, synthetic workload",
        "transport": args.transport,
        "tls_verification": args.transport == "https",
        "events": args.count,
        "batch_size": args.batch,
        "users": args.users,
        "query_workers": args.query_workers,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "enterprise_ready": False,
        "splunk_comparison": False,
        "resource_isolation": "Temporary application and data; host CPU/I/O were not reserved",
    }
    service.report = report
    try:
        report["server_version"] = request(admin, "GET", "/api/bootstrap")["version"]
        request(
            admin, "POST", "/api/setup", json={"name": "qa_admin", "password": password}
        )
        login(admin, "qa_admin", password)
        token = request(admin, "POST", "/api/tokens", json={"name": "qualification"})[
            "token"
        ]
        for number in range(args.users):
            name, initial, final = (
                f"qa_reader_{number}",
                secrets.token_urlsafe(32),
                secrets.token_urlsafe(32),
            )
            request(
                admin,
                "POST",
                "/api/users",
                json={"name": name, "password": initial, "role": "analyst"},
            )
            client = service.client()
            login(client, name, initial)
            request(
                client,
                "POST",
                "/api/me/password",
                json={"current": initial, "password": final},
            )
            login(client, name, final)
            clients.append(client)
        ingest = service.client()
        ingest.headers["authorization"] = "Bearer " + token
        visibility, query_times, markers, monitor_errors = [], [], [], []
        monitor_error_details = []
        backlog_samples = []
        lock, finished = threading.Lock(), threading.Event()

        def monitor():
            with service.client() as reader:
                login(reader, "qa_admin", password)
                deadline = time.monotonic() + args.timeout
                seen = set()
                while time.monotonic() < deadline:
                    with lock:
                        current = list(markers)
                    if finished.is_set() and len(seen) == len(current):
                        return
                    started = time.perf_counter()
                    try:
                        rows = aggregate(reader)
                        query_times.append((time.perf_counter() - started) * 1000)
                        indexed = int(rows[0]["n"]) if rows else 0
                        stamp = time.perf_counter()
                        for end, admitted in current:
                            if end <= indexed and end not in seen:
                                seen.add(end)
                                visibility.append((stamp - admitted) * 1000)
                        if len(query_times) % 5 == 0:
                            health = request(reader, "GET", "/api/health")
                            backlog_samples.append(
                                (health["pending"], health["oldest_pending_seconds"])
                            )
                    except httpx.HTTPStatusError as exc:
                        monitor_errors.append(exc.response.status_code)
                        monitor_error_details.append(
                            {
                                "status": exc.response.status_code,
                                "method": exc.request.method,
                                "path": exc.request.url.path,
                            }
                        )
                    time.sleep(0.02)
                monitor_errors.append("monitor_timeout")

        def observe():
            try:
                monitor()
            except Exception as exc:
                monitor_errors.append(type(exc).__name__)

        worker = threading.Thread(target=observe, daemon=True)
        worker.start()
        admissions = []
        started = time.perf_counter()
        first_batch = None
        try:
            for base in range(0, args.count, args.batch):
                values = [
                    event(n) for n in range(base, min(args.count, base + args.batch))
                ]
                first_batch = first_batch or values
                sent = time.perf_counter()
                receipt = request(
                    ingest, "POST", "/api/v1/events", json={"events": values}
                )
                if receipt["accepted"] != len(values) or not receipt.get("durable"):
                    raise AssertionError(
                        "HTTP receipt did not acknowledge the complete durable batch"
                    )
                admissions.append((time.perf_counter() - sent) * 1000)
                with lock:
                    markers.append((base + len(values), time.perf_counter()))
            admission_seconds = time.perf_counter() - started
            rows = wait_count(admin, args.count, args.timeout)
            searchable_seconds = time.perf_counter() - started
        finally:
            finished.set()
            worker.join(args.timeout + 1)
            ingest.close()
        if worker.is_alive():
            raise TimeoutError("Visibility observer did not stop")
        duplicate = request(
            admin, "POST", "/api/v1/events", json={"events": first_batch}
        )
        report.update(
            admission_seconds=admission_seconds,
            admitted_eps=args.count / admission_seconds,
            submission_to_all_searchable_seconds=searchable_seconds,
            end_to_end_indexed_eps=args.count / searchable_seconds,
            admission_latency_ms=distribution(admissions),
            query_latency_during_ingest_ms=distribution(query_times),
            acknowledged_batch_visibility_lag_ms=distribution(visibility),
            monitor_errors=monitor_errors,
            monitor_error_details=monitor_error_details,
            backlog={
                "samples": len(backlog_samples),
                "max_observed_pending": max(
                    (sample[0] for sample in backlog_samples), default=0
                ),
                "max_observed_oldest_seconds": max(
                    (sample[1] for sample in backlog_samples), default=0
                ),
                "pending_after_indexing": request(admin, "GET", "/api/health")[
                    "pending"
                ],
            },
            correctness=correctness(rows, args.count),
            duplicate_request={
                "accepted": duplicate["accepted"],
                "duplicate": duplicate["duplicate"],
                "passed": duplicate["accepted"] == 0
                and duplicate["duplicate"] == len(first_batch),
            },
        )

        def searches(client):
            samples, errors = [], []
            for _ in range(args.rounds):
                start = time.perf_counter()
                try:
                    aggregate(client)
                    samples.append((time.perf_counter() - start) * 1000)
                except httpx.HTTPStatusError as exc:
                    errors.append(exc.response.status_code)
            return samples, errors

        with ThreadPoolExecutor(max_workers=args.users) as pool:
            measured = list(pool.map(searches, clients))
        report["multiuser_search"] = {
            "attempted": args.users * args.rounds,
            "latency_ms": distribution(
                [sample for values, _ in measured for sample in values]
            ),
            "http_errors": [error for _, errors in measured for error in errors],
        }
        if args.crash_drill:
            extra = min(args.batch, 1000)
            values = [event(n) for n in range(args.count, args.count + extra)]
            receipt = request(admin, "POST", "/api/v1/events", json={"events": values})
            before = request(admin, "GET", "/api/health")
            service.stop()
            with closing(
                sqlite3.connect(
                    (service.directory / "data" / "control.sqlite3").as_uri()
                    + "?mode=ro",
                    uri=True,
                )
            ) as db:
                queued_after_kill = db.execute("SELECT count(*) FROM queue").fetchone()[
                    0
                ]
            service.start()
            admin.close()
            admin = service.client()
            login(admin, "qa_admin", password)
            retry = request(admin, "POST", "/api/v1/events", json={"events": values})
            recovered = wait_count(admin, args.count + extra, args.timeout)
            report["crash_restart"] = {
                "termination_verified": all(
                    service.stop_checks[-1].get(key) is True
                    for key in ("owned_process_exited", "listener_closed")
                )
                and service.stop_checks[-1]["database_handle_released"] is not False,
                "acknowledged_before_kill": receipt["accepted"],
                "pending_before_kill": before["pending"],
                "queued_after_kill": queued_after_kill,
                "replay_exercised": queued_after_kill > 0,
                "resubmission_accepted": retry["accepted"],
                "resubmission_duplicate": retry["duplicate"],
                "correctness": correctness(recovered, args.count + extra),
                "passed": receipt["accepted"] == extra
                and queued_after_kill > 0
                and retry["accepted"] == 0
                and retry["duplicate"] == extra
                and correctness(recovered, args.count + extra)["passed"],
            }
        report["passed"] = (
            report["correctness"]["passed"]
            and report["duplicate_request"]["passed"]
            and not report["monitor_errors"]
            and report["multiuser_search"]["latency_ms"]["samples"]
            == args.users * args.rounds
            and not report["multiuser_search"]["http_errors"]
            and (not args.crash_drill or report["crash_restart"]["passed"])
        )
        report["limitations"] = (
            "One local machine and synthetic data; no distributed quorum/network partition, "
            "long-duration soak, external collector or Splunk performance comparison. "
            "Rates include HTTP/TLS and service background indexing; query errors remain reported. "
            "Visibility lag is sampled per acknowledged batch, not per event."
        )
        return report
    finally:
        admin.close()
        for client in clients:
            client.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--isolated",
        action="store_true",
        help="Explicitly allow an owned temporary test service",
    )
    parser.add_argument("--count", type=int, default=10000)
    parser.add_argument("--batch", type=int, default=500)
    parser.add_argument("--users", type=int, default=4)
    parser.add_argument("--rounds", type=int, default=20)
    parser.add_argument("--query-workers", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--transport", choices=["https", "http"], default="https")
    parser.add_argument("--crash-drill", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if not args.isolated:
        parser.error(
            "--isolated is required; existing services and data paths are never targets"
        )
    if not (
        1 <= args.count <= 1000000
        and 1 <= args.batch <= 1000
        and 1 <= args.users <= 32
        and 1 <= args.rounds <= 1000
        and 1 <= args.query_workers <= 32
        and 5 <= args.timeout <= 600
    ):
        parser.error(
            "count 1..1000000, batch 1..1000, users 1..32, rounds 1..1000, timeout 5..600"
        )
    temporary = tempfile.TemporaryDirectory(prefix="sapientia-http-qualification-")
    service, report, failure = None, None, None
    args.output.parent.mkdir(parents=True, exist_ok=True)

    def publish():
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")

    try:
        service = IsolatedService(
            Path(temporary.name), args.transport, args.timeout, args.query_workers
        )
        service.start()
        report = qualify(service, args)
    except Exception as exc:
        failure = exc
        report = (service.report if service else None) or {
            "scope": "isolated qualification"
        }
        report.update(
            passed=False, report_complete=False, failure_type=type(exc).__name__
        )
    finally:
        if service:
            try:
                service.stop()
            except Exception as exc:
                failure = failure or exc
                report = report or {"scope": "isolated qualification"}
                report.update(passed=False, stop_error_type=type(exc).__name__)
            if report:
                report["service_stop_checks"] = service.stop_checks
        if report:
            log_path = Path(temporary.name) / "isolated-server.log"
            if log_path.is_file():
                saved_log = args.output.with_suffix(".server.log")
                saved_log.write_bytes(log_path.read_bytes())
                report["isolated_server_log"] = saved_log.name
            # Preserve measurements even when later cleanup fails.
            publish()
        try:
            temporary.cleanup()
        except Exception as exc:
            failure = failure or exc
            report = report or {"scope": "isolated qualification"}
            report.update(
                passed=False,
                cleanup_error_type=type(exc).__name__,
                retained_temporary_directory=temporary.name,
            )
            publish()
    print(json.dumps(report, indent=2))
    if failure:
        raise failure
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
