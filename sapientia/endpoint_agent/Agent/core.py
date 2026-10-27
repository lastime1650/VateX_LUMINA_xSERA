"""Shared Vatex LUMINA xSERA endpoint agent runtime. Standard-library-only by design."""

from __future__ import annotations

import ctypes
import hashlib
import importlib.util
import json
import logging
import math
import os
import platform
import secrets
import sqlite3
import ssl
import threading
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

VERSION = "lumina-xsera-agent/0.12"


def bounded_heartbeat(health):
    """Keep fleet health within the server's 4096-byte JSON admission limit."""

    def size(value):
        return len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode())

    if size(health) <= 3500:
        return health
    result = dict(
        health, details_omitted=True, full_details="private local status file"
    )
    fields = {
        "status",
        "state",
        "enabled",
        "revision",
        "rule_count",
        "policy_sha256",
        "kernel_permission_denial",
        "support",
        "independent_rollback_watchdog",
        "error",
        "key_id",
        "manifest_digest",
        "measured_files",
        "os_code_signature",
    }
    for name in (
        "providers",
        "defense",
        "kernel_prevention",
        "host_isolation",
        "capture",
        "package_integrity",
    ):
        component = health.get(name, {})
        summary = {"details_omitted": True}
        if isinstance(component, dict):
            for key in fields:
                value = component.get(key)
                if isinstance(value, str):
                    summary[key] = value[:160]
                elif value is None or type(value) in (bool, int, float):
                    summary[key] = value
            directories = component.get("watched_directories")
            if isinstance(directories, list):
                summary["directory_count"] = len(directories)
                summary["directory_scope_sha256"] = hashlib.sha256(
                    json.dumps(directories, sort_keys=True).encode()
                ).hexdigest()
        result[name] = summary
    if size(result) > 3500:
        for name in (
            "providers",
            "defense",
            "kernel_prevention",
            "host_isolation",
            "capture",
            "package_integrity",
        ):
            value = result[name]
            result[name] = {
                key: value[key][:32] if isinstance(value[key], str) else value[key]
                for key in ("state", "status", "enabled", "details_omitted")
                if key in value
            }
    if size(result) > 3500:
        raise ValueError("Fleet health exceeds the bounded heartbeat contract")
    return result


READ_ONLY = ()  # Telemetry collection remains read-only; response is separate opt-in.
MAX_COMMAND_LINE = 8192


def _response():
    # Qualification may load core.py as a standalone module. Create a private
    # package rooted at these verified local package bytes, preserving relative
    # imports without trusting the working directory or global import path.
    import sys

    name = (
        "_lumina_agent_"
        + __import__("hashlib")
        .sha256(str(Path(__file__).resolve().parent).encode())
        .hexdigest()[:16]
    )
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            name,
            Path(__file__).with_name("__init__.py"),
            submodule_search_locations=[str(Path(__file__).resolve().parent)],
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    fullname = name + ".response"
    if fullname not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            fullname, Path(__file__).with_name("response.py")
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[fullname] = module
        spec.loader.exec_module(module)
    return sys.modules[fullname]


response = _response()


class RunLock(response.Lock):
    """Lifetime agent fence, separate from short response poll/execution locks."""

    def __init__(self, directory):
        super().__init__(directory)
        self.path = Path(directory) / "agent-run.lock"
        response._no_links(self.path.parent)
        if self.path.exists() or self.path.is_symlink():
            response._no_links(self.path)


def bound_command_line(event: dict):
    """Match the server's mapped command-line limit, retaining truncation evidence."""
    data = event.get("data", {})
    process = data.get("process", {}) if isinstance(data, dict) else {}
    command = process.get("command_line") if isinstance(process, dict) else None
    if not isinstance(command, str) or len(command) <= MAX_COMMAND_LINE:
        return False
    process["command_line"] = command[:MAX_COMMAND_LINE]
    agent = data.setdefault("agent", {})
    if isinstance(agent, dict):
        agent["command_line_original_length"] = len(command)
        agent["command_line_truncated"] = True
    return True


def bound_entity_strings(event: dict):
    """Keep scalar endpoint fields within the server's 512-char mapping limit."""
    data = event.get("data")
    if not isinstance(data, dict):
        return False
    truncated = []

    def visit(value, prefix=""):
        if not isinstance(value, dict):
            return
        for key, item in value.items():
            path = prefix + key
            if isinstance(item, dict):
                visit(item, path + ".")
            elif (
                isinstance(item, str)
                and path not in {"process.command_line", "powershell.script_block"}
                and len(item) > 512
            ):
                value[key] = item[:512]
                truncated.append({"field": path, "original_length": len(item)})

    visit(data)
    if truncated:
        agent = data.setdefault("agent", {})
        if isinstance(agent, dict):
            agent["truncated_fields"] = truncated[:32]
    return bool(truncated)


def repair_legacy_eventlog_wire(event):
    """Repair only old native Event Log shapes the server could never admit."""
    data = event.get("data")
    if (
        not isinstance(data, dict)
        or data.get("agent", {}).get("collector") != "windows-event-log"
    ):
        return False
    changed = []
    code = data.get("event", {}).get("code")
    if type(code) is int:
        data["event"]["code"] = str(code)
        changed.append("event.code")
    for path in (
        "process.pid",
        "process.parent.pid",
        "source.port",
        "destination.port",
    ):
        node = data
        parts = path.split(".")
        for part in parts[:-1]:
            node = node.get(part, {}) if isinstance(node, dict) else {}
        value = node.get(parts[-1]) if isinstance(node, dict) else None
        if isinstance(value, str):
            try:
                number = int(value, 16 if value.lower().startswith("0x") else 10)
                maximum = 65535 if path.endswith("port") else 2**32 - 1
                if not 0 <= number <= maximum:
                    raise ValueError("legacy numeric field out of range")
                node[parts[-1]] = number
            except ValueError:
                node.pop(parts[-1])
            changed.append(path)

    def clean(node, prefix=""):
        if not isinstance(node, dict):
            return
        for key in list(node):
            value, field = node[key], prefix + key
            if isinstance(value, dict):
                clean(value, field + ".")
            elif value in ("", "-") and field != "process.command_line":
                node.pop(key)
                changed.append(field)

    clean(data)
    if changed:
        data["agent"]["legacy_wire_repaired"] = sorted(set(changed))[:32]
    return bool(changed)


def atomic_json(path: Path, value: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temp.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            os.chmod(temp, 0o600)
        if os.name == "nt":
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            move = kernel.MoveFileExW
            move.argtypes, move.restype = (
                (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32),
                ctypes.c_int,
            )

            def extended(value):
                value = str(value.absolute())
                return (
                    value
                    if value.startswith("\\\\?\\")
                    else "\\\\?\\UNC\\" + value[2:]
                    if value.startswith("\\\\")
                    else "\\\\?\\" + value
                )

            # Windows readers (including scanners) may briefly deny deletion
            # sharing. Keep the same fsynced temp file and bound retry waiting;
            # permanent ACL failures and unrelated errors still fail closed.
            deadline, delay = time.monotonic() + 1.0, 0.01
            while not move(extended(temp), extended(path), 0x1 | 0x8):
                error = ctypes.get_last_error()
                remaining = deadline - time.monotonic()
                if error not in {5, 32, 33} or remaining <= 0:
                    raise ctypes.WinError(error)
                time.sleep(min(delay, remaining))
                delay = min(0.1, delay * 2)
        else:
            os.replace(temp, path)
            directory = os.open(
                path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            )
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        temp.unlink(missing_ok=True)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ConnectionError("Endpoint redirects are forbidden")


class Transport:
    def __init__(self, url: str, ca: str, timeout: float = 10):
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in ("", "/")
        ):
            raise ValueError("Endpoint agent requires HTTPS")
        self.url = url.rstrip("/")
        self.context = ssl.create_default_context(cafile=str(Path(ca).resolve()))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.opener = build_opener(
            ProxyHandler({}), HTTPSHandler(context=self.context), NoRedirect()
        )
        self.timeout = max(1, min(30, timeout))

    def post(self, route: str, body: dict, credential: str | None = None):
        data = json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if credential:
            headers["Authorization"] = "Bearer " + credential
        request = Request(self.url + route, data=data, headers=headers, method="POST")
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                content = response.read(2 * 1024 * 1024 + 1)
                if len(content) > 2 * 1024 * 1024:
                    raise ValueError("Endpoint response exceeds 2 MiB")
                result = json.loads(content)
                if not isinstance(result, dict):
                    raise ValueError("Endpoint response must be an object")  # noqa: TRY004 -- Protocol failures are handled as ValueError.
                return result
        except HTTPError as error:
            raise RuntimeError(f"{route}: HTTP {error.code}") from error
        except URLError as error:
            raise ConnectionError(f"{route}: {error.reason}") from error


class Queue:
    """Durable at-least-once delivery; server event IDs make retries idempotent."""

    def __init__(self, path: Path, max_pending: int = 10000, capture_reserve: int = 0):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS pending (id TEXT PRIMARY KEY, body TEXT NOT NULL, created REAL NOT NULL)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS quarantined(id TEXT PRIMARY KEY,body TEXT NOT NULL,created REAL NOT NULL,reason TEXT NOT NULL)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS local_evaluation(id TEXT PRIMARY KEY,body TEXT NOT NULL,created REAL NOT NULL,rule_cursor INTEGER NOT NULL DEFAULT 0,policy_digest TEXT)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS capture_receipts(id TEXT PRIMARY KEY,body TEXT NOT NULL,created REAL NOT NULL)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS queue_totals(name TEXT PRIMARY KEY,n INTEGER NOT NULL,row_bytes INTEGER NOT NULL)"
        )
        for table in ("pending", "quarantined", "local_evaluation", "capture_receipts"):
            # Fixed identifiers; totals are transactional across worker connections.
            self.db.execute(
                f"INSERT OR IGNORE INTO queue_totals SELECT ?,count(*),coalesce(sum(length(CAST(body AS BLOB))),0) FROM {table}",
                (table,),
            )
            self.db.execute(
                f"CREATE TRIGGER IF NOT EXISTS queue_{table}_insert AFTER INSERT ON {table} BEGIN UPDATE queue_totals SET n=n+1,row_bytes=row_bytes+length(CAST(NEW.body AS BLOB)) WHERE name='{table}'; END"
            )
            self.db.execute(
                f"CREATE TRIGGER IF NOT EXISTS queue_{table}_delete AFTER DELETE ON {table} BEGIN UPDATE queue_totals SET n=n-1,row_bytes=row_bytes-length(CAST(OLD.body AS BLOB)) WHERE name='{table}'; END"
            )
            self.db.execute(
                f"CREATE TRIGGER IF NOT EXISTS queue_{table}_update AFTER UPDATE OF body ON {table} BEGIN UPDATE queue_totals SET row_bytes=row_bytes+length(CAST(NEW.body AS BLOB))-length(CAST(OLD.body AS BLOB)) WHERE name='{table}'; END"
            )
        self.db.commit()
        self.max_pending = max_pending
        self.capture_reserve = max(0, min(100000, int(capture_reserve)))
        self.max_bytes = 128 * 1024 * 1024

    def add(self, event: dict):
        self.add_many([event])

    def add_many(self, events, *, evaluate=False):
        """Commit a collection cycle atomically before advancing source cursors."""
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            count, size = self.db.execute(
                "SELECT n,row_bytes FROM queue_totals WHERE name='pending'"
            ).fetchone()
            receipt_count, receipt_bytes = self.db.execute(
                "SELECT n,row_bytes FROM queue_totals WHERE name='capture_receipts'"
            ).fetchone()
            for event in events:
                bound_command_line(event)
                bound_entity_strings(event)
                body = json.dumps(event, ensure_ascii=False, allow_nan=False)
                if len(body.encode()) > 64 * 1024:
                    raise ValueError(
                        "Telemetry envelope exceeds 64 KiB; source cursor retained"
                    )
                receipt = self.db.execute(
                    "SELECT body FROM capture_receipts WHERE id=?", (event["id"],)
                ).fetchone()
                if receipt and receipt[0] != body:
                    first = json.loads(receipt[0])
                    original_hash = (
                        first.get("data", {})
                        .get("agent", {})
                        .get("source_record_sha256")
                    )
                    current_hash = (
                        event.get("data", {})
                        .get("agent", {})
                        .get("source_record_sha256")
                    )
                    if (
                        not isinstance(original_hash, str)
                        or len(original_hash) != 64
                        or any(c not in "0123456789abcdef" for c in original_hash)
                        or original_hash != current_hash
                    ):
                        raise ValueError("Capture event identity content conflict")
                    body = receipt[
                        0
                    ]  # Preserve the first immutable source receipt and its enrichment.
                if not receipt:
                    self.db.execute(
                        "INSERT INTO capture_receipts VALUES(?,?,?)",
                        (event["id"], body, time.time()),
                    )
                    receipt_count += 1
                    receipt_bytes += len(body.encode())
                inserted = self.db.execute(
                    "INSERT OR IGNORE INTO pending VALUES (?,?,?)",
                    (event["id"], body, time.time()),
                ).rowcount
                if (
                    evaluate
                    and event.get("data", {}).get("event", {}).get("module")
                    != "local_defense"
                ):
                    old = self.db.execute(
                        "SELECT body FROM local_evaluation WHERE id=?", (event["id"],)
                    ).fetchone()
                    if old and old[0] != body:
                        raise ValueError(
                            "Local evaluation event identity content conflict"
                        )
                    self.db.execute(
                        "INSERT OR IGNORE INTO local_evaluation(id,body,created) VALUES(?,?,?)",
                        (event["id"], body, time.time()),
                    )
                count += inserted
                size += len(body.encode()) * inserted
                if (
                    count > self.max_pending + self.capture_reserve
                    or size > self.max_bytes
                ):
                    raise RuntimeError(
                        "Pending telemetry queue is full; no event was discarded"
                    )
            jobs = self.db.execute(
                "SELECT n,row_bytes FROM queue_totals WHERE name='local_evaluation'"
            ).fetchone()
            if (
                jobs[0] > self.max_pending + self.capture_reserve
                or jobs[1] > self.max_bytes
            ):
                raise RuntimeError(
                    "Durable local evaluation spool is full; source cursor retained"
                )
            # Bounded retry cache, separate from pending and evaluation work.
            # Eviction does not delete undelivered telemetry or unfinished work.
            while receipt_count > 100000 or receipt_bytes > self.max_bytes:
                oldest = self.db.execute(
                    "SELECT id,length(CAST(body AS BLOB)) FROM capture_receipts ORDER BY created,rowid LIMIT 1"
                ).fetchone()
                self.db.execute("DELETE FROM capture_receipts WHERE id=?", (oldest[0],))
                receipt_count -= 1
                receipt_bytes -= oldest[1]

    def evaluation_size(self):
        return self.db.execute(
            "SELECT n FROM queue_totals WHERE name='local_evaluation'"
        ).fetchone()[0]

    def evaluation_peek(self):
        row = self.db.execute(
            "SELECT id,body,rule_cursor,policy_digest FROM local_evaluation ORDER BY created,rowid LIMIT 1"
        ).fetchone()
        return (row[0], json.loads(row[1]), row[2], row[3]) if row else None

    def evaluation_settle(self, key, records, *, cursor, policy_digest, complete):
        # Outcomes are durable before the work receipt advances. A crash between
        # these commits replays only idempotent outcome records, never an effect.
        self.add_many(records)
        with self.db:
            if complete:
                self.db.execute("DELETE FROM local_evaluation WHERE id=?", (key,))
            else:
                self.db.execute(
                    "UPDATE local_evaluation SET rule_cursor=?,policy_digest=? WHERE id=?",
                    (cursor, policy_digest, key),
                )

    def peek(self, limit=50):
        rows = self.db.execute(
            "SELECT id,body FROM pending ORDER BY created,rowid LIMIT ?", (limit,)
        ).fetchall()
        events = []
        for key, body in rows:
            event = json.loads(body)
            changed_wire = repair_legacy_eventlog_wire(event)
            changed_command = bound_command_line(event)
            changed_fields = bound_entity_strings(event)
            if changed_wire or changed_command or changed_fields:
                self.db.execute(
                    "UPDATE pending SET body=? WHERE id=?",
                    (json.dumps(event, ensure_ascii=False), key),
                )
            events.append((key, event))
        self.db.commit()
        return events

    def remove(self, ids):
        self.db.executemany("DELETE FROM pending WHERE id=?", [(key,) for key in ids])
        self.db.commit()

    def size(self):
        return self.db.execute(
            "SELECT n FROM queue_totals WHERE name='pending'"
        ).fetchone()[0]

    def settle(self, rows, results):
        """Retain rejected telemetry in a bounded durable local review spool."""
        rejected = [
            (
                key,
                json.dumps(event, ensure_ascii=False),
                time.time(),
                "server_quarantine",
            )
            for (key, event), result in zip(rows, results)
            if result["quarantined"]
        ]
        with self.db:
            if rejected:
                existing = self.db.execute(
                    "SELECT n,row_bytes FROM queue_totals WHERE name='quarantined'"
                ).fetchone()
                if (
                    existing[0] + len(rejected) > self.max_pending
                    or existing[1] + sum(len(r[1].encode()) for r in rejected)
                    > self.max_bytes
                ):
                    raise RuntimeError(
                        "Local quarantine spool is full; delivery receipt retained for retry"
                    )
                self.db.executemany(
                    "INSERT OR IGNORE INTO quarantined VALUES(?,?,?,?)", rejected
                )
            self.db.executemany(
                "DELETE FROM pending WHERE id=?", [(key,) for key, _ in rows]
            )

    def quarantine_size(self):
        return self.db.execute(
            "SELECT n FROM queue_totals WHERE name='quarantined'"
        ).fetchone()[0]

    def close(self):
        self.db.close()


class Agent:
    def __init__(self, config: dict, collector, stop: threading.Event | None = None):
        self.config = config
        import importlib

        integrity_module = importlib.import_module(
            response.__package__ + ".package_integrity"
        )
        self.package_integrity = integrity_module.PackageIntegrity(config)
        self.collector = collector
        self.stop = stop or threading.Event()
        response._no_links(Path(config["state_dir"]).expanduser().absolute())
        self.directory = Path(config["state_dir"]).expanduser().resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.identity_path = self.directory / "identity.json"
        self.status_path = self.directory / "status.json"
        self.queue = Queue(
            self.directory / "pending.sqlite3",
            int(config.get("max_pending", 10000)),
            int(config.get("capture_reserve", 10000)),
        )
        self.transport = Transport(
            config["endpoint_url"],
            config["ca_file"],
            timeout=float(config.get("transport_timeout_seconds", 10)),
        )
        self.control_transport = Transport(
            config["endpoint_url"],
            config["ca_file"],
            timeout=max(1, min(5, float(config.get("control_timeout_seconds", 5)))),
        )
        self.identity = self._identity()
        self.sent = 0
        self.last_error = None
        self.errors = {}
        self._error_lock = threading.RLock()
        self._pending_metric = self.queue.size()
        self._evaluation_metric = self.queue.evaluation_size()
        self._quarantined_metric = self.queue.quarantine_size()
        self._provider_health = {"state": "initializing"}
        self._control_thread = None
        self._control_fatal = None
        self._capture_thread = None
        self._evaluation_thread = None
        self._data_worker_fatal = None
        self._policy_at = 0.0
        self._renew_at = 0.0
        self.defense = None
        defense_file = Path(__file__).with_name("defense.py")
        if defense_file.exists():
            import importlib

            self.defense = importlib.import_module(
                response.__package__ + ".defense"
            ).Defense(
                dict(
                    config,
                    **{
                        key: self.identity.get(key)
                        for key in ("agent_id", "tenant", "host", "index")
                    },
                ),
                response,
            )
        elif config.get("defense", {}).get("enabled"):
            self.errors["defense"] = "module_unavailable"
        self.kernel_prevention = None
        self.memory_observability = None
        if config.get("memory_observability", {}).get("enabled") is True:
            memory_module = importlib.import_module(
                response.__package__ + ".memory_observability"
            )
            self.memory_observability = memory_module.MemoryObservability(
                config, response.inspect_process
            )
        if config.get("kernel_prevention", {}).get("enabled"):
            import importlib

            module_name = (
                ".windows_app_control" if os.name == "nt" else ".kernel_prevention"
            )
            prevention_module = importlib.import_module(
                response.__package__ + module_name
            )
            prevention_type = (
                prevention_module.WindowsAppControl
                if os.name == "nt"
                else prevention_module.KernelPrevention
            )
            self.kernel_prevention = prevention_type(
                dict(
                    config,
                    **{
                        key: self.identity.get(key)
                        for key in ("agent_id", "tenant", "host", "index")
                    },
                ),
                response,
            )

    def _isolation_status(self):
        settings = self.config.get("response", {})
        if not settings.get("allow_host_isolation"):
            return {"enabled": False}
        import importlib

        operations = importlib.import_module(response.__package__ + ".operations")
        if hasattr(operations, "isolation_status"):
            return operations.isolation_status(settings)
        return {"enabled": True, "state": "unverified"}

    def _identity(self):
        if not self.identity_path.exists():
            raise RuntimeError("Agent is not enrolled; run the enroll command first")
        identity = json.loads(self.identity_path.read_text(encoding="utf-8"))
        if (
            identity.get("tenant") != self.config["tenant"]
            or identity.get("host") != self.config["host"]
        ):
            raise RuntimeError("Saved enrollment differs from configured tenant/host")
        if not identity.get("credential") or not identity.get("agent_id"):
            raise RuntimeError("Saved agent identity is incomplete")
        return identity

    def _post(self, route, body):
        transport = (
            self.control_transport
            if threading.current_thread() is self._control_thread
            else self.transport
        )
        return transport.post(route, body, self.identity["credential"])

    def status(self):
        data = {
            "agent_id": self.identity["agent_id"],
            "host": self.identity["host"],
            "tenant": self.identity["tenant"],
            "pending": self.queue.size(),
            "local_evaluation_pending": self.queue.evaluation_size(),
            "capture_capacity": self.queue.max_pending + self.queue.capture_reserve,
            "quarantined": self.queue.quarantine_size(),
            "sent_since_start": self.sent,
            "last_error": self.last_error,
            "updated_at": time.time(),
            "provider_health": self._provider_health,
            "memory_observability": self.memory_observability.status()
            if self.memory_observability
            else {"enabled": False, "state": "disabled"},
            "errors": dict(self.errors),
            "defense": self.defense.health() if self.defense else {"enabled": False},
            "kernel_prevention": self.kernel_prevention.status()
            if self.kernel_prevention
            else {"enabled": False},
            "host_isolation": self._isolation_status(),
            "package_integrity": self.package_integrity.measure(),
            "shutdown": dict(getattr(self, "_shutdown_state", {})),
        }
        self._pending_metric = data["pending"]
        self._evaluation_metric = data["local_evaluation_pending"]
        self._quarantined_metric = data["quarantined"]
        atomic_json(self.status_path, data)
        if self.config.get("public_status_file"):
            atomic_json(Path(self.config["public_status_file"]), data)
        return data

    def flush(self):
        # The endpoint API accepts up to 200 events. Larger batches are critical
        # when a noisy provider has already built a durable backlog.
        batch_size = max(10, min(200, int(self.config.get("send_batch_size", 50))))
        rows = self.queue.peek(limit=batch_size)
        if not rows:
            return 0
        response = self._post("/api/agent/ingest", {"events": [row[1] for row in rows]})
        return self._settle_delivery(rows, response)

    def _settle_delivery(self, rows, response):
        """Only exact validated durable ACKs authorize removing local rows."""
        results = response.get("results", [])
        if (
            response.get("durable") is not True
            or not isinstance(results, list)
            or len(results) != len(rows)
        ):
            raise RuntimeError("Server result count differs from submitted event count")
        accepted, duplicate = response.get("accepted"), response.get("duplicate")
        if (
            type(accepted) is not int
            or type(duplicate) is not int
            or min(accepted, duplicate) < 0
            or accepted + duplicate != len(rows)
        ):
            raise RuntimeError("Server durable receipt has invalid aggregate counts")
        quarantined = response.get("quarantined", 0)
        if type(quarantined) is not int or not 0 <= quarantined <= accepted:
            raise RuntimeError("Server durable receipt has invalid quarantine count")
        for (key, _), result in zip(rows, results):
            if (
                not isinstance(result, dict)
                or result.get("id") != key
                or type(result.get("quarantined")) is not bool
                or result.get("error")
            ):
                raise RuntimeError(
                    "Server receipt identity or result differs from submitted event"
                )
        self.queue.settle(rows, results)
        self.sent += len(rows)
        return len(rows)

    def heartbeat(self):
        def unhealthy(value):
            return isinstance(value, dict) and (
                value.get("status", value.get("state"))
                in {
                    "error",
                    "unavailable",
                    "degraded",
                    "expired",
                    "initializing",
                    "closing",
                    "unknown",
                    "failed",
                }
                or value.get("enabled") is True
                and value.get("state") == "stopped"
                or value.get("backlog_confirmed") is True
                or any(unhealthy(child) for child in value.values())
            )

        defense_health = self.defense.health() if self.defense else {"enabled": False}
        kernel_health = (
            self.kernel_prevention.status()
            if self.kernel_prevention
            else {"enabled": False}
        )
        isolation_health = self._isolation_status()
        integrity_health = self.package_integrity.measure()
        capture_health = {
            "state": "degraded"
            if self._pending_metric > self.queue.max_pending
            else "active",
            "transport_pending": self._pending_metric,
            "local_evaluation_pending": self._evaluation_metric,
            "capture_capacity": self.queue.max_pending + self.queue.capture_reserve,
            "source_capture_during_transport_backpressure": True,
            "hard_capacity_behavior": "explicit_coverage_failure_and_retained_source_cursor",
            "unobserved_polling_events_recoverable": False,
        }
        memory_health = (
            self.memory_observability.status()
            if self.memory_observability
            else {"enabled": False, "state": "disabled"}
        )
        return self._post(
            "/api/agent/heartbeat",
            {
                "health": bounded_heartbeat(
                    {
                        "status": "degraded"
                        if self.last_error
                        or unhealthy(self._provider_health)
                        or self._quarantined_metric
                        or unhealthy(defense_health)
                        or unhealthy(kernel_health)
                        or unhealthy(isolation_health)
                        or unhealthy(capture_health)
                        or unhealthy(memory_health)
                        or integrity_health.get("state") == "failed"
                        else "ok",
                        "platform": platform.system().lower(),
                        "version": VERSION,
                        "pending": self._pending_metric,
                        "quarantined": self._quarantined_metric,
                        "last_error": (self.last_error or "")[:300],
                        "response": response.capabilities(self.config),
                        "providers": self._provider_health,
                        "defense": defense_health,
                        "kernel_prevention": kernel_health,
                        "host_isolation": isolation_health,
                        "capture": capture_health,
                        "memory_observability": memory_health,
                        "package_integrity": integrity_health,
                    }
                )
            },
        )

    def poll(self):
        return response.poll(self)

    def _recover_isolation(self):
        """Local guard recovery remains available without network credentials."""
        import importlib

        operations = importlib.import_module(response.__package__ + ".operations")
        with response.Lock(self.directory):
            return operations.recover_linux_isolation(self.config["response"])

    def _attempt(self, stage, callback):
        try:
            result = callback()
            with self._error_lock:
                self.errors.pop(stage, None)
            return result
        except (
            OSError,
            RuntimeError,
            ValueError,
            ConnectionError,
            sqlite3.Error,
        ) as error:
            # Never persist a server payload, event body or credential in health.
            with self._error_lock:
                self.errors[stage] = type(error).__name__
            logging.getLogger(__name__).warning(
                "Agent %s deferred (%s)", stage, type(error).__name__
            )
            return None
        finally:
            with self._error_lock:
                self.last_error = (
                    "; ".join(k + ":" + v for k, v in sorted(self.errors.items()))
                    or None
                )

    def _control_cycle(self, heartbeat_at, poll_at):
        now = time.monotonic()
        if (
            not self.stop.is_set()
            and now >= poll_at
            and self.config.get("response", {}).get("quarantine_dir")
        ):
            self._attempt("isolation_recovery", self._recover_isolation)
        # A lost rotation reply invalidates the old ordinary bearer. Recover
        # that committed reply before trying poll; otherwise poll401 could
        # indefinitely prevent the renewal-only proof from being used.
        if (
            self.directory.joinpath("credential-recovery.json").exists()
            and now >= self._renew_at
        ):
            self._attempt("credential", self.renew)
            self._renew_at = time.monotonic() + 60
        if now >= heartbeat_at:
            self._attempt("heartbeat", self.heartbeat)
            heartbeat_at = time.monotonic() + 30
        if not self.stop.is_set() and now >= poll_at:
            self._attempt("response", self.poll)
            poll_at = time.monotonic() + 5
        with self._error_lock:
            response_ok = "response" not in self.errors
        expiry = self.identity.get("expires_at")
        if (
            response_ok
            and not self.stop.is_set()
            and now >= self._renew_at
            and (
                self.directory.joinpath("credential-recovery.json").exists()
                or isinstance(expiry, (int, float))
                and expiry <= time.time() + 7 * 86400
            )
        ):
            self._attempt("credential", self.renew)
            self._renew_at = time.monotonic() + 60
        if (
            self.defense
            and (
                self.config.get("defense", {}).get("enabled") or self.kernel_prevention
            )
            and not self.stop.is_set()
            and now >= self._policy_at
        ):
            self._attempt("defense_policy", self._fetch_policy)
            self._policy_at = time.monotonic() + 60
        return heartbeat_at, poll_at

    def _fetch_policy(self):
        result = self._post("/api/agent/defense-policy", {})
        bundle = result.get("bundle")
        if bundle is not None:
            from cryptography.exceptions import InvalidSignature

            try:
                if self.kernel_prevention:
                    self.defense.update(bundle, cache_only=True)
                else:
                    self.defense.update(bundle)
            except InvalidSignature:
                raise ValueError("Policy signature verification failed") from None

    def renew(self):
        """Rotate only after receipts, with durable recovery if the reply is lost."""
        with response.Lock(self.directory):
            return self._renew_locked()

    def _renew_locked(self):
        path = self.directory / "credential-recovery.json"
        if path.exists():
            proof = json.loads(path.read_text(encoding="utf-8"))
        else:
            proof = {
                "credential": self.identity["credential"],
                "recovery_key": secrets.token_urlsafe(32),
            }
            atomic_json(path, proof)
        transport = (
            self.control_transport
            if threading.current_thread() is self._control_thread
            else self.transport
        )
        result = transport.post(
            "/api/agent/renew",
            {"recovery_key": proof["recovery_key"]},
            proof["credential"],
        )
        if (
            not isinstance(result, dict)
            or any(
                result.get(key) != self.identity.get(key)
                for key in ("agent_id", "tenant", "host")
            )
            or (
                self.config.get("index") and result.get("index") != self.config["index"]
            )
            or not isinstance(result.get("credential"), str)
            or not 30 <= len(result["credential"]) <= 160
            or not all(
                c.isascii() and (c.isalnum() or c in "_-") for c in result["credential"]
            )
            or type(result.get("expires_at")) not in (int, float)
            or not math.isfinite(result["expires_at"])
            or not time.time() < result["expires_at"] <= time.time() + 91 * 86400
        ):
            raise RuntimeError("Credential renewal identity does not match this agent")
        updated = {**self.identity, **result}
        atomic_json(self.identity_path, updated)
        self.identity = updated
        path.unlink(missing_ok=True)
        return {"agent_id": updated["agent_id"], "expires_at": updated["expires_at"]}

    def _control_loop(self):
        heartbeat_at = poll_at = 0.0
        try:
            while not self.stop.is_set():
                heartbeat_at, poll_at = self._control_cycle(heartbeat_at, poll_at)
                self.stop.wait(0.25)
        except Exception as error:  # noqa: BLE001 -- Unexpected control failure must stop the service explicitly.
            self._control_fatal = type(error).__name__
            with self._error_lock:
                self.errors["control_worker"] = self._control_fatal
            logging.getLogger(__name__).error(
                "Endpoint control worker failed (%s)", self._control_fatal
            )
            self.stop.set()

    def run(self, once=False):
        lock = RunLock(self.directory)
        try:
            lock.__enter__()
        except RuntimeError:
            if self.kernel_prevention:
                self.kernel_prevention.close()
            if self.defense:
                self.defense.close()
            self.queue.close()
            raise
        try:
            return self._run_locked(once)
        finally:
            lock.__exit__(None, None, None)

    def _run_locked(self, once=False):
        interval = max(1.0, float(self.config.get("collect_interval_seconds", 10)))
        try:
            if self.kernel_prevention:
                self._attempt("kernel_policy_fetch", self._fetch_policy)
                self.kernel_prevention.start()
            if self.config.get("response", {}).get("allow_host_isolation"):
                import importlib

                operations = importlib.import_module(
                    response.__package__ + ".operations"
                )
                operations.recover_linux_isolation(self.config["response"])
            if not once:
                # Each worker owns its SQLite connections. Collection and local
                # evaluation must make progress even while HTTP transmission or
                # an OS provider is slow; never share a connection across threads.
                if self.defense:
                    self.defense.close()
                    self.defense.db = None
                self._capture_thread = threading.Thread(
                    target=self._capture_loop, name="endpoint-capture", daemon=False
                )
                self._evaluation_thread = threading.Thread(
                    target=self._evaluation_loop,
                    name="endpoint-evaluation",
                    daemon=False,
                )
                self._capture_thread.start()
                self._evaluation_thread.start()
                self._control_thread = threading.Thread(
                    target=self._control_loop, name="endpoint-control", daemon=False
                )
                self._control_thread.start()
            while not self.stop.is_set():
                self._attempt("telemetry", self._flush_cycle)
                # Transport pressure must not turn off polling or local detection.
                # A separate bounded capture reserve absorbs outages; exhausting
                # the hard bound is an explicit coverage failure, never healthy.
                if once:
                    self._attempt("collection", self._collect_cycle)
                    self._attempt("local_evaluation", self._evaluation_cycle)
                self._attempt("telemetry", self._flush_cycle)
                if once:
                    self._control_cycle(0.0, 0.0)
                self.status()
                if once:
                    break
                self.stop.wait(interval)
        finally:
            self.stop.set()
            if self.kernel_prevention:
                self.kernel_prevention.close()
            worker_failed = False
            for worker in (self._capture_thread, self._evaluation_thread):
                if worker:
                    worker.join(timeout=60)
                    if worker.is_alive():
                        worker_failed = True
            if self._control_thread:
                self._control_thread.join(timeout=60)
                if self._control_thread.is_alive():
                    worker_failed = True
            if self.defense and not self._evaluation_thread:
                self.defense.close()
            self._shutdown_state = {
                "workers_quiesced": not worker_failed,
                "snapshot_is_quiescent": not worker_failed,
                "final_snapshot": True,
                "transport_only": True,
                "policy_or_response_execution_during_drain": False,
            }
            try:
                if not worker_failed:
                    self._shutdown_drain()
                else:
                    self._shutdown_state.update(
                        drain_state="skipped_workers_active", durable_tail_retained=True
                    )
                # Capture may have committed one last batch after the ordinary
                # status snapshot. Read its durable counters only after joins.
                self.status()
            finally:
                self.queue.close()
            if worker_failed:
                raise RuntimeError(
                    "Endpoint control worker did not stop; execution outcome must be inspected"
                )
            if self._control_fatal:
                raise RuntimeError(
                    "Endpoint control worker failed; durable receipts retained"
                )
            if self._data_worker_fatal:
                raise RuntimeError(
                    "Endpoint capture/evaluation worker failed; durable work retained"
                )

    def _shutdown_drain(self):
        """Finite caller wait, transport only; a late ACK never settles local rows.

        Network/DNS can block inside an OS call. The request-only daemon owns no
        SQLite handle and cannot mutate queue state. The main thread applies an
        ACK only before the monotonic deadline; timeout retains the durable tail
        for idempotent retransmission after restart.
        """
        requested = self.config.get("shutdown_drain_seconds", 15)
        budget = (
            min(30.0, max(15.0, float(requested)))
            if type(requested) in (int, float) and math.isfinite(requested)
            else 15.0
        )
        deadline = time.monotonic() + budget
        state = self._shutdown_state
        state.update(
            drain_budget_seconds=budget,
            drain_state="draining",
            transport_worker_still_running=False,
            late_ack_ignored=False,
        )
        while self.queue.size():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                state["drain_state"] = "deadline_reached"
                break
            size = max(10, min(200, int(self.config.get("send_batch_size", 50))))
            rows = self.queue.peek(limit=size)
            result = {}

            def send(batch=rows, receipt=result):
                try:
                    receipt["response"] = self._post(
                        "/api/agent/ingest", {"events": [row[1] for row in batch]}
                    )
                except Exception as error:  # noqa: BLE001 -- Keep all failure receipts durable; never evaluate policy while stopping.
                    receipt["error"] = error

            worker = threading.Thread(
                target=send, name="endpoint-shutdown-transport", daemon=True
            )
            worker.start()
            worker.join(timeout=remaining)
            if worker.is_alive() or time.monotonic() >= deadline:
                state.update(
                    drain_state="deadline_reached",
                    transport_worker_still_running=worker.is_alive(),
                    late_ack_ignored=True,
                )
                break
            try:
                if "error" in result:
                    raise result["error"]
                self._settle_delivery(rows, result["response"])
            except Exception as error:  # noqa: BLE001 -- ACK validation/network failure must leave pending rows unchanged.
                state.update(drain_state="failed", error_type=type(error).__name__)
                break
        else:
            state["drain_state"] = "completed"
        state.update(
            pending_after_drain=self.queue.size(),
            local_evaluation_pending_after_drain=self.queue.evaluation_size(),
            durable_tail_retained=bool(
                self.queue.size() or self.queue.evaluation_size()
            ),
        )

    def _flush_cycle(self):
        for _ in range(30 if self.queue.size() > 5000 else 10):
            if not self.flush() or self.stop.is_set():
                break

    def _collect_cycle(self, *, queue=None):
        queue = self.queue if queue is None else queue
        if hasattr(self.collector, "begin_cycle"):
            self.collector.begin_cycle()
        memory = getattr(self, "memory_observability", None)
        if memory:
            memory.begin_cycle()
        try:
            events = self.collector.collect(self.identity["host"])
            if hasattr(self.collector, "provider_health"):
                self._provider_health = self.collector.provider_health()
            if self.kernel_prevention:
                events = [*events, *self.kernel_prevention.drain_events()]
            if memory:
                rows = list(getattr(self.collector, "last_rows", {}).values())
                events = [*events, *memory.collect(self.identity["host"], rows)]
            queue.add_many(
                events,
                evaluate=bool(
                    self.defense
                    and self.config.get("defense", {}).get("enabled") is True
                ),
            )
            if hasattr(self.collector, "checkpoint"):
                self.collector.checkpoint()
        except Exception:
            if memory:
                memory.rollback()
            if hasattr(self.collector, "rollback"):
                self.collector.rollback()
            raise

    def _evaluation_cycle(self, *, queue=None, defense=None):
        queue = self.queue if queue is None else queue
        defense = self.defense if defense is None else defense
        if not defense:
            return
        deadline = time.monotonic() + 2
        for _ in range(200):
            job = queue.evaluation_peek()
            if not job or time.monotonic() >= deadline:
                break
            key, event, cursor, digest = job
            result = defense.evaluate_resumable(
                event, cursor=cursor, policy_digest=digest
            )
            queue.evaluation_settle(
                key,
                result["events"],
                cursor=result["cursor"],
                policy_digest=result["policy_digest"],
                complete=result["complete"],
            )
            if not result["complete"]:
                break

    def _worker_queue(self):
        return Queue(
            self.directory / "pending.sqlite3",
            self.queue.max_pending,
            self.queue.capture_reserve,
        )

    def _data_failure(self, name, error):
        self._data_worker_fatal = type(error).__name__
        with self._error_lock:
            self.errors[name] = self._data_worker_fatal
        self.stop.set()

    def _capture_loop(self):
        queue = None
        try:
            queue = self._worker_queue()
            interval = max(1.0, float(self.config.get("collect_interval_seconds", 10)))
            while not self.stop.is_set():
                self._attempt("collection", lambda: self._collect_cycle(queue=queue))
                self.stop.wait(interval)
        except Exception as error:  # noqa: BLE001 -- unexpected worker failure is fatal and observable.
            self._data_failure("capture_worker", error)
        finally:
            if queue:
                queue.close()

    def _evaluation_loop(self):
        queue, defense = None, None
        try:
            queue = self._worker_queue()
            previous = self.defense
            if previous:
                defense = type(previous)(
                    previous.config, previous.response, clock=previous.clock
                )
                self.defense = defense
            while not self.stop.is_set():
                self._attempt(
                    "local_evaluation",
                    lambda: self._evaluation_cycle(queue=queue, defense=defense),
                )
                self.stop.wait(0.1)
        except Exception as error:  # noqa: BLE001 -- never hide a thread/SQLite ownership failure.
            self._data_failure("evaluation_worker", error)
        finally:
            if defense:
                defense.close()
                defense.db = None
            if queue:
                queue.close()


def enroll(config, token: str):
    candidate = Path(config["state_dir"]).expanduser().absolute()
    existing = candidate
    while not existing.exists():
        existing = existing.parent
    response._no_links(existing)
    candidate.mkdir(parents=True, exist_ok=True)
    response._no_links(candidate)
    directory = candidate.resolve()
    if os.name != "nt":
        os.chmod(directory, 0o700)
    with response.Lock(directory):
        return _enroll_locked(config, token)


def _enroll_locked(config, token: str):
    directory = Path(config["state_dir"]).expanduser().resolve()
    path = directory / "identity.json"
    if path.exists():
        raise RuntimeError("Agent already enrolled; existing identity preserved")
    recovery = directory / "enrollment-recovery.json"
    token_digest = hashlib.sha256(token.encode("ascii")).hexdigest()
    if recovery.exists():
        saved = json.loads(recovery.read_text(encoding="utf-8"))
        if (
            saved.get("token_digest") != token_digest
            or saved.get("tenant") != config["tenant"]
            or saved.get("host") != config["host"]
        ):
            raise RuntimeError(
                "Pending enrollment differs; explicit operator recovery required"
            )
        recovery_key = saved["recovery_key"]
    else:
        recovery_key = secrets.token_urlsafe(32)
        atomic_json(
            recovery,
            {
                "token_digest": token_digest,
                "recovery_key": recovery_key,
                "tenant": config["tenant"],
                "host": config["host"],
            },
        )
    registered = Transport(config["endpoint_url"], config["ca_file"]).post(
        "/api/agent/register",
        {"enrollment_token": token, "version": VERSION, "recovery_key": recovery_key},
    )
    if (
        registered.get("tenant") != config["tenant"]
        or registered.get("host") != config["host"]
        or (config.get("index") and registered.get("index") != config["index"])
    ):
        raise RuntimeError("Server enrollment identity does not match configuration")
    atomic_json(
        path,
        {
            **{
                key: registered[key]
                for key in (
                    "agent_id",
                    "credential",
                    "tenant",
                    "host",
                    "index",
                    "expires_at",
                )
            },
            "defense_public_key": registered.get("defense_public_key"),
        },
    )
    recovery.unlink(missing_ok=True)
    return {key: registered[key] for key in ("agent_id", "tenant", "host")}


def event(data: dict):
    return {"id": "agt-" + uuid.uuid4().hex, "data": data}
