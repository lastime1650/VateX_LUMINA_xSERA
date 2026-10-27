"""Optional bounded Syslog listeners; listeners are never enabled implicitly.

TCP/TLS support RFC6587 octet counting and newline-delimited messages. TCP
readers stop reading while their bounded admission queue is full. UDP cannot
signal backpressure: rejected datagrams have explicit counters. A received
frame is durable only after Store.ingest commits; transport receipt is no ACK.
"""

import errno
import hashlib
import queue
import re
import socket
import ssl
import threading
import time
import uuid
from dataclasses import dataclass
from types import MappingProxyType

from .connectors import parse_line
from .storage import CapacityError, normalize


@dataclass(frozen=True)
class SyslogSettings:
    host: str = "127.0.0.1"
    port: int = 5514
    transport: str = "udp"
    tenant: str = "default"
    source: str = "syslog"
    format: str = "auto"
    queue_size: int = 1000
    max_line_bytes: int = 65536
    max_connections: int = 32
    ssl_context: ssl.SSLContext | None = None
    peer_bindings: dict | None = None

    def __post_init__(self):
        if (
            not isinstance(self.host, str)
            or not 1 <= len(self.host) <= 253
            or "\0" in self.host
        ):
            raise ValueError("Syslog host must be a nonempty address")
        if type(self.port) is not int or not 0 <= self.port <= 65535:
            raise ValueError("Syslog port must be 0..65535")
        if self.transport not in {"udp", "tcp", "tls"} or self.format not in {
            "auto",
            "syslog",
            "cef",
        }:
            raise ValueError("Invalid Syslog transport or format")
        if not isinstance(self.tenant, str) or not re.fullmatch(
            r"[A-Za-z0-9_-]{1,64}", self.tenant
        ):
            raise ValueError("Invalid Syslog tenant")
        if not isinstance(self.source, str) or not 1 <= len(self.source) <= 256:
            raise ValueError("Syslog source must be 1..256 characters")
        for value, low, high in (
            (self.queue_size, 1, 10000),
            (self.max_line_bytes, 256, 65536),
            (self.max_connections, 1, 128),
        ):
            if type(value) is not int or not low <= value <= high:
                raise ValueError("Invalid Syslog resource budget")
        if self.transport == "tls":
            if not isinstance(self.ssl_context, ssl.SSLContext):
                raise ValueError("TLS Syslog requires a configured server SSLContext")
        elif self.ssl_context is not None:
            raise ValueError("SSLContext is only valid for TLS Syslog")
        if self.peer_bindings is not None:
            if (self.transport != "tls" or self.ssl_context.verify_mode != ssl.CERT_REQUIRED or
                    not isinstance(self.peer_bindings, dict) or not 1 <= len(self.peer_bindings) <= 256):
                raise ValueError("Syslog peer bindings require mutual TLS and 1..256 certificate fingerprints")
            bindings = {}
            for fingerprint, binding in self.peer_bindings.items():
                if (not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint) or
                        not isinstance(binding, dict) or set(binding) != {"tenant", "index"} or
                        any(not isinstance(binding[k], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", binding[k]) for k in ("tenant", "index"))):
                    raise ValueError("Invalid Syslog certificate tenant/index binding")
                bindings[fingerprint] = MappingProxyType(dict(binding))
            object.__setattr__(self, "peer_bindings", MappingProxyType(bindings))


class FrameTooLarge(ValueError):
    pass


class _Framer:
    """Bounded framing independent of packet boundaries; no partial EOF events."""

    def __init__(self, limit):
        self.limit = limit
        self.buffer = bytearray()

    def feed(self, data):
        self.buffer.extend(data)
        while self.buffer:
            if 48 <= self.buffer[0] <= 57:
                separator = self.buffer.find(b" ")
                if separator < 0:
                    if len(self.buffer) > 6 or not self.buffer.isdigit():
                        raise ValueError("Invalid RFC6587 frame length")
                    break
                prefix = self.buffer[:separator]
                if not prefix.isdigit() or len(prefix) > 6:
                    raise ValueError("Invalid RFC6587 frame length")
                length = int(prefix)
                if length > self.limit:
                    raise FrameTooLarge("Syslog frame exceeds line budget")
                if length < 1:
                    raise ValueError("Empty RFC6587 frame")
                end = separator + 1 + length
                if len(self.buffer) < end:
                    break
                frame = bytes(self.buffer[separator + 1 : end])
                del self.buffer[:end]
                yield frame
            else:
                end = self.buffer.find(b"\n")
                if end < 0:
                    if len(self.buffer) > self.limit:
                        raise FrameTooLarge("Syslog line exceeds line budget")
                    break
                if end > self.limit:
                    raise FrameTooLarge("Syslog line exceeds line budget")
                frame = bytes(self.buffer[:end]).removesuffix(b"\r")
                del self.buffer[: end + 1]
                yield frame


class SyslogReceiver:
    def __init__(self, store, settings):
        self.store = store
        self.settings = (
            SyslogSettings(**settings) if isinstance(settings, dict) else settings
        )
        if not isinstance(self.settings, SyslogSettings):
            raise TypeError("SyslogSettings or a settings dictionary required")
        self.address = None
        self._queue = queue.Queue(self.settings.queue_size)
        self._stop = threading.Event()
        self._lock = threading.RLock()
        self._socket = None
        self._listener = None
        self._worker = None
        self._clients = set()
        self._client_threads = set()
        self._started = False
        self._inflight = 0
        self._shutdown_deadline = None
        self._drain_failed = False
        self._last_error = None
        self._counts = dict.fromkeys(
            [
                "received",
                "admitted",
                "duplicate",
                "dropped_queue",
                "dropped_invalid",
                "dropped_oversized",
                "dropped_shutdown",
                "capacity_retries",
                "ingest_errors",
                "transport_errors",
                "connections_rejected",
            ],
            0,
        )

    def _count(self, name, amount=1):
        with self._lock:
            self._counts[name] += amount

    def start(self):
        with self._lock:
            if self._started or self._stop.is_set():
                raise RuntimeError("SyslogReceiver cannot be started twice")
            family = socket.AF_INET6 if ":" in self.settings.host else socket.AF_INET
            kind = (
                socket.SOCK_DGRAM
                if self.settings.transport == "udp"
                else socket.SOCK_STREAM
            )
            listener = socket.socket(family, kind)
            try:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((self.settings.host, self.settings.port))
                if kind == socket.SOCK_STREAM:
                    listener.listen(self.settings.max_connections)
                listener.settimeout(0.2)
            except Exception:
                listener.close()
                raise
            self._socket = listener
            self.address = listener.getsockname()
            self._worker = threading.Thread(
                target=self._admit, name="sapientia-syslog-admit", daemon=True
            )
            self._listener = threading.Thread(
                target=self._udp if kind == socket.SOCK_DGRAM else self._accept,
                name="sapientia-syslog-listen",
                daemon=True,
            )
            self._started = True
            self._worker.start()
            self._listener.start()
        return self

    def health(self):
        with self._lock:
            return {
                "enabled": self._started,
                "listening": bool(
                    self._listener
                    and self._listener.is_alive()
                    and not self._stop.is_set()
                ),
                "admission_running": bool(self._worker and self._worker.is_alive()),
                "transport": self.settings.transport,
                "address": list(self.address) if self.address else None,
                "tenant": self.settings.tenant,
                "mutual_tls": bool(self.settings.ssl_context and self.settings.ssl_context.verify_mode == ssl.CERT_REQUIRED),
                "certificate_bindings": len(self.settings.peer_bindings or {}),
                "queued": self._queue.qsize(),
                "inflight": self._inflight,
                "connections": len(self._clients),
                "last_error": self._last_error,
                **self._counts,
            }

    def _enqueue(self, frame, peer, block, binding=None):
        self._count("received")
        if len(frame) > self.settings.max_line_bytes:
            self._count("dropped_oversized")
            return
        try:
            text = frame.decode("utf-8").rstrip("\r\n")
            kind = self.settings.format
            if kind == "auto":
                kind = "cef" if text.startswith("CEF:") else "syslog"
            event = parse_line(text, kind, self.settings.source, str(uuid.uuid4()))
            event.setdefault("host", peer[0])
            event["raw"]["collector_peer"] = peer[0]
            event["raw"]["collector_transport"] = self.settings.transport
            event = normalize(event)
            if binding:
                event["index"] = binding["index"]
                event["raw"]["collector_client_fingerprint"] = binding["fingerprint"]
                event["_syslog_scope"] = dict(binding)
        except (ValueError, UnicodeError, TypeError, OverflowError):
            self._count("dropped_invalid")
            return
        while True:
            with self._lock:
                if self._stop.is_set():
                    break
                try:
                    self._queue.put_nowait(event)
                    return
                except queue.Full:
                    if not block:
                        self._count("dropped_queue")
                        return
            self._stop.wait(0.1)
        self._count("dropped_shutdown")

    def _udp(self):
        while not self._stop.is_set():
            try:
                data, peer = self._socket.recvfrom(self.settings.max_line_bytes + 1)
                self._enqueue(data, peer, False)
            except TimeoutError:
                continue
            except OSError as exc:
                if exc.errno in {errno.EMSGSIZE, 10040}:
                    # Windows recvfrom reports truncation as WSAEMSGSIZE.
                    self._count("received")
                    self._count("dropped_oversized")
                    continue
                if not self._stop.is_set():
                    self._count("transport_errors")
                return

    def _accept(self):
        while not self._stop.is_set():
            try:
                client, peer = self._socket.accept()
            except TimeoutError:
                continue
            except OSError:
                if not self._stop.is_set():
                    self._count("transport_errors")
                return
            with self._lock:
                if (
                    self._stop.is_set()
                    or len(self._clients) >= self.settings.max_connections
                ):
                    self._count("connections_rejected")
                    client.close()
                    continue
                self._clients.add(client)
                thread = threading.Thread(
                    target=self._read_client,
                    args=(client, peer),
                    name="sapientia-syslog-client",
                    daemon=True,
                )
                self._client_threads.add(thread)
                thread.start()

    def _read_client(self, client, peer):
        framer = _Framer(self.settings.max_line_bytes)
        original = client
        binding = None
        try:
            if self.settings.transport == "tls":
                wrapped = self.settings.ssl_context.wrap_socket(
                    client, server_side=True, do_handshake_on_connect=False
                )
                with self._lock:
                    self._clients.discard(client)
                    self._clients.add(wrapped)
                client = wrapped
                client.settimeout(1)
                client.do_handshake()
                if self.settings.peer_bindings is not None:
                    certificate = client.getpeercert(binary_form=True)
                    fingerprint = hashlib.sha256(certificate or b"").hexdigest()
                    selected = self.settings.peer_bindings.get(fingerprint)
                    if not selected:
                        raise ssl.SSLError("Client certificate has no configured telemetry binding")
                    binding = {**selected, "fingerprint": fingerprint}
            client.settimeout(0.2)
            while not self._stop.is_set():
                try:
                    data = client.recv(4096)
                except TimeoutError:
                    continue
                if not data:
                    if framer.buffer:
                        self._count("dropped_invalid")
                    return
                for frame in framer.feed(data):
                    self._enqueue(frame, peer, True, binding)
        except FrameTooLarge:
            self._count("dropped_oversized")
        except ValueError:
            self._count("dropped_invalid")
        except (OSError, ssl.SSLError):
            if not self._stop.is_set():
                self._count("transport_errors")
        finally:
            client.close()
            original.close()
            with self._lock:
                self._clients.discard(client)
                self._clients.discard(original)
                self._client_threads.discard(threading.current_thread())

    def _admit(self):
        while not self._stop.is_set() or not self._queue.empty():
            try:
                first = self._queue.get(timeout=0.1)
            except queue.Empty:
                continue
            batch = [first]
            while len(batch) < 32 and self.settings.peer_bindings is None:
                try:
                    batch.append(self._queue.get_nowait())
                except queue.Empty:
                    break
            with self._lock:
                self._inflight = len(batch)
            binding = batch[0].pop("_syslog_scope", None)
            while True:
                try:
                    scoped = {"allowed_indexes": [binding["index"]]} if binding else {}
                    ack = self.store.ingest(
                        binding["tenant"] if binding else self.settings.tenant,
                        batch,
                        actor="syslog:" + self.settings.transport,
                        **scoped,
                    )
                    self._count("admitted", ack["accepted"])
                    self._count("duplicate", ack["duplicate"])
                    with self._lock:
                        self._last_error = None
                    break
                except Exception as exc:  # noqa: BLE001 - retain frames across storage failures.
                    self._count(
                        "capacity_retries"
                        if isinstance(exc, CapacityError)
                        else "ingest_errors"
                    )
                    with self._lock:
                        self._last_error = type(exc).__name__
                    if isinstance(exc, (PermissionError, ValueError)):
                        # A permanently invalid frame must not poison the
                        # bounded queue or be retried as a capacity failure.
                        self._count("dropped_invalid", len(batch))
                        break
                    if (
                        self._stop.is_set()
                        and time.monotonic() >= self._shutdown_deadline
                    ):
                        self._count("dropped_shutdown", len(batch))
                        self._drain_failed = True
                        break
                    time.sleep(0.1)
            for _ in batch:
                self._queue.task_done()
            with self._lock:
                self._inflight = 0
            if self._drain_failed:
                while True:
                    try:
                        self._queue.get_nowait()
                        self._queue.task_done()
                        self._count("dropped_shutdown")
                    except queue.Empty:
                        return

    def close(self, timeout=5):
        if (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or not 0 < timeout <= 60
        ):
            raise ValueError("Syslog close timeout must be in 0..60 seconds")
        with self._lock:
            self._shutdown_deadline = time.monotonic() + timeout
            self._stop.set()
            sockets = ([self._socket] if self._socket else []) + list(self._clients)
        for item in sockets:
            try:
                item.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            item.close()
        if self._listener:
            self._listener.join(max(0, self._shutdown_deadline - time.monotonic()))
        with self._lock:
            threads = list(self._client_threads)
        for thread in threads:
            thread.join(max(0, self._shutdown_deadline - time.monotonic()))
        if self._worker:
            self._worker.join(max(0, self._shutdown_deadline - time.monotonic()) + 0.2)
        if (
            self._drain_failed
            or self._queue.unfinished_tasks
            or any(
                thread and thread.is_alive()
                for thread in [self._listener, self._worker, *threads]
            )
        ):
            raise RuntimeError(
                "Syslog shutdown could not durably admit every queued event; Store must remain open"
            )
