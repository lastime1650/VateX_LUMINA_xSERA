"""Explicitly scoped Linux kernel permission decisions, separate from reactive EDR.

FAN_OPEN_EXEC_PERM holds an executable open in the kernel until this listener
responds.  A SHA256 match is denied before exec, never killed after exec.  Marks
cover only immediate children of ordinary, explicitly configured directories.
The kernel releases outstanding requests on listener death: this component does
not claim crash-proof enforcement, interpreter input protection or an LSM.
"""
# ruff: noqa: BLE001 -- Permission workers must deny on every adapter/verifier failure and release kernel requests on listener failure.
# ruff: noqa: UP017 -- Distributed agent supports Python 3.10 without datetime.UTC.

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import platform
import queue
import re
import select
import stat
import struct
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from . import defense

FAN_OPEN_EXEC_PERM = 0x00040000
FAN_Q_OVERFLOW = 0x00004000
FAN_ALLOW, FAN_DENY = 1, 2
METADATA = struct.Struct("=IBBHQii")
RESPONSE = struct.Struct("=iI")
MAX_PENDING, WORKERS, MAX_AUDIT = 32, 4, 1024
MAX_DIRECTORIES, MAX_RULES = 32, 256
MAX_FILE = 64 * 1024 * 1024
FORBIDDEN_DIRECTORIES = {
    "/",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/usr",
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/run",
}


def parse_metadata(blob):
    """Reject malformed ABI records without stepping outside the bounded read."""
    position, events = 0, []
    while position < len(blob):
        if len(blob) - position < METADATA.size:
            raise ValueError("Truncated fanotify metadata")
        length, version, _reserved, metadata_length, mask, fd, pid = (
            METADATA.unpack_from(blob, position)
        )
        if (
            version != 3
            or not METADATA.size <= metadata_length <= length <= len(blob) - position
        ):
            raise ValueError("Unsupported or malformed fanotify metadata")
        events.append((mask, fd, pid))
        position += length
    return events


def validate_settings(settings):
    if not isinstance(settings, dict) or set(settings) - {
        "enabled",
        "directories",
        "rule_ids",
        "decision_timeout_ms",
        "max_file_bytes",
        "windows_mode",
        "windows_lease_seconds",
        "guarded_workload_mode",
        "guarded_workload_confirmed",
        "guarded_workload_lease_seconds",
    }:
        raise ValueError("Invalid kernel prevention settings")
    if settings.get("enabled") is not True:
        raise ValueError("Kernel prevention requires explicit local opt-in")
    guarded_mode = settings.get("guarded_workload_mode", "off")
    if guarded_mode not in {"off", "audit", "enforce"}:
        raise ValueError("Guarded workload mode must be off, audit or enforce")
    if guarded_mode != "off" and settings.get("guarded_workload_confirmed") is not True:
        raise PermissionError("Separate local guarded-workload confirmation required")
    lease = settings.get("guarded_workload_lease_seconds", 60)
    if type(lease) is not int or not 30 <= lease <= 300:
        raise ValueError("Guarded workload lease must be 30..300 seconds")
    directories, rule_ids = settings.get("directories"), settings.get("rule_ids")
    if (
        not isinstance(directories, list)
        or not 1 <= len(directories) <= MAX_DIRECTORIES
        or not all(isinstance(v, str) for v in directories)
        or len(set(directories)) != len(directories)
    ):
        raise ValueError("1..32 unique ordinary watched directories required")
    for name in directories:
        if (
            not isinstance(name, str)
            or not name
            or len(name) > 512
            or any(ord(c) < 32 for c in name)
        ):
            raise ValueError("Bounded absolute watched directory required")
        path = PurePosixPath(name)
        if (
            not path.is_absolute()
            or ".." in path.parts
            or str(path) != name
            or name in FORBIDDEN_DIRECTORIES
            or name.startswith(
                (
                    "/bin/",
                    "/sbin/",
                    "/lib/",
                    "/lib64/",
                    "/usr/",
                    "/proc/",
                    "/sys/",
                    "/dev/",
                    "/boot/",
                    "/etc/",
                    "/run/",
                )
            )
        ):
            raise ValueError(
                "System, relative and noncanonical directories cannot be watched"
            )
    if (
        not isinstance(rule_ids, list)
        or not 1 <= len(rule_ids) <= MAX_RULES
        or not all(
            isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9._-]{1,120}", v)
            for v in rule_ids
        )
        or len(set(rule_ids)) != len(rule_ids)
    ):
        raise ValueError("1..256 unique explicitly selected signed rule IDs required")
    timeout, maximum = (
        settings.get("decision_timeout_ms", 500),
        settings.get("max_file_bytes", MAX_FILE),
    )
    if type(timeout) is not int or not 50 <= timeout <= 2000:
        raise ValueError("Decision timeout must be 50..2000 ms")
    if type(maximum) is not int or not 1 <= maximum <= MAX_FILE:
        raise ValueError("Executable size bound must be 1..64 MiB")
    if (
        settings.get("windows_mode", "audit") not in {"audit", "enforce"}
        or type(settings.get("windows_lease_seconds", 60)) is not int
        or not 30 <= settings.get("windows_lease_seconds", 60) <= 300
    ):
        raise ValueError("Shared Windows mode/lease settings are invalid")
    return tuple(directories), frozenset(rule_ids), timeout / 1000, maximum


def project_rules(document, directories, rule_ids):
    """No behavioral rule is silently promoted into a pre-execution block."""
    selected, projected = set(), {}
    for rule in document["rules"]:
        if rule["id"] not in rule_ids:
            continue
        selected.add(rule["id"])
        if (
            rule.get("enabled") is not True
            or rule.get("action") != "terminate_process"
            or rule.get("exceptions")
        ):
            raise ValueError(
                "Selected kernel rule must be enabled, terminate_process and have no exceptions"
            )
        conditions = rule["conditions"]
        if (
            len(conditions) != 2
            or {c["field"] for c in conditions}
            != {"file.hash.sha256", "process.executable"}
            or any(
                c["op"] != "eq" or c.get("ignore_case", True) is not False
                for c in conditions
            )
        ):
            raise ValueError(
                "Kernel rule requires only exact case-sensitive executable path and SHA256"
            )
        values = {c["field"]: c["value"] for c in conditions}
        filename, digest = values["process.executable"], values["file.hash.sha256"]
        if (
            not isinstance(filename, str)
            or len(filename) > 512
            or any(ord(c) < 32 for c in filename)
        ):
            raise ValueError("Kernel executable must be a bounded path")
        path = PurePosixPath(filename)
        if (
            not path.is_absolute()
            or str(path) != filename
            or ".." in path.parts
            or str(path.parent) not in directories
        ):
            raise ValueError(
                "Kernel executable must be an immediate child of a watched directory"
            )
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("Kernel SHA256 must be lowercase hexadecimal")
        projected.setdefault(filename, {})[digest] = {
            "id": rule["id"],
            "severity": rule.get("severity", "high"),
            "mitre": tuple(rule.get("mitre", [])),
        }
    if selected != rule_ids:
        raise ValueError(
            "Every explicitly selected kernel rule must exist in the signed policy"
        )
    return projected


def project_allow_rules(document, directories, rule_ids):
    """An approved execution rule is distinct from a known malicious deny rule."""
    for rule in document["rules"]:
        if rule["id"] in rule_ids and rule.get("action") != "allow_execution":
            raise ValueError(
                "Guarded workload requires explicitly signed allow_execution rules"
            )
    adapted = dict(
        document,
        rules=[
            dict(rule, action="terminate_process") if rule["id"] in rule_ids else rule
            for rule in document["rules"]
        ],
    )
    return project_rules(adapted, directories, rule_ids)


def execution_decision(snapshot, filename, digest, guarded_mode="off"):
    rule = snapshot["rules"].get(filename, {}).get(digest)
    if guarded_mode != "off":
        return (
            rule is not None,
            "signed_allowlist_approved" if rule else "signed_allowlist_unapproved",
            rule,
        )
    return rule is None, "signed_hash_match" if rule else "no_signed_hash_match", rule


class SignedProjection:
    """Independent signed verification and durable anti-rollback for this worker."""

    def __init__(
        self,
        config,
        directories,
        rule_ids,
        response_module,
        clock=time.time,
        projector=project_rules,
    ):
        self.config, self.directories, self.rule_ids = config, directories, rule_ids
        self.response, self.clock = response_module, clock
        self.projector = projector
        self.last_revision, self.last_digest = None, None

    def load(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        settings = self.config.get("defense", {})
        key, filename = settings.get("public_key"), settings.get("bundle_file")
        if (
            not isinstance(key, str)
            or not re.fullmatch(r"[0-9a-f]{64}", key)
            or not isinstance(filename, str)
            or not Path(filename).is_absolute()
        ):
            raise ValueError("Pinned signing key and absolute defense bundle required")
        path = Path(filename)
        self.response._no_links(path)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags)
        try:
            before = os.fstat(fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_size > defense.MAX_BUNDLE
                or before.st_nlink != 1
            ):
                raise ValueError(
                    "Signed kernel policy must be a bounded, single-link ordinary file"
                )
            if os.name != "nt" and (
                before.st_uid != os.geteuid() or before.st_mode & 0o022
            ):
                raise PermissionError(
                    "Signed kernel policy must be service-owned and not externally writable"
                )
            blob = bytearray()
            while len(blob) <= defense.MAX_BUNDLE:
                piece = os.read(fd, min(65536, defense.MAX_BUNDLE + 1 - len(blob)))
                if not piece:
                    break
                blob.extend(piece)
            after = os.fstat(fd)
            if len(blob) > defense.MAX_BUNDLE or defense._file_stamp(
                before
            ) != defense._file_stamp(after):
                raise ValueError("Signed policy changed or exceeded size bound")
        finally:
            os.close(fd)
        bundle = json.loads(
            bytes(blob).decode("utf-8"), object_pairs_hook=defense._pairs
        )
        if (
            not isinstance(bundle, dict)
            or set(bundle) != {"document", "signature"}
            or not isinstance(bundle["signature"], str)
            or not re.fullmatch(r"[0-9a-f]{128}", bundle["signature"])
        ):
            raise ValueError("Invalid signed kernel policy bundle")
        body = defense.canonical(bundle["document"])
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
            bytes.fromhex(bundle["signature"]), body
        )
        document = defense.validate(bundle["document"], self.config, self.clock())
        rules = self.projector(document, self.directories, self.rule_ids)
        digest = hashlib.sha256(body).hexdigest()
        defense._cache_policy_revision(self.config, key, document["revision"], digest)
        self.last_revision, self.last_digest = document["revision"], digest
        return {
            "rules": rules,
            "revision": document["revision"],
            "digest": digest,
            "expires_at": document["expires_at"],
        }


class FanotifyBackend:
    """Real libc entry points: no simulated native support or shell commands."""

    native = True

    def __init__(self):
        if platform.system() != "Linux":
            raise OSError(
                "Kernel execution guard requires Linux; Windows requires separate OS application control"
            )
        release = platform.release().split(".")
        try:
            version = tuple(int(v.split("-")[0]) for v in release[:2])
        except ValueError:
            raise OSError("Cannot determine Linux kernel version") from None
        if version < (5, 0):
            raise OSError("FAN_OPEN_EXEC_PERM requires Linux 5.0 or newer")
        library = ctypes.CDLL(None, use_errno=True)
        try:
            self.init, self.mark = library.fanotify_init, library.fanotify_mark
        except AttributeError:
            raise OSError("The system libc does not expose fanotify") from None
        self.init.argtypes, self.init.restype = (
            [ctypes.c_uint, ctypes.c_uint],
            ctypes.c_int,
        )
        self.mark.argtypes, self.mark.restype = (
            [
                ctypes.c_int,
                ctypes.c_uint,
                ctypes.c_uint64,
                ctypes.c_int,
                ctypes.c_char_p,
            ],
            ctypes.c_int,
        )
        self.fd = -1

    def open(self, directories, response_module):
        # CONTENT class, CLOEXEC, NONBLOCK. Never enable unlimited queue/marks.
        self.fd = self.init(
            0x1 | 0x2 | 0x4, os.O_RDONLY | getattr(os, "O_LARGEFILE", 0) | os.O_CLOEXEC
        )
        if self.fd < 0:
            error = ctypes.get_errno()
            raise OSError(
                error,
                "fanotify_init failed; CAP_SYS_ADMIN and configured fanotify permission support are required",
            )
        try:
            for directory in directories:
                path = Path(directory)
                response_module._no_links(path)
                info = path.stat()
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or info.st_mode & 0o022
                ):
                    raise PermissionError(
                        "Watched directory must be service-owned and not externally writable"
                    )
                if (
                    self.mark(
                        self.fd,
                        0x1 | 0x4 | 0x8,
                        FAN_OPEN_EXEC_PERM | 0x08000000,
                        -100,
                        os.fsencode(directory),
                    )
                    < 0
                ):
                    error = ctypes.get_errno()
                    raise OSError(
                        error,
                        "fanotify permission directory mark failed; CONFIG_FANOTIFY_ACCESS_PERMISSIONS is required",
                    )
        except BaseException:
            self.close()
            raise

    def read(self, timeout):
        if self.fd < 0:
            return []
        ready, _, _ = select.select([self.fd], [], [], timeout)
        if not ready:
            return []
        try:
            return parse_metadata(os.read(self.fd, METADATA.size * 128))
        except BlockingIOError:
            return []

    def respond(self, fd, allow):
        blob = RESPONSE.pack(fd, FAN_ALLOW if allow else FAN_DENY)
        if os.write(self.fd, blob) != len(blob):
            raise OSError("Incomplete fanotify permission response")

    def close(self):
        fd, self.fd = self.fd, -1
        if fd >= 0:
            os.close(fd)


def hash_open_executable(fd, maximum, deadline, monotonic=time.monotonic):
    """Hash the kernel-supplied open inode, never reopen an attacker-named path."""
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise PermissionError(
            "Executable is not an ordinary file within the size bound"
        )
    filename = os.readlink(f"/proc/self/fd/{fd}")
    if (
        not filename.startswith("/")
        or filename.endswith(" (deleted)")
        or len(filename) > 512
    ):
        raise PermissionError("Executable path identity is unavailable")
    digest, offset = hashlib.sha256(), 0
    while True:
        if monotonic() >= deadline:
            raise TimeoutError("Executable hashing deadline exceeded")
        piece = os.pread(fd, min(65536, maximum + 1 - offset), offset)
        if not piece:
            break
        offset += len(piece)
        if offset > maximum:
            raise PermissionError("Executable grew beyond the size bound")
        digest.update(piece)
    after = os.fstat(fd)
    if (
        defense._file_stamp(before) != defense._file_stamp(after)
        or offset != before.st_size
        or os.readlink(f"/proc/self/fd/{fd}") != filename
    ):
        raise PermissionError(
            "Executable inode/path changed during permission decision"
        )
    named = os.stat(filename, follow_symlinks=False)
    if (named.st_dev, named.st_ino) != (after.st_dev, after.st_ino) or not stat.S_ISREG(
        named.st_mode
    ):
        raise PermissionError(
            "Executable pathname no longer identifies the opened inode"
        )
    return filename, digest.hexdigest(), (after.st_dev, after.st_ino)


def process_identity(pid, host):
    """Identity of the process attempting exec, not a claim the image ran."""
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        start = text[text.rfind(")") + 2 :].split()[19]
        boot = (
            Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        )
        if not start.isdigit() or not re.fullmatch(r"[0-9a-f-]{36}", boot):
            raise ValueError("Invalid native process identity")
        executable = os.readlink(f"/proc/{pid}/exe")
        return {
            "pid": pid,
            "guid": str(
                uuid.uuid5(uuid.NAMESPACE_OID, host + ":" + f"{boot}:{pid}:{start}")
            ),
            "start_identity": f"linux:{boot}:{start}",
            "executable": executable[:512],
        }
    except (OSError, ValueError, IndexError):
        return None


class KernelPrevention:
    """One permission loop, four bounded hash workers and an independent verifier.

    Slow storage cannot hold the permission loop: hashing uses duplicate FDs in
    daemon workers, and the loop responds DENY at the local deadline. At most
    four stuck reads can exist; the bounded queue then rejects new requests.
    Queue overflow is explicitly degraded coverage, never silently 'protected'.
    """

    def __init__(
        self,
        config,
        response_module,
        *,
        backend_factory=FanotifyBackend,
        clock=time.time,
        monotonic=time.monotonic,
    ):
        self.config, self.response = config, response_module
        self.backend_factory, self.clock, self.monotonic = (
            backend_factory,
            clock,
            monotonic,
        )
        self.settings = config.get("kernel_prevention", {})
        self.guarded_mode = self.settings.get("guarded_workload_mode", "off")
        self.guarded_deadline = None
        self.guarded_counts = {"approved": 0, "unapproved": 0}
        self._guarded_audit_dirty = False
        self.enabled = (
            isinstance(self.settings, dict) and self.settings.get("enabled") is True
        )
        self.backend, self.projection, self.snapshot = None, None, None
        self.error, self.running = None, False
        self.stop_event, self.lock = threading.Event(), threading.Lock()
        self.jobs, self.results, self.audit = (
            queue.Queue(MAX_PENDING),
            queue.Queue(MAX_PENDING),
            queue.Queue(MAX_AUDIT),
        )
        self.pending, self.threads = {}, []
        self.counters = {
            "allowed": 0,
            "denied": 0,
            "deadline_denied": 0,
            "overload_denied": 0,
            "queue_overflow": 0,
            "audit_dropped": 0,
        }

    def start(self):
        if not self.enabled:
            return False
        if self.running:
            return True
        if self.stop_event.is_set():
            raise RuntimeError("A closed kernel guard cannot be restarted")
        try:
            self.directories, self.rule_ids, self.timeout, self.maximum = (
                validate_settings(self.settings)
            )
            # Require the real platform before touching the policy state.
            self.backend = self.backend_factory()
            self.projection = SignedProjection(
                self.config,
                self.directories,
                self.rule_ids,
                self.response,
                self.clock,
                projector=project_allow_rules
                if self.guarded_mode != "off"
                else project_rules,
            )
            self.snapshot = self.projection.load()
            if self.guarded_mode == "enforce":
                self._verify_guarded_audit()
            if self.guarded_mode != "off":
                self.guarded_deadline = self.monotonic() + self.settings.get(
                    "guarded_workload_lease_seconds", 60
                )
            self.backend.open(self.directories, self.response)
            self.running = True
            for number in range(WORKERS):
                self.threads.append(
                    threading.Thread(
                        target=self._hash_worker,
                        name=f"lumina-kernel-hash-{number}",
                        daemon=True,
                    )
                )
            self.threads.append(
                threading.Thread(
                    target=self._policy_worker, name="lumina-kernel-policy", daemon=True
                )
            )
            self.threads.append(
                threading.Thread(
                    target=self._loop, name="lumina-kernel-permissions", daemon=True
                )
            )
            for thread in self.threads:
                thread.start()
            return True
        except Exception as error:
            self.error = str(error)[:512]
            if self.backend:
                self.backend.close()
            self.running = False
            raise

    def _policy_worker(self):
        while not self.stop_event.wait(0.5):
            try:
                snapshot = self.projection.load()
                if self.guarded_mode == "enforce":
                    self._verify_guarded_audit(snapshot)
            except Exception as error:
                with self.lock:
                    self.snapshot = None
                    self.error = "Policy verification failed: " + str(error)[:384]
            else:
                with self.lock:
                    if self.guarded_mode == "audit" and (
                        not self.snapshot
                        or self.snapshot["digest"] != snapshot["digest"]
                    ):
                        self.guarded_counts = {"approved": 0, "unapproved": 0}
                    self.snapshot = snapshot
                    if self.error and self.error.startswith(
                        "Policy verification failed:"
                    ):
                        self.error = None
                if self.guarded_mode == "audit" and self._guarded_audit_dirty:
                    try:
                        self._save_guarded_audit()
                    except Exception as error:
                        self.error = (
                            "Guarded audit receipt unavailable: " + type(error).__name__
                        )

    def _hash_worker(self):
        while not self.stop_event.is_set():
            try:
                token, fd, deadline, snapshot = self.jobs.get(timeout=0.05)
            except queue.Empty:
                continue
            try:
                filename, digest, identity = hash_open_executable(
                    fd, self.maximum, deadline, self.monotonic
                )
                allow, reason, rule = execution_decision(
                    snapshot, filename, digest, self.guarded_mode
                )
                answer = (
                    token,
                    allow,
                    reason,
                    filename,
                    digest,
                    identity,
                    rule,
                )
            except Exception as error:
                answer = (
                    token,
                    False,
                    "identity_or_hash_error",
                    None,
                    None,
                    None,
                    {"error": str(error)[:256]},
                )
            finally:
                os.close(fd)
                self.jobs.task_done()
            try:
                self.results.put_nowait(answer)
            except queue.Full:
                # The permission loop already times out outstanding requests.
                pass

    def _record(
        self,
        pid,
        allow,
        reason,
        snapshot,
        filename=None,
        digest=None,
        identity=None,
        rule=None,
    ):
        initiator = process_identity(pid, self.config["host"])
        data = {
            "@timestamp": datetime.fromtimestamp(
                self.clock(), timezone.utc
            ).isoformat(),
            "host": {"id": self.config["host"], "os": {"type": "linux"}},
            "event": {
                "action": "execution_allowed" if allow else "execution_denied",
                "module": "kernel_prevention",
                "provider": "linux.fanotify",
                "outcome": "success",
            },
            "agent": {
                "collector": "linux-kernel-exec-permission",
                "process_identity_kind": "unavailable_for_kernel_permission_observation",
            },
            "kernel_prevention": {
                "phase": "before_executable_open",
                "decision": "allow" if allow else "deny",
                "reason": reason,
                "kernel_response_confirmed": True,
                "target_image_created": False,
                "revision": snapshot["revision"] if snapshot else None,
                "policy_sha256": snapshot["digest"] if snapshot else None,
                "rule_id": rule.get("id") if rule else None,
                "guarded_workload_mode": self.guarded_mode,
                "would_deny": reason.startswith("audit_")
                and reason != "audit_signed_allowlist_approved",
            },
        }
        if initiator:
            data["kernel_prevention"]["initiator"] = initiator
        if filename:
            data["file"] = {"path": filename}
            if digest:
                data["file"]["hash"] = {"sha256": digest}
        if identity:
            data["kernel_prevention"]["inode"] = {
                "device": identity[0],
                "number": identity[1],
            }
        if rule and rule.get("mitre"):
            data["kernel_prevention"]["mitre"] = list(rule["mitre"])
        try:
            self.audit.put_nowait(
                {"id": "kernel-permission-" + uuid.uuid4().hex, "data": data}
            )
        except queue.Full:
            self.counters["audit_dropped"] += 1

    def _finish(
        self, token, allow, reason, filename=None, digest=None, identity=None, rule=None
    ):
        value = self.pending.pop(token, None)
        if value is None:
            return
        fd, pid, _deadline, snapshot = value
        try:
            if self.guarded_mode == "audit":
                allow, reason = True, "audit_" + reason
            self.backend.respond(fd, allow)
            self.counters["allowed" if allow else "denied"] += 1
            if reason == "decision_deadline":
                self.counters["deadline_denied"] += 1
            if reason == "bounded_queue_full":
                self.counters["overload_denied"] += 1
            self._record(pid, allow, reason, snapshot, filename, digest, identity, rule)
            if self.guarded_mode == "audit" and reason in {
                "audit_signed_allowlist_approved",
                "audit_signed_allowlist_unapproved",
            }:
                category = "approved" if reason.endswith("_approved") else "unapproved"
                self.guarded_counts[category] += 1
                # The policy worker persists receipts. Storage/fsync must never
                # hold the permission response loop or its decision deadlines.
                self._guarded_audit_dirty = True
        finally:
            os.close(fd)

    def _admit(self, mask, fd, pid):
        if mask & FAN_Q_OVERFLOW:
            self.counters["queue_overflow"] += 1
            self.error = "Kernel event queue overflow: permission coverage was lost"
        if fd < 0:
            return
        if not mask & FAN_OPEN_EXEC_PERM or pid <= 0:
            os.close(fd)
            return
        token = uuid.uuid4().hex
        with self.lock:
            snapshot = self.snapshot
        self.pending[token] = (fd, pid, self.monotonic() + self.timeout, snapshot)
        if not snapshot or self.clock() >= snapshot["expires_at"]:
            self._finish(token, False, "policy_invalid_or_expired")
            return
        if len(self.pending) > MAX_PENDING:
            self._finish(token, False, "bounded_queue_full")
            return
        worker_fd = os.dup(fd)
        os.set_inheritable(worker_fd, False)
        try:
            self.jobs.put_nowait((token, worker_fd, self.pending[token][2], snapshot))
        except queue.Full:
            os.close(worker_fd)
            self._finish(token, False, "bounded_queue_full")

    def _tick(self):
        while True:
            try:
                answer = self.results.get_nowait()
            except queue.Empty:
                break
            token, allow, reason, filename, digest, identity, rule = answer
            value = self.pending.get(token)
            # No late result, revoked/replaced policy or elapsed deadline can ALLOW.
            with self.lock:
                current = self.snapshot
            if value:
                if self.monotonic() >= value[2]:
                    allow, reason = False, "decision_deadline"
                elif (
                    not current
                    or self.clock() >= current["expires_at"]
                    or current["digest"] != value[3]["digest"]
                ):
                    allow, reason = False, "policy_changed_during_decision"
                self._finish(token, allow, reason, filename, digest, identity, rule)
        now = self.monotonic()
        for token, value in list(self.pending.items()):
            if now >= value[2]:
                self._finish(token, False, "decision_deadline")

    def _loop(self):
        try:
            while not self.stop_event.is_set():
                if (
                    self.guarded_deadline is not None
                    and self.monotonic() >= self.guarded_deadline
                ):
                    self.error = "Guarded workload lease expired; owned permission marks released"
                    break
                self._tick()
                for event in self.backend.read(0.01):
                    self._admit(*event)
                    self._tick()
        except Exception as error:
            self.error = "Permission listener failed: " + str(error)[:384]
        finally:
            # Closing the kernel group ALLOWS outstanding events by Linux design.
            # Explicit stop/failure never leaves a process stuck behind our FD.
            self.stop_event.set()
            self.backend.close()
            for fd, _pid, _deadline, _snapshot in self.pending.values():
                os.close(fd)
            self.pending.clear()
            self.running = False

    def drain_events(self, limit=200):
        if type(limit) is not int or not 1 <= limit <= MAX_AUDIT:
            raise ValueError("Kernel audit drain limit must be 1..1024")
        records = []
        for _ in range(limit):
            try:
                records.append(self.audit.get_nowait())
            except queue.Empty:
                break
        return records

    def status(self):
        with self.lock:
            snapshot = self.snapshot
        expired = snapshot is not None and self.clock() >= snapshot["expires_at"]
        return {
            "enabled": self.enabled,
            "state": "degraded"
            if self.error or expired
            else "active"
            if self.running
            else "disabled"
            if not self.enabled
            else "stopped",
            "kernel_permission_denial": bool(
                self.running and self.backend and self.backend.native
            ),
            "reactive_user_mode": False,
            "support": "linux-fanotify-executable-open-permission",
            "scope": "immediate_children_of_explicit_directories",
            "crash_behavior": "kernel_allows_outstanding_requests_on_listener_death",
            "decision_timeout_behavior": "deny_while_listener_alive",
            "overflow_behavior": "coverage_lost_and_reported",
            "interpreter_input_protection": False,
            "classification": "guarded_workload_approved_code_allowlist"
            if self.guarded_mode != "off"
            else "preapproved_exact_path_sha256_deny",
            "unknown_hash_behavior": "deny_unapproved_within_explicit_guarded_scope"
            if self.guarded_mode == "enforce"
            else "audit_unapproved_without_denial"
            if self.guarded_mode == "audit"
            else "allow_when_valid_signed_policy_does_not_match",
            "guarded_workload_mode": self.guarded_mode,
            "guarded_workload_native_qualified": False,
            "guarded_workload_lease_seconds": self.settings.get(
                "guarded_workload_lease_seconds", 60
            )
            if self.guarded_mode != "off"
            else None,
            "zero_day_classifier": False,
            "memory_exploit_prevention": False,
            "revision": snapshot["revision"] if snapshot else None,
            "policy_sha256": snapshot["digest"] if snapshot else None,
            "error": self.error,
            "watched_directories": list(getattr(self, "directories", ())),
            "pending_bound": MAX_PENDING,
            "hash_worker_bound": WORKERS,
            **self.counters,
        }

    health = status

    def _guarded_context(self, snapshot=None):
        snapshot = self.snapshot if snapshot is None else snapshot
        return {
            **{
                name: self.config[name]
                for name in ("tenant", "host", "agent_id", "index")
            },
            "policy_sha256": snapshot["digest"],
            "scope_sha256": hashlib.sha256(
                defense.canonical(list(self.directories))
            ).hexdigest(),
            "adapter_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        }

    def _save_guarded_audit(self):
        if not self.backend.native or not all(self.guarded_counts.values()):
            return  # Mock observations never qualify native enforcement.
        path = Path(self.config["state_dir"]) / "guarded-workload-audit.json"
        self.response._no_links(path.parent)
        if path.exists():
            self.response._no_links(path)
        receipt = dict(
            self._guarded_context(),
            native_confirmed=True,
            approved=self.guarded_counts["approved"],
            unapproved=self.guarded_counts["unapproved"],
            completed_at=self.clock(),
        )
        temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(defense.canonical(receipt))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            self._guarded_audit_dirty = False
        finally:
            temporary.unlink(missing_ok=True)

    def _verify_guarded_audit(self, snapshot=None):
        path = Path(self.config["state_dir"]) / "guarded-workload-audit.json"
        self.response._no_links(path)
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 8192 or info.st_nlink != 1:
            raise PermissionError(
                "Protected bounded native guarded-workload audit receipt required"
            )
        if os.name != "nt" and (info.st_uid != os.geteuid() or info.st_mode & 0o022):
            raise PermissionError(
                "Guarded-workload audit receipt must be service-owned and private"
            )
        receipt = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=defense._pairs
        )
        if not isinstance(receipt, dict):
            raise PermissionError("Guarded-workload audit receipt must be an object")
        completed = receipt.get("completed_at")
        if (
            any(
                receipt.get(key) != value
                for key, value in self._guarded_context(snapshot).items()
            )
            or receipt.get("native_confirmed") is not True
            or any(
                type(receipt.get(key)) is not int or receipt[key] < 1
                for key in ("approved", "unapproved")
            )
            or type(completed) not in (int, float)
            or not self.clock() - 86400 <= completed <= self.clock()
            or not self.backend.native
        ):
            raise PermissionError(
                "Same-policy/scope native approved and unapproved audit-first proof required"
            )

    def close(self):
        self.stop_event.set()
        # Read loop is nonblocking/select with <=10ms waits; join remains bounded.
        for thread in self.threads:
            if thread.name == "lumina-kernel-permissions":
                thread.join(timeout=2.5)
                if thread.is_alive():
                    self.error = (
                        "Permission listener did not stop within its shutdown bound"
                    )
                    self.backend.close()
        for thread in self.threads:
            if thread.name == "lumina-kernel-policy":
                thread.join(timeout=0.75)
        if self.backend and not self.threads:
            self.backend.close()
        while True:
            try:
                _token, fd, _deadline, _snapshot = self.jobs.get_nowait()
            except queue.Empty:
                break
            os.close(fd)
            self.jobs.task_done()
        self.running = False
