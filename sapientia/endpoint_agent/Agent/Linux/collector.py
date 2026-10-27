# ruff: noqa: UP017 -- Distributed runtime supports Python 3.10.
"""Distribution-neutral Linux endpoint collector.

The portable baseline uses ``/proc`` and the systemd journal.  When auditd is
enabled it also consumes the cursor-backed audit log, which fills the largest
gaps in polling (short-lived execs, file changes, ptrace and module loads).
This is still not an eBPF sensor: an optional eBPF/CO-RE collector can be
added later without changing the normalized event contract.
"""

import hashlib
import json
import os
import platform
import posixpath
import re
import selectors
import socket
import stat
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


class _ProcessSnapshot(list):
    """Present PID evidence distinguishes access loss from an observed exit."""

    def __init__(self):
        super().__init__()
        self.present_pids = set()


class LinuxCollector:
    def __init__(
        self, *, emit_initial=False, state_dir=None, emit_startup_inventory=True
    ):
        if platform.system() != "Linux":
            raise OSError("Linux collector requires Linux")
        if os.geteuid() != 0:
            raise PermissionError("Linux agent must run as root")
        self.seen = set()
        self.initialized = False
        self.emit_initial = emit_initial
        self.emit_startup_inventory = emit_startup_inventory
        self.snapshot_epoch = uuid.uuid4().hex
        self.snapshot_timestamp = datetime.now(timezone.utc).isoformat()
        self.boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self.clock_ticks = os.sysconf("SC_CLK_TCK")
        self.boot_time = next(
            int(line.split()[1])
            for line in Path("/proc/stat").read_text().splitlines()
            if line.startswith("btime ")
        )
        self.hostname = socket.gethostname()
        self.last_rows = {}
        self.sockets = set()
        self._tcp_epochs = {}
        self.provider_status = {}
        self.journal_path = (
            Path(state_dir) / "journal-cursor.json" if state_dir else None
        )
        self.audit_state_path = (
            Path(state_dir) / "audit-cursor.json" if state_dir else None
        )
        self.audit_log_path = Path(
            os.environ.get("AEGIS_AUDIT_LOG", "/var/log/audit/audit.log")
        )
        try:
            saved = (
                json.loads(self.journal_path.read_text(encoding="utf-8"))
                if self.journal_path
                else {}
            )
        except (OSError, ValueError):
            saved = {}
        self.journal_cursor = (
            saved.get("cursor") if saved.get("boot_id") == self.boot_id else None
        )
        try:
            audit_saved = (
                json.loads(self.audit_state_path.read_text(encoding="utf-8"))
                if self.audit_state_path
                else {}
            )
        except (OSError, ValueError):
            audit_saved = {}
        self.audit_offset = (
            int(audit_saved.get("offset", 0))
            if audit_saved.get("boot_id") == self.boot_id
            else 0
        )
        self.audit_inode = (
            audit_saved.get("inode")
            if audit_saved.get("boot_id") == self.boot_id
            else None
        )
        self.audit_generation = audit_saved.get("generation", "initial")
        self.audit_anchor = audit_saved.get("anchor")

    def provider_health(self):
        return dict(self.provider_status)

    def _observation_time(self, identifier):
        if not hasattr(self, "_observation_times"):
            self._observation_times = {}
        value = self._observation_times.setdefault(
            identifier, datetime.now(timezone.utc).isoformat()
        )
        if len(self._observation_times) > 100000:
            self._observation_times.pop(next(iter(self._observation_times)))
        return value

    def _rows(self):
        rows = _ProcessSnapshot()
        for path in Path("/proc").iterdir():
            if not path.name.isdigit():
                continue
            rows.present_pids.add(int(path.name))
            try:
                stat = (path / "stat").read_text()
                end = stat.rfind(")")
                name = stat[stat.find("(") + 1 : end]
                tail = stat[end + 2 :].split()
                ppid = int(tail[1])
                start_ticks = int(tail[19])
                command_bytes = (path / "cmdline").read_bytes()
                command = (
                    command_bytes.replace(b"\0", b" ")
                    .decode("utf-8", errors="replace")
                    .strip()
                )
                row = {
                    "pid": int(path.name),
                    "ppid": ppid,
                    "name": name,
                    "start": start_ticks,
                    "command_line": command[:8192],
                    "command_line_original_length": len(command),
                    "command_line_sha256": hashlib.sha256(
                        command.encode("utf-8")
                    ).hexdigest(),
                    "command_line_truncated": len(command) > 8192,
                    "command_line_raw_bytes": len(command_bytes),
                    "command_line_raw_sha256": hashlib.sha256(
                        command_bytes
                    ).hexdigest(),
                    "command_line_decode_replacement": "\ufffd" in command,
                }
                try:
                    row["executable"] = os.readlink(path / "exe")
                    status = (path / "status").read_text()
                    uid = re.search(r"^Uid:\s+(\d+)", status, re.MULTILINE)
                    if uid:
                        row["uid"] = int(uid.group(1))
                except (OSError, ValueError, IndexError):
                    # Kernel threads and short lived processes still give
                    # useful identity evidence, without inventing an exe.
                    row.pop("executable", None)
                # Optional exe/status access failure does not waive incarnation
                # verification across the command-line/metadata observation.
                latest = (path / "stat").read_text()
                if int(latest[latest.rfind(")") + 2 :].split()[19]) != start_ticks:
                    continue
                rows.append(row)
            except (
                OSError,
                ValueError,
                IndexError,
            ):
                continue
        return rows

    def processes(self):
        return [{k: v for k, v in row.items() if k != "start"} for row in self._rows()]

    def inventory(self):
        return {
            "hostname": self.hostname,
            "os": platform.platform(),
            "architecture": platform.machine(),
            "kernel": platform.release(),
            "process_count": len(self._rows()),
            "collector": "Linux /proc, TCP, journald and auditd",
            "coverage": {
                "process": "procfs polling",
                "network": "procfs TCP polling",
                "auth_service": "systemd journal",
                "syscall_file_memory": "auditd when /var/log/audit/audit.log is available",
            },
        }

    def begin_cycle(self):
        self._saved = (
            self.seen.copy(),
            self.initialized,
            self.last_rows.copy(),
            self.sockets.copy(),
            self.journal_cursor,
            self.audit_offset,
            self.audit_inode,
            self.audit_generation,
            getattr(self, "audit_anchor", None),
            getattr(self, "_tcp_epochs", {}).copy(),
        )

    def rollback(self):
        if hasattr(self, "_saved"):
            (
                self.seen,
                self.initialized,
                self.last_rows,
                self.sockets,
                self.journal_cursor,
                self.audit_offset,
                self.audit_inode,
                self.audit_generation,
                self.audit_anchor,
                self._tcp_epochs,
            ) = self._saved

    def checkpoint(self):
        from ..core import atomic_json

        if self.journal_path and self.journal_cursor:
            atomic_json(
                self.journal_path,
                {"boot_id": self.boot_id, "cursor": self.journal_cursor},
            )
        if self.audit_state_path:
            atomic_json(
                self.audit_state_path,
                {
                    "boot_id": self.boot_id,
                    "inode": self.audit_inode,
                    "offset": self.audit_offset,
                    "generation": self.audit_generation,
                    "anchor": getattr(self, "audit_anchor", None),
                },
            )

    @staticmethod
    def _audit_fields(line):
        """Parse auditd's quoted and unquoted key/value fields safely."""
        fields = {}
        for match in re.finditer(
            r"(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>\"(?:\\.|[^\"])*\"|[^\s]+)",
            line,
        ):
            value = match.group("value")
            if value.startswith('"') and value.endswith('"'):
                try:
                    value = json.loads(value)
                except ValueError:
                    value = value[1:-1]
            fields[match.group("key")] = value
        return fields

    @staticmethod
    def _audit_text(line, field):
        """Only audit string fields use hex encoding; quoted hex stays literal."""
        match = re.search(
            r"\b" + re.escape(field) + r'=("(?:\\.|[^"\\])*"|[^\s]+)', line
        )
        if not match:
            return None
        value = match.group(1)
        if value.startswith('"'):
            try:
                return json.loads(value)
            except ValueError:
                return value[1:-1]
        if len(value) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", value):
            return bytes.fromhex(value).decode("utf-8", errors="replace")
        return value

    @classmethod
    def _audit_arguments(cls, lines):
        """Join split EXECVE records and aN[part] records in numeric order."""
        values, parts = {}, {}
        for line in lines:
            for match in re.finditer(
                r'\ba(?P<index>\d+)(?:\[(?P<part>\d+)\])?=(?P<value>"(?:\\.|[^"\\])*"|[^\s]+)',
                line,
            ):
                index = int(match.group("index"))
                if index > 4095:
                    continue
                field = "a" + match.group("index")
                if match.group("part") is not None:
                    field += "[" + match.group("part") + "]"
                value = cls._audit_text(line, field)
                if match.group("part") is None:
                    values[index] = value
                elif int(match.group("part")) < 4096:
                    parts.setdefault(index, {})[int(match.group("part"))] = value
        for index, segments in parts.items():
            values[index] = "".join(segments[key] for key in sorted(segments))
        return [str(values[key]) for key in sorted(values)]

    @staticmethod
    def _audit_destination(lines):
        """SOCKADDR is a sockaddr struct, not proof of TCP versus UDP."""
        for line in lines:
            if not line.startswith("type=SOCKADDR "):
                continue
            value = LinuxCollector._audit_fields(line).get("saddr", "")
            try:
                raw = bytes.fromhex(value)
                family = int.from_bytes(raw[:2], "little")
                port = int.from_bytes(raw[2:4], "big")
                if family == 2 and len(raw) >= 8:  # Linux AF_INET ABI.
                    address = socket.inet_ntop(socket.AF_INET, raw[4:8])
                elif family == 10 and len(raw) >= 24:  # Linux AF_INET6 ABI.
                    address = socket.inet_ntop(socket.AF_INET6, raw[8:24])
                else:
                    continue
                return {"ip": address, "port": port}
            except (ValueError, OSError):
                continue
        return None

    @classmethod
    def _audit_closed_record(cls, lines):
        """Recognize a complete native event without requiring global quiet.

        auditd commonly omits EOE from its on-disk log. A syscall's declared
        PATH items, terminal PROCTITLE and, for exec, declared arguments close
        the represented event even while unrelated audit activity continues.
        Interleaved or truncated groups lacking those records stay replayable.
        """
        syscall = next(
            (line for line in lines if line.startswith("type=SYSCALL ")), None
        )
        if syscall is None:
            # These single-record user/daemon audit messages are not syscall
            # observations and are intentionally not normalized below.
            if len(lines) != 1:
                return False
            kind = lines[0].partition(" ")[0].removeprefix("type=")
            return kind.startswith(("USER_", "CRED_", "DAEMON_")) or kind in {
                "LOGIN",
                "CONFIG_CHANGE",
                "SERVICE_START",
                "SERVICE_STOP",
                "SYSTEM_BOOT",
                "SYSTEM_SHUTDOWN",
            }
        row = cls._audit_fields(syscall)
        declared = row.get("items", "")
        if not declared.isascii() or not declared.isdigit() or int(declared) > 4096:
            return False
        paths = [
            cls._audit_fields(line).get("item")
            for line in lines
            if line.startswith("type=PATH ")
        ]
        if len(paths) != int(declared) or set(paths) != {
            str(index) for index in range(int(declared))
        }:
            return False
        if not any(line.startswith("type=PROCTITLE ") for line in lines):
            return False
        exec_lines = [line for line in lines if line.startswith("type=EXECVE ")]
        is_exec = (row.get("arch"), row.get("syscall")) in {
            ("c000003e", "59"),
            ("c000003e", "322"),
            ("c00000b7", "221"),
            ("c00000b7", "281"),
            ("40000003", "11"),
            ("40000003", "358"),
        }
        if is_exec and row.get("success") != "no" and not exec_lines:
            return False
        if exec_lines:
            arguments = cls._audit_fields(exec_lines[0]).get("argc", "")
            if (
                not arguments.isascii()
                or not arguments.isdigit()
                or int(arguments) > 4096
            ):
                return False
            if len(cls._audit_arguments(exec_lines)) != int(arguments):
                return False
        return True

    @staticmethod
    def _audit_file_hash(path, path_record, deadline=None):
        """Bounded current-object enrichment; never hashes a reused inode/name."""
        descriptor = None
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
            )
            before = os.fstat(descriptor)
            evidence = LinuxCollector._audit_fields(path_record)
            device = evidence.get("dev", "")
            if re.fullmatch(r"[0-9a-fA-F]+:[0-9a-fA-F]+", device) and hasattr(
                os, "major"
            ):
                major, minor = (int(part, 16) for part in device.split(":"))
                if (major, minor) != (os.major(before.st_dev), os.minor(before.st_dev)):
                    return None
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size > 1024 * 1024
                or str(evidence.get("inode", "")).isdigit()
                and int(evidence["inode"]) != before.st_ino
            ):
                return None
            digest = hashlib.sha256()
            deadline = min(deadline or float("inf"), time.monotonic() + 0.1)
            while time.monotonic() < deadline:
                chunk = os.read(descriptor, 65536)
                if not chunk:
                    after = os.fstat(descriptor)
                    named = os.stat(path, follow_symlinks=False)
                    if (
                        before.st_dev,
                        before.st_ino,
                        before.st_size,
                        before.st_mtime_ns,
                        before.st_ctime_ns,
                    ) == (
                        after.st_dev,
                        after.st_ino,
                        after.st_size,
                        after.st_mtime_ns,
                        after.st_ctime_ns,
                    ) and (after.st_dev, after.st_ino) == (named.st_dev, named.st_ino):
                        return digest.hexdigest()
                    return None
                digest.update(chunk)
            return None
        except (OSError, ValueError):
            return None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _audit_events(self, host, limit=300):
        """Read auditd records incrementally and normalize high-value syscalls."""
        try:
            source = self.audit_log_path
            stat = source.stat()
            inode = getattr(stat, "st_ino", None)
            # Drain an unread rotated file before switching to the new inode.
            if self.audit_inode is not None and self.audit_inode != inode:
                for candidate in source.parent.glob(source.name + "*"):
                    try:
                        old = candidate.stat()
                        if (
                            old.st_ino == self.audit_inode
                            and old.st_size > self.audit_offset
                        ):
                            source, stat, inode = candidate, old, old.st_ino
                            break
                    except OSError:
                        continue
            if self.audit_inode != inode or self.audit_offset > stat.st_size:
                self.audit_offset, self.audit_inode = 0, inode
                # Stable across a crash before the durable queue/checkpoint
                # handoff; the original timestamp+serial is also in each ID.
                self.audit_generation = str(stat.st_dev) + ":" + str(inode)
            handle = source.open("rb")
            if self.audit_offset and getattr(self, "audit_anchor", None):
                handle.seek(max(0, self.audit_offset - 128))
                anchor = hashlib.sha256(
                    handle.read(min(128, self.audit_offset))
                ).hexdigest()
                if anchor != self.audit_anchor:
                    self.audit_offset = 0
                    self.audit_generation = (
                        str(stat.st_dev)
                        + ":"
                        + str(inode)
                        + ":"
                        + str(stat.st_mtime_ns)
                    )
                    self.provider_status["auditd"] = {
                        "status": "degraded",
                        "error": "Audit copytruncate or source rewrite detected",
                    }
        except OSError as error:
            self.provider_status["auditd"] = {
                "status": "unavailable",
                "error": type(error).__name__,
            }
            return []
        self.provider_status["auditd"] = {"status": "ok"}
        groups, starts, ends, completed = {}, {}, {}, set()
        origin = self.audit_offset
        try:
            handle.seek(origin)
            bytes_read = 0
            for _ in range(max(limit * 32, 256)):
                position = handle.tell()
                raw = handle.readline(65537)
                if not raw or not raw.endswith(b"\n"):
                    break
                if len(raw) > 65536:
                    self.provider_status["auditd"] = {
                        "status": "degraded",
                        "error": "Audit record exceeds 64 KiB",
                    }
                    break
                bytes_read += len(raw)
                if bytes_read > 4 * 1024 * 1024:
                    self.provider_status["auditd"] = {
                        "status": "degraded",
                        "error": "Audit page exceeds 4 MiB; unread source retained",
                    }
                    break
                line = raw.decode("utf-8", errors="replace")
                marker = re.search(r"msg=audit\(([^)]+)\)", line)
                if not marker:
                    if not groups:
                        origin = handle.tell()
                    continue
                serial = marker.group(1)
                starts.setdefault(serial, position)
                groups.setdefault(serial, []).append(line.rstrip("\n"))
                ends[serial] = handle.tell()
                if line.startswith("type=EOE "):
                    completed.add(serial)
            # Explicit EOE and structurally complete syscall/user records work
            # even on a continuously active log. Legacy incomplete records
            # without a declared structure still require a closed/quiet EOF.
            completed.update(
                key for key, lines in groups.items() if self._audit_closed_record(lines)
            )
            eof = handle.tell() >= stat.st_size
            quiet = source != self.audit_log_path or time.time() - stat.st_mtime >= 2
            if eof and quiet:
                completed.update(groups)
            chosen = [key for key in groups if key in completed][:limit]
            unprocessed = [starts[key] for key in groups if key not in chosen]
            self.audit_offset = (
                min(unprocessed) if unprocessed else max(ends.values(), default=origin)
            )
            groups = {key: groups[key] for key in chosen}
            if unprocessed:
                self.provider_status["auditd"] = {
                    "status": "degraded",
                    "pending_partial_serial": True,
                    "completion": "EOE, complete declared record, or quiet EOF (2 seconds)",
                }
            handle.seek(max(0, self.audit_offset - 128))
            self.audit_anchor = hashlib.sha256(
                handle.read(min(128, self.audit_offset))
            ).hexdigest()
        finally:
            handle.close()
        events = []
        syscall_tables = {
            "c000003e": {
                "42": "network_connection",
                "59": "process_created",
                "322": "process_created",
                "87": "file_deleted",
                "101": "process_accessed",
                "175": "driver_loaded",
                "176": "driver_unloaded",
                "257": "file_accessed",
                "263": "file_deleted",
                "313": "driver_loaded",
                "437": "file_accessed",
            },
            "c00000b7": {
                "56": "file_accessed",
                "35": "file_deleted",
                "117": "process_accessed",
                "105": "driver_loaded",
                "106": "driver_unloaded",
                "273": "driver_loaded",
                "221": "process_created",
                "281": "process_created",
                "203": "network_connection",
                "437": "file_accessed",
            },
            "40000003": {
                "5": "file_accessed",
                "11": "process_created",
                "26": "process_accessed",
                "10": "file_deleted",
                "128": "driver_loaded",
                "129": "driver_unloaded",
                "295": "file_accessed",
                "301": "file_deleted",
                "350": "driver_loaded",
                "358": "process_created",
                "362": "network_connection",
                "437": "file_accessed",
            },
        }
        hash_deadline = time.monotonic() + 0.5
        for serial, lines in groups.items():
            syscall = next(
                (line for line in lines if line.startswith("type=SYSCALL ")), ""
            )
            exec_lines = [line for line in lines if line.startswith("type=EXECVE ")]
            exec_line = exec_lines[0] if exec_lines else ""
            path_lines = [line for line in lines if line.startswith("type=PATH ")]
            row = self._audit_fields(syscall or exec_line)
            if str(row.get("pid", "")).isdigit() and int(row["pid"]) == os.getpid():
                # File enrichment opens are themselves auditable; avoid a
                # self-generated stream of the sensor's own hash reads.
                self.provider_status["auditd"]["self_records_filtered"] = (
                    self.provider_status["auditd"].get("self_records_filtered", 0) + 1
                )
                continue
            architecture = row.get("arch", "").lower()
            syscall_actions = syscall_tables.get(architecture, {})
            if row.get("syscall") and not syscall_actions:
                self.provider_status["auditd"] = {
                    "status": "degraded",
                    "error": "Unsupported audit architecture; numeric syscall classification skipped",
                }
            exec_fields = self._audit_fields(exec_line)
            action = None
            if exec_line:
                action = "process_created"
            elif row.get("syscall") in syscall_actions:
                action = syscall_actions[row["syscall"]]
            if any(
                self._audit_fields(line).get("nametype") == "CREATE"
                for line in path_lines
            ):
                action = "file_created"
            elif any(
                self._audit_fields(line).get("nametype") in {"DELETE", "DESTROY"}
                for line in path_lines
            ):
                action = "file_deleted"
            if not action:
                if row.get("syscall"):
                    action = "audit_syscall_unclassified"
                else:
                    continue
            stamp = next(
                (re.search(r"msg=audit\((\d+(?:\.\d+)?)", line) for line in lines), None
            )
            try:
                timestamp = (
                    datetime.fromtimestamp(
                        float(stamp.group(1)), timezone.utc
                    ).isoformat()
                    if stamp
                    else datetime.now(timezone.utc).isoformat()
                )
            except (ValueError, OverflowError):
                timestamp = datetime.now(timezone.utc).isoformat()
            command = self._audit_arguments(exec_lines)
            executable = self._audit_text(syscall, "exe") or row.get("comm")
            path = None
            selected_path_record = None
            cwd_line = next(
                (line for line in lines if line.startswith("type=CWD ")), ""
            )
            cwd = self._audit_text(cwd_line, "cwd")
            priority = {"DELETE": 0, "DESTROY": 0, "CREATE": 0, "NORMAL": 1}
            for path_line in sorted(
                path_lines,
                key=lambda line: priority.get(
                    self._audit_fields(line).get("nametype"), 2
                ),
            ):
                candidate = self._audit_text(path_line, "name")
                if candidate and candidate != "(null)":
                    path = (
                        posixpath.normpath(posixpath.join(cwd, candidate))
                        if cwd and cwd.startswith("/")
                        else candidate
                    )
                    selected_path_record = path_line
                    break
            attempted_action = action
            outcome = {"yes": "success", "no": "failure"}.get(
                row.get("success"), "unknown"
            )
            if outcome == "failure":
                action = attempted_action + "_failed"
            pid = row.get("pid") or exec_fields.get("pid")
            pid_value = int(pid) if str(pid).isdigit() else None
            guid = str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    host
                    + ":audit:"
                    + self.boot_id
                    + ":"
                    + self.audit_generation
                    + ":"
                    + serial
                    + ":"
                    + action,
                )
            )
            process = {
                "guid": guid,
                "pid": pid_value,
                "name": row.get("comm"),
                "executable": executable,
                "command_line": " ".join(command)[:8192],
            }
            observed_command = " ".join(command)
            data = {
                "@timestamp": timestamp,
                "host": {"id": host, "name": self.hostname, "os": {"type": "linux"}},
                "process": process,
                "event": {
                    "module": "auditd",
                    "action": action,
                    "code": row.get("syscall"),
                    "provider": "audit",
                    "outcome": outcome,
                },
                "agent": {
                    "collector": "auditd",
                    "coverage": "audit",
                    "command_line_original_length": len(observed_command),
                    "command_line_sha256": hashlib.sha256(
                        observed_command.encode("utf-8")
                    ).hexdigest(),
                    "command_line_truncated": len(observed_command) > 8192,
                    "process_identity_kind": "audit_record_only",
                    "process_response_eligible": False,
                    "source_record_sha256": hashlib.sha256(
                        "\n".join(lines).encode("utf-8")
                    ).hexdigest(),
                },
            }
            if row.get("syscall") is not None:
                data["audit"] = {
                    "syscall": row.get("syscall"),
                    "arch": row.get("arch"),
                    "record_id": guid,
                    "attempted_action": attempted_action,
                    "process_identity": "audit-record-only",
                }
            # A /proc snapshot can join audit observations only with native
            # incarnation, executable and temporal evidence. Integer btime has
            # one-second uncertainty: reject ambiguous near-birth observations.
            live = getattr(self, "_audit_rows", {}).get(pid_value)
            try:
                event_epoch = datetime.fromisoformat(timestamp).timestamp()
                observed_at = self._audit_observed_at
                birth_upper = self.boot_time + live["start"] / self.clock_ticks + 1
                bindable = (
                    live
                    and executable
                    and live.get("executable") == executable
                    and birth_upper <= event_epoch <= observed_at
                )
            except (AttributeError, KeyError, TypeError, ValueError):
                bindable = False
            if bindable:
                native_key = f"{self.boot_id}:{pid_value}:{live['start']}"
                process["guid"] = str(
                    uuid.uuid5(uuid.NAMESPACE_OID, host + ":" + native_key)
                )
                data["agent"]["observed_process_start_identity"] = (
                    f"linux:{self.boot_id}:{live['start']}"
                )
                data["agent"]["process_identity_kind"] = "linux_live_creation_time"
                data.setdefault("audit", {})["process_identity"] = (
                    "temporally_verified_live_incarnation"
                )
                parent = getattr(self, "_audit_rows", {}).get(live.get("ppid"))
                if parent and parent["start"] <= live["start"]:
                    process["parent"] = {
                        "pid": parent["pid"],
                        "name": parent["name"],
                        "guid": str(
                            uuid.uuid5(
                                uuid.NAMESPACE_OID,
                                host
                                + ":"
                                + f"{self.boot_id}:{parent['pid']}:{parent['start']}",
                            )
                        ),
                    }
            if str(row.get("uid", "")).isdigit():
                data["process"]["uid"] = int(row["uid"])
            if str(row.get("exit", "")).lstrip("-").isdigit():
                data["process"]["exit"] = {"code": int(row["exit"])}
            if path:
                data["file"] = {"path": path, "operation": action}
                if (
                    outcome == "success"
                    and action in {"file_created", "file_accessed"}
                    and path.startswith("/")
                ):
                    digest = (
                        self._audit_file_hash(path, selected_path_record, hash_deadline)
                        if time.monotonic() < hash_deadline
                        else None
                    )
                    if digest:
                        data["file"]["hash"] = {"sha256": digest}
                        data["file"]["hash_observation"] = (
                            "current stable object; audit inode checked when supplied"
                        )
            if attempted_action == "network_connection":
                destination = self._audit_destination(lines)
                if destination:
                    data["destination"] = destination
                data["network"] = {"direction": "outbound", "transport": "unknown"}
            if action.startswith("driver_"):
                data["driver"] = {"path": path or executable}
            if action == "process_accessed":
                data["process"]["access"] = {"mask": row.get("a2") or row.get("a1")}
            events.append({"id": "linux-audit-" + guid, "data": data})
        return events

    def _journal_output(self, command, limit, timeout=5):
        """Bound time, records and bytes without a blocking pipe readline."""
        proc = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
        lines, buffer, consumed = [], b"", 0
        deadline = time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as selector:
                os.set_blocking(proc.stdout.fileno(), False)
                selector.register(proc.stdout, selectors.EVENT_READ)
                while len(lines) < limit and consumed < 1024 * 1024:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        self.provider_status["journald"] = {
                            "status": "degraded",
                            "error": "Journal read deadline exceeded",
                        }
                        break
                    if not selector.select(remaining):
                        continue
                    chunk = os.read(
                        proc.stdout.fileno(), min(65536, 1024 * 1024 - consumed)
                    )
                    if not chunk:
                        break
                    consumed += len(chunk)
                    buffer += chunk
                    while b"\n" in buffer and len(lines) < limit:
                        line, buffer = buffer.split(b"\n", 1)
                        lines.append(line)
                if consumed >= 1024 * 1024 and len(lines) < limit:
                    self.provider_status["journald"] = {
                        "status": "degraded",
                        "error": "Journal page exceeds 1 MiB",
                    }
        finally:
            if proc.poll() is None:
                proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
            proc.stdout.close()
        if (
            proc.returncode
            and len(lines) < limit
            and not self.provider_status.get("journald", {}).get("error")
        ):
            self.provider_status["journald"] = {
                "status": "degraded",
                "error": "journalctl failed",
            }
        return lines

    def _journal_events(self, host, limit=300):
        """Cursor-backed systemd journal enrichment for auth/service events."""
        if self.journal_cursor is None:
            try:
                self.provider_status["journald"] = {"status": "ok"}
                lines = self._journal_output(
                    [
                        "journalctl",
                        "--system",
                        "--boot",
                        "--no-pager",
                        "-n",
                        "1",
                        "-o",
                        "json",
                    ],
                    1,
                )
                if lines:
                    self.journal_cursor = json.loads(lines[-1]).get("__CURSOR")
            except (OSError, subprocess.TimeoutExpired, ValueError) as error:
                self.provider_status["journald"] = {
                    "status": "unavailable",
                    "error": type(error).__name__,
                }
            return []
        command = [
            "journalctl",
            "--system",
            "--boot",
            "--no-pager",
            "-o",
            "json",
            "--after-cursor=" + self.journal_cursor,
        ]
        try:
            self.provider_status["journald"] = {"status": "ok"}
            journal_lines = self._journal_output(command, limit)
        except (OSError, subprocess.TimeoutExpired) as error:
            self.provider_status["journald"] = {
                "status": "degraded",
                "error": type(error).__name__,
            }
            return []
        events = []
        for line in journal_lines:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            cursor = row.get("__CURSOR")
            if cursor:
                self.journal_cursor = cursor
            message = row.get("MESSAGE", "")
            if not isinstance(message, str):
                continue
            ident = str(row.get("SYSLOG_IDENTIFIER") or row.get("_COMM") or "")
            comm = str(row.get("_COMM") or "")
            executable = str(row.get("_EXE") or "")
            transport = str(row.get("_TRANSPORT") or "")
            unit = str(row.get("_SYSTEMD_UNIT") or "")
            if unit in {"aegis-agent.service", "vatex-lumina-xsera-agent.service"}:
                continue
            action = module = None
            lower = message.lower()
            if ident in {"sshd", "ssh", "sshd-session"} and (
                comm.startswith("sshd")
                or executable.endswith(("/sshd", "/sshd-session"))
            ):
                module = "auth"
                if "failed password" in lower or "authentication failure" in lower:
                    action = "failed_logon"
                elif "accepted password" in lower or "accepted publickey" in lower:
                    action = "remote_logon"
                elif "invalid user" in lower:
                    action = "invalid_user"
            elif ident == "sudo" and (comm == "sudo" or executable.endswith("/sudo")):
                module = "auth"
                if "authentication failure" in lower:
                    action = "sudo_auth_failure"
                elif "command=" in lower:
                    action = "sudo_command"
            elif ident == "systemd" and (
                comm == "systemd" or executable.endswith("/systemd")
            ):
                module = "service"
                if lower.startswith("stopped "):
                    action = "service_stopped"
                elif lower.startswith("started "):
                    action = "service_started"
                elif lower.startswith("failed to start "):
                    action = "service_failed"
            elif (
                ident == "kernel"
                and transport == "kernel"
                and 'apparmor="DENIED"' in message
            ):
                module, action = "security", "security_denied"
            if not action:
                continue
            pid_text = str(row.get("_PID") or "")
            pid = int(pid_text) if pid_text.isdigit() else None
            stamp_raw = row.get("__REALTIME_TIMESTAMP")
            try:
                stamp = datetime.fromtimestamp(
                    int(stamp_raw) / 1_000_000, timezone.utc
                ).isoformat()
            except (TypeError, ValueError, OverflowError):
                stamp = datetime.now(timezone.utc).isoformat()
            user = re.search(
                r"(?:for (?:invalid user )?|USER=)([A-Za-z0-9_.-]+)", message
            )
            address = re.search(r"\bfrom ([0-9a-fA-F:.]+)\b", message)
            guid = str(uuid.uuid5(uuid.NAMESPACE_URL, host + ":journal:" + str(cursor)))
            events.append(
                {
                    "id": "linux-journal-" + guid,
                    "data": {
                        "@timestamp": stamp,
                        "host": {
                            "id": host,
                            "name": self.hostname,
                            "os": {"type": "linux"},
                        },
                        "user": {"name": user.group(1) if user else None},
                        "process": {"guid": guid, "pid": pid, "name": ident},
                        "source": {"ip": address.group(1) if address else None},
                        "event": {
                            "module": module,
                            "action": action,
                            "provider": ident,
                        },
                        "agent": {"collector": "journald", "coverage": "journal"},
                    },
                }
            )
        return events

    def _tcp_rows(self, host, by_pid):
        """Join /proc/net socket inodes to owning PIDs, with bounded fd scanning."""
        sockets = {}
        for name, family in (("tcp", 4), ("tcp6", 6)):
            try:
                lines = (Path("/proc/net") / name).read_text().splitlines()[1:]
            except OSError:
                continue
            for line in lines:
                columns = line.split()
                if len(columns) < 10 or columns[3] != "01":  # established TCP only
                    continue
                try:

                    def address(value, family=family):
                        raw, port = value.split(":")
                        octets = bytes.fromhex(raw)
                        if family == 4:
                            return socket.inet_ntop(socket.AF_INET, octets[::-1]), int(
                                port, 16
                            )
                        reordered = b"".join(
                            octets[i : i + 4][::-1] for i in range(0, 16, 4)
                        )
                        return socket.inet_ntop(socket.AF_INET6, reordered), int(
                            port, 16
                        )

                    sockets[columns[9]] = (*address(columns[1]), *address(columns[2]))
                except (ValueError, OSError):
                    continue
        owners = {}
        for pid in list(by_pid)[:2048]:
            try:
                for fd in (Path("/proc") / str(pid) / "fd").iterdir():
                    try:
                        target = os.readlink(fd)
                    except OSError:
                        continue
                    if target.startswith("socket:["):
                        inode = target[8:-1]
                        if inode in sockets:
                            owners[inode] = pid
            except OSError:
                continue
        current = {(inode, pid) for inode, pid in owners.items()}
        events = []
        for inode, pid in current - self.sockets:
            startup = not self.initialized and getattr(
                self, "emit_startup_inventory", False
            )
            if not self.initialized and not self.emit_initial and not startup:
                continue
            row = by_pid.get(pid)
            if not row:
                continue
            src_ip, src_port, dst_ip, dst_port = sockets[inode]
            key = f"{self.boot_id}:{pid}:{row['start']}"
            guid = str(uuid.uuid5(uuid.NAMESPACE_OID, host + ":" + key))
            if not hasattr(self, "_tcp_epochs"):
                self._tcp_epochs = {}
            epoch_key = (inode, pid, row["start"])
            self._tcp_epochs[epoch_key] = self._tcp_epochs.get(epoch_key, 0) + 1
            eid = str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    ":".join(
                        (
                            host,
                            getattr(self, "snapshot_epoch", ""),
                            inode,
                            key,
                            str(self._tcp_epochs[epoch_key]),
                        )
                    ),
                )
            )
            events.append(
                {
                    "id": (
                        "linux-tcp-inventory-"
                        + getattr(self, "snapshot_epoch", "")
                        + "-"
                        if startup
                        else "linux-tcp-"
                    )
                    + eid,
                    "data": {
                        "@timestamp": self._observation_time("linux-tcp-" + eid),
                        "host": {
                            "id": host,
                            "name": self.hostname,
                            "os": {"type": "linux"},
                        },
                        "process": {
                            "guid": guid,
                            "pid": pid,
                            "start_identity": f"linux:{self.boot_id}:{row['start']}",
                            "name": row["name"],
                            "executable": row.get("executable"),
                            "uid": row.get("uid"),
                            "command_line": row["command_line"],
                        },
                        "source": {"ip": src_ip, "port": src_port},
                        "destination": {"ip": dst_ip, "port": dst_port},
                        "network": {"protocol": "tcp"},
                        "event": {
                            "module": "inventory" if startup else "network",
                            "action": "network_connection_observed"
                            if startup
                            else "network_connection",
                        },
                        "agent": {
                            "collector": "procfs-tcp",
                            "coverage": "polling",
                            "command_line_original_length": row.get(
                                "command_line_original_length", len(row["command_line"])
                            ),
                            "command_line_sha256": row.get("command_line_sha256"),
                            "command_line_truncated": row.get(
                                "command_line_truncated", False
                            ),
                            "command_line_raw_bytes": row.get("command_line_raw_bytes"),
                            "command_line_raw_sha256": row.get(
                                "command_line_raw_sha256"
                            ),
                            "command_line_decode_replacement": row.get(
                                "command_line_decode_replacement", False
                            ),
                        },
                    },
                }
            )
        self.sockets = current
        self.provider_status["procfs_tcp"] = {
            "status": "ok",
            "coverage": "established TCP polling",
            "pid_limit": 2048,
            "truncated": len(by_pid) > 2048,
        }
        return events

    def collect(self, host):
        rows = self._rows()
        by_pid = {row["pid"]: row for row in rows}
        self._audit_rows = by_pid
        self._audit_observed_at = time.time()
        present = getattr(rows, "present_pids", set(by_pid))
        unknown = present - set(by_pid)
        self.provider_status["procfs"] = {
            "status": "degraded" if unknown else "ok",
            "coverage": "polling",
            "processes": len(rows),
            "present_identity_unavailable": len(unknown),
        }
        current = set()
        events = []
        for row in rows:
            key = f"{self.boot_id}:{row['pid']}:{row['start']}"
            current.add(key)
            startup = not self.initialized and getattr(
                self, "emit_startup_inventory", False
            )
            if startup and not hasattr(self, "snapshot_timestamp"):
                self.snapshot_timestamp = datetime.now(timezone.utc).isoformat()
            if key in self.seen or (
                not self.initialized and not self.emit_initial and not startup
            ):
                continue
            parent = by_pid.get(row["ppid"])
            if parent and parent["start"] > row["start"]:
                parent = None  # The current PID incarnation cannot be this parent.
            guid = str(uuid.uuid5(uuid.NAMESPACE_OID, host + ":" + key))
            parent_guid = (
                str(
                    uuid.uuid5(
                        uuid.NAMESPACE_OID,
                        host
                        + ":"
                        + f"{self.boot_id}:{parent['pid']}:{parent['start']}",
                    )
                )
                if parent
                else None
            )
            stamp = datetime.fromtimestamp(
                self.boot_time + row["start"] / self.clock_ticks, timezone.utc
            ).isoformat()
            events.append(
                {
                    "id": (
                        "linux-inventory-" + getattr(self, "snapshot_epoch", "") + "-"
                        if startup
                        else "linux-process-"
                    )
                    + guid,
                    "data": {
                        "@timestamp": self.snapshot_timestamp if startup else stamp,
                        "host": {
                            "id": host,
                            "name": self.hostname,
                            "os": {"type": "linux"},
                        },
                        "process": {
                            "guid": guid,
                            "pid": row["pid"],
                            "start_identity": "linux:"
                            + self.boot_id
                            + ":"
                            + str(row["start"]),
                            "name": row["name"],
                            "command_line": row["command_line"],
                            "executable": row.get("executable"),
                            "uid": row.get("uid"),
                            "parent": {
                                "guid": parent_guid,
                                "pid": row["ppid"],
                                "name": parent["name"] if parent else None,
                            },
                        },
                        "event": {
                            "module": "inventory" if startup else "process",
                            "action": "process_observed"
                            if startup
                            else "process_created",
                        },
                        "agent": {
                            "collector": "procfs",
                            "coverage": "polling",
                            "observed_process_start_time": stamp,
                            "command_line_original_length": row.get(
                                "command_line_original_length", len(row["command_line"])
                            ),
                            "command_line_sha256": row.get("command_line_sha256"),
                            "command_line_truncated": row.get(
                                "command_line_truncated", False
                            ),
                            "command_line_raw_bytes": row.get("command_line_raw_bytes"),
                            "command_line_raw_sha256": row.get(
                                "command_line_raw_sha256"
                            ),
                            "command_line_decode_replacement": row.get(
                                "command_line_decode_replacement", False
                            ),
                        },
                    },
                }
            )
        for key, row in self.last_rows.items():
            if key in current or row["pid"] in unknown:
                current.add(key)
                continue
            guid = str(uuid.uuid5(uuid.NAMESPACE_OID, host + ":" + key))
            events.append(
                {
                    "id": "linux-exit-" + guid,
                    "data": {
                        "@timestamp": self._observation_time("linux-exit-" + guid),
                        "host": {
                            "id": host,
                            "name": self.hostname,
                            "os": {"type": "linux"},
                        },
                        "process": {
                            "guid": guid,
                            "pid": row["pid"],
                            "name": row["name"],
                            "start_identity": "linux:"
                            + self.boot_id
                            + ":"
                            + str(row["start"]),
                        },
                        "event": {"module": "process", "action": "process_terminated"},
                        "agent": {"collector": "procfs", "coverage": "polling"},
                    },
                }
            )
        events.extend(self._tcp_rows(host, by_pid))
        events.extend(self._journal_events(host))
        events.extend(self._audit_events(host))
        self.last_rows = {
            key: row for key, row in self.last_rows.items() if row["pid"] in unknown
        } | {f"{self.boot_id}:{row['pid']}:{row['start']}": row for row in rows}
        self.seen = current
        self.initialized = True
        return events
