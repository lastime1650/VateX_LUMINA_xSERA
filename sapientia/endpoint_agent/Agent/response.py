# ruff: noqa: UP017 -- Distributed agent runtime also supports Python 3.10.
"""Locally opted-in, typed response executor. Never invokes a shell.

Durable execution markers precede OS effects. A crash between marker and result
is unknown and is never replayed. Windows uses process/file handles; Linux
requires pidfd for termination and claims a file before verifying/deleting it.
"""

import base64
import ctypes
import hashlib
import hmac
import json
import os
import select
import signal
import sqlite3
import stat
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

MARKER = ".lumina-response-root"
MARKER_TEXT = "allow-manual-file-delete\n"
MAX_FILE = 64 * 1024 * 1024


def canonical(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    )


def _outcome(kind, code, detail, *, success=False, executed=False):
    return {
        "success": success,
        "executed": executed,
        "type": kind,
        "code": code,
        "detail": detail[:2000],
    }


def _windows():
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.GetProcessTimes.argtypes = (wintypes.HANDLE,) + (
        ctypes.POINTER(wintypes.FILETIME),
    ) * 4
    kernel.QueryFullProcessImageNameW.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    )
    kernel.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.IsProcessCritical.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL))
    kernel.IsProcessCritical.restype = wintypes.BOOL
    return kernel, wintypes


def _win_identity(pid, host, handle, kernel, types):
    born, end, cpu, user = (types.FILETIME() for _ in range(4))
    if not kernel.GetProcessTimes(
        handle,
        ctypes.byref(born),
        ctypes.byref(end),
        ctypes.byref(cpu),
        ctypes.byref(user),
    ):
        raise OSError("Cannot verify process start identity")
    birth = (born.dwHighDateTime << 32) | born.dwLowDateTime
    size, executable = types.DWORD(32768), ctypes.create_unicode_buffer(32768)
    if not kernel.QueryFullProcessImageNameW(handle, 0, executable, ctypes.byref(size)):
        raise OSError("Cannot verify process executable")
    critical = types.BOOL()
    if not kernel.IsProcessCritical(handle, ctypes.byref(critical)):
        raise OSError("Cannot verify kernel critical-process flag")
    return {
        "pid": pid,
        "guid": str(uuid.uuid5(uuid.NAMESPACE_OID, host + ":" + f"{pid}:{birth}")),
        "start_identity": "windows:" + str(birth),
        "executable": executable.value,
        "critical": bool(critical.value),
    }


def _linux_identity(pid, host):
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    value = Path(f"/proc/{pid}/stat").read_text()
    fields = value[value.rfind(")") + 2 :].split()
    ticks = int(fields[19])
    return {
        "pid": pid,
        "guid": str(
            uuid.uuid5(uuid.NAMESPACE_OID, host + ":" + f"{boot}:{pid}:{ticks}")
        ),
        "start_identity": f"linux:{boot}:{ticks}",
        "executable": os.readlink(f"/proc/{pid}/exe"),
        "ppid": int(fields[1]),
    }


def inspect_process(pid, host):
    """Read actual kernel identity, for collector records and harmless QA only."""
    if type(pid) is not int or pid <= 4 or not isinstance(host, str) or not host:
        raise ValueError("PID >4 and host required")
    if os.name == "nt":
        kernel, types = _windows()
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            raise OSError("Process is unavailable or cannot be inspected")
        try:
            return _win_identity(pid, host, handle, kernel, types)
        finally:
            kernel.CloseHandle(handle)
    if not Path("/proc/sys/kernel/random/boot_id").is_file():
        raise OSError("Only Windows and Linux response are implemented")
    return _linux_identity(pid, host)


def _protected():
    protected = {os.getpid(), os.getppid()}
    if os.name == "nt":
        from .Windows.collector import _process_rows

        parents = {row["pid"]: row["ppid"] for row in _process_rows()}
        pid = os.getpid()
        for _ in range(128):
            pid = parents.get(pid, 0)
            if pid <= 4 or pid in protected and pid != os.getppid():
                break
            protected.add(pid)
    else:
        pid = os.getppid()
        for _ in range(128):
            try:
                pid = _linux_identity(pid, "local")["ppid"]
            except (OSError, ValueError, IndexError):
                break
            if pid <= 4 or pid in protected:
                break
            protected.add(pid)
    return protected


def _check_process(info, target, settings):
    critical_names = {
        "system",
        "registry",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "winlogon.exe",
        "svchost.exe",
        "systemd",
        "init",
        "sshd",
        "networkmanager",
        "systemd-networkd",
        "firewalld",
        "nft",
    }
    if (
        info.get("critical") is True
        or Path(info["executable"]).name.casefold() in critical_names
    ):
        raise PermissionError("Kernel-critical or OS/management process is protected")
    if info["pid"] in _protected() or any(
        info[key] != target[key if key != "guid" else "process_guid"]
        for key in ("pid", "guid", "start_identity")
    ):
        raise PermissionError(
            "PID reuse/start identity mismatch or protected agent/ancestor"
        )
    executable = os.path.normcase(str(Path(info["executable"]).resolve(strict=True)))
    allowed = settings.get("allowed_process_executables", [])
    if (
        not isinstance(allowed, list)
        or not 1 <= len(allowed) <= 32
        or executable
        not in {
            os.path.normcase(str(Path(p).resolve(strict=True)))
            for p in allowed
            if isinstance(p, str)
        }
    ):
        raise PermissionError("Executable is outside the local exact allowlist")
    instances = settings.get("allowed_process_instances", [])
    if instances and not any(
        isinstance(p, dict)
        and p.get("pid") == info["pid"]
        and p.get("start_identity") == info["start_identity"]
        for p in instances
    ):
        raise PermissionError("Process instance is outside the local exact allowlist")


def terminate(target, host, settings):
    pid = target["pid"]
    if os.name == "nt":
        kernel, types = _windows()
        handle = kernel.OpenProcess(0x1000 | 0x1 | 0x100000, False, pid)
        if not handle:
            raise OSError("Process cannot be opened for verified termination")
        try:
            info = _win_identity(pid, host, handle, kernel, types)
            _check_process(info, target, settings)
            if not kernel.TerminateProcess(handle, 1):
                raise OSError("Kernel rejected process termination")
            if kernel.WaitForSingleObject(handle, 2000) != 0:
                return _outcome(
                    "terminate_process",
                    "effect_unconfirmed",
                    "Termination requested but exit was not confirmed",
                    executed=None,
                )
        finally:
            kernel.CloseHandle(handle)
    else:
        if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
            raise OSError(
                "Linux termination requires pidfd; unsafe PID-only fallback is disabled"
            )
        fd = os.pidfd_open(pid)
        try:
            info = _linux_identity(pid, host)
            _check_process(info, target, settings)
            signal.pidfd_send_signal(fd, signal.SIGKILL)
            if not select.select([fd], [], [], 2)[0]:
                return _outcome(
                    "terminate_process",
                    "effect_unconfirmed",
                    "Termination requested but exit was not confirmed",
                    executed=None,
                )
        finally:
            os.close(fd)
    return _outcome(
        "terminate_process",
        "terminated",
        "Kernel-confirmed termination of the exact process instance; no persistent execution block",
        success=True,
        executed=True,
    )


def _no_links(path):
    for item in (path, *path.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise PermissionError("Symlink/reparse-point paths are forbidden")


def _file_target(path, settings):
    if (
        not isinstance(path, str)
        or not Path(path).is_absolute()
        or ".." in Path(path).parts
    ):
        raise ValueError("Canonical absolute path required")
    target = Path(path)
    _no_links(target)
    resolved = target.resolve(strict=True)
    protected = [Path(__file__).resolve().parent.parent]
    for key in ("_agent_state_dir", "quarantine_dir"):
        if isinstance(settings.get(key), str) and settings[key]:
            protected.append(Path(settings[key]).resolve())
    if any(resolved.is_relative_to(root) for root in protected):
        raise PermissionError(
            "Agent installation, state and quarantine catalog files are protected"
        )
    if (
        os.path.normcase(str(target)) != os.path.normcase(str(resolved))
        or not resolved.is_file()
    ):
        raise PermissionError("File must be canonical and regular")
    roots = settings.get("file_roots", [])
    if not isinstance(roots, list) or not 1 <= len(roots) <= 16:
        raise PermissionError("No local deletion roots configured")
    for value in roots:
        root = Path(value)
        _no_links(root)
        root = root.resolve(strict=True)
        marker = root / MARKER
        if root == root.parent or not marker.is_file():
            continue
        _no_links(marker)
        if (
            marker.stat().st_size <= 64
            and marker.read_text(encoding="utf-8") == MARKER_TEXT
            and resolved.is_relative_to(root)
            and resolved != marker
        ):
            if os.name != "nt":
                # A directory writable by another identity cannot safely support
                # name-based unlink. Require operator-owned private directories.
                for directory in (resolved.parent, *resolved.parent.parents):
                    if not directory.is_relative_to(root):
                        break
                    info = directory.stat()
                    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                        raise PermissionError(
                            "Deletion directories must be owned by this service and not writable by group/other"
                        )
            return resolved
    raise PermissionError("File is outside a locally marked deletion root")


def _win_delete(path, expected, destination=None):
    kernel, types = _windows()
    kernel.CreateFileW.argtypes = (
        types.LPCWSTR,
        types.DWORD,
        types.DWORD,
        ctypes.c_void_p,
        types.DWORD,
        types.DWORD,
        types.HANDLE,
    )
    kernel.CreateFileW.restype = types.HANDLE
    kernel.ReadFile.argtypes = (
        types.HANDLE,
        ctypes.c_void_p,
        types.DWORD,
        ctypes.POINTER(types.DWORD),
        ctypes.c_void_p,
    )
    kernel.GetFinalPathNameByHandleW.argtypes = (
        types.HANDLE,
        types.LPWSTR,
        types.DWORD,
        types.DWORD,
    )
    kernel.SetFileInformationByHandle.argtypes = (
        types.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        types.DWORD,
    )

    class Info(ctypes.Structure):
        _fields_ = [
            ("attributes", types.DWORD),
            ("created", types.FILETIME),
            ("access", types.FILETIME),
            ("written", types.FILETIME),
            ("volume", types.DWORD),
            ("size_high", types.DWORD),
            ("size_low", types.DWORD),
            ("links", types.DWORD),
            ("index_high", types.DWORD),
            ("index_low", types.DWORD),
        ]

    kernel.GetFileInformationByHandle.argtypes = (types.HANDLE, ctypes.POINTER(Info))
    handle = kernel.CreateFileW(
        str(path), 0x80000000 | 0x10000, 0, None, 3, 0x00200000, None
    )
    if handle in (None, ctypes.c_void_p(-1).value):
        raise OSError("File cannot be exclusively opened for verified deletion")
    try:
        info, final = Info(), ctypes.create_unicode_buffer(32768)
        if (
            not kernel.GetFileInformationByHandle(handle, ctypes.byref(info))
            or info.attributes & (0x400 | 0x10)
            or info.links != 1
            or (info.size_high << 32) | info.size_low > MAX_FILE
        ):
            raise PermissionError(
                "File is nonregular, linked, reparse or exceeds 64 MiB"
            )
        length = kernel.GetFinalPathNameByHandleW(handle, final, 32768, 0)
        if not 0 < length < 32768 or os.path.normcase(
            final.value.removeprefix("\\\\?\\")
        ) != os.path.normcase(str(path)):
            raise PermissionError("Opened file does not match canonical target")
        digest, read, buffer = (
            hashlib.sha256(),
            types.DWORD(),
            ctypes.create_string_buffer(65536),
        )
        deadline = time.monotonic() + 3
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError("File verification deadline exceeded")
            if not kernel.ReadFile(handle, buffer, 65536, ctypes.byref(read), None):
                raise OSError("File hashing failed")
            if not read.value:
                break
            digest.update(buffer.raw[: read.value])
        if not hmac.compare_digest(digest.hexdigest(), expected):
            raise PermissionError("File SHA256 changed; deletion refused")
        # FILE_DISPOSITION_INFO_EX: remove this verified name immediately.
        # Legacy delete-pending can leave a name visible while another hardlink
        # had recently existed, so do not claim confirmed removal from it.
        if destination is None:
            disposition = types.DWORD(0x1 | 0x2)
            if not kernel.SetFileInformationByHandle(
                handle, 21, ctypes.byref(disposition), ctypes.sizeof(disposition)
            ):
                raise OSError("Kernel rejected verified handle deletion")
        else:
            # FILE_RENAME_INFO pins the verified file; ReplaceIfExists is false.
            name = str(destination)

            class Rename(ctypes.Structure):
                _fields_ = [
                    ("replace", types.BOOL),
                    ("root", types.HANDLE),
                    ("length", types.DWORD),
                    ("name", ctypes.c_wchar * (len(name) + 1)),
                ]

            rename = Rename(False, None, len(name.encode("utf-16-le")), name)
            if not kernel.SetFileInformationByHandle(
                handle, 3, ctypes.byref(rename), ctypes.sizeof(rename)
            ):
                raise OSError("Kernel rejected verified handle rename")
    finally:
        kernel.CloseHandle(handle)


class EffectUnconfirmedError(OSError):
    """A partial OS effect could not be reversed; never represent nonexecution."""


def _linux_delete(path, expected):
    # Directory FD pins the parent. A private sibling name claims the actual
    # object before hashing; mismatches are preserved and restored if possible.
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    claimed = ".lumina-response-" + uuid.uuid4().hex
    moved = False
    try:
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > MAX_FILE
        ):
            raise PermissionError("File is nonregular, linked or exceeds 64 MiB")
        os.rename(path.name, claimed, src_dir_fd=parent, dst_dir_fd=parent)
        moved = True
        fd = os.open(claimed, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            actual = os.fstat(fd)
            if (
                (actual.st_dev, actual.st_ino) != (before.st_dev, before.st_ino)
                or not stat.S_ISREG(actual.st_mode)
                or actual.st_nlink != 1
            ):
                raise PermissionError("File identity changed; deletion refused")
            digest, deadline = hashlib.sha256(), time.monotonic() + 3
            while True:
                if time.monotonic() > deadline:
                    raise TimeoutError("File verification deadline exceeded")
                block = os.read(fd, 65536)
                if not block:
                    break
                digest.update(block)
            final = os.fstat(fd)
            if (
                final.st_size != actual.st_size
                or final.st_mtime_ns != actual.st_mtime_ns
                or not hmac.compare_digest(digest.hexdigest(), expected)
            ):
                raise PermissionError("File content changed; deletion refused")
            named = os.stat(claimed, dir_fd=parent, follow_symlinks=False)
            if (named.st_dev, named.st_ino) != (actual.st_dev, actual.st_ino):
                raise PermissionError("Claimed file changed; deletion refused")
            os.unlink(claimed, dir_fd=parent)
            moved = False
        finally:
            os.close(fd)
    finally:
        recovery_failure = None
        if moved:
            # Never overwrite a concurrently created original path.
            try:
                os.link(
                    claimed,
                    path.name,
                    src_dir_fd=parent,
                    dst_dir_fd=parent,
                    follow_symlinks=False,
                )
                os.unlink(claimed, dir_fd=parent)
            except OSError:
                recovery_failure = EffectUnconfirmedError(
                    "File was claimed but original-name restoration could not be confirmed. Inspect preserved recovery object: "
                    + str(path.parent / claimed)[:1500]
                )
        os.close(parent)
        if recovery_failure is not None:
            raise recovery_failure from None


def execute(target, host, settings):
    kind = target.get("type")
    if not isinstance(settings, dict) or settings.get("enabled") is not True:
        return _outcome(
            kind,
            "local_response_disabled",
            "Local operator has not enabled endpoint response",
        )
    try:
        if kind in {
            "inspect_process",
            "inspect_file",
            "collect_artifact",
            "quarantine_file",
            "restore_file",
            "isolate_host",
            "release_host",
        }:
            from . import operations

            if kind.startswith("inspect_") or kind == "collect_artifact":
                return operations.investigate(target, host, settings)
            if kind == "quarantine_file":
                return operations.quarantine(target, settings)
            if kind == "restore_file":
                return operations.restore(target, settings)
            return operations.isolate(target, settings)
        if (
            kind == "terminate_process"
            and settings.get("allow_process_termination") is True
        ):
            return terminate(target, host, settings)
        if kind == "delete_file" and settings.get("allow_file_delete") is True:
            path = _file_target(target["path"], settings)
            if path == Path(__file__).resolve() or path.is_relative_to(
                Path(__file__).resolve().parent.parent
            ):
                raise PermissionError("Agent installation/state files are protected")
            (_win_delete if os.name == "nt" else _linux_delete)(path, target["sha256"])
            if path.exists():
                return _outcome(
                    kind,
                    "effect_unconfirmed",
                    "Verified deletion requested but target name is still present or has been recreated",
                    executed=None,
                )
            return _outcome(
                kind,
                "deleted",
                "Verified regular file removed; deletion is not reversible by this agent",
                success=True,
                executed=True,
            )
        return _outcome(
            kind, "local_action_disabled", "This typed action is not locally enabled"
        )
    except EffectUnconfirmedError as exc:
        outcome = _outcome(kind, "effect_unconfirmed", str(exc), executed=None)
        if isinstance(getattr(exc, "data", None), dict):
            outcome["data"] = exc.data
        return outcome
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
        return _outcome(kind, "target_rejected", type(exc).__name__ + ": " + str(exc))


class Ledger:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.db = sqlite3.connect(self.directory / "response.sqlite3", timeout=1)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS executions(id TEXT PRIMARY KEY,digest TEXT NOT NULL,execution_id TEXT NOT NULL,lease TEXT NOT NULL,kind TEXT NOT NULL,state TEXT NOT NULL,result TEXT,reported INTEGER NOT NULL DEFAULT 0)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS execution_transport(id TEXT PRIMARY KEY,expires REAL NOT NULL,artifact_offset INTEGER NOT NULL DEFAULT 0,artifact_server_id TEXT)"
        )
        for row in self.db.execute(
            "SELECT * FROM executions WHERE state='executing'"
        ).fetchall():
            outcome = _outcome(
                row["kind"],
                "unknown_after_restart",
                "Execution marker exists without final receipt; OS effect is unknown and will not replay",
                executed=None,
            )
            self.db.execute(
                "UPDATE executions SET state='unknown',result=? WHERE id=?",
                (canonical(outcome), row["id"]),
            )
        self.db.commit()

    def close(self):
        self.db.close()

    def pending(self):
        return self.db.execute(
            "SELECT e.*,t.expires,coalesce(t.artifact_offset,0) AS artifact_offset,t.artifact_server_id FROM executions e LEFT JOIN execution_transport t ON t.id=e.id WHERE e.reported=0 AND e.result IS NOT NULL LIMIT 32"
        ).fetchall()

    def report(self, agent, budget=10):
        deadline = time.monotonic() + budget
        for row in self.pending():
            stopped = getattr(agent, "stop", None)
            if time.monotonic() >= deadline or (
                stopped is not None and stopped.is_set()
            ):
                break
            outcome = json.loads(row["result"])
            if row["kind"] == "inspect_process" and outcome["success"] and outcome.get("data", {}).get("publish_process_evidence") is True:
                if row["expires"] is None or row["expires"] <= time.time():
                    outcome = _outcome("inspect_process", "process_evidence_admission_unknown", "Inspection completed but its new original was not confirmed before command expiry")
                    outcome["data"] = {"source_response_command_id": row["id"], "transfer_state": "unknown"}
                else:
                    outcome = self.publish_process_evidence(agent, row, outcome)
                with self.db:
                    self.db.execute("UPDATE executions SET result=? WHERE id=?", (canonical(outcome), row["id"]))
            if (
                row["kind"] == "collect_artifact"
                and outcome["success"]
                and not outcome.get("data", {}).get("server_artifact_id")
            ):
                if row["expires"] is None or row["expires"] <= time.time():
                    outcome = _outcome(
                        "collect_artifact",
                        "artifact_transfer_unknown",
                        "Local collection completed but remote transfer did not complete before command expiry",
                    )
                    outcome["data"] = {"transfer_state": "unknown"}
                else:
                    outcome = self.upload_artifact(agent, row, outcome, deadline)
                with self.db:
                    self.db.execute(
                        "UPDATE executions SET result=? WHERE id=?",
                        (canonical(outcome), row["id"]),
                    )
            if time.monotonic() >= deadline or (
                stopped is not None and stopped.is_set()
            ):
                break
            agent._post(
                "/api/agent/result",
                {
                    "command_id": row["id"],
                    "lease_token": row["lease"],
                    "execution_id": row["execution_id"],
                    "result": outcome,
                },
            )
            with self.db:
                self.db.execute(
                    "UPDATE executions SET reported=1 WHERE id=?", (row["id"],)
                )

    def upload_artifact(self, agent, row, outcome, deadline):
        from . import operations

        identifier = outcome.get("data", {}).get("artifact_id", "")
        if (
            not isinstance(identifier, str)
            or len(identifier) != 36
            or not identifier.startswith("ART-")
            or any(c not in "0123456789abcdef" for c in identifier[4:])
        ):
            raise ValueError("Local artifact identity is invalid")
        directory, db = operations._state(agent.config.get("response", {}))
        db.close()
        path = directory / (identifier + ".bin")
        _no_links(path)
        from . import process_artifact
        maximum = process_artifact.limit(agent.config.get("response", {})) if outcome.get("data", {}).get("artifact_kind") == "process_executable" else 2 * 1024 * 1024
        if path.stat().st_size > maximum:
            raise ValueError("Remote artifact transport exceeds the collection byte limit")
        content = path.read_bytes()
        sha = hashlib.sha256(content).hexdigest()
        if sha != outcome["data"]["sha256"] or len(content) != outcome["data"]["bytes"]:
            raise ValueError("Local artifact no longer matches collection receipt")
        if row["artifact_server_id"]:
            outcome["data"]["server_artifact_id"] = row["artifact_server_id"]
            outcome["data"]["transport"] = (
                "complete evidence-bound TLS upload to management server"
            )
            return outcome
        acknowledged = None
        initial_offset = row["artifact_offset"]
        if initial_offset >= len(content) and content:
            initial_offset = max(0, len(content) - 32 * 1024)
        for offset in range(initial_offset, max(1, len(content)), 32 * 1024):
            stopped = getattr(agent, "stop", None)
            if (
                time.time() >= row["expires"]
                or time.monotonic() >= deadline
                or (stopped is not None and stopped.is_set())
            ):
                raise TimeoutError("Artifact transfer lease expired")
            chunk = content[offset : offset + 32 * 1024]
            acknowledged = agent._post(
                "/api/agent/commands/" + row["id"] + "/artifact",
                {
                    "lease_token": row["lease"],
                    "execution_id": row["execution_id"],
                    "offset": offset,
                    "total_bytes": len(content),
                    "sha256": sha,
                    "chunk_sha256": hashlib.sha256(chunk).hexdigest(),
                    "body_base64": base64.b64encode(chunk).decode("ascii"),
                },
            )
            if (
                acknowledged.get("sha256") != sha
                or type(acknowledged.get("received")) is not int
                or acknowledged["received"] < offset + len(chunk)
            ):
                raise ValueError("Artifact transfer acknowledgement mismatch")
            with self.db:
                self.db.execute(
                    "UPDATE execution_transport SET artifact_offset=?,artifact_server_id=? WHERE id=?",
                    (
                        acknowledged["received"],
                        acknowledged.get("artifact_id")
                        if acknowledged.get("complete") is True
                        else None,
                        row["id"],
                    ),
                )
        if (
            not acknowledged
            or acknowledged.get("complete") is not True
            or acknowledged["received"] != len(content)
        ):
            raise ValueError("Artifact transfer did not confirm complete object")
        outcome["data"]["server_artifact_id"] = acknowledged["artifact_id"]
        outcome["data"]["transport"] = (
            "complete evidence-bound TLS upload to management server"
        )
        return outcome

    def publish_process_evidence(self, agent, row, outcome):
        """An explicit inspection emits a new original; never edits the old one."""
        result = outcome["data"]
        if "process_evidence_record" not in result:
            identifier = "process-image-" + hashlib.sha256(canonical([row["id"], result["pid"], result["start_identity"], result["sha256"], result["file_identity"]]).encode()).hexdigest()
            record = {"id": identifier, "data": {"@timestamp": datetime.now(timezone.utc).isoformat(),
                "host": {"id": agent.identity["host"], "os": {"type": "windows" if os.name == "nt" else "linux"}},
                "process": {"pid": result["pid"], "guid": result["guid"], "start_identity": result["start_identity"],
                    "name": Path(result["executable"]).name, "executable": result["executable"], "hash": {"sha256": result["sha256"]},
                    "executable_evidence": {"bytes": result["bytes"], "file_identity": result["file_identity"], "observation": result["observation"]}},
                "event": {"module": "process_artifact", "action": "process_image_observed"},
                "agent": {"collector": "explicit_process_executable_inspection", "source_response_command_id": row["id"],
                    "process_response_eligible": True, "process_identity_kind": "live_creation_identity_and_stable_disk_hash"}}}
            result["process_evidence_record"] = record
            # Persist the exact event timestamp/body before admission for stable retries.
            with self.db:
                self.db.execute("UPDATE executions SET result=? WHERE id=?", (canonical(outcome), row["id"]))
        record = result["process_evidence_record"]
        reply = agent._post("/api/agent/ingest", {"events": [record]})
        if reply.get("durable") is not True or reply.get("accepted", 0) + reply.get("duplicate", 0) != 1 or len(reply.get("results", [])) != 1 or reply["results"][0].get("id") != record["id"] or reply["results"][0].get("quarantined") is not False:
            raise ValueError("New process executable evidence was not durably admitted")
        result["process_evidence_event_id"] = hashlib.sha256(canonical(["aegis.endpoint.v1", agent.identity["host"], record["id"]]).encode()).hexdigest()
        result["process_evidence_source_id"] = record["id"]
        result["source_response_command_id"] = row["id"]
        result["publish_process_evidence"] = False
        return outcome

    def handle(self, agent, delivery):
        command, signature = delivery.get("command"), delivery.get("signature")
        if not command:
            return None
        if not isinstance(command, dict) or set(command) != {
            "id",
            "agent_id",
            "tenant",
            "host",
            "index",
            "incident_id",
            "case_version",
            "action",
            "expires_at",
            "lease_until",
            "lease_token",
        }:
            raise ValueError("Unsupported response envelope")
        expected = hmac.new(
            agent.identity["credential"].encode("ascii"),
            canonical(command).encode(),
            hashlib.sha256,
        ).hexdigest()
        if (
            not isinstance(signature, str)
            or not hmac.compare_digest(
                signature.encode("utf-8"), expected.encode("ascii")
            )
            or any(
                command[key] != agent.identity[key]
                for key in ("agent_id", "tenant", "host")
            )
            or command["index"] != agent.config.get("index")
            or min(command["expires_at"], command["lease_until"]) <= time.time()
        ):
            raise PermissionError("Response signature, agent binding or expiry invalid")
        digest = hashlib.sha256(
            canonical(
                {
                    key: value
                    for key, value in command.items()
                    if key not in ("lease_token", "lease_until")
                }
            ).encode()
        ).hexdigest()
        with self.db:
            row = self.db.execute(
                "SELECT * FROM executions WHERE id=?", (command["id"],)
            ).fetchone()
            if row and row["digest"] != digest:
                raise ValueError("Conflicting durable command identity")
            if row and row["state"] != "prepared":
                self.report(agent)
                return command["id"]
            if not row:
                # Permanent execution/investigation history has no lifetime count ceiling.
                self.db.execute(
                    "INSERT INTO executions(id,digest,execution_id,lease,kind,state) VALUES(?,?,?,?,?,'prepared')",
                    (
                        command["id"],
                        digest,
                        uuid.uuid4().hex,
                        command["lease_token"],
                        command["action"]["type"],
                    ),
                )
            self.db.execute(
                "INSERT OR IGNORE INTO execution_transport(id,expires) VALUES(?,?)",
                (command["id"], command["expires_at"]),
            )
            row = self.db.execute(
                "SELECT * FROM executions WHERE id=?", (command["id"],)
            ).fetchone()
        ack = agent._post(
            "/api/agent/ack",
            {
                "command_id": command["id"],
                "lease_token": command["lease_token"],
                "execution_id": row["execution_id"],
            },
        )
        if not ack.get("execute"):
            with self.db:
                self.db.execute(
                    "UPDATE executions SET state='declined',reported=1 WHERE id=?",
                    (command["id"],),
                )
            return command["id"]
        if (
            ack.get("command_id") != command["id"]
            or ack.get("execution_id") != row["execution_id"]
            or ack.get("execute_until", 0) <= time.time()
        ):
            raise PermissionError("Execution ACK binding/expiry invalid")
        stopped = getattr(agent, "stop", None)
        if stopped is not None and stopped.is_set():
            outcome = _outcome(
                command["action"]["type"],
                "stopped_before_effect",
                "Agent stopped after ACK; no OS effect was attempted",
            )
            with self.db:
                self.db.execute(
                    "UPDATE executions SET state='complete',result=?,lease=? WHERE id=?",
                    (canonical(outcome), command["lease_token"], command["id"]),
                )
            return command["id"]
        with self.db:
            changed = self.db.execute(
                "UPDATE executions SET state='executing',lease=? WHERE id=? AND state='prepared'",
                (command["lease_token"], command["id"]),
            ).rowcount
        if changed != 1:
            raise RuntimeError("Command already has an execution marker")
        settings = dict(agent.config.get("response", {}))
        settings["_agent_state_dir"] = agent.config.get("state_dir", "")
        # Only this in-process adapter supplies the authenticated management
        # probe. A command/config JSON cannot fabricate the callback.
        settings["_management_probe"] = lambda: agent._post(
            "/api/agent/heartbeat", {"health": {"response": capabilities(agent.config)}}
        )
        outcome = execute(command["action"], command["host"], settings)
        with self.db:
            self.db.execute(
                "UPDATE executions SET state='complete',result=? WHERE id=?",
                (canonical(outcome), command["id"]),
            )
        self.report(agent)
        return command["id"]


def capabilities(config):
    settings = config.get("response", {})
    enabled = isinstance(settings, dict) and settings.get("enabled") is True
    actions = []
    if enabled and settings.get("allow_process_termination") is True:
        actions.append("terminate_process")
    if enabled and settings.get("allow_file_delete") is True:
        actions.append("delete_file")
    if enabled and settings.get("allow_investigation") is True:
        actions.extend(["inspect_process", "inspect_file", "collect_artifact"])
    if enabled and settings.get("allow_quarantine") is True:
        actions.append("quarantine_file")
    if enabled and settings.get("allow_restore") is True:
        actions.append("restore_file")
    management_digest = None
    isolation_error = None
    if enabled and settings.get("allow_host_isolation") is True:
        from . import operations

        try:
            # A newly unsupported apply path must not hide exact removal of an
            # older owned receipt. Release retains the same canonical binding.
            _, management_digest = operations.network_definition(
                settings, for_release=True
            )
            try:
                operations.network_definition(settings)
            except (ValueError, PermissionError, TypeError) as error:
                isolation_error = str(error)[:500]
                actions.append("release_host")
            else:
                actions.extend(["isolate_host", "release_host"])
        except (ValueError, PermissionError, TypeError) as error:
            isolation_error = str(error)[:500]
    return {
        "enabled": enabled,
        "actions": actions,
        "process_artifact_collection": {"enabled": enabled and settings.get("allow_investigation") is True and settings.get("allow_process_artifact_collection") is True,
            "maximum_bytes": settings.get("max_process_artifact_bytes", 32 * 1024 * 1024),
            "preparation": "explicit inspect_process capture creates a new original; no automatic hash enrichment"},
        "management_allowlist_digest": management_digest,
        "host_isolation_apply_supported": "isolate_host" in actions,
        "host_isolation_apply_error": isolation_error,
        "semantics": "locally opted-in typed effects; no arbitrary shell or permanent execution block",
    }


class Lock:
    """Cross-process exclusive poll/execution lock; never recovers a live marker."""

    def __init__(self, directory):
        self.path = Path(directory) / "response.lock"
        self.file = None

    def __enter__(self):
        self.file = self.path.open("a+b")
        try:
            if os.name == "nt":
                import msvcrt

                self.file.seek(0)
                if not self.file.read(1):
                    self.file.write(b"0")
                    self.file.flush()
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.file.close()
            self.file = None
            raise RuntimeError(
                "Another response poll/execution owns this state directory"
            ) from None
        return self

    def __exit__(self, *args):
        if self.file:
            self.file.close()  # Closing releases both Windows and POSIX locks.


def poll(agent):
    """Report durable receipts first, then claim/ACK one signed typed command."""
    if not isinstance(getattr(agent, "config", None), dict) or not agent.config.get(
        "state_dir"
    ):
        raise RuntimeError(
            "Endpoint response disabled without a protected configured state directory"
        )
    with Lock(agent.config["state_dir"]):
        ledger = Ledger(agent.config["state_dir"])
        try:
            ledger.report(agent)
            stopped = getattr(agent, "stop", None)
            if stopped is not None and stopped.is_set():
                return None
            delivery = agent._post("/api/agent/poll", {})
            return ledger.handle(agent, delivery)
        finally:
            ledger.close()
