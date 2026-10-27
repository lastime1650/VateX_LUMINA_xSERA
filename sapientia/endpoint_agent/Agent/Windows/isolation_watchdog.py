"""Independent finite Windows firewall rollback; removes only its receipt's rules."""

from __future__ import annotations

import argparse
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
from pathlib import Path


def arm(directory, identifier):
    from .. import cli, response

    path = Path(__file__).resolve()
    for candidate in (path, path.parent, path.parent.parent):
        response._no_links(candidate)
        cli._protected(candidate)
    process = subprocess.Popen(
        [
            getattr(sys, "_base_executable", sys.executable),
            "-I",
            "-B",
            str(path),
            "--state-dir",
            str(directory),
            "--isolation-id",
            identifier,
            "--parent-pid",
            str(os.getpid()),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW,
        close_fds=True,
    )
    messages = queue.Queue(maxsize=1)

    def read_ready():
        try:
            messages.put(process.stdout.readline(2049))
        except (OSError, ValueError):
            messages.put(b"")

    reader = threading.Thread(target=read_ready, daemon=True)
    reader.start()
    try:
        body = messages.get(timeout=3)
        if len(body) > 2048 or json.loads(body) != {
            "isolation_id": identifier,
            "ready": True,
            "pid": process.pid,
        }:
            raise PermissionError(
                "Windows rollback guard did not authenticate readiness"
            )
        return process.pid
    except (queue.Empty, ValueError, TypeError, PermissionError):
        process.terminate()
        process.wait(timeout=3)
        raise PermissionError(
            "Windows rollback guard not armed; no firewall effect permitted"
        ) from None
    finally:
        reader.join(timeout=1)
        process.stdout.close()


class ParentProcess:
    """Hold one process incarnation; a reused PID cannot extend isolation."""

    def __init__(self, pid):
        import ctypes
        from ctypes import wintypes

        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.OpenProcess.argtypes = (
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        )
        self.kernel.OpenProcess.restype = wintypes.HANDLE
        self.kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        self.kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
        self.handle = self.kernel.OpenProcess(0x00100000, False, pid)
        if not self.handle:
            raise PermissionError(
                "Cannot hold the rollback parent's process incarnation"
            )

    def alive(self):
        return (
            bool(self.handle) and self.kernel.WaitForSingleObject(self.handle, 0) == 258
        )

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--isolation-id", required=True)
    parser.add_argument("--parent-pid", type=int, required=True)
    args = parser.parse_args(argv)
    if (
        os.name != "nt"
        or not re.fullmatch(r"[0-9a-f]{32}", args.isolation_id)
        or args.parent_pid <= 4
    ):
        raise PermissionError(
            "Windows rollback requires native private receipt identity"
        )
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from Agent import cli, operations, response

    response._no_links(args.state_dir)
    cli._protected(args.state_dir, secret=True)
    _path, db = operations._state({"quarantine_dir": str(args.state_dir)})
    parent = None
    try:
        parent = ParentProcess(args.parent_pid)
        if not parent.alive():
            raise PermissionError("Rollback parent already exited before readiness")
        row = db.execute(
            "SELECT * FROM isolation WHERE id=?", (args.isolation_id,)
        ).fetchone()
        if not row or row["state"] != "preparing" or row["expires"] is None:
            raise PermissionError(
                "Only a prepared finite isolation receipt can arm rollback"
            )
        duration = row["expires"] - time.time()
        if not 0 < duration <= 301:
            raise PermissionError("Windows firewall safety lease exceeds 300 seconds")
        deadline = time.monotonic() + duration
        with db:
            db.execute(
                "UPDATE isolation SET guard_pid=? WHERE id=?",
                (os.getpid(), args.isolation_id),
            )
        print(
            json.dumps(
                {"isolation_id": args.isolation_id, "ready": True, "pid": os.getpid()}
            ),
            flush=True,
        )
        while True:
            row = db.execute(
                "SELECT * FROM isolation WHERE id=?", (args.isolation_id,)
            ).fetchone()
            if not row or row["state"] not in {"preparing", "isolated"}:
                return 0
            if time.monotonic() >= deadline or not parent.alive():
                definition = json.loads(row["definition"])
                if not release_owned(
                    operations, args.isolation_id, definition, args.state_dir
                ):
                    return 1  # Keep the active receipt visible as unconfirmed recovery.
                with db:
                    db.execute(
                        "UPDATE isolation SET state='lease_expired' WHERE id=? AND state IN ('preparing','isolated')",
                        (args.isolation_id,),
                    )
                return 0
            time.sleep(0.25)
    finally:
        if parent:
            parent.close()
        db.close()


def release_owned(
    operations,
    identifier,
    definition,
    directory,
    *,
    clock=time.monotonic,
    pause=time.sleep,
):
    """Bounded retries; a native failure never becomes a successful release."""
    errors = []
    until = clock() + 30
    for _ in range(3):
        if clock() >= until:
            break
        try:
            operations._driver(
                identifier,
                definition,
                release=True,
                deadline=min(until, clock() + 16),
                state_directory=directory,
            )
            return True  # The driver verifies that every owned rule was removed.
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            errors.append(type(error).__name__)
            if clock() < until:
                pause(min(0.1, until - clock()))
    import importlib

    runtime = importlib.import_module(operations.__package__ + ".core")
    runtime.atomic_json(
        Path(directory) / ("rollback-failure-" + identifier + ".json"),
        {
            "isolation_id": identifier,
            "confirmed_removed": False,
            "attempt_errors": errors,
            "total_budget_seconds": 30,
            "at": time.time(),
        },
    )
    return False


if __name__ == "__main__":
    raise SystemExit(main())
