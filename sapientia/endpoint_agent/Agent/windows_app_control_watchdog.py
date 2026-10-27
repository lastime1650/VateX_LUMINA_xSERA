"""Independent bounded rollback for one newly created xSERA App Control policy.

This file deliberately uses only the standard library and accepts a private
lease plan, never a shell command or a caller-selected executable. Parent death
does not terminate the watchdog. OS reboot/power loss is a separate limitation.
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path


def atomic_json(path, value):
    path = Path(path)
    temp = path.with_suffix(path.suffix + ".new")
    with temp.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def no_links(path):
    for item in (path, *path.parents):
        info = item.lstat()
        if item.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
            raise PermissionError("Lease paths may not contain links or reparse points")


def system_citool():
    if os.name != "nt":
        raise OSError("The App Control rollback watchdog requires Windows")
    buffer = ctypes.create_unicode_buffer(32768)
    library = ctypes.WinDLL("kernel32", use_last_error=True)
    function = library.GetSystemDirectoryW
    function.argtypes, function.restype = (
        [ctypes.c_wchar_p, ctypes.c_uint],
        ctypes.c_uint,
    )
    length = function(buffer, len(buffer))
    if not 0 < length < len(buffer):
        raise OSError("Unable to find the native Windows system directory")
    path = Path(buffer.value) / "CiTool.exe"
    no_links(path)
    if not path.is_file():
        raise OSError("Native CiTool is unavailable")
    return path


def policy_guid(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}",
        value,
    ):
        raise ValueError("One exact App Control policy GUID required")
    return value.upper()


def load_plan(filename):
    path = Path(filename)
    if not path.is_absolute():
        raise ValueError("Private absolute lease plan required")
    no_links(path)
    if path.stat().st_size > 8192:
        raise ValueError("Lease plan exceeds its size limit")
    plan = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(plan, dict)
        or set(plan) != {"schema", "policy_id", "nonce", "lease_seconds", "directory"}
        or plan["schema"] != "vatex.appcontrol.lease.v1"
    ):
        raise ValueError("Invalid lease plan")
    if not isinstance(plan["nonce"], str) or not re.fullmatch(
        r"[0-9a-f]{64}", plan["nonce"]
    ):
        raise ValueError("Invalid lease nonce")
    if type(plan["lease_seconds"]) is not int or not 30 <= plan["lease_seconds"] <= 300:
        raise ValueError("Rollback lease must be 30..300 seconds")
    if (
        not isinstance(plan["directory"], str)
        or Path(plan["directory"]) != path.parent
        or not path.parent.name.startswith("appcontrol-lease-")
    ):
        raise ValueError("Lease directory binding mismatch")
    plan["policy_id"] = policy_guid(plan["policy_id"])
    return plan, path.parent


def _run(citool, arguments):
    process = subprocess.run(
        [str(citool), *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
        check=False,
        shell=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if len(process.stdout) + len(process.stderr) > 2 * 1024 * 1024:
        raise RuntimeError("CiTool output exceeded its bound")
    return process


def _absent(citool, identifier):
    process = _run(citool, ["--list-policies", "-json"])
    if process.returncode:
        raise OSError("Unable to confirm the App Control policy inventory")
    inventory = json.loads(process.stdout)
    policies = inventory.get("Policies")
    if not isinstance(policies, list):
        raise TypeError("Unexpected CiTool inventory")
    expected = identifier.strip("{}").casefold()
    return not any(
        str(item.get("PolicyID", "")).strip("{}").casefold() == expected
        for item in policies
    )


def rollback(citool, identifier):
    """Only this GUID is removed; no policy directories or registry trees deleted."""
    identifier = policy_guid(identifier)
    last = None
    for _ in range(3):
        try:
            inventory = _run(citool, ["--list-policies", "-json"])
            if inventory.returncode:
                raise OSError("Unable to fence the App Control rollback inventory")
            policies = json.loads(inventory.stdout).get("Policies")
            if not isinstance(policies, list):
                raise TypeError("Unexpected rollback inventory")
            existing = [
                row
                for row in policies
                if str(row.get("PolicyID", "")).strip("{}").casefold()
                == identifier.strip("{}").casefold()
            ]
            if not existing:
                return {
                    "removed": True,
                    "policy_id": identifier,
                    "already_absent": True,
                }
            if (
                len(existing) != 1
                or existing[0].get("FriendlyName") != "Vatex LUMINA xSERA " + identifier
            ):
                return {
                    "removed": False,
                    "policy_id": identifier,
                    "error": "Policy ownership name differs; refusing to remove an unrelated policy",
                }
            _run(citool, ["--remove-policy", identifier, "-json"])
            _run(citool, ["--refresh", "-json"])
            if _absent(citool, identifier):
                return {"removed": True, "policy_id": identifier}
            last = "Policy is still listed after removal"
        except (
            OSError,
            ValueError,
            TypeError,
            RuntimeError,
            subprocess.TimeoutExpired,
        ) as error:
            last = str(error)[:512]
        time.sleep(0.2)
    return {"removed": False, "policy_id": identifier, "error": last}


def main(filename):
    plan, directory = load_plan(filename)
    citool = system_citool()
    # A monotonic deadline starts before handshake, independent of clock changes.
    started = time.monotonic()
    atomic_json(
        directory / "ready.json",
        {
            "schema": "vatex.appcontrol.watchdog.ready.v1",
            "pid": os.getpid(),
            "nonce": plan["nonce"],
            "policy_id": plan["policy_id"],
            "lease_seconds": plan["lease_seconds"],
        },
    )
    while time.monotonic() - started < plan["lease_seconds"]:
        release = directory / "release.json"
        if release.exists():
            try:
                no_links(release)
                if release.stat().st_size <= 8192:
                    value = json.loads(release.read_text(encoding="utf-8"))
                    if value == {
                        "nonce": plan["nonce"],
                        "policy_id": plan["policy_id"],
                    }:
                        break
            except (OSError, ValueError):
                # Invalid release requests never cancel the monotonic rollback.
                pass
        time.sleep(0.05)
    result = rollback(citool, plan["policy_id"])
    result.update({"nonce": plan["nonce"], "watchdog_pid": os.getpid()})
    atomic_json(directory / "rollback.json", result)
    return 0 if result["removed"] else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("One private lease-plan path is required")
    raise SystemExit(main(sys.argv[1]))
