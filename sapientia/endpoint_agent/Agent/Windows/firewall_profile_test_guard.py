"""TEST ONLY: finite exact-profile rollback for an explicitly marked QA run.

The product never imports this module or enables a disabled firewall profile.
The native qualification helper must arm this independent process before its
explicit temporary enable. It restores the original three Enabled bits and
removes only isolation receipts from this unique private QA agent's state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import re
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

PROFILES = {"1", "2", "4"}
PLAN_NAME = "windows-firewall-profile-plan.json"
MAX_ACTIVE_SECONDS = 100
ROLLBACK_RESERVE_SECONDS = 20


def validate(plan):
    expected = {
        "schema",
        "plan_id",
        "root",
        "state_dir",
        "original_profiles",
        "management_definition",
        "management_digest",
        "created",
        "active_seconds",
        "parent_pid",
        "parent_start_identity",
        "guard_sha256",
    }
    if (
        not isinstance(plan, dict)
        or set(plan) != expected
        or plan["schema"] != "xsera.qa-firewall-profile-plan.v1"
    ):
        raise ValueError("Exact test-only firewall plan schema is required")
    if not isinstance(plan["plan_id"], str) or not re.fullmatch(
        r"[0-9a-f]{32}", plan["plan_id"]
    ):
        raise ValueError("Private plan identity must be an exact UUID hex")
    profiles = plan["original_profiles"]
    if (
        not isinstance(profiles, dict)
        or set(profiles) != PROFILES
        or any(type(value) is not bool for value in profiles.values())
    ):
        raise ValueError("All three exact original firewall Enabled bits are required")
    if (
        type(plan["active_seconds"]) is not int
        or not 30 <= plan["active_seconds"] <= MAX_ACTIVE_SECONDS
    ):
        raise ValueError(
            "Active firewall window must be 30..100 seconds with a separate 20-second rollback reserve"
        )
    if (
        type(plan["created"]) not in (int, float)
        or not 0 < plan["created"] <= time.time() + 1
    ):
        raise ValueError("A finite present/past creation clock is required")
    if (
        type(plan["parent_pid"]) is not int
        or plan["parent_pid"] <= 4
        or not isinstance(plan["parent_start_identity"], str)
        or not re.fullmatch(r"windows:[0-9]+", plan["parent_start_identity"])
    ):
        raise ValueError("Exact native parent PID and start incarnation are required")
    for key in ("management_digest", "guard_sha256"):
        if not isinstance(plan[key], str) or not re.fullmatch(
            r"[0-9a-f]{64}", plan[key]
        ):
            raise ValueError(
                "Exact reviewed source and management SHA256 digests are required"
            )
    if not isinstance(plan["root"], str) or not isinstance(plan["state_dir"], str):
        raise ValueError("Exact absolute QA directory strings are required")  # noqa: TRY004 - private JSON plan validation.
    root, state = Path(plan["root"]), Path(plan["state_dir"])
    if (
        not root.is_absolute()
        or not state.is_absolute()
        or not re.fullmatch(r"native-windows-isolation-[0-9a-f]{32}", root.name)
        or state != root / "state" / "quarantine"
    ):
        raise ValueError(
            "Only the unique owned Windows isolation QA root/state is accepted"
        )
    definition = plan["management_definition"]
    if not isinstance(definition, dict) or set(definition) != {
        "allowlist",
        "endpoints",
    }:
        raise ValueError("Exact normalized product management definition required")
    from .. import operations, response

    normalized, digest = operations.network_definition(
        {
            "management_allowlist": definition["allowlist"],
            "management_endpoints": definition["endpoints"],
        }
    )
    if normalized != definition or digest != plan["management_digest"]:
        raise ValueError("Management definition differs from its reviewed digest")
    if hashlib.sha256(response.canonical(definition).encode()).hexdigest() != digest:
        raise ValueError("Management canonical digest is inconsistent")
    operations._windows_rules(
        "0" * 32, definition
    )  # validate four-IP bound without OS effects
    return plan


def protected_plan(path):
    from .. import cli, response

    path = Path(path)
    response._no_links(path)
    if (
        path.name != PLAN_NAME
        or path.stat().st_size > 8192
        or path.stat().st_nlink != 1
    ):
        raise PermissionError("Private bounded ordinary QA plan required")
    cli._protected(path, secret=True)
    plan = validate(json.loads(path.read_text(encoding="utf-8")))
    root = Path(plan["root"])
    if path.parent != root:
        raise PermissionError("Firewall plan is outside its exact owned QA root")
    for item in (
        root,
        Path(plan["state_dir"]),
        Path(__file__).resolve(),
        Path(__file__).resolve().parent,
    ):
        response._no_links(item)
        cli._protected(item, secret=item.is_dir())
    if (root / ".qa-synthetic-only").read_text(encoding="utf-8") != "synthetic-only\n":
        raise PermissionError("Explicit synthetic qualification marker required")
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != plan["guard_sha256"]:
        raise PermissionError("Independent QA guard source changed after review")
    return plan


def _tool():
    return (
        Path(os.environ.get("SystemRoot", "C:/Windows"))
        / "System32/WindowsPowerShell/v1.0/powershell.exe"
    )


def profiles():
    tool = _tool()
    script = "$ErrorActionPreference='Stop'; $p=New-Object -ComObject HNetCfg.FwPolicy2; $v=@{}; foreach($n in @(1,2,4)){$v[[string]$n]=[bool]$p.FirewallEnabled($n)}; [Console]::Write(($v|ConvertTo-Json -Compress))"
    output = subprocess.run(
        [str(tool), "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        check=True,
        timeout=4,
        shell=False,
        env=dict(os.environ, PSModulePath=str(tool.parent / "Modules")),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    ).stdout
    if len(output) > 1024:
        raise PermissionError("Native profile read exceeded its bound")
    result = json.loads(output)
    if (
        not isinstance(result, dict)
        or set(result) != PROFILES
        or any(type(value) is not bool for value in result.values())
    ):
        raise PermissionError("Actual firewall profile Enabled states are unverifiable")
    return result


def set_profiles(values):
    """Explicit TEST caller only; never called by the product isolation driver."""
    if (
        not isinstance(values, dict)
        or set(values) != PROFILES
        or any(type(value) is not bool for value in values.values())
    ):
        raise ValueError("Exact three Enabled boolean states required")
    tool = _tool()
    script = "$ErrorActionPreference='Stop'; $v=$env:LUMINA_QA_PROFILE_VALUES|ConvertFrom-Json; $p=New-Object -ComObject HNetCfg.FwPolicy2; foreach($n in @(1,2,4)){$p.FirewallEnabled($n)=[bool]$v.([string]$n)}"
    subprocess.run(
        [str(tool), "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        check=True,
        timeout=4,
        shell=False,
        env=dict(
            os.environ,
            LUMINA_QA_PROFILE_VALUES=json.dumps(values),
            PSModulePath=str(tool.parent / "Modules"),
        ),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    actual = profiles()
    if actual != values:
        raise PermissionError(
            "Exact firewall profile restoration/enable verification failed"
        )
    return actual


def parent_alive(plan):
    from .. import response

    try:
        return (
            response.inspect_process(plan["parent_pid"], "qa-profile-parent")[
                "start_identity"
            ]
            == plan["parent_start_identity"]
        )
    except (OSError, ValueError, PermissionError):
        return False


def cleanup_owned(plan, deadline):
    from .. import firewall_guard, operations

    path = Path(plan["state_dir"]) / "effects.sqlite3"
    if not path.exists():
        return {"receipt_ids": [], "rules_remaining": 0}
    operations.base._no_links(path)
    if not path.is_file() or path.stat().st_nlink != 1:
        raise PermissionError(
            "Only an ordinary single-link private QA effects database is accepted"
        )
    with sqlite3.connect(path, timeout=1) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute("SELECT * FROM isolation ORDER BY id LIMIT 4").fetchall()
    if len(rows) > 3:
        raise PermissionError(
            "Unique QA agent unexpectedly owns more than three isolation receipts"
        )
    identifiers = []
    for row in rows:
        if (
            not re.fullmatch(r"[0-9a-f]{32}", row["id"])
            or row["digest"] != plan["management_digest"]
            or json.loads(row["definition"]) != plan["management_definition"]
        ):
            raise PermissionError(
                "Unexpected receipt identity/definition; no broad firewall cleanup permitted"
            )
        if time.monotonic() >= deadline:
            raise TimeoutError("Independent firewall cleanup exhausted reserve")
        if firewall_guard._windows_owned(row["id"], deadline=deadline):
            operations._driver(
                row["id"],
                plan["management_definition"],
                release=True,
                deadline=deadline,
                state_directory=Path(plan["state_dir"]),
            )
        firewall_guard.verify_removed_windows(row["id"], deadline=deadline)
        identifiers.append(row["id"])
        with sqlite3.connect(path, timeout=1) as db:
            db.execute(
                "UPDATE isolation SET state='lease_expired' WHERE id=? AND state IN ('preparing','isolated')",
                (row["id"],),
            )
    return {"receipt_ids": identifiers, "rules_remaining": 0}


def restore(plan, reason):
    """Restore profile bits even if exact owned-rule cleanup subsequently fails."""
    result = {
        "schema": "xsera.qa-firewall-profile-rollback.v1",
        "plan_id": plan["plan_id"],
        "reason": reason,
        "passed": False,
        "profiles_restored": False,
        "owned_cleanup_confirmed": False,
    }
    end = time.monotonic() + ROLLBACK_RESERVE_SECONDS
    try:
        result["profiles_after"] = set_profiles(plan["original_profiles"])
        result["profiles_restored"] = True
    except Exception as exc:  # noqa: BLE001 - independent rollback must attempt both repairs.
        result["profile_error"] = type(exc).__name__
    try:
        result["owned_cleanup"] = cleanup_owned(plan, end)
        result["owned_cleanup_confirmed"] = True
    except Exception as exc:  # noqa: BLE001 - preserve an unconfirmed cleanup result.
        result["cleanup_error"] = type(exc).__name__
    result["passed"] = result["profiles_restored"] and result["owned_cleanup_confirmed"]
    result["completed"] = time.time()
    target = Path(plan["root"]) / "firewall-profile-guard-result.json"
    target.write_text(json.dumps(result), encoding="utf-8")
    return result


def arm(path):
    if os.name != "nt":
        raise PermissionError("Native Windows test-only profile guard required")
    plan = protected_plan(path)
    if profiles() != plan["original_profiles"]:
        raise PermissionError("Firewall profile baseline changed before arming")
    process = subprocess.Popen(
        [
            getattr(sys, "_base_executable", sys.executable),
            "-I",
            "-B",
            str(Path(__file__).resolve()),
            "--plan",
            str(path),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW,
        close_fds=True,
    )
    messages = queue.Queue(maxsize=1)
    reader = threading.Thread(
        target=lambda: messages.put(process.stdout.readline(2049)), daemon=True
    )
    reader.start()
    try:
        body = messages.get(timeout=5)
        value = json.loads(body)
        if (
            len(body) > 2048
            or not isinstance(value, dict)
            or type(value.get("ready")) is not bool
            or type(value.get("pid")) is not int
            or type(value.get("max_guard_seconds")) is not int
            or value
            != {
                "ready": True,
                "plan_id": plan["plan_id"],
                "pid": process.pid,
                "max_guard_seconds": plan["active_seconds"] + ROLLBACK_RESERVE_SECONDS,
            }
        ):
            raise PermissionError("Test-only profile rollback handshake mismatch")
        return process
    except (queue.Empty, ValueError, TypeError, PermissionError):
        process.terminate()
        process.wait(timeout=3)
        raise PermissionError(
            "Independent test guard failed readiness; no profile change permitted"
        ) from None
    finally:
        reader.join(timeout=1)
        process.stdout.close()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    args = parser.parse_args(argv)
    if os.name != "nt":
        raise PermissionError("Native Windows test-only guard required")
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    global __package__
    if not __package__:
        __package__ = "Agent.Windows"
    plan = protected_plan(args.plan)
    if profiles() != plan["original_profiles"] or not parent_alive(plan):
        raise PermissionError("Profile guard baseline/parent identity changed")
    deadline = time.monotonic() + plan["active_seconds"]
    print(
        json.dumps(
            {
                "ready": True,
                "plan_id": plan["plan_id"],
                "pid": os.getpid(),
                "max_guard_seconds": plan["active_seconds"] + ROLLBACK_RESERVE_SECONDS,
            }
        ),
        flush=True,
    )
    reason = "guard_failure"
    try:
        while True:
            done = Path(plan["root"]) / "firewall-profile-window-complete.json"
            if done.exists():
                completed = json.loads(done.read_text(encoding="utf-8"))
                if (
                    not isinstance(completed, dict)
                    or completed.get("complete") is not True
                    or completed
                    != {
                        "plan_id": plan["plan_id"],
                        "complete": True,
                    }
                ):
                    raise PermissionError(
                        "Profile completion signal differs from the exact owned plan"
                    )
                reason = "explicit_owned_window_complete"
                break
            if not parent_alive(plan):
                reason = "parent_incarnation_gone"
                break
            if time.monotonic() >= deadline:
                reason = "finite_test_window_expired"
                break
            time.sleep(0.2)
    finally:
        result = restore(plan, reason)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
