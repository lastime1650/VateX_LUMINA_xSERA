"""Owned temporary Python-process recovery probes, never production failover.

Tests the actual Store lock, admitted journal, backup/restore and migration
version fence. This is a single-machine active/passive rehearsal; it does not
implement distributed consensus, shared-disk fencing, or production promotion.
"""

import argparse
import json
import os
import secrets
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import closing
from pathlib import Path

from . import auth, backup, record_governance
from .storage import Settings, Store


def _worker(path, ready, stop, expected_locked=False):
    try:
        store = Store(Settings(Path(path), min_free_bytes=0))
    except RuntimeError:
        if expected_locked:
            Path(ready).write_text(
                json.dumps({"writer_refused": True}), encoding="utf-8"
            )
            return 0
        raise
    try:
        if expected_locked:
            raise RuntimeError("Second writer unexpectedly acquired Store")
        with store.control() as db:
            existing = db.execute(
                "SELECT 1 FROM receipts WHERE tenant=? AND event_id=?",
                ("ops-recovery", "owned-durable-event"),
            ).fetchone()
        if not existing:
            store.ingest(
                "ops-recovery",
                [
                    {
                        "event_id": "owned-durable-event",
                        "event_time": time.time(),
                        "message": "Synthetic process recovery sentinel",
                    }
                ],
            )
        store.flush()
        count = store.search("ops-recovery", {"query": "* | stats count"})["rows"][0][
            "count"
        ]
        Path(ready).write_text(
            json.dumps(
                {
                    "pid": os.getpid(),
                    "indexed": count,
                    "pending": store.health("ops-recovery")["pending"],
                }
            ),
            encoding="utf-8",
        )
        deadline = time.monotonic() + 35
        while not Path(stop).exists() and time.monotonic() < deadline:
            time.sleep(0.05)
    finally:
        store.close()
    return 0


def _spawn(root, label, data, *, expected_locked=False):
    ready, stop = root / (label + ".ready.json"), root / (label + ".stop")
    args = [
        sys.executable,
        "-B",
        "-m",
        "sapientia.operational_process_probe",
        "--worker",
        "--data",
        str(data),
        "--ready",
        str(ready),
        "--stop",
        str(stop),
    ]
    if expected_locked:
        args.append("--expected-locked")
    options = {
        "cwd": str(Path(__file__).resolve().parent.parent),
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.PIPE,
    }
    if os.name == "nt":
        options["creationflags"] = subprocess.CREATE_NO_WINDOW
    process = subprocess.Popen(args, **options)
    deadline = time.monotonic() + 20
    while not ready.exists():
        if process.poll() is not None or time.monotonic() >= deadline:
            if process.poll() is None:
                process.terminate()
            _, error = process.communicate(timeout=10)
            raise RuntimeError(
                "Owned recovery worker did not become ready: "
                + error.decode(errors="replace")[-500:]
            )
        time.sleep(0.05)
    return process, ready, stop, json.loads(ready.read_text(encoding="utf-8"))


def _finish(process, stop, *, terminate=False):
    if process.poll() is None:
        if terminate:
            process.terminate()  # Only the Popen object created by this probe.
        else:
            stop.write_text("stop", encoding="ascii")
    try:
        process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=10)


def _seed_owned_store(root, data):
    """Provision a diagnostic reserve only for this run's fresh temporary DB."""
    raw_root = Path(root)
    info = raw_root.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("Recovery fixture root cannot be a link")
    root, data = raw_root.resolve(strict=True), Path(data).resolve()
    if (
        not root.is_dir()
        or root.parent != Path(tempfile.gettempdir()).resolve()
        or not root.name.startswith("xsera-process-recovery-")
        or any(root.iterdir())
        or data != root / "active-store"
        or data.exists()
    ):
        raise ValueError("Recovery reserve requires a new owned temporary Store")
    with closing(Store(Settings(data, min_free_bytes=0))) as store:
        auth.create_user(
            store, "capacity-admin", secrets.token_urlsafe(32), "admin", "default"
        )
        record_governance.configure(
            store,
            {
                "name": "capacity-admin",
                "tenant": "default",
                "role": "admin",
                "allowed_indexes": ["*"],
            },
            {"version": 1, "min_free_percent": 1},
        )


def run():
    checks, children = [], []
    with tempfile.TemporaryDirectory(prefix="xsera-process-recovery-") as temporary:
        root, data = Path(temporary), Path(temporary) / "active-store"
        try:
            _seed_owned_store(root, data)
            active = _spawn(root, "active", data)
            children.append(active)
            contender = _spawn(root, "contender", data, expected_locked=True)
            children.append(contender)
            _finish(contender[0], contender[2])
            if not contender[3].get("writer_refused") or contender[0].returncode != 0:
                raise AssertionError("Actual second-process writer fence failed")
            checks.append(
                {
                    "name": "single_store_split_brain_writer_fence",
                    "passed": True,
                    "simultaneous_processes": 2,
                }
            )
            _finish(active[0], active[2], terminate=True)
            passive = _spawn(root, "passive", data)
            children.append(passive)
            if passive[3]["indexed"] != 1 or passive[3]["pending"] != 0:
                raise AssertionError("Takeover lost or duplicated durable sentinel")
            _finish(passive[0], passive[2])
            checks.append(
                {
                    "name": "owned_active_process_exit_passive_takeover",
                    "passed": True,
                    "unique_originals": 1,
                    "terminated_owned_processes": 1,
                    "automatic_production_failover": False,
                }
            )
            store = Store(Settings(data, min_free_bytes=0))
            try:
                manifest = backup.backup_online(store, root / "snapshot")
            finally:
                store.close()
            # Model an incompatible data migration as an actual future schema
            # record. The genuine startup version fence must reject it.
            with closing(sqlite3.connect(data / "control.sqlite3")) as db:
                db.execute(
                    "INSERT INTO xsera_schema_migrations VALUES(?,?,?,?)",
                    ("ops_incompatible_future_release", 999, "probe-only", time.time()),
                )
                db.commit()
            try:
                candidate = Store(Settings(data, min_free_bytes=0))
            except (RuntimeError, ValueError):
                rejected = True
            else:
                candidate.close()
                rejected = False
            if not rejected:
                raise AssertionError(
                    "Actual incompatible candidate schema was not refused"
                )
            backup.restore(root / "snapshot", root / "rollback-store")
            rollback = _spawn(root, "rollback", root / "rollback-store")
            children.append(rollback)
            _finish(rollback[0], rollback[2])
            if rollback[3]["indexed"] != 1:
                raise AssertionError(
                    "Restored rollback process did not recover sentinel"
                )
            checks.append(
                {
                    "name": "incompatible_schema_candidate_refused_snapshot_rollback",
                    "passed": True,
                    "online_snapshot": manifest["online"],
                    "restored_originals": 1,
                }
            )
            return {
                "schema": "xsera.process-recovery.v1",
                "passed": True,
                "synthetic": True,
                "native_host_effects": 0,
                "fixture_policy": {
                    "min_free_percent": 1,
                    "scope": "new owned temporary Store only",
                    "initialization_process": "parent before actual child startup",
                    "production_default_min_free_percent": record_governance.DEFAULT[
                        "min_free_percent"
                    ],
                },
                "checks": checks,
                "limits": [
                    "Single-machine owned process takeover; no distributed lease, quorum, SAN fencing or real two-server HA certification",
                    "Snapshot data rollback tests startup schema refusal; production software deployment replacement remains an operator-controlled workflow",
                    "No power-loss, physical hardware, Yocto BSP or OS reboot certification",
                ],
            }
        finally:
            for child in reversed(children):
                _finish(child[0], child[2])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--data")
    parser.add_argument("--ready")
    parser.add_argument("--stop")
    parser.add_argument("--expected-locked", action="store_true")
    args = parser.parse_args()
    if not args.worker or not all((args.data, args.ready, args.stop)):
        parser.error("Internal owned-worker arguments required")
    return _worker(args.data, args.ready, args.stop, args.expected_locked)


if __name__ == "__main__":
    raise SystemExit(main())
