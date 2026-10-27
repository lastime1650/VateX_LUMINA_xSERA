import subprocess
import sys
import time

import pytest

from sapientia.backup import backup, restore
from sapientia.query import Query, QueryError
from sapientia.runtime import run_due, save_rule
from sapientia.storage import Settings, Store


_CRASH_DISK_MODEL = """import os,sys,shutil
from pathlib import Path
owned_test_root=Path(sys.argv[1]).resolve()
real_disk_usage=shutil.disk_usage
def isolated_disk_usage(path):
    measured=real_disk_usage(path)
    if Path(path).resolve().is_relative_to(owned_test_root):
        return type(measured)(10*1024**4,2*1024**4,8*1024**4)
    return measured
shutil.disk_usage=isolated_disk_usage
"""


def test_nested_vendor_fields(tmp_path):
    s = Store(Settings(tmp_path, min_free_bytes=0))
    try:
        s.ingest(
            "a",
            [{"event_id": "1", "raw": {"network": {"port": 443}, "vendor": "Acme"}}],
        )
        s.flush()
        result = s.search(
            "a",
            {
                "language": "json",
                "query": {
                    "filters": [
                        {"field": "raw.network.port", "op": "gte", "value": 80}
                    ],
                    "fields": ["raw.vendor", "raw.network.port"],
                },
            },
        )
        assert result["rows"] == [{"raw.vendor": "Acme", "raw.network.port": "443"}]
        result = s.search(
            "a", {"query": "search raw.vendor=Acme | stats count by raw.vendor"}
        )
        assert result["rows"] == [{"raw.vendor": "Acme", "count": 1}]
    finally:
        s.close()


@pytest.mark.parametrize(
    "field",
    [
        "raw.x'); DROP TABLE events;--",
        "raw.$",
        "raw.*",
        "raw.a[0]",
        "raw.a.b.c.d.e.f.g.h.i",
        None,
        [],
    ],
)
def test_vendor_path_rejection(field):
    with pytest.raises(QueryError):
        Query.parse({"language": "json", "query": {"fields": [field]}})


def test_result_size_bound(tmp_path):
    s = Store(Settings(tmp_path, min_free_bytes=0))
    try:
        s.ingest("a", [{"event_id": str(i), "message": "x" * 30000} for i in range(80)])
        s.flush()
        with pytest.raises(ValueError, match="2 MiB"):
            s.search("a", {"query": "*", "limit": 100})
    finally:
        s.close()


def test_pending_events_defer_scheduler(tmp_path):
    s = Store(Settings(tmp_path, min_free_bytes=0))
    try:
        from sapientia.auth import create_user
        create_user(s, "analyst", "Testing-only-password-2026", "analyst", "a")
        s.ingest("a", [{"event_id": "1", "severity": "high"}])
        rid = save_rule(
            s,
            {"name": "analyst", "tenant": "a", "role": "analyst", "allowed_indexes": ["*"]},
            {"name": "rule", "query": {"query": "severity=high"}},
        )
        assert run_due(s, time.time() + 1) == 0
        with s.control() as db:
            assert (
                db.execute("SELECT last_end FROM rules WHERE id=?", (rid,)).fetchone()[
                    0
                ]
                is None
            )
        s.flush()
        with s.control() as db:
            retry_at = db.execute("SELECT retry_at FROM rule_execution WHERE rule_id=?", (rid,)).fetchone()[0]
        assert run_due(s, retry_at + 0.1) == 1
    finally:
        s.close()


def test_backup_restore_pending_and_indexed(tmp_path):
    src = tmp_path / "data"
    s = Store(Settings(src, min_free_bytes=0))
    s.ingest("a", [{"event_id": "indexed"}])
    s.flush()
    s.ingest("a", [{"event_id": "pending"}])
    with pytest.raises(RuntimeError):
        backup(src, tmp_path / "blocked")
    s.close()
    manifest = backup(src, tmp_path / "snapshot")
    assert len(manifest["sha256"]) == 2
    restored = tmp_path / "restored"
    restore(tmp_path / "snapshot", restored)
    s = Store(Settings(restored, min_free_bytes=0))
    try:
        assert s.health("a")["indexed"] == 1 and s.health("a")["pending"] == 1
        s.flush()
        assert s.health("a")["indexed"] == 2
    finally:
        s.close()
    with pytest.raises(ValueError):
        restore(tmp_path / "snapshot", restored)


def test_backup_tamper_rejected(tmp_path):
    src = tmp_path / "data"
    s = Store(Settings(src, min_free_bytes=0))
    s.close()
    backup(src, tmp_path / "snapshot")
    with (tmp_path / "snapshot" / "events.duckdb").open("ab") as f:
        f.write(b"corruption")
    with pytest.raises(ValueError, match="checksum"):
        restore(tmp_path / "snapshot", tmp_path / "new")
    assert not (tmp_path / "new").exists()


def test_abrupt_process_exit_queue_recovery(tmp_path):
    script = _CRASH_DISK_MODEL + """from sapientia.storage import Store,Settings
s=Store(Settings(Path(sys.argv[1]),min_free_bytes=0))
s.ingest('a',[{'event_id':'abrupt'}])
os._exit(23)
"""
    run = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)], capture_output=True, timeout=20
    )
    assert run.returncode == 23, run.stderr.decode()
    s = Store(Settings(tmp_path, min_free_bytes=0))
    try:
        assert s.health("a")["pending"] == 1
        s.flush()
        assert s.health("a")["indexed"] == 1
    finally:
        s.close()


def test_abrupt_exit_between_stores(tmp_path):
    script = _CRASH_DISK_MODEL + """from sapientia.storage import Store,Settings
s=Store(Settings(Path(sys.argv[1]),min_free_bytes=0))
s.ingest('a',[{'event_id':'abrupt'}])
s.flush(after_commit=lambda:os._exit(24))
"""
    run = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)], capture_output=True, timeout=20
    )
    assert run.returncode == 24, run.stderr.decode()
    s = Store(Settings(tmp_path, min_free_bytes=0))
    try:
        assert s.health("a")["pending"] == 1 and s.health("a")["indexed"] == 1
        s.flush()
        assert s.health("a")["indexed"] == 1 and s.health("a")["pending"] == 0
    finally:
        s.close()


def test_connector_checkpoint_cannot_overwrite_input(tmp_path):
    source = tmp_path / "input.ndjson"
    original = '{"message":"retain this original"}\n'
    source.write_text(original, encoding="utf-8")
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "sapientia.connectors",
            str(source),
            "--source",
            "test",
            "--checkpoint",
            str(source),
        ],
        capture_output=True,
        timeout=20,
    )
    assert run.returncode == 2
    assert "must not overwrite" in run.stderr.decode()
    assert source.read_text(encoding="utf-8") == original
