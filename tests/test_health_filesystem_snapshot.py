import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from sapientia import auth
from sapientia.api import create_app
from sapientia.storage import Settings, _storage_bytes


class Entry:
    def __init__(self, size=10, mode=stat.S_IFREG, error=None, path=None):
        self.size, self.mode, self.error = size, mode, error
        self.path = str(path or Path.cwd() / "synthetic-entry")

    def is_file(self, **kwargs):
        return stat.S_ISREG(self.mode)

    def is_dir(self, **kwargs):
        return stat.S_ISDIR(self.mode)

    def is_symlink(self):
        return stat.S_ISLNK(self.mode)

    def stat(self, **kwargs):
        if self.error:
            raise self.error
        return SimpleNamespace(st_size=self.size, st_mode=self.mode)


class Scan:
    def __init__(self, entries):
        self.entries = entries

    def __enter__(self):
        return iter(self.entries)

    def __exit__(self, *args):
        pass


def test_health_survives_wal_disappearing_during_size_snapshot(monkeypatch, tmp_path):
    app = create_app(Settings(tmp_path / "data", min_free_bytes=0), background=False)
    with TestClient(app) as client:
        auth.create_user(app.state.store, "admin", "Testing-only-password-2026")
        assert (
            client.post(
                "/api/login",
                json={"name": "admin", "password": "Testing-only-password-2026"},
            ).status_code
            == 200
        )
        directory = app.state.store.path
        entries = [
            Entry(path=directory / "control.sqlite3"),
            Entry(error=FileNotFoundError("synthetic vanished WAL"), path=directory / "control.sqlite3-wal"),
            Entry(size=3000, mode=stat.S_IFDIR, path=directory / "nested"),
            Entry(size=5000, mode=stat.S_IFLNK, path=directory / "link"),
        ]
        original_iterdir, original_scandir = Path.iterdir, os.scandir
        monkeypatch.setattr(
            Path,
            "iterdir",
            lambda path: iter(entries) if path == directory else original_iterdir(path),
        )
        monkeypatch.setattr(
            os,
            "scandir",
            lambda path: (
                Scan(entries) if str(path) == str(directory) else original_scandir(path)
            ),
        )
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.json()["storage_bytes"] == 10
        assert response.json()["indexed"] == response.json()["pending"] == 0
        footprint = response.json()["storage_footprint"]
        assert footprint["complete"] is False
        assert footprint["measured_bytes"] == 10
        assert footprint["metadata_errors"] == 1
        assert footprint["skipped_links"] == 1


def test_storage_size_does_not_hide_permission_failures(monkeypatch, tmp_path):
    monkeypatch.setattr(
        os, "scandir", lambda path: Scan([Entry(error=PermissionError("denied"))])
    )
    with pytest.raises(PermissionError, match="denied"):
        _storage_bytes(tmp_path)
