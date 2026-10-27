"""Operator capacity limits and offline full-text rebuild safety."""

import sys
import time
from types import SimpleNamespace

import pytest

from sapientia import __main__ as cli


@pytest.mark.parametrize("option,value", [
    ("--query-timeout", "nan"), ("--query-timeout", "121"),
    ("--fts-budget-gib", "0"), ("--fts-budget-gib", "1025"),
    ("--indexing-budget", "nan"), ("--indexing-budget", "0"),
    ("--reserve-gib", "nan"), ("--reserve-gib", "inf"),
    ("--reserve-gib", "0"), ("--reserve-gib", "1025"),
])
def test_invalid_capacity_is_rejected_before_server_creation(monkeypatch, option, value):
    monkeypatch.setattr(sys, "argv", ["lumina-xsera", "serve", option, value])
    with pytest.raises(SystemExit) as result:
        cli.main()
    assert result.value.code == 2


def test_explicit_capacity_reaches_actual_service_settings(monkeypatch, tmp_path):
    from sapientia import api

    captured = {}
    monkeypatch.setattr(sys, "argv", [
        "lumina-xsera", "--data", str(tmp_path), "serve", "--query-timeout", "30",
        "--fts-budget-gib", "32", "--indexing-budget", "0.5", "--reserve-gib", "10",
    ])
    def create(settings):
        captured["settings"] = settings
        return "local-test-app"
    monkeypatch.setattr(api, "create_app", create)
    monkeypatch.setitem(sys.modules, "uvicorn", SimpleNamespace(run=lambda app, **kw: captured.update(app=app, runtime=kw)))
    cli.main()
    settings = captured["settings"]
    assert settings.query_timeout == 30
    assert settings.fts_max_bytes == 32 * 1024**3
    assert settings.min_free_bytes == 10 * 1024**3
    assert settings.indexing_budget == .5
    assert captured["runtime"]["workers"] == 1


def test_offline_rebuild_does_not_initialize_a_mistyped_path(monkeypatch, tmp_path):
    missing = tmp_path / "does-not-exist"
    monkeypatch.setattr(sys, "argv", ["lumina-xsera", "--data", str(missing), "rebuild-fts"])
    with pytest.raises(SystemExit) as result:
        cli.main()
    assert result.value.code == 2
    assert not missing.exists()


def test_offline_rebuild_has_separate_deadline_and_always_closes(monkeypatch, tmp_path):
    from sapientia import log_search

    (tmp_path / "control.sqlite3").touch()
    (tmp_path / "events.duckdb").touch()
    captured = {}
    instance = SimpleNamespace(close=lambda: captured.update(closed=True))
    def store(settings):
        captured["settings"] = settings
        return instance
    def rebuild(value, deadline):
        assert value is instance
        assert 599 <= deadline - time.monotonic() <= 600
        raise RuntimeError("synthetic interrupted rebuild")
    monkeypatch.setattr(cli, "Store", store)
    monkeypatch.setattr(log_search, "rebuild", rebuild, raising=False)
    monkeypatch.setattr(sys, "argv", [
        "lumina-xsera", "--data", str(tmp_path), "rebuild-fts", "--max-seconds", "600", "--fts-budget-gib", "16",
    ])
    with pytest.raises(RuntimeError, match="synthetic"):
        cli.main()
    assert captured["closed"]
    assert captured["settings"].fts_max_bytes == 16 * 1024**3
