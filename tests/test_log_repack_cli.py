"""Offline repair must not create a typo directory or hide incomplete work."""

import json
import sys
from types import SimpleNamespace

import pytest

from sapientia import __main__ as cli
from sapientia.storage import Settings, Store


def arguments(monkeypatch, data, *options):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "lumina-xsera",
            "--data",
            str(data),
            "repack-logs",
            *options,
        ],
    )


def test_typo_directory_is_never_initialized(monkeypatch, tmp_path):
    missing = tmp_path / "does-not-exist"
    arguments(monkeypatch, missing)
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2
    assert not missing.exists()


@pytest.mark.parametrize(
    "options",
    [
        ["--max-files", "0"],
        ["--max-files", "65"],
        ["--max-seconds", "nan"],
        ["--max-seconds", "inf"],
        ["--reserve-gib", "nan"],
        ["--reserve-gib", "0"],
    ],
)
def test_invalid_limits_do_not_open_or_create_data(monkeypatch, tmp_path, options):
    missing = tmp_path / "uninitialized"
    arguments(monkeypatch, missing, *options)
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2
    assert not missing.exists()


def test_active_service_prevents_offline_repair(monkeypatch, tmp_path):
    data = tmp_path / "data"
    store = Store(Settings(data, min_free_bytes=0))
    try:
        arguments(monkeypatch, data)
        with pytest.raises(RuntimeError, match="already in use"):
            cli.main()
        assert store.analytics.execute("SELECT count(*) FROM events").fetchone()[0] == 0
    finally:
        store.close()


@pytest.mark.parametrize("complete", [True, False])
def test_partial_work_has_report_and_nonzero_exit(
    monkeypatch, tmp_path, capsys, complete
):
    (tmp_path / "control.sqlite3").touch()
    (tmp_path / "events.duckdb").touch()
    state = {"closed": False}
    report = {"complete": complete, "remaining_segments": 0 if complete else 4}
    instance = SimpleNamespace(
        segments=SimpleNamespace(repack=lambda **kwargs: report),
        close=lambda: state.update(closed=True),
    )
    monkeypatch.setattr(cli, "Store", lambda settings: instance)
    arguments(monkeypatch, tmp_path)
    if complete:
        cli.main()
    else:
        with pytest.raises(SystemExit) as error:
            cli.main()
        assert error.value.code == 2
    assert json.loads(capsys.readouterr().out) == report
    assert state["closed"]


def test_native_failure_always_releases_offline_store(monkeypatch, tmp_path):
    (tmp_path / "control.sqlite3").touch()
    (tmp_path / "events.duckdb").touch()
    state = {"closed": False}

    def fail(**kwargs):
        raise RuntimeError("synthetic repair interruption")

    instance = SimpleNamespace(
        segments=SimpleNamespace(repack=fail),
        close=lambda: state.update(closed=True),
    )
    monkeypatch.setattr(cli, "Store", lambda settings: instance)
    arguments(monkeypatch, tmp_path)
    with pytest.raises(RuntimeError, match="synthetic repair interruption"):
        cli.main()
    assert state["closed"]
