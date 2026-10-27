"""CLI backup defaults to chunked encryption and auto-detects its restore format."""
import json
import sys
from contextlib import closing

import pytest

from sapientia import __main__ as cli
from sapientia.storage import Settings, Store


def invoke(monkeypatch, capsys, *args):
    monkeypatch.setattr(sys, "argv", ["lumina-xsera", *map(str, args)])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _: "Synthetic-backup-passphrase-2026")
    cli.main()
    return json.loads(capsys.readouterr().out)


def test_cli_chunked_encrypted_backup_and_restore(tmp_path, monkeypatch, capsys):
    data, bundle, restored = tmp_path / "data", tmp_path / "bundle", tmp_path / "restored"
    with closing(Store(Settings(data, min_free_bytes=0))) as store:
        store.ingest("default", [{"event_id": "original", "message": "CLI synthetic telemetry"}])
        store.flush()
    backed = invoke(monkeypatch, capsys, "--data", data, "backup", bundle, "--encrypt")
    assert backed["format"] == 2 and backed["encrypted"] is True
    assert (bundle / "header.json").is_file()
    result = invoke(monkeypatch, capsys, "--data", restored, "restore", bundle, "--encrypted")
    assert result["format"] == 2 and result["sessions_revoked"] is True
    with closing(Store(Settings(restored, min_free_bytes=0))) as store:
        assert store.search("default", {"query": "*"})["returned"] == 1


def test_cli_archive_fetch_preserves_explicit_version(tmp_path, monkeypatch, capsys):
    from sapientia import archive_sink

    path = tmp_path / "config.json"
    path.write_text('{"marker":"synthetic"}')
    called = {}
    def fetch(config, key, destination, *, commit_version):
        called.update(config=config, key=key, destination=str(destination), version=commit_version)
        return {"fetched": True}
    monkeypatch.setattr(archive_sink, "fetch_bundle", fetch)
    assert invoke(monkeypatch, capsys, "archive-fetch", "prefix/id/commit.json", tmp_path / "fetched", "--config", path, "--commit-version", "known-version")["fetched"]
    assert called["version"] == "known-version" and called["config"] == {"marker": "synthetic"}


def test_archive_error_reports_partial_immutable_objects(capsys):
    from sapientia.archive_sink import ArchivePublishError

    def partial():
        raise ArchivePublishError("Archive publication failed", {"state": "partial", "confirmed_objects": 2, "uncertain_key": "x/commit.json"})
    with pytest.raises(SystemExit) as stopped:
        cli.archive_operation(partial)
    assert stopped.value.code == 1
    assert json.loads(capsys.readouterr().err)["report"]["confirmed_objects"] == 2
