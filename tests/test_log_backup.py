import time

import pytest

from sapientia import backup
from sapientia.storage import Settings, Store


def test_live_snapshot_contains_hot_queue_and_sealed_files_and_rebases(tmp_path):
    source, destination, restored = tmp_path / "source", tmp_path / "backup", tmp_path / "restored"
    store = Store(Settings(source, min_free_bytes=0))
    try:
        store.ingest("a", [{"event_id": "sealed", "message": "archived evidence"}])
        store.flush()
        assert store.segments.seal(now=time.time() + 2 * 86400)["sealed_events"] == 1
        store.ingest("a", [{"event_id": "hot"}])
        store.flush()
        store.ingest("a", [{"event_id": "queued"}])
        manifest = backup.backup_online(store, destination)
        assert manifest["online"] is True
        assert any(name.startswith("log-segments/") for name in manifest["sha256"])
        store.ingest("a", [{"event_id": "after-snapshot"}])
        backup.restore(destination, restored)
        clone = Store(Settings(restored, min_free_bytes=0))
        try:
            clone.flush()
            result = clone.search("a", {"query": "* | stats count"})
            assert result["rows"][0]["count"] == 3
            assert clone.segments.verify(deep=True)["valid"] is True
        finally:
            clone.close()
    finally:
        store.close()


def test_encrypted_backup_roundtrips_nested_partition_manifest(tmp_path):
    source = tmp_path / "source"
    store = Store(Settings(source, min_free_bytes=0))
    store.ingest("a", [{"event_id": "archive"}])
    store.flush()
    store.segments.seal(now=time.time() + 35 * 86400)
    store.close()
    archive, restored = tmp_path / "encrypted.sap", tmp_path / "restored"
    backup.backup_encrypted(source, archive, "Testing-only-passphrase-2026")
    backup.restore_encrypted(archive, restored, "Testing-only-passphrase-2026")
    clone = Store(Settings(restored, min_free_bytes=0))
    try:
        assert clone.search("a", {"query": "* | stats count"})["rows"][0]["count"] == 1
    finally:
        clone.close()


@pytest.mark.parametrize("name", ["../escaped.parquet", "log-segments/../evil.parquet", "log-segments/a/../../evil.parquet", "log-segments/a/file.exe", "C:/evil.parquet", "log-segments\\a\\b.parquet"])
def test_segment_backup_manifest_rejects_path_escape(name):
    assert not backup._safe_backup_name(name)


@pytest.mark.skipif(__import__('os').name != 'nt', reason='Windows sharing-mode publication guard')
def test_legacy_encrypted_restore_uses_bounded_sharing_retry(tmp_path,monkeypatch):
    from sapientia import backup_stream
    source=tmp_path/'source'
    store=Store(Settings(source,min_free_bytes=0))
    store.ingest('a',[{'event_id':'legacy-publication-proof'}])
    store.flush();store.close()
    archive, restored=tmp_path/'encrypted.sap', tmp_path/'restored'
    backup.backup_encrypted(source,archive,'Testing-only-passphrase-2026')
    actual=backup_stream.os.rename
    calls=[]
    def rename(old,new):
        calls.append((old,new))
        if len(calls)==1:
            failure=PermissionError('Synthetic scanner sharing conflict')
            failure.winerror=32
            raise failure
        return actual(old,new)
    monkeypatch.setattr(backup_stream.os,'rename',rename)
    backup.restore_encrypted(archive,restored,'Testing-only-passphrase-2026')
    assert len(calls)==2
    clone=Store(Settings(restored,min_free_bytes=0))
    try:
        assert clone.search('a',{'query':'* | stats count'})['rows'][0]['count']==1
    finally:
        clone.close()
