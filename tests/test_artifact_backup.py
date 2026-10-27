import hashlib
import json
import uuid

import pytest

from sapientia import backup, endpoint_artifacts
from sapientia.storage import Settings, Store


def artifact(store, state="complete"):
    identifier = "ART-" + uuid.uuid4().hex
    body = b"Harmless forensic backup fixture\n"
    digest = hashlib.sha256(body).hexdigest()
    directory = store.path / "response-artifacts"
    directory.mkdir(exist_ok=True)
    path = directory / (identifier + (".bin" if state == "complete" else ".part"))
    path.write_bytes(body)
    with store.control() as db:
        endpoint_artifacts.initialize(db)
        db.execute(
            "INSERT INTO endpoint_artifacts VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                identifier,
                "fixture-" + identifier,
                "default",
                "fixture-case",
                "endpoint",
                "fixture-agent",
                digest,
                len(body),
                len(body),
                state,
                1,
                1,
            ),
        )
    return identifier, path, body, digest


def test_online_backup_restores_complete_artifact_and_excludes_partial(tmp_path):
    store = Store(Settings(tmp_path / "data", min_free_bytes=0))
    try:
        identifier, _path, body, digest = artifact(store)
        partial, _, _, _ = artifact(store, "receiving")
        manifest = backup.backup_online(store, tmp_path / "snapshot")
        name = "response-artifacts/" + identifier + ".bin"
        assert manifest["schema"] == 2 and manifest["sha256"][name] == digest
        assert not any(partial in name for name in manifest["sha256"])
        backup.restore(tmp_path / "snapshot", tmp_path / "restored")
        assert (tmp_path / "restored" / name).read_bytes() == body
        assert not (
            tmp_path / "restored" / "response-artifacts" / (partial + ".part")
        ).exists()
    finally:
        store.close()


def test_modified_complete_artifact_blocks_backup(tmp_path):
    store = Store(Settings(tmp_path / "data", min_free_bytes=0))
    try:
        _, path, body, _ = artifact(store)
        path.write_bytes(b"x" * len(body))
        with pytest.raises(ValueError):
            backup.backup_online(store, tmp_path / "snapshot")
        assert not (tmp_path / "snapshot").exists()
    finally:
        store.close()


def test_restore_rejects_omitted_complete_object_before_publication(tmp_path):
    store = Store(Settings(tmp_path / "data", min_free_bytes=0))
    try:
        identifier, _, _, _ = artifact(store)
        backup.backup_online(store, tmp_path / "snapshot")
    finally:
        store.close()
    manifest_path = tmp_path / "snapshot" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    del manifest["sha256"]["response-artifacts/" + identifier + ".bin"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="omits objects"):
        backup.restore(tmp_path / "snapshot", tmp_path / "restored")
    assert not (tmp_path / "restored").exists()


@pytest.mark.parametrize(
    "name",
    [
        "response-artifacts/../secrets.key",
        "response-artifacts/ART-" + ("a" * 32) + ".part",
        "response-artifacts/C:\\Windows\\file.bin",
        "response-artifacts/ART-not-valid.bin",
    ],
)
def test_artifact_restore_path_contract_rejects_unsafe_members(name):
    assert not backup._safe_backup_name(name)
