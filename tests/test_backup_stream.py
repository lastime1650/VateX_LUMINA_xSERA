"""Small real multi-chunk snapshots; no giant-file throughput claim."""

import base64
import hashlib
import json
import os
import shutil
import time

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sapientia import auth, mfa
from sapientia import backup_stream as stream
from sapientia.backup import backup, sha256
from sapientia.storage import Settings, Store

PASSWORD = "Synthetic-stream-account-password-2026"
PASSPHRASE = "Synthetic-stream-backup-passphrase-2026"


class SyntheticBundle(tuple):
    def __repr__(self):
        return "<Synthetic encrypted backup fixture; credentials omitted>"


@pytest.fixture(scope="module")
def source_bundle(tmp_path_factory):
    root = tmp_path_factory.mktemp("stream-fixture")
    # Module fixtures execute before function-scoped autouse volume models.
    # Model only this owned synthetic backup tree; product policy stays at 20%.
    actual = shutil.disk_usage
    def owned_volume(path):
        target = os.path.realpath(path)
        measured = actual(path)
        if os.path.commonpath([target, os.path.realpath(root)]) == os.path.realpath(root):
            return type(measured)(10*1024**4, 2*1024**4, 8*1024**4)
        return measured
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(shutil, "disk_usage", owned_volume)
        return _source_bundle(root)


def _source_bundle(root):
    data, snapshot, bundle = root / "data", root / "snapshot", root / "bundle"
    store = Store(Settings(data, min_free_bytes=0))
    auth.create_user(store, "administrator", PASSWORD)
    session = auth.login(store, "administrator", PASSWORD)
    secret = mfa.enroll(
        store, {"name": "administrator", "tenant": "default", "role": "admin"}, PASSWORD
    )["secret"]
    store.ingest(
        "default",
        [{"event_id": "private", "message": "Synthetic-private-log-evidence-2026"}],
    )
    store.flush()
    store.segments.seal(now=time.time() + 2 * 86400)
    (data / ".membership-enrollment.json").write_text(
        '{"nonce":"Synthetic-private-membership-retry-2026"}', encoding="utf-8"
    )
    store.close()
    backup(data, snapshot)
    result = stream.encrypt_snapshot(snapshot, bundle, PASSPHRASE, chunk_size=32768)
    assert result["chunks"] > 3
    return SyntheticBundle((snapshot, bundle, result, session, secret))


def clone(source_bundle, tmp_path):
    target = tmp_path / "copy"
    shutil.copytree(source_bundle[1], target)
    return target


def manifest(bundle):
    encoded = (bundle / "header.json").read_bytes()
    header = json.loads(encoded)
    digest = hashlib.sha256(encoded).hexdigest()
    salt, prefix = stream._header(header)
    cipher = AESGCM(stream._key(PASSPHRASE, salt))
    value = json.loads(
        cipher.decrypt(
            stream._nonce(prefix, stream.MANIFEST_COUNTER),
            (bundle / "manifest.enc").read_bytes(),
            stream._aad(header, digest),
        )
    )
    return header, digest, prefix, cipher, value


def rewrite_manifest(bundle, transform):
    header, digest, prefix, cipher, value = manifest(bundle)
    transform(value)
    (bundle / "manifest.enc").write_bytes(
        cipher.encrypt(
            stream._nonce(prefix, stream.MANIFEST_COUNTER),
            stream._json(value),
            stream._aad(header, digest),
        )
    )


def test_real_roundtrip_preserves_originals_keys_and_revokes_session(
    source_bundle, tmp_path
):
    snapshot, bundle, original, session, secret = source_bundle
    destination = tmp_path / "restored"
    restored = stream.restore_bundle(bundle, destination, PASSPHRASE)
    assert restored["format"] == 2 and restored["sessions_revoked"]
    assert restored["chunks"] == original["chunks"]
    store = Store(Settings(destination, min_free_bytes=0))
    try:
        assert auth.identity(store, cookie=session["token"]) is None
        assert (
            store.search("default", {"query": "*"})["rows"][0]["message"]
            == "Synthetic-private-log-evidence-2026"
        )
        with store.control() as db:
            encrypted = db.execute("SELECT mfa_pending FROM users").fetchone()[0]
        assert mfa.decrypt(store, "administrator", encrypted) == secret
        assert (
            "Synthetic-private-membership-retry-2026"
            in (destination / ".membership-enrollment.json").read_text()
        )
    finally:
        store.close()
    # Encryption never migrates or rewrites its consistent source snapshot.
    for name, expected in json.loads((snapshot / "manifest.json").read_text())[
        "sha256"
    ].items():
        assert sha256(snapshot / name) == expected


def test_header_has_no_paths_and_ciphertexts_do_not_expose_content(source_bundle):
    _, bundle, _, _, secret = source_bundle
    header = json.loads((bundle / "header.json").read_bytes())
    assert set(header) == {
        "format",
        "schema",
        "bundle_id",
        "cipher",
        "kdf",
        "salt",
        "nonce_prefix",
        "chunk_bytes",
    }
    files = [
        bundle / "header.json",
        bundle / "manifest.enc",
        *(bundle / "chunks").iterdir(),
    ]
    forbidden = [
        b"control.sqlite3",
        b"events.duckdb",
        PASSPHRASE.encode(),
        secret.encode(),
        b"Synthetic-private-log-evidence-2026",
        b"Synthetic-private-membership-retry-2026",
    ]
    for file in files:
        assert not any(value in file.read_bytes() for value in forbidden)


@pytest.mark.parametrize(
    "kind",
    [
        "password",
        "header",
        "manifest",
        "chunk",
        "truncate",
        "missing",
        "swap",
        "extra",
        "extra-root",
    ],
)
def test_tampering_fails_before_any_restore_is_published(source_bundle, tmp_path, kind):
    bundle = clone(source_bundle, tmp_path)
    password = PASSPHRASE
    chunks = sorted((bundle / "chunks").iterdir())
    if kind == "password":
        password = "Wrong-synthetic-backup-passphrase-2026"
    elif kind == "header":
        header = json.loads((bundle / "header.json").read_bytes())
        header["bundle_id"] = "a" * 32
        (bundle / "header.json").write_bytes(stream._json(header))
    elif kind in {"manifest", "chunk"}:
        path = bundle / "manifest.enc" if kind == "manifest" else chunks[0]
        value = bytearray(path.read_bytes())
        value[len(value) // 2] ^= 1
        path.write_bytes(value)
    elif kind == "truncate":
        chunks[0].write_bytes(chunks[0].read_bytes()[:-1])
    elif kind == "missing":
        chunks[0].unlink()
    elif kind == "swap":
        first, second = chunks[0].read_bytes(), chunks[1].read_bytes()
        chunks[0].write_bytes(second)
        chunks[1].write_bytes(first)
    elif kind == "extra":
        (bundle / "chunks" / "ffffffff.bin").write_bytes(b"unused")
    else:
        (bundle / "unexpected.txt").write_bytes(b"unused")
    target = tmp_path / "failed"
    with pytest.raises(ValueError):
        stream.restore_bundle(bundle, target, password)
    assert not target.exists()
    assert not list(tmp_path.glob(".bundle-restore-*"))


@pytest.mark.parametrize(
    "kind", ["traversal", "absolute", "backslash", "duplicate", "counter", "digest"]
)
def test_even_authenticated_manifest_cannot_escape_or_reorder_files(
    source_bundle, tmp_path, kind
):
    bundle = clone(source_bundle, tmp_path)

    def mutate(value):
        files = value["files"]
        if kind in {"traversal", "absolute", "backslash"}:
            files[0]["path"] = {
                "traversal": "../outside",
                "absolute": "/outside",
                "backslash": r"..\outside",
            }[kind]
        elif kind == "duplicate":
            files[1]["path"] = files[0]["path"]
        elif kind == "counter":
            files[0]["first_chunk"] += 1
        else:
            files[0]["sha256"] = "0" * 64

    rewrite_manifest(bundle, mutate)
    target = tmp_path / "rejected"
    with pytest.raises(ValueError):
        stream.restore_bundle(bundle, target, PASSPHRASE)
    assert not target.exists() and not (tmp_path / "outside").exists()


def test_bundles_use_unique_key_parameters_and_never_reuse_a_nonce(
    source_bundle, tmp_path, monkeypatch
):
    actual = stream.AESGCM
    nonces = []

    class RecordingCipher:
        def __init__(self, key):
            self.inner = actual(key)

        def encrypt(self, nonce, value, aad):
            nonces.append(nonce)
            return self.inner.encrypt(nonce, value, aad)

    monkeypatch.setattr(stream, "AESGCM", RecordingCipher)
    target = tmp_path / "new"
    result = stream.encrypt_snapshot(
        source_bundle[0], target, PASSPHRASE, chunk_size=32768
    )
    assert len(nonces) == result["chunks"] + 1 == len(set(nonces))
    assert [int.from_bytes(nonce[-4:], "big") for nonce in nonces[:-1]] == list(
        range(result["chunks"])
    )
    assert nonces[-1][-4:] == b"\xff" * 4
    first, second = (
        json.loads((source_bundle[1] / "header.json").read_bytes()),
        json.loads((target / "header.json").read_bytes()),
    )
    assert (
        first["salt"] != second["salt"]
        and first["nonce_prefix"] != second["nonce_prefix"]
    )


def test_source_and_encrypted_hard_links_are_rejected(source_bundle, tmp_path):
    snapshot = tmp_path / "snapshot"
    shutil.copytree(source_bundle[0], snapshot)
    os.link(snapshot / "control.sqlite3", tmp_path / "alias.sqlite3")
    with pytest.raises(ValueError, match="hard links"):
        stream.encrypt_snapshot(snapshot, tmp_path / "unsafe", PASSPHRASE)
    bundle = clone(source_bundle, tmp_path)
    os.link(next((bundle / "chunks").iterdir()), tmp_path / "alias.bin")
    with pytest.raises(ValueError, match="hard links"):
        stream.restore_bundle(bundle, tmp_path / "unsafe-restore", PASSPHRASE)
    assert (
        not (tmp_path / "unsafe").exists()
        and not (tmp_path / "unsafe-restore").exists()
    )


def test_existing_or_racing_destinations_are_preserved(
    source_bundle, tmp_path, monkeypatch
):
    target = tmp_path / "existing"
    target.mkdir()
    (target / "sentinel").write_bytes(b"preserve")
    with pytest.raises(ValueError):
        stream.restore_bundle(source_bundle[1], target, PASSPHRASE)
    with pytest.raises(ValueError):
        stream.encrypt_snapshot(source_bundle[0], target, PASSPHRASE)
    actual = stream._publish

    def race(source, destination):
        destination.mkdir()
        (destination / "sentinel").write_bytes(b"racing destination")
        actual(source, destination)

    monkeypatch.setattr(stream, "_publish", race)
    racing = tmp_path / "racing"
    with pytest.raises(ValueError):
        stream.restore_bundle(source_bundle[1], racing, PASSPHRASE)
    assert (target / "sentinel").read_bytes() == b"preserve"
    assert (racing / "sentinel").read_bytes() == b"racing destination"


def test_format_represents_more_than_legacy_64gib_without_allocating_it():
    header = {
        "format": stream.FORMAT,
        "schema": 2,
        "bundle_id": "a" * 32,
        "cipher": "AES-256-GCM",
        "kdf": "scrypt-n32768-r8-p1",
        "salt": base64.b64encode(b"s" * 32).decode(),
        "nonce_prefix": base64.b64encode(b"p" * 8).decode(),
        "chunk_bytes": stream.CHUNK_BYTES,
    }
    size = 70 * 1024**3
    chunks = size // stream.CHUNK_BYTES
    files = [
        {
            "path": "events.duckdb",
            "size": size,
            "sha256": "0" * 64,
            "first_chunk": 0,
            "chunks": chunks,
        },
        {
            "path": "control.sqlite3",
            "size": 0,
            "sha256": "0" * 64,
            "first_chunk": chunks,
            "chunks": 0,
        },
        {
            "path": "manifest.json",
            "size": 0,
            "sha256": "0" * 64,
            "first_chunk": chunks,
            "chunks": 0,
        },
    ]
    assert (
        stream._manifest(
            {"schema": 2, "header_sha256": "d", "files": files, "total_chunks": chunks},
            header,
            "d",
        )
        == files
    )
    files[0]["size"] = (stream.MAX_CHUNKS + 1) * stream.CHUNK_BYTES
    files[0]["chunks"] = stream.MAX_CHUNKS + 1
    with pytest.raises(ValueError):
        stream._manifest(
            {
                "schema": 2,
                "header_sha256": "d",
                "files": files,
                "total_chunks": stream.MAX_CHUNKS + 1,
            },
            header,
            "d",
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows sharing-mode publication guard")
def test_publish_retries_transient_windows_sharing_failure(tmp_path, monkeypatch):
    source, destination = tmp_path / "source", tmp_path / "published"
    source.mkdir()
    (source / "sentinel").write_bytes(b"complete")
    actual, calls = stream.os.rename, []

    def rename(old, new):
        calls.append(1)
        if len(calls) == 1:
            error = PermissionError("Synthetic scanner sharing conflict")
            error.winerror = 32
            raise error
        return actual(old, new)

    monkeypatch.setattr(stream.os, "rename", rename)
    stream._publish(source, destination)
    assert len(calls) == 2 and (destination / "sentinel").read_bytes() == b"complete"
