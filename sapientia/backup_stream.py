"""Bounded, independently authenticated encrypted snapshot bundles (format 2).

One fresh scrypt key and nonce prefix per bundle; a global counter never repeats.
Only the bounded manifest and one <=8 MiB plaintext chunk are held in memory.
Local encryption is not KMS, WORM, or evidence of a remote retention service.
"""

import base64
import ctypes
import errno
import hashlib
import json
import os
import re
import secrets
import stat
import tempfile
import time
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .backup import _private_directory, _safe_backup_name, restore

CHUNK_BYTES = 8 * 1024 * 1024
MAX_CHUNKS = 1_000_000  # Up to ~7.63 TiB at the default chunk size.
MAX_FILES = 100_000
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MANIFEST_COUNTER = 0xFFFFFFFF
FORMAT = "lumina-xsera-encrypted-snapshot"


def _json(value):
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate encrypted backup JSON property")
        result[key] = value
    return result


def _load(value):
    try:
        return json.loads(value, object_pairs_hook=_pairs)
    except (UnicodeError, RecursionError):
        raise ValueError("Invalid encrypted backup JSON") from None


def _no_links(path):
    for item in (path, *path.parents):
        if item.exists() or item.is_symlink():
            metadata = item.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or getattr(metadata, "st_file_attributes", 0) & 0x400
            ):
                raise ValueError(
                    "Backup paths must not use symbolic links or reparse points"
                )


def _root(path, *, new=False):
    path = Path(path).absolute()
    _no_links(path)
    path = path.resolve()
    if new:
        if path.exists():
            raise ValueError("Encrypted backup destination must not exist")
    elif not path.is_dir():
        raise ValueError("Encrypted backup source must be a directory")
    return path


def _regular(path):
    _no_links(path)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError("Backup members must be regular files without hard links")
    return metadata


def _identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_nlink,
    )


def _read(path, maximum):
    before = _regular(path)
    if before.st_size > maximum:
        raise ValueError("Encrypted backup member exceeds its size bound")
    with path.open("rb") as stream:
        if _identity(os.fstat(stream.fileno())) != _identity(before):
            raise ValueError("Backup member changed before reading")
        value = stream.read(maximum + 1)
        if len(value) > maximum or _identity(os.fstat(stream.fileno())) != _identity(
            before
        ):
            raise ValueError("Backup member changed while reading")
    if _identity(_regular(path)) != _identity(before):
        raise ValueError("Backup member path changed while reading")
    return value


def _write(path, value):
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(value)
        output.flush()
        os.fsync(output.fileno())


def _sync_directory(path):
    if os.name != "nt":
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _publish(source, destination):
    """Rename without replacing even an empty directory created concurrently."""
    _no_links(destination)
    if destination.exists():
        raise ValueError("Encrypted backup destination already exists")
    if os.name == "nt":
        # A scanner can briefly open a newly fsynced member without DELETE
        # sharing. Retry only this bounded publication, never overwrite or copy
        # around a permanent permission error.
        deadline = time.monotonic() + 1
        while True:
            try:
                os.rename(source, destination)  # Windows refuses existing destinations.
                break
            except PermissionError as exc:
                if destination.exists():
                    raise ValueError(
                        "Encrypted backup destination already exists"
                    ) from None
                if (
                    getattr(exc, "winerror", None) not in {5, 32, 33}
                    or time.monotonic() >= deadline
                ):
                    raise
                time.sleep(0.05)
    else:
        library = ctypes.CDLL(None, use_errno=True)
        rename = getattr(library, "renameat2", None)
        if rename is None:
            raise RuntimeError("Safe bundle publication requires Linux renameat2")
        rename.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1):
            number = ctypes.get_errno()
            if number == errno.EEXIST:
                raise ValueError("Encrypted backup destination already exists")
            raise OSError(number, "Cannot publish encrypted backup bundle")
    _sync_directory(destination.parent)


def _key(passphrase, salt):
    if not isinstance(passphrase, str) or not 12 <= len(passphrase) <= 1024:
        raise ValueError("Backup passphrase must be 12..1024 characters")
    try:
        encoded = passphrase.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("Backup passphrase contains invalid Unicode") from None
    return Scrypt(salt=salt, length=32, n=32768, r=8, p=1).derive(encoded)


def _header(value):
    if not isinstance(value, dict) or set(value) != {
        "format",
        "schema",
        "bundle_id",
        "cipher",
        "kdf",
        "salt",
        "nonce_prefix",
        "chunk_bytes",
    }:
        raise ValueError("Invalid encrypted backup header")
    if (
        value["format"] != FORMAT
        or type(value["schema"]) is not int
        or value["schema"] != 2
        or value["cipher"] != "AES-256-GCM"
        or value["kdf"] != "scrypt-n32768-r8-p1"
    ):
        raise ValueError("Unsupported encrypted backup format")
    if not isinstance(value["bundle_id"], str) or not re.fullmatch(
        r"[a-f0-9]{32}", value["bundle_id"]
    ):
        raise ValueError("Invalid encrypted backup bundle identity")
    if (
        type(value["chunk_bytes"]) is not int
        or not 1024 <= value["chunk_bytes"] <= CHUNK_BYTES
    ):
        raise ValueError("Encrypted chunk size must be 1024..8388608 bytes")
    try:
        salt = base64.b64decode(value["salt"], validate=True)
        prefix = base64.b64decode(value["nonce_prefix"], validate=True)
    except (ValueError, TypeError):
        raise ValueError("Invalid encrypted backup key parameters") from None
    if len(salt) != 32 or len(prefix) != 8:
        raise ValueError("Invalid encrypted backup key parameters")
    return salt, prefix


def _aad(header, digest, path=None, ordinal=None, counter=None, size=None):
    return _json(
        [
            FORMAT,
            2,
            header["bundle_id"],
            digest,
            "manifest" if path is None else "chunk",
            path,
            ordinal,
            counter,
            size,
        ]
    )


def _nonce(prefix, counter):
    return prefix + counter.to_bytes(4, "big")


def _manifest(value, header, digest):
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "header_sha256", "files", "total_chunks"}
        or type(value["schema"]) is not int
        or value["schema"] != 2
        or value["header_sha256"] != digest
    ):
        raise ValueError("Invalid authenticated backup manifest")
    files = value["files"]
    if (
        not isinstance(files, list)
        or not 3 <= len(files) <= MAX_FILES
        or type(value["total_chunks"]) is not int
        or not 0 <= value["total_chunks"] <= MAX_CHUNKS
    ):
        raise ValueError("Encrypted backup exceeds its file or chunk bound")
    seen, counter = set(), 0
    for item in files:
        if not isinstance(item, dict) or set(item) != {
            "path",
            "size",
            "sha256",
            "first_chunk",
            "chunks",
        }:
            raise ValueError("Invalid encrypted backup file entry")
        path = item["path"]
        if not _safe_backup_name(path) or path in seen:
            raise ValueError("Unsafe or duplicate encrypted backup path")
        seen.add(path)
        if (
            type(item["size"]) is not int
            or not 0 <= item["size"] <= CHUNK_BYTES * MAX_CHUNKS
            or not isinstance(item["sha256"], str)
            or not re.fullmatch(r"[a-f0-9]{64}", item["sha256"])
        ):
            raise ValueError("Invalid encrypted backup file size or digest")
        chunks = (item["size"] + header["chunk_bytes"] - 1) // header["chunk_bytes"]
        if (
            type(item["first_chunk"]) is not int
            or item["first_chunk"] != counter
            or type(item["chunks"]) is not int
            or item["chunks"] != chunks
        ):
            raise ValueError("Encrypted backup chunk order is not contiguous")
        counter += chunks
        if counter > MAX_CHUNKS:
            raise ValueError("Encrypted backup exceeds its chunk bound")
    if (
        counter != value["total_chunks"]
        or not {"manifest.json", "control.sqlite3", "events.duckdb"} <= seen
    ):
        raise ValueError("Encrypted backup has missing files or chunks")
    return files


def encrypt_snapshot(
    source_consistent_snapshot_dir,
    destination_new_dir,
    passphrase,
    *,
    chunk_size=CHUNK_BYTES,
):
    source, destination = (
        _root(source_consistent_snapshot_dir),
        _root(destination_new_dir, new=True),
    )
    if destination.is_relative_to(source):
        raise ValueError("Encrypted bundle must be outside its source snapshot")
    header = {
        "format": FORMAT,
        "schema": 2,
        "bundle_id": uuid.uuid4().hex,
        "cipher": "AES-256-GCM",
        "kdf": "scrypt-n32768-r8-p1",
        "salt": base64.b64encode(secrets.token_bytes(32)).decode(),
        "nonce_prefix": base64.b64encode(secrets.token_bytes(8)).decode(),
        "chunk_bytes": chunk_size,
    }
    salt, prefix = _header(header)
    cipher, encoded_header = AESGCM(_key(passphrase, salt)), _json(header)
    digest = hashlib.sha256(encoded_header).hexdigest()
    snapshot_bytes = _read(source / "manifest.json", MAX_MANIFEST_BYTES)
    snapshot = _load(snapshot_bytes)
    hashes = snapshot.get("sha256") if isinstance(snapshot, dict) else None
    if (
        not isinstance(snapshot, dict)
        or type(snapshot.get("schema")) is not int
        or snapshot["schema"] not in (1, 2)
        or not isinstance(hashes, dict)
        or not {"control.sqlite3", "events.duckdb"} <= hashes.keys()
        or "manifest.json" in hashes
        or not 2 <= len(hashes) < MAX_FILES
    ):
        raise ValueError("Source must be a consistent backup snapshot")
    expected = {**hashes, "manifest.json": hashlib.sha256(snapshot_bytes).hexdigest()}
    files, counter, total = [], 0, 0
    for name in sorted(expected):
        if (
            not _safe_backup_name(name)
            or not isinstance(expected[name], str)
            or not re.fullmatch(r"[a-f0-9]{64}", expected[name])
        ):
            raise ValueError("Unsafe source snapshot manifest")
        metadata = _regular(source / name)
        chunks = (metadata.st_size + chunk_size - 1) // chunk_size
        files.append(
            {
                "path": name,
                "size": metadata.st_size,
                "sha256": expected[name],
                "first_chunk": counter,
                "chunks": chunks,
            }
        )
        counter += chunks
        total += metadata.st_size
    manifest = {
        "schema": 2,
        "header_sha256": digest,
        "files": files,
        "total_chunks": counter,
    }
    _manifest(manifest, header, digest)
    encoded_manifest = _json(manifest)
    if len(encoded_manifest) > MAX_MANIFEST_BYTES:
        raise ValueError("Encrypted backup manifest exceeds 64 MiB")
    destination.parent.mkdir(parents=True, exist_ok=True)
    _no_links(destination.parent)
    with tempfile.TemporaryDirectory(
        prefix=".encrypted-bundle-", dir=destination.parent
    ) as directory:
        temporary = Path(directory)
        _private_directory(temporary, created=True)
        bundle = temporary / "bundle"
        bundle.mkdir(mode=0o700)
        _private_directory(bundle, created=True)
        (bundle / "chunks").mkdir(mode=0o700)
        _private_directory(bundle / "chunks", created=True)
        _write(bundle / "header.json", encoded_header)
        for item in files:
            path = source / item["path"]
            before = _regular(path)
            actual = hashlib.sha256()
            with path.open("rb") as stream:
                if _identity(os.fstat(stream.fileno())) != _identity(before):
                    raise ValueError("Source snapshot file changed")
                for ordinal in range(item["chunks"]):
                    size = min(chunk_size, item["size"] - ordinal * chunk_size)
                    value = stream.read(size)
                    if len(value) != size:
                        raise ValueError("Source snapshot was truncated")
                    actual.update(value)
                    counter = item["first_chunk"] + ordinal
                    encrypted = cipher.encrypt(
                        _nonce(prefix, counter),
                        value,
                        _aad(header, digest, item["path"], ordinal, counter, size),
                    )
                    _write(bundle / "chunks" / f"{counter:08x}.bin", encrypted)
                if stream.read(1) or _identity(os.fstat(stream.fileno())) != _identity(
                    before
                ):
                    raise ValueError("Source snapshot file changed during encryption")
            if (
                _identity(_regular(path)) != _identity(before)
                or actual.hexdigest() != item["sha256"]
            ):
                raise ValueError("Source snapshot hash mismatch")
        _write(
            bundle / "manifest.enc",
            cipher.encrypt(
                _nonce(prefix, MANIFEST_COUNTER), encoded_manifest, _aad(header, digest)
            ),
        )
        _sync_directory(bundle / "chunks")
        _sync_directory(bundle)
        _publish(bundle, destination)
    return {
        "encrypted": True,
        "format": 2,
        "bundle_id": header["bundle_id"],
        "files": len(files),
        "bytes": total,
        "chunks": manifest["total_chunks"],
        "chunk_bytes": chunk_size,
        "maximum_chunks": MAX_CHUNKS,
    }


def restore_bundle(source_bundle_dir, destination_new_dir, passphrase):
    source, destination = _root(source_bundle_dir), _root(destination_new_dir, new=True)
    if destination.is_relative_to(source):
        raise ValueError("Restore destination must be outside its encrypted bundle")
    names = set()
    for item in source.iterdir():
        names.add(item.name)
        if len(names) > 3:
            raise ValueError("Unexpected encrypted backup bundle member")
    if names != {"header.json", "manifest.enc", "chunks"}:
        raise ValueError("Unexpected encrypted backup bundle member")
    encoded_header = _read(source / "header.json", 4096)
    header = _load(encoded_header)
    salt, prefix = _header(header)
    digest = hashlib.sha256(encoded_header).hexdigest()
    cipher = AESGCM(_key(passphrase, salt))
    try:
        manifest_bytes = cipher.decrypt(
            _nonce(prefix, MANIFEST_COUNTER),
            _read(source / "manifest.enc", MAX_MANIFEST_BYTES + 16),
            _aad(header, digest),
        )
    except InvalidTag:
        raise ValueError(
            "Encrypted backup authentication failed: wrong passphrase or altered bundle"
        ) from None
    manifest = _load(manifest_bytes)
    files = _manifest(manifest, header, digest)
    chunks = _root(source / "chunks")
    count = 0
    for path in chunks.iterdir():
        if (
            not re.fullmatch(r"[a-f0-9]{8}\.bin", path.name)
            or int(path.stem, 16) >= manifest["total_chunks"]
        ):
            raise ValueError("Unexpected encrypted backup chunk")
        _regular(path)
        count += 1
        if count > manifest["total_chunks"]:
            raise ValueError("Encrypted backup contains too many chunks")
    if count != manifest["total_chunks"]:
        raise ValueError("Encrypted backup is missing chunks")
    destination.parent.mkdir(parents=True, exist_ok=True)
    _no_links(destination.parent)
    with tempfile.TemporaryDirectory(
        prefix=".bundle-restore-", dir=destination.parent
    ) as directory:
        temporary = Path(directory)
        _private_directory(temporary, created=True)
        snapshot = temporary / "snapshot"
        snapshot.mkdir(mode=0o700)
        _private_directory(snapshot, created=True)
        for item in files:
            target = snapshot / item["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            actual = hashlib.sha256()
            with os.fdopen(descriptor, "wb") as output:
                for ordinal in range(item["chunks"]):
                    counter = item["first_chunk"] + ordinal
                    size = min(
                        header["chunk_bytes"],
                        item["size"] - ordinal * header["chunk_bytes"],
                    )
                    encrypted = _read(chunks / f"{counter:08x}.bin", size + 16)
                    if len(encrypted) != size + 16:
                        raise ValueError("Encrypted backup chunk was truncated")
                    try:
                        value = cipher.decrypt(
                            _nonce(prefix, counter),
                            encrypted,
                            _aad(header, digest, item["path"], ordinal, counter, size),
                        )
                    except InvalidTag:
                        raise ValueError(
                            "Encrypted backup chunk authentication failed"
                        ) from None
                    actual.update(value)
                    output.write(value)
                output.flush()
                os.fsync(output.fileno())
            if actual.hexdigest() != item["sha256"]:
                raise ValueError("Decrypted backup file hash mismatch")
        restored = temporary / "restored"
        restore(
            snapshot, restored
        )  # Validate audit checkpoint; revoke session/SSO state.
        _private_directory(restored)
        parents = {restored}
        for item in files:
            if item["path"] == "manifest.json":
                continue
            target = restored / item["path"]
            _regular(target)
            with target.open("r+b") as stream:
                stream.flush()
                os.fsync(stream.fileno())
            parents.update(
                parent
                for parent in target.parents
                if parent == restored or parent.is_relative_to(restored)
            )
        for parent in sorted(parents, key=lambda path: len(path.parts), reverse=True):
            _sync_directory(parent)
        _publish(restored, destination)
    return {
        "restored": str(destination),
        "encrypted": True,
        "format": 2,
        "sessions_revoked": True,
        "files": len(files),
        "chunks": manifest["total_chunks"],
    }
