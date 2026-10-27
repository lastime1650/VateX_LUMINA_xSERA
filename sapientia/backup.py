"""Offline, consistent two-store backup with verified manifests. No in-place restore."""

import base64
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import struct
import tarfile
import tempfile
import time
from contextlib import closing
from pathlib import Path

import duckdb
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .locking import ProcessLock


class AuditSnapshot:
    """Read an already copied SQLite database without opening a service store."""

    def __init__(self, path):
        self.path = Path(path)

    def control(self):
        from contextlib import contextmanager

        @contextmanager
        def connection():
            db = sqlite3.connect(
                (self.path / "control.sqlite3").as_uri() + "?mode=ro", uri=True
            )
            db.row_factory = sqlite3.Row
            try:
                yield db
            finally:
                db.close()

        return connection()


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _safe_backup_name(name):
    if not isinstance(name, str) or len(name) > 1024 or "\\" in name:
        return False
    parts = name.split("/")
    if name in ARCHIVE_NAMES:
        return True
    if re.fullmatch(r"response-artifacts/ART-[0-9a-f]{32}\.bin", name):
        return True
    return (
        len(parts) >= 3
        and parts[0] == "log-segments"
        and all(re.fullmatch(r"[A-Za-z0-9_-]+(?:\.parquet)?", p) for p in parts[1:])
        and parts[-1].endswith(".parquet")
    )


def _segment_files(data):
    with closing(
        sqlite3.connect((data / "control.sqlite3").as_uri() + "?mode=ro", uri=True)
    ) as db:
        exists = db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='log_segments'"
        ).fetchone()
        rows = (
            db.execute(
                "SELECT path,sha256 FROM log_segments WHERE state='ready'"
            ).fetchall()
            if exists
            else []
        )
    result = []
    for relative, expected in rows:
        name = "log-segments/" + relative.replace("\\", "/")
        path = data / name
        if (
            not _safe_backup_name(name)
            or path.resolve() != path
            or path.is_symlink()
            or sha256(path) != expected
        ):
            raise ValueError("Active log segment failed backup integrity verification")
        result.append(name)
    return result


def _artifact_files(data, control=None, verify=True):
    """Only complete immutable, evidence-bound objects in the captured DB."""
    database = control or data / "control.sqlite3"
    from . import endpoint_artifacts

    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as db:
        db.row_factory = sqlite3.Row
        exists = db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='endpoint_artifacts'"
        ).fetchone()
        rows = (
            db.execute(
                "SELECT * FROM endpoint_artifacts WHERE state='complete'"
            ).fetchall()
            if exists
            else []
        )
        bounded = []
        for row in rows:
            try:
                maximum = endpoint_artifacts.artifact_limit(db, row)
            except (sqlite3.Error, RuntimeError, ValueError, KeyError) as exc:
                raise ValueError(
                    "Endpoint artifact command binding failed backup verification"
                ) from exc
            bounded.append((row["id"], row["sha256"], row["total_bytes"], maximum))
    result = []
    for identifier, digest, size, maximum in bounded:
        name = "response-artifacts/" + identifier + ".bin"
        path = data / name
        if (
            not _safe_backup_name(name)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or type(size) is not int
            or not 0 <= size <= maximum
            or path.is_symlink()
            or path.resolve() != path
            or not path.is_file()
            or path.stat().st_size != size
            or verify
            and sha256(path) != digest
        ):
            raise ValueError("Complete endpoint artifact failed backup verification")
        result.append({"path": name, "sha256": digest})
    return result


def _publish_manifest(destination, names, online=False):
    from .audit_integrity import create_checkpoint

    manifest = {
        "schema": 2
        if any(n.startswith(("log-segments/", "response-artifacts/")) for n in names)
        else 1,
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sha256": {name: sha256(destination / name) for name in names},
        "audit_checkpoint": create_checkpoint(AuditSnapshot(destination)),
        "online": online,
        "note": "Contains credentials and logs. Protect this backup with encryption and access controls.",
    }
    with (destination / "manifest.json").open("x", encoding="utf-8") as stream:
        json.dump(manifest, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    return manifest


def backup_online(store, destination):
    """Snapshot live databases and immutable segments under the storage gate.

    Admission is briefly paused while copying the control/database snapshot;
    the service stays running. New arrivals resume during immutable file copy.
    External broker state and TLS keys still require their own backup.
    """
    destination = Path(destination).resolve()
    if destination.exists() or destination.is_relative_to(store.path / "log-segments"):
        raise ValueError("Backup destination must be new and outside managed segments")
    manager = getattr(store, "segments", None)
    if manager is None:
        raise ValueError("Online backup requires the partitioned storage manager")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".snapshot-", dir=manager.root
    ) as temporary:
        temporary = Path(temporary)
        _private_directory(temporary, created=True)
        snapshot = temporary / "snapshot"
        snapshot.mkdir()
        with store.flush_lock, store.segment_lock.read():
            with store.write_lock:
                files = manager.backup_files(verify=True)
                with (
                    closing(sqlite3.connect(store.operational)) as source,
                    closing(sqlite3.connect(snapshot / "control.sqlite3")) as target,
                ):
                    source.backup(target)
                con = store.analytics.cursor()
                attached = False
                try:
                    source_name = (
                        con.execute("SELECT current_database()")
                        .fetchone()[0]
                        .replace('"', '""')
                    )
                    location = (
                        str(snapshot / "events.duckdb")
                        .replace("\\", "/")
                        .replace("'", "''")
                    )
                    con.execute("ATTACH '" + location + "' AS online_snapshot")
                    attached = True
                    con.execute(
                        'COPY FROM DATABASE "' + source_name + '" TO online_snapshot'
                    )
                    con.execute("DETACH online_snapshot")
                    attached = False
                finally:
                    if attached:
                        con.execute("DETACH online_snapshot")
                    con.close()
                names = ["control.sqlite3", "events.duckdb"]
                artifacts = _artifact_files(
                    store.path, control=snapshot / "control.sqlite3", verify=False
                )
                for name in (
                    "secrets.key",
                    "node-membership.json",
                    ".membership-enrollment.json",
                ):
                    if (store.path / name).exists():
                        shutil.copyfile(store.path / name, snapshot / name)
                        names.append(name)
            for entry in files + artifacts:
                name = entry["path"]
                if not _safe_backup_name(name):
                    raise ValueError("Unsafe managed segment backup path")
                target = snapshot / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(store.path / name, target)
                if sha256(target) != entry["sha256"]:
                    raise ValueError("Log segment changed during online backup")
                names.append(name)
            manifest = _publish_manifest(snapshot, names, online=True)
        # Publish without overwriting any existing backup.
        destination.mkdir()
        _private_directory(destination, created=True)
        shutil.copytree(snapshot, destination, dirs_exist_ok=True)
    return manifest


def backup(data, destination, *, include_source_digest=False):
    if type(include_source_digest) is not bool:
        raise ValueError("Source fingerprint option must be boolean")
    destination = Path(destination).resolve()
    if destination.exists():
        raise ValueError("Backup destination must not exist")
    data = Path(data).resolve()
    if (
        not (data / "control.sqlite3").is_file()
        or not (data / "events.duckdb").is_file()
    ):
        raise ValueError("Source is not an initialized data directory")
    # Opening Store would migrate the very database we need for rollback.
    # Keep the service lock until both database snapshots and keys are copied.
    with closing(ProcessLock(data / "service.lock")):
        destination.mkdir(parents=True)
        _private_directory(destination, created=True)
        with (
            closing(
                sqlite3.connect(
                    (data / "control.sqlite3").as_uri() + "?mode=ro", uri=True
                )
            ) as source,
            closing(sqlite3.connect(destination / "control.sqlite3")) as target,
            target,
        ):
            source.backup(target)
        with closing(
            duckdb.connect(
                str(data / "events.duckdb"), config={"enable_external_access": "false"}
            )
        ) as analytics:
            analytics.execute("CHECKPOINT")
        # Windows holds the database file exclusively while DuckDB is connected.
        # Release that handle but retain the service process lock until copy completes.
        shutil.copyfile(data / "events.duckdb", destination / "events.duckdb")
        names = ["control.sqlite3", "events.duckdb"]
        for name in (
            "secrets.key",
            "node-membership.json",
            ".membership-enrollment.json",
        ):
            if (data / name).exists():
                shutil.copyfile(data / name, destination / name)
                if os.name != "nt":
                    (destination / name).chmod(0o600)
                names.append(name)
        for name in _segment_files(data) + [
            entry["path"] for entry in _artifact_files(data)
        ]:
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(data / name, target)
            names.append(name)
        manifest = _publish_manifest(destination, names)
        if include_source_digest:
            # The offline update must bind the live source at the exact
            # checkpoint/copy boundary, before this service lock is released.
            # Keep the on-disk backup manifest/default return contract intact.
            entries = {}
            for path in data.rglob("*"):
                if (
                    path.is_symlink()
                    or getattr(path.lstat(), "st_file_attributes", 0) & 0x400
                ):
                    raise ValueError("Source data links cannot be fingerprinted")
                if path.is_file() and path.name != "service.lock":
                    entries[path.relative_to(data).as_posix()] = sha256(path)
            manifest = {
                **manifest,
                "source_data_digest": hashlib.sha256(
                    json.dumps(
                        entries,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    ).encode()
                ).hexdigest(),
            }
        return manifest


def restore(source, destination):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if destination.exists():
        raise ValueError(
            "Restore destination must not exist; never overwrite live data"
        )
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    names = set(manifest.get("sha256", {}))
    required = {"control.sqlite3", "events.duckdb"}
    if (
        manifest.get("schema") not in (1, 2)
        or not required <= names
        or any(not _safe_backup_name(name) for name in names)
    ):
        raise ValueError("Unsupported backup manifest")
    for name in names:
        file = source / name
        if (
            file.is_symlink()
            or file.resolve() != file
            or sha256(file) != manifest["sha256"][name]
        ):
            raise ValueError("Backup checksum mismatch")
    required_objects = set(_segment_files(source)) | {
        item["path"] for item in _artifact_files(source)
    }
    if not required_objects <= names:
        raise ValueError(
            "Backup manifest omits objects referenced by the captured database"
        )
    if "audit_checkpoint" in manifest:
        from .audit_integrity import verify

        if not verify(AuditSnapshot(source), manifest["audit_checkpoint"])["valid"]:
            raise ValueError("Backup audit chain or checkpoint mismatch")
    destination.mkdir(parents=True)
    _private_directory(destination, created=True)
    for name in names:
        (destination / name).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, destination / name)
        if (
            name
            in {"secrets.key", "node-membership.json", ".membership-enrollment.json"}
            and os.name != "nt"
        ):
            (destination / name).chmod(0o600)
        if sha256(destination / name) != manifest["sha256"][name]:
            raise ValueError(
                "Restored file checksum mismatch; do not start this directory"
            )
    # Session cookies from a backup must not regain access on restoration.
    with closing(sqlite3.connect(destination / "control.sqlite3")) as db, db:
        db.execute("DELETE FROM sessions")
        for name in ("oidc_states", "oidc_mfa_challenges"):
            if db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
            ).fetchone():
                db.execute("DELETE FROM " + name)
        if db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='log_snapshots'"
        ).fetchone():
            db.execute("DELETE FROM log_snapshots")
    return {"restored": str(destination), "sessions_revoked": True}


# Stable wire identifier: old encrypted backups must remain restorable.
ENCRYPTED_MAGIC = b"SAPIENTIA-ENCRYPTED-BACKUP-1\n"
# GCM's per-nonce plaintext bound is just under 64 GiB. This format does not
# compress or materialize a whole archive in memory.
MAX_ARCHIVE_BYTES = (1 << 36) - 32
ARCHIVE_NAMES = {
    "manifest.json",
    "control.sqlite3",
    "events.duckdb",
    "secrets.key",
    "node-membership.json",
    ".membership-enrollment.json",
}


def _private_directory(path, *, created=False):
    """Protect an explicitly new empty directory; inspect existing paths only."""
    if type(created) is not bool:
        raise ValueError("Directory creation authority must be boolean")
    path = Path(os.path.abspath(path))
    for entry in (path, *path.parents):
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise PermissionError("Private backup path contains a link")
    if not path.is_dir() or created and any(path.iterdir()):
        raise PermissionError("New private backup directory must be empty")
    if os.name != "nt":
        if path.stat().st_uid != os.getuid():
            raise PermissionError("Private backup directory has another owner")
        if created:
            path.chmod(0o700)
        elif stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise PermissionError("Existing backup directory is not private")
        return
    # Windows mode=0700 can assign Administrators/OWNER RIGHTS rather than the
    # process user. Only a caller's freshly created empty directory is changed.
    import ctypes
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.POINTER(ctypes.c_void_p)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    advapi.OpenProcessToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)
    ]
    advapi.GetTokenInformation.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)
    ]
    advapi.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD, pointer,
        ctypes.c_void_p, pointer, ctypes.c_void_p, pointer,
    ]
    advapi.GetAclInformation.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_int
    ]
    advapi.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, pointer]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, pointer, ctypes.c_void_p
    ]
    advapi.GetSecurityDescriptorOwner.argtypes = [
        ctypes.c_void_p, pointer, ctypes.POINTER(wintypes.BOOL)
    ]
    advapi.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL), pointer,
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ]

    def sid_text(value):
        text = ctypes.c_wchar_p()
        if not advapi.ConvertSidToStringSidW(value, ctypes.byref(text)):
            raise PermissionError("Private backup SID is unavailable")
        try:
            return text.value
        finally:
            kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))

    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(
        kernel.GetCurrentProcess(), 8, ctypes.byref(token)
    ):
        raise PermissionError("Private backup process identity is unavailable")
    try:
        needed = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        user = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(token, 1, user, needed, ctypes.byref(needed)):
            raise PermissionError("Private backup process identity is unavailable")
        current = sid_text(ctypes.cast(user, pointer).contents.value)
    finally:
        kernel.CloseHandle(token)
    trusted_owners = {
        current, "S-1-5-18", "S-1-5-32-544",
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    }
    for attempt in range(2):
        owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        error = advapi.GetNamedSecurityInfoW(
            str(path), 1, 5, ctypes.byref(owner), None, ctypes.byref(dacl),
            None, ctypes.byref(descriptor),
        )
        if error:
            raise PermissionError("Private backup directory ACL is unavailable")
        try:
            if not owner or sid_text(owner) not in trusted_owners or not dacl:
                raise PermissionError("Private backup directory has an untrusted owner or ACL")
            if not created or attempt:
                sizes = (wintypes.DWORD * 3)()
                if not advapi.GetAclInformation(dacl, sizes, ctypes.sizeof(sizes), 2):
                    raise PermissionError("Private backup ACL is unavailable")
                for index in range(sizes[0]):
                    ace = ctypes.c_void_p()
                    if not advapi.GetAce(dacl, index, ctypes.byref(ace)):
                        raise PermissionError("Private backup ACL is unavailable")
                    header = ctypes.string_at(ace, 4)
                    if header[0] == 1:
                        continue
                    if header[0] != 0:
                        raise PermissionError("Unsupported private backup ACL grant")
                    if ctypes.c_uint32.from_address(ace.value + 4).value and sid_text(
                        ace.value + 8
                    ) not in {current, "S-1-5-18"}:
                        raise PermissionError("Existing backup directory permits another account access")
                return
        finally:
            kernel.LocalFree(descriptor)
        descriptor, owner, dacl = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        present, defaulted = wintypes.BOOL(), wintypes.BOOL()
        text = f"O:{current}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{current})"
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text, 1, ctypes.byref(descriptor), None
        ):
            raise PermissionError("Cannot construct private backup permissions")
        try:
            if (
                not advapi.GetSecurityDescriptorOwner(descriptor, ctypes.byref(owner), ctypes.byref(defaulted))
                or not advapi.GetSecurityDescriptorDacl(
                    descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
                )
                or not present
            ):
                raise PermissionError("Cannot inspect private backup permissions")
            if advapi.SetNamedSecurityInfoW(
                str(path), 1, 0x80000005, owner, None, dacl, None
            ):
                raise PermissionError("Cannot protect private backup directory")
        finally:
            kernel.LocalFree(descriptor)


def _archive_key(passphrase, salt):
    if not isinstance(passphrase, str) or not 12 <= len(passphrase) <= 1024:
        raise ValueError("Backup passphrase must be 12..1024 characters")
    return Scrypt(salt=salt, length=32, n=32768, r=8, p=1).derive(
        passphrase.encode("utf-8")
    )


class _EncryptingWriter:
    def __init__(self, stream, encryptor):
        self.stream, self.encryptor, self.total = stream, encryptor, 0

    def write(self, value):
        self.total += len(value)
        if self.total > MAX_ARCHIVE_BYTES:
            raise ValueError(
                "Encrypted backup exceeds this format's 64 GiB archive limit"
            )
        self.stream.write(self.encryptor.update(value))
        return len(value)

    def flush(self):
        self.stream.flush()


def backup_encrypted(data, destination, passphrase):
    """Create a streaming authenticated archive; passphrases never enter metadata."""
    data, destination = Path(data).resolve(), Path(destination).resolve()
    if destination.exists():
        raise ValueError("Encrypted backup destination must not exist")
    salt, nonce = os.urandom(16), os.urandom(12)
    key = _archive_key(passphrase, salt)
    header = json.dumps(
        {
            "schema": 1,
            "kdf": "scrypt",
            "n": 32768,
            "r": 8,
            "p": 1,
            "salt": base64.b64encode(salt).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "cipher": "AES-256-GCM",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    authenticated = ENCRYPTED_MAGIC + struct.pack(">I", len(header)) + header
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not data.is_dir():
        raise ValueError("Source is not an initialized data directory")
    with tempfile.TemporaryDirectory(
        prefix=".encrypted-backup-", dir=data
    ) as temporary:
        temporary = Path(temporary)
        _private_directory(temporary, created=True)
        manifest = backup(data, temporary / "snapshot")
        descriptor, pending = tempfile.mkstemp(
            prefix=".encrypted-backup-", dir=destination.parent
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(authenticated)
                encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
                encryptor.authenticate_additional_data(authenticated)
                writer = _EncryptingWriter(stream, encryptor)
                with tarfile.open(
                    fileobj=writer, mode="w|", format=tarfile.USTAR_FORMAT
                ) as archive:
                    for name in sorted(set(manifest["sha256"]) | {"manifest.json"}):
                        archive.add(
                            temporary / "snapshot" / name, arcname=name, recursive=False
                        )
                stream.write(encryptor.finalize())
                stream.write(encryptor.tag)
                stream.flush()
                os.fsync(stream.fileno())
            # Hard-link publication is atomic and refuses a competing destination.
            os.link(pending, destination)
        finally:
            if os.path.exists(pending):
                os.unlink(pending)
    return {
        "encrypted": True,
        "format": 1,
        "cipher": "AES-256-GCM",
        "destination": str(destination),
        "archive_limit_bytes": MAX_ARCHIVE_BYTES,
    }


def _decrypt_archive(source, destination, passphrase):
    size = source.stat().st_size
    with source.open("rb") as stream:
        prefix = stream.read(len(ENCRYPTED_MAGIC) + 4)
        if (
            not prefix.startswith(ENCRYPTED_MAGIC)
            or len(prefix) != len(ENCRYPTED_MAGIC) + 4
        ):
            raise ValueError("Unsupported encrypted backup format")
        length = struct.unpack(">I", prefix[-4:])[0]
        if not 1 <= length <= 4096:
            raise ValueError("Invalid encrypted backup header size")
        raw = stream.read(length)
        try:
            header = json.loads(raw)
            if (
                set(header)
                != {"schema", "kdf", "n", "r", "p", "salt", "nonce", "cipher"}
                or header["schema"] != 1
                or header["kdf"] != "scrypt"
                or header["n"] != 32768
                or header["r"] != 8
                or header["p"] != 1
                or header["cipher"] != "AES-256-GCM"
            ):
                raise ValueError()
            salt, nonce = (
                base64.b64decode(header[name], validate=True)
                for name in ("salt", "nonce")
            )
            if len(salt) != 16 or len(nonce) != 12:
                raise ValueError()
        except (ValueError, KeyError, TypeError):
            raise ValueError("Invalid encrypted backup header") from None
        encrypted_size = size - len(prefix) - length - 16
        if not 1024 <= encrypted_size <= MAX_ARCHIVE_BYTES:
            raise ValueError("Encrypted archive size is invalid or exceeds 64 GiB")
        stream.seek(-16, os.SEEK_END)
        tag = stream.read(16)
        stream.seek(len(prefix) + length)
        decryptor = Cipher(
            algorithms.AES(_archive_key(passphrase, salt)), modes.GCM(nonce, tag)
        ).decryptor()
        decryptor.authenticate_additional_data(prefix + raw)
        try:
            with destination.open("xb") as output:
                remaining = encrypted_size
                while remaining:
                    chunk = stream.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("Truncated encrypted archive")
                    output.write(decryptor.update(chunk))
                    remaining -= len(chunk)
                output.write(decryptor.finalize())
                output.flush()
                os.fsync(output.fileno())
        except InvalidTag:
            raise ValueError(
                "Encrypted backup authentication failed: wrong passphrase or altered archive"
            ) from None


def _extract_archive(source, destination):
    """Parse fixed USTAR headers without PAX/GNU expansion or extractall()."""
    destination.mkdir()
    seen, total = set(), 0
    with source.open("rb") as stream:
        while True:
            block = stream.read(512)
            if len(block) != 512:
                raise ValueError("Truncated backup archive")
            if block == b"\0" * 512:
                if stream.read(512) != b"\0" * 512:
                    raise ValueError("Invalid backup archive terminator")
                while padding := stream.read(1024 * 1024):
                    if padding.strip(b"\0"):
                        raise ValueError("Unexpected content after backup archive")
                break
            try:
                member = tarfile.TarInfo.frombuf(block, "utf-8", "strict")
            except (tarfile.HeaderError, UnicodeError):
                raise ValueError("Invalid backup archive header") from None
            if (
                not _safe_backup_name(member.name)
                or member.name in seen
                or member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE}
                or not 0 <= member.size <= MAX_ARCHIVE_BYTES
            ):
                raise ValueError(
                    "Backup archive contains an unsafe or unexpected member"
                )
            seen.add(member.name)
            total += member.size
            if (
                total > MAX_ARCHIVE_BYTES
                or member.size > source.stat().st_size - stream.tell()
            ):
                raise ValueError("Backup archive exceeds size limit or is truncated")
            (destination / member.name).parent.mkdir(parents=True, exist_ok=True)
            with (destination / member.name).open("xb") as output:
                remaining = member.size
                while remaining:
                    chunk = stream.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("Truncated backup member")
                    output.write(chunk)
                    remaining -= len(chunk)
            padding_size = -member.size % 512
            if stream.read(padding_size) != b"\0" * padding_size:
                raise ValueError("Invalid backup member padding")
    if not {"manifest.json", "control.sqlite3", "events.duckdb"} <= seen:
        raise ValueError("Backup archive is missing required files")


def restore_encrypted(source, destination, passphrase):
    """Authenticate completely before extraction and publish only a valid restore."""
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if destination.exists():
        raise ValueError(
            "Restore destination must not exist; never overwrite live data"
        )
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".encrypted-restore-", dir=destination.parent
    ) as temporary:
        temporary = Path(temporary)
        _private_directory(temporary, created=True)
        _decrypt_archive(source, temporary / "verified.tar", passphrase)
        _extract_archive(temporary / "verified.tar", temporary / "snapshot")
        restore(temporary / "snapshot", temporary / "restored")
        if destination.exists():
            raise ValueError("Restore destination already exists")
        # Share the bounded Windows sharing-mode/no-overwrite publisher with
        # format 2; authenticated format-1 restores need the same guarantee.
        from .backup_stream import _publish

        _publish(temporary / "restored", destination)
    return {"restored": str(destination), "encrypted": True, "sessions_revoked": True}
