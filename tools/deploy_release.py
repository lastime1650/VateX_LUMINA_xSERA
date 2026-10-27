"""Verify and stage signed offline CPU releases; never execute host responses.

Run this bootstrap from a separately trusted copy with Python/cryptography.
The public trust file must be provisioned outside both bundle and installation.
Deployment is offline after verification. Old code and data remain intact;
activation replaces one pointer only after the staged data passes startup.
"""

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid
import venv
import zipfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA = "xsera.offline-release.v1"
STATE_SCHEMA = "xsera.deployment.v1"
MAX_FILES = 10000
MAX_BYTES = 10 * 1024**3


def canonical(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()


def digest_file(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def read_json(path, maximum=8 * 1024**2):
    path = plain_path(path)
    if path.stat().st_size > maximum:
        raise ValueError("JSON size limit exceeded")
    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_pairs,
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError("Non-finite JSON")
        ),
    )


def plain_path(path):
    path = Path(os.path.abspath(path))
    for item in (path, *path.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Deployment paths cannot contain links or reparse points")
    return path


def child(root, name):
    if not isinstance(name, str) or not name or "\\" in name or ":" in name:
        raise ValueError("Invalid release member")
    value = PurePosixPath(name)
    if value.is_absolute() or any(part in ("..", ".", "") for part in name.split("/")):
        raise ValueError("Invalid release member")
    result = plain_path(root / Path(*value.parts))
    if not result.is_relative_to(root):
        raise ValueError("Release member escaped root")
    return result


class _WindowsAcl:
    """Fresh Win32 ACL inspection/application; no shell or permission cache."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes

        self.c, self.w = ctypes, wintypes
        self.api = ctypes.WinDLL("advapi32", use_last_error=True)
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        pointer = ctypes.POINTER(ctypes.c_void_p)
        self.kernel.GetCurrentProcess.restype = wintypes.HANDLE
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.LocalFree.argtypes = [ctypes.c_void_p]
        self.api.OpenProcessToken.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.HANDLE),
        ]
        self.api.GetTokenInformation.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self.api.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_wchar_p),
        ]
        self.api.GetNamedSecurityInfoW.argtypes = [
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            pointer,
            ctypes.c_void_p,
            pointer,
            ctypes.c_void_p,
            pointer,
        ]
        self.api.GetAclInformation.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_int,
        ]
        self.api.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, pointer]
        self.api.GetSecurityDescriptorControl.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.WORD),
            ctypes.POINTER(wintypes.DWORD),
        ]
        self.api.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            pointer,
            ctypes.c_void_p,
        ]
        self.api.GetSecurityDescriptorOwner.argtypes = [
            ctypes.c_void_p,
            pointer,
            ctypes.POINTER(wintypes.BOOL),
        ]
        self.api.GetSecurityDescriptorDacl.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.BOOL),
            pointer,
            ctypes.POINTER(wintypes.BOOL),
        ]
        self.api.SetNamedSecurityInfoW.argtypes = [
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        token = wintypes.HANDLE()
        if not self.api.OpenProcessToken(
            self.kernel.GetCurrentProcess(), 8, ctypes.byref(token)
        ):
            raise PermissionError("Installer process identity is unavailable")
        try:
            needed = wintypes.DWORD()
            self.api.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
            data = ctypes.create_string_buffer(needed.value)
            if not self.api.GetTokenInformation(
                token, 1, data, needed, ctypes.byref(needed)
            ):
                raise PermissionError("Installer process identity is unavailable")
            self.current = self.sid(ctypes.cast(data, pointer).contents.value)
        finally:
            self.kernel.CloseHandle(token)
        self.owners = {
            self.current,
            "S-1-5-18",
            "S-1-5-32-544",
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
        }

    def sid(self, pointer):
        value = self.c.c_wchar_p()
        if not self.api.ConvertSidToStringSidW(pointer, self.c.byref(value)):
            raise PermissionError("Installer ACL SID is unavailable")
        try:
            return value.value
        finally:
            self.kernel.LocalFree(self.c.cast(value, self.c.c_void_p))

    def inspect(self, path):
        c, w = self.c, self.w
        owner, dacl, descriptor = c.c_void_p(), c.c_void_p(), c.c_void_p()
        error = self.api.GetNamedSecurityInfoW(
            str(path),
            1,
            5,
            c.byref(owner),
            None,
            c.byref(dacl),
            None,
            c.byref(descriptor),
        )
        if error:
            raise PermissionError("Managed destination ACL is unavailable")
        try:
            if not owner or not dacl:
                raise PermissionError("Managed destination has no protected owner/DACL")
            control, revision = w.WORD(), w.DWORD()
            if not self.api.GetSecurityDescriptorControl(
                descriptor, c.byref(control), c.byref(revision)
            ):
                raise PermissionError("Managed destination ACL control is unavailable")
            counts = (w.DWORD * 3)()
            if not self.api.GetAclInformation(dacl, counts, c.sizeof(counts), 2):
                raise PermissionError("Managed destination ACL is unavailable")
            grants = []
            for position in range(counts[0]):
                ace = c.c_void_p()
                if not self.api.GetAce(dacl, position, c.byref(ace)):
                    raise PermissionError(
                        "Managed destination ACL entry is unavailable"
                    )
                header = c.string_at(ace, 4)
                if header[0] == 1:
                    continue
                if header[0] != 0:
                    raise PermissionError("Unsupported managed destination ACL grant")
                grants.append(
                    {
                        "sid": self.sid(ace.value + 8),
                        "rights": c.c_uint32.from_address(ace.value + 4).value,
                        "flags": header[1],
                    }
                )
            return {
                "owner": self.sid(owner),
                "protected": bool(control.value & 0x1000),
                "grants": grants,
            }
        finally:
            self.kernel.LocalFree(descriptor)

    def check_ancestor(self, path):
        state = self.inspect(path)
        if state["owner"] not in self.owners:
            raise PermissionError("Managed destination ancestor has an untrusted owner")
        # Other users may read or create unrelated sibling directories; they
        # must not replace this path via DELETE_CHILD, ownership or DACL grants.
        if any(
            not entry["flags"] & 8
            and entry["sid"] not in self.owners | {"S-1-3-4"}
            and entry["rights"] & 0x100D0040
            for entry in state["grants"]
        ):
            raise PermissionError(
                "Managed destination ancestor permits untrusted replacement"
            )

    def check_existing(self, path):
        state = self.inspect(path)
        if state["owner"] not in self.owners or any(
            entry["sid"] not in self.owners | {"S-1-3-4"}
            and entry["rights"] & 0x500D0156
            for entry in state["grants"]
        ):
            raise PermissionError(
                "Existing managed destination permits untrusted mutation"
            )

    def require_private(self, path, *, root=False):
        state = self.inspect(path)
        if state["owner"] not in self.owners or root and not state["protected"]:
            raise PermissionError("Managed destination owner/DACL is not protected")
        if any(
            entry["sid"] not in {self.current, "S-1-5-18"} and entry["rights"]
            for entry in state["grants"]
        ):
            raise PermissionError("Managed destination permits another account access")
        if root and not all(entry["flags"] & 3 == 3 for entry in state["grants"]):
            raise PermissionError("Managed destination DACL must protect descendants")
        return state

    def protect(self, path):
        if self.inspect(path)["owner"] not in self.owners:
            raise PermissionError("Refusing to change an untrusted destination owner")
        c, w = self.c, self.w
        descriptor, owner, dacl = c.c_void_p(), c.c_void_p(), c.c_void_p()
        defaulted, present = w.BOOL(), w.BOOL()
        trustees = sorted({self.current, "S-1-5-18"})
        text = (
            "O:"
            + self.current
            + "D:P"
            + "".join("(A;OICI;FA;;;" + sid + ")" for sid in trustees)
        )
        if not self.api.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text, 1, c.byref(descriptor), None
        ):
            raise PermissionError("Unable to construct private destination DACL")
        try:
            if (
                not self.api.GetSecurityDescriptorOwner(
                    descriptor, c.byref(owner), c.byref(defaulted)
                )
                or not self.api.GetSecurityDescriptorDacl(
                    descriptor, c.byref(present), c.byref(dacl), c.byref(defaulted)
                )
                or not present
            ):
                raise PermissionError("Unable to read private destination DACL")
            if self.api.SetNamedSecurityInfoW(
                str(path), 1, 0x80000005, owner, None, dacl, None
            ):
                raise PermissionError("Unable to protect managed destination DACL")
        finally:
            self.kernel.LocalFree(descriptor)


def _destination_members(root):
    for path in root.rglob("*"):
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400
            or stat.S_ISREG(info.st_mode)
            and info.st_nlink != 1
        ):
            raise ValueError(
                "Managed destination contains links or shared file identities"
            )
        yield path


def _prepare_destination(root):
    """Validate custody before creating a lock or changing destination ACLs."""
    root = plain_path(root)
    if root.exists():
        if not root.is_dir():
            raise ValueError("Managed destination must be a directory")
        if any(root.iterdir()):
            marker = root / "deployment.json"
            if not marker.is_file() or read_json(marker) != {
                "schema": STATE_SCHEMA,
                "profile": "cpu-observe",
            }:
                raise ValueError("Unmanaged nonempty destination is preserved")
    else:
        root.mkdir(mode=0o700, parents=True)
    if os.name == "nt":
        security = _WindowsAcl()
        for parent in root.parents:
            security.check_ancestor(parent)
        # Preflight before inheritance propagation: never modify a linked
        # object outside this independently recognized managed tree.
        if any(root.iterdir()):
            security.check_existing(root)
        for path in _destination_members(root):
            security.check_existing(path)
        security.protect(root)
        security.require_private(root, root=True)
        for path in _destination_members(root):
            security.require_private(path)
    return root


def private_directory(root, name, *, exist_ok=False):
    """Secure only directories this call creates inside a private managed root."""
    root, target = plain_path(root), child(plain_path(root), name)
    if not root.is_dir():
        raise ValueError("Private directory parent must already exist")
    security = _WindowsAcl() if os.name == "nt" else None
    if security:
        security.require_private(root)
    parts = target.relative_to(root).parts
    current = root
    for index, part in enumerate(parts):
        current = plain_path(current / part)
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            # Includes a losing creation race: never normalize a directory
            # another caller created, even if it is empty or administrator-owned.
            if index == len(parts) - 1 and not exist_ok:
                raise
            if not current.is_dir():
                raise ValueError("Private directory member is not a directory")
            if security:
                security.require_private(current)
        else:
            plain_path(current)
            if security:
                # Python 3.12 mode=0700 installs its own protected DACL on
                # Windows. Replace that new-directory DACL before any content.
                security.protect(current)
                security.require_private(current, root=True)
    return target


def atomic(path, value):
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".new")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(
            value, stream, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False
        )
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def verify_bundle(bundle, trust_file, *, destination=None):
    bundle, trust_file = plain_path(bundle), plain_path(trust_file)
    if (
        trust_file.is_relative_to(bundle)
        or destination
        and trust_file.is_relative_to(plain_path(destination))
    ):
        raise ValueError("Trust must be provisioned outside bundle and installation")
    trust, document = (
        read_json(trust_file, 65536),
        read_json(bundle / "release-manifest.json"),
    )
    if trust.get("schema") not in {"xsera.release.trust.v1", "xsera.agent.trust.v1"}:
        raise ValueError("Unsupported trust schema")
    if document.get("schema") != SCHEMA or document.get("profile") != "cpu-observe":
        raise ValueError("Unsupported release profile")
    signature = document.get("signature", {})
    key_id = signature.get("key_id")
    keys, revoked = trust.get("keys", {}), trust.get("revoked_key_ids", [])
    if (
        not isinstance(keys, dict)
        or not isinstance(revoked, list)
        or not isinstance(key_id, str)
    ):
        raise ValueError("Invalid trust or signer")  # noqa: TRY004 -- Untrusted release validation contract.
    if (
        signature.get("algorithm") != "Ed25519"
        or key_id not in keys
        or key_id in revoked
    ):
        raise PermissionError("Release signer is missing, untrusted or revoked")
    unsigned = {key: value for key, value in document.items() if key != "signature"}
    try:
        public = bytes.fromhex(keys[key_id])
        if hashlib.sha256(public).hexdigest()[:32] != key_id:
            raise ValueError("Key fingerprint mismatch")
        Ed25519PublicKey.from_public_bytes(public).verify(
            base64.b64decode(signature["value"], validate=True), canonical(unsigned)
        )
    except (InvalidSignature, ValueError, KeyError, TypeError) as error:
        raise PermissionError("Release signature verification failed") from error
    sequence = document.get("release_sequence")
    minimum = trust.get("minimum_release_sequence", 0)
    if type(sequence) is not int or type(minimum) is not int or sequence < minimum:
        raise PermissionError("Release below trusted minimum sequence")
    target = document.get("target", {})
    actual = {
        "system": platform.system().lower(),
        "machine": platform.machine().lower(),
        "python": f"{sys.version_info.major}.{sys.version_info.minor}",
    }
    if target != actual:
        raise ValueError(
            "Offline bundle target differs from this Python/OS/architecture"
        )
    files = document.get("files")
    if not isinstance(files, dict) or not files or len(files) > MAX_FILES:
        raise ValueError("Invalid release file inventory")
    total = 0
    for name, entry in files.items():
        path = child(bundle, name)
        if (
            not isinstance(entry, dict)
            or type(entry.get("bytes")) is not int
            or entry["bytes"] < 0
        ):
            raise ValueError("Invalid file description")
        total += entry["bytes"]
        if (
            total > MAX_BYTES
            or not path.is_file()
            or path.stat().st_size != entry["bytes"]
        ):
            raise ValueError("Release member missing or size differs")
        if digest_file(path) != entry.get("sha256"):
            raise PermissionError("Release member hash differs")
    actual_files = set()
    for path in bundle.rglob("*"):
        if path.is_symlink() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400:
            raise ValueError("Release contains a link")
        if path.is_file():
            actual_files.add(path.relative_to(bundle).as_posix())
            if len(actual_files) > MAX_FILES + 1:
                raise ValueError("Release file count limit exceeded")
    if actual_files != set(files) | {"release-manifest.json"}:
        raise ValueError("Release contains unlisted files")
    for field in ("wheel", "requirements_lock"):
        if document.get(field) not in files:
            raise ValueError("Missing signed installation input")
    return document


@contextmanager
def operation(root, filename=".deployment.lock"):
    if filename not in {".deployment.lock", "service.lock"}:
        raise ValueError("Invalid operation lock")
    root = (
        _prepare_destination(root)
        if filename == ".deployment.lock"
        else plain_path(root)
    )
    if not root.is_dir():
        raise ValueError("Lock directory must already exist")
    if os.name == "nt":
        _WindowsAcl().require_private(root)
    with plain_path(root / filename).open("a+b") as lock:
        if lock.seek(0, 2) == 0:
            lock.write(b"0")
            lock.flush()
        lock.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise RuntimeError("Another deployment operation is active") from error
        try:
            yield root
        finally:
            lock.seek(0)
            if os.name == "nt":
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock, fcntl.LOCK_UN)


def python_at(directory):
    return directory / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def environment(*, launch=False):
    result = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("PYTHON", "PIP_", "SAPIENTIA_", "SERA_", "XSERA_"))
    }
    result.update(
        PYTHONDONTWRITEBYTECODE="1",
        CUDA_VISIBLE_DEVICES="",
        SERA_AGENT_REQUIRE_SIGNED_PACKAGE="1",
        SAPIENTIA_BLOCK_NATIVE_RESPONSE="1",
    )
    if launch:
        # Explicit operator configuration needed for signed endpoint distribution.
        # Maintenance subprocesses never inherit this authority or test flags.
        for key in (
            "SAPIENTIA_AGENT_SIGNING_KEY_FILE",
            "SAPIENTIA_AGENT_ENDPOINT_URL",
            "SAPIENTIA_AGENT_CA_FILE",
        ):
            if key in os.environ:
                result[key] = os.environ[key]
    return result


def run(values, *, timeout=900):
    result = subprocess.run(
        list(map(str, values)),
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=environment(),
        timeout=timeout,
        check=False,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    if result.returncode:
        raise RuntimeError(
            "Staged operation failed; active deployment was not replaced (exit "
            + str(result.returncode)
            + ")"
        )
    return result.stdout


def verify_installed(bundle, manifest, environment_path):
    """Compare executable library bytes with RECORDs inside signed wheels.

    The Python runtime/bootstrap is a separately trusted prerequisite. Generated
    entry-point wrappers and RECORD files are not used by our -m launcher.
    The target contains no bootstrap pip. Bytecode is disabled at installation
    and launch, and unexpected importable files are rejected before execution.
    """
    site = environment_path / (
        "Lib/site-packages"
        if os.name == "nt"
        else f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages"
    )
    expected = {}
    for name in manifest["files"]:
        if not name.startswith("wheelhouse/") or not name.endswith(".whl"):
            continue
        with zipfile.ZipFile(child(bundle, name)) as wheel:
            records = [
                name
                for name in wheel.namelist()
                if name.endswith(".dist-info/RECORD")
                and len(PurePosixPath(name).parts) == 2
            ]
            if len(records) != 1:
                raise ValueError("Wheel RECORD missing or ambiguous")
            for row in csv.reader(io.StringIO(wheel.read(records[0]).decode("utf-8"))):
                member, encoded, _size = row
                if not encoded:
                    continue
                algorithm, raw = encoded.split("=", 1)
                if algorithm != "sha256":
                    raise ValueError("Wheel RECORD hash algorithm unsupported")
                parts = PurePosixPath(member).parts
                base, relative = site, member
                if parts and parts[0].endswith(".data"):
                    if len(parts) < 3:
                        raise ValueError("Invalid wheel data member")
                    if parts[1] == "scripts":
                        continue
                    if parts[1] in {"purelib", "platlib"}:
                        relative = "/".join(parts[2:])
                    elif parts[1] == "data":
                        base, relative = environment_path, "/".join(parts[2:])
                    else:
                        continue
                path = child(base, relative)
                target_hash = base64.urlsafe_b64decode(
                    raw + "=" * (-len(raw) % 4)
                ).hex()
                if path in expected and expected[path] != target_hash:
                    raise ValueError("Overlapping wheel content differs")
                if not path.is_file() or digest_file(path) != target_hash:
                    raise PermissionError("Installed library differs from signed wheel")
                expected[path] = target_hash
    if not expected:
        raise ValueError("No installed content verified")
    generated_metadata = {"INSTALLER", "REQUESTED", "direct_url.json", "RECORD"}
    for path in site.rglob("*"):
        path = plain_path(path)
        if not path.is_file() or path in expected:
            continue
        relative = path.relative_to(site)
        # pip emits these inert installation records; they never grant
        # execution authority and are not inputs to our integrity decision.
        if (
            len(relative.parts) == 2
            and relative.parts[0].endswith(".dist-info")
            and relative.name in generated_metadata
        ):
            continue
        raise PermissionError("Installed environment contains an unlisted file")
    return {
        "verified_files": len(expected),
        "python_runtime_independently_trusted": True,
    }


def data_digest(directory):
    # Includes all durable data, not mtime. A changed data tree blocks rollback;
    # operators must never silently discard records accepted after activation.
    values = {}
    for path in plain_path(directory).rglob("*"):
        if path.is_symlink() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400:
            raise ValueError("Data links cannot be fingerprinted")
        if path.is_file() and path.name not in {"service.lock"}:
            values[path.relative_to(directory).as_posix()] = digest_file(path)
    return hashlib.sha256(canonical(values)).hexdigest()


PROBE = """import json,sys
from pathlib import Path
from sapientia.storage import Store,Settings
from sapientia import __version__
from sapientia.api import create_app
root=Path(sys.argv[1])
app=create_app(Settings(root),background=False)
store=app.state.store
with store.control(local=True) as db:
 result={'version':__version__,'cases':db.execute('SELECT count(*) FROM incidents').fetchone()[0],
         'users':db.execute('SELECT count(*) FROM users').fetchone()[0]}
app.state.runtime.close();store.close()
print(json.dumps(result))
"""


def active(root):
    path = root / "active.json"
    if not path.exists():
        return None
    value = read_json(path, 65536)
    if value.get("schema") != STATE_SCHEMA:
        raise ValueError("Unrecognized deployment pointer")
    child(root, value["environment"])
    child(root, value["data"])
    return value


def stage(bundle, trust_file, destination, *, update=False):
    manifest = verify_bundle(bundle, trust_file, destination=destination)
    bundle = plain_path(bundle)
    with operation(destination) as root:
        previous = active(root)
        if bool(previous) != bool(update):
            raise ValueError(
                "Use update for an existing installation; install for a new one"
            )
        marker = root / "deployment.json"
        if not marker.exists():
            if {p.name for p in root.iterdir()} != {".deployment.lock"}:
                raise ValueError("Destination must be a new empty managed directory")
            atomic(marker, {"schema": STATE_SCHEMA, "profile": "cpu-observe"})
        elif read_json(marker).get("schema") != STATE_SCHEMA:
            raise ValueError("Unrecognized deployment directory")
        if (
            previous
            and manifest["release_sequence"] < previous["highest_release_sequence"]
        ):
            raise PermissionError("Normal update cannot downgrade release sequence")
        identifier = uuid.uuid4().hex
        for name in ("transactions", "releases", "data", "backups", "release_payloads"):
            private_directory(root, name, exist_ok=True)
        environment_path = child(root, "releases/" + identifier)
        cached_bundle = private_directory(root, "release_payloads/" + identifier)
        for filename in [*manifest["files"], "release-manifest.json"]:
            target = child(cached_bundle, filename)
            if target.parent != cached_bundle:
                private_directory(
                    cached_bundle, target.parent.relative_to(cached_bundle).as_posix(),
                    exist_ok=True,
                )
            shutil.copyfile(child(bundle, filename), target)
        verify_bundle(cached_bundle, trust_file, destination=root)
        bundle = cached_bundle
        data = child(root, "data/" + identifier)
        journal_file = child(root, "transactions/" + identifier + ".json")
        journal = {
            "schema": "xsera.deployment-transaction.v1",
            "id": identifier,
            "phase": "installing",
            "bundle": str(bundle),
            "trust_file": str(plain_path(trust_file)),
            "previous": previous,
            "environment": environment_path.relative_to(root).as_posix(),
            "data": data.relative_to(root).as_posix(),
            "version": manifest["version"],
            "release_sequence": manifest["release_sequence"],
            "manifest_digest": hashlib.sha256(canonical(manifest)).hexdigest(),
            "created": time.time(),
            "cpu_only": True,
            "native_response": "blocked",
        }
        atomic(journal_file, journal)
        try:
            private_directory(root, environment_path.relative_to(root).as_posix())
            venv.EnvBuilder(with_pip=False, clear=False, symlinks=False).create(
                environment_path
            )
            target_python = python_at(environment_path)
            run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-m",
                    "pip",
                    "--python",
                    target_python,
                    "install",
                    "--disable-pip-version-check",
                    "--no-input",
                    "--no-index",
                    "--no-compile",
                    "--only-binary=:all:",
                    "--require-hashes",
                    "--find-links",
                    bundle / "wheelhouse",
                    "-r",
                    child(bundle, manifest["requirements_lock"]),
                ]
            )
            run(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-m",
                    "pip",
                    "--python",
                    target_python,
                    "check",
                ]
            )
            installation_integrity = verify_installed(
                bundle, manifest, environment_path
            )
            if previous:
                snapshot = child(root, "backups/" + identifier)
                captured = json.loads(
                    run(
                        [
                            target_python,
                            "-I",
                            "-B",
                            "-c",
                            "import json,sys;from pathlib import Path;from sapientia.backup import backup;print(json.dumps(backup(Path(sys.argv[1]),Path(sys.argv[2]),include_source_digest=True)))",
                            child(root, previous["data"]),
                            snapshot,
                        ]
                    )
                    .strip()
                    .splitlines()[-1]
                )
                previous_digest = captured.get("source_data_digest")
                if not isinstance(previous_digest, str) or not re.fullmatch(
                    r"[0-9a-f]{64}", previous_digest
                ):
                    raise PermissionError(
                        "Backup did not bind the source snapshot boundary"
                    )
                journal["previous_data_digest"] = previous_digest
                journal["backup"] = snapshot.relative_to(root).as_posix()
                atomic(journal_file, journal)
                run(
                    [
                        target_python,
                        "-I",
                        "-B",
                        "-c",
                        "import sys;from pathlib import Path;from sapientia.backup import restore;restore(Path(sys.argv[1]),Path(sys.argv[2]))",
                        snapshot,
                        data,
                    ]
                )
            health = json.loads(
                run([target_python, "-I", "-B", "-c", PROBE, data])
                .strip()
                .splitlines()[-1]
            )
            if health["version"] != manifest["version"]:
                raise ValueError("Installed version differs from signed manifest")
            journal.update(
                phase="ready",
                health=health,
                data_digest=data_digest(data),
                installation_integrity=installation_integrity,
            )
            atomic(journal_file, journal)
        except BaseException as error:
            journal.update(
                phase="failed",
                failure_type=type(error).__name__,
                active_unchanged=active(root) == previous,
            )
            atomic(journal_file, journal)
            raise
        return journal


def activate(destination, transaction):
    if not re.fullmatch(r"[0-9a-f]{32}", transaction):
        raise ValueError("Invalid transaction identifier")
    with operation(destination) as root:
        path = child(root, "transactions/" + transaction + ".json")
        journal = read_json(path)
        if (
            journal["phase"] == "active"
            and (active(root) or {}).get("transaction") == transaction
        ):
            return active(root)
        if journal["phase"] != "ready" or active(root) != journal["previous"]:
            raise RuntimeError("Transaction is not ready or active deployment changed")
        manifest = verify_bundle(
            journal["bundle"], journal["trust_file"], destination=root
        )
        if (
            hashlib.sha256(canonical(manifest)).hexdigest()
            != journal["manifest_digest"]
        ):
            raise PermissionError("Staged release identity changed")
        verify_installed(
            Path(journal["bundle"]), manifest, child(root, journal["environment"])
        )
        if data_digest(child(root, journal["data"])) != journal["data_digest"]:
            raise PermissionError("Staged data changed after validation")
        value = {
            "schema": STATE_SCHEMA,
            "transaction": transaction,
            "environment": journal["environment"],
            "data": journal["data"],
            "version": journal["version"],
            "release_sequence": journal["release_sequence"],
            "highest_release_sequence": max(
                journal["release_sequence"],
                (journal["previous"] or {}).get("highest_release_sequence", 0),
            ),
            "activated_data_digest": journal["data_digest"],
            "bundle": journal["bundle"],
            "trust_file": journal["trust_file"],
            "manifest_digest": journal["manifest_digest"],
            "profile": "cpu-observe",
            "native_response": "blocked",
            "cpu_only": True,
        }
        # One atomic pointer names both code and data. A crash before/after this
        # line leaves the complete old or complete new deployment addressable.
        if journal["previous"]:
            with operation(child(root, journal["previous"]["data"]), "service.lock"):
                if data_digest(child(root, journal["previous"]["data"])) != journal.get(
                    "previous_data_digest"
                ):
                    raise PermissionError(
                        "Previous data changed after snapshot; restage to preserve accepted records"
                    )
                atomic(root / "active.json", value)
        else:
            atomic(root / "active.json", value)
        journal.update(phase="active", activated=time.time())
        atomic(path, journal)
        return value


def rollback(destination):
    with operation(destination) as root:
        current = active(root)
        if not current:
            raise ValueError("No active release")
        journal_path = child(root, "transactions/" + current["transaction"] + ".json")
        journal = read_json(journal_path)
        previous = journal.get("previous")
        if not previous:
            raise ValueError("No prior installation to restore")
        if (
            data_digest(child(root, current["data"]))
            != current["activated_data_digest"]
        ):
            raise PermissionError(
                "Current data changed; rollback would discard accepted records. Preserve and reconcile first."
            )
        old_manifest = verify_bundle(
            previous["bundle"], current["trust_file"], destination=root
        )
        if (
            hashlib.sha256(canonical(old_manifest)).hexdigest()
            != previous["manifest_digest"]
        ):
            raise PermissionError("Previous release changed")
        verify_installed(
            Path(previous["bundle"]), old_manifest, child(root, previous["environment"])
        )
        previous = {
            **previous,
            "highest_release_sequence": current["highest_release_sequence"],
        }
        with (
            operation(child(root, current["data"]), "service.lock"),
            operation(child(root, previous["data"]), "service.lock"),
        ):
            if (
                data_digest(child(root, current["data"]))
                != current["activated_data_digest"]
            ):
                raise PermissionError("Current data changed before rollback")
            atomic(root / "active.json", previous)
        journal.update(phase="rolled_back", rolled_back=time.time())
        atomic(journal_path, journal)
        return previous


def recover(destination, transaction):
    """Reconcile pointer/journal after interruption; never overwrite live data."""
    if not re.fullmatch(r"[0-9a-f]{32}", transaction):
        raise ValueError("Invalid transaction")
    with operation(destination) as root:
        path = child(root, "transactions/" + transaction + ".json")
        journal = read_json(path)
        current = active(root)
        if current and current.get("transaction") == transaction:
            manifest = verify_bundle(
                current["bundle"], current["trust_file"], destination=root
            )
            if (
                hashlib.sha256(canonical(manifest)).hexdigest()
                != current["manifest_digest"]
            ):
                raise PermissionError("Interrupted release signature changed")
            verify_installed(
                Path(current["bundle"]), manifest, child(root, current["environment"])
            )
            journal.update(phase="active", recovered=time.time())
        elif current == journal.get("previous") and journal["phase"] in {
            "installing",
            "failed",
        }:
            journal.update(
                phase="aborted", recovered=time.time(), active_unchanged=True
            )
        elif current == journal.get("previous") and journal["phase"] == "ready":
            manifest = verify_bundle(
                journal["bundle"], journal["trust_file"], destination=root
            )
            if (
                hashlib.sha256(canonical(manifest)).hexdigest()
                != journal["manifest_digest"]
            ):
                raise PermissionError("Interrupted staged release identity changed")
            verify_installed(
                Path(journal["bundle"]), manifest, child(root, journal["environment"])
            )
            if data_digest(child(root, journal["data"])) != journal["data_digest"]:
                raise PermissionError("Interrupted staged data changed")
            return {
                "phase": "ready",
                "id": transaction,
                "action": "Review and run activate, or retain current release",
            }
        else:
            raise RuntimeError("Deployment state requires operator reconciliation")
        atomic(path, journal)
        return {"phase": journal["phase"], "id": transaction, "native_host_effects": 0}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=(
            "verify",
            "install",
            "update",
            "activate",
            "rollback",
            "recover",
            "status",
            "launch",
        ),
    )
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--trust-file", type=Path)
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--transaction")
    parser.add_argument("--prepare-only", action="store_true")
    values = list(sys.argv[1:] if argv is None else argv)
    server_arguments = []
    if "--" in values:
        boundary = values.index("--")
        values, server_arguments = values[:boundary], values[boundary + 1 :]
    args = parser.parse_args(values)
    if server_arguments and args.command != "launch":
        parser.error("Server arguments apply only to launch")
    if args.command in {"verify", "install", "update"} and (
        not args.bundle or not args.trust_file
    ):
        parser.error("bundle and externally provisioned trust-file required")
    if args.command != "verify" and not args.destination:
        parser.error("destination required")
    if args.command == "verify":
        manifest = verify_bundle(
            args.bundle, args.trust_file, destination=args.destination
        )
        result = {
            "verified": True,
            "version": manifest["version"],
            "profile": manifest["profile"],
            "signer": manifest["signature"]["key_id"],
            "files": len(manifest["files"]),
        }
    elif args.command in {"install", "update"}:
        result = stage(
            args.bundle,
            args.trust_file,
            args.destination,
            update=args.command == "update",
        )
        if not args.prepare_only:
            result = activate(args.destination, result["id"])
    elif args.command == "activate":
        result = activate(args.destination, args.transaction or "")
    elif args.command == "rollback":
        result = rollback(args.destination)
    elif args.command == "recover":
        result = recover(args.destination, args.transaction or "")
    elif args.command == "status":
        result = active(plain_path(args.destination))
    else:
        with operation(args.destination) as root:
            value = active(root)
            if not value:
                raise ValueError("No active deployment")
            document = verify_bundle(
                value["bundle"], value["trust_file"], destination=root
            )
            if (
                hashlib.sha256(canonical(document)).hexdigest()
                != value["manifest_digest"]
            ):
                raise PermissionError("Active release differs from pinned release")
            verify_installed(
                Path(value["bundle"]), document, child(root, value["environment"])
            )
            result_code = subprocess.call(
                [
                    str(python_at(child(root, value["environment"]))),
                    "-I",
                    "-B",
                    "-m",
                    "sapientia",
                    "--data",
                    str(child(root, value["data"])),
                    "serve",
                    *server_arguments,
                ],
                env=environment(launch=True),
            )
            return result_code
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
