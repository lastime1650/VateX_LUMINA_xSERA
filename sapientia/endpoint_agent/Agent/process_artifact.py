"""Explicit, bounded live-process disk-image observation. Never executes bytes."""

import ctypes
import hashlib
import os
import stat
import time
from pathlib import Path

from . import response as base

MAX_BYTES = 32 * 1024 * 1024


def limit(settings):
    value = settings.get("max_process_artifact_bytes", MAX_BYTES)
    if type(value) is not int or not 1 <= value <= MAX_BYTES:
        raise ValueError("Process executable collection limit must be 1..32 MiB")
    return value


def _path(value):
    if not isinstance(value, str) or not value or "\0" in value:
        raise ValueError("Exact process executable path required")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or value.startswith(("\\\\", "//")):
        raise PermissionError("Local canonical process executable path required")
    if os.name == "nt" and (len(value) < 3 or value[1:3] not in {":\\", ":/"} or ":" in value[2:]):
        raise PermissionError("Device paths and alternate streams are forbidden")
    base._no_links(path)
    canonical = path.resolve(strict=True)
    if os.path.normcase(os.path.normpath(str(canonical))) != os.path.normcase(os.path.normpath(value)):
        raise PermissionError("Executable path must already be canonical")
    return canonical


def _instance(target, host, settings):
    info = base.inspect_process(target["pid"], host)
    path = _path(target["path"])
    actual = _path(info["executable"])
    if os.path.normcase(str(path)) != os.path.normcase(str(actual)):
        raise PermissionError("Live process executable differs from the reported path")
    allowed = settings.get("allowed_process_executables", [])
    if not isinstance(allowed, list) or not 1 <= len(allowed) <= 32 or os.path.normcase(str(path)) not in {os.path.normcase(str(_path(item))) for item in allowed}:
        raise PermissionError("Executable differs from the current exact no-link local allowlist")
    base._check_process(info, target, settings)
    return info, path


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def _read_fd(path, maximum, deadline, keep, verify_process=None):
    """Walk from the root with no-follow directory handles on POSIX."""
    parent = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    fd = None
    try:
        for component in path.parts[1:-1]:
            next_parent = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = next_parent
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=parent)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= maximum:
            raise PermissionError("Process image must be a single regular file within its byte limit")
        digest, body, total = hashlib.sha256(), bytearray(), 0
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("Process executable observation deadline exceeded")
            block = os.read(fd, min(65536, maximum + 1 - total))
            if not block:
                break
            total += len(block)
            if total > maximum:
                raise PermissionError("Process executable grew beyond its byte limit")
            digest.update(block)
            if keep:
                body.extend(block)
        if verify_process:
            verify_process({"device": before.st_dev, "inode": before.st_ino})
        after = os.fstat(fd)
        base._no_links(path)
        named = path.stat(follow_symlinks=False)
        if _stamp(before) != _stamp(after) or _stamp(after) != _stamp(named) or total != before.st_size:
            raise PermissionError("Process executable changed during observation")
        return {"device": before.st_dev, "inode": before.st_ino, "bytes": total, "modified_ns": before.st_mtime_ns}, digest.hexdigest(), bytes(body)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _read_windows(path, maximum, deadline, keep, verify_process=None):
    """Pin a read handle denying writes/deletes; reject reparse and path swaps."""
    kernel, types = base._windows()

    class Info(ctypes.Structure):
        _fields_ = [("attributes", types.DWORD), ("created", types.FILETIME), ("access", types.FILETIME),
                    ("written", types.FILETIME), ("volume", types.DWORD), ("size_high", types.DWORD),
                    ("size_low", types.DWORD), ("links", types.DWORD), ("index_high", types.DWORD), ("index_low", types.DWORD)]

    kernel.CreateFileW.argtypes = (types.LPCWSTR, types.DWORD, types.DWORD, ctypes.c_void_p, types.DWORD, types.DWORD, types.HANDLE)
    kernel.CreateFileW.restype = types.HANDLE
    kernel.GetFileInformationByHandle.argtypes = (types.HANDLE, ctypes.POINTER(Info))
    kernel.GetFileInformationByHandle.restype = types.BOOL
    kernel.GetFinalPathNameByHandleW.argtypes = (types.HANDLE, types.LPWSTR, types.DWORD, types.DWORD)
    kernel.GetFinalPathNameByHandleW.restype = types.DWORD
    kernel.ReadFile.argtypes = (types.HANDLE, ctypes.c_void_p, types.DWORD, ctypes.POINTER(types.DWORD), ctypes.c_void_p)
    kernel.ReadFile.restype = types.BOOL
    handle = kernel.CreateFileW(str(path), 0x80000000, 0x1, None, 3, 0x00200000 | 0x08000000, None)
    if handle in (None, ctypes.c_void_p(-1).value):
        raise OSError("Process image cannot be opened without permitting writes/deletion")
    try:
        def identity():
            info, final = Info(), ctypes.create_unicode_buffer(32768)
            if not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
                raise OSError("Cannot verify executable file identity")
            length = kernel.GetFinalPathNameByHandleW(handle, final, 32768, 0)
            if not 0 < length < 32768 or os.path.normcase(final.value.removeprefix("\\\\?\\")) != os.path.normcase(str(path)):
                raise PermissionError("Opened executable differs from the approved canonical path")
            size = (info.size_high << 32) | info.size_low
            if info.attributes & (0x400 | 0x10) or info.links != 1 or not 0 < size <= maximum:
                raise PermissionError("Executable is linked, reparse, nonregular or exceeds its byte limit")
            return (info.volume, info.index_high, info.index_low, size, info.written.dwHighDateTime, info.written.dwLowDateTime, info.links)

        before = identity()
        digest, body, total = hashlib.sha256(), bytearray(), 0
        buffer, read = ctypes.create_string_buffer(65536), types.DWORD()
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("Process executable observation deadline exceeded")
            if not kernel.ReadFile(handle, buffer, min(65536, maximum + 1 - total), ctypes.byref(read), None):
                raise OSError("Process executable read failed")
            if not read.value:
                break
            total += read.value
            if total > maximum:
                raise PermissionError("Process executable grew beyond its byte limit")
            block = buffer.raw[:read.value]
            digest.update(block)
            if keep:
                body.extend(block)
        if verify_process:
            verify_process(None)
        base._no_links(path)
        if before != identity() or total != before[3]:
            raise PermissionError("Process executable changed during observation")
        return {"volume": before[0], "file_id": str((before[1] << 32) | before[2]), "bytes": total,
                "modified_filetime": str((before[4] << 32) | before[5])}, digest.hexdigest(), bytes(body)
    finally:
        kernel.CloseHandle(handle)


def observe(target, host, settings, *, collect=False):
    if settings.get("enabled") is not True or settings.get("allow_investigation") is not True or settings.get("allow_process_artifact_collection") is not True:
        raise PermissionError("Process executable investigation requires explicit local opt-in")
    maximum = min(limit(settings), target.get("max_bytes", MAX_BYTES))
    if type(maximum) is not int or not 1 <= maximum <= MAX_BYTES:
        raise ValueError("Invalid process executable collection limit")
    before, path = _instance(target, host, settings)
    deadline = time.monotonic() + 5
    def verify_process(file_identity):
        current, current_path = _instance(target, host, settings)
        if any(before[key] != current[key] for key in ("pid", "guid", "start_identity", "executable")) or path != current_path:
            raise PermissionError("Process incarnation or executable changed during observation")
        if file_identity is not None:
            mapped = os.stat(f"/proc/{target['pid']}/exe")
            if (mapped.st_dev, mapped.st_ino) != (file_identity["device"], file_identity["inode"]):
                raise PermissionError("Process mapped image differs from the opened disk executable")
    identity, digest, body = (_read_windows if os.name == "nt" else _read_fd)(path, maximum, deadline, collect, verify_process)
    after, current_path = _instance(target, host, settings)
    if any(before[key] != after[key] for key in ("pid", "guid", "start_identity", "executable")) or path != current_path:
        raise PermissionError("Process incarnation or executable changed during observation")
    if os.name != "nt":
        # The kernel's current executable inode must be the exact opened disk object.
        mapped = os.stat(f"/proc/{target['pid']}/exe")
        if (mapped.st_dev, mapped.st_ino) != (identity["device"], identity["inode"]):
            raise PermissionError("Process mapped image differs from the opened disk executable")
    if collect and digest != target["sha256"]:
        raise PermissionError("Process executable hash differs from approved original evidence")
    return {"pid": before["pid"], "guid": before["guid"], "start_identity": before["start_identity"],
            "executable": str(path), "sha256": digest, "bytes": identity["bytes"], "file_identity": identity,
            "artifact_kind": "process_executable", "max_bytes": maximum,
            "observation": "stable current disk image of the verified live process; not memory or hardware attestation"}, body
