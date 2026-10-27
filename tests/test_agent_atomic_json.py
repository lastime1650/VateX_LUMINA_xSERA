"""Bounded Windows sharing retries preserve durable atomic replacement."""

import ctypes
import json
import os
import threading
import time
from types import SimpleNamespace

import pytest

from sapientia.endpoint_agent.Agent import core


def fake_move(monkeypatch, errors):
    clock = SimpleNamespace(now=0.0, sleeps=[], calls=[], last=0)
    def sleep(delay):
        assert 0 < delay <= 0.1
        clock.sleeps.append(delay)
        clock.now += delay
    def error(code):
        failure = PermissionError("Synthetic Windows replace denial")
        failure.winerror = code
        return failure
    class Move:
        def __call__(self, source, destination, flags):
            clock.calls.append((source, destination, flags))
            value = errors[min(len(clock.calls) - 1, len(errors) - 1)]
            clock.last = value
            if value:
                return 0
            if os.name != "nt":
                source, destination = source.removeprefix("\\\\?\\"), destination.removeprefix("\\\\?\\")
            os.replace(source, destination)
            return 1
    move = Move()
    monkeypatch.setattr(core, "ctypes", SimpleNamespace(
        WinDLL=lambda *args, **kwargs: SimpleNamespace(MoveFileExW=move),
        c_wchar_p=ctypes.c_wchar_p, c_uint32=ctypes.c_uint32, c_int=ctypes.c_int,
        get_last_error=lambda: clock.last, WinError=error))
    monkeypatch.setattr(core, "time", SimpleNamespace(monotonic=lambda: clock.now, sleep=sleep))
    monkeypatch.setattr(core, "os", SimpleNamespace(name="nt", fsync=os.fsync))
    return clock


def test_transient_windows_errors_retry_same_fsynced_temporary_file(tmp_path, monkeypatch):
    path = tmp_path / "status.json"
    path.write_text('{"value":1}', encoding="utf-8")
    clock = fake_move(monkeypatch, [5, 32, 33, 0])
    core.atomic_json(path, {"value": 2})
    assert json.loads(path.read_text()) == {"value": 2}
    assert len(clock.calls) == 4 and len({call[0] for call in clock.calls}) == 1
    assert all(call[2] == 0x1 | 0x8 for call in clock.calls)
    assert sum(clock.sleeps) == pytest.approx(0.07)
    assert not list(tmp_path.glob("*.tmp"))


@pytest.mark.parametrize("code", [5, 32, 33])
def test_permanent_windows_denial_is_bounded_and_preserves_original(tmp_path, monkeypatch, code):
    path = tmp_path / "status.json"
    before = b'{"value":1}'
    path.write_bytes(before)
    clock = fake_move(monkeypatch, [code])
    with pytest.raises(PermissionError) as caught:
        core.atomic_json(path, {"value": 2})
    assert caught.value.winerror == code
    assert clock.now == pytest.approx(1.0) and len(clock.calls) <= 16
    assert path.read_bytes() == before and not list(tmp_path.glob("*.tmp"))
    assert len({call[0] for call in clock.calls}) == 1


def test_other_windows_error_is_immediate_and_preserves_original(tmp_path, monkeypatch):
    path = tmp_path / "status.json"
    before = b'{"value":1}'
    path.write_bytes(before)
    clock = fake_move(monkeypatch, [2])
    with pytest.raises(PermissionError) as caught:
        core.atomic_json(path, {"value": 2})
    assert caught.value.winerror == 2
    assert len(clock.calls) == 1 and not clock.sleeps
    assert path.read_bytes() == before and not list(tmp_path.glob("*.tmp"))


def open_actual_reader(path):
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.CreateFileW("\\\\?\\" + str(path.absolute()), 0x80000000, 1, None, 3, 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    return kernel, handle


@pytest.mark.skipif(os.name != "nt", reason="Actual Win32 sharing semantics")
def test_actual_reader_release_allows_durable_status_update(tmp_path):
    path = tmp_path / "status.json"
    core.atomic_json(path, {"value": 1})
    kernel, handle = open_actual_reader(path)
    released = threading.Event()
    def release():
        time.sleep(0.08)
        assert kernel.CloseHandle(handle)
        released.set()
    reader = threading.Thread(target=release)
    reader.start()
    try:
        core.atomic_json(path, {"value": 2})
    finally:
        reader.join(2)
        if not released.is_set():
            kernel.CloseHandle(handle)
    assert released.is_set() and not reader.is_alive()
    assert json.loads(path.read_text()) == {"value": 2} and not list(tmp_path.glob("*.tmp"))


@pytest.mark.skipif(os.name != "nt", reason="Actual Win32 sharing semantics")
def test_actual_persistent_reader_fails_without_losing_previous_status(tmp_path):
    path = tmp_path / "status.json"
    core.atomic_json(path, {"value": 1})
    before = path.read_bytes()
    kernel, handle = open_actual_reader(path)
    started = time.monotonic()
    try:
        with pytest.raises(OSError) as caught:
            core.atomic_json(path, {"value": 2})
        elapsed = time.monotonic() - started
        assert caught.value.winerror in {5, 32, 33}
        assert 0.9 <= elapsed < 2
        assert path.read_bytes() == before and not list(tmp_path.glob("*.tmp"))
    finally:
        assert kernel.CloseHandle(handle)
    core.atomic_json(path, {"value": 2})
    assert json.loads(path.read_text()) == {"value": 2}
