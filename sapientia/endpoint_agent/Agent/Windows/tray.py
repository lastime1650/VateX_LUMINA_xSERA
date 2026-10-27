"""Native Win32 status GUI and notification icon; no third-party GUI runtime."""

import ctypes
import json
import os
from ctypes import wintypes
from pathlib import Path


def _status_text(config):
    path = Path(
        config.get("public_status_file") or Path(config["state_dir"]) / "status.json"
    )
    try:
        item = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "서비스 상태 파일이 없습니다. Services.msc에서 VatexLuminaXseraAgent를 확인하세요."
    return (
        f"호스트: {item.get('host')}\n에이전트: {item.get('agent_id')}\n"
        f"전송 대기: {item.get('pending')}건\n시작 후 전송: {item.get('sent_since_start')}건\n"
        f"최근 오류: {item.get('last_error') or '없음'}"
    )


def start_gui(config, tray=False):
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.MessageBoxW.argtypes = (
        wintypes.HWND,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.UINT,
    )
    if not tray:
        user32.MessageBoxW(
            None, _status_text(config), "Vatex LUMINA xSERA Endpoint Agent", 0x40
        )
        return
    _notification_area(config, user32)


def _notification_area(config, user32):
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    WM_USER, WM_COMMAND, WM_DESTROY = 0x0400, 0x0111, 0x0002
    WM_TRAY = WM_USER + 19
    WM_LBUTTONDBLCLK, WM_RBUTTONUP = 0x0203, 0x0205
    WNDPROC = ctypes.WINFUNCTYPE(
        ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
    )

    class WNDCLASS(ctypes.Structure):
        _fields_ = [
            ("style", wintypes.UINT),
            ("lpfnWndProc", WNDPROC),
            ("cbClsExtra", ctypes.c_int),
            ("cbWndExtra", ctypes.c_int),
            ("hInstance", wintypes.HINSTANCE),
            ("hIcon", wintypes.HICON),
            ("hCursor", wintypes.HANDLE),
            ("hbrBackground", wintypes.HBRUSH),
            ("lpszMenuName", wintypes.LPCWSTR),
            ("lpszClassName", wintypes.LPCWSTR),
        ]

    class NOTIFYICONDATA(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("hWnd", wintypes.HWND),
            ("uID", wintypes.UINT),
            ("uFlags", wintypes.UINT),
            ("uCallbackMessage", wintypes.UINT),
            ("hIcon", wintypes.HICON),
            ("szTip", wintypes.WCHAR * 128),
            ("dwState", wintypes.DWORD),
            ("dwStateMask", wintypes.DWORD),
            ("szInfo", wintypes.WCHAR * 256),
            ("uTimeoutOrVersion", wintypes.UINT),
            ("szInfoTitle", wintypes.WCHAR * 64),
            ("dwInfoFlags", wintypes.DWORD),
        ]

    user32.DefWindowProcW.restype = ctypes.c_ssize_t
    user32.DefWindowProcW.argtypes = (
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
    )
    user32.CreateWindowExW.restype = wintypes.HWND
    user32.CreateWindowExW.argtypes = (
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.HWND,
        wintypes.HMENU,
        wintypes.HINSTANCE,
        ctypes.c_void_p,
    )
    user32.LoadIconW.restype = wintypes.HICON
    user32.LoadIconW.argtypes = (wintypes.HINSTANCE, ctypes.c_void_p)
    kernel32.GetModuleHandleW.restype = wintypes.HINSTANCE
    kernel32.GetModuleHandleW.argtypes = (wintypes.LPCWSTR,)
    user32.CreatePopupMenu.restype = wintypes.HMENU
    user32.AppendMenuW.argtypes = (
        wintypes.HMENU,
        wintypes.UINT,
        ctypes.c_size_t,
        wintypes.LPCWSTR,
    )
    user32.TrackPopupMenu.argtypes = (
        wintypes.HMENU,
        wintypes.UINT,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.HWND,
        ctypes.c_void_p,
    )
    user32.DestroyMenu.argtypes = (wintypes.HMENU,)

    @WNDPROC
    def proc(hwnd, message, wparam, lparam):
        if message == WM_TRAY:
            if lparam == WM_LBUTTONDBLCLK:
                user32.MessageBoxW(
                    hwnd,
                    _status_text(config),
                    "Vatex LUMINA xSERA Endpoint Agent",
                    0x40,
                )
            elif lparam == WM_RBUTTONUP:
                menu = user32.CreatePopupMenu()
                user32.AppendMenuW(menu, 0, 100, "상태 확인")
                user32.AppendMenuW(menu, 0, 101, "설정 열기")
                user32.AppendMenuW(menu, 0, 102, "트레이 종료")
                point = wintypes.POINT()
                user32.GetCursorPos(ctypes.byref(point))
                user32.SetForegroundWindow(hwnd)
                user32.TrackPopupMenu(menu, 0, point.x, point.y, 0, hwnd, None)
                user32.DestroyMenu(menu)
            return 0
        if message == WM_COMMAND:
            command = wparam & 0xFFFF
            if command == 100:
                user32.MessageBoxW(
                    hwnd,
                    _status_text(config),
                    "Vatex LUMINA xSERA Endpoint Agent",
                    0x40,
                )
            elif command == 101:
                os.startfile(str(Path(config["state_dir"]).parent / "config.json"))
            elif command == 102:
                user32.DestroyWindow(hwnd)
            return 0
        if message == WM_DESTROY:
            user32.PostQuitMessage(0)
            return 0
        return user32.DefWindowProcW(hwnd, message, wparam, lparam)

    klass = WNDCLASS()
    klass.lpfnWndProc = proc
    klass.lpszClassName = "VatexLuminaXseraTrayWindow"
    klass.hInstance = kernel32.GetModuleHandleW(None)
    if not user32.RegisterClassW(ctypes.byref(klass)):
        raise OSError(ctypes.get_last_error(), "RegisterClassW failed")
    hwnd = user32.CreateWindowExW(
        0,
        klass.lpszClassName,
        "Vatex LUMINA xSERA Agent",
        0,
        0,
        0,
        0,
        0,
        None,
        None,
        klass.hInstance,
        None,
    )
    if not hwnd:
        raise OSError(ctypes.get_last_error(), "CreateWindowExW failed")
    item = NOTIFYICONDATA()
    item.cbSize = ctypes.sizeof(item)
    item.hWnd = hwnd
    item.uID = 1
    item.uFlags = 1 | 2 | 4
    item.uCallbackMessage = WM_TRAY
    item.hIcon = user32.LoadIconW(None, ctypes.c_void_p(32512))
    item.szTip = "Vatex LUMINA xSERA Endpoint Agent"
    if not shell32.Shell_NotifyIconW(0, ctypes.byref(item)):
        raise OSError(ctypes.get_last_error(), "Shell_NotifyIconW failed")
    try:
        message = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(message))
            user32.DispatchMessageW(ctypes.byref(message))
    finally:
        shell32.Shell_NotifyIconW(2, ctypes.byref(item))
