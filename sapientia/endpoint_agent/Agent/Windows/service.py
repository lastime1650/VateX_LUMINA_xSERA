"""Native Windows SCM bridge implemented with ctypes, without pywin32."""

import ctypes
import logging
import threading
from ctypes import wintypes

from ..cli import run_agent

SERVICE_NAME = "VatexLuminaXseraAgent"
SERVICE_WIN32_OWN_PROCESS = 0x10
SERVICE_STOPPED = 1
SERVICE_START_PENDING = 2
SERVICE_STOP_PENDING = 3
SERVICE_RUNNING = 4
SERVICE_ACCEPT_STOP = 1
SERVICE_CONTROL_STOP = 1


class SERVICE_STATUS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
    ]


SERVICE_MAIN = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))
SERVICE_HANDLER = ctypes.WINFUNCTYPE(None, wintypes.DWORD)


class SERVICE_TABLE_ENTRY(ctypes.Structure):
    _fields_ = [("lpServiceName", wintypes.LPWSTR), ("lpServiceProc", SERVICE_MAIN)]


def serve(config, collector_type):
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.RegisterServiceCtrlHandlerW.argtypes = (wintypes.LPCWSTR, SERVICE_HANDLER)
    advapi.RegisterServiceCtrlHandlerW.restype = wintypes.HANDLE
    advapi.SetServiceStatus.argtypes = (wintypes.HANDLE, ctypes.POINTER(SERVICE_STATUS))
    advapi.StartServiceCtrlDispatcherW.argtypes = (ctypes.POINTER(SERVICE_TABLE_ENTRY),)
    stop = threading.Event()
    handle = None

    def status(state, accepted=0, checkpoint=0, exit_code=0):
        item = SERVICE_STATUS(
            SERVICE_WIN32_OWN_PROCESS,
            state,
            accepted,
            1066 if exit_code else 0,
            exit_code,
            checkpoint,
            10000,
        )
        if handle:
            advapi.SetServiceStatus(handle, ctypes.byref(item))

    @SERVICE_HANDLER
    def handler(code):
        if code == SERVICE_CONTROL_STOP:
            status(SERVICE_STOP_PENDING, checkpoint=1)
            stop.set()

    @SERVICE_MAIN
    def service_main(_count, _args):
        nonlocal handle
        handle = advapi.RegisterServiceCtrlHandlerW(SERVICE_NAME, handler)
        if not handle:
            return
        status(SERVICE_START_PENDING, checkpoint=1)
        status(SERVICE_RUNNING, SERVICE_ACCEPT_STOP)
        failed = False
        try:
            run_agent(
                config,
                collector_type(
                    emit_initial=bool(config.get("emit_initial_processes", False)),
                    state_dir=config["state_dir"],
                ),
                stop=stop,
            )
        except Exception:
            failed = True
            logging.getLogger(__name__).exception("Windows service terminated")
        finally:
            status(SERVICE_STOPPED, exit_code=1 if failed else 0)

    entries = (SERVICE_TABLE_ENTRY * 2)()
    entries[0] = SERVICE_TABLE_ENTRY(SERVICE_NAME, service_main)
    entries[1] = SERVICE_TABLE_ENTRY(None, SERVICE_MAIN())
    if not advapi.StartServiceCtrlDispatcherW(entries):
        raise OSError(
            ctypes.get_last_error(), "Cannot connect to Windows Service Control Manager"
        )
