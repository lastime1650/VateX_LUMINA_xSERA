"""Resource limits for the owned CPU child; unsupported limits are explicit."""
import math
import os

MEMORY_BYTES = 2 * 1024**3


def assign_windows(pid):
    if os.name != "nt":
        return None, {"method": "child_rlimit", "os_enforced": None, "status": "applied in child"}
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL

    class Basic(ctypes.Structure):
        _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
                    ("flags", wintypes.DWORD), ("minimum_working_set", ctypes.c_size_t),
                    ("maximum_working_set", ctypes.c_size_t), ("active_processes", wintypes.DWORD),
                    ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD)]
    class IO(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in ("reads", "writes", "other", "read_bytes", "write_bytes", "other_bytes")]
    class Extended(ctypes.Structure):
        _fields_ = [("basic", Basic), ("io", IO), ("process_memory", ctypes.c_size_t),
                    ("job_memory", ctypes.c_size_t), ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t)]
    class CPU(ctypes.Structure):
        _fields_ = [("flags", wintypes.DWORD), ("rate", wintypes.DWORD)]
    policy = {"method": "windows_job", "os_enforced": False, "memory_bytes": MEMORY_BYTES,
              "max_processes": 1, "cpu_thread_limit": 1, "kill_on_job_close": False}
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        return None, {**policy, "status": "job unavailable", "error_code": ctypes.get_last_error()}
    limits = Extended()
    # ACTIVE_PROCESS | PROCESS_MEMORY | JOB_MEMORY | KILL_ON_JOB_CLOSE.
    limits.basic.flags = 0x8 | 0x100 | 0x200 | 0x2000
    limits.basic.active_processes = 1
    limits.process_memory = limits.job_memory = MEMORY_BYTES
    cpu = CPU(0x1 | 0x4, max(1, math.ceil(10000/max(1, os.cpu_count() or 1))))
    memory_set = bool(kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)))
    cpu_set = bool(kernel.SetInformationJobObject(job, 15, ctypes.byref(cpu), ctypes.sizeof(cpu)))
    process = kernel.OpenProcess(0x100 | 0x1 | 0x400, False, pid)
    assigned = bool(process and memory_set and kernel.AssignProcessToJobObject(job, process))
    error = ctypes.get_last_error()
    if process:
        kernel.CloseHandle(process)
    if not assigned:
        kernel.CloseHandle(job)
        return None, {**policy, "status": "job assignment unavailable; frame/thread/deadline limits still enforced", "error_code": error}
    policy.update(os_enforced=True, memory_enforced=True, process_limit_enforced=True,
                  cpu_rate_enforced=cpu_set, cpu_rate_hundredths_percent=cpu.rate if cpu_set else None,
                  cpu_budget_approximate_cores=1 if cpu_set else None, kill_on_job_close=True,
                  status="applied" if cpu_set else "memory/process applied; CPU job rate unsupported")
    return job, policy


def close_windows(handle):
    if handle is not None and os.name == "nt":
        import ctypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
        kernel.CloseHandle(handle)


def child_limits():
    if os.name == "nt":
        return {"method": "windows_job", "status": "parent assigns before first request"}
    try:
        import resource
        # Torch shared-library virtual mappings can exceed physical heap size.
        # This is an 8-GiB virtual-address cap, not a claim of a 2-GiB RSS cap.
        virtual = 8 * 1024**3
        old = resource.getrlimit(resource.RLIMIT_AS)
        hard = virtual if old[1] == resource.RLIM_INFINITY else min(virtual, old[1])
        resource.setrlimit(resource.RLIMIT_AS, (hard, hard))
        resource.setrlimit(resource.RLIMIT_CPU, (1800, 1805))
        return {"method": "linux_rlimit", "os_enforced": True, "virtual_address_bytes": hard,
                "process_cpu_seconds": 1800, "cpu_thread_limit": 1,
                "max_worker_processes_parent_enforced": 1, "rss_cap_enforced": False}
    except (ImportError, OSError, ValueError) as exc:
        return {"method": "rlimit_unavailable", "os_enforced": False,
                "status": type(exc).__name__, "frame_thread_deadline_limits_enforced": True}
