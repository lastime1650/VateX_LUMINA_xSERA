"""One bounded, framed CPU process reused by both approved ML model families.

This module imports no tensor framework. The child accepts bounded JSON only;
timeouts, malformed frames and child exits retire the process before reuse.
"""
import atexit
import json
import os
from pathlib import Path
import queue
import site
import subprocess
import sys
import threading
import time
import uuid

from .storage import CapacityError, encode

MAX_FRAME = 32 * 1024 * 1024
_lock = threading.Lock()
_process = None
_responses = None
_generation = 0
_requests = 0
_limit_handle = None
_limits = {}


def _retire():
    global _process, _responses, _limit_handle, _limits
    child, _process, _responses = _process, None, None
    if child is not None:
        try:
            child.kill()
            child.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass
        for pipe in (child.stdin, child.stdout):
            if pipe is not None:
                try:
                    pipe.close()
                except OSError:
                    pass
    from .cpu_ml_limits import close_windows
    close_windows(_limit_handle)
    _limit_handle, _limits = None, {}


def _read(child, responses):
    try:
        while True:
            frame = child.stdout.readline(MAX_FRAME + 1)
            if not frame or len(frame) > MAX_FRAME or not frame.endswith(b"\n"):
                responses.put(None)
                return
            responses.put(frame)
    except (OSError, ValueError):
        responses.put(None)


def request(payload, timeout=20):
    global _process, _responses, _generation, _requests, _limit_handle, _limits
    began = time.perf_counter()
    if type(timeout) not in (int, float) or not 0 < timeout <= 180:
        raise ValueError("CPU operation deadline must be within 0..180 seconds")
    identifier = uuid.uuid4().hex
    frame = (encode({"request_id": identifier, "payload": payload}) + "\n").encode("utf-8")
    if len(frame) > MAX_FRAME:
        raise CapacityError("CPU worker request exceeds 32 MiB")
    if not _lock.acquire(timeout=timeout):
        raise CapacityError("CPU worker concurrency deadline exceeded")
    try:
        reused = _process is not None and _process.poll() is None
        if not reused:
            _retire()
            try:
                executable = sys._base_executable if os.name == "nt" and getattr(sys, "_base_executable", None) else sys.executable
                environment = dict(os.environ, CUDA_VISIBLE_DEVICES="", OMP_NUM_THREADS="1", MKL_NUM_THREADS="1")
                if executable != sys.executable:
                    # Windows venv python.exe is a launcher which creates a
                    # second process. Launch the verified base interpreter
                    # directly with this environment's package paths.
                    paths = [*site.getsitepackages(), environment.get("PYTHONPATH", "")]
                    environment["PYTHONPATH"] = os.pathsep.join(path for path in paths if path)
                _process = subprocess.Popen(
                    [executable, str(Path(__file__).with_name("cpu_ml_worker.py")), "--persistent"],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    env=environment,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                    bufsize=64 * 1024,
                )
            except OSError:
                return {"worker_error": "Unavailable", "reason": "CPU worker could not start"}
            from .cpu_ml_limits import assign_windows
            _limit_handle, _limits = assign_windows(_process.pid)
            _responses = queue.Queue(maxsize=2)
            _generation += 1
            threading.Thread(target=_read, args=(_process, _responses), daemon=True,
                             name="xsera-cpu-result-reader").start()
        child, responses = _process, _responses
        try:
            # The child reads one bounded frame before executing; the lock keeps
            # request ordering exact. Writing occurs on a daemon so pipe writes
            # also obey the caller's deadline if a child stops reading.
            sent = queue.Queue(maxsize=1)
            def write():
                try:
                    remaining_frame = memoryview(frame)
                    while remaining_frame:
                        written = child.stdin.write(remaining_frame)
                        if not written:
                            raise OSError("CPU request pipe closed")
                        remaining_frame = remaining_frame[written:]
                    child.stdin.flush()
                    sent.put(True)
                except (OSError, ValueError):
                    sent.put(False)
            threading.Thread(target=write, daemon=True, name="xsera-cpu-request-writer").start()
            remaining = timeout-(time.perf_counter()-began)
            if remaining <= 0:
                raise queue.Empty
            if not sent.get(timeout=remaining):
                raise OSError("CPU request pipe failed")
            remaining = timeout-(time.perf_counter()-began)
            if remaining <= 0:
                raise queue.Empty
            answer = responses.get(timeout=remaining)
            if answer is None:
                raise ValueError("CPU child exited or returned an invalid frame")
            decoded = json.loads(answer)
            if not isinstance(decoded, dict) or decoded.get("request_id") != identifier or not isinstance(decoded.get("result"), dict):
                raise ValueError("CPU response identity mismatch")
            result = decoded["result"]
        except queue.Empty:
            _retire()
            raise CapacityError("CPU ML worker deadline exceeded") from None
        except (OSError, ValueError, TypeError):
            _retire()
            return {"worker_error": "Unavailable", "reason": "CPU framework returned an invalid framed response"}
        _requests += 1
        result.update(worker_wall_ms=(time.perf_counter()-began)*1000,
                      worker_pid=child.pid, worker_generation=_generation,
                      worker_reused=reused, worker_requests=_requests,
                      worker_process_limit=1)
        if os.name == "nt":
            result["runtime_limits"] = dict(_limits)
        return result
    finally:
        _lock.release()


def shutdown():
    # A running operation owns its deadline; shutdown waits only within that
    # bounded operation. At interpreter exit pipe closure also stops the child.
    if _lock.acquire(timeout=3):
        try:
            _retire()
        finally:
            _lock.release()


atexit.register(shutdown)
