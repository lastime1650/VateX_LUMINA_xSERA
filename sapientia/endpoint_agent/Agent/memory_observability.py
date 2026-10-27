# ruff: noqa: UP017 -- Distributed runtime supports Python 3.10.
"""Opt-in read-only layout metadata; no memory bytes, injection or malware verdict."""

import ctypes
import hashlib
import json
import os
import time
import uuid
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path


def linux_regions(pid, deadline, limit):
    with Path(f"/proc/{pid}/maps").open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    truncated = len(raw) > 1024 * 1024
    lines = raw[: 1024 * 1024].decode("utf-8", errors="replace").splitlines()
    regions, scanned = [], 0
    for line in lines[:limit]:
        if time.monotonic() >= deadline:
            return regions, scanned, False
        fields = line.split(maxsplit=5)
        if len(fields) < 5:
            raise ValueError("Malformed proc memory map")
        low, high = (int(value, 16) for value in fields[0].split("-"))
        permissions = fields[1]
        if not 0 <= low < high <= 2**64 - 1 or len(permissions) != 4:
            raise ValueError("Invalid proc memory map bounds")
        scanned += 1
        path = fields[5] if len(fields) > 5 else ""
        anonymous = (
            not path
            or path.startswith(("[anon", "/memfd:", "memfd:"))
            or path in {"[heap]", "[stack]"}
        )
        if "x" in permissions and ("w" in permissions or anonymous):
            regions.append(
                {
                    "address": hex(low),
                    "size": high - low,
                    "permissions": permissions,
                    "kind": "anonymous" if anonymous else "mapped",
                }
            )
    return regions, scanned, not truncated and len(lines) <= limit


class MemoryBasicInformation(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


def windows_regions(pid, deadline, limit):
    if os.name != "nt" or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise OSError("Read-only VirtualQueryEx requires a 64-bit Windows runtime")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes, kernel.OpenProcess.restype = (
        (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD),
        wintypes.HANDLE,
    )
    kernel.VirtualQueryEx.argtypes = (
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.POINTER(MemoryBasicInformation),
        ctypes.c_size_t,
    )
    kernel.VirtualQueryEx.restype = ctypes.c_size_t
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    handle = kernel.OpenProcess(
        0x0400, False, pid
    )  # QUERY_INFORMATION; never VM_READ/VM_WRITE.
    if not handle:
        raise PermissionError(
            "Memory layout query unavailable; no PPL or access bypass"
        )
    address, scanned, regions = 0, 0, []
    try:
        if not hasattr(kernel, "IsWow64Process2"):
            raise OSError("Verified target architecture requires IsWow64Process2")
        kernel.IsWow64Process2.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.WORD),
            ctypes.POINTER(wintypes.WORD),
        )
        kernel.IsWow64Process2.restype = wintypes.BOOL
        process_machine, native_machine = wintypes.WORD(), wintypes.WORD()
        if (
            not kernel.IsWow64Process2(
                handle, ctypes.byref(process_machine), ctypes.byref(native_machine)
            )
            or process_machine.value != 0
            or native_machine.value != 0x8664
        ):
            raise OSError(
                "Native x64 target memory layout only; cross-architecture query is unqualified"
            )
        while scanned < limit and address < 2**47 and time.monotonic() < deadline:
            info = MemoryBasicInformation()
            count = kernel.VirtualQueryEx(
                handle,
                ctypes.c_void_p(address),
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
            if count != ctypes.sizeof(info):
                return regions, scanned, False
            base, size = int(info.BaseAddress or 0), int(info.RegionSize)
            if size <= 0 or base + size <= address:
                raise ValueError("VirtualQueryEx made no progress")
            scanned += 1
            protection = info.Protect & 0xFF
            executable = protection in {0x10, 0x20, 0x40, 0x80}
            writable = protection in {0x40, 0x80}
            private = info.Type == 0x20000
            if info.State == 0x1000 and executable and (writable or private):
                regions.append(
                    {
                        "address": hex(base),
                        "size": size,
                        "permissions": "rwx" if writable else "r-x",
                        "kind": "anonymous" if private else "mapped",
                    }
                )
            address = base + size
        return (
            regions,
            scanned,
            False,
        )  # This provider deliberately reports sampling, never full memory coverage.
    finally:
        kernel.CloseHandle(handle)


class MemoryObservability:
    def __init__(self, config, inspector, *, reader=None, clock=time.time):
        self.settings = config.get("memory_observability", {})
        if not isinstance(self.settings, dict) or set(self.settings) - {
            "enabled",
            "max_processes",
            "max_regions",
            "budget_ms",
        }:
            raise ValueError("Invalid read-only memory observability settings")
        self.enabled = self.settings.get("enabled") is True
        if "enabled" in self.settings and type(self.settings["enabled"]) is not bool:
            raise ValueError("Memory-observability opt-in must be boolean")
        self.maximum = self.settings.get("max_processes", 16)
        self.region_limit = self.settings.get("max_regions", 512)
        budget = self.settings.get("budget_ms", 500)
        if (
            any(type(v) is not int for v in (self.maximum, self.region_limit, budget))
            or not 1 <= self.maximum <= 64
            or not 1 <= self.region_limit <= 1024
            or not 50 <= budget <= 2000
        ):
            raise ValueError(
                "Memory provider requires finite process/region/time bounds"
            )
        self.inspector, self.clock = inspector, clock
        self.reader = reader or (windows_regions if os.name == "nt" else linux_regions)
        self.budget = budget / 1000
        self.seen, self.observed_times = {}, {}
        self.session, self.rotation = uuid.uuid4().hex, 0
        self.health = {
            "state": "disabled" if not self.enabled else "initializing",
            "enabled": self.enabled,
        }

    def begin_cycle(self):
        self.saved = (self.seen.copy(), self.rotation)

    def rollback(self):
        if hasattr(self, "saved"):
            self.seen, self.rotation = self.saved

    def status(self):
        return dict(
            self.health,
            coverage="sampled_read_only_memory_layout",
            malware_classifier=False,
            native_qualified=False,
            decision_budget_semantics="cooperative_between_OS_calls",
            memory_bytes_read=False,
            injection_performed=False,
            gaps=[
                "short-lived unsampled processes",
                "PPL/access-denied processes",
                "behavior between samples",
                "payload content and exploit classification",
            ],
        )

    def collect(self, host, rows):
        if not self.enabled:
            return []
        deadline = time.monotonic() + self.budget
        pids = sorted(
            {
                row.get("pid")
                for row in rows
                if type(row.get("pid")) is int and row["pid"] > 4
            }
        )
        offset = self.rotation % max(1, len(pids))
        selected = (pids[offset:] + pids[:offset])[: self.maximum]
        self.rotation += len(selected)
        records, checked, errors, changed_identity = [], 0, 0, 0
        for pid in selected:
            if time.monotonic() >= deadline:
                break
            try:
                before = self.inspector(pid, host)
                regions, scanned, complete = self.reader(
                    pid, deadline, self.region_limit
                )
                after = self.inspector(pid, host)
                if any(
                    before.get(key) != after.get(key)
                    for key in ("pid", "guid", "start_identity", "executable")
                ):
                    changed_identity += 1
                    continue
                if (
                    before.get("pid") != pid
                    or not before.get("guid")
                    or not before.get("start_identity")
                    or not before.get("executable")
                ):
                    raise ValueError(
                        "Verified native memory observation identity required"
                    )
                if (
                    not isinstance(regions, list)
                    or len(regions) > self.region_limit
                    or type(scanned) is not int
                    or not 0 <= scanned <= self.region_limit
                    or type(complete) is not bool
                ):
                    raise ValueError("Memory provider returned invalid bounds")
                checked += 1
                rwx = sum(
                    "w" in item["permissions"] and "x" in item["permissions"]
                    for item in regions
                )
                anonymous = sum(item["kind"] == "anonymous" for item in regions)
                snapshot = {
                    "guid": before["guid"],
                    "executable": before["executable"],
                    "regions": regions,
                    "scanned": scanned,
                    "complete": complete,
                }
                digest = hashlib.sha256(
                    json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
                if not regions or self.seen.get(before["guid"]) == digest:
                    continue
                self.seen[before["guid"]] = digest
                timestamp = self.observed_times.setdefault(
                    digest,
                    datetime.fromtimestamp(self.clock(), timezone.utc).isoformat(),
                )
                records.append(
                    {
                        "id": "memory-observation-" + self.session + "-" + digest,
                        "data": {
                            "@timestamp": timestamp,
                            "host": {
                                "id": host,
                                "os": {
                                    "type": "windows" if os.name == "nt" else "linux"
                                },
                            },
                            "event": {
                                "module": "memory",
                                "action": "memory_observation",
                            },
                            "process": {
                                "guid": before["guid"],
                                "name": Path(
                                    before["executable"].replace("\\", "/")
                                ).name,
                                "executable": before["executable"],
                            },
                            "memory": {
                                "rwx_region_count": rwx,
                                "anonymous_executable_region_count": anonymous,
                                "regions": regions[:32],
                                "reported_regions_truncated": len(regions) > 32,
                                "regions_scanned": scanned,
                                "layout_complete": complete,
                                "sampled": True,
                                "confidence": "low",
                                "malicious_verdict": "unknown",
                                "read_process_memory": False,
                                "scope": "bounded_read_only_memory_layout",
                            },
                            "agent": {
                                "collector": "windows-virtual-query"
                                if os.name == "nt"
                                else "linux-proc-maps",
                                "coverage": "sampled",
                                "process_identity_kind": "verified_incarnation_read_only_observation",
                                "process_response_eligible": False,
                                "observed_process_pid": pid,
                                "observed_process_start_identity": before[
                                    "start_identity"
                                ],
                                "source_record_sha256": digest,
                            },
                        },
                    }
                )
            except (
                OSError,
                ValueError,
                TypeError,
                KeyError,
                OverflowError,
                AttributeError,
            ):
                errors += 1
        for cache in (self.seen, self.observed_times):
            while len(cache) > 4096:
                cache.pop(next(iter(cache)))
        self.health = {
            "state": "degraded"
            if errors or changed_identity or checked < len(selected)
            else "active",
            "enabled": True,
            "available_processes": len(pids),
            "selected_processes": len(selected),
            "checked_processes": checked,
            "inaccessible_or_invalid": errors,
            "identity_changed": changed_identity,
            "sampling_truncated": len(pids) > len(selected),
            "budget_ms": int(self.budget * 1000),
        }
        return records
