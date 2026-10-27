# ruff: noqa: UP017, FURB162 -- Distributed Python 3.10 needs explicit UTC and Z-suffix conversion.
"""Windows user-mode process and optional Sysmon/Defender collectors."""

import ctypes
import hashlib
import ipaddress
import json
import ntpath
import os
import platform
import re
import socket
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


def _filetime(value):
    return (value.dwHighDateTime << 32) | value.dwLowDateTime


def _process_rows():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.Process32FirstW.argtypes = (wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
    kernel.Process32NextW.argtypes = kernel.Process32FirstW.argtypes
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.GetProcessTimes.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    )
    kernel.QueryFullProcessImageNameW.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    )
    kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
    snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
    if snapshot in (0, ctypes.c_void_p(-1).value):
        raise OSError("CreateToolhelp32Snapshot failed")
    rows = []
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        valid = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
        while valid:
            pid = int(entry.th32ProcessID)
            handle = kernel.OpenProcess(0x1000, False, pid)
            created = wintypes.FILETIME()
            exited = wintypes.FILETIME()
            kernel_time = wintypes.FILETIME()
            user_time = wintypes.FILETIME()
            birth, executable = None, None
            if handle:
                try:
                    if kernel.GetProcessTimes(
                        handle,
                        ctypes.byref(created),
                        ctypes.byref(exited),
                        ctypes.byref(kernel_time),
                        ctypes.byref(user_time),
                    ):
                        birth = _filetime(created)
                    image = ctypes.create_unicode_buffer(32768)
                    length = wintypes.DWORD(len(image))
                    if kernel.QueryFullProcessImageNameW(
                        handle, 0, image, ctypes.byref(length)
                    ):
                        executable = image.value
                finally:
                    kernel.CloseHandle(handle)
            rows.append(
                {
                    "pid": pid,
                    "ppid": int(entry.th32ParentProcessID),
                    "name": entry.szExeFile,
                    "birth": birth,
                    "executable": executable,
                }
            )
            valid = kernel.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel.CloseHandle(snapshot)
    return rows


def _system_tool(name):
    """Use the OS system directory, never executable search through CWD/PATH."""
    if name not in {"wevtutil.exe", "sc.exe", "netstat.exe"}:
        raise ValueError("Unsupported native collection tool")
    if os.name == "nt":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetSystemDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
        kernel.GetSystemDirectoryW.restype = wintypes.UINT
        directory = ctypes.create_unicode_buffer(32768)
        length = kernel.GetSystemDirectoryW(directory, len(directory))
        if not 0 < length < len(directory):
            raise OSError("Windows system directory unavailable")
        root = directory.value
    else:
        # Enables inert cross-platform parser tests; executing this Windows
        # path on another OS still fails rather than searching its PATH.
        root = ntpath.join(os.environ.get("SystemRoot", "C:/Windows"), "System32")
    if not ntpath.isabs(root) or root.startswith("\\\\"):
        raise OSError("Absolute local Windows system directory required")
    return ntpath.join(root, name)


def _xml_events(channel, count=100, after=None, record_id=None):
    command = [
        _system_tool("wevtutil.exe"),
        "qe",
        channel,
        "/rd:false" if after is not None else "/rd:true",
        f"/c:{count}",
        "/f:xml",
    ]
    if record_id is not None:
        command.append(f"/q:*[System[EventRecordID={int(record_id)}]]")
    elif after is not None:
        command.append(f"/q:*[System[EventRecordID>{int(after)}]]")
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            timeout=12,
            creationflags=0x08000000,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("Event Log provider unavailable") from error
    if result.returncode:
        raise RuntimeError("Event Log channel unavailable or access denied")
    raw = result.stdout.decode("utf-8-sig", errors="replace")
    raw = re.sub(r"<\?xml[^>]*\?>", "", raw)
    try:
        if len(raw.encode("utf-8")) > 4 * 1024 * 1024:
            raise ValueError("Event XML exceeds its bound")
        root = SafeET.fromstring(
            "<Events>" + raw + "</Events>",
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except (ET.ParseError, DefusedXmlException, ValueError) as error:
        raise RuntimeError("Event Log provider returned malformed XML") from error
    return list(root)


def _integer(value, maximum=2**32 - 1):
    if value in (None, "", "-"):
        return None
    try:
        result = int(value, 16 if str(value).lower().startswith("0x") else 10)
    except (ValueError, TypeError):
        return None
    return result if 0 <= result <= maximum else None


def _compact(value):
    """Absent optional XML values must not become invalid empty typed fields."""
    if isinstance(value, dict):
        return {k: _compact(v) for k, v in value.items() if v not in (None, "", "-")}
    return value


CODE_INTEGRITY_CHANNEL = "Microsoft-Windows-CodeIntegrity/Operational"
CODE_INTEGRITY_ACTIONS = {
    3076: "execution_audit_would_deny",
    3077: "execution_denied",
    3089: "code_signature_metadata",
}


def _code_integrity_data(
    fields, system, *, host, host_name, record, epoch, stamp, code
):
    """A denied image has no created PID/GUID; preserve native observation facts.

    System.Execution belongs to the logging process. ProcessNameBuffer is the
    initiator, and SHA256Hash is the native Authenticode hash, not the flat hash.
    Neither is promoted to a created target process or an approved file digest.
    """
    namespace = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    originals = {
        key[:128]: value[:512]
        for key, value in list(fields.items())[:64]
        if isinstance(key, str) and isinstance(value, str)
    }

    def value(*names):
        result = next(
            (
                fields[name]
                for name in names
                if isinstance(fields.get(name), str) and fields[name] not in ("", "-")
            ),
            None,
        )
        return result[:512] if result else None

    def digest(*names, size=64):
        result = value(*names)
        return (
            result.lower()
            if result and re.fullmatch(r"[0-9a-fA-F]{" + str(size) + "}", result)
            else None
        )

    correlation = system.find(namespace + "Correlation")
    execution = system.find(namespace + "Execution")
    logging_pid = (
        _integer(execution.attrib.get("ProcessID")) if execution is not None else None
    )
    image = value("FileNameBuffer", "FileName")
    action = CODE_INTEGRITY_ACTIONS[code]
    if code == 3077 and image and image.casefold().endswith(".dll"):
        action = "image_load_denied"
    data = {
        "@timestamp": stamp or datetime.now(timezone.utc).isoformat(),
        "host": {"id": host, "name": host_name, "os": {"type": "windows"}},
        "event": {
            "module": "code_integrity",
            "action": action,
            "code": str(code),
            "provider": CODE_INTEGRITY_CHANNEL,
            "outcome": "failure" if code == 3077 else "unknown",
        },
        "file": {
            "path": image,
            "hash": {"sha256": digest("SHA256FlatHash")},
        },
        "code_integrity": {
            "verdict": "denied"
            if code == 3077
            else "audit_would_deny"
            if code == 3076
            else "signer_metadata",
            # CI denies an image load; DLLs can belong to an existing process.
            # Process creation is established only by independent execution facts.
            "image_loaded": False if code == 3077 else None,
            "policy_id": value("PolicyGUID", "PolicyID", "PolicyId"),
            "policy_name": value("PolicyName", "PolicyNameBuffer"),
            "activity_id": correlation.attrib.get("ActivityID")
            if correlation is not None
            else None,
            "initiator": {"executable": value("ProcessNameBuffer", "ProcessName")},
            "logging_process_pid": logging_pid,
            "requested_signing_level": _integer(fields.get("RequestedSigningLevel")),
            "validated_signing_level": _integer(fields.get("ValidatedSigningLevel")),
            "status": _integer(fields.get("Status")),
            "hash": {
                "authenticode_sha256": digest("SHA256Hash"),
                "authenticode_sha1": digest("SHA1Hash", size=40),
                "flat_sha1": digest("SHA1FlatHash", size=40),
            },
            "signature": {
                "publisher_name": value("PublisherName"),
                "issuer_name": value("IssuerName"),
                "signature_type": _integer(fields.get("SignatureType")),
                "verification_error": _integer(fields.get("VerificationError")),
                "signature_index": _integer(fields.get("SignatureIndex")),
                "total_signatures": _integer(fields.get("TotalSignatureCount")),
            },
            "original_fields": originals,
        },
        "agent": {
            "collector": "windows-event-log",
            "channel": CODE_INTEGRITY_CHANNEL,
            "record_id": record,
            "channel_epoch": epoch,
            "process_identity_kind": "unavailable_for_code_integrity_observation",
        },
    }
    return _compact(data)


def _record_anchor(root):
    namespace = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    system = root.find(namespace + "System")
    return (
        hashlib.sha256(ET.tostring(system, encoding="utf-8")).hexdigest()
        if system is not None
        else ""
    )


class WindowsCollector:
    def __init__(
        self,
        *,
        emit_initial=False,
        event_log=True,
        state_dir=None,
        emit_startup_inventory=True,
        powershell_log=True,
    ):
        if os.name != "nt":
            raise OSError("Windows collector requires Windows")
        self.seen = set()
        self.initialized = False
        self.emit_initial = emit_initial
        self.emit_startup_inventory = emit_startup_inventory
        self.snapshot_epoch = uuid.uuid4().hex
        self.snapshot_timestamp = datetime.now(timezone.utc).isoformat()
        self.powershell_log = powershell_log
        self.channel_rotation = 0
        self.sysmon_event_ids = set()
        self.event_log = event_log
        self.cursor_path = (
            Path(state_dir) / "eventlog-cursors.json" if state_dir else None
        )
        try:
            self.cursors = (
                json.loads(self.cursor_path.read_text(encoding="utf-8"))
                if self.cursor_path
                else {}
            )
        except (OSError, ValueError):
            self.cursors = {}
        self.host_name = socket.gethostname()
        self.tcp_seen = set()
        self.tcp_epochs = {}
        self.network_initialized = False
        self.providers = {}
        self.provider_processes = {}
        self.sysmon_available = self._sysmon_running()
        self._sysmon_check_at = time.monotonic() + 60

    def _sysmon_running(self):
        for name in ("Sysmon64", "Sysmon"):
            try:
                service = subprocess.run(
                    [_system_tool("sc.exe"), "query", name],
                    capture_output=True,
                    timeout=3,
                    creationflags=0x08000000,
                    check=False,
                )
                if service.returncode == 0 and b"RUNNING" in service.stdout.upper():
                    return True
            except (OSError, subprocess.TimeoutExpired):
                continue
        return False

    def _observation_time(self, identifier):
        if not hasattr(self, "_observation_times"):
            self._observation_times = {}
        value = self._observation_times.setdefault(
            identifier, datetime.now(timezone.utc).isoformat()
        )
        if len(self._observation_times) > 100000:
            self._observation_times.pop(next(iter(self._observation_times)))
        return value

    def _flow_fidelity(self, data):
        """Tuple overlap is possible duplication, never unique socket identity."""
        if data.get("event", {}).get("action") not in {
            "network_connection",
            "network_connection_observed",
        }:
            return
        agent = data.setdefault("agent", {})
        agent.update(
            {
                "duplicate_grade": "possible_cross_provider_flow",
                "count_semantics": "sensor_observations_not_unique_connections",
                "native_socket_generation": "unavailable",
            }
        )
        process = data.get("process", {})
        if not process.get("guid") or not process.get("start_identity"):
            agent["cross_provider_process_identity"] = "unverified_alias_no_flow_group"
            return
        try:
            src, dst = data["source"], data["destination"]
            ports = (src["port"], dst["port"])
            if any(type(port) is not int or not 0 <= port <= 65535 for port in ports):
                return
            protocol = data.get("network", {}).get("protocol", "").casefold()
            if protocol not in {"tcp", "6"}:
                return
            key = [
                data["host"]["id"],
                process["guid"],
                process["start_identity"],
                str(ipaddress.ip_address(src["ip"])),
                ports[0],
                str(ipaddress.ip_address(dst["ip"])),
                ports[1],
            ]
        except (KeyError, ValueError, TypeError, AttributeError):
            return
        agent["potential_flow_group"] = hashlib.sha256(
            json.dumps(key, separators=(",", ":")).encode()
        ).hexdigest()
        agent["cross_provider_process_identity"] = (
            "verified_native_incarnation_tuple_overlap_only"
        )

    def processes(self):
        return [
            {k: v for k, v in row.items() if k != "birth"} for row in _process_rows()
        ]

    def inventory(self):
        return {
            "hostname": self.host_name,
            "os": platform.platform(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "process_count": len(_process_rows()),
            "collector": "Windows user mode",
        }

    def provider_health(self):
        return {
            "providers": dict(self.providers),
            "coverage": "user-mode polling and configured Event Logs; no kernel prevention",
            "sysmon_capabilities": {
                "service_running": self.sysmon_available,
                "observed_event_ids": sorted(getattr(self, "sysmon_event_ids", set())),
                "configuration_verified": False,
                "network_fallback_retained": True,
            },
        }

    def _process_events(self, host):
        try:
            rows = _process_rows()
        except OSError:
            self.providers["toolhelp"] = {
                "state": "error",
                "code": "process_snapshot_failed",
            }
            if not hasattr(self, "process_history"):
                self.process_history = getattr(self, "last_rows", {}).copy()
            self.last_rows = {}
            return []
        self.providers["toolhelp"] = {
            "state": "ready",
            "coverage": "polling",
            "processes": len(rows),
        }
        by_pid = {row["pid"]: row for row in rows}
        previous = getattr(self, "process_history", getattr(self, "last_rows", {}))
        current = set()
        events = []
        for row in rows:
            if row["birth"] is None:
                continue
            key = f"{row['pid']}:{row['birth']}"
            current.add(key)
            startup = not self.initialized and getattr(
                self, "emit_startup_inventory", False
            )
            if startup and not hasattr(self, "snapshot_timestamp"):
                self.snapshot_timestamp = datetime.now(timezone.utc).isoformat()
            if key in self.seen or (
                not self.initialized and not self.emit_initial and not startup
            ):
                continue
            parent = by_pid.get(row["ppid"])
            parent_known = (
                parent is not None
                and parent["birth"] is not None
                and parent["birth"] <= row["birth"]
            )
            guid = str(uuid.uuid5(uuid.NAMESPACE_OID, host + ":" + key))
            parent_guid = (
                str(
                    uuid.uuid5(
                        uuid.NAMESPACE_OID,
                        host + ":" + f"{parent['pid']}:{parent['birth']}",
                    )
                )
                if parent_known
                else None
            )
            stamp = datetime.fromtimestamp(
                (row["birth"] - 116444736000000000) / 10000000, timezone.utc
            ).isoformat()
            data = {
                "@timestamp": self.snapshot_timestamp if startup else stamp,
                "host": {"id": host, "name": self.host_name, "os": {"type": "windows"}},
                "process": {
                    "guid": guid,
                    "pid": row["pid"],
                    "start_identity": "windows:" + str(row["birth"]),
                    "name": row["name"],
                    "executable": row.get("executable"),
                    "parent": {
                        "guid": parent_guid,
                        "pid": row["ppid"],
                        "name": parent["name"] if parent_known else None,
                    },
                },
                "event": {
                    "module": "inventory" if startup else "process",
                    "action": "process_observed" if startup else "process_created",
                },
                "agent": {
                    "collector": "toolhelp",
                    "coverage": "polling",
                    "observed_process_start_time": stamp,
                },
            }
            events.append(
                {
                    "id": (
                        "win-inventory-" + getattr(self, "snapshot_epoch", "") + "-"
                        if startup
                        else "win-process-"
                    )
                    + guid,
                    "data": data,
                }
            )
        for key, row in previous.items():
            if key in current:
                continue
            present = by_pid.get(row["pid"])
            if present is not None and present["birth"] is None:
                # The PID is still present. Loss of GetProcessTimes access is
                # neither an exit nor proof that this is the same incarnation.
                continue
            guid = str(uuid.uuid5(uuid.NAMESPACE_OID, host + ":" + key))
            observed = self._observation_time("win-exit-" + guid)
            events.append(
                {
                    "id": "win-exit-" + guid,
                    "data": {
                        "@timestamp": observed,
                        "host": {
                            "id": host,
                            "name": self.host_name,
                            "os": {"type": "windows"},
                        },
                        "process": {
                            "guid": guid,
                            "pid": row["pid"],
                            "name": row["name"],
                        },
                        "event": {"module": "process", "action": "process_terminated"},
                        "agent": {
                            "collector": "toolhelp",
                            "coverage": "polling",
                            "process_exit_evidence_kind": (
                                "inferred_pid_reuse"
                                if present is not None
                                else "inferred_missing_from_snapshot"
                            ),
                            "observation_time": observed,
                            "process_response_eligible": False,
                        },
                    },
                }
            )
        unknown_present = {
            key: row
            for key, row in previous.items()
            if row["pid"] in by_pid and by_pid[row["pid"]]["birth"] is None
        }
        # Retain uncertainty only in the historical cache. Fresh live rows feed
        # log and TCP binding, so inaccessible birth times never authorize a
        # response or attach a current socket to an older PID incarnation.
        self.last_rows = {
            f"{row['pid']}:{row['birth']}": row
            for row in rows
            if row["birth"] is not None
        }
        self.process_history = {**unknown_present, **self.last_rows}
        active_instances = {
            (row["pid"], row["birth"]) for row in self.process_history.values()
        }
        self.provider_processes = {
            key: identity
            for key, identity in self.provider_processes.items()
            if identity in active_instances
        }
        self.seen = current | set(unknown_present)
        self.initialized = True
        return events

    def _log_events(self, host, limit=2000):
        channels = [
            (CODE_INTEGRITY_CHANNEL, CODE_INTEGRITY_ACTIONS),
            (
                "Microsoft-Windows-Sysmon/Operational",
                {
                    1: "process_created",
                    3: "network_connection",
                    5: "process_terminated",
                    6: "driver_loaded",
                    7: "image_loaded",
                    8: "remote_thread_created",
                    10: "process_accessed",
                    11: "file_created",
                    13: "registry_value_set",
                    14: "registry_value_renamed",
                    22: "dns_query",
                    23: "file_deleted",
                    25: "process_tampered",
                    26: "file_deleted",
                },
            ),
            (
                "Security",
                {
                    4688: "process_created",
                    4689: "process_terminated",
                    4657: "registry_value_set",
                    4663: "file_accessed",
                    5156: "network_connection",
                    5157: "connection_blocked",
                    4624: "logon_success",
                    4625: "logon_failed",
                    4648: "explicit_credentials",
                    4768: "kerberos_ticket_requested",
                    4769: "kerberos_service_ticket_requested",
                },
            ),
            (
                "Microsoft-Windows-Windows Defender/Operational",
                {1116: "defender_detection", 1117: "defender_remediation"},
            ),
        ]
        if getattr(self, "powershell_log", True):
            channels.append(
                (
                    "Microsoft-Windows-PowerShell/Operational",
                    {
                        4103: "powershell_command",
                        4104: "powershell_script_block",
                    },
                )
            )
        offset = getattr(self, "channel_rotation", 0) % len(channels)
        channels = channels[offset:] + channels[:offset]
        self.channel_rotation = (offset + 1) % len(channels)
        quota = max(1, limit // len(channels))
        output = []
        namespace = "{http://schemas.microsoft.com/win/2004/08/events/event}"
        queried = {}
        for round_number in range(2):
            for channel, actions in channels:
                if len(output) >= limit:
                    break
                records = []
                channel_output_start = len(output)
                saved = self.cursors.get(channel)
                saved = (
                    {"record": saved, "epoch": 0} if isinstance(saved, int) else saved
                )
                previous = saved.get("record") if isinstance(saved, dict) else None
                epoch = saved.get("epoch", 0) if isinstance(saved, dict) else 0
                if round_number == 0:
                    try:
                        latest = _xml_events(channel, count=1)
                        head = latest[0] if latest else None
                        latest_record = (
                            int(
                                head.findtext(
                                    namespace + "System/" + namespace + "EventRecordID"
                                )
                            )
                            if head is not None
                            else 0
                        )
                        if previous is not None and latest_record:
                            anchor = _xml_events(channel, count=1, record_id=previous)
                            reset = (
                                latest_record < previous
                                or not anchor
                                or (
                                    saved.get("anchor")
                                    and _record_anchor(anchor[0]) != saved["anchor"]
                                )
                            )
                            if reset:
                                previous, epoch = 0, epoch + 1
                                self.providers[channel] = {
                                    "state": "degraded",
                                    "code": "channel_reset_or_retention_gap",
                                    "epoch": epoch,
                                }
                        roots = _xml_events(channel, count=2000, after=previous)
                    except (OSError, RuntimeError, ValueError, TypeError):
                        self.providers[channel] = {
                            "state": "error",
                            "code": "channel_query_failed",
                        }
                        continue
                    if (
                        self.providers.get(channel, {}).get("code")
                        != "channel_reset_or_retention_gap"
                    ):
                        self.providers[channel] = {
                            "state": "ready",
                            "configured_channel": True,
                        }
                    for root in roots:
                        system = root.find(namespace + "System")
                        if system is None:
                            continue
                        record = system.findtext(namespace + "EventRecordID")
                        code = system.findtext(namespace + "EventID")
                        if not record or not code:
                            continue
                        try:
                            records.append((int(record), int(code), root, system))
                        except ValueError:
                            self.providers[channel] = {
                                "state": "degraded",
                                "code": "malformed_record_identity",
                            }
                    queried[channel] = (records, latest_record, head)
                else:
                    if channel not in queried:
                        continue
                    records, latest_record, head = queried[channel]
                if previous is None:
                    if not self.emit_initial:
                        newest = max(records, default=None, key=lambda r: r[0])
                        self.cursors[channel] = {
                            "record": newest[0] if newest else 0,
                            "epoch": epoch,
                            "anchor": _record_anchor(newest[2]) if newest else "",
                        }
                        continue
                    previous = 0
                cursor = previous
                cursor_anchor = (
                    saved.get("anchor", "") if isinstance(saved, dict) else ""
                )
                for record, code, root, system in sorted(records):
                    if record <= previous:
                        continue
                    if len(output) >= limit or len(output) - channel_output_start >= (
                        quota if round_number == 0 else limit
                    ):
                        break
                    cursor = record
                    cursor_anchor = _record_anchor(root)
                    if code not in actions:
                        continue
                    if "Sysmon" in channel:
                        if not hasattr(self, "sysmon_event_ids"):
                            self.sysmon_event_ids = set()
                        self.sysmon_event_ids.add(code)
                    fields = {
                        item.attrib.get("Name", ""): item.text
                        for item in root.findall(
                            ".//" + namespace + "EventData/" + namespace + "Data"
                        )
                    }
                    timing = system.find(namespace + "TimeCreated")
                    stamp = (
                        timing.attrib.get("SystemTime") if timing is not None else None
                    )
                    if channel == "Microsoft-Windows-PowerShell/Operational":
                        text = (
                            fields.get("ScriptBlockText")
                            or fields.get("Payload")
                            or fields.get("ContextInfo")
                            or ""
                        )
                        block = {
                            "script_block": text[:8192],
                            "original_length": len(text),
                            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                            "truncated": len(text) > 8192,
                            "message_number": _integer(fields.get("MessageNumber")),
                            "message_total": _integer(fields.get("MessageTotal")),
                        }
                        block["complete"] = (
                            block["message_number"] == block["message_total"] == 1
                            and not block["truncated"]
                        )
                        if fields.get("ScriptBlockId"):
                            block["script_block_id"] = fields["ScriptBlockId"][:512]
                        execution = system.find(namespace + "Execution")
                        observed_pid = (
                            _integer(execution.attrib.get("ProcessID"))
                            if execution is not None
                            else None
                        )
                        output.append(
                            {
                                "id": "win-event-"
                                + str(
                                    uuid.uuid5(
                                        uuid.NAMESPACE_URL,
                                        ":".join(
                                            (
                                                host,
                                                channel,
                                                str(epoch),
                                                str(record),
                                                cursor_anchor,
                                            )
                                        ),
                                    )
                                ),
                                "data": {
                                    "@timestamp": stamp
                                    or datetime.now(timezone.utc).isoformat(),
                                    "host": {
                                        "id": host,
                                        "name": self.host_name,
                                        "os": {"type": "windows"},
                                    },
                                    "event": {
                                        "module": "script",
                                        "action": actions[code],
                                        "code": str(code),
                                        "provider": channel,
                                    },
                                    "powershell": block,
                                    "windows_event": {
                                        "observed_process": {"pid": observed_pid}
                                    },
                                    "agent": {
                                        "collector": "windows-event-log",
                                        "channel": channel,
                                        "record_id": record,
                                        "channel_epoch": epoch,
                                        "process_identity_kind": "unavailable_for_windows_event_log_observation",
                                        "process_response_eligible": False,
                                        "source_record_sha256": hashlib.sha256(
                                            ET.tostring(root, encoding="utf-8")
                                        ).hexdigest(),
                                    },
                                },
                            }
                        )
                        continue
                    if channel == CODE_INTEGRITY_CHANNEL:
                        data = _code_integrity_data(
                            fields,
                            system,
                            host=host,
                            host_name=self.host_name,
                            record=record,
                            epoch=epoch,
                            stamp=stamp,
                            code=code,
                        )
                        data["agent"]["source_record_sha256"] = hashlib.sha256(
                            ET.tostring(root, encoding="utf-8")
                        ).hexdigest()
                        output.append(
                            {
                                "id": "win-event-"
                                + str(
                                    uuid.uuid5(
                                        uuid.NAMESPACE_URL,
                                        host
                                        + ":"
                                        + channel
                                        + ":"
                                        + str(epoch)
                                        + ":"
                                        + str(record)
                                        + ":"
                                        + cursor_anchor,
                                    )
                                ),
                                "data": data,
                            }
                        )
                        continue
                    image = (
                        fields.get("Image")
                        or fields.get("SourceImage")
                        or fields.get("ProcessName")
                        or fields.get("NewProcessName")
                        or ""
                    )
                    process_id = (
                        fields.get("ProcessId")
                        or fields.get("SourceProcessId")
                        or fields.get("NewProcessId")
                    )
                    parent_pid, parent_image = (
                        fields.get("ParentProcessId"),
                        fields.get("ParentImage"),
                    )
                    if channel == "Security" and code == 4688:
                        # 4688 ProcessId is the creator, NewProcessId is the child.
                        process_id, image = (
                            fields.get("NewProcessId"),
                            fields.get("NewProcessName") or "",
                        )
                        parent_pid, parent_image = (
                            fields.get("ProcessId"),
                            fields.get("ParentProcessName"),
                        )
                    elif channel == "Security" and code in {5156, 5157}:
                        process_id = fields.get("ProcessID") or process_id
                        image = fields.get("Application") or image
                    elif "Windows Defender" in channel:
                        image = fields.get("Process Name") or image
                    process_name = os.path.basename(image.replace("\\", "/"))
                    pid_value = _integer(process_id)
                    native_guid = next(
                        (
                            fields[name]
                            for name in ("ProcessGuid", "SourceProcessGUID")
                            if channel == "Microsoft-Windows-Sysmon/Operational"
                            and isinstance(fields.get(name), str)
                            and fields[name] not in ("", "-")
                        ),
                        None,
                    )
                    creation_observation = (
                        actions[code] == "process_created"
                        and pid_value is not None
                        and pid_value > 0
                        and bool(image)
                    )
                    process_guid = native_guid or (
                        str(
                            uuid.uuid5(
                                uuid.NAMESPACE_URL,
                                ":".join(
                                    (
                                        "windows-creation",
                                        host,
                                        channel,
                                        str(epoch),
                                        str(record),
                                        cursor_anchor,
                                    )
                                ),
                            )
                        )
                        if creation_observation
                        else None
                    )
                    data = {
                        "@timestamp": stamp or datetime.now(timezone.utc).isoformat(),
                        "host": {
                            "id": host,
                            "name": self.host_name,
                            "os": {"type": "windows"},
                        },
                        "event": {
                            "module": "sysmon" if "Sysmon" in channel else "security",
                            "action": actions[code],
                            "code": str(code),
                            "provider": channel,
                        },
                        "user": {
                            "name": fields.get("User")
                            or fields.get("TargetUserName")
                            or fields.get("SubjectUserName")
                        },
                        "process": {
                            "guid": process_guid,
                            "name": process_name,
                            "pid": pid_value,
                            "executable": image,
                            "command_line": fields.get("CommandLine")
                            or fields.get("ProcessCommandLine"),
                            "parent": {
                                "guid": fields.get("ParentProcessGuid"),
                                "pid": _integer(parent_pid),
                                "name": os.path.basename(
                                    (parent_image or "").replace("\\", "/")
                                ),
                                "executable": parent_image,
                            },
                            "target": {
                                "guid": fields.get("TargetProcessGUID"),
                                "pid": _integer(fields.get("TargetProcessId")),
                                "executable": fields.get("TargetImage"),
                            },
                            "access": {"mask": fields.get("GrantedAccess")},
                            "tamper": {"type": fields.get("Type")},
                        },
                        "source": {
                            "ip": fields.get("SourceIp") or fields.get("IpAddress"),
                            "port": _integer(
                                fields.get("SourcePort") or fields.get("IpPort"), 65535
                            ),
                        },
                        "destination": {
                            "ip": fields.get("DestinationIp"),
                            "port": _integer(fields.get("DestinationPort"), 65535),
                        },
                        "network": {"protocol": fields.get("Protocol")},
                        "file": {
                            "path": fields.get("TargetFilename")
                            or fields.get("ObjectName"),
                            "hash": {
                                "sha256": next(
                                    (
                                        part[7:]
                                        for part in (fields.get("Hashes") or "").split(
                                            ","
                                        )
                                        if part.upper().startswith("SHA256=")
                                    ),
                                    None,
                                )
                            },
                        },
                        "registry": {
                            "path": fields.get("TargetObject")
                            or fields.get("ObjectName"),
                            "value": fields.get("Details"),
                        },
                        "dns": {
                            "question": {"name": fields.get("QueryName")},
                            "answers": fields.get("QueryResults"),
                        },
                        "dll": {"path": fields.get("ImageLoaded")},
                        "driver": {"path": fields.get("ImageLoaded")},
                        "agent": {
                            "collector": "windows-event-log",
                            "channel": channel,
                            "record_id": record,
                            "channel_epoch": epoch,
                            "process_identity_kind": "windows_provider_process_guid"
                            if native_guid
                            else "windows_creation_event_record"
                            if creation_observation
                            else "unavailable_for_windows_event_log_observation",
                            "process_response_eligible": False,
                            "source_record_sha256": hashlib.sha256(
                                ET.tostring(root, encoding="utf-8")
                            ).hexdigest(),
                        },
                    }
                    # Only a verified current creation identity permits a destructive
                    # response. Preserve historical provider GUID separately; PID alone
                    # is never enough to enrich an old event after PID reuse.
                    pid = data["process"]["pid"]
                    row = next(
                        (
                            r
                            for r in getattr(self, "last_rows", {}).values()
                            if r["pid"] == pid
                        ),
                        None,
                    )
                    identity = self.provider_processes.get(process_guid)
                    if process_guid and row and row.get("birth"):
                        born = (row["birth"] - 116444736000000000) / 10000000
                        image_matches = (
                            bool(image)
                            and isinstance(row.get("executable"), str)
                            and bool(row["executable"])
                            and ntpath.normcase(ntpath.normpath(image))
                            == ntpath.normcase(ntpath.normpath(row["executable"]))
                        )
                        try:
                            parsed = datetime.fromisoformat(
                                (fields.get("UtcTime") or stamp or "").replace(
                                    "Z", "+00:00"
                                )
                            )
                            created = (
                                parsed.replace(tzinfo=timezone.utc)
                                if parsed.tzinfo is None
                                else parsed
                            ).timestamp()
                        except ValueError:
                            created = -1
                        if (
                            actions[code] == "process_created"
                            and abs(created - born) <= 0.001
                            and process_name.casefold() == row["name"].casefold()
                            and image_matches
                        ):
                            identity = (pid, row["birth"])
                            self.provider_processes[process_guid] = identity
                            if len(self.provider_processes) > 4096:
                                self.provider_processes.pop(
                                    next(iter(self.provider_processes))
                                )
                        if identity == (pid, row["birth"]) and image_matches:
                            if native_guid:
                                data["agent"]["provider_process_guid"] = native_guid
                            else:
                                data["agent"]["creation_event_identity"] = process_guid
                            data["agent"]["process_identity_kind"] = (
                                "windows_live_creation_time"
                            )
                            data["agent"]["process_response_eligible"] = True
                            data["process"]["guid"] = str(
                                uuid.uuid5(
                                    uuid.NAMESPACE_OID,
                                    host + ":" + f"{pid}:{row['birth']}",
                                )
                            )
                            data["process"]["start_identity"] = "windows:" + str(
                                row["birth"]
                            )
                    parent_provider = data["process"]["parent"]["guid"]
                    parent_identity = self.provider_processes.get(parent_provider)
                    if parent_identity:
                        data["process"]["parent"]["guid"] = str(
                            uuid.uuid5(
                                uuid.NAMESPACE_OID,
                                host
                                + ":"
                                + f"{parent_identity[0]}:{parent_identity[1]}",
                            )
                        )
                    if data["process"]["guid"] is None:
                        data["windows_event"] = {
                            "observed_process": data.pop("process"),
                            "original_fields": {
                                key[:128]: value[:512]
                                for key, value in list(fields.items())[:64]
                                if isinstance(key, str) and isinstance(value, str)
                            },
                        }
                        observed = data["windows_event"]["observed_process"]
                        data["process"] = {
                            key: observed[key]
                            for key in (
                                "name",
                                "executable",
                                "command_line",
                                "access",
                                "tamper",
                            )
                            if observed.get(key) is not None
                        }
                    output.append(
                        {
                            "id": "win-event-"
                            + str(
                                uuid.uuid5(
                                    uuid.NAMESPACE_URL,
                                    host
                                    + ":"
                                    + channel
                                    + ":"
                                    + str(epoch)
                                    + ":"
                                    + str(record)
                                    + ":"
                                    + cursor_anchor,
                                )
                            ),
                            "data": _compact(data),
                        }
                    )
                self.cursors[channel] = {
                    "record": cursor,
                    "epoch": epoch,
                    "anchor": cursor_anchor,
                }
                eligible_left = sum(
                    record > cursor and code in actions
                    for record, code, _root, _system in records
                )
                head_code = (
                    head.findtext(namespace + "System/" + namespace + "EventID")
                    if head is not None
                    else None
                )
                # Every allowed parsed native record maps to one emitted observation.
                # The latest actual selected record can prove at least one eligible
                # record remains even when it is outside this bounded oldest batch.
                head_selected = bool(
                    latest_record > cursor
                    and head_code
                    and head_code.isdigit()
                    and int(head_code) in actions
                )
                confirmed = eligible_left > 0 or head_selected
                provider = self.providers[channel]
                if confirmed and provider.get("code") in (
                    None,
                    "eligible_source_backlog",
                ):
                    provider.update(state="degraded", code="eligible_source_backlog")
                elif (
                    not confirmed and provider.get("code") == "eligible_source_backlog"
                ):
                    provider["state"] = "ready"
                    provider.pop("code", None)
                provider.update(
                    {
                        "unread_record_span": max(0, latest_record - cursor),
                        "record_span_is_not_event_count": True,
                        "backlog": latest_record > cursor,
                        "backlog_confirmed": confirmed,
                        "known_eligible_buffered_records": eligible_left,
                        "selected_tail_record_observed": head_selected,
                        "backlog_uncertain": latest_record > cursor and not confirmed,
                        "fair_output_quota": quota,
                        "unused_channel_budget_borrowed": round_number == 1,
                        "query_record_limit": 2000,
                    }
                )
        return output

    def begin_cycle(self):
        self._saved = (
            self.cursors.copy(),
            self.seen.copy(),
            self.initialized,
            self.last_rows.copy() if hasattr(self, "last_rows") else None,
            self.tcp_seen.copy(),
            self.tcp_epochs.copy(),
            self.provider_processes.copy(),
            self.process_history.copy() if hasattr(self, "process_history") else None,
            getattr(self, "network_initialized", False),
        )

    def rollback(self):
        if not hasattr(self, "_saved"):
            return
        (
            self.cursors,
            self.seen,
            self.initialized,
            rows,
            self.tcp_seen,
            self.tcp_epochs,
            self.provider_processes,
            history,
            self.network_initialized,
        ) = self._saved
        if rows is None:
            if hasattr(self, "last_rows"):
                del self.last_rows
        else:
            self.last_rows = rows
        if history is None:
            if hasattr(self, "process_history"):
                del self.process_history
        else:
            self.process_history = history

    def _tcp_events(self, host):
        """Best-effort TCP fallback when Sysmon is not installed."""
        try:
            completed = subprocess.run(
                [_system_tool("netstat.exe"), "-ano", "-p", "tcp"],
                capture_output=True,
                timeout=8,
                creationflags=0x08000000,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            self.providers["tcp"] = {"state": "error", "code": "tcp_poll_failed"}
            return []
        if completed.returncode:
            self.providers["tcp"] = {"state": "error", "code": "tcp_poll_failed"}
            return []
        self.providers["tcp"] = {
            "state": "ready",
            "coverage": "established TCP polling",
        }
        current = set()
        events = []
        by_pid = {row["pid"]: row for row in getattr(self, "last_rows", {}).values()}
        startup = not getattr(self, "network_initialized", False) and getattr(
            self, "emit_startup_inventory", False
        )
        for line in completed.stdout.decode("utf-8", errors="replace").splitlines():
            parts = line.split()
            if (
                len(parts) != 5
                or parts[0].upper() != "TCP"
                or parts[3].upper() != "ESTABLISHED"
            ):
                continue
            try:
                pid = int(parts[4])
                row = by_pid[pid]
                src_ip, src_port = parts[1].rsplit(":", 1)
                dst_ip, dst_port = parts[2].rsplit(":", 1)
                src_ip, dst_ip = src_ip.strip("[]"), dst_ip.strip("[]")
                key = (pid, row["birth"], src_ip, src_port, dst_ip, dst_port)
                current.add(key)
                if key in self.tcp_seen:
                    continue
                self.tcp_epochs[key] = self.tcp_epochs.get(key, 0) + 1
                guid = str(
                    uuid.uuid5(uuid.NAMESPACE_OID, host + ":" + f"{pid}:{row['birth']}")
                )
                eid = str(
                    uuid.uuid5(
                        uuid.NAMESPACE_URL,
                        host
                        + ":"
                        + getattr(self, "snapshot_epoch", "")
                        + ":"
                        + str(key)
                        + ":"
                        + str(self.tcp_epochs[key]),
                    )
                )
                events.append(
                    {
                        "id": (
                            "win-tcp-inventory-"
                            + getattr(self, "snapshot_epoch", "")
                            + "-"
                            if startup
                            else "win-tcp-"
                        )
                        + eid,
                        "data": {
                            "@timestamp": self._observation_time("win-tcp-" + eid),
                            "host": {
                                "id": host,
                                "name": self.host_name,
                                "os": {"type": "windows"},
                            },
                            "process": {
                                "guid": guid,
                                "pid": pid,
                                "start_identity": "windows:" + str(row["birth"]),
                                "name": row["name"],
                            },
                            "source": {"ip": src_ip, "port": int(src_port)},
                            "destination": {"ip": dst_ip, "port": int(dst_port)},
                            "network": {"protocol": "tcp"},
                            "event": {
                                "module": "inventory" if startup else "network",
                                "action": "network_connection_observed"
                                if startup
                                else "network_connection",
                            },
                            "agent": {"collector": "netstat", "coverage": "polling"},
                        },
                    }
                )
            except (ValueError, KeyError):
                continue
        self.tcp_seen = current
        self.network_initialized = True
        return events

    def checkpoint(self):
        if not self.cursor_path:
            return
        from ..core import atomic_json

        atomic_json(self.cursor_path, self.cursors)

    def collect(self, host):
        if time.monotonic() >= getattr(self, "_sysmon_check_at", 0):
            self.sysmon_available = self._sysmon_running()
            self._sysmon_check_at = time.monotonic() + 60
        events = self._process_events(host)
        if self.event_log:
            events.extend(self._log_events(host, limit=max(0, 2000 - len(events))))
        # A running Sysmon service is not evidence that Event ID 3 is enabled,
        # unfiltered or readable. Retain the independently bounded fallback.
        events.extend(self._tcp_events(host))
        for record in events:
            self._flow_fidelity(record["data"])
        return events
