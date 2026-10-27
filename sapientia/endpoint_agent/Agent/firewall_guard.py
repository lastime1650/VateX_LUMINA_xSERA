"""Read-only native firewall capability guards; never changes global policy."""

import ctypes
import ipaddress
import json
import os
import platform
import stat
import subprocess
import time
import uuid
from pathlib import Path


def windows_tool():
    """The native OS directory, independent of inherited PATH/SystemRoot."""
    if os.name != "nt":
        raise PermissionError("Native Windows firewall COM requires Windows")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    buffer = ctypes.create_unicode_buffer(32768)
    kernel.GetSystemDirectoryW.argtypes = (ctypes.c_wchar_p, ctypes.c_uint32)
    kernel.GetSystemDirectoryW.restype = ctypes.c_uint32
    length = kernel.GetSystemDirectoryW(buffer, len(buffer))
    if not 0 < length < len(buffer):
        raise OSError("Native Windows system directory is unavailable")
    path = Path(buffer.value) / "WindowsPowerShell/v1.0/powershell.exe"
    if not path.is_file():
        raise PermissionError("Protected native Windows PowerShell is unavailable")
    return str(path)


def _windows_owned(identifier, deadline=None):
    import re

    if not isinstance(identifier, str) or not re.fullmatch(r"[0-9a-f]{32}", identifier):
        raise ValueError("Exact internal Windows firewall receipt required")
    timeout = 4 if deadline is None else min(4, deadline - time.monotonic())
    if timeout <= 0:
        raise TimeoutError("Owned firewall verification deadline exceeded")
    tool = Path(windows_tool())
    script = """$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$prefix='Lumina-Isolation-'+$env:LUMINA_FW_RECEIPT+'-'
$policy=New-Object -ComObject HNetCfg.FwPolicy2
$rows=@()
foreach($rule in $policy.Rules){
 if($rule.Name.StartsWith($prefix,[StringComparison]::Ordinal)){
  $rows+=@{name=$rule.Name;group=[string]$rule.Grouping;enabled=[bool]$rule.Enabled;action=[int]$rule.Action;direction=[int]$rule.Direction;protocol=[int]$rule.Protocol;remote=$rule.RemoteAddresses;localport=$rule.LocalPorts;remoteport=$rule.RemotePorts;profiles=[int]$rule.Profiles;application=$rule.ApplicationName;service=$rule.ServiceName;interfaces=$rule.InterfaceTypes;edge=[bool]$rule.EdgeTraversal}
 }
}
ConvertTo-Json -InputObject @($rows) -Compress -Depth 5
"""
    result = subprocess.run(
        [str(tool), "-NoProfile", "-NonInteractive", "-Command", script],
        env=dict(
            os.environ,
            LUMINA_FW_RECEIPT=identifier,
            PSModulePath=str(tool.parent / "Modules"),
        ),
        capture_output=True,
        check=True,
        timeout=timeout,
        shell=False,
    )
    if len(result.stdout) > 4 * 1024 * 1024:
        raise PermissionError("Owned firewall state exceeds bound")
    rows = json.loads(
        result.stdout.decode("utf-8-sig")
        if isinstance(result.stdout, bytes)
        else result.stdout
    )
    if (
        not isinstance(rows, list)
        or len(rows) > 4096
        or any(not isinstance(row, dict) for row in rows)
    ):
        raise PermissionError("Owned Windows firewall state is unverifiable")
    return rows


def _windows_addresses(value):
    result = set()
    for part in value.split(","):
        part = part.strip()
        if "-" in part:
            start, end = (ipaddress.ip_address(item) for item in part.split("-"))
            result.update(
                str(net) for net in ipaddress.summarize_address_range(start, end)
            )
        elif part:
            result.add(str(ipaddress.ip_network(part, strict=False)))
    return result


def verify_owned_windows(identifier, expected):
    """Rule creation return codes alone never prove effective exact filters."""
    rows = _windows_owned(identifier)
    if len(rows) != len(expected) or {row.get("name") for row in rows} != set(expected):
        raise PermissionError(
            "Owned Windows firewall rules are incomplete or unexpected"
        )
    for row in rows:
        planned = expected[row["name"]]
        if (
            row.get("enabled") is not True
            or row.get("group") != "Lumina-Isolation-" + identifier
            or row.get("action") != 0
            or row.get("direction") != planned["direction"]
            or row.get("protocol") != planned["protocol"]
            or row.get("profiles") not in (7, 2147483647)
            or row.get("application") not in (None, "")
            or row.get("service") not in (None, "")
            or row.get("interfaces") not in (None, "All")
            or row.get("edge") is not False
            or _windows_addresses(row.get("remote", ""))
            != _windows_addresses(planned["remote"])
            or planned["protocol"] == 6
            and any(
                (row.get(field) or "*").replace(" ", "") != planned[field]
                for field in ("localport", "remoteport")
            )
        ):
            raise PermissionError(
                "Owned Windows firewall filter differs from the approved exact definition"
            )
    return {"owned_rule_count": len(rows), "exact_filters_verified": True}


def verify_removed_windows(identifier, deadline=None):
    if _windows_owned(identifier, deadline=deadline):
        raise PermissionError("One or more owned Windows firewall rules remain")
    return True


def linux_tool():
    """Use a fixed root-owned system nft executable, never shell/PATH lookup."""
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise PermissionError("Linux firewall isolation requires native Linux root")
    for candidate in (Path("/usr/sbin/nft"), Path("/sbin/nft")):
        try:
            path = candidate.resolve(strict=True)
            info = path.stat()
        except OSError:
            continue
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
            or not info.st_mode & 0o111
        ):
            continue
        for parent in path.parents:
            owner = parent.stat()
            if owner.st_uid != 0 or owner.st_mode & 0o022:
                raise PermissionError("Linux firewall tool directory is unprotected")
        return str(path)
    raise PermissionError("A protected system nft executable is unavailable")


def verify_linux(identifier=None):
    """Verify real kernel access and, after apply, both owned drop hooks."""
    tool = linux_tool()
    command = [tool, "-j", "list", "tables"]
    if identifier is not None:
        import re

        if not isinstance(identifier, str) or not re.fullmatch(
            r"[0-9a-f]{32}", identifier
        ):
            raise ValueError("Internal firewall identity is invalid")
        command = [tool, "-j", "list", "table", "inet", "lumina_" + identifier]
    result = subprocess.run(
        command, capture_output=True, text=True, check=True, timeout=3, shell=False
    )
    if len(result.stdout) > 1024 * 1024:
        raise PermissionError("Native firewall state exceeds inspection bound")
    state = json.loads(result.stdout)
    if not isinstance(state, dict) or not isinstance(state.get("nftables"), list):
        raise PermissionError("Native firewall state is unverifiable")
    if identifier is not None:
        chains = {
            item["chain"].get("name"): item["chain"]
            for item in state["nftables"]
            if isinstance(item, dict) and isinstance(item.get("chain"), dict)
        }
        if set(chains) != {"input", "output"} or any(
            chain.get("family") != "inet"
            or chain.get("table") != "lumina_" + identifier
            or chain.get("type") != "filter"
            or chain.get("hook") != direction
            or chain.get("policy") != "drop"
            # New isolation must inspect conntrack direction/state after the
            # conntrack hook (-200), including locally originated OUTPUT.
            or chain.get("prio") != 0
            for direction, chain in chains.items()
        ):
            raise PermissionError(
                "Owned Linux isolation hooks are missing or ineffective"
            )
    return {
        "tool": tool,
        "native_kernel_access": True,
        "owned_hooks_verified": identifier is not None,
    }


def _native_properties():
    """IDispatch by property name avoids hardcoded INetFwPolicy2 vtable slots."""

    class GUID(ctypes.Structure):
        _fields_ = [
            ("a", ctypes.c_uint32),
            ("b", ctypes.c_uint16),
            ("c", ctypes.c_uint16),
            ("d", ctypes.c_ubyte * 8),
        ]

    class Value(ctypes.Union):
        _fields_ = [
            ("integer", ctypes.c_int32),
            ("boolean", ctypes.c_int16),
            ("pointer", ctypes.c_void_p),
            ("record", ctypes.c_void_p * 2),
        ]

    class Variant(ctypes.Structure):
        _fields_ = [
            ("kind", ctypes.c_uint16),
            ("r1", ctypes.c_uint16),
            ("r2", ctypes.c_uint16),
            ("r3", ctypes.c_uint16),
            ("value", Value),
        ]

    class Params(ctypes.Structure):
        _fields_ = [
            ("args", ctypes.POINTER(Variant)),
            ("named", ctypes.POINTER(ctypes.c_int32)),
            ("count", ctypes.c_uint32),
            ("named_count", ctypes.c_uint32),
        ]

    ole = ctypes.OleDLL("ole32")
    automation = ctypes.OleDLL("oleaut32")
    ole.CoInitializeEx.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
    ole.CoInitializeEx.restype = ctypes.c_int32
    ole.CoCreateInstance.argtypes = (
        ctypes.POINTER(GUID),
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(GUID),
        ctypes.POINTER(ctypes.c_void_p),
    )
    ole.CoCreateInstance.restype = ctypes.c_int32
    automation.VariantClear.argtypes = (ctypes.POINTER(Variant),)
    initialized = ole.CoInitializeEx(None, 0)
    if initialized not in (
        0,
        1,
        -2147417850,
    ):  # RPC_E_CHANGED_MODE uses caller's existing apartment.
        raise OSError("Cannot initialize firewall policy COM")
    instance = ctypes.c_void_p()
    clsid = GUID.from_buffer_copy(
        uuid.UUID("e2b3c97f-6ae1-41ac-817a-f6f92166d7dd").bytes_le
    )
    interface = GUID.from_buffer_copy(
        uuid.UUID("00020400-0000-0000-c000-000000000046").bytes_le
    )
    null_guid = GUID()
    try:
        if (
            ole.CoCreateInstance(
                ctypes.byref(clsid),
                None,
                1,
                ctypes.byref(interface),
                ctypes.byref(instance),
            )
            < 0
        ):
            raise OSError("Firewall policy service is unavailable")
        table = ctypes.cast(
            instance, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))
        ).contents
        get_name = ctypes.WINFUNCTYPE(
            ctypes.c_int32,
            ctypes.c_void_p,
            ctypes.POINTER(GUID),
            ctypes.POINTER(ctypes.c_wchar_p),
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_int32),
        )(table[5])
        invoke = ctypes.WINFUNCTYPE(
            ctypes.c_int32,
            ctypes.c_void_p,
            ctypes.c_int32,
            ctypes.POINTER(GUID),
            ctypes.c_uint32,
            ctypes.c_uint16,
            ctypes.POINTER(Params),
            ctypes.POINTER(Variant),
            ctypes.c_void_p,
            ctypes.c_void_p,
        )(table[6])

        def read(name, profile=None):
            identifier, names = ctypes.c_int32(), (ctypes.c_wchar_p * 1)(name)
            if (
                get_name(
                    instance,
                    ctypes.byref(null_guid),
                    names,
                    1,
                    0,
                    ctypes.byref(identifier),
                )
                < 0
            ):
                raise OSError("Firewall property unavailable")
            argument, result = Variant(), Variant()
            argument.kind, argument.value.integer = 3, profile or 0
            params = Params(
                ctypes.pointer(argument) if profile is not None else None,
                None,
                int(profile is not None),
                0,
            )
            try:
                if (
                    invoke(
                        instance,
                        identifier,
                        ctypes.byref(null_guid),
                        0,
                        2,
                        ctypes.byref(params),
                        ctypes.byref(result),
                        None,
                        None,
                    )
                    < 0
                ):
                    raise OSError("Firewall property query failed")
                if result.kind == 11:
                    return bool(result.value.boolean)
                if result.kind in (3, 22):
                    return result.value.integer
                if result.kind in (0, 1):
                    return None
                if result.kind & 0x2000:
                    if not result.value.pointer:
                        return []
                    automation.SafeArrayGetLBound.argtypes = (
                        ctypes.c_void_p,
                        ctypes.c_uint32,
                        ctypes.POINTER(ctypes.c_int32),
                    )
                    automation.SafeArrayGetUBound.argtypes = (
                        automation.SafeArrayGetLBound.argtypes
                    )
                    low, high = ctypes.c_int32(), ctypes.c_int32()
                    if (
                        automation.SafeArrayGetLBound(
                            result.value.pointer, 1, ctypes.byref(low)
                        )
                        < 0
                        or automation.SafeArrayGetUBound(
                            result.value.pointer, 1, ctypes.byref(high)
                        )
                        < 0
                    ):
                        raise PermissionError(
                            "Firewall excluded-interface state is unavailable"
                        )
                    if high.value < low.value:
                        return []
                raise PermissionError(
                    "Firewall property is not a supported safe scalar or empty interface list"
                )
            finally:
                automation.VariantClear(ctypes.byref(result))

        result = {
            "modify_state": read("LocalPolicyModifyState"),
            "profiles": {
                profile: {
                    "enabled": read("FirewallEnabled", profile),
                    "excluded": read("ExcludedInterfaces", profile),
                }
                for profile in (1, 2, 4)
            },
        }
        # Explicit domain policy disabling a profile overrides its local value.
        import winreg

        for profile, name in (
            (1, "DomainProfile"),
            (2, "PrivateProfile"),
            (4, "PublicProfile"),
            (2, "StandardProfile"),
        ):
            try:
                with winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    "SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\" + name,
                ) as key:
                    enabled, kind = winreg.QueryValueEx(key, "EnableFirewall")
                    if kind != winreg.REG_DWORD or enabled == 0:
                        result["profiles"][profile]["enabled"] = False
            except FileNotFoundError:
                pass
        return result
    finally:
        if instance:
            table = ctypes.cast(
                instance, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p))
            ).contents
            ctypes.WINFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p)(table[2])(instance)
        if initialized in (0, 1):
            ole.CoUninitialize()


def verify(properties=None):
    state = _native_properties() if properties is None else properties
    if (
        not isinstance(state, dict)
        or type(state.get("modify_state")) is not int
        or state["modify_state"] != 0
    ):
        raise PermissionError(
            "Windows local firewall rules are overridden or unverifiable"
        )
    profiles = state.get("profiles")
    if (
        not isinstance(profiles, dict)
        or set(profiles) != {1, 2, 4}
        or any(
            not isinstance(value, dict)
            or value.get("enabled") is not True
            or value.get("excluded") not in (None, [])
            for value in profiles.values()
        )
    ):
        raise PermissionError(
            "Every Windows firewall profile must be enabled without excluded interfaces"
        )
    return True
