# ruff: noqa: UP017 -- Distributed runtime supports Python 3.10.
"""Agent CLI shared by Windows service/GUI and Linux daemon."""

import argparse
import getpass
import importlib
import ipaddress
import json
import logging
import os
import re
import signal
import subprocess
import threading
from pathlib import Path

from .core import Agent, RunLock, atomic_json, enroll, response


def load_config(path):
    config = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    for field in ("endpoint_url", "ca_file", "tenant", "host", "state_dir"):
        if not isinstance(config.get(field), str) or not config[field]:
            raise ValueError("Config requires " + field)
    origin = Path(path).resolve().parent
    for field in ("ca_file", "state_dir", "public_status_file"):
        if not config.get(field):
            continue
        candidate = Path(config[field]).expanduser()
        if not candidate.is_absolute():
            config[field] = str((origin / candidate).resolve())
    return config


def run_agent(config, collector, *, once=False, stop=None):
    stop = stop or threading.Event()
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, lambda *_: stop.set())
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
    directory = Path(config["state_dir"])
    directory.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=str(directory / "agent.log"),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    Agent(config, collector, stop).run(once=once)


def main(os_name, collector_type, argv=None):
    parser = argparse.ArgumentParser(
        description=f"Vatex LUMINA xSERA {os_name} endpoint agent"
    )
    parser.add_argument(
        "command",
        choices=(
            "init-config",
            "enroll",
            "run",
            "once",
            "status",
            "simulate-case",
            "gui",
            "tray",
            "service",
            "response-policy",
            "defense-policy",
            "kernel-policy",
            "memory-policy",
        ),
    )
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument(
        "--token", help="One-time enrollment token; omitted to prompt securely"
    )
    parser.add_argument(
        "--token-file", type=Path, help="File containing the one-time enrollment token"
    )
    parser.add_argument("--endpoint-url")
    parser.add_argument("--ca-file")
    parser.add_argument("--tenant")
    parser.add_argument("--host")
    parser.add_argument("--state-dir")
    response_mode = parser.add_mutually_exclusive_group()
    response_mode.add_argument("--enable-response", action="store_true")
    response_mode.add_argument("--disable-response", action="store_true")
    parser.add_argument("--allow-process-executable", action="append", default=[])
    parser.add_argument(
        "--allow-process-instance",
        action="append",
        default=[],
        help="Exact PID:START_IDENTITY; repeat for additional instances",
    )
    parser.add_argument("--allow-file-root", action="append", default=[])
    parser.add_argument(
        "--mark-file-roots",
        action="store_true",
        help="Explicitly mark ONLY the listed existing private directories for irreversible deletion",
    )
    parser.add_argument("--confirm-response-policy", action="store_true")
    parser.add_argument("--allow-investigation", action="store_true")
    parser.add_argument("--allow-process-artifact-collection", action="store_true", help="Explicit read-only live-process disk image observation/collection; requires exact executable allowlist")
    parser.add_argument("--max-process-artifact-bytes", type=int, default=32 * 1024 * 1024)
    parser.add_argument("--allow-quarantine", action="store_true")
    parser.add_argument("--allow-restore", action="store_true")
    parser.add_argument("--allow-delete", action="store_true")
    parser.add_argument("--allow-termination", action="store_true")
    parser.add_argument("--quarantine-dir", type=Path)
    defense_mode = parser.add_mutually_exclusive_group()
    defense_mode.add_argument("--enable-defense", action="store_true")
    defense_mode.add_argument("--disable-defense", action="store_true")
    parser.add_argument("--confirm-defense-policy", action="store_true")
    parser.add_argument("--allow-host-isolation", action="store_true")
    parser.add_argument(
        "--management-endpoint",
        action="append",
        default=[],
        help="Exact direction,IP,port; direction is inbound or outbound",
    )
    parser.add_argument("--isolation-max-seconds", type=int, default=300)
    kernel_mode = parser.add_mutually_exclusive_group()
    kernel_mode.add_argument("--enable-kernel-prevention", action="store_true")
    kernel_mode.add_argument("--disable-kernel-prevention", action="store_true")
    parser.add_argument("--confirm-kernel-policy", action="store_true")
    parser.add_argument("--kernel-directory", action="append", default=[])
    parser.add_argument("--kernel-rule-id", action="append", default=[])
    parser.add_argument("--kernel-decision-timeout-ms", type=int, default=500)
    parser.add_argument("--kernel-max-file-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--kernel-mode", choices=("audit", "enforce"), default="audit")
    parser.add_argument("--kernel-lease-seconds", type=int, default=60)
    parser.add_argument(
        "--guarded-workload-mode", choices=("off", "audit", "enforce"), default="off"
    )
    parser.add_argument("--confirm-guarded-workload", action="store_true")
    parser.add_argument("--guarded-workload-lease-seconds", type=int, default=60)
    memory_mode = parser.add_mutually_exclusive_group()
    memory_mode.add_argument("--enable-memory-observability", action="store_true")
    memory_mode.add_argument("--disable-memory-observability", action="store_true")
    parser.add_argument("--confirm-memory-policy", action="store_true")
    parser.add_argument("--memory-max-processes", type=int, default=16)
    parser.add_argument("--memory-max-regions", type=int, default=512)
    parser.add_argument("--memory-budget-ms", type=int, default=500)
    args = parser.parse_args(argv)
    if args.command == "init-config":
        values = {
            "endpoint_url": args.endpoint_url,
            "ca_file": args.ca_file,
            "tenant": args.tenant,
            "host": args.host,
            "state_dir": args.state_dir,
            "collect_interval_seconds": 5,
            "max_pending": 10000,
            "capture_reserve": 10000,
            "emit_initial_processes": False,
            "emit_startup_inventory": True,
            "memory_observability": {"enabled": False},
        }
        if any(
            not value
            for key, value in values.items()
            if key in ("endpoint_url", "ca_file", "tenant", "host", "state_dir")
        ):
            parser.error(
                "init-config requires endpoint-url, ca-file, tenant, host, state-dir"
            )
        if args.config.exists():
            raise RuntimeError("Config already exists; existing settings preserved")
        atomic_json(args.config, values)
        return
    config = load_config(args.config)
    if args.command in {
        "response-policy",
        "defense-policy",
        "kernel-policy",
        "memory-policy",
    }:
        _administrator()
        confirmed = getattr(args, "confirm_" + args.command.replace("-", "_"))
        if not confirmed:
            raise PermissionError("Explicit local policy confirmation is required")
        _protected_installation(args.config, config)
        with RunLock(config["state_dir"]), response.Lock(config["state_dir"]):
            if args.command == "defense-policy":
                policy = defense_policy(config, args)
                config["defense"] = policy
            elif args.command == "kernel-policy":
                policy = kernel_policy(config, args)
                config["kernel_prevention"] = policy
            elif args.command == "memory-policy":
                if not (
                    args.enable_memory_observability
                    or args.disable_memory_observability
                ):
                    raise PermissionError(
                        "Explicit memory-observability enable or disable required"
                    )
                policy = {
                    "enabled": bool(args.enable_memory_observability),
                    "max_processes": args.memory_max_processes,
                    "max_regions": args.memory_max_regions,
                    "budget_ms": args.memory_budget_ms,
                }
                provider = importlib.import_module(
                    response.__package__ + ".memory_observability"
                )
                provider.MemoryObservability(
                    {"memory_observability": policy}, response.inspect_process
                )
                config["memory_observability"] = policy
            else:
                policy = response_policy(config, args)
                config["response"] = policy
            atomic_json(args.config, config)
        print(
            json.dumps(
                {
                    "command": args.command,
                    "response": response.capabilities(config),
                    "policy": policy,
                    "restart_required": True,
                },
                ensure_ascii=False,
            )
        )
        return
    if args.command == "enroll":
        if args.token and args.token_file:
            parser.error("Use token or token-file, not both")
        supplied = (
            args.token_file.read_text(encoding="utf-8").strip()
            if args.token_file
            else args.token
        )
        print(
            json.dumps(
                enroll(config, supplied or getpass.getpass("Enrollment token: ")),
                ensure_ascii=False,
            )
        )
    elif args.command in ("run", "once"):
        run_agent(
            config,
            collector_type(
                emit_initial=bool(config.get("emit_initial_processes", False)),
                emit_startup_inventory=bool(config.get("emit_startup_inventory", True)),
                state_dir=config["state_dir"],
            ),
            once=args.command == "once",
        )
    elif args.command == "status":
        path = Path(config["state_dir"]) / "status.json"
        print(
            path.read_text(encoding="utf-8")
            if path.exists()
            else '{"status":"not started"}'
        )
    elif args.command == "simulate-case":
        simulate_case(config, collector_type)
    elif args.command in ("gui", "tray", "service"):
        if os_name != "Windows":
            parser.error(args.command + " is Windows-only")
        if args.command == "service":
            from .Windows.service import serve

            serve(config, collector_type)
        else:
            from .Windows.tray import start_gui

            start_gui(config, tray=args.command == "tray")


def response_policy(config, args):
    """Explicit local administrator opt-in; never accepts policy from the SIEM."""
    _administrator()
    if not args.confirm_response_policy or not (
        args.enable_response or args.disable_response
    ):
        raise PermissionError(
            "Administrator/root, enable/disable and --confirm-response-policy are required"
        )
    if args.disable_response:
        return {
            "enabled": False,
            "allow_process_termination": False,
            "allow_file_delete": False,
            "allow_investigation": False,
            "allow_process_artifact_collection": False,
            "allow_quarantine": False,
            "allow_restore": False,
            "allow_host_isolation": False,
            "allowed_process_executables": [],
            "allowed_process_instances": [],
            "file_roots": [],
        }
    return _enabled_response_policy(config, args)


def _administrator():
    if os.name == "nt":
        import ctypes

        administrator = bool(ctypes.windll.shell32.IsUserAnAdmin())
    else:
        administrator = os.geteuid() == 0
    if not administrator:
        raise PermissionError("Local administrator/root is required")


def _protected(path, secret=False):
    """Reject writeable/link configuration; native ACL read only on Windows."""
    path = Path(path).absolute()
    response._no_links(path)
    if os.name != "nt":
        info = path.stat()
        if info.st_uid != os.geteuid() or info.st_mode & (0o077 if secret else 0o022):
            raise PermissionError("Policy path is not protected by the service owner")
        return
    tool = (
        Path(os.environ.get("SystemRoot", "C:/Windows"))
        / "System32/WindowsPowerShell/v1.0/powershell.exe"
    )
    script = """$ErrorActionPreference='Stop'
$trusted=@('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
$acl=Get-Acl -LiteralPath $env:LUMINA_LOCAL_POLICY_PATH
if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted){throw 'Untrusted owner'}
$rights=0xD0156
if($env:LUMINA_LOCAL_POLICY_SECRET -eq '1'){$rights=$rights -bor 1}
foreach($r in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
 if($r.IdentityReference.Value -eq 'S-1-3-4'){continue} # OWNER RIGHTS resolves to the verified trusted owner.
 if($r.IdentityReference.Value -eq 'S-1-3-0' -and ($r.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)){continue}
 if($r.AccessControlType -eq 'Allow' -and ($r.FileSystemRights -band $rights) -and $r.IdentityReference.Value -notin $trusted){throw 'Untrusted access'}
}
"""
    environment = dict(
        os.environ,
        LUMINA_LOCAL_POLICY_PATH=str(path),
        LUMINA_LOCAL_POLICY_SECRET="1" if secret else "0",
        PSModulePath=str(tool.parent / "Modules"),
    )
    result = subprocess.run(
        [str(tool), "-NoProfile", "-NonInteractive", "-Command", script],
        env=environment,
        capture_output=True,
        check=False,
        timeout=15,
    )
    if result.returncode:
        raise PermissionError("Policy path ACL is not protected")


def _protected_installation(filename, config):
    _protected(filename)
    _protected(Path(filename).absolute().parent)
    _protected(Path(__file__))
    state = Path(config["state_dir"])
    response._no_links(state.parent)
    if state.exists() or state.is_symlink():
        response._no_links(state)
    if not state.exists():
        state.mkdir(mode=0o700, parents=True)
        if os.name == "nt":
            tool = (
                Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/icacls.exe"
            )
            subprocess.run(
                [
                    str(tool),
                    str(state),
                    "/inheritance:r",
                    "/grant:r",
                    "*S-1-5-18:(OI)(CI)F",
                    "*S-1-5-32-544:(OI)(CI)F",
                ],
                capture_output=True,
                check=True,
                timeout=15,
            )
    _protected(state, secret=True)


def defense_policy(config, args):
    _administrator()
    if not args.confirm_defense_policy or not (
        args.enable_defense or args.disable_defense
    ):
        raise PermissionError(
            "Defense enable/disable and --confirm-defense-policy required"
        )
    if args.disable_defense:
        return dict(config.get("defense", {}), enabled=False)
    identity_path = Path(config["state_dir"]) / "identity.json"
    _protected(identity_path, secret=True)
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    key = identity.get("defense_public_key")
    if (
        not isinstance(key, str)
        or not re.fullmatch(r"[a-fA-F0-9]{64}", key)
        or not isinstance(identity.get("agent_id"), str)
        or not identity["agent_id"]
        or not isinstance(identity.get("index"), str)
        or not identity["index"]
        or any(
            identity.get(field) != config.get(field)
            for field in ("tenant", "host", "index")
        )
    ):
        raise PermissionError(
            "Current credential-bound enrollment key/agent/index required"
        )
    return {
        "enabled": True,
        "public_key": key,
        "bundle_file": str(Path(config["state_dir"]) / "defense-policy.json"),
    }


def _enabled_response_policy(config, args):
    executables, instances, roots = [], [], []
    if (
        len(args.allow_process_executable) > 32
        or len(args.allow_process_instance) > 128
        or len(args.allow_file_root) > 16
    ):
        raise ValueError("Response allowlist limits exceeded")
    for value in args.allow_process_executable:
        path = Path(value)
        response._no_links(path)
        if not path.is_absolute() or not path.is_file():
            raise ValueError("Exact existing executable absolute path required")
        executables.append(str(path.resolve(strict=True)))
    for value in args.allow_process_instance:
        pid, separator, start = value.partition(":")
        if not separator or not pid.isascii() or not pid.isdigit():
            raise ValueError("Process instance requires PID:START_IDENTITY")
        info = response.inspect_process(int(pid), config["host"])
        if start != info["start_identity"] or os.path.normcase(
            str(Path(info["executable"]).resolve())
        ) not in {os.path.normcase(p) for p in executables}:
            raise PermissionError(
                "Current process instance/executable differs from the explicit local allowlist"
            )
        instances.append({"pid": int(pid), "start_identity": start})
    blocked = {
        Path.home().resolve(),
        Path(config["state_dir"]).resolve(),
        Path(__file__).resolve().parents[1],
    }
    blocked.update(
        Path(p).resolve()
        for p in (
            "/",
            "/etc",
            "/usr",
            "/bin",
            "/sbin",
            "/var",
            "/tmp",
            "/home",
            "/root",
        )
        if os.name != "nt"
    )
    if os.name == "nt":
        blocked.update(
            Path(os.environ[key]).resolve()
            for key in (
                "SystemRoot",
                "ProgramFiles",
                "ProgramFiles(x86)",
                "ProgramData",
                "USERPROFILE",
            )
            if os.environ.get(key)
        )
    for value in args.allow_file_root:
        root = Path(value)
        response._no_links(root)
        if not root.is_absolute() or not root.is_dir():
            raise ValueError("Existing private directory absolute path required")
        root = root.resolve(strict=True)
        if (
            root == root.parent
            or root in blocked
            or any(p.is_relative_to(root) for p in blocked)
        ):
            raise PermissionError("Broad OS/home/installation roots are forbidden")
        if os.name != "nt":
            info = root.stat()
            if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise PermissionError(
                    "File root must be private and owned by the service identity"
                )
        _protected(root)
        marker = root / response.MARKER
        if args.mark_file_roots and not marker.exists():
            descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(response.MARKER_TEXT)
                handle.flush()
                os.fsync(handle.fileno())
        response._no_links(marker)
        if (
            marker.stat().st_size > 64
            or marker.read_text(encoding="utf-8") != response.MARKER_TEXT
        ):
            raise PermissionError(
                "Root marker is absent or invalid; review and use --mark-file-roots explicitly"
            )
        roots.append(str(root))
    investigation = bool(args.allow_investigation)
    process_artifact = bool(getattr(args, "allow_process_artifact_collection", False))
    process_maximum = getattr(args, "max_process_artifact_bytes", 32 * 1024 * 1024)
    if type(process_maximum) is not int or not 1 <= process_maximum <= 32 * 1024 * 1024:
        raise ValueError("Process artifact byte limit must be 1..32 MiB")
    if process_artifact and (not investigation or not executables):
        raise ValueError("Process artifact collection requires investigation and an exact executable allowlist")
    quarantine, restore = bool(args.allow_quarantine), bool(args.allow_restore)
    host_isolation = bool(getattr(args, "allow_host_isolation", False))
    extended = investigation or quarantine or restore or host_isolation or process_artifact
    if (quarantine or restore) and not roots:
        raise ValueError("Quarantine/restore requires explicit marked file roots")
    quarantine_dir = None
    if quarantine or restore or host_isolation or process_artifact:
        operations = importlib.import_module(response.__package__ + ".operations")
        state = Path(config["state_dir"]).resolve()
        directory = args.quarantine_dir or state / "quarantine"
        response._no_links(directory.parent)
        if directory.exists() or directory.is_symlink():
            response._no_links(directory)
        if (
            not directory.is_absolute()
            or directory == state
            or not directory.is_relative_to(state)
        ):
            raise PermissionError(
                "Quarantine directory must be a private state subdirectory"
            )
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        _protected(directory, secret=True)
        marker = directory / operations.MARKER
        if marker.exists() or marker.is_symlink():
            response._no_links(marker)
        if not marker.exists():
            with marker.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(operations.MARKER_TEXT)
                stream.flush()
                os.fsync(stream.fileno())
        if (
            marker.stat().st_size > 64
            or marker.read_text(encoding="utf-8") != operations.MARKER_TEXT
        ):
            raise PermissionError("Private quarantine marker is invalid")
        quarantine_dir = str(directory)
    if not executables and not roots and not investigation and not host_isolation:
        raise ValueError(
            "Enable response requires at least one exact executable or marked file root"
        )
    policy = {
        "enabled": True,
        "allow_process_termination": bool(executables)
        and (bool(args.allow_termination) or not extended),
        "allow_file_delete": bool(roots) and (bool(args.allow_delete) or not extended),
        "allow_investigation": investigation,
        "allow_process_artifact_collection": process_artifact,
        "max_process_artifact_bytes": process_maximum,
        "allow_quarantine": quarantine,
        "allow_restore": restore,
        "allow_host_isolation": host_isolation,
        "quarantine_dir": quarantine_dir,
        "allowed_process_executables": sorted(set(executables)),
        "allowed_process_instances": instances,
        "file_roots": sorted(set(roots)),
    }
    if host_isolation:
        endpoints = []
        for value in args.management_endpoint:
            direction, separator, address_port = value.partition(",")
            address, separator2, port = address_port.partition(",")
            if (
                not separator
                or not separator2
                or direction not in {"inbound", "outbound"}
            ):
                raise ValueError("Management endpoint requires direction,IP,port")
            ip = ipaddress.ip_address(address)
            if not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535:
                raise ValueError("Management endpoint requires TCP port 1..65535")
            endpoints.append({"ip": str(ip), "port": int(port), "direction": direction})
        if not endpoints or len(endpoints) > 8:
            raise ValueError("Host isolation requires 1..8 exact management endpoints")
        policy.update(
            management_endpoints=endpoints,
            management_allowlist=sorted(
                {
                    str(
                        ipaddress.ip_network(
                            row["ip"]
                            + (
                                "/32"
                                if ipaddress.ip_address(row["ip"]).version == 4
                                else "/128"
                            )
                        )
                    )
                    for row in endpoints
                }
            ),
            isolation_max_seconds=args.isolation_max_seconds,
            quarantine_dir=quarantine_dir
            or str(Path(config["state_dir"]).resolve() / "quarantine"),
        )
        operations = importlib.import_module(response.__package__ + ".operations")
        operations.network_definition(policy)
        maximum = 300 if os.name == "nt" else 3600
        if not 30 <= args.isolation_max_seconds <= maximum:
            raise ValueError(
                "Isolation safety lease must be 30.." + str(maximum) + " seconds"
            )
    elif getattr(args, "management_endpoint", []):
        raise ValueError("Management endpoints require explicit --allow-host-isolation")
    return policy


def kernel_policy(config, args):
    """Private stopped-agent local consent is separate from server signature approval."""
    _administrator()
    if not args.confirm_kernel_policy or not (
        args.enable_kernel_prevention or args.disable_kernel_prevention
    ):
        raise PermissionError(
            "Kernel prevention enable/disable and confirmation required"
        )
    if args.disable_kernel_prevention:
        return dict(config.get("kernel_prevention", {}), enabled=False)
    pinned = defense_policy(
        config,
        argparse.Namespace(
            confirm_defense_policy=True, enable_defense=True, disable_defense=False
        ),
    )
    config["defense"] = dict(
        pinned, enabled=bool(config.get("defense", {}).get("enabled"))
    )
    if (
        not 1 <= len(args.kernel_directory) <= 32
        or not 1 <= len(args.kernel_rule_id) <= 256
    ):
        raise ValueError(
            "Kernel policy requires explicit 1..32 directories and 1..256 rule IDs"
        )
    directories = []
    protected = {
        Path.home().resolve(),
        Path(config["state_dir"]).resolve(),
        Path(__file__).resolve().parents[1],
    }
    for value in args.kernel_directory:
        path = Path(value)
        response._no_links(path)
        if not path.is_absolute() or not path.is_dir():
            raise ValueError("Existing absolute prevention directory required")
        path = path.resolve()
        if (
            path == path.parent
            or path in protected
            or any(p.is_relative_to(path) for p in protected)
        ):
            raise PermissionError("Broad home, OS or agent directories are forbidden")
        _protected(path)
        directories.append(str(path))
    if not 50 <= args.kernel_decision_timeout_ms <= 2000:
        raise ValueError("Kernel decision timeout must be 50..2000 ms")
    if not 1 <= args.kernel_max_file_bytes <= 64 * 1024 * 1024:
        raise ValueError("Kernel file size must be 1..64 MiB")
    if not 30 <= args.kernel_lease_seconds <= 300:
        raise ValueError("Windows application-control lease must be 30..300 seconds")
    if any(
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", value)
        for value in args.kernel_rule_id
    ):
        raise ValueError("Kernel rule IDs must be exact bounded identifiers")
    settings = {
        "enabled": True,
        "directories": sorted(set(directories)),
        "rule_ids": sorted(set(args.kernel_rule_id)),
        "decision_timeout_ms": args.kernel_decision_timeout_ms,
        "max_file_bytes": args.kernel_max_file_bytes,
    }
    if os.name == "nt":
        if getattr(args, "guarded_workload_mode", "off") != "off":
            raise ValueError(
                "Guarded workload allowlist is Linux-only; Windows keeps exact-code deny"
            )
        settings.update(
            windows_mode=args.kernel_mode,
            windows_lease_seconds=args.kernel_lease_seconds,
        )
    elif getattr(args, "guarded_workload_mode", "off") != "off":
        if getattr(args, "confirm_guarded_workload", False) is not True:
            raise PermissionError("Separate guarded-workload confirmation required")
        settings.update(
            guarded_workload_mode=args.guarded_workload_mode,
            guarded_workload_confirmed=True,
            guarded_workload_lease_seconds=getattr(
                args, "guarded_workload_lease_seconds", 60
            ),
        )
    module = importlib.import_module(
        response.__package__
        + (".windows_app_control" if os.name == "nt" else ".kernel_prevention")
    )
    module.validate_settings(settings)
    return settings


def simulate_case(config, collector_type):
    """Explicit non-malicious lab stimulus; never executes a PowerShell command."""
    import uuid
    from datetime import datetime, timezone

    agent = Agent(config, collector_type())
    run_id = uuid.uuid4().hex
    for action, process in (
        ("process_created", "powershell.exe"),
        ("defender_detection", "MsMpEng.exe"),
    ):
        data = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "host": {"id": config["host"]},
            "user": {"name": "aegis-test"},
            "process": {
                "guid": str(uuid.uuid5(uuid.NAMESPACE_URL, run_id + ":" + process)),
                "name": process,
                "command_line": "SIMULATED EVENT - no command executed",
                "parent": {
                    "guid": str(uuid.uuid5(uuid.NAMESPACE_URL, run_id + ":parent"))
                },
            },
            "event": {
                "module": "security" if action == "defender_detection" else "process",
                "action": action,
            },
            "test": {
                "synthetic": True,
                "run_id": run_id,
                "origin": "agent simulate-case",
            },
        }
        agent.queue.add({"id": "agent-simulation-" + uuid.uuid4().hex, "data": data})
        print(f"queued {action}", flush=True)
        print(f"accepted {agent.flush()}", flush=True)
    agent.status()
    agent.queue.close()


if __name__ == "__main__":
    raise SystemExit("Use the Windows or Linux entry point")
