"""Bounded typed investigations and reversible effects; no remote shell input."""
# ruff: noqa: BLE001 -- Post-effect failures must report unknown; rollback probes also fail closed for any adapter error.

import hashlib
import ipaddress
import json
import os
import platform
import re
import select
import socket
import sqlite3
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path

from . import response as base

MARKER = ".lumina-quarantine-root"
MARKER_TEXT = "allow-reversible-quarantine\n"


def _uncertain(detail, data):
    error = base.EffectUnconfirmedError(detail)
    error.data = data
    raise error from None


def _state(settings):
    path = Path(settings.get("quarantine_dir", ""))
    if not path.is_absolute():
        raise PermissionError("An operator-created private quarantine_dir is required")
    base._no_links(path)
    marker = path / MARKER
    base._no_links(marker)
    if marker.read_text(encoding="utf-8") != MARKER_TEXT:
        raise PermissionError("Quarantine directory marker is unavailable")
    if os.name != "nt":
        info = path.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise PermissionError("Quarantine state must be service-owned and private")
    db = sqlite3.connect(path / "effects.sqlite3", timeout=1)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA synchronous=FULL")
    db.executescript("""
    CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY, original TEXT NOT NULL,
      object TEXT NOT NULL, sha256 TEXT NOT NULL, mode INTEGER NOT NULL, state TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS isolation(id TEXT PRIMARY KEY,digest TEXT NOT NULL,
      definition TEXT NOT NULL,state TEXT NOT NULL);
    """)
    columns = {row[1] for row in db.execute("PRAGMA table_info(isolation)")}
    for name, kind in (
        ("expires", "REAL"),
        ("guard_pid", "INTEGER"),
        ("guard_start_identity", "TEXT"),
    ):
        if name not in columns:
            db.execute("ALTER TABLE isolation ADD COLUMN " + name + " " + kind)
    db.commit()
    return path, db


def _read(path, expected, maximum=base.MAX_FILE):
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > maximum
        ):
            raise PermissionError("File must be unlinked regular bounded content")
        digest, deadline, body = hashlib.sha256(), time.monotonic() + 3, bytearray()
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("Investigation file deadline exceeded")
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            digest.update(chunk)
            if maximum <= 8 * 1024 * 1024:
                body.extend(chunk)
        after = os.fstat(fd)
        named = path.stat(follow_symlinks=False)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino):
            raise PermissionError("File changed during investigation")
        if digest.hexdigest() != expected:
            raise PermissionError("File hash differs from approved evidence")
        return before, bytes(body)
    finally:
        os.close(fd)


def _move(source, destination, expected):
    """No overwrite; Windows pins a handle, POSIX private parent claims first."""
    if destination.exists():
        raise PermissionError("Destination already exists")
    if os.name == "nt":
        base._win_delete(source, expected, destination=destination)
        return
    parent = os.open(source.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    claimed = ".lumina-claim-" + uuid.uuid4().hex
    moved = False
    try:
        before = os.stat(source.name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise PermissionError("Source is not a single regular file")
        os.rename(source.name, claimed, src_dir_fd=parent, dst_dir_fd=parent)
        moved = True
        claimed_path = source.parent / claimed
        actual, _ = _read(claimed_path, expected)
        if (actual.st_dev, actual.st_ino) != (before.st_dev, before.st_ino):
            raise PermissionError("Claimed object identity changed")
        os.link(
            claimed,
            destination.name,
            src_dir_fd=parent,
            dst_dir_fd=parent,
            follow_symlinks=False,
        )
        os.unlink(claimed, dir_fd=parent)
        moved = False
    finally:
        if moved:
            try:
                os.link(
                    claimed,
                    source.name,
                    src_dir_fd=parent,
                    dst_dir_fd=parent,
                    follow_symlinks=False,
                )
                os.unlink(claimed, dir_fd=parent)
            except OSError:
                os.close(parent)
                raise base.EffectUnconfirmedError(
                    "Claimed object preserved but original name could not be restored"
                ) from None
        os.close(parent)


def investigate(target, host, settings):
    kind = target["type"]
    if settings.get("allow_investigation") is not True:
        raise PermissionError("Read-only investigation is not locally enabled")
    if kind == "inspect_process":
        if target.get("capture_executable_evidence") is True:
            from . import process_artifact
            result, _ = process_artifact.observe(target, host, settings)
            result["publish_process_evidence"] = True
        else:
            info = base.inspect_process(target["pid"], host)
            base._check_process(info, target, settings)
            result = {key: info[key] for key in ("pid", "guid", "start_identity", "executable")}
    else:
        if kind == "collect_artifact" and target.get("source") == "process_executable":
            from . import process_artifact
            result, body = process_artifact.observe(target, host, settings, collect=True)
        else:
            path = base._file_target(target["path"], settings)
            info, body = _read(path, target["sha256"], 2 * 1024 * 1024 if kind == "collect_artifact" else base.MAX_FILE)
            result = {"sha256": target["sha256"], "bytes": info.st_size, "modified_ns": info.st_mtime_ns}
        if kind == "collect_artifact":
            directory, db = _state(settings)
            try:
                identifier = "ART-" + uuid.uuid4().hex
                artifact = directory / (identifier + ".bin")
                with artifact.open("xb") as stream:
                    stream.write(body)
                    stream.flush()
                    os.fsync(stream.fileno())
                if os.name != "nt":
                    artifact.chmod(0o600)
                result["artifact_id"] = identifier
                result["transport"] = (
                    "retained locally; contents are not sent in result"
                )
            finally:
                db.close()
    outcome = base._outcome(
        kind,
        "investigated",
        "Bounded evidence-verified read-only investigation",
        success=True,
    )
    outcome["data"] = result
    return outcome


def quarantine(target, settings):
    if settings.get("allow_quarantine") is not True:
        raise PermissionError("Reversible quarantine is not locally enabled")
    path = base._file_target(target["path"], settings)
    if path.is_relative_to(Path(base.__file__).resolve().parent.parent):
        raise PermissionError("Agent files are protected")
    directory, db = _state(settings)
    try:
        if path.is_relative_to(directory):
            raise PermissionError("Quarantine catalog and artifacts are protected")
        info, _ = _read(path, target["sha256"])
        identifier = "Q-" + uuid.uuid4().hex
        destination = path.parent / (".lumina-quarantine-" + identifier)
        # Permanent execution/investigation history has no lifetime count ceiling.
        with db:
            db.execute(
                "INSERT INTO files VALUES(?,?,?,?,?,'preparing')",
                (
                    identifier,
                    str(path),
                    str(destination),
                    target["sha256"],
                    stat.S_IMODE(info.st_mode),
                ),
            )
        _move(path, destination, target["sha256"])
        try:
            if os.name != "nt":
                destination.chmod(0o600)
            with db:
                db.execute(
                    "UPDATE files SET state='quarantined' WHERE id=?", (identifier,)
                )
        except Exception:
            _uncertain(
                "File moved but durable quarantine completion is unconfirmed",
                {"quarantine_id": identifier, "sha256": target["sha256"]},
            )
        outcome = base._outcome(
            "quarantine_file",
            "quarantined",
            "Exact file moved out of its original name; reversible by this catalog, no permanent execution block",
            success=True,
            executed=True,
        )
        outcome["data"] = {
            "quarantine_id": identifier,
            "sha256": target["sha256"],
            "bytes": info.st_size,
        }
        return outcome
    finally:
        db.close()


def restore(target, settings):
    if settings.get("allow_restore") is not True:
        raise PermissionError("Restore is not locally enabled")
    _, db = _state(settings)
    try:
        row = db.execute(
            "SELECT * FROM files WHERE id=?", (target["quarantine_id"],)
        ).fetchone()
        if (
            not row
            or row["state"] not in {"quarantined", "preparing", "restoring"}
            or row["original"] != target["path"]
            or row["sha256"] != target["sha256"]
        ):
            raise PermissionError("Exact active quarantine receipt required")
        source = base._file_target(row["object"], settings)
        destination = source.parent / Path(row["original"]).name
        if str(destination) != row["original"] or destination.exists():
            raise PermissionError("Original path is occupied or differs")
        with db:
            db.execute("UPDATE files SET state='restoring' WHERE id=?", (row["id"],))
        _move(source, destination, row["sha256"])
        try:
            if os.name != "nt":
                destination.chmod(row["mode"])
            with db:
                db.execute("UPDATE files SET state='restored' WHERE id=?", (row["id"],))
        except Exception:
            raise base.EffectUnconfirmedError(
                "File restored but durable completion is unconfirmed"
            ) from None
        return base._outcome(
            "restore_file",
            "restored",
            "Exact quarantined object restored without overwriting an existing path",
            success=True,
            executed=True,
        )
    finally:
        db.close()


def _qualified_management_endpoints(definition):
    """Native IPv6 management needs NDP/PMTU qualification before isolation."""
    for endpoint in definition.get("endpoints", []):
        address = ipaddress.ip_address(endpoint["ip"])
        if address.version == 6 and not address.is_loopback:
            raise PermissionError(
                "Non-loopback IPv6 management isolation is unsupported until "
                "native NDP and PMTU preservation are qualified"
            )


def network_definition(settings, *, for_release=False):
    allowed = settings.get("management_allowlist", [])
    endpoints = settings.get("management_endpoints", [])
    if (
        not isinstance(allowed, list)
        or not 1 <= len(allowed) <= 16
        or not isinstance(endpoints, list)
        or not 1 <= len(endpoints) <= 8
    ):
        raise PermissionError(
            "Exact management allowlist and reachable endpoints required"
        )
    networks = sorted(
        {str(ipaddress.ip_network(value, strict=True)) for value in allowed}
    )
    parsed = [ipaddress.ip_network(value) for value in networks]
    if any(
        net.prefixlen < (24 if net.version == 4 else 64) or net.is_multicast
        for net in parsed
    ):
        raise PermissionError(
            "Management networks must be narrowly scoped unicast prefixes"
        )
    normalized = []
    for endpoint in endpoints:
        if (
            not isinstance(endpoint, dict)
            or set(endpoint) not in ({"ip", "port"}, {"ip", "port", "direction"})
            or type(endpoint["port"]) is not int
            or not 1 <= endpoint["port"] <= 65535
        ):
            raise ValueError("Management endpoints require literal IP and TCP port")
        ip = ipaddress.ip_address(endpoint["ip"])
        if endpoint.get("direction", "outbound") not in {"inbound", "outbound"}:
            raise ValueError(
                "Management endpoint direction must be inbound or outbound"
            )
        if not any(ip.version == net.version and ip in net for net in parsed):
            raise PermissionError("Management endpoint is outside allowlist")
        item = {"ip": str(ip), "port": endpoint["port"]}
        if "direction" in endpoint:
            item["direction"] = endpoint["direction"]
        normalized.append(item)
    result = {
        "allowlist": networks,
        "endpoints": sorted(
            normalized,
            key=lambda x: (x["ip"], x["port"], x.get("direction", "outbound")),
        ),
    }
    if not for_release:
        _qualified_management_endpoints(result)
    return result, hashlib.sha256(base.canonical(result).encode()).hexdigest()


def _remaining(deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("Network response deadline exceeded")
    return left


def _reachable(definition, deadline=None):
    deadline = deadline or time.monotonic() + 8
    for endpoint in definition["endpoints"]:
        # An inbound SSH allowlist is locally verified by the operator; opening
        # a new TCP connection to the remote client's SSH port is unrelated.
        if endpoint.get("direction", "outbound") == "inbound":
            continue
        with socket.create_connection(
            (endpoint["ip"], endpoint["port"]), timeout=min(1, _remaining(deadline))
        ):
            pass


def _run(args, *, payload=None, deadline=None, max_timeout=5):
    subprocess.run(
        args,
        input=payload.encode("utf-8") if isinstance(payload, str) else payload,
        capture_output=True,
        check=True,
        timeout=min(max_timeout, _remaining(deadline))
        if deadline is not None
        else max_timeout,
        shell=False,
    )


def _port_complement(ports):
    ranges, start = [], 0
    for port in sorted(set(ports)):
        if start < port:
            ranges.append(str(start) if start == port - 1 else f"{start}-{port - 1}")
        start = port + 1
    if start <= 65535:
        ranges.append(str(start) if start == 65535 else f"{start}-65535")
    return ",".join(ranges)


def _windows_rules(identifier, definition):
    _qualified_management_endpoints(definition)
    prefix = "Lumina-Isolation-" + identifier
    by_ip = {}
    for endpoint in definition.get("endpoints", []):
        address = ipaddress.ip_address(endpoint["ip"])
        if address.is_loopback:
            continue  # Local management IPC remains available on both systems.
        item = by_ip.setdefault(str(address), {"local": [], "remote": []})
        item[
            "local" if endpoint.get("direction", "outbound") == "inbound" else "remote"
        ].append(endpoint["port"])
    if len(by_ip) > 4:
        raise PermissionError(
            "Windows exact isolation supports at most four non-loopback management IPs"
        )
    remainder = [ipaddress.ip_network("0.0.0.0/0"), ipaddress.ip_network("::/0")]
    exceptions = [
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("::1/128"),
        *(ipaddress.ip_network(address) for address in by_ip),
    ]
    for exception in exceptions:
        remainder = [
            part
            for network in remainder
            for part in (
                network.address_exclude(exception)
                if exception.version == network.version and exception.subnet_of(network)
                else []
                if network.version == exception.version and network.subnet_of(exception)
                else [network]
            )
        ]
    # Native RemoteAddresses supports literal IPv4/IPv6 intervals. Merge
    # contiguous CIDR fragments to keep exact exclusions compact, including
    # IPv6 /128 endpoints that otherwise require hundreds of CIDR tokens.
    intervals = []
    for version in (4, 6):
        blocks = sorted(
            (int(net.network_address), int(net.broadcast_address))
            for net in remainder
            if net.version == version
        )
        merged = []
        for start, end in blocks:
            if merged and start <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
            else:
                merged.append((start, end))
        address_type = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
        intervals.extend(
            str(address_type(start))
            if start == end
            else str(address_type(start)) + "-" + str(address_type(end))
            for start, end in merged
        )
    if len(intervals) > 32:
        raise PermissionError("Management exclusions exceed firewall bound")
    remote = ",".join(intervals)
    expected = {}
    for direction, native in (("in", 1), ("out", 2)):
        expected[prefix + "-" + direction] = {
            "direction": native,
            "protocol": 256,
            "remote": remote,
        }
    # Non-TCP is denied at every management IP independent of its allowed TCP
    # ports. One exact-address union per protocol has the same coverage as
    # separate per-IP copies, with 512+2N total rules instead of 512N+2.
    if by_ip:
        management_ips = ",".join(sorted(by_ip))
        for direction, native in (("in", 1), ("out", 2)):
            for protocol in range(256):
                if protocol != 6:
                    expected[f"{prefix}-p{protocol}-{direction}"] = {
                        "direction": native,
                        "protocol": protocol,
                        "remote": management_ips,
                    }
    for number, (address, ports) in enumerate(sorted(by_ip.items())):
        for direction, native in (("in", 1), ("out", 2)):
            expected[f"{prefix}-m{number}-tcp-{direction}"] = {
                "direction": native,
                "protocol": 6,
                "remote": address,
                # Native rule conditions are conjunctive. Constraining both
                # complements lets an unrelated flow evade a block by using
                # a port approved for the opposite direction. Restrict only
                # the receiving service port for this direction; the peer's
                # source port cannot broaden the management exception.
                "localport": _port_complement(ports["local"])
                if direction == "in"
                else "0-65535",
                "remoteport": _port_complement(ports["remote"])
                if direction == "out"
                else "0-65535",
            }
    return expected


def _windows_release_names(identifier):
    if not isinstance(identifier, str) or not re.fullmatch(r"[0-9a-f]{32}", identifier):
        raise ValueError("Exact internal Windows isolation receipt required")
    prefix = "Lumina-Isolation-" + identifier
    names = [prefix + "-in", prefix + "-out"]
    names.extend(
        f"{prefix}-p{protocol}-{direction}"
        for protocol in range(256)
        if protocol != 6
        for direction in ("in", "out")
    )
    for number in range(4):
        for direction in ("in", "out"):
            names.append(f"{prefix}-m{number}-tcp-{direction}")
            names.extend(
                f"{prefix}-m{number}-p{protocol}-{direction}"
                for protocol in range(256)
                if protocol != 6
            )
    return names


def _windows_cancel_path(identifier, directory, *, release):
    """A permanent private tombstone prevents a late child from activating."""
    if directory is None:
        if release:
            return None  # Legacy recovery can only remove existing exact names.
        raise PermissionError(
            "A private prepared Windows isolation receipt is required"
        )
    directory = Path(directory)
    if not directory.is_absolute():
        raise PermissionError(
            "A private absolute isolation state directory is required"
        )
    base._no_links(directory)
    from . import cli

    cli._protected(directory, secret=True)
    if (directory / MARKER).read_text(encoding="utf-8") != MARKER_TEXT:
        raise PermissionError("Private isolation state marker is unavailable")
    marker = directory / (".isolation-cancel-" + identifier)
    if release:
        try:
            fd = os.open(
                marker,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                0o600,
            )
        except FileExistsError:
            base._no_links(marker)
            if not stat.S_ISREG(marker.stat().st_mode):
                raise PermissionError("Isolation cancellation tombstone is invalid")
        else:
            try:
                os.write(fd, b"cancelled\n")
                os.fsync(fd)
            finally:
                os.close(fd)
    elif marker.exists():
        raise PermissionError("This exact isolation receipt has already been cancelled")
    lock = directory / (".isolation-mutation-" + identifier + ".lock")
    try:
        fd = os.open(
            lock,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
    except FileExistsError:
        base._no_links(lock)
        info = lock.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise PermissionError("Private isolation mutation fence is invalid")
    else:
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise PermissionError("Private isolation mutation fence is invalid")
            os.fsync(fd)
        finally:
            os.close(fd)
    return str(marker)


def _windows_batch(
    identifier,
    expected,
    *,
    release=False,
    deadline=None,
    cancel_path=None,
    expires=None,
):
    """One fixed native COM process; data enters bounded UTF-8 stdin only."""
    from . import firewall_guard

    allowed = set(_windows_release_names(identifier))
    if not expected or len(expected) > 4096 or set(expected) - allowed:
        raise PermissionError("Only exact generated isolation rule names are accepted")
    prefix = "Lumina-Isolation-" + identifier
    # Broad blocks are last on apply and first on release, so rollback restores
    # unrelated traffic before removing the remaining management restrictions.
    ordered = sorted(
        expected,
        key=lambda name: (name in {prefix + "-in", prefix + "-out"}, name),
        reverse=release,
    )
    rules = []
    for name in ordered:
        item = {"name": name}
        if not release:
            rule = expected[name]
            fields = {"direction", "protocol", "remote"} | (
                {"localport", "remoteport"} if rule.get("protocol") == 6 else set()
            )
            if (
                set(rule) != fields
                or type(rule.get("direction")) is not int
                or rule["direction"] not in (1, 2)
                or type(rule.get("protocol")) is not int
                or not 0 <= rule["protocol"] <= 256
            ):
                raise PermissionError("Invalid fixed Windows firewall filter")
            if not isinstance(
                rule["remote"], str
            ) or not firewall_guard._windows_addresses(rule["remote"]):
                raise PermissionError("Literal IP addresses are required for isolation")
            if rule["protocol"] == 6:
                for key in ("localport", "remoteport"):
                    if not re.fullmatch(
                        r"\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*", rule[key]
                    ):
                        raise PermissionError("Exact numeric TCP port ranges required")
                    for part in rule[key].split(","):
                        bounds = [int(value) for value in part.split("-")]
                        if not 0 <= bounds[0] <= bounds[-1] <= 65535:
                            raise PermissionError("TCP port range is invalid")
            item.update(rule)
        rules.append(item)
    plan = {
        "identifier": identifier,
        "release": release,
        "rules": [] if release else rules,
        "cancel_path": cancel_path,
        "legacy_release": release and cancel_path is None,
        "mutation_wait_ms": int(1000 * min(8 if release else 2, _remaining(deadline)))
        if deadline is not None
        else 8000
        if release
        else 2000,
    }
    if not release:
        if (
            not isinstance(cancel_path, str)
            or not Path(cancel_path).is_absolute()
            or Path(cancel_path).name != ".isolation-cancel-" + identifier
            or type(expires) not in (int, float)
            or not time.time() < expires <= time.time() + 301
        ):
            raise PermissionError(
                "A live finite Windows isolation cancellation fence is required"
            )
        parent = base.inspect_process(os.getpid(), "isolation-apply")
        if not re.fullmatch(r"windows:\d+", parent["start_identity"]):
            raise PermissionError("Native Windows apply parent identity is unavailable")
        plan.update(
            expires=expires,
            parent_pid=os.getpid(),
            parent_birth=parent["start_identity"].split(":", 1)[1],
            apply_budget_ms=int(
                1000 * (min(8, _remaining(deadline)) if deadline is not None else 8)
            ),
        )
    payload = json.dumps(
        plan,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(payload) > 1024 * 1024:
        raise PermissionError("Owned Windows firewall batch exceeds bound")
    tool = firewall_guard.windows_tool()
    script = r"""$ErrorActionPreference='Stop'
[Console]::InputEncoding=New-Object Text.UTF8Encoding($false)
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$text=[Console]::In.ReadToEnd()
if($text.Length -gt 1048576){throw 'Owned firewall input exceeds bound'}
$plan=ConvertFrom-Json -InputObject $text
if($plan.identifier -notmatch '^[0-9a-f]{32}$' -or @($plan.rules).Count -gt 4096){throw 'Invalid owned rule identity'}
$group='Lumina-Isolation-'+$plan.identifier
$prefix=$group+'-'
$allowed=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
[void]$allowed.Add($prefix+'in');[void]$allowed.Add($prefix+'out')
foreach($p in 0..255){if($p -ne 6){foreach($d in @('in','out')){[void]$allowed.Add($prefix+'p'+$p+'-'+$d)}}}
foreach($n in 0..3){foreach($d in @('in','out')){[void]$allowed.Add($prefix+'m'+$n+'-tcp-'+$d);foreach($p in 0..255){if($p -ne 6){[void]$allowed.Add($prefix+'m'+$n+'-p'+$p+'-'+$d)}}}}
foreach($item in $plan.rules){if(-not $allowed.Contains([string]$item.name)){throw 'Foreign or unexpected rule name'}}
$mutation=$null;$parent=$null
try{
 if([int]$plan.mutation_wait_ms -lt 1 -or [int]$plan.mutation_wait_ms -gt 8000){throw 'Finite isolation mutation wait is required'}
 if($plan.cancel_path){
  if(-not [IO.Path]::IsPathRooted([string]$plan.cancel_path) -or [IO.Path]::GetFileName([string]$plan.cancel_path) -cne ('.isolation-cancel-'+$plan.identifier)){throw 'Private exact cancellation fence is required'}
  $mutationPath=[IO.Path]::Combine([IO.Path]::GetDirectoryName([string]$plan.cancel_path),('.isolation-mutation-'+$plan.identifier+'.lock'))
  $wait=[Diagnostics.Stopwatch]::StartNew()
  while(-not $mutation){
   $attributes=[IO.File]::GetAttributes($mutationPath)
   if(($attributes -band [IO.FileAttributes]::ReparsePoint) -or ($attributes -band [IO.FileAttributes]::Directory)){throw 'Private mutation fence must be an ordinary file'}
   try{$mutation=[IO.File]::Open($mutationPath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)}catch [IO.IOException]{
    if($wait.Elapsed.TotalMilliseconds -ge [int]$plan.mutation_wait_ms){throw 'Owned isolation mutation fence is busy'}
    [Threading.Thread]::Sleep(25)
   }
  }
 }elseif(-not ([bool]$plan.release -and [bool]$plan.legacy_release)){throw 'Private mutation fence is required for active receipt'}
 $clock=[Diagnostics.Stopwatch]::StartNew()
 if(-not [bool]$plan.release){
  if(-not $plan.cancel_path -or [IO.Path]::GetFileName([string]$plan.cancel_path) -cne ('.isolation-cancel-'+$plan.identifier)){throw 'Private cancellation fence is required'}
  if([double]$plan.expires -le 0 -or [int]$plan.apply_budget_ms -lt 1 -or [int]$plan.apply_budget_ms -gt 8000){throw 'Finite apply lease is required'}
  $parent=[Diagnostics.Process]::GetProcessById([int]$plan.parent_pid)
  [void]$parent.Handle
  if($parent.StartTime.ToUniversalTime().ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture) -cne [string]$plan.parent_birth){throw 'Apply parent incarnation changed'}
 }
 function Assert-LiveApply {
  if([IO.File]::Exists([string]$plan.cancel_path) -or $parent.HasExited -or ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()/1000.0) -ge [double]$plan.expires -or $clock.Elapsed.TotalMilliseconds -ge [int]$plan.apply_budget_ms){throw 'Isolation apply was cancelled or its finite lease ended'}
 }
 $policy=New-Object -ComObject HNetCfg.FwPolicy2
 $existing=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
 $ambiguous=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
 $allowedFold=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
 foreach($name in $allowed){[void]$allowedFold.Add($name)}
 $foreignGroup=$false;$groupCount=0
 foreach($rule in $policy.Rules){
  $name=[string]$rule.Name
  if($allowedFold.Contains($name)){
   if(-not $allowed.Contains($name) -or -not $ambiguous.Add($name)){throw 'Ambiguous case variant or duplicate owned name'}
   if([bool]$plan.release -and [bool]$plan.legacy_release -and [string]$rule.Grouping -cne ''){throw 'A current grouped receipt requires its private cancellation fence'}
   if([string]$rule.Grouping -cne $group -and -not ([bool]$plan.release -and [bool]$plan.legacy_release -and [string]$rule.Grouping -ceq '' -and [string]$rule.Description -ceq 'Vatex LUMINA xSERA finite owned host isolation')){throw 'Canonical rule name has foreign group or unproven legacy provenance'}
  }
  if($name.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -and -not [bool]$plan.release){throw 'Owned receipt already has rules; reconcile first'}
  [void]$existing.Add($name)
  if(([string]$rule.Grouping).Equals($group,[StringComparison]::OrdinalIgnoreCase)){$groupCount++;if([string]$rule.Grouping -cne $group -or -not $allowed.Contains($name)){$foreignGroup=$true}}
 }
$affected=0
if($plan.release){
 if($groupCount -gt 0 -and -not $foreignGroup){[void]$policy.EnableRuleGroup(7,$group,$false)}
 $errors=0
 $remove=New-Object 'Collections.Generic.List[string]'
 foreach($d in @('in','out')){if($existing.Contains($prefix+$d)){[void]$remove.Add($prefix+$d)}}
 foreach($name in $existing){if($allowed.Contains($name) -and $name -ne ($prefix+'in') -and $name -ne ($prefix+'out')){[void]$remove.Add($name)}}
 foreach($name in $remove){try{$policy.Rules.Remove($name);$affected++}catch{$errors++}}
 if($errors){throw 'One or more exact owned rules could not be removed'}
}else{
 if($foreignGroup -or $groupCount -ne 0){throw 'A foreign same-group member prevents any apply'}
 Assert-LiveApply
 $staged=New-Object 'Collections.Generic.List[object]'
 $planned=New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal)
 foreach($item in $plan.rules){
  Assert-LiveApply
  $rule=New-Object -ComObject HNetCfg.FWRule
  $rule.Name=[string]$item.name;$rule.Description='Vatex LUMINA xSERA finite owned host isolation'
  $rule.Protocol=[int]$item.protocol;$rule.Direction=[int]$item.direction
  $rule.RemoteAddresses=[string]$item.remote;$rule.Profiles=7;$rule.Action=0;$rule.Enabled=$false;$rule.EdgeTraversal=$false;$rule.Grouping=$group
  if([int]$item.protocol -eq 6){$rule.LocalPorts=[string]$item.localport;$rule.RemotePorts=[string]$item.remoteport}
  [void]$staged.Add($rule)
  $planned.Add([string]$item.name,$rule)
 }
 foreach($rule in $staged){Assert-LiveApply;$policy.Rules.Add($rule);$affected++}
 $seen=New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
 $verified=0
 foreach($rule in $policy.Rules){
  if(([string]$rule.Grouping).Equals($group,[StringComparison]::OrdinalIgnoreCase)){
   $name=[string]$rule.Name
   if([string]$rule.Grouping -cne $group -or -not $planned.ContainsKey($name) -or -not $seen.Add($name)){throw 'Foreign or duplicate same-group member prevents activation'}
   $wanted=$planned[$name]
   if([bool]$rule.Enabled -or [int]$rule.Action -ne 0 -or [int]$rule.Profiles -notin @(7,2147483647) -or [int]$rule.Protocol -ne [int]$wanted.Protocol -or [int]$rule.Direction -ne [int]$wanted.Direction -or [string]$rule.RemoteAddresses -cne [string]$wanted.RemoteAddresses -or [bool]$rule.EdgeTraversal -or [string]$rule.ApplicationName -ne '' -or [string]$rule.ServiceName -ne '' -or [string]$rule.InterfaceTypes -notin @('','All')){throw 'Persisted disabled rule differs from exact staged filter'}
   if([int]$rule.Protocol -eq 6 -and ([string]$rule.LocalPorts -cne [string]$wanted.LocalPorts -or [string]$rule.RemotePorts -cne [string]$wanted.RemotePorts)){throw 'Persisted disabled TCP ports differ'}
   $verified++
  }
 }
 if($verified -ne $staged.Count){throw 'Disabled group membership is incomplete'}
 Assert-LiveApply
 [void]$policy.EnableRuleGroup(7,$group,$true)
 try{Assert-LiveApply}catch{[void]$policy.EnableRuleGroup(7,$group,$false);throw}
}
ConvertTo-Json -InputObject @{affected=$affected;release=[bool]$plan.release;identifier=[string]$plan.identifier} -Compress
}finally{
 if($parent){$parent.Dispose()}
 if($mutation){$mutation.Dispose()}
}
"""
    subprocess.run(
        [tool, "-NoProfile", "-NonInteractive", "-Command", script],
        input=payload,
        env=dict(os.environ, PSModulePath=str(Path(tool).parent / "Modules")),
        capture_output=True,
        check=True,
        timeout=min(12 if release else 8, _remaining(deadline))
        if deadline is not None
        else 12
        if release
        else 8,
        shell=False,
    )


def _driver(
    identifier,
    definition,
    release=False,
    deadline=None,
    *,
    state_directory=None,
    expires=None,
):
    """Only fixed OS tools; inputs are normalized networks and an internal UUID."""
    if not isinstance(identifier, str) or not re.fullmatch(r"[0-9a-f]{32}", identifier):
        raise ValueError("Internal firewall receipt identity is invalid")
    if not release:
        # Do not create cancellation/state files or access native tools before
        # rejecting unqualified management paths. Old receipts remain releasable.
        _qualified_management_endpoints(definition)
    if os.name == "nt":
        from . import firewall_guard

        cancel_path = _windows_cancel_path(identifier, state_directory, release=release)
        if not release:
            firewall_guard.verify()
        if release:
            _windows_batch(
                identifier,
                {name: {} for name in _windows_release_names(identifier)},
                release=True,
                deadline=deadline,
                cancel_path=cancel_path,
            )
            firewall_guard.verify_removed_windows(identifier, deadline=deadline)
            return
        expected = _windows_rules(identifier, definition)
        _windows_batch(
            identifier,
            expected,
            deadline=deadline,
            cancel_path=cancel_path,
            expires=expires,
        )
        firewall_guard.verify_owned_windows(identifier, expected)
        return
    from . import firewall_guard

    tool = firewall_guard.linux_tool()
    if not release:
        firewall_guard.verify_linux()
    # nft transaction is atomic. Existing tables are never flushed or modified.
    table = "lumina_" + identifier
    payload = (
        "delete table inet " + table + "\n"
        if release
        else "add table inet " + table + "\n"
    )
    if not release:
        for direction in ("input", "output"):
            # OUTPUT must run after conntrack (-200). Every management permit
            # binds the intended connection direction; a reused approved source
            # port must never exempt an unrelated new or established flow.
            payload += f"add chain inet {table} {direction} {{ type filter hook {direction} priority 0; policy drop; }}\n"
            payload += (
                f"add rule inet {table} {direction} iifname lo accept\n"
                if direction == "input"
                else f"add rule inet {table} {direction} oifname lo accept\n"
            )
            for endpoint in definition["endpoints"]:
                family = (
                    "ip" if ipaddress.ip_address(endpoint["ip"]).version == 4 else "ip6"
                )
                address = "saddr" if direction == "input" else "daddr"
                inbound = endpoint.get("direction", "outbound") == "inbound"
                original = (direction == "input") == inbound
                port = "dport" if original else "sport"
                tracked = (
                    "ct direction original ct state { new, established }"
                    if original
                    else "ct direction reply ct state established"
                )
                payload += f"add rule inet {table} {direction} {family} {address} {endpoint['ip']} tcp {port} {endpoint['port']} {tracked} counter accept\n"
    _run([tool, "-f", "-"], payload=payload, deadline=deadline)
    if not release:
        firewall_guard.verify_linux(identifier)


def _isolation_lease(settings, *, windows=False):
    duration = settings.get("isolation_max_seconds", 300)
    maximum = 300 if windows else 3600
    if type(duration) is not int or not 30 <= duration <= maximum:
        raise ValueError(
            "Isolation safety lease must be 30.." + str(maximum) + " seconds"
        )
    return duration


def _guard_matches(pid, directory, identifier, start_identity=None):
    if type(pid) is not int or pid <= 4:
        return False
    if start_identity:
        try:
            actual = base.inspect_process(pid, "isolation-guard")
            if actual["start_identity"] != start_identity:
                return False
            if platform.system() == "Windows":
                return os.path.normcase(actual["executable"]) == os.path.normcase(
                    getattr(sys, "_base_executable", sys.executable)
                )
        except (OSError, ValueError):
            return False
    elif platform.system() == "Windows":
        return False
    try:
        args = Path("/proc/" + str(pid) + "/cmdline").read_bytes().split(b"\0")
        expected = [
            str(Path(__file__).parent / "Linux/isolation_watchdog.py"),
            "--state-dir",
            str(directory),
            "--isolation-id",
            identifier,
        ]
        encoded = [value.encode() for value in expected]
        return any(
            args[index : index + len(encoded)] == encoded for index in range(len(args))
        )
    except OSError:
        return False


def _arm_watchdog(directory, identifier):
    """A separate session survives agent exit; handshake precedes nft effects."""
    path = Path(__file__).parent / "Linux/isolation_watchdog.py"
    base._no_links(path)
    for item in (path, path.parent, path.parent.parent):
        info = item.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError(
                "Isolation watchdog code must be protected and root-owned"
            )
    process = subprocess.Popen(
        [
            sys.executable,
            "-I",
            "-B",
            str(path),
            "--state-dir",
            str(directory),
            "--isolation-id",
            identifier,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )
    try:
        ready, _, _ = select.select([process.stdout], [], [], 3)
        message = os.read(process.stdout.fileno(), 2048) if ready else b""
        value = json.loads(message)
        if value != {"isolation_id": identifier, "ready": True, "pid": process.pid}:
            raise PermissionError("Isolation watchdog readiness is unverifiable")
        return process.pid
    except Exception:
        process.terminate()
        process.wait(timeout=3)
        raise PermissionError(
            "Isolation watchdog did not arm; no network effect is permitted"
        ) from None
    finally:
        process.stdout.close()


def _linux_table_exists(identifier):
    from . import firewall_guard

    tool = firewall_guard.linux_tool()
    result = subprocess.run(
        [tool, "-j", "list", "tables"],
        capture_output=True,
        text=True,
        check=True,
        timeout=3,
        shell=False,
    )
    if len(result.stdout) > 1024 * 1024:
        raise PermissionError("Native firewall table inventory exceeds bound")
    state = json.loads(result.stdout)
    if not isinstance(state, dict) or not isinstance(state.get("nftables"), list):
        raise PermissionError("Native firewall table inventory is unverifiable")
    return any(
        isinstance(item, dict)
        and isinstance(item.get("table"), dict)
        and item["table"].get("family") == "inet"
        and item["table"].get("name") == "lumina_" + identifier
        for item in state.get("nftables", [])
    )


def _expire_isolation(db, row):
    identifier = row["id"]
    if not re.fullmatch(r"[0-9a-f]{32}", identifier):
        raise PermissionError("Durable isolation identity is invalid")
    if _linux_table_exists(identifier):
        _driver(identifier, {}, release=True, deadline=time.monotonic() + 8)
    if _linux_table_exists(identifier):
        raise OSError("Owned isolation table remained after safety release")
    with db:
        db.execute(
            "UPDATE isolation SET state='lease_expired',guard_pid=NULL WHERE id=?",
            (identifier,),
        )


def recover_linux_isolation(settings):
    """Restart reconciliation: expired/unguarded leases release only owned rules.

    The retained public name is compatible with the 0.10 agent lifecycle hook;
    Windows is also handled to avoid falsely reporting no active isolation.
    """
    native = platform.system()
    if native not in {"Linux", "Windows"} or not settings.get("quarantine_dir"):
        return []
    directory, db = _state(settings)
    recovered = []
    try:
        for row in db.execute(
            "SELECT * FROM isolation WHERE state IN ('preparing','isolated')"
        ).fetchall():
            expires = row["expires"]
            if type(expires) not in (
                int,
                float,
            ) or not time.time() < expires <= time.time() + (
                300 if native == "Windows" else 3600
            ):
                if native == "Windows":
                    _driver(
                        row["id"],
                        json.loads(row["definition"]),
                        release=True,
                        deadline=time.monotonic() + 12,
                        state_directory=directory,
                    )
                    with db:
                        db.execute(
                            "UPDATE isolation SET state='lease_expired',guard_pid=NULL WHERE id=?",
                            (row["id"],),
                        )
                else:
                    _expire_isolation(db, row)
                recovered.append({"isolation_id": row["id"], "state": "lease_expired"})
            elif not _guard_matches(
                row["guard_pid"], directory, row["id"], row["guard_start_identity"]
            ):
                if native == "Windows":
                    _driver(
                        row["id"],
                        json.loads(row["definition"]),
                        release=True,
                        deadline=time.monotonic() + 12,
                        state_directory=directory,
                    )
                    with db:
                        db.execute(
                            "UPDATE isolation SET state='lease_expired',guard_pid=NULL WHERE id=?",
                            (row["id"],),
                        )
                    recovered.append(
                        {"isolation_id": row["id"], "state": "lease_expired"}
                    )
                    continue
                # A dead guard lost the original monotonic lease. A rolled-back
                # wall clock must never create a fresh, longer isolation lease.
                _expire_isolation(db, row)
                recovered.append({"isolation_id": row["id"], "state": "lease_expired"})
        return recovered
    finally:
        db.close()


def isolation_status(settings):
    supported = platform.system() in {"Linux", "Windows"}
    if not supported or not settings.get("quarantine_dir"):
        return {"supported": supported, "state": "released", "active": []}
    directory, db = _state(settings)
    try:
        rows = db.execute(
            "SELECT * FROM isolation WHERE state IN ('preparing','isolated')"
        ).fetchall()
        active = [
            {
                "isolation_id": row["id"],
                "state": row["state"],
                "expires": row["expires"],
                "guard_alive": _guard_matches(
                    row["guard_pid"],
                    directory,
                    row["id"],
                    row["guard_start_identity"],
                ),
            }
            for row in rows
        ]
        degraded = any(
            row["state"] == "preparing"
            or not row["guard_alive"]
            or type(row["expires"]) not in (int, float)
            or row["expires"] <= time.time()
            for row in active
        )
        return {
            "supported": True,
            "state": "degraded" if degraded else "isolated" if active else "released",
            "active": active,
        }
    finally:
        db.close()


def isolate(target, settings):
    if settings.get("allow_host_isolation") is not True:
        raise PermissionError("Host isolation is not locally enabled")
    definition, digest = network_definition(
        settings, for_release=target["type"] == "release_host"
    )
    if target["management_allowlist_digest"] != digest:
        raise PermissionError("Approved management configuration changed")
    probe = settings.get("_management_probe")
    if not callable(probe):
        raise PermissionError("An authenticated agent management probe is required")
    directory, db = _state(settings)
    deadline = time.monotonic() + 20
    identifier = uuid.uuid4().hex
    native_linux = platform.system() == "Linux"
    native_windows = platform.system() == "Windows"
    native_arguments = {"state_directory": directory} if native_windows else {}
    lease_seconds = _isolation_lease(settings, windows=native_windows)
    try:
        if target["type"] == "release_host":
            identifier = target["isolation_id"]
            row = db.execute(
                "SELECT * FROM isolation WHERE id=?", (identifier,)
            ).fetchone()
            if (
                not row
                or row["state"] not in {"isolated", "preparing"}
                or row["digest"] != digest
            ):
                raise PermissionError("Exact active isolation receipt required")
            try:
                _driver(
                    identifier,
                    definition,
                    release=True,
                    deadline=deadline,
                    **native_arguments,
                )
                _reachable(definition, deadline)
                _remaining(deadline)
                probe()
                _remaining(deadline)
                with db:
                    db.execute(
                        "UPDATE isolation SET state='released' WHERE id=?",
                        (identifier,),
                    )
            except Exception:
                _uncertain(
                    "Owned isolation rules were removed but management restoration could not be verified",
                    {"isolation_id": identifier, "management_allowlist_digest": digest},
                )
            return base._outcome(
                "release_host",
                "released",
                "Only this agent's exact isolation rules removed",
                success=True,
                executed=True,
            )
        if db.execute(
            "SELECT 1 FROM isolation WHERE state IN ('preparing','isolated') LIMIT 1"
        ).fetchone():
            raise PermissionError(
                "A prior isolation receipt requires operator reconciliation"
            )
        _reachable(definition, deadline)
        probe()
        if _remaining(deadline) < 10:
            raise TimeoutError("Insufficient isolation rollback reserve")
        expires = (
            time.time() + lease_seconds if native_linux or native_windows else None
        )
        with db:
            db.execute(
                "INSERT INTO isolation(id,digest,definition,state,expires) VALUES(?,?,?,'preparing',?)",
                (identifier, digest, base.canonical(definition), expires),
            )
        if native_linux or native_windows:
            try:
                if native_windows:
                    from .Windows.isolation_watchdog import arm

                    pid = arm(directory, identifier)
                else:
                    pid = _arm_watchdog(directory, identifier)
                start = base.inspect_process(pid, "isolation-guard")["start_identity"]
                with db:
                    db.execute(
                        "UPDATE isolation SET guard_start_identity=? WHERE id=?",
                        (start, identifier),
                    )
            except Exception:
                with db:
                    db.execute(
                        "UPDATE isolation SET state='not_applied' WHERE id=?",
                        (identifier,),
                    )
                raise
        try:
            _driver(
                identifier,
                definition,
                deadline=deadline - 8,
                **native_arguments,
                **({"expires": expires} if native_windows else {}),
            )
            _reachable(definition, deadline - 8)
            _remaining(deadline - 8)
            probe()
            _remaining(deadline - 8)
            if native_linux:
                from . import firewall_guard

                firewall_guard.verify_linux(identifier)
        except Exception:
            try:
                _driver(
                    identifier,
                    definition,
                    release=True,
                    deadline=deadline,
                    **native_arguments,
                )
                _reachable(definition, deadline)
                _remaining(deadline)
                probe()
                _remaining(deadline)
                with db:
                    db.execute(
                        "UPDATE isolation SET state='rolled_back' WHERE id=? AND state IN ('preparing','isolated')",
                        (identifier,),
                    )
            except Exception:
                _uncertain(
                    "Isolation application/management check failed and rollback is unconfirmed",
                    {"isolation_id": identifier, "management_allowlist_digest": digest},
                )
            return base._outcome(
                "isolate_host",
                "rolled_back",
                "Management verification failed; owned rules removed and connectivity rechecked",
            )
        try:
            if native_linux or native_windows:
                receipt = db.execute(
                    "SELECT * FROM isolation WHERE id=?", (identifier,)
                ).fetchone()
                if not receipt or not _guard_matches(
                    receipt["guard_pid"],
                    directory,
                    identifier,
                    receipt["guard_start_identity"],
                ):
                    raise PermissionError(
                        "Isolation safety guard ended before durable confirmation"
                    )
            with db:
                changed = db.execute(
                    "UPDATE isolation SET state='isolated' WHERE id=? AND state='preparing' AND expires>?"
                    if native_linux or native_windows
                    else "UPDATE isolation SET state='isolated' WHERE id=? AND state='preparing'",
                    (identifier, time.time())
                    if native_linux or native_windows
                    else (identifier,),
                ).rowcount
                if changed != 1:
                    raise PermissionError(
                        "Isolation finite receipt ended before confirmation"
                    )
        except Exception:
            try:
                _driver(
                    identifier,
                    definition,
                    release=True,
                    deadline=deadline,
                    **native_arguments,
                )
                rollback_confirmed = True
            except Exception:
                rollback_confirmed = (
                    False  # The independent guard retains recovery ownership.
                )
            _uncertain(
                "Isolation receipt or guard ended; owned rollback requested and durable effect is unconfirmed",
                {
                    "isolation_id": identifier,
                    "management_allowlist_digest": digest,
                    "rollback_confirmed": rollback_confirmed,
                },
            )
        outcome = base._outcome(
            "isolate_host",
            "isolated",
            "Owned network rules applied; exact management TCP endpoints remained reachable",
            success=True,
            executed=True,
        )
        outcome["data"] = {
            "isolation_id": identifier,
            "management_allowlist_digest": digest,
        }
        if native_linux or native_windows:
            outcome["data"]["expires"] = expires
            outcome["data"]["safety_lease_seconds"] = lease_seconds
        return outcome
    finally:
        db.close()
