# ruff: noqa: F811 -- Imported pytest fixtures are injected by argument name.
"""Typed native Linux contracts; OS effects are tested by the separate runner."""

import hashlib
import importlib
import json
import sqlite3
from types import SimpleNamespace

import pytest

from sapientia.endpoint_agent.Agent import firewall_guard, operations
from sapientia.endpoint_agent.Agent.Linux.collector import LinuxCollector
from tests.test_linux_collector_remediation import collector  # noqa: F401


def audit(serial, body):
    return (
        "type="
        + body.split(" ", 1)[0]
        + f" msg=audit(1700000000.123:{serial}): "
        + body.split(" ", 1)[1]
        + "\n"
    ).encode()


@pytest.mark.parametrize(
    "syscall,expected",
    [("59", "process_created"), ("87", "file_deleted"), ("42", "network_connection")],
)
def test_failed_native_syscall_never_claims_successful_effect(
    collector, syscall, expected
):
    collector.audit_log_path.write_bytes(
        audit(
            1,
            f'SYSCALL arch=c000003e syscall={syscall} success=no exit=-13 pid=123 comm="test" exe="/bin/test"',
        )
        + audit(1, "EOE complete=yes")
    )
    data = collector._audit_events("host")[0]["data"]
    assert data["event"]["outcome"] == "failure"
    assert data["event"]["action"] == expected + "_failed"
    assert data["audit"]["attempted_action"] == expected
    assert data["audit"]["process_identity"] == "audit-record-only"
    assert "start_identity" not in data["process"]


def test_multi_record_execve_arguments_and_split_parts_are_preserved(collector):
    collector.audit_log_path.write_bytes(
        audit(1, 'SYSCALL arch=c000003e syscall=59 success=yes pid=123 exe="/bin/test"')
        + audit(1, 'EXECVE argc=4 a0="/bin/test" a1="quoted-6162"')
        + audit(1, 'EXECVE a2=6162 a3_len=6 a3[0]="part"')
        + audit(1, 'EXECVE a3[1]="ed"')
        + audit(1, "EOE complete=yes")
    )
    data = collector._audit_events("host")[0]["data"]
    assert data["process"]["command_line"] == "/bin/test quoted-6162 ab parted"
    assert data["event"]["outcome"] == "success"


def test_audit_target_path_prefers_operation_and_resolves_cwd(collector):
    collector.audit_log_path.write_bytes(
        audit(1, 'SYSCALL arch=c000003e syscall=87 success=yes pid=123 exe="/bin/test"')
        + audit(1, 'CWD cwd="/opt/private"')
        + audit(1, 'PATH item=0 name="/opt/private" nametype=PARENT')
        + audit(1, "PATH item=1 name=7061796c6f61642e62696e nametype=DELETE")
        + audit(1, "EOE complete=yes")
    )
    assert (
        collector._audit_events("host")[0]["data"]["file"]["path"]
        == "/opt/private/payload.bin"
    )


@pytest.mark.parametrize(
    "encoded,ip,port",
    [
        ("020001BB0A0002020000000000000000", "10.0.2.2", 443),
        (
            "0A0001BB0000000020010DB800000000000000000000000100000000",
            "2001:db8::1",
            443,
        ),
    ],
)
def test_native_sockaddr_decodes_without_inventing_tcp(collector, encoded, ip, port):
    collector.audit_log_path.write_bytes(
        audit(1, 'SYSCALL arch=c000003e syscall=42 success=yes pid=123 exe="/bin/test"')
        + audit(1, "SOCKADDR saddr=" + encoded)
        + audit(1, "EOE complete=yes")
    )
    data = collector._audit_events("host")[0]["data"]
    assert data["destination"] == {"ip": ip, "port": port}
    assert data["network"]["transport"] == "unknown"
    assert "protocol" not in data["network"]


def test_quoted_hex_path_stays_literal():
    assert LinuxCollector._audit_text('name="6162"', "name") == "6162"
    assert LinuxCollector._audit_text("name=6162", "name") == "ab"


def test_native_audit_current_file_hash_is_bounded_and_inode_checked(tmp_path):
    path = tmp_path / "inert.bin"
    path.write_bytes(b"harmless-native-evidence")
    inode = path.stat().st_ino
    assert (
        LinuxCollector._audit_file_hash(str(path), "inode=" + str(inode))
        == hashlib.sha256(path.read_bytes()).hexdigest()
    )
    assert LinuxCollector._audit_file_hash(str(path), "inode=" + str(inode + 1)) is None
    path.write_bytes(b"0" * (1024 * 1024 + 1))
    assert (
        LinuxCollector._audit_file_hash(str(path), "inode=" + str(path.stat().st_ino))
        is None
    )


def test_audit_sensor_hash_reads_do_not_create_feedback_loop(collector):
    import os

    collector.audit_log_path.write_bytes(
        audit(
            1,
            f'SYSCALL arch=c000003e syscall=257 success=yes pid={os.getpid()} exe="/bin/python"',
        )
        + audit(1, "EOE complete=yes")
    )
    assert collector._audit_events("host") == []
    assert collector.provider_health()["auditd"]["self_records_filtered"] == 1
    assert collector.audit_offset == collector.audit_log_path.stat().st_size


def test_busy_native_audit_without_eoe_delivers_complete_file_records(
    collector, monkeypatch
):
    target, expected_hash = "/owned/owned.txt", "ab" * 32
    monkeypatch.setattr(collector, "_audit_file_hash", lambda *args: expected_hash)
    serial = (
        audit(
            1,
            'SYSCALL arch=c000003e syscall=257 success=yes pid=123 items=2 exe="/bin/test"',
        )
        + audit(1, 'CWD cwd="/"')
        + audit(1, 'PATH item=0 name="/owned" nametype=PARENT')
        + audit(
            1,
            'PATH item=1 name="' + target + '" nametype=CREATE inode=123',
        )
        + audit(1, "PROCTITLE proctitle=74657374")
    )
    collector.audit_log_path.write_bytes(
        serial + audit(2, 'USER_START pid=888 msg="active unrelated login"')
    )
    events = collector._audit_events("host")
    assert len(events) == 1
    assert events[0]["data"]["file"]["path"] == target
    assert events[0]["data"]["file"]["hash"]["sha256"] == expected_hash
    assert collector.audit_offset == collector.audit_log_path.stat().st_size


def test_busy_native_partial_path_and_exec_remain_replayable(collector):
    header = audit(
        1,
        'SYSCALL arch=c000003e syscall=59 success=yes pid=123 items=1 exe="/bin/test"',
    )
    first = (
        header
        + audit(1, 'EXECVE argc=2 a0="/bin/test"')
        + audit(1, "PROCTITLE proctitle=74657374")
    )
    collector.audit_log_path.write_bytes(
        first + audit(2, 'USER_AUTH pid=888 msg="busy"')
    )
    assert collector._audit_events("host") == []
    assert collector.audit_offset == 0
    with collector.audit_log_path.open("ab") as stream:
        stream.write(
            audit(1, 'PATH item=0 name="/owned/test" nametype=NORMAL')
            + audit(1, 'EXECVE a1="late"')
        )
    events = collector._audit_events("host")
    assert len(events) == 1
    assert events[0]["data"]["process"]["command_line"] == "/bin/test late"
    assert collector.audit_offset == collector.audit_log_path.stat().st_size


def test_same_mtime_but_changed_ctime_is_not_stable_current_file(monkeypatch, tmp_path):
    path = tmp_path / "inert.bin"
    path.write_bytes(b"harmless-content")
    original = operations.os.fstat
    calls = []

    def changed(descriptor):
        info = original(descriptor)
        values = {
            name: getattr(info, name)
            for name in (
                "st_dev",
                "st_ino",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
                "st_mode",
                "st_nlink",
            )
        }
        calls.append(True)
        if len(calls) % 2 == 0:
            values["st_ctime_ns"] += 1
        return SimpleNamespace(**values)

    monkeypatch.setattr(operations.os, "fstat", changed)
    assert (
        LinuxCollector._audit_file_hash(str(path), "inode=" + str(path.stat().st_ino))
        is None
    )
    with pytest.raises(PermissionError, match="changed"):
        operations._read(path, hashlib.sha256(path.read_bytes()).hexdigest())


def test_file_read_opens_nonblocking_before_regular_file_check(monkeypatch, tmp_path):
    path = tmp_path / "inert.bin"
    path.write_bytes(b"harmless")
    original = operations.os.open
    observed = []

    def safe_open(target, flags, *args, **kwargs):
        observed.append(flags)
        # Emulate the Linux O_NONBLOCK bit while the test runs on Windows.
        return original(target, flags & ~0x800, *args, **kwargs)

    monkeypatch.setattr(operations.os, "O_NONBLOCK", 0x800, raising=False)
    monkeypatch.setattr(operations.os, "open", safe_open)
    assert LinuxCollector._audit_file_hash(
        str(path), "inode=" + str(path.stat().st_ino)
    )
    operations._read(path, hashlib.sha256(path.read_bytes()).hexdigest())
    assert len(observed) == 2 and all(flags & 0x800 for flags in observed)


def test_linux_driver_exact_direction_ip_port_and_owned_transaction(monkeypatch):
    payloads, verified = [], []
    monkeypatch.setattr(operations, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(firewall_guard, "linux_tool", lambda: "/fixed/nft")
    monkeypatch.setattr(
        firewall_guard,
        "verify_linux",
        lambda identifier=None: verified.append(identifier),
    )
    monkeypatch.setattr(
        operations, "_run", lambda args, **kw: payloads.append((args, kw["payload"]))
    )
    definition = {
        "allowlist": ["192.0.2.0/24"],
        "endpoints": [
            {"ip": "192.0.2.1", "port": 8788},
            {"ip": "192.0.2.2", "port": 22, "direction": "inbound"},
        ],
    }
    identifier = "1" * 32
    operations._driver(identifier, definition)
    args, payload = payloads[0]
    assert args == ["/fixed/nft", "-f", "-"]
    assert "192.0.2.0/24" not in payload and "flush" not in payload
    assert (
        "output ip daddr 192.0.2.1 tcp dport 8788 ct direction original ct state { new, established } counter accept"
        in payload
    )
    assert (
        "input ip saddr 192.0.2.1 tcp sport 8788 ct direction reply ct state established counter accept"
        in payload
    )
    assert (
        "input ip saddr 192.0.2.2 tcp dport 22 ct direction original ct state { new, established } counter accept"
        in payload
    )
    assert (
        "output ip daddr 192.0.2.2 tcp sport 22 ct direction reply ct state established counter accept"
        in payload
    )
    assert payload.count("policy drop") == 2 and verified == [None, identifier]
    operations._driver(identifier, definition, release=True)
    assert payloads[1][1] == "delete table inet lumina_" + identifier + "\n"


@pytest.mark.parametrize("duration", [True, 0, 29, 3601, "300", None])
def test_safety_lease_rejects_unbounded_or_untyped_duration(duration):
    with pytest.raises(ValueError):
        operations._isolation_lease({"isolation_max_seconds": duration})


@pytest.mark.parametrize("duration", [30, 300, 3600])
def test_safety_lease_has_finite_local_bounds(duration):
    assert operations._isolation_lease({"isolation_max_seconds": duration}) == duration


def test_management_direction_must_be_explicit_typed_and_narrow():
    settings = {
        "management_allowlist": ["192.0.2.1/32"],
        "management_endpoints": [
            {"ip": "192.0.2.1", "port": 22, "direction": "inbound"}
        ],
    }
    definition, digest = operations.network_definition(settings)
    assert definition["endpoints"][0]["direction"] == "inbound" and len(digest) == 64
    settings["management_endpoints"][0]["direction"] = "either"
    with pytest.raises(ValueError):
        operations.network_definition(settings)


def test_windows_management_filters_exempt_only_exact_ip_tcp_ports():
    rules = operations._windows_rules(
        "4" * 32,
        {
            "allowlist": ["192.0.2.0/24"],
            "endpoints": [
                {"ip": "192.0.2.1", "port": 443},
                {"ip": "192.0.2.1", "port": 22, "direction": "inbound"},
            ],
        },
    )
    assert len(rules) == 514
    broad = rules["Lumina-Isolation-" + "4" * 32 + "-out"]
    networks = [
        __import__("ipaddress").ip_network(value)
        for value in firewall_guard._windows_addresses(broad["remote"])
    ]
    assert any(
        __import__("ipaddress").ip_address("192.0.2.2") in network
        for network in networks
        if network.version == 4
    )
    assert not any(
        __import__("ipaddress").ip_address("192.0.2.1") in network
        for network in networks
        if network.version == 4
    )
    tcp = rules["Lumina-Isolation-" + "4" * 32 + "-m0-tcp-out"]
    assert (
        tcp["protocol"] == 6
        and tcp["remoteport"] == "0-442,444-65535"
        and tcp["localport"] == "0-65535"
    )
    inbound = rules["Lumina-Isolation-" + "4" * 32 + "-m0-tcp-in"]
    assert inbound["localport"] == "0-21,23-65535"
    assert inbound["remoteport"] == "0-65535"
    assert {rule["protocol"] for name, rule in rules.items() if "-p" in name} == set(
        range(256)
    ) - {6}


def test_windows_union_compacts_non_tcp_without_losing_protocol_or_ip_coverage():
    addresses = ["192.0.2.1", "192.0.2.2", "198.51.100.1", "203.0.113.1"]
    rules = operations._windows_rules(
        "a" * 32, {"endpoints": [{"ip": address, "port": 443} for address in addresses]}
    )
    assert len(rules) == 520
    non_tcp = [rule for rule in rules.values() if rule["protocol"] not in (6, 256)]
    assert len(non_tcp) == 510
    for direction in (1, 2):
        assert {
            row["protocol"] for row in non_tcp if row["direction"] == direction
        } == set(range(256)) - {6}
    assert all(set(row["remote"].split(",")) == set(addresses) for row in non_tcp)
    assert len([row for row in rules.values() if row["protocol"] == 6]) == 8


def test_windows_com_uses_only_bounded_stdin_json_and_binary_pipes(
    monkeypatch, tmp_path
):
    called = []
    monkeypatch.setattr(
        firewall_guard, "windows_tool", lambda: "/native/powershell.exe"
    )
    monkeypatch.setattr(
        operations.subprocess, "run", lambda args, **kw: called.append((args, kw))
    )
    expected = operations._windows_rules(
        "b" * 32, {"endpoints": [{"ip": "192.0.2.1", "port": 443}]}
    )
    monkeypatch.setattr(
        operations.base,
        "inspect_process",
        lambda *args: {"start_identity": "windows:12345"},
    )
    operations._windows_batch(
        "b" * 32,
        expected,
        cancel_path=str(tmp_path / (".isolation-cancel-" + "b" * 32)),
        expires=operations.time.time() + 30,
    )
    args, options = called[0]
    payload = __import__("json").loads(options["input"])
    assert (
        isinstance(options["input"], bytes)
        and "text" not in options
        and "encoding" not in options
    )
    assert "LUMINA_FW" not in " ".join(options["env"])
    assert options["env"]["PSModulePath"].endswith("Modules")
    assert (
        args[0] == "/native/powershell.exe"
        and "ReadToEnd" in args[-1]
        and "HNetCfg.FWRule" in args[-1]
    )
    assert all(name not in " ".join(args) for name in expected)
    assert [row["name"] for row in payload["rules"]][-2:] == [
        "Lumina-Isolation-" + "b" * 32 + "-in",
        "Lumina-Isolation-" + "b" * 32 + "-out",
    ]
    names = operations._windows_release_names("b" * 32)
    operations._windows_batch("b" * 32, {name: {} for name in names}, release=True)
    released = __import__("json").loads(called[-1][1]["input"])
    assert released == {
        "identifier": "b" * 32,
        "release": True,
        "rules": [],
        "cancel_path": None,
        "legacy_release": True,
        "mutation_wait_ms": 8000,
    }
    assert len(called[-1][1]["input"]) < 180
    assert "Lumina-Isolation-" + "b" * 32 + "-m3-p255-out" in names
    assert len(set(names)) == len(names) == 2560
    assert called[-1][1]["timeout"] == 12 and called[0][1]["timeout"] == 8
    release_script = called[-1][0][-1]
    assert "$allowed.Contains($name)" in release_script
    assert release_script.index("foreach($d in @('in','out'))") < release_script.index(
        "foreach($name in $existing){if($allowed.Contains($name)"
    )


def test_windows_com_rejects_foreign_owned_names_before_subprocess(monkeypatch):
    monkeypatch.setattr(
        operations.subprocess,
        "run",
        lambda *args, **kw: pytest.fail("Foreign rule must never reach native COM"),
    )
    with pytest.raises(PermissionError):
        operations._windows_batch("b" * 32, {"foreign-rule": {}}, release=True)


def test_windows_cancel_tombstone_is_private_permanent_and_prevents_reapply(
    monkeypatch, tmp_path
):
    from sapientia.endpoint_agent.Agent import cli

    checked = []
    monkeypatch.setattr(
        cli, "_protected", lambda path, **kwargs: checked.append((path, kwargs))
    )
    (tmp_path / operations.MARKER).write_text(operations.MARKER_TEXT)
    identifier = "d" * 32
    path = operations._windows_cancel_path(identifier, tmp_path, release=True)
    assert __import__("pathlib").Path(path).read_bytes() == b"cancelled\n"
    assert operations._windows_cancel_path(identifier, tmp_path, release=True) == path
    with pytest.raises(PermissionError, match="cancelled"):
        operations._windows_cancel_path(identifier, tmp_path, release=False)
    assert checked and all(kwargs == {"secret": True} for _, kwargs in checked)
    assert operations._windows_cancel_path(identifier, None, release=True) is None
    with pytest.raises(PermissionError, match="prepared"):
        operations._windows_cancel_path(identifier, None, release=False)


@pytest.mark.parametrize("final_fault", ["lease_expired", "expires", "guard_dead"])
def test_isolation_final_confirmation_cannot_resurrect_an_expired_or_unguarded_receipt(
    monkeypatch, tmp_path, final_fault
):
    from sapientia.endpoint_agent.Agent.Windows import isolation_watchdog

    settings = {
        "allow_host_isolation": True,
        "management_allowlist": ["192.0.2.1/32"],
        "management_endpoints": [{"ip": "192.0.2.1", "port": 443}],
        "quarantine_dir": str(tmp_path),
        "_management_probe": lambda: None,
    }
    (tmp_path / operations.MARKER).write_text(operations.MARKER_TEXT)
    _definition, digest = operations.network_definition(settings)
    monkeypatch.setattr(operations.platform, "system", lambda: "Windows")
    monkeypatch.setattr(operations, "_reachable", lambda *args: None)
    monkeypatch.setattr(
        isolation_watchdog, "arm", lambda *args: __import__("os").getpid()
    )
    monkeypatch.setattr(
        operations, "_guard_matches", lambda *args: final_fault != "guard_dead"
    )
    calls = []

    def driver(identifier, _definition, *, release=False, **kwargs):
        calls.append((release, kwargs))
        if not release and final_fault != "guard_dead":
            connection = sqlite3.connect(tmp_path / "effects.sqlite3")
            with connection:
                connection.execute(
                    "UPDATE isolation SET state='lease_expired' WHERE id=?"
                    if final_fault == "lease_expired"
                    else "UPDATE isolation SET expires=0 WHERE id=?",
                    (identifier,),
                )
            connection.close()

    monkeypatch.setattr(operations, "_driver", driver)
    with pytest.raises(
        operations.base.EffectUnconfirmedError, match="receipt or guard ended"
    ):
        operations.isolate(
            {"type": "isolate_host", "management_allowlist_digest": digest}, settings
        )
    assert [release for release, _kwargs in calls] == [False, True]
    assert all(kwargs["state_directory"] == tmp_path for _release, kwargs in calls)
    connection = sqlite3.connect(tmp_path / "effects.sqlite3")
    try:
        state = connection.execute("SELECT state FROM isolation").fetchone()[0]
        assert state == (
            "lease_expired" if final_fault == "lease_expired" else "preparing"
        )
    finally:
        connection.close()


def _fake_com_script(
    monkeypatch,
    tmp_path,
    scenario,
    release,
    *,
    prepare=False,
    shared=False,
    hold_ms=1500,
):
    """Execute the product's fixed PS guards against fake COM, never the firewall."""
    import os
    import subprocess

    if os.name != "nt":
        pytest.skip(
            "Actual PowerShell mutex/FILETIME script contract is Windows-specific"
        )
    native_run = subprocess.run
    tool = firewall_guard.windows_tool()
    calls = []
    identifier = "e" * 32
    group = "Lumina-Isolation-" + identifier
    marker = tmp_path / (".isolation-cancel-" + identifier)
    (tmp_path / (".isolation-mutation-" + identifier + ".lock")).touch(exist_ok=True)
    expected = operations._windows_rules(identifier, {"endpoints": []})
    with monkeypatch.context() as capture:
        capture.setattr(
            operations.subprocess,
            "run",
            lambda args, **kwargs: calls.append((args, kwargs)),
        )
        operations._windows_batch(
            identifier,
            expected,
            release=release,
            cancel_path=str(marker),
            expires=operations.time.time() + 30,
        )
    args, options = calls[0]
    initial = []
    own = {
        "Name": group + "-in",
        "Grouping": group,
        "Enabled": True,
        "Description": "Vatex LUMINA xSERA finite owned host isolation",
    }
    if scenario == "foreign_group":
        initial = [
            {
                "Name": "foreign-unrelated-name",
                "Grouping": group,
                "Enabled": True,
                "Description": "foreign",
            }
        ]
        if release:
            initial.append(own)
    elif scenario == "wrong_group":
        initial = [{**own, "Grouping": "foreign-group"}]
    elif scenario == "case_variant":
        initial = [{**own, "Name": own["Name"].upper()}]
    elif scenario == "duplicate":
        initial = [own, dict(own)]
    elif scenario == "cancelled":
        marker.write_text("cancelled\n")
    elif scenario != "valid":
        raise AssertionError("Unknown adversarial test scenario")
    setup = r"""
class LuminaFakeRules : Collections.IEnumerable {
 static [string]$StateFile=''
 static [string]$SignalFile=''
 static [bool]$PauseFirstAdd=$false
 static [int]$HoldMilliseconds=1500
 [Collections.Generic.List[object]]$Rows
 [Collections.Generic.List[string]]$Removed
 [int]$Adds=0
 LuminaFakeRules(){$this.Rows=[Collections.Generic.List[object]]::new();$this.Removed=[Collections.Generic.List[string]]::new()}
 [Collections.IEnumerator] GetEnumerator(){return $this.Rows.GetEnumerator()}
 [void] Save(){if([LuminaFakeRules]::StateFile){[IO.File]::WriteAllText([LuminaFakeRules]::StateFile,(ConvertTo-Json -InputObject $this.Rows.ToArray() -Depth 7 -Compress))}}
 [void] Add([object]$value){$this.Adds++;$this.Rows.Add($value);$this.Save();if([LuminaFakeRules]::PauseFirstAdd -and $this.Adds -eq 1){[IO.File]::WriteAllText([LuminaFakeRules]::SignalFile,'inside-mutex');[Threading.Thread]::Sleep([LuminaFakeRules]::HoldMilliseconds)}}
 [void] Remove([string]$name){$this.Removed.Add($name);for($n=$this.Rows.Count-1;$n -ge 0;$n--){if([string]$this.Rows[$n].Name -ceq $name){$this.Rows.RemoveAt($n)}};$this.Save()}
}
class LuminaFakePolicy {
 [LuminaFakeRules]$Rules
 [int]$Enables=0
 [int]$Disables=0
 LuminaFakePolicy(){$this.Rules=[LuminaFakeRules]::new()}
 [void] EnableRuleGroup([int]$profiles,[string]$group,[bool]$enable){if($enable){$this.Enables++}else{$this.Disables++};foreach($row in $this.Rules.Rows){if([string]$row.Grouping -ieq $group){$row.Enabled=$enable}}}
}
function New-FakeRule {return [pscustomobject]@{Name='';Description='';Protocol=256;Direction=0;RemoteAddresses='';Profiles=7;Action=0;Enabled=$false;EdgeTraversal=$false;Grouping='';LocalPorts='';RemotePorts='';ApplicationName='';ServiceName='';InterfaceTypes='All'}}
SHARED_SETUP
$fakeInitial=ConvertFrom-Json -InputObject INITIAL
function New-FakePolicy {
 $script:fakePolicy=[LuminaFakePolicy]::new()
 $rows=$fakeInitial
 if([LuminaFakeRules]::StateFile -and [IO.File]::Exists([LuminaFakeRules]::StateFile)){$rows=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText([LuminaFakeRules]::StateFile))}
 foreach($row in $rows){$script:fakePolicy.Rules.Rows.Add($row)}
 return $script:fakePolicy
}
$threw=$false;$reason=''
try{
""".replace("INITIAL", "'" + json.dumps(initial).replace("'", "''") + "'")
    shared_setup = ""
    if shared:
        shared_setup = (
            "[LuminaFakeRules]::StateFile='"
            + str(tmp_path / "fake-native-rule-state.json").replace("'", "''")
            + "';[LuminaFakeRules]::SignalFile='"
            + str(tmp_path / "inside-native-mutex").replace("'", "''")
            + "';[LuminaFakeRules]::PauseFirstAdd="
            + ("$false" if release else "$true")
            + ";[LuminaFakeRules]::HoldMilliseconds="
            + str(hold_ms)
        )
    setup = setup.replace("SHARED_SETUP", shared_setup)
    script = (
        args[-1]
        .replace(
            "$policy=New-Object -ComObject HNetCfg.FwPolicy2", "$policy=New-FakePolicy"
        )
        .replace("$rule=New-Object -ComObject HNetCfg.FWRule", "$rule=New-FakeRule")
    )
    script = script.replace(
        "ConvertTo-Json -InputObject @{affected=$affected;release=[bool]$plan.release;identifier=[string]$plan.identifier} -Compress",
        "$null=$affected",
    )
    assert "-ComObject" not in script
    finish = r"""
}catch{$threw=$true;$reason=$_.Exception.Message}
ConvertTo-Json -InputObject @{threw=$threw;reason=$reason;adds=$fakePolicy.Rules.Adds;enables=$fakePolicy.Enables;disables=$fakePolicy.Disables;removed=$fakePolicy.Rules.Removed.ToArray();remaining=$fakePolicy.Rules.Rows.ToArray()} -Depth 7 -Compress
"""
    invocation = [
        tool,
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        setup + script + finish,
    ]
    if prepare:
        return invocation, options
    result = native_run(
        invocation,
        input=options["input"],
        env=options["env"],
        capture_output=True,
        check=False,
        timeout=12,
        shell=False,
    )
    if result.returncode:
        raise RuntimeError(
            "Fake native script failed: "
            + result.stderr.decode("utf-8", errors="replace")[:1500]
        )
    return json.loads(result.stdout.decode("utf-8-sig"))


@pytest.mark.parametrize(
    "scenario",
    ["foreign_group", "wrong_group", "case_variant", "duplicate", "cancelled"],
)
def test_fixed_native_script_rejects_adversarial_group_apply_without_effects(
    monkeypatch, tmp_path, scenario
):
    proof = _fake_com_script(monkeypatch, tmp_path, scenario, release=False)
    assert (
        proof["threw"] and proof["adds"] == proof["enables"] == proof["disables"] == 0
    )
    assert proof["removed"] == []
    assert all(row["Enabled"] for row in proof["remaining"])


@pytest.mark.parametrize("scenario", ["wrong_group", "case_variant", "duplicate"])
def test_fixed_native_script_ambiguous_release_never_mutates_foreign_rules(
    monkeypatch, tmp_path, scenario
):
    proof = _fake_com_script(monkeypatch, tmp_path, scenario, release=True)
    assert (
        proof["threw"] and proof["adds"] == proof["enables"] == proof["disables"] == 0
    )
    assert proof["removed"] == [] and all(row["Enabled"] for row in proof["remaining"])


def test_fixed_native_script_same_group_foreign_release_removes_only_owned_member(
    monkeypatch, tmp_path
):
    proof = _fake_com_script(monkeypatch, tmp_path, "foreign_group", release=True)
    assert (
        proof["threw"] is False
        and proof["adds"] == proof["enables"] == proof["disables"] == 0
    )
    assert proof["removed"] == ["Lumina-Isolation-" + "e" * 32 + "-in"]
    assert (
        len(proof["remaining"]) == 1
        and proof["remaining"][0]["Name"] == "foreign-unrelated-name"
        and proof["remaining"][0]["Enabled"] is True
    )


def test_fixed_native_script_valid_group_stages_then_enables_once_under_native_mutex(
    monkeypatch, tmp_path
):
    proof = _fake_com_script(monkeypatch, tmp_path, "valid", release=False)
    assert (
        proof["threw"] is False
        and proof["adds"] == 2
        and proof["enables"] == 1
        and proof["disables"] == 0
    )
    assert proof["removed"] == [] and all(row["Enabled"] for row in proof["remaining"])


@pytest.mark.parametrize("hold_ms", [1500, 7600])
def test_independent_native_release_fence_waits_for_inflight_apply_and_prevents_late_activation(
    monkeypatch, tmp_path, hold_ms
):
    import subprocess
    import time

    apply_args, apply_options = _fake_com_script(
        monkeypatch,
        tmp_path,
        "valid",
        False,
        prepare=True,
        shared=True,
        hold_ms=hold_ms,
    )
    release_args, release_options = _fake_com_script(
        monkeypatch, tmp_path, "valid", True, prepare=True, shared=True
    )
    process = subprocess.Popen(
        apply_args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=apply_options["env"],
    )
    try:
        process.stdin.write(apply_options["input"])
        process.stdin.close()
        until = time.monotonic() + 8
        while not (tmp_path / "inside-native-mutex").exists():
            if process.poll() is not None or time.monotonic() >= until:
                pytest.fail("Fake native apply did not reach its held receipt mutex")
            time.sleep(0.01)
        (tmp_path / (".isolation-cancel-" + "e" * 32)).write_text("cancelled\n")
        started = time.monotonic()
        release = subprocess.run(
            release_args,
            input=release_options["input"],
            env=release_options["env"],
            capture_output=True,
            check=True,
            timeout=12,
            shell=False,
        )
        release_elapsed = time.monotonic() - started
        process.wait(timeout=12)
        assert process.returncode == 0, process.stderr.read().decode(errors="replace")
        applied = json.loads(process.stdout.read().decode("utf-8-sig"))
        released = json.loads(release.stdout.decode("utf-8-sig"))
        assert applied["threw"] and applied["enables"] == 0 and applied["adds"] == 1
        assert released["threw"] is False and released["remaining"] == []
        assert released["removed"] == ["Lumina-Isolation-" + "e" * 32 + "-in"]
        assert json.loads((tmp_path / "fake-native-rule-state.json").read_text()) == []
        assert (
            release_elapsed >= hold_ms / 1000 - 0.7
        )  # It waited behind the in-flight native process.
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)
        process.stdout.close()
        process.stderr.close()


def test_windows_native_inventory_decodes_explicit_utf8_without_locale(monkeypatch):
    import json

    observed = []
    monkeypatch.setattr(
        firewall_guard, "windows_tool", lambda: "/native/powershell.exe"
    )

    def run(args, **kwargs):
        observed.append(kwargs)
        return SimpleNamespace(
            stdout=json.dumps([{"name": "UTF8 진단"}], ensure_ascii=False).encode(
                "utf-8"
            )
        )

    monkeypatch.setattr(firewall_guard.subprocess, "run", run)
    assert firewall_guard._windows_owned("b" * 32) == [{"name": "UTF8 진단"}]
    assert "text" not in observed[0] and "encoding" not in observed[0]


def test_windows_removed_verification_shares_finite_deadline(monkeypatch):
    observed = []
    monkeypatch.setattr(
        firewall_guard, "windows_tool", lambda: "/native/powershell.exe"
    )
    monkeypatch.setattr(firewall_guard.time, "monotonic", lambda: 20)
    monkeypatch.setattr(
        firewall_guard.subprocess,
        "run",
        lambda args, **kw: observed.append(kw) or SimpleNamespace(stdout=b"[]"),
    )
    assert firewall_guard.verify_removed_windows("b" * 32, deadline=21)
    assert observed[0]["timeout"] == 1
    with pytest.raises(TimeoutError):
        firewall_guard.verify_removed_windows("b" * 32, deadline=20)
    assert len(observed) == 1


@pytest.mark.parametrize(
    "guard,expires,receipt_state,expected",
    [
        (True, 21, "isolated", "isolated"),
        (True, 21, "preparing", "degraded"),
        (False, 21, "isolated", "degraded"),
        (True, 19, "isolated", "degraded"),
        (True, None, "isolated", "degraded"),
    ],
)
def test_active_isolation_with_dead_or_expired_guard_never_reports_healthy(
    monkeypatch, tmp_path, guard, expires, receipt_state, expected
):
    row = {
        "id": "c" * 32,
        "state": receipt_state,
        "expires": expires,
        "guard_pid": 123,
        "guard_start_identity": "instance",
    }
    db = SimpleNamespace(
        execute=lambda *args: SimpleNamespace(fetchall=lambda: [row]),
        close=lambda: None,
    )
    monkeypatch.setattr(operations, "_state", lambda settings: (tmp_path, db))
    monkeypatch.setattr(operations, "_guard_matches", lambda *args: guard)
    monkeypatch.setattr(operations.platform, "system", lambda: "Windows")
    monkeypatch.setattr(operations.time, "time", lambda: 20)
    state = operations.isolation_status({"quarantine_dir": str(tmp_path)})
    assert state["state"] == expected and len(state["active"]) == 1


def test_native_tool_output_does_not_decode_through_windows_cp949():
    operations._run(
        [
            __import__("sys").executable,
            "-I",
            "-c",
            "import sys; sys.stdout.buffer.write(bytes([255,254,237,149,156])); sys.stderr.buffer.write(bytes([255,254]))",
        ]
    )


def test_windows_management_ip_capacity_rejects_before_os_effect():
    with pytest.raises(PermissionError, match="four"):
        operations._windows_rules(
            "4" * 32,
            {
                "endpoints": [
                    {"ip": "192.0.2." + str(number), "port": 443}
                    for number in range(1, 6)
                ]
            },
        )


@pytest.mark.parametrize(
    "fault",
    [
        "count",
        "enabled",
        "action",
        "protocol",
        "remote",
        "localport",
        "remoteport",
        "application",
        "profiles",
        "group",
    ],
)
def test_windows_native_com_filters_must_match_exact_expected_definition(
    monkeypatch, fault
):
    name = "Lumina-Isolation-" + "5" * 32 + "-tcp-out"
    expected = {
        name: {
            "direction": 2,
            "protocol": 6,
            "remote": "192.0.2.1",
            "localport": "0-21,23-65535",
            "remoteport": "0-442,444-65535",
        }
    }
    row = {
        "name": name,
        "group": "Lumina-Isolation-" + "5" * 32,
        "enabled": True,
        "action": 0,
        "direction": 2,
        "protocol": 6,
        "remote": "192.0.2.1/255.255.255.255",
        "localport": "0-21,23-65535",
        "remoteport": "0-442,444-65535",
        "profiles": 7,
        "application": "",
        "service": "",
        "interfaces": "All",
        "edge": False,
    }
    rows = [row]
    monkeypatch.setattr(
        firewall_guard, "_windows_owned", lambda identifier, **kwargs: rows
    )
    assert firewall_guard.verify_owned_windows("5" * 32, expected)[
        "exact_filters_verified"
    ]
    row["profiles"] = 2147483647
    assert firewall_guard.verify_owned_windows("5" * 32, expected)[
        "exact_filters_verified"
    ]
    if fault == "count":
        rows.clear()
    else:
        row[fault] = {
            "enabled": False,
            "action": 1,
            "protocol": 17,
            "remote": "192.0.2.0/24",
            "localport": "*",
            "remoteport": "*",
            "application": "foreign.exe",
            "profiles": 1,
            "group": "Foreign-Grouping",
        }[fault]
    with pytest.raises(PermissionError):
        firewall_guard.verify_owned_windows("5" * 32, expected)


@pytest.mark.parametrize(
    "fault",
    ["missing_hook", "wrong_policy", "wrong_priority", "wrong_table", "invalid_json"],
)
def test_native_nft_state_must_verify_both_owned_drop_hooks(monkeypatch, fault):
    identifier = "2" * 32
    chains = [
        {
            "chain": {
                "name": direction,
                "family": "inet",
                "table": "lumina_" + identifier,
                "type": "filter",
                "hook": direction,
                "policy": "drop",
                "prio": 0,
            }
        }
        for direction in ("input", "output")
    ]
    if fault == "missing_hook":
        chains.pop()
    elif fault == "wrong_policy":
        chains[0]["chain"]["policy"] = "accept"
    elif fault == "wrong_priority":
        chains[0]["chain"]["prio"] = -300
    elif fault == "wrong_table":
        chains[0]["chain"]["table"] = "foreign"
    monkeypatch.setattr(firewall_guard, "linux_tool", lambda: "/fixed/nft")
    monkeypatch.setattr(
        firewall_guard.subprocess,
        "run",
        lambda *args, **kw: SimpleNamespace(
            stdout="garbage"
            if fault == "invalid_json"
            else json.dumps({"nftables": chains})
        ),
    )
    with pytest.raises((PermissionError, ValueError)):
        firewall_guard.verify_linux(identifier)


def test_watchdog_arms_before_expiry_and_clock_rollback_cannot_extend(
    monkeypatch, capsys, tmp_path
):
    watchdog = importlib.import_module(
        "sapientia.endpoint_agent.Agent.Linux.isolation_watchdog"
    )
    db = sqlite3.connect(tmp_path / "guard.sqlite3")
    db.row_factory = sqlite3.Row
    db.execute(
        "CREATE TABLE isolation(id TEXT,state TEXT,expires REAL,guard_pid INTEGER)"
    )
    identifier = "3" * 32
    db.execute("INSERT INTO isolation VALUES(?,'isolated',101,NULL)", (identifier,))
    db.commit()
    monkeypatch.setattr(watchdog.platform, "system", lambda: "Linux")
    monkeypatch.setattr(watchdog.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(operations, "_state", lambda settings: (tmp_path, db))
    monkeypatch.setattr(watchdog.time, "time", lambda: 100)
    times = iter([0, 0, 0, 2])
    monkeypatch.setattr(watchdog.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(watchdog.time, "sleep", lambda seconds: None)
    expired = []
    monkeypatch.setattr(
        operations,
        "_expire_isolation",
        lambda connection, row: expired.append(row["id"]),
    )
    watchdog.watch(tmp_path, identifier)
    assert expired == [identifier]
    assert json.loads(capsys.readouterr().out)["ready"] is True


@pytest.mark.parametrize("table_exists", [False, True])
def test_dead_linux_guard_releases_immediately_without_rearming_a_rolled_back_wall_clock_lease(
    monkeypatch, tmp_path, table_exists
):
    (tmp_path / operations.MARKER).write_text(operations.MARKER_TEXT)
    settings = {"quarantine_dir": str(tmp_path)}
    _path, db = operations._state(settings)
    identifier = "f" * 32
    with db:
        db.execute(
            "INSERT INTO isolation(id,digest,definition,state,expires,guard_pid,guard_start_identity) VALUES(?,?,?,'isolated',1000,123,'old-guard')",
            (identifier, "a" * 64, "{}"),
        )
    db.close()
    monkeypatch.setattr(operations.platform, "system", lambda: "Linux")
    monkeypatch.setattr(operations.time, "time", lambda: 20)
    monkeypatch.setattr(operations, "_guard_matches", lambda *args: False)
    monkeypatch.setattr(
        operations,
        "_arm_watchdog",
        lambda *args: pytest.fail(
            "A lost monotonic guard must never be rearmed from the wall clock"
        ),
    )
    state = {"exists": table_exists}
    calls = []
    monkeypatch.setattr(
        operations, "_linux_table_exists", lambda value: state["exists"]
    )

    def release(value, definition, *, release=False, **kwargs):
        assert value == identifier and release is True
        calls.append(value)
        state["exists"] = False

    monkeypatch.setattr(operations, "_driver", release)
    result = operations.recover_linux_isolation(settings)
    assert result == [{"isolation_id": identifier, "state": "lease_expired"}]
    assert len(calls) == int(table_exists)
    db = sqlite3.connect(tmp_path / "effects.sqlite3")
    try:
        assert db.execute("SELECT state,guard_pid FROM isolation").fetchone() == (
            "lease_expired",
            None,
        )
    finally:
        db.close()


def test_bounded_v2_nonce_peer_preserves_same_connection_across_idle_and_rejects_wrong_nonce(
    tmp_path,
):
    import socket
    import subprocess
    import sys
    import time
    import uuid

    from tools.qualify_linux_xdr import NONCE_PROBE_SOURCE

    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    nonce = uuid.uuid4().hex
    (tmp_path / "nonce-probe-config.json").write_text(json.dumps({"nonce": nonce}))
    source = (
        NONCE_PROBE_SOURCE.replace("192.0.2.41", "127.0.0.1")
        .replace("192.0.2.42", "127.0.0.1")
        .replace("20200", str(port))
        .replace("time.monotonic()+180", "time.monotonic()+3")
    )
    path = tmp_path / "own-loopback-peer.py"
    path.write_text(source)
    process = subprocess.Popen(
        [sys.executable, "-I", "-B", str(path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    connection = None
    try:
        until = time.monotonic() + 2
        while connection is None:
            try:
                connection = socket.create_connection(("127.0.0.1", port), timeout=1)
            except OSError:
                if process.poll() is not None or time.monotonic() >= until:
                    pytest.fail("Bounded local v2 peer did not initialize")
                time.sleep(0.01)
        identity = (
            connection.fileno(),
            connection.getsockname(),
            connection.getpeername(),
        )
        sequences = []
        for number in range(2):
            sequence = uuid.uuid4().hex
            sequences.append(sequence)
            frame = (nonce + ":" + sequence + "\n").encode()
            connection.sendall(frame[:19])
            time.sleep(0.02)
            connection.sendall(frame[19:])
            received = bytearray()
            while len(received) < len(frame):
                part = connection.recv(128)
                assert part, "Sequence echo closed before the complete frame"
                received.extend(part)
            assert bytes(received) == frame
            assert identity == (
                connection.fileno(),
                connection.getsockname(),
                connection.getpeername(),
            )
            if number == 0:
                time.sleep(1.2)
        connection.sendall(("0" * 32 + ":" + uuid.uuid4().hex + "\n").encode())
        assert connection.recv(128) == b""
        connection.close()
        connection = None
        process.wait(timeout=4)
        assert process.returncode == 0, process.stderr.read().decode(errors="replace")
        receipts = [
            json.loads(line)
            for line in (tmp_path / "nonce-probe-receipts.jsonl")
            .read_text()
            .splitlines()
        ]
        requests = [row for row in receipts if row["kind"] == "request_received"]
        assert [row["sequence"] for row in requests] == sequences
        assert len({row["connection_id"] for row in requests}) == 1
        assert receipts[-1]["kind"] == "expired" and receipts[-1]["messages"] == 2
    finally:
        if connection is not None:
            connection.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)
        process.stderr.close()


def _process_fixture(collector, monkeypatch):
    collector.boot_time, collector.clock_ticks, collector.emit_initial = 0, 100, True
    monkeypatch.setattr(collector, "_tcp_rows", lambda *args: [])
    monkeypatch.setattr(collector, "_journal_events", lambda *args: [])
    monkeypatch.setattr(collector, "_audit_events", lambda *args: [])


def _process_snapshot(*rows, present=None):
    from sapientia.endpoint_agent.Agent.Linux.collector import _ProcessSnapshot

    result = _ProcessSnapshot()
    result.extend(rows)
    result.present_pids = (
        {row["pid"] for row in rows} if present is None else set(present)
    )
    return result


@pytest.mark.parametrize("parent_start", [50, 150])
def test_linux_parent_guid_never_binds_a_newer_reused_pid_incarnation(
    collector, monkeypatch, parent_start
):
    _process_fixture(collector, monkeypatch)
    parent = {
        "pid": 41,
        "ppid": 1,
        "start": parent_start,
        "name": "possible-parent",
        "command_line": "owned",
    }
    child = {
        "pid": 42,
        "ppid": 41,
        "start": 100,
        "name": "owned-child",
        "command_line": "owned",
    }
    monkeypatch.setattr(collector, "_rows", lambda: _process_snapshot(parent, child))
    rows = {
        event["data"]["process"]["pid"]: event["data"]["process"]
        for event in collector.collect("host")
    }
    assert rows[42]["parent"]["pid"] == 41
    if parent_start < 100:
        assert rows[42]["parent"]["guid"] == rows[41]["guid"]
    else:
        assert rows[42]["parent"]["guid"] is None and rows[42]["parent"]["name"] is None


def test_linux_present_but_unreadable_pid_never_invents_exit_or_duplicate_creation(
    collector, monkeypatch
):
    _process_fixture(collector, monkeypatch)
    row = {"pid": 42, "ppid": 1, "start": 100, "name": "owned", "command_line": "owned"}
    snapshots = iter(
        [
            _process_snapshot(row),
            _process_snapshot(present={42}),
            _process_snapshot(row),
            _process_snapshot(),
            _process_snapshot(),
        ]
    )
    monkeypatch.setattr(collector, "_rows", lambda: next(snapshots))
    created = collector.collect("host")
    assert len(created) == 1
    assert collector.collect("host") == []
    assert collector.provider_status["procfs"]["status"] == "degraded"
    assert collector.provider_status["procfs"]["present_identity_unavailable"] == 1
    assert collector.collect("host") == []
    assert collector.provider_status["procfs"]["status"] == "ok"
    terminated = collector.collect("host")
    assert (
        len(terminated) == 1
        and terminated[0]["data"]["event"]["action"] == "process_terminated"
    )
    assert (
        terminated[0]["data"]["process"]["guid"]
        == created[0]["data"]["process"]["guid"]
    )
    assert (
        terminated[0]["data"]["process"]["start_identity"]
        == created[0]["data"]["process"]["start_identity"]
    )
    assert collector.collect("host") == []


def test_linux_observed_pid_reuse_closes_only_the_old_process_incarnation(
    collector, monkeypatch
):
    _process_fixture(collector, monkeypatch)
    old = {"pid": 42, "ppid": 1, "start": 100, "name": "old", "command_line": "owned"}
    snapshots = iter(
        [
            _process_snapshot(old),
            _process_snapshot({**old, "start": 200, "name": "new"}),
        ]
    )
    monkeypatch.setattr(collector, "_rows", lambda: next(snapshots))
    first = collector.collect("host")[0]["data"]["process"]
    events = {
        event["data"]["event"]["action"]: event["data"]["process"]
        for event in collector.collect("host")
    }
    assert events["process_terminated"]["guid"] == first["guid"]
    assert events["process_created"]["guid"] != first["guid"]
    assert events["process_created"]["start_identity"].endswith(":200")


def test_linux_optional_exe_access_failure_still_rechecks_pid_birth(
    monkeypatch, tmp_path
):
    from pathlib import Path

    from sapientia.endpoint_agent.Agent.Linux import collector as module

    proc = tmp_path / "proc"
    target = proc / "42"
    target.mkdir(parents=True)

    def stat_line(start):
        return "42 (owned) " + " ".join(["S", "1", *["0"] * 17, str(start), "0", "0"])

    (target / "stat").write_text(stat_line(100))
    (target / "cmdline").write_bytes(b"owned\0")
    monkeypatch.setattr(
        module, "Path", lambda value: proc if value == "/proc" else Path(value)
    )

    def denied_exe(_path):
        (target / "stat").write_text(stat_line(200))
        raise PermissionError("Fixture optional exe access loss")

    monkeypatch.setattr(module.os, "readlink", denied_exe)
    snapshot = module.LinuxCollector.__new__(module.LinuxCollector)._rows()
    assert snapshot == [] and snapshot.present_pids == {42}
