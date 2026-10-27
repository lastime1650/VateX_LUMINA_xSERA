"""Native-policy plans/rollback safety; mocks never certify Windows kernel effect."""

import base64
import copy
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sapientia.endpoint_agent.Agent import response
from sapientia.endpoint_agent.Agent import windows_app_control as module
from sapientia.endpoint_agent.Agent import windows_app_control_watchdog as watchdog
from sapientia.endpoint_agent.Agent.defense import SCHEMA, canonical

ID = "{79C4D446-7F18-4A16-A3E5-921F83EBBD9B}"
NAME = "Vatex LUMINA xSERA " + ID
NOW = 1800000000


def pe_bytes():
    blob = bytearray(256)
    blob[:2] = b"MZ"
    blob[0x3C:0x40] = (128).to_bytes(4, "little")
    blob[128:132] = b"PE\0\0"
    blob[150:152] = (2).to_bytes(2, "little")
    return bytes(blob)


def policy_xml(path):
    path.write_text(
        f'''<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="{module.NAMESPACE}" PolicyType="Base Policy">
<PolicyID>{ID}</PolicyID><BasePolicyID>{ID}</BasePolicyID><Rules><Rule><Option>Enabled:UMCI</Option></Rule></Rules>
<FileRules><Allow ID="a1" FileName="*"/><Allow ID="a2" FileName="*"/><Deny ID="deny" Hash="{"a" * 64}" FriendlyName="owned hash"/></FileRules>
<Signers/><SigningScenarios>
<SigningScenario Value="131"><ProductSigners><FileRulesRef><FileRuleRef RuleID="a1"/><FileRuleRef RuleID="deny"/></FileRulesRef></ProductSigners></SigningScenario>
<SigningScenario Value="12"><ProductSigners><FileRulesRef><FileRuleRef RuleID="a2"/><FileRuleRef RuleID="deny"/></FileRulesRef></ProductSigners></SigningScenario>
</SigningScenarios><Settings><Setting Provider="PolicyInfo" Key="Information" ValueName="Name"><Value><String>AllowAll</String></Value></Setting></Settings></SiPolicy>''',
        encoding="utf-8",
    )


@pytest.fixture
def signed(tmp_path):
    root, state = tmp_path / "owned-targets", tmp_path / "state"
    root.mkdir(mode=0o700)
    state.mkdir(mode=0o700)
    source = root / "unique-owned-payload.exe"
    source.write_bytes(pe_bytes())
    # CI projection uses canonical NT paths; Linux fixture hosts map only the
    # local file source, leaving signature and XML verification unchanged.
    directories = [str(root)] if os.name == "nt" else ["C:\\owned-targets"]
    filename = (
        str(source)
        if os.name == "nt"
        else "C:\\owned-targets\\unique-owned-payload.exe"
    )
    key = Ed25519PrivateKey.generate()
    config = {
        "host": "fixture-windows",
        "tenant": "default",
        "agent_id": "fixture-agent",
        "index": "endpoint",
        "state_dir": str(state),
        "defense": {
            "public_key": key.public_key().public_bytes_raw().hex(),
            "bundle_file": str(tmp_path / "signed.json"),
        },
        "kernel_prevention": {
            "enabled": True,
            "directories": directories,
            "rule_ids": ["deny-owned"],
            "windows_lease_seconds": 60,
        },
    }
    doc = {
        "schema": SCHEMA,
        **{v: config[v] for v in ("host", "tenant", "agent_id", "index")},
        "revision": 1,
        "issued_at": NOW - 60,
        "expires_at": NOW + 3600,
        "rules": [
            {
                "id": "deny-owned",
                "enabled": True,
                "action": "terminate_process",
                "conditions": [
                    {
                        "field": "file.hash.sha256",
                        "op": "eq",
                        "value": hashlib.sha256(pe_bytes()).hexdigest(),
                        "ignore_case": False,
                    },
                    {
                        "field": "process.executable",
                        "op": "eq",
                        "value": filename,
                        "ignore_case": False,
                    },
                ],
            }
        ],
    }
    Path(config["defense"]["bundle_file"]).write_text(
        json.dumps({"document": doc, "signature": key.sign(canonical(doc)).hex()}),
        encoding="utf-8",
    )
    return config, doc, source


class FakeNative:
    native = False

    def __init__(self):
        self.entries, self.calls, self.audit = {}, [], True

    def inventory(self):
        return dict(self.entries)

    def generate(self, paths, xml, identifier, name):
        self.calls.append("generate")
        policy_xml(xml)
        module.prepare_xml(xml, identifier, name, audit=True)

    def compile(self, xml, cip, audit):
        self.calls.append("compile-audit" if audit else "compile-enforce")
        module.prepare_xml(
            xml, module.read_policy_id(xml), module.read_policy_name(xml), audit=audit
        )
        self.audit = audit
        cip.write_bytes(b"native-policy-fixture" * 4)

    def apply(self, cip):
        self.calls.append("apply-audit" if self.audit else "apply-enforce")
        xml = cip.parent / "policy.xml"
        identifier, name = module.read_policy_id(xml), module.read_policy_name(xml)
        self.entries[identifier.strip("{}").upper()] = {
            "PolicyID": identifier,
            "FriendlyName": name,
            "IsEnforced": True,
            "IsAuthorized": True,
            "PolicyOptions": sorted(
                module.OPTIONS | ({"Enabled:Audit Mode"} if self.audit else set())
            ),
        }

    def remove(self, identifier):
        self.calls.append("remove-own-id")
        self.entries.pop(identifier.strip("{}").upper(), None)
        return {"removed": True, "policy_id": identifier}


def controller(signed, monkeypatch):
    config, _doc, source = signed
    native = FakeNative()
    if os.name != "nt":
        original_copy = module.copy_approved_executable
        monkeypatch.setattr(
            module,
            "copy_approved_executable",
            lambda _source, *args: original_copy(source, *args),
        )
        monkeypatch.setattr(module.Path, "is_dir", lambda _self: True)
        original_links = response._no_links
        monkeypatch.setattr(
            response,
            "_no_links",
            lambda path: None if str(path).startswith("C:\\") else original_links(path),
        )
    adapter = module.WindowsAppControl(
        config, response, backend_factory=lambda: native, clock=lambda: NOW
    )

    def ready(lease):
        native.calls.append("watchdog-handshake")
        adapter.nonce = "a" * 64
        adapter.expires_monotonic = time.monotonic() + lease
        adapter.watchdog_process = SimpleNamespace(poll=lambda: None)

    monkeypatch.setattr(adapter, "_start_watchdog", ready)
    return adapter, native


def test_default_audit_handshake_before_apply_never_claims_enforcement(
    signed, monkeypatch
):
    adapter, native = controller(signed, monkeypatch)
    assert adapter.start() is True
    try:
        assert native.calls.index("watchdog-handshake") < native.calls.index(
            "apply-audit"
        )
        assert "apply-enforce" not in native.calls
        assert adapter.status()["mode"] == "audit"
        assert adapter.status()["kernel_permission_denial"] is False
        assert adapter.status()["scope"] == "global_equivalent_native_code_hash"
        assert adapter.drain_events() == []  # No invented kernel/3077 block evidence.
        assert (
            adapter.manifest["native_hash_algorithm"]
            == "Windows Authenticode/PE and page hashes"
        )
    finally:
        adapter.close()
    assert adapter.status()["rollback"]["removed"] is True
    assert adapter.status()["enabled"] is True and adapter.status()["state"] == "stopped"
    assert adapter.status()["kernel_permission_denial"] is False
    assert native.entries == {}


def test_explicit_enforce_stages_audit_before_enforcement_and_mock_not_native(
    signed, monkeypatch
):
    signed[0]["kernel_prevention"]["windows_mode"] = "enforce"
    adapter, native = controller(signed, monkeypatch)
    assert adapter.start() is True
    try:
        assert native.calls.index("apply-audit") < native.calls.index("apply-enforce")
        assert adapter.status()["mode"] == "enforce"
        assert adapter.status()["kernel_permission_denial"] is False
        assert adapter.status()["code_integrity_3077_qualified"] is False
    finally:
        adapter.close()


def test_watchdog_missing_does_not_apply_native_policy(signed, monkeypatch):
    adapter, native = controller(signed, monkeypatch)
    monkeypatch.setattr(
        adapter,
        "_start_watchdog",
        lambda _lease: (_ for _ in ()).throw(RuntimeError("no handshake")),
    )
    with pytest.raises(RuntimeError, match="no handshake"):
        adapter.start()
    assert not any(v.startswith("apply") for v in native.calls)
    assert native.entries == {}


def test_expired_lease_releases_only_own_policy(signed, monkeypatch):
    adapter, native = controller(signed, monkeypatch)
    other = "FFFFFFFF-1111-2222-3333-444444444444"
    native.entries[other] = {"PolicyID": other, "FriendlyName": "existing unrelated"}
    adapter.start()
    adapter.expires_monotonic = time.monotonic() - 1
    assert adapter.status()["state"] == "stopped"
    assert set(native.entries) == {other}
    assert adapter.status()["automatic_lease_renewal"] is False


def test_policy_id_collision_never_removes_existing_policy(signed, monkeypatch):
    adapter, native = controller(signed, monkeypatch)
    monkeypatch.setattr(module.uuid, "uuid4", lambda: ID.strip("{}"))
    native.entries[ID.strip("{}")] = {
        "PolicyID": ID,
        "FriendlyName": "unrelated policy",
    }
    with pytest.raises(RuntimeError, match="already exists"):
        adapter.start()
    assert "remove-own-id" not in native.calls
    assert ID.strip("{}") in native.entries


def test_failed_apply_rolls_back_and_cannot_report_active(signed, monkeypatch):
    adapter, native = controller(signed, monkeypatch)

    def fail(cip):
        native.calls.append("partial-apply")
        identifier = module.read_policy_id(cip.parent / "policy.xml")
        native.entries[identifier.strip("{}")] = {
            "PolicyID": identifier,
            "FriendlyName": module.read_policy_name(cip.parent / "policy.xml"),
            "IsEnforced": False,
        }
        raise OSError("native refresh failed")

    monkeypatch.setattr(native, "apply", fail)
    with pytest.raises(OSError, match="refresh"):
        adapter.start()
    assert native.entries == {} and adapter.status()["state"] == "degraded"


def test_simultaneous_lease_expiry_health_and_close_remove_own_policy_once(
    signed, monkeypatch
):
    adapter, native = controller(signed, monkeypatch)
    adapter.start()
    original = native.remove
    entered, release = threading.Event(), threading.Event()
    calls = []

    def slow(identifier):
        calls.append(identifier)
        entered.set()
        assert release.wait(2)
        return original(identifier)

    monkeypatch.setattr(native, "remove", slow)
    adapter.expires_monotonic = time.monotonic() - 1
    first = threading.Thread(target=adapter.status)
    first.start()
    assert entered.wait(1)
    readers = [threading.Thread(target=adapter.close) for _ in range(8)]
    for reader in readers:
        reader.start()
    try:
        assert adapter.status()["state"] == "closing"
        assert adapter.status()["kernel_permission_denial"] is False
    finally:
        release.set()
        first.join(2)
        for reader in readers:
            reader.join(2)
    assert calls == [adapter.identifier]
    assert native.entries == {} and adapter.rollback_result["removed"] is True
    with pytest.raises(RuntimeError, match="cannot be restarted"):
        adapter.start()


def test_native_remove_exception_reports_unknown_rollback_and_keeps_watchdog_release(
    signed, monkeypatch
):
    adapter, native = controller(signed, monkeypatch)
    adapter.start()
    monkeypatch.setattr(
        native,
        "remove",
        lambda _id: (_ for _ in ()).throw(OSError("native inventory unavailable")),
    )
    adapter.close()
    assert adapter.rollback_result["removed"] is False
    assert adapter.status()["state"] == "degraded"
    assert (adapter.lease_dir / "release.json").is_file()


def test_disabled_does_not_read_or_mutate_native_policies(tmp_path):
    adapter = module.WindowsAppControl(
        {"state_dir": str(tmp_path)},
        response,
        backend_factory=lambda: pytest.fail("disabled native call"),
    )
    assert adapter.start() is False and adapter.status()["state"] == "disabled"
    assert adapter.status()["enabled"] is False
    adapter.close()


@pytest.mark.parametrize("mode", ["off", "ENFORCE", None, True])
def test_invalid_mode_fails_closed(mode):
    with pytest.raises(ValueError):
        module.validate_settings(
            {
                "enabled": True,
                "directories": ["C:\\owned"],
                "rule_ids": ["r"],
                "windows_mode": mode,
            }
        )


@pytest.mark.parametrize("lease", [True, 29, 301, "60"])
def test_lease_bound_is_not_implicitly_widened(lease):
    with pytest.raises(ValueError):
        module.validate_settings(
            {
                "enabled": True,
                "directories": ["C:\\owned"],
                "rule_ids": ["r"],
                "windows_lease_seconds": lease,
            }
        )


@pytest.mark.parametrize(
    "path",
    ["C:\\owned\\..\\other", "\\\\host\\share", "relative", "C:/owned", "C:\\owned\\"],
)
def test_remote_or_noncanonical_source_directory_rejected(path):
    with pytest.raises(ValueError):
        module.validate_settings(
            {"enabled": True, "directories": [path], "rule_ids": ["r"]}
        )


def test_windows_exact_projection_rejects_behavioral_and_critical_targets(signed):
    config, doc, _source = signed
    assert module.project_rules(
        doc, config["kernel_prevention"]["directories"], {"deny-owned"}
    )
    for name in ("python.exe", "powershell.exe", "CiTool.exe", "payload.dll"):
        mutated = copy.deepcopy(doc)
        conditions = mutated["rules"][0]["conditions"]
        conditions[1]["value"] = (
            str(config["kernel_prevention"]["directories"][0]) + "\\" + name
        )
        with pytest.raises(PermissionError):
            module.project_rules(
                mutated, config["kernel_prevention"]["directories"], {"deny-owned"}
            )


def test_pe_staging_requires_exact_original_signed_bytes_and_ordinary_exe(tmp_path):
    source, stage = tmp_path / "owned.exe", tmp_path / "staged.exe"
    source.write_bytes(pe_bytes())
    digest = hashlib.sha256(pe_bytes()).hexdigest()
    result = module.copy_approved_executable(source, stage, digest, 1024, response)
    assert stage.read_bytes() == source.read_bytes() and result["flat_sha256"] == digest
    with pytest.raises(PermissionError, match="signed evidence"):
        module.copy_approved_executable(
            source, tmp_path / "wrong.exe", "0" * 64, 1024, response
        )
    source.write_bytes(b"not-a-pe" * 16)
    with pytest.raises(PermissionError, match="PE"):
        module.copy_approved_executable(
            source,
            tmp_path / "not-pe.exe",
            hashlib.sha256(source.read_bytes()).hexdigest(),
            1024,
            response,
        )


def test_policy_xml_preserves_allowall_and_only_user_mode_exact_hash_denies(tmp_path):
    path = tmp_path / "policy.xml"
    policy_xml(path)
    result = module.prepare_xml(path, ID, NAME, audit=True)
    tree = module._xml(path)
    assert result["native_deny_hashes"] == 1 and result["audit"] is True
    assert module.read_policy_id(path) == ID and module.read_policy_name(path) == NAME
    assert "Enabled:Audit Mode" in {
        row.text for row in tree.findall("ci:Rules/ci:Rule/ci:Option", module.NS)
    }
    kernel_refs = tree.findall(
        "ci:SigningScenarios/ci:SigningScenario[@Value='131']/ci:ProductSigners/ci:FileRulesRef/ci:FileRuleRef",
        module.NS,
    )
    assert {row.get("RuleID") for row in kernel_refs} == {"a1"}
    module.prepare_xml(path, ID, NAME, audit=False)
    assert "Enabled:Audit Mode" not in {
        row.text
        for row in module._xml(path).findall("ci:Rules/ci:Rule/ci:Option", module.NS)
    }


def test_native_merge_allowall_friendly_metadata_is_not_an_extra_allow_condition(tmp_path):
    path = tmp_path / "native-merged.xml"
    policy_xml(path)
    path.write_text(
        path.read_text(encoding="utf-8").replace('FileName="*"', 'FileName="*" FriendlyName=""'),
        encoding="utf-8",
    )
    result = module.prepare_xml(path, ID, NAME, audit=True)
    assert result["native_deny_hashes"] == 1
    allows = module._xml(path).findall("ci:FileRules/ci:Allow", module.NS)
    assert len(allows) == 2 and all(row.get("FileName") == "*" for row in allows)


@pytest.mark.parametrize(
    "mutation", ["allowall", "hash", "signer", "unreferenced", "doctype"]
)
def test_unsafe_xml_never_compiles_as_native_policy(tmp_path, mutation):
    path = tmp_path / "policy.xml"
    policy_xml(path)
    text = path.read_text(encoding="utf-8")
    if mutation == "allowall":
        text = text.replace('FileName="*"', 'FileName="only-some.exe"', 1)
    elif mutation == "hash":
        text = text.replace('Hash="' + "a" * 64 + '"', 'FilePath="C:\\*"')
    elif mutation == "signer":
        text = text.replace("<Signers/>", '<Signers><Signer ID="foreign"/></Signers>')
    elif mutation == "unreferenced":
        text = text.replace('<FileRuleRef RuleID="deny"/>', "")
    else:
        text = text.replace(
            "<SiPolicy", '<!DOCTYPE SiPolicy [<!ENTITY x "bad">]><SiPolicy', 1
        )
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError):
        module.prepare_xml(path, ID, NAME, audit=False)


def test_powershell_source_never_interpolates_paths_as_code():
    injected = "C:\\owned\\'; Remove-Item -Recurse C:\\; '.exe"
    encoded = module._command("[Console]::Write($j.file)", {"file": injected})
    source = base64.b64decode(encoded).decode("utf-16-le")
    assert injected not in source and "Remove-Item" not in source
    assert "ConvertFrom-Json" in source and source.endswith("[Console]::Write($j.file)")


def test_native_powershell_uses_windows_shipped_modules_without_policy_bypass(monkeypatch):
    inherited = "C:\\untrusted-ps7\\Modules"
    monkeypatch.setenv("PSModulePath", inherited)
    calls = []

    def child(arguments, **kwargs):
        calls.append((arguments, kwargs))
        return SimpleNamespace(returncode=0, stdout="ready", stderr="")

    monkeypatch.setattr(module.subprocess, "run", child)
    native = Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    assert module._run_ps(native, "[Console]::Write('ready')", {}) == "ready"
    arguments, options = calls[0]
    source = base64.b64decode(arguments[-1]).decode("utf-16-le")
    assert inherited not in options["env"]["PSModulePath"]
    assert options["env"]["PSModulePath"] == str(native.parent / "Modules")
    assert "$env:PSModulePath=Join-Path $PSHOME 'Modules'" in source
    assert "ExecutionPolicy" not in source and "-ExecutionPolicy" not in arguments
    assert module.os.environ["PSModulePath"] == inherited


def test_native_hash_planning_batches_exact_paths_before_guard_with_finite_deadline(
    monkeypatch, tmp_path
):
    native = module.NativeAppControl.__new__(module.NativeAppControl)
    native.powershell = Path("native-powershell.exe")
    native.citool = Path("native-citool.exe")
    native.template = tmp_path / "AllowAll.xml"
    native.template.write_bytes(b"approved shipped template")
    calls = []

    def planned(_powershell, script, parameters, timeout):
        calls.append((script, parameters, timeout))

    monkeypatch.setattr(module, "_run_ps", planned)
    monkeypatch.setattr(module, "reject_management_hashes", lambda *_args: None)
    monkeypatch.setattr(module, "prepare_xml", lambda *_args, **_kwargs: None)
    paths = [tmp_path / "one.exe", tmp_path / "two.exe"]
    native.generate(paths, tmp_path / "policy.xml", ID, NAME)
    assert len(calls) == 2
    assert calls[0][1]["files"] == [str(path) for path in paths]
    assert calls[0][1]["template"] != calls[1][1]["template"]
    for _script, parameters, _timeout in calls:
        assert Path(parameters["template"]) != native.template
        assert Path(parameters["template"]).read_bytes() == b"approved shipped template"
    for script, _parameters, timeout in calls:
        assert script.count("New-CIPolicyRule") == 1
        assert "-DriverFilePath $j.files" in script and "$rules +=" not in script
        assert "$rules=New-CIPolicyRule" in script and "$rules=@(" not in script
        assert timeout == 120


def test_renamed_management_native_hash_is_rejected_even_if_flat_hash_differs(tmp_path):
    denied, protected = tmp_path / "denied.xml", tmp_path / "protected.xml"
    policy_xml(denied)
    policy_xml(protected)
    text = protected.read_text(encoding="utf-8").replace(
        '<Deny ID="deny"', '<Allow ID="deny"'
    )
    protected.write_text(text, encoding="utf-8")
    with pytest.raises(PermissionError, match="management"):
        module.reject_management_hashes(denied, protected)
    protected.write_text(text.replace("a" * 64, "b" * 64), encoding="utf-8")
    module.reject_management_hashes(denied, protected)


def test_watchdog_rollback_fences_foreign_name_and_touches_no_policy_directory(
    monkeypatch,
):
    calls = []

    def foreign(_tool, arguments):
        calls.append(arguments)
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {"Policies": [{"PolicyID": ID, "FriendlyName": "Microsoft foreign"}]}
            ),
            stderr="",
        )

    monkeypatch.setattr(watchdog, "_run", foreign)
    result = watchdog.rollback("unused-native-tool", ID)
    assert result["removed"] is False
    assert all(arguments[0] == "--list-policies" for arguments in calls)


def test_watchdog_removes_only_verified_unique_own_id(monkeypatch):
    calls, present = [], [True]

    def native(_tool, arguments):
        calls.append(arguments)
        if arguments[0] == "--remove-policy":
            assert arguments[1] == ID
            present[0] = False
        own = [{"PolicyID": ID, "FriendlyName": NAME}] if present[0] else []
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "Policies": own
                    + [{"PolicyID": "foreign", "FriendlyName": "preserve"}]
                }
            ),
            stderr="",
        )

    monkeypatch.setattr(watchdog, "_run", native)
    result = watchdog.rollback("unused-native-tool", ID)
    assert result["removed"] is True
    assert sum(arguments[0] == "--remove-policy" for arguments in calls) == 1


@pytest.mark.parametrize("identifier", ["*", "../", "", ID + " -rp foreign"])
def test_watchdog_guid_cannot_be_a_command_or_wildcard(identifier):
    with pytest.raises(ValueError):
        watchdog.policy_guid(identifier)


def test_private_watchdog_plan_binds_directory_nonce_and_lease(tmp_path):
    directory = tmp_path / "appcontrol-lease-owned"
    directory.mkdir()
    path = directory / "plan.json"
    plan = {
        "schema": "vatex.appcontrol.lease.v1",
        "policy_id": ID,
        "nonce": "a" * 64,
        "lease_seconds": 60,
        "directory": str(directory),
    }
    path.write_text(json.dumps(plan), encoding="utf-8")
    actual, root = watchdog.load_plan(path)
    assert actual == plan and root == directory
    plan["directory"] = str(tmp_path)
    path.write_text(json.dumps(plan), encoding="utf-8")
    with pytest.raises(ValueError, match="binding"):
        watchdog.load_plan(path)


def test_watchdog_launcher_uses_base_python_for_exact_ready_pid(
    signed, monkeypatch, tmp_path
):
    config, _doc, _source = signed
    adapter = module.WindowsAppControl(config, response)
    adapter.identifier = ID
    adapter.lease_dir = tmp_path / "appcontrol-lease-owned"
    adapter.lease_dir.mkdir()
    base = r"C:\fixture-runtime\base-python.exe"
    monkeypatch.setattr(module.sys, "_base_executable", base)
    calls = []

    def process(arguments, **kwargs):
        calls.append((arguments, kwargs))
        plan = json.loads(Path(arguments[-1]).read_text(encoding="utf-8"))
        watchdog.atomic_json(
            adapter.lease_dir / "ready.json",
            {
                "schema": "vatex.appcontrol.watchdog.ready.v1",
                "pid": 9912,
                "nonce": plan["nonce"],
                "policy_id": plan["policy_id"],
                "lease_seconds": plan["lease_seconds"],
            },
        )
        return SimpleNamespace(pid=9912, poll=lambda: None)

    monkeypatch.setattr(module.subprocess, "Popen", process)
    adapter._start_watchdog(60)
    assert calls[0][0][0] == base
    assert calls[0][1]["shell"] is False and calls[0][1]["close_fds"] is True
    assert adapter.watchdog_process.pid == 9912


def test_actual_harmless_base_python_child_pid_matches_launcher():
    base = getattr(sys, "_base_executable", sys.executable)
    process = subprocess.Popen(
        [
            base,
            "-I",
            "-c",
            "import json,os; print(json.dumps(dict(pid=os.getpid())),flush=True)",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    output, error = process.communicate(timeout=5)
    assert process.returncode == 0, error
    assert json.loads(output)["pid"] == process.pid


def test_native_adapter_rejects_other_os_before_policy_mutation(monkeypatch):
    monkeypatch.setattr(module.platform, "system", lambda: "Linux")
    with pytest.raises(OSError, match="requires Windows"):
        module.NativeAppControl()
