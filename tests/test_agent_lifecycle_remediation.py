"""Installer policy and SCM fixtures, never installs or starts an OS service."""

import ctypes
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from sapientia.endpoint_agent.Agent.Windows import service


@pytest.mark.parametrize("fatal", [False, True])
def test_service_reports_nonzero_fatal_stop_for_scm_recovery(monkeypatch, fatal):
    states = []

    def register(*args):
        return 1

    def set_status(_handle, pointer):
        value = ctypes.cast(pointer, ctypes.POINTER(service.SERVICE_STATUS)).contents
        states.append(
            (
                value.dwCurrentState,
                value.dwWin32ExitCode,
                value.dwServiceSpecificExitCode,
            )
        )

    def dispatcher(entries):
        entries[0].lpServiceProc(0, None)
        return 1

    api = SimpleNamespace(
        RegisterServiceCtrlHandlerW=register,
        SetServiceStatus=set_status,
        StartServiceCtrlDispatcherW=dispatcher,
    )
    monkeypatch.setattr(service.ctypes, "WinDLL", lambda *a, **k: api)

    def run(*a, **k):
        if fatal:
            raise RuntimeError("fixture fatal startup")

    monkeypatch.setattr(service, "run_agent", run)
    service.serve({"state_dir": "fixture"}, lambda **kwargs: object())
    assert states[-1] == (
        service.SERVICE_STOPPED,
        1066 if fatal else 0,
        1 if fatal else 0,
    )


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("safe", "accepted"),
        ("write", "rejected"),
        ("owner", "rejected"),
        ("link", "rejected"),
        ("creator_owner_inherit", "accepted"),
        ("creator_owner_direct", "rejected"),
    ],
)
def test_actual_installer_acl_function_rejects_untrusted_runtime_fixture(
    tmp_path, mode, expected
):
    installer = Path(__file__).parents[1] / "sapientia/endpoint_agent/install.ps1"
    function = (
        installer.read_text(encoding="utf-8")
        .split("function Assert-ProtectedRuntimeEntry", 1)[1]
        .split("$runtimeRoot =", 1)[0]
    )
    function = "function Assert-ProtectedRuntimeEntry" + function
    script = tmp_path / "acl-fixture.ps1"
    script.write_text(
        """
$trustedRuntimeSids = @('S-1-5-18','S-1-5-32-544')
$fixtureOwnerSid = 'S-1-5-32-544'
$fixtureRights = [Security.AccessControl.FileSystemRights]::ReadAndExecute
$fixtureAttributes = [IO.FileAttributes]::Normal
$fixtureSid = 'S-1-5-32-545'
$fixturePropagation = [Security.AccessControl.PropagationFlags]::None
"""
        + (
            {
                "safe": "",
                "write": "$fixtureRights = [Security.AccessControl.FileSystemRights]::Modify\n",
                "owner": "$fixtureOwnerSid = 'S-1-5-32-545'\n",
                "link": "$fixtureAttributes = [IO.FileAttributes]::ReparsePoint\n",
                "creator_owner_inherit": "$fixtureSid = 'S-1-3-0'; $fixtureRights = [Security.AccessControl.FileSystemRights]::FullControl; $fixturePropagation = [Security.AccessControl.PropagationFlags]::InheritOnly\n",
                "creator_owner_direct": "$fixtureSid = 'S-1-3-0'; $fixtureRights = [Security.AccessControl.FileSystemRights]::FullControl\n",
            }[mode]
        )
        + """
function Get-Item { param($LiteralPath,[switch]$Force); return [pscustomobject]@{Attributes=$fixtureAttributes} }
function Get-Acl {
 param($LiteralPath)
 $acl = [pscustomobject]@{}
 $acl | Add-Member ScriptMethod GetOwner { param($type); return [pscustomobject]@{Value=$fixtureOwnerSid} }
 $acl | Add-Member ScriptMethod GetAccessRules { param($a,$b,$type); return @([pscustomobject]@{AccessControlType='Allow';FileSystemRights=$fixtureRights;IdentityReference=[pscustomobject]@{Value=$fixtureSid};PropagationFlags=$fixturePropagation}) }
 return $acl
}
"""
        + function
        + "\ntry { Assert-ProtectedRuntimeEntry 'fixture-runtime'; Write-Output 'accepted' } catch { Write-Output 'rejected' }\n",
        encoding="utf-8",
    )
    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32/WindowsPowerShell/v1.0/powershell.exe"
    )
    result = subprocess.run(
        [
            str(powershell),
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script.read_text(encoding="utf-8"),
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    assert result.stdout.strip() == expected


def test_installer_enables_noncrash_recovery_and_preserves_explicit_resume_contract():
    root = Path(__file__).parents[1] / "sapientia/endpoint_agent"
    windows = (root / "install.ps1").read_text(encoding="utf-8")
    linux = (root / "install.sh").read_text(encoding="utf-8")
    assert "failureflag VatexLuminaXseraAgent 1" in windows
    assert "[switch]$ResumeEnrollment" in windows
    assert "--resume-enrollment" in linux
    assert "Runtime reparse paths are forbidden" in windows
    assert "Python runtime path is writable by non-root" in linux
