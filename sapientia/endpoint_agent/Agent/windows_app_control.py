"""Locally opted-in, bounded native Windows App Control hash-deny policies.

Approved flat SHA256 evidence is verified before ConfigCI derives the Windows
Authenticode/page hashes. Those native deny hashes apply globally to equivalent
code, not only to the source directory. No xSERA kernel driver is claimed.
The default is audit; explicit enforce is protected by an independent rollback
watchdog for one newly generated policy ID. Existing policies are never edited.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import ntpath
import os
import platform
import re
import secrets
import stat
import subprocess
import sys
import threading
import time
from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

from . import kernel_prevention
from . import windows_app_control_watchdog as watchdog

NAMESPACE = "urn:schemas-microsoft-com:sipolicy"
NS = {"ci": NAMESPACE}
MAX_FILE = 64 * 1024 * 1024
MAX_WINDOWS_RULES = 16
CRITICAL_NAMES = {
    "python.exe",
    "pythonw.exe",
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "conhost.exe",
    "citool.exe",
    "lsass.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "smss.exe",
    "services.exe",
    "svchost.exe",
    "codex.exe",
}
OPTIONS = {
    "Enabled:UMCI",
    "Enabled:Unsigned System Integrity Policy",
    "Enabled:Update Policy No Reboot",
    "Disabled:Script Enforcement",
}


def validate_settings(settings):
    allowed = {
        "enabled",
        "directories",
        "rule_ids",
        "decision_timeout_ms",
        "max_file_bytes",
        "windows_mode",
        "windows_lease_seconds",
    }
    if (
        not isinstance(settings, dict)
        or set(settings) - allowed
        or settings.get("enabled") is not True
    ):
        raise ValueError(
            "Native App Control requires explicit local kernel prevention opt-in"
        )
    directories, ids = settings.get("directories"), settings.get("rule_ids")
    if (
        not isinstance(directories, list)
        or not 1 <= len(directories) <= 16
        or not all(isinstance(v, str) and len(v) <= 512 for v in directories)
    ):
        raise ValueError("1..16 explicitly selected local directories required")
    for value in directories:
        if (
            not ntpath.isabs(value)
            or value.startswith(("\\\\", "\\?", "\\."))
            or ntpath.normpath(value) != value
            or ".." in value.replace("/", "\\").split("\\")
            or len(ntpath.splitdrive(value)[0]) != 2
        ):
            raise ValueError("Canonical local drive directories required")
    if len({ntpath.normcase(v) for v in directories}) != len(directories):
        raise ValueError("Unique local directories required")
    if (
        not isinstance(ids, list)
        or not 1 <= len(ids) <= MAX_WINDOWS_RULES
        or not all(
            isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9._-]{1,120}", v)
            for v in ids
        )
        or len(set(ids)) != len(ids)
    ):
        raise ValueError("1..16 unique selected signed App Control rule IDs required")
    mode, lease = (
        settings.get("windows_mode", "audit"),
        settings.get("windows_lease_seconds", 60),
    )
    if mode not in {"audit", "enforce"}:
        raise ValueError("Windows kernel mode must be audit or enforce")
    if type(lease) is not int or not 30 <= lease <= 300:
        raise ValueError("Independent rollback lease must be 30..300 seconds")
    maximum = settings.get("max_file_bytes", MAX_FILE)
    if type(maximum) is not int or not 1 <= maximum <= MAX_FILE:
        raise ValueError("App Control file bound must be 1..64 MiB")
    return tuple(directories), frozenset(ids), mode, lease, maximum


def project_rules(document, directories, ids):
    selected, results = set(), {}
    allowed = {ntpath.normcase(v) for v in directories}
    for rule in document["rules"]:
        if rule["id"] not in ids:
            continue
        selected.add(rule["id"])
        conditions = rule["conditions"]
        if (
            rule.get("enabled") is not True
            or rule.get("action") != "terminate_process"
            or rule.get("exceptions")
            or len(conditions) != 2
            or {c["field"] for c in conditions}
            != {"file.hash.sha256", "process.executable"}
            or any(
                c["op"] != "eq" or c.get("ignore_case", True) is not False
                for c in conditions
            )
        ):
            raise ValueError(
                "App Control rule requires enabled exact path/hash rule without behavioral conditions or exceptions"
            )
        values = {c["field"]: c["value"] for c in conditions}
        filename, digest = values["process.executable"], values["file.hash.sha256"]
        if (
            not isinstance(filename, str)
            or not ntpath.isabs(filename)
            or ntpath.normpath(filename) != filename
            or ntpath.normcase(ntpath.dirname(filename)) not in allowed
            or len(filename) > 512
            or ":" in ntpath.splitdrive(filename)[1]
            or filename.startswith("\\\\")
        ):
            raise ValueError(
                "Approved executable must be an exact local immediate child of an opted-in directory"
            )
        if (
            ntpath.basename(filename).casefold() in CRITICAL_NAMES
            or ntpath.splitext(filename)[1].casefold() != ".exe"
        ):
            raise PermissionError(
                "System/management executables and non-EXE files cannot be denied by this adapter"
            )
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("Exact lowercase flat SHA256 evidence required")
        results.setdefault(filename, {})[digest] = {
            "id": rule["id"],
            "severity": rule.get("severity", "high"),
            "mitre": tuple(rule.get("mitre", [])),
        }
    if selected != ids:
        raise ValueError(
            "Every selected App Control rule must exist in the approved signed policy"
        )
    return results


def _command(script, parameters):
    # Data never becomes PowerShell source: a fixed script consumes base64 JSON.
    payload = base64.b64encode(
        json.dumps(parameters, ensure_ascii=False).encode("utf-8")
    ).decode("ascii")
    preamble = (
        "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "
        "$env:PSModulePath=Join-Path $PSHOME 'Modules'; "
        "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); "
        "$j=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"
        + payload
        + "')) | ConvertFrom-Json; "
    )
    return base64.b64encode((preamble + script).encode("utf-16-le")).decode("ascii")


def _run_ps(powershell, script, parameters, timeout=30):
    # PowerShell 7 -> Python -> Windows PowerShell otherwise inherits the PS7
    # module path. Native ConfigCI/security commands must load Windows-shipped
    # modules, never a user/third-party replacement. Do not change execution policy.
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.casefold() != "psmodulepath"
    }
    environment["PSModulePath"] = str(Path(powershell).parent / "Modules")
    process = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            _command(script, parameters),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        shell=False,
        env=environment,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if len(process.stdout) + len(process.stderr) > 2 * 1024 * 1024:
        raise RuntimeError("Native App Control tool output exceeded its bound")
    if process.returncode:
        raise RuntimeError("Native App Control tool failed: " + process.stderr[-1500:])
    return process.stdout


def _truth(value):
    return value is True or isinstance(value, str) and value.casefold() == "true"


class NativeAppControl:
    native = True

    def __init__(self):
        if platform.system() != "Windows" or os.name != "nt":
            raise OSError("Native App Control adapter requires Windows")
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise PermissionError(
                "App Control deployment requires a local administrator token"
            )
        self.citool = watchdog.system_citool()
        system = self.citool.parent
        self.powershell = system / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        self.template = (
            system.parent
            / "schemas"
            / "CodeIntegrity"
            / "ExamplePolicies"
            / "AllowAll.xml"
        )
        watchdog.no_links(self.powershell)
        watchdog.no_links(self.template)
        _run_ps(
            self.powershell,
            "$names=@('New-CIPolicyRule','Merge-CIPolicy','ConvertFrom-CIPolicy','Set-RuleOption'); foreach($name in $names) { Get-Command -Name $name -ErrorAction Stop | Out-Null }; [Console]::Write('ConfigCI ready')",
            {},
            timeout=15,
        )

    def inventory(self):
        process = watchdog._run(self.citool, ["--list-policies", "-json"])
        if process.returncode:
            raise OSError("Unable to read native App Control inventory")
        value = json.loads(process.stdout)
        policies = value.get("Policies")
        if not isinstance(policies, list):
            raise TypeError("Unexpected native App Control policy inventory")
        return {
            str(row.get("PolicyID", "")).strip("{}").upper(): row for row in policies
        }

    def generate(self, paths, xml, identifier, name):
        # Merge-CIPolicy opens its source policies for write; a shipped Windows
        # template is protected by TrustedInstaller. Give the native tool its
        # own ordinary bounded copy for each plan, never the system source.
        if not 1 <= self.template.stat().st_size <= 2 * 1024 * 1024:
            raise ValueError("Native AllowAll template exceeds its bound")
        source = self.template.read_bytes()
        if not 1 <= len(source) <= 2 * 1024 * 1024:
            raise ValueError("Native AllowAll template exceeds its bound")
        templates = [
            xml.with_name("deny-AllowAll.xml"),
            xml.with_name("management-AllowAll.xml"),
        ]
        for template in templates:
            with template.open("xb") as output:
                output.write(source)
        _run_ps(
            self.powershell,
            "foreach($file in $j.files) { $signature=Get-AuthenticodeSignature -LiteralPath $file; if($signature.SignerCertificate -and $signature.SignerCertificate.Subject -match 'Microsoft') { throw 'Microsoft code cannot be denied by xSERA local hash adapter' } }; $rules=New-CIPolicyRule -Level Hash -DriverFilePath $j.files -Deny; if($rules.Count -eq 0) { throw 'No native hash rules generated' }; Merge-CIPolicy -PolicyPaths $j.template -OutputFilePath $j.xml -Rules $rules | Out-Null; [Console]::Write('Native hash rules generated')",
            {
                "files": [str(v) for v in paths],
                "template": str(templates[0]),
                "xml": str(xml),
            },
            timeout=120,
        )
        # A renamed interpreter/management executable still shares its native
        # code hash. Flat hashes/names alone cannot protect the rollback path.
        protected_xml = xml.with_name("management-code-hashes.xml")
        _run_ps(
            self.powershell,
            "$rules=New-CIPolicyRule -Level Hash -DriverFilePath $j.files; if($rules.Count -eq 0) { throw 'No management code hashes generated' }; Merge-CIPolicy -PolicyPaths $j.template -OutputFilePath $j.xml -Rules $rules | Out-Null; [Console]::Write('Management code hashes generated')",
            {
                "files": list(
                    dict.fromkeys(
                        [
                            sys.executable,
                            getattr(sys, "_base_executable", sys.executable),
                            str(self.powershell),
                            str(self.citool),
                        ]
                    )
                ),
                "template": str(templates[1]),
                "xml": str(protected_xml),
            },
            timeout=120,
        )
        reject_management_hashes(xml, protected_xml)
        prepare_xml(xml, identifier, name, audit=True)

    def compile(self, xml, cip, audit):
        prepare_xml(xml, read_policy_id(xml), read_policy_name(xml), audit=audit)
        _run_ps(
            self.powershell,
            "ConvertFrom-CIPolicy -XmlFilePath $j.xml -BinaryFilePath $j.cip | Out-Null; [Console]::Write('Native policy compiled')",
            {"xml": str(xml), "cip": str(cip)},
        )
        if not cip.is_file() or not 32 <= cip.stat().st_size <= 2 * 1024 * 1024:
            raise RuntimeError(
                "Compiled native policy is missing or outside size bounds"
            )

    def apply(self, cip):
        process = watchdog._run(self.citool, ["--update-policy", str(cip), "-json"])
        if process.returncode:
            raise OSError(
                "Native App Control rejected the policy: " + process.stderr[-1000:]
            )
        process = watchdog._run(self.citool, ["--refresh", "-json"])
        if process.returncode:
            raise OSError("Native App Control refresh failed")

    def remove(self, identifier):
        return watchdog.rollback(self.citool, identifier)


def _xml(path):
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("Native policy XML exceeds its bound")
    blob = path.read_bytes()
    if b"<!DOCTYPE" in blob.upper() or b"<!ENTITY" in blob.upper():
        raise ValueError("DTD/entity native policies forbidden")
    try:
        tree = ET.ElementTree(SafeET.fromstring(blob, forbid_dtd=True, forbid_entities=True, forbid_external=True))
    except (ET.ParseError, DefusedXmlException, ValueError) as error:
        raise ValueError("Invalid or unsafe native policy XML") from error
    if tree.getroot().tag != "{" + NAMESPACE + "}SiPolicy":
        raise ValueError("Invalid native policy namespace")
    return tree


def read_policy_id(path):
    return _xml(path).findtext("ci:PolicyID", namespaces=NS)


def read_policy_name(path):
    return _xml(path).findtext(
        "ci:Settings/ci:Setting[@Provider='PolicyInfo'][@ValueName='Name']/ci:Value/ci:String",
        namespaces=NS,
    )


def reject_management_hashes(deny_xml, protected_xml):
    denies = {
        row.get("Hash", "").casefold()
        for row in _xml(deny_xml).findall("ci:FileRules/ci:Deny", NS)
    }
    protects = {
        row.get("Hash", "").casefold()
        for row in _xml(protected_xml).findall("ci:FileRules/ci:Allow", NS)
        if row.get("Hash")
    }
    if not protects or any(
        not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value) for value in protects
    ):
        raise RuntimeError("Exact native management code hashes are unavailable")
    if denies & protects:
        raise PermissionError(
            "Native deny hash overlaps Python, PowerShell or the rollback management tool"
        )


def prepare_xml(path, identifier, name, *, audit):
    identifier = watchdog.policy_guid(identifier)
    if (
        not isinstance(name, str)
        or not name.startswith("Vatex LUMINA xSERA ")
        or len(name) > 128
    ):
        raise ValueError("Unique bounded xSERA policy name required")
    tree = _xml(path)
    root = tree.getroot()
    root.set("PolicyType", "Base Policy")
    for tag in ("PolicyID", "BasePolicyID"):
        value = root.find("ci:" + tag, NS)
        if value is None:
            raise ValueError("Native base policy IDs missing")
        value.text = identifier
    rules = root.find("ci:Rules", NS)
    if rules is None:
        raise ValueError("Native policy options missing")
    rules.clear()
    for option in sorted(OPTIONS | ({"Enabled:Audit Mode"} if audit else set())):
        ET.SubElement(
            ET.SubElement(rules, "{" + NAMESPACE + "}Rule"), "{" + NAMESPACE + "}Option"
        ).text = option
    file_rules = root.find("ci:FileRules", NS)
    if file_rules is None:
        raise ValueError("Native file rules missing")
    allows, denies = set(), set()
    for row in file_rules:
        kind = row.tag.rsplit("}", 1)[-1]
        if (
            kind == "Allow"
            and row.attrib.get("FileName") == "*"
            and {"ID", "FileName"} <= set(row.attrib)
            and not set(row.attrib) - {"ID", "FileName", "FriendlyName"}
            and len(row.attrib.get("FriendlyName", "")) <= 512
        ):
            allows.add(row.attrib["ID"])
        elif (
            kind == "Deny"
            and re.fullmatch(
                r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", row.attrib.get("Hash", "")
            )
            and not set(row.attrib) - {"ID", "FriendlyName", "Hash"}
        ):
            denies.add(row.attrib["ID"])
        else:
            raise ValueError(
                "Only AllowAll and exact native hash deny rules are permitted"
            )
    if len(allows) != 2 or not 1 <= len(denies) <= MAX_WINDOWS_RULES * 8:
        raise ValueError(
            "Native deny policy must preserve two AllowAll rules and bounded hash denies"
        )
    scenarios = root.findall("ci:SigningScenarios/ci:SigningScenario", NS)
    if {row.get("Value") for row in scenarios} != {"131", "12"}:
        raise ValueError("Both kernel and user mode AllowAll scenarios required")
    for scenario in scenarios:
        refs = scenario.find("ci:ProductSigners/ci:FileRulesRef", NS)
        if refs is None:
            raise ValueError("Native signing scenario lacks AllowAll references")
        if scenario.get("Value") == "131":
            for row in list(refs):
                if row.get("RuleID") in denies:
                    refs.remove(row)  # User-mode adapter never adds a driver deny.
        refs_ids = {row.get("RuleID") for row in refs}
        if not refs_ids & allows or refs_ids - allows - denies:
            raise ValueError("Native policy AllowAll/reference validation failed")
        if scenario.get("Value") == "12" and not denies <= refs_ids:
            raise ValueError("Native user-mode deny hashes are not referenced")
    for row in root.findall("ci:Signers/ci:Signer", NS):
        if row is not None:
            raise ValueError(
                "Signer rules are forbidden in this bounded native hash adapter"
            )
    setting = root.find(
        "ci:Settings/ci:Setting[@Provider='PolicyInfo'][@ValueName='Name']/ci:Value/ci:String",
        NS,
    )
    if setting is None:
        raise ValueError("Native policy friendly name field missing")
    setting.text = name
    ET.register_namespace("", NAMESPACE)
    tree.write(path, encoding="utf-8", xml_declaration=True)
    return {"policy_id": identifier, "audit": audit, "native_deny_hashes": len(denies)}


def copy_approved_executable(source, target, digest, maximum, response_module):
    response_module._no_links(source)
    response_module._no_links(target.parent)
    fd = os.open(
        source, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 64 <= before.st_size <= maximum
        ):
            raise PermissionError(
                "Approved executable must be a bounded single-link ordinary PE file"
            )
        body = bytearray()
        deadline = time.monotonic() + 3
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("Approved executable read deadline exceeded")
            piece = os.read(fd, min(65536, maximum + 1 - len(body)))
            if not piece:
                break
            body.extend(piece)
            if len(body) > maximum:
                raise PermissionError("Approved executable exceeded its bound")
        after = os.fstat(fd)
        named = source.stat(follow_symlinks=False)
        if (
            kernel_prevention.defense._file_stamp(before)
            != kernel_prevention.defense._file_stamp(after)
            or (named.st_dev, named.st_ino) != (after.st_dev, after.st_ino)
            or hashlib.sha256(body).hexdigest() != digest
        ):
            raise PermissionError(
                "Approved executable bytes/identity differ from signed evidence"
            )
        if body[:2] != b"MZ" or len(body) < 64:
            raise PermissionError(
                "Windows kernel hash adapter requires an ordinary PE executable"
            )
        header = int.from_bytes(body[0x3C:0x40], "little")
        if (
            header + 24 > len(body)
            or body[header : header + 4] != b"PE\0\0"
            or int.from_bytes(body[header + 22 : header + 24], "little") & 0x2000
        ):
            raise PermissionError(
                "Only PE EXE images, never DLL/driver policies, are supported"
            )
        with target.open("xb") as stream:
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
        return {"source": str(source), "flat_sha256": digest, "staged": str(target)}
    finally:
        os.close(fd)


class WindowsAppControl:
    def __init__(
        self,
        config,
        response_module,
        *,
        backend_factory=NativeAppControl,
        clock=time.time,
    ):
        self.config, self.response, self.backend_factory, self.clock = (
            config,
            response_module,
            backend_factory,
            clock,
        )
        self.settings = config.get("kernel_prevention", {})
        self.enabled = (
            isinstance(self.settings, dict) and self.settings.get("enabled") is True
        )
        self.backend, self.watchdog_process, self.lease_dir, self.identifier = (
            None,
            None,
            None,
            None,
        )
        self.mode, self.running, self.error, self.snapshot = "audit", False, None, None
        self.removal_authorized = False
        self.rollback_result, self.manifest, self.expires_monotonic = None, None, None
        self._close_lock, self._close_started, self._closing = (
            threading.Lock(),
            False,
            False,
        )

    def _start_watchdog(self, lease):
        filename = Path(__file__).with_name("windows_app_control_watchdog.py")
        self.response._no_links(filename)
        self.nonce = secrets.token_hex(32)
        plan = {
            "schema": "vatex.appcontrol.lease.v1",
            "policy_id": self.identifier,
            "nonce": self.nonce,
            "lease_seconds": lease,
            "directory": str(self.lease_dir),
        }
        watchdog.atomic_json(self.lease_dir / "plan.json", plan)
        self.watchdog_process = subprocess.Popen(
            [
                getattr(sys, "_base_executable", sys.executable),
                "-I",
                str(filename),
                str(self.lease_dir / "plan.json"),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            | getattr(subprocess, "DETACHED_PROCESS", 0),
        )
        deadline = time.monotonic() + 5
        ready = self.lease_dir / "ready.json"
        while time.monotonic() < deadline:
            if self.watchdog_process.poll() is not None:
                raise RuntimeError(
                    "Independent App Control rollback watchdog exited before handshake"
                )
            if ready.exists():
                self.response._no_links(ready)
                value = json.loads(ready.read_text(encoding="utf-8"))
                if value != {
                    "schema": "vatex.appcontrol.watchdog.ready.v1",
                    "pid": self.watchdog_process.pid,
                    "nonce": self.nonce,
                    "policy_id": self.identifier,
                    "lease_seconds": lease,
                }:
                    raise RuntimeError(
                        "Independent App Control rollback handshake mismatch"
                    )
                self.expires_monotonic = time.monotonic() + lease - 1
                return
            time.sleep(0.025)
        raise TimeoutError(
            "Independent App Control rollback watchdog handshake timed out"
        )

    def _inventory_entry(self):
        return self.backend.inventory().get(self.identifier.strip("{}").upper())

    def _confirm(self, *, enforced):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            entry = self._inventory_entry()
            options = entry.get("PolicyOptions") if entry else None
            # Native IsEnforced means loaded/active, including audit policies.
            # Blocking mode comes from the explicit Audit Mode policy option.
            if (
                entry
                and str(entry.get("FriendlyName", "")) == self.friendly_name
                and _truth(entry.get("IsEnforced"))
                and ("IsAuthorized" not in entry or _truth(entry["IsAuthorized"]))
                and isinstance(options, list)
                and all(isinstance(v, str) for v in options)
                and OPTIONS <= set(options)
                and ("Enabled:Audit Mode" in options) == (not enforced)
            ):
                return entry
            time.sleep(0.1)
        raise RuntimeError(
            "Native App Control inventory did not confirm the requested audit/enforcement state"
        )

    def start(self):
        if not self.enabled:
            return False
        if self.running:
            return True
        if self._close_started:
            raise RuntimeError("A closed App Control instance cannot be restarted")
        if self.identifier:
            raise RuntimeError("A released App Control instance cannot be restarted")
        try:
            directories, ids, desired, lease, maximum = validate_settings(self.settings)
            self.backend = self.backend_factory()
            for directory in directories:
                root = Path(directory)
                self.response._no_links(root)
                if not root.is_dir():
                    raise ValueError("Opted-in App Control directory is unavailable")
                protected = [
                    Path(sys.executable).parent,
                    Path(__file__).resolve().parent,
                ]
                if self.backend.native:
                    protected.extend(
                        [
                            self.backend.citool.parent.parent,
                            Path(os.environ.get("ProgramFiles", "C:\\Program Files")),
                            Path(
                                os.environ.get(
                                    "ProgramFiles(x86)", "C:\\Program Files (x86)"
                                )
                            ),
                        ]
                    )
                if any(
                    root == value or root.is_relative_to(value) for value in protected
                ):
                    raise PermissionError(
                        "Windows, installed agent, Python and Program Files directories cannot supply deny targets"
                    )
            projection = kernel_prevention.SignedProjection(
                self.config,
                directories,
                ids,
                self.response,
                self.clock,
                projector=project_rules,
            )
            self.snapshot = projection.load()
            self.identifier = "{" + str(uuid.uuid4()).upper() + "}"
            self.friendly_name = "Vatex LUMINA xSERA " + self.identifier
            if self.identifier.strip("{}").upper() in self.backend.inventory():
                raise RuntimeError(
                    "New policy ID unexpectedly already exists; refusing to change it"
                )
            self.removal_authorized = True
            state = Path(self.config["state_dir"])
            self.response._no_links(state)
            self.lease_dir = state / ("appcontrol-lease-" + uuid.uuid4().hex)
            self.lease_dir.mkdir(mode=0o700)
            sources = []
            for filename, hashes in self.snapshot["rules"].items():
                if len(hashes) != 1:
                    raise ValueError(
                        "One approved flat SHA256 per Windows source executable required"
                    )
                digest = next(iter(hashes))
                target = self.lease_dir / ("approved-" + uuid.uuid4().hex + ".exe")
                sources.append(
                    copy_approved_executable(
                        Path(filename), target, digest, maximum, self.response
                    )
                )
            xml, cip = (
                self.lease_dir / "policy.xml",
                self.lease_dir / (self.identifier + ".cip"),
            )
            self.backend.generate(
                [Path(row["staged"]) for row in sources],
                xml,
                self.identifier,
                self.friendly_name,
            )
            self.backend.compile(xml, cip, audit=True)
            self._start_watchdog(lease)
            self._watchdog_alive()
            self.backend.apply(cip)
            self._confirm(enforced=False)
            self.mode, self.running = "audit", True
            self.manifest = {
                "policy_id": self.identifier,
                "signed_policy_sha256": self.snapshot["digest"],
                "sources": sources,
                "xml_sha256": hashlib.sha256(xml.read_bytes()).hexdigest(),
                "cip_sha256": hashlib.sha256(cip.read_bytes()).hexdigest(),
                "native_hash_algorithm": "Windows Authenticode/PE and page hashes",
                "native_hash_scope": "global_equivalent_code",
            }
            watchdog.atomic_json(self.lease_dir / "manifest.json", self.manifest)
            if desired == "enforce":
                self._watchdog_alive()
                self.backend.compile(xml, cip, audit=False)
                self.backend.apply(cip)
                self._confirm(enforced=True)
                self.mode = "enforce"
            return True
        except Exception as error:
            self.error = str(error)[:1500]
            self.close()
            raise

    def _watchdog_alive(self):
        if (
            not self.watchdog_process
            or self.watchdog_process.poll() is not None
            or time.monotonic() >= self.expires_monotonic
        ):
            raise RuntimeError(
                "Independent rollback watchdog is unavailable or its local lease expired"
            )

    def status(self):
        valid_lease = (
            self.watchdog_process is not None
            and self.watchdog_process.poll() is None
            and self.expires_monotonic is not None
            and time.monotonic() < self.expires_monotonic
        )
        policy_valid = (
            self.snapshot is not None and self.clock() < self.snapshot["expires_at"]
        )
        if self.running and (not valid_lease or not policy_valid):
            self.close()
        return {
            "enabled": self.enabled,
            "state": "closing"
            if self._closing
            else "degraded"
            if self.error
            else "active"
            if self.running
            else "disabled"
            if not self.enabled
            else "stopped",
            "kernel_permission_denial": bool(
                self.running
                and self.mode == "enforce"
                and self.backend
                and self.backend.native
            ),
            "reactive_user_mode": False,
            "support": "windows-native-app-control",
            "mode": self.mode,
            "scope": "global_equivalent_native_code_hash",
            "policy_id": self.identifier,
            "policy_sha256": self.snapshot["digest"] if self.snapshot else None,
            "revision": self.snapshot["revision"] if self.snapshot else None,
            "independent_rollback_watchdog": bool(valid_lease),
            "lease_seconds": self.settings.get("windows_lease_seconds", 60),
            "automatic_lease_renewal": False,
            "rollback": self.rollback_result,
            "error": self.error,
            "kernel_driver_owned_by_xsera": False,
            "classification": "preapproved_native_pe_code_hash_deny",
            "zero_day_classifier": False,
            "memory_exploit_prevention": False,
            "code_integrity_3077_qualified": False,
            "crash_behavior": "independent_watchdog_removes_only_this_policy_after_lease",
            "reboot_behavior": "persistent_OS_policy_requires_operator_recovery_if_watchdog_is_lost",
        }

    health = status

    def drain_events(self, limit=200):
        if type(limit) is not int or not 1 <= limit <= 1024:
            raise ValueError("Native audit drain limit must be 1..1024")
        # Native CodeIntegrity events arrive through the Windows Event Log
        # collector. Never synthesize confirmed block events from policy apply.
        return []

    def close(self):
        # Main status and control-heartbeat can expire the same lease together.
        # Exactly one caller publishes release/removes the policy; other health
        # readers see closing without racing the same atomic temporary filename.
        with self._close_lock:
            if self._close_started:
                return
            self._close_started, self._closing, self.running = True, True, False
        try:
            try:
                if self.lease_dir and getattr(self, "nonce", None):
                    release = self.lease_dir / "release.json"
                    if not release.exists():
                        watchdog.atomic_json(
                            release, {"nonce": self.nonce, "policy_id": self.identifier}
                        )
            except (OSError, ValueError) as error:
                # A damaged local release file must not prevent native removal.
                self.error = (
                    "Independent watchdog release signal failed: " + str(error)[:512]
                )
            if self.backend and self.identifier and self.removal_authorized:
                try:
                    self.rollback_result = self.backend.remove(self.identifier)
                except (
                    OSError,
                    ValueError,
                    RuntimeError,
                    subprocess.TimeoutExpired,
                ) as error:
                    self.rollback_result = {
                        "removed": False,
                        "policy_id": self.identifier,
                        "error": str(error)[:512],
                    }
                if not self.rollback_result.get("removed"):
                    self.error = (
                        "Native App Control rollback could not be confirmed: "
                        + str(self.rollback_result.get("error", "unknown"))[:512]
                    )
        finally:
            self._closing = False
