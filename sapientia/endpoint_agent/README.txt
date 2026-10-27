Vatex LUMINA xSERA Endpoint Agent — source runtime distribution

Windows and Linux packages contain actual user-supplied AEGIS XDR_V2 collectors,
adapted for bound SIEM enrollment. This is an installable Python source package,
not a signed standalone EXE/MSI/ELF. Existing Python 3.10+ is required.
No automatic runtime download or pip installation occurs. The independently
trusted Python runtime must have the pinned cryptography and defusedxml versions
listed in Agent/requirements.txt before installation. Production packages and
fresh installs require an Ed25519 signature and an external public trust pin.
Do not remove or modify
that runtime after service installation. Use a system administrator-controlled
runtime accessible to SYSTEM/root, not a user's writable environment.

Generic package: NO enrollment token, administrator credential, CA, or endpoint
settings. Signed generic download requires an externally provisioned server
signing key even when server HTTPS enrollment is disabled. Unsigned production
packages are refused; no fallback ZIP is served when signing is unavailable.
An operator must configure SAPIENTIA_AGENT_ENDPOINT_URL=https://SERVER:PORT and
SAPIENTIA_AGENT_CA_FILE=public-CA.pem on the SIEM server, restart it, then create
a host/index-bound deployment. Download the scoped package via the XDR menu.
The enrollment token expires in 60..3600 seconds, is single-use and is never
an administrator/collector token. Redownloading rotates the unused token.

The release owner provisions SAPIENTIA_AGENT_SIGNING_KEY_FILE outside the release
and protects the private file. An independent channel must establish its public
fingerprint. Provision the matching xsera.agent.trust.v1 public JSON outside the
extracted and installed package; set SERA_AGENT_TRUSTED_KEYS_FILE to that absolute
protected path. The installer defaults to SERA_AGENT_REQUIRE_SIGNED_PACKAGE=1
and refuses 0. A revoked_key_ids entry refuses that signer at startup and on
every heartbeat measurement. No private key or self-selected trust root is bundled.
The installer/bootstrap itself must originate from an independently authenticated
release. A script from an untrusted archive cannot authenticate itself.

Before extracting, compare the ZIP SHA256 with the authenticated download's
X-Package-SHA256 header. Extract into a NEW PRIVATE directory; do not merge
other files into it. Internal manifest.json checksums detect accidental damage,
not attacker replacement or a code-signing identity. The mandatory Ed25519
signature authenticates the application manifest to your external pin; it is
not Authenticode, OS code signing or hardware attestation. Review scripts before
running. A scoped ZIP contains a short-lived secret: do not share it or send it
to a public file/AV scanning service. Remove the ZIP and extracted token after
successful enrollment; installers delete only the token file, not your ZIP.

Windows: elevated PowerShell, protected Python 3.10+ and dependencies:
  .\install.ps1 -Python 'C:\Path\To\python.exe' -TrustedKeysFile 'C:\Protected\agent-trust.json'
Creates LocalSystem SCM service VatexLuminaXseraAgent under ProgramData\Vatex\LUMINA\xSERA\Agent.
Install/state/credentials are accessible only to SYSTEM and Administrators.
No UAC bypass, tray/autostart Run entry, Sysmon download or EULA acceptance occurs.
Existing installations are refused; automatic update/uninstall is not provided.
User-mode process snapshots + existing Sysmon/Security/Defender/CodeIntegrity Event Logs and
TCP polling are collected. Short-lived processes can escape snapshot polling.

Linux: root, protected /usr/bin/python3 3.10+ and dependencies, systemd:
  export SERA_AGENT_TRUSTED_KEYS_FILE=/etc/xsera/agent-trust.json
  bash ./install.sh
Creates /opt/vatex-lumina-xsera-agent and root systemd service vatex-lumina-xsera-agent.service.
Uses /proc process/TCP snapshots, accessible systemd journal and existing auditd
logs. Does not install audit rules, change audit policy, deploy eBPF/kernel code,
or silently install OS/PyPI dependencies. No systemd: configure supervised run
explicitly using Agent/Linux/main.py run --config after protected enrollment.

Both: verified HTTPS with packaged public CA, TLS1.2+, no proxies/redirects or
certificate-disable option. Durable SQLite bounded queue retains stable event IDs
for at-least-once retry; SIEM durable admission deduplicates. Quarantine is explicit
and does not cause a false acknowledgement. Owner role/index revocation and exact
tenant/host/index binding are checked on EVERY authenticated server operation.
Agent credential lasts 90 days and can be revoked in SIEM. Re-enrollment/upgrade
must preserve or explicitly retire local identity; do not clone state folders.
Agent/deployment lists retain the complete currently authorized durable history,
prioritizing usable pending deployments and unrevoked/unexpired agents before
older history. Counts and permission scopes remain explicit.
No arbitrary shell, kernel anti-tamper or complete EDR coverage is claimed.
Developer fixtures may explicitly request an unbound development_fixture archive
and loopback-only runtime policy. It is not exposed as a server download option,
contains no enrollment authority and is rejected by production service installers.
Production packages cannot be downgraded to that profile. Runtime integrity
policy changes require restart and cannot turn a current failed measurement
into an unsigned production result.
Production installed trees reject unlisted bytecode, including __pycache__;
the service uses -B and dependencies must not precompile this Agent tree.
The development utility tools/provision_agent_test_signer.py requires --qa-only
and a NEW external directory. It creates disposable test keys, never establishes
an owner release identity, and never installs or automatically trusts its public key.
Keep production signing keys in an owner-controlled external ceremony. To revoke
a signer, independently update the protected trust file's revoked_key_ids list;
startup refuses it and the next heartbeat reports a failed integrity measurement.
Typed manual response is OFF by default. Locally confirmed commands below enable
inspect_process, inspect_file, collect_artifact, quarantine_file and restore_file,
or the old terminate_process/delete_file actions. Host isolate/release executors
exist behind separate explicit OS/management configuration. The response-policy
CLI supports --allow-host-isolation with exact --management-endpoint direction,IP,port
and --isolation-max-seconds (Windows 30..300; Linux 30..3600). An independent finite
rollback guard must authenticate readiness before any rule is applied. Disabled
Windows firewall profiles cause refusal; product code never silently enables them.
Process termination is one-time, not persistent
execution blocking. File deletion is permanent and limited to regular single-link
files <=64 MiB with exact SHA256 in a root marked by .lumina-response-root
containing exactly allow-manual-file-delete followed by newline. Linux roots
and subdirectories must be service-owned and not group/other writable.
Never opt in system/program directories or broadly writable runtime roots.
Each request is bound to current full-case ACL, evidence event, enrolled
host/index and case version. HTTPS/HMAC signed claims require durable ACK
and local execution markers before effects. Ambiguous crash outcomes are
unknown and never automatically re-executed; inspect the endpoint before
issuing a NEW request. Response receipts are agent-reported, not hardware
attestation. Revocation/cancellation after execution ACK cannot undo an
in-flight effect. Linux process termination requires kernel pidfd support. Windows file deletion
requires FileDispositionInfoEx/POSIX semantics support; unsupported kernels fail
closed. simulate-case emits labelled
synthetic logs and runs no attack command; it is not real attack qualification.

Provenance: PROVENANCE.json preserves original AEGIS XDR_V2 source hashes and
the historical license observation. On 2026-10-16 the project owner explicitly
confirmed public redistribution rights and Apache-2.0 licensing for the original
agent code as well as this project. This records the owner's direct declaration,
not an independent legal judgement. Preserve original attribution and separate
third-party notices. Python runtime is separately installed/licensed and not included.
Real Linux/Windows installation,
code signing, mass rollout, upgrades and diverse OS qualification require their
own evidence; source/package/protocol tests alone do not establish that coverage.

Optional kernel prevention (0.10, default OFF):
Stop the agent, then use kernel-policy --enable-kernel-prevention with explicit
--kernel-directory, --kernel-rule-id and --confirm-kernel-policy. Enrollment pins
the server policy verification key; enabling kernel prevention does not enable
reactive termination. Only current peer-approved exact path/SHA256 signed rules
are eligible. Windows defaults to audit; --kernel-mode enforce explicitly permits
a finite native App Control/UMCI policy (30..300 seconds, no automatic renewal).
Linux uses fanotify FAN_OPEN_EXEC_PERM on immediate children of selected protected
directories. It does not intercept interpreter script execution, other mounts or
arbitrary writable trees; closing or losing the listener ends blocking. Windows
native PE hashes can block equivalent code outside the source directory. No own
kernel driver, root-proof anti-tamper or hardware attestation is provided.

Detection continuity improvements (2026-10-13):
Capture, local rule evaluation and transport/control have separate workers and
thread-owned SQLite connections. Capture continues during HTTP backlog within a
bounded reserve (default pending10,000 + capture reserve10,000; 128MiB per spool).
If the hard bound or disk capacity is exhausted, health reports failure; polling
events never observed during that condition cannot be recovered or counted as
protected. Durable local event/rule cursors retain incomplete 2-second/200-output
evaluation work across restart, without replaying uncertain destructive effects.
The first canonical receipt of a native record is retained in a bounded retry
cache (100,000 records/128MiB), using raw record SHA256 to reject identity changes
while keeping later observational enrichment from changing an existing receipt.
No infinite retention or enterprise sensor-loss SLO is claimed.

Windows always retains bounded established-TCP polling alongside existing Sysmon;
a RUNNING service alone is not verified EventID3 configuration. Event-log channels
have individual quotas and rotation, with unread-record-span/backlog health.
Existing PowerShell Operational4103/4104 is collected read-only when accessible.
No OS logging policy is silently enabled. Each observed fragment has original
length/hash/truncation/counter fidelity; missing fragments are not complete code.
Unbound events retain descriptive process metadata but do not gain a destructive
PID/GUID/start identity. Windows ETW/AMSI/kernel-memory sensors remain unsupported.
Network records explicitly count sensor observations, not unique connections.
Potential cross-provider flow groups require the same verified native process
GUID/start identity and normalized endpoint tuple. They are possible overlap,
not proof of a unique socket generation; PID-only/unverified aliases are never
merged and original provider GUID/evidence is retained.

Startup inventory uses process_observed/network_connection_observed rather than
invented creation/connection time. Linux command lines preserve up to8KiB and
report original length, SHA256 and truncation. Audit records join a live process
GUID only with conservative birth-time and matching executable evidence; historic
PID alone is not joined and no destructive start identity is granted by that join.
Short-lived events outside configured audit coverage still need an independent
continuous sensor. Unmatched behavior is unknown, not a clean malware verdict.

Optional read-only memory layout observability (default OFF; native qualification pending):
Use the protected stopped-agent local CLI, never edit a running service policy:
  python -I -B Agent/Windows/main.py memory-policy --config config.json
  --enable-memory-observability --confirm-memory-policy
Linux uses Agent/Linux/main.py with the same options. Disable with
--disable-memory-observability --confirm-memory-policy. Installation owner/ACL and
lifetime locks apply; restart is required. Explicit bounds are available via
--memory-max-processes (1..64), --memory-max-regions (1..1024) and
--memory-budget-ms (50..2000). Time is a cooperative budget between OS calls,
not a claim that the OS itself can always be interrupted at that deadline.
Windows supports a 64-bit runtime and verified native x64 target using read-only
VirtualQueryEx region metadata. WoW64/other architectures and PPL/access-denied
processes are reported as coverage gaps. Linux reads bounded /proc/PID/maps.
Exact native identity is compared before and after; changed identity observations
are discarded. No ReadProcessMemory, memory content, write, injection or PPL bypass
is performed. Anonymous executable/RWX metadata is sampled, low-confidence and
unknown as a malware verdict: legitimate JIT/managed code also uses such pages.
Events do not contain destructive PID/start-identity authority. Use multi-signal
behavior corroboration; this provider is not an exploit or memory malware engine.

Linux guarded workload allowlist (explicit opt-in, native qualification pending):
This is an approved-code control for a dedicated private directory, not a generic
zero-day exploit or malicious-code classifier. Use a peer-approved signed policy
with action=allow_execution and exact path/SHA256 conditions. Known-bad
terminate_process rules cannot be implicitly converted into an allowlist.
Select only explicitly approved non-system directories and exact rule IDs:
  kernel-policy ... --enable-kernel-prevention --confirm-kernel-policy
  --guarded-workload-mode audit --confirm-guarded-workload
  --guarded-workload-lease-seconds 60 --kernel-directory /opt/dedicated-workload
  --kernel-rule-id approved-workload-code
Audit permits execution and records would_deny for unapproved code. Enforce must
be separately selected with --guarded-workload-mode enforce and requires an actual
native audit receipt observing approved and unapproved code for the SAME signed
digest, directory scope and adapter code within24 hours. Mock backends cannot
produce or consume qualifying native proof. Enforcement denies unapproved code
only inside the explicit direct-child scope and expires after30..300 seconds on
a monotonic clock, releasing the owned permission group. Policy replacement
requires new audit evidence. This control does not inspect interpreter inputs,
other directories, memory-only payloads or exploits in already approved code;
listener death still releases kernel blocking. Do not deploy an enforce setting
without dedicated-workload native qualification. Default known-hash deny remains
unchanged and Windows keeps its existing bounded App Control hash-deny adapter.

Local response opt-in (administrator/root only; no JSON editing):
1. Stop VatexLuminaXseraAgent / vatex-lumina-xsera-agent.service.
2. Create a NEW narrow private directory for deletable lab/response files.
   Windows elevated PowerShell example:
     New-Item -ItemType Directory C:\LuminaResponseLab
     icacls C:\LuminaResponseLab /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
   Linux example: install -d -m 0700 /var/lib/lumina-response-lab
3. Using the installed system Python, run the local entry point:
   python -I -B Agent/Windows/main.py response-policy --config config.json --enable-response --allow-file-root C:\LuminaResponseLab --mark-file-roots --confirm-response-policy
   Linux: python3 -I -B Agent/Linux/main.py response-policy --config config.json --enable-response --allow-file-root /var/lib/lumina-response-lab --mark-file-roots --confirm-response-policy
   These commands enable only file deletion within that marked root. No files
   are deleted by configuring the policy. Broad OS/home/install roots fail.
4. For process termination, additionally specify the exact approved executable:
   --allow-process-executable C:\TrustedRuntime\python.exe
   Optionally restrict exact currently running instances with repeated
   --allow-process-instance PID:START_IDENTITY (identity from collected evidence).
   Executable allowlists without instance entries allow any matching current
   process instance with matching evidence GUID/PID/start; choose carefully.
5. Restart the service; heartbeat reports enabled actions. In the case GUI choose
   Manual > Response > Agent, select exact enrolled evidence target, confirm the
   irreversible effect and submit. Review reported result; no automatic closure.
6. Disable locally: same entry point response-policy --config config.json
   --disable-response --confirm-response-policy, then restart the service.
   Existing root markers are preserved; disabling does not undo prior effects.
Response-policy requires a protected installation/config. The lifetime agent-run
lock and response lock reject configuration while the agent is running; stop the
service first. Owner/ACL and link checks run before local policy writes. Each
command replaces the complete response policy; it does not preserve prior enabled
actions silently. Private roots must remain private. Configuring never executes
an endpoint action, and disabling does not reverse a prior effect.

Read-only investigation (no delete/terminate/quarantine enabled):
  python -I -B Agent/Windows/main.py response-policy --config config.json --enable-response --allow-investigation --confirm-response-policy
This permits the typed inspection and bounded artifact-collection actions only.
Use the corresponding Agent/Linux/main.py entry point on Linux.

Process executable disk-image investigation (0.16; no process-memory scanning):
Add --allow-process-artifact-collection and an exact --allow-process-executable
entry to the explicit read-only investigation policy above. The image must match
the live GUID/PID/start identity and canonical path; prepared metadata is admitted
as a new original before the operator adds it to the Case and requests collection.
--max-process-artifact-bytes limits these images to at most 33554432 bytes.
Important OS/management/agent/ancestor processes and linked/reparse images remain
excluded. This option enables neither termination, deletion nor isolation. The
server verifies chunk/full SHA256 and performs offline YARA after transfer.

Reversible file quarantine and restoration:
  python -I -B Agent/Windows/main.py response-policy --config config.json --enable-response --allow-quarantine --allow-restore --allow-file-root C:\LuminaResponseLab --mark-file-roots --confirm-response-policy
The default quarantine catalog is the private state_dir/quarantine subdirectory,
marked by .lumina-quarantine-root with allow-reversible-quarantine and newline.
--quarantine-dir may select only a private subdirectory of the same state root.
Source roots still require the explicit response marker and exact evidence hash.
This command does not also enable deletion or process termination. Add
--allow-delete / --allow-termination with their explicit allowlists only when
those additional effects are intended. Restoring requires the recorded local
catalog identity and refuses an occupied destination; retain the catalog.

Signed offline reactive defense (default OFF, not pre-execution prevention):
  python -I -B Agent/Windows/main.py defense-policy --config config.json --enable-defense --confirm-defense-policy
Run stopped as administrator/root. This pins only defense_public_key saved by
verified enrollment, with the saved agent_id/tenant/host/index scope; no public-key
override flag or unsigned rule import exists. A legacy identity missing these
fields must recover/re-enroll deliberately before enabling. After restart the
agent fetches independently approved signed policies; without a valid bound,
unexpired bundle or the cryptography dependency it reports degraded and performs
no policy effect. An already cached policy remains valid until signed expiry
while offline. Local response flags and exact target allowlists still govern
terminate/quarantine, and interrupted outcomes remain unknown without replay.
Disable locally with defense-policy --config config.json --disable-defense
--confirm-defense-policy, then restart. The signed bundle and execution history
are preserved; no prior effect is reversed. Windows/Linux native provider and
isolation coverage require separate OS qualification, not these CLI tests.
