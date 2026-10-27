# Native kernel execution permission protection

This component is separate from the 0.9 reactive defense engine. An approved
`terminate_process` rule is projected into pre-execution protection only when a
local administrator explicitly selects its ID for kernel prevention. Selection
does not change all existing behavioral rules into execution blocks.

The selected rule must have exactly two case-sensitive `eq` conditions:
`file.hash.sha256` and `process.executable`, with `ignore_case: false`. It must be
enabled, have action `terminate_process`, and have no exceptions. The executable
must be an immediate child of a locally selected directory. A bounded signed
defense policy binds the tenant, host, agent, index, revision and expiry. The
enrollment signing key stays pinned; durable local state rejects older policies
and conflicting content at the same revision. Rule selection is local opt-in.

## Linux

`Agent/kernel_prevention.py` calls libc `fanotify_init` and `fanotify_mark` with
`FAN_CLASS_CONTENT` and `FAN_OPEN_EXEC_PERM`. Linux holds the executable open
until the listener writes `FAN_ALLOW` or `FAN_DENY`. A matching path and SHA256
produce `FAN_DENY` before execution; this is not a post-execution process kill.
The hash comes from the kernel-supplied opened file descriptor, with inode,
size, metadata and pathname identity checks. No shell command is executed.

Required support is Linux 5.0 or newer, `CONFIG_FANOTIFY`,
`CONFIG_FANOTIFY_ACCESS_PERMISSIONS`, and `CAP_SYS_ADMIN` in a context permitted
to create permission groups. Runtime syscall success is the support check;
being root or running a recent kernel alone is insufficient. Containers may
lack the required capability even when their UID is zero.

Marks cover only immediate children of 1..32 explicit ordinary directories.
The directories must be service-owned, not externally writable, and have no
symlink ancestors. System trees are excluded. This initial directory mode does
not recursively monitor a filesystem, cover other mount namespaces, protect
arbitrary user-writable trees, or intercept a script passed to an interpreter.

Defaults are a 500 ms decision deadline and a 64 MiB executable bound. Operators
can select 50..2000 ms and 1..64 MiB. One permission loop uses four hash workers,
32 pending requests, a bounded work queue and 1024 audit records. Slow hashing,
changed identities, invalid/expired policy, a full local queue or an elapsed
deadline produce a denial while the listener is alive. A late hash result
cannot issue a second response or allow an expired/replaced policy. Kernel
queue overflow and audit loss are reported as incomplete coverage.

Linux itself **allows outstanding requests when the fanotify group closes**.
Graceful shutdown releases the group so a process does not remain hung; listener
death therefore fails open. This component does not claim crash-proof or
tamper-proof LSM enforcement. A root adversary can stop the agent. Native
qualification must confirm permission denial, absence of the target's side
effect, benign execution, and successful execution after mark removal.

`Agent/Linux/native/fanotify_probe.c` is a small native prerequisite/ABI probe.
It adds and immediately closes one owned directory mark; it does not install a
service or driver. `tools/kernel_permission_payload.c` is a harmless native
qualification executable that creates one explicitly named owned marker.

## Windows

`Agent/windows_app_control.py` uses the operating system's App Control for
Business (ConfigCI and CiTool), not a proprietary xSERA kernel driver. It needs
a local administrator token, ConfigCI cmdlets, the native AllowAll template and
CiTool. This adapter initially targets Windows 11 with CiTool; older Windows
and versions lacking the native tools are unsupported rather than simulated.

Default `windows_mode` is `audit`. The explicit value `enforce` stages an audit
policy first and then removes the audit option for the same newly created ID.
The adapter preserves AllowAll in both kernel and user-mode scenarios, adds
only bounded native hash denies to the user-mode scenario, disables script
enforcement for this policy, and does not modify existing policies. A hash deny
is global for equivalent native code; the source-directory selection is an
approval/provenance restriction, not a runtime path restriction.

Windows uses Authenticode/PE and page hashes, which differ from a flat SHA256.
The adapter first checks the complete original bytes against the signed flat
SHA256, stages a private copy, and asks ConfigCI to derive the native hashes.
It validates the generated XML before compilation. System/management executable
names, installed agent/Python/Windows/Program Files trees, non-EXE files and
Microsoft-signed source images are rejected. Qualification should use a unique
harmless binary compiled for that test, never a copy of an installed application.
Native deny hashes are also compared with ConfigCI hashes of the current Python
interpreter, native PowerShell and CiTool so renaming or changing a file's flat
hash cannot silently block the rollback management path.

A separate standard-library watchdog starts and handshakes **before** any
native policy is applied. Its monotonic rollback lease is 30..300 seconds
(default 60), with no automatic renewal. Cleanup removes only the newly created
GUID with the exact xSERA friendly name, verifies its absence and preserves all
other policies. Explicit close signals the same independent watchdog and also
requests verified removal. A failed/partial native apply invokes rollback.

Native hash planning batches the bounded exact file list and the management
hash list in two ConfigCI calls, each with a 120-second deadline, before the
watchdog lease begins. Each call receives its own private copy of the shipped
AllowAll template because ConfigCI opens source policies for write; the Windows
system template is never passed to that write-capable operation.
Native Windows PowerShell uses only Windows-shipped
modules so an inherited PowerShell 7 module path cannot replace its tools;
the adapter does not change the machine or process execution policy.

The lease bounds when rollback starts; native removal/refresh/inventory commands
have their own finite timeout/retry limits. Host reboot or power loss can lose
the watchdog while leaving a persistent OS policy; operator recovery and a
managed recovery service are required for that case. This bounded prototype is
not persistent enterprise WDAC policy lifecycle management, code signing,
tamper protection, WHQL certification, or all-channel AV prevention.

Native policy application alone does not certify a blocked execution. Actual
qualification must correlate a 3077 CodeIntegrity event with the exact native
policy ID and denied file, observe that its payload did not run, and prove the
payload runs after removal. Audit qualification uses event 3076 and confirms the
payload does run. The adapter does not synthesize confirmed block telemetry;
native CodeIntegrity events belong in the Windows Event Log collector.

CodeIntegrity 3077 alone establishes image-load denial, including DLLs loaded
by an existing process; it does not establish whether a new process was created.
The collector reports `image_loaded: false`, distinguishes DLL
`image_load_denied`, and creates no target process identity. Events 3076 and 3089
leave the image-load outcome unknown. The harmless EXE qualification separately
proves its main-method marker did not run before native policy removal.

## Primary references

- [Linux fanotify API and permission/close behavior](https://man7.org/linux/man-pages/man7/fanotify.7.html)
- [fanotify mark types and executable permission scope](https://man7.org/linux/man-pages/man2/fanotify_mark.2.html)
- [fanotify group creation and capability requirements](https://man7.org/linux/man-pages/man2/fanotify_init.2.html)
- [Microsoft standalone AllowAll plus hash-deny guidance](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/create-appcontrol-deny-policy)
- [Microsoft native hash algorithms and policy options](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/select-types-of-rules-to-create)
- [Microsoft CiTool commands](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/operations/citool-commands)
- [Microsoft CodeIntegrity audit/enforcement event guidance](https://learn.microsoft.com/windows-server/security/osconfig/osconfig-how-to-configure-app-control-for-business)
- [Microsoft PowerShell module-path inheritance through intermediate processes](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
