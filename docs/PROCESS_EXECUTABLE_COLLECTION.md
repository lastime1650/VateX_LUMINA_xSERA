# Explicit process executable collection

This operation reads the current on-disk executable of a selected live process.
It never executes the sample, dumps process memory, terminates a process, changes
firewall policy, or approves a response. Agent reports are authenticated assertions,
not hardware attestation or proof of all code mapped into the process.

## Local enablement

The existing administrator/root response configuration must explicitly include
`--allow-investigation --allow-process-artifact-collection` and one or more exact
`--allow-process-executable` paths, together with the existing confirmation flag.
The new read-only option does not implicitly enable termination or deletion.
`--max-process-artifact-bytes` defaults to 33,554,432 (32 MiB), may be lowered,
and cannot exceed 32 MiB. Collected bytes use the existing private artifact spool.

The 32 MiB process-only ceiling permits moderate executable images that exceeded
the old 2 MiB forensic limit while bounding agent memory, I/O, transfer time and
server analysis input. Larger images fail explicitly. This is not coverage of all
executable sizes. Legacy file collection and legacy signature/sandbox processing
keep their 2 MiB limit; large process images require the dedicated YARA analyzer.
No external sandbox submission is enabled automatically.

## Two explicit steps when an original has no hash

1. Select an enrolled Case process original with GUID, PID, creation identity and
   executable path. Request `prepare_only:true`. The server creates an ordinary
   `inspect_process` command with `capture_executable_evidence:true` and the exact
   reported path; clients cannot submit another path or hash.
2. The opted-in agent rechecks the current process, exact local executable
   allowlist and stable file. It hashes only this explicitly requested file,
   publishes a **new** authenticated `process_image_observed` original, and reports
   its `process_evidence_event_id` and source command. A lost reply retries the
   same original body and ID without executing inspection again.
3. Explicitly add that new original to the Case through the existing bookmark API.
   Reload the target list and select that original for collection. Existing
   originals and Case membership are never silently rewritten.

Existing native collector polling does not hash every process or change its CPU
budget. Both Windows and Linux use the shared explicit observation module.

## API and immutable evidence

`GET /api/yara/collection-targets?incident_id=…` returns current Case version,
eligible/needs-prepare rows, server-generated actions, target IDs, and existing
command states. `POST /api/yara/collections` accepts only Case/event/agent IDs,
Case version, request ID, reason, optional preparation flag and optional target ID.
Status remains `GET /api/agent-responses/{id}`. Analyst/admin role, complete current
Case/index authority, enrolled host/agent provenance, original receipt, TTL and
Case version are checked through the existing response lifecycle.

Actual collection is the additive frozen action `collect_artifact` with
`source:process_executable`, exact GUID/PID/start identity/path/SHA256 and bounded
`max_bytes`. Windows pins a read-only file handle that denies writes/deletion and
checks its final path, identity and attributes. POSIX walks directory descriptors
without following links and checks the current `/proc/PID/exe` inode. Both recheck
process identity while the file is open, reject symlink/reparse/hardlink objects,
file replacement/mutation, and hash mismatch. Some OS files with multiple hardlinks
are deliberately unsupported by this conservative reader.

Bytes reuse the existing 32 KiB chunk protocol and completed-transfer receipt.
The larger retained artifact is backed up/restored only with its exact frozen
command/tenant/Case/index/agent/hash binding. YARA can join artifact.command_id to
the response's original event and immutable receipt; a scan is still a static file
result, not a calibrated malicious probability or an automatic host action.

Regression uses mocked process identities and harmless temporary byte files,
real authenticated admission/transfer, restart retry and backup/restore. Windows
and Linux native process/fleet qualification remains separate from these tests.
