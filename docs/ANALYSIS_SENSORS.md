# xSERA external sensor integration

This optional path accepts actual JSON from operator-managed Suricata, Zeek,
Falco, Tetragon and osquery. It does not install these programs or perform packet
inspection itself. No kernel module, BPF program, firewall policy, audit policy,
host blocking, malware sample execution or automatic response is invoked.

## Configuration and approval

Open **확장 분석 · 연구 → 외부 센서 → 센서 연결 만들기**. Select one exact index,
sensor host/account, source realm and a connector environment reference. The
reference is metadata; this API uses a current authenticated local user session
and current index permissions, not the reference as a password. Choose `replay`
only for fixtures (realm is then `virtual-lab`) or `live` for real sensor reports.
An independent administrator must review the source, parser scope, approved
query/policy names and optional Case creation before intake.

Registration creates a real source registry entry and a draft atomic intelligence
policy. Independent review activates that policy. Its filters bind the actual
source receipt's `projection.source_id`, sensor alert flag and immutable mode.
Indexed originals therefore pass through the existing signal/Story/composite/Case
pipeline with exact original ancestry, current author/reviewer scope, source
revocation and revision checks. A sensor alert is a reported hypothesis, not a
malware probability. Revocation preserves original logs and Case history.

The intake body is `{version, events:[{id,log,kind?}], cursor, checkpoint_version}`.
`log` is the original sensor object. Preserve stable source IDs and cursors on
retry. Admission and source receipt precede checkpoint commit. Zeek `kind` is one
of `conn`, `dns`, `http`, `ssl`, `notice` and supplies the log-file context when
the JSON line has no `_path`. Fields are bounded, exact source timestamps require
timezone ISO8601 or epoch seconds, and malformed/oversized events are rejected.
No timestamp, process GUID, boot identity or process lineage is invented.

## Supported detection meanings

| Sensor | Alerts | Other observations |
|---|---|---|
| Suricata | EVE `alert`, explicit signature and numeric signature ID | flow, DNS, HTTP, TLS, stats, fileinfo |
| Zeek | `notice` with explicit note | conn, DNS, HTTP, ssl |
| Falco | Warning/Error/Critical/Alert/Emergency rule results | Notice/Informational/Debug rule results |
| Tetragon | Only explicitly reviewed `policy_name` values | process_exec, process_exit, process_kprobe |
| osquery | `added` rows from explicitly reviewed query names | other differential rows; inventory alone is not malicious |

An imported Falco or osquery PID does not establish a process GUID. External
surveillance should supply exact source, host, boot/process identity where its
format supports it. Cross-sensor correlation still requires existing approved
identity or complete flow evidence; matching a hostname alone is not causality.

`POST /api/analysis/sensors/sources/{id}/health` accepts explicit reported
captured/dropped counts, state and version. The console labels these reports as
unverified; reset/restart/loss require operational investigation. Received JSON
and a zero reported drop counter are not independent proof of lossless capture.
No installed or healthy local sensor is claimed by replay.

## Read-only forwarding and optional deployment

`tools/forward_analysis_sensor.py` reads a selected existing JSONL log and sends
one complete line at a time to its reviewed binding over authenticated HTTPS.
Use `--endpoint`, `--binding`, `--log`, `--state`, `--username`, and an environment
variable named by `--password-env`. Use a trusted CA (`--ca-file` if necessary).
`--once` sends at most one line. Loopback HTTP requires the explicit test-only
`--allow-loopback-http` option; normal network use requires TLS verification.
The private cursor state advances only after durable admission and checkpoint
ACK. Incomplete tails are left pending. Invalid lines are not silently skipped.
Use one owned writer per state file and binding. Review file rotation and source
timestamp behavior in the actual environment before unattended deployment.

`deploy/analysis-sensors/` contains disabled-by-default configuration examples
and a systemd template. They are provisioning inputs, not evidence of an installed
or qualified sensor. Native OS installation, telemetry accuracy, packet drops,
encrypted network visibility and realistic CPU/EPS must be measured separately.

## CPU and sensor considerations

Keep packet sensors separate from the xSERA management process where bandwidth
requires it. Prefer one selected Linux syscall sensor (Falco **or** Tetragon) for
a measured target rather than starting redundant sensors. osquery inventory is
scheduled and bounded. All adapters remain standard-library CPU JSON parsing.

