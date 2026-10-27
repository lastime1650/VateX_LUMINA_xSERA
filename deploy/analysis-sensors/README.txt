Optional external sensors; disabled until explicitly installed/configured.
These are starting points, not automatic installation or actual sensor proof.

Suricata: use a passive SPAN/TAP interface, EVE JSON alert/flow/dns/http/tls.
Keep capture process separately budgeted; disable IPS/enforcement for this path.
Zeek: export JSON conn/dns/http/ssl/notice logs, pass --zeek-kind per log file.
Falco: enable JSON output to an operator-owned log, retain rule name/priority
and output_fields; measure syscall event loss and field coverage.
Tetragon: export process_exec/process_exit/process_kprobe JSON. Only explicitly
reviewed policy_name values produce xSERA atomic alerts. No enforcement policy.
osquery: use differential logging. Inventory names do not alert by default;
independently review the exact alert query names first.

Install only from the project's official release distribution on an isolated
target first. Review each program/rule license. Do not put passwords in unit or
source files. Use a private 0600 EnvironmentFile and a dedicated current local
xSERA account with the exact index scope. Rotate credentials separately.

