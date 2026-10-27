# Safe virtual response and operational recovery qualification

The paced simulation can use `tools.virtual_response_lab.run_response_lifecycle`
with two independently authenticated transports on the same loopback origin.
The adapter accepts only an active `virtual-lab` source. The server separately
requires `Settings.simulation_mode=True`; ordinary instances refuse fake assets
and virtual effect preparation. It never imports or invokes the native Agent
executor. Windows/Linux isolation and FortiGate/Cisco IP block actions change
only the isolated database's virtual device state.

The real workflow is original source receipt → detector/Case evidence → prepare
an intent with current Case/source/asset versions → independent approval →
dispatch → reported result → confirmed durable virtual readback. Approval expires
300 seconds after preparation, while isolation/block leases are separately
bounded to 5–300 seconds. Cancellation is available before dispatch. An optional
`request_id` identifies a fresh intent after cancellation/expiry. Dispatch cannot
refresh an old approval or adopt an obsolete asset, source, Case, requester or
approver scope. Case merge/split/re-evaluation cannot move the evidence of a
prepared, approved, dispatching, reported, unknown or partial response.
The target original must also match its admitted registry epoch and immutable
product/account/realm snapshot; a reused source ID cannot authorize a new account
using historical observations.

The adapter tests a repeated dispatch after a lost reply and optionally requests
release/unblock of the exact owned effect. The virtual state and reported/final
receipt commit together. Interrupted dispatch without a final readback becomes
`unknown`, which never authorizes a blind retry. Every virtual result includes
`mode=virtual`, `native_effect=false`, `synthetic_hardware_effect=true` and
`native_qualification=false`. Genuine endpoint result ingestion rejects virtual
proof markers. Even a correctly signed qualification document explicitly marked
as a virtual/synthetic platform or capability cannot claim `native=true`.

`tools.operational_recovery_lab.qualify_operational(isolated=True)` creates and
removes its own temporary stores. Its eight executable probes cover durable
admission restart, exception injection after the analytics commit, queue/disk
reserve rejection and retry, exclusive writer ownership, permission/source
revision before approved dispatch, unknown and confirmed response recovery,
online backup/restore, receipt history preservation and corrupted-snapshot
rejection before restore publication. The output reports each actual outcome
individually; an unsuccessful probe makes the overall result unsuccessful. It
does not take a live Store or stop a running service. The command line requires
`--isolated --output <report.json>`.

Case re-evaluation now uses a durable 100-Case continuation page, narrows candidate
sources before paging and checks the entire current Case scope before proposing.
Related exact episodes remain available across pages and temporary Store restart;
configuration revisions reset the continuation. Every proposal still requires
independent current review. A split is also rechecked on a representative Case
that was cached by an earlier page.

Legacy entity/time Case grouping keeps its default for compatibility, but every
new contribution stores association quality explicitly: a nearby entity/time
match is a hypothesis, a reported process/session identity is source-reported,
and neither asserts causal proof or independent sensor attestation. Policies and
analysis Case adapters can opt into `case_grouping=require_exact_identity`;
observations without an exact reported episode then receive separate Cases
rather than losing the detection. Ordinary nearby grouping also skips frozen
response Cases, so new evidence cannot silently replace an approved snapshot.

Feature UEBA resumes the oldest unfinished completed interval after delay,
temporary resource rejection or Store restart. Its scheduler rechecks the two
preceding buckets for bounded late arrival and publishes identical observations
idempotently. Results state `unbounded_lateness_covered=false`. Events arriving
more than two buckets late require an explicit authorized historical evaluation.
Source byte counters still require genuine per-event deltas, and missing telemetry
is not converted to zero. Sensor-loss and training-contamination exclusion remain
unproven; these are visible quality limits rather than malicious probabilities.

These checks qualify software contracts on synthetic input and virtual state.
Exception injection and graceful reopening do not prove hard power-loss recovery,
multi-node HA, fleet soak, physical appliance policy enforcement, native IPv6
isolation, independent hardware readback, SOC MTTR improvement, or a Yocto/BSP
image. Historical native Linux/Windows evidence and remaining corrections are
documented separately in `ISOLATION_SAFETY_QUALIFICATION.md`; this simulation does
not replace those results or refresh their qualification.
