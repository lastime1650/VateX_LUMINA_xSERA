# Derived schema and isolated comparison contract

Security projections now use additive version 4. All version 3 fields remain;
stored version 3 projections are read without being rewritten. New admissions
use the implementation and pinned OCSF mapping digest in their parser identity.
Admission bytes, redaction, receipt identity, index permissions, and enrolled
Agent command authority remain under their existing contracts.

`event_semantics` distinguishes a process found by inventory from a process
launch. `process_observed`, `process_inventory`, and `memory_observation` have
an observation time and no inferred occurrence time. Other events retain their
reported activity; an explicit occurrence timestamp remains source-reported.
Reported precision, clock quality, offset, and server-received time are separate
attributes. Missing or mistyped identity fields stay null. No clock correction
or kernel capture claim is inferred.

Device UID, boot ID, container UID/namespace, parent start identity, and file
volume/object/generation are optional exact identity context. PID, shared user,
host name, and file path alone are never new incarnation identifiers. The
additional `device`, `boot`, `container`, and `file_object` relations are scoped
by registered source, account, and realm. A file object requires volume, object,
and generation; a reused file path supplies none of these. Reported boot or
container mismatches reject process and parent links. Relations remain analytic
associations and never authorize an endpoint response.

## OCSF derived subset

`ocsf_mapping.py` pins OCSF 1.4.0 and mapping profile 1. It maps explicit process,
file, authentication, and network actions to their OCSF classes. A process
observation maps to Other, never Launch. Unknown actions/fields remain Unknown
or null, while xSERA observation and source semantics remain under `unmapped`.
This is a documented derived subset, not schema conformance certification.

`GET /api/v3/ocsf/events/{event_id}` requires current access to the original
receipt and registered projection. It returns a derived view; it does not
change originals or upgrade old projections in storage.

The numeric mappings follow the pinned upstream definitions:

- [Process Activity](https://github.com/ocsf/ocsf-schema/blob/v1.4.0/events/system/process_activity.json)
- [File System Activity](https://github.com/ocsf/ocsf-schema/blob/v1.4.0/events/system/file_activity.json)
- [Authentication](https://github.com/ocsf/ocsf-schema/blob/v1.4.0/events/iam/authentication.json)
- [Network Activity](https://github.com/ocsf/ocsf-schema/blob/v1.4.0/events/network/network_activity.json)

## Historical Shadow comparison

`POST /api/v3/shadow/compare` freezes one explicit tenant/index-scoped window,
up to seven days and 5,000 admitted originals. It refuses an oversized cohort;
it never labels a truncated sample a complete comparison. Events, receipts,
original projection records, and per-event source authority versions are copied
into an immutable snapshot. Parser/TI, scoped identity and asset state, UEBA
baselines, intelligence policy revisions, CPU model/review/activation metadata,
and implementation hashes are pinned in its context manifest. Model weights
and tenant-wide configuration are fingerprinted, not exposed in result bodies.

The baseline exact correlation rules evaluate the frozen normalized originals.
Candidate rules evaluate a fresh in-memory DuckDB copy with server-derived
`raw.analysis.projection` and `raw.analysis.ocsf`. Reserved derived fields are
removed from vendor data before candidate mapping and are populated only where
the snapshot has a source-bound projection. Both sides use the existing exact
detector, including its deterministic chain selection and bounded chain cursor.
No live Case, finding, risk contribution, SOAR run, endpoint command, scheduled
detector state, model state, or original telemetry is changed. Only comparison
records and their audit/replay metadata are appended.

Minimal request, using existing policies:

```json
{
  "start": 1791936000,
  "end": 1791936600,
  "indexes": ["public"],
  "policy_ids": ["existing-policy-id"],
  "max_events": 5000
}
```

`baseline_rules` and `candidate_rules` optionally replace either side with
`[{"id":"stable-rule-id","definition":{...}}]`, using the existing validated
correlation rule format, up to 16 rules per side. Candidate filter fields can
reference the new derived schema. Results compare rule/entity/original-ID
decisions and exact evidence fingerprints, reporting added, removed, changed,
and unchanged decisions. A changed rule revision is kept in the changed report.

`GET /api/v3/shadow/context?index=public` returns the current context digest;
supplying it as `expected_context_digest` prevents comparison against unexpected
configuration. Context, authority, engine, and receipts are rechecked before
publication. Rule owners and requesters must both currently cover all requested
indexes. Tokens cannot create or replay comparisons.

`GET /api/v3/shadow/runs` provides bounded cursor paging, and
`GET /api/v3/shadow/runs/{id}` returns an authorized comparison. Tenant and index
scope are checked before access. Hidden run IDs never appear in cursor output.
`POST /api/v3/shadow/runs/{id}/replay` repeats the frozen execution, appends a
replay receipt, and reports whether the entire canonical result digest matches.
Subsequent live intake and rule/config edits do not alter the stored snapshot.
Current owner/requester grants remain mandatory. If the pinned evaluator code
has changed, replay refuses and requests a new comparison. Integrity failures
in either stored snapshot or result are rejected.

This exact-detector comparison establishes reproducibility and derived-schema
compatibility. It does not measure native sensor recall or independently
re-execute the entire graph, AI, Case, response, and operating-system pipeline.
Those capabilities require their own simulation and validation evidence.

## Frozen signal, Story, composite, and CPU comparison

`intelligence_shadow.py` adds a separate pure staged evaluator at
`POST /api/v3/shadow/intelligence/compare`. It captures the same explicit
receipt-bound original window and independently freezes the policies for both
sides. It runs the actual typed atomic matcher and original-overlap dependency
calculator used by the unified engine. It reconstructs process instances,
reported parent edges, observation/flow/file nodes, and Story membership from
the frozen projection indexing order. Baseline uses captured projections;
candidate uses the current pinned v4 mapper over captured per-event authority.
An absent, ambiguous, or mismatched boot/parent context stays unresolved.

Composite policies execute in dependency order, with cycle/depth checks,
fixed join keys and event-time windows. A bounded exact search inspects
alternative complete chains before choosing one qualified chain per anchor.
Same-event atomic rules and partially overlapping upstream composites share
original ancestry; they cannot satisfy a requirement for two disjoint original
groups. Every emitted composite retains all ancestor original IDs. Reported
associations and disjoint original groups do not prove causality or statistical
independence.

The request has `start`, `end`, and `indexes`, plus either existing `policy_ids`
or `baseline_policies` / `candidate_policies`. Each supplied policy is
`{"id":"stable-id","revision":1,"definition":{...}}`, using the normal
validated atomic/composite policy format. Supplied definitions are shadow
drafts; they never activate live policies. Policies may have a Case adapter,
but this pure execution never invokes it. Up to 32 policies per side, 5,000
originals, 10,000 signals, eight dependency levels, 32 originals per signal,
100,000 candidate combinations, and explicit execution/byte bounds apply.
Budget exhaustion or incomplete/invalid output fails without publishing a
partial comparison. Successful output records `execution.status=complete`
and a completed frozen event cursor for each side.

Optional `baseline_model_id` and `candidate_model_id` snapshot an existing
authorized CPU model's exact revision, digest, JSON weights, threshold, feature
schema, and framework version. Frozen event features are recomputed from the
captured admitted originals. The bounded PyTorch subprocess actually executes
those frozen weights; the comparison does not call the live ML inference writer.
Its job artifact retains the model/weight/feature/output hashes and predictions.
No live model, inference run, signal, graph, evidence hold, Case, SOAR, command,
or scheduled cursor is mutated. With a requested model the window is limited
to 1,000 originals to match the bounded worker contract.

If the CPU framework is unavailable, its version differs from the frozen model,
or the inference worker cannot run within its deadline, the job explicitly says
`status=excluded`, `executed=false`, and `시스템에서 호환되지 않음`. Atomic,
graph, and composite evaluation continues. That exclusion is pinned for replay;
installing a runtime later does not silently change an old comparison. A model
that successfully executed must execute under the same framework on replay;
loss of that compatibility fails full replay instead of claiming an identical
partial execution. Timings are kept out of canonical decision digests.

`GET /api/v3/shadow/intelligence/runs` pages authorized comparison metadata.
`GET /api/v3/shadow/intelligence/runs/{id}` returns its result; `POST` to
`/api/v3/shadow/intelligence/runs/{id}/replay` repeats the frozen pipeline and
compares the full result digest. Replay uses captured originals and weights,
so later retention or live model/rule edits cannot change its input. Current
requester and policy/model-owner grants, snapshot/result integrity, and pinned
implementation digests remain mandatory.

The result includes the exact tested capabilities. This evaluator does not
invent legacy finding/UEBA signals, execute operational Case merging, send
responses, or claim sensor/OS reproduction. CPU predictions describe deviation
from the training distribution, not a calibrated malicious probability.

## Frozen CPU sequence model extension

The same endpoint accepts `baseline_sequence_model_id` and
`candidate_sequence_model_id`. Optional `sequence_windows` is a list of at most
32 objects containing only `event_ids` (2..32 IDs each). No feature vectors,
labels, model code, or weights are accepted from this request. Otherwise windows
use the frozen indexing order within exact source/version/index, reported
host/device/boot and user/session/container/namespace context, in chunks of 12; final partial windows
require at least three originals. Strictly increasing reported time is required.
The frozen event cohort remains limited to 1,000 originals when any model is
requested. The job records evaluated windows and unselected/unusable original
IDs instead of implying every original received a sequence prediction.

The server captures the visible model's immutable definition and JSON GRU
weights, thresholds, feature contract/implementation digests, source contexts,
owner and any existing independent reviewer. Candidate visibility does not
activate a model. Captured originals supply real `[batch,time,55]` inputs to the
bounded trusted CPU evaluator; padding uses the model's length mask. No live
sequence model pointer, inference row, signal, Story, Case, hold or response is
written. Replay uses the captured weights and originals, while current complete
requester/model/source-owner/reviewer scope and evaluator integrity are checked.
Successful sequence jobs must fully execute on replay; exclusions remain pinned.
The frozen engine also pins the actual GRU worker file, CPU resource-limit
and immutable model-decode/memo implementation, canonical serialization/storage and manifest implementation,
plus Python implementation/version. A change to one of these files rejects
replay before feature comparison or CPU execution. Existing capsules remain
readable; capsules captured under a different engine require a new comparison
and are never silently reinterpreted or rewritten.

Stored composites retain server-generated `input_models` revision/model/feature
pins in addition to `input_revisions`. Caller definitions cannot supply internal
pins. Frozen candidates derive them from authorized model snapshots and emitted
model signals must match the exact pinned revision and model digest. This is a
bounded deterministic model/evidence comparison; it does not reproduce native
sensor losses, live Case decisions, responses, or a large production deployment.

Live composite execution now captures prequalified input/scope rows in durable
pages and searches indexed join partitions with resumable DFS bookmarks. Its
former global 2,000-row ceiling does not apply. This does not expand the separate
pure Shadow budgets documented above: a Shadow request that exceeds its fixed
window, combination or byte budget still fails without partial success.

Live candidate expiry can be deferred by scoped unfinished SERVER admission
work and new delayed-derived signals' exact receipt ancestry, including the
final-input gap after queues drain. A reported ancient event timestamp does not
extend it. This live scheduler watermark never substitutes for frozen Shadow
event-window coherence or reads a current live queue during deterministic
comparison/replay. Original scope, receipt, source and current model/reviewer
checks remain mandatory. The live cutoff and durable cohort protect ancestry
against capacity cleanup until completion; ordinary TTL resumes once no related
unfinished work or new inputs remain, independently of Case/hold/model refs.
