# xSERA CPU ML runtime

## Implemented behavior

The optional CPU engine is a real PyTorch autoencoder, not a keyword score. It
learns a 7 → 6 → 3 → 6 → 7 reconstruction model with Adam and deterministic
initialization. Its outputs describe deviation from an explicitly reviewed
normal cohort. They are **not malicious probabilities or automatic response
authorization**. Common signals may use the anomaly, model digest, exact
original IDs and feature error breakdown as additional investigation evidence.

Training requires at least 16 explicitly selected persisted original event IDs
and 8 separate holdout IDs in exact authorized indexes. The operator explicitly
acknowledges reviewing the normal cohort. No attack labels or simulation
ground truth are model features. Holdout reconstruction errors calibrate the
threshold; this is not an independent malicious Precision/Recall benchmark.
Host/time/source leakage and normal training contamination still need an
independent operational evaluation before a production decision.

An independently authorized analyst or administrator, different from the
model creator, reviews and activates each immutable revision. Both the owner
and reviewer's current grants are rechecked for active inference. Rollback is
an explicit fresh peer review and activation of an older immutable revision.
Revoked users or reduced grants stop use of their model. Shadow inference can
evaluate a visible candidate without activation and must not issue a Case or
response. Model training never starts automatically.

## Feature contract

`xsera.cpu-features.v1` contains seven values bounded to [0, 1]:

| Feature | Definition |
|---|---|
| hour_sin, hour_cos | UTC event-time circular coordinates, shifted/scaled from [-1,1] |
| remote_port_scaled | Explicit destination port clamped to 0..65535, divided by 65535 |
| command_length_scaled | Explicit command string length clamped to 8192, divided by 8192 |
| network_external | Explicit destination IP is globally routable according to Python ipaddress |
| process_depth | Explicit source-provided depth clamped to 32, divided by 32; no inferred ancestry |
| file_activity | Explicit file path or explicit file action |

Missing optional features encode as zero; absence does not prove benignness.
Canonical security fields are preferred; structured vendor fields and explicit
`raw.xdr.data` process/destination/file/event values supply fallbacks. A parent
GUID does not invent process depth. Each inference lists missing source features.
The immutable model pins a feature-contract digest in addition to the schema;
a runtime with different extraction semantics rejects that model.
Reserved documentation IPs are not considered globally routable. The complete
original digest and source mapping version accompany feature provenance.
Event IDs are looked up again in the authorized persisted store: a caller cannot
replace the original with fabricated features. Training and inference snapshots
retain receipt, original, feature and model hashes. Corresponding original IDs
enter the existing evidence protection catalog.

`compatible_models` selects an active reviewed model covering every requested
exact index. The common-signal writer calls `validate_publication` inside its
reserved write transaction: model activation, independent review, current
grants, architecture/schema, immutable digest and exact revision are rechecked
after inference. A stale prediction cannot bypass a model disable or change.

Weights are small finite JSON arrays under a fixed architecture and a canonical
SHA-256 manifest. No pickle, torch.load, TorchScript, model plugins, arbitrary
file upload or model-supplied source code is executed. A digest detects accidental
or unauthorized content changes within the existing store; it is not a digital
signature independent of control DB access.

## Installation and limits

The base server imports no PyTorch. Optional CPU-only installation, in the
project's Python 3.12+ environment:

```text
python -m pip install torch==2.13.0+cpu --index-url https://download.pytorch.org/whl/cpu
```

Use the official [PyTorch CPU package index](https://download.pytorch.org/whl/cpu/torch/)
and [official installation guidance](https://pytorch.org/get-started/locally/).
The project optional extra is `ml-cpu`; use the explicit CPU index when building
an offline wheelhouse. The source tree was executed on Windows AMD64 with
Python 3.12 and PyTorch 2.13.0+cpu in the earlier release snapshot; CUDA runtime was absent. The current source includes later changes. This does not qualify
all Linux/ARM hardware combinations.

Both model families reuse one framed persistent subprocess using the same interpreter.
`CUDA_VISIBLE_DEVICES` is empty and every tensor/module explicitly uses CPU.
PyTorch intra/inter-op, MKL and OpenMP are limited to one thread. Training is
limited to 1000 training + 1000 holdout records and 120 epochs; inference is
limited to 1000 original IDs per call. JSON input/output is limited to 2 MiB.
The parent terminates training after 25 seconds and inference after 15 seconds;
status has a 30-second deadline. A per-process lock bounds concurrent CPU workers
to one; lock/pipe/frame handling share the operation's wall-clock deadline.
Malformed frames, child exits and deadlines retire the child before reuse.
The worker reloads only JSON weights, never executable model files.
Dataset and model dimensions bound tensor
allocation, but process memory needs an OS resource limit in an appliance.

`duration_ms` measures tensor execution; `worker_wall_ms` includes interpreter
and framework startup. Small batches can spend much more time importing the
framework than computing. Persistent framework reuse removes repeated startup
within the same server interpreter. Cold start, warm worker time and tensor
execution remain separate measured fields. Windows starts the current base
Python interpreter directly with the same environment's package paths, avoiding
the venv launcher's extra child process.

On Windows the owned worker is assigned, before its first request, to an
anonymous Job Object with a 2-GiB process/job committed-memory limit, one process,
kill-on-close and a hard CPU rate approximating one logical CPU. The tested
Windows host accepted all limits and real PyTorch execution under them.
If a host's existing job restrictions prevent assignment, runtime_limits
explicitly reports unsupported/partial enforcement; it does not claim success.
Linux applies an 8-GiB virtual-address RLIMIT_AS and a cumulative 1800-second
CPU limit in the child, in addition to the framework's one-thread limit.
This is not a 2-GiB Linux RSS cap or target-device qualification. A dedicated
service account, service/cgroup memory and CPU policy, and target-hardware
validation remain required for an appliance.

Missing, incompatible or failed PyTorch returns unavailable with
**시스템에서 호환되지 않음**. Traditional detection and simulation continue.
Deadline expiration is an explicit bounded-operation error. No fallback dummy
model masquerades as working AI.

## API

All routes require a current local user and tenant/index scope:

| Route | Purpose |
|---|---|
| GET /api/v3/ml/status | CPU framework smoke test/cached compatibility |
| GET /api/v3/ml/models | Visible immutable model revisions and validation metrics |
| POST /api/v3/ml/models | Train from name, indexes, training_ids, validation_ids, epochs, normal_training_confirmed |
| POST /api/v3/ml/models/{id}/activate | Independent review, body `{"notes":"..."}` |
| POST /api/v3/ml/models/{id}/rollback | Fresh peer review to reactivate an older revision |
| POST /api/v3/ml/models/{id}/disable | Explicitly stop active use |
| POST /api/v3/ml/models/{id}/infer | Authorized original event_ids, optional shadow boolean |

Current local user authentication is required; ingest credentials cannot train
or approve models. Immutable models, review history, inference records and audit
events are persisted in control.sqlite3 and follow existing backup policy.

## Ordered GRU sequence models

The optional sequence family is a real forward-only CPU GRU with 24 hidden
units. Input is a three-dimensional tensor [batch, time, feature], not a 3-D
visualization. Fifty-five label-free semantic and missingness values describe
reported event categories, command categories, authentication outcomes,
destination-port categories, network-byte magnitudes, file/DNS/registry/email/
cloud facts, UTC event time and relative time gaps. Source-provided identity
fields determine grouping but their identifier strings are not model features.

Each sequence contains 2..32 strictly increasing original event times under
one authenticated source revision, exact tenant/index, host ID/boot ID and
reported user/session/container/namespace identity when present. Missing
identities are not invented. The live scheduler uses fixed 12-event windows.
GRU packing excludes padded steps from recurrent state; explicit missingness
features distinguish absent source attributes from observed zero values.
Reported ordering does not prove sensor hardware attestation or causality.

Training takes an external reviewed manifest containing scenario IDs,
family/host groups, ordered original IDs and normal/attack labels. These fields
are never telemetry features. Original/scenario/family/host sets must be
disjoint across training, calibration and holdout; their actual time ranges
must also be disjoint and ordered. Manifest host groups must equal persisted
original hosts. Originals and current source authority are rechecked when
publishing the immutable candidate, after inference and before Signal use.
Up to 4096 total scenarios/two million feature values and 60 epochs are allowed;
sequence frames are at most 32 MiB with a 120-second training deadline.
Original queries use small batches respecting the Store's existing 2-MiB cap.

Composite validation can reuse decoded model JSON and its immutable hashes
inside one reserved write transaction. A separate bounded process LRU reuses
only hash-verified immutable model content across transactions after complete
fresh raw-row equality (model/tenant/creator/revision/scope/JSON/digest). Current
caller, creator, reviewer, active pointer, retirement and all registered source
grants/versions remain freshly checked on every hit; receipt or authorization
results are never cached. The opaque transaction memo still expires at its
boundary even when a SQLite connection is reused. Both content stores are
limited to 16 entries/32 MiB of serialized raw model JSON; decoded Python trees
have additional memory overhead. Cache statistics contain counts only, and
controlled cache clearing changes no model, grant, evidence or Store state.

Training chooses a candidate epoch by calibration loss and selects the winning
score partition by calibration F1/false-positive tie breaking. Its threshold is
the midpoint between the nearest predicted-negative/predicted-positive score
boundaries, preserving every calibration prediction while providing score
margin within that interval. Boundary/tied scores retain the winning cut when
no interior float is representable. This is a decision margin, not probability
calibration or evidence of resistance to real domain/time drift. Holdout inputs never enter the
training worker or choose weights/thresholds. Explicit evaluation refetches
frozen holdout originals and reports confusion counts, precision, recall, FPR
and F1, together with a separately trained unordered mean-feature baseline.
Reverse-order score sensitivity is an ablation diagnostic, not a new malware
ground-truth benchmark. Candidate activation requires a stored heldout assessment
and a different currently authorized reviewer. Rollback requires fresh review.

Scores are uncalibrated classifier outputs. They are not malicious probabilities
or endpoint-response permission. A balanced harmless synthetic benchmark does
not establish operational precision, unknown-threat recall, sensor loss,
training-poisoning resistance or long-term drift. Native device,
production EPS/latency and target-OS qualification remain separate work.

Public sequence API (current user and full declared index scope required):

| Route | Purpose |
|---|---|
| GET /api/v3/ml/sequences/models | Candidate/version inventory and stored assessment summaries |
| POST /api/v3/ml/sequences/models | Reviewed training/calibration/holdout manifests, name/indexes/epochs |
| POST /api/v3/ml/sequences/models/{id}/evaluate | Actual frozen independent holdout evaluation |
| GET /api/v3/ml/sequences/models/{id}/assessment | Read stored assessment without CPU work |
| POST /api/v3/ml/sequences/models/{id}/activate | Independent notes and current-grant activation |
| POST /api/v3/ml/sequences/models/{id}/rollback | Fresh independent rollback approval |
| POST /api/v3/ml/sequences/models/{id}/disable | Stop active use and queued stream processing |
| POST /api/v3/ml/sequences/models/{id}/infer | Ordered original-ID windows; optional shadow boolean |

Trusted frozen Shadow helpers validate captured model/feature digests and
evaluate captured original vectors through the same CPU implementation. They
exclude clocks/PIDs from replay result hashes and create no live run rows,
Case, response or evidence references. No public route accepts arbitrary tensors.

## Evidence payload archival and inactive model retirement

Permanent run rows and audit history have no lifetime count quota. Normal and
shadow inference payloads are temporary: after 24 hours or more than 128
unarchived payloads for the same model, bounded archival replaces normal result
details with count/digest summaries. Explicit scoped archival uses
POST /api/v3/ml/runs/archive with family, exact run IDs and notes.
Live anomaly results and original references remain protected. Overlapping
windows retain an original if any live anomaly uses it. Separate Case,
bookmark, model-training and pending-work references are never removed.
Archival only releases that run's temporary references; actual originals are
deleted solely by existing capacity cleanup, respecting permanent recording
and the production reserve policy.

An inactive model can be explicitly retired with
POST /api/v3/ml/models/{family}/{id}/retire, where family is autoencoder or
sequence. A different current reviewer with complete model scope must approve
notes; active pointers, pending/running bound work and immutable hashes are
checked in one transaction. Weights, dataset provenance, digest, assessment
and audit rows remain readable. Only that version's training references are
released; other model/Case/anomaly/queue references continue protection.
Retired versions cannot be activated or inferred, including the ordinary
shadow API. Existing trusted frozen replay capsules remain independent
historical comparison artifacts and create no live effects.
