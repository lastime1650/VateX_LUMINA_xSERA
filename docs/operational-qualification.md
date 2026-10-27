# Reviewed operational qualification

The operational console/API runs evidence-producing software rehearsals in new
temporary Stores. It never promotes a production passive server or dispatches
an endpoint command. An active tenant administrator creates a plan with exact
indexes; a different current administrator reviews its exact revision. Editing
invalidates review. Owner, editor, reviewer and caller permissions are checked
again at execution and before recording a qualified outcome. A revoked or
changed approval produces an `authority_changed` receipt with `qualified=false`.

`/api/ops/qualification/plans` accepts `name`, `indexes`, `kind`, and
`expected_revision`. The kinds are `response_twin`, `recovery_process`, and
`integrity_bootstrap`. Review uses `/plans/{id}/review` with `approve`, `reason`,
and `expected_revision`; execution uses `/plans/{id}/run` with only
`expected_revision`. Results and content digests remain in `/runs/{id}` and the
tenant audit. Only one bounded rehearsal runs at once. No command, target path,
remote endpoint or key material can be supplied through these APIs.

## Response and process evidence

The response twin uses the existing Case/evidence-bound prepare, independent
approval, dispatch and receipt mechanism in a disposable simulation Store. It
checks durable isolation state, a deliberately finite five-second real-time
lease, reopening the Store, and a separately approved exact-owned release of a
synthetic false positive. The management-channel check is an explicit digital
twin policy assertion; it does not test an OS firewall or real packets. Physical
OS reboot and real endpoint recovery remain unavailable. Native response rows
and native host effects must both remain zero.

The recovery process probe creates only its own Python child processes. An
active process owns the actual Store lock, a second process must be refused,
and an owned active process is terminated before the passive process reopens
the Store and verifies its durable original. A real online snapshot is then
taken. An intentionally incompatible future migration is rejected by the real
startup schema fence, the snapshot is restored to a new directory, and a new
process verifies the restored original. All owned children are stopped before
temporary data cleanup. These checks qualify single-machine software contracts;
they do not implement distributed consensus, shared-disk fencing, multi-server
automatic promotion, power-loss recovery, or production software replacement.

## Package signatures and trust bootstrap

Provision an Ed25519 PKCS8 PEM private key outside the downloaded Agent archive
and outside any web-served directory. Set the service environment variable
`SAPIENTIA_AGENT_SIGNING_KEY_FILE` to that protected file. The server signs the
canonical complete manifest, which contains the exact package member hashes.
No endpoint can upload a signer key or change its path. Keep the key backed up
and protected by the deployment account/OS permissions.

An `integrity_bootstrap` plan pins the currently configured signer's public-key
fingerprint. A different administrator approves that exact plan. Successful
execution exports a **public** trust document in the run result; the private key
and its path never appear in the result. Changing the configured key requires
a new plan and independent approval. Independently verify the exported public
fingerprint through a trusted channel and provision the public trust file
outside the extracted package and installation directory. Export does not
automatically install or trust it on any host.

For a required signed Agent installation, set these local installer variables:

```text
SERA_AGENT_TRUSTED_KEYS_FILE=<protected external public trust JSON>
SERA_AGENT_REQUIRE_SIGNED_PACKAGE=1
```

The installer preserves `manifest.json`; configuration persists the local trust
file location and required mode. Startup verifies the pinned Ed25519 signature
and installed Agent member hashes before Agent initialization. Heartbeats
repeat the measurement and report the manifest digest, signing key ID, measured
member count, release and state. Required verification failure refuses startup;
later failure is reported as degraded integrity. Default legacy installations
without a trust configuration remain explicitly `checksum_only` or
`unavailable`; they never claim a trusted signature. Ed25519 verification needs
the local `cryptography` Python dependency; required mode refuses startup when
it is unavailable. No installer or native OS service was executed during the
software qualification.

This is application manifest authentication, **not** Authenticode, an OS vendor
certificate, Secure Boot, or hardware remote attestation. The initial verifier,
Python runtime and local trust file must themselves be independently trusted
and protected. A compromised privileged runtime can forge local measurements.
An application signing key authenticates bytes and does not by itself establish
release freshness; operator-controlled release approval and rollback policy
remain necessary. Removing a signer from local trust requires operator
provisioning; exporting a new document does not silently replace existing trust.

## Delivery SLO measurements

`PUT /api/ops/source-slo/{source_id}` configures an exact current source version,
paired `sequence_path`/`epoch_path` (or both null), a silence budget and gap/drop
budgets. The sequence paths must address bounded raw scalar fields. It is an
explicit source contract, not inference from arbitrary event IDs. A new policy
revision starts a new measurement epoch; lifetime server receipt totals remain
separate. Changing a source version requires a new policy revision.

The admission hook counts only newly committed source receipts, using the
actual post-pipeline durable payload in the same transaction. A failed admission
or checkpoint transaction does not increment counters. Exact retry pages do not
increment them. Sequence discontinuities are provisional missing numbers; late
originals fill them. The first observed sequence establishes a boundary, so no
unobserved prefix is guessed. Missing/invalid sequence fields, more than sixteen
epochs, or more than 128 unresolved gap ranges per epoch produce explicit
coverage failure. Sequence replay with a new original is counted separately.

`GET /api/ops/source-slo` reports receipt count, last received time, silence,
provisional gaps and coverage diagnostics. Sensor `captured`/`dropped` counters
remain separately marked reports, with their origin mode and report time. They
are not independently verified loss measurements. Pre-capture loss, polling
blind spots, and loss in a source without a sequence contract remain unavailable,
never an invented zero. A gap-free observed stream is not proof that all real
events were captured.

Run the combined disposable HTTP qualification with:

```text
python -m tools.qualify_ops_hardening --output <external evidence JSON path>
```

The result contains actual reviewed HTTP workflow receipts, real elapsed lease
and source silence observations, owned process recovery outcomes, and a
disposable signed-package tamper check. It excludes passwords and private keys.
The disposable key is probe material, not a production trust bootstrap. Physical
devices, multi-server HA, physical reboot, code-signing certification and Yocto
BSP validation remain explicitly unqualified until separately executed.
