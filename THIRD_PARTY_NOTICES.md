# xSERA third-party notices

Project-owned source and original XDR_V2 rules are licensed under Apache-2.0;
see `LICENSE` and `NOTICE`. This statement does not change the licenses of the
third-party content below. Preserve the original notices embedded in each file.
This inventory records sources and applicable notices, not an independent legal
opinion or a promise that an arbitrary appliance image may be redistributed.

## Project-owned detection rules

The original four XDR_V2 JSON packs contain 950 rules (100 + 200 + 600 + 50).
On 2026-10-16, the human project user directly declared ownership of copyright
and redistribution rights for these rules, requested entire-source open
distribution, and selected Apache-2.0. We record that declaration in
`sapientia/catalogs/provenance.json`; we did not independently investigate title.
The original rule files and their SHA256 values remain unchanged. Project-authored
additional rules use Apache-2.0. This declaration excludes third-party material.
The human user separately confirmed copyright and public Apache-2.0 licensing
rights for the original AEGIS/XDR_V2 agent code. Its original origin/history and
the direct declaration are recorded in `sapientia/endpoint_agent/PROVENANCE.json`.
This confirmation does not relicense agent dependencies or external SDKs.

## Content included in the source and Python package

| Content | Upstream revision | Original license and retained text |
| --- | --- | --- |
| MITRE ATT&CK Enterprise v19.2 snapshot | Pinned file SHA256 in `sapientia/catalogs/provenance.json` | MITRE ATT&CK terms, `sapientia/catalogs/LICENSE-MITRE.txt` |
| Neo23x0/signature-base YARA, 547 files / 1,760 definitions | `94a1c48d7ab499879287ff611dfe7f9c56376030` | Detection Rule License 1.1, `sapientia/catalogs/yara/licenses/signature_base-LICENSE.txt` |
| ReversingLabs YARA, 289 files / 289 definitions | `e0a0be54aa1e11ccfd6854e4f19e9476f328fd84` | MIT, `sapientia/catalogs/yara/licenses/reversinglabs-LICENSE.txt` |
| bartblaze YARA, 82 files / 95 definitions | `5cc871d82361de8a80d387ec8bbd01fe4258b4a9` | MIT, `sapientia/catalogs/yara/licenses/bartblaze-LICENSE.txt` |
| JPCERT/CC YARA, 73 files / 141 definitions | `7837438e7bcb100bcc7f9d2be09152b19d967c0c` | BSD-3-Clause, `sapientia/catalogs/yara/licenses/jpcert-LICENSE.txt` |
| Mandiant capa-rules, 1,042 YAML rules | `2af9fbfc1c9b4634dbeb76b5d34fca9389fa7f80` | Apache-2.0, `sapientia/catalogs/capa/LICENSE.txt` |

YARA totals are 991 files / 2,285 definitions, including nine private helper
definitions (2,276 public). Counts describe content, not measured detection
accuracy. Exact authors, repositories, rule URLs, commits, license URLs, source
hashes and filtering decisions are retained in `sapientia/catalogs/yara/manifest.json`.
The capa manifest retains every distributed rule path, byte length and SHA256.
The aggregate `sapientia/catalogs/third_party_manifest.json` points to those
unchanged source manifests and license texts. Embedded author/copyright notices
are authoritative; the project does not claim authorship of those rules.

DRL 1.1 requires retention of supplied author attribution in messages based on
matches. YARA run results and signal notice bundles preserve attribution for all
reported matches, including matches beyond the 32-row signal preview. Case
evidence and exports retain these notices from exact persisted run ancestry.
If the bounded engine output omits matches, coverage is explicitly incomplete;
the system does not silently describe that result as complete.

Sources: [signature-base](https://github.com/Neo23x0/signature-base),
[ReversingLabs](https://github.com/reversinglabs/reversinglabs-yara-rules),
[bartblaze](https://github.com/bartblaze/Yara-rules),
[JPCERT/CC](https://github.com/JPCERTCC/jpcert-yara),
[capa-rules](https://github.com/mandiant/capa-rules),
[MITRE ATT&CK](https://attack.mitre.org/resources/terms-of-use/).

## Installed dependencies and optional runtimes

The source archive and application wheel do not contain the project's virtual
environments or installed dependency distributions. The release SBOM identifies
the installed dependency scope separately from the files actually distributed.
Installing a dependency does not relicense it under the project's Apache license.
Preserve each dependency's license files and notices when constructing an offline
dependency bundle, container, appliance or OS image.

| Component | Observed or supported version | Terms / distribution scope |
| --- | --- | --- |
| yara-python | 4.5.4 | Apache-2.0; separately installed analysis extra; YARA rule licenses are separate |
| pySigma | 2.0.1 | **LGPL-2.1-only** in installed distribution metadata and license text; optional converter, not the license of imported Sigma rules |
| PyYAML | 6.0.3 | MIT; optional Sigma YAML input dependency |
| defusedxml | 0.7.1 | Python Software Foundation License (PSFL in installed metadata); separately installed dependency |
| flare-capa | 9.4.0 | Apache-2.0; separately installed optional runtime; bundled capa rules listed above |
| flare-floss | 3.1.1 | Apache-2.0; separately installed optional runtime |
| speakeasy-emulator | 1.5.11 | MIT; separately installed optional emulation runtime and its own dependencies |
| ClamAV | Operator-selected local service | Upstream GNU GPL version 2 COPYING and component notices; program, signatures and database distribution require their own review; not bundled |
| CAPEv2 | Operator-selected local service | GPL-3.0 program; signatures, dependencies and guest OS licenses remain separate; not bundled |
| NATS client nats-py | 2.16.0 observed | Apache-2.0; separately installed dependency |
| NATS server vendor directory | 2.15.0 provenance record | Apache-2.0 text at `vendor/nats/LICENSE`; source archive policy excludes the local executable and executable archives |

Local CAPE/ClamAV protocol fixtures are not proof that those services or their
databases are installed. Process isolation and HTTP integration are operational
boundaries, not automatic exemption from license obligations. No CAPE guest OS,
VM image, malware sample, FLIRT database, ClamAV signature database, paid rule
subscription or academic-only implementation is included by this project.

Upstream program terms: [pySigma 2.0.1](https://github.com/SigmaHQ/pySigma/blob/v2.0.1/LICENSE),
[capa](https://github.com/mandiant/capa),
[FLOSS](https://github.com/mandiant/flare-floss),
[Speakeasy](https://github.com/mandiant/speakeasy),
[ClamAV](https://github.com/Cisco-Talos/clamav/blob/main/COPYING.txt),
[CAPE](https://github.com/kevoreilly/CAPEv2/blob/master/LICENSE),
[NATS](https://github.com/nats-io/nats-server).

## Sigma and operator imports

No external SigmaHQ rule corpus is bundled. The project includes its own small
examples and a converter. Imported JSON/YAML source is retained byte-for-byte by
SHA256; author, license and references are copied into the converted revision's
reviewed snapshot and server-derived signal notices. A missing license is
`unspecified`, not Apache-2.0 or assumed permission. Legacy YAML revisions whose
metadata was not extracted retain their original source; the system reports that
limitation without requiring optional parsers for native runtime execution.

Independent technical review/activation approves the tested detection revision.
It does not establish copyright ownership or permission to redistribute an
operator's imported rules. Before redistributing additional rule packs, signatures,
dependencies or images, retain their exact original licenses and review the actual
distribution and any required corresponding-source obligations.
