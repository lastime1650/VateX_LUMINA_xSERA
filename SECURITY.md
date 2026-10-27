# Security and release boundaries

The signed CPU observation distribution blocks native host response on the server
and ships endpoint mutation, isolation, kernel and emulation controls disabled.
Virtual response is an explicitly labelled simulation. Installing xSERA does not
authorize process termination, file deletion, firewall changes or driver loading.

Verify the release manifest with a separately trusted copy of
`tools/deploy_release.py`, trusted Python 3.12 and cryptography. Provision public
trust outside the download and installation; compare its fingerprint through an
independent trusted channel. Keep signing private keys outside application data
and downloads, with owner-only permissions. A key distributed with its own payload
does not authenticate that payload. Rotation requires provisioning the new trusted
public key before signing releases with it; revoked keys fail verification on the
next verification/start. A trusted minimum release sequence prevents downgrade.

Use TLS and explicit administrator enrollment; do not expose a development HTTP
console to the Internet. This source distribution provides no shared password,
production certificate, private key or sample malware. Restrict write access to
the installation, configuration, trust, Python runtime and data directory. These
signature checks do not protect an operating system already controlled by an
administrator-level attacker.

The offline installer stages separate code and data, verifies hashes and startup,
and commits one pointer. Stop the managed server before update. Activation refuses
when the prior data changed after its snapshot; rollback refuses to discard newly
accepted records. Preserve and reconcile those records before recovery. Keep an
independent tested backup; an atomic pointer is not distributed HA or a substitute
for a backup.

Release reports distinguish synthetic regression from field qualification. Real
sensors, platform services, long-running operational loads, identity providers,
physical response and VM containment require their own target-site
validation. Do not treat synthetic model accuracy as field detection accuracy.

For a vulnerability, contact the maintainer through the private security reporting
channel of the repository/distribution where this source was obtained. A public
contact address is not configured in this source tree. Do not post credentials,
customer telemetry, executable samples or working exploitation details publicly.
