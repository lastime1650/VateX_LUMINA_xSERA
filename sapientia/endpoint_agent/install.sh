#!/usr/bin/env bash
set -euo pipefail
[[ "${EUID}" -eq 0 ]] || { echo 'Run as root' >&2; exit 1; }
base="$(cd "$(dirname "$0")" && pwd)"
python_bin="${SERA_PYTHON:-/usr/bin/python3}"
[[ "$python_bin" == /usr/bin/python3 ]] || { echo 'Service installation requires /usr/bin/python3; custom runtime supervision must be configured explicitly' >&2; exit 2; }
deployment="${1:-$base/deployment.json}"
token_file="${2:-$base/enrollment.token}"
ca_file="${3:-$base/ca.pem}"
resume="${4:-}"
# The fixed system runtime and ancestors must be root-owned and non-writable.
runtime="$(readlink -f -- "$python_bin")"
ancestor="$runtime"
while [[ "$ancestor" != / ]]; do
    [[ "$(stat -c %u -- "$ancestor")" == 0 ]] || { echo 'Untrusted Python runtime ownership' >&2; exit 2; }
    mode="$(stat -c %a -- "$ancestor")"
    (( (8#$mode & 8#022) == 0 )) || { echo 'Python runtime path is writable by non-root' >&2; exit 2; }
    ancestor="$(dirname -- "$ancestor")"
done
"$python_bin" -I -B -c 'import sys; assert sys.version_info >= (3,10), "Python 3.10+ required"'
[[ "${SERA_AGENT_REQUIRE_SIGNED_PACKAGE:-1}" == 1 ]] || { echo 'Production installation cannot disable package signatures' >&2; exit 2; }
trust_file="${SERA_AGENT_TRUSTED_KEYS_FILE:-}"
[[ "$trust_file" == /* && -f "$trust_file" && ! -L "$trust_file" ]] || { echo 'An externally provisioned absolute public trust file is required' >&2; exit 2; }
for entry in "$trust_file" "$(dirname -- "$trust_file")"; do
    [[ "$(stat -c %u -- "$entry")" == 0 ]] || { echo 'External trust must be root-owned' >&2; exit 2; }
    mode="$(stat -c %a -- "$entry")"
    (( (8#$mode & 8#022) == 0 )) || { echo 'External trust must not be writable by non-root' >&2; exit 2; }
done
export SERA_AGENT_REQUIRE_SIGNED_PACKAGE=1
"$python_bin" -I -B -c 'import cryptography, defusedxml; from importlib.metadata import version; from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey; assert version("cryptography") == "50.0.2" and version("defusedxml") == "0.7.1", "Pinned production prerequisites required: Agent/requirements.txt"'
"$python_bin" -I -B "$base/verify_package.py"
[[ -f "$deployment" && -f "$token_file" && -f "$ca_file" ]] || { echo 'Scoped deployment JSON, token file and CA required; generic ZIP contains none' >&2; exit 2; }
[[ ! -L /opt/vatex-lumina-xsera-agent ]] || { echo 'Installation symlink rejected' >&2; exit 2; }
if [[ -e /opt/vatex-lumina-xsera-agent ]]; then
    [[ "$resume" == --resume-enrollment && ! -e /opt/vatex-lumina-xsera-agent/config.json ]] || { echo 'Existing install preserved; incomplete enrollment requires --resume-enrollment as fourth argument' >&2; exit 2; }
    [[ "$(stat -c %u /opt/vatex-lumina-xsera-agent)" == 0 ]] || { echo 'Untrusted existing installation' >&2; exit 2; }
fi
command -v systemctl >/dev/null || { echo 'systemd is required' >&2; exit 2; }
[[ ! -e /etc/systemd/system/vatex-lumina-xsera-agent.service ]] || { echo 'Existing service preserved' >&2; exit 2; }
install -d -m 0700 /opt/vatex-lumina-xsera-agent
cp -R -- "$base/Agent" /opt/vatex-lumina-xsera-agent/Agent
install -m 0600 "$base/manifest.json" /opt/vatex-lumina-xsera-agent/manifest.json
install -m 0600 "$base/configure.py" /opt/vatex-lumina-xsera-agent/configure.py
"$python_bin" -I -B /opt/vatex-lumina-xsera-agent/configure.py --directory /opt/vatex-lumina-xsera-agent --deployment "$deployment" --token-file "$token_file" --ca-file "$ca_file"
# Use a fixed system executable in the service, never shell interpolation of a caller's path.
cat > /etc/systemd/system/vatex-lumina-xsera-agent.service <<'UNIT'
[Unit]
Description=Vatex LUMINA xSERA Endpoint Agent
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
WorkingDirectory=/opt/vatex-lumina-xsera-agent
ExecStart=/usr/bin/python3 -I -B /opt/vatex-lumina-xsera-agent/Agent/Linux/main.py run --config /opt/vatex-lumina-xsera-agent/config.json
Restart=on-failure
RestartSec=10
UMask=0077
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 /etc/systemd/system/vatex-lumina-xsera-agent.service
systemctl daemon-reload
systemctl enable --now vatex-lumina-xsera-agent.service
rm -f -- "$token_file"
echo 'Installed vatex-lumina-xsera-agent.service. Existing auditd/journal access is used; no audit rules, kernel/eBPF module, remote shell or isolation was installed.'
