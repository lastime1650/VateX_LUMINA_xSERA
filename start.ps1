$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$xseraPython = "$PSScriptRoot\.venv\Scripts\python.exe"
$xseraTLS = "$PSScriptRoot\private\loopback-tls"
& $xseraPython -m tools.configure_loopback_tls $xseraTLS --repair-strict
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$env:SAPIENTIA_AGENT_ENDPOINT_URL = 'https://127.0.0.1:8788'
$env:SAPIENTIA_AGENT_CA_FILE = "$xseraTLS\ca.pem"
$env:SAPIENTIA_BLOCK_NATIVE_RESPONSE = '1'
& $xseraPython -m sapientia --data "$PSScriptRoot\data" serve --host 127.0.0.1 --port 8787 --agent-port 8788 --agent-cert "$xseraTLS\server.pem" --agent-key "$xseraTLS\server.key"
exit $LASTEXITCODE
