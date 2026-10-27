@echo off
cd /d "%~dp0"
if errorlevel 1 exit /b 1
set "XseraLocalPython=%~dp0.venv\Scripts\python.exe"
if not exist "%XseraLocalPython%" (
  echo Required local Python runtime is missing.
  exit /b 1
)
"%XseraLocalPython%" -m tools.configure_loopback_tls "%~dp0private\loopback-tls" --repair-strict
if errorlevel 1 exit /b 1
set "SAPIENTIA_AGENT_ENDPOINT_URL=https://127.0.0.1:8788"
set "SAPIENTIA_AGENT_CA_FILE=%~dp0private\loopback-tls\ca.pem"
set "SAPIENTIA_BLOCK_NATIVE_RESPONSE=1"
"%XseraLocalPython%" -m sapientia --data "%~dp0data" serve --host 127.0.0.1 --port 8787 --agent-port 8788 --agent-cert "%~dp0private\loopback-tls\server.pem" --agent-key "%~dp0private\loopback-tls\server.key"
exit /b %errorlevel%
