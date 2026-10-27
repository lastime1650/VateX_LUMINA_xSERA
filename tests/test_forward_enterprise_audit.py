"""CLI authentication, fixed server routes and nonsecret output."""

import argparse
import json

import pytest

from tools import forward_enterprise_audit as cli


@pytest.mark.parametrize("value", ["http://192.0.2.1", "http://localhost", "https://user:password@example.invalid", "https://example.invalid/private", "https://example.invalid#token", "https://example.invalid?a=token", "https://example.invalid\\private", " https://example.invalid"])
def test_cli_refuses_url_credentials_unverified_http_and_ambiguous_paths(value):
    with pytest.raises(argparse.ArgumentTypeError):
        cli.server_url(value)


def test_cli_keeps_session_secrets_in_memory_and_uses_exact_collector_route(monkeypatch, capsys):
    calls = []
    secret = "synthetic-cli-password-only"
    monkeypatch.setenv("XSERA_AUDIT_PASSWORD", secret)
    class Response:
        def __init__(self, value):
            self.value = value
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return None
        def read(self, maximum):
            return json.dumps(self.value).encode()
    class Opener:
        def open(self, request, timeout):
            calls.append(request)
            if request.full_url.endswith("/api/login"):
                assert json.loads(request.data)["password"] == secret
                return Response({"csrf": "synthetic-csrf-only"})
            if request.full_url.endswith("/collector/collect"):
                data = json.loads(request.data)
                assert data["checkpoint_version"] == 4 and data["source_version"] == 2 and data["content_type"] is None
                return Response({"status": "completed", "complete": True, "durable_records": 2, "cloud_live_tested": False})
            if request.full_url.endswith("/collector"):
                return Response({"available": True, "source_version": 2, "checkpoint_version": 4, "product": "entra_signin"})
            assert request.full_url.endswith("/api/logout")
            return Response({"ok": True})
    monkeypatch.setattr(cli.urllib.request, "build_opener", lambda *handlers: Opener())
    assert cli.main(["--server", "http://127.0.0.1:8000", "--source", "registered-source", "--username", "admin"]) == 0
    output = capsys.readouterr().out
    assert secret not in output and "synthetic-csrf-only" not in output
    assert json.loads(output)["durable_records"] == 2
    assert [request.get_method() for request in calls] == ["POST", "GET", "POST", "POST"]
    assert calls[2].full_url == "http://127.0.0.1:8000/api/ops/enterprise/sources/registered-source/collector/collect"
