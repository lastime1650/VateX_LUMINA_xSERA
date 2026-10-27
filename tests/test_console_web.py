"""Entrypoint assets must load under the application's actual browser policy."""

import argparse
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from fastapi.testclient import TestClient

from sapientia.api import create_app
from sapientia.storage import Settings
from tools import qa_console_server


class Entrypoint(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.assets = []
        self.ids = {}
        self.inline_handlers = []
        self.inline_scripts = []
        self.in_script = False
        self.feed(source)

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if attrs.get("id"):
            self.ids[attrs["id"]] = attrs
        self.inline_handlers.extend(key for key in attrs if key.startswith("on"))
        if tag == "script":
            self.in_script = True
            assert attrs.get("src"), "Strict script CSP requires external scripts"
            assert "defer" in attrs, "Modules must register before DOMContentLoaded"
            self.assets.append((attrs["src"], "javascript"))
        elif tag == "link" and attrs.get("rel") == "stylesheet":
            self.assets.append((attrs["href"], "css"))

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_script = False

    def handle_data(self, data):
        if self.in_script and data.strip():
            self.inline_scripts.append(data)


@pytest.fixture
def client(tmp_path):
    app = create_app(Settings(tmp_path, min_free_bytes=0), background=False)
    with TestClient(app) as client:
        yield client


def test_console_entrypoint_assets_load_with_strict_same_origin_script_policy(client):
    response = client.get("/")
    assert response.status_code == 200
    document = Entrypoint(response.text)
    assert document.assets and len(document.assets) == len(set(document.assets))
    assert not document.inline_handlers and not document.inline_scripts
    policy = response.headers["content-security-policy"]
    assert "script-src 'self'" in policy
    assert "frame-ancestors 'none'" in policy
    assert "base-uri 'none'" in policy
    for path, media_type in document.assets:
        address = urlsplit(path)
        assert not address.scheme and not address.netloc
        assert path.startswith("/static/") and ".." not in address.path.split("/")
        asset = client.get(path)
        assert asset.status_code == 200, f"Entrypoint dependency missing: {path}"
        assert media_type in asset.headers["content-type"]
        assert asset.content.strip()
        assert asset.headers["x-content-type-options"] == "nosniff"


def test_anonymous_console_does_not_render_authenticated_workspace_or_execute_api(
    client,
):
    response = client.get("/")
    document = Entrypoint(response.text)
    assert "hidden" in document.ids["shell"]
    assert "hidden" in document.ids["auth"]
    assert document.ids["identity"].get("value") is None
    assert document.ids["tenant"].get("value") is None
    for path in ("/api/console/summary", "/api/xdr/status", "/api/entities"):
        assert client.get(path).status_code == 401


@pytest.mark.parametrize("role", ["admin", "viewer"])
def test_explicit_qa_launcher_seeds_before_runtime_and_retains_real_role(
    tmp_path, monkeypatch, role
):
    monkeypatch.delenv("SAPIENTIA_XDR_CONFIG", raising=False)
    monkeypatch.setattr(
        qa_console_server.tempfile, "mkdtemp", lambda prefix: str(tmp_path)
    )
    app, details = qa_console_server.build(role)
    assert Path(details["directory"]) == tmp_path
    assert (tmp_path / ".qa-synthetic-only").is_file()
    assert app.state.runtime.thread is None
    assert not app.state.xdr_bridge.status()["configured"]
    with TestClient(app) as client:
        login = client.post(
            "/api/login",
            json={"name": details["name"], "password": details["password"]},
        )
        assert login.status_code == 200 and login.json()["role"] == role
        result = client.get("/api/console/summary")
        assert result.status_code == 200, result.text
        assert result.json()["telemetry"]["event_count"] == 618
        assert result.json()["cases"]["total"] == 1
        assert not client.get("/api/xdr/status").json()["containment_enabled"]
    assert app.state.store.closed


def test_qa_launcher_rejects_live_service_port():
    assert qa_console_server.qa_port("8788") == 8788
    with pytest.raises(argparse.ArgumentTypeError):
        qa_console_server.qa_port("8787")
