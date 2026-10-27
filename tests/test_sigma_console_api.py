"""Sigma console contracts use the current principal and actual optional parser."""

from test_enterprise_api import client, login, success  # noqa: F401 - shared HTTP fixture.

from sapientia import sigma_backend


def sample():
    return {
        "profile": "pysigma-json-v3",
        "rule": {
            "title": "PowerShell encoded command mapping example",
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "process": {"Image|endswith": "\\powershell.exe"},
                "command": {"CommandLine|contains": ["-enc", "-EncodedCommand"]},
                "condition": "process and command",
            },
        },
        "field_mapping": {"Image": "raw.process_path", "CommandLine": "raw.command_line"},
        "logsource_mapping": {
            "category": {"field": "sourcetype", "value": "process"},
            "product": {"field": "raw.platform", "value": "windows"},
        },
    }


def test_sigma_status_authentication_viewer_and_existing_preview_roles(client):
    assert client.get("/api/content/sigma/status").status_code == 401
    login(client, "viewer_a")
    value = success(client.get("/api/content/sigma/status"))
    assert value["profile"] == sigma_backend.PROFILE
    assert value["available"] == sigma_backend.status()["available"]
    assert value["general_sigma_backend"] is False
    assert value["preview_only"] is True
    assert value["supported_modifiers"] == sorted(sigma_backend.MODIFIERS)
    assert value["limits"]["input_bytes"] == 65536
    assert client.post("/api/content/sigma/preview", json=sample()).status_code == 403


def test_sigma_console_sample_uses_actual_parser_or_honest_unavailable(client):
    login(client, "analyst_a")
    with client.app.state.store.control() as db:
        before = db.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
    response = client.post("/api/content/sigma/preview", json=sample())
    if sigma_backend.status()["available"]:
        value = success(response)
        assert value["query_only"] is True
        assert value["profile"] == "pysigma-json-v3"
        assert value["semantic_ir"]["version"] == 3
        assert value["upstream"]["version"]
        assert "raw.process_path" in value["query"]["query"]
        assert value["limitations"]
    else:
        assert response.status_code == 400, response.text
        assert "pySigma runtime unavailable" in response.text
    # Converting a rule does not publish a policy or trigger endpoint actions.
    with client.app.state.store.control() as db:
        assert db.execute("SELECT COUNT(*) FROM audit").fetchone()[0] == before


def test_sigma_console_rejects_missing_scope_unsupported_and_execution_fields(client):
    login(client, "analyst_a")
    no_mapping = sample()
    no_mapping["logsource_mapping"] = {}
    unsupported = sample()
    unsupported["rule"]["detection"]["command"] = {"CommandLine|base64offset": "payload"}
    executable = {**sample(), "execute": True}
    for body in [no_mapping, unsupported, executable, []]:
        response = client.post("/api/content/sigma/preview", json=body)
        assert response.status_code == 400, response.text
