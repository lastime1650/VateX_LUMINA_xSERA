"""Qualification gates only; never invokes a native policy/compiler/executable."""

import hashlib
import io
import json
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from sapientia import agent_distribution
from tools import qualify_windows_kernel as module
from tests.signing_support import release_signer  # noqa: F401

pytestmark = pytest.mark.usefixtures("release_signer")


def bound_package():
    return agent_distribution.package(
        "windows",
        {
            "tenant": "qa-fixture",
            "host": "owned",
            "index_name": "endpoint",
            "expires": 1800000000,
        },
        "fixture-synthetic-credential-not-valid-for-any-service",
        {
            "endpoint_url": "https://127.0.0.1:18788",
            "ca_pem": b"fixture-public-ca-not-used-by-this-test",
        },
    )[0]


def rewrite(blob, mutation):
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        items = {name: archive.read(name) for name in archive.namelist()}
    manifest = json.loads(items.pop("manifest.json"))
    mutation(items, manifest)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, body in items.items():
            archive.writestr(name, body)
        archive.writestr("manifest.json", json.dumps(manifest))
    return output.getvalue()


def test_bound_enrollment_files_are_manifest_verified_before_configuration(tmp_path):
    manifest = module.verified_package(bound_package(), tmp_path)
    assert module.ENROLLMENT_FILES <= set(manifest["files"])
    assert all((tmp_path / name).is_file() for name in module.ENROLLMENT_FILES)
    assert (tmp_path / "Agent/windows_app_control.py").is_file()
    assert not (tmp_path / "state").exists()


def test_generic_unbound_runtime_is_rejected_before_configurator(tmp_path):
    generic = agent_distribution.package("windows")[0]
    with pytest.raises(PermissionError, match="manifest/member"):
        module.verified_package(generic, tmp_path)


@pytest.mark.parametrize("filename", ["deployment.json", "enrollment.token", "ca.pem"])
def test_missing_enrollment_member_rejected_even_if_manifest_is_rewritten(
    tmp_path, filename
):
    def remove(items, manifest):
        items.pop(filename)
        manifest["files"].pop(filename)

    with pytest.raises(PermissionError, match="manifest/member"):
        module.verified_package(rewrite(bound_package(), remove), tmp_path)


def test_stale_native_module_rejected_before_executable_effects(tmp_path):
    def stale(items, manifest):
        filename = "Agent/windows_app_control_watchdog.py"
        items[filename] += b"\n# stale candidate\n"
        manifest["files"][filename] = hashlib.sha256(items[filename]).hexdigest()

    with pytest.raises(PermissionError, match="currently reviewed"):
        module.verified_package(rewrite(bound_package(), stale), tmp_path)


@pytest.mark.parametrize("filename", ["../outside.py", "C:outside.py", "C:/outside.py"])
def test_manifest_cannot_authorize_member_escape(tmp_path, filename):
    def escaping(items, manifest):
        items[filename] = b"untrusted"
        manifest["files"][filename] = hashlib.sha256(b"untrusted").hexdigest()

    with pytest.raises(PermissionError):
        module.verified_package(rewrite(bound_package(), escaping), tmp_path)


def test_live_mutations_require_explicit_optin_before_trial_constructor(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(
        module,
        "Trial",
        lambda *_args: pytest.fail("Qualification constructed without explicit opt-in"),
    )
    with pytest.raises(SystemExit):
        module.main(
            [
                "--fixture",
                str(tmp_path / "unused.json"),
                "--output",
                str(tmp_path / "unused-output.json"),
            ]
        )


def session_client(status=200, principal="qa-admin"):
    client = SimpleNamespace(cookies={}, headers={}, calls=[])

    def get(path):
        client.calls.append(("GET", path))
        return SimpleNamespace(status_code=status, json=lambda: {"name": principal, "tenant": "qa-tenant"})

    def post(path, json):
        client.calls.append(("POST", path))
        client.cookies["fixture-cookie"] = "synthetic-not-an-authentication-token"
        return SimpleNamespace(status_code=200, json=lambda: {"csrf": "synthetic-csrf"})

    client.get, client.post = get, post
    return client


def test_private_qa_session_validated_before_reuse_without_additional_login(tmp_path):
    path = tmp_path / "sessions.json"
    person = {"username": "qa-admin", "password": "synthetic-unused", "tenant": "qa-tenant"}
    initial = session_client()
    module.qa_session(initial, person, "admin", path, "https://127.0.0.1:18788")
    assert initial.calls == [("POST", "/api/login")]
    cached = session_client()
    module.qa_session(cached, person, "admin", path, "https://127.0.0.1:18788")
    assert cached.calls == [("GET", "/api/me")]
    assert cached.headers["X-CSRF-Token"] == "synthetic-csrf"


def test_private_qa_session_cannot_reuse_wrong_tenant_or_principal(tmp_path):
    path = tmp_path / "sessions.json"
    person = {"username": "qa-admin", "password": "synthetic-unused", "tenant": "qa-tenant"}
    module.qa_session(session_client(), person, "admin", path, "https://127.0.0.1:18788")
    wrong = session_client(principal="different-principal")
    with pytest.raises(PermissionError, match="principal"):
        module.qa_session(wrong, person, "admin", path, "https://127.0.0.1:18788")
    assert wrong.calls == [("GET", "/api/me")]


def test_expired_private_qa_session_respects_normal_login_throttle(tmp_path):
    path = tmp_path / "sessions.json"
    person = {"username": "qa-admin", "password": "synthetic-unused", "tenant": "qa-tenant"}
    module.qa_session(session_client(), person, "admin", path, "https://127.0.0.1:18788")
    before = path.read_bytes()
    expired = session_client(status=401)

    def rejected(path, json):
        expired.calls.append(("POST", path))
        return SimpleNamespace(status_code=429)

    expired.post = rejected
    with pytest.raises(RuntimeError, match="429.*no retry"):
        module.qa_session(expired, person, "admin", path, "https://127.0.0.1:18788")
    assert expired.calls == [("GET", "/api/me"), ("POST", "/api/login")]
    assert not expired.cookies and "X-CSRF-Token" not in expired.headers
    assert path.read_bytes() == before


def test_private_qa_session_never_reuses_cache_for_another_endpoint(tmp_path):
    path = tmp_path / "sessions.json"
    person = {"username": "qa-admin", "password": "synthetic-unused", "tenant": "qa-tenant"}
    module.qa_session(session_client(), person, "admin", path, "https://127.0.0.1:18788")
    client = session_client()
    with pytest.raises(PermissionError, match="endpoint"):
        module.qa_session(client, person, "admin", path, "https://127.0.0.1:8788")
    assert not client.calls


def test_case_qualification_reads_actual_detection_version_before_owned_disable():
    trial = module.Trial.__new__(module.Trial)
    trial.directory, trial.host = Path("owned-fixture"), "QA-WINDOWS-OWNED"
    calls = []
    records = []

    def api(method, path, **kwargs):
        calls.append((method, path, kwargs))
        if path == "/api/detections/preview":
            return {"match_count": 1}
        if path == "/api/detections" and method == "POST":
            return {"id": "own-policy"}
        if path == "/api/detections" and method == "GET":
            return [{"id": "unrelated", "version": 99}, {"id": "own-policy", "version": 7}]
        if path == "/api/incidents":
            return [{"id": "own-case", "entity": trial.host}]
        if path == "/api/incidents/own-case/attack-context":
            return {"threat_score": 100, "severity": "critical"}
        if path == "/api/detections/own-policy" and method == "PATCH":
            assert kwargs["json"] == {"enabled": False, "version": 7}
            return {"updated": True}
        pytest.fail("Unexpected qualification API operation")

    trial.api = api
    trial.record = lambda name, **details: records.append((name, details))
    trial.case_flow()
    assert records[0][0] == "actual_native_ci_denial_to_detection_critical_case"
    assert calls[-1][:2] == ("PATCH", "/api/detections/own-policy")
