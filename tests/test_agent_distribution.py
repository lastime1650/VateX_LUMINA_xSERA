"""Real downloadable member checks, credential isolation, ACL and TLS boundaries."""

import copy
import hashlib
import importlib.util
import io
import json
import shutil
import subprocess
import sys
import threading
import zipfile
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from sapientia import access, auth, pipeline
from sapientia import agent_distribution as ad
from sapientia.api import create_app
from sapientia.storage import ConflictError, Settings, Store
from tests.signing_support import (
    release_signer,  # noqa: F401 -- Module explicitly requests this fixture.
)
from tests.test_xdr_bridge import PASSWORD, actor, event
from tools.qualification import certificate

pytestmark = pytest.mark.usefixtures("release_signer")


@pytest.fixture
def source_store(tmp_path):
    store = Store(Settings(tmp_path / "store", min_free_bytes=0))
    for name, tenant, role in (
        ("admin_a", "a", "admin"),
        ("admin_b", "b", "admin"),
        ("admin_other", "a", "admin"),
        ("analyst_a", "a", "analyst"),
        ("viewer_a", "a", "viewer"),
    ):
        auth.create_user(store, name, PASSWORD, role, tenant)
    yield store
    store.close()


@pytest.fixture
def config(tmp_path, release_signer):  # noqa: F811 -- Explicit signing prerequisite follows imported fixture users.
    cert, _ = certificate(tmp_path)
    return {"endpoint_url": "https://127.0.0.1:8788", "ca_pem": cert.read_bytes()}


def deployed(service, who=None, platform="windows", host="HOST-01", index="endpoint"):
    who = who or actor()
    item = service.create(who, {"platform": platform, "host": host, "index": index})
    blob, digest, _ = service.download(who, item["id"])
    assert hashlib.sha256(blob).hexdigest() == digest
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        token = archive.read("enrollment.token").decode()
    return item, token, blob


def enrolled(service, **kwargs):
    item, token, blob = deployed(service, **kwargs)
    identity = service.enroll({"enrollment_token": token, "version": "sera-agent/0.1"})
    return identity, item, token, blob


@pytest.mark.parametrize("platform", ["windows", "linux"])
def test_generic_package_deterministic_secret_free_valid_manifest(platform, tmp_path):
    first = ad.package(platform)
    second = ad.package(platform)
    assert first == second and first[2].endswith("-python.zip")
    with zipfile.ZipFile(io.BytesIO(first[0])) as archive:
        names = archive.namelist()
        assert not {"enrollment.token", "deployment.json", "ca.pem"} & set(names)
        assert not any(
            n.startswith("/") or ".." in n.split("/") or "\\" in n for n in names
        )
        assert len(names) == len(set(names))
        manifest = json.loads(archive.read("manifest.json"))
        assert set(names) == set(manifest["files"]) | {"manifest.json"}
        for name, digest in manifest["files"].items():
            assert hashlib.sha256(archive.read(name)).hexdigest() == digest
        archive.extractall(tmp_path / "package")
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(tmp_path / "package/verify_package.py")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    (tmp_path / "package/Agent/core.py").write_text("tampered", encoding="utf-8")
    assert (
        subprocess.run(
            [sys.executable, "-I", "-B", str(tmp_path / "package/verify_package.py")],
            capture_output=True,
            check=False,
        ).returncode
        != 0
    )


def test_scoped_package_no_broad_secret_and_download_rotation(source_store, config):
    service = ad.Distribution(source_store, config)
    item, first, blob = deployed(service)
    assert "token" not in json.dumps(item)
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        configfile = json.loads(archive.read("deployment.json"))
        assert configfile["host"] == "HOST-01" and configfile["index"] == "endpoint"
        assert (
            configfile["tenant"] == "a" and archive.read("ca.pem") == config["ca_pem"]
        )
    rotated = service.download(actor(), item["id"])[0]
    with pytest.raises(PermissionError):
        service.enroll({"enrollment_token": first, "version": "v1"})
    with zipfile.ZipFile(io.BytesIO(rotated)) as archive:
        token = archive.read("enrollment.token").decode()
    result = service.enroll({"enrollment_token": token, "version": "v1"})
    assert result["host"] == "HOST-01" and result["index"] == "endpoint"
    with pytest.raises(PermissionError):
        service.enroll({"enrollment_token": token, "version": "v1"})
    with pytest.raises(ConflictError):
        service.download(actor(), item["id"])
    with source_store.control() as db:
        saved = db.execute("SELECT credential_digest FROM endpoint_agents").fetchone()[
            0
        ]
        assert saved != result["credential"] and token not in str(
            db.execute("SELECT * FROM endpoint_deployments").fetchall()
        )


@pytest.mark.parametrize(
    "host", ["../a", "a/b", "host; rm x", "a\nb", "$(whoami)", 'a"b', "", "한글"]
)
def test_host_never_enters_os_command_or_archive_path(source_store, config, host):
    with pytest.raises(ValueError):
        ad.Distribution(source_store, config).create(
            actor(), {"platform": "windows", "host": host, "index": "endpoint"}
        )


def test_current_owner_grant_and_tenant_restrict_download_and_registration(
    source_store, config
):
    service = ad.Distribution(source_store, config)
    item, token, _ = deployed(service)
    with pytest.raises(KeyError):
        service.download(actor("admin_b", "b"), item["id"])
    with pytest.raises(PermissionError):
        service.download(actor("admin_other"), item["id"])
    access.set_for_user(source_store, actor(), "admin_a", ["other"])
    with pytest.raises(KeyError):
        service.download(actor(), item["id"])
    with pytest.raises(PermissionError):
        service.enroll({"enrollment_token": token, "version": "v1"})
    assert service.deployments(actor("admin_b", "b"))["deployments"] == []


def test_ingest_fixed_identity_durable_retry_and_current_acl(source_store, config):
    service = ad.Distribution(source_store, config)
    ident, _, _, _ = enrolled(service)
    credential = ident["credential"]
    payload = {"events": [event(host="HOST-01")]}
    result = service.ingest(credential, payload)
    assert (
        result["accepted"] == 1
        and result["durable"]
        and result["results"] == [{"id": "one", "quarantined": False}]
    )
    assert service.ingest(credential, payload)["duplicate"] == 1
    with source_store.control() as db:
        queued = db.execute("SELECT tenant,payload FROM queue").fetchone()
        assert (
            queued["tenant"] == "a"
            and json.loads(queued["payload"])["index"] == "endpoint"
        )
    wrong = copy.deepcopy(payload)
    wrong["events"][0]["data"]["host"]["id"] = "VICTIM"
    with pytest.raises(PermissionError):
        service.ingest(credential, wrong)
    for key in ("tenant", "index", "format"):
        wrong = {**payload, key: "victim"}
        with pytest.raises(ValueError):
            service.ingest(credential, wrong)
        wrong = copy.deepcopy(payload)
        wrong["events"][0][key] = "victim"
        with pytest.raises(ValueError):
            service.ingest(credential, wrong)
    service.heartbeat(credential, {"health": {"status": "ok", "pending": 0}})
    assert service.poll(credential, {})["command"] is None
    access.set_for_user(source_store, actor(), "admin_a", ["different"])
    for callback, data in (
        (service.ingest, payload),
        (service.heartbeat, {"health": {}}),
        (service.poll, {}),
    ):
        with pytest.raises(PermissionError):
            callback(credential, data)


def test_bound_index_parser_route_denied_and_quarantine_explicit(source_store, config):
    service = ad.Distribution(source_store, config)
    ident, _, _, _ = enrolled(service)
    pipeline.save(
        source_store,
        actor(),
        "endpoint-policy",
        {
            "version": 0,
            "definition": {
                "source": "aegis-xdr",
                "enabled": True,
                "route_index": "secret",
            },
        },
    )
    with pytest.raises(PermissionError):
        service.ingest(ident["credential"], {"events": [event(host="HOST-01")]})
    with source_store.control() as db:
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 0
    pipeline.save(
        source_store,
        actor(),
        "endpoint-policy",
        {
            "version": 1,
            "definition": {
                "source": "aegis-xdr",
                "enabled": True,
                "required_fields": ["raw.missing"],
            },
        },
    )
    result = service.ingest(ident["credential"], {"events": [event(host="HOST-01")]})
    assert result["quarantined"] == 1 and result["results"][0]["quarantined"]
    assert service.ingest(ident["credential"], {"events": [event(host="HOST-01")]})[
        "results"
    ][0]["quarantined"]


def test_duplicate_host_revoke_scope_expiry_and_secretless_listing(
    source_store, config
):
    service = ad.Distribution(source_store, config)
    ident, _, _, _ = enrolled(service)
    _, token, _ = deployed(service)
    with pytest.raises(ConflictError):
        service.enroll({"enrollment_token": token, "version": "v1"})
    assert service.agents(actor("admin_b", "b"))["agents"] == []
    listing = service.agents(actor())
    assert "credential" not in json.dumps(listing) and "token" not in json.dumps(
        listing
    )
    with pytest.raises(KeyError):
        service.revoke(actor("admin_b", "b"), ident["agent_id"])
    service.revoke(actor(), ident["agent_id"])
    with pytest.raises(PermissionError):
        service.poll(ident["credential"], {})
    new = service.enroll({"enrollment_token": token, "version": "v1"})
    with source_store.control() as db:
        db.execute(
            "UPDATE endpoint_agents SET expires=0 WHERE id=?", (new["agent_id"],)
        )
    with pytest.raises(PermissionError):
        service.poll(new["credential"], {})


def test_config_https_only_and_no_private_key(tmp_path, monkeypatch, config):
    pem = tmp_path / "ca.pem"
    pem.write_bytes(config["ca_pem"])
    monkeypatch.setenv("SAPIENTIA_AGENT_CA_FILE", str(pem))
    for url in (
        "http://127.0.0.1:8788",
        "https://user:secret@host",
        "https://host/path",
        "https://host/?x=1",
        "https://host/#x",
        "https://host:99999",
    ):
        monkeypatch.setenv("SAPIENTIA_AGENT_ENDPOINT_URL", url)
        with pytest.raises(ValueError):
            ad.load_config()
    monkeypatch.setenv("SAPIENTIA_AGENT_ENDPOINT_URL", "https://127.0.0.1:8788")
    assert ad.load_config()["ca_pem"] == config["ca_pem"]
    pem.write_bytes(config["ca_pem"] + b"-----BEGIN PRIVATE KEY-----")
    with pytest.raises(ValueError):
        ad.load_config()


def test_registered_public_api_auth_csrf_tls_and_per_agent_bearer(
    tmp_path, monkeypatch, config
):
    ca = tmp_path / "ca.pem"
    ca.write_bytes(config["ca_pem"])
    monkeypatch.setenv("SAPIENTIA_AGENT_ENDPOINT_URL", config["endpoint_url"])
    monkeypatch.setenv("SAPIENTIA_AGENT_CA_FILE", str(ca))
    app = create_app(Settings(tmp_path / "api", min_free_bytes=0), background=False)
    auth.create_user(app.state.store, "admin_a", PASSWORD, "admin", "a")
    with TestClient(app, base_url="https://testserver") as client:
        assert client.get("/api/xdr/agents/packages/windows").status_code == 401
        login = client.post(
            "/api/login", json={"name": "admin_a", "password": PASSWORD}
        )
        csrf = {"x-csrf-token": login.json()["csrf"]}
        generic = client.get("/api/xdr/agents/packages/windows")
        assert (
            generic.status_code == 200
            and hashlib.sha256(generic.content).hexdigest()
            == generic.headers["x-package-sha256"]
        )
        payload = {"platform": "windows", "host": "HOST-01", "index": "endpoint"}
        assert (
            client.post("/api/xdr/agents/deployments", json=payload).status_code == 403
        )
        created = client.post("/api/xdr/agents/deployments", json=payload, headers=csrf)
        assert created.status_code == 201, created.text
        download = client.post(created.json()["package_url"], headers=csrf)
        assert (
            download.status_code == 200
            and "no-store" in download.headers["cache-control"]
        )
        with zipfile.ZipFile(io.BytesIO(download.content)) as archive:
            token = archive.read("enrollment.token").decode()
        body = {"enrollment_token": token, "version": "v1"}
        assert (
            client.post("http://testserver/api/agent/register", json=body).status_code
            == 403
        )
        assert (
            client.post(
                "/api/agent/register", json=body, headers={"x-forwarded-proto": "https"}
            ).status_code
            == 403
        )
        registered = client.post("/api/endpoint-agent/register", json=body)
        assert registered.status_code == 200, registered.text
        assert "no-store" in registered.headers["cache-control"]
        credential = registered.json()["credential"]
        assert client.post("/api/agent/poll", json={}).status_code == 401
        assert (
            client.post(
                "/api/agent/poll",
                json={},
                headers={"authorization": "Bearer " + credential},
            ).json()["command"]
            is None
        )
        assert client.post("/api/agent/register", json=body).status_code == 401
        assert (
            client.post(
                "/api/agent/poll",
                json={},
                headers={b"authorization": b"Bearer \xff\xfe"},
            ).status_code
            == 401
        )


def test_generic_status_remains_downloadable_without_https_config(source_store):
    service = ad.Distribution(source_store)
    status = service.status()
    assert not status["deployment_enabled"] and len(status["generic_packages"]) == 2
    assert (
        status["collections"]["windows"]
        and not status["remote_commands"]
        and not status["containment"]
    )
    with pytest.raises(ValueError):
        service.create(actor(), {"platform": "linux", "host": "a", "index": "endpoint"})


def test_downloaded_runtime_refuses_untrusted_remote_command(tmp_path):
    blob, _, _ = ad.package("linux")
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        archive.extractall(tmp_path)
    spec = importlib.util.spec_from_file_location(
        "downloaded_agent_core", tmp_path / "Agent/core.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    agent = object.__new__(module.Agent)
    agent._post = lambda *a: {
        "command": {"id": "malicious", "action": "collect_processes"}
    }
    with pytest.raises(RuntimeError, match="disabled"):
        agent.poll()
    for url in ("http://127.0.0.1", "https://u:p@host", "https://host/redirect"):
        with pytest.raises(ValueError):
            module.Transport(url, "absent.pem")


def test_enrollment_expiry_owner_role_and_bounded_health(source_store, config):
    service = ad.Distribution(source_store, config)
    item, token, _ = deployed(service)
    with source_store.control() as db:
        db.execute(
            "UPDATE endpoint_deployments SET expires=0 WHERE id=?", (item["id"],)
        )
    with pytest.raises(PermissionError):
        service.enroll({"enrollment_token": token, "version": "v1"})
    identity, _, _, _ = enrolled(service)
    with pytest.raises(ValueError):
        service.heartbeat(identity["credential"], {"health": {"oversized": "a" * 4096}})
    with source_store.control() as db:
        db.execute("UPDATE users SET role='analyst' WHERE name='admin_a'")
    with pytest.raises(PermissionError):
        service.poll(identity["credential"], {})
    assert (
        service.agents(actor("admin_other"))["agents"][0]["status"]
        == "owner_permission_revoked"
    )


def test_http_enrollment_rate_and_worker_backpressure(tmp_path, monkeypatch, config):
    ca = tmp_path / "ca.pem"
    ca.write_bytes(config["ca_pem"])
    monkeypatch.setenv("SAPIENTIA_AGENT_ENDPOINT_URL", config["endpoint_url"])
    monkeypatch.setenv("SAPIENTIA_AGENT_CA_FILE", str(ca))
    app = create_app(
        Settings(tmp_path / "bounded-api", min_free_bytes=0), background=False
    )
    barrier = threading.Barrier(5)
    release = threading.Event()

    def blocked(*_):
        barrier.wait(timeout=10)
        release.wait(timeout=10)
        return {"command": None}

    monkeypatch.setattr(app.state.agent_distribution, "poll", blocked)
    with TestClient(app, base_url="https://testserver") as client:
        body = {"enrollment_token": "x" * 40, "version": "v1"}
        for _ in range(20):
            assert client.post("/api/agent/register", json=body).status_code == 401
        limited = client.post("/api/agent/register", json=body)
        assert limited.status_code == 429 and limited.headers["retry-after"] == "60"
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = [
                pool.submit(
                    client.post,
                    "/api/agent/poll",
                    json={},
                    headers={"authorization": "Bearer " + "x" * 40},
                )
                for _ in range(4)
            ]
            try:
                barrier.wait(timeout=10)
                busy = client.post(
                    "/api/agent/poll",
                    json={},
                    headers={"authorization": "Bearer " + "x" * 40},
                )
                assert busy.status_code == 503 and busy.headers["retry-after"] == "1"
            finally:
                release.set()
            assert all(f.result(timeout=10).status_code == 200 for f in futures)


def test_thousand_history_rows_do_not_hide_active_or_scoped_agents(
    source_store, config
):
    service = ad.Distribution(source_store, config)
    identity, _item, _, _ = enrolled(service)
    pending, _, _ = deployed(service, host="HOST-02")
    with source_store.control() as db:
        db.executemany(
            "INSERT INTO endpoint_deployments(id,tenant,owner,platform,host,index_name,created,expires,revoked) VALUES(?,?,?,?,?,?,?,?,?)",
            [
                (
                    "HDEP-" + str(i),
                    "a",
                    "admin_a",
                    "linux",
                    "OLD-" + str(i),
                    "endpoint",
                    9999999999 + i,
                    0,
                    1,
                )
                for i in range(1001)
            ],
        )
        db.executemany(
            "INSERT INTO endpoint_agents(id,tenant,owner,platform,host,index_name,deployment_id,credential_digest,created,expires,version,revoked) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    "HAGT-" + str(i),
                    "a",
                    "admin_a",
                    "linux",
                    "OLD-" + str(i),
                    "endpoint",
                    "unused",
                    "unused" + str(i),
                    9999999999 + i,
                    0,
                    "v1",
                    1,
                )
                for i in range(1001)
            ],
        )
        db.executemany(
            "INSERT INTO endpoint_agents(id,tenant,owner,platform,host,index_name,deployment_id,credential_digest,created,expires,version,revoked) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    "HIDDEN-" + str(i),
                    "a",
                    "admin_a",
                    "linux",
                    "HIDDEN-" + str(i),
                    "secret",
                    "unused",
                    "hidden" + str(i),
                    9999999999 + i,
                    0,
                    "v1",
                    1,
                )
                for i in range(1001)
            ],
        )
    access.set_for_user(source_store, actor(), "admin_a", ["endpoint"])
    fleet = service.agents(actor())
    assert (
        fleet["truncated"] is False
        and fleet["limit"] is None
        and fleet["count"] == fleet["total"] == 1002
        and fleet["total_at_least"] == 1002
    )
    assert (
        fleet["agents"][0]["id"] == identity["agent_id"]
        and fleet["agents"][0]["collections"]
    )
    assert all(a["index"] == "endpoint" for a in fleet["agents"])
    deployments = service.deployments(actor())
    assert (
        deployments["truncated"] is False
        and deployments["count"] == deployments["total"] == 1003
    )
    assert deployments["deployments"][0]["id"] == pending["id"]
    assert service.agents(actor("admin_b", "b"))["total"] == 0


def test_extracted_configure_matches_tenant_index_identity_contract(
    tmp_path, config, monkeypatch
):
    extracted = tmp_path / "package"
    extracted.mkdir()
    deployment = {
        "tenant": "_team",
        "host": "HOST-01",
        "index_name": "_endpoint",
        "expires": 9999999999,
    }
    with zipfile.ZipFile(
        io.BytesIO(ad.package("linux", deployment, "x" * 40, config)[0])
    ) as archive:
        archive.extractall(extracted)
    monkeypatch.setattr(sys, "path", sys.path.copy())
    monkeypatch.delitem(sys.modules, "Agent", raising=False)
    monkeypatch.delitem(sys.modules, "Agent.core", raising=False)
    spec = importlib.util.spec_from_file_location(
        "extracted_agent_configure", extracted / "configure.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls = []
    monkeypatch.setattr(module, "enroll", lambda cfg, token: calls.append((cfg, token)))
    settings, token, ca = (
        extracted / filename
        for filename in ("deployment.json", "enrollment.token", "ca.pem")
    )
    values = json.loads(settings.read_text(encoding="utf-8"))
    target = tmp_path / "install"
    target.mkdir()
    shutil.copytree(extracted / "Agent", target / "Agent")
    for filename in ("manifest.json", "configure.py"):
        shutil.copy2(extracted / filename, target / filename)
    result = module.configure(target, settings, token, ca)
    assert (
        result["enrolled"]
        and calls[0][0]["tenant"] == "_team"
        and calls[0][0]["index"] == "_endpoint"
    )
    assert (target / "config.json").is_file()
    saved = json.loads((target / "config.json").read_text())
    assert (
        saved["package_integrity"]["required"] is True
        and saved["package_integrity"]["profile"] == "production"
    )
    assert (
        not saved["response"]["enabled"]
        and not saved["defense"]["enabled"]
        and not saved["kernel_prevention"]["enabled"]
    )
    values["index"] = "invalid.dot"
    settings.write_text(json.dumps(values), encoding="utf-8")
    with pytest.raises(ValueError, match="index"):
        module.configure(tmp_path / "invalid", settings, token, ca)


@pytest.mark.parametrize(
    "change",
    [
        "deployment",
        "token",
        "ca",
        "manifest_unsigned",
        "missing_trust",
        "trust_inside",
        "environment_disable",
        "configure_member",
    ],
)
def test_production_configure_refuses_unbound_inputs_before_enrollment_or_state(
    tmp_path,
    config,
    monkeypatch,
    release_signer,  # noqa: F811 -- Explicit imported pytest fixture.
    change,
):
    extracted, target = tmp_path / "package", tmp_path / "install"
    deployment = {
        "tenant": "a",
        "host": "HOST",
        "index_name": "endpoint",
        "expires": 9999999999,
    }
    with zipfile.ZipFile(
        io.BytesIO(ad.package("linux", deployment, "x" * 40, config)[0])
    ) as archive:
        archive.extractall(extracted)
    target.mkdir()
    shutil.copytree(extracted / "Agent", target / "Agent")
    for name in ("manifest.json", "configure.py"):
        shutil.copy2(extracted / name, target / name)
    spec = importlib.util.spec_from_file_location(
        "guarded_extracted_configure", extracted / "configure.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls = []
    monkeypatch.setattr(module, "enroll", lambda *_: calls.append(True))
    settings, token, ca = (
        extracted / name for name in ("deployment.json", "enrollment.token", "ca.pem")
    )
    if change == "deployment":
        data = json.loads(settings.read_text())
        data["host"] = "DIFFERENT"
        settings.write_text(json.dumps(data))
    elif change == "token":
        token.write_text("y" * 40)
    elif change == "ca":
        ca.write_bytes(ca.read_bytes() + b"\n")
    elif change == "manifest_unsigned":
        data = json.loads((target / "manifest.json").read_text())
        data.pop("signature")
        (target / "manifest.json").write_text(json.dumps(data))
    elif change == "missing_trust":
        monkeypatch.delenv("SERA_AGENT_TRUSTED_KEYS_FILE")
    elif change == "trust_inside":
        inside = target / "trust.json"
        inside.write_bytes(release_signer["trust_file"].read_bytes())
        monkeypatch.setenv("SERA_AGENT_TRUSTED_KEYS_FILE", str(inside))
    elif change == "environment_disable":
        monkeypatch.setenv("SERA_AGENT_REQUIRE_SIGNED_PACKAGE", "0")
    else:
        (target / "configure.py").write_text("changed")
    with pytest.raises((ValueError, OSError)):
        module.configure(target, settings, token, ca)
    assert (
        not calls
        and not (target / "config.json").exists()
        and not (target / "state").exists()
    )
