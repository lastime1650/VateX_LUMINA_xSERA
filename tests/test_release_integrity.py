"""Pinned manifest verification, tamper rejection and actual startup measurement."""
# ruff: noqa: F811 -- Explicit imported pytest fixture.

import importlib
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from sapientia import agent_distribution, release_integrity
from sapientia.endpoint_agent.Agent import core
from sapientia.endpoint_agent.Agent.package_integrity import (
    PackageIntegrity,
    verify,
    verify_signature,
)
from tests.signing_support import (
    local_agent_development_config,
    release_signer,  # noqa: F401 -- Explicit pytest fixture.
)


@pytest.mark.parametrize("mutation", ["member", "revocation", "policy_downgrade"])
def test_agent_startup_and_heartbeat_use_actual_integrity_measurement(
    signed, tmp_path, monkeypatch, mutation
):
    root, trust, key_id = signed
    integrity_module = importlib.import_module(
        core.response.__package__ + ".package_integrity"
    )
    monkeypatch.setattr(
        integrity_module,
        "PackageIntegrity",
        lambda config: PackageIntegrity(config, root),
    )
    monkeypatch.setattr(core, "Transport", lambda *args, **kwargs: None)
    monkeypatch.setattr(core.Agent, "_post", lambda self, route, body: body)
    settings = {
        "state_dir": str(tmp_path / "state"),
        "endpoint_url": "https://fixture",
        "ca_file": "fixture",
        "tenant": "a",
        "host": "HOST",
        "index": "endpoint",
        "package_integrity": {"required": True, "trust_file": str(trust)},
    }
    from pathlib import Path

    core.atomic_json(
        Path(settings["state_dir"]) / "identity.json",
        {
            "agent_id": "fixture",
            "credential": "private-synthetic-test-only",
            "tenant": "a",
            "host": "HOST",
            "index": "endpoint",
        },
    )
    agent = core.Agent(settings, type("Collector", (), {"collect": lambda *args: []})())
    try:
        before = agent.heartbeat()["health"]
        assert before["package_integrity"]["state"] == "verified_signed"
        if mutation == "member":
            (root / "Agent/core.py").write_text("tampered", encoding="utf-8")
        elif mutation == "revocation":
            value = json.loads(trust.read_text())
            value["revoked_key_ids"] = [key_id]
            trust.write_text(json.dumps(value), encoding="utf-8")
        else:
            settings["package_integrity"]["required"] = False
        after = agent.heartbeat()["health"]
        assert (
            after["package_integrity"]["state"] == "failed"
            and after["status"] == "degraded"
        )
        with pytest.raises(ValueError, match="startup|disabled"):
            core.Agent(settings, type("Collector", (), {"collect": lambda *args: []})())
    finally:
        agent.queue.close()


@pytest.fixture
def signed(tmp_path, release_signer):
    key_id, trust = release_signer["key_id"], release_signer["trust_file"]
    root = tmp_path / "package"
    root.mkdir()
    with zipfile.ZipFile(
        io.BytesIO(agent_distribution.package("windows")[0])
    ) as archive:
        archive.extractall(root)
        assert not any(
            "private.pem" in n or "trust.json" in n for n in archive.namelist()
        )
    return root, trust, key_id


def test_actual_archive_signature_and_installed_code_measurement(signed):
    root, trust, key_id = signed
    measured = verify(root, trust_file=trust, require_signature=True)
    assert measured["state"] == "verified_signed" and measured["key_id"] == key_id
    assert not measured["os_code_signature"] and not measured["hardware_attestation"]
    integrity = PackageIntegrity(
        {"package_integrity": {"required": True, "trust_file": str(trust)}}, root
    )
    assert integrity.startup["state"] == "verified_signed"
    (root / "Agent/core.py").write_text("tampered", encoding="utf-8")
    assert integrity.measure()["state"] == "failed"
    with pytest.raises(ValueError, match="startup"):
        PackageIntegrity(
            {"package_integrity": {"required": True, "trust_file": str(trust)}}, root
        )


@pytest.mark.parametrize("mutation", ["manifest", "member", "extra", "missing"])
def test_archive_tamper_is_rejected(signed, mutation):
    root, trust, _ = signed
    if mutation == "manifest":
        path = root / "manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["release"] = "forged"
        path.write_text(json.dumps(manifest), encoding="utf-8")
    elif mutation == "member":
        (root / "Agent/core.py").write_text("changed", encoding="utf-8")
    elif mutation == "extra":
        (root / "Agent/extra.py").write_text("changed", encoding="utf-8")
    else:
        (root / "Agent/core.py").unlink()
    with pytest.raises(ValueError):
        verify(root, trust_file=trust, require_signature=True)


def test_archive_cannot_bootstrap_its_own_trust_or_unknown_key(signed):
    root, trust, _ = signed
    inside = root / "trust.json"
    inside.write_bytes(trust.read_bytes())
    with pytest.raises(ValueError, match="outside"):
        verify(root, trust_file=inside, require_signature=True)
    inside.unlink()
    trust.write_text(
        json.dumps({"schema": "xsera.agent.trust.v1", "keys": {}}), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="trusted"):
        verify(root, trust_file=trust, require_signature=True)


def test_production_unsigned_refused_and_explicit_loopback_fixture_is_untrusted(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("SAPIENTIA_AGENT_SIGNING_KEY_FILE", raising=False)
    assert not release_integrity.status()["available"]
    with pytest.raises(ValueError, match="startup"):
        PackageIntegrity({}, tmp_path)
    with pytest.raises(ValueError, match="externally provisioned"):
        agent_distribution.package("linux")
    blob = agent_distribution.package("linux", development_fixture=True)[0]
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        archive.extractall(tmp_path / "package")
    with pytest.raises(ValueError, match="not a production"):
        verify(tmp_path / "package")
    measured = verify(
        tmp_path / "package", development_fixture=True, require_signature=False
    )
    assert measured["state"] == "checksum_only" and measured["key_id"] is None
    assert (
        PackageIntegrity(
            local_agent_development_config({}), tmp_path / "package"
        ).startup["state"]
        == "checksum_only"
    )
    with pytest.raises(ValueError, match="disabled"):
        PackageIntegrity({"package_integrity": {"required": False}}, tmp_path)
    settings = local_agent_development_config({})
    settings["endpoint_url"] = "https://remote.example"
    with pytest.raises(ValueError, match="loopback"):
        PackageIntegrity(settings, tmp_path)


def test_production_default_requires_external_trust_and_refuses_downgrade(signed):
    root, trust, _ = signed
    with pytest.raises(ValueError, match="startup"):
        PackageIntegrity({}, root)
    assert (
        PackageIntegrity(
            {"package_integrity": {"trust_file": str(trust)}}, root
        ).startup["state"]
        == "verified_signed"
    )
    with pytest.raises(ValueError, match="downgraded"):
        verify(root, trust_file=trust, require_signature=False)
    with pytest.raises(ValueError, match="downgraded"):
        PackageIntegrity(local_agent_development_config({}), root)


def test_signer_revocation_and_runtime_policy_change_fail_closed(signed):
    root, trust, key_id = signed
    settings = {"package_integrity": {"trust_file": str(trust)}}
    integrity = PackageIntegrity(settings, root)
    settings["package_integrity"]["required"] = False
    assert integrity.measure()["state"] == "failed"
    settings["package_integrity"].pop("required")
    policy = json.loads(trust.read_text())
    policy["revoked_key_ids"] = [key_id]
    trust.write_text(json.dumps(policy), encoding="utf-8")
    assert integrity.measure()["state"] == "failed"
    with pytest.raises(ValueError, match="revoked"):
        verify(root, trust_file=trust)
    with pytest.raises(ValueError, match="startup"):
        PackageIntegrity(settings, root)


def test_standalone_bootstrap_does_not_execute_untrusted_verifier_member(
    signed, tmp_path
):
    root, _trust, _ = signed
    marker = tmp_path / "untrusted-member-executed.txt"
    payload = (
        "from pathlib import Path\nPath("
        + repr(str(marker))
        + ").write_text('executed')\n"
    )
    member = root / "Agent/package_integrity.py"
    member.write_text(payload, encoding="utf-8")
    manifest_file = root / "manifest.json"
    manifest = json.loads(manifest_file.read_text())
    import hashlib

    manifest["files"]["Agent/package_integrity.py"] = hashlib.sha256(
        member.read_bytes()
    ).hexdigest()
    manifest_file.write_text(json.dumps(manifest), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(root / "verify_package.py")],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode != 0 and not marker.exists()
    assert "signature" in result.stderr.lower()


def test_scoped_enrollment_cannot_be_created_as_unsigned_development_fixture():
    with pytest.raises(ValueError, match="without enrollment"):
        agent_distribution.package(
            "linux", {}, "fixture-token", {}, development_fixture=True
        )


def test_environment_or_cli_flag_cannot_downgrade_production_verification(
    signed, monkeypatch
):
    root, _trust, _ = signed
    for extra in ([], ["--development-fixture"]):
        monkeypatch.setenv("SERA_AGENT_REQUIRE_SIGNED_PACKAGE", "0")
        result = subprocess.run(
            [sys.executable, "-I", "-B", str(root / "verify_package.py"), *extra],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert result.returncode != 0


def test_external_key_required_before_server_issues_packages_and_deployments(
    tmp_path, monkeypatch
):
    from sapientia.storage import Settings, Store
    from tests.test_backend_upgrade import actor

    monkeypatch.delenv("SAPIENTIA_AGENT_SIGNING_KEY_FILE", raising=False)
    store = Store(Settings(tmp_path / "store", min_free_bytes=0))
    try:
        service = agent_distribution.Distribution(
            store, {"endpoint_url": "https://127.0.0.1", "ca_pem": b"unused"}
        )
        state = service.status()
        assert not state["deployment_enabled"] and not state["generic_packages"]
        assert (
            state["signing"]["production_required"]
            and not state["signing"]["unsigned_distribution_allowed"]
        )
        with pytest.raises(ValueError, match="signing key"):
            service.create(
                actor(), {"platform": "linux", "host": "HOST", "index": "public"}
            )
        with store.control() as db:
            assert (
                db.execute("SELECT count(*) FROM endpoint_deployments").fetchone()[0]
                == 0
            )
    finally:
        store.close()


def test_qa_key_provisioning_is_explicit_external_non_overwriting_and_signs(
    tmp_path, monkeypatch, capsys
):
    from tools import provision_agent_test_signer as provisioning

    directory = tmp_path / "disposable-key"
    with pytest.raises(ValueError, match="only provisions disposable"):
        provisioning.provision(directory, qa_only=False)
    assert not directory.exists()
    result = provisioning.provision(directory, qa_only=True)
    monkeypatch.setenv("SAPIENTIA_AGENT_SIGNING_KEY_FILE", result["private_file"])
    manifest = release_integrity.sign(
        {
            "schema": "sera.agent.package.v1",
            "distribution_profile": "production",
            "files": {},
        }
    )
    assert manifest["signature"]["key_id"] == result["key_id"]
    trust = json.loads(Path(result["trust_file"]).read_text(encoding="utf-8"))
    assert set(trust["keys"]) == {result["key_id"]}
    assert verify_signature(manifest, trust) == result["key_id"]
    assert not result["owner_release_qualification"]
    assert not result["automatic_trust_installation"]
    before = Path(result["private_file"]).read_bytes()
    with pytest.raises(FileExistsError):
        provisioning.provision(directory, qa_only=True)
    assert Path(result["private_file"]).read_bytes() == before
    assert capsys.readouterr().out == ""


def test_qa_key_cli_prints_public_fingerprint_only(tmp_path, monkeypatch, capsys):
    from tools import provision_agent_test_signer as provisioning

    directory = tmp_path / "cli-disposable-key"
    monkeypatch.setattr(
        sys,
        "argv",
        ["provision_agent_test_signer.py", "--directory", str(directory), "--qa-only"],
    )
    provisioning.main()
    result = json.loads(capsys.readouterr().out)
    assert set(result) == {
        "qa_only",
        "key_id",
        "owner_release_qualification",
        "secret_material_printed",
    }
    assert result["qa_only"] and not result["owner_release_qualification"]
    assert not result["secret_material_printed"]
    assert len(result["key_id"]) == 32


def test_qa_key_provisioning_refuses_release_tree_before_creating_files(
    tmp_path, monkeypatch
):
    from tools import provision_agent_test_signer as provisioning

    release = tmp_path / "fake-release"
    monkeypatch.setattr(
        provisioning, "__file__", str(release / "tools" / "provision.py")
    )
    with pytest.raises(ValueError, match="outside the release"):
        provisioning.provision(release / "untrusted-signing-key", qa_only=True)
    assert not release.exists()


def test_dotdot_alias_cannot_self_trust_installed_package(signed):
    root, trust, _ = signed
    internal = root / "trust.json"
    internal.write_bytes(trust.read_bytes())
    outside = root.parent / "outside"
    outside.mkdir()
    alias = outside / ".." / root.name / "trust.json"
    assert alias.resolve() == internal.resolve()
    with pytest.raises(ValueError, match="outside the package"):
        verify(root, trust_file=alias, installed=True)


@pytest.mark.parametrize(
    "relative", ["Agent/extra.pyc", "Agent/__pycache__/core.cpython-313.pyc"]
)
def test_production_installed_measurement_refuses_unmeasured_bytecode(signed, relative):
    root, trust, _ = signed
    assert verify(root, trust_file=trust, installed=True)["state"] == "verified_signed"
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"unmeasured-bytecode")
    with pytest.raises(ValueError, match="bytecode"):
        verify(root, trust_file=trust, installed=True)
