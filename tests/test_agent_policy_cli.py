"""Local opt-in controls; fixture-only policies, no native response/network actions."""

import copy
import hashlib
import json
from pathlib import Path

import pytest

from sapientia.endpoint_agent.Agent import cli, core
from tests.signing_support import local_agent_development_config


@pytest.fixture
def installation(tmp_path, monkeypatch):
    config = {
        "endpoint_url": "https://fixture",
        "ca_file": str(tmp_path / "ca.pem"),
        "tenant": "fixture",
        "host": "HOST",
        "index": "endpoint",
        "state_dir": str(tmp_path / "state"),
    }
    Path(config["state_dir"]).mkdir()
    file = tmp_path / "config.json"
    core.atomic_json(file, config)
    identity = {
        "agent_id": "agent-fixture",
        "credential": "fixture-only",
        "tenant": "fixture",
        "host": "HOST",
        "index": "endpoint",
        "defense_public_key": "a" * 64,
    }
    core.atomic_json(Path(config["state_dir"]) / "identity.json", identity)
    monkeypatch.setattr(cli, "_administrator", lambda: None)
    # Permission rejection is covered separately; this fixture only supplies
    # an already administrator-protected synthetic installation.
    monkeypatch.setattr(cli, "_protected", lambda *a, **k: None)
    return file, config, identity


def invoke(file, command, *flags):
    cli.main("Windows", None, [command, "--config", str(file), *flags])


def test_readonly_investigation_does_not_enable_destructive_actions(installation):
    file, _, _ = installation
    invoke(
        file,
        "response-policy",
        "--enable-response",
        "--allow-investigation",
        "--confirm-response-policy",
    )
    applied = json.loads(file.read_text())["response"]
    assert applied["allow_investigation"] is True
    assert not any(
        applied[key]
        for key in [
            "allow_process_termination",
            "allow_file_delete",
            "allow_quarantine",
            "allow_restore",
            "allow_host_isolation",
        ]
    )


def test_quarantine_restore_explicit_flags_require_roots_and_mark_private_state(
    installation, tmp_path
):
    file, config, _ = installation
    allowed = tmp_path / "narrow-files"
    allowed.mkdir()
    invoke(
        file,
        "response-policy",
        "--enable-response",
        "--allow-quarantine",
        "--allow-restore",
        "--allow-file-root",
        str(allowed),
        "--mark-file-roots",
        "--confirm-response-policy",
    )
    applied = json.loads(file.read_text())["response"]
    assert applied["allow_quarantine"] and applied["allow_restore"]
    configuration = dict(config, response=applied)
    actions = core.response.capabilities(configuration)["actions"]
    assert {"quarantine_file", "restore_file"} <= set(actions)
    assert not {"delete_file", "terminate_process", "isolate_host"} & set(actions)
    assert not applied["allow_file_delete"] and not applied["allow_process_termination"]
    assert Path(applied["quarantine_dir"]).is_relative_to(Path(config["state_dir"]))
    ops = __import__(core.response.__package__ + ".operations", fromlist=["MARKER"])
    assert (Path(applied["quarantine_dir"]) / ops.MARKER).read_text() == ops.MARKER_TEXT
    assert list(allowed.iterdir()) == [allowed / core.response.MARKER]


@pytest.mark.parametrize("flag", ["--allow-quarantine", "--allow-restore"])
def test_file_effect_optin_without_explicit_roots_is_rejected(installation, flag):
    file, config, _ = installation
    with pytest.raises(ValueError, match="marked file roots"):
        invoke(
            file,
            "response-policy",
            "--enable-response",
            flag,
            "--confirm-response-policy",
        )
    assert json.loads(file.read_text()) == config


def test_quarantine_state_cannot_escape_private_state_root(installation, tmp_path):
    file, config, _ = installation
    allowed = tmp_path / "narrow-files"
    allowed.mkdir()
    with pytest.raises(PermissionError, match="state subdirectory"):
        invoke(
            file,
            "response-policy",
            "--enable-response",
            "--allow-quarantine",
            "--allow-file-root",
            str(allowed),
            "--mark-file-roots",
            "--quarantine-dir",
            str(tmp_path / "outside"),
            "--confirm-response-policy",
        )
    assert json.loads(file.read_text()) == config
    assert not (tmp_path / "outside").exists()


def test_cli_policy_drives_real_harmless_quarantine_and_restore(installation, tmp_path):
    file, _, _ = installation
    allowed = tmp_path / "narrow-files"
    allowed.mkdir()
    invoke(
        file,
        "response-policy",
        "--enable-response",
        "--allow-quarantine",
        "--allow-restore",
        "--allow-file-root",
        str(allowed),
        "--mark-file-roots",
        "--confirm-response-policy",
    )
    applied = json.loads(file.read_text())["response"]
    target = allowed / "harmless-cli-fixture.txt"
    body = b"Harmless local opt-in integration fixture\n"
    target.write_bytes(body)
    original = {
        "type": "quarantine_file",
        "path": str(target),
        "sha256": hashlib.sha256(body).hexdigest(),
    }
    outcome = core.response.execute(original, "HOST", applied)
    assert outcome["success"] is True and outcome["executed"] is True
    assert not target.exists()
    restoration = dict(
        original, type="restore_file", quarantine_id=outcome["data"]["quarantine_id"]
    )
    restored = core.response.execute(restoration, "HOST", applied)
    assert restored["success"] is True and restored["executed"] is True
    assert target.read_bytes() == body


def test_disable_clears_every_action_without_removing_existing_catalog(installation):
    file, config, _ = installation
    catalog = Path(config["state_dir"]) / "quarantine"
    catalog.mkdir()
    (catalog / "fixture.bin").write_bytes(b"harmless")
    invoke(file, "response-policy", "--disable-response", "--confirm-response-policy")
    applied = json.loads(file.read_text())["response"]
    assert not applied["enabled"]
    assert not any(v for k, v in applied.items() if k.startswith("allow_"))
    assert (catalog / "fixture.bin").read_bytes() == b"harmless"


@pytest.mark.parametrize(
    "command,mode",
    [("response-policy", "--enable-response"), ("defense-policy", "--enable-defense")],
)
def test_missing_confirmation_changes_nothing(installation, command, mode):
    file, config, _ = installation
    with pytest.raises(PermissionError, match="confirmation"):
        invoke(file, command, mode)
    assert json.loads(file.read_text()) == config


def test_signed_defense_enable_pins_only_saved_credential_identity_key(installation):
    file, config, identity = installation
    config["defense"] = {"public_key": "b" * 64, "enabled": False}
    core.atomic_json(file, config)
    invoke(file, "defense-policy", "--enable-defense", "--confirm-defense-policy")
    applied = json.loads(file.read_text())["defense"]
    assert (
        applied["enabled"] and applied["public_key"] == identity["defense_public_key"]
    )
    assert applied["bundle_file"] == str(
        Path(config["state_dir"]) / "defense-policy.json"
    )
    invoke(file, "defense-policy", "--disable-defense", "--confirm-defense-policy")
    disabled = json.loads(file.read_text())["defense"]
    assert (
        not disabled["enabled"]
        and disabled["public_key"] == identity["defense_public_key"]
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("defense_public_key", None),
        ("agent_id", ""),
        ("index", "other"),
        ("tenant", "other"),
        ("host", "other"),
    ],
)
def test_defense_wrong_or_missing_enrollment_scope_never_enables(
    installation, field, value
):
    file, config, identity = installation
    changed = copy.deepcopy(identity)
    changed[field] = value
    core.atomic_json(Path(config["state_dir"]) / "identity.json", changed)
    with pytest.raises(PermissionError, match="credential-bound"):
        invoke(file, "defense-policy", "--enable-defense", "--confirm-defense-policy")
    assert json.loads(file.read_text()) == config


@pytest.mark.parametrize(
    "command,flags",
    [
        (
            "response-policy",
            ["--enable-response", "--allow-investigation", "--confirm-response-policy"],
        ),
        ("defense-policy", ["--enable-defense", "--confirm-defense-policy"]),
    ],
)
def test_running_agent_lifetime_lock_refuses_local_policy_change(
    installation, command, flags
):
    file, config, _ = installation
    with (
        core.RunLock(config["state_dir"]),
        pytest.raises(RuntimeError, match="owns this state"),
    ):
        invoke(file, command, *flags)
    assert json.loads(file.read_text()) == config


def test_private_path_failure_precedes_policy_write(installation, monkeypatch):
    file, config, _ = installation

    def reject(*args, **kwargs):
        raise PermissionError("fixture unprotected owner/ACL")

    monkeypatch.setattr(cli, "_protected", reject)
    with pytest.raises(PermissionError, match="unprotected"):
        invoke(
            file,
            "response-policy",
            "--enable-response",
            "--allow-investigation",
            "--confirm-response-policy",
        )
    assert json.loads(file.read_text()) == config


def test_agent_run_holds_lifetime_lock_through_collection_and_releases_on_stop(
    installation, monkeypatch
):
    _file, config, _ = installation
    monkeypatch.setattr(core, "Transport", lambda *a, **k: None)
    item = core.Agent(local_agent_development_config(config), type("Collector", (), {"collect": lambda *a: []})())

    def running(_):
        with pytest.raises(RuntimeError), core.RunLock(config["state_dir"]):
            pass

    monkeypatch.setattr(item, "_run_locked", running)
    try:
        item.run(once=True)
        with core.RunLock(config["state_dir"]):
            pass
    finally:
        item.defense.close()
        item.queue.close()
