"""Local consent boundaries; no native policy or firewall effects."""
# ruff: noqa: F811 -- Explicitly reuse the imported pytest installation fixture.

import argparse
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from sapientia.endpoint_agent.Agent import cli
from tests.test_agent_policy_cli import installation, invoke  # noqa: F401


def kernel_args(directory, **changes):
    values = {
        "confirm_kernel_policy": True,
        "enable_kernel_prevention": True,
        "disable_kernel_prevention": False,
        "kernel_directory": [str(directory)],
        "kernel_rule_id": ["qa-rule"],
        "kernel_decision_timeout_ms": 500,
        "kernel_max_file_bytes": 1024,
        "kernel_lease_seconds": 60,
        "kernel_mode": "audit",
    }
    values.update(changes)
    return argparse.Namespace(**values)


@pytest.mark.parametrize("native", ["nt", "posix"])
def test_kernel_cli_pins_identity_without_enabling_reactive_defense(
    installation, tmp_path, monkeypatch, native
):
    _file, config, identity = installation
    directory = tmp_path / "narrow-executable-directory"
    directory.mkdir()
    monkeypatch.setattr(cli, "os", SimpleNamespace(name=native))
    if native == "posix":
        # The native Linux validator is tested on POSIX paths separately;
        # this Windows CLI fixture checks platform dispatch and serialized shape.
        calls = []
        original_import = cli.importlib.import_module
        monkeypatch.setattr(
            cli,
            "importlib",
            SimpleNamespace(
                import_module=lambda name: (
                    SimpleNamespace(
                        validate_settings=lambda settings: calls.append(settings.copy())
                    )
                    if name.endswith(".kernel_prevention")
                    else original_import(name)
                )
            ),
        )
    policy = cli.kernel_policy(config, kernel_args(directory))
    assert config["defense"]["public_key"] == identity["defense_public_key"]
    assert config["defense"]["enabled"] is False
    assert policy["enabled"] and policy["directories"] == [str(directory.resolve())]
    if native == "nt":
        assert (
            policy["windows_mode"] == "audit" and policy["windows_lease_seconds"] == 60
        )
    else:
        assert not any(key.startswith("windows_") for key in policy)
        assert calls == [policy]


def test_windows_cli_rejects_more_rules_than_native_adapter_before_publication(
    installation, tmp_path
):
    file, config, _identity = installation
    directory = tmp_path / "narrow"
    directory.mkdir()
    with pytest.raises(ValueError, match="1..16"):
        cli.kernel_policy(
            config,
            kernel_args(
                directory, kernel_rule_id=["rule-" + str(i) for i in range(17)]
            ),
        )
    assert json.loads(file.read_text()).get("kernel_prevention") is None


@pytest.mark.parametrize(
    "changes",
    [
        {"kernel_rule_id": ["../escape"]},
        {"kernel_decision_timeout_ms": 49},
        {"kernel_max_file_bytes": 67108865},
        {"kernel_lease_seconds": 301},
    ],
)
def test_invalid_kernel_settings_never_publish_config(installation, tmp_path, changes):
    file, config, _identity = installation
    directory = tmp_path / "narrow"
    directory.mkdir()
    with pytest.raises(ValueError):
        cli.kernel_policy(config, kernel_args(directory, **changes))
    assert json.loads(file.read_text()).get("kernel_prevention") is None


def test_isolation_only_cli_creates_marked_private_receipt_store(installation):
    file, config, _identity = installation
    invoke(
        file,
        "response-policy",
        "--enable-response",
        "--allow-host-isolation",
        "--management-endpoint",
        "outbound,127.0.0.1,18788",
        "--isolation-max-seconds",
        "30",
        "--confirm-response-policy",
    )
    policy = json.loads(file.read_text())["response"]
    from sapientia.endpoint_agent.Agent import operations

    state = Path(policy["quarantine_dir"])
    assert state.is_relative_to(Path(config["state_dir"]))
    assert (state / operations.MARKER).read_text() == operations.MARKER_TEXT
    assert policy["management_allowlist"] == ["127.0.0.1/32"]
    assert policy["allow_host_isolation"] and not policy["allow_file_delete"]


def test_isolation_without_exact_management_endpoint_never_publishes(installation):
    file, config, _identity = installation
    with pytest.raises(ValueError, match="management endpoints"):
        invoke(
            file,
            "response-policy",
            "--enable-response",
            "--allow-host-isolation",
            "--confirm-response-policy",
        )
    assert json.loads(file.read_text()) == config
