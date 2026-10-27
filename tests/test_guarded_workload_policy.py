# ruff: noqa: F811 -- Imported pytest fixtures are injected by argument name.
"""Guarded workload allowlist safety contracts. No native kernel effects."""

import json
import time
from pathlib import Path

import pytest

from sapientia.endpoint_agent.Agent import kernel_prevention as module
from sapientia.endpoint_agent.Agent import response
from sapientia.endpoint_agent.Agent.defense import Defense
from tests.test_kernel_prevention import (
    DIGEST,
    EXECUTABLE,
    NOW,
    FakeBackend,
    emit,
    guard_for,
    signed,  # noqa: F401 -- imported fixture
    wait_for,
)


def allow_policy(signed, mode="audit"):
    config, document, _key, write = signed
    document["rules"][0]["action"] = "allow_execution"
    config["kernel_prevention"].update(
        guarded_workload_mode=mode,
        guarded_workload_confirmed=True,
        guarded_workload_lease_seconds=30,
    )
    write(document)
    return config, document


@pytest.mark.parametrize("mode", ["all", "global", True, 1, ""])
def test_invalid_guarded_mode_rejected_before_native_api(signed, mode):
    config, _document = allow_policy(signed)
    config["kernel_prevention"]["guarded_workload_mode"] = mode
    with pytest.raises(ValueError):
        module.validate_settings(config["kernel_prevention"])


def test_guarded_policy_needs_independent_local_optin(signed):
    config, _document = allow_policy(signed)
    config["kernel_prevention"].pop("guarded_workload_confirmed")
    with pytest.raises(PermissionError):
        module.validate_settings(config["kernel_prevention"])


@pytest.mark.parametrize("lease", [True, 0, 29, 301, "60"])
def test_guarded_lease_is_finite_typed_local_bound(signed, lease):
    config, _document = allow_policy(signed)
    config["kernel_prevention"]["guarded_workload_lease_seconds"] = lease
    with pytest.raises(ValueError):
        module.validate_settings(config["kernel_prevention"])


def test_known_bad_deny_rules_cannot_silently_become_allowlist(signed):
    config, document, _key, _write = signed
    settings = config["kernel_prevention"]
    with pytest.raises(ValueError, match="allow_execution"):
        module.project_allow_rules(
            document, settings["directories"], set(settings["rule_ids"])
        )


def test_approved_hash_allowlist_denies_unapproved_variants_only_in_explicit_mode(
    signed,
):
    config, document = allow_policy(signed)
    settings = config["kernel_prevention"]
    snapshot = {
        "rules": module.project_allow_rules(
            document, settings["directories"], set(settings["rule_ids"])
        )
    }
    assert module.execution_decision(snapshot, EXECUTABLE, DIGEST, "enforce")[0] is True
    assert module.execution_decision(snapshot, EXECUTABLE, "0" * 64, "enforce")[:2] == (
        False,
        "signed_allowlist_unapproved",
    )
    assert (
        module.execution_decision(
            snapshot, "/opt/fixture-watched/renamed", DIGEST, "enforce"
        )[0]
        is False
    )
    assert module.execution_decision(snapshot, EXECUTABLE, "0" * 64, "off")[0] is True


def test_signed_allow_execution_rule_never_reaches_reactive_effect_executor(signed):
    config, _document = allow_policy(signed)
    config["defense"]["enabled"] = True
    defense = Defense(config, response, clock=lambda: NOW)
    try:
        data = {
            "host": {"id": config["host"]},
            "event": {"action": "process_created"},
            "process": {"executable": EXECUTABLE},
            "file": {"hash": {"sha256": DIGEST}},
        }
        assert defense.evaluate([{"id": "owned-allow-only", "data": data}]) == []
        assert defense.counters["matched"] == defense.counters["succeeded"] == 0
    finally:
        defense.close()


def test_audit_allows_unapproved_code_reports_would_deny_and_mock_never_qualifies(
    signed, monkeypatch, tmp_path
):
    config, _document = allow_policy(signed)
    guard, backend = guard_for(
        signed, monkeypatch, lambda *_args: (EXECUTABLE, "0" * 64, (10, 20))
    )
    try:
        fd = emit(backend, tmp_path)
        wait_for(lambda: len(backend.answers) == 1)
        assert backend.answers[0][:2] == (fd, True)
        record = guard.drain_events()[0]["data"]["kernel_prevention"]
        assert record["reason"] == "audit_signed_allowlist_unapproved"
        assert record["would_deny"] is True
        assert guard.status()["guarded_workload_native_qualified"] is False
        assert not (Path(config["state_dir"]) / "guarded-workload-audit.json").exists()
    finally:
        guard.close()


def test_enforce_cannot_start_without_same_scope_native_audit_receipt(signed):
    config, _document = allow_policy(signed, "enforce")
    backend = FakeBackend()
    guard = module.KernelPrevention(
        config, response, backend_factory=lambda: backend, clock=lambda: NOW
    )
    with pytest.raises(OSError):
        guard.start()
    assert backend.closed and guard.running is False


def test_fake_native_receipt_does_not_promote_mock_backend_to_enforcement(signed):
    config, _document = allow_policy(signed, "enforce")
    backend = FakeBackend()
    guard = module.KernelPrevention(
        config, response, backend_factory=lambda: backend, clock=lambda: NOW
    )
    guard.directories, guard.rule_ids, _, _ = module.validate_settings(
        config["kernel_prevention"]
    )
    guard.snapshot = module.SignedProjection(
        config,
        guard.directories,
        guard.rule_ids,
        response,
        clock=lambda: NOW,
        projector=module.project_allow_rules,
    ).load()
    receipt = dict(
        guard._guarded_context(),
        native_confirmed=True,
        approved=1,
        unapproved=1,
        completed_at=NOW,
    )
    (Path(config["state_dir"]) / "guarded-workload-audit.json").write_text(
        json.dumps(receipt)
    )
    with pytest.raises(PermissionError, match="audit-first"):
        guard.start()
    assert backend.closed and guard.running is False


def test_local_monotonic_lease_releases_owned_group_even_with_valid_signed_policy(
    signed, monkeypatch
):
    allow_policy(signed)
    guard, backend = guard_for(signed, monkeypatch)
    try:
        guard.guarded_deadline = time.monotonic() - 1
        wait_for(lambda: backend.closed)
        assert "lease expired" in guard.error
        assert guard.running is False
    finally:
        guard.close()
