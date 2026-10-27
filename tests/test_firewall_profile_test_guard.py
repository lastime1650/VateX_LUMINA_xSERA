"""Test-only rollback contracts; no actual profile or firewall rule mutation."""

import hashlib
import io
import json
import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from sapientia.endpoint_agent.Agent import operations, response
from sapientia.endpoint_agent.Agent.Windows import firewall_profile_test_guard as guard
from tools import qualify_windows_isolation as qualification


@pytest.fixture(autouse=True)
def no_native_mutation(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("This contract suite must not execute an actual OS tool")

    monkeypatch.setattr(guard.subprocess, "run", forbidden)
    monkeypatch.setattr(guard.subprocess, "Popen", forbidden)


@pytest.fixture
def plan(tmp_path):
    root = tmp_path / ("native-windows-isolation-" + "a" * 32)
    state = root / "state" / "quarantine"
    state.mkdir(parents=True)
    (root / ".qa-synthetic-only").write_text("synthetic-only\n")
    (state / operations.MARKER).write_text(operations.MARKER_TEXT)
    settings = {
        "management_allowlist": [
            "127.0.0.1/32",
            *(ip + "/32" for ip, _port in qualification.PEERS),
        ],
        "management_endpoints": [
            {"ip": "127.0.0.1", "port": 18788},
            *[
                {"ip": ip, "port": port, "direction": "outbound"}
                for ip, port in qualification.PEERS
            ],
        ],
    }
    definition, digest = operations.network_definition(settings)
    return {
        "schema": "xsera.qa-firewall-profile-plan.v1",
        "plan_id": "b" * 32,
        "root": str(root),
        "state_dir": str(state),
        "original_profiles": {"1": True, "2": False, "4": False},
        "management_definition": definition,
        "management_digest": digest,
        "created": time.time(),
        "active_seconds": 100,
        "parent_pid": 12345,
        "parent_start_identity": "windows:123456",
        "guard_sha256": hashlib.sha256(b"reviewed test guard").hexdigest(),
    }


def test_plan_retains_every_original_bit_and_fixed_peers_without_os_effect(plan):
    accepted = guard.validate(plan)
    assert accepted["original_profiles"] == {"1": True, "2": False, "4": False}
    assert accepted["active_seconds"] + guard.ROLLBACK_RESERVE_SECONDS <= 120
    assert (
        len(
            {
                row["ip"]
                for row in accepted["management_definition"]["endpoints"]
                if row["ip"] != "127.0.0.1"
            }
        )
        == 4
    )


@pytest.mark.parametrize(
    "key,value",
    [
        ("active_seconds", 101),
        ("active_seconds", 0),
        ("active_seconds", True),
        ("original_profiles", {"1": True, "2": False}),
        ("original_profiles", {"1": True, "2": "false", "4": False}),
        ("original_profiles", {"1": True, "2": False, "4": False, "8": False}),
        ("parent_pid", 4),
        ("parent_pid", True),
        ("parent_start_identity", "windows:../"),
        ("management_digest", "0" * 64),
        ("guard_sha256", "not-a-digest"),
        ("created", float("nan")),
        ("created", float("inf")),
        ("root", "C:/Windows"),
        ("state_dir", "C:/Vatex_LUMINA_xSERA/data"),
    ],
)
def test_unsafe_plan_is_rejected_before_any_native_effect(plan, key, value):
    plan[key] = value
    with pytest.raises((ValueError, PermissionError)):
        guard.validate(plan)


def test_profile_restoration_and_own_cleanup_both_required_for_success(
    plan, monkeypatch
):
    calls = []
    monkeypatch.setattr(
        guard,
        "set_profiles",
        lambda original: (
            calls.append(("restore_profiles", original.copy())) or original.copy()
        ),
    )
    monkeypatch.setattr(
        guard,
        "cleanup_owned",
        lambda value, deadline: (
            calls.append(("cleanup", value["root"]))
            or {"receipt_ids": ["c" * 32], "rules_remaining": 0}
        ),
    )
    result = guard.restore(plan, "finite_window")
    assert (
        result["passed"]
        and result["profiles_restored"]
        and result["owned_cleanup_confirmed"]
    )
    assert calls[0] == ("restore_profiles", {"1": True, "2": False, "4": False})
    assert json.loads(
        (
            __import__("pathlib").Path(plan["root"])
            / "firewall-profile-guard-result.json"
        ).read_text()
    )["passed"]


def test_cleanup_failure_still_restores_original_profile_bits(plan, monkeypatch):
    restored = []
    monkeypatch.setattr(
        guard, "set_profiles", lambda value: restored.append(value.copy()) or value
    )

    def cleanup_failure(*args):
        raise TimeoutError("fixture owned cleanup deadline")

    monkeypatch.setattr(guard, "cleanup_owned", cleanup_failure)
    result = guard.restore(plan, "parent_gone")
    assert restored == [plan["original_profiles"]]
    assert (
        result["profiles_restored"]
        and not result["passed"]
        and not result["owned_cleanup_confirmed"]
    )


def test_profile_failure_still_attempts_only_owned_cleanup(plan, monkeypatch):
    cleaned = []

    def profile_failure(*args):
        raise PermissionError("fixture unverifiable restoration")

    monkeypatch.setattr(guard, "set_profiles", profile_failure)
    monkeypatch.setattr(
        guard,
        "cleanup_owned",
        lambda value, deadline: (
            cleaned.append(value["root"]) or {"receipt_ids": [], "rules_remaining": 0}
        ),
    )
    result = guard.restore(plan, "explicit_complete")
    assert (
        cleaned == [plan["root"]]
        and not result["passed"]
        and result["owned_cleanup_confirmed"]
    )


def test_parent_pid_reuse_is_not_a_live_rollback_owner(plan, monkeypatch):
    monkeypatch.setattr(
        response,
        "inspect_process",
        lambda pid, host: {"start_identity": "windows:999999"},
    )
    assert not guard.parent_alive(plan)
    monkeypatch.setattr(
        response,
        "inspect_process",
        lambda pid, host: {"start_identity": plan["parent_start_identity"]},
    )
    assert guard.parent_alive(plan)


def test_profile_native_commands_accept_only_three_typed_boolean_bits(
    plan, monkeypatch
):
    calls = []

    def native(args, **options):
        calls.append((args, options))
        values = options.get("env", {}).get("LUMINA_QA_PROFILE_VALUES")
        return SimpleNamespace(
            stdout=json.dumps(
                json.loads(values) if values else plan["original_profiles"]
            )
        )

    monkeypatch.setattr(guard.subprocess, "run", native)
    monkeypatch.setattr(guard, "profiles", lambda: plan["original_profiles"].copy())
    assert guard.set_profiles(plan["original_profiles"]) == plan["original_profiles"]
    args, options = calls[0]
    assert options["shell"] is False and options["timeout"] <= 4
    assert "FirewallEnabled" in args[-1] and "Reset" not in args[-1]
    assert (
        json.loads(options["env"]["LUMINA_QA_PROFILE_VALUES"])
        == plan["original_profiles"]
    )
    with pytest.raises(ValueError):
        guard.set_profiles({"1": True, "2": False, "4": False, "other": True})


def test_owned_cleanup_never_deletes_foreign_receipt_or_changes_profiles(
    plan, monkeypatch
):
    from pathlib import Path

    state, db = operations._state({"quarantine_dir": plan["state_dir"]})
    with db:
        db.execute(
            "INSERT INTO isolation(id,digest,definition,state) VALUES(?,?,?,'isolated')",
            ("c" * 32, "0" * 64, response.canonical(plan["management_definition"])),
        )
    db.close()
    calls = []
    monkeypatch.setattr(
        operations, "_driver", lambda *args, **kwargs: calls.append(args)
    )
    with pytest.raises(PermissionError, match="Unexpected receipt"):
        guard.cleanup_owned(plan, time.monotonic() + 5)
    assert calls == []
    assert (Path(state) / "effects.sqlite3").exists()


def test_owned_receipt_cleanup_is_exact_and_idempotent(plan, monkeypatch):
    from sapientia.endpoint_agent.Agent import firewall_guard

    _, db = operations._state({"quarantine_dir": plan["state_dir"]})
    with db:
        db.execute(
            "INSERT INTO isolation(id,digest,definition,state) VALUES(?,?,?,'isolated')",
            (
                "c" * 32,
                plan["management_digest"],
                response.canonical(plan["management_definition"]),
            ),
        )
    db.close()
    present, calls = {"c" * 32}, []
    monkeypatch.setattr(
        firewall_guard,
        "_windows_owned",
        lambda identifier, **kwargs: [object()] if identifier in present else [],
    )
    monkeypatch.setattr(
        firewall_guard,
        "verify_removed_windows",
        lambda identifier, **kwargs: (
            identifier not in present or pytest.fail("Owned rules remained")
        ),
    )

    def release(identifier, definition, **kwargs):
        assert kwargs["release"] is True and definition == plan["management_definition"]
        assert kwargs["state_directory"] == Path(plan["state_dir"])
        calls.append(identifier)
        present.remove(identifier)

    monkeypatch.setattr(operations, "_driver", release)
    first = guard.cleanup_owned(plan, time.monotonic() + 5)
    second = guard.cleanup_owned(plan, time.monotonic() + 5)
    assert first == second and calls == ["c" * 32]
    with sqlite3.connect(
        __import__("pathlib").Path(plan["state_dir"]) / "effects.sqlite3"
    ) as check:
        assert (
            check.execute("SELECT state FROM isolation").fetchone()[0]
            == "lease_expired"
        )


def test_failed_guard_readiness_never_authorizes_profile_enable(plan, monkeypatch):
    monkeypatch.setattr(guard, "protected_plan", lambda path: plan)
    monkeypatch.setattr(guard, "profiles", lambda: plan["original_profiles"])
    state = {"terminated": False}

    class Process:
        pid = 321
        stdout = io.BytesIO(b'{"ready":true,"plan_id":"wrong","pid":321}\n')

        def terminate(self):
            state["terminated"] = True

        def wait(self, timeout):
            return 0

    monkeypatch.setattr(guard.subprocess, "Popen", lambda *args, **kwargs: Process())
    with pytest.raises(PermissionError, match="no profile change"):
        guard.arm("fixture-only")
    assert state["terminated"]


def test_verified_profile_handshake_is_bound_to_plan_pid_and_120_second_budget(
    plan, monkeypatch
):
    monkeypatch.setattr(guard, "protected_plan", lambda path: plan)
    monkeypatch.setattr(guard, "profiles", lambda: plan["original_profiles"])

    class Process:
        pid = 321
        stdout = io.BytesIO(
            (
                json.dumps(
                    {
                        "ready": True,
                        "plan_id": plan["plan_id"],
                        "pid": 321,
                        "max_guard_seconds": 120,
                    }
                )
                + "\n"
            ).encode()
        )

    monkeypatch.setattr(guard.subprocess, "Popen", lambda *args, **kwargs: Process())
    assert guard.arm("fixture-only").pid == 321


def test_profile_baseline_change_prevents_guard_arm(plan, monkeypatch):
    monkeypatch.setattr(guard, "protected_plan", lambda path: plan)
    monkeypatch.setattr(guard, "profiles", lambda: {"1": True, "2": True, "4": False})
    with pytest.raises(PermissionError, match="baseline changed"):
        guard.arm("fixture-only")


def test_quiet_preparation_cannot_run_native_profile_window_without_exact_switch():
    with pytest.raises(SystemExit):
        qualification.main(
            ["--fixture", "fixture", "--output", "output", "--allow-profile-test"]
        )


def test_own_nonce_probe_validates_nonce_before_opening_socket(monkeypatch):
    calls = []
    monkeypatch.setattr(
        qualification.socket,
        "create_connection",
        lambda *args, **kwargs: calls.append(args),
    )
    with pytest.raises(ValueError):
        qualification.nonce_probe("../../wrong")
    assert calls == []


def test_failed_native_probe_is_false_not_a_claimed_denial_fixture(monkeypatch):
    def failed(*args, **kwargs):
        raise OSError("fixture unavailable probe")

    monkeypatch.setattr(qualification.socket, "create_connection", failed)
    assert qualification.nonce_probe("f" * 32) is False


def test_guard_never_weakens_product_firewall_failclosed_contract():
    assert "firewall_profile_test_guard" not in operations.isolate.__code__.co_names
    assert "set_profiles" not in operations.isolate.__code__.co_names


@pytest.mark.parametrize("ready", [1, "true", None])
def test_numeric_or_string_ready_cannot_authenticate_profile_change(
    plan, monkeypatch, ready
):
    monkeypatch.setattr(guard, "protected_plan", lambda path: plan)
    monkeypatch.setattr(guard, "profiles", lambda: plan["original_profiles"])

    class Process:
        pid = 321
        stdout = io.BytesIO(
            (
                json.dumps(
                    {
                        "ready": ready,
                        "plan_id": plan["plan_id"],
                        "pid": 321,
                        "max_guard_seconds": 120,
                    }
                )
                + "\n"
            ).encode()
        )

        def terminate(self):
            pass

        def wait(self, timeout):
            return 0

    monkeypatch.setattr(guard.subprocess, "Popen", lambda *args, **kwargs: Process())
    with pytest.raises(PermissionError):
        guard.arm("fixture-only")


def test_safety_cleanup_receipt_bound_rejects_unexpected_extra_ownership(
    plan, monkeypatch
):
    _, db = operations._state({"quarantine_dir": plan["state_dir"]})
    with db:
        for value in range(4):
            db.execute(
                "INSERT INTO isolation(id,digest,definition,state) VALUES(?,?,?,'isolated')",
                (
                    format(value, "032x"),
                    plan["management_digest"],
                    response.canonical(plan["management_definition"]),
                ),
            )
    db.close()
    with pytest.raises(PermissionError, match="more than three"):
        guard.cleanup_owned(plan, time.monotonic() + 5)


def test_guard_uses_actual_base_python_to_avoid_venv_launcher_pid_mismatch(
    plan, monkeypatch
):
    monkeypatch.setattr(guard, "protected_plan", lambda path: plan)
    monkeypatch.setattr(guard, "profiles", lambda: plan["original_profiles"])
    monkeypatch.setattr(
        guard.sys, "_base_executable", "C:/protected-native-python/python.exe"
    )
    calls = []

    class Process:
        pid = 321
        stdout = io.BytesIO(
            (
                json.dumps(
                    {
                        "ready": True,
                        "plan_id": plan["plan_id"],
                        "pid": 321,
                        "max_guard_seconds": 120,
                    }
                )
                + "\n"
            ).encode()
        )

    monkeypatch.setattr(
        guard.subprocess,
        "Popen",
        lambda args, **kwargs: calls.append(args) or Process(),
    )
    guard.arm("fixture-only")
    assert calls[0][0] == "C:/protected-native-python/python.exe"
