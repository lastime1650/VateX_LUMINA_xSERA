"""Isolation management preflight contracts; never creates native effects."""

import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from sapientia.endpoint_agent.Agent import firewall_guard, operations, response


def settings(address, *, direction="outbound"):
    version = ":" in address
    return {
        "management_allowlist": [address + ("/128" if version else "/32")],
        "management_endpoints": [
            {"ip": address, "port": 443, "direction": direction}
        ],
        "quarantine_dir": "must-not-be-created",
        "allow_host_isolation": True,
        "isolation_max_seconds": 30,
    }


def no_effect(*_args, **_kwargs):
    raise AssertionError("Unsupported IPv6 management must fail before effects")


@pytest.fixture(autouse=True)
def native_effect_fence(monkeypatch):
    # No test may reach a real host's subprocess or Windows COM backend, even
    # if its simulated OS branch is incorrect. Positive payload tests mock _run.
    monkeypatch.setattr(operations.subprocess, "run", no_effect)
    monkeypatch.setattr(operations, "_windows_batch", no_effect)
    monkeypatch.setattr(firewall_guard, "_windows_owned", no_effect)


@pytest.mark.parametrize(
    "address", ["2001:db8::10", "fe80::10", "::ffff:192.0.2.10", "::"]
)
@pytest.mark.parametrize("direction", ["inbound", "outbound"])
def test_nonloopback_ipv6_management_is_explicitly_unqualified(address, direction):
    with pytest.raises(PermissionError, match=r"(?i)IPv6.*(NDP|neighbor|PMTU|qualification)"):
        operations.network_definition(settings(address, direction=direction))


@pytest.mark.parametrize("native", ["Linux", "Windows"])
def test_unsupported_management_rejected_before_state_probe_guard_and_driver(
    monkeypatch, native
):
    configuration = settings("2001:db8::10")
    configuration["_management_probe"] = no_effect
    monkeypatch.setattr(operations.platform, "system", lambda: native)
    for name in ("_state", "_driver", "_reachable"):
        monkeypatch.setattr(operations, name, no_effect)
    monkeypatch.setattr(firewall_guard, "verify", no_effect)
    monkeypatch.setattr(firewall_guard, "verify_linux", no_effect)
    with pytest.raises(PermissionError, match=r"(?i)IPv6.*(NDP|neighbor|PMTU|qualification)"):
        operations.isolate(
            {"type": "isolate_host", "management_allowlist_digest": "unused"},
            configuration,
        )


def test_mixed_ipv4_and_remote_ipv6_rejects_whole_definition_before_state(
    monkeypatch,
):
    configuration = settings("192.0.2.10")
    configuration["management_allowlist"].append("2001:db8::10/128")
    configuration["management_endpoints"].append(
        {"ip": "2001:db8::10", "port": 443}
    )
    monkeypatch.setattr(operations, "_state", no_effect)
    monkeypatch.setattr(operations, "_driver", no_effect)
    with pytest.raises(PermissionError, match=r"(?i)IPv6.*(NDP|neighbor|PMTU|qualification)"):
        operations.isolate(
            {"type": "isolate_host", "management_allowlist_digest": "unused"},
            configuration,
        )


@pytest.mark.parametrize("address", ["192.0.2.10", "127.0.0.1", "::1"])
@pytest.mark.parametrize("direction", ["inbound", "outbound"])
def test_ipv4_and_local_ipv6_management_definitions_remain_valid(
    address, direction
):
    definition, digest = operations.network_definition(
        settings(address, direction=direction)
    )
    assert definition["endpoints"] == [
        {"ip": address, "port": 443, "direction": direction}
    ]
    assert len(digest) == 64


def test_ipv6_loopback_apply_keeps_only_owned_loopback_policy(monkeypatch):
    captured = []
    monkeypatch.setattr(operations, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(operations.platform, "system", lambda: "Linux")
    monkeypatch.setattr(firewall_guard, "linux_tool", lambda: "/usr/sbin/nft")
    monkeypatch.setattr(firewall_guard, "verify_linux", lambda *_args: None)
    monkeypatch.setattr(
        operations,
        "_run",
        lambda args, **kwargs: captured.append((args, kwargs["payload"])),
    )
    definition, _digest = operations.network_definition(settings("::1"))
    operations._driver("1" * 32, definition)
    assert captured[0][0] == ["/usr/sbin/nft", "-f", "-"]
    payload = captured[0][1]
    assert "iifname lo accept" in payload and "oifname lo accept" in payload
    assert "policy drop" in payload
    assert "icmpv6" not in payload  # Local IPC does not imply qualified NDP.


@pytest.mark.parametrize("native", ["Linux", "Windows"])
def test_low_level_apply_cannot_bypass_unqualified_ipv6_preflight(
    monkeypatch, native
):
    monkeypatch.setattr(operations.platform, "system", lambda: native)
    monkeypatch.setattr(
        operations, "os", SimpleNamespace(name="posix" if native == "Linux" else "nt")
    )
    for name in ("_run", "_windows_cancel_path", "_windows_batch"):
        monkeypatch.setattr(operations, name, no_effect)
    monkeypatch.setattr(firewall_guard, "linux_tool", no_effect)
    monkeypatch.setattr(firewall_guard, "windows_tool", no_effect)
    monkeypatch.setattr(firewall_guard, "verify_linux", no_effect)
    monkeypatch.setattr(firewall_guard, "verify", no_effect)
    definition = {
        "allowlist": ["2001:db8::10/128"],
        "endpoints": [{"ip": "2001:db8::10", "port": 443}],
    }
    with pytest.raises(PermissionError, match=r"(?i)IPv6.*(NDP|neighbor|PMTU|qualification)"):
        operations._driver("2" * 32, definition)


def test_older_ipv6_receipt_can_still_release_exact_linux_owned_table(monkeypatch):
    captured = []
    monkeypatch.setattr(operations, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(operations.platform, "system", lambda: "Linux")
    monkeypatch.setattr(firewall_guard, "linux_tool", lambda: "/usr/sbin/nft")
    monkeypatch.setattr(
        operations,
        "_run",
        lambda args, **kwargs: captured.append((args, kwargs["payload"])),
    )
    operations._driver(
        "3" * 32,
        {
            "allowlist": ["2001:db8::10/128"],
            "endpoints": [{"ip": "2001:db8::10", "port": 443}],
        },
        release=True,
    )
    assert captured == [
        (
            ["/usr/sbin/nft", "-f", "-"],
            "delete table inet lumina_" + "3" * 32 + "\n",
        )
    ]


def test_typed_legacy_ipv6_release_remains_reachable_with_exact_receipt(
    monkeypatch,
):
    class MemoryConnection(sqlite3.Connection):
        closed = False

        def close(self):
            self.closed = True  # Inspect the in-memory final receipt below.

    db = sqlite3.connect(":memory:", factory=MemoryConnection)
    db.row_factory = sqlite3.Row
    db.execute(
        "CREATE TABLE isolation(id TEXT,digest TEXT,definition TEXT,state TEXT)"
    )
    configuration = settings("2001:db8::10")
    definition, digest = operations.network_definition(
        configuration, for_release=True
    )
    identifier = "4" * 32
    db.execute(
        "INSERT INTO isolation VALUES(?,?,?,'isolated')",
        (identifier, digest, json.dumps(definition)),
    )
    calls = []
    configuration["_management_probe"] = lambda: calls.append("authenticated-probe")
    monkeypatch.setattr(operations.platform, "system", lambda: "Linux")
    monkeypatch.setattr(operations, "_state", lambda _settings: (Path("virtual"), db))

    def remove_exact(value, requested, *, release=False, **_kwargs):
        assert value == identifier and requested == definition and release is True
        calls.append("exact-owned-release")

    monkeypatch.setattr(operations, "_driver", remove_exact)
    monkeypatch.setattr(
        operations, "_reachable", lambda *_args: calls.append("management-restored")
    )
    try:
        result = operations.isolate(
            {
                "type": "release_host",
                "isolation_id": identifier,
                "management_allowlist_digest": digest,
            },
            configuration,
        )
        assert result["success"] is True and result["executed"] is True
        assert calls == [
            "exact-owned-release",
            "management-restored",
            "authenticated-probe",
        ]
        assert db.execute("SELECT state FROM isolation").fetchone()[0] == "released"
        assert db.closed is True
    finally:
        sqlite3.Connection.close(db)


@pytest.mark.parametrize("address", ["192.0.2.10", "::1"])
def test_qualified_management_capabilities_publish_both_actions_without_effects(
    monkeypatch, address
):
    for name in ("_state", "_driver", "_reachable"):
        monkeypatch.setattr(operations, name, no_effect)
    configuration = settings(address)
    configuration["enabled"] = True
    capability = response.capabilities({"response": configuration})
    assert capability["actions"] == ["isolate_host", "release_host"]
    assert capability["host_isolation_apply_supported"] is True
    assert capability["host_isolation_apply_error"] is None
    assert capability["management_allowlist_digest"] == operations.network_definition(
        configuration
    )[1]


def test_legacy_ipv6_capabilities_publish_only_bound_release_without_effects(
    monkeypatch,
):
    for name in ("_state", "_driver", "_reachable"):
        monkeypatch.setattr(operations, name, no_effect)
    configuration = settings("2001:db8::10")
    configuration["enabled"] = True
    expected = operations.network_definition(configuration, for_release=True)[1]
    capability = response.capabilities({"response": configuration})
    assert capability["actions"] == ["release_host"]
    assert capability["management_allowlist_digest"] == expected
    assert capability["host_isolation_apply_supported"] is False
    assert "NDP" in capability["host_isolation_apply_error"]


@pytest.mark.parametrize("disabled", ["enabled", "allow_host_isolation"])
def test_local_optin_disabled_never_publishes_isolation_actions(
    monkeypatch, disabled
):
    monkeypatch.setattr(operations, "network_definition", no_effect)
    configuration = settings("2001:db8::10")
    configuration["enabled"] = True
    configuration[disabled] = False
    capability = response.capabilities({"response": configuration})
    assert capability["actions"] == []
    assert capability["management_allowlist_digest"] is None
    assert capability["host_isolation_apply_supported"] is False


def test_malformed_management_capabilities_publish_no_actions_or_digest(
    monkeypatch,
):
    for name in ("_state", "_driver", "_reachable"):
        monkeypatch.setattr(operations, name, no_effect)
    configuration = settings("192.0.2.10")
    configuration["enabled"] = True
    configuration["management_endpoints"][0]["port"] = True
    capability = response.capabilities({"response": configuration})
    assert capability["actions"] == []
    assert capability["management_allowlist_digest"] is None
    assert capability["host_isolation_apply_supported"] is False
    assert capability["host_isolation_apply_error"]
