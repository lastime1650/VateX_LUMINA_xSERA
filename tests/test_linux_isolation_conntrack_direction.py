"""Linux connection-direction fences; packet effects need native namespaces."""

import json
import sqlite3
from types import SimpleNamespace

import pytest

from sapientia.endpoint_agent.Agent import firewall_guard, operations


@pytest.fixture(autouse=True)
def never_execute_native_tools(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("A contract test reached a real native tool")

    monkeypatch.setattr(operations.subprocess, "run", forbidden)
    monkeypatch.setattr(operations, "_windows_batch", forbidden)
    monkeypatch.setattr(operations, "os", SimpleNamespace(name="posix"))


def capture_payload(monkeypatch):
    payloads = []
    monkeypatch.setattr(firewall_guard, "linux_tool", lambda: "/fixed/nft")
    monkeypatch.setattr(firewall_guard, "verify_linux", lambda *_args: None)
    monkeypatch.setattr(
        operations,
        "_run",
        lambda _args, **kwargs: payloads.append(kwargs["payload"]),
    )
    operations._driver(
        "a" * 32,
        {
            "allowlist": ["192.0.2.2/32"],
            "endpoints": [
                {"ip": "192.0.2.2", "port": 443, "direction": "outbound"},
                {"ip": "192.0.2.2", "port": 22, "direction": "inbound"},
            ],
        },
    )
    return payloads[0]


def test_output_and_input_hooks_are_after_conntrack_with_drop_policy(monkeypatch):
    payload = capture_payload(monkeypatch)
    assert payload.count("priority 0; policy drop;") == 2
    assert "priority -300" not in payload and "flush" not in payload


def test_management_original_packets_are_exact_tracked_service_direction(
    monkeypatch,
):
    payload = capture_payload(monkeypatch)
    original = "ct direction original ct state { new, established } counter accept"
    assert "output ip daddr 192.0.2.2 tcp dport 443 " + original in payload
    assert "input ip saddr 192.0.2.2 tcp dport 22 " + original in payload
    assert payload.count(original) == 2


def test_return_packets_cannot_exempt_established_inverse_source_port_flows(
    monkeypatch,
):
    payload = capture_payload(monkeypatch)
    reply = "ct direction reply ct state established counter accept"
    assert "input ip saddr 192.0.2.2 tcp sport 443 " + reply in payload
    assert "output ip daddr 192.0.2.2 tcp sport 22 " + reply in payload
    assert payload.count(reply) == 2
    # Established alone could preserve a pre-isolation inverse connection.
    assert "tcp sport 443 ct state established" not in payload
    assert "tcp sport 22 ct state established" not in payload


def test_no_blanket_established_accept_or_unrelated_protocol_exception(monkeypatch):
    rules = [line for line in capture_payload(monkeypatch).splitlines() if " rule " in line]
    assert len(rules) == 6  # Two loopback and four exact management packet rules.
    assert all("ifname lo accept" in rule or "ct direction " in rule for rule in rules)
    assert not any("ct state established accept" in rule for rule in rules)
    assert not any("udp" in rule or "icmp" in rule for rule in rules)


@pytest.mark.parametrize("priority", [-300, -200, -150, 1])
def test_new_native_apply_verifier_rejects_any_other_hook_priority(
    monkeypatch, priority
):
    identifier = "b" * 32
    rows = [
        {
            "chain": {
                "name": name,
                "table": "lumina_" + identifier,
                "family": "inet",
                "type": "filter",
                "hook": name,
                "policy": "drop",
                "prio": 0,
            }
        }
        for name in ("input", "output")
    ]
    monkeypatch.setattr(firewall_guard, "linux_tool", lambda: "/fixed/nft")
    monkeypatch.setattr(
        firewall_guard.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=json.dumps({"nftables": rows})),
    )
    assert firewall_guard.verify_linux(identifier)["owned_hooks_verified"] is True
    rows[1]["chain"]["prio"] = priority
    with pytest.raises(PermissionError):
        firewall_guard.verify_linux(identifier)


def test_legacy_receipt_expiry_removes_exact_table_without_apply_verifier(
    monkeypatch,
):
    identifier = "c" * 32
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE isolation(id TEXT,state TEXT,guard_pid INTEGER)")
    db.execute("INSERT INTO isolation VALUES(?,'isolated',123)", (identifier,))
    table_exists = iter([True, False])
    payloads = []
    monkeypatch.setattr(
        operations, "_linux_table_exists", lambda _id: next(table_exists)
    )
    monkeypatch.setattr(firewall_guard, "linux_tool", lambda: "/fixed/nft")
    monkeypatch.setattr(
        firewall_guard,
        "verify_linux",
        lambda *_args: (_ for _ in ()).throw(AssertionError("Legacy removal must not revalidate apply hooks")),
    )
    monkeypatch.setattr(
        operations,
        "_run",
        lambda _args, **kwargs: payloads.append(kwargs["payload"]),
    )
    try:
        operations._expire_isolation(db, {"id": identifier})
        assert payloads == ["delete table inet lumina_" + identifier + "\n"]
        assert db.execute("SELECT state,guard_pid FROM isolation").fetchone() == (
            "lease_expired",
            None,
        )
    finally:
        db.close()
