"""Pure Windows isolation predicate checks; never apply native firewall rules."""

import ipaddress

import pytest

from sapientia.endpoint_agent.Agent import operations

IDENTIFIER = "7" * 32
MANAGEMENT_IP = "192.0.2.8"


def contains_port(ranges, value):
    return any(
        int(part.split("-")[0]) <= value <= int(part.split("-")[-1])
        for part in ranges.split(",")
    )


def contains_address(ranges, value):
    address = ipaddress.ip_address(value)
    for part in ranges.split(","):
        bounds = part.split("-")
        start = ipaddress.ip_address(bounds[0])
        end = ipaddress.ip_address(bounds[-1])
        if (
            start.version == address.version
            and int(start) <= int(address) <= int(end)
        ):
            return True
    return False


def blocked(rules, direction, local_port, remote_port, address=MANAGEMENT_IP, protocol=6):
    return any(
        rule["direction"] == direction
        and rule["protocol"] in (256, protocol)
        and contains_address(rule["remote"], address)
        and (
            rule["protocol"] != 6
            or contains_port(rule["localport"], local_port)
            and contains_port(rule["remoteport"], remote_port)
        )
        for rule in rules.values()
    )


@pytest.fixture
def rules():
    return operations._windows_rules(
        IDENTIFIER,
        {
            "endpoints": [
                {"ip": MANAGEMENT_IP, "port": 443, "direction": "outbound"},
                {"ip": MANAGEMENT_IP, "port": 8788, "direction": "inbound"},
            ]
        },
    )


@pytest.mark.parametrize(
    ("direction", "local_port", "remote_port", "expected"),
    [
        (2, 49152, 443, False),
        (1, 8788, 49152, False),
        (2, 49152, 50000, True),
        (1, 50000, 49152, True),
        # Prior conjunction of both port complements missed these exact tuples.
        (2, 8788, 50000, True),
        (1, 50000, 443, True),
        (2, 8788, 443, False),
        (1, 8788, 443, False),
    ],
)
def test_management_exception_is_directional_not_opposite_source_port(
    rules, direction, local_port, remote_port, expected
):
    assert blocked(rules, direction, local_port, remote_port) is expected


@pytest.mark.parametrize("direction", [1, 2])
@pytest.mark.parametrize("protocol", [0, 1, 17, 41, 58, 255])
def test_management_ip_never_implicitly_allows_non_tcp(rules, direction, protocol):
    assert blocked(rules, direction, 0, 0, protocol=protocol)


@pytest.mark.parametrize("direction", [1, 2])
@pytest.mark.parametrize("address", ["192.0.2.9", "198.51.100.1", "2001:db8::9"])
def test_unapproved_ip_still_blocked_even_at_approved_ports(rules, direction, address):
    assert blocked(rules, direction, 8788, 443, address=address)


def test_old_two_complements_leave_opposite_port_predicate_gap(rules):
    historical = {name: dict(rule) for name, rule in rules.items()}
    prefix = "Lumina-Isolation-" + IDENTIFIER
    historical[prefix + "-m0-tcp-out"]["localport"] = "0-8787,8789-65535"
    historical[prefix + "-m0-tcp-in"]["remoteport"] = "0-442,444-65535"
    assert not blocked(historical, 2, 8788, 50000)
    assert not blocked(historical, 1, 50000, 443)
    assert blocked(rules, 2, 8788, 50000)
    assert blocked(rules, 1, 50000, 443)


def test_one_sided_management_never_grants_other_direction():
    rules = operations._windows_rules(
        IDENTIFIER, {"endpoints": [{"ip": MANAGEMENT_IP, "port": 443}]}
    )
    assert not blocked(rules, 2, 49152, 443)
    assert blocked(rules, 1, 50000, 443)
    inbound_only = operations._windows_rules(
        IDENTIFIER,
        {"endpoints": [{"ip": MANAGEMENT_IP, "port": 8788, "direction": "inbound"}]},
    )
    assert not blocked(inbound_only, 1, 8788, 49152)
    assert blocked(inbound_only, 2, 8788, 50000)


def test_multiple_management_ports_do_not_widen_any_other_port():
    rules = operations._windows_rules(
        IDENTIFIER,
        {
            "endpoints": [
                {"ip": MANAGEMENT_IP, "port": port, "direction": direction}
                for direction, port in [("outbound", 443), ("outbound", 8443), ("inbound", 8788)]
            ]
        },
    )
    for remote in (443, 8443):
        assert not blocked(rules, 2, 8788, remote)
    assert blocked(rules, 2, 8788, 8444)
    assert blocked(rules, 1, 8789, 443)


def test_explicit_all_port_range_keeps_existing_numeric_native_contract(rules):
    prefix = "Lumina-Isolation-" + IDENTIFIER
    assert rules[prefix + "-m0-tcp-out"]["localport"] == "0-65535"
    assert rules[prefix + "-m0-tcp-in"]["remoteport"] == "0-65535"
    assert len(rules) == 514
    assert set(rules).issubset(operations._windows_release_names(IDENTIFIER))
