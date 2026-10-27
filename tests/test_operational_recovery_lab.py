"""Executable isolated qualification of actual storage/authority contracts."""

import pytest

from tools.operational_recovery_lab import qualify_operational


def test_isolation_required_before_opening_any_store(tmp_path):
    with pytest.raises(ValueError, match="isolated"):
        qualify_operational(parent=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_all_bounded_operational_probes_report_real_outcomes_and_limits(tmp_path):
    result = qualify_operational(isolated=True, parent=tmp_path)
    assert result["passed"], result["checks"]
    assert len(result["checks"]) == 8 and all(check["passed"] for check in result["checks"])
    assert not result["native_effect"] and not result["host_os_or_network_mutated"]
    assert "not hard power loss" in result["limits"][0]
    assert list(tmp_path.iterdir()) == []
