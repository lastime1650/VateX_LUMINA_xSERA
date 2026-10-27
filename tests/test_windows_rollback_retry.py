"""Transient and permanent native rollback failures; no firewall effects."""

import json
from types import SimpleNamespace

from sapientia.endpoint_agent.Agent.Windows.isolation_watchdog import release_owned


def test_transient_rollback_failure_retries_then_confirms_without_false_failure(
    tmp_path,
):
    calls = []

    def driver(*args, **kwargs):
        calls.append(kwargs)
        if len(calls) < 3:
            raise OSError("Synthetic native release failure")

    operations = SimpleNamespace(_driver=driver)
    assert release_owned(
        operations,
        "a" * 32,
        {},
        tmp_path,
        clock=lambda: 50,
        pause=lambda _seconds: None,
    )
    assert len(calls) == 3 and all(c["release"] and c["deadline"] == 66 for c in calls)
    assert all(c["state_directory"] == tmp_path for c in calls)
    assert not list(tmp_path.iterdir())


def test_permanent_rollback_failure_stays_unconfirmed_and_persists_typed_errors(
    tmp_path,
):
    calls = []

    def driver(*_args, **_kwargs):
        calls.append(True)
        raise OSError("Do not persist server payloads or credentials")

    operations = SimpleNamespace(
        _driver=driver, __package__="sapientia.endpoint_agent.Agent"
    )
    assert (
        release_owned(
            operations,
            "b" * 32,
            {},
            tmp_path,
            clock=lambda: 50,
            pause=lambda _seconds: None,
        )
        is False
    )
    record = json.loads(
        (tmp_path / ("rollback-failure-" + "b" * 32 + ".json")).read_text()
    )
    assert len(calls) == 3 and record["confirmed_removed"] is False
    assert record["attempt_errors"] == ["OSError"] * 3
    assert "credentials" not in json.dumps(record)


def test_native_attempts_and_backoff_share_one_30_second_recovery_deadline(tmp_path):
    now = [50.0]
    calls = []

    def driver(*_args, **kwargs):
        calls.append(kwargs["deadline"])
        now[0] = kwargs["deadline"]
        raise TimeoutError("Each simulated native attempt consumed its budget")

    def pause(seconds):
        now[0] += seconds

    operations = SimpleNamespace(
        _driver=driver, __package__="sapientia.endpoint_agent.Agent"
    )
    assert not release_owned(
        operations,
        "c" * 32,
        {},
        tmp_path,
        clock=lambda: now[0],
        pause=pause,
    )
    assert calls == [66.0, 80.0]
    assert now[0] == 80.0
    record = json.loads(
        (tmp_path / ("rollback-failure-" + "c" * 32 + ".json")).read_text()
    )
    assert record["attempt_errors"] == ["TimeoutError", "TimeoutError"]
