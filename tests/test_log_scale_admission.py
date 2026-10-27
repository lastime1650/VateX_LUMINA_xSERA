"""HTTP advice scheduling with fake clocks/clients; no service, Store or workload."""

import json
import threading
from array import array
from datetime import UTC, datetime
from email.utils import format_datetime
from types import SimpleNamespace

import httpx
import pytest

from tools import log_qualification_diagnostics as diagnostics
from tools import qualify_log_scale as scale


class Clock:
    def __init__(self):
        self.now = 0.0
        self.epoch = 1_700_000_000.0
        self.wall_offset = 0.0
        self.sleeps = []
        self.on_sleep = None

    def monotonic(self):
        return self.now

    def time(self):
        return self.epoch + self.now + self.wall_offset

    def sleep(self, seconds):
        assert 0 < seconds
        self.sleeps.append(seconds)
        self.now += seconds
        if self.on_sleep is not None:
            self.on_sleep()


class Client:
    def __init__(self, clock, actions):
        self.clock, self.actions, self.calls = clock, iter(actions), []

    def post(self, path, **kwargs):
        self.calls.append({"at": self.clock.monotonic(), "path": path, **kwargs})
        result = next(self.actions)
        if callable(result):
            result = result(self.clock)
        if isinstance(result, Exception):
            raise result
        return result


class Evidence:
    def __init__(self):
        self.observations, self.captures = [], []

    def observe(self, response, context, attempt, elapsed, error=None):
        self.observations.append(
            (diagnostics.http_evidence(response, error), context, attempt, elapsed)
        )

    def capture(self, kind, context):
        self.captures.append((kind, context))


def ack(accepted=1, duplicate=0):
    return httpx.Response(
        202, json={"durable": True, "accepted": accepted, "duplicate": duplicate}
    )


def capacity(retry_after="5", status=503):
    headers = {} if retry_after is None else {"Retry-After": retry_after}
    return httpx.Response(status, headers=headers, json={"detail": "untrusted-detail"})


@pytest.fixture
def admission(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(scale, "time", clock)

    def make(
        actions, mode="server_backoff", batch_seconds=300, attempts=64, overall=1000
    ):
        trial = scale.Trial.__new__(scale.Trial)
        trial.args = SimpleNamespace(
            admission_mode=mode,
            admission_batch_seconds=batch_seconds,
            admission_max_attempts=attempts,
            query_timeout=15,
            max_seconds=overall,
        )
        trial.deadline = clock.now + overall
        trial.monitor_stop = threading.Event()
        saves, resource_calls = [], []
        trial.record = SimpleNamespace(failure=None, save=lambda: saves.append(True))
        trial.evidence = Evidence()
        client = Client(clock, actions)
        trial.clients = {"default": (None, client)}
        trial.resource_check = lambda: resource_calls.append(clock.now)
        trial.attempt_latency, trial.batch_latency = array("d"), array("d")
        trial.metrics = {
            key: 0
            for key in (
                "accepted_acks",
                "duplicate_acks",
                "unique_original_events_acked",
                "original_wire_bytes",
                "transport_retries",
                "capacity_retries",
                "http_requests",
                "wire_request_bytes_including_retries",
                "retry_waits",
                "maximum_batch_attempts",
                "late_ack_batches",
            )
        }
        trial.metrics.update(
            retry_wait_seconds=0.0,
            retry_after_classifications={
                key: 0
                for key in ("delta", "http_date", "missing", "invalid", "out_of_policy")
            },
        )
        body = scale.dumps({"events": [{"event_id": "stable", "raw": {"sequence": 0}}]})
        return trial, client, body, clock, saves, resource_calls

    return make


def test_default_burst8_keeps_original_attempts_sleeps_and_ignores_retry_after(
    admission,
):
    trial, client, body, clock, saves, resources = admission(
        [capacity()] * 8, mode="burst8", batch_seconds=1, attempts=1
    )
    with pytest.raises(scale.ScaleFailure, match="retry budget exhausted") as caught:
        trial.admit("default", body, 1)
    assert caught.value.kind == "admission_retry"
    assert len(client.calls) == trial.metrics["capacity_retries"] == 8
    assert clock.sleeps == [0.05, 0.1, 0.2, 0.4, 0.8, 0.8, 0.8, 0.8]
    assert client.calls[-1]["at"] == pytest.approx(3.15)
    assert clock.now == pytest.approx(3.95)
    assert len(resources) == 8 and saves == [True]
    assert all(call["content"] is body for call in client.calls)
    assert scale.admission_retry_policy(trial.args)["max_attempts"] == 8


@pytest.mark.parametrize("status", [429, 503])
def test_server_advice_waits_five_seconds_with_no_early_post(admission, status):
    trial, client, body, clock, _, resources = admission(
        [capacity(status=status), ack()]
    )
    assert trial.admit("default", body, 1)["accepted"] == 1
    assert [call["at"] for call in client.calls] == [0, 5]
    assert max(clock.sleeps) <= 0.25 and resources == [0]
    assert trial.metrics["retry_wait_seconds"] == 5
    assert trial.metrics["retry_after_classifications"]["delta"] == 1
    assert trial.metrics["http_requests"] == 2
    assert trial.metrics["wire_request_bytes_including_retries"] == 2 * len(body)
    assert trial.metrics["unique_original_events_acked"] == 1
    assert trial.batch_latency == array("d", [5])


def test_ninth_attempt_succeeds_only_in_explicit_optional_mode(admission):
    trial, client, body, _, _, _ = admission([capacity()] * 8 + [ack()])
    trial.admit("default", body, 1)
    assert len(client.calls) == trial.metrics["maximum_batch_attempts"] == 9
    assert client.calls[-1]["at"] == 40
    assert trial.admission_summary()["retry_policy"]["client_durable_outbox"] is False


def test_http_date_deadline_uses_one_wall_clock_conversion(admission):
    trial, client, body, clock, _, _ = admission([])
    header = format_datetime(datetime.fromtimestamp(clock.time() + 5, UTC), usegmt=True)
    client.actions = iter([capacity(header), ack()])
    clock.on_sleep = lambda: setattr(clock, "wall_offset", 86_400)
    trial.admit("default", body, 1)
    assert client.calls[1]["at"] == 5
    assert trial.metrics["retry_after_classifications"]["http_date"] == 1


def test_resource_observation_time_is_already_part_of_response_advice_wait(admission):
    trial, client, body, clock, _, _ = admission([capacity(), ack()])
    trial.resource_check = lambda: setattr(clock, "now", clock.now + 7)
    trial.admit("default", body, 1)
    assert client.calls[1]["at"] == 7 and clock.sleeps == []


@pytest.mark.parametrize("header", ["0", "Wed, 21 Oct 2015 07:28:00 GMT"])
def test_zero_and_past_advice_have_a_minimum_retry_delay(admission, header):
    trial, client, body, _, _, _ = admission([capacity(header), ack()])
    trial.admit("default", body, 1)
    assert client.calls[1]["at"] == 1


@pytest.mark.parametrize(
    "value", ["", "-1", "1.5", "NaN", "+5", "5, 10", "x" * 65, " " * 65 + "5"]
)
def test_malformed_advice_uses_labeled_fallback(value):
    assert scale.admission_retry_delay(httpx.Headers({"Retry-After": value}), 2, 0) == (
        "invalid",
        4,
    )


def test_non_ascii_and_duplicate_fields_do_not_parse_as_valid_advice():
    headers = httpx.Headers([(b"Retry-After", b"\xe9")], encoding="latin-1")
    assert scale.admission_retry_delay(headers, 0, 0) == ("invalid", 1)
    duplicated = httpx.Headers([("Retry-After", "5"), ("Retry-After", "10")])
    assert scale.admission_retry_delay(duplicated, 0, 0) == ("invalid", 1)


def test_missing_advice_fallback_is_bounded_and_not_a_busy_loop(admission):
    trial, client, body, _, _, _ = admission([capacity(None)] * 6 + [ack()])
    trial.admit("default", body, 1)
    assert [call["at"] for call in client.calls] == [0, 1, 3, 7, 15, 25, 35]
    assert trial.metrics["retry_after_classifications"]["missing"] == 6


@pytest.mark.parametrize("header", ["121", "9" * 64, "Wed, 21 Oct 2099 07:28:00 GMT"])
def test_advice_outside_policy_fails_without_early_retry(admission, header):
    trial, client, body, clock, saves, _ = admission([capacity(header)])
    with pytest.raises(scale.ScaleFailure) as caught:
        trial.admit("default", body, 1)
    assert caught.value.kind == "admission_retry_advice"
    assert len(client.calls) == 1 and clock.sleeps == [] and saves == [True]
    assert trial.metrics["retry_after_classifications"]["out_of_policy"] == 1


@pytest.mark.parametrize("batch_seconds,overall", [(4, 1000), (300, 4), (5, 1000)])
def test_advice_that_cannot_fit_budget_never_retries_early(
    admission, batch_seconds, overall
):
    trial, client, body, clock, _, _ = admission(
        [capacity()], batch_seconds=batch_seconds, overall=overall
    )
    with pytest.raises(scale.ScaleFailure) as caught:
        trial.admit("default", body, 1)
    assert caught.value.kind == "admission_retry_budget"
    assert len(client.calls) == 1 and clock.sleeps == []


def test_attempt_limit_terminates_without_extra_last_failure_sleep(admission):
    trial, client, body, clock, saves, _ = admission([capacity()] * 3, attempts=3)
    with pytest.raises(scale.ScaleFailure) as caught:
        trial.admit("default", body, 1)
    assert caught.value.kind == "admission_retry"
    assert len(client.calls) == trial.metrics["maximum_batch_attempts"] == 3
    assert clock.now == 10 and saves == [True]


def test_cooperative_wait_honors_monitor_failure_and_cancellation(admission):
    trial, client, body, clock, _, _ = admission([capacity()])
    failure = scale.ScaleFailure("capacity_disk", "synthetic guard failure")
    clock.on_sleep = lambda: setattr(trial.record, "failure", failure)
    with pytest.raises(scale.ScaleFailure) as caught:
        trial.admit("default", body, 1)
    assert caught.value is failure and len(client.calls) == 1
    assert trial.metrics["retry_wait_seconds"] == 0.25
    trial.record.failure = None
    clock.on_sleep = lambda: trial.monitor_stop.set()
    client.actions = iter([capacity()])
    with pytest.raises(scale.ScaleFailure) as caught:
        trial.admit("default", body, 1)
    assert caught.value.kind == "interrupted" and len(client.calls) == 2


def test_resource_failure_is_not_converted_to_an_admission_retry(admission):
    trial, client, body, clock, _, _ = admission([capacity()])
    failure = scale.ScaleFailure("capacity_ram", "synthetic RAM guard")

    def fail():
        raise failure

    trial.resource_check = fail
    with pytest.raises(scale.ScaleFailure) as caught:
        trial.admit("default", body, 1)
    assert caught.value is failure and len(client.calls) == 1 and clock.sleeps == []


def test_transport_lost_ack_reuses_body_and_counts_one_logical_original(admission):
    trial, client, body, _, _, _ = admission(
        [httpx.ReadError("private transport text"), ack(accepted=0, duplicate=1)]
    )
    trial.admit("default", body, 1)
    assert all(call["content"] is body for call in client.calls)
    assert trial.metrics["transport_retries"] == 1
    assert (
        trial.metrics["duplicate_acks"]
        == trial.metrics["unique_original_events_acked"]
        == 1
    )
    assert trial.metrics["accepted_acks"] == 0
    assert trial.metrics["wire_request_bytes_including_retries"] == 2 * len(body)
    assert trial.metrics["original_wire_bytes"] == len(body)
    assert "private transport text" not in json.dumps(trial.evidence.observations)


@pytest.mark.parametrize("status", [400, 403, 409, 422, 500])
def test_nonretryable_http_failure_is_immediate(admission, status):
    trial, client, body, clock, _, resources = admission([httpx.Response(status)])
    with pytest.raises(scale.ScaleFailure) as caught:
        trial.admit("default", body, 1)
    assert caught.value.kind == "http"
    assert len(client.calls) == 1 and clock.sleeps == resources == []


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(202, content=b"invalid JSON"),
        httpx.Response(202, json=[]),
        httpx.Response(202, json={"durable": False, "accepted": 1, "duplicate": 0}),
        httpx.Response(202, json={"durable": True, "accepted": True, "duplicate": 0}),
        httpx.Response(202, json={"durable": True, "accepted": 0, "duplicate": 0}),
        httpx.Response(202, json={"durable": True, "accepted": -1, "duplicate": 2}),
        httpx.Response(202, json={"durable": True, "accepted": 2, "duplicate": -1}),
    ],
)
@pytest.mark.parametrize("mode", ["burst8", "server_backoff"])
def test_invalid_durable_receipt_is_never_retried_or_counted(admission, response, mode):
    trial, client, body, clock, _, _ = admission([response], mode=mode)
    with pytest.raises(scale.ScaleFailure) as caught:
        trial.admit("default", body, 1)
    assert caught.value.kind == "integrity"
    assert len(client.calls) == 1 and clock.sleeps == []
    assert trial.metrics["unique_original_events_acked"] == 0


def test_late_valid_ack_is_counted_then_fails_cooperative_budget(admission):
    def late(clock):
        clock.now += 4
        return ack()

    trial, client, body, _, _, _ = admission([late], batch_seconds=3)
    with pytest.raises(scale.ScaleFailure) as caught:
        trial.admit("default", body, 1)
    assert caught.value.kind == "admission_retry_budget"
    assert (
        trial.metrics["unique_original_events_acked"]
        == trial.metrics["late_ack_batches"]
        == 1
    )
    assert client.calls[0]["timeout"] == 3


def test_replay_ack_is_not_counted_as_an_original(admission):
    trial, _, body, _, _, _ = admission([ack(accepted=0, duplicate=1)])
    trial.admit("default", body, 1, original=False)
    assert (
        trial.metrics["unique_original_events_acked"]
        == trial.metrics["original_wire_bytes"]
        == 0
    )
    assert trial.metrics["duplicate_acks"] == 1


def test_cli_defaults_preserve_burst8_and_optional_mode_reports_distinct_limits():
    args = scale.parse_args(["--report", "new.json"])
    assert scale.admission_retry_policy(args)["mode"] == "burst8"
    args = scale.parse_args(
        ["--report", "new.json", "--admission-mode", "server_backoff"]
    )
    policy = scale.admission_retry_policy(args)
    assert policy["batch_budget_seconds"] == 300 and policy["max_attempts"] == 64
    assert policy["overall_budget_seconds"] == args.max_seconds == 7200
    assert policy["retry_after_max_seconds"] == 120
    assert policy["client_durable_outbox"] is False


@pytest.mark.parametrize("mode", ["burst8", "server_backoff"])
def test_trial_initializes_explicit_mode_metrics_and_correct_diagnostic_scope(
    monkeypatch, tmp_path, mode
):
    monkeypatch.setattr(scale, "Service", lambda *args: SimpleNamespace())
    monkeypatch.setattr(scale, "source_identity", dict)
    args = scale.parse_args(["--report", "new.json", "--admission-mode", mode])
    record = scale.Recorder(tmp_path / "not-written.json", {})
    trial = scale.Trial(
        args, tmp_path, record, {"base_epoch": 1_700_000_000, "corpus_key": "ab" * 32}
    )
    scope = record.value["admission_diagnostics"]["timing_scope"]
    if mode == "server_backoff":
        assert "server_backoff" in scope and "unchanged8" not in scope
        assert trial.metrics["maximum_batch_attempts"] == 0
    else:
        assert "unchanged8-attempt" in scope
        assert "maximum_batch_attempts" not in trial.metrics
    assert trial.admission_summary()["retry_policy"]["mode"] == mode
    assert not record.target.exists()


@pytest.mark.parametrize("target_complete", [False, True])
def test_final_report_keeps_failure_and_separates_target_from_partial_fts(
    monkeypatch, tmp_path, target_complete
):
    from tools import qualify_security_flow

    def phase(name, population):
        return {
            "phase": name,
            "population": population,
            "passed": True,
            "fts_population": {"passed": True, "expected_population": population},
            "actual_fts_population": {
                "passed": True,
                "expected_population": population,
            },
        }

    class FailedTrial:
        def __init__(self, args, directory, record, config):
            self.record = record

        def run(self):
            phases = [
                phase("cold", 500_000),
                phase("incremental", 1_000_000),
                phase("capacity", 5_000_000),
            ]
            if target_complete:
                phases += [
                    phase("capacity", 50_000_000),
                    phase("after_restart", 50_000_000),
                ]
            self.record.update(fts=phases)
            raise scale.ScaleFailure("admission_retry", "Retained synthetic failure")

        def close(self):
            self.record.update(shutdown={"passed": True})

    monkeypatch.setattr(scale, "WORK", tmp_path)
    monkeypatch.setattr(scale, "Trial", FailedTrial)
    monkeypatch.setattr(
        scale,
        "system_resources",
        lambda _: {
            "disk_free_bytes": 100 * 1024**3,
            "available_ram_bytes": 8 * 1024**3,
            "rss_bytes": 1,
        },
    )
    monkeypatch.setattr(
        qualify_security_flow, "private_directory", lambda path: path.mkdir()
    )
    report = tmp_path / "new-report.json"
    assert scale.main(["--report", str(report), "--events", "50000000"]) == 1
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["passed"] is data["storage_integrity_passed"] is False
    assert data["failure"]["kind"] == "admission_retry"
    assert data["fts_qualified"] is target_complete
    assert data["fts_recorded_phase_checks_passed"] is True
    assert data["fts_highest_verified_population"] == (
        50_000_000 if target_complete else 5_000_000
    )
    assert data["fts_required_population"] == 50_000_000
    assert data["settings"]["admission_retry_policy"]["mode"] == "burst8"


@pytest.mark.parametrize(
    "flags",
    [
        ["--admission-mode", "durable_producer"],
        ["--admission-batch-seconds", "nan"],
        ["--admission-batch-seconds", "inf"],
        ["--admission-batch-seconds", "0"],
        ["--admission-batch-seconds", "601"],
        ["--admission-max-attempts", "0"],
        ["--admission-max-attempts", "65"],
    ],
)
def test_cli_rejects_unbounded_optional_admission_limits(flags):
    with pytest.raises(SystemExit):
        scale.parse_args(["--report", "new.json", *flags])
