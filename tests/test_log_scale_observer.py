"""Private population-budget routing; fake clients only, no service or workload."""

from types import SimpleNamespace

import httpx
import pytest

from tools import log_qualification_diagnostics as diagnostics
from tools import qualify_log_scale as scale


@pytest.fixture
def observer(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(scale, "time", SimpleNamespace(monotonic=lambda: now[0]))
    calls, failures = [], []

    class Client:
        response = httpx.Response(200, json={"registry_count": 12})
        error = None
        advance = 0

        def get(self, path, **kwargs):
            calls.append(("GET", path, kwargs))
            now[0] += self.advance
            if self.error:
                raise self.error
            return self.response

        def request(self, method, path, **kwargs):
            calls.append((method, path, kwargs))
            return self.response

    client = Client()
    trial = scale.Trial.__new__(scale.Trial)
    trial.record = SimpleNamespace(failure=None)
    trial.deadline = 1000
    trial.args = SimpleNamespace(query_timeout=15, fts_observation_timeout=600)
    trial.control = client
    trial.observe_http_failure = lambda method, path, began, **values: failures.append(
        (method, path, diagnostics.http_evidence(**values))
    )
    return trial, client, now, calls, failures


@pytest.mark.parametrize("query_timeout", [15, 120])
def test_population_budget_is_separate_from_ordinary_search_requests(
    observer, query_timeout
):
    trial, client, _, calls, _ = observer
    trial.args.query_timeout = query_timeout
    result = trial.actual_fts_population_request()
    assert result == {"registry_count": 12}
    method, path, options = calls[0]
    assert method == "GET" and path == "/__qa/scale/fts-population"
    assert float(options["headers"]["X-QA-Observation-Budget"]) == 600
    assert options["timeout"] == 605
    trial.request(client, "POST", "/api/logs/snapshots", json={"query": {}})
    assert calls[-1][2]["timeout"] == query_timeout + 5
    assert "X-QA-Observation-Budget" not in calls[-1][2].get("headers", {})
    assert trial.args.query_timeout == query_timeout


def test_observer_clips_header_and_transport_to_whole_run_deadline(observer):
    trial, _, _, calls, _ = observer
    trial.deadline = 40
    trial.actual_fts_population_request()
    assert float(calls[0][2]["headers"]["X-QA-Observation-Budget"]) == 40
    assert calls[0][2]["timeout"] == 40


def test_expired_whole_budget_never_sends_observation(observer):
    trial, _, now, calls, _ = observer
    now[0] = trial.deadline
    with pytest.raises(scale.ScaleFailure) as caught:
        trial.actual_fts_population_request()
    assert caught.value.kind == "time_budget" and calls == []


@pytest.mark.parametrize("transport", [False, True])
def test_observer_failure_is_captured_once_without_retry_or_private_text(
    observer, transport
):
    trial, client, _, calls, failures = observer
    if transport:
        client.error = httpx.ReadTimeout("private connection detail")
    else:
        client.response = httpx.Response(
            503, json={"detail": "private response detail"}
        )
    with pytest.raises(scale.ScaleFailure) as caught:
        trial.actual_fts_population_request()
    assert caught.value.kind == ("transport" if transport else "http")
    assert len(calls) == len(failures) == 1
    assert failures[0][1] == "/__qa/scale/fts-population"
    assert "private" not in str(caught.value) and "private" not in str(failures)


def test_response_after_whole_budget_does_not_publish_success(observer):
    trial, client, _, calls, _ = observer
    client.advance = 1001
    with pytest.raises(scale.ScaleFailure) as caught:
        trial.actual_fts_population_request()
    assert caught.value.kind == "time_budget" and len(calls) == 1


@pytest.mark.parametrize(
    "configured,requested,expected",
    [(120, "600", 120), (600, "2000", 600), (600, "0.25", 0.25)],
)
def test_private_server_observation_budget_respects_configured_ceiling(
    configured, requested, expected
):
    assert scale.fts_observation_budget(configured, requested) == expected


@pytest.mark.parametrize("bad", [True, 0, -1, 601, float("nan"), float("inf"), "600"])
def test_server_rejects_invalid_configured_observation_budget(bad):
    with pytest.raises(ValueError, match="deadline"):
        scale.fts_observation_budget(bad, "120")


@pytest.mark.parametrize("bad", [True, None, "", "nan", "inf", "0", "-1", "private"])
def test_server_rejects_invalid_requested_observation_budget(bad):
    with pytest.raises(ValueError, match="deadline"):
        scale.fts_observation_budget(600, bad)


def test_cli_observer_defaults_and_explicit_budget_do_not_change_search_timeout():
    default = scale.parse_args(["--report", "new.json"])
    assert default.fts_observation_timeout == default.query_timeout == 120
    explicit = scale.parse_args(
        [
            "--report",
            "new.json",
            "--query-timeout",
            "15",
            "--fts-observation-timeout",
            "600",
        ]
    )
    assert explicit.fts_observation_timeout == 600 and explicit.query_timeout == 15


@pytest.mark.parametrize("value", ["0", "-1", "601", "nan", "inf", "1.5"])
def test_cli_rejects_unbounded_observation_budget(value):
    with pytest.raises(SystemExit):
        scale.parse_args(["--report", "new.json", "--fts-observation-timeout", value])


def test_observation_flag_does_not_add_a_product_query_timeout_choice():
    with pytest.raises(SystemExit):
        scale.parse_args(["--report", "new.json", "--query-timeout", "600"])
