import json

import pytest

from tools import qualification
from tools.qualification import correctness, distribution, main, percentile


def test_nearest_rank_percentiles_include_tail_outlier():
    samples = list(range(1, 20)) + [1000]
    assert distribution(samples) == {
        "samples": 20,
        "p50": 10,
        "p95": 19,
        "max": 1000,
        "method": "nearest-rank",
    }
    assert distribution([])["p95"] is None
    with pytest.raises(ValueError):
        percentile(samples, 0)


def test_count_alone_does_not_hide_duplicate_or_corrupt_sequence():
    expected = [{"n": 4, "distinct_ids": 4, "sequence_sum": 6}]
    assert correctness(expected, 4)["passed"]
    assert not correctness([{"n": 4, "distinct_ids": 3, "sequence_sum": 6}], 4)[
        "passed"
    ]
    assert not correctness([{"n": 4, "distinct_ids": 4, "sequence_sum": 7}], 4)[
        "passed"
    ]


def test_explicit_isolation_required_before_any_service_can_start(tmp_path):
    with pytest.raises(SystemExit) as exc:
        main(["--output", str(tmp_path / "never-created.json")])
    assert exc.value.code == 2
    assert not (tmp_path / "never-created.json").exists()


def test_measurements_survive_cleanup_failure(monkeypatch, tmp_path):
    class Temporary:
        name = str(tmp_path / "owned-temp")

        def __init__(self, **kwargs):
            pass

        def cleanup(self):
            raise PermissionError("Synthetic cleanup failure")

    class Service:
        def __init__(self, *args):
            self.stop_checks = [{"listener_closed": True}]

        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(qualification.tempfile, "TemporaryDirectory", Temporary)
    monkeypatch.setattr(qualification, "IsolatedService", Service)
    monkeypatch.setattr(
        qualification, "qualify", lambda *args: {"passed": True, "admitted_eps": 123}
    )
    destination = tmp_path / "failed-run.json"
    with pytest.raises(PermissionError, match="Synthetic cleanup failure"):
        main(["--isolated", "--output", str(destination)])
    value = json.loads(destination.read_text(encoding="utf-8"))
    assert value["admitted_eps"] == 123
    assert value["passed"] is False
    assert value["cleanup_error_type"] == "PermissionError"
    assert value["service_stop_checks"] == [{"listener_closed": True}]
