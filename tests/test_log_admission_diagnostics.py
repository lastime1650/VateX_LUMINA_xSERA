"""Small private-evidence regressions; no Store, service or scale workload."""

import json
import sqlite3
import threading
import time
from array import array
from types import SimpleNamespace

import httpx
import pytest

from tools import log_qualification_diagnostics as evidence
from tools import qualify_log_platform as platform
from tools import qualify_log_scale as scale

CAPACITY_DETAIL = "Full-text pending journal full; indexing must catch up before source acknowledgement"
SECRET = "never-emit-private-token-or-log-body"


@pytest.mark.parametrize("detail", [SECRET, {"token": SECRET}, [SECRET], SECRET * 500])
def test_response_details_never_copy_unknown_text_or_payload(detail):
    result = evidence.http_evidence(httpx.Response(429, json={"detail": detail}))
    assert result["status"] == 429 and "omitted" in result["detail_code"]
    assert SECRET not in json.dumps(result)
    known = evidence.http_evidence(
        httpx.Response(503, json={"detail": CAPACITY_DETAIL})
    )
    assert known["detail_code"] == "fts_journal_full"


def test_observations_and_first_failure_snapshots_are_bounded():
    calls, target = [], {}
    observed = evidence.AdmissionEvidence(
        target, lambda deadline, context: calls.append(deadline) or {}
    )
    for attempt in range(100):
        observed.observe(
            httpx.Response(429, json={"detail": SECRET}),
            {"batch_events": 1},
            attempt % 8,
            0.01,
        )
        observed.capture("first_capacity", {"batch_events": 1})
    observed.capture("admission_failed", {"batch_events": 1})
    observed.capture("admission_failed", {"batch_events": 1})
    observed.capture("unneeded_third_snapshot", {})
    assert observed.finish()
    assert len(target["attempts"]) == 64 and target["dropped_attempts"] == 36
    assert len(calls) == len(target["snapshots"]) == 2
    assert SECRET not in json.dumps(target)
    assert all(0 < item["budget_seconds"] <= 2 for item in target["snapshots"])


def raising_snapshot(deadline, context):
    raise RuntimeError(SECRET)


def test_snapshot_failure_keeps_only_exception_type():
    target = {}
    observed = evidence.AdmissionEvidence(target, raising_snapshot)
    observed.capture("admission_failed", {})
    assert target["snapshots"][0]["observation_error"] == "RuntimeError"
    assert SECRET not in json.dumps(target)


def test_first_capacity_snapshot_never_blocks_original_retry_sequence(monkeypatch):
    started, release, completed = (
        threading.Event(),
        threading.Event(),
        threading.Event(),
    )

    def snapshot(deadline, context):
        if context["diagnostic_cause"] == "first_capacity":
            started.set()
            try:
                release.wait(2)
            finally:
                completed.set()
        return {}

    monkeypatch.setattr(platform, "monitor", lambda *args, **kwargs: None)
    monkeypatch.setattr(platform.time, "sleep", lambda seconds: None)
    client = RejectingClient()
    metrics = {
        "accepted_acks": 0,
        "duplicate_acks": 0,
        "capacity_retries": 0,
        "transport_retries": 0,
        "request_seconds": [],
    }
    target = {}
    observed = evidence.AdmissionEvidence(target, snapshot)
    try:
        with pytest.raises(
            platform.CheckFailure, match="Admission retry budget exhausted"
        ):
            platform.admit(client, [{"raw": {"sequence": 461000}}], metrics, observed)
        assert started.wait(0.5)
        assert client.calls == 8 and metrics["capacity_retries"] == 8
        # All producer retries failed while the first snapshot is still blocked.
        # A synchronous first snapshot would finish/timed-out before reaching here.
        assert not completed.is_set()
    finally:
        release.set()
        assert observed.finish()
    assert target["background_snapshot_finished"] is True


def test_unfinished_owned_diagnostic_thread_is_never_reported_as_completed():
    release, started = threading.Event(), threading.Event()

    def snapshot(deadline, context):
        started.set()
        release.wait(2)
        return {}

    target = {}
    observed = evidence.AdmissionEvidence(target, snapshot, budget_seconds=0.001)
    try:
        observed.capture("first_capacity", {})
        assert started.wait(0.5)
        assert observed.finish() is False
        assert target["background_snapshot_finished"] is False
    finally:
        release.set()
        assert observed.finish()


@pytest.mark.parametrize("budget", [True, 0, -1, float("nan"), float("inf"), 3])
def test_unbounded_or_nonfinite_diagnostic_deadlines_are_rejected(budget):
    with pytest.raises(ValueError, match="finite"):
        evidence.AdmissionEvidence({}, raising_snapshot, budget)


@pytest.fixture
def private_store(tmp_path):
    control = tmp_path / "control.sqlite3"
    with sqlite3.connect(control) as db:
        db.executescript(
            "CREATE TABLE log_fts_state(singleton,indexed_documents,pending_documents,pending_bytes,"
            "applied_sequence,bootstrap_required,generation,purges,last_error);"
            "INSERT INTO log_fts_state VALUES(1,7,3,901,11,0,4,2,'sqlite_interrupted');"
            "CREATE TABLE log_fts_inflight(seq);INSERT INTO log_fts_inflight VALUES(1);"
            "CREATE TABLE queue(payload);"
        )
        db.execute("INSERT INTO queue VALUES(?)", (SECRET,))
    cache = tmp_path / "log-search" / "terms.sqlite3"
    cache.parent.mkdir()
    with sqlite3.connect(cache) as db:
        db.executescript(
            "CREATE TABLE metadata(format_version,applied_sequence,generation,purges,documents);"
            "INSERT INTO metadata VALUES(2,11,4,2,7);"
        )
    return SimpleNamespace(path=tmp_path, operational=control), cache


def runtime():
    return SimpleNamespace(
        health=lambda: {
            "fulltext_worker_running": True,
            "fulltext_error": "OperationalError",
            "fulltext_error_code": "sqlite_interrupted",
            "error": None,
            "raw_debug": SECRET,
        }
    )


def test_local_diagnostics_are_read_only_scalars_and_keep_exact_error_code(
    private_store,
):
    store, cache = private_store
    before = [store.operational.read_bytes(), cache.read_bytes()]
    result = evidence.local_snapshot(store, runtime(), time.monotonic() + 1)
    assert result["control"] == {
        "indexed_documents": 7,
        "pending_documents": 3,
        "pending_bytes": 901,
        "applied_sequence": 11,
        "bootstrap_required": 0,
        "generation": 4,
        "purges": 2,
        "inflight": 1,
        "source_pending": 1,
        "last_error": "sqlite_interrupted",
    }
    assert result["runtime"]["fulltext_error_code"] == "sqlite_interrupted"
    assert result["runtime"]["fulltext_worker_running"] is True
    assert result["cache_metadata"]["documents"] == 7
    assert SECRET not in json.dumps(result)
    assert [store.operational.read_bytes(), cache.read_bytes()] == before


def test_missing_control_observation_keeps_worker_liveness_without_creating_files(
    tmp_path,
):
    store = SimpleNamespace(path=tmp_path, operational=tmp_path / "absent.sqlite3")
    result = evidence.local_snapshot(store, runtime(), time.monotonic() + 1)
    assert result["control_observation_error"] == "OperationalError"
    assert result["runtime"]["fulltext_worker_running"] is True
    assert not store.operational.exists() and result["cache_exists"] is False


@pytest.mark.parametrize(
    "code",
    [
        "sqlite_interrupted",
        "sqlite_busy",
        "sqlite_error",
        "disk_quota",
        "disk_reserve",
        "journal_capacity",
        "deadline",
        "cache_conflict",
    ],
)
def test_stable_product_error_codes_are_not_sanitized_away(code):
    assert evidence.error_code(code) == code
    assert evidence.error_code({"secret": SECRET}) == "unrecognized_error_code"


def test_public_snapshot_has_finite_http_deadline_and_omits_unselected_fields():
    calls = []
    client = SimpleNamespace(
        get=lambda path, timeout: (
            calls.append((path, timeout))
            or httpx.Response(
                200,
                json={
                    "search": {
                        "fulltext": {
                            "state": "error",
                            "error": "sqlite_interrupted",
                            "ready": False,
                            "pending_documents": 3,
                            "pending_bytes": 901,
                            "raw": SECRET,
                        }
                    },
                    "snapshots": [{"private": SECRET}],
                },
            )
        )
    )
    result = evidence.public_snapshot(client, 0.5)
    assert calls == [("/api/logs/status", 0.5)]
    assert result["http_timeout_seconds"] == 0.5
    assert result["fulltext"]["error"] == "sqlite_interrupted"
    assert SECRET not in json.dumps(result)


def test_expired_snapshot_budget_performs_no_http_or_sqlite_creation(tmp_path):
    store = SimpleNamespace(path=tmp_path, operational=tmp_path / "absent.sqlite3")
    client = SimpleNamespace(
        get=lambda *args, **kwargs: pytest.fail("HTTP after deadline")
    )
    result = evidence.combined_snapshot(store, runtime(), client, time.monotonic() - 1)
    assert (
        result["observation_error"] == "diagnostic_deadline"
        and not store.operational.exists()
    )


class RejectingClient:
    def __init__(self, status=429, transport=False):
        self.calls, self.status, self.transport = 0, status, transport

    def post(self, *args, **kwargs):
        self.calls += 1
        if self.transport:
            raise httpx.ReadTimeout(SECRET)
        return httpx.Response(self.status, json={"detail": CAPACITY_DETAIL})


@pytest.mark.parametrize("transport", [False, True])
def test_platform_diagnostics_preserve_eight_retries_and_original_failure(
    monkeypatch, transport
):
    sleeps = []
    monkeypatch.setattr(platform, "monitor", lambda *args, **kwargs: None)
    monkeypatch.setattr(platform.time, "sleep", sleeps.append)
    client = RejectingClient(transport=transport)
    metrics = {
        "accepted_acks": 0,
        "duplicate_acks": 0,
        "capacity_retries": 0,
        "transport_retries": 0,
        "request_seconds": [],
    }
    target = {}
    observed = evidence.AdmissionEvidence(target, raising_snapshot)
    with pytest.raises(platform.CheckFailure, match="Admission retry budget exhausted"):
        platform.admit(
            client,
            [{"raw": {"sequence": 461000, "payload": SECRET}}],
            metrics,
            observed,
        )
    assert observed.finish()
    assert client.calls == 8 and sum(sleeps) == pytest.approx(4.55)
    assert metrics["transport_retries" if transport else "capacity_retries"] == 8
    assert target["attempts"][-1]["attempt"] == 8
    assert target["snapshots"][-1]["minimum_sequence"] == 461000
    assert SECRET not in json.dumps(target)


@pytest.mark.parametrize("transport", [False, True])
def test_scale_diagnostics_preserve_eight_retries_and_original_failure(
    tmp_path, monkeypatch, transport
):
    sleeps = []
    monkeypatch.setattr(scale.time, "sleep", sleeps.append)
    trial = scale.Trial.__new__(scale.Trial)
    trial.guard = lambda: None
    trial.resource_check = dict
    trial.args = SimpleNamespace(query_timeout=15)
    trial.deadline = time.monotonic() + 60
    trial.clients = {
        "default": (None, RejectingClient(status=503, transport=transport))
    }
    trial.metrics = dict.fromkeys(
        (
            "accepted_acks",
            "duplicate_acks",
            "capacity_retries",
            "transport_retries",
            "http_requests",
            "wire_request_bytes_including_retries",
            "unique_original_events_acked",
        ),
        0,
    )
    trial.attempt_latency, trial.batch_latency = array("d"), array("d")
    trial.record = scale.Recorder(tmp_path / "report.json", {})
    target = trial.record.value["admission_diagnostics"] = {}
    trial.evidence = evidence.AdmissionEvidence(target, raising_snapshot)
    body = scale.dumps({"events": [{"raw": {"sequence": 461000, "payload": SECRET}}]})
    with pytest.raises(scale.ScaleFailure, match="retry budget exhausted") as failed:
        trial.admit("default", body, 1)
    assert trial.evidence.finish()
    assert failed.value.kind == "admission_retry"
    assert trial.clients["default"][1].calls == 8 and sum(sleeps) == pytest.approx(3.95)
    assert target["attempts"][-1]["attempt"] == 8
    assert target["snapshots"][-1]["minimum_sequence"] == 461000
    assert SECRET not in json.dumps(target)


def test_malformed_body_cannot_replace_retry_failure_during_diagnostics():
    assert evidence.encoded_batch_summary(
        b"not JSON " + SECRET.encode(), 1000, 461000
    ) == {
        "batch_events": 1000,
        "acknowledged_before": 461000,
    }


def test_failed_scale_run_still_checks_helper_identity_and_stops_owned_service(
    tmp_path, monkeypatch
):
    initial = {
        "product_source_sha256": "product",
        "harness_sha256": "harness",
        "diagnostics_helper_sha256": "helper",
    }
    monkeypatch.setattr(
        scale,
        "source_identity",
        lambda: {**initial, "diagnostics_helper_sha256": "changed"},
    )
    stopped = []
    trial = scale.Trial.__new__(scale.Trial)
    trial.source = initial
    trial.record = scale.Recorder(tmp_path / "report.json", {})
    trial.monitor_stop, trial.monitor = threading.Event(), None
    trial.disconnect = lambda: None
    trial.admission_summary = dict
    trial.service = SimpleNamespace(
        stop=lambda: stopped.append(True),
        starts=[],
        stop_checks=[
            {
                "owned_process_exited": True,
                "listener_closed": True,
                "database_handle_released": True,
            }
        ],
    )
    with pytest.raises(scale.ScaleFailure, match="helper bytes changed"):
        trial.close()
    assert stopped == [True]
    assert trial.record.value["source_unchanged_during_run"] is True
    assert trial.record.value["harness_unchanged_during_run"] is False
    assert trial.record.value["shutdown"]["passed"] is False


@pytest.mark.parametrize(
    ("detail", "code"),
    [
        (
            "Log search deadline exceeded while waiting for storage",
            "snapshot_storage_deadline",
        ),
        ("Log snapshot deadline exceeded; narrow the time range", "snapshot_deadline"),
        ("Full-text search deadline exceeded", "fts_search_deadline"),
        (
            "Tenant snapshot quota exhausted; close expired searches",
            "snapshot_tenant_quota",
        ),
        ("Tenant snapshot quota exhausted during publication", "snapshot_tenant_quota"),
        (
            "Snapshot disk budget exceeded; narrow the time range",
            "snapshot_disk_budget",
        ),
        ("Snapshot disk reserve reached", "snapshot_disk_reserve"),
    ],
)
def test_snapshot_failure_codes_require_exact_known_messages(detail, code):
    assert (
        evidence.http_evidence(httpx.Response(503, json={"detail": detail}))[
            "detail_code"
        ]
        == code
    )
    unknown = evidence.http_evidence(
        httpx.Response(503, json={"detail": detail + " " + SECRET})
    )
    assert unknown["detail_code"] == "unrecognized_detail_omitted"
    assert SECRET not in json.dumps(unknown)


@pytest.mark.parametrize("tool", ["platform", "scale"])
@pytest.mark.parametrize(
    ("detail", "code"),
    [
        ("Log snapshot deadline exceeded; narrow the time range", "snapshot_deadline"),
        (SECRET, "unrecognized_detail_omitted"),
    ],
)
def test_snapshot_http_failure_retains_only_safe_code_without_another_request(
    tmp_path, monkeypatch, tool, detail, code
):
    calls = []

    def rejected(*args, **kwargs):
        calls.append(kwargs)
        return httpx.Response(503, json={"detail": detail})

    client = SimpleNamespace(request=rejected)
    path = "/api/logs/snapshots?private=" + SECRET
    if tool == "platform":
        report = {"stage": "snapshot"}
        probe = platform.ResourceProbe(report)
        monkeypatch.setattr(platform, "_probe", probe)
        monkeypatch.setattr(platform, "monitor", lambda *args: None)
        with pytest.raises(
            platform.CheckFailure, match="HTTP 503 instead of 201"
        ) as failed:
            platform.request(client, "POST", path, expected=201)
        observations = report["http_requests"]["observations"]
    else:
        trial = scale.Trial.__new__(scale.Trial)
        trial.guard = lambda: None
        trial.args = SimpleNamespace(query_timeout=15)
        trial.deadline = time.monotonic() + 60
        trial.record = scale.Recorder(tmp_path / "report.json", {"stage": "snapshot"})
        with pytest.raises(scale.ScaleFailure, match="returned HTTP 503") as failed:
            trial.expect(client, "POST", path, expected=201)
        assert failed.value.kind == "http"
        assert 0 < calls[0]["timeout"] <= 20
        observations = trial.record.value["http_failures"]["observations"]
    assert len(calls) == len(observations) == 1
    assert observations[0]["status"] == 503
    assert observations[0]["detail_code"] == code
    assert observations[0]["path"] == "/api/logs/snapshots"
    assert SECRET not in json.dumps(observations) + str(failed.value)


def test_scale_http_failure_observations_are_bounded_and_success_not_recorded(tmp_path):
    trial = scale.Trial.__new__(scale.Trial)
    trial.guard = lambda: None
    trial.args = SimpleNamespace(query_timeout=15)
    trial.deadline = time.monotonic() + 60
    trial.record = scale.Recorder(tmp_path / "report.json", {})
    success = SimpleNamespace(request=lambda *args, **kwargs: httpx.Response(200))
    assert trial.request(success, "GET", "/api/logs/status").status_code == 200
    assert "http_failures" not in trial.record.value
    rejected = SimpleNamespace(
        request=lambda *args, **kwargs: httpx.Response(503, json={"detail": SECRET})
    )
    for _ in range(65):
        trial.request(rejected, "POST", "/api/logs/snapshots")
    observations = trial.record.value["http_failures"]
    assert len(observations["observations"]) == observations["limit"] == 64
    assert observations["dropped"] == 1
    assert SECRET not in json.dumps(observations)


def test_platform_qualification_protects_own_new_directory_before_marker(tmp_path, monkeypatch):
    from sapientia.backup import _private_directory

    class ProtectedDirectoryObserved(Exception):
        pass

    observed = []

    def protect(path, *, created):
        assert path.parent == tmp_path and path.name.startswith("log-platform-qa-")
        assert created is True and not list(path.iterdir())
        _private_directory(path, created=created)
        observed.append(path)
        # Stop before markers, Store creation, server startup or any workload.
        raise ProtectedDirectoryObserved()

    monkeypatch.setattr(platform, "WORK", tmp_path)
    monkeypatch.setattr(platform, "_probe", None)
    monkeypatch.setattr(platform, "ResourceProbe", lambda report: object())
    monkeypatch.setattr(platform, "monitor", lambda *args, **kwargs: None)
    monkeypatch.setattr(platform, "_private_directory", protect)
    with pytest.raises(ProtectedDirectoryObserved):
        platform.qualify({}, 1, 1)
    assert len(observed) == 1 and not list(observed[0].iterdir())
