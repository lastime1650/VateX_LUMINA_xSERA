"""Private QA monitor faults only; no product Store, service, or scale load."""

import asyncio
import errno
import hashlib
import json
import sqlite3
import threading
import time
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from tools import qualify_log_scale as scale


def sharing_error(code=32):
    exc = PermissionError(errno.EACCES, "private secret path/token")
    exc.winerror = code
    return exc


@pytest.mark.parametrize("code", [32, 33])
def test_report_transient_windows_sharing_only_retries_replace(
    tmp_path, monkeypatch, code
):
    target = tmp_path / "checkpoint.json"
    scale.atomic_json(target, {"old": True})
    native_replace, calls, sleeps = scale.os.replace, [], []

    def replace(source, destination):
        calls.append((source, destination))
        assert json.loads(target.read_text(encoding="utf-8")) == {"old": True}
        if len(calls) < 5:
            raise sharing_error(code)
        native_replace(source, destination)

    monkeypatch.setattr(scale.os, "replace", replace)
    monkeypatch.setattr(scale.time, "sleep", sleeps.append)
    scale.atomic_json(target, {"new": True})
    assert len(calls) == 5 and len({x[0] for x in calls}) == 1
    assert sleeps == [0.05, 0.1, 0.2, 0.35] and sum(sleeps) <= 0.7
    assert json.loads(target.read_text(encoding="utf-8")) == {"new": True}
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.parametrize("code", [32, 33])
def test_report_permanent_sharing_preserves_prior_checkpoint(
    tmp_path, monkeypatch, code
):
    target = tmp_path / "checkpoint.json"
    scale.atomic_json(target, {"old": True})
    calls, sleeps = [], []

    def replace(*args):
        calls.append(args)
        raise sharing_error(code)

    monkeypatch.setattr(scale.os, "replace", replace)
    monkeypatch.setattr(scale.time, "sleep", sleeps.append)
    with pytest.raises(PermissionError):
        scale.atomic_json(target, {"new": True})
    assert len(calls) == 5 and sum(sleeps) <= 0.7
    assert json.loads(target.read_text(encoding="utf-8")) == {"old": True}
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.parametrize(
    "failure",
    [sharing_error(5), OSError(errno.ENOSPC, "secret"), OSError(errno.EIO, "secret")],
)
def test_report_acl_space_and_io_errors_never_retry(tmp_path, monkeypatch, failure):
    target = tmp_path / "checkpoint.json"
    scale.atomic_json(target, {"old": True})
    calls = []

    def replace(*args):
        calls.append(args)
        raise failure

    monkeypatch.setattr(scale.os, "replace", replace)
    monkeypatch.setattr(scale.time, "sleep", lambda _: pytest.fail("Unexpected retry"))
    with pytest.raises(OSError) as caught:
        scale.atomic_json(target, {"new": True})
    assert caught.value is failure and len(calls) == 1
    assert json.loads(target.read_text(encoding="utf-8")) == {"old": True}


def test_report_fsync_failure_is_not_retried_or_published(tmp_path, monkeypatch):
    target = tmp_path / "checkpoint.json"
    scale.atomic_json(target, {"old": True})

    def fsync(_):
        raise sharing_error(32)

    monkeypatch.setattr(scale.os, "fsync", fsync)
    monkeypatch.setattr(scale.os, "replace", lambda *_: pytest.fail("Must not publish"))
    monkeypatch.setattr(
        scale.time, "sleep", lambda _: pytest.fail("Must not retry fsync")
    )
    with pytest.raises(PermissionError):
        scale.atomic_json(target, {"new": True})
    assert json.loads(target.read_text(encoding="utf-8")) == {"old": True}
    assert list(tmp_path.iterdir()) == [target]


def healthy_sample():
    return {
        "rss_bytes": 100,
        "available_ram_bytes": 2**30,
        "disk_free_bytes": 2**30,
        "pending": 0,
    }


class OneCycle:
    def __init__(self):
        self.waits = 0

    def wait(self, seconds):
        assert seconds == 15
        self.waits += 1
        return self.waits > 1


class Client:
    def __init__(self, response=None, enter=None, close=None):
        self.headers = {}
        self.response = response or httpx.Response(200, json=healthy_sample())
        self.enter_error, self.close_error = enter, close
        self.closed = False
        self.calls = []

    def __enter__(self):
        if self.enter_error:
            raise self.enter_error
        return self

    def __exit__(self, *args):
        self.closed = True
        if self.close_error:
            raise self.close_error

    def get(self, path, **kwargs):
        self.calls.append((path, kwargs))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


@pytest.fixture
def monitor(tmp_path):
    trial = object.__new__(scale.Trial)
    trial.started = time.monotonic()
    trial.deadline = trial.started + 60
    trial.record = scale.Recorder(tmp_path / "report.json", {"stage": "unit"})
    trial.monitor_stop, trial.paused = OneCycle(), threading.Event()
    trial.config = {"control_token": "private-secret", "reserve_bytes": 1000}
    trial.args = SimpleNamespace(min_free_ram_mib=1, max_rss_gib=1)
    trial.metrics = {"unique_original_events_acked": 10}
    trial.admission_summary = lambda: {"acked": 10}
    trial.client = Client()
    trial.service = SimpleNamespace(client=lambda: trial.client, generation=1)
    return trial


@pytest.mark.parametrize(
    "phase",
    [
        "construct",
        "enter",
        "headers",
        "transport",
        "status",
        "decode",
        "summary",
        "save",
        "print",
        "close",
    ],
)
def test_monitor_classifies_all_fault_phases_without_secrets(
    monitor, monkeypatch, capsys, phase
):
    expected = {
        "construct": ("client_open", "PermissionError"),
        "enter": ("client_open", "PermissionError"),
        "headers": ("client_headers", "PermissionError"),
        "transport": ("resource_http", "ReadTimeout"),
        "status": ("resource_status", "ScaleFailure"),
        "decode": ("resource_decode", "JSONDecodeError"),
        "summary": ("admission_summary", "PermissionError"),
        "save": ("record_save", "PermissionError"),
        "print": ("progress_print", "BrokenPipeError"),
        "close": ("client_close", "PermissionError"),
    }[phase]

    def fail(*args, **kwargs):
        raise sharing_error(5)

    if phase == "construct":
        monitor.service.client = fail
    elif phase == "enter":
        monitor.client.enter_error = sharing_error(5)
    elif phase == "headers":

        class Headers:
            __setitem__ = fail

        monitor.client.headers = Headers()
    elif phase == "transport":
        monitor.client.response = httpx.ReadTimeout("https://secret/token")
    elif phase == "status":
        monitor.client.response = httpx.Response(503, text="private-secret")
    elif phase == "decode":
        monitor.client.response = httpx.Response(200, text="private-secret")
    elif phase == "summary":
        monitor.admission_summary = fail
    elif phase == "save":
        monitor.record.save = fail
    elif phase == "print":

        def print_failure(*args, **kwargs):
            raise BrokenPipeError(errno.EPIPE, "private-secret")

        monkeypatch.setattr(scale, "print", print_failure, raising=False)
    elif phase == "close":
        monitor.client.close_error = sharing_error(5)
    monitor.monitoring()
    assert monitor.record.failure.kind == "telemetry"
    detail = monitor.record.value["monitor_failure"]
    assert (detail["operation"], detail["exception_type"]) == expected
    if phase == "status":
        assert detail["http_status"] == 503
    assert "private-secret" not in json.dumps(monitor.record.value)
    assert "https://secret" not in json.dumps(monitor.record.value)
    assert "private-secret" not in capsys.readouterr().err
    if phase not in {"construct", "enter"}:
        assert monitor.client.closed
    if phase == "save":
        assert (
            monitor.record.value["monitor_persist_failure"]["exception_type"]
            == "PermissionError"
        )
    if phase == "transport":
        assert monitor.client.calls == [("/__qa/scale/resources", {"timeout": 5})]


def test_client_close_error_does_not_replace_first_probe_error(monitor):
    monitor.client.response = httpx.ReadTimeout("private-secret")
    monitor.client.close_error = sharing_error(5)
    monitor.monitoring()
    assert monitor.record.value["monitor_failure"] == {
        "operation": "resource_http",
        "exception_type": "ReadTimeout",
    }
    assert monitor.record.value["monitor_close_failure"]["operation"] == "client_close"


@pytest.mark.parametrize(
    ("field", "value", "kind"),
    [
        ("rss_bytes", 2**31, "capacity_rss"),
        ("available_ram_bytes", 0, "capacity_ram"),
        ("disk_free_bytes", 0, "capacity_disk"),
    ],
)
def test_resource_breach_remains_first_fatal_when_persistence_fails(
    monitor, field, value, kind
):
    monitor.client.response = httpx.Response(
        200, json={**healthy_sample(), field: value}
    )

    def save():
        raise OSError(errno.ENOSPC, "private-secret")

    monitor.record.save = save
    monitor.monitoring()
    assert monitor.record.failure.kind == kind
    assert monitor.record.value["latest_resources"][field] == value
    assert monitor.record.value["resource_samples"][-1][field] == value
    assert monitor.record.value["monitor_failure"]["operation"] == "resource_guard"
    assert monitor.record.value["monitor_persist_failure"]["errno"] == errno.ENOSPC


def test_memory_failure_is_retained_if_report_cannot_be_saved(monitor):
    monitor.client.response = httpx.ReadTimeout("private-secret")
    monitor.record.save = lambda: (_ for _ in ()).throw(OSError(errno.ENOSPC, "secret"))
    monitor.monitoring()
    with pytest.raises(scale.ScaleFailure, match="Resource monitor could not continue"):
        monitor.guard()
    assert monitor.record.value["monitor_failure"]["exception_type"] == "ReadTimeout"


def test_error_metadata_allows_only_known_types_numeric_codes_and_phases():
    class secret_type(Exception):
        errno = "password"
        winerror = 99999

    result = scale.monitor_error("secret/url", secret_type("token"), True)
    assert result == {"operation": "unknown", "exception_type": "other_error_type"}
    assert scale.monitor_error("record_save", sharing_error(33), 503) == {
        "operation": "record_save",
        "exception_type": "PermissionError",
        "errno": errno.EACCES,
        "winerror": 33,
        "http_status": 503,
    }


def test_healthy_monitor_keeps_fields_guard_and_cadence(monitor, capsys):
    monitor.monitoring()
    assert monitor.record.failure is None and monitor.monitor_stop.waits == 2
    value = json.loads(monitor.record.target.read_text(encoding="utf-8"))
    assert value["latest_resources"]["pending"] == 0
    assert value["latest_resources"]["acknowledged_original_events"] == 10
    assert value["latest_resources"]["service_generation"] == 1
    assert value["admission"] == {"acked": 10}
    assert json.loads(capsys.readouterr().out)["acknowledged"] == 10
    assert monitor.client.closed


def make_control(path):
    with sqlite3.connect(path) as db:
        db.executescript("""
            CREATE TABLE queue(seq INTEGER PRIMARY KEY);
            INSERT INTO queue VALUES(1);
            CREATE TABLE log_fts_inflight(seq INTEGER PRIMARY KEY);
            INSERT INTO log_fts_inflight VALUES(1);
            CREATE TABLE log_fts_state(singleton INTEGER PRIMARY KEY,indexed_documents INTEGER,
                pending_documents INTEGER,pending_bytes INTEGER,applied_sequence INTEGER,
                bootstrap_required INTEGER,generation INTEGER,purges INTEGER,last_error TEXT);
            INSERT INTO log_fts_state VALUES(1,7,1,50,7,0,2,0,NULL);
        """)


def test_resource_probe_uses_read_only_connection_and_cleans_it(tmp_path, monkeypatch):
    path = tmp_path / "control.sqlite3"
    make_control(path)
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    native_connect, connections, queries = sqlite3.connect, [], []

    class Connection(sqlite3.Connection):
        def execute(self, sql, *args):
            queries.append(sql)
            if sql == "BEGIN":
                with pytest.raises(sqlite3.OperationalError, match="readonly"):
                    super().execute("INSERT INTO queue VALUES(2)")
                self.rollback()
            return super().execute(sql, *args)

    def connect(database, **kwargs):
        assert database.endswith("?mode=ro") and kwargs["uri"] is True
        assert 0 <= kwargs["timeout"] <= 0.1
        db = native_connect(database, **kwargs, factory=Connection)
        connections.append(db)
        return db

    monkeypatch.setattr(scale.sqlite3, "connect", connect)
    monkeypatch.setattr(scale, "system_resources", lambda _: healthy_sample())
    result = scale.read_resource_snapshot(
        tmp_path, path, SimpleNamespace(health=lambda: {"error": None})
    )
    assert result["pending"] == 1 and result["fts_state"]["indexed_documents"] == 7
    assert result["fts_state"]["inflight"] == 1 and result["indexer"] == {"error": None}
    assert "PRAGMA query_only=ON" in queries and "BEGIN" in queries
    assert not any("synchronous" in sql for sql in queries)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connections[0].execute("SELECT 1")


def test_resource_probe_consistent_control_snapshot_with_concurrent_writer(
    tmp_path, monkeypatch
):
    path = tmp_path / "control.sqlite3"
    make_control(path)
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA journal_mode=WAL")
    native_connect = sqlite3.connect

    class Connection(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql.startswith("SELECT indexed_documents"):
                with native_connect(path) as writer:
                    writer.execute("INSERT INTO queue VALUES(2)")
                    writer.execute("UPDATE log_fts_state SET pending_documents=2")
            return super().execute(sql, *args)

    monkeypatch.setattr(
        scale.sqlite3,
        "connect",
        lambda *a, **kw: native_connect(*a, **kw, factory=Connection),
    )
    monkeypatch.setattr(scale, "system_resources", lambda _: healthy_sample())
    result = scale.read_resource_snapshot(tmp_path, path, SimpleNamespace(health=dict))
    assert result["pending"] == result["fts_state"]["pending_documents"] == 1
    with native_connect(path) as db:
        assert db.execute("SELECT count(*) FROM queue").fetchone()[0] == 2


def test_resource_probe_sqlite_progress_deadline_and_close(tmp_path, monkeypatch):
    path = tmp_path / "control.sqlite3"
    make_control(path)
    with sqlite3.connect(path) as db:
        db.executescript(
            "DROP TABLE queue; CREATE VIEW queue AS WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000000) SELECT x FROM n;"
        )
    native_connect, connections = sqlite3.connect, []
    now = [0.0]

    class Connection(sqlite3.Connection):
        def set_progress_handler(self, callback, steps):
            if callback is not None:

                def expired():
                    now[0] = 3
                    return callback()

                return super().set_progress_handler(expired, steps)
            return super().set_progress_handler(None, steps)

    def connect(*args, **kwargs):
        db = native_connect(*args, **kwargs, factory=Connection)
        connections.append(db)
        return db

    monkeypatch.setattr(scale.sqlite3, "connect", connect)
    monkeypatch.setattr(scale.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(scale, "system_resources", lambda _: healthy_sample())
    with pytest.raises(sqlite3.OperationalError, match="interrupted"):
        scale.read_resource_snapshot(tmp_path, path, SimpleNamespace(health=dict))
    with pytest.raises(sqlite3.ProgrammingError, match="closed"):
        connections[0].execute("SELECT 1")


def test_resource_probe_missing_path_does_not_create_database(tmp_path, monkeypatch):
    path = tmp_path / "missing.sqlite3"
    monkeypatch.setattr(scale, "system_resources", lambda _: healthy_sample())
    with pytest.raises(sqlite3.OperationalError):
        scale.read_resource_snapshot(tmp_path, path, SimpleNamespace(health=dict))
    assert not path.exists()


def test_resource_probe_expired_os_observation_never_opens_database(
    tmp_path, monkeypatch
):
    now = [0]

    def sample(_):
        now[0] = 3
        return healthy_sample()

    monkeypatch.setattr(scale.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(scale, "system_resources", sample)
    monkeypatch.setattr(
        scale.sqlite3,
        "connect",
        lambda *_a, **_kw: pytest.fail("Expired probe opened a database"),
    )
    with pytest.raises(scale.ScaleFailure, match="deadline"):
        scale.read_resource_snapshot(
            tmp_path, tmp_path / "control.sqlite3", SimpleNamespace(health=dict)
        )


def test_resource_probe_busy_database_fails_and_releases_connection(
    tmp_path, monkeypatch
):
    path = tmp_path / "control.sqlite3"
    make_control(path)
    monkeypatch.setattr(scale, "system_resources", lambda _: healthy_sample())
    with sqlite3.connect(path) as writer:
        writer.execute("BEGIN EXCLUSIVE")
        began = time.monotonic()
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            scale.read_resource_snapshot(tmp_path, path, SimpleNamespace(health=dict))
        assert time.monotonic() - began < 1
    # A failed read has not left an open read transaction preventing later writes.
    with sqlite3.connect(path, timeout=0.1) as writer:
        writer.execute("INSERT INTO queue VALUES(2)")


def test_resource_observation_is_threaded_and_asgi_remains_responsive(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    worker = []

    def probe(*args):
        worker.append(threading.get_ident())
        entered.set()
        assert release.wait(2)
        return {"pending": 0}

    monkeypatch.setattr(scale, "read_resource_snapshot", probe)
    app = FastAPI()

    @app.get("/resource")
    async def resource():
        return await scale.resource_snapshot(None, None, None)

    @app.get("/ping")
    async def ping():
        return {"ok": True}

    async def exercise():
        main_thread = threading.get_ident()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://private"
        ) as client:
            pending = asyncio.create_task(client.get("/resource"))
            try:
                for _ in range(100):
                    if entered.is_set():
                        break
                    await asyncio.sleep(0.001)
                assert entered.is_set()
                response = await asyncio.wait_for(client.get("/ping"), timeout=0.5)
                assert response.json() == {"ok": True} and not pending.done()
                assert worker == [worker[0]] and worker[0] != main_thread
            finally:
                release.set()
            assert (await pending).json() == {"pending": 0}

    asyncio.run(exercise())


def test_actual_aggregate_ranges_are_retained_and_missing_rejected():
    expected = scale.progression(13, 0)
    row = {
        "n": "3",
        "distinct_ids": "3",
        "sequence_sum": "18",
        "minimum_sequence": "0",
        "maximum_sequence": "12",
    }
    assert scale.validate_aggregate(row, expected) == {
        "count": 3,
        "distinct_ids": 3,
        "sequence_sum": 18,
        "minimum_sequence": 0,
        "maximum_sequence": 12,
    }
    for field in ("minimum_sequence", "maximum_sequence"):
        with pytest.raises(scale.ScaleFailure):
            scale.validate_aggregate(
                {k: v for k, v in row.items() if k != field}, expected
            )
    empty = scale.validate_aggregate(
        {"n": 0, "distinct_ids": 0}, scale.progression(0, 0)
    )
    assert empty["minimum_sequence"] is empty["maximum_sequence"] is None


def test_integrity_records_validated_actual_tenant_and_scope_ranges():
    total = 13
    scopes = scale.expected_scopes(total)
    trial = object.__new__(scale.Trial)
    trial.clients = {tenant: (tenant, None) for tenant in scale.TENANTS}
    trial.config = {"base_epoch": 1700000000}
    trial.record = scale.Recorder(None, {})

    def aggregate(value):
        return {
            "n": str(value["count"]),
            "distinct_ids": str(value["count"]),
            "sequence_sum": str(value["sequence_sum"]),
            "minimum_sequence": str(value["minimum_sequence"]),
            "maximum_sequence": str(value["maximum_sequence"]),
        }

    def expect(tenant, method, path, json):
        if json["language"] == "json":
            rows = [
                {"index_name": index, "count": scopes[(tenant, index)]["count"]}
                for index in scale.INDEXES
            ]
        elif " by index_name" in json["query"]:
            rows = [
                {"index_name": index, **aggregate(scopes[(tenant, index)])}
                for index in scale.INDEXES
            ]
        else:
            values = [scopes[(tenant, index)] for index in scale.INDEXES]
            rows = [
                aggregate(
                    {
                        "count": sum(x["count"] for x in values),
                        "sequence_sum": sum(x["sequence_sum"] for x in values),
                        "minimum_sequence": min(x["minimum_sequence"] for x in values),
                        "maximum_sequence": max(x["maximum_sequence"] for x in values),
                    }
                )
            ]
        return httpx.Response(200, json={"rows": rows})

    trial.expect = expect
    result = trial.integrity(total, "unit")
    assert result["global_count"] == result["global_distinct_ids"] == 13
    assert result["sequence_sum"] == 78
    assert result["global_sequence_min"] == 0 and result["global_sequence_max"] == 12
    assert len(result["tenant_global_rows"]) == 2 and len(result["scope_rows"]) == 6
    assert result["numeric_type_coverage"] == [
        {
            "tenant": tenant,
            "typed_numeric_and_namespace_count": sum(
                scopes[(tenant, index)]["count"] for index in scale.INDEXES
            ),
            "indexes": {
                index: scopes[(tenant, index)]["count"] for index in scale.INDEXES
            },
        }
        for tenant in scale.TENANTS
    ]
    assert all(
        type(row["minimum_sequence"]) is int and type(row["maximum_sequence"]) is int
        for row in result["scope_rows"]
    )
