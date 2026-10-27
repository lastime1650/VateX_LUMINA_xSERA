"""Small pure-helper tests: this module never starts a server or a Store."""

import json
import sqlite3
import threading
from types import SimpleNamespace

import pytest

from tools import qualify_log_scale as scale


@pytest.fixture
def corpus():
    return scale.Corpus("realistic", 1_700_000_000, b"x" * 32)


def test_stable_variable_realistic_corpus(corpus):
    values = [corpus.event(i)[1] for i in range(1000)]
    assert values == [corpus.event(i)[1] for i in range(1000)]
    sizes = [len(scale.dumps(event)) for event in values]
    assert 900 < sum(sizes) / len(sizes) < 1100
    assert min(sizes) < 900 and max(sizes) > 1150
    assert len({len(event["raw"]) for event in values}) == 5
    assert len({event["raw"]["trace_id"] for event in values}) == len(values)
    assert all(type(event["raw"]["sequence"]) is int for event in values)
    other = scale.Corpus("realistic", corpus.base_epoch, b"y" * 32)
    assert other.event(4)[1]["raw"]["payload"] != values[4]["raw"]["payload"]
    assert other.event(4)[1]["event_id"] == values[4]["event_id"]


def test_small_profile_is_distinct_from_realistic():
    corpus = scale.Corpus("small", 1_700_000_000, b"x" * 32)
    values = [corpus.event(i)[1] for i in range(20)]
    assert 250 < sum(len(scale.dumps(event)) for event in values) / len(values) < 450
    assert all("trace_id" not in event["raw"] for event in values)


def test_streaming_batches_obey_both_bounds_and_cover_input(corpus, monkeypatch):
    monkeypatch.setattr(scale, "BODY_LIMIT", 3500)
    monkeypatch.setattr(scale, "BATCH_LIMIT", 2)
    seen = set()
    for tenant, body, count in corpus.batches(9, 91):
        rows = json.loads(body)["events"]
        assert len(body) <= 3500 and count == len(rows) <= 2
        assert body == scale.dumps({"events": rows})
        for event in rows:
            ordinal = event["raw"]["sequence"]
            assert ordinal not in seen and scale.scope_for(ordinal)[0] == tenant
            assert scale.scope_for(ordinal)[1] == event["index"]
            seen.add(ordinal)
    assert seen == set(range(9, 91))


@pytest.mark.parametrize("total", [0, 1, 5, 6, 7, 127, 6001])
def test_exact_expected_scopes_match_independent_enumeration(total):
    expected = scale.expected_scopes(total)
    for scope, value in expected.items():
        numbers = [n for n in range(total) if scale.scope_for(n) == scope]
        assert value == {
            "count": len(numbers),
            "sequence_sum": sum(numbers),
            "minimum_sequence": min(numbers, default=None),
            "maximum_sequence": max(numbers, default=None),
        }
    for tenant in scale.TENANTS:
        assert scale.expected_sentinels(total, tenant) == sum(
            n % 997 == 0 and scale.scope_for(n)[0] == tenant for n in range(total)
        )


def test_fifty_million_exact_sum_is_within_json_integer_range():
    total = 50_000_000
    expected = scale.expected_scopes(total)
    assert sum(row["count"] for row in expected.values()) == total
    assert (
        sum(row["sequence_sum"] for row in expected.values())
        == total * (total - 1) // 2
        < 2**53
    )


@pytest.mark.parametrize("bad", [True, None, 1.5, float("nan"), "1.1", 2**53])
def test_aggregate_does_not_truncate_invalid_numbers(bad):
    with pytest.raises(scale.ScaleFailure, match="integral|exact JSON"):
        scale.exact_integer(bad)


def test_aggregate_checks_distinct_sum_range_and_empty():
    expected = scale.progression(13, 0)
    row = {
        "n": 3,
        "distinct_ids": 3,
        "sequence_sum": 18,
        "minimum_sequence": 0,
        "maximum_sequence": 12,
    }
    assert scale.validate_aggregate(row, expected)["count"] == 3
    for field in ("distinct_ids", "sequence_sum", "maximum_sequence"):
        with pytest.raises(scale.ScaleFailure):
            scale.validate_aggregate({**row, field: 1}, expected)
    assert (
        scale.validate_aggregate({"n": 0, "distinct_ids": 0}, scale.progression(0, 0))[
            "count"
        ]
        == 0
    )


def test_nearest_rank_percentiles_and_byte_units():
    summary = scale.latency_summary([*range(99), 1000])
    assert summary["p50_seconds"] == 49
    assert summary["p95_seconds"] == 94
    assert summary["p99_seconds"] == 98
    assert summary["max_seconds"] == 1000
    byte_values = scale.byte_summary([350, 1024])
    assert byte_values["p99_bytes"] == 1024
    assert not any(key.endswith("_seconds") for key in byte_values)
    assert scale.latency_summary([])["p95_seconds"] is None


def test_atomic_checkpoint_failure_keeps_previous_complete_report(
    tmp_path, monkeypatch
):
    path = tmp_path / "report.json"
    scale.atomic_json(path, {"progress": 1})

    def fail_replace(*args):
        raise OSError("synthetic replacement failure")

    monkeypatch.setattr(scale.os, "replace", fail_replace)
    with pytest.raises(OSError, match="replacement failure"):
        scale.atomic_json(path, {"progress": 2})
    assert json.loads(path.read_text()) == {"progress": 1}
    assert list(tmp_path.iterdir()) == [path]


def test_report_must_be_new_and_inside_task_roots(tmp_path):
    target = tmp_path / "nested" / "new.json"
    assert scale.validate_report_path(target, roots=(tmp_path,)) == target.resolve()
    existing = tmp_path / "old.json"
    existing.write_text("{}")
    for path in (existing, tmp_path / "invalid.txt", tmp_path.parent / "outside.json"):
        with pytest.raises(scale.ScaleFailure) as failure:
            scale.validate_report_path(path, roots=(tmp_path,))
        assert failure.value.kind == "isolation"


@pytest.mark.parametrize(
    ("field", "value", "kind"),
    [
        ("disk_free_bytes", 100, "capacity_disk"),
        ("available_ram_bytes", 99, "capacity_ram"),
        ("rss_bytes", 1001, "capacity_rss"),
    ],
)
def test_resource_guard_failures_are_not_success(field, value, kind):
    sample = {"disk_free_bytes": 1000, "available_ram_bytes": 1000, "rss_bytes": 100}
    with pytest.raises(scale.ScaleFailure) as failure:
        scale.guard_resources({**sample, field: value}, 100, 100, 1000)
    assert failure.value.kind == kind


def test_capacity_projection_includes_control_fts_and_baseline():
    result = scale.capacity_projection(
        {"control_including_fts_journal": 120, "parquet_segments": 180},
        {"control_including_fts_journal": 20, "parquet_segments": 80},
        100,
        1000,
        2000,
        500,
    )
    assert result["remaining_linear_estimate_bytes"] == 1800
    assert (
        result["observed_growth_bytes_per_event"]["control_including_fts_journal"] == 1
    )
    assert result["available_above_reserve_bytes"] == 1500
    assert result["fits_linear_estimate"] is False


def test_storage_component_measurement_includes_fts_journal(tmp_path):
    files = {
        "control.sqlite3": 3,
        "control.sqlite3-wal": 5,
        "events.duckdb": 7,
        "log-segments/a.parquet": 11,
        "log-search/fulltext.sqlite3": 13,
        "other": 17,
    }
    for name, size in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x" * size)
    assert scale.component_bytes(tmp_path) == {
        "control_including_fts_journal": 8,
        "hot_duckdb": 7,
        "parquet_segments": 11,
        "fts_cache": 13,
        "other": 17,
    }


def test_resource_samples_are_bounded_but_extrema_survive(tmp_path):
    record = scale.Recorder(tmp_path / "report.json", {})
    for elapsed, rss, ram, disk in (
        (0, 10, 90, 100),
        (1, 99, 80, 99),
        (15, 20, 70, 80),
        (30, 30, 60, 70),
    ):
        scale.observe_resources(
            record,
            {
                "elapsed_seconds": elapsed,
                "rss_bytes": rss,
                "available_ram_bytes": ram,
                "disk_free_bytes": disk,
            },
            limit=2,
        )
    assert [x["elapsed_seconds"] for x in record.value["resource_samples"]] == [15, 30]
    assert record.value["resource_samples_older_dropped"] == 1
    assert record.value["resource_extrema"] == {
        "peak_rss_bytes": 99,
        "minimum_available_ram_bytes": 60,
        "minimum_disk_free_bytes": 70,
    }
    scale.observe_resources(
        record,
        {
            "elapsed_seconds": 31,
            "rss_bytes": 1000,
            "available_ram_bytes": 2,
            "disk_free_bytes": 3,
        },
        preserve=True,
        limit=2,
    )
    record.save()
    assert (
        json.loads(record.target.read_text())["resource_samples"][-1]["rss_bytes"]
        == 1000
    )


def verified_fts_phase(phase, population):
    return {
        "phase": phase,
        "population": population,
        "passed": True,
        "fts_population": {"passed": True, "expected_population": population},
        "actual_fts_population": {"passed": True, "expected_population": population},
    }


def test_missing_incremental_or_failed_fts_never_qualifies():
    cold = verified_fts_phase("cold", 500_000)
    incremental = verified_fts_phase("incremental", 1_000_000)
    restart = verified_fts_phase("after_restart", 1_000_000)
    assert not scale.fts_is_qualified([], 1_000_000)
    assert not scale.fts_is_qualified([cold], 1_000_000)
    assert scale.fts_is_qualified([cold, incremental, restart], 1_000_000)
    assert not scale.fts_is_qualified(
        [cold, incremental, restart, {"phase": "capacity", "passed": False}], 1_000_000
    )
    assert not scale.fts_is_qualified(
        [cold, {"phase": "incremental", "passed": True}, restart], 1_000_000
    )
    assert not scale.fts_is_qualified(
        [cold, {**incremental, "actual_fts_population": {"passed": False}}, restart],
        1_000_000,
    )


def test_partial_fifty_million_run_never_qualifies_earlier_fts_milestones():
    results = [
        verified_fts_phase("cold", 500_000),
        verified_fts_phase("incremental", 1_000_000),
        verified_fts_phase("capacity", 5_000_000),
    ]
    summary = scale.fts_qualification_summary(results, 50_000_000)
    assert summary["fts_qualified"] is False
    assert summary["fts_recorded_phase_checks_passed"] is True
    assert summary["fts_highest_verified_population"] == 5_000_000
    assert summary["fts_required_population"] == 50_000_000
    results.extend(
        verified_fts_phase("capacity", total)
        for total in (10_000_000, 25_000_000, 50_000_000)
    )
    assert not scale.fts_is_qualified(results, 50_000_000)
    assert not scale.fts_is_qualified(
        [*results, verified_fts_phase("after_restart", 5_000_000)], 50_000_000
    )
    results.append(verified_fts_phase("after_restart", 50_000_000))
    assert scale.fts_is_qualified(results, 50_000_000)
    results.append({"phase": "capacity", "population": 50_000_000, "passed": False})
    summary = scale.fts_qualification_summary(results, 50_000_000)
    assert (
        summary["fts_qualified"] is summary["fts_recorded_phase_checks_passed"] is False
    )
    assert summary["fts_highest_verified_population"] == 50_000_000


@pytest.mark.parametrize("bad", [None, 1_000_000.0, True, 0, -1])
def test_fts_qualification_requires_explicit_integer_target(bad):
    results = [
        verified_fts_phase("cold", 500_000),
        verified_fts_phase("incremental", 1_000_000),
        verified_fts_phase("after_restart", 1_000_000),
    ]
    assert not scale.fts_is_qualified(results, bad)


@pytest.mark.parametrize("key", ["fts_population", "actual_fts_population"])
@pytest.mark.parametrize("bad", [None, True, 999_999, 1_000_000.0])
def test_fts_target_checks_cannot_use_missing_or_mismatched_population_metadata(
    key, bad
):
    results = [
        verified_fts_phase("cold", 500_000),
        verified_fts_phase("incremental", 1_000_000),
        verified_fts_phase("after_restart", 1_000_000),
    ]
    results[-1][key]["expected_population"] = bad
    assert not scale.fts_is_qualified(results, 1_000_000)


def test_fts_unknown_phase_or_larger_population_cannot_supply_target_coverage():
    results = [
        verified_fts_phase("cold", 500_000),
        verified_fts_phase("incremental", 1_000_000),
        verified_fts_phase("unknown", 5_000_000),
        verified_fts_phase("after_restart", 5_000_000),
    ]
    assert not scale.fts_is_qualified(results, 5_000_000)
    assert not scale.fts_is_qualified(results, 1_000_000)
    assert (
        scale.fts_qualification_summary([], 50_000_000)[
            "fts_highest_verified_population"
        ]
        == 0
    )


def fts_state():
    return {
        "indexed_documents": 12,
        "pending_documents": 0,
        "applied_sequence": 14,
        "bootstrap_required": 0,
        "inflight": 0,
    }


def test_private_fts_population_observation_is_exact_and_not_sequence_equal_to_count():
    result = scale.validate_fts_population(fts_state(), 12)
    assert result["passed"] is True and result["observed"]["indexed_documents"] == 12
    assert (
        result["observed"]["applied_sequence"] == 14
    )  # Deletes/replays may advance sequence.


@pytest.mark.parametrize(
    ("field", "bad"),
    [
        ("indexed_documents", True),
        ("pending_documents", False),
        ("applied_sequence", True),
        ("bootstrap_required", False),
        ("inflight", False),
        ("indexed_documents", "12"),
        ("indexed_documents", 12.0),
        ("applied_sequence", -1),
        ("indexed_documents", 11),
        ("pending_documents", 1),
        ("inflight", 1),
        ("bootstrap_required", 1),
    ],
)
def test_private_fts_population_rejects_bool_mismatch_and_unfinished_state(field, bad):
    with pytest.raises(scale.ScaleFailure) as failure:
        scale.validate_fts_population({**fts_state(), field: bad}, 12)
    assert failure.value.kind == "fts_population"


def test_private_fts_population_rejects_missing_state_and_invalid_expected_population():
    for state, population in ((None, 12), ({}, 12), (fts_state(), True)):
        with pytest.raises(scale.ScaleFailure):
            scale.validate_fts_population(state, population)


@pytest.fixture
def actual_fts_cache(tmp_path):
    path = tmp_path / "terms.sqlite3"
    with sqlite3.connect(path) as db:
        db.executescript(
            "CREATE TABLE metadata(documents INTEGER);INSERT INTO metadata VALUES(12);"
            "CREATE TABLE registry(tenant TEXT NOT NULL,event_id TEXT NOT NULL,"
            "term_rowid INTEGER NOT NULL UNIQUE,digest TEXT NOT NULL,index_name TEXT NOT NULL,"
            "PRIMARY KEY(tenant,event_id)) WITHOUT ROWID;"
            "CREATE VIRTUAL TABLE terms USING fts5(tenant UNINDEXED,event_id UNINDEXED,message,raw,"
            "tokenize='unicode61 remove_diacritics 2');"
        )
        for sequence in range(12):
            tenant, index = scale.scope_for(sequence)
            db.execute(
                "INSERT INTO registry VALUES(?,?,?,?,?)",
                (tenant, str(sequence), sequence + 1, str(sequence), index),
            )
            db.execute(
                "INSERT INTO terms VALUES(?,?,?,?)",
                (tenant, str(sequence), "synthetic", "{}"),
            )
    return path


def test_actual_fts_rows_are_read_only_and_exact_across_six_scopes(actual_fts_cache):
    before = actual_fts_cache.read_bytes()
    result = scale.read_fts_population(actual_fts_cache, threading.Lock(), 1)
    proof = scale.validate_actual_fts_population(result, 12)
    assert proof["passed"] and result["registry_count"] == result["terms_count"] == 12
    assert result["terms_population_relation"].startswith("terms_content")
    assert len(result["tenants"]) == 2
    assert all(
        row["indexes"] == dict.fromkeys(scale.INDEXES, 2) for row in result["tenants"]
    )
    assert actual_fts_cache.read_bytes() == before
    assert not actual_fts_cache.with_name("terms.sqlite3-journal").exists()


def test_actual_observer_uses_content_rows_and_one_registry_group_walk(
    actual_fts_cache, monkeypatch
):
    connect, sql = sqlite3.connect, []

    def traced(*args, **kwargs):
        db = connect(*args, **kwargs)
        db.set_trace_callback(sql.append)
        return db

    monkeypatch.setattr(scale.sqlite3, "connect", traced)
    result = scale.read_fts_population(actual_fts_cache, threading.Lock(), 1)
    assert scale.validate_actual_fts_population(result, 12)["passed"]
    normalized = [" ".join(statement.lower().split()) for statement in sql]
    assert "select count(*) from terms_content" in normalized
    assert "select count(*) from terms" not in normalized
    assert "select count(*) from registry" not in normalized
    assert (
        sum("from registry group by tenant" in statement for statement in normalized)
        == 1
    )


@pytest.mark.parametrize(
    "mode", ["contentless", "external", "ordinary", "changed_columns"]
)
def test_actual_observer_rejects_unverified_fts_storage_formats(tmp_path, mode):
    path = tmp_path / "unknown.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE registry(tenant TEXT NOT NULL,event_id TEXT NOT NULL,index_name TEXT NOT NULL,"
            "PRIMARY KEY(tenant,event_id)) WITHOUT ROWID"
        )
        if mode == "ordinary":
            db.executescript(
                "CREATE TABLE terms(tenant,event_id,message,raw);"
                "CREATE TABLE terms_content(id INTEGER PRIMARY KEY,c0,c1,c2,c3);"
            )
        else:
            options = {
                "contentless": ",content=''",
                "external": ",content='external_rows'",
                "changed_columns": ",unexpected",
            }[mode]
            if mode == "external":
                db.execute("CREATE TABLE external_rows(tenant,event_id,message,raw)")
            db.execute(
                "CREATE VIRTUAL TABLE terms USING fts5(tenant UNINDEXED,event_id UNINDEXED,message,raw"
                + options
                + ",tokenize='unicode61 remove_diacritics 2')"
            )
    before = path.read_bytes()
    with pytest.raises(scale.ScaleFailure, match="internal-content schema"):
        scale.read_fts_population(path, threading.Lock(), 1)
    assert path.read_bytes() == before


def test_actual_observer_rejects_nullable_registry_instead_of_hiding_null_index(
    actual_fts_cache,
):
    with sqlite3.connect(actual_fts_cache) as db:
        db.executescript(
            "ALTER TABLE registry RENAME TO prior;"
            "CREATE TABLE registry(tenant TEXT NOT NULL,event_id TEXT NOT NULL,index_name TEXT,"
            "PRIMARY KEY(tenant,event_id)) WITHOUT ROWID;"
            "INSERT INTO registry SELECT tenant,event_id,index_name FROM prior;"
            "UPDATE registry SET index_name=NULL WHERE event_id='0';"
        )
    with pytest.raises(scale.ScaleFailure, match="non-null"):
        scale.read_fts_population(actual_fts_cache, threading.Lock(), 1)


def test_extra_unknown_tenants_and_negative_unknown_counts_never_qualify(
    actual_fts_cache,
):
    with sqlite3.connect(actual_fts_cache) as db:
        for ordinal in range(4):
            db.execute(
                "INSERT INTO registry VALUES(?,?,?,?,?)",
                (
                    "unknown_" + str(ordinal),
                    str(ordinal),
                    100 + ordinal,
                    "digest",
                    "main",
                ),
            )
    observation = scale.read_fts_population(actual_fts_cache, threading.Lock(), 1)
    assert len(observation["tenants"]) == len(scale.TENANTS) + 1
    with pytest.raises(scale.ScaleFailure):
        scale.validate_actual_fts_population(observation, 12)
    observation["registry_count"] = observation["terms_count"] = 12
    with pytest.raises(scale.ScaleFailure, match="tenant"):
        scale.validate_actual_fts_population(observation, 12)
    observation["tenants"] = observation["tenants"][:2]
    observation["tenants"][0]["unknown_index_count"] = -1
    with pytest.raises(scale.ScaleFailure, match="scope"):
        scale.validate_actual_fts_population(observation, 12)


def test_actual_fts_rows_reject_lying_ready_counters(actual_fts_cache):
    # Simulate an acknowledged ready state whose metadata/control counters agree
    # while an actual searchable row is missing. The old scalar proof passes.
    assert scale.validate_fts_population(fts_state(), 12)["passed"]
    with sqlite3.connect(actual_fts_cache) as db:
        db.execute("DELETE FROM terms WHERE rowid=(SELECT min(rowid) FROM terms)")
        assert db.execute("SELECT documents FROM metadata").fetchone()[0] == 12
    result = scale.read_fts_population(actual_fts_cache, threading.Lock(), 1)
    assert result["registry_count"] == 12 and result["terms_count"] == 11
    with pytest.raises(scale.ScaleFailure, match="Actual FTS registry/terms"):
        scale.validate_actual_fts_population(result, 12)


@pytest.mark.parametrize("change", ["unknown_index", "wrong_scope", "unknown_tenant"])
def test_actual_fts_scope_counts_reject_equal_total_wrong_population(
    actual_fts_cache, change
):
    with sqlite3.connect(actual_fts_cache) as db:
        if change == "unknown_index":
            db.execute(
                "UPDATE registry SET index_name='unconfigured' WHERE event_id='0'"
            )
        elif change == "wrong_scope":
            db.execute("UPDATE registry SET index_name='endpoint' WHERE event_id='0'")
        else:
            db.execute("UPDATE registry SET tenant='unconfigured' WHERE event_id='0'")
    result = scale.read_fts_population(actual_fts_cache, threading.Lock(), 1)
    assert result["registry_count"] == result["terms_count"] == 12
    with pytest.raises(scale.ScaleFailure, match="scope|tenant"):
        scale.validate_actual_fts_population(result, 12)


def test_actual_fts_observation_lock_deadline_and_missing_cache_never_create_file(
    tmp_path,
):
    path = tmp_path / "missing.sqlite3"
    with pytest.raises(scale.ScaleFailure, match="absent"):
        scale.read_fts_population(path, threading.Lock(), 0.01)
    assert not path.exists()
    path.write_bytes(b"not sqlite")
    lock = threading.Lock()
    lock.acquire()
    try:
        with pytest.raises(scale.ScaleFailure, match="lock deadline"):
            scale.read_fts_population(path, lock, 0.001)
    finally:
        lock.release()
    with pytest.raises(scale.ScaleFailure, match="SQLite observation"):
        scale.read_fts_population(path, lock, 1)
    assert lock.acquire(blocking=False)
    lock.release()


@pytest.mark.parametrize("field", ["registry_count", "terms_count"])
def test_actual_fts_population_rejects_bool_and_missing_scopes(actual_fts_cache, field):
    result = scale.read_fts_population(actual_fts_cache, threading.Lock(), 1)
    with pytest.raises(scale.ScaleFailure):
        scale.validate_actual_fts_population({**result, field: True}, 12)
    with pytest.raises(scale.ScaleFailure):
        scale.validate_actual_fts_population({**result, "tenants": []}, 12)


@pytest.mark.parametrize(
    "field", ["event_time", "sourcetype", "severity", "index_name"]
)
def test_export_sample_validates_added_original_fields(corpus, field):
    tenant, expected = corpus.event(0)
    row = json.loads(scale.dumps(expected))
    row["index_name"] = row.pop("index")
    row["raw"]["security"] = {
        "schema_version": 1
    }  # Additive normalized provenance is allowed.
    scale.validate_sample_event(row, expected, tenant, tenant, expected["index"])
    row[field] = row[field] + 1 if field == "event_time" else "synthetic-mismatch"
    with pytest.raises(scale.ScaleFailure, match="independent deterministic"):
        scale.validate_sample_event(row, expected, tenant, tenant, expected["index"])


def test_export_sample_missing_and_mistyped_original_raw_fields_fail(corpus):
    tenant, expected = corpus.event(1)
    row = json.loads(scale.dumps(expected))
    row["index_name"] = row.pop("index")
    row["raw"]["sequence"] = True
    with pytest.raises(scale.ScaleFailure):
        scale.validate_sample_event(row, expected, tenant, tenant, expected["index"])
    row["raw"] = dict(expected["raw"])
    del row["raw"]["synthetic"]
    with pytest.raises(scale.ScaleFailure):
        scale.validate_sample_event(row, expected, tenant, tenant, expected["index"])


def test_cleanup_stops_owned_service_even_when_client_cleanup_fails(tmp_path):
    calls = []
    trial = scale.Trial.__new__(scale.Trial)
    trial.monitor_stop, trial.monitor = threading.Event(), None
    trial.record = scale.Recorder(tmp_path / "report.json", {})
    trial.service = SimpleNamespace(
        stop=lambda: calls.append("stop"), stop_checks=[], starts=[]
    )
    trial.admission_summary = dict

    def fail_disconnect():
        raise RuntimeError("synthetic disconnect failure")

    trial.disconnect = fail_disconnect
    with pytest.raises(RuntimeError, match="disconnect failure"):
        trial.close()
    assert calls == ["stop"]
    assert trial.record.value["shutdown"]["passed"] is False
    assert trial.record.value["shutdown"]["server_retained"] is None


def test_parse_rejects_unbounded_or_unsafe_profile_arguments():
    for flags in (
        ["--events", "50000001"],
        ["--reserve-gib", "9"],
        ["--fts-budget-gib", "inf"],
        ["--query-timeout", "100000"],
        ["--max-seconds", "10"],
        ["--min-free-ram-mib", "1"],
    ):
        with pytest.raises(SystemExit):
            scale.parse_args(["--report", "new.json", *flags])


def test_public_integrity_query_contract_compiles_without_a_store():
    from sapientia.query import Query

    payload = {
        "language": "spl",
        "earliest": 1700000000,
        "latest": 1700003600,
        "query": "search * | stats " + scale.STATS + " by index_name",
    }
    sql, args = Query.parse(payload).compile(
        "default", allowed_indexes=list(scale.INDEXES)
    )
    assert "index_name" in sql and "default" in args
    assert "sequence_sum" in sql and "distinct_ids" in sql
    typed = Query.parse(
        {
            "language": "json",
            "query": {
                "filters": [
                    {"field": "raw.sequence", "op": "number_gte", "value": 0},
                    {"field": "raw.sequence", "op": "number_lt", "value": 50_000_000},
                    {"field": "event_id", "op": "regex", "value": "^scale_default_"},
                ],
                "group_by": ["index_name"],
                "sort": "count",
            },
        }
    )
    sql, args = typed.compile("default", allowed_indexes=list(scale.INDEXES))
    assert "count(*) AS count" in sql and "json_type" in sql and "default" in args
