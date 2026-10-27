"""Shared server-generated analytics limits fail closed and release their slots."""

import threading
import time

import duckdb
import pytest

from sapientia.storage import CapacityError, Settings, Store


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0, query_timeout=2))
    yield value
    value.close()


def usable(store):
    assert store.analytics_query("SELECT 1 AS n", [], max_rows=1)["rows"] == [{"n": 1}]


def test_overpopulation_raises_instead_of_silently_truncating(store):
    with pytest.raises(CapacityError, match="row bound"):
        store.analytics_query("SELECT i FROM range(3) t(i)", [], max_rows=2)
    exact = store.analytics_query("SELECT i FROM range(2) t(i)", [], max_rows=2)
    assert exact["returned"] == 2 and exact["rows"] == [{"i": 0}, {"i": 1}]
    usable(store)


def test_serialized_utf8_output_limit_is_enforced(store):
    with pytest.raises(ValueError, match="2 MiB"):
        store.analytics_query("SELECT repeat('가', 750000) AS text", [], max_rows=1)
    usable(store)


def test_busy_shared_query_slots_apply_to_analytics_and_release(store):
    for _ in range(store.settings.workers):
        assert store.query_slots.acquire(False)
    try:
        with pytest.raises(CapacityError, match="concurrency"):
            store.analytics_query("SELECT 1 AS n", [], max_rows=1)
    finally:
        for _ in range(store.settings.workers):
            store.query_slots.release()
    usable(store)


def test_already_cancelled_request_does_not_run_or_leak_slot(store):
    cancelled = threading.Event()
    cancelled.set()
    with pytest.raises(RuntimeError, match="cancelled"):
        store.analytics_query("SELECT 1 AS n", [], cancel=cancelled, max_rows=1)
    usable(store)


@pytest.mark.parametrize("mode", ["cancel", "deadline"])
def test_running_query_interrupted_within_bound_and_connection_reusable(store, mode):
    stop = threading.Event()
    timer = threading.Timer(0.15, stop.set)
    timer.daemon = True
    started = time.monotonic()
    if mode == "cancel":
        timer.start()
    try:
        with pytest.raises((RuntimeError, duckdb.Error)):
            store.analytics_query(
                "SELECT sum(i*j) AS n FROM range(1000000000) a(i) CROSS JOIN range(1000) b(j)",
                [],
                cancel=stop,
                timeout=0.15 if mode == "deadline" else 2,
                max_rows=1,
            )
        assert time.monotonic() - started < 2
    finally:
        timer.cancel()
        if timer.ident is not None:
            timer.join()
    usable(store)


@pytest.mark.parametrize(
    "options",
    [
        {"max_rows": 0},
        {"max_rows": True},
        {"max_rows": 10001},
        {"timeout": 0},
        {"timeout": True},
        {"timeout": float("nan")},
    ],
)
def test_invalid_resource_bounds_are_rejected(store, options):
    with pytest.raises(ValueError):
        store.analytics_query("SELECT 1 AS n", [], **options)
    usable(store)
