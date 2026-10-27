"""Real peer HTTP/TLS and quorum-journal tests for bounded exact reduction."""

import json
import secrets
import socket
import threading
import time
from contextlib import contextmanager

import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from test_cluster import quorum as quorum_fixture
from test_cluster import retry
from test_federation import config, node, payload
from test_federation import master as master_fixture

from sapientia.federation import PEER_PATH, Federation, FederationError, signed_headers
from sapientia.storage import CapacityError, encode

quorum = quorum_fixture
master = master_fixture


def metrics_query(group_by=None, **kwargs):
    return payload(
        {
            "filters": [{"field": "source", "op": "eq", "value": "metrics"}],
            "group_by": group_by or [],
            "aggregates": [
                {"op": "count", "as": "events"},
                {"op": "sum", "field": "raw.n", "as": "total"},
                {"op": "avg", "field": "raw.n", "as": "mean"},
                {"op": "min", "field": "raw.n", "as": "minimum"},
                {"op": "max", "field": "raw.n", "as": "maximum"},
                {"op": "distinct", "field": "raw.tag", "as": "unique_tags"},
            ],
            **kwargs,
        },
        limit=1,
    )


def add_metrics(store, values, tags=None, host="metric", tenant="a", index="main"):
    tags = tags or ["same"] * len(values)
    store.ingest(
        tenant,
        [
            {
                "event_id": "metric-" + str(n),
                "event_time": 500 + n / 10000,
                "source": "metrics",
                "host": host,
                "index": index,
                "raw": {"n": value, "tag": tag},
            }
            for n, (value, tag) in enumerate(zip(values, tags))
        ],
    )
    store.flush()


def test_real_partitions_weighted_numeric_and_typed_distinct(
    master, tmp_path, monkeypatch
):
    with (
        node(tmp_path, monkeypatch, 0) as a,
        node(tmp_path, monkeypatch, 1, tls=True) as b,
    ):
        add_metrics(
            a[0], [1, 3, None, "100", True, 2.0], ["same", "same", 2, "2", None, True]
        )
        add_metrics(b[0], [10, 20, 30], [2.0, "same", "2"])
        federation = Federation(master, config([a[2], b[2]]))
        result = federation.search({"tenant": "a"}, metrics_query(["host"]), ["main"])
        assert result["rows"] == [
            {
                "host": "metric",
                "events": 9,
                "total": 66.0,
                "mean": 11.0,
                "minimum": 1.0,
                "maximum": 30.0,
                "unique_tags": 4,
            }
        ]
        assert len(result["nodes"]) == 2
        assert len({part["dataset_id"] for part in result["nodes"]}) == 2
        assert result["complete"] and result["returned"] == 1
        # An input projection limit is never a sampling limit for aggregation.
        denied = federation.search({"tenant": "a"}, metrics_query(), [])
        assert denied["rows"] == [
            {
                "events": 0,
                "total": None,
                "mean": None,
                "minimum": None,
                "maximum": None,
                "unique_tags": 0,
            }
        ]


def test_full_window_more_than_limit_and_no_cross_tenant_index(
    master, tmp_path, monkeypatch
):
    with node(tmp_path, monkeypatch, 0) as a, node(tmp_path, monkeypatch, 1) as b:
        for store in (a[0], b[0]):
            add_metrics(store, list(range(1000)))
            store.ingest(
                "a",
                [
                    {
                        "event_id": "extra",
                        "event_time": 500,
                        "source": "metrics",
                        "raw": {"n": 1000, "tag": "same"},
                    }
                ],
            )
            store.ingest(
                "b",
                [
                    {
                        "event_id": "other-metric",
                        "event_time": 500,
                        "source": "metrics",
                        "raw": {"n": 900000},
                    }
                ],
            )
            store.ingest(
                "a",
                [
                    {
                        "event_id": "private-metric",
                        "event_time": 500,
                        "source": "metrics",
                        "index": "private",
                        "raw": {"n": 900000},
                    }
                ],
            )
            store.flush()
        federation = Federation(master, config([a[2], b[2]]))
        result = federation.search({"tenant": "a"}, metrics_query(), ["main"])
        assert result["rows"][0]["events"] == 2002
        assert result["rows"][0]["total"] == 1001000
        assert result["rows"][0]["mean"] == 500


def test_integer_sum_preserves_cancellation_across_partitions(
    master, tmp_path, monkeypatch
):
    maximum = 2**53 - 1
    with node(tmp_path, monkeypatch, 0) as a, node(tmp_path, monkeypatch, 1) as b:
        add_metrics(a[0], [maximum, 1])
        add_metrics(b[0], [-maximum])
        result = Federation(master, config([a[2], b[2]])).search(
            {"tenant": "a"}, metrics_query(), ["main"]
        )
        assert result["rows"][0]["total"] == 1
        assert type(result["rows"][0]["total"]) is int
        assert result["rows"][0]["mean"] == pytest.approx(1 / 3)


def test_request_uses_cached_addresses_but_keeps_https_validation(
    master, tmp_path, monkeypatch
):
    with node(tmp_path, monkeypatch, 0, tls=True) as a:
        federation = Federation(master, {"include_local": False, "peers": [a[2]]})

        def no_request_dns(*_args, **_kwargs):
            raise AssertionError("Per-request DNS can exceed a socket deadline")

        monkeypatch.setattr(socket, "getaddrinfo", no_request_dns)
        result = federation.search({"tenant": "a"}, payload({"group_by": []}), ["main"])
        assert result["rows"] == [{"count": 1}]


@pytest.mark.parametrize("values", [[2**53 + 1], [2**53 - 1, 2**53 - 1]])
def test_unsafe_numeric_input_or_result_rejected_not_rounded(
    master, tmp_path, monkeypatch, values
):
    with node(tmp_path, monkeypatch, 0) as a:
        add_metrics(a[0], values)
        with pytest.raises(FederationError) as error:
            Federation(master, config([a[2]])).search(
                {"tenant": "a"}, metrics_query(), ["main"]
            )
        assert error.value.status_code == 413


def test_exact_distinct_and_group_caps_reject_visible(master, tmp_path, monkeypatch):
    with node(tmp_path, monkeypatch, 0) as a, node(tmp_path, monkeypatch, 1) as b:
        add_metrics(a[0], [1, 2], ["a", "b"])
        add_metrics(b[0], [3, 4], ["b", "c"])
        federation = Federation(master, config([a[2], b[2]], max_distinct=2))
        with pytest.raises(FederationError, match="global distinct") as error:
            federation.search({"tenant": "a"}, metrics_query(), ["main"])
        assert error.value.status_code == 413
        a[1].max_distinct = 1
        with pytest.raises(FederationError, match="HTTP 413") as error:
            federation.search({"tenant": "a"}, metrics_query(), ["main"])
        assert error.value.status_code == 413 or "HTTP 413" in str(error.value)
        a[1].max_distinct = 10000
        federation = Federation(master, config([a[2], b[2]], max_groups=1))
        b[0].ingest(
            "a",
            [
                {
                    "event_id": "new-host",
                    "event_time": 500,
                    "source": "metrics",
                    "host": "second",
                    "raw": {"n": 5},
                }
            ],
        )
        b[0].flush()
        with pytest.raises(FederationError, match="group cap"):
            federation.search({"tenant": "a"}, metrics_query(["host"]), ["main"])


@pytest.mark.parametrize(
    "metric",
    [
        {"op": "median", "field": "raw.n", "as": "x"},
        {"op": "sum", "field": "message", "as": "x"},
        {"op": "sum", "field": "raw.n);DROP", "as": "x"},
        {"op": "count", "field": "host", "as": "x"},
        {"op": "count", "as": "__internal"},
        {"op": [], "as": "x"},
        {"op": "count", "as": "index"},
    ],
)
def test_unsupported_or_injected_aggregates_rejected(master, metric):
    federation = Federation(master, {})
    with pytest.raises(ValueError):
        federation.search({"tenant": "a"}, payload({"aggregates": [metric]}), ["main"])


def test_local_segment_and_peer_auth_locks_respect_budget(
    master, tmp_path, monkeypatch
):
    entered, release = threading.Event(), threading.Event()

    def hold_segment():
        with master.segment_lock.write():
            entered.set()
            release.wait(2)

    thread = threading.Thread(target=hold_segment)
    thread.start()
    assert entered.wait(1)
    try:
        start = time.monotonic()
        with pytest.raises(FederationError) as error:
            Federation(master, {"timeout": 0.1}).search(
                {"tenant": "a"}, metrics_query(), ["main"]
            )
        assert error.value.status_code in (503, 504)
        assert time.monotonic() - start < 0.3
    finally:
        release.set()
        thread.join(2)
    with node(tmp_path, monkeypatch, 0) as peer:
        store, federation, configuration, secret = peer
        entered.clear()
        release.clear()

        def hold_control():
            with store.write_lock:
                entered.set()
                release.wait(2)

        thread = threading.Thread(target=hold_control)
        thread.start()
        assert entered.wait(1)
        body = encode(
            {
                "version": 1,
                "recipient": configuration["key_id"],
                "tenant": "a",
                "allowed_indexes": ["main"],
                "payload": payload({"group_by": []}),
                "budget_ms": 80,
            }
        ).encode()
        headers = signed_headers(configuration["key_id"], secret, body)
        try:
            start = time.monotonic()
            with pytest.raises(FederationError) as error:
                federation.handle_peer(body, headers)
            assert error.value.status_code == 504
            assert time.monotonic() - start < 0.25
        finally:
            release.set()
            thread.join(2)
        # The 80 ms request above proves bounded lock failure. Recovery has a
        # separate fresh budget so CPU contention cannot masquerade as a lock.
        recovery = {**json.loads(body), "budget_ms": 1000}
        recovery_body = encode(recovery).encode()
        recovery_headers = signed_headers(configuration["key_id"], secret, recovery_body)
        assert federation.handle_peer(recovery_body, recovery_headers)["rows"] == [
            {"count": 1}
        ]


def test_dataset_declarations_fenced_and_deadline_bounded(
    master, tmp_path, monkeypatch
):
    with node(tmp_path, monkeypatch, 0) as a:
        forged = {**a[2], "dataset_id": "wrong", "replica_set": "wrong"}
        federation = Federation(master, config([forged]))
        with pytest.raises(FederationError):
            federation.search({"tenant": "a"}, metrics_query(), ["main"])
        for peers in (
            [
                {**a[2], "dataset_id": "same"},
                {**a[2], "name": "other", "dataset_id": "same"},
            ],
        ):
            with pytest.raises(FederationError, match="Conflicting replica"):
                Federation(master, config(peers))
        with pytest.raises(FederationError, match="quorum journal"):
            Federation(master, {"local_replica_set": "pretend"})
    with node(tmp_path, monkeypatch, 2, delay=0.4) as slow:
        # Static candidates reserve part of one total budget for fallback.
        peers = [
            {**slow[2], "dataset_id": "same", "replica_set": "same"},
            {**slow[2], "name": "second", "dataset_id": "same", "replica_set": "same"},
        ]
        federation = Federation(master, config(peers, timeout=0.1))
        start = time.monotonic()
        with pytest.raises(FederationError):
            federation.search({"tenant": "a"}, metrics_query(), ["main"])
        assert time.monotonic() - start < 0.25


@contextmanager
def replica_peer(store, monkeypatch, number):
    variable, key_id = f"FEDERATED_QUORUM_{number}", f"quorum{number}"
    monkeypatch.setenv(variable, secrets.token_urlsafe(32))
    federation = Federation(
        store,
        {
            "local_name": f"replica{number}",
            "grants": [
                {
                    "key_id": key_id,
                    "secret_env": variable,
                    "tenants": ["a"],
                    "indexes": ["main"],
                }
            ],
        },
    )
    app = FastAPI()

    @app.post(PEER_PATH)
    async def search(request: Request):
        try:
            return await run_in_threadpool(
                federation.handle_peer, await request.body(), request.headers
            )
        except FederationError as exc:
            return JSONResponse({"detail": str(exc)}, exc.status_code)

    bound = socket.socket()
    bound.bind(("127.0.0.1", 0))
    bound.listen()
    server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
    thread = threading.Thread(target=lambda: server.run(sockets=[bound]), daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.01)
    assert server.started
    try:
        yield {
            "name": f"replica{number}",
            "url": f"http://127.0.0.1:{bound.getsockname()[1]}",
            "key_id": key_id,
            "secret_env": variable,
            "tenants": ["a"],
            "indexes": ["main"],
            "dataset_id": federation.dataset_id,
            "replica_set": federation.replica_set,
            "preference": number,
        }
    finally:
        server.should_exit = True
        thread.join(5)
        bound.close()
        assert not thread.is_alive()


def test_real_quorum_replica_dedup_lag_fallback_and_quorum_loss(
    quorum, master, monkeypatch
):
    node_factory, brokers, _restart = quorum
    a, b = node_factory("a"), node_factory("b")
    try:
        retry(
            lambda: a.ingest(
                "a",
                [
                    {
                        "event_id": str(i),
                        "event_time": 500,
                        "source": "metrics",
                        "raw": {"n": i, "tag": "same"},
                    }
                    for i in range(3)
                ],
            )
        )
        a.replica.catch_up()
        b.replica.catch_up()
        assert not b.replica.readiness(tenant="a", allowed_indexes=["main"])["ready"]
        a.flush()
        b.flush()
        probe = b.replica.readiness(tenant="a", allowed_indexes=["main"])
        assert (
            probe["ready"]
            and not probe["quorum_verified"]
            and probe["requires_read_barrier"]
        )
        with (
            replica_peer(a, monkeypatch, 0) as pa,
            replica_peer(b, monkeypatch, 1) as pb,
        ):
            federation = Federation(master, config([pa, pb], timeout=3))
            result = federation.search({"tenant": "a"}, metrics_query(), ["main"])
            assert (
                result["rows"][0]["events"] == 3
            )  # Full copies are not independent partitions.
            assert (
                len(result["nodes"]) == 1 and result["nodes"][0]["name"] == "replica0"
            )
            master_and_replica = Federation(
                a, config([pb], include_local=True, local_indexes=["main"], timeout=3)
            )
            local_result = master_and_replica.search(
                {"tenant": "a"}, metrics_query(), ["*"]
            )
            assert (
                local_result["rows"][0]["events"] == 3
                and len(local_result["nodes"]) == 1
            )
            events = federation.search(
                {"tenant": "a"},
                payload({"fields": ["event_id", "event_time"]}),
                ["main"],
            )
            identities = {row["_federated_id"] for row in events["rows"]}
            # The preferred replica has admitted data but its analytical index lags.
            retry(
                lambda: a.ingest(
                    "a",
                    [
                        {
                            "event_id": "next",
                            "event_time": 500,
                            "source": "metrics",
                            "raw": {"n": 5},
                        }
                    ],
                )
            )
            b.replica.catch_up()
            b.flush()
            fallback = federation.search({"tenant": "a"}, metrics_query(), ["main"])
            assert fallback["rows"][0]["events"] == 4
            assert fallback["nodes"][0]["name"] == "replica1"
            assert fallback["nodes"][0]["attempts"] == [
                {"name": "replica0", "status": 503}
            ]
            local_fallback = master_and_replica.search(
                {"tenant": "a"}, metrics_query(), ["*"]
            )
            assert local_fallback["rows"][0]["events"] == 4
            assert local_fallback["nodes"][0]["name"] == "replica1"
            stable = federation.search(
                {"tenant": "a"},
                payload({"fields": ["event_id", "event_time"]}),
                ["main"],
            )
            assert identities < {row["_federated_id"] for row in stable["rows"]}
            fenced_query = metrics_query()
            fenced_query["minimum_sequences"] = {pa["dataset_id"]: 2**31}
            with pytest.raises(FederationError):
                federation.search({"tenant": "a"}, fenced_query, ["main"])
            with b.control() as db:
                db.execute(
                    "INSERT INTO retention_intents VALUES(?,?,?,?,?)",
                    (
                        "federation-retention-test",
                        "a",
                        time.time() + 1,
                        '["0"]',
                        time.time(),
                    ),
                )
            with pytest.raises(CapacityError, match="retention"):
                b.replica.read_barrier(tenant="a", allowed_indexes=["main"])
            b.flush()
            # A ready full copy still cannot claim a fresh read without quorum.
            for broker in brokers[:2]:
                broker.terminate()
                broker.wait(10)
            failed = Federation(master, config([pb], timeout=0.3))
            start = time.monotonic()
            with pytest.raises(FederationError):
                failed.search({"tenant": "a"}, metrics_query(), ["main"])
            assert time.monotonic() - start < 0.7
    finally:
        a.close()
        b.close()
