import asyncio

import nats
import pytest
from cluster_readiness import wait_brokers_ready
from nats.js.errors import ServiceUnavailableError


class Broker:
    def __init__(self, results):
        self.results = iter(results)
        self.closed = False
        self.requests = 0

    def jetstream(self, timeout):
        assert timeout == 1
        return self

    async def account_info(self):
        self.requests += 1
        result = next(self.results)
        if isinstance(result, BaseException):
            raise result
        return result

    async def close(self):
        self.closed = True


def connect_brokers(monkeypatch, brokers):
    remaining = iter(brokers)
    calls = []

    async def connect(**kwargs):
        calls.append(kwargs)
        return next(remaining)

    monkeypatch.setattr(nats, "connect", connect)
    return calls


def test_each_broker_requires_authenticated_account_readiness(monkeypatch):
    brokers = [Broker([{}]), Broker([{}]), Broker([{}])]
    calls = connect_brokers(monkeypatch, brokers)
    asyncio.run(wait_brokers_ready([1, 2, 3], "fixture-token"))
    assert [call["servers"] for call in calls] == [
        ["nats://127.0.0.1:1"],
        ["nats://127.0.0.1:2"],
        ["nats://127.0.0.1:3"],
    ]
    assert all(call["token"] == "fixture-token" for call in calls)
    assert all(call["max_reconnect_attempts"] == 0 for call in calls)
    assert all(broker.closed and broker.requests == 1 for broker in brokers)


@pytest.mark.parametrize(
    "transient",
    [nats.errors.TimeoutError(), ServiceUnavailableError(code=503, err_code=10008)],
)
def test_only_known_transient_readiness_failure_is_retried(monkeypatch, transient):
    broker = Broker([transient, {}])
    connect_brokers(monkeypatch, [broker])
    asyncio.run(wait_brokers_ready([1], "fixture-token"))
    assert broker.requests == 2 and broker.closed


@pytest.mark.parametrize(
    "error",
    [
        ServiceUnavailableError(code=503, err_code=999),
        ServiceUnavailableError(code=403, err_code=10008),
        nats.errors.AuthorizationError(),
    ],
)
def test_nontransient_error_is_not_hidden(monkeypatch, error):
    broker = Broker([error, {}])
    connect_brokers(monkeypatch, [broker])
    with pytest.raises(type(error)) as caught:
        asyncio.run(wait_brokers_ready([1], "fixture-token"))
    assert caught.value is error
    assert broker.requests == 1 and broker.closed


def test_global_deadline_is_bounded_and_connection_closed(monkeypatch):
    broker = Broker([ServiceUnavailableError(code=503, err_code=10008)])
    connect_brokers(monkeypatch, [broker])
    with pytest.raises(TimeoutError):
        asyncio.run(wait_brokers_ready([1], "fixture-token", timeout=0.02))
    assert broker.requests == 1 and broker.closed


def test_cancellation_is_not_retried_and_connection_closed(monkeypatch):
    broker = Broker([asyncio.CancelledError()])
    connect_brokers(monkeypatch, [broker])
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(wait_brokers_ready([1], "fixture-token"))
    assert broker.requests == 1 and broker.closed
