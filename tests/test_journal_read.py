import asyncio

import pytest
from nats.js.errors import NotFoundError, ServiceUnavailableError

from sapientia.cluster import Bridge
from sapientia.storage import CapacityError


def test_recovery_read_retries_temporary_service_unavailable():
    bridge = object.__new__(Bridge)
    attempts = []

    async def operation():
        attempts.append(1)
        if len(attempts) < 3:
            raise ServiceUnavailableError(code=503, err_code=10008)
        return "recovered"

    assert asyncio.run(bridge.read_available(operation)) == "recovered"
    assert len(attempts) == 3


def test_read_recovery_does_not_hide_missing_journal_entry():
    bridge = object.__new__(Bridge)

    async def missing():
        raise NotFoundError(code=404, err_code=10037)

    with pytest.raises(NotFoundError):
        asyncio.run(bridge.read_available(missing))


def test_read_recovery_deadline_is_fail_closed():
    bridge = object.__new__(Bridge)

    async def unavailable():
        raise ServiceUnavailableError(code=503, err_code=10008)

    with pytest.raises(CapacityError):
        asyncio.run(bridge.read_available(unavailable, budget=0.02))
