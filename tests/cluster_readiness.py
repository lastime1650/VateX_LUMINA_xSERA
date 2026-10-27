"""Authenticated, bounded readiness of the disposable integration brokers."""

import asyncio

import nats
from nats.js.errors import ServiceUnavailableError


async def wait_brokers_ready(ports, token, timeout=15):
    # A listening TCP socket does not establish a JetStream metadata leader.
    # This is a fixture precondition; no Store operation or assertion is retried.
    async with asyncio.timeout(timeout):
        for port in ports:
            client = await nats.connect(
                servers=[f"nats://127.0.0.1:{port}"],
                token=token,
                connect_timeout=1,
                max_reconnect_attempts=0,
            )
            try:
                stream = client.jetstream(timeout=1)
                while True:
                    try:
                        await stream.account_info()
                        break
                    except nats.errors.TimeoutError:
                        pass
                    except ServiceUnavailableError as exc:
                        if exc.code != 503 or exc.err_code != 10008:
                            raise
                    await asyncio.sleep(0.1)
            finally:
                await client.close()
