"""A waiting lifecycle writer must not invert the virtual dispatch lock order."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

from sapientia import action_runtime, effect_receipts
from tests.test_backend_upgrade import actor
from tests.test_virtual_response import client, fixture


def test_dispatch_concurrent_with_segment_lifecycle_writer(client, monkeypatch):
    store, source, prepared = fixture(client)
    approved = effect_receipts.transition(store, actor("peer"), prepared["id"], 1, "approved", {})
    reached_read = threading.Event()
    writer_finished = threading.Event()
    original_read = store.segment_lock.read
    @contextmanager
    def read(*args, **kwargs):
        reached_read.set()
        with original_read(*args, **kwargs):
            yield
    def lifecycle():
        with store.segment_lock.write(), store.write_lock:
            store.segments.bump(content=False)
            writer_finished.set()
    with ThreadPoolExecutor(max_workers=2) as pool:
        with original_read():
            writer = pool.submit(lifecycle)
            end = time.monotonic()+2
            while not store.segment_lock.waiting and time.monotonic() < end:
                time.sleep(.001)
            assert store.segment_lock.waiting
            monkeypatch.setattr(store.segment_lock, "read", read)
            dispatch = pool.submit(action_runtime.dispatch, store, actor(), prepared["id"], approved["version"])
            assert reached_read.wait(2)
        writer.result(timeout=5)
        result = dispatch.result(timeout=5)
    assert writer_finished.is_set()
    assert result["state"] == "confirmed" and result["native_effect"] is False
    assert action_runtime.asset(store, actor(), source["id"])["state"]["effect_count"] == 1
