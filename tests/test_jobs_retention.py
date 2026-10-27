import subprocess
import sys
import time

import pytest

from sapientia import jobs
from sapientia.storage import ConflictError, Settings, Store
from tests.test_extended import _CRASH_DISK_MODEL


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    from sapientia.auth import create_user
    create_user(value, "analyst", "Testing-only-password-2026", "analyst", "a")
    create_user(value, "admin", "Testing-only-password-2026", "admin", "a")
    yield value
    value.close()


WHO = {"name": "analyst", "tenant": "a", "role": "analyst"}


def test_job_owner_tenant_page_and_completion(store):
    job = jobs.submit(
        store,
        WHO,
        {"query": "| makeresults count=12 | streamstats count AS n | table n"},
    )
    manager = jobs.JobManager(store)
    manager.execute(manager.claim())
    assert jobs.status(store, WHO, job)["state"] == "done"
    page = jobs.result(store, WHO, job, 5, 3)
    assert [r["n"] for r in page["rows"]] == [6, 7, 8]
    assert page["next_offset"] == 8 and page["total_materialized"] == 12
    for other in ({**WHO, "tenant": "b"}, {**WHO, "name": "different"}):
        with pytest.raises(KeyError):
            jobs.result(store, other, job)
    assert (
        jobs.result(store, {**WHO, "role": "admin", "name": "admin"}, job)["returned"]
        == 12
    )


def test_queued_cancel_and_running_cancel(store):
    job = jobs.submit(store, WHO, {"query": "| makeresults count=2"})
    assert jobs.cancel(store, WHO, job)["state"] == "cancelled"
    manager = jobs.JobManager(store)
    assert manager.claim() is None
    job = jobs.submit(store, WHO, {"query": "| makeresults count=2"})
    claimed = manager.claim()
    assert jobs.cancel(store, WHO, job)["state"] == "cancel_requested"
    manager.execute(claimed)
    assert jobs.status(store, WHO, job)["state"] == "cancelled"
    with pytest.raises(ConflictError):
        jobs.result(store, WHO, job)


def test_abandoned_worker_job_is_reclaimed(store):
    job = jobs.submit(store, WHO, {"query": "| makeresults count=2"})
    manager = jobs.JobManager(store)
    assert manager.claim()["id"] == job
    assert manager.claim() is None
    with store.control() as db:
        db.execute("UPDATE search_jobs SET lease=? WHERE id=?", (time.time() - 1, job))
    assert manager.claim()["id"] == job


def test_retention_replays_after_power_loss(tmp_path):
    program = _CRASH_DISK_MODEL + """from sapientia.storage import Store,Settings
from tests.capacity_helpers import purge as capacity_purge
s=Store(Settings(Path(sys.argv[1]),min_free_bytes=0,retention_days=0))
s.ingest('a',[{'event_id':'old'}]);s.flush()
def die():os._exit(29)
capacity_purge(s,after_delete=die)
"""
    process = subprocess.run(
        [sys.executable, "-c", program, str(tmp_path)], capture_output=True, timeout=20, check=False
    )
    assert process.returncode == 29, process.stderr.decode()
    store = Store(Settings(tmp_path, min_free_bytes=0, retention_days=0))
    try:
        with store.control() as db:
            assert (
                db.execute("SELECT count(*) FROM retention_intents").fetchone()[0] == 1
            )
            assert (
                db.execute("SELECT count(*) FROM retention_applied").fetchone()[0] == 0
            )
            assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 1
            original_digest = db.execute("SELECT digest FROM receipts").fetchone()[0]
        with pytest.raises(ConflictError, match="Retention.*pending"):
            store.ingest("a", [{"event_id": "old", "message": "new generation"}])
        with store.control() as db:
            assert db.execute("SELECT digest FROM receipts").fetchone()[0] == original_digest
        store.flush()
        with store.control() as db:
            assert (
                db.execute("SELECT count(*) FROM retention_applied").fetchone()[0] == 1
            )
            assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 0
        assert store.health("a")["indexed"] == 0
        # A genuinely new receipt with the expired ID must survive old intent replay.
        assert store.ingest("a", [{"event_id": "old", "message": "new generation"}])["accepted"] == 1
        assert store.flush() == 1
        assert store.health("a")["indexed"] == 1
        assert store.search("a", {"query": "* | table message"})["rows"] == [{"message": "new generation"}]
        with store.control() as db:
            assert db.execute("SELECT digest FROM receipts").fetchone()[0] != original_digest
    finally:
        store.close()
