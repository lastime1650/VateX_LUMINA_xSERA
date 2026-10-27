"""Regression coverage for isolation, retry windows, cancellation and draining."""

import json
import threading
import time

import pytest

from sapientia import access, jobs
from sapientia.runtime import Runtime, rule_health, run_due, save_rule
from sapientia.storage import Settings, Store


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    with value.control() as db:
        for name, tenant in (("owner_a", "a"), ("owner_b", "b")):
            db.execute(
                "INSERT INTO users(name,password,role,tenant) VALUES(?,?,?,?)",
                (name, "test-only-no-login", "admin", tenant),
            )
    yield value
    value.close()


def who(tenant):
    return {"name": "owner_" + tenant, "tenant": tenant, "role": "admin"}


def test_poison_rules_do_not_starve_other_tenant_and_keep_original_window(store):
    now = time.time()
    # Simulate rules saved by the old parser-only validator.
    with store.control() as db:
        for number in range(20):
            key = f"broken-{number:02}"
            db.execute(
                "INSERT INTO rules VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    key,
                    "a",
                    key,
                    json.dumps(
                        {
                            "query": '| makeresults | eval message="a" | regex message="["'
                        }
                    ),
                    30,
                    60,
                    1,
                    1,
                    now - 2,
                    None,
                    None,
                ),
            )
            db.execute(
                "INSERT INTO rule_execution(rule_id,owner) VALUES(?,?)",
                (key, "owner_a"),
            )
    healthy = save_rule(
        store, who("b"), {"name": "healthy", "query": {"query": "| makeresults"}}
    )
    with store.control() as db:
        db.execute("UPDATE rules SET next_run=? WHERE id=?", (now - 1, healthy))
    assert run_due(store, now, budget=3) == 1
    bad = rule_health(store, "a")
    assert all(row["next_run"] == now - 2 for row in bad)
    attempted = sum(
        row["last_end"] is None and row["failures"] == 1 and row["retry_at"] > now
        for row in bad
    )
    # The 3-second work budget may yield before filling all 20 batch slots under
    # parallel CPU/IO load. Tenant b still completed in the first fair pass;
    # subsequent passes finish untouched rules without retrying earlier failures.
    assert 1 <= attempted <= 19
    deadline = time.monotonic() + 15
    while any(row["failures"] == 0 for row in bad) and time.monotonic() < deadline:
        assert run_due(store, now + 0.1, budget=3) == 0
        bad = rule_health(store, "a")
        assert all(row["next_run"] == now - 2 and row["last_end"] is None for row in bad)
        assert all(row["failures"] in {0, 1} for row in bad)
        time.sleep(.01)
    assert len(bad) == 20 and all(row["failures"] == 1 and row["retry_at"] > now + .1 for row in bad)
    with store.control() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM findings WHERE rule_id=?", (healthy,)
            ).fetchone()[0]
            == 1
        )


def test_save_rule_runtime_probe_rejects_invalid_regex(store):
    with pytest.raises(Exception, match="(?i)regex|regular|missing|bracket|invalid"):
        save_rule(
            store,
            who("a"),
            {
                "name": "bad",
                "query": {
                    "query": '| makeresults | eval message="a" | regex message="["'
                },
            },
        )
    assert not rule_health(store, "a")


def test_saved_execution_uses_current_acl_and_disabled_owner_fails_closed(store):
    store.ingest("a", [{"event_id": "secret", "index": "private"}])
    store.flush()
    rule = save_rule(store, who("a"), {"name": "restricted", "query": {"query": "*"}})
    access.set_for_user(store, who("a"), "owner_a", [])
    assert run_due(store, time.time() + 1) == 1
    with store.control() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM findings WHERE rule_id=?", (rule,)
            ).fetchone()[0]
            == 0
        )
    job = jobs.submit(store, who("a"), {"query": "*"})
    with store.control() as db:
        db.execute("UPDATE users SET disabled=1 WHERE name='owner_a'")
    manager = jobs.JobManager(store)
    manager.execute(manager.claim())
    assert jobs.status(store, who("a"), job)["state"] == "failed"


def test_materialized_job_results_cannot_outlive_index_grant(store):
    job = jobs.submit(store, who("a"), {"query": "| makeresults"})
    manager = jobs.JobManager(store)
    manager.execute(manager.claim())
    assert jobs.result(store, who("a"), job)["returned"] == 1
    access.set_for_user(store, who("a"), "owner_a", [])
    with pytest.raises(PermissionError, match="permissions changed"):
        jobs.result(store, who("a"), job)


def test_indexer_drains_multiple_batches_without_fixed_one_second_sleep(store):
    store.settings.indexing_batch = 5
    store.settings.indexing_budget = 2
    store.ingest("a", [{"event_id": str(n)} for n in range(12)])
    runtime = Runtime(store)
    assert runtime.drain() is False
    assert runtime.last_batches == 3 and runtime.last_indexed == 12
    assert store.health("a")["pending"] == 0
    assert runtime.health()["indexed_eps"] > 0
    runtime.stop.set()
    assert runtime.drain() is False
    assert runtime.last_indexed == 0


def test_indexer_work_budget_yields_and_close_cancels(store, monkeypatch):
    store.settings.indexing_batch = 2
    store.settings.indexing_budget = 0.01
    store.ingest("a", [{"event_id": "pending-work-budget"}])
    calls = []

    def slow_flush(batch):
        calls.append(batch)
        time.sleep(0.02)
        return batch

    monkeypatch.setattr(store, "flush", slow_flush)
    runtime = Runtime(store)
    assert runtime.drain() is True
    assert calls == [2]
    runtime.thread = threading.Thread(target=runtime.loop)
    runtime.thread.start()
    runtime.close()
    assert not runtime.thread.is_alive()
    assert store.health("a")["pending"] == 1
