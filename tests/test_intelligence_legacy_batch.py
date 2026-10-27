# ruff: noqa: F811 - shared disposable Store pytest fixture.
"""Legacy bridge prefix checkpoints retain durable publications and authority."""

import json
import threading
import time
from contextlib import contextmanager

import pytest

from sapientia import access
from sapientia import intelligence as core
from tests.test_backend_upgrade import actor, lab  # noqa: F401
from tests.test_intelligence import policy, seed


def contributions(lab, count=4, *, native=False):
    if not native:
        policy(lab, "A")
        seed(lab, stages=("A",) * count)
    with lab.control() as db:
        db.execute("INSERT INTO incidents(id,tenant,entity,entity_field,name,created,updated,status) VALUES('legacy-case','a','asset','host','Synthetic legacy bridge',?,?,'open')", (time.time(), time.time()))
        for number in range(count):
            db.execute("INSERT INTO risk_contributions VALUES(?,?,?,?,?,?,?,?,?,?)", ("legacy-contribution-" + str(number), "a", "legacy-case", "intelligence:already-published" if native else "legacy-rule-" + str(number), "asset", "host", time.time(), 20, '{"native_metadata":"already-published"}' if native else json.dumps({"event_ids": ["event-" + str(number)], "severity": "high", "evaluation": {"policy_version": 1}}), '["public"]'))


def state(lab):
    with lab.control() as db:
        return (db.execute("SELECT cursor FROM intelligence_cursors WHERE worker='contributions'").fetchone()[0], db.execute("SELECT count(*) FROM intelligence_signals WHERE kind='legacy'").fetchone()[0])


def test_native_contributions_skip_in_one_commit_without_unused_policy_reads(lab, monkeypatch, record_property):
    contributions(lab, 32, native=True)
    original = lab.control
    measured = {"connections": 0, "commits": 0, "policy_reads": 0}
    @contextmanager
    def control(*args, **kwargs):
        measured["connections"] += 1
        with original(*args, **kwargs) as db:
            def trace(sql):
                measured["commits"] += sql == "COMMIT"
                measured["policy_reads"] += "FROM intelligence_policies" in sql
            db.set_trace_callback(trace)
            yield db
    with monkeypatch.context() as changes:
        changes.setattr(lab, "control", control)
        assert core._legacy(lab, maximum=32) == 0
    assert measured == {"connections": 2, "commits": 1, "policy_reads": 0}
    assert state(lab) == (32, 0)
    record_property("legacy_proof", json.dumps({"type": "native_skip", "contributions": 32, **measured, "cursor": state(lab)[0]}))


def test_exception_after_publication_commits_only_completed_prefix_and_retry_deduplicates(lab, monkeypatch):
    contributions(lab)
    original = core._legacy_one
    def interrupted(store, row, declaration, evidence):
        result = original(store, row, declaration, evidence)
        if row["sequence"] == 3:
            raise RuntimeError("Crash after durable publication before prefix acknowledgement")
        return result
    with monkeypatch.context() as changes:
        changes.setattr(core, "_legacy_one", interrupted)
        with pytest.raises(RuntimeError, match="Crash after durable"):
            core._legacy(lab)
    assert state(lab) == (2, 3)
    assert core._legacy(lab) == 1
    assert state(lab) == (4, 4)
    assert core._legacy(lab) == 0


def test_checkpoint_failure_replays_a_committed_publication_without_duplicates(lab, monkeypatch):
    contributions(lab, 1)
    original = lab.control
    class Connection:
        def __init__(self, db):
            self.db = db
        def __getattr__(self, name):
            return getattr(self.db, name)
        def execute(self, sql, *args):
            if sql.startswith("UPDATE intelligence_cursors SET cursor=max(cursor,"):
                raise RuntimeError("Owned cursor commit fault")
            return self.db.execute(sql, *args)
    @contextmanager
    def control(*args, **kwargs):
        with original(*args, **kwargs) as db:
            yield Connection(db)
    with monkeypatch.context() as changes:
        changes.setattr(lab, "control", control)
        with pytest.raises(RuntimeError, match="cursor commit fault"):
            core._legacy(lab)
    assert state(lab) == (0, 1)
    assert core._legacy(lab) == 0
    assert state(lab) == (1, 1)


def test_cancel_flushes_only_completed_prefix_and_pre_cancel_has_no_progress(lab, monkeypatch):
    contributions(lab, 3)
    cancelled = threading.Event()
    cancelled.set()
    assert core._legacy(lab, cancel=cancelled) == 0 and state(lab) == (0, 0)
    cancelled.clear()
    original = core._legacy_one
    def one(store, row, declaration, evidence):
        result = original(store, row, declaration, evidence)
        cancelled.set()
        return result
    with monkeypatch.context() as changes:
        changes.setattr(core, "_legacy_one", one)
        assert core._legacy(lab, cancel=cancelled) == 1
    assert state(lab) == (1, 1)
    assert core._legacy(lab) == 2 and state(lab) == (3, 3)


def test_concurrent_slow_worker_cannot_regress_a_newer_completed_cursor(lab, monkeypatch):
    contributions(lab, 4)
    blocked, release = threading.Event(), threading.Event()
    original = core._legacy_one
    errors, results = [], []
    def one(store, row, declaration, evidence):
        result = original(store, row, declaration, evidence)
        if threading.current_thread().name == "legacy-slow-prefix":
            blocked.set()
            if not release.wait(10):
                raise RuntimeError("Synthetic concurrent worker did not release")
        return result
    def slow():
        try:
            results.append(core._legacy(lab, maximum=1))
        except Exception as exc:  # noqa: BLE001 - thread exceptions must reach the test.
            errors.append(exc)
    monkeypatch.setattr(core, "_legacy_one", one)
    worker = threading.Thread(target=slow, name="legacy-slow-prefix")
    worker.start()
    try:
        assert blocked.wait(10)
        assert core._legacy(lab, maximum=4) == 3
        assert state(lab) == (4, 4)
    finally:
        release.set()
        worker.join(10)
    assert not worker.is_alive() and not errors and results == [1]
    assert state(lab) == (4, 4)


@pytest.mark.parametrize("change", ["reviewer", "owner_scope"])
def test_current_authority_revocation_excludes_later_rows_without_reusing_approval(lab, monkeypatch, change):
    contributions(lab, 2)
    original = core._legacy_one
    def one(store, row, declaration, evidence):
        result = original(store, row, declaration, evidence)
        if row["sequence"] == 1:
            if change == "reviewer":
                with store.control() as db:
                    db.execute("UPDATE users SET disabled=1 WHERE name='peer'")
            else:
                access.set_for_user(store, actor(), "owner", ["private"])
        return result
    monkeypatch.setattr(core, "_legacy_one", one)
    assert core._legacy(lab) == 1 and state(lab) == (2, 1)
    with lab.control() as db:
        assert db.execute("SELECT count(*) FROM intelligence_decisions WHERE reason='legacy_excluded'").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM endpoint_responses").fetchone()[0] == 0
