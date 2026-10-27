"""Cross-scope graph privacy and current publication authority regressions."""

import importlib.util
import json
import threading
import time

import pytest

from sapientia import access, auth, cpu_ml, evidence_scope, intelligence, intelligence_findings, principal, runtime
from sapientia.storage import Settings, Store, encode

PASSWORD = "Isolated-intelligence-safety-account-2026"


def actor(name="trainer_a", indexes=None):
    return {"name": name, "tenant": "b" if name.endswith("_b") else "a",
            "role": "admin" if name == "admin_a" else "analyst",
            "allowed_indexes": ["*"] if indexes is None else indexes}


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    intelligence.initialize(value)
    cpu_ml.initialize(value)
    runtime.initialize(value)
    for name in ("trainer_a", "reviewer_a", "trainer_b", "reviewer_b", "admin_a"):
        who = actor(name)
        auth.create_user(value, name, PASSWORD, who["role"], who["tenant"])
    yield value
    value.close()


def active_policy(store, tenant="a", adapter=None):
    created = intelligence.save_policy(store, actor("trainer_"+tenant), {
        "name": "Reviewed safety rule "+tenant, "kind": "atomic", "indexes": ["main"],
        "enabled": True, "version": 0, "filters": [{"field": "raw.action", "op": "eq", "value": "hit"}],
        "case_adapter": adapter})
    intelligence.review_policy(store, actor("reviewer_"+tenant), created["id"], {"version": 1, "approve": True, "reason": "Independent original-row authority review"})
    return created


def published(store, event_id, **extra):
    return intelligence.publish(store, actor(), {"event_ids": [event_id], "kind": "atomic", "rule_id": "safety-source", "rule_revision": 1,
                                                "features": {}, "severity": "info", "confidence_grade": "test_original", **extra})


def test_same_file_in_distinct_stories_cannot_leak_private_original(store):
    store.ingest("a", [{"event_id": "public-file", "index": "public", "raw": {"xdr": {"data": {"file": {"path": "C:/same.bin"}}}}},
                       {"event_id": "private-file", "index": "private", "raw": {"xdr": {"data": {"file": {"path": "C:/same.bin"}}}}}])
    store.flush()
    public = published(store, "public-file")
    private = published(store, "private-file")
    assert public["story_id"] != private["story_id"]
    detail = intelligence.story(store, actor(indexes=["public"]), public["story_id"])
    assert detail["indexes"] == ["public"]
    assert not any("private-file" in node["event_ids"] for node in detail["nodes"])
    assert all(set(node["indexes"]) <= {"public"} for node in detail["nodes"])
    assert all(set(edge["indexes"]) <= {"public"} for edge in detail["edges"])
    with pytest.raises(KeyError):
        intelligence.story(store, actor(indexes=["public"]), private["story_id"])


def test_revoked_reviewer_item_does_not_starve_later_tenant(store):
    active_policy(store, "a")
    active_policy(store, "b")
    store.ingest("a", [{"event_id": "a-unavailable", "raw": {"action": "hit"}}])
    store.ingest("b", [{"event_id": "b-valid", "raw": {"action": "hit"}}])
    store.flush()
    with store.control() as db:
        db.execute("UPDATE users SET disabled=1 WHERE name='reviewer_a'")
    intelligence.run_due(store, budget=10, max_runs=8)
    visible = intelligence.signals(store, actor("trainer_b"), count=100)["items"]
    assert any(row["kind"] == "atomic" and row["event_ids"] == ["b-valid"] for row in visible)
    with store.control() as db:
        cursor = db.execute("SELECT cursor FROM intelligence_cursors WHERE worker='events'").fetchone()[0]
        assert cursor >= db.execute("SELECT max(seq) FROM intelligence_event_outbox").fetchone()[0]


def test_ml_signal_publication_rechecks_current_reviewer(store):
    if importlib.util.find_spec("torch") is None:
        pytest.skip("Optional CPU PyTorch unavailable")
    if not cpu_ml.runtime_status()["available"]:
        pytest.skip("CPU PyTorch incompatible on this system")
    now = time.time()-120
    events = [{"event_id": "cpu-normal-"+str(i), "event_time": now+i, "host": "real-original-host", "raw": {"command_line": "echo normal"}} for i in range(25)]
    store.ingest("a", events)
    store.flush()
    model = cpu_ml.train(store, actor(), {"name": "Current reviewer publication", "indexes": ["main"],
        "training_ids": ["cpu-normal-"+str(i) for i in range(16)], "validation_ids": ["cpu-normal-"+str(i) for i in range(16,24)],
        "epochs": 30, "normal_training_confirmed": True})
    assert model["status"] == "completed"
    cpu_ml.activate(store, actor("reviewer_a"), model["id"], "Independently reviewed source and holdout IDs")
    data = {"event_ids": ["cpu-normal-24"], "kind": "ml", "rule_id": "ml:"+model["id"],
            "rule_revision": model["revision"], "features": cpu_ml.extract_features(events[-1]),
            "severity": "info", "confidence_grade": "model_distribution_deviation", "model_digest": model["digest"]}
    intelligence.publish(store, actor(), data)
    with store.control() as db:
        db.execute("UPDATE users SET disabled=1 WHERE name='reviewer_a'")
    with pytest.raises(PermissionError):
        intelligence.publish(store, actor(), data)


def test_case_step_evidence_retains_original_host_and_ip(store):
    policy = active_policy(store, adapter={"entity_field": "host", "risk_score": 40, "severity": "high", "cooldown": 0})
    store.ingest("a", [{"event_id": "case-original", "host": "actual-source-host", "raw": {"action": "hit", "src_ip": "10.9.1.2"}}])
    store.flush()
    with principal.transaction(store, actor(), write=True) as (db, current):
        row = db.execute("SELECT * FROM intelligence_policies WHERE id=?", (policy["id"],)).fetchone()
        signal = intelligence.publish_in_transaction(store, db, current, {"event_ids": ["case-original"], "kind": "atomic", "rule_id": policy["id"],
            "rule_revision": 1, "features": {}, "severity": "high", "confidence_grade": "test_original"})
        intelligence._case(store, db, current, row, json.loads(row["definition"]), signal)
        evidence = json.loads(db.execute("SELECT evidence FROM risk_contributions WHERE tenant='a'").fetchone()[0])
        original = evidence["steps"][0]["events"][0]
        assert original["host"] == "actual-source-host"
        assert original["raw.security.src_ip"] == "10.9.1.2"


def test_finding_bridge_excludes_aggregates_advances_cursor_and_checks_verdict(store):
    active_policy(store)
    access.set_for_user(store, actor("admin_a"), "trainer_a", ["main"])
    store.ingest("a", [{"event_id": "finding-original", "host": "finding-host", "raw": {"action": "hit"}}])
    store.flush()
    original = evidence_scope.originals(store, actor(indexes=["main"]), ["finding-original"])["finding-original"]
    sample = {key: original[key] for key in ("event_id", "event_time", "host", "source", "index_name")}
    with store.control() as db:
        db.execute("INSERT INTO rules VALUES(?,?,?,?,?,?,?,?,?,?,?)", ("saved-rule", "a", "Saved original rows", encode({"text": ""}), 30, 60, 1, 1, time.time(), None, None))
        db.execute("INSERT INTO rule_execution(rule_id,owner) VALUES('saved-rule','trainer_a')")
        for identifier, evidence in (("aggregate", {"sample": [{"count": 10}], "access_scope": ["main"]}),
                                    ("original-finding", {"sample": [sample], "access_scope": ["main"], "matched_at_least": 1})):
            db.execute("INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?)", (identifier, "a", "saved-rule", "Finding", time.time(), "new", "", 1, encode(evidence)))
    result = intelligence_findings.run_due(store, budget=10)
    assert result["excluded"] == 1 and result["published"] == 1
    items = intelligence.signals(store, actor(), count=100)["items"]
    finding = next(item for item in items if item["kind"] == "finding")
    assert finding["event_ids"] == ["finding-original"] and finding["metadata"]["sample_subset_only"]
    with principal.transaction(store, actor(), write=True) as (db, current):
        assert intelligence_findings.validate_parent(db, current, finding)
        db.execute("UPDATE findings SET status='false_positive' WHERE id='original-finding'")
        assert not intelligence_findings.validate_parent(db, current, finding)
        assert db.execute("SELECT cursor FROM intelligence_cursors WHERE worker='findings'").fetchone()[0] == 2


def test_finding_original_read_finishes_with_pending_real_segment_writer(store, monkeypatch):
    active_policy(store)
    access.set_for_user(store, actor("admin_a"), "trainer_a", ["main"])
    store.ingest("a", [{"event_id": "existing-finding-source", "host": "original-host", "raw": {"action": "hit"}}])
    store.flush()
    original = evidence_scope.originals(store, actor(indexes=["main"]), ["existing-finding-source"])["existing-finding-source"]
    sample = {key: original[key] for key in ("event_id", "event_time", "host", "source", "index_name")}
    with store.control() as db:
        db.execute("INSERT INTO rules VALUES(?,?,?,?,?,?,?,?,?,?,?)", ("barrier-rule", "a", "Original lookup", encode({"text": ""}), 30, 60, 1, 1, time.time(), None, None))
        db.execute("INSERT INTO rule_execution(rule_id,owner) VALUES('barrier-rule','trainer_a')")
        db.execute("INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?)", ("barrier-finding", "a", "barrier-rule", "Finding", time.time(), "new", "", 1, encode({"sample": [sample], "access_scope": ["main"]})))
    store.ingest("a", [{"event_id": "simultaneous-indexed", "host": "indexer-host"}])
    finished, failures, threads = threading.Event(), [], []
    real_export = intelligence_findings._export
    def writer():
        try:
            with store.segment_lock.write():
                store.flush()
        except Exception as exc:
            failures.append(exc)
        finally:
            finished.set()
    def with_waiting_writer(*args):
        assert getattr(store.segment_lock.local, "reads", 0) > 0
        worker = threading.Thread(target=writer, daemon=True)
        threads.append(worker)
        worker.start()
        with store.segment_lock.condition:
            assert store.segment_lock.condition.wait_for(lambda: store.segment_lock.waiting > 0, timeout=2)
        return real_export(*args)  # Uses actual nested analytics query with writer pending.
    monkeypatch.setattr(intelligence_findings, "_export", with_waiting_writer)
    try:
        result = intelligence_findings.run_due(store, budget=10)
        assert result["published"] == 1 and not result["retry"]
        assert finished.wait(3)
        assert not failures
        assert store.analytics_query("SELECT count(*) AS n FROM events_all WHERE tenant='a' AND event_id='simultaneous-indexed'", [], max_rows=1)["rows"][0]["n"] == 1
    finally:
        for worker in threads:
            worker.join(3)
