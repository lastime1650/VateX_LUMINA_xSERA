"""Interrupted capacity cleanup cannot admit a new body for a retained identity."""

import json
import time

import pytest

from sapientia import backup
from sapientia.cluster import Replica
from sapientia.storage import CapacityError, ConflictError, Settings, Store, encode
from capacity_helpers import purge, tag_intent


@pytest.fixture(params=[False, True], ids=["hot", "sealed"])
def pending(store_path, request, monkeypatch):
    store = Store(Settings(store_path, min_free_bytes=0))
    now = time.time()
    original = {"event_id": "same", "message": "original-token"}
    store.ingest("a", [original])
    store.flush()
    if request.param:
        store.segments.seal(now=now + 2 * 86400)
    apply = store._apply_retention_locked
    calls = 0

    def unavailable_after_plan(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("synthetic physical deletion unavailable")
        return apply(*args, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(store, "_apply_retention_locked", unavailable_after_plan)
        with pytest.raises(RuntimeError, match="physical deletion unavailable"):
            purge(store, cutoff=now + 100 * 86400)
    try:
        yield store, original, now
    finally:
        store.close()


@pytest.fixture
def store_path(tmp_path):
    return tmp_path / "data"


def test_pending_identity_rejected_atomically_unrelated_admission_continues(pending):
    store, original, _ = pending
    replacement = {"event_id": "same", "message": "replacement-token"}
    with pytest.raises(ConflictError, match="Retention.*pending"):
        store.ingest("a", [{"event_id": "rolled-back"}, replacement])
    with store.control(local=True) as db:
        assert db.execute("SELECT count(*) FROM queue").fetchone()[0] == 0
        assert db.execute("SELECT event_id FROM receipts").fetchone()[0] == "same"
    assert store.ingest("a", [{"event_id": "unrelated"}])["accepted"] == 1
    assert store.ingest("b", [replacement])["accepted"] == 1
    store.segments.save_policy("a", "main", {
        "hot_days": 1, "warm_days": 2, "cold_days": 3,
        "retention_days": 0, "hold": True, "version": 0,
    })
    assert store.flush() == 2
    with pytest.raises(ConflictError, match="different content"):
        store.ingest("a", [replacement])
    assert store.ingest("a", [original])["duplicate"] == 1
    assert store.search("a", {"query": "event_id=same | table message"})["rows"] == [
        {"message": "original-token"}
    ]
    with store.control(local=True) as db:
        assert db.execute(
            "SELECT count(*) FROM log_fts_journal WHERE tenant='a' AND message='replacement-token'"
        ).fetchone()[0] == 0


def test_completed_physical_purge_releases_identity_for_new_body(pending):
    store, _, _ = pending
    replacement = {"event_id": "same", "message": "replacement-token"}
    with pytest.raises(ConflictError, match="Retention.*pending"):
        store.ingest("a", [replacement])
    assert store.flush() == 0
    with store.control(local=True) as db:
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 0
    assert store.ingest("a", [replacement])["accepted"] == 1
    assert store.flush() == 1
    assert store.search("a", {"query": "* | table message"})["rows"] == [
        {"message": "replacement-token"}
    ]


def test_legacy_or_peer_missing_held_receipt_keeps_recovery_fenced(pending):
    store, _, _ = pending
    # Simulate an old-version intent or a peer's already replicated retirement.
    with store.control(local=True) as db:
        db.execute("DELETE FROM receipts WHERE tenant='a' AND event_id='same'")
    store.segments.save_policy("a", "main", {
        "hot_days": 1, "warm_days": 2, "cold_days": 3,
        "retention_days": 0, "hold": True, "version": 0,
    })
    with pytest.raises(ConflictError, match="lacks its admission receipt"):
        store.flush()
    with pytest.raises(ConflictError, match="Retention.*pending"):
        store.ingest("a", [{"event_id": "same", "message": "replacement-token"}])
    assert store.analytics.execute(
        "SELECT message FROM events_all WHERE tenant='a' AND event_id='same'"
    ).fetchone()[0] == "original-token"
    with store.control(local=True) as db:
        assert db.execute("SELECT count(*) FROM retention_applied").fetchone()[0] == 0


def test_crash_after_physical_deletion_preserves_receipt_until_recovery(pending):
    store, _, now = pending

    def crash():
        raise RuntimeError("synthetic post-delete crash")

    with pytest.raises(RuntimeError, match="post-delete crash"):
        with store.flush_lock, store.segment_lock.write(), store.write_lock:
            store._apply_retention_segments_locked(after_delete=crash)
    assert store.analytics.execute("SELECT count(*) FROM events_all").fetchone()[0] == 0
    with store.control(local=True) as db:
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM retention_applied").fetchone()[0] == 0
    with pytest.raises(ConflictError, match="Retention.*pending"):
        store.ingest("a", [{"event_id": "same", "message": "replacement-token"}])
    assert store.flush() == 0
    with store.control(local=True) as db:
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 0
    assert store.ingest("a", [{"event_id": "same", "message": "replacement-token"}])["accepted"] == 1


def complete_held_intent(store):
    store.segments.save_policy("a", "main", {
        "hot_days": 1, "warm_days": 2, "cold_days": 3,
        "retention_days": 0, "hold": True, "version": 0,
    })
    assert store.flush() == 0


def replay_source(store, *, message=None, later_receipt=False):
    cursor = store.analytics.execute("SELECT * FROM events_all WHERE tenant='a' AND event_id='same'")
    row = dict(zip([col[0] for col in cursor.description], cursor.fetchone()))
    payload = {key: row[key] for key in (
        "event_id", "event_time", "source", "sourcetype", "host", "severity", "message"
    )}
    payload["raw"] = json.loads(row["raw"])
    payload["index"] = row["index_name"]
    if message is not None:
        payload["message"] = message
    with store.control(local=True) as db:
        db.execute("INSERT INTO queue(tenant,event_id,payload,received) VALUES(?,?,?,?)", (
            "a", "same", encode(payload), row["received"] + int(later_receipt),
        ))


def test_completed_local_hold_then_peer_receipt_retirement_rejects_new_body(pending):
    store, _, _ = pending
    complete_held_intent(store)
    with store.control(local=True) as db:
        db.execute("DELETE FROM receipts WHERE tenant='a' AND event_id='same'")
    with pytest.raises(ConflictError, match="retained"):
        store.ingest("a", [{"event_id": "same", "message": "replacement-token"}])
    with store.control(local=True) as db:
        assert db.execute("SELECT count(*) FROM queue").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 0


@pytest.mark.parametrize("later_receipt", [False, True])
def test_replicated_queue_body_or_receipt_collision_never_silently_acknowledged(pending, later_receipt):
    store, _, _ = pending
    complete_held_intent(store)
    replay_source(store, message="replacement-token", later_receipt=later_receipt)
    with pytest.raises(ConflictError, match="retained"):
        store.flush()
    with store.control(local=True) as db:
        assert db.execute("SELECT count(*) FROM queue").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM log_fts_inflight").fetchone()[0] == 1
    assert store.analytics.execute(
        "SELECT message FROM events_all WHERE tenant='a' AND event_id='same'"
    ).fetchone()[0] == "original-token"


def test_identical_queue_replay_after_seal_or_hot_commit_still_acknowledged(pending):
    store, _, _ = pending
    complete_held_intent(store)
    replay_source(store)
    assert store.flush() == 1
    with store.control(local=True) as db:
        assert db.execute("SELECT count(*) FROM queue").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM log_fts_inflight").fetchone()[0] == 0
    assert store.analytics.execute("SELECT count(*) FROM events_all").fetchone()[0] == 1


def test_new_batch_after_completed_history_uses_only_local_key_probes(pending):
    store, _, _ = pending
    complete_held_intent(store)
    analytics = store.analytics

    class NoSourceRead:
        def cursor(self):
            raise AssertionError("Ordinary admission must not query hot or sealed originals")

    store.analytics = NoSourceRead()
    try:
        assert store.ingest("a", [{"event_id": f"new-{n}"} for n in range(1000)])["accepted"] == 1000
    finally:
        store.analytics = analytics
    with store.control(local=True) as db:
        for table in ("log_retained_identities", "log_retention_pending_keys"):
            plan = " ".join(row[3] for row in db.execute(
                "EXPLAIN QUERY PLAN SELECT 1 FROM json_each(?) i CROSS JOIN " + table + " k WHERE k.tenant=? AND k.event_id=i.value LIMIT 1",
                ('["new-id"]', "a"),
            ))
            assert "SEARCH k USING PRIMARY KEY" in plan
            assert "SCAN k" not in plan
    assert store.flush() == 1000


def test_legacy_catalog_reconciliation_streams_once_and_survives_restart(pending):
    store, _, _ = pending
    complete_held_intent(store)
    store.segments.save_policy("a", "main", {
        "hot_days": 1, "warm_days": 2, "cold_days": 3,
        "retention_days": 0, "hold": False, "version": 1,
    })
    with store.control(local=True) as db:
        db.execute("DELETE FROM log_retention_identity_state")
        db.execute("DELETE FROM log_retained_identities")
        db.execute("DELETE FROM receipts")
    path = store.path
    store.close()
    clone = Store(Settings(path, min_free_bytes=0))
    try:
        with clone.control(local=True) as db:
            assert db.execute("SELECT count(*) FROM log_retained_identities").fetchone()[0] == 1
        with pytest.raises(ConflictError, match="retained"):
            clone.ingest("a", [{"event_id": "same", "message": "replacement-token"}])
        analytics = clone.analytics

        class NoMigrationScan:
            def cursor(self):
                raise AssertionError("Completed identity migration must not rescan hot originals")

        clone.analytics = NoMigrationScan()
        try:
            clone._initialize_retention_identities()
        finally:
            clone.analytics = analytics
    finally:
        clone.close()


def test_failed_legacy_reconciliation_does_not_publish_completion_marker(pending):
    store, _, _ = pending
    complete_held_intent(store)
    with store.control(local=True) as db:
        db.execute("DELETE FROM log_retention_identity_state")
        db.execute("DELETE FROM log_retained_identities")
    analytics = store.analytics

    class FailedMigrationScan:
        def cursor(self):
            raise RuntimeError("synthetic migration I/O failure")

    store.analytics = FailedMigrationScan()
    try:
        with pytest.raises(RuntimeError, match="migration I/O failure"):
            store._initialize_retention_identities()
    finally:
        store.analytics = analytics
    with store.control(local=True) as db:
        assert db.execute("SELECT count(*) FROM log_retention_identity_state").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM log_retained_identities").fetchone()[0] == 0
    store._initialize_retention_identities()
    with store.control(local=True) as db:
        assert db.execute("SELECT count(*) FROM log_retained_identities").fetchone()[0] == 1


def test_legacy_reconciliation_disk_reserve_failure_keeps_source_and_marker_atomic(pending, monkeypatch):
    store, _, _ = pending
    complete_held_intent(store)
    with store.control(local=True) as db:
        db.execute("DELETE FROM log_retention_identity_state")
        db.execute("DELETE FROM log_retained_identities")
    reserve = store._retention_identity_reserve
    calls = 0

    def capacity_failure(extra=0):
        nonlocal calls
        calls += 1
        if calls == 3:
            raise CapacityError("synthetic migration disk reserve reached")
        return reserve(extra)

    with monkeypatch.context() as scoped:
        scoped.setattr(store, "_retention_identity_reserve", capacity_failure)
        with pytest.raises(CapacityError, match="disk reserve"):
            store._initialize_retention_identities()
    with store.control(local=True) as db:
        assert db.execute("SELECT count(*) FROM log_retention_identity_state").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM log_retained_identities").fetchone()[0] == 0
    assert store.analytics.execute("SELECT message FROM events_all").fetchone()[0] == "original-token"
    store._initialize_retention_identities()


def test_online_backup_restore_preserves_local_exception_catalog_and_triggers(pending, tmp_path):
    store, _, _ = pending
    complete_held_intent(store)
    with store.control(local=True) as db:
        db.execute("DELETE FROM receipts")
    destination, restored = tmp_path / "backup", tmp_path / "restored"
    backup.backup_online(store, destination)
    backup.restore(destination, restored)
    clone = Store(Settings(restored, min_free_bytes=0))
    try:
        with pytest.raises(ConflictError, match="retained"):
            clone.ingest("a", [{"event_id": "same", "message": "replacement-token"}])
        with clone.control(local=True) as db:
            db.execute("INSERT INTO retention_intents VALUES(?,?,?,?,?)", ("new-pending", "a", 1, '["new-id"]', time.time()))
            tag_intent(db, "new-pending")
        with pytest.raises(ConflictError, match="Retention.*pending"):
            clone.ingest("a", [{"event_id": "new-id"}])
    finally:
        clone.close()


def test_replica_catchup_and_local_applied_triggers_keep_pending_keys_exact(tmp_path):
    store = Store(Settings(tmp_path, min_free_bytes=0))
    try:
        replica = object.__new__(Replica)
        replica.store, replica.config, replica.key = store, {"cluster_id": "test"}, b"x" * 32
        with store.control(local=True) as db:
            db.execute("CREATE TABLE replica_state(singleton INTEGER PRIMARY KEY,cluster_id TEXT,sequence INTEGER,digest TEXT)")
            db.execute("INSERT INTO replica_state VALUES(1,'test',0,?)", ("0" * 64,))
        payload, _, _ = replica.pack(0, "0" * 64, [{
            "sql": "INSERT INTO retention_intents VALUES(?,?,?,?,?)",
            "params": ["replicated", "a", 1, '["pending"]', time.time()], "many": False,
        }])

        class OneFrame:
            def last_sequence(self, **_):
                return 1

            def get(self, sequence, **_):
                assert sequence == 1
                return payload

        replica.bridge = OneFrame()
        assert replica.catch_up() == 1
        with store.control(local=True) as db:
            tag_intent(db, "replicated")
        with pytest.raises(ConflictError, match="Retention.*pending"):
            store.ingest("a", [{"event_id": "pending"}])
        with store.control(local=True) as db:
            db.execute("INSERT INTO retention_applied VALUES(?,?)", ("replicated", time.time()))
            assert db.execute("SELECT count(*) FROM log_retention_pending_keys").fetchone()[0] == 0
            db.execute("DELETE FROM retention_applied WHERE id='replicated'")
            assert db.execute("SELECT event_id FROM log_retention_pending_keys").fetchone()[0] == "pending"
            db.execute("UPDATE retention_intents SET payload=? WHERE id='replicated'", ('["changed"]',))
            assert db.execute("SELECT event_id FROM log_retention_pending_keys").fetchone()[0] == "changed"
            db.execute("DELETE FROM retention_intents WHERE id='replicated'")
            assert db.execute("SELECT count(*) FROM log_retention_pending_keys").fetchone()[0] == 0
    finally:
        store.close()
