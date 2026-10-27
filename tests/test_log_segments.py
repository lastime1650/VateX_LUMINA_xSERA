import json
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from contextlib import contextmanager

import duckdb
import pytest

from sapientia.log_segments import SegmentError
from sapientia.storage import ConflictError, Settings, Store
from tests.capacity_helpers import purge,tag_intent


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path / "data", min_free_bytes=0))
    try:
        yield value
    finally:
        value.close()


def ingest(store, events):
    store.ingest("a", events)
    store.flush()


def count(store, allowed=None):
    return store.search("a", {"query": "* | stats count", "earliest": 0, "latest": time.time()+1}, allowed_indexes=allowed)["rows"][0]["count"]


def policy(store, index="one", hold=False):
    return store.segments.save_policy("a", index, {"hot_days": 1, "warm_days": 2, "cold_days": 3, "retention_days": 0, "hold": hold, "version": 0})


def test_real_utc_index_partitions_remove_hot_and_query_all(store):
    now = time.time()
    ingest(store, [{"event_id": "a", "index": "one", "event_time": now},
                   {"event_id": "b", "index": "two", "event_time": now},
                   {"event_id": "c", "index": "one", "event_time": now-86400}])
    result = store.segments.seal(now=now+2*86400)
    assert result["sealed_events"] == 3
    assert store.analytics.execute("SELECT count(*) FROM events").fetchone()[0] == 0
    rows = store.segments.status("a")["segments"]
    assert len(rows) == 3
    assert all((store.path / "log-segments" / row["path"]).is_file() for row in rows)
    assert all(row["tier"] == "warm" for row in rows)
    assert count(store) == 3
    assert count(store, ["one"]) == 2
    assert count(store, []) == 0
    json_query = {"language": "json", "query": {"group_by": ["index"]}, "earliest": 0, "latest": now+1}
    assert sorted(row["count"] for row in store.search("a", json_query)["rows"]) == [1, 2]
    assert store.segments.verify(deep=True)["segments"] == 3


def test_searchable_warm_cold_archive_lifecycle(store):
    now = time.time()
    ingest(store, [{"event_id": "a", "message": "needle"}])
    for age, expected in [(2, "warm"), (8, "cold"), (31, "archive")]:
        store.segments.maintenance(now=now+age*86400)
        assert store.segments.status("a")["segments"][0]["tier"] == expected
        assert store.search("a", {"query": 'needle | stats count'})["rows"] == [{"count": 1}]
        assert store.health("a")["indexed"] == 1
        assert store.analytics.execute("SELECT count(*) FROM events").fetchone()[0] == 0


def test_sealing_limits_only_policy_eligible_partitions(store):
    now = time.time()
    store.segments.save_policy("a", "long", {"hot_days": 10, "warm_days": 20, "cold_days": 30, "retention_days": 0, "hold": False, "version": 0})
    events = [{"event_id": f"long-{day}", "index": "long", "event_time": now-(100+day)*86400} for day in range(65)]
    events += [{"event_id": f"recent-{day}", "event_time": now-(200+day)*86400} for day in range(65)]
    events.append({"event_id": "eligible", "index": "short", "event_time": now})
    ingest(store, events)
    store.analytics.execute("UPDATE events SET received=? WHERE index_name IN ('long','short')", [now-2*86400])
    assert store.segments.seal(now=now)["sealed_events"] == 1
    assert store.analytics.execute("SELECT count(*) FROM events WHERE event_id='eligible'").fetchone()[0] == 0
    assert count(store) == 131


def test_published_manifest_crash_restart_reconciles_exactly_once(tmp_path):
    path = tmp_path / "crash"
    program = """import os,sys,time
from pathlib import Path
from sapientia.storage import Store,Settings
import shutil
owned=Path(sys.argv[1]).resolve()
original_usage=shutil.disk_usage
def fixture_usage(path):
    measured=original_usage(path)
    return type(measured)(10*1024**4,2*1024**4,8*1024**4) if Path(path).resolve().is_relative_to(owned) else measured
shutil.disk_usage=fixture_usage
s=Store(Settings(Path(sys.argv[1]),min_free_bytes=0))
s.ingest('a',[{'event_id':'one'}]);s.flush()
s.segments.seal(now=time.time()+2*86400,after_publish=lambda:os._exit(71))
"""
    result = subprocess.run([sys.executable, "-c", program, str(path)], capture_output=True, timeout=30, check=False)
    assert result.returncode == 71, result.stderr.decode()
    restored = Store(Settings(path, min_free_bytes=0))
    try:
        assert count(restored) == 1
        assert restored.analytics.execute("SELECT count(*) FROM events").fetchone()[0] == 0
        assert restored.segments.verify(deep=True)["valid"]
        assert restored.ingest("a", [{"event_id": "one"}])["duplicate"] == 1
    finally:
        restored.close()


def test_same_process_publication_failure_requires_reconciliation(store):
    ingest(store, [{"event_id": "one"}])
    def fail():
        raise RuntimeError("after publish")
    with pytest.raises(RuntimeError, match="after publish"):
        store.segments.seal(now=time.time()+2*86400, after_publish=fail)
    with pytest.raises(SegmentError, match="reconciliation"):
        count(store)
    store.segments.maintenance(now=time.time()+2*86400)
    assert count(store) == 1
    assert store.analytics.execute("SELECT count(*) FROM events").fetchone()[0] == 0


@pytest.mark.parametrize("missing", [False, True])
def test_corrupt_or_missing_archive_fails_closed_and_releases_init_lock(store, missing):
    ingest(store, [{"event_id": "one"}])
    store.segments.maintenance(now=time.time()+31*86400)
    row = store.segments.status("a")["segments"][0]
    path = store.path / "log-segments" / row["path"]
    original = path.read_bytes()
    if missing:
        path.unlink()
    else:
        path.write_bytes(b"X" + original[1:])
    with pytest.raises(SegmentError):
        count(store)
    store.close()
    with pytest.raises(SegmentError):
        Store(Settings(store.path, min_free_bytes=0))
    path.write_bytes(original)
    repaired = Store(Settings(store.path, min_free_bytes=0))
    try:
        assert count(repaired) == 1
    finally:
        repaired.close()


def test_per_index_retention_hold_and_partial_segment_rewrite(store):
    now = time.time()
    policy(store)
    ingest(store, [{"event_id": "old", "index": "one"}, {"event_id": "fresh", "index": "one"},
                   {"event_id": "other", "index": "two"}])
    store.analytics.execute("UPDATE events SET received=? WHERE event_id='old'", [now-5*86400])
    store.analytics.execute("UPDATE events SET received=? WHERE event_id IN ('fresh','other')", [now-2*86400])
    store.segments.seal(now=now)
    before = next(row for row in store.segments.status("a")["segments"] if row["index_name"] == "one")
    purges = store.purge_generation
    assert store.retain(now) == 0
    assert purge(store,now,event_ids=["old"]) == 1
    assert store.purge_generation > purges
    assert count(store) == 2
    after = next(row for row in store.segments.status("a")["segments"] if row["index_name"] == "one")
    assert after["sha256"] != before["sha256"] and after["rows"] == 1
    assert not (store.path / "log-segments" / before["path"]).exists()
    assert store.segments.verify(deep=True)["valid"]


def test_index_hold_and_case_event_hold_apply_across_tiers(store):
    now = time.time()
    policy(store, hold=True)
    policy(store, "two")
    ingest(store, [{"event_id": "held-index", "index": "one"},
                   {"event_id": "held-case", "index": "two"}, {"event_id": "expires", "index": "two"}])
    with store.control() as db:
        db.execute("INSERT INTO log_evidence_holds VALUES(?,?,?,?,?,?,?)", ("a", "two", "held-case", "case1", now, None, "legal hold"))
    store.segments.seal(now=now+2*86400)
    assert purge(store,now+5*86400) == 1
    assert count(store) == 2
    with store.control() as db:
        db.execute("DELETE FROM log_evidence_holds")
    assert purge(store,now+5*86400) == 1
    assert count(store) == 1


def test_hold_is_rechecked_when_replaying_an_existing_intent(store):
    now = time.time()
    ingest(store, [{"event_id": "protected"}])
    store.segments.seal(now=now+2*86400)
    with store.control() as db:
        db.execute("INSERT INTO retention_intents VALUES(?,?,?,?,?)", ("intent", "a", now+100, json.dumps(["protected"]), now))
        tag_intent(db,"intent")
        db.execute("INSERT INTO log_evidence_holds VALUES(?,?,?,?,?,?,?)", ("a", "main", "protected", "case1", now, None, "hold before replay"))
    store.flush()
    assert count(store) == 1
    assert store.purge_generation == 0


@pytest.mark.parametrize("batch_rows", [1000,5000])
def test_capacity_cleanup_traverses_more_than_ten_thousand_held_events(store, monkeypatch, batch_rows):
    now = time.time()
    events = [{"event_id": f"held-{number:05d}"} for number in range(10001)]
    events.append({"event_id": "z-expired"})
    for start in range(0, len(events), 1000):
        store.ingest("a", events[start:start+1000])
    store.flush(batch=20000)
    store.analytics.execute("UPDATE events SET received=?", [now-100*86400])
    with store.control() as db:
        db.executemany("INSERT INTO log_evidence_holds VALUES(?,?,?,?,?,?,?)", [
            ("a", "main", event["event_id"], f"case-{number//5000}", now, None, "retention hold")
            for number, event in enumerate(events[:-1])
        ])
    from sapientia import auth,pressure_retention,record_governance
    auth.create_user(store,"capacity-admin","Capacity-fixture-only-password-2026","admin","default")
    record_governance.configure(store,{"name":"capacity-admin","tenant":"default","role":"admin"},{"version":1,"cleanup_batch_rows":batch_rows,"min_free_percent":20})
    original_usage=shutil.disk_usage
    owned=store.path.resolve()
    def pressured(path):
        measured=original_usage(path)
        return type(measured)(10*1024**4,9*1024**4,1024**4) if Path(path).resolve().is_relative_to(owned) else measured
    from pathlib import Path
    with monkeypatch.context() as patch:
        patch.setattr(shutil,"disk_usage",pressured)
        first=pressure_retention.step(store)
        assert first["scanned"]==batch_rows and first["protected_scanned"]==batch_rows and first["deleted_rows"]==0
        with sqlite3.connect(store.operational) as db:
            saved=json.loads(db.execute("SELECT definition FROM record_capacity_cleanup_state").fetchone()[0])
            assert saved["after"]==first["after"] and saved["scanned"]==batch_rows
        for _ in range(12):
            last=pressure_retention.step(store)
            if last.get("deleted_rows")==1:
                break
        assert last["deleted_rows"]==1 and last["scanned"]==10002 and last["protected_scanned"]==10001
    assert count(store) == 10001
    assert store.analytics.execute("SELECT count(*) FROM events_all WHERE event_id='z-expired'").fetchone()[0] == 0


def test_late_legacy_expiry_is_cancelled_without_blocking_permanent_originals(store):
    now=time.time()
    ingest(store,[{"event_id":"permanent-original","message":"keep original"}])
    with store.control(local=True) as db:
        db.execute("INSERT INTO retention_intents VALUES(?,?,?,?,?)",("late-legacy","a",now+100,json.dumps(["permanent-original"]),now))
    assert store.flush()==0 and count(store)==1
    with store.control(local=True) as db:
        assert db.execute("SELECT reason FROM record_retention_cancellations WHERE id='late-legacy'").fetchone()[0]=="permanent recording enabled"
        assert db.execute("SELECT count(*) FROM receipts WHERE event_id='permanent-original'").fetchone()[0]==1
    assert store.ingest("a",[{"event_id":"permanent-original","message":"keep original"}])["duplicate"]==1


def test_logical_expiry_invalidates_derived_copies_before_physical_delete(store, monkeypatch):
    now = time.time()
    ingest(store, [{"event_id": "expires"}])
    store.analytics.execute("UPDATE events SET received=?", [now-100*86400])
    original = store._apply_retention_locked
    calls = 0
    def fail_after_plan(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("physical delete unavailable")
        return original(*args, **kwargs)
    previous = store.purge_generation
    monkeypatch.setattr(store, "_apply_retention_locked", fail_after_plan)
    with pytest.raises(RuntimeError, match="physical delete unavailable"):
        purge(store,now)
    assert store.purge_generation > previous
    assert store.analytics.execute("SELECT count(*) FROM events_all").fetchone()[0] == 1
    with store.control(local=True) as db:
        assert db.execute("SELECT count(*) FROM retention_intents i LEFT JOIN retention_applied a ON a.id=i.id WHERE a.id IS NULL").fetchone()[0] == 1
    monkeypatch.setattr(store, "_apply_retention_locked", original)
    assert purge(store,now) == 1
    assert count(store) == 0


@pytest.mark.parametrize("unavailable", [False, True])
def test_retention_replay_quorum_fences_fresh_holds_and_fails_closed(store, unavailable):
    now = time.time()
    ingest(store, [{"event_id": "protected"}])
    with store.control(local=True) as db:
        db.execute("INSERT INTO retention_intents VALUES(?,?,?,?,?)", ("intent", "a", now+100, json.dumps(["protected"]), now))
        tag_intent(db,"intent")
    class Fence:
        def barrier(self):
            assert store.write_lock._is_owned()
            if unavailable:
                raise RuntimeError("quorum unavailable")
            with store.control(local=True) as db:
                db.execute("INSERT INTO log_evidence_holds VALUES(?,?,?,?,?,?,?)", ("a", "main", "protected", "case", now, None, "caught-up hold"))
    store.replica = Fence()
    try:
        if unavailable:
            with pytest.raises(RuntimeError, match="quorum unavailable"), store.flush_lock:
                store._apply_retention_locked(now=now)
        else:
            with store.flush_lock:
                assert store._apply_retention_locked(now=now) == 0
    finally:
        store.replica = None
    if unavailable:
        assert store.analytics.execute("SELECT count(*) FROM events_all").fetchone()[0] == 1
        with pytest.raises(ConflictError, match="Retention deletion is pending"):
            count(store)
    else:
        assert count(store) == 1
    with store.control(local=True) as db:
        assert db.execute("SELECT count(*) FROM retention_applied").fetchone()[0] == (0 if unavailable else 1)


def test_relocation_rebuilds_absolute_parquet_view_paths(store, tmp_path):
    ingest(store, [{"event_id": "one"}])
    store.segments.seal(now=time.time()+2*86400)
    store.close()
    moved = tmp_path / "moved"
    shutil.copytree(store.path, moved)
    relocated = Store(Settings(moved, min_free_bytes=0))
    try:
        assert count(relocated) == 1
        assert all(not item["path"].startswith(str(store.path)) for item in relocated.segments.backup_files())
    finally:
        relocated.close()


def test_external_access_remains_disabled_with_only_managed_paths(store, tmp_path):
    ingest(store, [{"event_id": "one"}])
    store.segments.seal(now=time.time()+2*86400)
    assert store.analytics.execute("SELECT current_setting('enable_external_access')").fetchone()[0] is False
    forbidden = tmp_path / "outside.parquet"
    with pytest.raises(duckdb.Error, match="disabled|Permission|not allowed"):
        store.analytics.execute("COPY (SELECT 1) TO ? (FORMAT PARQUET)", [str(forbidden)])
    assert not forbidden.exists()
    assert store.segments.verify(deep=True)["valid"]


def test_corrupted_manifest_path_is_not_interpreted_as_sql_or_filesystem(store):
    ingest(store, [{"event_id": "one"}])
    store.segments.seal(now=time.time()+2*86400)
    with store.control(local=True) as db:
        db.execute("UPDATE log_segments SET path=?", ("../outside.parquet'); SELECT 1 --",))
    with pytest.raises(SegmentError, match="Invalid managed segment path"):
        count(store)


def test_old_queue_replay_does_not_recreate_sealed_hot_copies(store):
    store.ingest("a", [{"event_id": "one", "message": "stable"}])
    with store.control() as db:
        payload, received = db.execute("SELECT payload,received FROM queue").fetchone()
    store.flush()
    store.segments.seal(now=time.time()+2*86400)
    with store.control(local=True) as db:
        db.execute("INSERT INTO queue(tenant,event_id,payload,received) VALUES(?,?,?,?)", ("a", "one", payload, received))
    store.flush()
    assert count(store) == 1
    assert store.analytics.execute("SELECT count(*) FROM events").fetchone()[0] == 0


def test_sealed_key_filter_keeps_same_event_id_in_another_tenant(store):
    ingest(store, [{"event_id": "shared", "message": "tenant a"}])
    store.segments.seal(now=time.time()+2*86400)
    store.ingest("b", [{"event_id": "shared", "message": "tenant b"}])
    assert store.flush() == 1
    rows = store.analytics_query("SELECT tenant,event_id,message FROM events_all ORDER BY tenant", [])["rows"]
    assert rows == [{"tenant": "a", "event_id": "shared", "message": "tenant a"},
                    {"tenant": "b", "event_id": "shared", "message": "tenant b"}]
    assert store.analytics.execute("SELECT tenant FROM events").fetchall() == [("b",)]


def test_sealed_filter_crash_after_hot_commit_replays_exactly_once(store):
    ingest(store, [{"event_id": "sealed"}])
    store.segments.seal(now=time.time()+2*86400)
    store.ingest("a", [{"event_id": "hot", "message": "committed before queue acknowledgement"}])
    def fail():
        raise RuntimeError("after hot commit")
    with pytest.raises(RuntimeError, match="after hot commit"):
        store.flush(after_commit=fail)
    store.close()
    restored = Store(Settings(store.path, min_free_bytes=0))
    try:
        assert restored.flush() == 1
        assert count(restored) == 2
        assert restored.analytics.execute("SELECT event_id FROM events").fetchall() == [("hot",)]
        assert restored.health("a")["pending"] == 0
    finally:
        restored.close()


def test_flush_rejects_corrupted_sealed_identity_source_and_preserves_queue(store):
    ingest(store, [{"event_id": "sealed"}])
    store.segments.seal(now=time.time()+2*86400)
    path = store.path / "log-segments" / store.segments.status("a")["segments"][0]["path"]
    value = path.read_bytes()
    path.write_bytes(b"X"+value[1:])
    store.ingest("a", [{"event_id": "pending"}])
    with pytest.raises(SegmentError, match="checksum"):
        store.flush()
    with store.control(local=True) as db:
        assert db.execute("SELECT event_id FROM queue").fetchall()[0][0] == "pending"
    assert store.analytics.execute("SELECT count(*) FROM events").fetchone()[0] == 0


def test_segment_reader_lease_blocks_file_movement(store):
    now = time.time()
    ingest(store, [{"event_id": "one"}])
    store.segments.seal(now=now+2*86400)
    started, finished = threading.Event(), threading.Event()
    def move():
        started.set()
        store.segments.maintenance(now=now+31*86400)
        finished.set()
    with store.segment_lock.read():
        thread = threading.Thread(target=move)
        thread.start()
        assert started.wait(2)
        assert not finished.wait(0.1)
        assert count(store) == 1
    thread.join(10)
    assert finished.is_set()
    assert store.segments.status("a")["segments"][0]["tier"] == "archive"


def test_writer_wait_and_hash_verification_share_query_deadline(store):
    entered, release = threading.Event(), threading.Event()
    def writer():
        with store.segment_lock.write():
            entered.set()
            release.wait(3)
    thread = threading.Thread(target=writer)
    thread.start()
    assert entered.wait(2)
    started = time.monotonic()
    try:
        with pytest.raises(RuntimeError, match="Segment read deadline"):
            store.analytics_query("SELECT 1 AS value", [], timeout=0.05)
        assert time.monotonic()-started < 1
    finally:
        release.set()
        thread.join(3)
    ingest(store, [{"event_id": "one"}])
    store.segments.seal(now=time.time()+2*86400)
    with pytest.raises(RuntimeError, match="Segment read deadline"):
        store.segments.verify(deep=True, deadline=time.monotonic()-0.1)


def test_ingestion_scope_rechecks_original_and_parser_routing_atomically(store):
    with pytest.raises(PermissionError):
        store.ingest("a", [{"event_id": "no", "index": "one"}], allowed_indexes=["one"], authorization=lambda db: [])
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 0
    assert store.ingest("a", [{"event_id": "yes", "index": "one"}], allowed_indexes=["one"], authorization=lambda db: ["one"])["accepted"] == 1
    store.flush()
    assert count(store, ["one"]) == 1


@pytest.mark.parametrize("index,data", [("../escape", {}), ("*", {}), ("one", {"hot_days": 2, "warm_days": 1, "cold_days": 3, "retention_days": 4, "hold": False, "version": 0})])
def test_lifecycle_configuration_fails_closed(store, index, data):
    with pytest.raises(ValueError):
        store.segments.save_policy("a", index, data)


def test_sealed_identity_catalog_uses_exact_pk_probes(store, monkeypatch):
    ingest(store, [{"event_id": "shared"}, {"event_id": "other"}])
    store.segments.seal(now=time.time()+2*86400)
    observed, original = [], store.control
    @contextmanager
    def traced(*args, **kwargs):
        with original(*args, **kwargs) as db:
            db.set_trace_callback(observed.append)
            yield db
    monkeypatch.setattr(store, "control", traced)
    found = store.segments.sealed_keys([("a", "shared"), ("b", "shared"), ("a", "missing")])
    assert set(found) == {("a", "shared")}
    statement = next(sql for sql in observed if sql.startswith("WITH wanted"))
    with original(local=True) as db:
        plan = [row[3] for row in db.execute("EXPLAIN QUERY PLAN " + statement)]
    assert any("SEARCH k USING PRIMARY KEY (tenant=? AND event_id=?)" in detail for detail in plan)
    assert not any("SCAN k" in detail for detail in plan)


def test_union_all_is_published_only_after_identity_reconciliation(store):
    ingest(store, [{"event_id": "sealed", "index": "one"}])
    store.segments.seal(now=time.time()+2*86400)
    ingest(store, [{"event_id": "hot", "index": "two"}])
    definition = store.analytics.execute("SELECT sql FROM duckdb_views() WHERE view_name='events_all'").fetchone()[0]
    assert "UNION ALL" in definition and "row_number" not in definition.lower()
    plan = store.analytics.execute("EXPLAIN SELECT count(*) FROM events_all WHERE index_name='one'").fetchall()
    assert "WINDOW" not in str(plan)
    assert count(store) == 2
    assert count(store, ["one"]) == 1
    assert store.segments.verify(deep=True)["valid"]


def test_existing_segment_keys_migrate_once_without_restart_rewrites(store):
    ingest(store, [{"event_id": "one"}, {"event_id": "two"}])
    store.segments.seal(now=time.time()+2*86400)
    with store.control(local=True) as db:
        db.execute("DELETE FROM log_sealed_key_state")
        db.execute("DELETE FROM log_sealed_keys")
        db.execute("DELETE FROM log_sealed_key_manifests")
    store.close()
    migrated = Store(Settings(store.path, min_free_bytes=0))
    try:
        assert count(migrated) == 2
        with migrated.control(local=True) as db:
            assert db.execute("SELECT count(*) FROM log_sealed_keys").fetchone()[0] == 2
            db.execute("CREATE TRIGGER forbid_key_rewrite BEFORE INSERT ON log_sealed_keys BEGIN SELECT RAISE(ABORT,'unexpected identity rewrite'); END")
        migrated.close()
        restarted = Store(Settings(store.path, min_free_bytes=0))
        try:
            assert count(restarted) == 2
            assert restarted.segments.verify(deep=True)["valid"]
        finally:
            restarted.close()
    finally:
        migrated.close()


@pytest.mark.parametrize("change", ["missing", "received", "orphan"])
def test_identity_catalog_corruption_fails_deep_verify_and_startup(store, change):
    ingest(store, [{"event_id": "one"}])
    store.segments.seal(now=time.time()+2*86400)
    with store.control(local=True) as db:
        if change == "missing":
            db.execute("DELETE FROM log_sealed_keys")
        elif change == "received":
            db.execute("UPDATE log_sealed_keys SET received=received+1")
        else:
            db.execute("INSERT INTO log_sealed_keys VALUES('a','orphan','missing',0)")
    with pytest.raises(SegmentError, match="identity catalog"):
        store.segments.verify(deep=True)
    store.close()
    with pytest.raises(SegmentError, match="identity catalog"):
        Store(Settings(store.path, min_free_bytes=0))


def test_old_store_migration_rejects_duplicate_sealed_identity_atomically(store):
    ingest(store, [{"event_id": "one"}])
    store.segments.seal(now=time.time()+2*86400)
    row = store.segments.status("a")["segments"][0]
    relative, duplicate = store.segments._new_path("a", row["index_name"], row["day"], row["tier"])
    shutil.copyfile(store.path/"log-segments"/row["path"], duplicate)
    with store.control(local=True) as db:
        db.execute("INSERT INTO log_segments SELECT ?,tenant,index_name,day,tier,?,sha256,rows,min_time,max_time,min_received,max_received,state,created,updated,revision FROM log_segments WHERE id=?", (uuid.uuid4().hex, relative, row["id"]))
        db.execute("DELETE FROM log_sealed_key_state")
        db.execute("DELETE FROM log_sealed_keys")
        db.execute("DELETE FROM log_sealed_key_manifests")
    store.close()
    with pytest.raises(SegmentError, match="duplicated"):
        Store(Settings(store.path, min_free_bytes=0))
    with sqlite3.connect(store.operational) as db:
        assert db.execute("SELECT count(*) FROM log_sealed_keys").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM log_sealed_key_state").fetchone()[0] == 0


def test_expired_sealed_identity_can_be_reused_after_complete_purge(store):
    now = time.time()
    ingest(store, [{"event_id": "reuse", "message": "old"}])
    store.segments.seal(now=now+2*86400)
    assert purge(store,now+100*86400) == 1
    with store.control(local=True) as db:
        assert db.execute("SELECT count(*) FROM log_sealed_keys").fetchone()[0] == 0
    assert store.ingest("a", [{"event_id": "reuse", "message": "new"}])["accepted"] == 1
    store.flush()
    assert count(store) == 1
    assert store.search("a", {"query": "* | table message"})["rows"] == [{"message": "new"}]


def test_storage_moves_do_not_advance_content_generation(store):
    before = store.content_generation
    ingest(store, [{"event_id": "one"}])
    indexed = store.content_generation
    assert indexed > before
    for age in (2, 8, 31):
        store.segments.maintenance(now=time.time()+age*86400)
        assert store.content_generation == indexed
    assert purge(store,time.time()+100*86400) == 1
    assert store.content_generation > indexed


def test_health_reports_capacity_and_stale_metrics_explicitly(store):
    held = []
    try:
        for _ in range(store.settings.workers):
            assert store.query_slots.acquire(blocking=False)
            held.append(True)
        result = store.health("a")
        assert result["indexed"] is None
        assert result["analytics_status"]["state"] == "unavailable"
        assert "concurrency" in result["analytics_status"]["error"]
    finally:
        for _ in held:
            store.query_slots.release()
    assert store.health("a")["indexed"] == 0
    ingest(store, [{"event_id": "new"}])
    held = []
    try:
        for _ in range(store.settings.workers):
            assert store.query_slots.acquire(blocking=False)
            held.append(True)
        result = store.health("a")
        assert result["indexed"] == 0
        assert result["analytics_status"]["state"] == "stale"
        assert result["analytics_status"]["age_seconds"] is not None
        store.segments.bump(purge=True, content=False)
        result = store.health("a")
        assert result["indexed"] is None
        assert result["analytics_status"]["state"] == "unavailable"
    finally:
        for _ in held:
            store.query_slots.release()
    result = store.health("a")
    assert result["indexed"] == 1
    assert result["storage_bytes_scope"] == "root_regular_files_only"
    assert "storage_footprint" in result


def test_health_timeout_never_masks_segment_corruption(store):
    ingest(store, [{"event_id": "one"}])
    store.segments.seal(now=time.time()+2*86400)
    row = store.segments.status("a")["segments"][0]
    path = store.path/"log-segments"/row["path"]
    data = path.read_bytes()
    path.write_bytes(b"X"+data[1:])
    with pytest.raises(SegmentError, match="checksum"):
        store.health("a")


def test_retention_copy_failure_fences_search_until_physical_recovery(store, monkeypatch):
    now = time.time()
    policy(store)
    ingest(store, [{"event_id": "old", "index": "one"}, {"event_id": "fresh", "index": "one"}])
    store.analytics.execute("UPDATE events SET received=? WHERE event_id='old'", [now-5*86400])
    store.analytics.execute("UPDATE events SET received=? WHERE event_id='fresh'", [now-2*86400])
    store.segments.seal(now=now)
    original = store.segments._copy_query
    def unavailable(*args, **kwargs):
        raise OSError("synthetic storage failure before publication")
    monkeypatch.setattr(store.segments, "_copy_query", unavailable)
    with pytest.raises(OSError, match="before publication"):
        purge(store,now,event_ids=["old"])
    assert store.segments.verify(deep=True)["valid"]
    assert store.analytics.execute("SELECT count(*) FROM events_all").fetchone()[0] == 2
    with pytest.raises(ConflictError, match="Retention deletion is pending"):
        count(store)
    health = store.health("a")
    assert health["indexed"] is None
    assert health["analytics_status"]["state"] == "unavailable"
    assert "Retention deletion is pending" in health["analytics_status"]["error"]
    monkeypatch.setattr(store.segments, "_copy_query", original)
    assert store.flush() == 0
    assert count(store) == 1
    with store.control(local=True) as db:
        assert db.execute("SELECT event_id FROM log_sealed_keys").fetchone()[0] == "fresh"


def test_health_handles_real_duckdb_deadline_interrupt(store, monkeypatch):
    original, interrupted = store._analytics_query, []
    def slow_analytics(*args, **kwargs):
        try:
            return original("SELECT sum(sin(i)) FROM range(1000000000) AS t(i)", [], max_rows=1, timeout=0.01)
        except duckdb.InterruptException:
            interrupted.append(True)
            raise
    monkeypatch.setattr(store, "_analytics_query", slow_analytics)
    started = time.monotonic()
    result = store.health("a")
    assert interrupted
    assert time.monotonic()-started < 2
    assert result["indexed"] is None
    assert result["analytics_status"]["state"] == "unavailable"
    assert result["analytics_status"]["error_code"] == "analytics_deadline_exceeded"
    assert result["analytics_status"]["error"] == "Health analytics deadline exceeded"
