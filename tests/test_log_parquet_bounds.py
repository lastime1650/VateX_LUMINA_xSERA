"""Physical row-group limits and explicit, evidence-preserving legacy repair."""

import hashlib
import os
import sqlite3
import time
import types
import uuid
from contextlib import closing
from types import SimpleNamespace

import pytest

from sapientia import log_search, log_segments
from sapientia.log_segments import COLUMNS, SegmentError, file_hash, sql_path
from sapientia.storage import CapacityError, Settings, Store, encode


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path / "data", min_free_bytes=0))
    try:
        yield value
    finally:
        value.close()


def legacy_writer(self, sql, args, path):
    """Produce an actual pre-bound format file, without editing product code."""
    pending = path.parent / (".pending-" + uuid.uuid4().hex)
    try:
        self.store.analytics.execute(
            "COPY ("
            + sql
            + ") TO "
            + sql_path(pending)
            + " (FORMAT PARQUET, COMPRESSION ZSTD)",
            args,
        )
        log_segments._sync(pending)
        digest = file_hash(pending)
        os.replace(pending, path)
        log_segments._sync_directory(path.parent)
        return digest
    finally:
        pending.unlink(missing_ok=True)


def native_fixture(store, monkeypatch, scopes=1, legacy=True, count=17001):
    # Native fixture creation keeps failure-boundary tests small and quick.
    # The full receipt/FTS integration case below uses ordinary ingest instead.
    store.analytics.execute(
        "INSERT INTO events(tenant,event_id,event_time,received,source,sourcetype,host,severity,message,raw,index_name) "
        "SELECT 'a','native-'||i,1700000000,?,'fixture','json','host','info','wide fixture',"
        "json_object('sequence',i,'text',?,'nested',json_object('value',NULL)),"
        "'one'||CAST(i%? AS VARCHAR) FROM range(?) t(i)",
        [time.time(), "한글😀" * 100, scopes, count * scopes],
    )
    with monkeypatch.context() as patch:
        if legacy:
            patch.setattr(
                store.segments,
                "_copy_query",
                types.MethodType(legacy_writer, store.segments),
            )
        store.segments.seal(now=time.time() + 2 * 86400, batch=100000)
    return store.segments._rows()


def key_state(store):
    with store.control(local=True) as db:
        return {
            "manifests": [
                tuple(row)
                for row in db.execute(
                    "SELECT segment_id,rows,key_digest,format_version FROM log_sealed_key_manifests ORDER BY segment_id"
                )
            ],
            "generation": tuple(
                db.execute(
                    "SELECT value,content,purges FROM log_event_generation"
                ).fetchone()
            ),
        }


def full_digest(store):
    digest = hashlib.sha256()
    con = store.analytics.cursor()
    try:
        con.execute("SELECT " + COLUMNS + " FROM events_all ORDER BY tenant,event_id")
        while rows := con.fetchmany(250):
            for row in rows:
                digest.update((encode(list(row)) + "\n").encode())
    finally:
        con.close()
    return digest.hexdigest()


def receipt_digest(store):
    digest = hashlib.sha256()
    with store.control(local=True) as db:
        for row in db.execute("SELECT * FROM receipts ORDER BY tenant,event_id"):
            digest.update((encode(list(row)) + "\n").encode())
    return digest.hexdigest()


@pytest.mark.parametrize("count", [14335, 16383, 16384, 17001, 18433, 32769])
def test_shared_writer_physically_bounds_native_batch_edge_shapes(
    store, monkeypatch, count
):
    rows = native_fixture(store, monkeypatch, legacy=False, count=count)
    assert len(rows) == 1 and rows[0]["rows"] == count
    path = store.segments._path(rows[0]["path"])
    groups = store.analytics.execute(
        "SELECT row_group_id,max(row_group_num_rows) FROM parquet_metadata(?) GROUP BY row_group_id ORDER BY row_group_id",
        [str(path)],
    ).fetchall()
    assert len(groups) >= (count + 16383) // 16384
    assert sum(row[1] for row in groups) == count
    assert max(row[1] for row in groups) <= 16384
    assert store.segments.verify(deep=True)["valid"]


def test_explicit_repack_preserves_all_rows_receipts_holds_and_ready_fts(
    store, monkeypatch
):
    for offset in range(0, 17001, 1000):
        events = [
            {
                "event_id": f"event-{number:05}",
                "event_time": 1700000000.0,
                "index": "one",
                "source": "fixture",
                "host": "host",
                "severity": "high",
                "message": f"needle{number} 한글😀\n\t",
                "raw": {
                    "sequence": number,
                    "text": "한글😀" * 64,
                    "nested": [
                        None,
                        True,
                        False,
                        -0.0,
                        1e-7,
                        2**128 + 1,
                        10**200,
                        {"control": "\u0000\r\b"},
                    ],
                },
            }
            for number in range(offset, min(offset + 1000, 17001))
        ]
        store.ingest("a", events)
        store.flush()
    for _ in range(100):
        with store.control(local=True) as db:
            if not db.execute("SELECT pending_documents FROM log_fts_state").fetchone()[
                0
            ]:
                break
        log_search.drain(store, budget=3, max_documents=5000)
    with store.control(local=True) as db:
        assert (
            db.execute("SELECT pending_documents FROM log_fts_state").fetchone()[0] == 0
        )
        db.execute(
            "INSERT INTO log_evidence_holds VALUES(?,?,?,?,?,?,?)",
            (
                "a",
                "one",
                "event-00001",
                "case1",
                time.time(),
                None,
                "Synthetic preservation proof",
            ),
        )
    with monkeypatch.context() as patch:
        patch.setattr(
            store.segments,
            "_copy_query",
            types.MethodType(legacy_writer, store.segments),
        )
        store.segments.seal(now=time.time() + 2 * 86400, batch=100000)
    row = store.segments._rows()[0]
    old = store.segments._path(row["path"])
    assert store.segments._max_row_group_rows(old) == 17001
    original_hash = file_hash(old)
    # Neither a query nor startup silently rewrites a compatible old file.
    assert store.search(
        "a", {"language": "json", "query": {"fields": ["event_id"]}, "earliest": 0}
    )["returned"]
    store.close()
    store.__init__(store.settings)
    assert old.exists() and file_hash(old) == original_hash
    before, receipts, keys = full_digest(store), receipt_digest(store), key_state(store)
    fts = store.path / "log-search" / "terms.sqlite3"
    fts_hash = file_hash(fts)
    result = store.segments.repack(max_files=1)
    assert result["rewritten_segments"] == 1 and result["rewritten_events"] == 17001
    assert result["complete"] and result["remaining_segments"] == 0
    current = store.segments._rows()[0]
    assert (
        current["id"] == row["id"]
        and current["path"] != row["path"]
        and not old.exists()
    )
    assert (
        store.segments._max_row_group_rows(store.segments._path(current["path"]))
        <= 16384
    )
    assert full_digest(store) == before and receipt_digest(store) == receipts
    after = key_state(store)
    assert after["manifests"] == keys["manifests"]
    assert after["generation"] == (keys["generation"][0] + 1, *keys["generation"][1:])
    assert result["physical_generation"] == after["generation"][0]
    assert (
        result["content_generation"] == keys["generation"][1]
        and result["purge_generation"] == keys["generation"][2]
    )
    assert file_hash(fts) == fts_hash
    with closing(sqlite3.connect(fts)) as db:
        assert db.execute("SELECT count(*) FROM registry").fetchone()[0] == 17001
        assert db.execute(
            "SELECT event_id FROM terms WHERE terms MATCH ?", ("needle1",)
        ).fetchall() == [("event-00001",)]
    with store.control(local=True) as db:
        assert (
            db.execute("SELECT event_id FROM log_evidence_holds").fetchone()[0]
            == "event-00001"
        )
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 17001
    assert (
        store.ingest(
            "a",
            [
                {
                    "event_id": "event-00001",
                    "event_time": 1700000000.0,
                    "index": "one",
                    "source": "fixture",
                    "host": "host",
                    "severity": "high",
                    "message": "needle1 한글😀\n\t",
                    "raw": {
                        "sequence": 1,
                        "text": "한글😀" * 64,
                        "nested": [
                            None,
                            True,
                            False,
                            -0.0,
                            1e-7,
                            2**128 + 1,
                            10**200,
                            {"control": "\u0000\r\b"},
                        ],
                    },
                }
            ],
        )["duplicate"]
        == 1
    )
    unchanged = key_state(store)
    repeated = store.segments.repack()
    assert (
        repeated["rewritten_segments"]
        == repeated["rewritten_events"]
        == repeated["remaining_segments"]
        == 0
    )
    assert repeated["complete"] and key_state(store) == unchanged


@pytest.mark.parametrize("time_limited", [False, True])
def test_repack_stops_only_between_complete_files_and_can_resume(
    store, monkeypatch, time_limited
):
    native_fixture(store, monkeypatch, scopes=2)
    before, clock = full_digest(store), {"now": 0.0}
    if time_limited:
        original = store.segments._replace

        def delayed(*args, **kwargs):
            result = original(*args, **kwargs)
            clock["now"] = 2.0
            return result

        with monkeypatch.context() as patch:
            patch.setattr(log_segments.time, "monotonic", lambda: clock["now"])
            patch.setattr(store.segments, "_replace", delayed)
            result = store.segments.repack(max_seconds=1)
    else:
        result = store.segments.repack(max_files=1)
    assert result["rewritten_segments"] == result["remaining_segments"] == 1
    assert (
        not result["complete"]
        and result["budget_semantics"] == "cooperative_per_file_not_hard_io_deadline"
    )
    assert full_digest(store) == before and store.segments.verify(deep=True)["valid"]
    resumed = store.segments.repack()
    assert resumed["rewritten_segments"] == 1 and resumed["complete"]
    assert full_digest(store) == before


@pytest.mark.parametrize("after_write", [False, True])
def test_reserve_failure_never_publishes_replacement_or_removes_original(
    store, monkeypatch, after_write
):
    row = native_fixture(store, monkeypatch)[0]
    original = store.segments._path(row["path"])
    before, keys, digest = full_digest(store), key_state(store), file_hash(original)
    calls = []
    store.settings.min_free_bytes = 1024

    def space(_path):
        calls.append(1)
        # Repack preflight, shared-writer preflight, then real post-COPY check.
        return SimpleNamespace(free=10**12 if after_write and len(calls) <= 2 else 0)

    with monkeypatch.context() as patch:
        patch.setattr(log_segments.shutil, "disk_usage", space)
        with pytest.raises(CapacityError, match="Segment disk reserve"):
            store.segments.repack()
    assert len(calls) == (3 if after_write else 1)
    assert original.exists() and file_hash(original) == digest
    assert (
        store.segments._rows()[0] == row
        and full_digest(store) == before
        and key_state(store) == keys
    )
    assert list(store.segments.root.rglob("*.parquet")) == [original]
    assert not list(store.segments.root.rglob(".pending-*"))


def test_catalog_failure_rolls_back_keys_and_restart_discards_only_orphan(
    store, monkeypatch
):
    row = native_fixture(store, monkeypatch)[0]
    original = store.segments._path(row["path"])
    before, keys, digest = full_digest(store), key_state(store), file_hash(original)
    catalog = store.segments._catalog_keys

    def fail_after_keys(*args, **kwargs):
        catalog(*args, **kwargs)
        raise SegmentError("Synthetic catalog failure before commit")

    with monkeypatch.context() as patch:
        patch.setattr(store.segments, "_catalog_keys", fail_after_keys)
        with pytest.raises(SegmentError, match="before commit"):
            store.segments.repack()
    assert original.exists() and file_hash(original) == digest
    assert (
        key_state(store) == keys
        and store.segments._rows()[0] == row
        and full_digest(store) == before
    )
    assert len(list(store.segments.root.rglob("*.parquet"))) == 2
    store.close()
    store.__init__(store.settings)
    assert list(store.segments.root.rglob("*.parquet")) == [original]
    assert full_digest(store) == before and store.segments.verify(deep=True)["valid"]


@pytest.mark.parametrize(
    "arguments",
    [
        {"max_files": 0},
        {"max_files": 65},
        {"max_files": True},
        {"max_files": 1.5},
        {"max_seconds": 0},
        {"max_seconds": 0.001},
        {"max_seconds": 3601},
        {"max_seconds": float("inf")},
        {"max_seconds": float("nan")},
        {"max_seconds": True},
    ],
)
def test_repack_rejects_unbounded_or_ambiguous_budgets(store, arguments):
    with pytest.raises(ValueError, match="Repack"):
        store.segments.repack(**arguments)
