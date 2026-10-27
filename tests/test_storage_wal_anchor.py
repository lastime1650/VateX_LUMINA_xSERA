"""Idle WAL lifetime changes no fresh transaction, authority or backup semantics."""

import gc
import sqlite3
import subprocess
import sys
import threading
import weakref
from contextlib import closing, contextmanager
from pathlib import Path

import pytest

from sapientia import auth, backup, jobs, principal, source_registry
from sapientia.storage import Settings, Store


@pytest.fixture
def store(tmp_path):
    value=Store(Settings(tmp_path/"owned",min_free_bytes=0))
    try:
        yield value
    finally:
        value.close()


def test_anchor_never_services_queries_and_each_control_is_fresh_full_closed(store):
    anchor=store._wal_anchor;queries=[]
    anchor.set_trace_callback(queries.append)
    with store.control() as first:
        assert first is not anchor and first.execute("PRAGMA synchronous").fetchone()[0]==2
        first.execute("CREATE TEMP TABLE isolated(value INTEGER)")
    with store.control() as second:
        assert second is not first and second is not anchor
        assert second.execute("PRAGMA journal_mode").fetchone()[0]=="wal"
        with pytest.raises(sqlite3.OperationalError,match="no such table"):
            second.execute("SELECT * FROM isolated")
    for closed in (first,second):
        with pytest.raises(sqlite3.ProgrammingError,match="closed"):
            closed.execute("SELECT 1")
    assert not anchor.in_transaction and anchor.total_changes==0 and queries==[]


def test_commit_exception_rollback_and_current_source_principal_are_fresh(store):
    auth.create_user(store,"wal-owner","Owned-WAL-fixture-password-2026","admin","wal-lab")
    who={"name":"wal-owner","tenant":"wal-lab","role":"admin","allowed_indexes":["*"]}
    source=source_registry.save(store,who,{"index":"public","product":"json","account":"wal-fixture","realm":"virtual-lab","credential_ref":"env:SAPIENTIA_CONNECTOR_WAL","version":0})
    with store.control() as db:
        db.execute("CREATE TABLE owned_marker(value INTEGER)")
        assert principal.current(db,who)==who
    with pytest.raises(RuntimeError,match="rollback"),store.control() as db:
        db.execute("INSERT INTO owned_marker VALUES(1)")
        raise RuntimeError("Owned rollback check")
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM owned_marker").fetchone()[0]==0
        db.execute("UPDATE users SET disabled=1 WHERE name='wal-owner'")
        db.execute("UPDATE source_registry SET state='revoked' WHERE id=?",(source["id"],))
    with store.control() as db:
        with pytest.raises(PermissionError):
            principal.current(db,who)
        assert db.execute("SELECT state FROM source_registry WHERE id=?",(source["id"],)).fetchone()[0]=="revoked"
    assert not store._wal_anchor.in_transaction and store._wal_anchor.total_changes==0


def test_idle_anchor_holds_no_snapshot_and_checkpoint_backup_include_new_commits(store,tmp_path):
    with store.control() as db:
        db.execute("CREATE TABLE owned_backup_marker(value TEXT)")
        db.execute("INSERT INTO owned_backup_marker VALUES('first')")
    with store.control() as db:
        db.execute("INSERT INTO owned_backup_marker VALUES('second')")
        assert db.execute("SELECT count(*) FROM owned_backup_marker").fetchone()[0]==2
    destination=tmp_path/"online-backup"
    result=backup.backup_online(store,destination)
    assert result["online"]
    with closing(sqlite3.connect(destination/"control.sqlite3")) as db:
        assert db.execute("SELECT value FROM owned_backup_marker ORDER BY rowid").fetchall()==[("first",),("second",)]
    with store.control() as db:
        assert db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0]==0
    assert not store._wal_anchor.in_transaction


def test_cross_thread_close_releases_anchor_and_handles_before_reopen(store):
    anchor=store._wal_anchor;errors=[]

    def close():
        try:store.close()
        except Exception as exc:errors.append(exc)  # noqa: BLE001 -- Re-assert every background close failure on the test thread.

    thread=threading.Thread(target=close);thread.start();thread.join(timeout=10)
    assert not thread.is_alive() and errors==[] and store.closed and not store._wal_anchor_finalizer.alive
    with pytest.raises(sqlite3.ProgrammingError,match="closed"):
        anchor.execute("SELECT 1")
    with closing(sqlite3.connect(store.operational)) as db:
        assert db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0]==0
    renamed=store.operational.with_suffix(".owned-closed")
    assert renamed.resolve().is_relative_to(store.path)
    store.operational.rename(renamed);renamed.rename(store.operational)
    reopened=Store(Settings(store.path,min_free_bytes=0));reopened.close()


def test_replica_routing_stays_separate_from_local_anchor(store):
    class Replica:
        called=0
        @contextmanager
        def control(self):
            self.called+=1
            with closing(sqlite3.connect(":memory:")) as db:
                yield db
        def close(self):pass
    replica=Replica();store.replica=replica
    with store.control() as remote:
        assert remote.execute("PRAGMA database_list").fetchone()[2]==""
    with store.control(local=True) as local:
        assert Path(local.execute("PRAGMA database_list").fetchone()[2])==store.operational
    assert replica.called==1 and not store._wal_anchor.in_transaction


def test_late_constructor_failure_closes_anchor_and_process_resources(tmp_path,monkeypatch):
    captured=[];open_anchor=Store._open_wal_anchor

    def opened(store):
        open_anchor(store);captured.append(store._wal_anchor)

    def fail(_store):raise RuntimeError("Owned late initialization failure")

    with monkeypatch.context() as patch:
        patch.setattr(Store,"_open_wal_anchor",opened);patch.setattr(jobs,"initialize",fail)
        with pytest.raises(RuntimeError,match="late initialization"):
            Store(Settings(tmp_path/"failed",min_free_bytes=0))
    assert len(captured)==1
    with pytest.raises(sqlite3.ProgrammingError,match="closed"):
        captured[0].execute("SELECT 1")
    reopened=Store(Settings(tmp_path/"failed",min_free_bytes=0));reopened.close()


def test_anchor_attach_failure_closes_partial_handle(tmp_path,monkeypatch):
    captured=[];connect=sqlite3.connect
    class BrokenAnchor(sqlite3.Connection):
        closed=False
        def execute(self,sql,*args,**kwargs):
            if sql.startswith("SELECT name FROM sqlite_master"):
                raise RuntimeError("Owned anchor attachment failure")
            return super().execute(sql,*args,**kwargs)
        def close(self):
            self.closed=True;return super().close()
    def broken(*args,**kwargs):
        if kwargs.get("check_same_thread") is False:
            kwargs["factory"]=BrokenAnchor
            value=connect(*args,**kwargs);captured.append(value);return value
        return connect(*args,**kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(sqlite3,"connect",broken)
        with pytest.raises(RuntimeError,match="anchor attachment"):
            Store(Settings(tmp_path/"failed-anchor",min_free_bytes=0))
    assert len(captured)==1 and captured[0].closed
    reopened=Store(Settings(tmp_path/"failed-anchor",min_free_bytes=0));reopened.close()


def test_gc_finalizer_captures_only_anchor_not_store(tmp_path):
    value=Store(Settings(tmp_path/"abandoned",min_free_bytes=0))
    anchor=value._wal_anchor;reference=weakref.ref(value);finalizer=value._wal_anchor_finalizer
    del value
    for _ in range(3):gc.collect()
    assert reference() is None and not finalizer.alive
    with pytest.raises(sqlite3.ProgrammingError,match="closed"):
        anchor.execute("SELECT 1")


def test_abrupt_process_crash_recovers_full_commits_and_reopens(tmp_path):
    path=tmp_path/"child-owned"
    code="""
import os,sys
from pathlib import Path
from sapientia.storage import Store,Settings
store=Store(Settings(Path(sys.argv[1]),min_free_bytes=0))
assert 'torch' not in sys.modules
with store.control() as db:db.execute('CREATE TABLE owned_crash(value INTEGER)')
for value in range(25):
 with store.control() as db:db.execute('INSERT INTO owned_crash VALUES(?)',(value,))
assert not store._wal_anchor.in_transaction and store._wal_anchor.total_changes==0
os._exit(71)
"""
    result=subprocess.run([sys.executable,"-c",code,str(path)],cwd=Path(__file__).parents[1],check=False,timeout=60,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
    assert result.returncode==71
    value=Store(Settings(path,min_free_bytes=0))
    try:
        with value.control() as db:
            assert db.execute("SELECT count(*) FROM owned_crash").fetchone()[0]==25
            assert db.execute("PRAGMA integrity_check").fetchone()[0]=="ok"
    finally:value.close()
