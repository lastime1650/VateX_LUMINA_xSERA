import json
import sqlite3
from contextlib import closing

import duckdb
import pytest

from sapientia.backup import backup, backup_encrypted, restore, restore_encrypted
from sapientia.locking import ProcessLock

PASSPHRASE = "Legacy-schema-backup-passphrase-2026"


def legacy_data(path):
    """An initialized old schema which a new Store would alter on opening."""
    path.mkdir()
    with closing(sqlite3.connect(path / "control.sqlite3")) as db, db:
        db.executescript("""
            CREATE TABLE schema_version(version INTEGER PRIMARY KEY);
            INSERT INTO schema_version VALUES(1);
            CREATE TABLE users(name TEXT PRIMARY KEY,password TEXT NOT NULL,role TEXT NOT NULL,tenant TEXT NOT NULL);
            INSERT INTO users VALUES('legacy-admin','preserved-password-hash','admin','default');
            CREATE TABLE rules(id TEXT PRIMARY KEY,tenant TEXT,name TEXT,query TEXT,interval INTEGER,lookback INTEGER,threshold INTEGER,enabled INTEGER,next_run REAL,last_end REAL,error TEXT);
            INSERT INTO rules VALUES('old-rule','default','Existing rule','{}',30,300,1,1,1700000000,1699999990,NULL);
            CREATE TABLE sessions(digest TEXT PRIMARY KEY,name TEXT NOT NULL,expires REAL NOT NULL,csrf TEXT NOT NULL);
            INSERT INTO sessions VALUES('old-session','legacy-admin',9999999999,'old-csrf');
            CREATE TABLE audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,at REAL,tenant TEXT,actor TEXT,action TEXT,detail TEXT,previous TEXT,digest TEXT);
        """)
    with closing(duckdb.connect(str(path / "events.duckdb"))) as db:
        db.execute("""
            CREATE TABLE events(tenant VARCHAR,event_id VARCHAR,event_time DOUBLE,received DOUBLE,source VARCHAR,sourcetype VARCHAR,host VARCHAR,severity VARCHAR,message VARCHAR,raw VARCHAR,PRIMARY KEY(tenant,event_id));
            INSERT INTO events VALUES('default','old-event',1700000000,1700000001,'sensor','syslog','server','high','Existing evidence','{"value":123}');
        """)
    (path / "secrets.key").write_bytes(bytes(range(32)))
    (path / "node-membership.json").write_text(
        json.dumps({"node_id": "existing-node", "credential": "preserved-node-key"}),
        encoding="utf-8",
    )
    return path


def logical_state(path):
    with closing(
        sqlite3.connect((path / "control.sqlite3").as_uri() + "?mode=ro", uri=True)
    ) as db:
        schema = db.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
        ).fetchall()
        tables = {
            name: db.execute("SELECT * FROM " + name).fetchall()
            for name in ("schema_version", "users", "rules", "sessions", "audit")
        }
        columns = {
            name: db.execute("PRAGMA table_info(" + name + ")").fetchall()
            for name in ("users", "rules")
        }
    with closing(duckdb.connect(str(path / "events.duckdb"), read_only=True)) as db:
        events_schema = db.execute("PRAGMA table_info('events')").fetchall()
        events = db.execute("SELECT * FROM events").fetchall()
    return {
        "schema": schema,
        "tables": tables,
        "columns": columns,
        "events_schema": events_schema,
        "events": events,
        "secret": (path / "secrets.key").read_bytes(),
        "membership": (path / "node-membership.json").read_bytes(),
    }


@pytest.mark.parametrize("encrypted", [False, True])
def test_old_schema_and_data_survive_backup_without_store_initialization(
    tmp_path, encrypted
):
    data = legacy_data(tmp_path / "legacy")
    before = logical_state(data)
    destination = tmp_path / ("snapshot.sba" if encrypted else "snapshot")
    restored = tmp_path / "restored"
    if encrypted:
        backup_encrypted(data, destination, PASSPHRASE)
        restore_encrypted(destination, restored, PASSPHRASE)
    else:
        backup(data, destination)
        assert logical_state(destination) == before
        restore(destination, restored)
    assert logical_state(data) == before
    expected = {**before, "tables": {**before["tables"], "sessions": []}}
    assert logical_state(restored) == expected
    # The original eleven-value rule INSERT remains valid after restoring.
    with closing(sqlite3.connect(restored / "control.sqlite3")) as db, db:
        db.execute(
            "INSERT INTO rules VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("new-rule", "default", "Rule", "{}", 30, 300, 1, 1, 0, 0, None),
        )


@pytest.mark.parametrize("encrypted", [False, True])
def test_offline_backup_rejects_held_process_lock_without_migration(
    tmp_path, encrypted
):
    data = legacy_data(tmp_path / "legacy")
    before = logical_state(data)
    destination = tmp_path / ("blocked.sba" if encrypted else "blocked")
    with (
        closing(ProcessLock(data / "service.lock")),
        pytest.raises(RuntimeError, match="already in use"),
    ):
        if encrypted:
            backup_encrypted(data, destination, PASSPHRASE)
        else:
            backup(data, destination)
    assert not destination.exists()
    assert logical_state(data) == before
    assert not list(data.glob(".encrypted-backup-*"))
