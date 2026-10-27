"""Indexed-ACK-transaction projections/outbox for registered source evidence."""

import json

from . import migrations, security_schema
from .storage import encode


def initialize(store):
    migrations.apply_store(store, "projections", [
        "CREATE TABLE IF NOT EXISTS event_projections(seq INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT NOT NULL,event_id TEXT NOT NULL,index_name TEXT NOT NULL,source_id TEXT NOT NULL,event_time REAL NOT NULL,received REAL NOT NULL,receipt_digest TEXT NOT NULL,parser_digest TEXT NOT NULL,projection TEXT NOT NULL,UNIQUE(tenant,event_id,parser_digest))",
        "CREATE INDEX IF NOT EXISTS event_projection_scope ON event_projections(tenant,source_id,event_time,seq)"])


def journal_indexed(store, db, rows):
    if not db.execute("SELECT 1 FROM source_event_receipts LIMIT 1").fetchone():
        return
    for row in rows:
        proof = db.execute("SELECT * FROM source_event_receipts WHERE tenant=? AND event_id=?", (row["tenant"], row["event_id"])).fetchone()
        if not proof or not proof["source_definition"]:
            continue
        original = db.execute("SELECT digest,received FROM receipts WHERE tenant=? AND event_id=?", (row["tenant"], row["event_id"])).fetchone()
        if not original or original["digest"] != proof["receipt_digest"] or original["received"] != row["received"]:
            raise ValueError("Projection admission proof changed")
        event = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
        authority = json.loads(proof["source_definition"])
        projection = security_schema.project(event, authority)
        db.execute("INSERT OR IGNORE INTO event_projections(tenant,event_id,index_name,source_id,event_time,received,receipt_digest,parser_digest,projection) VALUES(?,?,?,?,?,?,?,?,?)",
                   (row["tenant"], row["event_id"], event["index"], proof["source_id"], event["event_time"], row["received"], proof["receipt_digest"], security_schema.PARSER_DIGEST, encode(projection)))


def retire(db, tenant, identifiers, cutoff):
    """Retire derivatives only after their original receipt, in its transaction.

    Held identities are excluded by Store. A queued or newly admitted incarnation
    retains its receipt, so crash recovery cannot purge its projection/proof.
    """
    for table in ("event_projections", "source_event_receipts"):
        db.execute(
            "DELETE FROM " + table + " WHERE tenant=? AND received<? "
            "AND event_id IN (SELECT value FROM json_each(?)) "
            "AND NOT EXISTS(SELECT 1 FROM receipts r WHERE r.tenant=" + table + ".tenant AND r.event_id=" + table + ".event_id) "
            "AND NOT EXISTS(SELECT 1 FROM queue q WHERE q.tenant=" + table + ".tenant AND q.event_id=" + table + ".event_id)",
            (tenant, cutoff, encode(identifiers)),
        )
