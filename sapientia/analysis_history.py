"""Bounded full-result retention; cursors and compact receipts outlive result bodies.

Only these two server-owned tables are handled. Retention never touches original
events, findings, Cases, policies, source acknowledgements or schedule cursors.
An archived result is not returned as an empty successful analysis.
"""

import hashlib
import time

FULL_RESULTS = 1000
RECEIPTS = 100000
RECEIPT_SECONDS = 31 * 86400
TABLES = {"behavior_runs", "analysis_schedule_runs"}


def initialize(db):
    db.executescript("""
    CREATE TABLE IF NOT EXISTS analysis_history_receipts(
      tenant TEXT NOT NULL,kind TEXT NOT NULL,run_id TEXT NOT NULL,
      result_digest TEXT NOT NULL,original_created REAL NOT NULL,archived REAL NOT NULL,
      PRIMARY KEY(tenant,kind,run_id));
    CREATE INDEX IF NOT EXISTS analysis_history_receipt_age
      ON analysis_history_receipts(tenant,archived,kind,run_id);
    """)


def retain(db, tenant, table, *, now=None, maximum=None):
    """Compatibility hook: preserve full result bodies and receipts permanently."""
    if table not in TABLES:
        raise ValueError("Unsupported analysis history table")
    return {"archived_bodies": 0, "body_limit": None, "compact_receipt_limit": None,
            "compact_receipt_seconds": None, "permanent": True,
            "source_events_or_case_evidence_deleted": False}
