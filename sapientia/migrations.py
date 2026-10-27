"""Atomic additive migrations with immutable checksums and downgrade refusal."""

import hashlib
import json
import re
import sqlite3
import time
from pathlib import Path

SUPPORTED = {name: 1 for name in (
    "qualification", "source_registry", "effects", "projections", "source_blobs",
    "connectors", "identity_observations", "correlation_v2", "case_graph",
    "content_manifest", "action_runtime", "fleet", "audit_anchor")}
SUPPORTED["connectors"] = 2
SUPPORTED["correlation_v2"] = 2
SUPPORTED["record_governance"] = 2
SUPPORTED["detector_ops"] = 1
SUPPORTED.update({name: 1 for name in (
    "intelligence", "cpu_ml", "shadow_analysis", "intelligence_shadow", "case_intelligence", "behavior_features"
)})
SUPPORTED.update({"ml_datasets": 2, "intelligence_scale": 1, "cpu_sequence": 1,
                  "cpu_ml_lifecycle": 2, "intelligence_sequence": 1,
                  "case_intelligence": 2})
SUPPORTED.update({"analysis_engines": 2, "research_behavior": 2,
                  "sensor_adapters": 1, "online_analytics": 1,
                  "sequence_event_time": 2, "advanced_intelligence": 1})
SUPPORTED['sigma_imports'] = 2
SUPPORTED.update({name: 1 for name in (
    'research_horizon', 'research_evaluation', 'research_rebaseline',
    'ops_qualification', 'source_delivery_slo', 'signal_evidence',
)})
SUPPORTED['research_evaluation'] = 2
NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


def initialize(db):
    db.execute("CREATE TABLE IF NOT EXISTS xsera_schema_migrations(component TEXT NOT NULL,version INTEGER NOT NULL,checksum TEXT NOT NULL,applied REAL NOT NULL,PRIMARY KEY(component,version))")


def supported(db):
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='xsera_schema_migrations'").fetchone():
        return
    for row in db.execute("SELECT component,max(version) FROM xsera_schema_migrations GROUP BY component"):
        if row[0] not in SUPPORTED or row[1] > SUPPORTED[row[0]] or row[1] < 1:
            raise ValueError("Unsupported control schema: " + str(row[0]))


def guard_file(path):
    path = Path(path)
    if path.is_file():
        db = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
        try:
            supported(db)
        finally:
            db.close()


def apply(db, component, version, statements):
    if not NAME.fullmatch(component) or component not in SUPPORTED or type(version) is not int or not 1 <= version <= SUPPORTED[component]:
        raise ValueError("Unsupported migration")
    if not isinstance(statements, (list, tuple)) or not statements or any(not isinstance(s, str) or len(s) > 65536 for s in statements):
        raise ValueError("Bounded static migration statements required")
    checksum = hashlib.sha256(json.dumps(statements, separators=(",", ":")).encode()).hexdigest()
    db.execute("SAVEPOINT xsera_migration")
    try:
        initialize(db)
        supported(db)
        old = db.execute("SELECT checksum FROM xsera_schema_migrations WHERE component=? AND version=?", (component, version)).fetchone()
        if old:
            if old[0] != checksum:
                raise ValueError("Migration checksum changed; use a new version")
        else:
            current = db.execute("SELECT coalesce(max(version),0) FROM xsera_schema_migrations WHERE component=?", (component,)).fetchone()[0]
            if current != version - 1:
                raise ValueError("Migration sequence is incomplete")
            for statement in statements:
                db.execute(statement)
            db.execute("INSERT INTO xsera_schema_migrations VALUES(?,?,?,?)", (component, version, checksum, time.time()))
        db.execute("RELEASE xsera_migration")
    except BaseException:
        db.execute("ROLLBACK TO xsera_migration")
        db.execute("RELEASE xsera_migration")
        raise


def apply_store(store, component, statements, version=1):
    with store.control(local=True) as db:
        apply(db, component, version, statements)
