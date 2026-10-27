"""Fresh ordered projection validation uses two reads per bounded TX chunk."""

import copy
import json
import sqlite3

import pytest

from sapientia import intelligence, security_schema
from sapientia import research_behavior as research
from tests.test_research_behavior import actor
from tests.test_research_behavior import seed as seed_store
from tests.test_research_behavior import store as _store_fixture

store = _store_fixture


@pytest.fixture
def db():
    value = sqlite3.connect(":memory:")
    value.row_factory = sqlite3.Row
    value.executescript("""
        CREATE TABLE source_registry(tenant TEXT,id TEXT,state TEXT,version INTEGER,
                                     PRIMARY KEY(tenant,id));
        CREATE TABLE source_event_receipts(tenant TEXT,event_id TEXT,source_id TEXT,
            source_version INTEGER,source_definition TEXT,PRIMARY KEY(tenant,event_id));
        CREATE TABLE markers(value TEXT);
    """)
    yield value
    value.close()


def seed(db, count):
    records = {}
    for i in range(2):
        db.execute("INSERT INTO source_registry VALUES('a',?,'active',1)", (f"source-{i}",))
    for i in range(count):
        eid = f"event-{i}"
        authority = {"id": f"source-{i%2}", "version": 1, "product": "json",
                     "realm": "virtual-lab", "account": "owned-fixture"}
        db.execute("INSERT INTO source_event_receipts VALUES('a',?,?,1,?)",
                   (eid, authority["id"], json.dumps(authority)))
        records[eid] = {"event_id": eid, "event_time": 1700000000+i, "index_name": "public",
                        "source": "fixture", "host": "host-"+str(i%3),
                        "raw": {"security": {"action": "network_connect", "src_ip": "10.0.0.1",
                                             "dest_ip": "192.0.2.1", "src_port": 12000+i,
                                             "dest_port": 443, "protocol": "tcp"}}}
    db.commit()
    db.execute("BEGIN IMMEDIATE")
    return records


def previous(db, tenant, records):
    return {eid: intelligence._projection(db, tenant, record) for eid, record in records.items()}


def batched(db, tenant, records, monkeypatch):
    project = intelligence._projections
    results, chunks = {}, []
    def capture(connection, current_tenant, chunk):
        assert connection is db and connection.in_transaction
        assert current_tenant == tenant and len(chunk) <= 32
        chunks.append(list(chunk))
        values = project(connection, current_tenant, chunk)
        results.update(values)
        return values
    with monkeypatch.context() as patch:
        patch.setattr(intelligence, "_projections", capture)
        assert research._validate_projections(db, tenant, records) is None
    return results, chunks


@pytest.mark.parametrize("count", [0, 1, 31, 32, 33, 64, 65])
def test_exact_projection_parity_and_same_transaction_chunk_boundaries(db, monkeypatch, count):
    records = seed(db, count)
    pristine = copy.deepcopy(records)
    expected = previous(db, "a", records)
    actual, chunks = batched(db, "a", records, monkeypatch)
    assert actual == expected and records == pristine
    assert chunks == [list(records)[offset:offset+32] for offset in range(0, count, 32)]
    assert db.in_transaction
    if count > 32:
        with pytest.raises(ValueError, match="At most 32"):
            intelligence._projections(db, "a", records)


def test_32_projection_validations_read_current_receipts_and_sources_in_two_queries(db, monkeypatch):
    records = seed(db, 32)
    statements = []
    db.set_trace_callback(statements.append)
    try:
        old = previous(db, "a", records)
        old_reads = [s for s in statements if s.startswith("SELECT")]
        statements.clear()
        new, _ = batched(db, "a", records, monkeypatch)
        new_reads = [s for s in statements if s.startswith("SELECT")]
    finally:
        db.set_trace_callback(None)
    assert old == new and len(old_reads) == 64 and len(new_reads) == 2
    assert "source_event_receipts" in new_reads[0] and "source_registry" in new_reads[1]


def test_manual_analysis_still_rejects_more_than_32_originals_before_opening_store():
    with pytest.raises(ValueError, match="1..32 original event IDs required"):
        research.analyze(None, actor(), {"event_ids": [f"event-{i}" for i in range(33)]})


def test_actual_32_original_analyze_uses_two_projection_reads_in_its_write_transaction(store, monkeypatch):
    seed_store(store)
    validate = research._validate_projections
    measurements = []
    def measured(db, tenant, records):
        assert db.in_transaction and len(records) == 32
        statements = []
        db.set_trace_callback(statements.append)
        try:
            previous(db, tenant, records)
            old_count = sum(s.startswith("SELECT") for s in statements)
            statements.clear()
            result = validate(db, tenant, records)
            new_count = sum(s.startswith("SELECT") for s in statements)
        finally:
            db.set_trace_callback(None)
        measurements.append((old_count, new_count))
        return result
    monkeypatch.setattr(research, "_validate_projections", measured)
    run = research.analyze(store, actor(), {"event_ids": [f"research-{i}" for i in range(32)]})
    assert measurements == [(64, 2)]
    assert len(run["event_ids"]) == 32 and run["mode"] == "shadow"
    assert research.get_run(store, actor(), run["id"]) == run


@pytest.mark.parametrize("change", ["revoked", "version", "missing_source", "malformed_authority",
                                  "missing_authority_field", "malformed_security", "malformed_ip"])
@pytest.mark.parametrize("bad_offset", [0, 32])
def test_same_first_projection_failure_and_order_across_chunks(db, monkeypatch, change, bad_offset):
    records = seed(db, 33)
    eid = f"event-{bad_offset}"
    if change in {"revoked", "version", "missing_source"}:
        authority = json.loads(db.execute("SELECT source_definition FROM source_event_receipts WHERE event_id=?", (eid,)).fetchone()[0])
        authority["id"] = "target-source"
        db.execute("INSERT INTO source_registry VALUES('a','target-source','active',1)")
        db.execute("UPDATE source_event_receipts SET source_id='target-source',source_definition=? WHERE event_id=?", (json.dumps(authority), eid))
    if change == "revoked":
        db.execute("UPDATE source_registry SET state='revoked' WHERE id='target-source'")
    elif change == "version":
        db.execute("UPDATE source_registry SET version=2 WHERE id='target-source'")
    elif change == "missing_source":
        db.execute("DELETE FROM source_registry WHERE id='target-source'")
    elif change == "malformed_authority":
        db.execute("UPDATE source_event_receipts SET source_definition='{' WHERE event_id=?", (eid,))
    elif change == "missing_authority_field":
        db.execute("UPDATE source_event_receipts SET source_definition='{}' WHERE event_id=?", (eid,))
    elif change == "malformed_security":
        records[eid]["raw"]["security"] = []
    else:
        records[eid]["raw"]["security"]["src_ip"] = "not-an-ip"
    real_project, visits = security_schema.project, []
    def observed(record, authority):
        visits.append(record["event_id"])
        return real_project(record, authority)
    monkeypatch.setattr(security_schema, "project", observed)
    with pytest.raises((PermissionError, ValueError, KeyError)) as old:
        previous(db, "a", records)
    old_order = list(visits)
    visits.clear()
    with pytest.raises(type(old.value)) as new:
        research._validate_projections(db, "a", records)
    assert str(new.value) == str(old.value) and visits == old_order


@pytest.mark.parametrize("change", ["missing_receipt", "empty_authority", "foreign_receipt"])
def test_absent_receipts_have_the_same_none_projection_semantics(db, monkeypatch, change):
    records = seed(db, 33)
    if change == "missing_receipt":
        db.execute("DELETE FROM source_event_receipts WHERE event_id='event-32'")
    elif change == "empty_authority":
        db.execute("UPDATE source_event_receipts SET source_definition='' WHERE event_id='event-32'")
    else:
        db.execute("UPDATE source_event_receipts SET tenant='foreign' WHERE event_id='event-32'")
    old = previous(db, "a", records)
    new, _ = batched(db, "a", records, monkeypatch)
    assert old == new and new["event-32"] is None
    # Live authenticated-source requirements are still checked separately by
    # the unchanged _verify_sources call before this validation-only helper.


def test_every_invocation_observes_same_transaction_source_and_receipt_changes(db, monkeypatch):
    records = seed(db, 33)
    first, _ = batched(db, "a", records, monkeypatch)
    authority = json.loads(db.execute("SELECT source_definition FROM source_event_receipts WHERE event_id='event-32'").fetchone()[0])
    authority["account"] = "changed-during-transaction"
    db.execute("UPDATE source_event_receipts SET source_definition=? WHERE event_id='event-32'", (json.dumps(authority),))
    second, _ = batched(db, "a", records, monkeypatch)
    assert second == previous(db, "a", records) and second != first
    db.execute("UPDATE source_registry SET state='revoked' WHERE id='source-0'")
    with pytest.raises(PermissionError, match="revoked"):
        research._validate_projections(db, "a", records)


def test_projection_error_still_rolls_back_caller_transaction(db):
    records = seed(db, 33)
    records["event-32"]["raw"]["security"] = []
    with pytest.raises(ValueError, match="Typed security object"), db:
        db.execute("INSERT INTO markers VALUES('must-roll-back')")
        research._validate_projections(db, "a", records)
    assert db.execute("SELECT count(*) FROM markers").fetchone()[0] == 0
    assert not db.in_transaction
