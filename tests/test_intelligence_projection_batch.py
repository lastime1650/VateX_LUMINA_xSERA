"""Publication batches fresh source reads with exact singleton semantics."""
import pytest

from sapientia import evidence_scope, intelligence
from tests.test_backend_upgrade import actor
from tests.test_backend_upgrade import lab as _lab
from tests.test_intelligence import seed

lab = _lab


def test_batch_equals_singletons_and_reduces_queries_without_authority_reuse(lab):
    source, events = seed(lab, stages=("A",) * 32)
    records = evidence_scope.originals(lab, actor(), [e["event_id"] for e in events])
    with lab.control() as db:
        expected = {key: intelligence._projection(db, "a", row) for key, row in records.items()}
        queries = []
        db.set_trace_callback(queries.append)
        assert intelligence._projections(db, "a", records) == expected
        db.set_trace_callback(None)
        assert len([q for q in queries if q.startswith("SELECT")]) == 2
        db.execute("UPDATE source_registry SET state='disabled' WHERE id=?", (source["id"],))
        with pytest.raises(PermissionError, match="revoked"):
            intelligence._projections(db, "a", records)


def test_missing_receipt_preserves_singleton_none_semantics(lab):
    _, events = seed(lab)
    records = evidence_scope.originals(lab, actor(), [e["event_id"] for e in events])
    with lab.control() as db:
        db.execute("DELETE FROM source_event_receipts WHERE event_id=?", (events[0]["event_id"],))
        assert intelligence._projections(db, "a", records) == {key: intelligence._projection(db, "a", row) for key, row in records.items()}
