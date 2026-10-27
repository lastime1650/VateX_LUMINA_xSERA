import hashlib
import json
import time

import pytest

from sapientia.storage import ConflictError, Settings, Store, encode, normalize


def test_original_receipt_survives_derived_schema_upgrade(tmp_path):
    store = Store(Settings(tmp_path, min_free_bytes=0))
    try:
        original = {
            "event_id": "legacy-retry",
            "raw": {"user": "alice", "action": "login_failed"},
        }
        legacy = normalize(original)
        legacy["raw"] = original["raw"]
        legacy.pop("event_time")
        legacy.pop("index")
        digest = hashlib.sha256(encode(legacy).encode()).hexdigest()
        with store.control() as db:
            db.execute(
                "INSERT INTO receipts VALUES(?,?,?,?)",
                ("a", original["event_id"], digest, time.time()),
            )
        assert store.ingest("a", [original])["duplicate"] == 1
        store.ingest("a", [{**original, "event_id": "new-event"}])
        store.flush()
        row = store.search("a", {"query": "search event_id=new-event | table raw"})[
            "rows"
        ][0]
        raw = json.loads(row["raw"]) if isinstance(row["raw"], str) else row["raw"]
        assert raw["user"] == "alice" and raw["action"] == "login_failed"
        assert raw["security"]["user"] == "alice"
        assert (
            store.ingest("a", [{**original, "event_id": "new-event"}])["duplicate"] == 1
        )
        with pytest.raises(ConflictError):
            store.ingest(
                "a", [{**original, "event_id": "new-event", "raw": {"user": "bob"}}]
            )
    finally:
        store.close()


def test_size_and_depth_checks_include_enrichment():
    too_large = {"raw": {"user": "a" * 200, "padding": "x" * 65500}}
    with pytest.raises(ValueError, match="64 KiB"):
        normalize(too_large)
    nested = {}
    for _ in range(600):
        nested = {"a": nested}
    with pytest.raises(ValueError, match="nesting"):
        normalize({"raw": nested})
