"""Grouping quality is visible; strict association never drops an alert."""

import json
import time

import pytest

from sapientia import detection_automation, detections
from sapientia.storage import encode
from tests.test_detection_remediation import store, who


def _emit(store, *, grouping=None, guid=None, suffix="", freeze_first=False):
    definition = detections.validate({"name": "Explicit association", "entity_field": "host", "cooldown": 0,
        "steps": [{"filters": []}], **({"case_grouping": grouping} if grouping else {})})
    end = time.time()
    matches = [{"entity": "shared-host", "entity_field": "host", "event_ids": ["original-"+str(n)+suffix], "severity": "high", "mitre": [],
        "indexes": ["main"], "steps": [{"step": 1, "events": [{"event_id": "original-"+str(n)+suffix,
        "event_time": end-2+n, "host": "shared-host", **({"raw.xdr.data.process.guid": guid} if guid else {})}]}]} for n in range(2)]
    policy = {"id": "quality-policy"+suffix, "tenant": "a", "name": definition["name"], "version": 1}
    store.ingest("a", [{"event_id": match["event_ids"][0], "event_time": end-2+n, "host": "shared-host",
        "raw": {"xdr": {"data": {"process": {"guid": guid}}}} if guid else {}} for n, match in enumerate(matches)])
    store.flush()
    with store.control() as db:
        first = detections._emit_matches(db, store, policy, definition, matches[:1], end,
            mode="manual", scheduled_end=end, actor="owner", guard=who())
        assert first["emitted"] == 1
        if freeze_first:
            case_id = db.execute("SELECT incident_id FROM risk_contributions WHERE policy_id=?", (policy["id"],)).fetchone()[0]
            db.execute("INSERT INTO effect_receipts VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", ("frozen-quality", "a", case_id, 1,
                '["main"]', "owner", "peer", '{}', "approved", 2, end, end))
        second = detections._emit_matches(db, store, policy, definition, matches[1:], end,
            mode="manual", scheduled_end=end, actor="owner", guard=who())
        assert second["emitted"] == 1
        return [dict(row) for row in db.execute("SELECT * FROM risk_contributions WHERE policy_id=? ORDER BY id", (policy["id"],))]


def test_default_preserves_legacy_grouping_but_labels_hypothesis_truthfully(store):
    rows = _emit(store)
    assert len({row["incident_id"] for row in rows}) == 1
    for row in rows:
        quality = json.loads(row["evidence"])["case_quality"]
        assert quality["entity_time_hypothesis"] and not quality["causality_proven"]
        assert not quality["independent_sensor_attestation"] and not quality["response_authorized"]


def test_opt_in_exact_identity_separates_unproven_associations_without_losing_evidence(store):
    rows = _emit(store, grouping="require_exact_identity")
    assert len({row["incident_id"] for row in rows}) == 2
    assert all(json.loads(row["evidence"])["case_quality"]["require_exact_identity"] for row in rows)


def test_opt_in_exact_identity_still_groups_same_reported_process_and_keeps_causality_limit(store):
    rows = _emit(store, grouping="require_exact_identity", guid="reported-guid")
    assert len({row["incident_id"] for row in rows}) == 1
    assert all(json.loads(row["evidence"])["case_quality"]["reported_identity_only"] for row in rows)
    assert all(not json.loads(row["evidence"])["case_quality"]["causality_proven"] for row in rows)


def test_nearby_fallback_never_changes_frozen_approved_case_snapshot(store):
    rows = _emit(store, freeze_first=True)
    assert len({row["incident_id"] for row in rows}) == 2
    with store.control() as db:
        frozen = db.execute("SELECT incident_id,case_version,definition FROM effect_receipts WHERE id='frozen-quality'").fetchone()
        assert db.execute("SELECT version FROM incidents WHERE id=?", (frozen["incident_id"],)).fetchone()[0] == frozen["case_version"] == 1
        assert frozen["definition"] == '{}'


def test_case_adapter_retains_explicit_mode_and_legacy_shape():
    assert "case_grouping" not in detection_automation.validate_case_adapter({"entity_field": "host"})
    assert detection_automation.validate_case_adapter({"entity_field": "host", "case_grouping": "require_exact_identity"})["case_grouping"] == "require_exact_identity"
    for invalid in [None, True, [], {}, "auto_merge"]:
        with pytest.raises(ValueError):
            detections.validate({"name": "Bad grouping", "steps": [{"filters": []}], "case_grouping": invalid})
