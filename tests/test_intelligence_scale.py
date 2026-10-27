import json
import sqlite3
import time
from contextlib import closing

import pytest

from sapientia import auth, detections
from sapientia.storage import CapacityError, Settings, Store

WHO = {
    "name": "analyst",
    "tenant": "soc",
    "role": "analyst",
    "allowed_indexes": ["main"],
}


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    auth.create_user(
        value, WHO["name"], "Scale-test-account-password-2026", "analyst", "soc"
    )
    yield value
    value.close()


def incident(db, identifier, at, status="new", tenant="soc", entity="host-a"):
    db.execute(
        "INSERT INTO incidents(id,tenant,entity,entity_field,name,created,updated,status) VALUES(?,?,?,'host','Scale incident',?,?,?)",
        (identifier, tenant, entity, at, at, status),
    )


def facts(
    db,
    incident_id,
    amount,
    at,
    prefix="fact",
    index="main",
    tenant="soc",
    entity="host-a",
    weight=1,
    same_event=False,
):
    evidence = json.dumps(
        {
            "event_ids": ["event"],
            "steps": [
                {
                    "step": "Match",
                    "events": [
                        {
                            "event_id": "event",
                            "event_time": at,
                            "index": index,
                            "host": entity,
                        }
                    ],
                }
            ],
        }
    )
    db.executemany(
        "INSERT INTO risk_contributions VALUES(?,?,?,?,?,'host',?,?,?,?)",
        [
            (
                f"{prefix}-{i:06d}",
                tenant,
                incident_id,
                "policy",
                entity,
                at,
                weight,
                evidence if same_event else evidence.replace('"event"', json.dumps(f"{prefix}-event-{i:06d}")),
                json.dumps([index]),
            )
            for i in range(amount)
        ],
    )


def test_large_old_tenant_history_does_not_disable_recent_incidents(store):
    now = time.time()
    with store.control() as db:
        incident(db, "old", now - 9 * 86400)
        facts(db, "old", 10010, now - 9 * 86400, prefix="old")
        incident(db, "recent", now)
        facts(db, "recent", 1, now, prefix="recent")
    listed = detections.incident_list(store, WHO)
    assert listed[0]["id"] == "recent" and listed[0]["contribution_count"] == 1
    assert detections.incident_detail(store, WHO, "recent")["total_count"] == 1
    old = detections.incident_detail(store, WHO, "old")
    assert (
        old["contribution_count"] == 10010
        and old["page_count"] == 3
        and old["next_cursor"]
    )


def test_exact_risk_aggregates_all_authorized_facts_beyond_10000(store):
    now = time.time()
    with store.control() as db:
        incident(db, "visible", now - 86400)
        facts(db, "visible", 10050, now - 86400, weight=1)
        incident(db, "hidden", now)
        facts(db, "hidden", 10, now, prefix="private", index="private", weight=100)
        incident(db, "false", now, status="false_positive")
        facts(db, "false", 10, now, prefix="false", weight=100)
        incident(db, "other", now, tenant="other")
        facts(db, "other", 10, now, prefix="other", tenant="other", weight=100)
    result = detections.entity_risk(store, WHO, now=now)
    assert len(result) == 1
    row = result[0]
    assert row["contribution_count"] == 10050
    assert row["uncapped_score"] == pytest.approx(5025)
    assert row["risk_score"] == 100
    assert len(row["contributions"]) == 20 and row["sample_truncated"]
    assert row["uncapped_score"] > sum(
        item["decayed_weight"] for item in row["contributions"]
    )


def test_incident_and_entity_pagination_is_complete_without_duplicates(store):
    now = time.time()
    with store.control() as db:
        incident(db, "paged", now)
        facts(db, "paged", 8, now)
    cursor, identifiers = None, []
    while True:
        page = detections.incident_detail(store, WHO, "paged", cursor=cursor, count=3)
        assert page["contribution_count"] == 8 and page["page_count"] <= 3
        identifiers.extend(item["id"] for item in page["contributions"])
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert len(identifiers) == len(set(identifiers)) == 8
    first = detections.entity_evidence(store, WHO, "host", "host-a", count=4, now=now)
    second = detections.entity_evidence(
        store, WHO, "host", "host-a", cursor=first["next_cursor"], count=4, now=now
    )
    assert first["total_count"] == second["total_count"] == 8
    assert not second["next_cursor"]
    assert not {r["id"] for r in first["contributions"]} & {
        r["id"] for r in second["contributions"]
    }


def test_mixed_index_incident_denies_every_page_and_feedback(store):
    now = time.time()
    with store.control() as db:
        incident(db, "mixed", now)
        facts(db, "mixed", 3, now)
        facts(db, "mixed", 1, now, prefix="private", index="private")
        db.execute(
            "INSERT INTO incident_feedback(tenant,incident_id,actor,at,status,note) VALUES('soc','mixed','analyst',?,'triage','private note')",
            (now,),
        )
    assert detections.incident_list(store, WHO) == []
    with pytest.raises(KeyError):
        detections.incident_detail(store, WHO, "mixed", count=1)
    assert (
        detections.incident_detail(store, {**WHO, "allowed_indexes": ["*"]}, "mixed")[
            "feedback"
        ][0]["note"]
        == "private note"
    )


def test_feedback_rechecks_private_contribution_added_before_write_lock(
    store, monkeypatch
):
    now = time.time()
    with store.control() as db:
        incident(db, "feedback-race", now)
        facts(db, "feedback-race", 1, now)
    real_lock = store.write_lock

    class ConcurrentDetection:
        def __enter__(self):
            real_lock.acquire()
            with store.control() as db:
                facts(db, "feedback-race", 1, now, prefix="racing", index="private")

        def __exit__(self, *args):
            real_lock.release()

    with monkeypatch.context() as patch:
        patch.setattr(store, "write_lock", ConcurrentDetection())
        with pytest.raises(KeyError, match="Incident not found"):
            detections.update_incident(
                store,
                WHO,
                "feedback-race",
                {"status": "triage", "owner": "analyst", "version": 1, "note": "race"},
            )
    with store.control() as db:
        assert db.execute(
            "SELECT status,version FROM incidents WHERE id='feedback-race'"
        ).fetchone()[:] == ("new", 1)
        assert db.execute("SELECT count(*) FROM incident_feedback").fetchone()[0] == 0
        assert (
            db.execute(
                "SELECT count(*) FROM audit WHERE action='incident.feedback'"
            ).fetchone()[0]
            == 0
        )


def test_feedback_authorization_holds_sqlite_writer_reservation(store, monkeypatch):
    now = time.time()
    with store.control() as db:
        incident(db, "reserved", now)
        facts(db, "reserved", 1, now)
    real_authorize = detections._authorize_incident

    def inspect_authorization(db, who, identifier):
        assert db.in_transaction
        with (
            closing(sqlite3.connect(store.operational, timeout=0)) as competing,
            pytest.raises(sqlite3.OperationalError, match="locked"),
        ):
            facts(competing, "reserved", 1, now, prefix="racing", index="private")
        return real_authorize(db, who, identifier)

    monkeypatch.setattr(detections, "_authorize_incident", inspect_authorization)
    detections.update_incident(
        store,
        WHO,
        "reserved",
        {"status": "triage", "owner": "analyst", "version": 1, "note": "safe"},
    )
    with store.control() as db:
        assert db.execute(
            "SELECT status,version FROM incidents WHERE id='reserved'"
        ).fetchone()[:] == ("triage", 2)
        assert db.execute("SELECT count(*) FROM incident_feedback").fetchone()[0] == 1


def test_large_sql_work_has_a_deadline_without_partial_results(store, monkeypatch):
    now = time.time()
    with store.control() as db:
        incident(db, "large", now)
        facts(db, "large", 10010, now)
    monkeypatch.setattr(detections, "QUERY_BUDGET_SECONDS", -1)
    with pytest.raises(CapacityError, match="deadline"):
        detections.entity_risk(store, WHO, now=now)


def test_feedback_preserves_all_history_after_record_count_limit_removal(store):
    now = time.time()
    with store.control() as db:
        incident(db, "feedback", now)
        facts(db, "feedback", 1, now)
        db.executemany(
            "INSERT INTO incident_feedback(tenant,incident_id,actor,at,status,note) VALUES('soc','feedback','analyst',?,'triage',?)",
            [(now + i, str(i)) for i in range(205)],
        )
    page = detections.incident_detail(store, WHO, "feedback")
    assert len(page["feedback"]) == 205
    assert [row["note"] for row in page["feedback"]] == [str(n) for n in reversed(range(205))]
    assert page["feedback_limit"] is None and not page["feedback_truncated"]


def test_oversized_evidence_fails_before_risk_persistence(store):
    now = time.time()
    data = {
        "name": "Bounded evidence",
        "entity_field": "raw.user",
        "window": 2000,
        "interval": 30,
        "steps": [
            {
                "name": f"Step {step}",
                "filters": [{"field": "raw.action", "op": "eq", "value": str(step)}],
                "min_count": 100,
            }
            for step in range(8)
        ],
    }
    store.ingest(
        "soc",
        [
            {
                "event_id": f"{number:06d}" + "e" * 250,
                "host": "h" * 256,
                "source": "s" * 256,
                "event_time": now - 1000 + number,
                "raw": {"user": "u" * 256, "action": str(number // 100)},
            }
            for number in range(800)
        ],
    )
    store.flush()
    definition = detections.validate(data)
    with pytest.raises(CapacityError, match="512 KiB"):
        detections.evaluate(store, "soc", definition, now, ["main"])
    policy_id = detections.save(store, WHO, data)
    with store.control() as db:
        scheduled_end = db.execute(
            "SELECT next_run FROM correlation_policies WHERE id=?", (policy_id,)
        ).fetchone()[0]
    # Setup can take over a second; run the policy at its actual saved schedule.
    assert detections.run_due(store, scheduled_end + 1) == 0
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0] == 0
        assert (
            "512 KiB"
            in db.execute(
                "SELECT error FROM correlation_policies WHERE id=?", (policy_id,)
            ).fetchone()[0]
        )


@pytest.mark.parametrize("cursor", ["../bad", "a" * 513, "WzEsICJ4IiwgM10"])
def test_malformed_cursors_are_rejected(store, cursor):
    now = time.time()
    with store.control() as db:
        incident(db, "cursor", now)
        facts(db, "cursor", 1, now)
    with pytest.raises(ValueError, match="cursor"):
        detections.incident_detail(store, WHO, "cursor", cursor=cursor)


def test_repeated_exact_event_set_does_not_inflate_risk_at_scale(store):
    now=time.time()
    with store.control() as db:
        incident(db,'repeated',now-86400)
        facts(db,'repeated',10050,now-86400,weight=1,same_event=True)
    row=detections.entity_risk(store,WHO,now=now)[0]
    assert row['contribution_count']==10050
    assert row['independent_event_sets']==1
    assert row['uncapped_score']==pytest.approx(0.5)
    assert row['risk_score']==pytest.approx(0.5)
