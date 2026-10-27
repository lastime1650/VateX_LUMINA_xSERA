"""Case grouping contracts authored from code semantics, independent of any benchmark corpus."""

import json
import time

import pytest

from sapientia import detections, runtime
from sapientia.storage import Settings, Store


@pytest.fixture
def lab(tmp_path):
    store = Store(Settings(tmp_path, min_free_bytes=0, query_timeout=15))
    runtime.initialize(store)
    with store.control() as db:
        db.execute(
            "INSERT INTO users(name,password,role,tenant) VALUES('episode_owner','synthetic-no-login','admin','a')"
        )
    yield store
    store.close()


def run(lab, rows, relation):
    end = time.time()
    actor = {
        "name": "episode_owner",
        "tenant": "a",
        "role": "admin",
        "allowed_indexes": ["*"],
    }
    events = []
    for identifier, action, guid, parent, delta in rows:
        events.append(
            {
                "event_id": identifier,
                "event_time": end + delta,
                "host": "same-endpoint",
                "raw": {
                    "action": action,
                    "xdr": {
                        "data": {
                            "session": {"id": "shared-login-not-campaign"},
                            "process": {"guid": guid, "parent": {"guid": parent}},
                        }
                    },
                },
            }
        )
    lab.ingest("a", events)
    lab.flush(100)
    identifier = detections.save(
        lab,
        actor,
        {
            "name": "explicit episode",
            "window": 60,
            "cooldown": 300,
            "relation": relation,
            "steps": [
                {"filters": [{"field": "raw.action", "op": "eq", "value": "start"}]},
                {
                    "filters": [{"field": "raw.action", "op": "eq", "value": "end"}],
                    "within_seconds": 30,
                },
            ],
        },
    )
    with lab.control() as db:
        db.execute(
            "UPDATE correlation_policies SET next_run=? WHERE id=?", (end, identifier)
        )
    assert detections.run_due(lab, end, budget=5) == 1
    with lab.control() as db:
        evidence = [
            json.loads(row[0])
            for row in db.execute("SELECT evidence FROM risk_contributions")
        ]
        cases = db.execute("SELECT count(*) FROM incidents").fetchone()[0]
    return evidence, cases


def test_same_logon_does_not_merge_independent_process_scoped_episodes(lab):
    evidence, cases = run(
        lab,
        [
            ("a-start", "start", "process-A", "shell", -20),
            ("a-end", "end", "process-A", "shell", -15),
            ("b-start", "start", "process-B", "shell", -10),
            ("b-end", "end", "process-B", "shell", -5),
        ],
        {"mode": "same_value", "field": "raw.xdr.data.process.guid"},
    )
    assert len(evidence) == 2 and cases == 2
    assert {tuple(row["episode"]["basis"]) for row in evidence} == {
        ("process", "process-A"),
        ("process", "process-B"),
    }


def test_explicit_common_parent_preserves_explainable_lineage_grouping(lab):
    evidence, cases = run(
        lab,
        [
            ("root", "start", "root-process", "shell", -20),
            ("child-a", "end", "child-A", "root-process", -10),
            ("child-b", "end", "child-B", "root-process", -5),
        ],
        {"mode": "parent_guid", "field": "raw.xdr.data.process.guid"},
    )
    assert len(evidence) == 2 and cases == 1
    assert all(
        row["episode"]["basis"] == ["process_lineage", "root-process"]
        for row in evidence
    )


def test_explicit_session_relation_keeps_its_declared_session_group(lab):
    evidence, cases = run(
        lab,
        [
            ("a-start", "start", "process-A", "shell", -20),
            ("a-end", "end", "process-A", "shell", -15),
            ("b-start", "start", "process-B", "shell", -10),
            ("b-end", "end", "process-B", "shell", -5),
        ],
        {"mode": "same_value", "field": "raw.xdr.data.session.id"},
    )
    assert len(evidence) == 2 and cases == 1
    assert all(
        row["episode"]["basis"] == ["session", "shared-login-not-campaign"]
        for row in evidence
    )
