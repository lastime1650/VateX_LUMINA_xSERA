"""Due-first candidate selection preserves valid-row archival semantics."""

import json
import random
import sqlite3

import pytest

from sapientia import research_behavior_lifecycle as lifecycle

# Independent pre-optimization query, retained for semantic differential tests.
_PREVIOUS_SQL = """
SELECT r.* FROM research_behavior_runs r
WHERE NOT EXISTS(SELECT 1 FROM research_behavior_archives a WHERE a.id=r.id)
AND NOT(r.mode='live' AND json_extract(r.body,'$.decision.anomaly')=1)
AND NOT EXISTS(SELECT 1 FROM policies p WHERE p.tenant=r.tenant AND p.hold=1)
AND NOT EXISTS(SELECT 1 FROM record_case_evidence_refs e WHERE e.tenant=r.tenant
    AND e.kind IN ('bookmark','contribution')
    AND e.event_id IN (SELECT value FROM json_each(r.body,'$.event_ids')))
AND (r.created<=? OR (SELECT count(*) FROM research_behavior_runs n
    WHERE n.tenant=r.tenant AND n.model_id IS r.model_id AND n.created>r.created
    AND NOT EXISTS(SELECT 1 FROM research_behavior_archives a WHERE a.id=n.id))>=?)
ORDER BY r.created LIMIT ?
"""


@pytest.fixture
def db():
    value = sqlite3.connect(":memory:")
    value.executescript("""
        CREATE TABLE research_behavior_runs(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,
            owner TEXT NOT NULL,indexes TEXT NOT NULL,model_id TEXT,created REAL NOT NULL,
            mode TEXT NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL);
        CREATE INDEX research_behavior_run_scope ON research_behavior_runs(tenant,created);
        CREATE TABLE research_behavior_archives(id TEXT PRIMARY KEY);
        CREATE TABLE policies(tenant TEXT PRIMARY KEY,hold INTEGER);
        CREATE TABLE record_case_evidence_refs(tenant TEXT NOT NULL,event_id TEXT NOT NULL,
            kind TEXT NOT NULL,record_id TEXT NOT NULL,
            PRIMARY KEY(tenant,event_id,kind,record_id)) WITHOUT ROWID;
        CREATE INDEX record_case_evidence_origin ON record_case_evidence_refs(kind,record_id);
    """)
    yield value
    value.close()


def add(db, identifier, created, *, tenant="a", model="model", mode="shadow", anomaly=False):
    body = json.dumps({"decision": {"anomaly": anomaly}, "event_ids": ["event-" + identifier]})
    db.execute("INSERT INTO research_behavior_runs VALUES(?,?,?,?,?,?,?,?,?)",
               (identifier, tenant, "owner", '["public"]', model, created, mode, body, "not-used-by-selection"))


def candidates(db, query=lifecycle._DUE_RUNS_SQL, *, cutoff=0, newer=128, limit=16):
    return [r[0] for r in db.execute(query, (cutoff, newer, limit))]


def parity(db, **options):
    actual = candidates(db, **options)
    assert actual == candidates(db, _PREVIOUS_SQL, **options)
    return actual


def test_age_cutoff_is_inclusive_and_future_run_is_not_due(db):
    add(db, "older", 999)
    add(db, "boundary", 1000)
    add(db, "newer", 1000.0001)
    assert parity(db, cutoff=1000) == ["older", "boundary"]


@pytest.mark.parametrize("model", [None, "model"])
def test_newer_128_boundary_keeps_tenant_model_is_strict_time_and_archive_rules(db, model):
    add(db, "target", 1000, model=model)
    for i in range(127):
        add(db, f"new-{i}", 1001+i, model=model)
    add(db, "same-time", 1000, model=model)
    add(db, "other-tenant", 2000, tenant="b", model=model)
    add(db, "other-model", 2001, model="null" if model is None else None)
    add(db, "archived-newer", 2002, model=model)
    db.execute("INSERT INTO research_behavior_archives VALUES('archived-newer')")
    assert parity(db) == []
    add(db, "new-128", 2003, model=model)
    # Equal timestamps do not count one another, but both have 128 newer runs.
    assert set(parity(db)) == {"target", "same-time"}


def test_all_protection_predicates_and_sql_null_semantics_are_preserved(db):
    rows = [
        ("live-anomaly", "a", "live", True),
        ("live-null", "a", "live", None),
        ("shadow-anomaly", "a", "shadow", True),
        ("bookmark", "a", "shadow", False),
        ("contribution", "a", "shadow", False),
        ("other-ref-kind", "a", "shadow", False),
        ("foreign-ref", "a", "shadow", False),
        ("held", "held-tenant", "shadow", False),
        ("archived", "a", "shadow", False),
    ]
    for i, (identifier, tenant, mode, anomaly) in enumerate(rows):
        add(db, identifier, i, tenant=tenant, mode=mode, anomaly=anomaly)
    db.executemany("INSERT INTO record_case_evidence_refs VALUES(?,?,?,?)", [
        ("a", "event-bookmark", "bookmark", "case"),
        ("a", "event-contribution", "contribution", "case"),
        ("a", "event-other-ref-kind", "research_behavior_run", "run"),
        ("b", "event-foreign-ref", "bookmark", "foreign-case"),
    ])
    db.execute("INSERT INTO policies VALUES('held-tenant',1)")
    db.execute("INSERT INTO research_behavior_archives VALUES('archived')")
    assert parity(db, cutoff=100) == ["shadow-anomaly", "other-ref-kind", "foreign-ref"]


def test_limit_applies_after_protected_candidates_without_starvation(db):
    for i in range(20):
        add(db, f"protected-{i}", i, mode="live", anomaly=True)
    for i in range(3):
        add(db, f"eligible-{i}", 20+i)
    assert parity(db, cutoff=100, limit=2) == ["eligible-0", "eligible-1"]
    assert parity(db, cutoff=100, limit=16) == ["eligible-0", "eligible-1", "eligible-2"]


@pytest.mark.parametrize("seed", [3, 17, 29, 43, 101])
def test_valid_mixed_corpus_has_identical_ordered_candidates(db, seed):
    rng = random.Random(seed)
    for i in range(240):
        identifier = f"run-{i}"
        tenant = rng.choice(["a", "b", "held"])
        add(db, identifier, rng.randrange(1000)+i/1000, tenant=tenant,
            model=rng.choice([None, "first", "second"]),
            mode=rng.choice(["shadow", "live"]), anomaly=rng.choice([False, True, None]))
        if rng.randrange(7) == 0:
            db.execute("INSERT INTO research_behavior_archives VALUES(?)", (identifier,))
        if rng.randrange(5) == 0:
            db.execute("INSERT INTO record_case_evidence_refs VALUES(?,?,?,?)",
                       (tenant, "event-"+identifier, rng.choice(["bookmark", "contribution", "research_behavior_run"]), identifier))
    db.execute("INSERT INTO policies VALUES('held',1)")
    for cutoff, newer, limit in [(0, 128, 16), (500, 128, 16), (0, 5, 3), (500, 5, 16), (1000, 128, 1)]:
        parity(db, cutoff=cutoff, newer=newer, limit=limit)


def test_recent_normal_runs_skip_protection_work_without_changing_results(db):
    for i in range(76):
        add(db, f"recent-{i}", 1000+i, mode="live")
    db.executemany("INSERT INTO record_case_evidence_refs VALUES(?,?,?,?)",
                   [("a", f"unrelated-{i}", "contribution", "case") for i in range(4096)])
    calls = []

    def extract(body, path):
        assert path == "$.decision.anomaly"
        calls.append(body)
        return json.loads(body)["decision"]["anomaly"]

    db.create_function("json_extract", 2, extract)
    instructions = []
    for query in (_PREVIOUS_SQL, lifecycle._DUE_RUNS_SQL):
        calls.clear()
        steps = []
        db.set_progress_handler(lambda steps=steps: steps.append(1) or 0, 100)
        try:
            assert candidates(db, query) == []
        finally:
            db.set_progress_handler(None, 0)
        instructions.append((len(calls), len(steps)))
    assert instructions[0][0] == 76
    assert instructions[1][0] == 0
    # VM work, not a fragile wall-clock or whole-pipeline performance claim.
    assert instructions[1][1] < instructions[0][1]


def test_not_due_is_not_a_claim_of_malformed_payload_integrity(db):
    add(db, "malformed", 1000)
    db.execute("UPDATE research_behavior_runs SET body='{' WHERE id='malformed'")
    assert candidates(db) == []
    with pytest.raises(sqlite3.OperationalError, match="malformed JSON"):
        candidates(db, _PREVIOUS_SQL)
    # Once due, the protected branch still parses and rejects invalid JSON.
    # An unselected row has not passed archival hash or authority verification.
    for query in (_PREVIOUS_SQL, lifecycle._DUE_RUNS_SQL):
        with pytest.raises(sqlite3.OperationalError, match="malformed JSON"):
            candidates(db, query, cutoff=1000)
