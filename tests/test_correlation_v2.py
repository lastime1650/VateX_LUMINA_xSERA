"""Cross-product flow association, source fencing and frozen-page recovery."""

import json
import copy
import time

import pytest

from sapientia import access, correlation_runtime, source_registry
from tests.test_backend_upgrade import actor
from tests.test_virtual_telemetry import client, register
from tools.simulation.loggers import ATTACK_IP, generate


def load(client, count=30):
    base = time.time()-120
    sources = {}
    for profile in ("windows", "cisco_asa", "fortigate"):
        source = register(client, profile)
        sources[profile] = source
        events, _ = generate(profile, count, base_time=base)
        response = client.post("/api/v2/sources/"+source["id"]+"/intake", json={"version": 1, "events": events, "cursor": "all", "checkpoint_version": 0})
        assert response.status_code == 202, response.text
    client.app.state.store.flush()
    data = {"name": "Virtual cross-domain chain", "version": 0, "sources": [v["id"] for v in sources.values()],
            "window": 600, "within_seconds": 2, "enabled": True,
            "steps": [{"product": p, "filters": [{"field": "flow.dest_ip", "op": "eq", "value": ATTACK_IP}]} for p in sources],
            "case_adapter": {"entity_field": "raw.analysis.resolved_entity", "risk_score": 60, "severity": "high", "mitre": ["T1071.001"], "cooldown": 0}}
    response = client.post("/api/v2/correlations", json=data)
    assert response.status_code == 201, response.text
    return response.json(), sources


def drain(store, now=None):
    for _ in range(50):
        correlation_runtime.run_due(store, now=now, budget=.15, max_runs=1)
        with store.control() as db:
            row = db.execute("SELECT snapshot_seq,error,completed_seq FROM correlation_plans").fetchone()
        assert row["error"] is None, row["error"]
        if row["completed_seq"] and not row["snapshot_seq"]:
            return
    raise AssertionError("V2 frontier did not drain")


def test_cross_product_original_evidence_and_no_native_claim(client):
    plan, sources = load(client)
    store = client.app.state.store
    drain(store)
    with store.control() as db:
        rows = db.execute("SELECT evidence FROM risk_contributions WHERE policy_id=?", ("v2:"+plan["id"]+":1",)).fetchall()
    assert len(rows) == 6
    for row in rows:
        evidence = json.loads(row[0])
        assert len(evidence["event_ids"]) == 3
        association = evidence["analysis"]["identity"]
        assert association["native_capture_proven"] is False
        assert association["automatic_endpoint_authorization"] is False
        assert association["causality_proven"] is False
        assert association["clock_assurance"] == "unknown"
    correlation_runtime.run_due(store, budget=1)
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0] == 6


def test_source_revoke_blocks_plan_and_scope_hides_it(client):
    plan, sources = load(client)
    store = client.app.state.store
    source_registry.revoke(store, actor(), sources["cisco_asa"]["id"], 1)
    correlation_runtime.run_due(store, budget=1)
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0] == 0
        assert db.execute("SELECT error FROM correlation_plans").fetchone()[0] == "PermissionError"
    access.set_for_user(store, actor(), "owner", ["sim_windows"])
    assert correlation_runtime.listing(store, actor()) == []


def test_small_budget_uses_frozen_window_and_event_frontier(client, monkeypatch):
    plan, sources = load(client, 100)
    store = client.app.state.store
    now = time.time()
    monkeypatch.setattr(correlation_runtime, "PAGE", 1)
    correlation_runtime.run_due(store, now=now, budget=1)
    with store.control() as db:
        row = dict(db.execute("SELECT * FROM correlation_plans").fetchone())
    assert row["snapshot_seq"] > 0 and row["frozen_end"] == now
    drain(store, now=now+700)
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0] == 20


def test_plan_refuses_negative_or_unbounded_expression(client):
    with pytest.raises(ValueError):
        correlation_runtime.validate({"name": "arbitrary-expression", "query": "eval(__import__)"})


def test_same_flow_with_two_endpoint_process_reports_is_ambiguous(client):
    plan, sources = load(client, 5)
    store = client.app.state.store
    with store.control() as db:
        original = json.loads(db.execute("SELECT projection FROM event_projections WHERE source_id=? ORDER BY seq LIMIT 1", (sources["windows"]["id"],)).fetchone()[0])
    events, _ = generate("windows", 1, seed=987, base_time=original["event_time"])
    path = "/api/v2/sources/"+sources["windows"]["id"]+"/intake"
    assert client.post(path, json={"version": 1, "events": events, "cursor": "ambiguous", "checkpoint_version": 1}).status_code == 202
    store.flush()
    drain(store)
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0] == 0
