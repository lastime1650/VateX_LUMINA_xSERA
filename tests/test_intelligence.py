"""Operational ancestry, replay cursors, review pins and positive alternatives."""
import json
import time

import pytest

from sapientia import connector_runtime, intelligence as core, source_registry
from sapientia.storage import CapacityError, ConflictError
from tests.test_backend_upgrade import lab, actor


def policy(store, name, **fields):
    value = {"name": name, "kind": "atomic", "indexes": ["public"], "enabled": True,
             "filters": [{"field": "raw.stage", "op": "eq", "value": name}], **fields}
    saved = core.save_policy(store, actor(), value)
    core.review_policy(store, actor("peer"), saved["id"], {"version": 1, "approve": True, "reason": "Independent test review"})
    return saved, value


def seed(store, stages=("A", "B", "C")):
    source = source_registry.save(store, actor(), {"index": "public", "product": "json", "account": "asset", "realm": "lab", "credential_ref": "env:SAPIENTIA_CONNECTOR_LAB", "version": 0})
    at = time.time() - 30
    events = [{"event_id": f"event-{n}", "event_time": at+n, "host": "asset", "raw": {"stage": stage, "xdr": {"data": {
        "process": {"guid": "process-one", "start_identity": "incarnation-one"}, "host": {"id": "device", "boot_id": "boot"},
        "event": {"action": "process_observed" if n==0 else "network_connection", "timestamp_precision_seconds": .01}}}}} for n,stage in enumerate(stages)]
    connector_runtime.intake(store, actor(), source["id"], {"version": 1, "events": events, "cursor": "seed", "checkpoint_version": 0})
    while store.flush():
        pass
    return source, events


def composites(store, name, inputs, **fields):
    return policy(store, name, kind="composite", inputs=inputs, join_on="story", minimum_independent_groups=2, **fields)[0]


def tick(store, loops=5):
    for _ in range(loops):
        core.run_due(store, budget=2, max_runs=8)


def test_live_signals_story_case_ancestry_and_restart_cursor(lab):
    a,_=policy(lab,"A")
    b,_=policy(lab,"B")
    ab=composites(lab,"AB",[{"rule_id":a["id"]},{"rule_id":b["id"]}], case_adapter={"entity_field":"host","risk_score":60,"severity":"high","mitre":[],"cooldown":0})
    _,events=seed(lab)
    tick(lab)
    rows=core.signals(lab,actor(),count=100)["items"]
    combined=next(s for s in rows if s["rule_id"]==ab["id"])
    assert combined["event_ids"]==["event-0","event-1"]
    assert combined["evidence_dependency"]["disjoint_original_groups"]==2
    assert combined["malicious_probability"] is None
    assert all(not s["automatic_endpoint_authorization"] for s in rows)
    graph=core.story(lab,actor(),combined["story_id"])
    assert any(n["body"].get("observed_not_created") for n in graph["nodes"])
    with lab.control() as db:
        evidence=json.loads(db.execute("SELECT evidence FROM risk_contributions").fetchone()[0])
        assert {e["host"] for e in evidence["steps"][0]["events"]}=={"asset"}
        counts=[db.execute("SELECT count(*) FROM "+table).fetchone()[0] for table in ("intelligence_signals","intelligence_story_history","risk_contributions")]
        db.execute("UPDATE intelligence_cursors SET cursor=0 WHERE worker='events'")
    tick(lab)
    with lab.control() as db:
        assert counts==[db.execute("SELECT count(*) FROM "+table).fetchone()[0] for table in ("intelligence_signals","intelligence_story_history","risk_contributions")]


def test_all_alternatives_and_partial_original_dependency(lab):
    a,_=policy(lab,"A")
    a2,_=policy(lab,"A2",filters=[{"field":"raw.stage","op":"eq","value":"A"}])
    b,_=policy(lab,"B")
    choice=composites(lab,"choice",[{"rule_id":a["id"]},{"kind":"atomic"}])
    reuse=composites(lab,"reuse",[{"rule_id":a["id"]},{"rule_id":a2["id"]}])
    seed(lab)
    tick(lab)
    rows=core.signals(lab,actor(),count=100)["items"]
    assert next(s for s in rows if s["rule_id"]==choice["id"])["event_ids"]==["event-0","event-1"]
    assert not any(s["rule_id"]==reuse["id"] for s in rows)
    assert core._dependencies([["a","b"],["b","c"],["d"]])["disjoint_original_groups"]==2
    assert core._dependencies([["a"],["b"]],["same-anomaly","same-anomaly"])["disjoint_original_groups"]==1


def test_parent_revision_pins_and_independent_approval(lab):
    a,value=policy(lab,"A")
    b,_=policy(lab,"B")
    child=composites(lab,"AB",[{"rule_id":a["id"]},{"rule_id":b["id"]}])
    stored=next(r for r in core.policies(lab,actor()) if r["id"]==child["id"])
    assert stored["definition"]["input_revisions"][a["id"]]["version"]==1
    changed=core.save_policy(lab,actor(),{**value,"version":1},a["id"])
    with pytest.raises(PermissionError):
        core.review_policy(lab,actor(),a["id"],{"version":2,"approve":True,"reason":"Self review"})
    core.review_policy(lab,actor("peer"),a["id"],{"version":2,"approve":True,"reason":"Independent revised review"})
    seed(lab)
    tick(lab)
    assert not any(s["rule_id"]==child["id"] for s in core.signals(lab,actor())["items"])
    with lab.control() as db:
        assert "Pinned parent revision changed" in db.execute("SELECT error FROM intelligence_composite_state WHERE id=?",(child["id"],)).fetchone()[0]


def test_more_than_eight_composites_receive_fair_durable_runs(lab):
    a,_=policy(lab,"A")
    b,_=policy(lab,"B")
    ids={composites(lab,f"AB-{n}",[{"rule_id":a["id"]},{"rule_id":b["id"]}])["id"] for n in range(12)}
    seed(lab)
    tick(lab,8)
    assert ids <= {s["rule_id"] for s in core.signals(lab,actor(),count=1000)["items"]}
    before=len(core.decisions(lab,actor(),count=1000)["items"])
    tick(lab)
    assert len(core.decisions(lab,actor(),count=1000)["items"])==before


def test_strict_clock_unknown_or_overlapping_intervals_cannot_assert_order():
    definition={"ordered":True,"clock_policy":"strict"}
    a={"event_window":{"start":1,"end":1,"precision_seconds":None}}
    b={"event_window":{"start":2,"end":2,"precision_seconds":.1}}
    assert not core._ordered(a,b,definition)
    a["event_window"]["precision_seconds"]=2
    assert not core._ordered(a,b,definition)
    a["event_window"]["precision_seconds"]=.1
    assert core._ordered(a,b,definition)


def test_user_cannot_spoof_internal_pins_labels_or_dependency_cycles(lab):
    with pytest.raises(ValueError):
        core.save_policy(lab,actor(),{"name":"spoof","kind":"atomic","indexes":["public"],"filters":[{"field":"raw.ground_truth","op":"eq","value":"attack"}]})
    with pytest.raises(ValueError):
        core._definition({"name":"spoof","kind":"atomic","indexes":["public"],"filters":[{"field":"raw.stage","op":"eq","value":"A"}],"input_revisions":{}})
    signal={"id":"a","entity_key":"same","event_ids":["a"],"event_window":{"start":1,"end":1},"rule_id":"A"}
    with pytest.raises(CapacityError):
        core._qualified_chain(signal,[],{"inputs":[{"rule_id":"A"},{"rule_id":"B"}],"join_on":"entity","ordered":False,"window":300,"minimum_independent_groups":2},deadline=0.0001)


def test_connected_partial_evidence_uses_maximum_risk_term():
    from sapientia.evidence_dependencies import adjusted
    rows=[{"id":str(n),"evidence":json.dumps({"event_ids":ids}),"term":weight} for n,(ids,weight) in enumerate([(["a","b"],30),(["b","c"],60),(["c","d"],40),(["e"],15)])]
    result=adjusted(rows)
    assert result=={"score":75,"groups":2,"distinct_sets":4}
