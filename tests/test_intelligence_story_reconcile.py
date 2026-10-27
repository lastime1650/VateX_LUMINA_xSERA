"""Late delivery keeps current graphs connected without rewriting past facts."""

import copy
import json
import time

import pytest

from sapientia import access, connector_runtime, intelligence, intelligence_story_reconcile as reconcile, principal, source_registry
from sapientia.storage import ConflictError, encode
from tests.test_backend_upgrade import actor, lab  # noqa: F401 - temporary real Store.


def setup(lab, monkeypatch, **child_changes):
    source = source_registry.save(lab, actor(), {"index": "public", "product": "json", "account": "asset", "realm": "lab", "credential_ref": "env:SAPIENTIA_CONNECTOR_LAB", "version": 0})
    at = time.time()-10
    def event(identifier, guid, start, parent=None):
        process = {"guid": guid, "start_identity": start, "name": guid+".exe"}
        if parent:
            process["parent"] = {"guid": parent[0], "start_identity": parent[1]}
        return {"event_id": identifier, "event_time": at+(1 if parent else 0), "host": "asset", "raw": {
            "xdr": {"data": {"event": {"action": "process_created"}, "host": {"id": "device", "boot_id": "boot"}, "process": process}}}}
    child = event("late-child", "C", "child-incarnation", ("P", "parent-incarnation"))
    for field, value in child_changes.items():
        current = child["raw"]["xdr"]["data"]
        parts = field.split(".")
        for part in parts[:-1]:
            current = current[part]
        if value is None:
            current.pop(parts[-1], None)
        else:
            current[parts[-1]] = value
    connector_runtime.intake(lab, actor(), source["id"], {"version": 1, "events": [child], "cursor": "child-first", "checkpoint_version": 0})
    lab.flush()
    def publish(identifier):
        return intelligence.publish(lab, actor(), {"event_ids": [identifier], "kind": "atomic", "rule_id": identifier,
            "rule_revision": 1, "features": {}, "severity": "medium", "confidence_grade": "source_reported"})
    first = publish("late-child")
    parent = event("late-parent", "P", "parent-incarnation")
    connector_runtime.intake(lab, actor(), source["id"], {"version": 1, "events": [parent], "cursor": "parent-later", "checkpoint_version": 1})
    lab.flush()
    # Model a recovery worker that runs relationship reconciliation after both
    # signal snapshots have already been committed, including future hook use.
    actual = reconcile.reconcile
    monkeypatch.setattr(reconcile, "reconcile", lambda store,db,user,story_id,process_node_id=None: story_id)
    second = publish("late-parent")
    monkeypatch.setattr(reconcile, "reconcile", actual)
    with lab.control() as db:
        node = db.execute("SELECT id FROM intelligence_story_nodes WHERE tenant='a' AND kind='process' AND json_extract(body,'$.projection.process.guid')='P'").fetchone()[0]
    return source, first, second, node


def apply(lab, story, node):
    with lab.segment_lock.read(deadline=time.monotonic()+3), principal.transaction(lab, actor(), ("admin", "analyst"), write=True) as (db, fresh):
        return reconcile.reconcile(lab, db, fresh, story, node)


def test_late_parent_atomically_canonicalizes_nodes_and_edges_preserving_original_signal_snapshots(lab, monkeypatch):
    _, child, parent, node = setup(lab, monkeypatch)
    assert child["story_id"]!=parent["story_id"]
    assert apply(lab, parent["story_id"], node)==parent["story_id"]
    with lab.control() as db:
        assert reconcile.resolve(db, "a", child["story_id"])==parent["story_id"]
        assert db.execute("SELECT count(*) FROM intelligence_story_nodes WHERE tenant='a' AND story_id=?", (child["story_id"],)).fetchone()[0]==0
        assert db.execute("SELECT count(*) FROM intelligence_story_nodes WHERE tenant='a' AND story_id=?", (parent["story_id"],)).fetchone()[0]==4
        original = db.execute("SELECT story_id,body FROM intelligence_signals WHERE id=?", (child["id"],)).fetchone()
        assert original["story_id"]==child["story_id"] and json.loads(original["body"])["story_id"]==child["story_id"]
        edges = [dict(row) for row in db.execute("SELECT * FROM intelligence_story_edges WHERE tenant='a' AND relation='reported_parent'")]
        assert len(edges)==1 and set(json.loads(edges[0]["event_ids"]))=={"late-child", "late-parent"}
        history = [json.loads(row[0]) for row in db.execute("SELECT record FROM intelligence_story_history WHERE story_id=?", (child["story_id"],))]
        assert any(item.get("kind")=="current_story_reconciled" for item in history)
        before = db.execute("SELECT count(*) FROM intelligence_story_aliases").fetchone()[0]
    apply(lab, parent["story_id"], node)
    with lab.control() as db:
        assert db.execute("SELECT count(*) FROM intelligence_story_aliases").fetchone()[0]==before


@pytest.mark.parametrize("changes", [
    {"host.boot_id": "different-boot"}, {"host.id": "different-device"}, {"host.boot_id": None},
    {"process.parent.start_identity": "reused-parent-birth"}, {"process.parent.start_identity": None},
])
def test_incomplete_or_mismatched_reported_incarnation_never_becomes_late_parent_alias(lab, monkeypatch, changes):
    _, child, parent, node = setup(lab, monkeypatch, **changes)
    apply(lab, parent["story_id"], node)
    with lab.control() as db:
        assert reconcile.resolve(db, "a", child["story_id"])==child["story_id"]
        assert db.execute("SELECT count(*) FROM intelligence_story_aliases").fetchone()[0]==0


def test_source_revocation_and_current_scope_prevent_late_relationship_changes(lab, monkeypatch):
    source, child, parent, node = setup(lab, monkeypatch)
    source_registry.revoke(lab, actor(), source["id"], 1)
    apply(lab, parent["story_id"], node)
    with lab.control() as db:
        assert reconcile.resolve(db, "a", child["story_id"])==child["story_id"]
    access.set_for_user(lab, actor(), "owner", ["private"])
    with pytest.raises(PermissionError, match="permissions changed"):
        with lab.control() as db:
            reconcile.reconcile(lab, db, actor(), parent["story_id"], node)


def test_partial_story_scope_cannot_canonicalize_or_resolve_hidden_current_graph(lab, monkeypatch):
    _, child, parent, node = setup(lab, monkeypatch)
    with lab.control() as db:
        db.execute("UPDATE intelligence_stories SET indexes=? WHERE id=?", (encode(["private", "public"]), child["story_id"]))
    limited = {**actor(), "allowed_indexes": ["public"]}
    with principal.transaction(lab, limited, ("admin",), write=True) as (db, current):
        reconcile.reconcile(lab, db, current, parent["story_id"], node)
        assert reconcile.resolve(db, "a", child["story_id"])==child["story_id"]
    apply(lab, parent["story_id"], node)
    with lab.control() as db:
        assert reconcile.current(db, limited, child["story_id"]) is None
        assert reconcile.current(db, actor(), child["story_id"])==parent["story_id"]


def _case(db, identifier, story, event_id, projection):
    match = {"entity": "asset", "entity_field": "host", "event_ids": [event_id], "indexes": ["public"],
        "steps": [{"step": 1, "events": [{"event_id": event_id, "raw.xdr.data.process.guid": projection["process"]["guid"]}]}],
        "analysis": {"story_id": story}}
    episode = __import__('sapientia.detections', fromlist=['_episode'])._episode(match)
    now=time.time()
    db.execute("INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?)", (identifier, "a", "asset", "host", identifier, now, now, "new", "", 1))
    db.execute("INSERT INTO risk_contributions VALUES(?,?,?,?,?,?,?,?,?,?)", (identifier+"-contrib", "a", identifier, "policy", "asset", "host", now, 30, encode({**match,"episode":episode}), '["public"]'))
    return match, episode


def test_graph_reconciliation_keeps_existing_case_owners_split_and_frozen_approvals_untouched(lab, monkeypatch):
    from sapientia import case_intelligence
    _, child, parent, node = setup(lab, monkeypatch)
    with lab.control() as db:
        projections = {json.loads(row[0])["projection"]["process"]["guid"]:json.loads(row[0])["projection"] for row in db.execute("SELECT body FROM intelligence_story_nodes WHERE kind='process'")}
        _case(db,"child-case",child["story_id"],"late-child",projections["C"])
        match, episode = _case(db,"parent-case",parent["story_id"],"late-parent",projections["P"])
    apply(lab, parent["story_id"], node)
    with lab.control() as db:
        routed = case_intelligence.route(db,actor(),{**match,"event_ids":["unseen-later"]},episode,time.time())
        assert routed["incident_id"] is None
        assert {"child-case","parent-case"}<=set(routed["blocked_case_ids"])
        assert db.execute("SELECT version FROM incidents WHERE id='child-case'").fetchone()[0]==1
        assert db.execute("SELECT version FROM incidents WHERE id='parent-case'").fetchone()[0]==1
        assert db.execute("SELECT incident_id FROM risk_contributions WHERE id='child-case-contrib'").fetchone()[0]=="child-case"
        assert db.execute("SELECT count(*) FROM case_movement_history").fetchone()[0]==0


def test_unrelated_inventory_does_not_create_a_lifetime_ceiling_and_alias_cycles_refuse(lab, monkeypatch):
    _, child, parent, node = setup(lab, monkeypatch)
    with lab.control() as db:
        projection = json.loads(db.execute("SELECT body FROM intelligence_story_nodes WHERE id=?", (node,)).fetchone()[0])["projection"]
        for position in range(1001):
            unrelated = copy.deepcopy(projection)
            unrelated["process"]["guid"]="unrelated-"+str(position)
            db.execute("INSERT INTO intelligence_story_nodes VALUES(?,?,?,?,?,?,?)", ("unrelated-"+str(position),"a",parent["story_id"],"process",'["public"]','[]',encode({"projection":unrelated})))
    apply(lab,parent["story_id"],node)
    with lab.control() as db:
        assert reconcile.resolve(db,"a",child["story_id"])==parent["story_id"]
        db.execute("INSERT INTO intelligence_story_aliases VALUES(?,?,?,?,?,?)",("a",parent["story_id"],child["story_id"],1,'{}',time.time()))
        with pytest.raises(ConflictError,match="cycle"):
            reconcile.resolve(db,"a",child["story_id"])
