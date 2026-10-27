"""Real Store regressions for continued ownership and reviewed Case changes."""

import json
import time

import pytest

from sapientia import access, case_intelligence as ci, casework, contribution_verdicts as verdicts, detections
from sapientia.storage import ConflictError, encode
from tests.test_casework import case as original_case


@pytest.fixture
def case(tmp_path):
    for value in original_case.__wrapped__(tmp_path):
        ci.initialize(value[0])
        yield value


def _case(db, actor, identifier, entity="alice", indexes=("public",), process="process-a", event="original", created=None, story=None):
    created = time.time() if created is None else created
    db.execute("INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?)", (identifier, actor["tenant"], entity, "raw.user", identifier, created, created, "new", "", 1))
    match = {"entity": entity, "entity_field": "raw.user", "event_ids": [event], "indexes": list(indexes),
        "steps": [{"step": 1, "events": [{"event_id": event, "event_time": created, "raw.xdr.data.process.guid": process}]}]}
    episode = detections._episode(match)
    if story:
        match["analysis"] = {"story_id": story}
    db.execute("INSERT INTO risk_contributions VALUES(?,?,?,?,?,?,?,?,?,?)", ("contribution-"+identifier, actor["tenant"], identifier, "policy", entity, "raw.user", created, 50, encode({**match, "episode": episode}), encode(list(indexes))))
    db.execute("INSERT INTO incident_episodes VALUES(?,?,?,?,?)", (identifier, actor["tenant"], episode["key"], episode["grade"], encode(episode["basis"])))
    return match, episode


def _merge(store, actor, source, target):
    source_case, target_case = detections.incident_detail(store, actor, source), detections.incident_detail(store, actor, target)
    return verdicts.regroup(store, actor, source, "merge", {"version": source_case["version"], "target_id": target, "target_version": target_case["version"], "reason": "Verified related synthetic episodes"})


def test_merge_routes_later_distinct_evidence_to_current_owner_and_retains_origins(case):
    store, actor, _ = case
    with store.control() as db:
        match, episode = _case(db, actor, "source", event="source-e1")
        _case(db, actor, "target", process="process-b", event="target-e1")
    note = casework.act(store, actor, "source", {"request_id": "preserve-note", "action": {"type": "add_note", "note": "Original investigation provenance"}})
    task = casework.act(store, actor, "source", {"request_id": "preserve-task", "action": {"type": "add_task", "title": "Review source", "description": "", "mandatory": True}})
    _merge(store, actor, "source", "target")
    with store.control() as db:
        routed = ci.route(db, actor, {**match, "event_ids": ["later-e2"]}, episode, time.time())
        assert routed["incident_id"] == "target"
        assert "source" in routed["blocked_case_ids"]
        assert db.execute("SELECT incident_id FROM risk_contributions WHERE id='contribution-source'").fetchone()[0] == "target"
        with pytest.raises(ConflictError, match="required tasks"):
            verdicts.require_resolution(db, actor, "target")
    source_workspace = casework.workspace(store, actor, "source")
    assert note["id"] in {value["id"] for value in source_workspace["notes"]}
    assert task["id"] in {value["id"] for value in source_workspace["tasks"]}


def test_transitive_merge_alias_reaches_latest_case_without_lineage_cycle(case):
    store, actor, _ = case
    with store.control() as db:
        match, episode = _case(db, actor, "a")
        _case(db, actor, "b", process="process-b")
        _case(db, actor, "c", process="process-c")
    _merge(store, actor, "a", "b")
    _merge(store, actor, "b", "c")
    with store.control() as db:
        assert ci.route(db, actor, {**match, "event_ids": ["later"]}, episode, time.time())["incident_id"] == "c"


def test_story_alias_routes_related_process_with_different_episode_key(case):
    store, actor, _ = case
    with store.control() as db:
        match, episode = _case(db, actor, "source", story="durable-story")
        _case(db, actor, "target", process="other-process")
    _merge(store, actor, "source", "target")
    changed = {**match, "steps": [{"step": 1, "events": [{"event_id": "later", "raw.xdr.data.process.guid": "child-process"}]}], "event_ids": ["later"]}
    with store.control() as db:
        routed = ci.route(db, actor, changed, detections._episode(changed), time.time())
        assert routed["incident_id"]=="target"


def test_split_unique_episode_routes_new_arrivals_to_split_owner(case):
    store, actor, identifier = case
    with store.control() as db:
        match, episode = _case(db, actor, "helper", event="split-original")
        db.execute("UPDATE risk_contributions SET incident_id=? WHERE id='contribution-helper'", (identifier,))
        db.execute("DELETE FROM incidents WHERE id='helper'")
        db.execute("DELETE FROM incident_episodes WHERE incident_id='helper'")
    split = verdicts.regroup(store, actor, identifier, "split", {"version": 1, "reason": "Independent process episode", "contribution_ids": ["contribution-helper"]})
    with store.control() as db:
        routed = ci.route(db, actor, {**match, "event_ids": ["new-split-event"]}, episode, time.time())
        assert routed["incident_id"] == split["target_id"]
        assert identifier in routed["blocked_case_ids"]


def test_split_shared_episode_is_durable_barrier_and_exact_originals_have_owner(case):
    store, actor, _ = case
    with store.control() as db:
        match, episode = _case(db, actor, "shared", event="left")
        copy = json.loads(db.execute("SELECT evidence FROM risk_contributions WHERE id='contribution-shared'").fetchone()[0])
        copy["event_ids"] = ["right"]
        db.execute("INSERT INTO risk_contributions VALUES(?,?,?,?,?,?,?,?,?,?)", ("second-shared", actor["tenant"], "shared", "second", "alice", "raw.user", time.time(), 40, encode(copy), encode(["public"])))
    split = verdicts.regroup(store, actor, "shared", "split", {"version": 1, "reason": "Analyst distinguishes independent investigations", "contribution_ids": ["second-shared"]})
    with store.control() as db:
        for ids, expected in [(["right", "new"], split["target_id"]), (["left", "new"], "shared"), (["new"], None), (["left", "right"], None)]:
            routed = ci.route(db, actor, {**match, "event_ids": ids}, episode, time.time())
            assert routed["incident_id"] == expected
            assert {"shared", split["target_id"]} <= set(routed["blocked_case_ids"])


def test_route_never_broadens_overlapping_scopes_or_revoked_target_visibility(case):
    store, actor, _ = case
    with store.control() as db:
        match, episode = _case(db, actor, "source")
        _case(db, actor, "target", indexes=("public", "private"), process="process-b")
    _merge(store, actor, "source", "target")
    with store.control() as db:
        limited = {**actor, "allowed_indexes": ["public"]}
        assert ci.route(db, limited, match, episode, time.time())["incident_id"] is None
        changed = ci.route(db, actor, {**match, "indexes": ["public", "third"]}, episode, time.time())
        assert changed["incident_id"] is None
        assert {"source", "target"} <= set(changed["blocked_case_ids"])


def _frozen_endpoint(db, actor, incident):
    db.execute("INSERT INTO endpoint_responses(id,tenant,incident_id,agent_id,host,index_name,requester,scope,request_id,request_digest,evidence_event_id,case_version,action,reason,state,created,expires) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("frozen", actor["tenant"], incident, "agent", "host", "public", actor["name"], '["public"]', "frozen-test", "digest", "original", 1, '{}', "Frozen evidence", "queued", time.time(), time.time()+300))


def test_regroup_cannot_rebind_frozen_response_or_rewrite_its_snapshot(case):
    store, actor, _ = case
    with store.control() as db:
        _case(db, actor, "source")
        _case(db, actor, "target", process="process-b")
        _frozen_endpoint(db, actor, "source")
    with pytest.raises(ConflictError, match="frozen response"):
        _merge(store, actor, "source", "target")
    with store.control() as db:
        assert db.execute("SELECT case_version,state,incident_id FROM endpoint_responses WHERE id='frozen'").fetchone()[:] == (1, "queued", "source")
        assert db.execute("SELECT incident_id FROM risk_contributions WHERE id='contribution-source'").fetchone()[0] == "source"


def test_regroup_does_not_override_frozen_soar_approval(case):
    store, actor, _ = case
    with store.control() as db:
        _case(db, actor, "source")
        _case(db, actor, "target", process="process-b")
        db.execute("INSERT INTO soar_runs(id,tenant,playbook_id,revision,definition,revision_digest,incident_id,requested_by,request_id,requested_scope,snapshot,snapshot_digest,config_digest,state,expected_incident_version,created,updated,next_run) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("approved-run", actor["tenant"], "playbook", 1, '{}', "definition", "target", actor["name"], "approval-test", '["public"]', '{}', "snapshot", "config", "queued", 1, time.time(), time.time(), time.time()))
    with pytest.raises(ConflictError, match="frozen response"):
        _merge(store, actor, "source", "target")
    with store.control() as db:
        assert db.execute("SELECT expected_incident_version,state,snapshot_digest FROM soar_runs WHERE id='approved-run'").fetchone()[:] == (1, "queued", "snapshot")


@pytest.mark.parametrize("state", ["prepared", "approved", "dispatching", "reported", "unknown", "partial"])
def test_pending_effect_protocol_receipt_fences_case_regroup_and_snapshot(case, state):
    store, actor, _ = case
    with store.control() as db:
        _case(db, actor, "source")
        _case(db, actor, "target", process="process-b")
        db.execute("INSERT INTO effect_receipts VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", ("pending-effect", actor["tenant"], "source", 1,
            '["public"]', actor["name"], "admin_a", '{"virtual":true}', state, 1, time.time(), time.time()))
    with pytest.raises(ConflictError, match="frozen response"):
        _merge(store, actor, "source", "target")
    with store.control() as db:
        assert db.execute("SELECT incident_id,case_version,state,definition FROM effect_receipts WHERE id='pending-effect'").fetchone()[:] == ("source", 1, state, '{"virtual":true}')


def test_scoped_reevaluation_pages_beyond_100_and_retains_cross_page_groups(case):
    store, actor, _ = case
    configure(store, actor)
    now = time.time()
    with store.control() as db:
        for n in range(210):
            _case(db, actor, "unrelated-"+str(n), indexes=("private",), process="unrelated-"+str(n), created=now-n*.001)
        for n in range(125):
            _case(db, actor, "selected-"+str(n), process="shared-cross-page" if n in {0, 124} else "unique-"+str(n),
                  event="selected-original-"+str(n), created=now-1-n*.001)
    assert ci.run_due(store, now+1, budget=2) == 0
    with store.control() as db:
        progress = dict(db.execute("SELECT * FROM case_reevaluation_work").fetchone())
        assert progress["scanned"] == 100
        assert db.execute("SELECT error FROM case_reevaluation_config").fetchone()[0] is None
    settings = store.settings
    store.close()
    from sapientia.storage import Store
    restarted = Store(settings)
    try:
        assert ci.run_due(restarted, now+2, budget=2) == 1
        items = ci.proposals(restarted, actor)["items"]
        assert len(items) == 1 and {items[0]["source_id"], items[0]["target_id"]} == {"selected-0", "selected-124"}
        with restarted.control() as db:
            assert db.execute("SELECT count(*) FROM case_reevaluation_work").fetchone()[0] == 0
            assert db.execute("SELECT count(*) FROM case_reevaluation_groups").fetchone()[0] == 0
    finally:
        restarted.close()


def test_split_of_cached_cross_page_representative_never_becomes_merge_proposal(case):
    store, actor, _ = case
    configure(store, actor)
    now = time.time()
    with store.control() as db:
        for n in range(105):
            _case(db, actor, "paged-"+str(n), process="cross-page" if n in {0, 104} else "unique-"+str(n),
                  event="paged-original-"+str(n), created=now-n*.001)
        record = json.loads(db.execute("SELECT evidence FROM risk_contributions WHERE id='contribution-paged-0'").fetchone()[0])
        record["event_ids"] = ["split-right"]
        db.execute("INSERT INTO risk_contributions VALUES(?,?,?,?,?,?,?,?,?,?)", ("split-cached", actor["tenant"], "paged-0", "policy", "alice", "raw.user", now, 30, encode(record), '["public"]'))
    assert ci.run_due(store, now+1, budget=2) == 0
    split = verdicts.regroup(store, actor, "paged-0", "split", {"version": 1, "reason": "Independent reported episode",
        "contribution_ids": ["split-cached"]})
    assert split["target_id"]
    assert ci.run_due(store, now+2, budget=2) == 0
    assert ci.proposals(store, actor)["items"] == []


def configure(store, actor):
    admin = {**actor, "name": "admin_a", "role": "admin"}
    ci.configure(store, admin, {"indexes": ["public"], "enabled": True, "exact_attachment": True, "interval": 30, "version": 0})
    return admin


def proposal(case):
    store, actor, _ = case
    configure(store, actor)
    with store.control() as db:
        _case(db, actor, "source", event="e1", created=time.time())
        _case(db, actor, "target", event="e2", created=time.time()-1)
    assert ci.run_due(store, time.time()+1) == 1
    return ci.proposals(store, actor)["items"][0]


def test_opt_in_reevaluation_proposes_and_independent_review_merges_atomically(case):
    item = proposal(case)
    store, actor, _ = case
    assert not item["automatic_merge"]
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM risk_contributions WHERE incident_id='source'").fetchone()[0] == 1
    result = ci.review(store, actor, item["id"], {"version": 1, "approve": True, "reason": "Independently reviewed exact related process episode"})
    assert result["state"] == "approved" and result["movement_id"] and not result["response_authorized"]
    assert len(ci.history(store, actor, item["id"])["items"]) == 2
    assert detections.incident_detail(store, actor, "target")["contribution_count"] == 2


def test_changed_case_or_owner_acl_prevents_stale_proposal_mutation(case):
    item = proposal(case)
    store, actor, _ = case
    with store.control() as db:
        db.execute("UPDATE incidents SET version=version+1 WHERE id='source'")
    with pytest.raises(ConflictError, match="version changed"):
        ci.review(store, actor, item["id"], {"version": 1, "approve": True, "reason": "Stale review must fail"})
    admin = {**actor, "name": "admin_a", "role": "admin"}
    access.set_for_user(store, admin, "admin_a", ["private"])
    with pytest.raises(PermissionError, match="owner lost"):
        ci.review(store, actor, item["id"], {"version": 1, "approve": True, "reason": "Revoked owner must fail"})


def test_disabled_reevaluation_and_independent_approval_enforced(case):
    store, actor, _ = case
    assert ci.configuration(store, actor)["enabled"] is False
    assert ci.run_due(store, time.time()) == 0
    item = proposal(case)
    admin = {**actor, "name": "admin_a", "role": "admin"}
    with pytest.raises(PermissionError, match="independent"):
        ci.review(store, admin, item["id"], {"version": 1, "approve": True, "reason": "Owner cannot approve own proposal"})


def test_emitter_hook_routes_replayed_post_merge_originals_into_target(case):
    store, actor, _ = case
    now = time.time()
    def observation(identifier, branch, guid):
        return {"event_id": identifier, "event_time": now, "index": "public", "host": "test-host",
            "raw": {"user": "runtime-test", "branch": branch, "xdr": {"data": {"process": {"guid": guid}}}}}
    store.ingest("a", [observation("runtime-a1", "a", "runtime-process-a"), observation("runtime-b1", "b", "runtime-process-b")])
    store.flush()
    policies = []
    for branch in ("a", "b"):
        policies.append(detections.save(store, actor, {"name": "Runtime branch "+branch,
            "entity_field": "raw.user", "window": 300,
            "relation": {"mode": "same_value", "field": "raw.xdr.data.process.guid"},
            "steps": [{"filters": [{"field": "raw.branch", "op": "eq", "value": branch}]}]}))
    detections.run_due(store, time.time()+1)
    with store.control() as db:
        source = db.execute("SELECT incident_id FROM risk_contributions WHERE policy_id=?", (policies[0],)).fetchone()[0]
        target = db.execute("SELECT incident_id FROM risk_contributions WHERE policy_id=?", (policies[1],)).fetchone()[0]
    _merge(store, actor, source, target)
    store.ingest("a", [observation("runtime-a2", "a", "runtime-process-a")])
    store.flush()
    replay = detections.replay(store, actor, policies[0], time.time(), 1, "post-merge-runtime-replay")
    assert replay["emitted"]>=1
    with store.control() as db:
        contributions = db.execute("SELECT incident_id,evidence FROM risk_contributions WHERE tenant=? AND policy_id=?", (actor["tenant"], policies[0])).fetchall()
        later = [row for row in contributions if "runtime-a2" in json.loads(row["evidence"])["event_ids"]]
        assert later and {row["incident_id"] for row in later}=={target}


def test_real_post_split_new_observation_does_not_silently_recombine_old_cases(case):
    store, analyst, _ = case
    now=time.time()
    def observation(identifier, branch):
        return {"event_id":identifier,"event_time":now,"index":"public","host":"test-host",
            "raw":{"user":"split-runtime","branch":branch,"xdr":{"data":{"process":{"guid":"shared-split-process"}}}}}
    store.ingest("a",[observation("split-a1","a"),observation("split-b1","b")])
    store.flush()
    policies=[detections.save(store,analyst,{"name":"Split branch "+branch,"entity_field":"raw.user","window":300,
        "relation":{"mode":"same_value","field":"raw.xdr.data.process.guid"},
        "steps":[{"filters":[{"field":"raw.branch","op":"eq","value":branch}]}]}) for branch in ("a","b")]
    setup_deadline = time.monotonic() + 10
    prepared = set()
    last_setup_result = None
    setup_turns = 0
    while time.monotonic() < setup_deadline:
        # Each scheduled turn retains its normal bounded budget and guards.
        # Readiness requires actual contributions from both saved policies.
        last_setup_result = detections.run_due(store, time.time()+1)
        setup_turns += 1
        with store.control() as db:
            prepared = {
                row["policy_id"] for row in db.execute(
                    "SELECT DISTINCT policy_id FROM risk_contributions "
                    "WHERE tenant=? AND policy_id IN (?,?)",
                    (analyst["tenant"], *policies),
                )
            }
        if prepared == set(policies):
            break
        time.sleep(min(.05, max(0, setup_deadline-time.monotonic())))
    if prepared != set(policies):
        with store.control() as db:
            readiness = [dict(row) for row in db.execute(
                "SELECT id,name,enabled,next_run,last_end,retry_at,failures,error "
                "FROM correlation_policies WHERE tenant=? AND id IN (?,?) ORDER BY id",
                (analyst["tenant"], *policies),
            )]
        pytest.fail(encode({"reason": "Both split-fixture policies did not produce contributions within the bounded setup wait",
            "missing_policy_ids": sorted(set(policies)-prepared), "turns": setup_turns,
            "last_run_result": last_setup_result, "policy_readiness": readiness}))
    with store.control() as db:
        first=db.execute("SELECT id,incident_id FROM risk_contributions WHERE policy_id=?",(policies[0],)).fetchone()
        selected=db.execute("SELECT id,incident_id FROM risk_contributions WHERE policy_id=?",(policies[1],)).fetchone()
        assert first["incident_id"]==selected["incident_id"]
    source=first["incident_id"]
    version=detections.incident_detail(store,analyst,source)["version"]
    split=verdicts.regroup(store,analyst,source,"split",{"version":version,"reason":"Analyst separated related but independent investigations","contribution_ids":[selected["id"]]})
    store.ingest("a",[observation("split-a2","a")])
    store.flush()
    detections.replay(store,analyst,policies[0],time.time(),1,"post-split-replay")
    with store.control() as db:
        later=[row for row in db.execute("SELECT incident_id,evidence FROM risk_contributions WHERE policy_id=?",(policies[0],)) if "split-a2" in json.loads(row["evidence"])["event_ids"]]
        assert later and all(row["incident_id"] not in {source,split["target_id"]} for row in later)
