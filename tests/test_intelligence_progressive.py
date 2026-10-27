"""Real stored evidence beyond former global caps; durable scheduling resumes."""

import copy
import json
import time

from sapientia import cpu_ml, intelligence as core
from sapientia.storage import Store, encode
from tests.test_backend_upgrade import actor, lab as _backend_lab
from tests.test_intelligence import composites, policy, seed, tick

lab=_backend_lab


def clone(db, body, identifier, rule=None):
    body=copy.deepcopy(body)
    body.update(id=identifier,rule_id=rule or body["rule_id"])
    body["context_digest"]=identifier
    columns=["id","tenant","indexes","event_ids","parent_signal_ids","entity_key","story_id","kind","rule_id","rule_revision","features","severity","confidence_grade","created","mode","definition_digest","context_digest","body"]
    values=[]
    for column in columns:
        value=body if column=="body" else body[column]
        values.append(encode(value) if column in {"indexes","event_ids","parent_signal_ids","features","body"} else value)
    db.execute("INSERT INTO intelligence_signals("+",".join(columns)+") VALUES("+",".join("?" for _ in columns)+")",values)


def drain_composite(store,identifier,turns=100):
    for _ in range(turns):
        core._composites(store,maximum=8,deadline=time.monotonic()+1)
        with store.control() as db:
            state=db.execute("SELECT * FROM intelligence_composite_state WHERE id=?",(identifier,)).fetchone()
            if state and state["last_seq"]==state["snapshot_seq"] and not state["error"]:
                return
    raise AssertionError("Bounded composite did not complete its durable cohort")


def test_more_than_2000_unrelated_private_signals_do_not_block_public_composite(lab):
    a,_=policy(lab,"A");b,_=policy(lab,"B");seed(lab);tick(lab)
    lab.ingest("a",[{"event_id":"private-noise","index":"private"}]);lab.flush()
    hidden=core.publish(lab,actor(),{"event_ids":["private-noise"],"kind":"atomic","rule_id":"unrelated","rule_revision":1,"features":{},"severity":"info","confidence_grade":"original"})
    with lab.control() as db:
        for n in range(2105):
            clone(db,hidden,"private-noise-"+str(n))
    child=composites(lab,"public-AB",[{"rule_id":a["id"]},{"rule_id":b["id"]}])
    drain_composite(lab,child["id"])
    with lab.control() as db:
        assert db.execute("SELECT qualified FROM intelligence_composite_work WHERE id=?",(child["id"],)).fetchone()[0]==2
        body=json.loads(db.execute("SELECT body FROM intelligence_signals WHERE rule_id=?",(child["id"],)).fetchone()[0])
        assert body["event_ids"]==["event-0","event-1"]
        assert db.execute("SELECT count(*) FROM intelligence_composite_cohort WHERE policy_id=? AND json_extract(body,'$.indexes[0]')='private'",(child["id"],)).fetchone()[0]==0


def test_more_than_2000_relevant_dependent_alternatives_resume_after_restart(lab):
    a,_=policy(lab,"A");policy(lab,"B");seed(lab);tick(lab)
    originals=core.signals(lab,actor(),count=100)["items"]
    anchor=next(s for s in originals if s["rule_id"]==a["id"])
    independent=next(s for s in originals if s["kind"]=="atomic" and s["event_ids"]==["event-1"])
    with lab.control() as db:
        for n in range(2105):
            clone(db,anchor,"dependent-"+str(n).zfill(5),"external-B")
        # The independent choice deliberately sorts after all shared originals.
        independent["event_window"]=copy.deepcopy(anchor["event_window"])
        clone(db,independent,"zz-independent-choice","external-B")
    child=composites(lab,"large-relevant",[{"rule_id":a["id"]},{"rule_id":"external-B"}])
    for _ in range(20):
        core._composites(lab,deadline=time.monotonic()+1)
        with lab.control() as db:
            work=dict(db.execute("SELECT * FROM intelligence_composite_work WHERE id=?",(child["id"],)).fetchone())
        if work["phase"]=="evaluate" and work["examined"]:
            break
    assert work["qualified"]==2107 and work["examined"]>0
    assert json.loads(work["search"]).get("anchor_id")==anchor["id"]
    assert work["phase"]=="evaluate"  # Exhaustion is pending, never false success.
    saved=lab.settings
    lab.close()
    reopened=Store(saved)
    try:
        drain_composite(reopened,child["id"])
        with reopened.control() as db:
            body=json.loads(db.execute("SELECT body FROM intelligence_signals WHERE rule_id=?",(child["id"],)).fetchone()[0])
            assert body["event_ids"]==["event-0","event-1"]
            assert body["evidence_dependency"]["disjoint_original_groups"]==2
            assert "zz-independent-choice" in body["parent_signal_ids"]
            assert db.execute("SELECT examined FROM intelligence_composite_work WHERE id=?",(child["id"],)).fetchone()[0]>2105
    finally:
        reopened.close()


def queued(store,index,amount,created,prefix):
    store.ingest("a",[{"event_id":prefix+str(n),"index":index} for n in range(amount)]);store.flush()
    with store.control() as db:
        db.executemany("INSERT INTO intelligence_ml_jobs VALUES(?,?,?,?,?,'pending',0,NULL,0,?,NULL)",[(prefix+str(n),"a",prefix+str(n),"owner",index,created) for n in range(amount)])


def test_global_16_jobs_in_four_models_do_not_spawn_four_fresh_microbatches(lab,monkeypatch):
    calls=[]
    def compatible(store,who,indexes):
        return [{"id":"model-"+indexes[0],"indexes":indexes}]
    def infer(store,who,events,**kwargs):
        calls.append((kwargs["model_id"],len(events)))
        return {"status":"completed","results":[],"duration_ms":1,"worker_wall_ms":2}
    monkeypatch.setattr(cpu_ml,"compatible_models",compatible);monkeypatch.setattr(cpu_ml,"infer_events",infer)
    now=time.time()
    for index in ("one","two","three","four"):
        queued(lab,index,4,now,index)
    assert core._ml_due(lab,coalesce=True)==0 and calls==[]
    with lab.control() as db:
        assert db.execute("SELECT count(*) FROM intelligence_ml_batch_diagnostics WHERE state='waiting'").fetchone()[0]==4
        db.execute("UPDATE intelligence_ml_jobs SET created=?",(now-6,))
    assert core._ml_due(lab,coalesce=True)==16
    assert sorted(amount for _,amount in calls)==[4,4,4,4]


def test_compatible_cross_index_model_batches_and_other_model_is_served_fairly(lab,monkeypatch):
    calls=[]
    def compatible(store,who,indexes):
        return [{"id":"shared" if indexes[0] in {"one","two"} else "other","indexes":["one","two"] if indexes[0] in {"one","two"} else ["three"]}]
    def infer(store,who,events,**kwargs):
        calls.append((kwargs["model_id"],len(events)))
        return {"status":"completed","results":[]}
    monkeypatch.setattr(cpu_ml,"compatible_models",compatible);monkeypatch.setattr(cpu_ml,"infer_events",infer)
    now=time.time()
    queued(lab,"one",24,now-10,"one");queued(lab,"two",24,now-9,"two");queued(lab,"three",16,now-6,"three")
    assert core._ml_due(lab,coalesce=True)==32 and calls==[("shared",32)]
    assert core._ml_due(lab,coalesce=True)==32 and calls[1]==("other",16) and calls[2]==("shared",16)
    assert core.analysis_slo(lab,{**actor(),"allowed_indexes":["one"]})["model_batches"]==[]


def test_real_phase_clocks_include_atomic_case_completion_and_hide_other_indexes(lab):
    policy(lab,"A",case_adapter={"entity_field":"host","risk_score":40,"severity":"high","cooldown":0})
    seed(lab,stages=("A",));tick(lab)
    slo=core.analysis_slo(lab,actor())
    assert slo["cohort_count"]==1 and not slo["max_eps_measured"]
    row=slo["records"][0]
    assert row["received"]<=row["indexed_at"]<=row["analysis_started_at"]<=row["analysis_completed_at"]
    assert row["first_detection_at"] and row["first_case_at"]
    assert slo["metrics"]["received_to_first_case"]["samples"]==1
    assert slo["metrics"]["sequence_completion"]["missing"]==1
    assert core.analysis_slo(lab,{**actor(),"allowed_indexes":["private"]})["records"]==[]
    with lab.control() as db:
        db.execute("UPDATE intelligence_event_phases SET first_case_at=received-1")
    assert core.analysis_slo(lab,actor())["metrics"]["received_to_first_case"]["clock_reversal"]==1


def test_reviewer_revocation_while_large_capture_pending_excludes_without_completion(lab):
    a,_=policy(lab,"A");policy(lab,"B");seed(lab);tick(lab)
    anchor=next(s for s in core.signals(lab,actor())["items"] if s["rule_id"]==a["id"])
    with lab.control() as db:
        for n in range(2105):
            clone(db,anchor,"revoke-candidate-"+str(n),"external-B")
    child=composites(lab,"revoked-large",[{"rule_id":a["id"]},{"rule_id":"external-B"}])
    core._composites(lab,deadline=time.monotonic()+1)
    with lab.control() as db:
        before=dict(db.execute("SELECT * FROM intelligence_composite_state WHERE id=?",(child["id"],)).fetchone())
        db.execute("UPDATE users SET disabled=1 WHERE name='peer'")
    core._composites(lab,deadline=time.monotonic()+1)
    with lab.control() as db:
        after=dict(db.execute("SELECT * FROM intelligence_composite_state WHERE id=?",(child["id"],)).fetchone())
        assert after["last_seq"]==before["last_seq"]<after["snapshot_seq"] and after["error"]
        assert db.execute("SELECT count(*) FROM intelligence_signals WHERE rule_id=?",(child["id"],)).fetchone()[0]==0
