"""Server admission backlog and final derived tails preserve exact evidence."""
import json
import time

import pytest

from sapientia import access, connector_runtime, intelligence as core, source_registry
from sapientia.storage import Store, encode
from tests.capacity_helpers import purge
from tests.test_backend_upgrade import actor, lab as _backend_lab
from tests.test_intelligence import composites, policy, seed
from tests.test_intelligence_progressive import drain_composite

lab=_backend_lab


def arrange(store,monkeypatch,case=False):
    clock=[time.time()+1]
    monkeypatch.setattr(core.time,"time",lambda:clock[0])
    a,value=policy(store,"A",window=900)
    b,_=policy(store,"B",window=900)
    child=composites(store,"late-AB",[{"rule_id":a["id"]},{"rule_id":b["id"]}],window=900,
        **({"case_adapter":{"entity_field":"host","risk_score":60,"severity":"high","mitre":[],"cooldown":0}} if case else {}))
    source,events=seed(store,stages=("A","B"))
    assert core._outbox(store,maximum=1)==1
    core._ml_due(store,maximum=32)
    drain_composite(store,child["id"])
    with store.control() as db:
        row=db.execute("SELECT * FROM intelligence_policies WHERE id=?",(child["id"],)).fetchone()
        definition=json.loads(row["definition"])
        before=dict(db.execute("SELECT * FROM intelligence_composite_state WHERE id=?",(child["id"],)).fetchone())
        assert before["last_seq"]==before["snapshot_seq"]
        assert db.execute("SELECT count(*) FROM intelligence_signals WHERE rule_id=?",(child["id"],)).fetchone()[0]==0
    return clock,a,value,b,child,source,events,definition,before


def finish_originals(store):
    assert core._outbox(store,maximum=32)>=1
    core._ml_due(store,maximum=32)
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM intelligence_event_outbox WHERE seq>(SELECT cursor FROM intelligence_cursors WHERE worker='events')").fetchone()[0]==0
        assert db.execute("SELECT count(*) FROM intelligence_ml_jobs WHERE state='pending'").fetchone()[0]==0


def test_more_than_900s_pending_then_final_tail_creates_exact_case(lab,monkeypatch):
    clock,_,_,_,child,_,_,definition,before=arrange(lab,monkeypatch,case=True)
    admitted=clock[0]
    clock[0]+=901
    with lab.control() as db:
        assert core._candidate_cutoff(db,"a",definition,child["id"],before["last_seq"])==pytest.approx(admitted-900)
        assert "event-0" in core.protected_ids(db,"a",["event-0"])
    finish_originals(lab)
    # No queue remains. NEW late B's original receipt, not its reported event
    # timestamp or a permanent extension, keeps A in the next frozen cohort.
    with lab.control() as db:
        assert core._candidate_cutoff(db,"a",definition,child["id"],before["last_seq"])==pytest.approx(admitted-900)
    drain_composite(lab,child["id"])
    with lab.control() as db:
        body=json.loads(db.execute("SELECT body FROM intelligence_signals WHERE rule_id=?",(child["id"],)).fetchone()[0])
        assert body["event_ids"]==["event-0","event-1"]
        assert body["evidence_dependency"]["disjoint_original_groups"]==2
        assert body["event_window"]["end"]-body["event_window"]["start"]<=900
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0]==1
        contribution=json.loads(db.execute("SELECT evidence FROM risk_contributions").fetchone()[0])
        assert {e["event_id"] for step in contribution["steps"] for e in step["events"]}=={"event-0","event-1"}
        state=db.execute("SELECT * FROM intelligence_composite_state WHERE id=?",(child["id"],)).fetchone()
        assert state["window_end"]==pytest.approx(admitted)


def test_pending_and_final_tail_survive_real_pressure_then_expire_after_completion(lab,monkeypatch):
    clock,_,_,_,child,_,_,definition,before=arrange(lab,monkeypatch)
    admitted=clock[0]
    clock[0]+=901
    assert purge(lab,event_ids=["event-0"])==0
    finish_originals(lab)
    # The cursor committed, but composite capture has not started yet.
    assert purge(lab,event_ids=["event-0"])==0
    with lab.control() as db:
        assert core.protected_ids(db,"a",["event-0"])=={"event-0"}
        assert db.execute("SELECT count(*) FROM receipts WHERE event_id='event-0'").fetchone()[0]==1
    drain_composite(lab,child["id"])
    clock[0]=admitted+1802
    with lab.control() as db:
        state=db.execute("SELECT * FROM intelligence_composite_state WHERE id=?",(child["id"],)).fetchone()
        assert state["last_seq"]==state["snapshot_seq"]
        assert core._candidate_cutoff(db,"a",definition,child["id"],state["last_seq"])==pytest.approx(clock[0]-900)
        assert core.protected_ids(db,"a",["event-0"])==set()
    assert purge(lab,event_ids=["event-0"])==1
    with lab.control() as db:
        assert db.execute("SELECT count(*) FROM receipts WHERE event_id='event-0'").fetchone()[0]==0


def test_restart_between_last_original_commit_and_next_capture(lab,monkeypatch):
    clock,_,_,_,child,_,_,_,_=arrange(lab,monkeypatch)
    clock[0]+=901
    finish_originals(lab)
    settings=lab.settings
    lab.close()
    reopened=Store(settings)
    try:
        drain_composite(reopened,child["id"])
        with reopened.control() as db:
            body=json.loads(db.execute("SELECT body FROM intelligence_signals WHERE rule_id=?",(child["id"],)).fetchone()[0])
            assert body["event_ids"]==["event-0","event-1"]
            assert not db.execute("SELECT error FROM intelligence_composite_state WHERE id=?",(child["id"],)).fetchone()[0]
    finally:
        reopened.close()


@pytest.mark.parametrize("revocation",["source","reviewer","owner_scope","parent_revision"])
def test_late_tail_never_bypasses_fresh_authority(lab,monkeypatch,revocation):
    clock,a,value,_,child,source,_,_,_=arrange(lab,monkeypatch,case=True)
    clock[0]+=901
    finish_originals(lab)
    if revocation=="source":
        source_registry.revoke(lab,actor(),source["id"],1)
    elif revocation=="reviewer":
        with lab.control() as db:
            db.execute("UPDATE users SET disabled=1 WHERE name='peer'")
    elif revocation=="owner_scope":
        access.set_for_user(lab,actor(),"owner",["private"])
    else:
        core.save_policy(lab,actor(),{**value,"version":1},a["id"])
    for _ in range(3):
        core._composites(lab,deadline=time.monotonic()+1)
    with lab.control() as db:
        assert db.execute("SELECT count(*) FROM intelligence_signals WHERE rule_id=?",(child["id"],)).fetchone()[0]==0
        assert db.execute("SELECT count(*) FROM risk_contributions").fetchone()[0]==0


def test_old_reported_timestamp_on_new_admission_does_not_extend_ttl(lab,monkeypatch):
    clock=[time.time()+1]
    monkeypatch.setattr(core.time,"time",lambda:clock[0])
    a,_=policy(lab,"A",window=900);b,_=policy(lab,"B",window=900)
    child=composites(lab,"old-reported",[{"rule_id":a["id"]},{"rule_id":b["id"]}],window=900)
    source,events=seed(lab,stages=("A",))
    core._outbox(lab,maximum=32);core._ml_due(lab,maximum=32)
    drain_composite(lab,child["id"])
    clock[0]+=901
    event={**events[0],"event_id":"new-ancient-event","event_time":clock[0]-31536000,
           "raw":{**events[0]["raw"],"stage":"B"}}
    connector_runtime.intake(lab,actor(),source["id"],{"version":1,"events":[event],"cursor":"new-admission","checkpoint_version":1})
    lab.flush();finish_originals(lab)
    with lab.control() as db:
        row=db.execute("SELECT definition FROM intelligence_policies WHERE id=?",(child["id"],)).fetchone()
        definition=json.loads(row[0])
        state=db.execute("SELECT last_seq FROM intelligence_composite_state WHERE id=?",(child["id"],)).fetchone()[0]
        assert core._candidate_cutoff(db,"a",definition,child["id"],state)==pytest.approx(clock[0]-900)
    drain_composite(lab,child["id"])
    with lab.control() as db:
        assert db.execute("SELECT count(*) FROM intelligence_signals WHERE rule_id=?",(child["id"],)).fetchone()[0]==0


def test_private_and_foreign_pending_admission_cannot_extend_public_cutoff(lab,monkeypatch):
    clock,_,_,_,child,_,_,definition,_=arrange(lab,monkeypatch)
    admitted=clock[0]
    finish_originals(lab);drain_composite(lab,child["id"])
    policy(lab,"private",indexes=["private"],window=900)
    lab.ingest("a",[{"event_id":"private-pending","index":"private"}]);lab.flush()
    # Use a genuine foreign admission and its receipt to fixture an unfinished
    # foreign outbox. The scoped cutoff must not inspect or inherit that age.
    lab.ingest("b",[{"event_id":"foreign-pending","index":"public"}]);lab.flush()
    with lab.control() as db:
        db.execute("INSERT OR IGNORE INTO intelligence_event_outbox(id,tenant,event_id,index_name,received) SELECT 'foreign-fixture','b',event_id,'public',received FROM receipts WHERE tenant='b' AND event_id='foreign-pending'")
    clock[0]=admitted+1802
    with lab.control() as db:
        last=db.execute("SELECT last_seq FROM intelligence_composite_state WHERE id=?",(child["id"],)).fetchone()[0]
        assert core._candidate_cutoff(db,"a",definition,child["id"],last)==pytest.approx(clock[0]-900)
        assert core.protected_ids(db,"a",["event-0"])==set()


def test_model_queue_watermark_uses_exact_scope_and_server_receipts(lab,monkeypatch):
    clock,_,_,b,child,_,_,definition,_=arrange(lab,monkeypatch)
    admitted=clock[0]
    finish_originals(lab);drain_composite(lab,child["id"])
    clock[0]+=1802
    # This fixtures scheduling records only, and makes no CPU inference claim.
    model_definition={**definition,"inputs":[{"kind":"ml","rule_id":"ml:sequence:expected-model"},{"rule_id":b["id"]}]}
    with lab.control() as db:
        last=db.execute("SELECT coalesce(max(seq),0) FROM intelligence_signals").fetchone()[0]
        db.execute("INSERT INTO intelligence_sequence_jobs VALUES(?,?,?,?,?,?,?,'pending',NULL,NULL,NULL,NULL)",("queue-foreign-scope","expected-model","a","owner",encode(["public","private"]),encode(["event-0"]),clock[0]))
        db.execute("INSERT INTO intelligence_sequence_jobs VALUES(?,?,?,?,?,?,?,'pending',NULL,NULL,NULL,NULL)",("queue-other-model","other-model","a","owner",encode(["public"]),encode(["event-0"]),clock[0]))
        assert core._candidate_cutoff(db,"a",model_definition,child["id"],last)==pytest.approx(clock[0]-900)
        db.execute("INSERT INTO intelligence_sequence_jobs VALUES(?,?,?,?,?,?,?,'running',?,NULL,NULL,NULL)",("queue-expected","expected-model","a","owner",encode(["public"]),encode(["event-0"]),clock[0],clock[0]))
        assert core._candidate_cutoff(db,"a",model_definition,child["id"],last)==pytest.approx(admitted-900)
        db.execute("UPDATE intelligence_sequence_jobs SET state='completed' WHERE id='queue-expected'")
        assert core._candidate_cutoff(db,"a",model_definition,child["id"],last)==pytest.approx(clock[0]-900)
