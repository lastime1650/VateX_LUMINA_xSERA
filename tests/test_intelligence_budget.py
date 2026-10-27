"""Slow immutable-model setup must not starve durable analysis progress."""
import copy
import json
import threading
import time
from contextlib import contextmanager

import pytest

from sapientia import auth, cpu_sequence, intelligence as core, principal
from sapientia.storage import ConflictError, encode
from tests.test_backend_upgrade import actor, lab as _backend_lab
from tests.test_intelligence import composites, policy, seed, tick
from tests.test_intelligence_sequence_shadow import sequence_model as _sequence_model

lab=_backend_lab
sequence_model=_sequence_model


def test_slow_approved_setup_still_advances_capture_and_dfs(lab,monkeypatch):
    a,_=policy(lab,"A");b,_=policy(lab,"B");seed(lab,stages=("A","B"));tick(lab)
    child=composites(lab,"slow-setup",[{"rule_id":a["id"]},{"rule_id":b["id"]}])
    authority=core._authority
    def slow(db,row,**kwargs):
        result=authority(db,row,**kwargs)
        if row["kind"]=="composite":
            time.sleep(.06)
        return result
    monkeypatch.setattr(core,"_authority",slow)
    observations=[]
    for _ in range(8):
        core._composites(lab,deadline=time.monotonic()+.025)
        with lab.control() as db:
            work=dict(db.execute("SELECT * FROM intelligence_composite_work WHERE id=?",(child["id"],)).fetchone())
            observations.append(work)
            body=db.execute("SELECT body FROM intelligence_signals WHERE rule_id=?",(child["id"],)).fetchone()
        if body:
            break
    assert observations[0]["scan_seq"]>0
    assert any(row["examined"]>0 for row in observations)
    assert body and json.loads(body[0])["event_ids"]==["event-0","event-1"]
    assert json.loads(body[0])["evidence_dependency"]["disjoint_original_groups"]==2


def test_observations_skip_unconsumed_composite_parents_and_publish_once_per_owner(lab,monkeypatch):
    a,_=policy(lab,"A");b,_=policy(lab,"B")
    composites(lab,"observation-scope",[{"rule_id":a["id"]},{"rule_id":b["id"]}])
    seed(lab)
    authority=core._authority;published=[]
    def scoped(db,row,**kwargs):
        if row["kind"]=="composite":
            assert kwargs.get("include_parents") is False
        return authority(db,row,**kwargs)
    publish=core.publish_in_transaction
    def counted(store,db,who,data):
        if data["kind"]=="observation":
            published.append(data["event_ids"])
        return publish(store,db,who,data)
    monkeypatch.setattr(core,"_authority",scoped)
    monkeypatch.setattr(core,"publish_in_transaction",counted)
    assert core._outbox(lab,maximum=16,deadline=time.monotonic()+2)==3
    assert published==[["event-0"],["event-1"],["event-2"]]
    with lab.control() as db:
        assert db.execute("SELECT count(*) FROM intelligence_signals WHERE kind='observation'").fetchone()[0]==3
        assert db.execute("SELECT count(*) FROM intelligence_signals WHERE kind='composite'").fetchone()[0]==0


def test_cancelled_turn_does_not_use_minimum_progress_to_execute(lab):
    a,_=policy(lab,"A");b,_=policy(lab,"B");seed(lab);tick(lab)
    child=composites(lab,"cancelled",[{"rule_id":a["id"]},{"rule_id":b["id"]}])
    cancel=threading.Event();cancel.set()
    assert core._composites(lab,cancel=cancel,deadline=time.monotonic()+.1)==0
    with lab.control() as db:
        assert db.execute("SELECT count(*) FROM intelligence_composite_work WHERE id=?",(child["id"],)).fetchone()[0]==0


def test_changed_policy_owner_cannot_use_prior_group_principal(lab,monkeypatch):
    auth.create_user(lab,"successor","Synthetic-password-budget-2026","admin","a")
    saved,_=policy(lab,"A",case_adapter={"entity_field":"host","risk_score":40,"severity":"high","cooldown":0})
    seed(lab,stages=("A",))
    transaction=principal.transaction
    @contextmanager
    def changed(store,who,roles=("admin","analyst","viewer"),*,write=False):
        with transaction(store,who,roles,write=write) as (db,fresh):
            if write and who["name"]=="owner":
                db.execute("UPDATE intelligence_policies SET owner='successor' WHERE id=?",(saved["id"],))
            yield db,fresh
    monkeypatch.setattr(principal,"transaction",changed)
    assert core._outbox(lab,deadline=time.monotonic()+1)==1
    with lab.control() as db:
        assert db.execute("SELECT count(*) FROM intelligence_signals").fetchone()[0]==0
        assert db.execute("SELECT count(*) FROM incidents").fetchone()[0]==0
        assert db.execute("SELECT outcome FROM intelligence_event_phases").fetchone()[0]=="excluded"


def test_1536_source_model_pin_memo_reuses_only_immutable_work_and_rechecks_same_tx_changes(lab,sequence_model,monkeypatch):
    # This is an explicit registry/serialization stress fixture. The additional
    # contexts and padding are not represented as independently trained data.
    model,_,_=sequence_model
    with lab.control() as db:
        row=db.execute("SELECT * FROM cpu_sequence_models WHERE id=?",(model["id"],)).fetchone()
        definition,snapshot=json.loads(row["definition"]),json.loads(row["snapshot"])
        source=db.execute("SELECT * FROM source_registry WHERE id=?",(definition["sources"][0]["id"],)).fetchone()
        contexts=copy.deepcopy(definition["sources"])
        for n in range(1535):
            current=dict(source);current["id"]="stress-source-"+str(n);current["account"]="stress-account-"+str(n)
            raw_definition=json.loads(current["definition"]);raw_definition["account"]=current["account"]
            current["definition"]=encode(raw_definition)
            columns=list(current)
            db.execute("INSERT INTO source_registry("+",".join(columns)+") VALUES("+",".join("?" for _ in columns)+")",[current[name] for name in columns])
            contexts.append({name:current[name] for name in ("id","version","index_name","product","account","realm","owner")})
        assert len(contexts)==1536
        definition["sources"]=contexts
        definition["serialization_stress_fixture"]="x"*(9*1024*1024)
        digest=cpu_sequence._digest({"definition":definition,"snapshot":snapshot})
        db.execute("UPDATE cpu_sequence_models SET definition=?,digest=? WHERE id=?",(encode(definition),digest,model["id"]))
    calls=[];real_digest=core.release_manifest.digest
    def count_digest(value):
        if isinstance(value,dict) and "serialization_stress_fixture" in value:
            calls.append(1)
        return real_digest(value)
    monkeypatch.setattr(core.release_manifest,"digest",count_digest)
    with principal.transaction(lab,actor(),write=True) as (db,fresh),core._authority_memo(db) as memo:
        pin=core._input_model_pin(lab,db,fresh,"ml:sequence:"+model["id"],require_review=False,memo=memo)
        assert pin["digest"]==digest
        assert core._input_model_pin(lab,db,fresh,"ml:sequence:"+model["id"],require_review=False,memo=memo)==pin
        assert calls==[]  # The authoritative loader's digest is reused too.
        db.execute("UPDATE source_registry SET state='revoked' WHERE id=?",(contexts[-1]["id"],))
        with pytest.raises(PermissionError,match="source unavailable"):
            core._input_model_pin(lab,db,fresh,"ml:sequence:"+model["id"],require_review=False,memo=memo)
        db.execute("UPDATE source_registry SET state='active' WHERE id=?",(contexts[-1]["id"],))
        changed=copy.deepcopy(definition);changed["serialization_stress_fixture"]="changed"
        db.execute("UPDATE cpu_sequence_models SET definition=? WHERE id=?",(encode(changed),model["id"]))
        with pytest.raises(ConflictError,match="hash mismatch"):
            core._input_model_pin(lab,db,fresh,"ml:sequence:"+model["id"],require_review=False,memo=memo)
    assert memo["pins"]=={}
