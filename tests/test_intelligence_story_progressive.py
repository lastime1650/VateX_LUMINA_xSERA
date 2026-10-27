"""Indexed explicit identities and recovery of a large late-parent cohort."""

import json
import time

from sapientia import connector_runtime,intelligence as core,intelligence_story_reconcile as reconcile,principal,source_registry
from sapientia.storage import Store,encode
from tests.test_backend_upgrade import actor,lab as _backend_lab
from tests.test_intelligence_story_reconcile import setup,apply

lab=_backend_lab


def test_parent_lookup_uses_expression_index_after_2105_other_device_incarnations(lab,monkeypatch):
    _,child,parent,node=setup(lab,monkeypatch)
    with lab.control() as db:
        original=db.execute("SELECT body FROM intelligence_story_nodes WHERE id=?",(node,)).fetchone()[0]
        projection=json.loads(original)["projection"]
        for n in range(2105):
            value=json.loads(original);value["projection"]["device"]["uid"]="other-"+str(n)
            db.execute("INSERT INTO intelligence_story_nodes VALUES(?,?,?,?,?,?,?)",("other-device-"+str(n),"a",parent["story_id"],"process",'["public"]','[]',encode(value)))
        plan=" ".join(row[3] for row in db.execute("EXPLAIN QUERY PLAN SELECT id FROM intelligence_story_nodes WHERE tenant=? AND kind='process' AND json_extract(body,'$.projection.source_id')=? AND json_extract(body,'$.projection.account')=? AND json_extract(body,'$.projection.realm')=? AND json_extract(body,'$.projection.process.guid')=? AND json_extract(body,'$.projection.process.start_identity')=? AND json_extract(body,'$.projection.device.uid')=? AND json_extract(body,'$.projection.device.boot_id')=?",("a",projection["source_id"],projection["account"],projection["realm"],"P","parent-incarnation","device","boot")))
        assert "intelligence_story_parent_identity" in plan
    apply(lab,parent["story_id"],node)
    with lab.control() as db:
        assert reconcile.resolve(db,"a",child["story_id"])==parent["story_id"]
        assert db.execute("SELECT body FROM intelligence_story_nodes WHERE id=?",(node,)).fetchone()[0]==original


def test_hidden_members_prevent_alias_resolution_even_when_story_header_is_public(lab,monkeypatch):
    _,child,parent,node=setup(lab,monkeypatch)
    apply(lab,parent["story_id"],node)
    with lab.control() as db:
        db.execute("UPDATE intelligence_story_nodes SET indexes='[\"private\",\"public\"]' WHERE id=?",(node,))
        assert reconcile.current(db,{**actor(),"allowed_indexes":["public"]},child["story_id"]) is None
        assert reconcile.current(db,actor(),child["story_id"])==parent["story_id"]


def test_more_than_1000_actual_late_children_continue_after_restart_without_losing_members(lab):
    source=source_registry.save(lab,actor(),{"index":"public","product":"json","account":"asset","realm":"lab","credential_ref":"env:SAPIENTIA_CONNECTOR_LAB","version":0})
    at=time.time()-100
    events=[{"event_id":"child-"+str(n),"event_time":at+1+n/10000,"host":"asset","raw":{"xdr":{"data":{"event":{"action":"process_created"},"host":{"id":"device","boot_id":"boot"},"process":{"guid":"C"+str(n),"start_identity":"child-birth-"+str(n),"parent":{"guid":"P","start_identity":"parent-birth"}}}}}} for n in range(1030)]
    connector_runtime.intake(lab,actor(),source["id"],{"version":1,"events":events[:1000],"cursor":"children-1","checkpoint_version":0})
    connector_runtime.intake(lab,actor(),source["id"],{"version":1,"events":events[1000:],"cursor":"children-2","checkpoint_version":1})
    while lab.flush():
        pass
    records=lab.analytics_query("SELECT event_id,event_time,received,source,sourcetype,host,severity,message,raw,index_name FROM events_all WHERE tenant='a' AND index_name='public' ORDER BY event_id",[],max_rows=1030)["rows"]
    assert len(records)==1030
    # Build the exact ordinary Story publisher path from actual indexed originals.
    # Batches keep writer reservations bounded; the parent genuinely arrives later.
    for position in range(0,len(records),64):
        with lab.segment_lock.read(deadline=time.monotonic()+3),principal.transaction(lab,actor(),write=True) as (db,fresh):
            for value in records[position:position+64]:
                record={**value,"raw":json.loads(value["raw"])}
                record["admission_digest"]=db.execute("SELECT digest FROM receipts WHERE tenant='a' AND event_id=?",(record["event_id"],)).fetchone()[0]
                core._story(db,lab,fresh,record,core._projection(db,"a",record))
    parent={"event_id":"late-parent","event_time":at,"host":"asset","raw":{"xdr":{"data":{"event":{"action":"process_created"},"host":{"id":"device","boot_id":"boot"},"process":{"guid":"P","start_identity":"parent-birth"}}}}}
    connector_runtime.intake(lab,actor(),source["id"],{"version":1,"events":[parent],"cursor":"parent","checkpoint_version":2});lab.flush()
    published=core.publish(lab,actor(),{"event_ids":["late-parent"],"kind":"atomic","rule_id":"late-parent","rule_revision":1,"features":{},"severity":"info","confidence_grade":"source_reported"})
    with lab.control() as db:
        assert db.execute("SELECT count(*) FROM intelligence_story_aliases").fetchone()[0]==128
        assert db.execute("SELECT count(*) FROM intelligence_story_reconcile_jobs WHERE state='pending'").fetchone()[0]==1
    settings=lab.settings;lab.close();reopened=Store(settings)
    try:
        for _ in range(12):
            reconcile.run_due(reopened,budget=2,max_runs=2)
        with reopened.control() as db:
            assert db.execute("SELECT count(*) FROM intelligence_story_aliases").fetchone()[0]==1030
            assert db.execute("SELECT count(*) FROM intelligence_story_reconcile_jobs WHERE state='pending'").fetchone()[0]==0
            assert db.execute("SELECT count(*) FROM intelligence_story_nodes WHERE story_id=?",(published["story_id"],)).fetchone()[0]==2062
            assert db.execute("SELECT count(*) FROM intelligence_story_edges WHERE relation='reported_parent'").fetchone()[0]==1030
            assert db.execute("SELECT count(DISTINCT event_id) FROM intelligence_story_history WHERE tenant='a'").fetchone()[0]==1031
    finally:
        reopened.close()
