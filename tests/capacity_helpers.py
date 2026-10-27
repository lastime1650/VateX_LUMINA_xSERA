"""Real capacity-tagged purge journal in an owned synthetic Store.

Tests choose a bounded original cohort so disk pressure simulation never touches
other fixtures. This uses the product's planner and physical recovery path;
permanent recording, Case evidence protection and all holds remain enabled.
"""
import json
import time
import uuid

from sapientia import pressure_retention


def tag_intent(db, identifier):
    """Mark an injected test intent as capacity cleanup, never time expiry."""
    version=db.execute("SELECT version FROM record_management_policy WHERE singleton=1").fetchone()[0]
    db.execute("INSERT INTO capacity_retention_intents VALUES(?,?,?,?,?)",(identifier,"test-pressure-"+identifier,version,1,time.time()))


def purge(store, cutoff=None, event_ids=None, after_delete=None, plan_only=False):
    cutoff=time.time()+.01 if cutoff is None else cutoff
    with store.flush_lock,store.segment_lock.write(),store.write_lock:
        removed=store._apply_retention_locked() if not plan_only else 0
        with store.control(local=True) as db:
            policy=db.execute("SELECT version,definition FROM record_management_policy WHERE singleton=1").fetchone()
        definition=json.loads(policy["definition"])
        rows=store.analytics.execute("SELECT received,tenant,event_id FROM events_all WHERE received<? ORDER BY received,tenant,event_id",[cutoff]).fetchall()
        if event_ids is not None:
            wanted=set(event_ids)
            rows=[r for r in rows if r[2] in wanted]
        state={"policy_version":policy["version"],"cycle_id":"test-pressure-"+uuid.uuid4().hex,"cutoff":cutoff,"protected_scanned":0,"scanned":0}
        if rows:
            pressure_retention._plan(store,state,rows,definition)
        return removed if plan_only else removed+store._apply_retention_locked(after_delete=after_delete)
