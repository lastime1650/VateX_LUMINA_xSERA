"""Bounded immutable raw-original manifests for multi-day CPU investigations."""

import json
import time
import uuid

from . import migrations, principal
from . import research_fusion_v2 as fusion
from .research_behavior_graph import digest
from .storage import CapacityError, ConflictError, encode

MAX_CACHE=4096
MAX_SNAPSHOT=1024
MAX_BYTES=8*1024*1024


def initialize(store):
    migrations.apply_store(store,"research_horizon",[
        "CREATE TABLE IF NOT EXISTS research_horizon_cache(model_id TEXT NOT NULL,tenant TEXT NOT NULL,event_id TEXT NOT NULL,index_name TEXT NOT NULL,event_time REAL NOT NULL,received REAL NOT NULL,host_key TEXT NOT NULL,proof TEXT NOT NULL,PRIMARY KEY(model_id,event_id))",
        "CREATE INDEX IF NOT EXISTS research_horizon_cache_scope ON research_horizon_cache(tenant,model_id,event_time)",
        "CREATE TABLE IF NOT EXISTS research_horizon_snapshots(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,model_id TEXT NOT NULL,run_id TEXT NOT NULL,created REAL NOT NULL,indexes TEXT NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL,state TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS research_horizon_snapshot_scope ON research_horizon_snapshots(tenant,model_id,created)",
    ])


def _sample(rows,limit):
    rows=sorted(rows,key=lambda r:(r["event_time"],r["event_id"]))
    if len(rows)<=limit:return rows
    if limit<=0:return []
    if limit==1:return rows[-1:]
    return [rows[round(i*(len(rows)-1)/(limit-1))] for i in range(limit)]


def prepare(store,actor,model,records):
    """Select references first; all selected raw inputs are then re-read and pinned."""
    from . import research_behavior as research
    mandatory=set(records);hosts={fusion.host_key(r) for r in records.values()}-{None}
    at=max(r["event_time"] for r in records.values())
    with store.control() as db:
        cached=[dict(r) for r in db.execute("SELECT * FROM research_horizon_cache WHERE tenant=? AND model_id=? AND event_time>=? AND host_key IN (SELECT value FROM json_each(?)) ORDER BY event_time,event_id LIMIT ?",(actor["tenant"],model["id"],at-604800,encode(sorted(hosts)),MAX_CACHE)) if r["event_id"] not in mandatory]
    future=[r for r in cached if r["event_time"]>at];guards={}
    for candidate in future:
        # One real raw watermark per host preserves conservative late-event
        # suppression. Such future-reported rows never enter positive windows.
        guards[candidate["host_key"]]=candidate
    cached=[r for r in cached if r["event_time"]<=at]
    buckets=[[],[],[]]
    for row in cached:
        age=max(0,at-row["event_time"]);buckets[0 if age<=3600 else 1 if age<=86400 else 2].append(row)
    selected=list(guards.values())[:32]
    available=MAX_SNAPSHOT-len(records)-len(selected);quotas=[available//2,available//4,available-available//2-available//4]
    sampled=[]
    for bucket,quota in zip(buckets,quotas):sampled.extend(_sample(bucket,quota))
    chosen={r["event_id"] for r in sampled}
    remaining=[r for r in cached if r["event_id"] not in chosen]
    sampled.extend(_sample(remaining,available-len(sampled)));selected.extend(sampled)
    accepted=dict(records);excluded=[];size=sum(len(encode(r).encode()) for r in records.values())
    if size>MAX_BYTES:raise CapacityError("Current research evidence exceeds long snapshot byte budget")
    for offset in range(0,len(selected),MAX_SNAPSHOT):
        batch=selected[offset:offset+MAX_SNAPSHOT]
        try:loaded=research._originals(store,actor,[r["event_id"] for r in batch])
        except (KeyError,PermissionError,ConflictError):
            loaded={}
            for candidate in batch:
                try:loaded.update(research._originals(store,actor,[candidate["event_id"]]))
                except (KeyError,PermissionError,ConflictError) as exc:excluded.append({"event_id":candidate["event_id"],"reason":str(exc)[:180]})
        expected={r["event_id"]:json.loads(r["proof"]) for r in batch}
        for eid,record in loaded.items():
            if research._proofs({eid:record})[0]!=expected[eid]:
                excluded.append({"event_id":eid,"reason":"Historical original/source epoch changed"});continue
            cost=len(encode(record).encode())
            if size+cost>MAX_BYTES:
                excluded.append({"event_id":eid,"reason":"Bounded 8 MiB raw snapshot capacity"});continue
            accepted[eid]=record;size+=cost
    snapshot_id="RHS-"+uuid.uuid4().hex
    proof=research._proofs(accepted)
    span=max(r["event_time"] for r in accepted.values())-min(r["event_time"] for r in accepted.values())
    body={"schema":"xsera.research-long-raw.v1","id":snapshot_id,"tenant":actor["tenant"],"owner":actor["name"],"model_id":model["id"],
        "model_digest":model["digest"],"model_revision":model["revision"],"reviewed_at":model["reviewed"],"mode":model["review_mode"],
        "indexes":sorted({r["index_name"] for r in accepted.values()}),"event_ids":sorted(accepted),"originals":proof,
        "coverage":{"horizons_seconds":list(fusion.HORIZONS),"selected_originals":len(accepted),"available_cached_candidates":len(cached)+len(records)+len(guards),
            "coverage_saturated":len(cached)+len(records)+len(guards)>MAX_SNAPSHOT or bool(excluded),"observed_span_seconds":span,
            "future_watermark_guards":sum(r["event_id"] in accepted for r in guards.values()),"future_context_excluded":len(future)-sum(r["event_id"] in accepted for r in guards.values()),"future_guard_use":"suppression only; per-current positive windows exclude future reported timestamps",
            "raw_snapshot_bytes":size,"max_originals":MAX_SNAPSHOT,"cache_max_originals":MAX_CACHE,
            "selection":"deterministic stratified time sample when capped; score describes selected observed originals only",
            "source_completeness_attested":False,"full_population_coverage_claimed":False,"excluded":excluded[:128]},
        "feature_contract_digest":json.loads(model["snapshot"])["fusion"]["contract_digest"]}
    descriptor={"snapshot_id":snapshot_id,"digest":digest(body),"count":len(proof),"indexes":body["indexes"]}
    return {"body":body,"descriptor":descriptor,"records":accepted}


def commit(store,db,actor,model,run,prepared,current_ids,*,observe=False):
    from . import evidence_scope
    from . import research_behavior as research
    records=prepared["records"];body=prepared["body"];descriptor=prepared["descriptor"]
    evidence_scope.recheck(db,actor,records)
    research._verify_sources(db,actor,research._proofs(records),required=run["mode"]=="live")
    db.execute("INSERT INTO research_horizon_snapshots VALUES(?,?,?,?,?,?,?,?,?,?)",(body["id"],actor["tenant"],actor["name"],model["id"],run["id"],run["created"],encode(body["indexes"]),encode(body),descriptor["digest"],"retained"))
    db.executemany("INSERT OR IGNORE INTO record_case_evidence_refs VALUES(?,?,?,?)",[(actor["tenant"],eid,"research_long_snapshot",body["id"]) for eid in body["event_ids"]])
    # Invalid historical authority must not repeatedly poison otherwise valid
    # current work. Capacity sampling exclusions remain cached for later views.
    for exclusion in body["coverage"]["excluded"]:
        if exclusion["reason"]!="Bounded 8 MiB raw snapshot capacity":
            eid=exclusion["event_id"]
            db.execute("DELETE FROM research_horizon_cache WHERE tenant=? AND model_id=? AND event_id=?",(actor["tenant"],model["id"],eid))
            db.execute("DELETE FROM record_case_evidence_refs WHERE tenant=? AND kind='research_long_cache' AND record_id=? AND event_id=?",(actor["tenant"],model["id"],eid))
    for eid in current_ids if observe else []:
        record=records[eid]
        result=next(r for r in run["results"] if r["event_id"]==eid)
        if not record.get("source_authority") or not fusion.host_key(record) or result["fusion"]["evidence"]["late_event"]:continue
        db.execute("INSERT OR IGNORE INTO research_horizon_cache VALUES(?,?,?,?,?,?,?,?)",(model["id"],actor["tenant"],eid,record["index_name"],record["event_time"],record["received"],fusion.host_key(record),encode(research._proofs({eid:record})[0])))
        db.execute("INSERT OR IGNORE INTO record_case_evidence_refs VALUES(?,?,?,?)",(actor["tenant"],eid,"research_long_cache",model["id"]))
    prune_cache(db,actor["tenant"],model["id"],run["created"])


def prune_cache(db,tenant,model_id,now):
    end=db.execute("SELECT max(event_time) FROM research_horizon_cache WHERE tenant=? AND model_id=?",(tenant,model_id)).fetchone()[0]
    if end is None:return
    obsolete=[r[0] for r in db.execute("SELECT event_id FROM research_horizon_cache WHERE tenant=? AND model_id=? AND (event_time<? OR received<?)",(tenant,model_id,end-604800,now-8*86400))]
    obsolete += [r[0] for r in db.execute("SELECT event_id FROM research_horizon_cache WHERE tenant=? AND model_id=? ORDER BY event_time DESC,event_id LIMIT -1 OFFSET ?",(tenant,model_id,MAX_CACHE))]
    for eid in set(obsolete):
        db.execute("DELETE FROM research_horizon_cache WHERE tenant=? AND model_id=? AND event_id=?",(tenant,model_id,eid))
        db.execute("DELETE FROM record_case_evidence_refs WHERE tenant=? AND kind='research_long_cache' AND record_id=? AND event_id=?",(tenant,model_id,eid))


def replay(store,db,actor,run,*,memo=None):
    from . import research_behavior as research
    descriptor=run.get("long_evidence")
    if not isinstance(descriptor,dict) or set(descriptor)!={"snapshot_id","digest","count","indexes"}:raise ConflictError("Exact long evidence manifest required")
    row=db.execute("SELECT * FROM research_horizon_snapshots WHERE tenant=? AND id=?",(actor["tenant"],descriptor["snapshot_id"])).fetchone()
    if not row or row["state"]!="retained" or row["run_id"]!=run["id"]:raise ConflictError("Long raw manifest unavailable")
    body=json.loads(row["body"])
    if digest(body)!=descriptor["digest"] or row["digest"]!=descriptor["digest"] or len(body["originals"])!=descriptor["count"] or body["indexes"]!=descriptor["indexes"]:
        raise ConflictError("Long manifest digest/ancestry differs")
    if (not 1<=len(body["event_ids"])<=MAX_SNAPSHOT or len(set(body["event_ids"]))!=len(body["event_ids"])
        or body["model_id"]!=run["model_id"] or body["model_digest"]!=run["model_digest"] or body["model_revision"]!=run["model_revision"]
        or body["reviewed_at"]!=run["reviewed_at"] or body["mode"]!=run["mode"]
        or body["feature_contract_digest"] not in fusion.COMPATIBLE_CONTRACTS
        or body["feature_contract_digest"]!=run.get("fusion_context",{}).get("input_contract_digest")
        or not principal.contains(actor["allowed_indexes"],body["indexes"])):
        raise ConflictError("Long manifest model/source epoch binding differs")
    # Current receipts/ACL/source pins are deliberately re-read even when pure
    # feature calculations are memoized by the surrounding transaction.
    records=research._originals(store,actor,body["event_ids"],db=db)
    if research._proofs(records)!=body["originals"]:raise ConflictError("Long raw originals changed or expired")
    research._verify_sources(db,actor,body["originals"],required=True)
    return records,body


def cleanup(store,now=None,maximum=4):
    now=time.time() if now is None else now;compacted=0
    with store.control() as db:
        rows=db.execute("SELECT h.*,r.mode,r.body AS run_body FROM research_horizon_snapshots h JOIN research_behavior_runs r ON r.id=h.run_id WHERE h.state='retained' AND NOT(r.mode='live' AND json_extract(r.body,'$.decision.anomaly')=1) AND NOT EXISTS(SELECT 1 FROM policies p WHERE p.tenant=h.tenant AND p.hold=1) AND NOT EXISTS(SELECT 1 FROM record_case_evidence_refs e WHERE e.tenant=h.tenant AND e.kind IN ('bookmark','contribution') AND e.event_id IN (SELECT value FROM json_each(h.body,'$.event_ids'))) AND (h.created<? OR (SELECT count(*) FROM research_horizon_snapshots n WHERE n.model_id=h.model_id AND n.state='retained' AND n.created>h.created)>=128) ORDER BY h.created LIMIT ?",(now-86400,maximum)).fetchall()
        for row in rows:
            run=json.loads(row["run_body"])
            hold=db.execute("SELECT hold FROM policies WHERE tenant=?",(row["tenant"],)).fetchone()
            if (hold and hold[0]) or (row["mode"]=="live" and run["decision"]["anomaly"]):continue
            body=json.loads(row["body"])
            if db.execute("SELECT 1 FROM record_case_evidence_refs WHERE tenant=? AND kind IN ('bookmark','contribution') AND event_id IN (SELECT value FROM json_each(?)) LIMIT 1",(row["tenant"],encode(body["event_ids"]))).fetchone():continue
            summary={"schema":body["schema"],"compacted":True,"original_manifest_digest":row["digest"],"originals_digest":digest(body["originals"]),"count":len(body["event_ids"]),"indexes":body["indexes"],"coverage":body["coverage"]}
            db.execute("UPDATE research_horizon_snapshots SET state='compacted',body=? WHERE id=?",(encode(summary),row["id"]))
            db.execute("DELETE FROM record_case_evidence_refs WHERE tenant=? AND kind='research_long_snapshot' AND record_id=?",(row["tenant"],row["id"]))
            compacted+=1
        for row in db.execute("SELECT DISTINCT tenant,model_id FROM research_horizon_cache LIMIT 64").fetchall():prune_cache(db,row["tenant"],row["model_id"],now)
    return {"compacted":compacted,"maximum_cached_originals_per_model":MAX_CACHE,"maximum_raw_originals_per_snapshot":MAX_SNAPSHOT}


def release_retired_cache(db,tenant,model_id):
    db.execute("DELETE FROM research_horizon_cache WHERE tenant=? AND model_id=?",(tenant,model_id))
    db.execute("DELETE FROM record_case_evidence_refs WHERE tenant=? AND kind='research_long_cache' AND record_id=?",(tenant,model_id))
