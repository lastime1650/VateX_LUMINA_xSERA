"""Current Story aliases for explicitly reported late parent incarnations.

Signal bodies and frozen comparison snapshots preserve the Story ID known at
their creation. Current joins follow aliases after complete ACL checks. Story
reconciliation never merges Cases or changes frozen response approvals.
"""

import json
import time
import uuid

from . import identity_resolver, principal, release_manifest
from .storage import CapacityError, ConflictError, encode

MAX_NODES = 1000
MAX_ALIASES = 64


def resolve(db, tenant, identifier):
    """Resolve current ownership without rewriting the historical identifier."""
    seen = set()
    for _ in range(MAX_ALIASES):
        if identifier in seen:
            raise ConflictError("Story alias cycle requires repair")
        seen.add(identifier)
        row = db.execute("SELECT target_id FROM intelligence_story_aliases WHERE tenant=? AND source_id=?", (tenant, identifier)).fetchone()
        if not row:
            return identifier
        identifier = row["target_id"]
    raise CapacityError("Story alias chain exceeds 64 identities")


def current(db, actor, identifier):
    seen=set()
    for _ in range(MAX_ALIASES):
        if identifier in seen:
            raise ConflictError("Story alias cycle requires repair")
        seen.add(identifier)
        row=db.execute("SELECT indexes FROM intelligence_stories WHERE tenant=? AND id=?",(actor["tenant"],identifier)).fetchone()
        if not row or not principal.contains(actor["allowed_indexes"],json.loads(row["indexes"])) or not _complete_graph(db,actor,identifier):
            return None
        alias=db.execute("SELECT target_id,basis FROM intelligence_story_aliases WHERE tenant=? AND source_id=?",(actor["tenant"],identifier)).fetchone()
        if not alias:
            return identifier
        scope=json.loads(alias["basis"]).get("indexes",json.loads(row["indexes"]))
        if not principal.contains(actor["allowed_indexes"],scope):
            return None
        identifier=alias["target_id"]
    raise CapacityError("Story alias chain exceeds 64 identities")


def _complete_graph(db,actor,identifier):
    if actor["allowed_indexes"]==["*"]:
        return True
    for table in ("intelligence_story_nodes","intelligence_story_edges"):
        if db.execute("SELECT 1 FROM "+table+" n WHERE tenant=? AND story_id=? AND EXISTS (SELECT 1 FROM json_each(n.indexes) i WHERE i.value NOT IN (SELECT value FROM json_each(?))) LIMIT 1",(actor["tenant"],identifier,encode(actor["allowed_indexes"]))).fetchone():
            return False
    return True


def _projection(node):
    body = json.loads(node["body"])
    value = body.get("projection")
    return value if isinstance(value, dict) else None


def _safe_parent(db, tenant, previous, following):
    if not previous or not following or not identity_resolver.parent_link(previous, following):
        return False
    if identity_resolver.relation_key(None, None, previous, "process") is None or identity_resolver.relation_key(None, None, following, "process") is None:
        return False
    parent, child = previous["process"], following["process"]
    # Missing device/boot/asserted parent birth stays unknown. A GUID is not a
    # reusable process identity across boots or multiple devices at a source.
    if not identity_resolver.identity_text(child.get("parent_start_identity")) or child["parent_start_identity"]!=parent.get("start_identity"):
        return False
    for name in ("uid", "boot_id"):
        value = previous.get("device", {}).get(name)
        if not identity_resolver.identity_text(value) or value!=following.get("device", {}).get(name):
            return False
    if previous.get("container", {}).get("namespace")!=following.get("container", {}).get("namespace"):
        return False
    if previous.get("source_version")!=following.get("source_version"):
        return False
    source = db.execute("SELECT state,version FROM source_registry WHERE tenant=? AND id=?", (tenant, previous["source_id"])).fetchone()
    return bool(source and source["state"]=="active" and source["version"]==previous["source_version"])


def _cycle(db, tenant, parent_id, child_id):
    rows = db.execute("""WITH RECURSIVE descendants(id) AS (
      SELECT ? UNION SELECT e.to_id FROM intelligence_story_edges e
      JOIN descendants d ON d.id=e.from_id
      WHERE e.tenant=? AND e.relation='reported_parent')
      SELECT id FROM descendants LIMIT ?""", (child_id, tenant, MAX_NODES+1)).fetchall()
    if len(rows)>MAX_NODES:
        raise CapacityError("Parent relation scan exceeds 1000 links")
    return parent_id in {row[0] for row in rows}


def _route_owners(db, tenant, keys):
    owners = set()
    routes = db.execute("SELECT * FROM case_episode_routes WHERE tenant=? AND episode_key IN ("+','.join('?' for _ in keys)+") AND state!='superseded'", (tenant, *keys)).fetchall()
    for row in routes:
        owners.add(row["target_case"])
        if row["state"]=="partitioned":
            owners.add(row["source_case"])
    story_ids = [value.removeprefix("story:") for value in keys]
    contributions = db.execute("SELECT incident_id,evidence,indexes FROM risk_contributions WHERE tenant=? "
        "AND (json_extract(evidence,'$.analysis.story_id') IN (?,?) OR json_extract(evidence,'$.story_id') IN (?,?)) LIMIT 10001",
        (tenant, *story_ids, *story_ids)).fetchall()
    if len(contributions)>10000:
        raise CapacityError("Current Story Case ownership exceeds bounded scan; use analyst regrouping")
    for row in contributions:
        body = json.loads(row["evidence"])
        analysis = body.get("analysis") if isinstance(body.get("analysis"), dict) else {}
        identifier = analysis.get("story_id") or body.get("story_id")
        if identifier and "story:"+identifier in keys:
            owners.add(row["incident_id"])
    return owners, routes, contributions


def _case_aliases(db, actor, source, target, indexes, at):
    """Canonical Story ownership is distinct from an analyst Case decision."""
    keys = ["story:"+source, "story:"+target]
    owners, routes, contributions = _route_owners(db, actor["tenant"], keys)
    if len(owners)<=1:
        db.execute("UPDATE case_episode_routes SET episode_key=? WHERE tenant=? AND episode_key=?",
                   (keys[1], actor["tenant"], keys[0]))
        return False
    # Existing multiple Cases remain distinct, even if their new graph has one
    # current root. Each exact original set keeps an owner; new ambiguous logs
    # must be reviewed instead of entering either old Case automatically.
    grouped = {identifier: set() for identifier in owners}
    for route in routes:
        grouped[route["target_case"]].update(json.loads(route["event_ids"]))
        if route["state"]=="partitioned":
            grouped[route["source_case"]].update(json.loads(route["retained_event_ids"]))
    for row in contributions:
        body = json.loads(row["evidence"])
        analysis = body.get("analysis") if isinstance(body.get("analysis"), dict) else {}
        story = analysis.get("story_id") or body.get("story_id")
        if row["incident_id"] in grouped and "story:"+str(story) in keys:
            grouped[row["incident_id"]].update(body.get("event_ids", []))
    db.execute("UPDATE case_episode_routes SET state='superseded' WHERE tenant=? AND episode_key IN (?,?)",
               (actor["tenant"], *keys))
    for owner in sorted(owners):
        other = next(identifier for identifier in sorted(owners) if identifier!=owner)
        remaining = set().union(*(ids for identifier, ids in grouped.items() if identifier!=owner))
        db.execute("INSERT INTO case_episode_routes VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), actor["tenant"], keys[1], encode(indexes), other, owner,
             "story-reconcile:"+source, "partitioned", encode(sorted(grouped[owner])), encode(sorted(remaining)), at))
    return True


def _merge(db, store, actor, parent, child, parent_projection, child_projection):
    tenant = actor["tenant"]
    source_id, target_id = resolve(db, tenant, child["story_id"]), resolve(db, tenant, parent["story_id"])
    if source_id==target_id or _cycle(db, tenant, parent["id"], child["id"]):
        return target_id if source_id==target_id else source_id
    source = db.execute("SELECT * FROM intelligence_stories WHERE tenant=? AND id=?", (tenant, source_id)).fetchone()
    target = db.execute("SELECT * FROM intelligence_stories WHERE tenant=? AND id=?", (tenant, target_id)).fetchone()
    if not source or not target:
        return source_id
    if json.loads(source["body"]).get("identity_basis")!="reported_process_instance" or json.loads(target["body"]).get("identity_basis")!="reported_process_instance":
        return source_id
    indexes = sorted(set(json.loads(source["indexes"]))|set(json.loads(target["indexes"])))
    if not principal.contains(actor["allowed_indexes"], indexes):
        return source_id
    # The declared union must cover every retained node/edge, not just headers.
    if not _complete_graph(db,actor,source_id) or not _complete_graph(db,actor,target_id):
        return source_id
    owners,_,_=_route_owners(db,tenant,["story:"+source_id,"story:"+target_id])
    try:
        for owner in owners:
            principal.incident(db,actor,owner)
    except (PermissionError,KeyError):
        return source_id
    at = time.time()
    basis = {"kind": "late_explicit_parent_incarnation", "parent_node": parent["id"], "child_node": child["id"],
        "source_id": parent_projection["source_id"], "source_version": parent_projection["source_version"],
        "account": parent_projection["account"], "realm": parent_projection["realm"],
        "device": parent_projection["device"], "parent_start_identity": child_projection["process"]["parent_start_identity"],
        "source_story_version": source["version"], "target_story_version": target["version"],
        "indexes": indexes, "original_signal_bodies_preserved": True, "automatic_case_merge": False,
        "causality_proven": False, "automatic_endpoint_authorization": False}
    db.execute("INSERT INTO intelligence_story_aliases VALUES(?,?,?,?,?,?)", (tenant, source_id, target_id, 1, encode(basis), at))
    for table in ("intelligence_story_nodes", "intelligence_story_edges"):
        db.execute("UPDATE "+table+" SET story_id=? WHERE tenant=? AND story_id=?", (target_id, tenant, source_id))
    target_body = json.loads(target["body"])
    target_body["current_relationship_basis"] = "explicit_reported_parent_incarnation"
    source_body = {**json.loads(source["body"]), "current_owner": target_id, "active": False}
    db.execute("UPDATE intelligence_stories SET indexes=?,created=min(created,?),updated=max(updated,?),version=version+1,body=? WHERE tenant=? AND id=?",
               (encode(indexes), source["created"], source["updated"], encode(target_body), tenant, target_id))
    db.execute("UPDATE intelligence_stories SET version=version+1,body=? WHERE tenant=? AND id=?", (encode(source_body), tenant, source_id))
    ids = sorted({parent_projection["event_id"], child_projection["event_id"]})
    edge_id = release_manifest.digest([tenant, target_id, parent["id"], child["id"], "reported_parent", ids])
    db.execute("INSERT OR IGNORE INTO intelligence_story_edges VALUES(?,?,?,?,?,?,?,?,?,?,?)", (edge_id, tenant, target_id, parent["id"], child["id"], "reported_parent", "late_explicit_parent_incarnation", "source_reported", encode(ids), encode(indexes), child_projection["event_time"]))
    blocked = _case_aliases(db, actor, source_id, target_id, indexes, at)
    record = {"kind": "current_story_reconciled", "source_id": source_id, "target_id": target_id, "basis": basis, "case_routing_barrier": blocked, "actor": actor["name"], "at": at}
    for identifier in (source_id, target_id):
        db.execute("INSERT INTO intelligence_story_history(tenant,story_id,event_id,record,at) VALUES(?,?,?,?,?)", (tenant, identifier, child_projection["event_id"], encode(record), at))
    store.audit(db, tenant, actor["name"], "intelligence.story.reconcile", record)
    return target_id


def _nearby(db, tenant, projection, children=False, *, strict=True, cursor="", count=128):
    if not projection:
        return []
    process = projection.get("process", {})
    guid = process.get("guid") if children else process.get("parent_guid")
    if not identity_resolver.identity_text(guid):
        return []
    birth=process.get("start_identity") if children else process.get("parent_start_identity")
    device,container=projection.get("device",{}),projection.get("container",{})
    if strict and (not identity_resolver.identity_text(birth) or any(not identity_resolver.identity_text(device.get(name)) for name in ("uid","boot_id"))):
        return []
    guid_path="$.projection.process.parent_guid" if children else "$.projection.process.guid"
    birth_path="$.projection.process.parent_start_identity" if children else "$.projection.process.start_identity"
    # Literal JSON paths match the additive expression indexes, including old
    # stored v3 projections. Missing fields stay NULL; no projection is rewritten.
    clauses=["tenant=?","kind='process'","json_extract(body,'$.projection.source_id') IS ?","json_extract(body,'$.projection.account') IS ?","json_extract(body,'$.projection.realm') IS ?","json_extract(body,'"+guid_path+"')=?"]
    values=[tenant,projection.get("source_id"),projection.get("account"),projection.get("realm"),guid]
    if birth is not None:
        clauses.append("json_extract(body,'"+birth_path+"') IS ?");values.append(birth)
    for path,value in (("device.uid",device.get("uid")),("device.boot_id",device.get("boot_id")),("container.uid",container.get("uid")),("container.namespace",container.get("namespace"))):
        clauses.append("json_extract(body,'$.projection."+path+"') IS ?");values.append(value)
    clauses.extend(["json_extract(body,'$.projection.source_version') IS ?","id>?"])
    values.extend([projection.get("source_version"),cursor,count])
    return db.execute("SELECT * FROM intelligence_story_nodes WHERE "+" AND ".join(clauses)+" ORDER BY id LIMIT ?",values).fetchall()


def reconcile(store, db, actor, story_id, process_node_id=None, *, cursor="", count=128):
    """Publisher hook after appending a reported process node and history.

    The caller already owns the write transaction. Every new alias, graph move,
    Case barrier and history record commits together, or none of them do.
    """
    fresh = principal.current(db, actor, ("admin", "analyst"))
    if fresh!=actor:
        raise PermissionError("Current Story writer permissions changed")
    if process_node_id:
        focus = db.execute("SELECT * FROM intelligence_story_nodes WHERE tenant=? AND id=? AND kind='process'", (actor["tenant"], process_node_id)).fetchone()
    else:
        rows = db.execute("SELECT * FROM intelligence_story_nodes WHERE tenant=? AND story_id=? AND kind='process' LIMIT 2", (actor["tenant"], story_id)).fetchall()
        focus = rows[0] if len(rows)==1 else None
    if not focus:
        return resolve(db, actor["tenant"], story_id)
    if not principal.contains(actor["allowed_indexes"],json.loads(focus["indexes"])) or not current(db,actor,focus["story_id"]):
        raise KeyError("Process Story is outside complete current scope")
    # A new parent can reconcile existing children; a new child can reconcile
    # its earlier unresolved parent root. No chronology is invented.
    focus_projection = _projection(focus)
    children=_nearby(db,actor["tenant"],focus_projection,children=True,cursor=cursor,count=count+1)
    candidates = ([focus] if not cursor else [])+children[:count]
    for child in candidates:
        projection = _projection(child)
        if not principal.contains(actor["allowed_indexes"],json.loads(child["indexes"])) or not current(db,actor,child["story_id"]):
            continue
        parents = [node for node in _nearby(db, actor["tenant"], projection,count=2) if principal.contains(actor["allowed_indexes"],json.loads(node["indexes"])) and current(db,actor,node["story_id"]) and _safe_parent(db, actor["tenant"], _projection(node), projection)]
        if len(parents)!=1:
            continue
        parent = parents[0]
        _merge(db, store, fresh, parent, child, _projection(parent), projection)
    more=len(children)>count
    next_cursor=children[count-1]["id"] if more else (children[-1]["id"] if children else cursor)
    db.execute("INSERT INTO intelligence_story_reconcile_jobs VALUES(?,?,?,?,?,?,?,NULL) ON CONFLICT(tenant,focus_id) DO UPDATE SET owner=excluded.owner,indexes=excluded.indexes,cursor=excluded.cursor,state=excluded.state,updated=excluded.updated,error=NULL",(actor["tenant"],focus["id"],actor["name"],encode(actor["allowed_indexes"]),next_cursor,"pending" if more else "complete",time.time()))
    return resolve(db, actor["tenant"], story_id)


def run_due(store,cancel=None,budget=.25,max_runs=2):
    until=time.monotonic()+max(.01,min(3,budget));done=0
    with store.control() as db:
        jobs=[dict(row) for row in db.execute("SELECT * FROM intelligence_story_reconcile_jobs WHERE state='pending' ORDER BY updated,tenant,focus_id LIMIT ?",(max_runs,))]
    for job in jobs:
        if time.monotonic()>=until or cancel is not None and cancel.is_set():
            break
        try:
            with store.segment_lock.read(deadline=time.monotonic()+3),principal.transaction(store,{"name":job["owner"],"tenant":job["tenant"],"role":"analyst","allowed_indexes":json.loads(job["indexes"])},("admin","analyst"),write=True) as (db,actor):
                node=db.execute("SELECT * FROM intelligence_story_nodes WHERE tenant=? AND id=?",(actor["tenant"],job["focus_id"])).fetchone()
                if not node:
                    raise KeyError("Relationship focus no longer exists")
                reconcile(store,db,actor,node["story_id"],node["id"],cursor=job["cursor"])
            done+=1
        except (KeyError,PermissionError,ConflictError,CapacityError) as exc:
            with store.write_lock,store.control(local=True) as db:
                db.execute("UPDATE intelligence_story_reconcile_jobs SET state=?,updated=?,error=? WHERE tenant=? AND focus_id=?",("pending" if isinstance(exc,CapacityError) else "excluded",time.time(),str(exc),job["tenant"],job["focus_id"]))
    return done
