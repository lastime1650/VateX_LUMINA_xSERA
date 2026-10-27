"""Durable evidence routing and reviewed Case re-evaluation.

Analyst regrouping changes evidence ownership, not the provenance of a Case.
Aliases are tenant and exact source-scope bound. A split of indistinguishable
episodes creates a routing barrier: a new observation needs a new Case or an
analyst decision rather than silently undoing the split. Re-evaluation is
explicitly enabled and only proposes merges; it never approves a response.
"""

import hashlib
import json
import time
import uuid

from . import evidence_scope as evidence, migrations, principal
from .storage import CapacityError, ConflictError, encode

EDIT = ("admin", "analyst")
MAX_ROUTES = 256


def initialize(store):
    with store.control(local=True) as db:
        schema = """
        CREATE TABLE IF NOT EXISTS case_episode_routes(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,episode_key TEXT NOT NULL,
          indexes TEXT NOT NULL,source_case TEXT NOT NULL,target_case TEXT NOT NULL,
          movement_id TEXT NOT NULL,state TEXT NOT NULL,event_ids TEXT NOT NULL,
          retained_event_ids TEXT NOT NULL,created REAL NOT NULL);
        CREATE INDEX IF NOT EXISTS case_route_lookup
          ON case_episode_routes(tenant,episode_key,created);
        CREATE TABLE IF NOT EXISTS case_reevaluation_config(
          tenant TEXT PRIMARY KEY,owner TEXT NOT NULL,indexes TEXT NOT NULL,
          enabled INTEGER NOT NULL,exact_attachment INTEGER NOT NULL,
          interval INTEGER NOT NULL,version INTEGER NOT NULL,next_run REAL NOT NULL,
          error TEXT);
        CREATE TABLE IF NOT EXISTS case_reevaluation_proposals(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,
          indexes TEXT NOT NULL,source_case TEXT NOT NULL,target_case TEXT NOT NULL,
          source_version INTEGER NOT NULL,target_version INTEGER NOT NULL,
          config_version INTEGER NOT NULL,state TEXT NOT NULL,version INTEGER NOT NULL,
          created REAL NOT NULL,updated REAL NOT NULL,record TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS case_proposal_tenant
          ON case_reevaluation_proposals(tenant,state,created);
        CREATE TABLE IF NOT EXISTS case_reevaluation_history(
          proposal_id TEXT NOT NULL,version INTEGER NOT NULL,record TEXT NOT NULL,
          PRIMARY KEY(proposal_id,version));
        """
        migrations.apply(db, "case_intelligence", 1, [part.strip() for part in schema.split(";") if part.strip()])
        migrations.apply(db, "case_intelligence", 2, [
            "CREATE TABLE IF NOT EXISTS case_reevaluation_work(tenant TEXT PRIMARY KEY,config_version INTEGER NOT NULL,frozen_end REAL NOT NULL,after_updated REAL NOT NULL,after_id TEXT NOT NULL,scanned INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS case_reevaluation_groups(tenant TEXT NOT NULL,config_version INTEGER NOT NULL,episode_key TEXT NOT NULL,indexes TEXT NOT NULL,entity_field TEXT NOT NULL,entity TEXT NOT NULL,target_case TEXT NOT NULL,PRIMARY KEY(tenant,config_version,episode_key,indexes,entity_field,entity))"])


def _scope(value):
    return sorted(set(json.loads(value) if isinstance(value, str) else value))


def _row_episode(row):
    from .detections import _episode

    record = json.loads(row["evidence"])
    episode = record.get("episode") or _episode({
        **record, "entity_field": row["entity_field"], "entity": row["entity"],
    })
    return episode, set(record.get("event_ids", []))


def _story(record):
    analysis = record.get("analysis") if isinstance(record.get("analysis"), dict) else {}
    value = analysis.get("story_id") or record.get("story_id")
    return value if isinstance(value, str) and 1<=len(value)<=256 else None


def record_movement(db, actor, source_id, target_id, kind, movement_id, rows, selected):
    """Same transaction as the evidence move; source IDs remain immutable."""
    selected = set(selected)
    grouped = {}
    for row in rows:
        episode, ids = _row_episode(row)
        indexes = encode(_scope(row["indexes"]))
        keys = [episode["key"]]
        story = _story(json.loads(row["evidence"]))
        if story:
            keys.append("story:"+story)
        for route_key in keys:
            group = grouped.setdefault((route_key, indexes), {"moved": set(), "retained": set()})
            group["moved" if row["id"] in selected else "retained"].update(ids)
    if len(grouped) > MAX_ROUTES:
        raise CapacityError("Case movement exceeds 256 distinct scoped episodes")
    if kind == "merge":
        # Transitive aliases now reach the current owner, without a redirect loop.
        db.execute("UPDATE case_episode_routes SET target_case=? WHERE tenant=? AND target_case=?",
                   (target_id, actor["tenant"], source_id))
        db.execute("UPDATE case_episode_routes SET state='superseded' WHERE tenant=? "
                   "AND state='partitioned' AND source_case=? AND target_case=?",
                   (actor["tenant"], source_id, target_id))
        db.execute("UPDATE case_episode_routes SET state='superseded' WHERE tenant=? "
                   "AND state='partitioned' AND source_case=? AND target_case=?",
                   (actor["tenant"], target_id, target_id))
    for (key, indexes), group in grouped.items():
        if not group["moved"]:
            continue
        # A later split supersedes aliases for that same episode at this owner.
        if kind == "split":
            db.execute("UPDATE case_episode_routes SET state='superseded' WHERE tenant=? "
                       "AND episode_key=? AND indexes=? AND target_case=? AND state='redirect'",
                       (actor["tenant"], key, indexes, source_id))
        state = "partitioned" if group["retained"] else "redirect"
        db.execute("INSERT INTO case_episode_routes VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                   (str(uuid.uuid4()), actor["tenant"], key, indexes, source_id,
                    target_id, movement_id, state, encode(sorted(group["moved"])),
                    encode(sorted(group["retained"])), time.time()))


def frozen(db, tenant, incident_id):
    """Do not rewrite a pending/active approved execution's evidence ownership."""
    if db.execute("SELECT 1 FROM soar_runs WHERE tenant=? AND incident_id=? "
                  "AND state IN ('pending_approval','queued','retry','waiting','sending') LIMIT 1",
                  (tenant, incident_id)).fetchone():
        return True
    if db.execute("SELECT 1 FROM effect_receipts WHERE tenant=? AND incident_id=? "
                  "AND state IN ('prepared','approved','dispatching','reported','unknown','partial') LIMIT 1",
                  (tenant, incident_id)).fetchone():
        return True
    return bool(db.execute("SELECT 1 FROM endpoint_responses WHERE tenant=? AND incident_id=? "
                           "AND state IN ('queued','claimed','started') LIMIT 1",
                           (tenant, incident_id)).fetchone())


def assert_mutation_allowed(db, actor, *incident_ids):
    if any(frozen(db, actor["tenant"], identifier) for identifier in incident_ids):
        raise ConflictError("Case has a pending or active frozen response; cancel or finish it before regrouping")


def _visible_target(db, actor, target, indexes):
    if not principal.contains(actor["allowed_indexes"], indexes):
        return False
    try:
        row = principal.incident(db, actor, target)
    except KeyError:
        return False
    return row["status"] in {"new", "triage"} and not frozen(db, actor["tenant"], target)


def route(db, guard, match, episode, end):
    """Transactional emitter hook; both selection and nearby fallback are scoped.

    Caller must exclude blocked_case_ids even when incident_id is None. No
    entity/IP coincidence is an alias and no closed Case is reopened here.
    """
    scope = _scope(match["indexes"])
    keys = [episode["key"]]
    story = _story(match)
    if story:
        keys.append("story:"+story)
    all_rows = db.execute("SELECT * FROM case_episode_routes WHERE tenant=? AND episode_key IN ("+','.join('?' for _ in keys)+") "
                      "AND state!='superseded' ORDER BY created DESC,id LIMIT ?",
                      (guard["tenant"], *keys, MAX_ROUTES + 1)).fetchall()
    rows = [row for row in all_rows if _scope(row["indexes"]) == scope]
    if len(all_rows) > MAX_ROUTES:
        raise CapacityError("Episode routing bound exceeded; analyst review required")
    blocked, targets = set(), set()
    ids = set(match.get("event_ids", []))
    conflicts = [row for row in all_rows if _scope(row["indexes"]) != scope and set(_scope(row["indexes"])) & set(scope)]
    for row in conflicts:
        blocked.update((row["source_case"], row["target_case"]))
    if conflicts:
        blocked.update(value for row in rows for value in (row["source_case"], row["target_case"]))
        return {"incident_id": None, "blocked_case_ids": sorted(blocked), "reason": "changed_overlapping_scope_requires_review"}
    if rows:
        for row in rows:
            blocked.add(row["source_case"])
            if row["state"] == "partitioned":
                blocked.add(row["target_case"])
                moved, retained = set(json.loads(row["event_ids"])), set(json.loads(row["retained_event_ids"]))
                left, right = bool(ids & moved), bool(ids & retained)
                target = row["target_case"] if left and not right else row["source_case"] if right and not left else None
                if target and _visible_target(db, guard, target, scope):
                    targets.add(target)
            elif _visible_target(db, guard, row["target_case"], scope):
                targets.add(row["target_case"])
            else:
                blocked.add(row["target_case"])
        # Multiple distinct owners are explicit ambiguity, never latest-wins.
        target = next(iter(targets)) if len(targets) == 1 else None
        if len(targets) > 1:
            blocked.update(targets)
        return {"incident_id": target, "blocked_case_ids": sorted(blocked),
                "reason": "analyst_scoped_alias" if target else "split_or_closed_owner_requires_review"}
    config = db.execute("SELECT * FROM case_reevaluation_config WHERE tenant=? AND enabled=1 "
                        "AND exact_attachment=1", (guard["tenant"],)).fetchone()
    if config and ids and principal.contains(_scope(config["indexes"]), scope):
        try:
            owner = principal.current(db, {"name": config["owner"], "tenant": guard["tenant"],
                "role": "admin", "allowed_indexes": _scope(config["indexes"])}, ("admin",))
        except PermissionError:
            return {"incident_id": None, "blocked_case_ids": [], "reason": "configuration_owner_unavailable"}
        if principal.contains(owner["allowed_indexes"], scope):
            candidates = db.execute("SELECT r.*,i.status FROM risk_contributions r JOIN incidents i "
                "ON i.tenant=r.tenant AND i.id=r.incident_id WHERE r.tenant=? AND r.entity=? "
                "AND r.entity_field=? AND r.indexes=? AND r.at>=? AND r.at<=? "
                "AND i.status IN ('new','triage') ORDER BY r.at DESC LIMIT 100",
                (guard["tenant"], match["entity"], match["entity_field"], encode(scope), end-86400, end+86400)).fetchall()
            for candidate in candidates:
                if set(json.loads(candidate["evidence"]).get("event_ids", [])) == ids:
                    if _visible_target(db, guard, candidate["incident_id"], scope):
                        targets.add(candidate["incident_id"])
                    else:
                        blocked.add(candidate["incident_id"])
    return {"incident_id": next(iter(targets)) if len(targets) == 1 else None,
            "blocked_case_ids": sorted(blocked | (targets if len(targets) > 1 else set())),
            "reason": "opt_in_exact_original_set" if len(targets) == 1 else "no_unambiguous_alias"}


def configure(store, who, data):
    if not isinstance(data, dict) or set(data) != {"indexes", "enabled", "exact_attachment", "interval", "version"}:
        raise ValueError("indexes, enabled, exact_attachment, interval and version are required; automatic merges are unavailable")
    indexes = sorted(evidence.indexes(data["indexes"]))
    if type(data["enabled"]) is not bool or type(data["exact_attachment"]) is not bool:
        raise ValueError("Typed booleans required")
    interval = evidence.integer(data["interval"], "interval", 30, 86400)
    version = evidence.integer(data["version"], "version", 0, 2**31-1)
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        if not principal.contains(actor["allowed_indexes"], indexes):
            raise PermissionError("Re-evaluation indexes exceed current permissions")
        old = db.execute("SELECT version FROM case_reevaluation_config WHERE tenant=?", (actor["tenant"],)).fetchone()
        if (old[0] if old else 0) != version:
            raise ConflictError("Re-evaluation configuration version changed")
        db.execute("INSERT INTO case_reevaluation_config VALUES(?,?,?,?,?,?,?,?,NULL) ON CONFLICT(tenant) "
            "DO UPDATE SET owner=excluded.owner,indexes=excluded.indexes,enabled=excluded.enabled,"
            "exact_attachment=excluded.exact_attachment,interval=excluded.interval,version=excluded.version,"
            "next_run=excluded.next_run,error=NULL",
            (actor["tenant"], actor["name"], encode(indexes), int(data["enabled"]),
             int(data["exact_attachment"]), interval, version+1, time.time()))
        db.execute("DELETE FROM case_reevaluation_work WHERE tenant=?", (actor["tenant"],))
        db.execute("DELETE FROM case_reevaluation_groups WHERE tenant=?", (actor["tenant"],))
        result = {**data, "indexes": indexes, "version": version+1, "automatic_merges": False}
        store.audit(db, actor["tenant"], actor["name"], "case.reevaluation.configure", result)
        return result


def configuration(store, who):
    with principal.transaction(store, who) as (db, actor):
        row = db.execute("SELECT * FROM case_reevaluation_config WHERE tenant=?", (actor["tenant"],)).fetchone()
        if row and not principal.contains(actor["allowed_indexes"], _scope(row["indexes"])):
            raise KeyError("Configuration not found")
        return {**dict(row), "indexes": _scope(row["indexes"]), "automatic_merges": False} if row else {
            "enabled": False, "exact_attachment": False, "version": 0, "automatic_merges": False}


def _proposal(db, store, actor, config, left, right, episode, indexes, now):
    source, target = (left, right) if left["created"] >= right["created"] else (right, left)
    record = {"schema": "xsera.case-reevaluation.v1", "kind": "merge", "source_id": source["id"],
        "target_id": target["id"], "source_version": source["version"], "target_version": target["version"],
        "episode_key": episode, "indexes": indexes, "reason": "Shared exact reported episode in a complete source scope",
        "automatic_merge": False, "response_authorized": False, "config_version": config["version"]}
    identifier = hashlib.sha256(encode([actor["tenant"], record]).encode()).hexdigest()
    if db.execute("SELECT 1 FROM case_reevaluation_proposals WHERE id=?", (identifier,)).fetchone():
        return False
    db.execute("INSERT INTO case_reevaluation_proposals VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
               (identifier, actor["tenant"], actor["name"], encode(indexes), source["id"], target["id"],
                source["version"], target["version"], config["version"], "pending", 1, now, now, encode(record)))
    db.execute("INSERT INTO case_reevaluation_history VALUES(?,?,?)",
               (identifier, 1, encode({"state": "pending", "at": now, "actor": actor["name"], "proposal": record})))
    store.audit(db, actor["tenant"], actor["name"], "case.reevaluation.propose", {"id": identifier, **record})
    return True


def run_due(store, now=None, cancel=None, budget=1.0, max_runs=2):
    now = evidence.number(time.time() if now is None else now, "scheduler time")
    budget = evidence.number(budget, "budget", .01, 10)
    max_runs = evidence.integer(max_runs, "max_runs", 1, 8)
    until, total = time.monotonic() + budget, 0
    with store.control() as db:
        configs = [dict(row) for row in db.execute("SELECT * FROM case_reevaluation_config WHERE enabled=1 AND next_run<=? ORDER BY next_run LIMIT ?", (now, max_runs))]
    for config in configs:
        if time.monotonic() >= until or (cancel and cancel.is_set()):
            break
        who = {"name": config["owner"], "tenant": config["tenant"], "role": "admin", "allowed_indexes": _scope(config["indexes"])}
        try:
            with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
                current = db.execute("SELECT * FROM case_reevaluation_config WHERE tenant=?", (actor["tenant"],)).fetchone()
                if current["version"] != config["version"] or not current["enabled"]:
                    continue
                if not principal.contains(actor["allowed_indexes"], _scope(config["indexes"])):
                    raise PermissionError("Configuration owner lost source scope")
                work = db.execute("SELECT * FROM case_reevaluation_work WHERE tenant=?", (actor["tenant"],)).fetchone()
                if not work or work["config_version"] != config["version"]:
                    db.execute("DELETE FROM case_reevaluation_groups WHERE tenant=?", (actor["tenant"],))
                    db.execute("INSERT OR REPLACE INTO case_reevaluation_work VALUES(?,?,?,?,?,0)",
                               (actor["tenant"], config["version"], now, now+1, ""))
                    work = db.execute("SELECT * FROM case_reevaluation_work WHERE tenant=?", (actor["tenant"],)).fetchone()
                # Scope narrows the candidate scan before its bounded page. The
                # complete Case scope is still checked below, including bookmarks
                # and archived evidence. Continuation is durable across restart.
                cases = db.execute("""SELECT i.* FROM incidents i WHERE tenant=? AND status IN ('new','triage')
                  AND updated>=? AND updated<=? AND (updated<? OR (updated=? AND id>?))
                  AND EXISTS(SELECT 1 FROM risk_contributions r,json_each(r.indexes) s
                    WHERE r.tenant=i.tenant AND r.incident_id=i.id
                    AND s.value IN (SELECT value FROM json_each(?)))
                  ORDER BY updated DESC,id LIMIT 101""", (actor["tenant"], work["frozen_end"]-86400,
                    work["frozen_end"], work["after_updated"], work["after_updated"], work["after_id"], config["indexes"])).fetchall()
                from .contribution_verdicts import _scope as case_scope

                processed = []
                for case in cases[:100]:
                    if time.monotonic() >= until or (cancel and cancel.is_set()):
                        break
                    processed.append(case)
                    try:
                        principal.incident(db, actor, case["id"])
                    except KeyError:
                        continue
                    indexes = case_scope(db, actor, case["id"])
                    if not indexes or not principal.contains(_scope(config["indexes"]), indexes) or frozen(db, actor["tenant"], case["id"]):
                        continue
                    episodes = db.execute("SELECT * FROM incident_episodes WHERE tenant=? AND incident_id=? AND grade='exact_reported_identity'", (actor["tenant"], case["id"])).fetchall()
                    for episode in episodes:
                        # An analyst split is a durable veto on automatic re-combination.
                        if db.execute("SELECT 1 FROM case_episode_routes WHERE tenant=? AND episode_key=? AND state='partitioned' AND (source_case=? OR target_case=?) LIMIT 1",
                                      (actor["tenant"], episode["episode_key"], case["id"], case["id"])).fetchone():
                            continue
                        key = (episode["episode_key"], encode(indexes), case["entity_field"], case["entity"])
                        group = db.execute("SELECT target_case FROM case_reevaluation_groups WHERE tenant=? AND config_version=? AND episode_key=? AND indexes=? AND entity_field=? AND entity=?",
                                           (actor["tenant"], config["version"], *key)).fetchone()
                        target = None
                        if group and group[0] != case["id"]:
                            try:
                                candidate = principal.incident(db, actor, group[0])
                                barrier = db.execute("SELECT 1 FROM case_episode_routes WHERE tenant=? AND episode_key=? AND state='partitioned' AND (source_case=? OR target_case=?) LIMIT 1",
                                                     (actor["tenant"], key[0], candidate["id"], candidate["id"])).fetchone()
                                if candidate["status"] in {"new", "triage"} and case_scope(db, actor, candidate["id"]) == indexes and not frozen(db, actor["tenant"], candidate["id"]) and not barrier:
                                    target = candidate
                            except KeyError:
                                pass
                        if target is not None:
                            total += int(_proposal(db, store, actor, current, case, target, key[0], indexes, now))
                        elif not group or group[0] != case["id"]:
                            db.execute("INSERT OR REPLACE INTO case_reevaluation_groups VALUES(?,?,?,?,?,?,?)",
                                       (actor["tenant"], config["version"], *key, case["id"]))
                finished = len(cases)<=100 and len(processed)==len(cases)
                if finished:
                    db.execute("DELETE FROM case_reevaluation_work WHERE tenant=?", (actor["tenant"],))
                    db.execute("DELETE FROM case_reevaluation_groups WHERE tenant=?", (actor["tenant"],))
                elif processed:
                    last = processed[-1]
                    db.execute("UPDATE case_reevaluation_work SET after_updated=?,after_id=?,scanned=scanned+? WHERE tenant=?",
                               (last["updated"], last["id"], len(processed), actor["tenant"]))
                db.execute("UPDATE case_reevaluation_config SET next_run=?,error=NULL WHERE tenant=? AND version=?",
                           (now+config["interval"] if finished else now, actor["tenant"], config["version"]))
        except (PermissionError, KeyError, CapacityError) as exc:
            with store.control() as db:
                db.execute("UPDATE case_reevaluation_config SET error=?,next_run=? WHERE tenant=? AND version=?", (str(exc)[:500], now+config["interval"], config["tenant"], config["version"]))
    return total


def _authorize_proposal(db, actor, identifier):
    row = db.execute("SELECT * FROM case_reevaluation_proposals WHERE tenant=? AND id=?", (actor["tenant"], identifier)).fetchone()
    if not row or not principal.contains(actor["allowed_indexes"], _scope(row["indexes"])):
        raise KeyError("Proposal not found")
    principal.incident(db, actor, row["source_case"])
    principal.incident(db, actor, row["target_case"])
    owner = principal.current(db, {"name": row["owner"], "tenant": actor["tenant"], "role": "admin", "allowed_indexes": _scope(row["indexes"])}, ("admin",))
    if not principal.contains(owner["allowed_indexes"], _scope(row["indexes"])):
        raise PermissionError("Proposal owner lost evidence scope")
    return row


def proposals(store, who, after="", count=100):
    evidence.integer(count, "count", 1, 200)
    evidence.text(after, "cursor", 256, empty=True)
    with principal.transaction(store, who) as (db, actor):
        rows = db.execute("SELECT * FROM case_reevaluation_proposals WHERE tenant=? AND id>? ORDER BY id LIMIT ?", (actor["tenant"], after, count+1)).fetchall()
        items = []
        for row in rows[:count]:
            try:
                _authorize_proposal(db, actor, row["id"])
            except (KeyError, PermissionError):
                continue
            items.append({"id": row["id"], "version": row["version"], "state": row["state"], "created": row["created"], **json.loads(row["record"])})
        return {"items": items, "next_cursor": rows[count-1]["id"] if len(rows)>count else None}


def history(store, who, identifier):
    with principal.transaction(store, who) as (db, actor):
        _authorize_proposal(db, actor, identifier)
        return {"items": [json.loads(row[0]) for row in db.execute("SELECT record FROM case_reevaluation_history WHERE proposal_id=? ORDER BY version", (identifier,))]}


def review(store, who, identifier, data):
    if not isinstance(data, dict) or set(data) != {"version", "approve", "reason"}:
        raise ValueError("version, approve and reason are required")
    version = evidence.integer(data["version"], "version", 1, 2**31-1)
    reason = evidence.text(data["reason"], "review reason", 2000)
    if type(data["approve"]) is not bool:
        raise ValueError("Typed approve boolean required")
    with principal.transaction(store, who, EDIT) as (db, actor):
        row = dict(_authorize_proposal(db, actor, identifier))
        if row["version"] != version or row["state"] != "pending":
            raise ConflictError("Proposal state/version changed")
        if data["approve"] and row["owner"] == actor["name"]:
            raise PermissionError("An independent analyst or administrator must review a merge proposal")

    def commit(db, fresh, movement=None):
        current = _authorize_proposal(db, fresh, identifier)
        config = db.execute("SELECT * FROM case_reevaluation_config WHERE tenant=?", (fresh["tenant"],)).fetchone()
        if current["version"] != version or current["state"] != "pending":
            raise ConflictError("Proposal state/version changed")
        if data["approve"] and (not config or not config["enabled"] or config["version"] != row["config_version"]):
            raise ConflictError("Proposal configuration changed; generate a fresh proposal")
        state, at = ("approved" if data["approve"] else "rejected"), time.time()
        result = {"id": identifier, "state": state, "version": version+1, "actor": fresh["name"],
            "at": at, "reason": reason, "movement_id": movement["id"] if movement else None,
            "response_authorized": False}
        db.execute("UPDATE case_reevaluation_proposals SET state=?,version=?,updated=? WHERE id=?", (state, version+1, at, identifier))
        db.execute("INSERT INTO case_reevaluation_history VALUES(?,?,?)", (identifier, version+1, encode(result)))
        store.audit(db, fresh["tenant"], fresh["name"], "case.reevaluation.review", result)
        return result

    if data["approve"]:
        from .contribution_verdicts import regroup

        reviewed = {}
        def after(db, fresh, movement):
            reviewed.update(commit(db, fresh, movement))
        regroup(store, actor, row["source_case"], "merge", {"version": row["source_version"],
            "target_id": row["target_case"], "target_version": row["target_version"], "reason": reason}, _after=after)
        return reviewed
    with principal.transaction(store, actor, EDIT, write=True) as (db, fresh):
        return commit(db, fresh)


def register(app, store, runtime, who, body):
    from fastapi import Request
    from starlette.concurrency import run_in_threadpool
    from . import behavior_features

    @app.get("/api/v3/cases/reevaluation/config")
    async def get_config(request: Request):
        return await run_in_threadpool(configuration, store, who(request))

    @app.put("/api/v3/cases/reevaluation/config")
    async def put_config(request: Request):
        return await run_in_threadpool(configure, store, who(request, ("admin",)), await body(request))

    @app.get("/api/v3/cases/reevaluation/proposals")
    async def list_proposals(request: Request):
        return await run_in_threadpool(proposals, store, who(request), request.query_params.get("after", ""), int(request.query_params.get("count", "100")))

    @app.get("/api/v3/cases/reevaluation/proposals/{identifier}/history")
    async def proposal_history(identifier: str, request: Request):
        return await run_in_threadpool(history, store, who(request), identifier)

    @app.post("/api/v3/cases/reevaluation/proposals/{identifier}/review")
    async def proposal_review(identifier: str, request: Request):
        return await run_in_threadpool(review, store, who(request, EDIT), identifier, await body(request))

    behavior_features.register(app, store, runtime, who, body)
