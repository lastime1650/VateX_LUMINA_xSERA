"""Durable, evidence-bound signals, stories and positive composite detections.

All decisions retain original ancestry. A reported relationship is never device
authority or a calibrated malicious probability. Policies require independent
activation; expensive analysis runs after the original indexing commit.
"""

import json
import math
import re
import time
import uuid
from contextlib import contextmanager

from . import access, evidence_scope, identity_resolver, migrations, principal, release_manifest
from .storage import CapacityError, ConflictError, encode

SCHEMA = "xsera.signal.v1"
KINDS = {"observation", "atomic", "legacy", "finding", "behavior", "ml", "composite"}
SEVERITIES = {"info", "low", "medium", "high", "critical"}
PATH = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){0,9}\Z")


def initialize(store):
    migrations.apply_store(store, "intelligence", [
        "CREATE TABLE IF NOT EXISTS intelligence_policies(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,indexes TEXT NOT NULL,kind TEXT NOT NULL,definition TEXT NOT NULL,version INTEGER NOT NULL,state TEXT NOT NULL,approver TEXT,approval_digest TEXT,updated REAL NOT NULL)",
        "CREATE TABLE IF NOT EXISTS intelligence_policy_revisions(id TEXT NOT NULL,tenant TEXT NOT NULL,version INTEGER NOT NULL,definition TEXT NOT NULL,digest TEXT NOT NULL,updated REAL NOT NULL,PRIMARY KEY(tenant,id,version))",
        "CREATE TABLE IF NOT EXISTS intelligence_signals(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,tenant TEXT NOT NULL,indexes TEXT NOT NULL,event_ids TEXT NOT NULL,parent_signal_ids TEXT NOT NULL,entity_key TEXT NOT NULL,story_id TEXT,kind TEXT NOT NULL,rule_id TEXT NOT NULL,rule_revision INTEGER NOT NULL,features TEXT NOT NULL,severity TEXT NOT NULL,confidence_grade TEXT NOT NULL,created REAL NOT NULL,mode TEXT NOT NULL,definition_digest TEXT NOT NULL,context_digest TEXT NOT NULL,body TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS intelligence_signal_window ON intelligence_signals(tenant,mode,created,rule_id,seq)",
        "CREATE TABLE IF NOT EXISTS intelligence_event_outbox(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,tenant TEXT NOT NULL,event_id TEXT NOT NULL,index_name TEXT NOT NULL,received REAL NOT NULL)",
        "CREATE TABLE IF NOT EXISTS intelligence_cursors(worker TEXT PRIMARY KEY,cursor INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS intelligence_ml_jobs(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,event_id TEXT NOT NULL,owner TEXT NOT NULL,index_name TEXT NOT NULL,state TEXT NOT NULL,attempts INTEGER NOT NULL,error TEXT,retry_at REAL NOT NULL,created REAL NOT NULL,finished REAL)",
        "CREATE TABLE IF NOT EXISTS intelligence_stories(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,indexes TEXT NOT NULL,root_key TEXT NOT NULL,version INTEGER NOT NULL,created REAL NOT NULL,updated REAL NOT NULL,body TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS intelligence_story_nodes(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,story_id TEXT NOT NULL,kind TEXT NOT NULL,indexes TEXT NOT NULL,event_ids TEXT NOT NULL,body TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS intelligence_story_edges(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,story_id TEXT NOT NULL,from_id TEXT NOT NULL,to_id TEXT NOT NULL,relation TEXT NOT NULL,basis TEXT NOT NULL,confidence_grade TEXT NOT NULL,event_ids TEXT NOT NULL,indexes TEXT NOT NULL,event_time REAL NOT NULL)",
        "CREATE TABLE IF NOT EXISTS intelligence_story_history(seq INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT NOT NULL,story_id TEXT NOT NULL,event_id TEXT NOT NULL,record TEXT NOT NULL,at REAL NOT NULL)",
        "CREATE TABLE IF NOT EXISTS intelligence_evidence_refs(tenant TEXT NOT NULL,event_id TEXT NOT NULL,record_id TEXT NOT NULL,protected_until REAL NOT NULL,PRIMARY KEY(tenant,event_id,record_id))",
        "CREATE TABLE IF NOT EXISTS intelligence_decisions(seq INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT NOT NULL,policy_id TEXT NOT NULL,version INTEGER NOT NULL,indexes TEXT NOT NULL,signal_id TEXT,reason TEXT NOT NULL,detail TEXT NOT NULL,at REAL NOT NULL)",
        "CREATE TABLE IF NOT EXISTS intelligence_composite_state(id TEXT PRIMARY KEY,version INTEGER NOT NULL,last_seq INTEGER NOT NULL,snapshot_seq INTEGER NOT NULL,anchor_seq INTEGER NOT NULL,window_end REAL NOT NULL,updated REAL NOT NULL,error TEXT)",
        "CREATE TABLE IF NOT EXISTS intelligence_story_aliases(tenant TEXT NOT NULL,source_id TEXT NOT NULL,target_id TEXT NOT NULL,version INTEGER NOT NULL,basis TEXT NOT NULL,at REAL NOT NULL,PRIMARY KEY(tenant,source_id))",
        "INSERT OR IGNORE INTO intelligence_cursors VALUES('events',0)",
        "INSERT OR IGNORE INTO intelligence_cursors VALUES('contributions',0)",
        "INSERT OR IGNORE INTO intelligence_cursors VALUES('findings',0)",
    ])
    migrations.apply_store(store, "intelligence_scale", [
        "CREATE INDEX IF NOT EXISTS intelligence_signal_select ON intelligence_signals(tenant,mode,rule_id,kind,seq)",
        "CREATE INDEX IF NOT EXISTS intelligence_ml_pending_scope ON intelligence_ml_jobs(state,tenant,owner,index_name,retry_at,created,id)",
        "CREATE TABLE IF NOT EXISTS intelligence_composite_work(id TEXT PRIMARY KEY,version INTEGER NOT NULL,snapshot_seq INTEGER NOT NULL,scan_seq INTEGER NOT NULL,phase TEXT NOT NULL,search TEXT NOT NULL,examined INTEGER NOT NULL,qualified INTEGER NOT NULL,updated REAL NOT NULL)",
        "CREATE TABLE IF NOT EXISTS intelligence_composite_cohort(policy_id TEXT NOT NULL,snapshot_seq INTEGER NOT NULL,seq INTEGER NOT NULL,signal_id TEXT NOT NULL,join_key TEXT NOT NULL,kind TEXT NOT NULL,rule_id TEXT NOT NULL,event_start REAL NOT NULL,event_end REAL NOT NULL,body TEXT NOT NULL,PRIMARY KEY(policy_id,seq))",
        "CREATE INDEX IF NOT EXISTS intelligence_composite_partition ON intelligence_composite_cohort(policy_id,join_key,rule_id,kind,event_end,seq)",
        "CREATE INDEX IF NOT EXISTS intelligence_composite_member ON intelligence_composite_cohort(policy_id,signal_id)",
        "CREATE TABLE IF NOT EXISTS intelligence_ml_scope_schedule(tenant TEXT NOT NULL,owner TEXT NOT NULL,index_name TEXT NOT NULL,served REAL NOT NULL,PRIMARY KEY(tenant,owner,index_name))",
        "CREATE TABLE IF NOT EXISTS intelligence_ml_batch_diagnostics(id INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT NOT NULL,owner TEXT NOT NULL,model_id TEXT,indexes TEXT NOT NULL,pending_count INTEGER NOT NULL,oldest_created REAL NOT NULL,ready INTEGER NOT NULL,selected INTEGER NOT NULL,state TEXT NOT NULL,started REAL,finished REAL,duration_ms REAL,worker_wall_ms REAL,detail TEXT NOT NULL,at REAL NOT NULL)",
        "CREATE TABLE IF NOT EXISTS intelligence_event_phases(tenant TEXT NOT NULL,event_id TEXT NOT NULL,index_name TEXT NOT NULL,received REAL NOT NULL,indexed_at REAL,analysis_started_at REAL,analysis_completed_at REAL,first_signal_at REAL,first_detection_at REAL,first_case_at REAL,first_composite_at REAL,ml_queued_at REAL,ml_started_at REAL,ml_finished_at REAL,sequence_queued_at REAL,sequence_started_at REAL,sequence_finished_at REAL,outcome TEXT,error TEXT,PRIMARY KEY(tenant,event_id,received))",
        "CREATE INDEX IF NOT EXISTS intelligence_phase_scope ON intelligence_event_phases(tenant,index_name,received,event_id)",
        "INSERT OR IGNORE INTO intelligence_event_phases(tenant,event_id,index_name,received,outcome) SELECT tenant,event_id,index_name,received,'historical_phase_unknown' FROM intelligence_event_outbox",
        "CREATE INDEX IF NOT EXISTS intelligence_story_parent_identity ON intelligence_story_nodes(tenant,kind,json_extract(body,'$.projection.source_id'),json_extract(body,'$.projection.account'),json_extract(body,'$.projection.realm'),json_extract(body,'$.projection.process.guid'),json_extract(body,'$.projection.process.start_identity'),json_extract(body,'$.projection.device.uid'),json_extract(body,'$.projection.device.boot_id'),json_extract(body,'$.projection.container.uid'),json_extract(body,'$.projection.container.namespace'))",
        "CREATE INDEX IF NOT EXISTS intelligence_story_child_identity ON intelligence_story_nodes(tenant,kind,json_extract(body,'$.projection.source_id'),json_extract(body,'$.projection.account'),json_extract(body,'$.projection.realm'),json_extract(body,'$.projection.process.parent_guid'),json_extract(body,'$.projection.process.parent_start_identity'),json_extract(body,'$.projection.device.uid'),json_extract(body,'$.projection.device.boot_id'),json_extract(body,'$.projection.container.uid'),json_extract(body,'$.projection.container.namespace'))",
        "CREATE INDEX IF NOT EXISTS intelligence_story_members ON intelligence_story_nodes(tenant,story_id,kind,id)",
        "CREATE INDEX IF NOT EXISTS intelligence_story_edge_members ON intelligence_story_edges(tenant,story_id,relation,from_id,to_id)",
        "CREATE TABLE IF NOT EXISTS intelligence_story_reconcile_jobs(tenant TEXT NOT NULL,focus_id TEXT NOT NULL,owner TEXT NOT NULL,indexes TEXT NOT NULL,cursor TEXT NOT NULL,state TEXT NOT NULL,updated REAL NOT NULL,error TEXT,PRIMARY KEY(tenant,focus_id))",
    ])


def _phase(db, tenant, event_ids, **values):
    """Server wall-clock milestones, visible only with their durable transaction.

    Unknown historical phases remain NULL. Source event time is never used as a
    processing timestamp; these timestamps are not a maximum-EPS measurement.
    """
    allowed = {"indexed_at", "analysis_started_at", "analysis_completed_at", "first_signal_at", "first_detection_at", "first_case_at", "first_composite_at", "ml_queued_at", "ml_started_at", "ml_finished_at", "sequence_queued_at", "sequence_started_at", "sequence_finished_at", "outcome", "error"}
    if set(values) - allowed:
        raise ValueError("Unknown server analysis phase")
    for eid in event_ids:
        row = db.execute("SELECT o.received,o.index_name FROM intelligence_event_outbox o JOIN receipts r ON r.tenant=o.tenant AND r.event_id=o.event_id AND r.received=o.received WHERE o.tenant=? AND o.event_id=? ORDER BY o.seq DESC LIMIT 1", (tenant, eid)).fetchone()
        if not row:
            continue
        db.execute("INSERT OR IGNORE INTO intelligence_event_phases(tenant,event_id,index_name,received) VALUES(?,?,?,?)", (tenant, eid, row["index_name"], row["received"]))
        for name, value in values.items():
            if name in {"outcome", "error"}:
                db.execute("UPDATE intelligence_event_phases SET " + name + "=? WHERE tenant=? AND event_id=? AND received=?", (value, tenant, eid,row["received"]))
            else:
                db.execute("UPDATE intelligence_event_phases SET " + name + "=coalesce(" + name + ",?) WHERE tenant=? AND event_id=? AND received=?", (value, tenant, eid,row["received"]))


def _value(value, path):
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _conditions(filters):
    if not isinstance(filters, list) or not 1 <= len(filters) <= 16:
        raise ValueError("Atomic rules require 1..16 positive typed filters")
    result = []
    for item in filters:
        if not isinstance(item, dict) or set(item) != {"field", "op", "value"}:
            raise ValueError("Filters require field/op/value")
        field, op, value = item["field"], item["op"], item["value"]
        if not isinstance(field, str) or not PATH.fullmatch(field) or field.split(".")[0] not in {"event", "projection", "raw"}:
            raise ValueError("Unsupported signal field path")
        if any(p in {"ground_truth", "scenario_label", "expected_detected", "label"} for p in field.split(".")):
            raise ValueError("Evaluation labels cannot be detector input")
        if op not in {"eq", "contains", "startswith", "gte", "gt", "in", "exists"}:
            raise ValueError("Unsupported signal filter operator")
        values = value if op == "in" else [value]
        if not isinstance(values, list) or not 1 <= len(values) <= 32 or any(type(v) not in {str, int, float, bool} or isinstance(v, str) and len(v) > 2048 or type(v) is float and not math.isfinite(v) for v in values):
            raise ValueError("Bounded finite typed filter value required")
        if op == "exists" and type(value) is not bool:
            raise ValueError("exists requires a boolean")
        result.append(dict(item))
    return result


def _matches(context, filters):
    for f in filters:
        actual, wanted, op = _value(context, f["field"]), f["value"], f["op"]
        if op == "exists":
            ok = (actual is not None) == wanted
        elif op == "eq":
            ok = type(actual) is type(wanted) and actual == wanted
        elif op == "in":
            ok = any(type(actual) is type(v) and actual == v for v in wanted)
        elif op in {"contains", "startswith"}:
            ok = isinstance(actual, str) and isinstance(wanted, str) and (wanted in actual if op == "contains" else actual.startswith(wanted))
        else:
            ok = type(actual) in {int, float} and type(wanted) in {int, float} and math.isfinite(actual) and (actual >= wanted if op == "gte" else actual > wanted)
        if not ok:
            return False
    return True


def _atomic_matches(context, definition):
    if 'condition_tree' in definition:
        from . import native_predicates
        if definition.get('condition_contract') != native_predicates.CONTRACT_DIGEST:
            raise ConflictError('Native condition evaluator changed; review a new policy revision')
        return native_predicates.matches(context, definition['condition_tree'])
    return _matches(context, definition['filters'])


def _definition(data):
    common = {"name", "kind", "indexes", "version", "enabled", "severity", "confidence_grade", "case_adapter", "window", "filters", "condition_tree", "inputs", "join_on", "minimum_independent_groups", "ordered", "clock_policy", "correlation"}
    if not isinstance(data, dict) or set(data) - common:
        raise ValueError("Unknown intelligence policy field")
    name, kind = data.get("name"), data.get("kind")
    if not isinstance(name, str) or not 1 <= len(name) <= 120 or kind not in {"atomic", "composite"}:
        raise ValueError("Policy needs name and atomic/composite kind")
    indexes = access.validate(data.get("indexes", []))
    if not indexes or indexes == ["*"]:
        raise ValueError("Intelligence policies require exact declared indexes")
    if type(data.get("version", 0)) is not int or data.get("version", 0) < 0 or type(data.get("enabled", False)) is not bool:
        raise ValueError("Typed version and enabled required")
    severity = data.get("severity", "medium")
    if severity not in SEVERITIES:
        raise ValueError("Unsupported signal severity")
    window = data.get("window", 300)
    if type(window) is not int or not 1 <= window <= 86400:
        raise ValueError("Composite/preservation window must be 1..86400 seconds")
    from .detection_automation import validate_case_adapter
    result = {"name": name, "kind": kind, "indexes": sorted(indexes), "enabled": data.get("enabled", False), "severity": severity,
              "confidence_grade": evidence_scope.text(data.get("confidence_grade", "source_reported"), "confidence_grade", 64), "window": window,
              "case_adapter": validate_case_adapter(data.get("case_adapter"))}
    if kind == "atomic":
        if 'correlation' in data:
            raise ValueError('Correlation requires a composite policy')
        if 'condition_tree' in data:
            if 'filters' in data:
                raise ValueError('Choose filters or condition_tree, not both')
            from . import native_predicates
            result['condition_tree'] = native_predicates.validate(data['condition_tree'])
            result['condition_contract'] = native_predicates.CONTRACT_DIGEST
        else:
            result["filters"] = _conditions(data.get("filters"))
    else:
        if 'condition_tree' in data:
            raise ValueError('Boolean original conditions require an atomic policy')
        inputs = data.get("inputs")
        if not isinstance(inputs, list) or not (1 if 'correlation' in data else 2) <= len(inputs) <= 8:
            raise ValueError("Composite requires 2..8 input selectors")
        for item in inputs:
            if not isinstance(item, dict) or not item or set(item) - {"rule_id", "kind"}:
                raise ValueError("Selectors accept exact rule_id and/or kind")
            if "rule_id" in item:
                evidence_scope.text(item["rule_id"], "rule_id")
            if "kind" in item and item["kind"] not in KINDS - {"observation"}:
                raise ValueError("Unsupported composite input kind")
            if item.get("kind") == "composite" and "rule_id" not in item:
                raise ValueError("Composite parents require an exact rule ID")
        if len({encode(i) for i in inputs}) != len(inputs):
            raise ValueError("Composite input selectors must differ")
        join = data.get("join_on", "entity")
        if join not in {"entity", "story", "flow", "process", "session"}:
            raise ValueError("Unsupported composite join")
        minimum = data.get("minimum_independent_groups", 1 if 'correlation' in data else 2)
        if type(minimum) is not int or not 1 <= minimum <= len(inputs) or type(data.get("ordered", False)) is not bool:
            raise ValueError("Typed evidence-group minimum and ordering required")
        clock = data.get("clock_policy", "reported")
        if clock not in {"reported", "strict"}:
            raise ValueError("Clock policy must be reported or strict")
        result.update(inputs=inputs, join_on=join, minimum_independent_groups=minimum, ordered=data.get("ordered", False), clock_policy=clock)
        if 'correlation' in data:
            from . import native_correlations
            result['correlation'] = native_correlations.validate(data['correlation'], inputs, window)
            result['correlation_contract'] = native_correlations.CONTRACT_DIGEST
    if len(encode(result).encode()) > 32768:
        raise ValueError("Intelligence policy exceeds 32 KiB")
    return result


def _cycles(db, tenant, identifier, definition):
    definitions = {r["id"]: json.loads(r["definition"]) for r in db.execute("SELECT id,definition FROM intelligence_policies WHERE tenant=?", (tenant,))}
    definitions[identifier] = definition
    def visit(node, path):
        if node in path:
            raise ValueError("Composite dependency cycle is forbidden")
        if len(path) >= 8:
            raise ValueError("Composite dependency depth exceeds eight")
        for item in definitions.get(node, {}).get("inputs", []):
            parent = item.get("rule_id")
            if parent in definitions:
                visit(parent, path | {node})
    visit(identifier, set())


def save_policy(store, who, data, identifier=None):
    definition = _definition(data)
    with principal.transaction(store, who, ("admin", "analyst"), write=True) as (db, actor):
        if not principal.contains(actor["allowed_indexes"], definition["indexes"]):
            raise PermissionError("Policy indexes are outside current authority")
        old = db.execute("SELECT * FROM intelligence_policies WHERE tenant=? AND id=?", (actor["tenant"], identifier)).fetchone() if identifier else None
        if identifier and not old:
            raise KeyError("Intelligence policy not found")
        if (old["version"] if old else 0) != data.get("version", 0):
            raise ConflictError("Intelligence policy version changed")
        if old and old["owner"] != actor["name"] and actor["role"] != "admin":
            raise PermissionError("Only owner or administrator can edit")
        if old:
            from . import sigma_imports
            sigma_imports.assert_native_editable(db, actor, identifier)
        identifier = identifier or "INT-" + uuid.uuid4().hex
        _cycles(db, actor["tenant"], identifier, definition)
        pins,model_pins = {},{}
        for selector in definition.get("inputs", []):
            rule_id=selector.get("rule_id","")
            if rule_id.startswith("ml:") or rule_id.startswith(('online:anomaly:','online:drift:')):
                required_kind='ml' if rule_id.startswith('ml:') else 'finding'
                if selector.get("kind",required_kind)!=required_kind:
                    raise ValueError("Reviewed model selector kind differs from its model family")
                pin=_input_model_pin(store,db,actor,rule_id)
                if not principal.contains(definition["indexes"],pin["indexes"]):
                    raise PermissionError("Composite must declare the model's complete index scope")
                model_pins[rule_id]=pin
            parent = db.execute("SELECT * FROM intelligence_policies WHERE tenant=? AND id=?", (actor["tenant"], selector.get("rule_id"))).fetchone()
            if parent:
                if not principal.contains(actor["allowed_indexes"], json.loads(parent["indexes"])):
                    raise KeyError("Parent policy not found in complete scope")
                pins[parent["id"]] = {"version": parent["version"], "definition_digest": release_manifest.digest(json.loads(parent["definition"]))}
        if pins:
            definition["input_revisions"] = pins
        if model_pins:
            definition["input_models"]=model_pins
        version = (old["version"] if old else 0) + 1
        now, digest = time.time(), release_manifest.digest(definition)
        db.execute("INSERT INTO intelligence_policies VALUES(?,?,?,?,?,?,?,'draft',NULL,NULL,?) ON CONFLICT(id) DO UPDATE SET indexes=excluded.indexes,kind=excluded.kind,definition=excluded.definition,version=excluded.version,state='draft',approver=NULL,approval_digest=NULL,updated=excluded.updated",
                   (identifier, actor["tenant"], old["owner"] if old else actor["name"], encode(definition["indexes"]), definition["kind"], encode(definition), version, now))
        db.execute("INSERT INTO intelligence_policy_revisions VALUES(?,?,?,?,?,?)", (identifier, actor["tenant"], version, encode(definition), digest, now))
        store.audit(db, actor["tenant"], actor["name"], "intelligence.policy.save", {"id": identifier, "version": version, "digest": digest, "approval_required": True})
        return {"id": identifier, "version": version, "state": "draft", "definition_digest": digest}


def review_policy(store, who, identifier, data):
    if not isinstance(data, dict) or set(data) != {"version", "approve", "reason"} or type(data["approve"]) is not bool:
        raise ValueError("Review requires version,approve,reason")
    reason = evidence_scope.text(data["reason"], "review reason", 2000)
    with principal.transaction(store, who, ("admin", "analyst"), write=True) as (db, actor):
        row = db.execute("SELECT * FROM intelligence_policies WHERE tenant=? AND id=?", (actor["tenant"], identifier)).fetchone()
        if not row or not principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
            raise KeyError("Intelligence policy not found")
        from . import sigma_imports
        sigma_imports.assert_native_editable(db, actor, identifier)
        if row["version"] != data["version"] or row["state"] != "draft":
            raise ConflictError("Policy is not this draft revision")
        owner = principal.current(db, {"name": row["owner"], "tenant": row["tenant"], "role": "analyst"}, ("admin", "analyst"))
        if owner["name"] == actor["name"] or not principal.contains(owner["allowed_indexes"], json.loads(row["indexes"])):
            raise PermissionError("An independent currently authorized reviewer is required")
        definition = json.loads(row["definition"])
        _cycles(db, row["tenant"], row["id"], definition)
        if data["approve"]:
            _parents_current(db, row["tenant"], definition,owner,store)
        state = "active" if data["approve"] and definition["enabled"] else "disabled"
        digest = release_manifest.digest({"id": identifier, "version": row["version"], "definition": definition, "approver": actor["name"]})
        db.execute("UPDATE intelligence_policies SET state=?,approver=?,approval_digest=?,updated=? WHERE id=?", (state, actor["name"], digest, time.time(), identifier))
        store.audit(db, actor["tenant"], actor["name"], "intelligence.policy.review", {"id": identifier, "state": state, "reason": reason, "approval_digest": digest})
        return {"id": identifier, "version": row["version"], "state": state}


def activate_imported_in_transaction(store, db, owner, reviewer, data, identifier=None):
    """Trusted import adapter transition; approval/binding commit in caller TX."""
    if not db.in_transaction:
        raise ConflictError('Imported activation requires a reserved transaction')
    owner = principal.current(db, owner, ('admin', 'analyst'))
    reviewer = principal.current(db, reviewer, ('admin', 'analyst'))
    if owner['tenant'] != reviewer['tenant'] or owner['name'] == reviewer['name']:
        raise PermissionError('Independent import owner and reviewer required')
    definition = _definition(data)
    if not definition['enabled'] or not ('condition_tree' in definition if definition['kind'] == 'atomic' else 'correlation' in definition):
        raise ValueError('Imported activation requires an enabled native Boolean atomic rule')
    if any(not principal.contains(person['allowed_indexes'], definition['indexes']) for person in (owner, reviewer)):
        raise PermissionError('Current complete import owner/reviewer scope required')
    old = db.execute('SELECT * FROM intelligence_policies WHERE tenant=? AND id=?', (owner['tenant'], identifier)).fetchone() if identifier else None
    if identifier and not old:
        raise KeyError('Imported native policy unavailable')
    if old and old['owner'] != owner['name']:
        raise PermissionError('Imported native owner changed')
    if (old['version'] if old else 0) != data.get('version', 0):
        raise ConflictError('Imported native revision changed')
    identifier = identifier or 'INT-' + uuid.uuid4().hex
    pins = {}
    for selector in definition.get('inputs', []):
        parent = db.execute('SELECT * FROM intelligence_policies WHERE tenant=? AND id=?', (owner['tenant'], selector['rule_id'])).fetchone()
        if not parent or not principal.contains(owner['allowed_indexes'], json.loads(parent['indexes'])):
            raise PermissionError('Complete current correlation parent scope required')
        _authority(db, parent)
        pins[parent['id']] = {'version': parent['version'], 'definition_digest': release_manifest.digest(json.loads(parent['definition']))}
    if pins:
        definition['input_revisions'] = pins
    _cycles(db, owner['tenant'], identifier, definition)
    _parents_current(db, owner['tenant'], definition, owner, store)
    version = (old['version'] if old else 0) + 1
    now = time.time()
    definition_digest = release_manifest.digest(definition)
    approval = release_manifest.digest({'id':identifier, 'version':version, 'definition':definition, 'approver':reviewer['name']})
    db.execute("INSERT INTO intelligence_policies VALUES(?,?,?,?,?,?,?,'active',?,?,?) ON CONFLICT(id) DO UPDATE SET indexes=excluded.indexes,kind=excluded.kind,definition=excluded.definition,version=excluded.version,state='active',approver=excluded.approver,approval_digest=excluded.approval_digest,updated=excluded.updated",
               (identifier, owner['tenant'], owner['name'], encode(definition['indexes']), definition['kind'], encode(definition), version, reviewer['name'], approval, now))
    db.execute('INSERT INTO intelligence_policy_revisions VALUES(?,?,?,?,?,?)', (identifier, owner['tenant'], version, encode(definition), definition_digest, now))
    store.audit(db, owner['tenant'], reviewer['name'], 'intelligence.policy.import.activate', {'id':identifier,'version':version,'owner':owner['name'],'definition_digest':definition_digest,'approval_digest':approval})
    return {'id':identifier,'version':version,'state':'active','definition_digest':definition_digest,'definition':definition}


@contextmanager
def _authority_memo(db):
    """One reserved caller transaction; fresh authority checks stay mandatory."""
    from . import cpu_sequence
    with cpu_sequence.authority_memo(db) as sequence:
        memo={"sequence":sequence,"pins":{},"research":{}}
        try:
            yield memo
        finally:
            memo["pins"].clear()
            memo['research'].clear()


def _input_model_pin(store,db,actor,rule_id,require_review=True,memo=None):
    definition_digest=None
    if rule_id.startswith('ml:research:'):
        from . import research_behavior
        row,snapshot=research_behavior._verify_model(db,actor,rule_id[len('ml:research:'):],require_active=require_review)
        if require_review and row['review_mode']!='live':
            raise PermissionError('Composite requires a reviewed live research model')
        return {'model_family':'research','id':row['id'],'revision':row['revision'],'digest':row['digest'],
                'feature_contract_digest':snapshot['feature_contract_digest'],'definition_digest':row['digest'],
                'indexes':json.loads(row['indexes']),'reviewed_at':row['reviewed']}
    if rule_id.startswith(('online:anomaly:','online:drift:')):
        from . import online_analytics
        row,snapshot=online_analytics._model(db,actor,rule_id.split(':',2)[2],require_review)
        return {'model_family':'online','id':row['id'],'revision':row['revision'],'digest':row['digest'],
                'feature_contract_digest':snapshot['feature_contract_digest'],'definition_digest':row['digest'],'indexes':json.loads(row['indexes'])}
    if rule_id.startswith("ml:sequence:"):
        from . import cpu_sequence
        kwargs={"memo":memo["sequence"]} if memo is not None else {}
        row,model_definition,_=cpu_sequence._load(db,actor,rule_id[len("ml:sequence:"):],require_review=require_review,**kwargs)
        if memo is not None:
            definition_digest=cpu_sequence.decoded_model(db,memo["sequence"],"sequence",row)[2]
        family="sequence"
    else:
        from . import cpu_ml
        row,model_definition,_=cpu_ml._load(db,actor,rule_id[3:],require_review=require_review)
        family="autoencoder"
    # _load still rereads the exact raw row and all current authority on each
    # call. Only its immutable decoded instance's deterministic digest is reused.
    key=(family,row["id"],row["revision"],row["digest"],id(model_definition))
    if memo is not None and key in memo["pins"]:
        return memo["pins"][key]
    pin={"model_family":family,"id":row["id"],"revision":row["revision"],"digest":row["digest"],"feature_contract_digest":model_definition["feature_contract_digest"],"definition_digest":definition_digest or release_manifest.digest(model_definition),"indexes":json.loads(row["indexes"])}
    if memo is not None:
        memo["pins"][key]=pin
    return pin


def _parents_current(db, tenant, definition, actor=None, store=None,memo=None):
    for identifier, pin in definition.get("input_revisions", {}).items():
        row = db.execute("SELECT * FROM intelligence_policies WHERE tenant=? AND id=?", (tenant, identifier)).fetchone()
        if not row or row["version"] != pin["version"] or release_manifest.digest(json.loads(row["definition"])) != pin["definition_digest"]:
            raise ConflictError("Pinned parent revision changed; review a new composite revision")
        _authority(db, row,memo=memo)
    for rule_id,pin in definition.get("input_models",{}).items():
        if actor is None or _input_model_pin(store,db,actor,rule_id,memo=memo)!=pin:
            raise ConflictError("Pinned input model changed; review a new composite revision")


def _authority(db, row,*,memo=None,include_parents=True):
    if row is None:
        raise KeyError("Intelligence policy unavailable")
    definition = json.loads(row["definition"])
    actor = principal.current(db, {"name": row["owner"], "tenant": row["tenant"], "role": "analyst"}, ("admin", "analyst"))
    reviewer = principal.current(db, {"name": row["approver"], "tenant": row["tenant"], "role": "analyst"}, ("admin", "analyst"))
    if actor["name"] == reviewer["name"] or any(not principal.contains(a["allowed_indexes"], definition["indexes"]) for a in (actor, reviewer)):
        raise PermissionError("Current policy owner/reviewer scope unavailable")
    expected = release_manifest.digest({"id": row["id"], "version": row["version"], "definition": definition, "approver": reviewer["name"]})
    if row["state"] != "active" or not definition["enabled"] or expected != row["approval_digest"]:
        raise ConflictError("Policy approval unavailable or changed")
    if 'condition_tree' in definition:
        from . import native_predicates
        if definition.get('condition_contract') != native_predicates.CONTRACT_DIGEST:
            raise ConflictError('Native condition evaluator changed; review a new revision')
    if 'correlation' in definition:
        from . import native_correlations
        if definition.get('correlation_contract') != native_correlations.CONTRACT_DIGEST:
            raise ConflictError('Correlation evaluator changed; review a new revision')
    from . import sigma_imports
    sigma_imports.validate_native_binding(db, actor, row, definition)
    if include_parents:
        _parents_current(db, row["tenant"], definition,actor,memo=memo)
    return actor, definition


def policies(store, who):
    with principal.transaction(store, who) as (db, actor):
        return [{**dict(r), "indexes": json.loads(r["indexes"]), "definition": json.loads(r["definition"])} for r in db.execute("SELECT * FROM intelligence_policies WHERE tenant=? ORDER BY id", (actor["tenant"],)) if principal.contains(actor["allowed_indexes"], json.loads(r["indexes"]))]


def journal_indexed(store, db, indexed_rows):
    """Only references in the existing indexing ACK; never model/graph work."""
    scopes = {}
    for row in indexed_rows:
        tenant = row["tenant"]
        if tenant not in scopes:
            scopes[tenant] = [set(json.loads(r[0])) for r in db.execute("SELECT indexes FROM intelligence_policies WHERE tenant=? AND state='active'", (tenant,))]
            scopes[tenant].extend(set(json.loads(r[0])) for r in db.execute("SELECT m.indexes FROM cpu_sequence_models m JOIN cpu_sequence_active a ON a.model_id=m.id AND a.tenant=m.tenant WHERE m.tenant=?",(tenant,)))
        payload = json.loads(row["payload"]) if isinstance(row["payload"], str) else row["payload"]
        index = payload.get("index", payload.get("index_name", "main"))
        if not any(index in s for s in scopes[tenant]):
            continue
        ident = release_manifest.digest([tenant, row["event_id"], row["received"]])
        db.execute("INSERT OR IGNORE INTO intelligence_event_outbox(id,tenant,event_id,index_name,received) VALUES(?,?,?,?,?)", (ident, tenant, row["event_id"], index, row["received"]))
        if db.execute("SELECT changes()").fetchone()[0]:
            _phase(db, tenant, [row["event_id"]], indexed_at=time.time(), outcome="indexed")


def protected_ids(db, tenant, ids, now=None):
    if not ids:
        return set()
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='intelligence_cursors'").fetchone():
        return set()
    now = time.time() if now is None else now
    cursor = db.execute("SELECT cursor FROM intelligence_cursors WHERE worker='events'").fetchone()[0]
    protected = {r[0] for r in db.execute("SELECT event_id FROM intelligence_event_outbox WHERE tenant=? AND seq>? AND event_id IN (SELECT value FROM json_each(?)) UNION SELECT event_id FROM intelligence_evidence_refs WHERE tenant=? AND protected_until>? AND event_id IN (SELECT value FROM json_each(?)) UNION SELECT event_id FROM intelligence_ml_jobs WHERE tenant=? AND state='pending' AND event_id IN (SELECT value FROM json_each(?))", (tenant, cursor, encode(ids), tenant, now, encode(ids), tenant, encode(ids)))}
    pending = db.execute("SELECT p.id,p.version,p.definition,p.indexes,s.version AS state_version,s.last_seq,s.snapshot_seq,s.window_end FROM intelligence_policies p LEFT JOIN intelligence_composite_state s ON s.id=p.id WHERE p.tenant=? AND p.state='active' AND p.kind='composite'", (tenant,)).fetchall()
    requested = set(ids)
    for state in pending:
        definition = json.loads(state["definition"])
        current=state["state_version"]==state["version"]
        last_seq=state["last_seq"] if current else 0
        cutoff=_candidate_cutoff(db,tenant,definition,state["id"],last_seq,now)
        if current and state["snapshot_seq"]>last_seq:
            cutoff=min(cutoff,state["window_end"]-definition["window"])
        predicate,args=_cohort_sql({"tenant":tenant},definition,state["id"],cutoff)
        # Include the final delayed-derived input before its next frozen capture.
        # Queue references alone disappear when that original's cursor commits.
        for row in db.execute("SELECT s.event_ids FROM intelligence_signals s WHERE "+predicate+" AND EXISTS (SELECT 1 FROM json_each(s.event_ids) e WHERE e.value IN (SELECT value FROM json_each(?)))",[*args,encode(ids)]):
            protected.update(requested&set(json.loads(row[0])))
    from importlib.util import find_spec
    if find_spec(__package__+".intelligence_sequence"):
        from . import intelligence_sequence
        protected.update(intelligence_sequence.protected_ids(db,tenant,ids,now))
    from . import sequence_event_time
    protected.update(sequence_event_time.protected_ids(db,tenant,ids))
    from . import research_behavior
    protected.update(research_behavior.protected_ids(db,tenant,ids,now))
    from . import online_analytics
    protected.update(online_analytics.protected_ids(db,tenant,ids))
    return protected


def _projection(db, tenant, record):
    proof = db.execute("SELECT * FROM source_event_receipts WHERE tenant=? AND event_id=?", (tenant, record["event_id"])).fetchone()
    if not proof or not proof["source_definition"]:
        return None
    source = db.execute("SELECT state,version FROM source_registry WHERE tenant=? AND id=?", (tenant, proof["source_id"])).fetchone()
    if not source or source["state"] != "active" or source["version"] != proof["source_version"]:
        raise PermissionError("Registered source revoked or changed")
    from .security_schema import project
    return project({**record, "index": record["index_name"]}, json.loads(proof["source_definition"]))


def _projections(db, tenant, records):
    """Same projection semantics, with fresh source facts in two bounded reads.

    Caller still checks every original's current evidence authority. This shares
    no permission or projection result across calls or transactions.
    """
    if not records:
        return {}
    if len(records) > 32:
        raise ValueError("At most 32 publication projections are supported")
    receipts = {row["event_id"]: row for row in db.execute(
        "SELECT * FROM source_event_receipts WHERE tenant=? AND event_id IN (SELECT value FROM json_each(?))",
        (tenant, encode(list(records))))}
    identifiers = sorted({row["source_id"] for row in receipts.values() if row["source_definition"]})
    sources = {row["id"]: row for row in db.execute(
        "SELECT id,state,version FROM source_registry WHERE tenant=? AND id IN (SELECT value FROM json_each(?))",
        (tenant, encode(identifiers)))} if identifiers else {}
    from .security_schema import project
    definitions, result = {}, {}
    for identifier, record in records.items():
        proof = receipts.get(identifier)
        if not proof or not proof["source_definition"]:
            result[identifier] = None
            continue
        source = sources.get(proof["source_id"])
        if not source or source["state"] != "active" or source["version"] != proof["source_version"]:
            raise PermissionError("Registered source revoked or changed")
        text = proof["source_definition"]
        if text not in definitions:
            definitions[text] = json.loads(text)
        result[identifier] = project({**record, "index": record["index_name"]}, definitions[text])
    return result


def _node(db, tenant, story_id, identifier, kind, indexes, event_id, body):
    old = db.execute("SELECT indexes,event_ids,body FROM intelligence_story_nodes WHERE tenant=? AND id=?", (tenant, identifier)).fetchone()
    scope = sorted(set(indexes) | (set(json.loads(old["indexes"])) if old else set()))
    events = sorted({event_id} | (set(json.loads(old["event_ids"])) if old else set()))
    db.execute("INSERT INTO intelligence_story_nodes VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET indexes=excluded.indexes,event_ids=excluded.event_ids", (identifier, tenant, story_id, kind, encode(scope), encode(events), encode(body)))


def _story(db, store, actor, record, projection):
    tenant, indexes, event_id = actor["tenant"], [record["index_name"]], record["event_id"]
    process_key = identity_resolver.relation_key(store, actor, projection, "process") if projection else None
    event_node = "EVENT-" + release_manifest.digest([tenant, event_id])
    existing_event = db.execute("SELECT story_id FROM intelligence_story_nodes WHERE tenant=? AND id=?", (tenant, event_node)).fetchone()
    if existing_event:
        from . import intelligence_story_reconcile
        canonical = intelligence_story_reconcile.current(db, actor, existing_event["story_id"])
        if not canonical:
            raise KeyError("Existing Story is outside complete current scope")
        return canonical, process_key
    root_key, parent_node = process_key, None
    if projection and process_key and projection["process"].get("parent_guid"):
        from . import intelligence_story_reconcile
        candidates = []
        for row in intelligence_story_reconcile._nearby(db, tenant, projection, strict=False):
            parent = json.loads(row["body"]).get("projection")
            if parent and principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])) and identity_resolver.parent_link(parent, projection) and intelligence_story_reconcile.current(db,actor,row["story_id"]):
                candidates.append(row)
        if len(candidates) == 1:
            parent_node = candidates[0]
            parent_story = db.execute("SELECT root_key FROM intelligence_stories WHERE id=? AND tenant=?", (parent_node["story_id"], tenant)).fetchone()
            root_key = parent_story[0] if parent_story else None
    # Unknown identity remains an event-scoped story, never a fabricated process.
    root_key = root_key or release_manifest.digest([tenant, "event", event_id])
    story_id = "STORY-" + release_manifest.digest([tenant, root_key])
    old = db.execute("SELECT * FROM intelligence_stories WHERE id=? AND tenant=?", (story_id, tenant)).fetchone()
    scope = sorted(set(indexes) | (set(json.loads(old["indexes"])) if old else set()))
    body = {"root_key": root_key, "identity_basis": "reported_process_instance" if process_key else "unresolved_event",
            "causality_proven": False, "automatic_endpoint_authorization": False, "clock_assurance": (projection or {}).get("clock_precision"), "native_capture_proven": False}
    db.execute("INSERT INTO intelligence_stories VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET indexes=excluded.indexes,updated=max(updated,excluded.updated),version=version+1", (story_id, tenant, encode(scope), root_key, 1, record["event_time"], record["event_time"], encode(body)))
    _node(db, tenant, story_id, event_node, "event", indexes, event_id, {"event_id": event_id, "event_time": record["event_time"], "received": record["received"], "admission_digest": record["admission_digest"], "action": (projection or {}).get("action"), "source_id": (projection or {}).get("source_id"), "observed_not_created": _value(record["raw"], "xdr.data.event.action") in {"process_observed", "network_connection_observed"}})
    if process_key:
        process_node = "PROCESS-" + release_manifest.digest([tenant, process_key])
        _node(db, tenant, story_id, process_node, "process", indexes, event_id, {"projection": projection, "identity_key": process_key})
        _edge(db, tenant, story_id, process_node, event_node, "performed_observation", "exact_reported_process_instance", indexes, [event_id], record["event_time"])
        if parent_node:
            parent_proof=json.loads(parent_node["body"])["projection"]["event_id"]
            _edge(db, tenant, story_id, parent_node["id"], process_node, "reported_parent", "explicit_parent_guid_and_incarnation", indexes, [event_id,parent_proof], record["event_time"])
    if projection and projection.get("flow"):
        key = identity_resolver.relation_key(store, actor, projection, "flow")
        flow_node = "FLOW-" + release_manifest.digest([tenant, key, story_id])
        _node(db, tenant, story_id, flow_node, "flow", indexes, event_id, {"flow": projection["flow"], "realm": projection["realm"], "ownership_proven": False})
        _edge(db, tenant, story_id, event_node, flow_node, "reported_flow", "complete_reported_five_tuple", indexes, [event_id], record["event_time"])
    file_object = (projection or {}).get("file") or _value(record["raw"], "xdr.data.file")
    if isinstance(file_object, dict) and file_object.get("path"):
        file_key = release_manifest.digest([tenant, (projection or {}).get("source_id"), file_object])
        file_node = "FILE-" + release_manifest.digest([file_key, story_id])
        _node(db, tenant, story_id, file_node, "file", indexes, event_id, {"file": file_object, "object_version_known": bool(file_object.get("object_id") or file_object.get("sha256") or _value(file_object, "hash.sha256"))})
        _edge(db, tenant, story_id, event_node, file_node, "reported_file_activity", "original_event_field", indexes, [event_id], record["event_time"])
    db.execute("INSERT INTO intelligence_story_history(tenant,story_id,event_id,record,at) VALUES(?,?,?,?,?)", (tenant, story_id, event_id, encode({"event_node": event_node, "root_key": root_key, "parent_resolved": bool(parent_node)}), time.time()))
    if process_key:
        from . import intelligence_story_reconcile
        story_id = intelligence_story_reconcile.reconcile(store,db,actor,story_id,process_node)
    return story_id, process_key


def _edge(db, tenant, story_id, left, right, relation, basis, indexes, event_ids, event_time):
    identifier = release_manifest.digest([tenant, story_id, left, right, relation, sorted(event_ids)])
    db.execute("INSERT OR IGNORE INTO intelligence_story_edges VALUES(?,?,?,?,?,?,?,?,?,?,?)", (identifier, tenant, story_id, left, right, relation, basis, "source_reported", encode(sorted(set(event_ids))), encode(indexes), event_time))


def _dependencies(sets, groups=None):
    components = []
    for position, values in enumerate(sets):
        values = set(values)
        if groups and groups[position]:
            values.add("dependency-group:" + groups[position])
        overlaps = [i for i, old in enumerate(components) if values & old]
        for i in reversed(overlaps):
            values |= components.pop(i)
        components.append(values)
    return {"disjoint_original_groups": len(components), "shared_originals": len(set().union(*map(set, sets))) < sum(len(set(s)) for s in sets),
            "statistical_independence_proven": False, "malicious_probability": None}


def publish_in_transaction(store, db, actor, data, *, memo=None):
    required = {"event_ids", "kind", "rule_id", "rule_revision", "features", "severity", "confidence_grade"}
    optional = {"parent_signal_ids", "entity_key", "story_id", "context_digest", "model_digest", "metadata", "mode", "window", "definition_digest"}
    if not isinstance(data, dict) or not required <= set(data) or set(data) - required - optional:
        raise ValueError("Typed signal identity/evidence/features required")
    actor = principal.current(db, actor, ("admin", "analyst"))
    event_ids = data["event_ids"]
    if not isinstance(event_ids, list) or not 1 <= len(event_ids) <= 32 or len(set(event_ids)) != len(event_ids) or any(not isinstance(v, str) or not 1 <= len(v) <= 256 for v in event_ids):
        raise ValueError("Signal requires 1..32 unique exact original IDs")
    if data["kind"] not in KINDS or data["severity"] not in SEVERITIES or type(data["rule_revision"]) is not int or data["rule_revision"] < 1:
        raise ValueError("Signal kind/severity/revision unavailable")
    rule_id = evidence_scope.text(data["rule_id"], "rule_id")
    confidence = evidence_scope.text(data["confidence_grade"], "confidence_grade", 64)
    if not isinstance(data["features"], dict) or len(encode(data["features"]).encode()) > 16384:
        raise ValueError("Bounded feature dictionary required")
    if not isinstance(data.get('metadata',{}),dict):
        raise ValueError('Typed signal metadata required')
    mode = data.get("mode", "live")
    if mode not in {"live", "shadow"}:
        raise ValueError("Signal mode must be live/shadow")
    parents = data.get("parent_signal_ids", [])
    managed = db.execute("SELECT * FROM intelligence_policies WHERE tenant=? AND id=?", (actor['tenant'], rule_id)).fetchone() if data['kind'] == 'composite' else None
    managed_definition = json.loads(managed['definition']) if managed else {}
    parent_limit = 32 if 'correlation' in managed_definition else 8
    if not isinstance(parents, list) or len(parents) > parent_limit or len(set(parents)) != len(parents):
        raise ValueError("Bounded unique parent signals required")
    records = evidence_scope.originals(store, actor, event_ids)
    evidence_scope.recheck(db, actor, records)
    original_sets, dependency_groups = [], []
    research_memo = memo.get('research') if memo is not None else None
    evidence_walk = {'count': 0, 'cache': {}}
    for parent_id in parents:
        row = db.execute("SELECT * FROM intelligence_signals WHERE tenant=? AND id=? AND mode=?", (actor["tenant"], parent_id, mode)).fetchone()
        if not row or not principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
            raise KeyError("Parent signal not found")
        ids = json.loads(row["event_ids"])
        if not set(ids) <= set(event_ids):
            raise ValueError("Composite must retain complete original ancestry")
        from . import signal_evidence
        original_sets.append(signal_evidence.ancestry(store, db, actor, json.loads(row['body']), memo=research_memo, walk=evidence_walk)['event_ids'])
        dependency_groups.append(json.loads(row["body"]).get("metadata", {}).get("dependency_group"))
    indexes = sorted({r["index_name"] for r in records.values()})
    from . import signal_evidence
    full_evidence = signal_evidence.ancestry(store, db, actor, {**data, 'indexes': indexes}, memo=research_memo, walk=evidence_walk)
    indexes = full_evidence['indexes']
    first = min(records.values(), key=lambda r: (r["event_time"], r["event_id"]))
    projections = _projections(db, actor["tenant"], records)
    projection = projections[first["event_id"]]
    metadata = dict(data.get("metadata", {}))
    if "sigma_import" in metadata:
        raise ValueError("Sigma import provenance is server-derived")
    if 'evidence_manifest' in metadata and not (data['kind'] == 'ml' and rule_id.startswith('ml:research:')):
        raise ValueError('Long evidence provenance requires an immutable research run')
    if data["kind"] == "atomic":
        policy = db.execute("SELECT * FROM intelligence_policies WHERE tenant=? AND id=?", (actor["tenant"], rule_id)).fetchone()
        if policy is not None:
            from . import sigma_imports
            definition = json.loads(policy["definition"])
            origin = sigma_imports.signal_metadata(db, actor, policy, definition)
            if origin:
                _authority(db, policy)
                if (data["rule_revision"] != policy["version"] or parents or len(records) != 1
                    or data.get("definition_digest") != release_manifest.digest(definition)
                    or not _atomic_matches({"event": first, "raw": first["raw"], "projection": projection or {}}, definition)):
                    raise ConflictError("Managed Sigma signal must match current approved native predicate and original")
                metadata.update(origin)
    if 'correlation' in managed_definition:
        from . import native_correlations, sigma_imports
        _authority(db, managed)
        native_correlations.validate_publication(store, db, actor, data, managed_definition)
        metadata.update(sigma_imports.signal_metadata(db, actor, managed, managed_definition) or {})
    if data["kind"] == "ml" and mode == "live":
        if not rule_id.startswith("ml:"):
            raise ValueError("ML signals require an exact immutable model ID")
        if rule_id.startswith('ml:research:'):
            from . import advanced_intelligence
            advanced_intelligence.validate_signal(store,db,actor,data,memo=research_memo)
        elif rule_id.startswith("ml:sequence:"):
            from . import cpu_sequence
            cpu_sequence.validate_publication(store,db,actor,rule_id[len("ml:sequence:"):],data.get("model_digest"),data["rule_revision"])
        else:
            from . import cpu_ml
            cpu_ml.validate_publication(store, db, actor, rule_id[3:], data.get("model_digest"), data["rule_revision"])
    if mode == "live":
        story_id, process_key = _story(db, store, actor, first, projection)
    else:
        story_id, process_key = None, None
    declared_story = data.get("story_id")
    if declared_story:
        story = db.execute("SELECT * FROM intelligence_stories WHERE tenant=? AND id=?", (actor["tenant"], declared_story)).fetchone()
        if not story or not principal.contains(actor["allowed_indexes"], json.loads(story["indexes"])):
            raise KeyError("Story not found in complete scope")
        members = {r[0] for r in db.execute("SELECT event_id FROM intelligence_story_history WHERE tenant=? AND story_id=?", (actor["tenant"], declared_story))}
        if not set(event_ids) <= members:
            raise ValueError("Declared story must contain every original")
        story_id = declared_story
    association_keys = {}
    if projection:
        for name, relation in (("flow", "flow"), ("process", "process"), ("session", "auth_session")):
            association_keys[name] = identity_resolver.relation_key(store, actor, projection, relation)
    entity_key = data.get("entity_key") or process_key or association_keys.get("flow") or release_manifest.digest([actor["tenant"], "event", first["event_id"]])
    if not isinstance(entity_key, str) or not 1 <= len(entity_key) <= 256:
        raise ValueError("Bounded entity key required")
    context = {"parser": (projection or {}).get("parser_digest"), "sources": [], "model_digest": data.get("model_digest")}
    for record in records.values():
        source = db.execute("SELECT source_id,source_version,receipt_digest FROM source_event_receipts WHERE tenant=? AND event_id=?", (actor["tenant"], record["event_id"])).fetchone()
        if source:
            context["sources"].append(dict(source))
    context_digest = data.get("context_digest") or release_manifest.digest(context)
    definition_digest = data.get("definition_digest") or release_manifest.digest([rule_id, data["rule_revision"]])
    identifier = "SIG-" + release_manifest.digest([actor["tenant"], mode, data["kind"], rule_id, data["rule_revision"], sorted(event_ids), sorted(parents), context_digest])
    old = db.execute("SELECT body FROM intelligence_signals WHERE tenant=? AND id=?", (actor["tenant"], identifier)).fetchone()
    if old:
        return {**json.loads(old[0]), "duplicate": True}
    window = data.get("window", 86400)
    if type(window) is not int or not 1 <= window <= 86400:
        raise ValueError("Bounded signal input protection required")
    times = [r["event_time"] for r in records.values()]
    precisions = [(p or {}).get("clock_precision") for p in projections.values()]
    precision = max(precisions) if all(type(p) in {int, float} and math.isfinite(p) for p in precisions) else None
    body = {"schema": SCHEMA, "id": identifier, "tenant": actor["tenant"], "indexes": indexes, "event_ids": sorted(event_ids), "parent_signal_ids": sorted(parents),
            "entity_key": entity_key, "story_id": story_id, "kind": data["kind"], "rule_id": rule_id, "rule_revision": data["rule_revision"],
            "features": data["features"], "severity": data["severity"], "confidence_grade": confidence, "created": time.time(), "mode": mode,
            "definition_digest": definition_digest, "context_digest": context_digest, "model_digest": data.get("model_digest"), "association_keys": association_keys,
            "event_window": {"start": min(times), "end": max(times), "precision_seconds": precision, "clock_attested": False}, "originals": [evidence_scope.reference(r) for r in sorted(records.values(), key=lambda r: r["event_id"])],
            "evidence_dependency": _dependencies(original_sets or [full_evidence['event_ids']], dependency_groups or None), "metadata": metadata, "malicious_probability": None,
            "automatic_endpoint_authorization": False}
    if len(encode(body).encode()) > 256 * 1024:
        raise CapacityError("Signal evidence body exceeds 256 KiB")
    db.execute("INSERT INTO intelligence_signals(id,tenant,indexes,event_ids,parent_signal_ids,entity_key,story_id,kind,rule_id,rule_revision,features,severity,confidence_grade,created,mode,definition_digest,context_digest,body) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
               (identifier, actor["tenant"], encode(indexes), encode(body["event_ids"]), encode(parents), entity_key, story_id, body["kind"], rule_id, body["rule_revision"], encode(body["features"]), body["severity"], confidence, body["created"], mode, definition_digest, context_digest, encode(body)))
    if mode == "live":
        signal_evidence.retain(store, db, actor, body, full_evidence)
        db.executemany("INSERT INTO intelligence_evidence_refs VALUES(?,?,?,?)", [(actor["tenant"], eid, identifier, max(time.time(), max(times)) + window) for eid in full_evidence['event_ids']])
        _phase(db,actor["tenant"],event_ids,first_signal_at=body["created"],**({"first_detection_at":body["created"]} if body["kind"]!="observation" else {}),**({"first_composite_at":body["created"]} if body["kind"]=="composite" else {}))
    return {**body, "duplicate": False}


def publish(store, who, data):
    with store.segment_lock.read(deadline=time.monotonic()+3), principal.transaction(store, who, ("admin", "analyst"), write=True) as (db, actor):
        return publish_in_transaction(store, db, actor, data)


def _flat(record):
    result = {k: v for k, v in record.items() if k != "raw"}
    def walk(value, path):
        if isinstance(value, dict):
            for key, child in value.items():
                walk(child, path + "." + key)
        elif type(value) in {str, int, float, bool} or value is None:
            result[path] = value
    walk(record["raw"], "raw")
    return result


def _case(store, db, actor, policy, definition, signal, *, memo=None):
    adapter = definition.get("case_adapter")
    if not adapter or signal["mode"] != "live":
        return None
    from . import detections
    records = evidence_scope.originals(store, actor, signal["event_ids"])
    evidence_scope.recheck(db, actor, records)
    events = [_flat(r) for r in sorted(records.values(), key=lambda r: (r["event_time"], r["event_id"]))]
    from . import intelligence_story_reconcile
    story_id = intelligence_story_reconcile.current(db,actor,signal["story_id"]) if signal.get("story_id") else None
    entity = "story:" + story_id if definition.get("join_on") == "story" and story_id else "intelligence:" + signal["entity_key"]
    field = adapter["entity_field"]
    match = {"entity": entity, "entity_field": field, "steps": [{"step": "composite" if policy["kind"] == "composite" else "atomic", "events": events, "matched": len(events)}],
             "event_ids": sorted(records), "indexes": signal["indexes"], "severity": adapter["severity"], "risk_weight": adapter["risk_score"], "mitre": adapter["mitre"],
             "explanation": "Evidence-bound " + policy["kind"] + " signal; reported association is not causal proof", "analysis": {"signal_id": signal["id"], "story_id": story_id, "recorded_story_id": signal["story_id"], "parent_signal_ids": signal["parent_signal_ids"], "evidence_dependency": signal["evidence_dependency"]}}
    declared = {**adapter, "steps": [], "evaluation_delay": 0}
    from . import content_notices
    match["analysis"]["content_notices"] = content_notices.for_signal(db, actor, signal, memo=memo)
    identity = {"id": "intelligence:" + policy["id"] + ":" + str(policy["version"]), "tenant": actor["tenant"], "name": definition["name"], "version": policy["version"]}
    outcome=detections._emit_matches(db, store, identity, declared, [match], signal["event_window"]["end"], mode="intelligence", scheduled_end=signal["event_window"]["end"], actor=actor["name"], guard=actor)
    if outcome.get("emitted",0):
        from . import signal_evidence
        full_evidence = signal_evidence.ancestry(store, db, actor, signal, memo=memo.get('research') if memo is not None else None)
        signal_evidence.protect_case(db, actor, signal, full_evidence)
        _phase(db,actor["tenant"],signal["event_ids"],first_case_at=time.time())
    return outcome


def _decision(db, row, actor, signal, reason, detail=None):
    detail = encode(detail or {})
    if db.execute("SELECT 1 FROM intelligence_decisions WHERE tenant=? AND policy_id=? AND version=? AND signal_id IS ? AND reason=? AND detail=?", (row["tenant"], row["id"], row["version"], signal, reason, detail)).fetchone():
        return
    db.execute("INSERT INTO intelligence_decisions(tenant,policy_id,version,indexes,signal_id,reason,detail,at) VALUES(?,?,?,?,?,?,?,?)", (row["tenant"], row["id"], row["version"], row["indexes"], signal, reason, detail, time.time()))


def _outbox(store, cancel=None, maximum=16, deadline=None):
    def legacy():
        with store.control() as db:
            cursor = db.execute("SELECT cursor FROM intelligence_cursors WHERE worker='events'").fetchone()[0]
            rows = [dict(r) for r in db.execute("SELECT * FROM intelligence_event_outbox WHERE seq>? ORDER BY seq LIMIT ?", (cursor, maximum))]
            declared={}
            for tenant in {row["tenant"] for row in rows}:
                declared[tenant]=[dict(r) for r in db.execute("SELECT * FROM intelligence_policies WHERE tenant=? AND state='active' ORDER BY id",(tenant,))]
        completed = 0
        for item in rows:
            if cancel is not None and cancel.is_set() or deadline and time.monotonic() >= deadline:
                break
            with store.write_lock,store.control(local=True) as db:
                _phase(db,item["tenant"],[item["event_id"]],analysis_started_at=time.time())
            active=[r for r in declared[item["tenant"]] if item["index_name"] in json.loads(r["indexes"])]
            owners={}
            for policy in active:
                owners.setdefault(policy["owner"],[]).append(policy)
            processed, job_owner = False, None
            for owner,owned in owners.items():
                try:
                    with store.segment_lock.read(deadline=time.monotonic()+3), principal.transaction(store, {"name": owner, "tenant": item["tenant"], "role": "analyst"}, ("admin", "analyst"), write=True) as (db, actor):
                        authorized=[]
                        for policy in owned:
                            fresh=db.execute("SELECT * FROM intelligence_policies WHERE tenant=? AND id=?",(item["tenant"],policy["id"])).fetchone()
                            try:
                                if fresh is not None and fresh["owner"]!=owner:
                                    raise PermissionError("Policy owner changed during the declared turn")
                                # Observation is an original, not a composite
                                # decision. Its source/scope/approval are current;
                                # downstream model pins are checked at composite use.
                                checked_actor,definition=_authority(db,fresh,include_parents=fresh is not None and fresh["kind"]=="atomic")
                                if checked_actor!=actor:
                                    raise PermissionError("Policy principal changed during original processing")
                                if item["index_name"] in definition["indexes"]:
                                    authorized.append((fresh,definition))
                            except (PermissionError,KeyError,ConflictError,ValueError) as exc:
                                _decision(db,policy,None,None,"original_excluded",{"event_id":item["event_id"],"reason":type(exc).__name__})
                        if not authorized:
                            continue
                        record = evidence_scope.originals(store, actor, [item["event_id"]])[item["event_id"]]
                        projection = _projection(db, actor["tenant"], record)
                        publish_in_transaction(store, db, actor, {"event_ids": [item["event_id"]], "kind": "observation", "rule_id": "indexed-observation", "rule_revision": 1,
                            "features": {}, "severity": "info", "confidence_grade": "authenticated_source_assertion" if projection else "admitted_original", "window": max(definition["window"] for _,definition in authorized)})
                        for fresh,definition in authorized:
                            if fresh["kind"] != 'atomic':
                                continue
                            try:
                                matched = _atomic_matches({"event": record, "raw": record["raw"], "projection": projection or {}}, definition)
                            except ValueError as exc:
                                _decision(db, fresh, actor, None, 'predicate_excluded', {'event_id':item['event_id'],'reason':str(exc)[:500]})
                                continue
                            if matched:
                                signal = publish_in_transaction(store, db, actor, {"event_ids": [item["event_id"]], "kind": "atomic", "rule_id": fresh["id"], "rule_revision": fresh["version"], "features": {}, "severity": definition["severity"], "confidence_grade": definition["confidence_grade"], "window": definition["window"], "definition_digest": release_manifest.digest(definition)})
                                outcome = _case(store, db, actor, fresh, definition, signal)
                                if not signal["duplicate"]:
                                    _decision(db, fresh, actor, signal["id"], "matched", {"case_emission": outcome})
                    processed, job_owner = True, actor["name"]
                except (PermissionError, KeyError, ConflictError, ValueError) as exc:
                    with store.write_lock, store.control(local=True) as db:
                        for policy in owned:
                            _decision(db, policy, None, None, "original_excluded", {"event_id": item["event_id"], "reason": type(exc).__name__})
                # ML itself uses an isolated bounded worker and current reviewed model.
            with store.write_lock, store.control(local=True) as db:
                if processed:
                    db.execute("INSERT OR IGNORE INTO intelligence_ml_jobs VALUES(?,?,?,?,?,'pending',0,NULL,0,?,NULL)", (item["id"], item["tenant"], item["event_id"], job_owner, item["index_name"], time.time()))
                    _phase(db,item["tenant"],[item["event_id"]],ml_queued_at=time.time())
                db.execute("UPDATE intelligence_cursors SET cursor=? WHERE worker='events'", (item["seq"],))
                _phase(db,item["tenant"],[item["event_id"]],analysis_completed_at=time.time(),outcome="processed" if processed else "excluded")
            completed += 1
        return completed

    import sys

    from . import intelligence_original_batch

    return intelligence_original_batch.run(store, sys.modules[__name__], cancel, maximum, deadline, legacy)


def _ml_due(store, cancel=None, maximum=32, coalesce=False):
    now=time.time()
    with store.control() as db:
        scopes=[dict(r) for r in db.execute("SELECT j.tenant,j.owner,j.index_name,count(*) AS n,min(j.created) AS oldest,coalesce(s.served,0) AS served FROM intelligence_ml_jobs j LEFT JOIN intelligence_ml_scope_schedule s ON s.tenant=j.tenant AND s.owner=j.owner AND s.index_name=j.index_name WHERE j.state='pending' AND j.retry_at<=? GROUP BY j.tenant,j.owner,j.index_name ORDER BY served,oldest,j.tenant,j.owner,j.index_name LIMIT 64",(now,))]
    from . import cpu_ml
    groups={}
    for scope in scopes:
        tenant,owner,index=scope["tenant"],scope["owner"],scope["index_name"]
        try:
            models = cpu_ml.compatible_models(store, {"name":owner,"tenant":tenant,"role":"analyst"}, [index])
            identifier = models[0]["id"] if models else None
            group=groups.setdefault((tenant,owner,identifier),{"scopes":[],"n":0,"oldest":scope["oldest"],"served":scope["served"],"authority_indexes":models[0]["indexes"] if models else []})
            group["scopes"].append(scope);group["n"]+=scope["n"];group["oldest"]=min(group["oldest"],scope["oldest"]);group["served"]=min(group["served"],scope["served"])
        except (PermissionError,KeyError,ConflictError) as exc:
            with store.write_lock,store.control(local=True) as db:
                rows=db.execute("SELECT event_id,id FROM intelligence_ml_jobs WHERE state='pending' AND retry_at<=? AND tenant=? AND owner=? AND index_name=? ORDER BY created,id LIMIT ?",(now,tenant,owner,index,maximum)).fetchall()
                for job in rows:
                    db.execute("UPDATE intelligence_ml_jobs SET state='excluded',finished=?,attempts=attempts+1,error=? WHERE id=? AND state='pending'",(time.time(),type(exc).__name__,job["id"]))
                    _phase(db,tenant,[job["event_id"]],ml_finished_at=time.time(),error=type(exc).__name__)
                db.execute("INSERT INTO intelligence_ml_scope_schedule VALUES(?,?,?,?) ON CONFLICT(tenant,owner,index_name) DO UPDATE SET served=excluded.served",(tenant,owner,index,now))
    completed = 0
    # Readiness is per compatible reviewed model, never the global queue count.
    # Persistent process reuse is owned by the CPU runtime; this scheduler only
    # decides which exact authorized originals belong in each bounded request.
    for (tenant, owner, identifier),group in sorted(groups.items(),key=lambda item:(item[1]["served"],item[1]["oldest"],str(item[0]))):
        if cancel is not None and cancel.is_set():
            break
        if completed>=maximum:
            break
        indexes=sorted(scope["index_name"] for scope in group["scopes"])
        diagnostic_indexes=sorted(set(indexes)|set(group["authority_indexes"]))
        ready=not coalesce or identifier is None or group["n"]>=16 or now-group["oldest"]>=5
        with store.write_lock,store.control(local=True) as db:
            previous=db.execute("SELECT state,pending_count,oldest_created FROM intelligence_ml_batch_diagnostics WHERE tenant=? AND owner=? AND model_id IS ? AND indexes=? ORDER BY id DESC LIMIT 1",(tenant,owner,identifier,encode(diagnostic_indexes))).fetchone()
            if not ready:
                if not previous or tuple(previous)!=("waiting",group["n"],group["oldest"]):
                    db.execute("INSERT INTO intelligence_ml_batch_diagnostics(tenant,owner,model_id,indexes,pending_count,oldest_created,ready,selected,state,detail,at) VALUES(?,?,?,?,?,?,0,0,'waiting',?,?)",(tenant,owner,identifier,encode(diagnostic_indexes),group["n"],group["oldest"],encode({"minimum_batch":16,"max_wait_seconds":5,"group_basis":"tenant/owner/exact-compatible-reviewed-model"}),now))
                continue
            batch=[dict(r) for r in db.execute("SELECT * FROM intelligence_ml_jobs WHERE state='pending' AND retry_at<=? AND tenant=? AND owner=? AND index_name IN (SELECT value FROM json_each(?)) ORDER BY created,id LIMIT ?",(now,tenant,owner,encode(indexes),maximum-completed))]
            if not batch:
                continue
            started=time.time()
            db.execute("INSERT INTO intelligence_ml_batch_diagnostics(tenant,owner,model_id,indexes,pending_count,oldest_created,ready,selected,state,started,detail,at) VALUES(?,?,?,?,?,?,1,?,'started',?,?,?)",(tenant,owner,identifier,encode(diagnostic_indexes),group["n"],group["oldest"],len(batch),started,encode({"minimum_batch":16,"max_wait_seconds":5,"oldest_wait_seconds":started-group["oldest"]}),started))
            diagnostic=db.execute("SELECT last_insert_rowid()").fetchone()[0]
            _phase(db,tenant,[job["event_id"] for job in batch],ml_started_at=started)
            for index in indexes:
                db.execute("INSERT INTO intelligence_ml_scope_schedule VALUES(?,?,?,?) ON CONFLICT(tenant,owner,index_name) DO UPDATE SET served=excluded.served",(tenant,owner,index,started))
        try:
            actor = {"name": owner, "tenant": tenant, "role": "analyst"}
            outcome = cpu_ml.infer_events(store, actor, [{"event_id": j["event_id"]} for j in batch], model_id=identifier) if identifier else {"status": "no_active_model", "results": []}
            store.intelligence_ml_status = outcome.get("status")
            for prediction in outcome.get("results", []):
                if prediction.get("anomaly"):
                    publish(store, actor, {"event_ids": prediction["event_ids"], "kind": "ml", "rule_id": "ml:" + prediction["model_id"], "rule_revision": prediction["revision"], "features": prediction["features"], "severity": "medium", "confidence_grade": "model_distribution_deviation", "model_digest": prediction["digest"], "metadata": {"score": prediction["score"], "threshold": prediction["threshold"], "probability_calibrated": False, "run_id": outcome.get("run_id"), "provenance": prediction.get("provenance"), "feature_error": prediction.get("feature_error"), "duration_ms": outcome.get("duration_ms"), "worker_wall_ms": outcome.get("worker_wall_ms")}})
            store.intelligence_ml_error = None
            with store.write_lock, store.control(local=True) as db:
                for job in batch:
                    db.execute("UPDATE intelligence_ml_jobs SET state=?,finished=?,attempts=attempts+1,error=? WHERE id=? AND state='pending'", ("completed" if outcome.get("status") == "completed" else "excluded", time.time(), outcome.get("compatibility") or outcome.get("status"), job["id"]))
                    _phase(db,tenant,[job["event_id"]],ml_finished_at=time.time())
                db.execute("UPDATE intelligence_ml_batch_diagnostics SET state=?,finished=?,duration_ms=?,worker_wall_ms=?,detail=? WHERE id=?",("completed" if outcome.get("status")=="completed" else "excluded",time.time(),outcome.get("duration_ms"),outcome.get("worker_wall_ms"),encode({"status":outcome.get("status"),"run_id":outcome.get("run_id"),"oldest_wait_seconds":started-group["oldest"],"selected":len(batch)}),diagnostic))
            completed += len(batch)
        except (PermissionError, KeyError, ConflictError, CapacityError, ValueError, RuntimeError) as exc:
            store.intelligence_ml_error = type(exc).__name__
            with store.write_lock, store.control(local=True) as db:
                for job in batch:
                    terminal = job["attempts"] >= 2 or isinstance(exc, (PermissionError, KeyError))
                    db.execute("UPDATE intelligence_ml_jobs SET state=?,attempts=attempts+1,error=?,retry_at=?,finished=? WHERE id=?", ("failed" if terminal else "pending", type(exc).__name__, time.time()+5, time.time() if terminal else None, job["id"]))
                    if terminal:
                        _phase(db,tenant,[job["event_id"]],ml_finished_at=time.time(),error=type(exc).__name__)
                db.execute("UPDATE intelligence_ml_batch_diagnostics SET state='failed',finished=?,detail=? WHERE id=?",(time.time(),encode({"error":type(exc).__name__,"retry_retained":any(job["attempts"]<2 for job in batch)}),diagnostic))
    return completed


def _join(signal, join):
    if join == "entity":
        return signal["entity_key"]
    if join == "story":
        return signal.get("story_id")
    return signal.get("association_keys", {}).get(join)


def _ordered(previous, following, definition):
    if not definition["ordered"]:
        return True
    left, right = previous["event_window"], following["event_window"]
    if definition.get("clock_policy") == "strict":
        a, b = left.get("precision_seconds"), right.get("precision_seconds")
        return type(a) in {int, float} and type(b) in {int, float} and math.isfinite(a) and math.isfinite(b) and left["end"] + a < right["start"] - b
    return left["end"] < right["start"]


def _qualified_chain(anchor, signals, definition, deadline=None, cancel=None):
    """Search alternatives; a nearby dependent input cannot mask another match."""
    key = _join(anchor, definition["join_on"])
    if not key:
        return None
    examined = 0
    def visit(chain, position):
        nonlocal examined
        examined += 1
        if examined > 10000 or deadline and time.monotonic() >= deadline or cancel is not None and cancel.is_set():
            raise CapacityError("Composite alternatives deferred at bounded work budget")
        if position == len(definition["inputs"]):
            dependency = _dependencies([s["event_ids"] for s in chain], [s.get("metadata", {}).get("dependency_group") for s in chain])
            ids = {e for s in chain for e in s["event_ids"]}
            return chain if len(ids) <= 32 and dependency["disjoint_original_groups"] >= definition["minimum_independent_groups"] else None
        selector = definition["inputs"][position]
        used = {s["id"] for s in chain}
        choices = [s for s in signals if s["id"] not in used and all(s.get(k) == v for k, v in selector.items()) and _join(s, definition["join_on"]) == key and abs(s["event_window"]["end"] - anchor["event_window"]["end"]) <= definition["window"] and _ordered(chain[-1], s, definition)]
        choices.sort(key=lambda s: (abs(s["event_window"]["start"] - anchor["event_window"]["start"]), s["id"]))
        for choice in choices:
            found = visit(chain + [choice], position + 1)
            if found:
                return found
        return None
    return visit([anchor], 1)


def _selector_sql(selector, alias="s"):
    return " AND ".join(alias+"."+key+"=?" for key in sorted(selector)),[selector[key] for key in sorted(selector)]


def _cohort_sql(actor,definition,identifier,window_start):
    clauses=["s.tenant=?","s.mode='live'","s.rule_id!=?","s.kind!='observation'","s.created>=?","json_array_length(s.indexes)>0","NOT EXISTS(SELECT 1 FROM json_each(s.indexes) i WHERE i.value NOT IN (SELECT value FROM json_each(?)))"]
    args=[actor["tenant"],identifier,window_start,encode(definition["indexes"])]
    inputs=[]
    for selector in definition["inputs"]:
        part,values=_selector_sql(selector);inputs.append("("+part+")");args.extend(values)
    clauses.append("("+" OR ".join(inputs)+")")
    for parent,pin in definition.get("input_revisions",{}).items():
        clauses.append("(s.rule_id!=? OR (s.rule_revision=? AND s.definition_digest=?))")
        args.extend([parent,pin["version"],pin["definition_digest"]])
    return " AND ".join(clauses),args


def _candidate_cutoff(db,tenant,definition,identifier,last_seq,now=None):
    """Defer operational expiry for scoped, server-admitted unfinished work.

    Signal creation TTL is separate from the unchanged reported event-window
    coherence rule. A final late derived input remains observable after queues
    drain: only recently created NEW eligible signals can extend its next
    frozen capture to their exact ancestry's admission time. Reported source
    timestamps never set this watermark, and unrelated scope cannot delay it.
    """
    now=time.time() if now is None else now
    if type(now) not in (int,float) or not math.isfinite(now):
        raise ValueError("Finite server candidate clock required")
    scope=encode(definition["indexes"])
    clocks=[now]
    row=db.execute("SELECT min(e.received) FROM intelligence_event_outbox e WHERE e.tenant=? AND e.seq>(SELECT cursor FROM intelligence_cursors WHERE worker='events') AND e.index_name IN (SELECT value FROM json_each(?))",(tenant,scope)).fetchone()
    if row and row[0] is not None:
        clocks.append(row[0])
    selectors=definition["inputs"]
    wildcard_ml=any(s.get("kind")=="ml" and "rule_id" not in s for s in selectors)
    sequence_ids=[s["rule_id"][len("ml:sequence:"):] for s in selectors if s.get("rule_id","").startswith("ml:sequence:")]
    autoencoder=wildcard_ml or any(s.get("rule_id","").startswith("ml:") and not s["rule_id"].startswith("ml:sequence:") for s in selectors)
    tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('intelligence_ml_jobs','intelligence_sequence_jobs','intelligence_sequence_buffers')")}
    if autoencoder and "intelligence_ml_jobs" in tables:
        row=db.execute("SELECT min(r.received) FROM intelligence_ml_jobs j JOIN receipts r ON r.tenant=j.tenant AND r.event_id=j.event_id WHERE j.tenant=? AND j.state IN ('pending','running') AND j.index_name IN (SELECT value FROM json_each(?))",(tenant,scope)).fetchone()
        if row and row[0] is not None:
            clocks.append(row[0])
    if wildcard_ml or sequence_ids:
        model_clause="" if wildcard_ml else " AND q.model_id IN (SELECT value FROM json_each(?))"
        model_args=[] if wildcard_ml else [encode(sorted(set(sequence_ids)))]
        if "intelligence_sequence_jobs" in tables:
            row=db.execute("SELECT min(r.received) FROM intelligence_sequence_jobs q,json_each(q.event_ids) e JOIN receipts r ON r.tenant=q.tenant AND r.event_id=e.value WHERE q.tenant=? AND q.state IN ('pending','running') AND json_array_length(q.indexes)>0 AND NOT EXISTS(SELECT 1 FROM json_each(q.indexes) i WHERE i.value NOT IN (SELECT value FROM json_each(?)))"+model_clause,[tenant,scope,*model_args]).fetchone()
            if row and row[0] is not None:
                clocks.append(row[0])
        if "intelligence_sequence_buffers" in tables:
            row=db.execute("SELECT min(r.received) FROM intelligence_sequence_buffers q,json_each(q.event_ids) e JOIN receipts r ON r.tenant=q.tenant AND r.event_id=e.value WHERE q.tenant=? AND q.index_name IN (SELECT value FROM json_each(?))"+model_clause,[tenant,scope,*model_args]).fetchone()
            if row and row[0] is not None:
                clocks.append(row[0])
    predicate,args=_cohort_sql({"tenant":tenant},definition,identifier,now-definition["window"])
    row=db.execute("SELECT min(r.received) FROM intelligence_signals s,json_each(s.event_ids) e JOIN receipts r ON r.tenant=s.tenant AND r.event_id=e.value WHERE "+predicate+" AND s.seq>?",[*args,last_seq]).fetchone()
    if row and row[0] is not None:
        clocks.append(row[0])
    if any(type(value) not in (int,float) or not math.isfinite(value) for value in clocks):
        raise ValueError("Finite server admission watermark required")
    return min(clocks)-definition["window"]


def _parent_valid(store,db,actor,body,definition,memo=None):
    """Revalidate parents at capture and emission; a frozen cohort grants nothing."""
    # Reserved model/engine identifiers cannot borrow an unrelated kind's
    # validation path, including atomic parents without a policy row.
    reserved_finding=body.get('rule_id','').startswith(('online:anomaly:','online:drift:','analysis-engine:')) or body.get('rule_id')=='yara:binary'
    if (body.get('rule_id','').startswith('ml:') and body.get('kind')!='ml') or (reserved_finding and body.get('kind')!='finding'):
        return False
    if not principal.contains(definition["indexes"],body["indexes"]):
        return False
    ids=body["event_ids"]
    references={reference["event_id"]:reference["admission_digest"] for reference in body.get("originals",[])}
    proofs=db.execute("SELECT r.event_id,r.digest,s.source_id,s.source_version,x.version,x.state FROM receipts r LEFT JOIN source_event_receipts s ON s.tenant=r.tenant AND s.event_id=r.event_id LEFT JOIN source_registry x ON x.tenant=s.tenant AND x.id=s.source_id WHERE r.tenant=? AND r.event_id IN (SELECT value FROM json_each(?))",(actor["tenant"],encode(ids))).fetchall()
    if set(references)!=set(ids) or len(proofs)!=len(ids) or any(row["digest"]!=references[row["event_id"]] or row["source_id"] is not None and (row["state"]!="active" or row["version"]!=row["source_version"]) for row in proofs):
        return False
    pin=definition.get("input_revisions",{}).get(body["rule_id"])
    if pin and (body["rule_revision"]!=pin["version"] or body["definition_digest"]!=pin["definition_digest"]):
        return False
    if body["kind"] in {"atomic","composite"}:
        policy=db.execute("SELECT * FROM intelligence_policies WHERE tenant=? AND id=?",(actor["tenant"],body["rule_id"])).fetchone()
        if policy:
            try:
                _,parent_definition=_authority(db,policy,memo=memo)
            except (PermissionError,KeyError,ConflictError):
                return False
            if policy["version"]!=body["rule_revision"] or release_manifest.digest(parent_definition)!=body["definition_digest"]:
                return False
            if 'correlation' in parent_definition:
                from . import native_correlations
                return native_correlations.validate_parent(store, db, actor, body, parent_definition)
    elif body["kind"]=="ml":
        try:
            if body['rule_id'].startswith('ml:research:'):
                from . import advanced_intelligence
                return advanced_intelligence.validate_parent(store,db,actor,body,memo=memo)
            elif body["rule_id"].startswith("ml:sequence:"):
                from . import cpu_sequence
                kwargs={"memo":memo["sequence"]} if memo is not None else {}
                cpu_sequence.validate_publication(store,db,actor,body["rule_id"][len("ml:sequence:"):],body.get("model_digest"),body["rule_revision"],**kwargs)
            else:
                from . import cpu_ml
                cpu_ml.validate_publication(store,db,actor,body["rule_id"][3:],body.get("model_digest"),body["rule_revision"])
        except (KeyError,PermissionError,ConflictError,ValueError):
            return False
    if body.get("kind")=="finding" and body.get("rule_id")=="yara:binary":
        from . import yara_intelligence
        return yara_intelligence.validate_parent(store,db,actor,body,memo=memo)
    if body.get('kind')=='finding' and body.get('rule_id','').startswith('analysis-engine:'):
        from . import analysis_engines
        return analysis_engines.validate_parent(store,db,actor,body,memo=memo)
    if body.get('kind')=='finding' and body.get('rule_id','').startswith(('online:anomaly:','online:drift:')):
        from . import online_analytics
        return online_analytics.validate_parent(store,db,actor,body,memo=memo)
    from . import intelligence_findings
    return intelligence_findings.validate_parent(db,actor,body)


def _story_epoch(db,actor,definition):
    if definition["join_on"]!="story":
        return None
    row=db.execute("SELECT count(*),coalesce(max(at),0) FROM intelligence_story_aliases WHERE tenant=?",(actor["tenant"],)).fetchone()
    return list(row)


def _progressive_chain(store,db,actor,policy,definition,anchor,search,deadline,cancel,maximum=256,memo=None):
    """Checkpoint a deterministic DFS over indexed join partitions.

    Memory and work per turn are bounded, while large positive cohorts and
    alternative sets continue from durable bookmarks instead of truncation.
    """
    policy_id,key=policy["id"],_join(anchor,definition["join_on"])
    if not key or not _parent_valid(store,db,actor,anchor,definition,memo=memo):
        return None,None,0
    state=search if search.get("anchor_id")==anchor["id"] else {"anchor_id":anchor["id"],"ids":[anchor["id"]],"bookmarks":[None,None]}
    work=0
    def load(identifier):
        row=db.execute("SELECT body FROM intelligence_composite_cohort WHERE policy_id=? AND signal_id=?",(policy_id,identifier)).fetchone()
        return json.loads(row[0]) if row else None
    while work<maximum and (work==0 or not (deadline and time.monotonic()>=deadline)) and not (cancel is not None and cancel.is_set()):
        chain=[load(identifier) for identifier in state["ids"]]
        if any(body is None for body in chain):
            raise ConflictError("Frozen composite search member disappeared")
        position=len(chain)
        if position==len(definition["inputs"]):
            from . import signal_evidence
            dependency=_dependencies([signal_evidence.ancestry(store, db, actor, s, memo=memo.get('research') if memo else None)['event_ids'] for s in chain],[s.get("metadata",{}).get("dependency_group") for s in chain])
            if len({eid for s in chain for eid in s["event_ids"]})<=32 and dependency["disjoint_original_groups"]>=definition["minimum_independent_groups"] and all(_parent_valid(store,db,actor,s,definition,memo=memo) for s in chain):
                return chain,None,work
            state["ids"].pop();work+=1
            continue
        selector,args=_selector_sql(definition["inputs"][position],"c")
        clauses=["c.policy_id=?","c.join_key=?",selector,"c.event_end>=?","c.event_end<=?"]
        values=[policy_id,key,*args,anchor["event_window"]["end"]-definition["window"],anchor["event_window"]["end"]+definition["window"]]
        clauses.append("c.signal_id NOT IN (SELECT value FROM json_each(?))");values.append(encode(state["ids"]))
        distance="abs(c.event_start-?)"
        bookmark=state["bookmarks"][position]
        if bookmark:
            clauses.append("("+distance+">? OR ("+distance+"=? AND c.signal_id>?))")
            values.extend([anchor["event_window"]["start"],bookmark[0],anchor["event_window"]["start"],bookmark[0],bookmark[1]])
        values.append(anchor["event_window"]["start"])
        row=db.execute("SELECT c.body,c.signal_id FROM intelligence_composite_cohort c WHERE "+" AND ".join(clauses)+" ORDER BY "+distance+",c.signal_id LIMIT 1",values).fetchone()
        work+=1
        if not row:
            state["bookmarks"][position]=None
            if position==1:
                return None,None,work
            state["ids"].pop()
            continue
        body=json.loads(row["body"])
        state["bookmarks"][position]=[abs(body["event_window"]["start"]-anchor["event_window"]["start"]),body["id"]]
        if not _ordered(chain[-1],body,definition) or not _parent_valid(store,db,actor,body,definition,memo=memo):
            continue
        state["ids"].append(body["id"])
        if len(state["bookmarks"])<=position+1:
            state["bookmarks"].append(None)
        else:
            state["bookmarks"][position+1]=None
    return None,state,work


def _composites(store, cancel=None, maximum=8, deadline=None):
    with store.control() as db:
        policies_to_run = [dict(r) for r in db.execute("SELECT p.* FROM intelligence_policies p LEFT JOIN intelligence_composite_state s ON p.id=s.id WHERE p.state='active' AND p.kind='composite' ORDER BY coalesce(s.updated,0),p.id LIMIT ?", (maximum,))]
    emitted = 0
    for policy in policies_to_run:
        if cancel is not None and cancel.is_set() or deadline and time.monotonic() >= deadline:
            break
        processing_budget=max(.001,min(5.,deadline-time.monotonic())) if deadline else None
        committed_emissions = 0
        try:
            with store.segment_lock.read(deadline=time.monotonic()+3), principal.transaction(store, {"name": policy["owner"], "tenant": policy["tenant"], "role": "analyst"}, ("admin", "analyst"), write=True) as (db, actor), _authority_memo(db) as memo:
                fresh = db.execute("SELECT * FROM intelligence_policies WHERE tenant=? AND id=?", (policy["tenant"], policy["id"])).fetchone()
                actor, definition = _authority(db, fresh,memo=memo)
                if 'correlation' in definition:
                    from . import native_correlations
                    emitted += native_correlations.run_policy(store, db, actor, fresh, definition, deadline=deadline, cancel=cancel, memo=memo)
                    # All composite families share this scheduling timestamp;
                    # a separate correlation cursor must not monopolize the
                    # oldest-first queue when more than eight rules are active.
                    db.execute("INSERT INTO intelligence_composite_state VALUES(?,?,0,0,0,0,?,NULL) ON CONFLICT(id) DO UPDATE SET version=excluded.version,updated=excluded.updated,error=NULL", (fresh['id'], fresh['version'], time.time()))
                    continue
                state = db.execute("SELECT * FROM intelligence_composite_state WHERE id=?", (fresh["id"],)).fetchone()
                if not state or state["version"] != fresh["version"]:
                    db.execute("INSERT INTO intelligence_composite_state VALUES(?,?,0,0,0,0,?,NULL) ON CONFLICT(id) DO UPDATE SET version=excluded.version,last_seq=0,snapshot_seq=0,anchor_seq=0,window_end=0,error=NULL", (fresh["id"], fresh["version"], time.time()))
                    state = db.execute("SELECT * FROM intelligence_composite_state WHERE id=?", (fresh["id"],)).fetchone()
                if state["snapshot_seq"] == state["last_seq"]:
                    cutoff=_candidate_cutoff(db,actor["tenant"],definition,fresh["id"],state["last_seq"])
                    candidate_sql,args=_cohort_sql(actor,definition,fresh["id"],cutoff)
                    largest=db.execute("SELECT coalesce(max(s.seq),0) FROM intelligence_signals s WHERE "+candidate_sql,args).fetchone()[0]
                    if largest <= state["last_seq"]:
                        db.execute("UPDATE intelligence_composite_state SET updated=? WHERE id=?", (time.time(), fresh["id"]))
                        continue
                    db.execute("UPDATE intelligence_composite_state SET snapshot_seq=?,anchor_seq=0,window_end=? WHERE id=?", (largest, cutoff+definition["window"], fresh["id"]))
                    state = db.execute("SELECT * FROM intelligence_composite_state WHERE id=?", (fresh["id"],)).fetchone()
                epoch=_story_epoch(db,actor,definition)
                work=db.execute("SELECT * FROM intelligence_composite_work WHERE id=?",(fresh["id"],)).fetchone()
                if not work or work["version"]!=fresh["version"] or work["snapshot_seq"]!=state["snapshot_seq"] or json.loads(work["search"]).get("epoch")!=epoch:
                    db.execute("DELETE FROM intelligence_composite_cohort WHERE policy_id=?",(fresh["id"],))
                    db.execute("INSERT INTO intelligence_composite_work VALUES(?,?,?,0,'capture',?,0,0,?) ON CONFLICT(id) DO UPDATE SET version=excluded.version,snapshot_seq=excluded.snapshot_seq,scan_seq=0,phase='capture',search=excluded.search,examined=0,qualified=0,updated=excluded.updated",(fresh["id"],fresh["version"],state["snapshot_seq"],encode({"epoch":epoch}),time.time()))
                    db.execute("UPDATE intelligence_composite_state SET anchor_seq=0 WHERE id=?",(fresh["id"],))
                    state=db.execute("SELECT * FROM intelligence_composite_state WHERE id=?",(fresh["id"],)).fetchone()
                    work=db.execute("SELECT * FROM intelligence_composite_work WHERE id=?",(fresh["id"],)).fetchone()
                search=json.loads(work["search"])
                # Immutable model decoding/current authority are required setup,
                # not candidate work. Give this admitted policy a bounded slice
                # after setup; the reserved principal transaction still has its
                # independent hard deadline and the next policy uses the outer
                # deadline. Tiny slices still commit one unit of durable work.
                processing_deadline=time.monotonic()+processing_budget if processing_budget is not None else None
                if work["phase"]=="capture":
                    candidate_sql,args=_cohort_sql(actor,definition,fresh["id"],state["window_end"]-definition["window"])
                    raw_rows=db.execute("SELECT s.* FROM intelligence_signals s WHERE "+candidate_sql+" AND s.seq>? AND s.seq<=? ORDER BY s.seq LIMIT 256",[*args,work["scan_seq"],state["snapshot_seq"]]).fetchall()
                    scanned=0
                    for row in raw_rows:
                        if scanned and processing_deadline and time.monotonic()>=processing_deadline or cancel is not None and cancel.is_set():
                            break
                        body=json.loads(row["body"])
                        valid=_parent_valid(store,db,actor,body,definition,memo=memo)
                        if valid and definition["join_on"]=="story":
                            from . import intelligence_story_reconcile
                            body["story_id"]=intelligence_story_reconcile.current(db,{**actor,"allowed_indexes":definition["indexes"]},body.get("story_id")) if body.get("story_id") else None
                        key=_join(body,definition["join_on"])
                        if valid and key:
                            db.execute("INSERT OR IGNORE INTO intelligence_composite_cohort VALUES(?,?,?,?,?,?,?,?,?,?)",(fresh["id"],state["snapshot_seq"],row["seq"],body["id"],key,body["kind"],body["rule_id"],body["event_window"]["start"],body["event_window"]["end"],encode(body)))
                        db.execute("UPDATE intelligence_composite_work SET scan_seq=? WHERE id=?",(row["seq"],fresh["id"]))
                        scanned+=1
                    if scanned==len(raw_rows) and len(raw_rows)<256:
                        db.execute("UPDATE intelligence_composite_work SET phase='evaluate',scan_seq=?,qualified=(SELECT count(*) FROM intelligence_composite_cohort WHERE policy_id=?) WHERE id=?",(state["snapshot_seq"],fresh["id"],fresh["id"]))
                    db.execute("UPDATE intelligence_composite_work SET updated=? WHERE id=?",(time.time(),fresh["id"]))
                    work=db.execute("SELECT * FROM intelligence_composite_work WHERE id=?",(fresh["id"],)).fetchone()
                if work["phase"]=="capture":
                    db.execute("UPDATE intelligence_composite_state SET updated=?,error=NULL WHERE id=?",(time.time(),fresh["id"]))
                    continue
                selector,args=_selector_sql(definition["inputs"][0],"c")
                anchors=db.execute("SELECT c.seq,c.body FROM intelligence_composite_cohort c WHERE c.policy_id=? AND c.seq>? AND "+selector+" ORDER BY c.seq LIMIT 65",[fresh["id"],state["anchor_seq"],*args]).fetchall()
                completed_anchors=0
                for row in anchors[:64]:
                    if completed_anchors and processing_deadline and time.monotonic()>=processing_deadline or cancel is not None and cancel.is_set():
                        break
                    anchor=json.loads(row["body"])
                    chain,continuation,examined=_progressive_chain(store,db,actor,fresh,definition,anchor,search,processing_deadline,cancel,memo=memo)
                    db.execute("UPDATE intelligence_composite_work SET examined=examined+?,search=?,updated=? WHERE id=?",(examined,encode({"epoch":epoch,**(continuation or {})}),time.time(),fresh["id"]))
                    if continuation:
                        search={"epoch":epoch,**continuation}
                        break
                    if chain:
                        ids = sorted({e for s in chain for e in s["event_ids"]})
                        from . import signal_evidence
                        # One exact short-original set is reused only within
                        # this reserved actor/Store transaction. Each use still
                        # rechecks current principal, receipts and source scope.
                        with evidence_scope.prefetch_transaction(store, db, [(actor, ids)]):
                            dependency = _dependencies([signal_evidence.ancestry(store, db, actor, s, memo=memo.get('research') if memo else None)['event_ids'] for s in chain], [s.get("metadata", {}).get("dependency_group") for s in chain])
                            signal = publish_in_transaction(store, db, actor, {"event_ids": ids, "kind": "composite", "rule_id": fresh["id"], "rule_revision": fresh["version"], "features": {"disjoint_original_groups": dependency["disjoint_original_groups"]}, "severity": definition["severity"], "confidence_grade": definition["confidence_grade"], "parent_signal_ids": [s["id"] for s in chain], "entity_key": _join(anchor, definition["join_on"]), "window": definition["window"], "definition_digest": release_manifest.digest(definition), "context_digest": release_manifest.digest([s["context_digest"] for s in chain]), "metadata": {"join_on": definition["join_on"], "reported_association_only": True}}, memo=memo)
                            outcome = _case(store, db, actor, fresh, definition, signal, memo=memo)
                        if not signal["duplicate"]:
                            committed_emissions += 1
                            _decision(db, fresh, actor, signal["id"], "matched", {"case_emission": outcome, "dependency": dependency})
                    else:
                        _decision(db, fresh, actor, anchor["id"], "no_qualified_chain", {"snapshot_seq": state["snapshot_seq"]})
                    db.execute("UPDATE intelligence_composite_state SET anchor_seq=? WHERE id=?", (row["seq"], fresh["id"]))
                    search={"epoch":epoch};completed_anchors+=1
                if completed_anchors==len(anchors):
                    db.execute("UPDATE intelligence_composite_state SET last_seq=snapshot_seq WHERE id=?", (fresh["id"],))
                    db.execute("UPDATE intelligence_composite_work SET phase='complete',search=? WHERE id=?",(encode({"epoch":epoch}),fresh["id"]))
                db.execute("UPDATE intelligence_composite_state SET updated=?,error=NULL WHERE id=?", (time.time(), fresh["id"]))
            emitted += committed_emissions
        except (PermissionError, KeyError, ConflictError, ValueError, CapacityError) as exc:
            with store.write_lock, store.control(local=True) as db:
                db.execute("INSERT INTO intelligence_composite_state VALUES(?,?,0,0,0,0,?,?) ON CONFLICT(id) DO UPDATE SET updated=excluded.updated,error=excluded.error", (policy["id"], policy["version"], time.time(), str(exc)))
                _decision(db, policy, None, None, "composite_deferred" if isinstance(exc, CapacityError) else "composite_excluded", {"reason": str(exc)})
    return emitted


def _legacy_one(store, row, declaration, evidence):
    actor = {"name": declaration["owner"], "tenant": row["tenant"], "role": "analyst"}
    with store.segment_lock.read(deadline=time.monotonic()+3), principal.transaction(store, actor, ("admin", "analyst"), write=True) as (db, current):
        _authority(db, db.execute("SELECT * FROM intelligence_policies WHERE id=?", (declaration["id"],)).fetchone())
        principal.incident(db, current, row["incident_id"])
        signal = publish_in_transaction(store, db, current, {"event_ids": evidence["event_ids"], "kind": "legacy", "rule_id": row["policy_id"], "rule_revision": evidence.get("evaluation", {}).get("policy_version", 1), "features": {"risk_weight": row["weight"]}, "severity": evidence.get("severity", "medium"), "confidence_grade": "evidence_backed_policy_hypothesis", "metadata": {"incident_id": row["incident_id"], "contribution_id": row["id"], "verdict": "see current analyst judgement"}})
        return int(not signal["duplicate"])


def _legacy(store, maximum=16, cancel=None, deadline=None):
    with store.control() as db:
        cursor = db.execute("SELECT cursor FROM intelligence_cursors WHERE worker='contributions'").fetchone()[0]
        rows = [dict(r) for r in db.execute("SELECT rowid AS sequence,* FROM risk_contributions WHERE rowid>? ORDER BY rowid LIMIT ?", (cursor, maximum))]
    published, completed = 0, cursor
    try:
        for row in rows:
            if cancel is not None and cancel.is_set() or deadline and time.monotonic() >= deadline:
                break
            # Native contributions already have a signal. Skipping them needs
            # no evidence decode, principal query, or individual fsync.
            if row["policy_id"].startswith("intelligence:"):
                completed = row["sequence"]
                continue
            evidence = json.loads(row["evidence"])
            if evidence.get("event_ids"):
                with store.control() as db:
                    active = [dict(r) for r in db.execute("SELECT * FROM intelligence_policies WHERE tenant=? AND state='active'", (row["tenant"],)) if principal.contains(json.loads(r["indexes"]), json.loads(row["indexes"]))]
                if active:
                    declaration = active[0]
                    try:
                        published += _legacy_one(store, row, declaration, evidence)
                    except (PermissionError, KeyError, ConflictError, ValueError) as exc:
                        with store.write_lock, store.control(local=True) as db:
                            _decision(db, declaration, None, None, "legacy_excluded", {"contribution_id": row["id"], "reason": type(exc).__name__})
            # Set only after publication or its durable exclusion succeeded.
            completed = row["sequence"]
    finally:
        if completed > cursor:
            with store.write_lock, store.control(local=True) as db:
                # A crash before this commit replays deterministic publications;
                # cancellation/errors retain exactly the completed prefix. A
                # concurrent worker must never have its newer cursor regressed.
                db.execute("UPDATE intelligence_cursors SET cursor=max(cursor,?) WHERE worker='contributions'", (completed,))
    return published


def run_due(store, now=None, cancel=None, budget=.25, max_runs=2, include_ml=True, original_budget=None):
    # Each original cursor commit follows its durable signals, not wall time.
    budget = max(.05, min(5., float(budget)))
    original_slice = budget
    if original_budget is not None:
        if type(original_budget) not in (int, float) or not math.isfinite(original_budget):
            raise ValueError("Original processing budget must be a finite number")
        original_slice = max(.05, min(1., float(original_budget)))
    originals = _outbox(store, cancel, maximum=max(1, min(32, max_runs * 8)), deadline=time.monotonic()+original_slice)
    ml = _ml_due(store, cancel, maximum=32) if include_ml else 0
    legacy = _legacy(store, maximum=max(1, min(32, max_runs * 8)), cancel=cancel, deadline=time.monotonic()+budget)
    from . import intelligence_findings
    findings = intelligence_findings.run_due(store, cancel=cancel, budget=budget, max_runs=max_runs)
    composites = _composites(store, cancel, maximum=8, deadline=time.monotonic()+budget)
    from . import intelligence_story_reconcile
    relationships=intelligence_story_reconcile.run_due(store,cancel=cancel,budget=budget,max_runs=max_runs)
    return {"originals": originals, "ml_jobs": ml, "legacy_signals": legacy, "finding_signals": findings, "composites": composites,"relationship_jobs":relationships}


def signals(store, who, cursor=0, count=100, mode="live"):
    if type(cursor) is not int or cursor < 0 or type(count) is not int or not 1 <= count <= 1000 or mode not in {"live", "shadow"}:
        raise ValueError("Typed signal cursor/count/mode required")
    with principal.transaction(store, who) as (db, actor):
        rows = db.execute("SELECT * FROM intelligence_signals WHERE tenant=? AND mode=? AND seq>? ORDER BY seq LIMIT ?", (actor["tenant"], mode, cursor, count + 1)).fetchall()
        visible = []
        for row in rows[:count]:
            if principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
                body = json.loads(row["body"])
                body["originals_currently_available"] = all(db.execute("SELECT 1 FROM receipts WHERE tenant=? AND event_id=?", (actor["tenant"], eid)).fetchone() for eid in body["event_ids"])
                visible.append(body)
        return {"items": visible, "next_cursor": rows[count - 1]["seq"] if len(rows) > count else None, "complete": len(rows) <= count, "record_count_limit": None}


def stories(store, who):
    with principal.transaction(store, who) as (db, actor):
        return [{**dict(r), "indexes": json.loads(r["indexes"]), "body": json.loads(r["body"])} for r in db.execute("SELECT * FROM intelligence_stories WHERE tenant=? ORDER BY updated,id", (actor["tenant"],)) if principal.contains(actor["allowed_indexes"], json.loads(r["indexes"]))]


def story(store, who, identifier):
    with principal.transaction(store, who) as (db, actor):
        requested = identifier
        from . import intelligence_story_reconcile
        identifier = intelligence_story_reconcile.current(db,actor,identifier)
        if not identifier:
            raise KeyError("Story not found in complete scope")
        row = db.execute("SELECT * FROM intelligence_stories WHERE tenant=? AND id=?", (actor["tenant"], identifier)).fetchone()
        if not row or not principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
            raise KeyError("Story not found in complete scope")
        nodes = [{**dict(r), "body": json.loads(r["body"]), "event_ids": json.loads(r["event_ids"]), "indexes": json.loads(r["indexes"])} for r in db.execute("SELECT * FROM intelligence_story_nodes WHERE tenant=? AND story_id=?", (actor["tenant"], identifier))]
        edges = [{**dict(r), "event_ids": json.loads(r["event_ids"]), "indexes": json.loads(r["indexes"])} for r in db.execute("SELECT * FROM intelligence_story_edges WHERE tenant=? AND story_id=?", (actor["tenant"], identifier))]
        if any(not principal.contains(actor["allowed_indexes"], r["indexes"]) for r in nodes + edges):
            raise KeyError("Story not found in complete scope")
        return {**dict(row), "requested_story_id":requested,"alias_resolved":requested!=identifier,"body": json.loads(row["body"]), "indexes": json.loads(row["indexes"]), "nodes": nodes, "edges": edges, "causality_proven": False, "automatic_endpoint_authorization": False}


def decisions(store, who, cursor=0, count=100):
    if type(cursor) is not int or cursor < 0 or type(count) is not int or not 1 <= count <= 1000:
        raise ValueError("Typed diagnostic cursor/count required")
    with principal.transaction(store, who) as (db, actor):
        rows = db.execute("SELECT * FROM intelligence_decisions WHERE tenant=? AND seq>? ORDER BY seq LIMIT ?", (actor["tenant"], cursor, count + 1)).fetchall()
        return {"items": [{**dict(r), "detail": json.loads(r["detail"]), "indexes": json.loads(r["indexes"])} for r in rows[:count] if principal.contains(actor["allowed_indexes"], json.loads(r["indexes"]))], "next_cursor": rows[count-1]["seq"] if len(rows) > count else None, "complete": len(rows) <= count}


def analysis_slo(store,who,start=None,end=None):
    """Exact authorized server-clock cohort; absent stages are coverage gaps."""
    end=time.time() if end is None else evidence_scope.number(end,"end")
    start=end-86400 if start is None else evidence_scope.number(start,"start")
    if not start<end or end-start>7*86400:
        raise ValueError("Server analysis SLO window must be positive and at most seven days")
    with principal.transaction(store,who) as (db,actor):
        scope=encode(actor["allowed_indexes"])
        clause="" if actor["allowed_indexes"]==["*"] else " AND index_name IN (SELECT value FROM json_each(?))"
        args=[actor["tenant"],start,end]+([] if not clause else [scope])
        rows=[dict(row) for row in db.execute("SELECT * FROM intelligence_event_phases WHERE tenant=? AND received>=? AND received<?"+clause+" ORDER BY received,event_id LIMIT 50001",args)]
        if len(rows)>50000:
            raise CapacityError("Analysis SLO cohort exceeds 50000; narrow the server-received window")
        cursor=db.execute("SELECT cursor FROM intelligence_cursors WHERE worker='events'").fetchone()[0]
        pending=db.execute("SELECT count(*),min(received) FROM intelligence_event_outbox WHERE tenant=? AND seq>?"+clause,[actor["tenant"],cursor]+([] if not clause else [scope])).fetchone()
        jobs=[dict(row) for row in db.execute("SELECT state,count(*) AS n,min(created) AS oldest_created FROM intelligence_ml_jobs WHERE tenant=?"+clause+" GROUP BY state",[actor["tenant"]]+([] if not clause else [scope]))]
        batches=[{**dict(row),"indexes":json.loads(row["indexes"]),"detail":json.loads(row["detail"])} for row in db.execute("SELECT * FROM intelligence_ml_batch_diagnostics b WHERE tenant=? AND NOT EXISTS (SELECT 1 FROM json_each(b.indexes) i WHERE ?!='[\"*\"]' AND i.value NOT IN (SELECT value FROM json_each(?))) ORDER BY id DESC LIMIT 100",(actor["tenant"],scope,scope))]
        composite=[{**dict(row),"indexes":json.loads(row["indexes"])} for row in db.execute("SELECT s.*,p.indexes,w.phase,w.scan_seq,w.examined,w.qualified FROM intelligence_composite_state s JOIN intelligence_policies p ON p.id=s.id LEFT JOIN intelligence_composite_work w ON w.id=s.id WHERE p.tenant=? AND NOT EXISTS (SELECT 1 FROM json_each(p.indexes) i WHERE ?!='[\"*\"]' AND i.value NOT IN (SELECT value FROM json_each(?))) ORDER BY s.updated,s.id",(actor["tenant"],scope,scope))]
    metrics={}
    for name,left,right in (("received_to_indexed","received","indexed_at"),("index_to_atomic_policy_completion","indexed_at","analysis_completed_at"),("received_to_first_detection","received","first_detection_at"),("received_to_first_case","received","first_case_at"),("received_to_first_composite","received","first_composite_at"),("ml_queue_wait","ml_queued_at","ml_started_at"),("ml_completion","ml_queued_at","ml_finished_at"),("sequence_completion","sequence_queued_at","sequence_finished_at")):
        values=[];missing=negative=0
        for row in rows:
            if row[left] is None or row[right] is None:
                missing+=1
            elif row[right]<row[left]:
                negative+=1
            else:
                values.append((row[right]-row[left])*1000)
        values.sort()
        metrics[name]={"samples":len(values),"missing":missing,"clock_reversal":negative,"p50_ms":values[math.ceil(len(values)*.5)-1] if values else None,"p95_ms":values[math.ceil(len(values)*.95)-1] if values else None,"max_ms":values[-1] if values else None}
    return {"schema":"xsera.analysis-slo.v1","window":{"start":start,"end":end,"basis":"server_received"},"cohort_count":len(rows),"records":rows,"metrics":metrics,"queue":{"pending_originals":pending[0],"oldest_original_received":pending[1],"ml_jobs":jobs},"model_batches":batches,"composite_cohorts":composite,"method":"exact nearest-rank; committed server wall-clock milestones","max_eps_measured":False,"latency_sla_certified":False,"limitations":["Historical phases remain unknown","Atomic policy completion excludes later composite/model completion","Absent detection or Case stages are not successes","Clock reversals are reported and excluded from latency percentiles"]}


def register(app, store, runtime, who, body):
    from fastapi import Request
    from starlette.concurrency import run_in_threadpool
    @app.get("/api/v3/intelligence/policies")
    def policy_list(request: Request):
        return policies(store, who(request))
    @app.post("/api/v3/intelligence/policies", status_code=201)
    async def policy_save(request: Request):
        return await run_in_threadpool(save_policy, store, who(request, ("admin", "analyst")), await body(request))
    @app.put("/api/v3/intelligence/policies/{identifier}")
    async def policy_edit(identifier: str, request: Request):
        return await run_in_threadpool(save_policy, store, who(request, ("admin", "analyst")), await body(request), identifier)
    @app.post("/api/v3/intelligence/policies/{identifier}/review")
    async def policy_review(identifier: str, request: Request):
        return await run_in_threadpool(review_policy, store, who(request, ("admin", "analyst")), identifier, await body(request))
    @app.get("/api/v3/intelligence/signals")
    def signal_list(request: Request, cursor: int = 0, count: int = 100, mode: str = "live"):
        return signals(store, who(request), cursor, count, mode)
    @app.get("/api/v3/intelligence/stories")
    def story_list(request: Request):
        return stories(store, who(request))
    @app.get("/api/v3/intelligence/stories/{identifier}")
    def story_get(identifier: str, request: Request):
        return story(store, who(request), identifier)
    @app.get("/api/v3/intelligence/decisions")
    def decision_list(request: Request, cursor: int = 0, count: int = 100):
        return decisions(store, who(request), cursor, count)
    @app.get("/api/v3/intelligence/slo")
    def analysis_slo_get(request:Request,start:float|None=None,end:float|None=None):
        return analysis_slo(store,who(request),start,end)
