"""Full original ancestry behind bounded signal summaries and Case references."""
import json

from . import evidence_scope, migrations, principal, release_manifest
from .storage import ConflictError, encode


def initialize(store):
    migrations.apply_store(store, "signal_evidence", [
        "CREATE TABLE IF NOT EXISTS signal_evidence_manifests(tenant TEXT NOT NULL,signal_id TEXT NOT NULL,digest TEXT NOT NULL,indexes TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(tenant,signal_id))",
    ])


def ancestry(store, db, actor, signal, *, memo=None, path=(), walk=None):
    if len(path) > 8 or signal.get("id") in path:
        raise ValueError("Signal ancestry is cyclic or exceeds eight levels")
    walk = {'count': 0, 'cache': {}} if walk is None else walk
    key = signal.get('id')
    if key and key in walk['cache']:
        return walk['cache'][key]
    walk['count'] += 1
    if walk['count'] > 4096:
        raise ValueError('Signal ancestry exceeds 4096 visited nodes')
    ids = set(signal["event_ids"])
    indexes = set(signal.get("indexes", []))
    manifests = []
    proofs = {p['event_id']: p for p in signal.get('originals', [])}
    if signal.get("rule_id", "").startswith("ml:research:"):
        from . import advanced_intelligence, research_behavior
        run_id = signal.get("metadata", {}).get("research_run_id")
        # Match the existing bridge: caller needs the complete model scope,
        # while immutable publication is revalidated as the current run owner.
        run = advanced_intelligence._verified(store, db, actor, run_id, memo=memo)
        owner = principal.current(db, {'name': run['owner'], 'tenant': actor['tenant'], 'role': 'analyst'}, ('admin', 'analyst'))
        full = research_behavior.long_publication_evidence(store, db, owner, run_id, memo=memo)
        descriptor = full["descriptor"]
        if descriptor != signal.get("metadata", {}).get("evidence_manifest"):
            raise ConflictError("Research evidence manifest differs from immutable run")
        ids.update(full["event_ids"])
        proofs.update({p['event_id']: p for p in full['proofs']})
        if descriptor:
            indexes.update(descriptor["indexes"])
            manifests.append(descriptor)
    for parent_id in signal.get("parent_signal_ids", []):
        row = db.execute("SELECT body FROM intelligence_signals WHERE tenant=? AND id=?", (actor["tenant"], parent_id)).fetchone()
        if not row:
            raise KeyError("Complete signal ancestry unavailable")
        parent = json.loads(row[0])
        if not principal.contains(actor["allowed_indexes"], parent["indexes"]):
            raise KeyError("Complete ancestry outside current scope")
        full = ancestry(store, db, actor, parent, memo=memo, path=(*path, signal.get("id", "pending")), walk=walk)
        ids.update(full["event_ids"])
        indexes.update(full["indexes"])
        manifests.extend(full["manifests"])
        proofs.update({p['event_id']: p for p in full['proofs']})
    if len(ids) > 32768:
        raise ValueError("Complete ancestry exceeds bounded 32768 originals")
    if not principal.contains(actor["allowed_indexes"], sorted(indexes)):
        raise PermissionError("Complete evidence scope unavailable")
    manifests = {release_manifest.digest(value): value for value in manifests}
    result = {"event_ids": sorted(ids), "indexes": sorted(indexes), "manifests": [manifests[k] for k in sorted(manifests)], 'proofs': [proofs[k] for k in sorted(proofs)]}
    if key:
        walk['cache'][key] = result
    return result


def historical_manifest(db, actor, signal, *, cache=None, path=()):
    """Read authority for retained history, independent of model activation."""
    cache = {} if cache is None else cache
    identifier = signal['id']
    if identifier in path or len(path) > 8 or len(cache) >= 4096:
        raise ValueError('Historical ancestry traversal limit reached')
    if identifier in cache:
        return cache[identifier]
    if not principal.contains(actor['allowed_indexes'], signal['indexes']):
        raise KeyError('Complete historical signal scope unavailable')
    if signal.get('rule_id', '').startswith('ml:research:'):
        model = db.execute('SELECT indexes FROM research_behavior_models WHERE tenant=? AND id=?', (actor['tenant'], signal['rule_id'][len('ml:research:'):])).fetchone()
        if not model or not principal.contains(actor['allowed_indexes'], json.loads(model['indexes'])):
            raise KeyError('Complete historical model scope unavailable')
    manifest = db.execute('SELECT * FROM signal_evidence_manifests WHERE tenant=? AND signal_id=?', (actor['tenant'], identifier)).fetchone()
    if manifest:
        full = json.loads(manifest['body'])
        if release_manifest.digest(full) != manifest['digest']:
            raise ConflictError('Retained evidence manifest hash changed')
        indexes = json.loads(manifest['indexes'])
        if (not principal.contains(actor['allowed_indexes'], indexes)
            or sorted({p['index_name'] for p in full['proofs']}) != indexes
            or set(full['event_ids']) != {p['event_id'] for p in full['proofs']}
            or not set(signal['event_ids']) <= set(full['event_ids'])):
            raise KeyError('Complete historical evidence scope unavailable')
    else:
        if signal.get('metadata', {}).get('evidence_manifest'):
            raise ConflictError('Historical long evidence manifest unavailable')
        full = {'event_ids': signal['event_ids'], 'manifests': [], 'proofs': signal['originals']}
    for parent_id in signal.get('parent_signal_ids', []):
        parent = db.execute('SELECT body FROM intelligence_signals WHERE tenant=? AND id=?', (actor['tenant'], parent_id)).fetchone()
        if not parent:
            raise KeyError('Historical parent unavailable')
        historical_manifest(db, actor, json.loads(parent[0]), cache=cache, path=(*path, identifier))
    cache[identifier] = full
    return full


def retain(store, db, actor, signal, full):
    if not full["manifests"]:
        return
    proofs = {p['event_id']: p for p in full['proofs']}
    proofs.update({p['event_id']: p for p in signal['originals']})
    if set(proofs) != set(full['event_ids']):
        raise ConflictError('Complete signal proof manifest required')
    descriptor = {"event_ids": full["event_ids"], "manifests": full["manifests"], 'proofs': [proofs[k] for k in sorted(proofs)]}
    db.execute("INSERT OR IGNORE INTO signal_evidence_manifests VALUES(?,?,?,?,?)",
               (actor["tenant"], signal["id"], release_manifest.digest(descriptor), encode(full["indexes"]), encode(descriptor)))


def protect_case(db, actor, signal, full):
    # Emitter fingerprints are based on short originals. Extend that exact
    # contribution's permanent raw protection without inflating the UI payload.
    for row in db.execute("SELECT id FROM risk_contributions WHERE tenant=? AND json_extract(evidence,'$.analysis.signal_id')=?", (actor["tenant"], signal["id"])):
        db.executemany("INSERT OR IGNORE INTO record_case_evidence_refs VALUES(?,?,?,?)",
                       [(actor["tenant"], eid, "contribution", row["id"]) for eid in full["event_ids"]])


def page(store, who, signal_id, offset=0, count=32):
    evidence_scope.integer(offset, "offset", 0, 32768)
    evidence_scope.integer(count, "count", 1, 32)
    with store.segment_lock.read(), principal.transaction(store, who) as (db, actor):
        row = db.execute("SELECT body FROM intelligence_signals WHERE tenant=? AND id=?", (actor["tenant"], signal_id)).fetchone()
        if not row:
            raise KeyError("Signal unavailable")
        signal = json.loads(row[0])
        if not principal.contains(actor["allowed_indexes"], signal["indexes"]):
            raise KeyError("Complete signal scope unavailable")
        full = historical_manifest(db, actor, signal)
        ids = full["event_ids"][offset:offset+count]
        records = evidence_scope.originals(store, actor, ids) if ids else {}
        evidence_scope.recheck(db, actor, records)
        proofs = {p['event_id']: p for p in full['proofs']}
        if any(any(proofs.get(eid, {}).get(key) != value for key, value in evidence_scope.reference(record).items()) for eid, record in records.items()):
            raise ConflictError('Historical original differs from retained proof')
        from . import content_notices
        notices = content_notices.for_signal(db, actor, signal)
        return {"signal_id": signal_id, "items": [records[eid] for eid in ids], "total": len(full["event_ids"]),
                "content_notices": notices,
                "next_offset": offset+count if offset+count < len(full["event_ids"]) else None,
                "manifests": full["manifests"], "complete_current_authority_checked": True,
                'scope': 'historical_original_evidence_only_no_current_detection_authorization'}
