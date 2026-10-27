"""Current-scope research -> publication -> derived signals -> Case navigation."""
import json
import time

from fastapi import Request
from starlette.concurrency import run_in_threadpool

from . import principal, research_behavior, signal_evidence
from .storage import ConflictError, encode


def trace(store, who, identifier):
    run = research_behavior.get_run(store, who, identifier)
    with principal.transaction(store, who) as (db, actor):
        model = db.execute("SELECT indexes FROM research_behavior_models WHERE tenant=? AND id=?", (actor['tenant'], run['model_id'])).fetchone()
        if not model or not principal.contains(actor['allowed_indexes'], json.loads(model['indexes'])):
            raise KeyError('Research trace requires complete model scope')
        publication = db.execute('SELECT state,signal_id,error FROM advanced_research_publications WHERE tenant=? AND run_id=?', (actor['tenant'], identifier)).fetchone()
        publication = dict(publication) if publication else {'state': 'not_published', 'signal_id': None, 'error': None}
        if publication['signal_id']:
            base = db.execute('SELECT body FROM intelligence_signals WHERE tenant=? AND id=?', (actor['tenant'], publication['signal_id'])).fetchone()
            base = json.loads(base[0]) if base else None
            if (not base or base['metadata'].get('research_run_id') != identifier
                or base['rule_id'] != 'ml:research:'+run['model_id']
                or base['model_digest'] != run['model_digest'] or base['rule_revision'] != run['model_revision']
                or sorted(base['event_ids']) != sorted(run['event_ids'])
                or base['metadata'].get('evidence_manifest') != run.get('long_evidence')):
                raise ConflictError('Publication binding differs from immutable research run')
        found = {}
        frontier = [publication['signal_id']] if publication['signal_id'] else []
        truncated = False
        read_cache = {}
        for _ in range(9):
            if not frontier:
                break
            rows = db.execute("SELECT body FROM intelligence_signals WHERE tenant=? AND (id IN (SELECT value FROM json_each(?)) OR EXISTS(SELECT 1 FROM json_each(parent_signal_ids) p WHERE p.value IN(SELECT value FROM json_each(?)))) ORDER BY seq LIMIT 201", (actor['tenant'], encode(frontier), encode(frontier))).fetchall()
            if len(rows) > 200:
                truncated = True
                break
            next_frontier = []
            for row in rows:
                signal = json.loads(row[0])
                if signal['id'] in found:
                    continue
                if not principal.contains(actor['allowed_indexes'], signal['indexes']):
                    continue
                try:
                    signal_evidence.historical_manifest(db, actor, signal, cache=read_cache)
                except (KeyError, PermissionError, ConflictError, ValueError):
                    continue
                if len(found) >= 200:
                    truncated = True
                    break
                found[signal['id']] = signal
                next_frontier.append(signal['id'])
            frontier = next_frontier
        if frontier:
            truncated = True
        cases = []
        for row in db.execute("SELECT DISTINCT i.id,i.name,i.status FROM risk_contributions r JOIN incidents i ON i.tenant=r.tenant AND i.id=r.incident_id WHERE r.tenant=? AND json_extract(r.evidence,'$.analysis.signal_id') IN(SELECT value FROM json_each(?)) ORDER BY i.id LIMIT 201", (actor['tenant'], encode(list(found)))):
            try:
                principal.incident(db, actor, row['id'])
            except KeyError:
                continue
            cases.append(dict(row))
        descriptor = run.get('long_evidence')
        return {'run_id': identifier, 'publication': publication,
                'signals': [{'id': s['id'], 'kind': s['kind'], 'rule_id': s['rule_id'], 'parent_signal_ids': s['parent_signal_ids']} for s in found.values()],
                'cases': cases[:200], 'evidence': {'short_count': len(run['event_ids']), 'long_count': descriptor['count'] if descriptor else 0, 'manifest_id': descriptor['snapshot_id'] if descriptor else None},
                'complete': not truncated and len(cases) <= 200,
                'limits': {'signals': 200, 'depth': 8, 'cases': 200},
                'links': {'signal_evidence': '/api/intelligence/signals/'+publication['signal_id']+'/evidence' if publication['signal_id'] else None}}


def pipeline_status(store, who, runtime):
    from . import intelligence, pipeline_slo
    with principal.transaction(store, who) as (db, actor):
        scope = actor['allowed_indexes']
        queued = db.execute("SELECT count(*),min(received) FROM queue WHERE tenant=? AND (?='[\"*\"]' OR COALESCE(json_extract(payload,'$.index'),'main') IN(SELECT value FROM json_each(?)))", (actor['tenant'], encode(scope), encode(scope))).fetchone()
    end = time.time()
    return {'queue': {'events': queued[0], 'oldest_age_seconds': max(0, end-queued[1]) if queued[1] else 0},
            'analysis': intelligence.analysis_slo(store, who, end-3600, end),
            'pipeline': pipeline_slo.snapshot(store, who, end-3600, end),
            'dispatch': runtime.dispatch.snapshot() if actor['role'] == 'admin' and scope == ['*'] else {'durable_poll_fallback': True},
            'claims': {'sustained_enterprise_capacity_certified': False, 'native_host_effects': 0}}


def register(app, store, runtime, who, body):
    @app.get('/api/ops/enterprise/sources/{identifier}/starter')
    async def enterprise_starter(identifier: str, request: Request):
        from . import enterprise_adapters
        return await run_in_threadpool(enterprise_adapters.starter, store, who(request), identifier)

    @app.get('/api/ops/enterprise/sources/{identifier}/collector')
    async def enterprise_collector_status(identifier: str, request: Request):
        from . import enterprise_collectors
        return await run_in_threadpool(enterprise_collectors.status, store, who(request), identifier)

    @app.post('/api/ops/enterprise/sources/{identifier}/collector/collect')
    async def enterprise_collect(identifier: str, request: Request):
        from . import enterprise_collectors
        return await run_in_threadpool(enterprise_collectors.collect, store, who(request, ('admin',)), identifier, await body(request))
    @app.get('/api/research/runs/{identifier}/trace')
    async def get_trace(identifier: str, request: Request):
        return await run_in_threadpool(trace, store, who(request), identifier)

    @app.get('/api/intelligence/signals/{identifier}/evidence')
    async def evidence(identifier: str, request: Request, offset: int = 0, count: int = 32):
        return await run_in_threadpool(signal_evidence.page, store, who(request), identifier, offset, count)

    @app.get('/api/ops/pipeline')
    async def pipeline(request: Request):
        return await run_in_threadpool(pipeline_status, store, who(request), runtime)
