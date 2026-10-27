"""Authenticated release/source/qualification APIs; no unqualified effect execution."""

from fastapi import Request
from fastapi.responses import StreamingResponse
from starlette.concurrency import run_in_threadpool

from . import action_runtime, connector_runtime, correlation_runtime, effect_receipts, principal, qualification_registry, release_manifest, source_registry, record_governance


def exact(data, fields):
    if not isinstance(data, dict) or set(data) != set(fields):
        raise ValueError("Exact request fields required")
    return data


def register(app, store, runtime, who, body):
    @app.get("/api/v2/effects/{identifier}/history")
    def effect_history(identifier: str, request: Request):
        with principal.transaction(store, who(request)) as (db, actor):
            effect_receipts.visible(db, actor, identifier)
            return {"id": identifier, "history": [dict(r) for r in db.execute("SELECT * FROM effect_receipt_history WHERE id=? ORDER BY version", (identifier,))], "record_count_limit": None}
    @app.get("/api/v2/records/management")
    async def record_management(request: Request):
        return await run_in_threadpool(record_governance.status, store, who(request, ("admin",)))

    @app.put("/api/v2/records/management")
    async def record_management_save(request: Request):
        return await run_in_threadpool(record_governance.configure, store, who(request, ("admin",)), await body(request))

    @app.get("/api/v2/records/{resource}")
    async def records_page(resource: str, request: Request):
        count = int(request.query_params["count"]) if "count" in request.query_params else None
        return await run_in_threadpool(record_governance.page, store, who(request), resource, request.query_params.get("cursor"), count)

    @app.get("/api/v2/records/{resource}/export")
    def records_export(resource: str, request: Request):
        actor = who(request)
        if resource not in record_governance.RESOURCES and resource != "logs":
            raise ValueError("Unsupported durable record resource")
        principal.recheck(store, actor)
        if resource != "logs":
            record_governance.page(store, actor, resource, count=1)
        return StreamingResponse(record_governance.export(store, actor, resource), media_type="application/x-ndjson")
    @app.post("/api/v2/simulation/assets", status_code=201)
    async def virtual_asset(request: Request):
        return await run_in_threadpool(action_runtime.create_asset, store, who(request, ("admin",)), await body(request))

    @app.get("/api/v2/simulation/assets/{source_id}")
    async def virtual_asset_get(source_id: str, request: Request):
        return await run_in_threadpool(action_runtime.asset, store, who(request), source_id)

    @app.post("/api/v2/effects/{identifier}/simulate")
    async def virtual_effect(identifier: str, request: Request):
        data = exact(await body(request), {"version"})
        return await run_in_threadpool(action_runtime.dispatch, store, who(request, ("admin", "analyst")), identifier, data["version"])
    @app.get("/api/v2/release")
    async def release(request: Request):
        with principal.transaction(store, who(request, ("admin",)), ("admin",)) as (_, actor):
            pass
        result = await run_in_threadpool(release_manifest.current_identity)
        who(request, ("admin",))
        principal.recheck(store, actor, ("admin",))
        return result

    @app.get("/api/v2/sources")
    async def sources(request: Request):
        return await run_in_threadpool(source_registry.listing, store, who(request))

    @app.get("/api/v2/correlations")
    async def correlations(request: Request):
        return await run_in_threadpool(correlation_runtime.listing, store, who(request))

    @app.post("/api/v2/correlations", status_code=201)
    async def correlation_create(request: Request):
        return await run_in_threadpool(correlation_runtime.save, store, who(request, ("admin", "analyst")), await body(request))

    @app.put("/api/v2/correlations/{identifier}")
    async def correlation_update(identifier: str, request: Request):
        return await run_in_threadpool(correlation_runtime.save, store, who(request, ("admin", "analyst")), await body(request), identifier)

    @app.post("/api/v2/sources", status_code=201)
    async def source_create(request: Request):
        return await run_in_threadpool(source_registry.save, store, who(request, ("admin",)), await body(request))

    @app.put("/api/v2/sources/{identifier}")
    async def source_update(identifier: str, request: Request):
        return await run_in_threadpool(source_registry.save, store, who(request, ("admin",)), await body(request), identifier)

    @app.post("/api/v2/sources/{identifier}/revoke")
    async def source_revoke(identifier: str, request: Request):
        data = exact(await body(request), {"version"})
        await run_in_threadpool(source_registry.revoke, store, who(request, ("admin",)), identifier, data["version"])
        return {"revoked": True}

    @app.post("/api/v2/sources/{identifier}/intake", status_code=202)
    async def source_intake(identifier: str, request: Request):
        return await run_in_threadpool(connector_runtime.intake, store, who(request, ("admin", "analyst")), identifier, await body(request))

    @app.post("/api/v2/qualification", status_code=201)
    async def qualification(request: Request):
        return await run_in_threadpool(qualification_registry.record, store, who(request, ("admin",)), await body(request))

    @app.post("/api/v2/qualification/check")
    async def check(request: Request):
        data = exact(await body(request), {"capability", "platform", "config_digest", "source_digest", "package_digest"})
        return await run_in_threadpool(qualification_registry.check, store, who(request), **data)

    @app.post("/api/v2/incidents/{incident_id}/effects/prepare", status_code=201)
    async def prepare(incident_id: str, request: Request):
        return await run_in_threadpool(effect_receipts.prepare, store, who(request, ("admin", "analyst")), incident_id, await body(request))

    @app.post("/api/v2/effects/{identifier}/approve")
    async def approve(identifier: str, request: Request):
        data = exact(await body(request), {"version"})
        return await run_in_threadpool(effect_receipts.transition, store, who(request, ("admin", "analyst")), identifier, data["version"], "approved", {})

    @app.post("/api/v2/effects/{identifier}/cancel")
    async def effect_cancel(identifier: str, request: Request):
        data = exact(await body(request), {"version"})
        return await run_in_threadpool(effect_receipts.transition, store, who(request, ("admin", "analyst")), identifier, data["version"], "cancelled", {})

    @app.post("/api/v2/effects/{identifier}/simulation-recover")
    async def virtual_recover(identifier: str, request: Request):
        data = exact(await body(request), {"version"})
        return await run_in_threadpool(action_runtime.recover_unknown, store, who(request, ("admin", "analyst")), identifier, data["version"])

    @app.get("/api/v2/effects/{identifier}")
    def effect(identifier: str, request: Request):
        with principal.transaction(store, who(request)) as (db, actor):
            row = effect_receipts.visible(db, actor, identifier)
            return {"id": row["id"], "state": row["state"], "version": row["version"], "effect_execution": False,
                    "meaning": "Recorded workflow state; independent provider/native qualification is separate"}
