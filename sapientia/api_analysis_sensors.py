"""Current-user API for reviewed external sensor intake and coverage."""

from fastapi import Request
from starlette.concurrency import run_in_threadpool

from . import sensor_adapters

PREFIX = "/api/analysis/sensors"


def register(app, store, runtime, who, body):
    @app.get(PREFIX + "/catalog")
    def catalog(request: Request):
        who(request)
        return sensor_adapters.catalog()

    @app.get(PREFIX + "/sources")
    async def sources(request: Request):
        return await run_in_threadpool(sensor_adapters.listing, store, who(request))

    @app.post(PREFIX + "/sources", status_code=201)
    async def create(request: Request):
        return await run_in_threadpool(
            sensor_adapters.save, store, who(request, ("admin",)), await body(request)
        )

    @app.post(PREFIX + "/sources/{identifier}/review")
    async def review(identifier: str, request: Request):
        return await run_in_threadpool(
            sensor_adapters.review,
            store,
            who(request, ("admin",)),
            identifier,
            await body(request),
        )

    @app.post(PREFIX + "/sources/{identifier}/revoke")
    async def revoke(identifier: str, request: Request):
        return await run_in_threadpool(
            sensor_adapters.revoke,
            store,
            who(request, ("admin",)),
            identifier,
            await body(request),
        )

    @app.post(PREFIX + "/sources/{identifier}/intake", status_code=202)
    async def intake(identifier: str, request: Request):
        return await run_in_threadpool(
            sensor_adapters.intake,
            store,
            who(request, ("admin", "analyst")),
            identifier,
            await body(request),
        )

    @app.post(PREFIX + "/sources/{identifier}/health")
    async def health(identifier: str, request: Request):
        return await run_in_threadpool(
            sensor_adapters.health_report,
            store,
            who(request, ("admin", "analyst")),
            identifier,
            await body(request),
        )

    @app.post(PREFIX + "/preview")
    async def preview(request: Request):
        user = who(request, ("admin", "analyst"))
        data = await body(request)
        if not isinstance(data, dict) or set(data) != {"binding_id", "event"}:
            raise ValueError("Expected binding_id,event")
        with sensor_adapters.principal.transaction(
            store, user, ("admin", "analyst")
        ) as (db, actor):
            row = sensor_adapters._visible(db, actor, data["binding_id"])
            source = dict(
                sensor_adapters.source_registry.visible(db, actor, row["source_id"])
            )
        return {
            "original": sensor_adapters.decode(data["event"], source),
            "persisted": False,
            "signal_created": False,
            "case_created": False,
        }
