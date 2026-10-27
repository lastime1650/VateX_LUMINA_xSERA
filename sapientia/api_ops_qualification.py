"""Authenticated operational rehearsal, integrity and delivery coverage API."""

from fastapi import Request
from starlette.concurrency import run_in_threadpool

from . import ops_qualification as ops
from . import release_integrity, source_delivery_slo

PREFIX = "/api/ops/qualification"


def register(app, store, runtime, who, body):
    @app.get(PREFIX + "/status")
    def status(request: Request):
        return ops.status(store, who(request))

    @app.get(PREFIX + "/plans")
    def plans(request: Request):
        return ops.plans(store, who(request))

    @app.post(PREFIX + "/plans", status_code=201)
    async def create(request: Request):
        return await run_in_threadpool(
            ops.save, store, who(request, ("admin",)), await body(request)
        )

    @app.put(PREFIX + "/plans/{identifier}")
    async def edit(identifier: str, request: Request):
        return await run_in_threadpool(
            ops.save, store, who(request, ("admin",)), await body(request), identifier
        )

    @app.post(PREFIX + "/plans/{identifier}/review")
    async def review(identifier: str, request: Request):
        return await run_in_threadpool(
            ops.review, store, who(request, ("admin",)), identifier, await body(request)
        )

    @app.post(PREFIX + "/plans/{identifier}/run")
    async def run(identifier: str, request: Request):
        return await run_in_threadpool(
            ops.run, store, who(request, ("admin",)), identifier, await body(request)
        )

    @app.get(PREFIX + "/runs")
    def runs(request: Request):
        return ops.runs(store, who(request))

    @app.get(PREFIX + "/runs/{identifier}")
    def get_run(identifier: str, request: Request):
        return ops.get_run(store, who(request), identifier)

    @app.get("/api/ops/integrity/status")
    def integrity(request: Request):
        who(request, ("admin",))
        return release_integrity.status()

    @app.get("/api/ops/source-slo")
    def source_slo(request: Request):
        return source_delivery_slo.listing(store, who(request))

    @app.put("/api/ops/source-slo/{identifier}")
    async def source_slo_save(identifier: str, request: Request):
        return await run_in_threadpool(
            source_delivery_slo.save,
            store,
            who(request, ("admin",)),
            identifier,
            await body(request),
        )
