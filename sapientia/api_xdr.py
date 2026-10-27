"""Authenticated AEGIS endpoint intake and evidence projections."""

import os

from fastapi import Request
from starlette.concurrency import run_in_threadpool

from . import principal, xdr_bridge


def register(app, store, runtime, who, body):
    if not hasattr(app.state, "xdr_bridge"):
        app.state.xdr_bridge = xdr_bridge.load_config(
            os.environ.get("SAPIENTIA_XDR_CONFIG")
        )

    def number(query, key):
        try:
            return float(query[key])
        except (KeyError, ValueError, TypeError):
            raise ValueError(key + " must be an epoch timestamp") from None

    def integer(query, key, default):
        try:
            return int(query.get(key, default))
        except (ValueError, TypeError):
            raise ValueError(key + " must be an integer") from None

    @app.get("/api/xdr/status")
    def status(request: Request):
        user = who(request)
        with principal.transaction(store, user):
            return app.state.xdr_bridge.status()

    @app.post("/api/xdr/intake", status_code=202)
    async def intake(request: Request):
        actor = who(request, ("admin", "analyst"))
        return await run_in_threadpool(
            xdr_bridge.intake, store, actor, await body(request)
        )

    @app.get("/api/xdr/telemetry")
    async def telemetry(request: Request):
        actor = who(request)
        query = request.query_params
        return await run_in_threadpool(
            xdr_bridge.telemetry,
            store,
            actor,
            number(query, "start"),
            number(query, "end"),
            query.get("host"),
            integer(query, "limit", 100),
            runtime.stop,
        )

    @app.get("/api/xdr/process-tree")
    async def process_tree(request: Request):
        actor = who(request)
        query = request.query_params
        return await run_in_threadpool(
            xdr_bridge.process_tree,
            store,
            actor,
            number(query, "start"),
            number(query, "end"),
            query.get("host"),
            runtime.stop,
        )

    @app.get("/api/xdr/remote-summary")
    async def remote_summary(request: Request):
        actor = who(request, ("admin",))
        return await run_in_threadpool(app.state.xdr_bridge.summary, store, actor)
