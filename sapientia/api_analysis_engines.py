"""Authenticated fixed-engine analysis API; samples never come from request paths."""
from fastapi import Request
from starlette.concurrency import run_in_threadpool
from . import analysis_engines as engines

PREFIX = "/api/analysis-engines"


def _exact(data, required, optional=()):
    if not isinstance(data, dict) or not set(required) <= set(data) or set(data) - set(required) - set(optional):
        raise ValueError("Expected fields: " + ",".join(required))
    return data


def register(app, store, runtime, who, body):
    @app.get(PREFIX + "/status")
    async def status(request: Request):
        return await run_in_threadpool(engines.status, store, who(request))

    @app.get(PREFIX + "/artifacts")
    async def artifacts(request: Request):
        return await run_in_threadpool(engines.list_artifacts, store, who(request), incident_id=request.query_params.get("incident_id"))

    @app.get(PREFIX + "/runs")
    async def runs(request: Request):
        return await run_in_threadpool(engines.list_runs, store, who(request), incident_id=request.query_params.get("incident_id"))

    @app.get(PREFIX + "/runs/{identifier}")
    async def run(identifier: str, request: Request):
        return await run_in_threadpool(engines.get_run, store, who(request), identifier)

    @app.post(PREFIX + "/runs", status_code=201)
    async def scan(request: Request):
        data = _exact(await body(request), ("artifact_id", "engine"), ("emit_signal", "approval_id"))
        return await run_in_threadpool(engines.scan_artifact, store, who(request, ("admin", "analyst")), data["artifact_id"], data["engine"], emit_signal=data.get("emit_signal", True), approval_id=data.get("approval_id"))

    @app.post(PREFIX + "/runs/{identifier}/poll")
    async def poll(identifier: str, request: Request):
        _exact(await body(request), ())
        return await run_in_threadpool(engines.poll_run, store, who(request, ("admin", "analyst")), identifier)

    @app.get(PREFIX + "/approvals")
    async def approvals(request: Request):
        return await run_in_threadpool(engines.list_approvals, store, who(request), incident_id=request.query_params.get("incident_id"))

    @app.post(PREFIX + "/approvals", status_code=201)
    async def request_approval(request: Request):
        return await run_in_threadpool(engines.request_approval, store, who(request, ("admin",)), await body(request))

    @app.post(PREFIX + "/approvals/{identifier}/review")
    async def review(identifier: str, request: Request):
        return await run_in_threadpool(engines.review_approval, store, who(request, ("admin",)), identifier, await body(request))
