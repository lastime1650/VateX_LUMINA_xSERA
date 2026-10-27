"""Authenticated explicit analysis automation and executable readiness endpoints."""

from fastapi import Request
from starlette.concurrency import run_in_threadpool

from . import detection_automation, rule_templates


def register(app, store, runtime, who, body):
    @app.get("/api/analysis/schedules")
    async def schedules(request: Request):
        return await run_in_threadpool(
            detection_automation.list_schedules, store, who(request)
        )

    @app.post("/api/analysis/schedules", status_code=201)
    async def save_schedule(request: Request):
        return await run_in_threadpool(
            detection_automation.save_schedule,
            store,
            who(request, ("admin", "analyst")),
            await body(request),
        )

    @app.patch("/api/analysis/schedules/{identifier}")
    async def toggle_schedule(identifier: str, request: Request):
        data = await body(request)
        if not isinstance(data, dict) or set(data) != {"enabled", "version"}:
            raise ValueError("Schedule requires enabled/version")
        return await run_in_threadpool(
            detection_automation.toggle_schedule,
            store,
            who(request, ("admin", "analyst")),
            identifier,
            data["enabled"],
            data["version"],
        )

    @app.get("/api/analysis/status")
    async def status(request: Request):
        return await run_in_threadpool(detection_automation.status, store, who(request))

    @app.post("/api/rule-templates/{identifier}/readiness")
    async def readiness(identifier: str, request: Request):
        return await run_in_threadpool(
            rule_templates.readiness,
            store,
            who(request, ("admin", "analyst")),
            identifier,
            await body(request),
        )
