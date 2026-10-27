"""Authenticated console API for offline process-binary YARA analysis."""

from fastapi import Request
from starlette.concurrency import run_in_threadpool

from . import yara_manager

PREFIX = "/api/yara"


def _exact(data, required, optional=()):
    if (
        not isinstance(data, dict)
        or not set(required) <= set(data)
        or set(data) - set(required) - set(optional)
    ):
        raise ValueError("Expected fields: " + ", ".join(required))
    return data


def register(app, store, runtime, who, body):
    @app.get(PREFIX + "/status")
    async def status(request: Request):
        result = await run_in_threadpool(yara_manager.status, store, who(request))
        result["worker_running"] = bool(
            runtime.yara_thread and runtime.yara_thread.is_alive()
        )
        result["worker_error"] = runtime.yara_worker_error
        return result

    @app.get(PREFIX + "/rules")
    async def rules(request: Request):
        query = request.query_params
        try:
            offset, limit = (
                int(query.get("offset", "0")),
                int(query.get("limit", "100")),
            )
        except ValueError:
            raise ValueError("offset and limit require integers") from None
        return await run_in_threadpool(
            yara_manager.list_rules,
            store,
            who(request),
            q=query.get("q", ""),
            offset=offset,
            limit=limit,
            origin=query.get("origin", "all"),
            state=query.get("state", "all"),
        )

    @app.post(PREFIX + "/rules", status_code=201)
    async def create_rule(request: Request):
        return await run_in_threadpool(
            yara_manager.save_rule, store, who(request, ("admin",)), await body(request)
        )

    @app.get(PREFIX + "/rules/{identifier}")
    async def get_rule(identifier: str, request: Request):
        return await run_in_threadpool(
            yara_manager.get_rule, store, who(request), identifier
        )

    @app.put(PREFIX + "/rules/{identifier}")
    async def update_rule(identifier: str, request: Request):
        return await run_in_threadpool(
            yara_manager.save_rule,
            store,
            who(request, ("admin",)),
            await body(request),
            identifier,
        )

    @app.delete(PREFIX + "/rules/{identifier}")
    async def delete_rule(identifier: str, request: Request):
        data = _exact(await body(request), ("expected_revision", "reason"))
        return await run_in_threadpool(
            yara_manager.delete_rule,
            store,
            who(request, ("admin",)),
            identifier,
            data["expected_revision"],
            data["reason"],
        )

    @app.post(PREFIX + "/rules/{identifier}/restore")
    async def restore_rule(identifier: str, request: Request):
        data = _exact(await body(request), ("expected_revision",))
        return await run_in_threadpool(
            yara_manager.restore_rule,
            store,
            who(request, ("admin",)),
            identifier,
            data["expected_revision"],
        )

    @app.post(PREFIX + "/rules/{identifier}/review")
    async def review_rule(identifier: str, request: Request):
        data = _exact(await body(request), ("expected_revision", "approve", "reason"))
        return await run_in_threadpool(
            yara_manager.review_rule,
            store,
            who(request, ("admin",)),
            identifier,
            data["expected_revision"],
            data["approve"],
            data["reason"],
        )

    @app.post(PREFIX + "/validate")
    async def validate(request: Request):
        who(request, ("admin", "analyst"))
        data = _exact(await body(request), ("source",))
        return await run_in_threadpool(yara_manager.validate, data["source"])

    @app.post(PREFIX + "/build")
    async def build(request: Request):
        who(request, ("admin", "analyst"))
        return await run_in_threadpool(yara_manager.build_rule, await body(request))

    @app.get(PREFIX + "/artifacts")
    async def artifacts(request: Request):
        return await run_in_threadpool(
            yara_manager.list_artifacts,
            store,
            who(request),
            incident_id=request.query_params.get("incident_id"),
        )

    @app.get(PREFIX + "/runs")
    async def runs(request: Request):
        return await run_in_threadpool(
            yara_manager.list_runs,
            store,
            who(request),
            incident_id=request.query_params.get("incident_id"),
        )

    @app.get(PREFIX + "/runs/{identifier}")
    async def run(identifier: str, request: Request):
        return await run_in_threadpool(
            yara_manager.get_run, store, who(request), identifier
        )

    @app.post(PREFIX + "/scans", status_code=201)
    async def scan(request: Request):
        data = _exact(
            await body(request), ("artifact_id",), ("rule_ids", "emit_signal")
        )
        return await run_in_threadpool(
            yara_manager.scan_artifact,
            store,
            who(request, ("admin", "analyst")),
            data["artifact_id"],
            rule_ids=data.get("rule_ids"),
            emit_signal=data.get("emit_signal", True),
        )

    @app.get(PREFIX + "/collection-targets")
    async def collection_targets(request: Request):
        from . import yara_collection

        return await run_in_threadpool(
            yara_collection.targets,
            store,
            who(request),
            request.query_params.get("incident_id"),
        )

    @app.post(PREFIX + "/collections", status_code=201)
    async def collect(request: Request):
        from . import yara_collection

        return await run_in_threadpool(
            yara_collection.request,
            store,
            who(request, ("admin", "analyst")),
            await body(request),
        )
