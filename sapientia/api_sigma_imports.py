"""Authenticated Sigma upload custody, native validation and exact rollout."""

from fastapi import Request
from starlette.concurrency import run_in_threadpool

from . import sigma_imports as imports

READ = ("admin", "analyst", "viewer")
EDIT = ("admin", "analyst")
PREFIX = "/api/content/sigma/imports"


def register(app, store, runtime, who, body):
    def route(method, path, callback, roles=READ, status_code=200):
        async def endpoint(request: Request):
            actor = who(request, roles)
            data = await body(request) if method != "GET" else {}
            return await run_in_threadpool(callback, actor, request.path_params, data)

        app.add_api_route(
            PREFIX + path,
            endpoint,
            methods=[method],
            status_code=status_code,
            name="sigma_import_" + method + path,
        )

    route("GET", "/status", lambda actor, params, data: imports.status())
    route("GET", "", lambda actor, params, data: imports.listing(store, actor))
    route(
        "POST",
        "",
        lambda actor, params, data: imports.save(store, actor, data),
        EDIT,
        201,
    )
    route(
        "GET",
        "/{identifier}",
        lambda actor, params, data: imports.get(store, actor, params["identifier"]),
    )
    route(
        "PUT",
        "/{identifier}",
        lambda actor, params, data: imports.save(
            store, actor, data, params["identifier"]
        ),
        EDIT,
    )
    for action in ("convert", "validate", "activate"):

        def invoke(actor, params, data, action=action):
            imports._fields(data, {"expected_revision"})
            return getattr(imports, action)(
                store, actor, params["identifier"], data["expected_revision"]
            )

        route("POST", "/{identifier}/" + action, invoke, EDIT)
    route(
        "POST",
        "/{identifier}/review",
        lambda actor, params, data: imports.review(
            store, actor, params["identifier"], data
        ),
        EDIT,
    )
    route(
        "POST",
        "/{identifier}/retire",
        lambda actor, params, data: imports.retire(
            store, actor, params["identifier"], data
        ),
        EDIT,
    )
    route("POST", "/{identifier}/rollback", lambda actor, params, data: imports.rollback(store, actor, params["identifier"], data), EDIT)
    route("POST", "/{identifier}/apply-mapping", lambda actor, params, data: imports.apply_mapping(store, actor, params["identifier"], data), EDIT)
    for action, callback in (("mapping-suggestions", imports.mapping_suggestions), ("fixture-candidates", imports.fixture_candidates)):
        def proposal(actor, params, data, callback=callback):
            imports._fields(data, {"expected_revision"})
            return callback(store, actor, params["identifier"], data["expected_revision"])
        route("POST", "/{identifier}/" + action, proposal, EDIT)
