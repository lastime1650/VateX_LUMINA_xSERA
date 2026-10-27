"""Authenticated ATT&CK references, source templates and case evidence context."""

from fastapi import Request
from starlette.concurrency import run_in_threadpool

from . import attack_catalog, principal, rule_templates


def _boolean(query, name, default=None):
    value = query.get(name)
    if value is None:
        return default
    if value not in ("true", "false"):
        raise ValueError(name + " must be true or false")
    return value == "true"


def _integer(query, name, default):
    try:
        return int(query.get(name, default))
    except (ValueError, TypeError):
        raise ValueError(name + " must be an integer") from None


def register(app, store, runtime, who, body):
    def route(path, callback):
        async def endpoint(request: Request):
            actor = who(request)

            def read():
                with principal.transaction(store, actor) as (_, fresh):
                    pass
                result = callback(fresh, request.path_params, request.query_params)
                principal.recheck(store, fresh)
                return result

            return await run_in_threadpool(read)

        app.add_api_route(path, endpoint, methods=["GET"], name="templates_" + path)

    route(
        "/api/attack/catalog",
        lambda u, p, q: attack_catalog.listing(
            q.get("search", ""),
            q.get("tactic"),
            q.get("platform"),
            _boolean(q, "include_inactive", False),
            _integer(q, "offset", 0),
            _integer(q, "limit", 100),
        ),
    )
    route(
        "/api/attack/techniques/{identifier}",
        lambda u, p, q: {
            **attack_catalog.metadata(),
            "technique": attack_catalog.technique(p["identifier"], detail=True),
        },
    )
    route("/api/rule-templates/summary", lambda u, p, q: rule_templates.summary())
    route(
        "/api/rule-templates",
        lambda u, p, q: rule_templates.listing(
            q.get("search", ""),
            q.get("platform"),
            _boolean(q, "supported"),
            _integer(q, "offset", 0),
            _integer(q, "limit", 50),
        ),
    )
    route(
        "/api/rule-templates/{identifier}",
        lambda u, p, q: rule_templates.detail(p["identifier"]),
    )
    route(
        "/api/incidents/{incident_id}/attack-context",
        lambda u, p, q: attack_catalog.attack_context(store, u, p["incident_id"]),
    )

    @app.post("/api/rule-templates/{identifier}/apply", status_code=201)
    async def apply_template(identifier: str, request: Request):
        actor = who(request, ("admin", "analyst"))
        return await run_in_threadpool(
            rule_templates.apply, store, actor, identifier, await body(request)
        )
