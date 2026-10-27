"""Authenticated adapters for bounded enterprise workflows; no raw SQL endpoint."""

from fastapi import Request
from starlette.concurrency import run_in_threadpool

from . import (
    behavior,
    casework,
    content,
    contribution_verdicts,
    detection_readiness,
    detections,
    entities,
    pipeline,
    sigma_backend,
    sigma_rules,
    soar,
    soar_bindings,
    source_health,
)

EDIT = ("admin", "analyst")
READ = ("admin", "analyst", "viewer")


def _fields(data, required=(), optional=()):
    if (
        not isinstance(data, dict)
        or not set(required) <= set(data)
        or set(data) - set(required) - set(optional)
    ):
        raise ValueError(
            "Expected fields: "
            + ", ".join(required)
            + "; optional: "
            + ", ".join(optional)
        )
    return data


def _integer(query, name, default):
    try:
        return int(query.get(name, default))
    except (TypeError, ValueError):
        raise ValueError(name + " must be an integer") from None


def _number(query, name):
    try:
        return float(query[name])
    except (KeyError, TypeError, ValueError):
        raise ValueError(name + " must be an epoch timestamp") from None


def register(app, store, runtime, who, body):
    def empty(data, callback):
        _fields(data)
        return callback()

    def route(method, path, callback, roles=READ):
        async def endpoint(request: Request):
            actor = who(request, roles)
            data = await body(request) if method != "GET" else {}
            return await run_in_threadpool(
                callback, actor, request.path_params, request.query_params, data
            )

        app.add_api_route(
            path, endpoint, methods=[method], name="enterprise_" + method + "_" + path
        )

    route("GET", "/api/detection-readiness",
          lambda u, p, q, d: detection_readiness.status(store, u), EDIT)

    def replay_detection(u, p, q, d):
        _fields(d, ("end", "version", "request_id"))
        return detections.replay(
            store,
            u,
            p["policy_id"],
            d["end"],
            d["version"],
            d["request_id"],
            cancel=runtime.stop,
        )

    route("POST", "/api/detections/{policy_id}/replay", replay_detection, EDIT)

    route("GET", "/api/entities", lambda u, p, q, d: entities.list_entities(store, u))
    route(
        "GET",
        "/api/entities/resolve",
        lambda u, p, q, d: entities.resolve(store, u, q.get("type"), q.get("value")),
    )
    route(
        "GET",
        "/api/entities/graph",
        lambda u, p, q, d: entities.graph(
            store, u, _number(q, "start"), _number(q, "end"), _integer(q, "limit", 100)
        ),
    )
    route("POST", "/api/entities", lambda u, p, q, d: entities.save(store, u, d), EDIT)
    route(
        "GET",
        "/api/entities/{entity_id}",
        lambda u, p, q, d: entities.get(store, u, p["entity_id"]),
    )
    route(
        "PUT",
        "/api/entities/{entity_id}",
        lambda u, p, q, d: entities.save(store, u, d, p["entity_id"]),
        EDIT,
    )
    route(
        "GET",
        "/api/entities/{entity_id}/timeline",
        lambda u, p, q, d: entities.timeline(
            store,
            u,
            p["entity_id"],
            _number(q, "start"),
            _number(q, "end"),
            _integer(q, "limit", 100),
        ),
    )

    route(
        "GET",
        "/api/behavior/baselines",
        lambda u, p, q, d: behavior.list_baselines(store, u),
        EDIT,
    )
    route(
        "POST",
        "/api/behavior/baselines",
        lambda u, p, q, d: behavior.train(store, u, d, cancel=runtime.stop),
        EDIT,
    )
    route(
        "GET",
        "/api/behavior/baselines/{baseline_id}",
        lambda u, p, q, d: behavior.get(store, u, p["baseline_id"]),
        EDIT,
    )

    def evaluate_behavior(u, p, q, d):
        _fields(d, ("start", "end"))
        return behavior.evaluate(
            store, u, p["baseline_id"], d["start"], d["end"], cancel=runtime.stop
        )

    route(
        "POST",
        "/api/behavior/baselines/{baseline_id}/evaluate",
        evaluate_behavior,
        EDIT,
    )
    route(
        "GET",
        "/api/behavior/runs",
        lambda u, p, q, d: behavior.list_runs(store, u, q.get("baseline_id")),
        EDIT,
    )
    route(
        "GET",
        "/api/behavior/runs/{run_id}",
        lambda u, p, q, d: behavior.get_run(store, u, p["run_id"]),
        EDIT,
    )

    route("GET", "/api/content/packages", lambda u, p, q, d: content.list_for(store, u))

    def save_content(u, p, q, d):
        _fields(d, ("package", "expected_version"))
        return content.save(store, u, d["package"], d["expected_version"])

    route("POST", "/api/content/packages", save_content, EDIT)
    route(
        "POST",
        "/api/content/dry-run",
        lambda u, p, q, d: content.dry_run(store, u, d),
        EDIT,
    )
    route(
        "GET",
        "/api/content/sigma/status",
        lambda u, p, q, d: {
            **sigma_backend.status(),
            "preview_only": True,
            "supported_modifiers": sorted(sigma_backend.MODIFIERS),
            "limits": {
                "input_bytes": 65536,
                "field_mappings": 32,
                "selections": 16,
                "container_entries": 32,
                "structure_depth": 16,
                "regex_characters": 512,
            },
        },
    )
    route(
        "POST",
        "/api/content/sigma/preview",
        lambda u, p, q, d: sigma_rules.preview_sigma(d),
        EDIT,
    )
    route(
        "GET",
        "/api/content/packages/{name}",
        lambda u, p, q, d: content.get(store, u, p["name"], q.get("revision")),
    )
    route(
        "GET",
        "/api/content/packages/{name}/export",
        lambda u, p, q, d: content.export_package(
            store, u, p["name"], q.get("revision")
        ),
    )
    route(
        "GET",
        "/api/content/packages/{name}/coverage",
        lambda u, p, q, d: content.coverage(
            store, u, p["name"], q.get("revision"), _integer(q, "lookback", 86400)
        ),
        EDIT,
    )

    def test_content(u, p, q, d):
        _fields(d, (), ("revision",))
        return content.test(store, u, p["name"], d.get("revision"))

    route("POST", "/api/content/packages/{name}/test", test_content, EDIT)

    def activate_content(fn):
        def call(u, p, q, d):
            _fields(d, ("revision", "expected_active"))
            return fn(store, u, p["name"], d["revision"], d["expected_active"])

        return call

    route(
        "POST",
        "/api/content/packages/{name}/publish",
        activate_content(content.publish),
        ("admin",),
    )
    route(
        "POST",
        "/api/content/packages/{name}/rollback",
        activate_content(content.rollback),
        ("admin",),
    )

    route("GET", "/api/parsers", lambda u, p, q, d: pipeline.list_for(store, u), EDIT)
    route(
        "PUT",
        "/api/parsers/{name}",
        lambda u, p, q, d: pipeline.save(store, u, p["name"], d),
        ("admin",),
    )
    route(
        "POST",
        "/api/parsers/preview",
        lambda u, p, q, d: pipeline.preview(store, u, d),
        EDIT,
    )
    route(
        "GET",
        "/api/quarantine",
        lambda u, p, q, d: pipeline.quarantine(
            store, u, _integer(q, "offset", 0), _integer(q, "count", 10)
        ),
        EDIT,
    )
    route(
        "POST",
        "/api/quarantine/replay",
        lambda u, p, q, d: pipeline.replay(store, u, d),
        ("admin",),
    )
    route(
        "GET",
        "/api/source-monitors",
        lambda u, p, q, d: source_health.list_for(store, u),
        EDIT,
    )
    route(
        "POST",
        "/api/source-monitors",
        lambda u, p, q, d: source_health.save(store, u, d),
        EDIT,
    )
    route(
        "PUT",
        "/api/source-monitors/{monitor_id}",
        lambda u, p, q, d: source_health.save(store, u, d, p["monitor_id"]),
        EDIT,
    )
    route(
        "POST",
        "/api/source-monitors/{monitor_id}/evaluate",
        lambda u, p, q, d: empty(
            d,
            lambda: source_health.evaluate(
                store, u, p["monitor_id"], cancel=runtime.stop
            ),
        ),
        EDIT,
    )

    route(
        "GET",
        "/api/incidents/{incident_id}/workspace",
        lambda u, p, q, d: casework.workspace(store, u, p["incident_id"]),
    )
    route(
        "GET", "/api/incidents/{incident_id}/verdicts",
        lambda u, p, q, d: contribution_verdicts.list_verdicts(
            store, u, p["incident_id"], q.get("after", ""), _integer(q, "count", 100)
        ),
    )
    route(
        "PUT", "/api/incidents/{incident_id}/contributions/{contribution_id}/verdict",
        lambda u, p, q, d: contribution_verdicts.adjudicate(
            store, u, p["incident_id"], p["contribution_id"], d
        ), EDIT,
    )
    for operation in ("split", "merge"):
        route(
            "POST", "/api/incidents/{incident_id}/" + operation,
            lambda u, p, q, d, op=operation: contribution_verdicts.regroup(
                store, u, p["incident_id"], op, d
            ), EDIT,
        )
    route(
        "GET", "/api/incidents/{incident_id}/movements",
        lambda u, p, q, d: contribution_verdicts.movement_history(store, u, p["incident_id"]),
    )
    route(
        "PUT",
        "/api/incidents/{incident_id}/workspace",
        lambda u, p, q, d: casework.configure(store, u, p["incident_id"], d),
        EDIT,
    )
    route(
        "POST",
        "/api/incidents/{incident_id}/actions",
        lambda u, p, q, d: casework.act(store, u, p["incident_id"], d),
        EDIT,
    )
    route(
        "PATCH",
        "/api/incidents/{incident_id}/tasks/{task_id}",
        lambda u, p, q, d: casework.update_task(
            store, u, p["incident_id"], p["task_id"], d
        ),
        EDIT,
    )
    route(
        "POST",
        "/api/incidents/{incident_id}/bookmarks",
        lambda u, p, q, d: casework.bookmark(store, u, p["incident_id"], d),
        EDIT,
    )
    route(
        "GET",
        "/api/incidents/{incident_id}/export",
        lambda u, p, q, d: casework.export_case(store, u, p["incident_id"]),
    )
    route(
        "GET", "/api/playbooks", lambda u, p, q, d: soar.list_playbooks(store, u), EDIT
    )
    route(
        "GET",
        "/api/playbook-bindings",
        lambda u, p, q, d: soar_bindings.listing(store, u),
        EDIT,
    )
    route(
        "POST",
        "/api/playbook-bindings",
        lambda u, p, q, d: soar_bindings.save(store, u, d),
        EDIT,
    )
    route("POST", "/api/playbooks", lambda u, p, q, d: soar.save(store, u, d), EDIT)
    route(
        "GET",
        "/api/playbooks/{playbook_id}",
        lambda u, p, q, d: soar.get_playbook(store, u, p["playbook_id"]),
        EDIT,
    )
    route(
        "PUT",
        "/api/playbooks/{playbook_id}",
        lambda u, p, q, d: soar.save(store, u, d, p["playbook_id"]),
        EDIT,
    )

    def start_run(u, p, q, d):
        _fields(d, ("incident_id", "request_id"))
        return soar.start_run(
            store, u, p["playbook_id"], d["incident_id"], d["request_id"]
        )

    route("POST", "/api/playbooks/{playbook_id}/runs", start_run, EDIT)
    route(
        "GET",
        "/api/playbook-runs",
        lambda u, p, q, d: soar.list_runs(store, u, q.get("incident_id")),
        EDIT,
    )
    route(
        "GET",
        "/api/playbook-runs/{run_id}",
        lambda u, p, q, d: soar.get_run(store, u, p["run_id"]),
        EDIT,
    )
    route(
        "POST",
        "/api/playbook-runs/{run_id}/approve",
        lambda u, p, q, d: empty(d, lambda: soar.approve(store, u, p["run_id"])),
        EDIT,
    )
    route(
        "POST",
        "/api/playbook-runs/{run_id}/cancel",
        lambda u, p, q, d: empty(d, lambda: soar.cancel_run(store, u, p["run_id"])),
        EDIT,
    )
