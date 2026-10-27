"""Authenticated downloads and independent HTTPS-only endpoint credentials."""

import json
import threading
import time
from collections import OrderedDict, deque

from fastapi import HTTPException, Request
from fastapi.responses import Response
from starlette.concurrency import run_in_threadpool

from . import agent_distribution, endpoint_policies, endpoint_response, principal


def register(app, store, runtime, who, body):
    if not hasattr(app.state, "agent_distribution"):
        app.state.agent_distribution = agent_distribution.Distribution(
            store, agent_distribution.load_config()
        )
    service = app.state.agent_distribution
    endpoint_policies.initialize(store)
    slots = threading.BoundedSemaphore(4)
    rate_lock = threading.Lock()
    attempts = OrderedDict()

    @app.get("/api/incidents/{incident_id}/agent-response")
    async def response_listing(incident_id: str, request: Request):
        return await run_in_threadpool(
            endpoint_response.listing,
            store,
            who(request, ("admin", "analyst")),
            incident_id,
        )

    @app.post("/api/incidents/{incident_id}/agent-response", status_code=201)
    async def response_create(incident_id: str, request: Request):
        return await run_in_threadpool(
            endpoint_response.create,
            store,
            who(request, ("admin", "analyst")),
            incident_id,
            await body(request),
        )

    @app.get("/api/agent-responses/{identifier}")
    async def response_get(identifier: str, request: Request):
        return await run_in_threadpool(
            endpoint_response.get, store, who(request, ("admin", "analyst")), identifier
        )

    @app.post("/api/agent-responses/{identifier}/cancel")
    async def response_cancel(identifier: str, request: Request):
        actor = who(request, ("admin", "analyst"))
        if await body(request) != {}:
            raise ValueError("Cancellation body must be empty")
        return await run_in_threadpool(
            endpoint_response.cancel, store, actor, identifier
        )

    def download_response(result):
        blob, digest, filename = result
        return Response(
            blob,
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Package-SHA256": digest,
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @app.get("/api/xdr/agents/distribution")
    def distribution_status(request: Request):
        with principal.transaction(store, who(request)):
            return service.status()

    @app.get("/api/xdr/agents/packages/{platform}")
    def generic_package(platform: str, request: Request):
        with principal.transaction(
            store, who(request, ("admin", "analyst")), ("admin", "analyst"), write=True
        ) as (db, actor):
            result = agent_distribution.package(platform)
            store.audit(
                db,
                actor["tenant"],
                actor["name"],
                "endpoint.runtime.download",
                {"platform": platform, "sha256": result[1]},
            )
        return download_response(result)

    @app.get("/api/xdr/agents/deployments")
    def deployments(request: Request):
        return service.deployments(who(request, ("admin",)))

    @app.post("/api/xdr/agents/deployments", status_code=201)
    async def create_deployment(request: Request):
        actor = who(request, ("admin",))
        return await run_in_threadpool(service.create, actor, await body(request))

    @app.post("/api/xdr/agents/deployments/{identifier}/package")
    def deployment_package(identifier: str, request: Request):
        return download_response(service.download(who(request, ("admin",)), identifier))

    @app.get("/api/xdr/agents")
    def agents(request: Request):
        return service.agents(who(request))

    @app.get("/api/xdr/agents/defense-policies")
    def defense_policies(request: Request):
        return endpoint_policies.listing(store, who(request, ("admin", "analyst")))

    @app.post("/api/xdr/agents/defense-policies", status_code=201)
    async def defense_save(request: Request):
        return await run_in_threadpool(
            endpoint_policies.save, store, who(request, ("admin",)), await body(request)
        )

    @app.post("/api/xdr/agents/defense-policies/{identifier}/approve")
    async def defense_approve(identifier: str, request: Request):
        if await body(request) != {}:
            raise ValueError("Defense approval body must be empty")
        return await run_in_threadpool(
            endpoint_policies.approve, store, who(request, ("admin",)), identifier
        )

    @app.get("/api/xdr/agents/defense-policies/{identifier}/bundle")
    def defense_bundle(identifier: str, request: Request):
        result = endpoint_policies.bundle(
            store, who(request, ("admin", "analyst")), identifier
        )
        return Response(
            json.dumps(result),
            media_type="application/json",
            headers={
                "Cache-Control": "no-store",
                "Content-Disposition": 'attachment; filename="xsera-defense-policy.json"',
            },
        )

    @app.delete("/api/xdr/agents/{identifier}")
    def revoke(identifier: str, request: Request):
        return service.revoke(who(request, ("admin",)), identifier)

    def endpoint(request):
        # Do not trust Forwarded headers as proof of a confidential transport.
        if request.url.scheme != "https" or any(
            name in request.headers
            for name in ("forwarded", "x-forwarded-proto", "x-forwarded-host")
        ):
            raise HTTPException(403, "Endpoint protocol requires direct verified HTTPS")
        if not service.config:
            raise HTTPException(403, "Endpoint enrollment is disabled")

    def credential(request):
        endpoint(request)
        header = request.headers.get("authorization", "")
        if not header.startswith("Bearer "):
            raise HTTPException(401, "Endpoint credential required")
        return header[7:]

    async def invoke(request, callback, *args):
        if not slots.acquire(blocking=False):
            raise HTTPException(
                503,
                "Endpoint admission workers are busy; retry stable event IDs",
                headers={"Retry-After": "1"},
            )
        try:
            return await run_in_threadpool(callback, *args, await body(request))
        except PermissionError:
            raise HTTPException(
                401, "Endpoint authentication or current index grant denied"
            ) from None
        finally:
            slots.release()

    @app.post("/api/agent/register")
    @app.post("/api/endpoint-agent/register")
    async def enroll(request: Request):
        endpoint(request)
        now = time.monotonic()
        with rate_lock:
            ip = request.client.host if request.client else "unknown"
            recent = attempts.setdefault(ip, deque())
            attempts.move_to_end(ip)
            while len(attempts) > 1024:
                attempts.popitem(last=False)
            while recent and recent[0] <= now - 60:
                recent.popleft()
            if len(recent) >= 20:
                raise HTTPException(
                    429,
                    "Too many enrollment attempts; wait one minute",
                    headers={"Retry-After": "60"},
                )
            recent.append(now)
        result = await invoke(request, service.enroll)
        result["defense_public_key"] = await run_in_threadpool(
            endpoint_policies.public_key, store, result["tenant"]
        )
        return Response(
            json.dumps(result),
            media_type="application/json",
            headers={"Cache-Control": "no-store"},
        )

    @app.post("/api/agent/heartbeat")
    @app.post("/api/endpoint-agent/heartbeat")
    async def heartbeat(request: Request):
        return await invoke(request, service.heartbeat, credential(request))

    @app.post("/api/agent/defense-policy")
    @app.post("/api/endpoint-agent/defense-policy")
    async def defense_fetch(request: Request):
        return await invoke(
            request, endpoint_policies.fetch, store, service, credential(request)
        )

    @app.post("/api/agent/renew")
    @app.post("/api/endpoint-agent/renew")
    async def renew(request: Request):
        return await invoke(request, service.renew, credential(request))

    @app.post("/api/agent/commands/{command_id}/artifact")
    async def artifact_upload(command_id: str, request: Request):
        return await invoke(
            request,
            endpoint_response.artifact_upload,
            store,
            service,
            credential(request),
            command_id,
        )

    @app.get("/api/endpoint-artifacts/{artifact_id}/download")
    async def artifact_download(artifact_id: str, request: Request):
        blob, filename, digest = await run_in_threadpool(
            endpoint_response.artifact_download,
            store,
            who(request, ("admin", "analyst")),
            artifact_id,
        )
        return Response(
            blob,
            media_type="application/octet-stream",
            headers={
                "Cache-Control": "no-store",
                "X-Artifact-SHA256": digest,
                "Content-Disposition": 'attachment; filename="' + filename + '"',
                "X-Content-Type-Options": "nosniff",
            },
        )

    @app.post("/api/agent/ingest")
    @app.post("/api/endpoint-agent/events")
    async def events(request: Request):
        return await invoke(request, service.ingest, credential(request))

    @app.post("/api/agent/poll")
    @app.post("/api/endpoint-agent/poll")
    async def poll(request: Request):
        return await invoke(request, service.poll, credential(request))

    @app.post("/api/agent/ack")
    @app.post("/api/endpoint-agent/ack")
    async def execution_ack(request: Request):
        return await invoke(request, service.response_ack, credential(request))

    @app.post("/api/agent/result")
    @app.post("/api/endpoint-agent/result")
    async def execution_result(request: Request):
        return await invoke(request, service.response_result, credential(request))
