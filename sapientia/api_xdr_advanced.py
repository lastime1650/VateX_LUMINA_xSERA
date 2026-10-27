"""Authenticated typed operational analytics and artifact verdict endpoints."""

import importlib.util

from fastapi import Request
from fastapi.responses import Response
from starlette.concurrency import run_in_threadpool

from . import (
    detection_governance,
    file_verdicts,
    pipeline_slo,
    principal,
    risk_priority,
    sandbox_provider,
    temporal_identity,
)

PREFIX = "/api/xdr/advanced"
EDIT = ("admin", "analyst")


def _exact(data, fields):
    if not isinstance(data, dict) or set(data) != set(fields):
        raise ValueError("Expected exact fields: " + ", ".join(fields))
    return data


def _number(query, name):
    try:
        return float(query[name])
    except (ValueError, TypeError, KeyError):
        raise ValueError(name + " requires an epoch timestamp") from None


def register(app, store, runtime, who, body):
    @app.get(PREFIX + "/capabilities")
    def capabilities(request: Request):
        with principal.transaction(store, who(request)):
            return {
                "schema": "xsera.advanced-capabilities.v1",
                "identity": {
                    "kinds": ["ip", "user", "nat"],
                    "exact_nat_tuple": True,
                    "ambiguity_explicit": True,
                    "automatic_endpoint_authorization": False,
                },
                "governance": {
                    "peer_approval": True,
                    "expiry": True,
                    "critical_storm_bypass": True,
                    "logs_deleted": False,
                },
                "priority": {"model": risk_priority.MODEL, "probability": False},
                "slo": {
                    "method": "exact nearest rank",
                    "max_visible_cohort": pipeline_slo.MAX_COHORT,
                    "enterprise_certification": False,
                },
                "file_verdict": {
                    "sample_execution": False,
                    "pe_elf_headers": True,
                    "managed_signatures": ["sha256", "literal", "yara"],
                    "yara_runtime_available": importlib.util.find_spec("yara")
                    is not None,
                    "sandbox_sample_egress": False,
                    "optional_authenticated_provider_pull": True,
                    "sample_access_requires_peer_approved_opt_in": True,
                    "sample_egress_by_default": False,
                    "provider_sdk_access_protocol": sandbox_provider.ACCESS_PROTOCOL,
                    "external_provider_verification": True,
                    "provider_result_protocol": sandbox_provider.PROTOCOL,
                    "provider_trust_peer_approval": True,
                    "trained_ml": False,
                },
            }

    @app.get(PREFIX + "/identity")
    async def bindings(request: Request):
        try:
            limit = int(request.query_params.get("limit", "100"))
        except ValueError:
            raise ValueError("limit requires an integer") from None
        return await run_in_threadpool(
            temporal_identity.list_bindings, store, who(request), limit=limit
        )

    @app.post(PREFIX + "/identity", status_code=201)
    async def create_binding(request: Request):
        return await run_in_threadpool(
            temporal_identity.save, store, who(request, EDIT), await body(request)
        )

    @app.put(PREFIX + "/identity/{identifier}")
    async def update_binding(identifier: str, request: Request):
        return await run_in_threadpool(
            temporal_identity.save,
            store,
            who(request, EDIT),
            await body(request),
            identifier,
        )

    @app.post(PREFIX + "/identity/resolve")
    async def resolve_binding(request: Request):
        actor = who(request)
        data = await body(request)
        if set(data) - {"kind", "lookup", "at", "session_id"} or not {
            "kind",
            "lookup",
            "at",
        } <= set(data):
            raise ValueError(
                "Identity resolve requires kind,lookup,at and optional session_id"
            )
        return await run_in_threadpool(
            temporal_identity.resolve,
            store,
            actor,
            data["kind"],
            data["lookup"],
            data["at"],
            data.get("session_id"),
        )

    @app.post(PREFIX + "/identity/{identifier}/revoke")
    async def revoke_binding(identifier: str, request: Request):
        actor = who(request, EDIT)
        data = _exact(await body(request), ("version", "reason"))
        return await run_in_threadpool(
            temporal_identity.revoke,
            store,
            actor,
            identifier,
            data["version"],
            data["reason"],
        )

    @app.get(PREFIX + "/identity/{identifier}/history")
    async def binding_history(identifier: str, request: Request):
        return await run_in_threadpool(
            temporal_identity.history, store, who(request), identifier
        )

    @app.get(PREFIX + "/governance")
    async def governance_rules(request: Request):
        return await run_in_threadpool(
            detection_governance.list_rules, store, who(request)
        )

    @app.get(PREFIX + "/policies")
    async def governance_policies(request: Request):
        return await run_in_threadpool(
            detection_governance.list_policies, store, who(request, EDIT)
        )

    @app.post(PREFIX + "/governance", status_code=201)
    async def create_governance(request: Request):
        return await run_in_threadpool(
            detection_governance.save, store, who(request, EDIT), await body(request)
        )

    @app.put(PREFIX + "/governance/{identifier}")
    async def update_governance(identifier: str, request: Request):
        return await run_in_threadpool(
            detection_governance.save,
            store,
            who(request, EDIT),
            await body(request),
            identifier,
        )

    @app.post(PREFIX + "/governance/{identifier}/review")
    async def review_governance(identifier: str, request: Request):
        actor = who(request, ("admin",))
        data = _exact(await body(request), ("version", "approve", "reason"))
        return await run_in_threadpool(
            detection_governance.review,
            store,
            actor,
            identifier,
            data["version"],
            data["approve"],
            data["reason"],
        )

    @app.post(PREFIX + "/governance/{identifier}/revoke")
    async def revoke_governance(identifier: str, request: Request):
        actor = who(request, EDIT)
        data = _exact(await body(request), ("version", "reason"))
        return await run_in_threadpool(
            detection_governance.revoke,
            store,
            actor,
            identifier,
            data["version"],
            data["reason"],
        )

    @app.get(PREFIX + "/governance/decisions")
    async def governance_decisions(request: Request):
        actor = who(request)
        query = request.query_params
        return await run_in_threadpool(
            detection_governance.decisions,
            store,
            actor,
            _number(query, "start"),
            _number(query, "end"),
        )

    @app.get(PREFIX + "/assets/{entity_id}/risk-context")
    async def risk_context(entity_id: str, request: Request):
        return await run_in_threadpool(
            risk_priority.context, store, who(request), entity_id
        )

    @app.put(PREFIX + "/assets/{entity_id}/risk-context")
    async def save_risk_context(entity_id: str, request: Request):
        return await run_in_threadpool(
            risk_priority.save_context,
            store,
            who(request, EDIT),
            entity_id,
            await body(request),
        )

    @app.get(PREFIX + "/cases/{incident_id}/priority")
    async def case_priority(incident_id: str, request: Request):
        return await run_in_threadpool(
            risk_priority.case_priority,
            store,
            who(request),
            incident_id,
            request.query_params.get("entity_id"),
        )

    @app.get(PREFIX + "/slo")
    async def slo(request: Request):
        actor = who(request)
        return await run_in_threadpool(
            pipeline_slo.snapshot,
            store,
            actor,
            _number(request.query_params, "start"),
            _number(request.query_params, "end"),
        )

    @app.get(PREFIX + "/signature-bundles")
    async def bundles(request: Request):
        return await run_in_threadpool(file_verdicts.list_bundles, store, who(request))

    @app.post(PREFIX + "/signature-bundles", status_code=201)
    async def create_bundle(request: Request):
        return await run_in_threadpool(
            file_verdicts.save_bundle,
            store,
            who(request, ("admin",)),
            await body(request),
        )

    @app.put(PREFIX + "/signature-bundles/{identifier}")
    async def update_bundle(identifier: str, request: Request):
        return await run_in_threadpool(
            file_verdicts.save_bundle,
            store,
            who(request, ("admin",)),
            await body(request),
            identifier,
        )

    @app.post(PREFIX + "/signature-bundles/{identifier}/review")
    async def review_bundle(identifier: str, request: Request):
        actor = who(request, ("admin",))
        data = _exact(await body(request), ("version", "approve", "reason"))
        return await run_in_threadpool(
            file_verdicts.review_bundle,
            store,
            actor,
            identifier,
            data["version"],
            data["approve"],
            data["reason"],
        )

    @app.post(PREFIX + "/signature-bundles/{identifier}/revoke")
    async def revoke_bundle(identifier: str, request: Request):
        actor = who(request, ("admin",))
        data = _exact(await body(request), ("version", "reason"))
        return await run_in_threadpool(
            file_verdicts.revoke_bundle,
            store,
            actor,
            identifier,
            data["version"],
            data["reason"],
        )

    @app.post(PREFIX + "/artifacts/{artifact_id}/analyze")
    async def analyze_artifact(artifact_id: str, request: Request):
        actor = who(request, EDIT)
        data = await body(request)
        if set(data) - {"bundle_ids"}:
            raise ValueError("Artifact analysis accepts optional bundle_ids only")
        return await run_in_threadpool(
            file_verdicts.analyze_artifact,
            store,
            actor,
            artifact_id,
            data.get("bundle_ids"),
        )

    @app.get(PREFIX + "/cases/{incident_id}/verdicts")
    async def case_verdicts(incident_id: str, request: Request):
        return await run_in_threadpool(
            file_verdicts.case_verdicts, store, who(request), incident_id
        )

    @app.post(PREFIX + "/artifacts/{artifact_id}/sandbox", status_code=201)
    async def request_sandbox(artifact_id: str, request: Request):
        actor = who(request, EDIT)
        data = await body(request)
        if set(data) - {"provider", "ttl"} or "provider" not in data:
            raise ValueError(
                "Sandbox job requires provider and optional ttl; no sample is sent"
            )
        return await run_in_threadpool(
            file_verdicts.request_sandbox,
            store,
            actor,
            artifact_id,
            data["provider"],
            ttl=data.get("ttl", 3600),
        )

    @app.post(PREFIX + "/sandbox/{identifier}/result")
    async def sandbox_result(identifier: str, request: Request):
        return await run_in_threadpool(
            file_verdicts.complete_sandbox,
            store,
            who(request, ("admin",)),
            identifier,
            await body(request),
        )

    @app.get(PREFIX + "/sandbox/{identifier}")
    async def sandbox_job(identifier: str, request: Request):
        return await run_in_threadpool(
            file_verdicts.sandbox_job, store, who(request), identifier
        )

    @app.get(PREFIX + "/sandbox-providers")
    async def sandbox_providers(request: Request):
        return await run_in_threadpool(
            sandbox_provider.list_providers, store, who(request)
        )

    @app.post(PREFIX + "/sandbox-providers", status_code=201)
    async def create_sandbox_provider(request: Request):
        return await run_in_threadpool(
            sandbox_provider.save_provider,
            store,
            who(request, ("admin",)),
            await body(request),
        )

    @app.post(PREFIX + "/sandbox-providers/{identifier}/review")
    async def review_sandbox_provider(identifier: str, request: Request):
        data = _exact(await body(request), ("version", "approve", "reason"))
        return await run_in_threadpool(
            sandbox_provider.review_provider,
            store,
            who(request, ("admin",)),
            identifier,
            data["version"],
            data["approve"],
            data["reason"],
        )

    @app.post(PREFIX + "/sandbox-providers/{identifier}/revoke")
    async def revoke_sandbox_provider(identifier: str, request: Request):
        data = _exact(await body(request), ("version", "reason"))
        return await run_in_threadpool(
            sandbox_provider.revoke_provider,
            store,
            who(request, ("admin",)),
            identifier,
            data["version"],
            data["reason"],
        )

    @app.post(PREFIX + "/artifacts/{artifact_id}/attested-sandbox", status_code=201)
    async def request_attested_sandbox(artifact_id: str, request: Request):
        data = await body(request)
        if (
            not isinstance(data, dict)
            or not {"profile_id"} <= set(data)
            or set(data) - {"profile_id", "ttl"}
        ):
            raise ValueError("Attested sandbox requires profile_id and optional ttl")
        return await run_in_threadpool(
            sandbox_provider.request_job,
            store,
            who(request, EDIT),
            artifact_id,
            data["profile_id"],
            ttl=data.get("ttl", 3600),
        )

    @app.post(PREFIX + "/sandbox/{identifier}/attested-result")
    async def attested_sandbox_result(identifier: str, request: Request):
        return await run_in_threadpool(
            sandbox_provider.complete_job,
            store,
            who(request, ("admin",)),
            identifier,
            await body(request),
        )

    async def provider_body(request):
        if request.url.scheme != "https":
            raise PermissionError("Provider sample exchange requires HTTPS")
        return await body(request)

    @app.post(PREFIX + "/provider-exchange/poll")
    async def provider_poll(request: Request):
        data = _exact(await provider_body(request), ("credential",))
        return await run_in_threadpool(
            sandbox_provider.poll_jobs, store, data["credential"]
        )

    @app.post(PREFIX + "/provider-exchange/{identifier}/sample")
    async def provider_sample(identifier: str, request: Request):
        data = _exact(await provider_body(request), ("credential",))
        sample, digest = await run_in_threadpool(
            sandbox_provider.sample_for_provider, store, data["credential"], identifier
        )
        return Response(
            sample,
            media_type="application/octet-stream",
            headers={"X-Sample-Sha256": digest, "Cache-Control": "no-store"},
        )

    @app.post(PREFIX + "/provider-exchange/{identifier}/result")
    async def provider_result(identifier: str, request: Request):
        data = _exact(await provider_body(request), ("credential", "result"))
        return await run_in_threadpool(
            sandbox_provider.result_from_provider,
            store,
            data["credential"],
            identifier,
            data["result"],
        )
