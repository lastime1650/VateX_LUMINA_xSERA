"""Authenticated intelligence, scoped operations, and explicit recovery APIs."""

import time
from copy import deepcopy

from fastapi import HTTPException, Request
from starlette.concurrency import run_in_threadpool

from . import access, audit_integrity, detections, lookups


def register(app, store, runtime, membership, who, body, appliance_admin, appliance_change):
    @app.get("/api/federation/status")
    def federation_status(request: Request):
        who(request)
        return {"enabled": app.state.federation is not None}

    @app.post("/api/federation/search")
    async def federation_search(request: Request):
        user = who(request)
        if app.state.federation is None:
            raise HTTPException(404, "Federation is not configured")
        payload = await body(request)

        def execute():
            from .runtime import owner_indexes

            result = app.state.federation.search(user, payload, user["allowed_indexes"])
            if (
                owner_indexes(store, user["name"], user["tenant"])
                != user["allowed_indexes"]
            ):
                raise PermissionError("Federation permissions changed during execution")
            with store.control() as db:
                store.audit(
                    db,
                    user["tenant"],
                    user["name"],
                    "federation.search",
                    {
                        "nodes": [node["name"] for node in result["nodes"]],
                        "returned": result["returned"],
                        "access_scope": user["allowed_indexes"],
                    },
                )
            return result

        return await run_in_threadpool(execute)

    @app.post("/api/federation/peer/search")
    async def federation_peer(request: Request):
        if app.state.federation is None:
            raise HTTPException(404, "Federation is not configured")
        raw = await request.body()
        if len(raw) > 256 * 1024:
            raise HTTPException(413, "Federation request exceeds 256 KiB")
        return await run_in_threadpool(
            app.state.federation.handle_peer, raw, dict(request.headers)
        )

    @app.get("/api/lookups")
    def lookup_list(request: Request):
        return lookups.list_for(store, who(request, ("admin", "analyst")))

    @app.get("/api/lookups/{name}")
    def lookup_get(name: str, request: Request):
        user = who(request, ("admin", "analyst"))
        return lookups.get(store, user["tenant"], name)

    @app.put("/api/lookups/{name}")
    async def lookup_save(name: str, request: Request):
        user = who(request, ("admin",))
        return lookups.save(store, user, name, await body(request))

    @app.get("/api/users/{name}/indexes")
    def user_indexes(name: str, request: Request):
        actor = who(request, ("admin",))
        with store.control() as db:
            if not db.execute(
                "SELECT 1 FROM users WHERE name=? AND tenant=?", (name, actor["tenant"])
            ).fetchone():
                raise KeyError(name)
        return {
            "name": name,
            "allowed_indexes": access.get_for_user(store, name, actor["tenant"]),
        }

    @app.put("/api/users/{name}/indexes")
    async def user_indexes_set(name: str, request: Request):
        actor = who(request, ("admin",))
        data = await body(request)
        if set(data) != {"allowed_indexes"}:
            raise ValueError("Expected allowed_indexes")
        return access.set_for_user(store, actor, name, data["allowed_indexes"])

    @app.post("/api/cluster/members/{node_id}/recover")
    def recover_member(node_id: str, request: Request):
        return appliance_change(appliance_admin(request), membership.recover_member, node_id)

    @app.get("/api/audit/integrity")
    def integrity(request: Request):
        appliance_admin(request)
        return audit_integrity.verify(store)

    @app.post("/api/audit/checkpoint")
    def checkpoint(request: Request):
        appliance_admin(request)
        return audit_integrity.create_checkpoint(store)

    @app.post("/api/audit/verify")
    async def verify_checkpoint(request: Request):
        appliance_admin(request)
        data = await body(request)
        return await run_in_threadpool(audit_integrity.verify, store, data)

    @app.get("/api/operations")
    def operations(request: Request):
        user = who(request, ("admin", "analyst"))
        from .runtime import rule_health, scheduler_health

        metrics = runtime.health()
        node_operator = (
            user["tenant"] == "default"
            and user["role"] == "admin"
            and user["allowed_indexes"] == ["*"]
        )
        if not node_operator:
            metrics = {
                key: metrics[key]
                for key in (
                    "last_tick",
                    "error",
                    "scheduler_tick",
                    "scheduler_error",
                    "detection_error",
                )
            }
        return {
            "indexer": metrics,
            "scheduler": scheduler_health(store, user["tenant"]),
            "rules": rule_health(store, user["tenant"]),
            "queue": store.health(
                user["tenant"], allowed_indexes=user["allowed_indexes"]
            ),
            "correlation_policies": [
                {
                    "id": p["id"],
                    "name": p["name"],
                    "error": p["error"],
                    "failures": p["failures"],
                    "retry_at": p["retry_at"],
                    "last_end": p["last_end"],
                }
                for p in detections.list_policies(store, user)
            ],
            "node_metrics_visible": node_operator,
            "syslog": (
                runtime.syslog.health()
                if getattr(runtime, "syslog", None)
                else {"enabled": False}
            )
            if node_operator
            else {"restricted": True},
        }

    @app.get("/api/detections/templates")
    def templates(request: Request):
        who(request, ("admin", "analyst"))
        definitions = [
            {
                "id": "failed-login-then-success",
                "definition": {
                    "name": "반복 인증 실패 후 로그인 성공",
                    "entity_field": "raw.user",
                    "window": 900,
                    "interval": 30,
                    "cooldown": 900,
                    "risk_score": 55,
                    "severity": "high",
                    "mitre": ["T1110", "T1078"],
                    "steps": [
                        {
                            "name": "동일 사용자 인증 실패 3회",
                            "filters": [
                                {
                                    "field": "raw.action",
                                    "op": "eq",
                                    "value": "login_failed",
                                }
                            ],
                            "min_count": 3,
                        },
                        {
                            "name": "이후 인증 성공",
                            "filters": [
                                {
                                    "field": "raw.action",
                                    "op": "eq",
                                    "value": "login_success",
                                }
                            ],
                            "min_count": 1,
                        },
                    ],
                },
            },
            {
                "id": "endpoint-network-chain",
                "definition": {
                    "name": "의심 프로세스 실행 후 외부 연결",
                    "entity_field": "host",
                    "window": 300,
                    "interval": 30,
                    "cooldown": 300,
                    "risk_score": 65,
                    "severity": "high",
                    "mitre": ["T1059", "T1071"],
                    "steps": [
                        {
                            "name": "의심 프로세스",
                            "filters": [
                                {
                                    "field": "raw.action",
                                    "op": "eq",
                                    "value": "suspicious_process",
                                }
                            ],
                        },
                        {
                            "name": "외부 연결",
                            "filters": [
                                {
                                    "field": "raw.action",
                                    "op": "eq",
                                    "value": "external_connection",
                                }
                            ],
                        },
                    ],
                },
            },
        ]
        canonical = deepcopy(definitions[0]["definition"])
        canonical["name"] = "서로 다른 소스의 인증 실패 후 성공"
        canonical["entity_field"] = "raw.security.user"
        for step, outcome in zip(canonical["steps"], ("failure", "success")):
            step["filters"] = [
                {"field": "raw.security.action", "op": "eq", "value": "authentication"},
                {"field": "raw.security.outcome", "op": "eq", "value": outcome},
            ]
        definitions.insert(
            0, {"id": "canonical-authentication-chain", "definition": canonical}
        )
        return definitions

    @app.get("/api/detections")
    def policies(request: Request):
        return detections.list_policies(store, who(request, ("admin", "analyst")))

    @app.post("/api/detections", status_code=201)
    async def create_policy(request: Request):
        actor = who(request, ("admin", "analyst"))
        return {"id": detections.save(store, actor, await body(request))}

    @app.patch("/api/detections/{policy_id}")
    async def toggle_policy(policy_id: str, request: Request):
        actor = who(request, ("admin", "analyst"))
        data = await body(request)
        if set(data) != {"enabled", "version"}:
            raise ValueError("Expected enabled and version")
        detections.toggle(store, actor, policy_id, data["enabled"], data["version"])
        return {"updated": True}

    @app.post("/api/detections/preview")
    async def preview(request: Request):
        actor = who(request, ("admin", "analyst"))
        data = await body(request)
        if set(data) - {"definition", "end"} or "definition" not in data:
            raise ValueError("Expected definition and optional end")
        definition = detections.validate(data["definition"])
        end = data.get("end", time.time())
        if isinstance(end, bool) or not isinstance(end, (int, float)):
            raise ValueError("end must be epoch seconds")  # noqa: TRY004 - invalid request data.
        matches = await run_in_threadpool(
            detections.evaluate,
            store,
            actor["tenant"],
            definition,
            end,
            actor["allowed_indexes"],
        )
        return {
            "matches": matches,
            "match_count": len(matches),
            "persisted": False,
            "window_end": end,
        }

    @app.get("/api/risk/entities")
    def risk(request: Request):
        return detections.entity_risk(store, who(request, ("admin", "analyst")))

    @app.get("/api/incidents")
    def incidents(request: Request):
        return detections.incident_list(store, who(request, ("admin", "analyst")))

    @app.get("/api/incidents/{incident_id}")
    def incident(incident_id: str, request: Request):
        try:
            count = int(request.query_params.get("count", "3"))
        except ValueError:
            raise ValueError("Invalid page count")
        return detections.incident_detail(
            store,
            who(request, ("admin", "analyst")),
            incident_id,
            cursor=request.query_params.get("cursor"),
            count=count,
        )

    @app.get("/api/risk/evidence")
    def risk_evidence(request: Request):
        user = who(request, ("admin", "analyst"))
        try:
            count = int(request.query_params.get("count", "20"))
        except ValueError:
            raise ValueError("Invalid page count")
        return detections.entity_evidence(
            store,
            user,
            request.query_params.get("entity_field", "host"),
            request.query_params.get("entity", ""),
            cursor=request.query_params.get("cursor"),
            count=count,
        )

    @app.patch("/api/incidents/{incident_id}")
    async def incident_update(incident_id: str, request: Request):
        actor = who(request, ("admin", "analyst"))
        detections.update_incident(store, actor, incident_id, await body(request))
        return {"updated": True}
