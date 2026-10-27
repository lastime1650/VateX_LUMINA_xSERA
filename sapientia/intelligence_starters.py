"""Source-scoped console starters; preview never installs or activates content.

Atomic starters describe reported observations. Composite starters bind exact
currently approved inputs and retain the existing policy review path. Original
disjointness is an evidence property, not statistical sensor independence.
"""

import copy
import json

from fastapi import Request
from starlette.concurrency import run_in_threadpool

from . import intelligence, principal, release_manifest
from .storage import ConflictError, encode

EDITORS = ("admin", "analyst")
WARNINGS = [
    "시작 템플릿은 현장 탐지 효과가 검증된 규칙이 아닙니다. 실제 수집 필드와 오탐을 확인하세요.",
    "미리보기는 정책·사건·장치 대응을 생성하지 않습니다. 저장 후 다른 분석가의 독립 검토가 필요합니다.",
    "원본이 겹치지 않는 근거 묶음은 통계적으로 독립적인 센서 또는 악성 확률을 뜻하지 않습니다.",
]


def _atomic(identifier, name, description, filters):
    return {
        "id": identifier,
        "name": name,
        "kind": "atomic",
        "description": description,
        "filters": filters,
        "requirements": {"reviewed_model": False, "parent_policy_count": 0},
        "qualification": "unqualified_source_observation",
    }


CATALOG = (
    _atomic(
        "authentication-failure",
        "인증 실패 관측",
        "정규화된 인증 실패 원본입니다. 단일 실패만으로 공격을 확정하지 않습니다.",
        [
            {"field": "raw.security.action", "op": "eq", "value": "authentication"},
            {"field": "raw.security.outcome", "op": "eq", "value": "failure"},
        ],
    ),
    _atomic(
        "authentication-success",
        "인증 성공 관측",
        "정규화된 인증 성공 원본입니다. 정상 업무도 일치할 수 있습니다.",
        [
            {"field": "raw.security.action", "op": "eq", "value": "authentication"},
            {"field": "raw.security.outcome", "op": "eq", "value": "success"},
        ],
    ),
    _atomic(
        "endpoint-process-created",
        "엔드포인트 프로세스 생성 관측",
        "aegis.endpoint.v1 프로세스 생성 필드가 있는 원본만 선택합니다.",
        [
            {"field": "event.sourcetype", "op": "eq", "value": "aegis:endpoint"},
            {"field": "raw.xdr.schema", "op": "eq", "value": "aegis.endpoint.v1"},
            {
                "field": "raw.xdr.data.event.action",
                "op": "eq",
                "value": "process_created",
            },
        ],
    ),
    _atomic(
        "endpoint-file-deleted",
        "엔드포인트 파일 삭제 관측",
        "파일 삭제 원본을 선택합니다. 백업·관리 작업의 정상 삭제를 별도로 검토하세요.",
        [
            {"field": "event.sourcetype", "op": "eq", "value": "aegis:endpoint"},
            {"field": "raw.xdr.schema", "op": "eq", "value": "aegis.endpoint.v1"},
            {"field": "raw.xdr.data.event.action", "op": "eq", "value": "file_deleted"},
        ],
    ),
    _atomic(
        "network-blocked",
        "네트워크 차단 보고 관측",
        "장치가 보고한 정규화된 차단 기록입니다. xSERA가 새 차단을 실행하는 동작이 아닙니다.",
        [
            {"field": "raw.security.action", "op": "eq", "value": "network_connection"},
            {"field": "raw.security.outcome", "op": "eq", "value": "blocked"},
        ],
    ),
    _atomic(
        "endpoint-network-connection",
        "엔드포인트 네트워크 연결 관측",
        "aegis.endpoint.v1 연결 원본을 선택합니다. 연결 자체는 악성 판정이 아닙니다.",
        [
            {"field": "event.sourcetype", "op": "eq", "value": "aegis:endpoint"},
            {"field": "raw.xdr.schema", "op": "eq", "value": "aegis.endpoint.v1"},
            {
                "field": "raw.xdr.data.event.action",
                "op": "eq",
                "value": "network_connection",
            },
        ],
    ),
    {
        "id": "ml-with-one-atomic",
        "name": "검토된 CPU 모델 신호와 단일 근거 결합",
        "kind": "composite",
        "description": "현재 활성·독립 승인된 CPU 모델과 한 개의 활성 단일 정책을 정확히 연결합니다.",
        "requirements": {"reviewed_model": True, "parent_policy_count": 1},
        "qualification": "unqualified_composite_hypothesis",
    },
    {
        "id": "ml-with-two-atomics",
        "name": "검토된 CPU 모델 신호와 두 근거 결합",
        "kind": "composite",
        "description": "현재 활성·독립 승인된 CPU 모델과 서로 다른 두 활성 단일 정책을 연결합니다. 원본이 겹치면 최소 근거 조건을 충족하지 않습니다.",
        "requirements": {"reviewed_model": True, "parent_policy_count": 2},
        "qualification": "unqualified_composite_hypothesis",
    },
)


def listing(store, who):
    with principal.transaction(store, who):
        return {
            "items": copy.deepcopy(CATALOG),
            "total": len(CATALOG),
            "atomic": 6,
            "composite": 2,
            "installed": False,
            "enabled": False,
            "activation": "independent_review",
            "warnings": list(WARNINGS),
        }


def preview(store, who, identifier, data):
    template = next((item for item in CATALOG if item["id"] == identifier), None)
    if template is None:
        raise KeyError("Intelligence starter template not found")
    common = {"indexes", "name", "enabled", "window"}
    allowed = common | (
        {"model_rule_id", "parent_policy_ids", "join_on", "create_case"}
        if template["kind"] == "composite"
        else set()
    )
    if not isinstance(data, dict) or set(data) - allowed:
        raise ValueError(
            "Starter requires explicit indexes and only its declared binding fields"
        )
    definition = {
        "name": data.get("name", template["name"]),
        "kind": template["kind"],
        "indexes": data.get("indexes", []),
        "version": 0,
        "enabled": data.get("enabled", False),
        "window": data.get("window", 300),
        "severity": "high" if template["kind"] == "composite" else "low",
        "confidence_grade": "evidence_backed_policy_hypothesis"
        if template["kind"] == "composite"
        else "source_reported",
    }
    if template["kind"] == "atomic":
        definition["filters"] = copy.deepcopy(template["filters"])
    else:
        parents, model = data.get("parent_policy_ids"), data.get("model_rule_id")
        count = template["requirements"]["parent_policy_count"]
        if (
            not isinstance(parents, list)
            or len(parents) != count
            or any(
                not isinstance(value, str) or not 1 <= len(value) <= 256
                for value in parents
            )
            or len(set(parents)) != count
        ):
            raise ValueError("Exact distinct parent policy IDs are required")
        if (
            not isinstance(model, str)
            or not model.startswith("ml:")
            or not 4 <= len(model) <= 256
        ):
            raise ValueError(
                "An exact currently reviewed CPU model rule ID is required"
            )
        if type(data.get("create_case", False)) is not bool:
            raise ValueError("create_case must be boolean")
        definition.update(
            inputs=[
                {"rule_id": model, "kind": "ml"},
                *[{"rule_id": parent, "kind": "atomic"} for parent in parents],
            ],
            join_on=data.get("join_on", "entity"),
            minimum_independent_groups=count + 1,
            ordered=False,
            clock_policy="reported",
        )
        if data.get("create_case", False):
            definition["case_adapter"] = {
                "name": definition["name"],
                "entity_field": "host",
                "risk_score": 75,
                "severity": "high",
                "mitre": [],
                "cooldown": 300,
                "case_grouping": "require_exact_identity",
            }
    definition = intelligence._definition(definition)
    bindings = {"parents": []}
    with principal.transaction(store, who, EDITORS) as (db, actor):
        if not principal.contains(actor["allowed_indexes"], definition["indexes"]):
            raise PermissionError("Starter indexes exceed current authority")
        if template["kind"] == "composite":
            model_pin = intelligence._input_model_pin(store, db, actor, model)
            if not principal.contains(definition["indexes"], model_pin["indexes"]):
                raise PermissionError("Declare the model's complete index scope")
            bindings["model"] = {"rule_id": model, **model_pin}
            for parent_id in parents:
                row = db.execute(
                    "SELECT * FROM intelligence_policies WHERE tenant=? AND id=?",
                    (actor["tenant"], parent_id),
                ).fetchone()
                if not row or not principal.contains(
                    actor["allowed_indexes"], json.loads(row["indexes"])
                ):
                    raise KeyError("Parent policy not found in complete current scope")
                if row["kind"] != "atomic":
                    raise ValueError("ML starters require exact atomic parent policies")
                if row["state"] != "active":
                    raise ConflictError(
                        "An independently approved active atomic parent is required"
                    )
                _, parent_definition = intelligence._authority(db, row)
                if not principal.contains(
                    definition["indexes"], parent_definition["indexes"]
                ):
                    raise PermissionError("Declare every parent's complete index scope")
                bindings["parents"].append(
                    {
                        "id": row["id"],
                        "version": row["version"],
                        "definition_digest": release_manifest.digest(parent_definition),
                        "indexes": parent_definition["indexes"],
                    }
                )
        # _definition accepts only public fields: server-private pins are added
        # afresh by save_policy, then checked again during independent review.
        result = {
            "template_id": identifier,
            "definition": definition,
            "bindings": bindings,
            "definition_digest": release_manifest.digest(definition),
            "persisted": False,
            "live_effects": False,
            "automatic_response_authorized": False,
            "warnings": list(WARNINGS),
        }
        if len(encode(result).encode()) > 32768:
            raise ValueError("Starter preview exceeds 32 KiB")
    principal.recheck(store, actor, EDITORS)
    return result


def register(app, store, runtime, who, body):
    @app.get("/api/v3/intelligence/templates")
    async def templates(request: Request):
        return await run_in_threadpool(listing, store, who(request))

    @app.post("/api/v3/intelligence/templates/{identifier}/preview")
    async def template_preview(identifier: str, request: Request):
        return await run_in_threadpool(
            preview, store, who(request, EDITORS), identifier, await body(request)
        )
