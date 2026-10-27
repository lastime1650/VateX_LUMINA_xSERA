"""Log lifecycle, full-text, complete exports and live snapshot administration."""

import shutil
import tempfile
import uuid
from pathlib import Path

from fastapi import Request
from fastapi.responses import Response, StreamingResponse
from starlette.concurrency import run_in_threadpool

from . import log_search, principal
from .backup import _private_directory, backup_online


def register(app, store, runtime, who, body):
    log_search.initialize(store)

    @app.get("/api/logs/status")
    async def status(request: Request):
        actor = who(request)
        def collect():
            with principal.transaction(store, actor) as (_, fresh):
                scope = fresh["allowed_indexes"]
            result = store.segments.status(fresh["tenant"], scope)
            policies = [p for p in store.segments.policies(fresh["tenant"]) if scope == ["*"] or p["index_name"] in scope]
            output = {"storage": result, "policies": policies, "search": log_search.status(store, fresh),
                    "replication": store.replica.status() if store.replica else {"configured": False},
                    "federation": app.state.federation.status() if app.state.federation else {"configured": False}}
            principal.recheck(store, fresh)
            return output
        return await run_in_threadpool(collect)

    @app.put("/api/logs/indexes/{index_name}/lifecycle")
    async def lifecycle(index_name: str, request: Request):
        actor, data = who(request, ("admin",)), await body(request)
        def save():
            with store.write_lock:
                with principal.transaction(store, actor, ("admin",)) as (_, fresh):
                    if not principal.contains(fresh["allowed_indexes"], [index_name]):
                        raise PermissionError("Index outside administrative scope")
                return store.segments.save_policy(fresh["tenant"], index_name, data, fresh["name"])
        return await run_in_threadpool(save)

    @app.post("/api/logs/maintenance")
    async def maintain(request: Request):
        actor, data = who(request, ("admin",)), await body(request)
        if set(data) != {"index_name"}:
            raise ValueError("An exact index_name is required")
        with principal.transaction(store, actor, ("admin",)) as (_, fresh):
            if not principal.contains(fresh["allowed_indexes"], [data["index_name"]]):
                raise PermissionError("Index outside administrative scope")
        result = await run_in_threadpool(store.segments.maintenance, tenant=fresh["tenant"], index=data["index_name"])
        with principal.transaction(store, fresh, ("admin",), write=True) as (db, current):
            store.audit(db, current["tenant"], current["name"], "logs.maintenance", {"index_name": data["index_name"], **result})
        await run_in_threadpool(log_search.maintenance, store)
        return result

    @app.post("/api/logs/snapshots", status_code=201)
    async def snapshot(request: Request):
        actor, data = who(request), await body(request)
        return await run_in_threadpool(log_search.create, store, actor, data)

    @app.get("/api/logs/snapshots/{snapshot_id}")
    async def page(snapshot_id: str, request: Request):
        actor = who(request)
        try:
            after = int(request.query_params.get("after", "0"))
            limit = int(request.query_params.get("limit", "500"))
        except ValueError:
            raise ValueError("after and limit must be integers") from None
        return await run_in_threadpool(log_search.page, store, actor, snapshot_id, after, limit)

    @app.get("/api/logs/snapshots/{snapshot_id}/export")
    async def export(snapshot_id: str, request: Request):
        actor = who(request)
        try:
            after = int(request.query_params.get("after", "0"))
            limit = int(request.query_params.get("limit", "1000"))
        except ValueError:
            raise ValueError("after and limit must be integers") from None
        result, text = await run_in_threadpool(log_search.ndjson, store, actor, snapshot_id, after, limit)
        return Response(text, media_type="application/x-ndjson", headers={
            "Content-Disposition": 'attachment; filename="xsera-' + snapshot_id + '-' + str(after) + '.ndjson"',
            "X-Next-After": str(result["next_after"]) if result["next_after"] is not None else "",
            "X-Total-Rows": str(result["total"]), "X-Snapshot-SHA256": result["sha256_ndjson"]})

    @app.delete("/api/logs/snapshots/{snapshot_id}")
    async def close(snapshot_id: str, request: Request):
        return await run_in_threadpool(log_search.close, store, who(request), snapshot_id)

    @app.get("/api/logs/snapshots/{snapshot_id}/download")
    async def download(snapshot_id: str, request: Request):
        actor = who(request)
        metadata = await run_in_threadpool(log_search.download_info, store, actor, snapshot_id)
        def stream():
            position, sent = 0, 0
            while True:
                page, value = log_search.ndjson(store, actor, snapshot_id, position, 1000)
                chunk = value.encode("utf-8")
                sent += len(chunk)
                if sent > metadata["bytes"]:
                    raise RuntimeError("Snapshot export changed unexpectedly")
                if chunk:
                    yield chunk
                if page["next_after"] is None:
                    if sent != metadata["bytes"]:
                        raise RuntimeError("Snapshot export was incomplete")
                    break
                position = page["next_after"]
        return StreamingResponse(stream(), media_type="application/x-ndjson", headers={
            "Content-Disposition": 'attachment; filename="xsera-' + snapshot_id + '.ndjson"',
            "Content-Length": str(metadata["bytes"]), "X-Total-Rows": str(metadata["rows"]),
            "X-Snapshot-SHA256": metadata["sha256"], "Cache-Control": "no-store"})

    @app.post("/api/logs/backups", status_code=201)
    async def backup(request: Request):
        actor, data = who(request, ("admin",)), await body(request)
        if set(data) != {"passphrase"} or not isinstance(data["passphrase"], str) or not 12 <= len(data["passphrase"]) <= 1024:
            raise ValueError("Provide a 12..1024 character backup passphrase; destination is server-managed")
        with principal.transaction(store, actor, ("admin",)) as (_, fresh):
            if fresh["tenant"] != "default" or fresh["allowed_indexes"] != ["*"]:
                raise PermissionError("Whole-appliance backup requires the default-tenant unrestricted administrator")
        ident = uuid.uuid4().hex
        root = store.path / "private" / "online-backups"
        destination = root / ident
        def protect():
            from .backup_stream import encrypt_snapshot
            try:
                root.mkdir(parents=True)
            except FileExistsError:
                _private_directory(root)
            else:
                _private_directory(root, created=True)
            with tempfile.TemporaryDirectory(prefix=".encrypt-", dir=root) as work:
                temporary = Path(work)
                _private_directory(temporary, created=True)
                manifest = backup_online(store, temporary / "snapshot")
                result = encrypt_snapshot(temporary / "snapshot", destination, data["passphrase"])
            try:
                with principal.transaction(store, fresh, ("admin",), write=True) as (db, current):
                    if current["tenant"] != "default" or current["allowed_indexes"] != ["*"]:
                        raise PermissionError("Whole-appliance backup authority was revoked during creation")
                    store.audit(db, current["tenant"], current["name"], "logs.backup.online", {"id": ident, "format": 2, "files": result["files"]})
            except Exception:
                shutil.rmtree(destination)
                raise
            return {"id": ident, "manifest": manifest, "online": True, **result,
                    "note": "Encrypted server-side bundle. Restore requires the passphrase. External broker/TLS configuration is backed up separately."}
        return await run_in_threadpool(protect)

    @app.get("/api/logs/cases/{case_id}/hold")
    async def case_hold(case_id: str, request: Request):
        from . import log_governance
        return await run_in_threadpool(log_governance.get_case_hold, store, who(request), case_id)

    @app.put("/api/logs/cases/{case_id}/hold")
    async def hold_case(case_id: str, request: Request):
        from . import log_governance
        return await run_in_threadpool(log_governance.hold_case, store, who(request, ("admin",)), case_id, await body(request))

    @app.delete("/api/logs/cases/{case_id}/hold")
    async def release_case(case_id: str, request: Request):
        from . import log_governance
        return await run_in_threadpool(log_governance.release_case_hold, store, who(request, ("admin",)), case_id, await body(request))
