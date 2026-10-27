import hashlib
import hmac
import json
import logging
import re
import sqlite3
import threading
import time
from collections import OrderedDict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

import duckdb
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from . import __version__, auth
from .brand import CATEGORY, CATEGORY_NAME, PRODUCT_NAME
from .membership import Membership
from .runtime import Runtime, save_rule
from .storage import CapacityError, ConflictError, Settings, Store

LOG = logging.getLogger("sapientia")

AGENT_ACTIONS = {
    "register",
    "heartbeat",
    "defense-policy",
    "renew",
    "ingest",
    "poll",
    "ack",
    "result",
}
LEGACY_AGENT_ACTIONS = (AGENT_ACTIONS - {"ingest"}) | {"events"}


def agent_plane_allowed(scope):
    if scope.get("type") != "http" or scope.get("method") != "POST":
        return False
    path = scope.get("path", "")
    if path in {"/api/agent/" + action for action in AGENT_ACTIONS} | {
        "/api/endpoint-agent/" + action for action in LEGACY_AGENT_ACTIONS
    }:
        return True
    if re.fullmatch(r"/api/agent/commands/RSP-[0-9a-f]{32}/artifact", path):
        return True
    return (
        path == "/api/xdr/advanced/provider-exchange/poll"
        or re.fullmatch(
            r"/api/xdr/advanced/provider-exchange/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/(?:sample|result)",
            path,
        )
        is not None
    )


class AgentPlane:
    """Route guard around the same app/Store; never starts a second lifecycle."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            return await self.app(scope, receive, send)
        if not agent_plane_allowed(scope):
            if scope["type"] == "websocket":
                return await send({"type": "websocket.close", "code": 1008})
            return await JSONResponse(
                {"detail": "Route unavailable on agent plane"}, 404
            )(scope, receive, send)
        return await self.app(scope, receive, send)


class BodyLimit:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        # Buffer a bounded body before dispatch, including chunked requests.
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > 2 * 1024 * 1024:
                response = JSONResponse({"detail": "Request exceeds 2 MiB"}, 413)
                return await response(scope, receive, send)
            if not message.get("more_body", False):
                break
        delivered = False

        async def bounded_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        return await self.app(scope, bounded_receive, send)


def create_app(settings=None, background=True, *, agent_only=False):
    if type(agent_only) is not bool:
        raise ValueError("agent_only must be boolean")
    settings = settings or Settings(Path("data"))
    store = Store(settings)
    runtime = Runtime(store)
    membership = Membership(store)
    # Cookies are host/path scoped, not port scoped. Isolate independent local
    # appliances; a real replicated deployment intentionally shares its realm.
    realm = (
        store.replica.config["cluster_id"]
        if store.replica
        else membership.node["node_id"]
    )
    cookie_name = "sapientia_session_" + hashlib.sha256(realm.encode()).hexdigest()[:16]
    failures = OrderedDict()
    login_lock = threading.Lock()
    memory_warning_at = float("-inf")

    @asynccontextmanager
    async def lifespan(app):
        if background:
            runtime.start()
        yield
        runtime.close()
        store.close()

    app = FastAPI(
        title=PRODUCT_NAME,
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.store, app.state.runtime = store, runtime
    app.state.agent_only = agent_only
    app.state.membership = membership
    app.state.cookie_name = cookie_name
    from .oidc import OIDCProvider, load_config

    oidc_config = load_config(settings.oidc)
    app.state.oidc = OIDCProvider(store, oidc_config) if oidc_config else None
    from .federation import Federation, FederationError
    from .federation import load_config as load_federation

    app.state.federation = (
        Federation(store, load_federation(settings.federation))
        if settings.federation
        else None
    )

    @app.exception_handler(FederationError)
    async def federation_error(request, exc):
        return JSONResponse({"detail": str(exc)}, exc.status_code)

    oidc_binding_cookie = cookie_name + "_oidc"
    oidc_challenge_cookie = cookie_name + "_oidc_mfa"
    sso_network_slots = threading.BoundedSemaphore(4)
    sso_attempts = OrderedDict()
    sso_rate_lock = threading.Lock()

    def sso_admit(request, operation):
        ip = request.client.host
        now = time.monotonic()
        with sso_rate_lock:
            counters = sso_attempts.setdefault(ip, {})
            sso_attempts.move_to_end(ip)
            while len(sso_attempts) > 1024:
                sso_attempts.popitem(last=False)
            recent = counters.setdefault(operation, deque())
            while recent and recent[0] <= now - 60:
                recent.popleft()
            limit = 12 if operation == "mfa" else 20
            if len(recent) >= limit:
                raise HTTPException(
                    429,
                    "Too many SSO attempts; wait one minute",
                    headers={"Retry-After": "60"},
                )
            recent.append(now)

    async def sso_work(request, operation, callback, *args):
        sso_admit(request, operation)
        if not sso_network_slots.acquire(blocking=False):
            raise HTTPException(
                503,
                "SSO authentication is busy; retry later",
                headers={"Retry-After": "5"},
            )
        try:
            return await run_in_threadpool(callback, *args)
        finally:
            sso_network_slots.release()

    def sso_provider():
        if app.state.oidc is None:
            raise HTTPException(404, "SSO is not configured")
        return app.state.oidc

    def sso_session(request, session, redirect=False):
        response = (
            RedirectResponse("/", status_code=303)
            if redirect
            else JSONResponse({k: v for k, v in session.items() if k != "token"})
        )
        response.set_cookie(
            cookie_name,
            session["token"],
            max_age=28800,
            httponly=True,
            secure=request.url.scheme == "https",
            samesite="strict",
        )
        response.delete_cookie(oidc_binding_cookie, path="/api/sso")
        response.delete_cookie(oidc_challenge_cookie, path="/api/sso")
        return response

    @app.get("/api/sso/status")
    def sso_status():
        return {"enabled": app.state.oidc is not None}

    @app.get("/api/sso/start")
    async def sso_start(request: Request):
        result = await sso_work(request, "start", sso_provider().start)
        response = RedirectResponse(result["authorization_url"], status_code=303)
        response.set_cookie(
            oidc_binding_cookie,
            result["browser_token"],
            max_age=result["expires_in"],
            path="/api/sso",
            httponly=True,
            secure=request.url.scheme == "https",
            samesite="lax",
        )
        return response

    @app.get("/api/sso/callback")
    async def sso_callback(request: Request):
        if request.query_params.get("error"):
            raise HTTPException(400, "The identity provider did not complete sign-in")
        result = await sso_work(
            request,
            "callback",
            sso_provider().callback,
            request.query_params.get("state"),
            request.query_params.get("code"),
            request.cookies.get(oidc_binding_cookie),
        )
        if result.get("mfa_required"):
            response = RedirectResponse("/?sso_mfa=1", status_code=303)
            response.set_cookie(
                oidc_challenge_cookie,
                result["challenge"],
                max_age=result["expires_in"],
                path="/api/sso",
                httponly=True,
                secure=request.url.scheme == "https",
                samesite="strict",
            )
            return response
        return sso_session(request, result, redirect=True)

    @app.post("/api/sso/mfa")
    async def sso_mfa(request: Request):
        data = await body(request)
        if set(data) != {"otp"} or not isinstance(data["otp"], str):
            raise ValueError("Expected authenticator otp")
        result = await sso_work(
            request,
            "mfa",
            sso_provider().complete_mfa,
            request.cookies.get(oidc_challenge_cookie),
            request.cookies.get(oidc_binding_cookie),
            data["otp"],
        )
        return sso_session(request, result)

    app.add_middleware(BodyLimit)

    @app.middleware("http")
    async def security(request, call_next):
        if agent_only and not agent_plane_allowed(request.scope):
            return JSONResponse({"detail": "Route unavailable on agent plane"}, 404)
        # Same-origin API mutations. No CORS or trusting proxy-forwarded headers.
        origin = request.headers.get("origin")
        if (
            request.method not in {"GET", "HEAD"}
            and origin
            and origin != str(request.base_url).rstrip("/")
        ):
            return JSONResponse({"detail": "Cross-origin request rejected"}, 403)
        if store.replica and request.url.path.startswith("/api/"):
            try:
                await run_in_threadpool(store.replica.barrier)
            except CapacityError as exc:
                return JSONResponse(
                    {"detail": str(exc)}, 503, headers={"Retry-After": "5"}
                )
        response = await call_next(request)
        response.headers.update(
            {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Cache-Control": "no-store",
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            }
        )
        return response

    @app.exception_handler(ValueError)
    async def invalid(request, exc):
        return JSONResponse(
            {"detail": str(exc)}, 409 if isinstance(exc, ConflictError) else 400
        )

    @app.exception_handler(CapacityError)
    async def capacity(request, exc):
        return JSONResponse({"detail": str(exc)}, 503, headers={"Retry-After": "5"})

    @app.exception_handler(PermissionError)
    async def forbidden(request, exc):
        return JSONResponse({"detail": str(exc)}, 403)

    @app.exception_handler(KeyError)
    async def missing(request, exc):
        return JSONResponse({"detail": "Resource not found"}, 404)

    @app.exception_handler(duckdb.OutOfMemoryException)
    async def query_memory(request, exc):
        nonlocal memory_warning_at
        now = time.monotonic()
        if now - memory_warning_at >= 30:
            LOG.warning("Query rejected: query_memory_budget")
            memory_warning_at = now
        return JSONResponse(
            {
                "detail": "Query memory budget exceeded; narrow the time range or fields",
                "code": "query_memory_budget",
            },
            503,
            headers={"Retry-After": "5"},
        )

    @app.exception_handler(duckdb.Error)
    async def query_error(request, exc):
        return JSONResponse(
            {
                "detail": "Query failed or resource deadline exceeded; check supported field types and narrow the time range"
            },
            422,
        )

    @app.exception_handler(sqlite3.IntegrityError)
    async def conflict(request, exc):
        return JSONResponse(
            {"detail": "Resource already exists or conflicts with current state"}, 409
        )

    async def body(request):
        if request.headers.get("content-type", "").split(";")[0] != "application/json":
            raise HTTPException(415, "Use application/json")
        try:
            value = await request.json()
        except (ValueError, RecursionError):
            raise HTTPException(400, "Invalid JSON")
        if not isinstance(value, dict):
            raise HTTPException(400, "Expected JSON object")
        return value

    def who(request, roles=("admin", "analyst", "viewer")):
        authorization = request.headers.get("authorization", "")
        if request.url.path.startswith(
            "/services/collector"
        ) and authorization.startswith("Splunk "):
            authorization = "Bearer " + authorization[7:]
        bearer = authorization[7:] if authorization.startswith("Bearer ") else None
        user = auth.identity(store, request.cookies.get(cookie_name), bearer)
        if not user:
            raise HTTPException(401, "Authentication required")
        if user["role"] not in roles:
            raise HTTPException(403, "Insufficient role")
        if user.get("must_change") and request.url.path not in {
            "/api/me",
            "/api/logout",
            "/api/me/password",
        }:
            raise HTTPException(
                403, "Password change required before using this account"
            )
        if (
            request.method not in {"GET", "HEAD"}
            and user["kind"] == "session"
            and not hmac.compare_digest(
                request.headers.get("x-csrf-token", "").encode("utf-8"),
                user["csrf"].encode("utf-8"),
            )
        ):
            raise HTTPException(403, "CSRF verification failed")
        return user

    @app.get("/api/bootstrap")
    def bootstrap():
        with store.control() as db:
            configured = bool(db.execute("SELECT 1 FROM users LIMIT 1").fetchone())
        return {
            "configured": configured,
            "product": PRODUCT_NAME,
            "product_category": CATEGORY,
            "product_category_name": CATEGORY_NAME,
            "version": __version__,
            "setup_mode": "appliance-https" if settings.appliance_setup else "loopback",
        }

    @app.post("/api/setup")
    async def setup(request: Request):
        local = request.client.host in {"127.0.0.1", "::1", "testclient"} and urlsplit(
            str(request.url)
        ).hostname in {"localhost", "127.0.0.1", "::1", "testserver"}
        if not local and not (
            settings.appliance_setup and request.url.scheme == "https"
        ):
            raise HTTPException(
                403,
                "Initial setup requires loopback or explicitly enabled appliance HTTPS access",
            )
        data = await body(request)
        await run_in_threadpool(
            auth.create_user, store, data.get("name"), data.get("password"), first=True
        )
        return {"configured": True}

    @app.post("/api/login")
    async def login(request: Request):
        data = await body(request)
        name, password = data.get("name"), data.get("password")
        if (
            not isinstance(name, str)
            or not isinstance(password, str)
            or len(name) > 64
            or len(password) > 128
        ):
            raise HTTPException(400, "Invalid credentials format")
        ip = request.client.host
        with login_lock:
            now = time.monotonic()
            attempts = failures.setdefault(ip, deque())
            failures.move_to_end(ip)
            while len(failures) > 10000:
                failures.popitem(last=False)
            while attempts and attempts[0] < now - 300:
                attempts.popleft()
            if len(attempts) >= 10:
                raise HTTPException(429, "Too many login attempts; wait five minutes")
            attempts.append(now)
        otp = data.get("otp")
        if otp is not None and (not isinstance(otp, str) or len(otp) > 8):
            raise HTTPException(400, "Invalid authenticator code format")
        user = await run_in_threadpool(auth.login, store, name, password, otp)
        if not user:
            with store.write_lock, store.control() as db:
                known = db.execute(
                    "SELECT tenant FROM users WHERE name=?", (name,)
                ).fetchone()
                store.audit(
                    db,
                    known[0] if known else "authentication",
                    name,
                    "login.failed",
                    {"ip": ip},
                )
            raise HTTPException(401, "Invalid credentials")
        response = JSONResponse({k: v for k, v in user.items() if k != "token"})
        response.set_cookie(
            cookie_name,
            user["token"],
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
            max_age=28800,
        )
        return response

    @app.get("/api/me")
    def me(request: Request):
        return who(request)

    @app.post("/api/me/password")
    async def password_change(request: Request):
        user = who(request)
        data = await body(request)
        result = await run_in_threadpool(
            auth.change_password,
            store,
            user,
            data.get("current"),
            data.get("password"),
            data.get("otp"),
        )
        response = JSONResponse(result)
        response.delete_cookie(cookie_name)
        return response

    @app.get("/api/me/mfa")
    def mfa_status(request: Request):
        user = who(request)
        return {"enabled": bool(user.get("mfa_enabled"))}

    @app.post("/api/me/mfa/enroll")
    async def mfa_enroll(request: Request):
        from . import mfa

        user = who(request)
        data = await body(request)
        return await run_in_threadpool(mfa.enroll, store, user, data.get("password"))

    @app.post("/api/me/mfa/confirm")
    async def mfa_confirm(request: Request):
        from . import mfa

        user = who(request)
        data = await body(request)
        result = await run_in_threadpool(mfa.confirm, store, user, data.get("otp"))
        response = JSONResponse(result)
        response.delete_cookie(cookie_name)
        return response

    @app.post("/api/me/mfa/disable")
    async def mfa_disable(request: Request):
        from . import mfa

        user = who(request)
        data = await body(request)
        result = await run_in_threadpool(
            mfa.disable, store, user, data.get("password"), data.get("otp")
        )
        response = JSONResponse(result)
        response.delete_cookie(cookie_name)
        return response

    @app.post("/api/logout")
    def logout(request: Request):
        user = who(request)
        with store.write_lock, store.control() as db:
            db.execute(
                "DELETE FROM sessions WHERE digest=?",
                (auth.digest(request.cookies.get(cookie_name, "")),),
            )
            store.audit(db, user["tenant"], user["name"], "logout", {})
        response = JSONResponse({"ok": True})
        response.delete_cookie(cookie_name)
        return response

    @app.get("/api/health")
    def health(request: Request):
        user = who(request)
        return {
            **store.health(user["tenant"], allowed_indexes=user["allowed_indexes"]),
            "worker_error": runtime.last_error,
            "worker_last_tick": runtime.last_tick,
            "version": __version__,
            "deployment": "cluster" if store.replica else "single-node",
            "cluster": store.replica.status() if store.replica else None,
        }

    @app.post("/api/v1/events", status_code=202)
    async def ingest(request: Request):
        user = who(request, ("admin", "ingest"))
        data = await body(request)
        if set(data) != {"events"}:
            raise ValueError("Expected events only; tenant is derived from credentials")
        return await run_in_threadpool(
            auth.ingest_authorized, store, user, data["events"]
        )

    def appliance_admin(request):
        from . import access

        with store.control() as db:
            user = access.require_full_admin(db, who(request, ("admin",)))
        if user["tenant"] != "default":
            raise HTTPException(
                403, "Appliance membership requires the default-tenant administrator"
            )
        return user

    def appliance_change(user, operation, *args, include_actor=True):
        from . import access

        # Membership itself takes this lock before the store lock. Preserve that
        # order and keep grants unchanged through bounded network/file effects.
        with membership.lock, store.write_lock:
            with store.control() as db:
                current = access.require_full_admin(db, user)
                if current["tenant"] != "default":
                    raise PermissionError(
                        "Appliance management requires the default-tenant administrator"
                    )
            return operation(current, *args) if include_actor else operation(*args)

    @app.get("/api/cluster")
    def cluster_status(request: Request):
        appliance_admin(request)
        return membership.status()

    @app.get("/api/cluster/discovery")
    def cluster_discovery():
        return membership.discovery()

    @app.post("/api/cluster/master")
    async def cluster_master(request: Request):
        user = appliance_admin(request)
        return await run_in_threadpool(
            appliance_change, user, membership.create, await body(request)
        )

    @app.post("/api/cluster/join")
    async def cluster_join(request: Request):
        user = appliance_admin(request)
        return await run_in_threadpool(
            appliance_change, user, membership.join, await body(request)
        )

    @app.post("/api/cluster/refresh")
    async def cluster_refresh(request: Request):
        user = appliance_admin(request)
        return await run_in_threadpool(
            appliance_change, user, membership.refresh, include_actor=False
        )

    peer_attempts = OrderedDict()
    peer_gate = threading.BoundedSemaphore(2)

    def peer_call(request, data, operation):
        # Public enrollment uses its own shared secret, not a browser session.
        # Bound Argon2/network work, including forwarding through a Slave.
        with login_lock:
            now = time.monotonic()
            ip = request.client.host
            recent = peer_attempts.setdefault(ip, deque())
            peer_attempts.move_to_end(ip)
            while len(peer_attempts) > 10000:
                peer_attempts.popitem(last=False)
            while recent and recent[0] < now - 60:
                recent.popleft()
            if len(recent) >= 20:
                raise HTTPException(429, "Too many appliance requests; wait one minute")
            recent.append(now)
        if not peer_gate.acquire(blocking=False):
            raise HTTPException(429, "Appliance enrollment is busy; retry later")
        try:
            return operation(data)
        finally:
            peer_gate.release()

    @app.post("/api/cluster/peer/join")
    async def cluster_peer_join(request: Request):
        return await run_in_threadpool(
            peer_call, request, await body(request), membership.accept
        )

    @app.post("/api/cluster/peer/status")
    async def cluster_peer_status(request: Request):
        return await run_in_threadpool(
            peer_call, request, await body(request), membership.peer_status
        )

    @app.post("/api/search")
    async def search(request: Request):
        from starlette.concurrency import run_in_threadpool

        user = who(request)
        data = await body(request)
        result = await run_in_threadpool(
            store.search, user["tenant"], data, allowed_indexes=user["allowed_indexes"]
        )
        with store.write_lock, store.control() as db:
            store.audit(
                db,
                user["tenant"],
                user["name"],
                "search",
                {
                    "language": data.get("language", "spl"),
                    "returned": result["returned"],
                },
            )
        return result

    @app.post("/services/collector/event")
    @app.post("/services/collector")
    async def hec_ingest(request: Request):
        from .integration import hec

        user = who(request, ("admin", "ingest"))
        if request.headers.get("content-type", "").split(";")[0] != "application/json":
            raise HTTPException(415, "HEC requires application/json")
        try:
            raw = (await request.body()).decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("HEC body must be UTF-8")
        try:
            payload = json.loads(raw)
        except ValueError:
            try:
                payload = [
                    json.loads(line) for line in raw.splitlines() if line.strip()
                ]
            except ValueError:
                raise ValueError("Invalid HEC JSON")
        result = await run_in_threadpool(
            auth.ingest_authorized, store, user, hec(payload)
        )
        return {"text": "Success", "code": 0, **result}

    @app.post("/v1/logs")
    async def otlp_ingest(request: Request):
        from .integration import otlp

        user = who(request, ("admin", "ingest"))
        data = await body(request)
        await run_in_threadpool(auth.ingest_authorized, store, user, otlp(data))
        return {"partialSuccess": {}}

    @app.get("/api/tokens")
    def tokens(request: Request):
        user = who(request, ("admin",))
        return auth.list_tokens(store, user)

    @app.post("/api/search/jobs", status_code=202)
    async def search_submit(request: Request):
        from . import jobs

        user = who(request)
        data = await body(request)
        job_id = await run_in_threadpool(jobs.submit, store, user, data)
        return {"id": job_id, "state": "queued"}

    @app.get("/api/search/jobs")
    def search_history(request: Request):
        user = who(request)
        with store.control() as db:
            return [
                dict(r)
                for r in db.execute(
                    "SELECT id,owner,state,created,started,finished,error,expires FROM search_jobs WHERE tenant=? AND owner=? AND expires>? ORDER BY created DESC LIMIT 50",
                    (user["tenant"], user["name"], time.time()),
                )
            ]

    @app.get("/api/search/jobs/{job_id}")
    def search_status(job_id: str, request: Request):
        from . import jobs

        try:
            return jobs.status(store, who(request), job_id)
        except KeyError:
            raise HTTPException(404, "Search job not found")

    @app.get("/api/search/jobs/{job_id}/results")
    def search_results(
        job_id: str, request: Request, offset: int = 0, count: int = 100
    ):
        from . import jobs

        try:
            return jobs.result(store, who(request), job_id, offset, count)
        except KeyError:
            raise HTTPException(404, "Search job not found")

    @app.post("/api/search/jobs/{job_id}/cancel")
    def search_cancel(job_id: str, request: Request):
        from . import jobs

        try:
            return jobs.cancel(store, who(request), job_id)
        except KeyError:
            raise HTTPException(404, "Search job not found")

    @app.post("/api/tokens")
    async def token(request: Request):
        user = who(request, ("admin",))
        data = await body(request)
        if set(data) - {"name", "lifetime_days", "allowed_indexes"}:
            raise ValueError(
                "Expected name, optional lifetime_days and exact allowed_indexes"
            )
        indexes = (
            ["main"] if data.get("allowed_indexes") is None else data["allowed_indexes"]
        )
        return {
            "token": auth.issue_token(
                store, user, data.get("name"), data.get("lifetime_days", 90), indexes
            ),
            "scope": "ingest",
            "allowed_indexes": sorted(indexes),
            "note": "Displayed once; store securely",
        }

    @app.delete("/api/tokens/{token_id}")
    def revoke(token_id: str, request: Request):
        user = who(request, ("admin",))
        return auth.revoke_token(store, user, token_id)

    @app.post("/api/users")
    async def user_create(request: Request):
        from . import access

        user = who(request, ("admin",))
        data = await body(request)
        if not {"name", "password"} <= set(data) or set(data) - {
            "name",
            "password",
            "role",
        }:
            raise ValueError("Expected name, password and optional role")
        # A tenant admin cannot create principals in a different tenant.
        await run_in_threadpool(
            auth.create_user,
            store,
            data.get("name"),
            data.get("password"),
            data.get("role", "viewer"),
            user["tenant"],
            actor=user["name"],
            must_change=True,
            authorization=lambda db: access.require_full_admin(db, user),
        )
        return {"created": True}

    @app.get("/api/users")
    def user_list(request: Request):
        user = who(request, ("admin",))
        with store.control() as db:
            return [
                dict(r)
                for r in db.execute(
                    "SELECT name,role,disabled,must_change,password_changed,mfa_secret IS NOT NULL AS mfa_enabled FROM users WHERE tenant=? ORDER BY name",
                    (user["tenant"],),
                )
            ]

    @app.get("/api/dashboards")
    def dashboard_list(request: Request):
        from . import dashboards

        return dashboards.list_for(store, who(request))

    @app.post("/api/dashboards", status_code=201)
    async def dashboard_create(request: Request):
        from . import dashboards

        user = who(request, ("admin", "analyst"))
        return {
            "id": await run_in_threadpool(
                dashboards.save, store, user, await body(request)
            )
        }

    @app.put("/api/dashboards/{dashboard_id}")
    async def dashboard_update(dashboard_id: str, request: Request):
        from . import dashboards

        user = who(request, ("admin", "analyst"))
        try:
            return {
                "id": await run_in_threadpool(
                    dashboards.save, store, user, await body(request), dashboard_id
                )
            }
        except KeyError:
            raise HTTPException(404, "Dashboard not found")

    @app.patch("/api/users/{name}")
    async def user_update(name: str, request: Request):
        from . import access, principal

        user = who(request, ("admin",))
        data = await body(request)
        if (
            set(data) != {"role", "disabled"}
            or not isinstance(data["role"], str)
            or data["role"] not in {"admin", "analyst", "viewer"}
            or type(data["disabled"]) is not bool
        ):
            raise ValueError("Expected role and disabled boolean")
        with principal.transaction(store, user, ("admin",), write=True) as (
            db,
            current,
        ):
            access.require_full_admin(db, current)
            target = db.execute(
                "SELECT role,disabled FROM users WHERE name=? AND tenant=?",
                (name, user["tenant"]),
            ).fetchone()
            if not target:
                raise HTTPException(404, "User not found")
            if (
                target["role"] == "admin"
                and not target["disabled"]
                and (data["role"] != "admin" or data["disabled"])
            ):
                admins = db.execute(
                    "SELECT count(*) FROM users WHERE tenant=? AND role='admin' AND disabled=0",
                    (user["tenant"],),
                ).fetchone()[0]
                if admins <= 1:
                    raise HTTPException(
                        409,
                        "The last active administrator cannot be disabled or demoted",
                    )
            db.execute(
                "UPDATE users SET role=?,disabled=? WHERE name=? AND tenant=?",
                (data["role"], int(data["disabled"]), name, user["tenant"]),
            )
            db.execute("DELETE FROM sessions WHERE name=?", (name,))
            store.audit(
                db, user["tenant"], user["name"], "user.update", {"name": name, **data}
            )
        return {"updated": True, "sessions_revoked": True}

    @app.get("/api/rules")
    def rules(request: Request):
        user = who(request)
        with store.control() as db:
            result = []
            for row in db.execute(
                "SELECT r.*,o.trigger AS trigger_json,o.case_adapter AS adapter_json "
                "FROM rules r LEFT JOIN rule_detection_options o ON o.rule_id=r.id "
                "WHERE r.tenant=? ORDER BY r.name",
                (user["tenant"],),
            ):
                item = dict(row)
                trigger = item.pop("trigger_json")
                adapter = item.pop("adapter_json")
                item["trigger"] = (
                    json.loads(trigger)
                    if trigger
                    else {"mode": "rows", "value": item["threshold"]}
                )
                item["case_adapter"] = json.loads(adapter) if adapter else None
                result.append(item)
            return result

    @app.post("/api/rules")
    async def rule_create(request: Request):
        user = who(request, ("admin", "analyst"))
        return {"id": save_rule(store, user, await body(request))}

    @app.patch("/api/rules/{rule_id}")
    async def rule_toggle(rule_id: str, request: Request):
        user = who(request, ("admin", "analyst"))
        data = await body(request)
        if set(data) != {"enabled"} or not isinstance(data["enabled"], bool):
            raise ValueError("Expected enabled boolean")
        with store.write_lock, store.control() as db:
            row = db.execute(
                "UPDATE rules SET enabled=? WHERE id=? AND tenant=?",
                (int(data["enabled"]), rule_id, user["tenant"]),
            )
            if not row.rowcount:
                raise HTTPException(404, "Rule not found")
            store.audit(
                db, user["tenant"], user["name"], "rule.toggle", {"id": rule_id, **data}
            )
        return {"ok": True}

    @app.get("/api/findings")
    def findings(request: Request):
        user = who(request)
        with store.control() as db:
            rows = db.execute(
                "SELECT * FROM findings WHERE tenant=? ORDER BY created DESC",
                (user["tenant"],),
            ).fetchall()
        visible = []
        for row in rows:
            evidence = json.loads(row["evidence"])
            scope = evidence.get("access_scope")
            if (
                user["allowed_indexes"] == ["*"]
                or scope is not None
                and scope != ["*"]
                and set(scope) <= set(user["allowed_indexes"])
            ):
                visible.append(dict(row))
        return visible

    @app.patch("/api/findings/{finding_id}")
    async def finding_update(finding_id: str, request: Request):
        user = who(request, ("admin", "analyst"))
        data = await body(request)
        if (
            set(data) != {"status", "owner", "version"}
            or data["status"] not in {"new", "triage", "resolved", "false_positive"}
            or not isinstance(data["owner"], str)
            or len(data["owner"]) > 64
            or type(data["version"]) is not int
        ):
            raise ValueError("Expected valid status, owner, version")
        with store.write_lock, store.control() as db:
            prior = db.execute(
                "SELECT evidence FROM findings WHERE id=? AND tenant=?",
                (finding_id, user["tenant"]),
            ).fetchone()
            if not prior:
                raise HTTPException(
                    409, "Finding changed or unavailable; refresh before updating"
                )
            scope = json.loads(prior[0]).get("access_scope")
            if user["allowed_indexes"] != ["*"] and (
                scope is None
                or scope == ["*"]
                or not set(scope) <= set(user["allowed_indexes"])
            ):
                raise HTTPException(
                    409, "Finding changed or unavailable; refresh before updating"
                )
            row = db.execute(
                "UPDATE findings SET status=?,owner=?,version=version+1 WHERE id=? AND tenant=? AND version=?",
                (
                    data["status"],
                    data["owner"],
                    finding_id,
                    user["tenant"],
                    data["version"],
                ),
            )
            if not row.rowcount:
                raise HTTPException(
                    409, "Finding changed or unavailable; refresh before updating"
                )
            store.audit(
                db,
                user["tenant"],
                user["name"],
                "finding.update",
                {"id": finding_id, **data},
            )
        return {"ok": True}

    @app.put("/api/policy")
    async def policy(request: Request):
        from . import access, principal

        user = who(request, ("admin",))
        data = await body(request)
        if (
            set(data) != {"days", "hold"}
            or type(data["days"]) is not int
            or not 1 <= data["days"] <= 3650
            or type(data["hold"]) is not bool
        ):
            raise ValueError("Retention days 1..3650, hold boolean required")
        with principal.transaction(store, user, ("admin",), write=True) as (
            db,
            current,
        ):
            access.require_full_admin(db, current)
            db.execute(
                "INSERT INTO policies VALUES(?,?,?) ON CONFLICT(tenant) DO UPDATE SET days=excluded.days,hold=excluded.hold",
                (current["tenant"], data["days"], int(data["hold"])),
            )
            store.audit(db, user["tenant"], user["name"], "policy.update", data)
        return {
            "ok": True,
            "note": "Enforced by hourly maintenance; hold prevents automatic event deletion",
        }

    @app.get("/api/audit")
    def audit(request: Request):
        from . import access, principal

        user = who(request, ("admin",))
        with principal.transaction(store, user, ("admin",)) as (db, current):
            access.require_full_admin(db, current)
            return [
                dict(r)
                for r in db.execute(
                    "SELECT seq,at,actor,action,detail,digest FROM audit WHERE tenant=? OR (tenant='authentication' AND ?='default') ORDER BY seq DESC",
                    (user["tenant"], user["tenant"]),
                )
            ]

    from .api_logs import register as register_logs

    register_logs(app, store, runtime, who, body)
    web = Path(__file__).parent / "web"
    from .api_extensions import register

    register(
        app, store, runtime, membership, who, body, appliance_admin, appliance_change
    )
    from .api_detection_ops import register as register_detection_ops
    from .api_enterprise import register as register_enterprise

    register_detection_ops(app, store, runtime, who, body)

    register_enterprise(app, store, runtime, who, body)
    from .api_console import register as register_console
    from .api_xdr import register as register_xdr

    register_console(app, store, runtime, who, body)
    register_xdr(app, store, runtime, who, body)
    from .api_xdr_advanced import register as register_xdr_advanced

    register_xdr_advanced(app, store, runtime, who, body)
    from .api_yara import register as register_yara

    register_yara(app, store, runtime, who, body)
    from . import api_ops_qualification, api_research_trace
    for module in (api_ops_qualification, api_research_trace):
        module.register(app, store, runtime, who, body)
    from . import api_analysis_engines, api_analysis_sensors, api_research_behavior, sequence_event_time, online_analytics, api_sigma_imports
    for module in (api_analysis_engines, api_analysis_sensors, api_research_behavior, sequence_event_time, online_analytics, api_sigma_imports):
        module.register(app, store, runtime, who, body)
    from .api_backend_ops import register as register_backend_ops

    register_backend_ops(app, store, runtime, who, body)
    from . import intelligence, cpu_ml, cpu_sequence, intelligence_sequence, shadow_analysis, intelligence_shadow, case_intelligence, intelligence_starters, ml_datasets

    for module in (intelligence, cpu_ml, cpu_sequence, intelligence_sequence, shadow_analysis, intelligence_shadow, case_intelligence, intelligence_starters, ml_datasets):
        module.register(app, store, runtime, who, body)
    from .api_agents import register as register_agents

    register_agents(app, store, runtime, who, body)
    from .api_templates import register as register_templates

    register_templates(app, store, runtime, who, body)
    from .fortigate import register as register_fortigate

    register_fortigate(app, store, runtime, who, body)
    app.mount("/static", StaticFiles(directory=web), name="static")

    @app.get("/")
    def home():
        return FileResponse(web / "index.html")

    return app
