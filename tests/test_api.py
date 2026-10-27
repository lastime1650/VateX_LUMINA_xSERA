import pytest
from fastapi.testclient import TestClient

from sapientia.api import create_app
from sapientia.auth import create_user
from sapientia.storage import Settings

PASSWORD = "Testing-only-password-2026"


@pytest.fixture
def client(tmp_path):
    app = create_app(Settings(tmp_path, min_free_bytes=0), background=False)
    with TestClient(app) as c:
        yield c


def sign_in(c, name="admin", role="admin", tenant="default"):
    create_user(c.app.state.store, name, PASSWORD, role, tenant)
    response = c.post("/api/login", json={"name": name, "password": PASSWORD})
    assert response.status_code == 200, response.text
    c.headers["X-CSRF-Token"] = response.json()["csrf"]
    return response.json()


def test_bootstrap_and_one_time_setup(client):
    assert not client.get("/api/bootstrap").json()["configured"]
    assert (
        client.post(
            "/api/setup", json={"name": "admin", "password": PASSWORD}
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/api/setup", json={"name": "again", "password": PASSWORD}
        ).status_code
        == 400
    )
    assert client.get("/api/bootstrap").json()["configured"]


def test_setup_remote_host_denied(client):
    assert (
        client.post(
            "/api/setup",
            headers={"Host": "attacker.example"},
            json={"name": "admin", "password": PASSWORD},
        ).status_code
        == 403
    )


def test_auth_csrf_and_headers(client):
    assert client.get("/api/health").status_code == 401
    sign_in(client)
    result = client.get("/api/health")
    assert result.status_code == 200
    assert "frame-ancestors 'none'" in result.headers["content-security-policy"]
    assert "httponly" in str(client.cookies).lower() or client.cookies.get(
        client.app.state.cookie_name
    )
    del client.headers["X-CSRF-Token"]
    assert client.post("/api/search", json={"query": "*"}).status_code == 403


def test_origin_and_content_type(client):
    sign_in(client)
    assert (
        client.post(
            "/api/search",
            headers={"Origin": "https://other.example"},
            json={"query": "*"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/search",
            content='{"query":"*"}',
            headers={"Content-Type": "text/plain"},
        ).status_code
        == 415
    )


def test_api_ingest_search_token_and_revoke(client):
    sign_in(client)
    issued = client.post("/api/tokens", json={"name": "edr"})
    assert issued.status_code == 200
    token = issued.json()["token"]
    headers = {"Authorization": "Bearer " + token}
    payload = {
        "events": [
            {
                "event_id": "stable",
                "source": "edr",
                "message": "blocked",
                "severity": "high",
            }
        ]
    }
    assert (
        client.post("/api/v1/events", headers=headers, json=payload).status_code == 202
    )
    assert (
        client.post("/api/v1/events", headers=headers, json=payload).json()["duplicate"]
        == 1
    )
    assert (
        client.post("/api/search", headers=headers, json={"query": "*"}).status_code
        == 403
    )
    client.app.state.store.flush()
    assert (
        client.post("/api/search", json={"query": "search severity=high"}).json()[
            "returned"
        ]
        == 1
    )
    tid = client.get("/api/tokens").json()[0]["id"]
    assert client.delete("/api/tokens/" + tid).status_code == 200
    assert (
        client.post("/api/v1/events", headers=headers, json=payload).status_code == 401
    )


def test_viewer_cannot_mutate(client):
    sign_in(client, name="viewer", role="viewer")
    assert client.post("/api/search", json={"query": "*"}).status_code == 200
    for path, data in [
        ("/api/tokens", {"name": "no"}),
        ("/api/rules", {}),
        ("/api/v1/events", {"events": []}),
    ]:
        assert client.post(path, json=data).status_code == 403
    assert client.put("/api/policy", json={"days": 1, "hold": False}).status_code == 403


def test_no_tenant_override(client):
    sign_in(client)
    assert (
        client.post(
            "/api/v1/events", json={"tenant": "other", "events": [{}]}
        ).status_code
        == 400
    )
    assert (
        client.post("/api/search", json={"query": "*", "tenant": "other"}).status_code
        == 400
    )


def test_tenant_finding_update_isolation(client):
    sign_in(client, tenant="a")
    with client.app.state.store.control() as db:
        db.execute(
            "INSERT INTO findings VALUES('hidden','b','r','secret',0,'new','',1,'{}')"
        )
    assert client.get("/api/findings").json() == []
    assert (
        client.patch(
            "/api/findings/hidden",
            json={"status": "resolved", "owner": "admin", "version": 1},
        ).status_code
        == 409
    )


def test_finding_optimistic_concurrency(client):
    sign_in(client)
    with client.app.state.store.control() as db:
        db.execute(
            "INSERT INTO findings VALUES('f','default','r','found',0,'new','',1,'{}')"
        )
    data = {"status": "triage", "owner": "admin", "version": 1}
    assert client.patch("/api/findings/f", json=data).status_code == 200
    assert client.patch("/api/findings/f", json=data).status_code == 409


def test_resource_limits(client):
    sign_in(client)
    assert (
        client.post("/api/search", json={"query": "*", "limit": 1001}).status_code
        == 400
    )
    assert (
        client.post("/api/v1/events", json={"events": [{}] * 1001}).status_code == 400
    )
    assert (
        client.post(
            "/api/v1/events",
            content=b"x" * (2 * 1024 * 1024 + 1),
            headers={"Content-Type": "application/json"},
        ).status_code
        == 413
    )


def test_login_rate_limit(client):
    for _ in range(10):
        assert (
            client.post(
                "/api/login", json={"name": "missing", "password": "wrong"}
            ).status_code
            == 401
        )
    assert (
        client.post(
            "/api/login", json={"name": "missing", "password": "wrong"}
        ).status_code
        == 429
    )


def test_logout_revokes_session(client):
    sign_in(client)
    cookie = client.cookies.get(client.app.state.cookie_name)
    assert client.post("/api/logout").status_code == 200
    client.cookies.set(client.app.state.cookie_name, cookie)
    assert client.get("/api/me").status_code == 401


def test_independent_appliance_cookies_do_not_collide(tmp_path):
    app_a = create_app(Settings(tmp_path / "a", min_free_bytes=0), background=False)
    app_b = create_app(Settings(tmp_path / "b", min_free_bytes=0), background=False)
    with TestClient(app_a) as first, TestClient(app_b) as second:
        sign_in(first, "admin_a")
        sign_in(second, "admin_b")
        assert app_a.state.cookie_name != app_b.state.cookie_name
        # The browser stores both localhost cookies regardless of server port.
        first.cookies.update(second.cookies)
        second.cookies.update(first.cookies)
        assert first.get("/api/me").json()["name"] == "admin_a"
        assert second.get("/api/me").json()["name"] == "admin_b"


def test_new_user_forced_rotation_and_last_administrator(client):
    sign_in(client)
    assert (
        client.patch(
            "/api/users/admin", json={"role": "viewer", "disabled": False}
        ).status_code
        == 409
    )
    assert (
        client.post(
            "/api/users",
            json={"name": "analyst", "password": PASSWORD, "role": "analyst"},
        ).status_code
        == 200
    )
    response = client.post("/api/login", json={"name": "analyst", "password": PASSWORD})
    client.headers["X-CSRF-Token"] = response.json()["csrf"]
    assert client.get("/api/me").json()["must_change"]
    assert client.post("/api/search", json={"query": "*"}).status_code == 403
    assert (
        client.post(
            "/api/me/password",
            json={"current": PASSWORD, "password": PASSWORD + "-changed"},
        ).status_code
        == 200
    )
    assert client.get("/api/me").status_code == 401
    response = client.post(
        "/api/login", json={"name": "analyst", "password": PASSWORD + "-changed"}
    )
    client.headers["X-CSRF-Token"] = response.json()["csrf"]
    assert client.post("/api/search", json={"query": "*"}).status_code == 200


def test_ui_assets(client):
    r = client.get("/")
    assert r.status_code == 200 and "Vatex LUMINA" in r.text
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/style.css").status_code == 200
    for name in ["horizon.css", "horizon.js", "enterprise.js", "appliance.js"]:
        assert client.get("/static/" + name).status_code == 200
    assert client.get("/static/../control.sqlite3").status_code == 404


def test_policy_validated_and_audited(client):
    sign_in(client)
    assert client.put("/api/policy", json={"days": 0, "hold": False}).status_code == 400
    assert client.put("/api/policy", json={"days": 30, "hold": True}).status_code == 200
    assert client.get("/api/health").json()["legal_hold"] is True
    assert any(x["action"] == "policy.update" for x in client.get("/api/audit").json())
