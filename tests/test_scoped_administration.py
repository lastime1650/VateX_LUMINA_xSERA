import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from sapientia import access, auth
from sapientia.api import create_app
from sapientia.storage import Settings

PASSWORD = "Scoped-administration-test-2026"
ROOT = {"name": "rootadmin", "tenant": "default", "role": "admin"}
SCOPED = {
    "name": "scopedadmin",
    "tenant": "default",
    "role": "admin",
    "allowed_indexes": ["public"],
}


@pytest.fixture
def client(tmp_path):
    app = create_app(Settings(tmp_path / "data", min_free_bytes=0), background=False)
    store = app.state.store
    auth.create_user(store, ROOT["name"], PASSWORD)
    auth.create_user(store, SCOPED["name"], PASSWORD)
    auth.create_user(store, "publicuser", PASSWORD, "viewer")
    auth.create_user(store, "privateuser", PASSWORD, "viewer")
    access.set_for_user(store, ROOT, SCOPED["name"], ["public"])
    access.set_for_user(store, ROOT, "publicuser", ["public"])
    with TestClient(app) as value:
        yield value


def login(client, name):
    client.cookies.clear()
    response = client.post("/api/login", json={"name": name, "password": PASSWORD})
    assert response.status_code == 200
    client.headers["X-CSRF-Token"] = response.json()["csrf"]


@pytest.mark.parametrize("indexes", [["*"], ["private"], ["public", "private"]])
def test_scoped_admin_cannot_expand_own_or_managed_grants(client, indexes):
    store = client.app.state.store
    for target in (SCOPED["name"], "publicuser"):
        with pytest.raises(PermissionError):
            access.set_for_user(store, SCOPED, target, indexes)
        assert access.get_for_user(store, target, "default") == ["public"]


def test_scoped_admin_cannot_manage_unrestricted_or_disabled_unrestricted_target(
    client,
):
    store = client.app.state.store
    for disabled in (0, 1):
        with store.control() as db:
            db.execute(
                "UPDATE users SET disabled=? WHERE name='privateuser'", (disabled,)
            )
        with pytest.raises(PermissionError):
            access.set_for_user(store, SCOPED, "privateuser", [])
    # A scoped admin can still manage an existing subordinate scope.
    access.set_for_user(store, SCOPED, "publicuser", [])
    access.set_for_user(store, SCOPED, "publicuser", ["public"])


def test_scoped_account_creation_and_role_or_disabled_changes_are_rejected(client):
    login(client, SCOPED["name"])
    for role in ("admin", "analyst", "viewer"):
        response = client.post(
            "/api/users", json={"name": "newuser", "password": PASSWORD, "role": role}
        )
        assert response.status_code == 403
    for target in ("privateuser", "publicuser", ROOT["name"]):
        response = client.patch(
            f"/api/users/{target}", json={"role": "admin", "disabled": False}
        )
        assert response.status_code == 403
    with client.app.state.store.control() as db:
        assert not db.execute("SELECT 1 FROM users WHERE name='newuser'").fetchone()
        assert (
            db.execute("SELECT role FROM users WHERE name='publicuser'").fetchone()[0]
            == "viewer"
        )


def test_unrestricted_account_administration_is_preserved_and_input_typed(client):
    login(client, ROOT["name"])
    response = client.post(
        "/api/users", json={"name": "newuser", "password": PASSWORD, "role": "admin"}
    )
    assert response.status_code == 200
    with client.app.state.store.control() as db:
        user = db.execute(
            "SELECT role,must_change FROM users WHERE name='newuser'"
        ).fetchone()
        assert tuple(user) == ("admin", 1)
    assert access.get_for_user(client.app.state.store, "newuser", "default") == ["*"]
    assert (
        client.patch(
            "/api/users/publicuser", json={"role": "analyst", "disabled": False}
        ).status_code
        == 200
    )
    assert (
        client.patch(
            "/api/users/publicuser", json={"role": [], "disabled": False}
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/users", json={"name": "badrole", "password": PASSWORD, "role": []}
        ).status_code
        == 400
    )


def test_creation_rechecks_current_scope_in_same_write_transaction(client):
    store = client.app.state.store
    stale_root = {**ROOT, "allowed_indexes": ["*"]}
    access.set_for_user(store, ROOT, ROOT["name"], ["public"])
    with pytest.raises(PermissionError):
        auth.create_user(
            store,
            "newuser",
            PASSWORD,
            actor=ROOT["name"],
            authorization=lambda db: access.require_full_admin(db, stale_root),
        )
    with store.control() as db:
        assert not db.execute("SELECT 1 FROM users WHERE name='newuser'").fetchone()


def test_scoped_admin_cannot_manage_appliance_tenant_retention_or_read_whole_audit(
    client,
):
    login(client, SCOPED["name"])
    assert client.get("/api/cluster").status_code == 403
    for path in (
        "/api/cluster/master",
        "/api/cluster/join",
        "/api/cluster/refresh",
        "/api/cluster/members/00000000-0000-4000-8000-000000000001/recover",
    ):
        assert client.post(path, json={}).status_code == 403
    assert client.put("/api/policy", json={"days": 1, "hold": False}).status_code == 403
    assert client.get("/api/audit").status_code == 403
    assert client.get("/api/audit/integrity").status_code == 403
    assert client.post("/api/audit/checkpoint", json={}).status_code == 403
    assert client.post("/api/audit/verify", json={}).status_code == 403
    with client.app.state.store.control() as db:
        assert not db.execute(
            "SELECT 1 FROM policies WHERE tenant='default'"
        ).fetchone()


def test_full_admin_appliance_policy_and_audit_remain_available(client, monkeypatch):
    login(client, ROOT["name"])
    seen = []
    monkeypatch.setattr(
        client.app.state.membership,
        "create",
        lambda actor, data: seen.append(actor) or {"created": True},
    )
    assert client.post("/api/cluster/master", json={}).status_code == 200
    assert seen[0]["allowed_indexes"] == ["*"]
    assert client.get("/api/cluster").status_code == 200
    assert client.put("/api/policy", json={"days": 30, "hold": True}).status_code == 200
    assert client.get("/api/audit").status_code == 200
    assert client.get("/api/audit/integrity").json()["valid"] is True
    checkpoint = client.post("/api/audit/checkpoint", json={})
    assert checkpoint.status_code == 200
    assert client.post("/api/audit/verify", json=checkpoint.json()).json()["valid"] is True


def test_appliance_operation_rechecks_scope_after_waiting_for_membership_lock(
    client, monkeypatch
):
    login(client, ROOT["name"])
    store, membership = client.app.state.store, client.app.state.membership
    checked, calls = threading.Event(), []
    original = access.require_full_admin

    def authority(db, actor):
        value = original(db, actor)
        checked.set()
        return value

    monkeypatch.setattr(access, "require_full_admin", authority)
    monkeypatch.setattr(
        membership,
        "create",
        lambda actor, data: calls.append(actor) or {"created": True},
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        with membership.lock:
            pending = pool.submit(client.post, "/api/cluster/master", json={})
            assert checked.wait(5)
            access.set_for_user(store, ROOT, ROOT["name"], ["public"])
        assert pending.result(timeout=10).status_code == 403
    assert calls == []


@pytest.mark.parametrize("mutation", ["must_change=1", "disabled=1", "role='viewer'"])
def test_index_administration_rechecks_current_account(client, mutation):
    store = client.app.state.store
    with store.control() as db:
        db.execute("UPDATE users SET " + mutation + " WHERE name='scopedadmin'")
    with pytest.raises(PermissionError):
        access.set_for_user(store, SCOPED, "publicuser", [])
    assert access.get_for_user(store, "publicuser", "default") == ["public"]
