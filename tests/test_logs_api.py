import hashlib

import pytest
from fastapi.testclient import TestClient

from sapientia import auth, log_search
from sapientia.api import create_app
from sapientia.storage import Settings


@pytest.fixture
def client(tmp_path):
    app = create_app(Settings(tmp_path, min_free_bytes=0), background=False)
    with TestClient(app) as c:
        auth.create_user(
            app.state.store, "admin", "Testing-only-password-2026", "admin", "default"
        )
        login = c.post(
            "/api/login",
            json={"name": "admin", "password": "Testing-only-password-2026"},
        )
        assert login.status_code == 200
        c.headers["X-CSRF-Token"] = login.json()["csrf"]
        yield c


def test_log_lifecycle_scoped_admin_and_status(client):
    result = client.get("/api/logs/status")
    assert result.status_code == 200, result.text
    assert set(result.json()["storage"]["tiers"]) == {"hot", "warm", "cold", "archive"}
    policy = {
        "hot_days": 1,
        "warm_days": 7,
        "cold_days": 30,
        "retention_days": 0,
        "hold": False,
        "version": 0,
    }
    response = client.put("/api/logs/indexes/firewall/lifecycle", json=policy)
    assert response.status_code == 200, response.text
    assert response.json()["retention_days"] == 0
    timed_policy = {**policy, "retention_days": 180, "version": 1}
    assert client.put("/api/logs/indexes/firewall/lifecycle", json=timed_policy).status_code == 400
    assert (
        client.put("/api/logs/indexes/firewall/lifecycle", json=policy).status_code
        == 409
    )
    assert (
        client.post(
            "/api/logs/maintenance", json={"index_name": "firewall"}
        ).status_code
        == 200
    )
    auth.create_user(
        client.app.state.store,
        "reader",
        "Testing-only-password-2026",
        "viewer",
        "default",
    )
    login = client.post(
        "/api/login", json={"name": "reader", "password": "Testing-only-password-2026"}
    )
    client.headers["X-CSRF-Token"] = login.json()["csrf"]
    assert client.get("/api/logs/status").status_code == 200
    assert (
        client.put("/api/logs/indexes/firewall/lifecycle", json=policy).status_code
        == 403
    )
    assert client.post("/api/logs/backups", json={}).status_code == 403


def test_complete_log_export_and_csrf(client):
    store = client.app.state.store
    for offset in (0, 1000):
        store.ingest(
            "default",
            [
                {"event_id": str(n), "message": "security telemetry"}
                for n in range(offset, min(offset + 1000, 1203))
            ],
        )
    while store.flush():
        pass
    result = client.post(
        "/api/logs/snapshots", json={"query": {}, "fulltext": "security"}
    )
    # This fixture deliberately has no runtime worker. Interactive catch-up is
    # bounded and must refuse to publish a partial full-text population.
    assert result.status_code == 503, result.text
    with store.control(local=True) as db:
        assert db.execute("SELECT count(*) FROM log_snapshots").fetchone()[0] == 0
    root = store.path / "log-search"
    assert not list(root.glob("*.pending"))
    assert not [
        path for path in root.glob("*.sqlite3") if log_search.ID.fullmatch(path.stem)
    ]
    progress = client.get("/api/logs/status").json()["search"]["fulltext"]
    assert progress["ready"] is False and progress["pending_documents"] > 0

    # Original structured search remains complete while full-text catches up.
    structured = client.post("/api/logs/snapshots", json={"query": {}})
    assert structured.status_code == 201, structured.text
    assert structured.json()["rows"] == 1203
    assert (
        client.delete("/api/logs/snapshots/" + structured.json()["id"]).status_code
        == 200
    )
    for _ in range(8):
        processed = log_search.drain(store, budget=2, max_documents=250)
        assert 0 <= processed["processed"] <= 250
        progress = client.get("/api/logs/status").json()["search"]["fulltext"]
        if progress["ready"]:
            break
    assert progress["ready"] is True and progress["pending_documents"] == 0

    result = client.post(
        "/api/logs/snapshots", json={"query": {}, "fulltext": "security"}
    )
    assert result.status_code == 201, result.text
    snapshot = result.json()
    assert snapshot["rows"] == 1203
    first = client.get("/api/logs/snapshots/" + snapshot["id"] + "/export?limit=1000")
    assert len(first.text.splitlines()) == 1000
    second = client.get(
        "/api/logs/snapshots/"
        + snapshot["id"]
        + "/export?after="
        + first.headers["X-Next-After"]
    )
    assert len(second.text.splitlines()) == 203
    assert second.headers["X-Next-After"] == ""
    complete = client.get("/api/logs/snapshots/" + snapshot["id"] + "/download")
    assert len(complete.content) == int(complete.headers["Content-Length"])
    assert len(complete.text.splitlines()) == 1203
    assert hashlib.sha256(complete.content).hexdigest() == snapshot["sha256_ndjson"]
    assert client.delete("/api/logs/snapshots/" + snapshot["id"]).status_code == 200
    del client.headers["X-CSRF-Token"]
    assert client.post("/api/logs/snapshots", json={"query": {}}).status_code == 403


def test_online_backup_route_uses_private_destination(client):
    response = client.post(
        "/api/logs/backups", json={"passphrase": "Testing-backup-secret-2026"}
    )
    assert response.status_code == 201, response.text
    assert response.json()["online"] is True
    assert response.json()["encrypted"] is True
    assert response.json()["format"] == 2
    directory = (
        client.app.state.store.path
        / "private"
        / "online-backups"
        / response.json()["id"]
    )
    assert (directory / "header.json").is_file()
    assert not (directory / "control.sqlite3").exists()
    assert response.json()["manifest"]["audit_checkpoint"]["sequence"] > 0
    assert (
        client.post("/api/logs/backups", json={"destination": "C:/outside"}).status_code
        == 400
    )


def test_online_backup_revoked_scope_does_not_publish(client, monkeypatch):
    from sapientia import api_logs

    original = api_logs.backup_online

    def revoke(store, destination):
        result = original(store, destination)
        with store.control() as db:
            db.execute(
                "INSERT OR REPLACE INTO user_index_access VALUES(?,?,?)",
                ("default", "admin", '["main"]'),
            )
        return result

    monkeypatch.setattr(api_logs, "backup_online", revoke)
    result = client.post(
        "/api/logs/backups", json={"passphrase": "Testing-backup-secret-2026"}
    )
    assert result.status_code == 403, result.text
    root = client.app.state.store.path / "private" / "online-backups"
    assert not list(root.iterdir())
