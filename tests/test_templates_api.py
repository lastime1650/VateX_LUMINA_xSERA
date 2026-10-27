from test_enterprise_api import (  # noqa: F401 - shared public HTTP fixture.
    client,
    login,
)

from sapientia import access, detections


def test_reference_routes_authentication_filters_and_viewer_read(client):  # noqa: F811 - shared pytest fixture.
    assert client.get("/api/attack/catalog").status_code == 401
    assert client.get("/api/rule-templates").status_code == 401
    login(client, "viewer_a")
    summary = client.get("/api/rule-templates/summary")
    assert summary.status_code == 200 and summary.json()["total"] == 962
    page = client.get(
        "/api/rule-templates",
        params={
            "search": "T1059.001",
            "platform": "windows",
            "supported": "true",
            "limit": 2,
        },
    )
    assert page.status_code == 200 and len(page.json()["items"]) == 2
    assert page.json()["items"][0]["supported"]
    catalog = client.get(
        "/api/attack/catalog", params={"tactic": "TA0002", "search": "T1059.001"}
    )
    assert (
        catalog.status_code == 200
        and catalog.json()["techniques"][0]["id"] == "T1059.001"
    )
    assert client.get("/api/attack/techniques/T1059.001").json()["technique"][
        "description"
    ]
    assert client.get("/api/attack/techniques/T9999").status_code == 404
    for url in [
        "/api/attack/catalog?limit=201",
        "/api/attack/catalog?include_inactive=yes",
        "/api/rule-templates?limit=101",
        "/api/rule-templates?supported=yes",
    ]:
        assert client.get(url).status_code == 400
    assert (
        client.post(
            "/api/rule-templates/R-WIN-001/apply",
            json={"index": "endpoint", "accept_adaptation": True},
        ).status_code
        == 403
    )


def test_apply_csrf_scope_and_disabled_behavior_policy(client):  # noqa: F811 - shared pytest fixture.
    login(client)
    payload = {"index": "endpoint", "accept_adaptation": True}
    csrf = client.headers.pop("X-CSRF-Token")
    assert (
        client.post("/api/rule-templates/R-LAB-001/apply", json=payload).status_code
        == 403
    )
    client.headers["X-CSRF-Token"] = csrf
    assert (
        client.post(
            "/api/rule-templates/R-LAB-001/apply", json={"index": "endpoint"}
        ).status_code
        == 400
    )
    result = client.post("/api/rule-templates/R-LAB-001/apply", json=payload)
    assert result.status_code == 201, result.text
    assert result.json()["enabled"] is False
    store = client.app.state.store
    actor = {"name": "admin_a", "tenant": "a", "role": "admin"}
    policy = detections.list_policies(store, actor)[0]
    assert (
        policy["enabled"] == 0
        and policy["definition"]["steps"][1]["within_seconds"] == 120
    )
    access.set_for_user(store, actor, "admin_a", ["public"])
    login(client)
    assert (
        client.post("/api/rule-templates/R-WIN-001/apply", json=payload).status_code
        == 403
    )
    assert (
        len(
            detections.list_policies(
                store, {"name": "admin_b", "tenant": "b", "role": "admin"}
            )
        )
        == 0
    )
    assert client.get("/api/incidents/not-present/attack-context").status_code == 404
