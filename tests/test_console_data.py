import json
import threading
import time
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sapientia import (
    api_console,
    auth,
    casework,
    console_data,
    detections,
    entities,
    soar,
    source_health,
)
from sapientia.storage import CapacityError, Settings, Store, encode


@pytest.fixture
def console(tmp_path):
    store = Store(Settings(tmp_path, min_free_bytes=0))
    auth.create_user(store, "reader", "Synthetic-console-password-2026", "analyst", "a")
    actor = {
        "name": "reader",
        "tenant": "a",
        "role": "analyst",
        "allowed_indexes": ["*"],
    }
    now = time.time()
    yield store, actor, now
    store.close()


def incident(
    store, identifier, now, *, tenant="a", indexes=None, severity="high", status="new"
):
    with store.control() as db:
        db.execute(
            "INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                identifier,
                tenant,
                "host-" + identifier,
                "host",
                "Case " + identifier,
                now - 10,
                now - 1,
                status,
                "",
                1,
            ),
        )
        db.execute(
            "INSERT INTO risk_contributions VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                "risk-" + identifier,
                tenant,
                identifier,
                "policy",
                "host-" + identifier,
                "host",
                now - 5,
                50,
                encode({"severity": severity}),
                encode(indexes or ["public"]),
            ),
        )


def result(console, **kwargs):
    store, actor, now = console
    return console_data.summary(store, actor, now - 3600, now, **kwargs)


def test_measured_empty_population_and_no_invented_integrations(console):
    value = result(console)
    assert value["telemetry"]["event_count"] == 0
    assert value["telemetry"]["stored_payload_bytes"] == 0
    assert value["telemetry"]["last_received"] is None
    assert len(value["telemetry"]["series"]) == 48
    assert value["cases"]["total"] == 0
    assert value["integrations"]["configured_source_monitors"] == 0
    assert value["integrations"]["observed_sources"] == 0
    assert value["issues"]["combined_total"] is None


def test_full_population_totals_survive_bounded_tables_and_unicode_bytes(console):
    store, actor, now = console
    store.ingest(
        "a",
        [
            {
                "event_id": str(i),
                "source": "source-" + str(i),
                "host": "host-" + str(i),
                "event_time": now - 50,
                "message": "보안",
                "raw": {"name": "서울"},
            }
            for i in range(125)
        ],
    )
    store.ingest("b", [{"event_id": "outsider", "source": "hidden"}])
    store.flush()
    for i in range(215):
        incident(store, str(i), now, severity="critical" if i % 2 else "medium")
    # Received timestamps were assigned after `now`; the range is evaluated now.
    value = console_data.summary(store, actor, now - 3600)
    telemetry = value["telemetry"]
    assert (
        telemetry["event_count"]
        == telemetry["source_count"]
        == telemetry["observed_host_count"]
        == 125
    )
    assert len(telemetry["sources"]) == 100 and telemetry["source_rows_truncated"]
    assert sum(p["event_count"] for p in telemetry["series"]) == 125
    expected_bytes = store.analytics.execute(
        "SELECT sum(octet_length(encode(raw))+octet_length(encode(message))) FROM events WHERE tenant='a'"
    ).fetchone()[0]
    assert telemetry["stored_payload_bytes"] == expected_bytes
    assert telemetry["arrival_lag_p95_seconds"] >= 50
    assert (
        value["cases"]["total"]
        == value["issues"]["correlation_evidence"]["total"]
        == 215
    )
    assert len(value["cases"]["recent"]) == 50 and value["cases"]["rows_truncated"]
    assert sum(p["created"] for p in value["cases"]["series"]) == 215
    assert sum(value["cases"]["response_modes"].values()) == 215


def test_all_context_authorization_tenant_indexes_bookmarks_inventory_monitors(console):
    store, actor, now = console
    with store.control() as db:
        db.execute(
            "INSERT INTO user_index_access VALUES(?,?,?)", ("a", "reader", '["public"]')
        )
    actor["allowed_indexes"] = ["public"]
    incident(store, "visible", now)
    incident(store, "mixed", now, indexes=["public", "private"], severity="critical")
    incident(store, "bookmark", now)
    incident(store, "other-tenant", now, tenant="b")
    with store.control() as db:
        db.execute(
            "INSERT INTO case_bookmarks VALUES(?,?,?,?,?,?,?,?,?)",
            (
                "bookmark",
                "a",
                "bookmark",
                "secret-event",
                "private",
                "hidden",
                "reader",
                now - 4,
                "{}",
            ),
        )
        for fid, scope in [
            ("allowed", ["public"]),
            ("wide", ["public", "private"]),
            ("all", ["*"]),
            ("missing", None),
            ("bad", "public"),
        ]:
            db.execute(
                "INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    fid,
                    "a",
                    "rule",
                    fid,
                    now - 5,
                    "new",
                    "",
                    1,
                    encode({"access_scope": scope}),
                ),
            )
    store.ingest(
        "a",
        [
            {"event_id": "public", "index": "public", "host": "known"},
            {"event_id": "private", "index": "private", "host": "secret"},
            {"event_id": "unknown", "index": "public"},
        ],
    )
    store.flush()
    entities.save(
        store,
        actor,
        {
            "kind": "host",
            "name": "Registered",
            "indexes": ["public"],
            "aliases": [{"type": "hostname", "value": "known"}],
        },
    )
    source_health.save(
        store,
        actor,
        {
            "version": 0,
            "definition": {
                "name": "Auth logs",
                "source": "auth",
                "indexes": ["public"],
            },
        },
    )
    value = console_data.summary(store, actor, now - 3600)
    assert value["cases"]["total"] == 1
    assert value["cases"]["recent"][0]["id"] == "visible"
    assert value["cases"]["by_severity"]["critical"] == 0
    assert value["issues"]["correlation_evidence"]["total"] == 1
    assert value["issues"]["saved_search_findings"]["total"] == 1
    assert (
        value["telemetry"]["event_count"] == 2
        and value["assets"]["observed_hosts"] == 1
    )
    assert value["assets"]["explicit_inventory"]["by_kind"]["host"] == 1
    assert value["integrations"]["monitor_statuses"]["not_evaluated"] == 1
    assert "secret" not in json.dumps(value)
    with store.control() as db:
        db.execute(
            "UPDATE user_index_access SET allowed_indexes='[]' WHERE name='reader'"
        )
    denied = console_data.summary(store, actor, now - 3600)
    assert denied["cases"]["total"] == denied["telemetry"]["event_count"] == 0


def test_case_severity_complete_context_sla_real_status_and_manual_attribution(console):
    store, actor, now = console
    for identifier, status in [
        ("open", "new"),
        ("done", "resolved"),
        ("fp", "false_positive"),
    ]:
        incident(store, identifier, now, severity="low", status=status)
    with store.control() as db:
        db.execute(
            "INSERT INTO risk_contributions SELECT 'risk-extra',tenant,incident_id,policy_id,entity,entity_field,at-90000,weight,?,indexes FROM risk_contributions WHERE incident_id='open'",
            (encode({"severity": "critical"}),),
        )
        db.execute(
            "INSERT INTO case_workspaces VALUES(?,?,?,?,?,?,?)",
            ("a", "open", "critical", now - 1, "[]", 1, now),
        )
        db.execute(
            "INSERT INTO case_workspaces VALUES(?,?,?,?,?,?,?)",
            ("a", "done", "low", now - 1, "[]", 1, now),
        )
    casework.act(
        store,
        actor,
        "open",
        {
            "request_id": "manual-note",
            "action": {"type": "add_note", "note": "Reviewed"},
        },
    )
    value = console_data.summary(store, actor, now - 3600)
    assert (
        value["cases"]["open"]
        == value["cases"]["resolved"]
        == value["cases"]["false_positive"]
        == 1
    )
    assert (
        value["cases"]["sla"]["configured"] == 2
        and value["cases"]["sla"]["overdue"] == 1
    )
    assert value["cases"]["by_severity"]["critical"] == 1
    assert (
        value["issues"]["correlation_evidence"]["total"] == 3
    )  # Earlier critical fact is outside selected time.
    assert value["cases"]["response_modes"]["manual"] == 1
    assert value["cases"]["response_actions"]["manual"] == 1
    assert (
        next(c for c in value["cases"]["recent"] if c["id"] == "open")["severity"]
        == "critical"
    )


def test_current_account_recheck_and_cancellation_fail_closed(console, monkeypatch):
    store, _, _ = console
    original = store.analytics_query

    def revoke(*args, **kwargs):
        result = original(*args, **kwargs)
        with store.control() as db:
            db.execute("UPDATE users SET disabled=1 WHERE name='reader'")
        return result

    monkeypatch.setattr(store, "analytics_query", revoke)
    with pytest.raises(PermissionError):
        result(console)
    with pytest.raises(CapacityError, match="cancelled"):
        result(console, cancel=lambda: True)


def test_response_partition_tracks_real_soar_lifecycle_without_summing_actions(console):
    store, actor, now = console
    auth.create_user(
        store, "approver", "Synthetic-console-password-2026", "analyst", "a"
    )
    approver = {**actor, "name": "approver"}
    for identifier in ("finished", "queued", "pending", "manual", "unhandled"):
        incident(store, identifier, now)
    saved = soar.save(
        store,
        actor,
        {
            "name": "Review",
            "version": 0,
            "steps": [
                {
                    "id": "note",
                    "action": {"type": "add_note", "note": "Reviewed through workflow"},
                }
            ],
        },
    )
    completed = soar.start_run(store, actor, saved["id"], "finished", "finished")
    soar.approve(store, approver, completed["id"])
    assert soar.run_due(store) == 1
    queued = soar.start_run(store, actor, saved["id"], "queued", "queued")
    soar.approve(store, approver, queued["id"])
    soar.start_run(store, actor, saved["id"], "pending", "pending")
    # A manual action on an executing case must not create a second category.
    for identifier in ("manual", "queued"):
        casework.act(
            store,
            actor,
            identifier,
            {
                "request_id": "manual-" + identifier,
                "action": {"type": "add_note", "note": "Analyst note"},
            },
        )
    value = console_data.summary(store, actor, now - 3600)
    assert value["cases"]["response_modes"] == {
        "executing": 1,
        "awaiting_approval": 1,
        "attention": 0,
        "completed": 1,
        "manual": 1,
        "unhandled": 1,
    }
    assert value["cases"]["response_actions"]["soar"] == 1
    assert value["cases"]["response_actions"]["manual"] == 2
    assert sum(value["cases"]["response_modes"].values()) == value["cases"]["total"]
    assert (
        sum(row["count"] for row in value["cases"]["response_outcomes"])
        == value["cases"]["total"]
    )
    assert {
        row["status"]
        for row in value["cases"]["response_outcomes"]
        if row["response_mode"] == "completed"
    } == {"new"}


def test_legacy_judgement_is_manual_but_receipt_paired_soar_feedback_is_not(console):
    store, actor, now = console
    auth.create_user(
        store, "approver", "Synthetic-console-password-2026", "analyst", "a"
    )
    approver = {**actor, "name": "approver"}
    for identifier in ("legacy", "soar-resolved"):
        incident(store, identifier, now)
    detections.update_incident(
        store,
        actor,
        "legacy",
        {
            "status": "triage",
            "owner": "reader",
            "version": 1,
            "note": "Analyst judgement through legacy route",
        },
    )
    saved = soar.save(
        store,
        actor,
        {
            "name": "Resolve",
            "version": 0,
            "steps": [
                {
                    "id": "resolve",
                    "action": {
                        "type": "set_status",
                        "status": "resolved",
                        "note": "Approved workflow conclusion",
                    },
                }
            ],
        },
    )
    run = soar.start_run(store, actor, saved["id"], "soar-resolved", "resolution")
    soar.approve(store, approver, run["id"])
    assert soar.run_due(store) == 1
    value = console_data.summary(store, actor, now - 3600)
    modes = {item["id"]: item["response_mode"] for item in value["cases"]["recent"]}
    assert modes == {"legacy": "manual", "soar-resolved": "completed"}
    assert value["cases"]["response_modes"]["manual"] == 1
    assert {"response_mode": "manual", "status": "triage", "count": 1} in value[
        "cases"
    ]["response_outcomes"]
    assert value["cases"]["response_actions"]["manual"] == 0
    assert value["cases"]["response_actions"]["soar"] == 1
    # A cancelled run still has the actual approved response receipt/feedback;
    # its SOAR-generated judgement must not be relabeled as manual activity.
    with store.control() as db:
        db.execute("UPDATE soar_runs SET state='cancelled' WHERE id=?", (run["id"],))
    cancelled = console_data.summary(store, actor, now - 3600)
    assert {
        item["id"]: item["response_mode"] for item in cancelled["cases"]["recent"]
    } == {"legacy": "manual", "soar-resolved": "attention"}
    assert cancelled["cases"]["response_modes"]["manual"] == 1


@pytest.mark.parametrize(
    "start,end",
    [
        (True, None),
        (0, float("inf")),
        (0, float("nan")),
        (5, 4),
        (-1, 10),
        (0, 400 * 86400),
        (0, 1e12),
    ],
)
def test_malformed_windows(console, start, end):
    store, actor, _ = console
    with pytest.raises(ValueError):
        console_data.summary(store, actor, start, end)


def test_http_adapter_uses_worker_and_rejects_duplicate_or_unknown_parameters(
    console, monkeypatch
):
    store, actor, now = console
    threads = []
    original = console_data.summary

    def tracked(*args, **kwargs):
        threads.append(threading.current_thread().name)
        return original(*args, **kwargs)

    monkeypatch.setattr(console_data, "summary", tracked)
    app = FastAPI()
    from fastapi.responses import JSONResponse

    @app.exception_handler(ValueError)
    async def invalid(request, error):
        return JSONResponse({"detail": str(error)}, status_code=400)

    api_console.register(
        app,
        store,
        SimpleNamespace(stop=threading.Event()),
        lambda request, roles: actor,
        None,
    )
    with TestClient(app) as client:
        assert (
            client.get(
                "/api/console/summary", params={"start": now - 3600, "end": now}
            ).status_code
            == 200
        )
        assert client.get("/api/console/summary?start=1&start=2").status_code == 400
        assert client.get("/api/console/summary?sql=SELECT").status_code == 400
        assert client.get("/api/console/summary?start=no").status_code == 400
    assert threads and all("AnyIO" in name for name in threads)


def test_http_deadline_cancels_worker_and_bounds_entire_request(console, monkeypatch):
    store, actor, _ = console
    stopped = threading.Event()

    def slow_summary(*args, cancel, **kwargs):
        while not cancel():
            time.sleep(0.005)
        stopped.set()
        raise CapacityError("Cancelled")

    monkeypatch.setattr(console_data, "SECONDS", 0.08)
    monkeypatch.setattr(console_data, "summary", slow_summary)
    app = FastAPI()
    from fastapi.responses import JSONResponse

    @app.exception_handler(CapacityError)
    async def capacity(request, error):
        return JSONResponse({"detail": str(error)}, status_code=429)

    api_console.register(
        app,
        store,
        SimpleNamespace(stop=threading.Event()),
        lambda request, roles: actor,
        None,
    )
    with TestClient(app) as client:
        began = time.monotonic()
        response = client.get("/api/console/summary")
        elapsed = time.monotonic() - began
    assert response.status_code == 429
    assert elapsed < 0.5
    assert stopped.wait(0.5)


def test_initial_password_change_flow_is_available_while_other_console_apis_blocked(
    tmp_path,
):
    from sapientia.api import create_app

    app = create_app(Settings(tmp_path, min_free_bytes=0), background=False)
    auth.create_user(
        app.state.store,
        "initial_user",
        "Synthetic-initial-password-2026",
        "viewer",
        must_change=True,
    )
    with TestClient(app) as client:
        login = client.post(
            "/api/login",
            json={
                "name": "initial_user",
                "password": "Synthetic-initial-password-2026",
            },
        )
        assert login.status_code == 200
        who = login.json()
        assert who["must_change"] and not who["mfa_enabled"]
        assert client.get("/api/me").status_code == 200
        assert client.get("/api/me/mfa").status_code == 403
        assert client.get("/api/console/summary").status_code == 403
        changed = client.post(
            "/api/me/password",
            headers={"X-CSRF-Token": who["csrf"]},
            json={
                "current": "Synthetic-initial-password-2026",
                "password": "Synthetic-replacement-password-2026",
            },
        )
        assert changed.status_code == 200
        assert client.get("/api/me").status_code == 401
