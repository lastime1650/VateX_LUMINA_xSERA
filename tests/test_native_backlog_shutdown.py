# ruff: noqa: F811 -- Imported pytest fixtures are injected by argument name.
"""Bounded native-source scheduling and truthful shutdown; no OS/network effects."""

import json
import sqlite3

import pytest
from sapientia.endpoint_agent.Agent import core
from sapientia.endpoint_agent.Agent.Windows import collector as windows
from tests.test_agent_remediation import client, sensor, xml  # noqa: F401


def channel_queries(monkeypatch, tables):
    queries = []

    def query(name, count=100, after=None, record_id=None):
        queries.append((name, count, after, record_id))
        rows = tables.get(name, [])
        if record_id is not None:
            return [
                r
                for r in rows
                if int(r.findtext("{*}System/{*}EventRecordID")) == record_id
            ]
        return (
            rows[-count:]
            if after is None
            else [
                r for r in rows if int(r.findtext("{*}System/{*}EventRecordID")) > after
            ][:count]
        )

    monkeypatch.setattr(windows, "_xml_events", query)
    return queries


def test_idle_quota_is_borrowed_without_requery_and_rare_sources_are_preserved(
    sensor, monkeypatch
):
    sysmon = "Microsoft-Windows-Sysmon/Operational"
    security = "Security"
    tables = {
        sysmon: [xml(i, 7, {"Image": r"C:\owned.exe"}) for i in range(1, 16)],
        security: [xml(1, 4625)],
    }
    queries = channel_queries(monkeypatch, tables)
    produced = sensor._log_events("HOST", limit=10)
    counts = {
        name: sum(r["data"]["event"]["provider"] == name for r in produced)
        for name in tables
    }
    assert counts == {sysmon: 9, security: 1}
    assert len(produced) == 10
    assert sum(q[0] == sysmon and q[1] == 2000 for q in queries) == 1
    assert sensor.providers[sysmon]["backlog_confirmed"] is True
    assert sensor.providers[sysmon]["state"] == "degraded"
    assert sensor.providers[sysmon]["known_eligible_buffered_records"] == 6
    assert sensor.providers[sysmon]["record_span_is_not_event_count"] is True
    assert sensor.providers[sysmon]["unused_channel_budget_borrowed"] is True
    assert sensor.cursors[sysmon]["record"] == 9


def test_unsupported_record_span_does_not_become_selected_event_backlog(
    sensor, monkeypatch
):
    sysmon = "Microsoft-Windows-Sysmon/Operational"
    rows = [xml(1, 7), xml(50_000, 2)]  # EventID2 has no collector action.
    channel_queries(monkeypatch, {sysmon: rows})
    output = sensor._log_events("HOST", limit=1)
    assert len(output) == 1
    assert sensor.providers[sysmon]["unread_record_span"] == 49_999
    assert sensor.providers[sysmon]["backlog_confirmed"] is False
    assert sensor.providers[sysmon]["backlog_uncertain"] is True
    assert sensor.providers[sysmon]["state"] == "ready"


def test_fully_borrowed_drain_clears_confirmed_backlog(sensor, monkeypatch):
    sysmon = "Microsoft-Windows-Sysmon/Operational"
    channel_queries(monkeypatch, {sysmon: [xml(i, 7) for i in range(1, 9)]})
    assert len(sensor._log_events("HOST", limit=10)) == 8
    assert sensor.cursors[sysmon]["record"] == 8
    assert sensor.providers[sysmon]["backlog_confirmed"] is False
    assert sensor.providers[sysmon]["state"] == "ready"


def ack(body):
    events = body["events"]
    return {
        "durable": True,
        "accepted": len(events),
        "duplicate": 0,
        "results": [{"id": e["id"], "quarantined": False} for e in events],
    }


def seed(client, amount=1):
    client.queue.add_many(
        [
            {"id": f"owned-{i}", "data": {"event": {"action": "fixture_observation"}}}
            for i in range(amount)
        ]
    )
    client._shutdown_state = {"workers_quiesced": True, "transport_only": True}


def test_shutdown_only_delivers_to_ingest_and_exact_ack_drains_tail(client):
    seed(client, 403)
    client.config["send_batch_size"] = 200
    routes = []

    def post(route, body):
        routes.append(route)
        return ack(body)

    client._post = post
    client._shutdown_drain()
    assert routes == ["/api/agent/ingest"] * 3
    assert client.sent == 403 and client.queue.size() == 0
    assert client._shutdown_state["drain_state"] == "completed"
    assert client._shutdown_state["drain_budget_seconds"] == 15
    assert client._shutdown_state["durable_tail_retained"] is False


def test_shutdown_invalid_or_unacknowledged_delivery_keeps_durable_rows(client):
    seed(client)
    client._post = lambda *args: {"durable": False, "results": []}
    client._shutdown_drain()
    assert client.queue.size() == 1 and client.sent == 0
    assert client._shutdown_state["drain_state"] == "failed"
    assert client._shutdown_state["error_type"] == "RuntimeError"
    assert client._shutdown_state["durable_tail_retained"] is True


def test_shutdown_caller_deadline_ignores_late_ack_without_thread_sqlite_access(
    client, monkeypatch
):
    seed(client)
    client.config["shutdown_drain_seconds"] = 999
    client._post = lambda route, body: ack(body)
    active = []

    class SlowRequest:
        def __init__(self, *, target, name, daemon):
            assert daemon is True
            self.target = target
            active.append(self)

        def start(self):
            pass

        def join(self, timeout):
            assert 0 < timeout <= 30

        def is_alive(self):
            return True

    monkeypatch.setattr(core.threading, "Thread", SlowRequest)
    client._shutdown_drain()
    assert client.queue.size() == 1
    assert client._shutdown_state["drain_budget_seconds"] == 30
    assert client._shutdown_state["drain_state"] == "deadline_reached"
    assert client._shutdown_state["late_ack_ignored"] is True
    active[0].target()  # Request returns after the deadline; no settle callback.
    assert client.queue.size() == 1 and client.sent == 0


def test_joined_late_capture_gets_drained_and_final_status_matches_sqlite(
    client, monkeypatch
):
    def capture():
        client.stop.wait()
        queue = client._worker_queue()
        try:
            queue.add_many(
                [
                    {
                        "id": "late-capture",
                        "data": {"event": {"action": "fixture_observation"}},
                    }
                ]
            )
        finally:
            queue.close()

    client._capture_loop = capture
    client._evaluation_loop = lambda: client.stop.wait()
    client._control_loop = lambda: client.stop.wait()
    client._flush_cycle = lambda: client.stop.set()
    client._post = lambda route, body: ack(body)
    client._run_locked()
    final = json.loads(client.status_path.read_text())
    with sqlite3.connect(client.directory / "pending.sqlite3") as db:
        assert db.execute("SELECT count(*) FROM pending").fetchone()[0] == 0
    assert final["pending"] == 0 and final["sent_since_start"] == 1
    assert final["shutdown"]["workers_quiesced"] is True
    assert final["shutdown"]["final_snapshot"] is True
    assert final["shutdown"]["drain_state"] == "completed"


def test_live_worker_never_authorizes_shutdown_transport_drain(client):
    seed(client)

    class ActiveWorker:
        def join(self, timeout):
            pass

        def is_alive(self):
            return True

    client._capture_thread = ActiveWorker()
    client._flush_cycle = lambda: None
    client._control_cycle = lambda *args: None
    client._post = lambda *args: pytest.fail(
        "No transport allowed while a data worker is active"
    )
    with pytest.raises(RuntimeError, match="did not stop"):
        client._run_locked(once=True)
    final = json.loads(client.status_path.read_text())
    assert final["pending"] == 1
    assert final["shutdown"]["workers_quiesced"] is False
    assert final["shutdown"]["drain_state"] == "skipped_workers_active"
    assert final["shutdown"]["snapshot_is_quiescent"] is False


@pytest.mark.parametrize(
    "confirmed,expected",
    [(True, "degraded"), (False, "ok")],
    ids=["confirmed-selected-backlog", "uncertain-record-span"],
)
def test_heartbeat_degrades_only_confirmed_source_selection_backlog(
    client, confirmed, expected
):
    client._provider_health = {
        "providers": {
            "sysmon": {
                "state": "ready",
                "backlog": True,
                "backlog_confirmed": confirmed,
                "unread_record_span": 87_717,
                "record_span_is_not_event_count": True,
            }
        }
    }
    captured = {}

    def post(route, body):
        captured.update(route=route, body=body)
        return {}

    client._post = post
    client.heartbeat()
    assert captured["route"] == "/api/agent/heartbeat"
    assert captured["body"]["health"]["status"] == expected


def test_shutdown_network_failure_retains_tail_without_credential_renewal(client):
    seed(client)

    def failed(*args):
        raise ConnectionError("fixture-only transport outage")

    client._post = failed
    client._shutdown_drain()
    assert client.queue.size() == 1 and client.sent == 0
    assert client._shutdown_state["drain_state"] == "failed"
    assert client._shutdown_state["error_type"] == "ConnectionError"
    assert client._shutdown_state["durable_tail_retained"] is True
