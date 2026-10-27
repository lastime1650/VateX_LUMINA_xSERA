"""Projection retention follows durable originals, holds and recovery fences."""

import time

import pytest

from tests.test_virtual_telemetry import client, register
from tests.capacity_helpers import purge as capacity_purge
from tools.simulation.loggers import generate


def load(client):
    source = register(client, "windows")
    events, _ = generate("windows", 2)
    path = "/api/v2/sources/"+source["id"]+"/intake"
    body = {"version": 1, "events": events, "cursor": "first", "checkpoint_version": 0}
    assert client.post(path, json=body).status_code == 202
    store = client.app.state.store
    store.flush()
    return store, source, path, body


def counts(store):
    with store.control() as db:
        return tuple(db.execute("SELECT count(*) FROM "+table).fetchone()[0]
                     for table in ("receipts", "source_event_receipts", "event_projections"))


def test_permanent_originals_then_capacity_retirement_allows_new_incarnation(client):
    store, source, path, body = load(client)
    assert counts(store) == (2, 2, 2)
    assert store.retain(time.time()+100*86400) == 0
    assert counts(store) == (2, 2, 2)
    assert store.search("a",{"query":"*"},allowed_indexes=[source["index"]])["returned"] == 2
    assert capacity_purge(store) == 2
    assert counts(store) == (0, 0, 0)
    # Refresh the disposable login after the future maintenance-time check.
    login = client.post("/api/login", json={"name": "owner", "password": "Virtual-simulation-password-2026"})
    client.headers["X-CSRF-Token"] = login.json()["csrf"]
    body["cursor"], body["checkpoint_version"] = "second", 1
    reply = client.post(path, json=body)
    assert reply.status_code == 202, reply.text
    assert reply.json()["accepted"] == 2
    store.flush()
    assert counts(store) == (2, 2, 2)


def test_index_hold_preserves_projection_and_original_identity(client):
    store, source, _, _ = load(client)
    store.segments.save_policy("a", source["index"], {"hot_days": 1, "warm_days": 2, "cold_days": 3,
                               "retention_days": 0, "hold": True, "version": 0})
    assert store.retain(time.time()+100*86400) == 0
    assert capacity_purge(store) == 0
    assert counts(store) == (2, 2, 2)


def test_crash_after_original_delete_recovery_retires_derivatives(client):
    store, source, path, body = load(client)
    def crash():
        raise RuntimeError("injected retention crash")
    with pytest.raises(RuntimeError, match="injected"):
        capacity_purge(store, after_delete=crash)
    assert counts(store) == (2, 2, 2)
    assert client.post(path, json=body).status_code == 409
    store.flush()
    assert counts(store) == (0, 0, 0)
