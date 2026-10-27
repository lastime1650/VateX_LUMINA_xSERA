import threading

import pytest

from sapientia import access, auth, entities
from sapientia.storage import CapacityError, ConflictError, Settings, Store

PASSWORD = "Synthetic-entity-test-password-2026"


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    entities.initialize(value)
    auth.create_user(value, "admin_a", PASSWORD, "admin", "a")
    auth.create_user(value, "reader_a", PASSWORD, "analyst", "a")
    auth.create_user(value, "admin_b", PASSWORD, "admin", "b")
    yield value
    value.close()


def actor(name="admin_a", tenant="a", indexes=None):
    return {
        "name": name,
        "tenant": tenant,
        "role": "analyst" if name == "reader_a" else "admin",
        "allowed_indexes": ["*"] if indexes is None else indexes,
    }


def definition(alias="alice", indexes=None, **extra):
    return {
        "kind": "user",
        "name": "Alice",
        "aliases": [{"type": "username", "value": alias}],
        "indexes": indexes or ["public"],
        "criticality": 4,
        "tags": ["finance"],
        "version": 0,
        **extra,
    }


def grant(store, name, indexes):
    access.set_for_user(store, actor(), name, indexes)


def test_typed_alias_version_ambiguity_and_tenant_isolation(store):
    saved = entities.save(store, actor(), definition())
    assert saved["version"] == 1
    assert entities.resolve(store, actor(), "username", "alice")["id"] == saved["id"]
    assert entities.list_entities(store, actor("admin_b", "b")) == []
    with pytest.raises(KeyError):
        entities.get(store, actor("admin_b", "b"), saved["id"])
    with pytest.raises(ConflictError, match="ambiguous"):
        entities.save(store, actor(), definition())
    # Type and tenant are both part of alias identity.
    entities.save(
        store,
        actor(),
        {
            **definition(),
            "kind": "host",
            "aliases": [{"type": "hostname", "value": "alice"}],
        },
    )
    entities.save(store, actor("admin_b", "b"), definition())
    updated = entities.save(
        store, actor(), {**definition("alice2"), "version": 1}, saved["id"]
    )
    assert updated["version"] == 2
    with pytest.raises(KeyError):
        entities.resolve(store, actor(), "username", "alice")
    with pytest.raises(ConflictError):
        entities.save(store, actor(), {**definition(), "version": 1}, saved["id"])


def test_inventory_requires_complete_current_index_scope(store):
    broad = entities.save(store, actor(), definition(indexes=["public", "private"]))
    narrow = entities.save(store, actor(), definition("bob"))
    grant(store, "reader_a", ["public"])
    reader = actor("reader_a")  # stale wildcard is intersected with current ACL
    assert [e["id"] for e in entities.list_entities(store, reader)] == [narrow["id"]]
    with pytest.raises(KeyError):
        entities.get(store, reader, broad["id"])
    with pytest.raises(KeyError):
        entities.resolve(store, reader, "username", "alice")
    with pytest.raises(PermissionError):
        entities.save(store, reader, definition("mallory", ["private"]))
    grant(store, "reader_a", [])
    assert entities.list_entities(store, reader) == []


def test_timeline_full_count_sample_and_graph_only_authorized_evidence(store):
    saved = entities.save(store, actor(), definition())
    for tenant, prefix, index, count in [
        ("a", "ok", "public", 7),
        ("a", "secret", "private", 2),
        ("b", "other", "public", 2),
    ]:
        store.ingest(
            tenant,
            [
                {
                    "event_id": f"{prefix}{i}",
                    "event_time": 100 + i,
                    "index": index,
                    "host": "host1",
                    "raw": {
                        "user": "alice",
                        "src_ip": "192.0.2.2",
                        "dest_ip": "192.0.2.3",
                    },
                }
                for i in range(count)
            ],
        )
    store.ingest(
        "a",
        [
            {
                "event_id": "prose",
                "event_time": 105,
                "index": "public",
                "message": "alice owns host2 and connected to 192.0.2.4",
            }
        ],
    )
    store.flush()
    grant(store, "reader_a", ["public"])
    reader = actor("reader_a")
    timeline = entities.timeline(store, reader, saved["id"], 99, 110, 2)
    assert timeline["total"] == 7 and timeline["truncated"]
    assert [e["event_id"] for e in timeline["events"]] == ["ok0", "ok1"]
    graph = entities.graph(store, reader, 99, 110)
    assert graph["matched_events"] == 8
    assert {node["name"] for node in graph["nodes"]} == {
        "Alice",
        "host1",
        "192.0.2.2",
        "192.0.2.3",
    }
    assert len(graph["edges"]) == 6
    assert all(
        edge["relation"] == "co_observed" and edge["count"] == 7
        for edge in graph["edges"]
    )
    assert all(len(edge["evidence"]) == 5 for edge in graph["edges"])
    assert all(
        e["event_id"].startswith("ok")
        for edge in graph["edges"]
        for e in edge["evidence"]
    )
    with pytest.raises(CapacityError, match="node bound"):
        entities.graph(store, reader, 99, 110, limit=2)


def test_graph_canonical_ip_alias_and_unknown_host_omission(store):
    saved = entities.save(
        store,
        actor(),
        {
            **definition(),
            "kind": "ip",
            "aliases": [{"type": "ip", "value": "2001:0db8::1"}],
        },
    )
    assert entities.resolve(store, actor(), "ip", "2001:db8::1")["id"] == saved["id"]
    store.ingest(
        "a", [{"event_time": 100, "index": "public", "raw": {"src_ip": "2001:db8::1"}}]
    )
    store.flush()
    graph = entities.graph(store, actor(), 0, 101)
    assert len(graph["nodes"]) == 1 and graph["nodes"][0]["id"] == saved["id"]


def test_email_device_aliases_and_cross_subtype_ambiguity(store):
    email = entities.save(
        store,
        actor(),
        {
            **definition(),
            "aliases": [{"type": "email", "value": "alice@example.invalid"}],
        },
    )
    device = entities.save(
        store,
        actor(),
        {
            **definition(),
            "name": "Device One",
            "kind": "device",
            "aliases": [{"type": "device_id", "value": "dev-1"}],
        },
    )
    with pytest.raises(ConflictError, match="ambiguous"):
        entities.save(store, actor(), definition("alice@example.invalid"))
    store.ingest(
        "a",
        [
            {
                "event_id": "explicit",
                "event_time": 100,
                "index": "public",
                "raw": {
                    "security": {"user": "alice@example.invalid", "device_id": "dev-1"}
                },
            }
        ],
    )
    store.flush()
    graph = entities.graph(store, actor(), 99, 101)
    assert {node["id"] for node in graph["nodes"]} == {email["id"], device["id"]}
    assert (
        len(graph["edges"]) == 1
        and graph["edges"][0]["evidence"][0]["event_id"] == "explicit"
    )
    assert entities.timeline(store, actor(), email["id"], 99, 101)["total"] == 1


def test_disabled_principal_denied_and_graph_revocation_rechecked(store, monkeypatch):
    grant(store, "reader_a", ["public"])
    original = store.analytics_query

    def revoke(*args, **kwargs):
        result = original(*args, **kwargs)
        with store.control() as db:
            db.execute("UPDATE users SET disabled=1 WHERE name='reader_a'")
        return result

    monkeypatch.setattr(store, "analytics_query", revoke)
    with pytest.raises(PermissionError):
        entities.graph(store, actor("reader_a"), 0, 100)
    with pytest.raises(PermissionError):
        entities.list_entities(store, actor("reader_a"))


def test_query_slot_cancellation_and_post_query_revocation(store, monkeypatch):
    saved = entities.save(store, actor(), definition())
    for _ in range(store.settings.workers):
        assert store.query_slots.acquire(False)
    try:
        with pytest.raises(CapacityError, match="concurrency"):
            entities.timeline(store, actor(), saved["id"], 0, 100)
    finally:
        for _ in range(store.settings.workers):
            store.query_slots.release()
    stop = threading.Event()
    stop.set()
    with pytest.raises(RuntimeError, match="cancelled"):
        entities.graph(store, actor(), 0, 100, cancel=stop)
    grant(store, "reader_a", ["public"])
    original = store.analytics_query

    def revoke(*args, **kwargs):
        result = original(*args, **kwargs)
        grant(store, "reader_a", [])
        return result

    monkeypatch.setattr(store, "analytics_query", revoke)
    with pytest.raises(PermissionError, match="changed"):
        entities.timeline(store, actor("reader_a"), saved["id"], 0, 100)


@pytest.mark.parametrize(
    "change",
    [
        {"kind": []},
        {"aliases": [{"type": [], "value": "x"}]},
        {"indexes": ["*"]},
        {"criticality": True},
        {"aliases": [{"type": "ip", "value": "bad"}]},
        {"version": -1},
    ],
)
def test_reject_malformed_entity_input(store, change):
    with pytest.raises(ValueError):
        entities.save(store, actor(), {**definition(), **change})
