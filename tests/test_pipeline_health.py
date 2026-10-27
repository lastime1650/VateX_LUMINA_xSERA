import json
import time

import pytest

from sapientia import access, auth, pipeline, source_health
from sapientia.storage import ConflictError, Settings, Store


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    for name, role, tenant in [
        ("admin_a", "admin", "a"),
        ("analyst_a", "analyst", "a"),
        ("admin_b", "admin", "b"),
    ]:
        auth.create_user(
            value, name, "Synthetic-pipeline-health-password-2026", role, tenant
        )
    yield value
    value.close()


def actor(name="admin_a", tenant="a", role="admin", scope=None):
    return {
        "name": name,
        "tenant": tenant,
        "role": role,
        "allowed_indexes": ["*"] if scope is None else scope,
    }


def definition(**kw):
    return {
        "source": "vendor",
        "mappings": {"raw.security.user": "raw.vendor_user"},
        "redact_fields": ["raw.password"],
        "required_fields": ["raw.vendor_user"],
        **kw,
    }


def save(store, data=None, version=0):
    return pipeline.save(
        store,
        actor(),
        "vendor_parser",
        {"version": version, "definition": definition() if data is None else data},
    )


def test_pipeline_redaction_route_and_receipt_compatibility(store):
    save(store, definition(route_index="endpoint"))
    event = {
        "event_id": "stable",
        "source": "vendor",
        "raw": {"vendor_user": "alice", "password": "Do-not-persist-this-secret"},
    }
    assert store.ingest("a", [event])["accepted"] == 1
    store.flush()
    result = store.search(
        "a", {"query": "search * | table index raw.password raw.security.user"}
    )["rows"]
    assert result == [
        {
            "index": "endpoint",
            "raw.password": "[REDACTED]",
            "raw.security.user": "alice",
        }
    ]
    save(store, definition(route_index="changed"), version=1)
    assert store.ingest("a", [event])["duplicate"] == 1
    assert (
        store.search("a", {"query": "search * | stats count"})["rows"][0]["count"] == 1
    )


def test_decoded_secret_cannot_escape_redaction_through_mapping_or_message(store):
    policy = definition(
        decode_message_json=True,
        mappings={
            "raw.vendor_user": "raw.parsed.user",
            "raw.copied_secret": "raw.parsed.password",
        },
        redact_fields=["raw.parsed.password", "message"],
    )
    save(store, policy)
    good = {
        "event_id": "decoded-secret",
        "source": "vendor",
        "message": '{"user":"alice","password":"No-Secret-Persistence"}',
        "raw": {},
    }
    assert store.ingest("a", [good])["accepted"] == 1
    assert pipeline.quarantine(store, actor())["total_count"] == 0
    store.flush()
    row = store.search("a", {"query": "search * | table raw message"})["rows"][0]
    assert "No-Secret-Persistence" not in str(row)
    raw = json.loads(row["raw"])
    # Whole-message redaction also removes decoded copies of that body. A
    # policy that needs selected decoded identities should redact only its
    # sensitive fields; their serialized message copies are scrubbed too.
    assert raw["vendor_user"] == "[REDACTED]"
    assert raw["copied_secret"] == "[REDACTED]"
    assert row["message"] == "[REDACTED]"
    bad = {
        "event_id": "bad-secret",
        "source": "vendor",
        "message": "invalid No-Secret-Persistence",
        "raw": {},
    }
    assert store.ingest("a", [bad])["quarantined"] == 1
    assert "No-Secret-Persistence" not in str(pipeline.quarantine(store, actor()))


def test_quarantine_is_durable_sanitized_and_replayed_once(store):
    save(store)
    bad = {
        "event_id": "failure",
        "source": "vendor",
        "raw": {"password": "Private-content"},
    }
    ack = store.ingest("a", [bad])
    assert ack["accepted"] == ack["quarantined"] == 1
    assert store.flush() == 0
    row = pipeline.quarantine(store, actor())["rows"][0]
    assert row["payload"]["raw"]["password"] == "[REDACTED]"
    assert "Private-content" not in str(row)
    assert store.ingest("a", [bad])["duplicate"] == 1
    assert pipeline.replay(store, actor(), {"event_ids": ["failure"]})["queued"] == 0
    save(store, definition(required_fields=[]), version=1)
    assert pipeline.replay(store, actor(), {"event_ids": ["failure"]})["queued"] == 1
    assert pipeline.quarantine(store, actor())["total_count"] == 0
    store.flush()
    assert store.ingest("a", [bad])["duplicate"] == 1
    with pytest.raises(KeyError):
        pipeline.replay(store, actor(), {"event_ids": ["failure"]})


def test_reject_rolls_back_batch_and_quarantine_has_no_lifetime_quota(store, monkeypatch):
    save(store, definition(on_failure="reject"))
    with pytest.raises(ValueError):
        store.ingest(
            "a",
            [
                {
                    "event_id": "good",
                    "source": "vendor",
                    "raw": {"vendor_user": "alice"},
                },
                {"event_id": "bad", "source": "vendor"},
            ],
        )
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 0
    save(store, definition(), version=1)
    monkeypatch.setattr(pipeline, "MAX_QUARANTINE_EVENTS", 0)
    events = [
        {"event_id": "good", "source": "vendor", "raw": {"vendor_user": "alice"}},
        {"event_id": "bad", "source": "vendor", "raw": {"password": "Do-not-retain-this-secret"}},
    ]
    accepted = store.ingest("a", events)
    assert accepted["accepted"] == 2 and accepted["quarantined"] == 1
    assert store.ingest("a", events)["duplicate"] == 2
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 2
        assert db.execute("SELECT count(*) FROM queue").fetchone()[0] == 1
    held = pipeline.quarantine(store, actor())
    assert held["total_count"] == 1
    assert held["rows"][0]["payload"]["raw"]["password"] == "[REDACTED]"
    assert "Do-not-retain-this-secret" not in str(held)


def test_parser_preview_json_redaction_and_scoped_registry(store):
    result = pipeline.preview(
        store,
        actor(),
        {
            "definition": definition(
                decode_message_json=True,
                mappings={"raw.security.user": "raw.parsed.user"},
                required_fields=["raw.security.user"],
                redact_fields=["raw.parsed.password"],
            ),
            "event": {
                "source": "vendor",
                "message": '{"user":"alice","password":"secret"}',
            },
        },
    )
    assert result["persisted"] is False and not result["errors"]
    assert result["event"]["raw"]["parsed"]["password"] == "[REDACTED]"
    save(store)
    with pytest.raises(ConflictError):
        save(store)
    assert pipeline.list_for(store, actor("admin_b", "b")) == []
    with pytest.raises(PermissionError):
        pipeline.list_for(store, actor(scope=["main"]))
    with pytest.raises(PermissionError):
        pipeline.save(
            store,
            actor("analyst_a", role="analyst"),
            "no",
            {"version": 0, "definition": definition()},
        )


@pytest.mark.parametrize(
    "body",
    [
        {"required_fields": [{}]},
        {"on_failure": []},
        {"enabled": 1},
        {"route_index": "*"},
        {"mappings": {"raw.target": "tenant"}},
    ],
)
def test_invalid_parser_definitions_fail_cleanly(body):
    with pytest.raises(ValueError):
        pipeline.validate(definition(**body))


def test_source_silence_lag_missing_and_tenant_scope(store):
    saved = source_health.save(
        store,
        actor(),
        {
            "version": 0,
            "definition": {
                "name": "Vendor health",
                "source": "vendor",
                "indexes": ["public"],
                "max_lag": 10,
                "required_fields": ["raw.security.user"],
            },
        },
    )
    result = source_health.evaluate(store, actor(), saved["id"])
    assert result["issues"] == ["silent"] and result["recent_events"] == 0
    now = time.time()
    store.ingest(
        "a",
        [
            {
                "event_id": "old-arrival",
                "source": "vendor",
                "index": "public",
                "event_time": now - 100,
            }
        ],
    )
    store.ingest(
        "b",
        [
            {
                "event_id": "other",
                "source": "vendor",
                "index": "public",
                "raw": {"security": {"user": "not-a"}},
            }
        ],
    )
    store.ingest(
        "a",
        [
            {
                "event_id": "private",
                "source": "vendor",
                "index": "private",
                "raw": {"security": {"user": "not-public"}},
            }
        ],
    )
    store.flush()
    result = source_health.evaluate(store, actor(), saved["id"], now=time.time() + 1)
    assert result["recent_events"] == 1
    assert set(result["issues"]) == {"lagging", "incomplete"}
    assert result["missing_fields"] == {"raw.security.user": 1}
    assert source_health.list_for(store, actor("admin_b", "b")) == []
    assert source_health.list_for(store, actor(scope=["private"])) == []
    access.set_for_user(store, actor(), "admin_a", ["private"])
    with pytest.raises(KeyError):
        source_health.evaluate(store, actor(), saved["id"])


def test_source_monitor_owner_disable_is_visible_error(store):
    saved = source_health.save(
        store,
        actor(),
        {
            "version": 0,
            "definition": {"name": "Health", "source": "vendor", "indexes": ["main"]},
        },
    )
    with store.control() as db:
        db.execute("UPDATE users SET disabled=1 WHERE name='admin_a'")
    assert source_health.run_due(store, now=time.time() + 1) == 1
    rows = source_health.list_for(store, actor("analyst_a", role="analyst"))
    assert (
        rows[0]["id"] == saved["id"] and rows[0]["result"]["error"] == "PermissionError"
    )
