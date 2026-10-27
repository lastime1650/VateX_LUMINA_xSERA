"""Synthetic intake least privilege, live admission authority and privacy copies."""

import copy
import json
import time

import pytest
from fastapi.testclient import TestClient

from sapientia import access, auth, fortigate, normalization, pipeline, xdr_bridge
from sapientia import agent_distribution as ad
from sapientia.api import create_app
from sapientia.storage import Settings, Store
from tests.test_agent_distribution import enrolled
from tests.test_fortigate import sample
from tests.test_xdr_bridge import event
from tools.qualification import certificate

PASSWORD = "Synthetic-intake-governance-password-2026"
WHO = {"name": "admin_a", "tenant": "a", "role": "admin", "allowed_indexes": ["*"]}


@pytest.fixture
def store(tmp_path):
    result = Store(Settings(tmp_path / "data", min_free_bytes=0))
    auth.create_user(result, "admin_a", PASSWORD, tenant="a")
    auth.create_user(result, "admin_b", PASSWORD, tenant="b")
    yield result
    result.close()


def count_admissions(store):
    with store.control() as db:
        return tuple(
            db.execute(
                "SELECT (SELECT count(*) FROM receipts),(SELECT count(*) FROM queue),(SELECT count(*) FROM ingest_quarantine)"
            ).fetchone()
        )


def test_new_collector_exact_scope_and_issuer_binding(store):
    token = auth.issue_token(store, WHO, "limited", allowed_indexes=["public"])
    identity = auth.identity(store, bearer=token)
    assert (
        identity["allowed_indexes"] == ["public"] and identity["issued_by"] == "admin_a"
    )
    assert (
        auth.ingest_authorized(
            store, identity, [{"event_id": "public", "index": "public"}]
        )["accepted"]
        == 1
    )
    for scope in (["*"], [], ["public", "*"], ["public", "public"]):
        with pytest.raises(ValueError):
            auth.issue_token(store, WHO, "bad", allowed_indexes=scope)
    with pytest.raises(PermissionError):
        auth.issue_token(store, {**WHO, "tenant": "b"}, "forged")
    access.set_for_user(store, WHO, "admin_a", ["public"])
    with pytest.raises(PermissionError):
        auth.issue_token(store, WHO, "private", allowed_indexes=["private"])
    assert auth.identity(store, bearer=token)["allowed_indexes"] == ["public"]
    access.set_for_user(store, WHO, "admin_a", [])
    assert auth.identity(store, bearer=token) is None
    with pytest.raises(PermissionError):
        auth.ingest_authorized(
            store, identity, [{"event_id": "stale", "index": "public"}]
        )
    assert count_admissions(store) == (1, 1, 0)


@pytest.mark.parametrize(
    "column,value",
    [("disabled", 1), ("must_change", 1), ("role", "analyst"), ("tenant", "b")],
)
def test_token_and_stale_snapshot_stop_when_issuer_changes(store, column, value):
    token = auth.issue_token(store, WHO, "current")
    snapshot = auth.identity(store, bearer=token)
    with store.control() as db:
        db.execute("UPDATE users SET " + column + "=? WHERE name='admin_a'", (value,))
    assert auth.identity(store, bearer=token) is None
    with pytest.raises(PermissionError):
        auth.ingest_authorized(store, snapshot, [{"event_id": "denied"}])
    assert count_admissions(store) == (0, 0, 0)


def test_default_rotation_expiry_and_revocation(store):
    token = auth.issue_token(store, WHO, "default")
    assert auth.identity(store, bearer=token)["allowed_indexes"] == ["main"]
    assert auth.list_tokens(store, WHO)[0]["status"] == "active"
    with store.control() as db:
        db.execute(
            "UPDATE tokens SET expires=? WHERE digest=?",
            (time.time() - 1, auth.digest(token)),
        )
    assert auth.identity(store, bearer=token) is None
    token = auth.issue_token(store, WHO, "revoked")
    snapshot = auth.identity(store, bearer=token)
    auth.revoke_token(store, WHO, auth.digest(token))
    assert auth.identity(store, bearer=token) is None
    with pytest.raises(PermissionError):
        auth.ingest_authorized(store, snapshot, [{"event_id": "revoked"}])
    legacy = "a" * 43
    with store.control() as db:
        db.execute(
            "INSERT INTO tokens VALUES(?,?,?,?,?,?)",
            (
                auth.digest(legacy),
                "legacy",
                "a",
                "ingest",
                time.time(),
                time.time() + 1000,
            ),
        )
    auth.initialize(store)
    assert auth.identity(store, bearer=legacy) is None
    assert (
        next(row for row in auth.list_tokens(store, WHO) if row["name"] == "legacy")[
            "status"
        ]
        == "legacy_requires_rotation"
    )


def test_cross_index_and_parser_route_reject_batch_atomically(store):
    who = auth.identity(
        store, bearer=auth.issue_token(store, WHO, "public", allowed_indexes=["public"])
    )
    with pytest.raises(PermissionError):
        auth.ingest_authorized(
            store,
            who,
            [
                {"event_id": "good", "index": "public"},
                {"event_id": "bad", "index": "private"},
            ],
        )
    assert count_admissions(store) == (0, 0, 0)
    pipeline.save(
        store,
        WHO,
        "route",
        {
            "version": 0,
            "definition": {
                "source": "vendor",
                "route_index": "private",
                "required_fields": ["raw.missing"],
            },
        },
    )
    with pytest.raises(PermissionError):
        auth.ingest_authorized(
            store,
            who,
            [
                {"event_id": "good", "index": "public"},
                {"event_id": "route", "source": "vendor", "index": "public"},
            ],
        )
    assert count_admissions(store) == (0, 0, 0)


@pytest.mark.parametrize("adapter", ["http", "hec", "otlp"])
def test_actual_intake_routes_enforce_token_index_scope(tmp_path, adapter):
    app = create_app(Settings(tmp_path / "api", min_free_bytes=0), background=False)
    auth.create_user(app.state.store, "admin_a", PASSWORD, tenant="a")
    token = auth.issue_token(
        app.state.store,
        WHO,
        "api",
        allowed_indexes=["main"] if adapter == "otlp" else ["public"],
    )
    with TestClient(app) as client:
        headers = {"Authorization": "Bearer " + token}
        if adapter == "http":
            path, good = (
                "/api/v1/events",
                {"events": [{"event_id": "allowed", "index": "public"}]},
            )
            bad = {"events": [{"event_id": "bad", "index": "private"}]}
        elif adapter == "hec":
            path, good = (
                "/services/collector",
                {
                    "event": {"user": "synthetic"},
                    "index": "public",
                    "fields": {"vatex_event_id": "allowed"},
                },
            )
            bad = {**good, "index": "private", "fields": {"vatex_event_id": "bad"}}
            headers["Authorization"] = "Splunk " + token
        else:

            def payload(index, identifier):
                return {
                    "resourceLogs": [
                        {
                            "scopeLogs": [
                                {
                                    "logRecords": [
                                        {
                                            "body": {"stringValue": "synthetic"},
                                            "attributes": [
                                                {
                                                    "key": "vatex.index",
                                                    "value": {"stringValue": index},
                                                },
                                                {
                                                    "key": "vatex.event_id",
                                                    "value": {
                                                        "stringValue": identifier
                                                    },
                                                },
                                            ],
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }

            path, good, bad = (
                "/v1/logs",
                payload("public", "allowed"),
                payload("private", "bad"),
            )
        response = client.post(path, headers=headers, json=good)
        assert response.status_code in {200, 202}, response.text
        if adapter == "otlp":
            # This adapter intentionally targets main; arbitrary attributes do
            # not grant routing authority. A collector without main is denied.
            denied = auth.issue_token(
                app.state.store, WHO, "other", allowed_indexes=["public"]
            )
            headers["Authorization"] = "Bearer " + denied
        response = client.post(path, headers=headers, json=bad)
        assert response.status_code == 403, response.text
        assert count_admissions(app.state.store) == (1, 1, 0)


@pytest.mark.parametrize("adapter", ["fortigate", "xdr", "enrolled"])
def test_adapter_admission_rechecks_after_initial_authorization(
    store, tmp_path, monkeypatch, adapter, release_signer
):
    original = store.ingest

    def race(*args, **kwargs):
        with store.control() as db:
            db.execute("UPDATE users SET disabled=1 WHERE name='admin_a'")
        return original(*args, **kwargs)

    if adapter == "enrolled":
        cert, _ = certificate(tmp_path)
        service = ad.Distribution(
            store,
            {"endpoint_url": "https://127.0.0.1:8788", "ca_pem": cert.read_bytes()},
        )
        identity, _, _, _ = enrolled(service, host="HOST-01")
        call = lambda: service.ingest(
            identity["credential"], {"events": [event(host="HOST-01")]}
        )
    elif adapter == "fortigate":
        call = lambda: fortigate.intake(
            store, WHO, {"index": "public", "events": [{"id": "race", "log": sample()}]}
        )
    else:
        call = lambda: xdr_bridge.intake(
            store, WHO, {"format": "agent", "index": "public", "events": [event()]}
        )
    monkeypatch.setattr(store, "ingest", race)
    with pytest.raises(PermissionError):
        call()
    assert count_admissions(store) == (0, 0, 0)


@pytest.mark.parametrize(
    "secret", ["Synthetic-PII-Email@example.invalid", 'secret"\\\u2603', "x"]
)
def test_redaction_removes_all_known_raw_derived_encoded_copies_and_quarantine(
    store, secret
):
    pipeline.save(
        store,
        WHO,
        "privacy",
        {
            "version": 0,
            "definition": {
                "source": "vendor",
                "decode_message_json": True,
                "redact_fields": ["raw.user"],
                "mappings": {
                    "raw.security.user": "raw.parsed.user",
                    "raw.copy": "raw.parsed.user",
                },
                "required_fields": ["raw.missing"],
            },
        },
    )
    message = json.dumps({"user": secret, "public": "allowed"})
    source = {
        "event_id": "private",
        "source": "vendor",
        "message": message,
        "raw": {
            "user": secret,
            "line": "header " + message,
            "nested": [{"duplicate": secret}],
        },
    }
    original = copy.deepcopy(source)
    assert store.ingest("a", [source])["quarantined"] == 1
    assert source == original
    row = pipeline.quarantine(store, WHO)["rows"][0]
    serialized = (
        json.dumps(row["payload"]["raw"], ensure_ascii=False)
        + row["payload"]["message"]
    )
    assert secret not in serialized and json.dumps(secret)[1:-1] not in serialized
    assert row["payload"]["raw"].get("security", {}).get("user") is None
    assert row["payload"]["raw"]["copy"] == "[REDACTED]"
    assert row["payload"]["raw"]["parsed"]["public"] == "allowed"
    assert store.ingest("a", [source])["duplicate"] == 1


def test_recomputed_canonical_metadata_preserves_actual_parser_provenance(store):
    pipeline.save(
        store,
        WHO,
        "map",
        {
            "version": 0,
            "definition": {
                "source": "vendor",
                "mappings": {"raw.security.user": "raw.vendor_user"},
            },
        },
    )
    store.ingest(
        "a",
        [
            {
                "event_id": "mapped",
                "source": "vendor",
                "raw": {"vendor_user": "synthetic"},
            }
        ],
    )
    with store.control() as db:
        record = json.loads(db.execute("SELECT payload FROM queue").fetchone()[0])
    security = record["raw"]["security"]
    assert security["user"] == "synthetic"
    assert security["mapping"] == "managed-parser-v1"
    assert security["provenance"]["user"] == ["raw.vendor_user"]
    assert normalization.normalize(record) == record


@pytest.mark.parametrize(
    "canonical",
    [
        None,
        [],
        {"src_ip": "not-ip"},
        {"user": {"name": "bad"}},
        {"schema": "forged", "user": "alice"},
        {"version": True, "user": "alice"},
        {"user": "other"},
        {"outcome": []},
        {"huge": 10**500},
    ],
)
def test_invalid_canonical_never_enters_durable_state(store, canonical):
    with pytest.raises(ValueError):
        store.ingest(
            "a",
            [
                {"event_id": "first"},
                {
                    "event_id": "invalid",
                    "raw": {"user": "alice", "security": canonical},
                },
            ],
        )
    assert count_admissions(store) == (0, 0, 0)


def test_partial_source_canonical_is_validated_and_cannot_block_enrichment():
    result = normalization.normalize(
        {
            "raw": {
                "security": {"device_id": "synthetic-device"},
                "user": "alice",
                "action": "login_failed",
            }
        }
    )
    value = result["raw"]["security"]
    assert value["user"] == "alice" and value["outcome"] == "failure"
    assert value["device_id"] == "synthetic-device"
    assert value["unverified_fields"] == ["device_id"]
    assert normalization.normalize(result) == result


def test_fortigate_canonical_preserved_but_source_conflict_rejected():
    record = fortigate.envelope({"id": "forti", "log": sample()}, "firewall")
    assert normalization.normalize(record) == record
    assert record["raw"]["security"]["outcome"] == "blocked"
    record["raw"]["security"]["src_ip"] = "192.0.2.99"
    with pytest.raises(ValueError, match="conflicts"):
        normalization.normalize(record)


def test_fortigate_unspecified_addresses_remain_raw_without_fake_entity():
    record = fortigate.envelope(
        {"id": "unspecified", "log": sample(srcip="0.0.0.0", dstip="::")}, "firewall"
    )
    assert record["raw"]["fortigate"]["srcip"] == "0.0.0.0"
    assert "src_ip" not in record["raw"]["security"]
    assert "dest_ip" not in record["raw"]["security"]


def test_redaction_handles_noncanonical_and_nested_json_escapes(store):
    pipeline.save(
        store,
        WHO,
        "escaped",
        {
            "version": 0,
            "definition": {
                "source": "vendor",
                "redact_fields": ["raw.user"],
                "required_fields": ["raw.missing"],
            },
        },
    )
    message = '{"user":"\\u0061lice","other":"allowed"}'
    record = {
        "event_id": "escaped",
        "source": "vendor",
        "message": message,
        "raw": {
            "user": "alice",
            "line": "syslog-prefix " + message,
            "encoded": json.dumps(message),
        },
    }
    assert store.ingest("a", [record])["quarantined"] == 1
    payload = pipeline.quarantine(store, WHO)["rows"][0]["payload"]
    assert json.loads(payload["message"])["user"] == "[REDACTED]"
    assert json.loads(json.loads(payload["raw"]["encoded"]))["user"] == "[REDACTED]"
    assert "\\u0061lice" not in json.dumps(payload) and "alice" not in json.dumps(
        payload
    )
