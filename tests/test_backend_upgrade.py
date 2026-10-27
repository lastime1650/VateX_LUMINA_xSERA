"""Cross-authority, tamper, downgrade and loss-accounting regression."""

import base64
import copy
import sqlite3
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sapientia import access, auth, migrations, qualification_registry as qr, release_manifest as rm, sensor_capabilities as sc, source_registry as sr
from sapientia.storage import ConflictError, Settings, Store


@pytest.fixture
def lab(tmp_path):
    store = Store(Settings(tmp_path / "db", min_free_bytes=0))
    try:
        for name, role, tenant in (("owner", "admin", "a"), ("peer", "admin", "a"), ("foreign", "admin", "b"), ("reader", "viewer", "a")):
            auth.create_user(store, name, "Synthetic-password-upgrade-2026", role, tenant)
        yield store
    finally:
        store.close()


def actor(name="owner", tenant="a", role="admin"):
    return {"name": name, "tenant": tenant, "role": role, "allowed_indexes": ["*"]}


def config():
    return {"index": "public", "product": "cisco_asa", "account": "ASA-01", "realm": "lab", "credential_ref": "env:SAPIENTIA_CONNECTOR_LAB", "version": 0}


def test_registry_revocation_revision_and_foreign_existence(lab):
    item = sr.save(lab, actor(), config())
    assert sr.get(lab, actor(), item["id"])["version"] == 1
    assert sr.listing(lab, actor("foreign", "b")) == []
    with pytest.raises(KeyError):
        sr.get(lab, actor("foreign", "b"), item["id"])
    with pytest.raises(ConflictError):
        sr.save(lab, actor(), config(), item["id"])
    sr.revoke(lab, actor(), item["id"], 1)
    assert sr.get(lab, actor(), item["id"])["state"] == "revoked"


def test_registry_current_scope_and_secret_reference(lab):
    item = sr.save(lab, actor(), config())
    access.set_for_user(lab, actor(), "owner", ["other"])
    with pytest.raises(KeyError):
        sr.get(lab, actor(), item["id"])
    with pytest.raises(PermissionError):
        sr.save(lab, actor(), config())
    with pytest.raises(ValueError):
        sr.save(lab, actor(), {**config(), "credential_ref": "secret-value"})


def test_atomic_migration_refuses_changed_checksum_and_rolls_back():
    db = sqlite3.connect(":memory:")
    migrations.apply(db, "effects", 1, ["CREATE TABLE x(id INTEGER PRIMARY KEY)"])
    migrations.apply(db, "effects", 1, ["CREATE TABLE x(id INTEGER PRIMARY KEY)"])
    with pytest.raises(ValueError, match="checksum"):
        migrations.apply(db, "effects", 1, ["CREATE TABLE x(id TEXT)"])
    with pytest.raises(sqlite3.OperationalError):
        migrations.apply(db, "source_registry", 1, ["CREATE TABLE y(id INTEGER)", "NOT VALID SQL"])
    assert db.execute("SELECT 1 FROM sqlite_master WHERE name='y'").fetchone() is None
    db.close()


def test_future_schema_refused_before_store_writes(tmp_path):
    root = tmp_path / "future"
    root.mkdir()
    path = root / "control.sqlite3"
    with sqlite3.connect(path) as db:
        migrations.initialize(db)
        db.execute("INSERT INTO xsera_schema_migrations VALUES('effects',999,'x',0)")
    before = path.read_bytes()
    with pytest.raises(ValueError, match="Unsupported control schema"):
        Store(Settings(root, min_free_bytes=0))
    assert path.read_bytes() == before
    assert not (root / "events.duckdb").exists()


@pytest.mark.parametrize("counter", ["dropped", "reset", "backlog"])
def test_loss_never_reported_ready(counter):
    result = sc.provider({"state": "ready", "counters": {counter: 1}})
    assert result["state"] == "degraded"
    assert result["native_capture_proven"] is False
    assert result["clock_grade"] == "unknown"


@pytest.mark.parametrize("value", [True, -1, float("nan"), "3"])
def test_typed_provider_counters_reject_coercion(value):
    with pytest.raises(ValueError):
        sc.provider({"state": "ready", "counters": {"captured": value}})


def test_pinned_signature_expiry_and_false_summary():
    key = Ed25519PrivateKey.generate()
    trusted = {"external-qa": base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()}
    now = time.time()
    doc = {"schema": qr.SCHEMA, "signer": "external-qa", "tenant": "a", "indexes": ["public"],
           "source_digest": "a" * 64, "package_digest": "b" * 64, "config_digest": "c" * 64, "tool_digest": "d" * 64,
           "platform": "virtual-windows", "capability": "simulation", "native": False, "passed": True,
           "checks": [{"name": "durable-ingest", "passed": True, "artifact_digest": "e" * 64}], "created": now - 1, "expires": now + 60}
    envelope = {"document": doc, "signature": base64.b64encode(key.sign(rm.canonical(doc))).decode()}
    assert qr.verify(envelope, trusted)["native"] is False
    with pytest.raises(PermissionError):
        qr.verify(envelope, {})
    changed = copy.deepcopy(envelope)
    changed["document"]["native"] = True
    with pytest.raises(PermissionError):
        qr.verify(changed, trusted)
    with pytest.raises(ValueError, match="expired"):
        qr.verify(envelope, trusted, now=now + 61)
    changed["document"]["checks"][0]["passed"] = False
    with pytest.raises(ValueError, match="summary"):
        qr.verify(changed, trusted)


def test_source_manifest_deterministic_and_current():
    first = rm.build()
    assert rm.verify(first)["matches"]
    assert first["native_qualified"] is False and first["code_signed"] is False
    changed = {**first, "source_digest": "0" * 64}
    assert not rm.verify(changed)["matches"]
