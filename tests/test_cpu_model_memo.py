"""Loader authority fixtures, not trained-model or performance evidence."""
import copy
import json
import time
import uuid

import pytest

from sapientia import (
    access,
    auth,
    cpu_model_memo,
    cpu_sequence,
    principal,
    source_registry,
)
from sapientia.storage import ConflictError, Settings, Store, encode


@pytest.fixture
def scoped_model(tmp_path):
    cpu_model_memo.clear_content_cache()
    store = Store(Settings(tmp_path, min_free_bytes=0))
    for name, role in (("memo-owner", "analyst"), ("memo-reviewer", "analyst"), ("memo-admin", "admin")):
        auth.create_user(store, name, "Memo-fixture-password-2026", role, "memo")
    who = {"name": "memo-owner", "tenant": "memo", "role": "analyst", "allowed_indexes": ["*"]}
    admin = {**who, "name": "memo-admin", "role": "admin"}
    source = source_registry.save(store, admin, {"index": "public", "product": "json", "account": "memo-fixture",
        "realm": "synthetic", "credential_ref": "env:SAPIENTIA_CONNECTOR_MEMO_FIXTURE", "version": 0})
    identifier, review = str(uuid.uuid4()), str(uuid.uuid4())
    with store.write_lock, store.control() as db:
        row = db.execute("SELECT * FROM source_registry WHERE id=?", (source["id"],)).fetchone()
        context = {key: row[key] for key in ("id", "version", "index_name", "product", "account", "realm", "owner")}
        definition = {"name": "Immutable authority fixture", "indexes": ["public"], "architecture": copy.deepcopy(cpu_sequence.ARCHITECTURE),
            "feature_contract_digest": cpu_sequence.FEATURE_CONTRACT_DIGEST, "sources": [context], "split_summary": {}, "holdout_digest": "fixture"}
        snapshot = {"schema": cpu_sequence.MODEL_SCHEMA, "feature_schema": cpu_sequence.FEATURE_SCHEMA,
                    "weights": {}, "pooled_weights": {}, "threshold": .5, "pooled_threshold": .5}
        digest = cpu_sequence._digest({"definition": definition, "snapshot": snapshot})
        db.execute("INSERT INTO cpu_sequence_models VALUES(?,?,?,?,?,?,?,?,?,?,?)", (identifier, "memo", "memo-owner", definition["name"], 1,
            encode(["public"]), time.time(), encode(definition), encode(snapshot), digest, "{}"))
        db.execute("INSERT INTO cpu_sequence_reviews VALUES(?,?,?,?,?,?)", (review, "memo", identifier, "memo-reviewer", time.time(), "Guard fixture review"))
        db.execute("INSERT INTO cpu_sequence_active VALUES(?,?,?,?,?)", ("memo", definition["name"], identifier, review, time.time()))
    yield store, who, identifier, digest, source["id"]
    store.close()
    cpu_model_memo.clear_content_cache()


def test_memo_reuses_only_hash_parse_work_and_frozen_values(scoped_model, monkeypatch):
    store, who, identifier, digest, _source = scoped_model
    with principal.transaction(store, who, write=True) as (db, actor):
        original = db.execute("SELECT * FROM cpu_sequence_models WHERE id=?", (identifier,)).fetchone()
        real_loads, counts = json.loads, []
        def tracked_loads(value, *args, **kwargs):
            if value in (original["definition"], original["snapshot"]):
                counts.append(value)
            return real_loads(value, *args, **kwargs)
        monkeypatch.setattr(cpu_model_memo.json, "loads", tracked_loads)
        with cpu_sequence.authority_memo(db) as memo:
            first, definition, snapshot = cpu_sequence._load(db, actor, identifier, True, memo=memo)
            second, same_definition, same_snapshot = cpu_sequence._load(db, actor, identifier, True, memo=memo)
            pin = cpu_sequence.validate_publication(store, db, actor, identifier, digest, 1, memo=memo)
            assert pin["active"] and first["id"] == second["id"] and len(counts) == 2
            assert same_definition is definition and same_snapshot is snapshot
            with pytest.raises(TypeError, match="immutable"):
                definition["sources"][0]["version"] = 900
            with pytest.raises(TypeError, match="immutable"):
                definition["sources"].append({})
            with pytest.raises(TypeError, match="immutable"):
                snapshot["threshold"] = 0
            assert cpu_sequence._digest({"definition": definition, "snapshot": snapshot}) == digest
        with pytest.raises(ConflictError, match="boundaries"):
            cpu_sequence._load(db, actor, identifier, True, memo=memo)


@pytest.mark.parametrize("column", ["definition", "snapshot"])
def test_same_transaction_raw_model_tampering_is_not_cached(scoped_model, column):
    store, who, identifier, _digest, _source = scoped_model
    with principal.transaction(store, who, write=True) as (db, actor), cpu_sequence.authority_memo(db) as memo:
        row, _, _ = cpu_sequence._load(db, actor, identifier, True, memo=memo)
        changed = json.loads(row[column])
        changed["tampered"] = True
        db.execute("UPDATE cpu_sequence_models SET "+column+"=? WHERE id=?", (encode(changed), identifier))
        with pytest.raises(ConflictError, match="hash mismatch"):
            cpu_sequence._load(db, actor, identifier, True, memo=memo)


@pytest.mark.parametrize("mutation,expected", [
    ("caller_grant", PermissionError), ("owner_grant", PermissionError), ("reviewer_grant", PermissionError),
    ("source_owner_grant", PermissionError), ("source_version", ConflictError), ("source_disabled", PermissionError),
    ("active_removed", PermissionError), ("retired", ConflictError), ("revision", ConflictError),
])
def test_memo_never_caches_current_scope_source_review_or_revision(scoped_model, mutation, expected):
    store, who, identifier, digest, source = scoped_model
    # Different actor for the owner-grant case ensures that creator grants,
    # rather than just the current caller check, independently remain fresh.
    selected = {**who, "name": "memo-reviewer"} if mutation == "owner_grant" else who
    with principal.transaction(store, selected, write=True) as (db, actor), cpu_sequence.authority_memo(db) as memo:
        cpu_sequence.validate_publication(store, db, actor, identifier, digest, 1, memo=memo)
        if mutation.endswith("grant"):
            name = {"caller_grant": actor["name"], "owner_grant": "memo-owner", "reviewer_grant": "memo-reviewer", "source_owner_grant": "memo-admin"}[mutation]
            db.execute("INSERT INTO user_index_access VALUES(?,?,?)", ("memo", name, encode(["private"])))
        elif mutation == "source_version":
            db.execute("UPDATE source_registry SET version=version+1 WHERE id=?", (source,))
        elif mutation == "source_disabled":
            db.execute("UPDATE source_registry SET state='disabled' WHERE id=?", (source,))
        elif mutation == "active_removed":
            db.execute("DELETE FROM cpu_sequence_active WHERE model_id=?", (identifier,))
        elif mutation == "retired":
            db.execute("INSERT INTO cpu_ml_retired_models VALUES(?,?,?,?,?,?,?,?)", ("sequence", identifier, "memo", "memo-reviewer", time.time(), encode(["public"]), digest, '{"retired":true}'))
        elif mutation == "revision":
            db.execute("UPDATE cpu_sequence_models SET revision=revision+1 WHERE id=?", (identifier,))
        with pytest.raises(expected):
            cpu_sequence.validate_publication(store, db, actor, identifier, digest, 1, memo=memo)


def test_memo_rejects_reused_connection_new_transaction_and_other_database(scoped_model):
    store, who, identifier, _digest, _source = scoped_model
    with principal.transaction(store, who, write=True) as (db, actor), cpu_sequence.authority_memo(db) as memo:
        row, _, _ = cpu_sequence._load(db, actor, identifier, True, memo=memo)
        with store.control() as other, pytest.raises(ConflictError, match="boundaries"):
            cpu_model_memo.decoded_model(other, memo, "sequence", row)
    # A wrong-connection attempt invalidates the memo rather than leaving
    # reusable decoded state. Also prove commit/new-BEGIN on the exact same
    # live connection is detected even before the context exits.
    with principal.transaction(store, who, write=True) as (db, actor), cpu_sequence.authority_memo(db) as memo:
        cpu_sequence._load(db, actor, identifier, True, memo=memo)
        db.execute("/* boundary */ COMMIT")
        db.execute("BEGIN IMMEDIATE")
        with pytest.raises(ConflictError, match="boundaries"):
            cpu_sequence._load(db, actor, identifier, True, memo=memo)


def test_content_reuse_across_new_transactions_never_reuses_source_authority(scoped_model, monkeypatch):
    store, who, identifier, _digest, _source = scoped_model
    real_sources, calls = cpu_sequence._sources_current, []
    def checked_sources(*args, **kwargs):
        calls.append(True)
        return real_sources(*args, **kwargs)
    monkeypatch.setattr(cpu_sequence, "_sources_current", checked_sources)
    with principal.transaction(store, who, write=True) as (db, actor):
        _, first, first_weights = cpu_sequence._load(db, actor, identifier, True)
    with principal.transaction(store, who, write=True) as (db, actor):
        _, second, second_weights = cpu_sequence._load(db, actor, identifier, True)
        assert second is first and second_weights is first_weights
        assert len(calls) == 2 and cpu_model_memo.content_cache_status()["hits"] >= 1
    # The content survives a transaction; authority does not. Revoke the
    # independently owned source and prove a fresh call rejects that same body.
    admin = {**who, "name": "memo-admin", "role": "admin"}
    access.set_for_user(store, admin, "memo-admin", ["private"])
    with principal.transaction(store, who, write=True) as (db, actor), pytest.raises(PermissionError, match="source owner"):
        cpu_sequence._load(db, actor, identifier, True)
    assert len(calls) == 3


@pytest.mark.parametrize("column", ["definition", "snapshot"])
def test_content_cache_rechecks_raw_tamper_after_a_completed_transaction(scoped_model, column):
    store, who, identifier, _digest, _source = scoped_model
    with principal.transaction(store, who, write=True) as (db, actor):
        row, _, _ = cpu_sequence._load(db, actor, identifier, True)
    changed = json.loads(row[column])
    changed["changed_after_commit"] = True
    with store.write_lock, store.control() as db:
        db.execute("UPDATE cpu_sequence_models SET "+column+"=? WHERE id=?", (encode(changed), identifier))
    with principal.transaction(store, who, write=True) as (db, actor), pytest.raises(ConflictError, match="hash mismatch"):
        cpu_sequence._load(db, actor, identifier, True)


@pytest.mark.parametrize("field,value", [("id", "different-model"), ("tenant", "different-tenant"),
    ("owner", "different-owner"), ("revision", 2), ("indexes", '["private"]')])
def test_content_identity_includes_model_tenant_owner_revision_and_raw_scope(scoped_model, field, value):
    store, _who, identifier, _digest, _source = scoped_model
    with store.control() as db:
        row = dict(db.execute("SELECT * FROM cpu_sequence_models WHERE id=?", (identifier,)).fetchone())
    first = cpu_model_memo.content_model("sequence", row)
    second = cpu_model_memo.content_model("sequence", {**row, field: value})
    assert first[0] is not second[0]
    assert cpu_model_memo.content_cache_status()["misses"] == 2


def test_content_cache_bounds_and_lru_eviction_are_enforced(scoped_model, monkeypatch):
    store, _who, identifier, _digest, _source = scoped_model
    with store.control() as db:
        row = dict(db.execute("SELECT * FROM cpu_sequence_models WHERE id=?", (identifier,)).fetchone())
    size = len(row["definition"].encode()) + len(row["snapshot"].encode())
    monkeypatch.setattr(cpu_model_memo, "MAX_MODELS", 2)
    monkeypatch.setattr(cpu_model_memo, "MAX_RAW_BYTES", 2*size)
    for i in range(5):
        cpu_model_memo.content_model("sequence", {**row, "id": str(i)})
    status = cpu_model_memo.content_cache_status()
    assert status["entries"] == 2 and status["raw_bytes"] <= 2*size
    cpu_model_memo.content_model("sequence", {**row, "id": "0"})
    assert cpu_model_memo.content_cache_status()["misses"] == 6
    cpu_model_memo.clear_content_cache()
    monkeypatch.setattr(cpu_model_memo, "MAX_RAW_BYTES", size-1)
    first = cpu_model_memo.content_model("sequence", row)
    second = cpu_model_memo.content_model("sequence", row)
    status = cpu_model_memo.content_cache_status()
    assert status["entries"] == 0 and status["raw_bytes"] == 0
    assert status["misses"] == 2 and first[0] is not second[0]
