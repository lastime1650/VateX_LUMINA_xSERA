"""Real source receipt counters, recovered out-of-order gaps and honest limits."""

import time

import pytest

from sapientia import access, auth, connector_runtime, pipeline, source_registry
from sapientia import source_delivery_slo as slo
from sapientia.storage import ConflictError, Settings, Store


def actor(name="owner", tenant="a", role="admin"):
    return {"name": name, "tenant": tenant, "role": role, "allowed_indexes": ["*"]}


@pytest.fixture
def delivery(tmp_path):
    store = Store(Settings(tmp_path / "store", min_free_bytes=0))
    for name, tenant, role in (
        ("owner", "a", "admin"),
        ("limited", "a", "admin"),
        ("foreign", "b", "admin"),
    ):
        auth.create_user(store, name, "Delivery-SLO-private-test-2026", role, tenant)
    source = source_registry.save(
        store,
        actor(),
        {
            "index": "delivery",
            "product": "json",
            "account": "stream",
            "realm": "lab",
            "credential_ref": "env:SAPIENTIA_CONNECTOR_DELIVERY",
            "version": 0,
        },
    )
    yield store, source
    store.close()


def configure(store, source, **kwargs):
    return slo.save(
        store,
        actor(),
        source["id"],
        {
            "expected_revision": 0,
            "source_version": 1,
            "sequence_path": "raw.telemetry.sequence",
            "epoch_path": "raw.telemetry.epoch",
            "max_silence_seconds": 30,
            "max_gap": 0,
            "max_reported_drop": 0,
            **kwargs,
        },
    )


def intake(store, source, values, checkpoint=0):
    events = [
        {
            "event_id": f"event-{checkpoint}-{n}",
            "event_time": 1700000000,
            "host": "sender",
            "raw": {"telemetry": {"sequence": seq, "epoch": epoch}},
        }
        for n, (seq, epoch) in enumerate(values)
    ]
    return connector_runtime.intake(
        store,
        actor(),
        source["id"],
        {
            "version": 1,
            "events": events,
            "cursor": str(checkpoint + 1),
            "checkpoint_version": checkpoint,
        },
    )


def test_durable_gaps_recover_on_late_originals_and_duplicates_do_not_count(delivery):
    store, source = delivery
    configure(store, source)
    first = intake(store, source, [(1, "boot"), (4, "boot")])
    item = slo.listing(store, actor())["items"][0]
    assert item["server_receipts"] == 2 and item["provisional_sequence_gaps"] == 2
    assert item["reasons"] == ["sequence_gap_budget_exceeded"]
    second = intake(
        store, source, [(2, "boot"), (3, "boot")], first["checkpoint_version"]
    )
    item = slo.listing(store, actor())["items"][0]
    assert (
        item["provisional_sequence_gaps"] == 0 and item["counters"]["out_of_order"] == 2
    )
    assert item["state"] == "within_configured_budget"
    assert item["pre_capture_loss"] == "unavailable_not_observable"
    with store.control() as db:
        assert (
            db.execute("SELECT count(*) FROM source_event_receipts").fetchone()[0] == 4
        )
    # Replaying the exact admitted page is idempotent, including its SLO counters.
    repeated = intake(store, source, [(2, "boot"), (3, "boot")], 1)
    assert second["accepted"] == 2 and repeated["duplicate"] == 2
    assert slo.listing(store, actor())["items"][0]["counters"]["observed_unique"] == 4


def test_bad_or_absent_sequences_are_coverage_failures_not_fake_zero_loss(delivery):
    store, source = delivery
    configure(store, source)
    intake(store, source, [(True, "boot"), (None, "boot"), (10, "boot"), (1, "boot2")])
    item = slo.listing(store, actor())["items"][0]
    assert item["counters"]["invalid_sequence"] == 1
    assert item["counters"]["missing_sequence"] == 1
    assert item["provisional_sequence_gaps"] == 0
    assert "sequence_coverage_incomplete" in item["reasons"]
    assert len(item["counters"]["epochs"]) == 2
    assert (
        slo.listing(store, actor(), now=time.time() + 60)["items"][0]["reasons"][0]
        == "source_silence"
    )


def test_source_scope_contract_revision_and_policy_change_boundary(delivery):
    store, source = delivery
    configure(store, source)
    access.set_for_user(store, actor(), "limited", ["other"])
    assert slo.listing(store, actor("limited"))["items"] == []
    assert slo.listing(store, actor("foreign", "b"))["items"] == []
    with pytest.raises((KeyError, PermissionError)):
        slo.save(
            store,
            actor("limited"),
            source["id"],
            {
                "expected_revision": 1,
                "source_version": 1,
                "sequence_path": None,
                "epoch_path": None,
                "max_silence_seconds": 30,
                "max_gap": 0,
                "max_reported_drop": 0,
            },
        )
    with pytest.raises(ConflictError):
        configure(store, source)
    source_registry.save(
        store,
        actor(),
        {
            key: source[key]
            for key in (
                "index",
                "product",
                "account",
                "realm",
                "credential_ref",
                "version",
            )
        },
        source["id"],
    )
    assert slo.listing(store, actor())["items"][0]["reasons"] == [
        "source_contract_changed"
    ]


def test_sequence_accounting_capacity_is_explicit_not_silent(delivery):
    store, source = delivery
    configure(store, source)
    intake(store, source, [(1, "epoch-" + str(n)) for n in range(17)])
    item = slo.listing(store, actor())["items"][0]
    assert item["counters"]["coverage_exhausted"] is True
    assert len(item["counters"]["epochs"]) == 16
    assert "sequence_coverage_incomplete" in item["reasons"]


def test_sequence_uses_actual_post_pipeline_durable_payload(delivery, monkeypatch):
    store, source = delivery
    configure(store, source)
    original = pipeline.apply

    def strip_sequence(record, policy):
        result, errors = original(record, policy)
        result = {**result, "raw": {**result["raw"], "telemetry": {"epoch": "boot"}}}
        return result, errors

    monkeypatch.setattr(pipeline, "apply", strip_sequence)
    intake(store, source, [(7, "boot")])
    item = slo.listing(store, actor())["items"][0]
    assert item["server_receipts"] == 1
    assert item["counters"]["missing_sequence"] == 1
    assert item["counters"]["sequence_observed"] == 0
