# ruff: noqa: F811 - imported pytest fixture names are reused as parameters.
"""Real pySigma upload conversion, native execution and version-bound custody."""

import json
import time

import pytest

from sapientia import (
    access,
    connector_runtime,
    intelligence,
    principal,
    sigma_backend,
    source_registry,
)
from sapientia import sigma_imports as imports
from sapientia.storage import ConflictError
from tests.test_backend_upgrade import (  # noqa: F401 - owned disposable Store fixture.
    actor,
    lab,
)


def source(lab, account="sigma-fixture"):
    return source_registry.save(
        lab,
        actor(),
        {
            "index": "public",
            "product": "json",
            "account": account,
            "realm": "virtual-lab",
            "credential_ref": "env:SAPIENTIA_CONNECTOR_SIGMA_FIXTURE",
            "version": 0,
        },
    )


def payload(source, **changes):
    rule = {
        "title": "Boolean process command with suppression",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "a": {"CommandLine|contains": "powershell"},
            "b": {"CommandLine|contains": "cmd.exe"},
            "excluded": {"User|cased": "trusted"},
            "condition": "(a or b) and not excluded",
        },
    }
    rows = [
        ("a", "PowerShell -enc", "investigator", True),
        ("b", "CMD.EXE /c", "investigator", True),
        ("suppressed", "powershell", "trusted", False),
        ("negative", "echo harmless", "investigator", False),
    ]
    fixtures = [
        {
            "name": name,
            "source_id": source["id"],
            "expect": expected,
            "event": {
                "event_id": "fixture-" + name,
                "event_time": 1700000000,
                "index": "public",
                "host": "sigma-host",
                "sourcetype": "process",
                "raw": {"command": command, "user": user, "platform": "windows"},
            },
        }
        for name, command, user, expected in rows
    ]
    return {
        "expected_revision": 0,
        "name": "Imported Boolean Sigma",
        "format": "json",
        "source_text": json.dumps(rule),
        "indexes": ["public"],
        "field_mapping": {"CommandLine": "raw.command", "User": "raw.user"},
        "logsource_mapping": {
            "category": {"field": "sourcetype", "value": "process"},
            "product": {"field": "raw.platform", "value": "windows"},
        },
        "source_contracts": [{"source_id": source["id"], "version": source["version"]}],
        "severity": "high",
        "case_adapter": None,
        "fixtures": fixtures,
        **changes,
    }


def ready(lab, data):
    value = imports.save(lab, actor(), data)
    value = imports.convert(lab, actor(), value["id"], 1)
    assert value["state"] == "converted"
    value = imports.validate(lab, actor(), value["id"], 1)
    assert value["validation"]["passed"], value
    assert value["state"] == "validated"
    value = imports.review(
        lab,
        actor("peer"),
        value["id"],
        {
            "expected_revision": 1,
            "approve": True,
            "reason": "Independent Boolean and suppression fixture review",
        },
    )
    return value


def activated(lab, data):
    value = ready(lab, data)
    return imports.activate(lab, actor(), value["id"], 1)


def test_real_json_workflow_preserves_original_hash_native_ir_and_independent_approval(
    lab,
):
    data = payload(source(lab))
    saved = activated(lab, data)
    assert saved["state"] == "active" and saved["native_policy_version"] == 1
    assert saved["parser_version"] == sigma_backend.status()["version"]
    assert saved["converted"]["native_ir_version"] == 1
    assert saved["payload"]["source_text"] == data["source_text"]
    assert [item["action"] for item in saved["history"]] == [
        "save",
        "convert",
        "validate",
        "review",
        "activate",
    ]
    assert saved["review"]["reviewer"] == "peer"
    tree = json.dumps(saved["converted"]["native_policy"]["condition_tree"])
    assert '"op": "or"' in tree and '"op": "not"' in tree
    with principal.transaction(lab, actor()) as (db, _who):
        native = db.execute(
            "SELECT * FROM intelligence_policies WHERE id=?",
            (saved["native_policy_id"],),
        ).fetchone()
        intelligence._authority(db, native)


def test_no_self_review_no_untested_activation_and_mapping_edit_invalidates_every_stage(
    lab,
):
    data = payload(source(lab))
    value = imports.save(lab, actor(), data)
    with pytest.raises(ConflictError):
        imports.activate(lab, actor(), value["id"], 1)
    imports.convert(lab, actor(), value["id"], 1)
    imports.validate(lab, actor(), value["id"], 1)
    with pytest.raises(PermissionError):
        imports.review(
            lab,
            actor(),
            value["id"],
            {
                "expected_revision": 1,
                "approve": True,
                "reason": "Self review forbidden",
            },
        )
    imports.review(
        lab,
        actor("peer"),
        value["id"],
        {"expected_revision": 1, "approve": True, "reason": "Independent review"},
    )
    active = imports.activate(lab, actor(), value["id"], 1)
    edited = imports.save(
        lab,
        actor(),
        {
            **data,
            "expected_revision": 1,
            "field_mapping": {
                **data["field_mapping"],
                "CommandLine": "raw.other_command",
            },
        },
        value["id"],
    )
    assert edited["revision"] == 2 and edited["state"] == "imported"
    assert all(key not in edited for key in ("converted", "validation", "review"))
    with principal.transaction(lab, actor()) as (db, _who):
        native = db.execute(
            "SELECT * FROM intelligence_policies WHERE id=?",
            (active["native_policy_id"],),
        ).fetchone()
        assert native["state"] == "active"
        intelligence._authority(db, native)
        assert edited["active_deployment"]["revision"] == 1
    with pytest.raises(ConflictError):
        imports.activate(lab, actor(), value["id"], 1)
    with pytest.raises(ConflictError):
        imports.activate(lab, actor(), value["id"], 2)


def test_real_native_atomic_to_composite_to_case_uses_boolean_semantics_without_parser(
    lab, monkeypatch
):
    declared = source(lab)
    data = payload(declared)
    decoded = json.loads(data["source_text"])
    decoded.update(author="Original Sigma author", license="DRL-1.1", references=["https://example.invalid/sigma/source"])
    data["source_text"] = json.dumps(decoded)
    active = activated(lab, data)
    # Removing the optional converter cannot disable already approved native IR.
    monkeypatch.setattr(
        sigma_backend, "status", lambda: {"available": False, "version": None}
    )
    other = intelligence.save_policy(
        lab,
        actor(),
        {
            "name": "Network evidence",
            "kind": "atomic",
            "indexes": ["public"],
            "enabled": True,
            "filters": [{"field": "raw.stage", "op": "eq", "value": "network"}],
        },
    )
    intelligence.review_policy(
        lab,
        actor("peer"),
        other["id"],
        {"version": 1, "approve": True, "reason": "Independent network fixture"},
    )
    composite = intelligence.save_policy(
        lab,
        actor(),
        {
            "name": "Imported Sigma plus network",
            "kind": "composite",
            "indexes": ["public"],
            "enabled": True,
            "inputs": [
                {"rule_id": active["native_policy_id"]},
                {"rule_id": other["id"]},
            ],
            "join_on": "entity",
            "minimum_independent_groups": 2,
            "case_adapter": {
                "entity_field": "host",
                "risk_score": 60,
                "severity": "high",
                "mitre": [],
                "cooldown": 0,
            },
        },
    )
    intelligence.review_policy(
        lab,
        actor("peer"),
        composite["id"],
        {
            "version": 1,
            "approve": True,
            "reason": "Independent composite and Case ancestry",
        },
    )
    now = time.time() - 10
    events = []
    for n, fixture in enumerate(payload(declared)["fixtures"]):
        events.append(
            {
                **fixture["event"],
                "event_id": "live-" + fixture["name"],
                "event_time": now + n,
            }
        )
    events.append(
        {
            "event_id": "live-network",
            "event_time": now + 5,
            "index": "public",
            "host": "sigma-host",
            "raw": {"stage": "network"},
        }
    )
    for event in events:
        event["raw"]["xdr"] = {
            "data": {
                "process": {
                    "guid": "sigma-process",
                    "start_identity": "sigma-process-instance",
                },
                "host": {"id": "sigma-device", "boot_id": "sigma-boot"},
                "event": {
                    "action": "process_observed",
                    "timestamp_precision_seconds": 0.01,
                },
            }
        }
    connector_runtime.intake(
        lab,
        actor(),
        declared["id"],
        {
            "version": 1,
            "events": events,
            "cursor": "sigma-live",
            "checkpoint_version": 0,
        },
    )
    while lab.flush():
        pass
    for _ in range(5):
        intelligence.run_due(lab, budget=2, max_runs=8)
    signals = intelligence.signals(lab, actor(), count=1000)["items"]
    imported = [
        signal for signal in signals if signal["rule_id"] == active["native_policy_id"]
    ]
    assert {tuple(signal["event_ids"]) for signal in imported} == {
        ("live-a",),
        ("live-b",),
    }
    combined = [signal for signal in signals if signal["rule_id"] == composite["id"]]
    assert combined and all(
        "live-network" in signal["event_ids"] for signal in combined
    )
    assert all("live-suppressed" not in signal["event_ids"] for signal in combined)
    assert all(
        signal["metadata"]["sigma_import"]["import_id"] == active["id"]
        for signal in imported
    )
    from sapientia import content_notices, casework
    assert all(signal["metadata"]["sigma_import"]["content_notices"]["items"][0]["author"] == "Original Sigma author" for signal in imported)
    with principal.transaction(lab, actor()) as (db, fresh):
        for signal in combined:
            notice = content_notices.for_signal(db, fresh, signal)
            assert any(item.get("author") == "Original Sigma author" and item.get("license") == "DRL-1.1" for item in notice["items"])
        case_id = db.execute("SELECT incident_id FROM risk_contributions WHERE policy_id=? LIMIT 1", ("intelligence:" + composite["id"] + ":1",)).fetchone()[0]
    exported = casework.export_case(lab, actor(), case_id)
    assert any(item.get("author") == "Original Sigma author" for item in exported["content_notices"]["items"])
    publication = {
        "event_ids": ["live-a"],
        "kind": "atomic",
        "rule_id": active["native_policy_id"],
        "rule_revision": 1,
        "features": {},
        "severity": "high",
        "confidence_grade": "reviewed_sigma_rule",
        "definition_digest": active["converted"]["native_definition_digest"],
    }
    for spoof in [
        {**publication, "metadata": {"sigma_import": {"import_id": active["id"]}}},
        {**publication, "event_ids": ["live-negative"]},
        {**publication, "rule_revision": 2},
    ]:
        with pytest.raises((ValueError, ConflictError)):
            intelligence.publish(lab, actor(), spoof)
    with lab.control() as db:
        assert db.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] >= 1
        assert db.execute("SELECT COUNT(*) FROM effect_receipts").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM endpoint_responses").fetchone()[0] == 0


@pytest.mark.parametrize(
    "text", ['{"title":"a","title":"b"}', "[]", "null", "{broken", '{"v":NaN}']
)
def test_malformed_json_and_duplicate_keys_are_rejected(text):
    with pytest.raises(ValueError):
        imports._decode(text, "json")


@pytest.mark.parametrize(
    "text",
    [
        "a: &a {b: c}\nx: *a",
        "a: 1\na: 2",
        "---\ntitle: one\n---\ntitle: two",
        "!!python/object/apply:os.system ['anything']",
        "a:\n  <<: {x: 2}",
    ],
)
def test_yaml_aliases_duplicate_multidocument_and_custom_tags_are_rejected(text):
    with pytest.raises(ValueError):
        imports._decode(text, "yaml")


def test_actual_yaml_dates_and_same_native_ir(lab):
    import yaml

    data = payload(source(lab))
    rule = json.loads(data["source_text"])
    rule["date"] = "2026-10-16"
    data.update(format="yaml", source_text=yaml.safe_dump(rule, sort_keys=False))
    value = ready(lab, data)
    assert (
        value["state"] == "approved"
        and value["parser_version"] == sigma_backend.status()["version"]
    )


def test_source_revision_reviewer_scope_and_native_direct_edit_cannot_bypass_review(
    lab,
):
    declared = source(lab)
    active = activated(lab, payload(declared))
    policy = active["converted"]["native_policy"]
    with pytest.raises(ConflictError):
        intelligence.review_policy(
            lab,
            actor("peer"),
            active["native_policy_id"],
            {"version": 1, "approve": True, "reason": "Direct bypass"},
        )
    with pytest.raises(ConflictError):
        intelligence.save_policy(
            lab,
            actor(),
            {
                **{
                    key: value
                    for key, value in policy.items()
                    if key != "condition_contract"
                },
                "version": 1,
            },
            active["native_policy_id"],
        )
    source_registry.revoke(lab, actor(), declared["id"], 1)
    with principal.transaction(lab, actor()) as (db, _who):
        native = db.execute(
            "SELECT * FROM intelligence_policies WHERE id=?",
            (active["native_policy_id"],),
        ).fetchone()
        with pytest.raises(ConflictError):
            intelligence._authority(db, native)


def test_foreign_viewer_and_out_of_scope_access(lab):
    value = imports.save(lab, actor(), payload(source(lab)))
    assert imports.listing(lab, actor("foreign", tenant="b"))["items"] == []
    with pytest.raises(KeyError):
        imports.get(lab, actor("foreign", tenant="b"), value["id"])
    assert (
        imports.get(lab, actor("reader", role="viewer"), value["id"])["id"]
        == value["id"]
    )
    with pytest.raises(PermissionError):
        imports.convert(lab, actor("reader", role="viewer"), value["id"], 1)
    access.set_for_user(lab, actor(), "peer", ["other"])
    with pytest.raises(KeyError):
        imports.convert(lab, actor("peer"), value["id"], 1)


def test_activation_rolls_back_native_policy_if_binding_transaction_fails(
    lab, monkeypatch
):
    value = ready(lab, payload(source(lab)))
    original = intelligence.activate_imported_in_transaction

    def fail_after_native(*args, **kwargs):
        original(*args, **kwargs)
        raise ConflictError("Injected binding failure after native insertion")

    monkeypatch.setattr(
        intelligence, "activate_imported_in_transaction", fail_after_native
    )
    with pytest.raises(ConflictError):
        imports.activate(lab, actor(), value["id"], 1)
    with lab.control() as db:
        assert (
            db.execute("SELECT count(*) FROM intelligence_policies").fetchone()[0] == 0
        )
        assert (
            db.execute("SELECT count(*) FROM intelligence_policy_revisions").fetchone()[
                0
            ]
            == 0
        )
        assert (
            db.execute("SELECT count(*) FROM sigma_import_bindings").fetchone()[0] == 0
        )
    assert imports.get(lab, actor(), value["id"])["state"] == "approved"


def test_current_reviewer_revocation_blocks_activation_and_retire_preserves_history(
    lab,
):
    value = ready(lab, payload(source(lab)))
    access.set_for_user(lab, actor(), "peer", ["other"])
    with pytest.raises(PermissionError):
        imports.activate(lab, actor(), value["id"], 1)
    value = imports.retire(
        lab,
        actor(),
        value["id"],
        {"expected_revision": 1, "reason": "Preserve rejected deployment audit"},
    )
    assert value["state"] == "retired" and value["review"]["reviewer"] == "peer"
    assert (
        value["history"][-1]["body"]["detail"]["reason"]
        == "Preserve rejected deployment audit"
    )


def test_mapping_and_source_immutable_hash_tamper_cannot_activate(lab):
    value = ready(lab, payload(source(lab)))
    with lab.control() as db:
        body = json.loads(
            db.execute(
                "SELECT body FROM sigma_imports WHERE id=?", (value["id"],)
            ).fetchone()[0]
        )
        body["converted"]["native_policy"]["name"] = "Tampered converted policy"
        db.execute(
            "UPDATE sigma_imports SET body=? WHERE id=?",
            (json.dumps(body), value["id"]),
        )
    with pytest.raises(ConflictError):
        imports.activate(lab, actor(), value["id"], 1)


def test_unsupported_modifiers_aggregation_and_missing_source_mapping_do_not_convert(
    lab,
):
    declared = source(lab)
    for change in ["modifier", "aggregation", "mapping"]:
        data = payload(declared)
        rule = json.loads(data["source_text"])
        if change == "modifier":
            rule["detection"]["a"] = {"CommandLine|base64offset": "anything"}
        elif change == "aggregation":
            rule["detection"]["condition"] = "a | count() > 1"
        else:
            data["logsource_mapping"] = {}
        data["source_text"] = json.dumps(rule)
        value = imports.save(lab, actor(), data)
        with pytest.raises(ValueError):
            imports.convert(lab, actor(), value["id"], 1)
        assert imports.get(lab, actor(), value["id"])["state"] == "imported"
