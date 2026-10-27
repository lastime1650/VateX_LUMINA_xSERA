"""Independent Sigma custody audit; disposable Stores and inert JSON only."""

import copy
import json

import pytest

from sapientia import (
    access,
    auth,
    intelligence,
    principal,
    sigma_backend,
    sigma_imports,
    source_registry,
)
from sapientia.storage import ConflictError
from tests import test_sigma_imports as fixtures

actor, lab, payload = fixtures.actor, fixtures.lab, fixtures.payload


@pytest.fixture
def active(lab):
    for name in ("source_owner", "change_admin"):
        auth.create_user(
            lab, name, "Independent-sigma-audit-password-2026", "admin", "a"
        )
    declared = source_registry.save(
        lab,
        actor("source_owner"),
        {
            "index": "public",
            "product": "json",
            "account": "independent-sigma-source",
            "realm": "virtual-lab",
            "credential_ref": "env:SAPIENTIA_CONNECTOR_SIGMA_AUDIT",
            "version": 0,
        },
    )
    imported = sigma_imports.save(lab, actor(), payload(declared))
    imported = sigma_imports.save(
        lab,
        actor("change_admin"),
        payload(declared, expected_revision=1),
        imported["id"],
    )
    sigma_imports.convert(lab, actor(), imported["id"], 2)
    sigma_imports.validate(lab, actor(), imported["id"], 2)
    for name in ("owner", "change_admin"):
        with pytest.raises(PermissionError, match="independent"):
            sigma_imports.review(
                lab,
                actor(name),
                imported["id"],
                {"expected_revision": 2, "approve": True, "reason": "No self review"},
            )
    sigma_imports.review(
        lab,
        actor("peer"),
        imported["id"],
        {"expected_revision": 2, "approve": True, "reason": "Independent audit review"},
    )
    value = sigma_imports.activate(lab, actor(), imported["id"], 2)
    with principal.transaction(lab, actor()) as (db, _fresh):
        row = db.execute(
            "SELECT * FROM intelligence_policies WHERE id=?",
            (value["native_policy_id"],),
        ).fetchone()
        intelligence._authority(db, row)
    return value, declared


@pytest.mark.parametrize(
    "participant", ["owner", "change_admin", "peer", "source_owner"]
)
@pytest.mark.parametrize("revocation", ["scope", "disabled"])
def test_every_current_participant_is_required_at_native_execution(
    lab, active, participant, revocation
):
    value, _declared = active
    if revocation == "scope":
        access.set_for_user(lab, actor(), participant, ["private"])
    else:
        with principal.transaction(lab, actor(), write=True) as (db, _fresh):
            db.execute("UPDATE users SET disabled=1 WHERE name=?", (participant,))
    with lab.control() as db:
        row = db.execute(
            "SELECT * FROM intelligence_policies WHERE id=?",
            (value["native_policy_id"],),
        ).fetchone()
        with pytest.raises((PermissionError, ConflictError)):
            intelligence._authority(db, row)


def test_registered_source_guard_rejects_generic_other_source_old_version_and_wrong_index(
    lab, active
):
    value, declared = active
    event = value["payload"]["fixtures"][0]["event"]
    context = {
        "event": {**event, "index_name": "public"},
        "raw": event["raw"],
        "projection": {"source_id": declared["id"], "source_version": 1},
    }
    native = value["converted"]["native_policy"]
    assert intelligence._atomic_matches(context, native)
    for projection in (
        {},
        {"source_id": "unrelated-source", "source_version": 1},
        {"source_id": declared["id"], "source_version": 2},
    ):
        altered = {**context, "projection": projection}
        assert not intelligence._atomic_matches(altered, native)
    altered = copy.deepcopy(context)
    altered["event"]["index_name"] = "private"
    assert not intelligence._atomic_matches(altered, native)


def test_parser_unavailable_does_not_break_readonly_or_approved_native_authority(
    lab, active, monkeypatch
):
    value, _declared = active
    monkeypatch.setattr(
        sigma_backend, "status", lambda: {"available": False, "version": None}
    )
    assert sigma_imports.get(lab, actor(), value["id"])["state"] == "active"
    with principal.transaction(lab, actor()) as (db, _fresh):
        row = db.execute(
            "SELECT * FROM intelligence_policies WHERE id=?",
            (value["native_policy_id"],),
        ).fetchone()
        intelligence._authority(db, row)


def test_validation_cannot_replace_new_revision_committed_during_evaluation(
    lab, monkeypatch
):
    declared = fixtures.source(lab)
    data = payload(declared)
    value = sigma_imports.save(lab, actor(), data)
    sigma_imports.convert(lab, actor(), value["id"], 1)
    original = intelligence._atomic_matches
    edited = False

    def interleave(context, definition):
        nonlocal edited
        if not edited:
            edited = True
            sigma_imports.save(
                lab, actor(), {**data, "expected_revision": 1}, value["id"]
            )
        return original(context, definition)

    monkeypatch.setattr(intelligence, "_atomic_matches", interleave)
    with pytest.raises(ConflictError, match="revision changed"):
        sigma_imports.validate(lab, actor(), value["id"], 1)
    current = sigma_imports.get(lab, actor(), value["id"])
    assert current["revision"] == 2 and current["state"] == "imported"
    assert not any(key in current for key in ("converted", "validation", "review"))


def test_activation_helper_wrong_version_and_foreign_scope_roll_back(lab, active):
    value, _declared = active
    native = {
        key: item
        for key, item in value["converted"]["native_policy"].items()
        if key != "condition_contract"
    }
    with principal.transaction(lab, actor(), write=True) as (db, _fresh):
        before = db.execute(
            "SELECT count(*) FROM intelligence_policy_revisions"
        ).fetchone()[0]
        with pytest.raises(ConflictError, match="revision changed"):
            intelligence.activate_imported_in_transaction(
                lab,
                db,
                actor(),
                actor("peer"),
                {**native, "version": 0},
                value["native_policy_id"],
            )
        with pytest.raises(PermissionError):
            intelligence.activate_imported_in_transaction(
                lab, db, actor(), actor("foreign", tenant="b"), native
            )
        assert (
            db.execute("SELECT count(*) FROM intelligence_policy_revisions").fetchone()[
                0
            ]
            == before
        )
        assert db.execute("SELECT count(*) FROM endpoint_responses").fetchone()[0] == 0


@pytest.mark.parametrize(
    "kind,text",
    [
        (
            "yaml",
            "title: duplicate\ndetection: {a: {CommandLine: x}, condition: a}\ntitle: hidden",
        ),
        ("yaml", "a: &a [one]\nb: [*a,*a,*a]"),
        ("yaml", "a: !!python/object/apply:os.system ['never-run']"),
        (
            "json",
            '{"detection":{"a":{"CommandLine":"x","CommandLine":"hidden"},"condition":"a"},"title":"duplicate"}',
        ),
    ],
)
def test_nested_duplicate_keys_aliases_and_constructor_tags_are_rejected(kind, text):
    with pytest.raises(ValueError):
        sigma_imports._decode(text, kind)


def test_foreign_and_native_custody_read_are_fail_closed(lab, active):
    value, _declared = active
    with pytest.raises(KeyError):
        sigma_imports.get(lab, actor("foreign", tenant="b"), value["id"])
    # Corrupt only the disposable copy: no caller or bound policy can consume it.
    with principal.transaction(lab, actor(), write=True) as (db, _fresh):
        row = db.execute(
            "SELECT body FROM sigma_imports WHERE id=?", (value["id"],)
        ).fetchone()
        body = json.loads(row[0])
        body["payload"]["source_text"] += " "
        db.execute(
            "UPDATE sigma_imports SET body=? WHERE id=?",
            (json.dumps(body), value["id"]),
        )
    with pytest.raises(ConflictError, match="immutable import revision"):
        sigma_imports.get(lab, actor(), value["id"])
