"""Endpoint-bearing definitions cannot expose private index evidence/targets."""
# ruff: noqa: F811 -- Imported fixtures are injected by pytest argument names.

import copy
import json
import time

import pytest

from sapientia import access, soar, soar_bindings
from sapientia.storage import encode
from tests.test_agent_distribution import config, source_store  # noqa: F401
from tests.test_endpoint_response import response_case  # noqa: F401
from tests.test_xdr_bridge import actor


def definition(body, version=0):
    return {
        "name": "Private endpoint target",
        "version": version,
        "steps": [
            {
                "id": "inspect",
                "action": {
                    "type": "endpoint_response",
                    **{
                        key: body[key]
                        for key in ("agent_id", "evidence_event_id", "reason")
                    },
                    "action": {**body["action"], "type": "inspect_process"},
                },
            }
        ],
    }


def public_case(store):
    now = time.time()
    with store.control() as db:
        db.execute(
            "INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                "public-case",
                "a",
                "public-host",
                "host",
                "Public synthetic case",
                now,
                now,
                "new",
                "",
                1,
            ),
        )
        db.execute(
            "INSERT INTO risk_contributions VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                "public-fact",
                "a",
                "public-case",
                "public-policy",
                "public-host",
                "host",
                now,
                10,
                encode({"event_ids": []}),
                encode(["public"]),
            ),
        )
        policy = db.execute(
            "SELECT * FROM correlation_policies WHERE tenant='a' LIMIT 1"
        ).fetchone()
        payload = json.loads(policy["definition"])
        payload["indexes"] = ["public"]
        db.execute(
            "UPDATE correlation_policies SET definition=? WHERE id=?",
            (encode(payload), policy["id"]),
        )
    return policy["id"]


def generic(store):
    return soar.save(
        store,
        actor(),
        {
            "name": "Tenant generic",
            "version": 0,
            "steps": [
                {
                    "id": "note",
                    "action": {"type": "add_note", "note": "Shared tenant note"},
                }
            ],
        },
    )


def test_scopes_derived_from_actual_proof_and_generic_remains_shared(response_case):
    store, _, _, _, body = response_case
    private = soar.save(store, actor(), definition(body))
    shared = generic(store)
    with store.control() as db:
        assert json.loads(
            db.execute(
                "SELECT indexes FROM soar_playbook_scopes WHERE playbook_id=?",
                (private["id"],),
            ).fetchone()[0]
        ) == ["endpoint"]
    access.set_for_user(store, actor(), "analyst_a", ["public"])
    limited = actor("analyst_a", role="analyst")
    assert [row["id"] for row in soar.list_playbooks(store, limited)] == [shared["id"]]
    assert soar.get_playbook(store, limited, shared["id"])["name"] == "Tenant generic"
    with pytest.raises(KeyError):
        soar.get_playbook(store, limited, private["id"])
    with pytest.raises(KeyError):
        soar.get_playbook(store, actor("admin_b", "b"), private["id"])
    access.set_for_user(store, actor(), "analyst_a", ["endpoint"])
    assert (
        soar.get_playbook(store, limited, private["id"])["definition"]["steps"][0][
            "action"
        ]["agent_id"]
        == body["agent_id"]
    )


def test_limited_author_cannot_save_or_remove_private_revision(response_case):
    store, _, _, _, body = response_case
    limited = actor("analyst_a", role="analyst")
    access.set_for_user(store, actor(), "analyst_a", ["endpoint"])
    book = soar.save(store, limited, definition(body))
    access.set_for_user(store, actor(), "analyst_a", ["public"])
    with pytest.raises(KeyError):
        soar.save(store, limited, definition(body))
    replacement = {
        "name": "Scope stripping attempt",
        "version": 1,
        "steps": [
            {
                "id": "note",
                "action": {"type": "add_note", "note": "Generic replacement"},
            }
        ],
    }
    with pytest.raises(KeyError):
        soar.save(store, limited, replacement, book["id"])
    with store.control() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM soar_revisions WHERE playbook_id=?", (book["id"],)
            ).fetchone()[0]
            == 1
        )


@pytest.mark.parametrize("fault", ["unknown_event", "other_agent", "generic_origin"])
def test_save_cannot_invent_registered_evidence_scope(response_case, fault):
    store, _, _, _, body = response_case
    payload = definition(copy.deepcopy(body))
    target = payload["steps"][0]["action"]
    if fault == "unknown_event":
        target["evidence_event_id"] = "not-admitted"
    elif fault == "other_agent":
        target["agent_id"] = "wrong-agent"
    else:
        with store.control() as db:
            db.execute(
                "DELETE FROM endpoint_event_receipts WHERE tenant='a' AND event_id=?",
                (body["evidence_event_id"],),
            )
    with pytest.raises(KeyError):
        soar.save(store, actor(), payload)
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM soar_playbooks").fetchone()[0] == 0


def test_full_revision_scope_guards_run_and_binding_on_public_case(response_case):
    store, _, _, _, body = response_case
    policy_id = public_case(store)
    book = soar.save(store, actor(), definition(body))
    run = soar.start_run(
        store, actor(), book["id"], "public-case", "private-book-public-case"
    )
    binding = soar_bindings.save(
        store,
        actor(),
        {
            "policy_id": policy_id,
            "playbook_id": book["id"],
            "enabled": False,
            "version": 0,
        },
    )
    with store.control() as db:
        assert json.loads(
            db.execute(
                "SELECT scope FROM soar_bindings WHERE id=?", (binding["id"],)
            ).fetchone()[0]
        ) == ["endpoint", "public"]
    access.set_for_user(store, actor(), "analyst_a", ["public"])
    limited = actor("analyst_a", role="analyst")
    with pytest.raises(KeyError):
        soar.start_run(store, limited, book["id"], "public-case", "limited-private")
    with pytest.raises(KeyError):
        soar.get_run(store, limited, run["id"])
    assert soar.list_runs(store, limited, "public-case")["runs"] == []
    assert soar_bindings.listing(store, limited)["bindings"] == []
    with pytest.raises(KeyError):
        soar_bindings.save(
            store,
            limited,
            {
                "policy_id": policy_id,
                "playbook_id": book["id"],
                "enabled": True,
                "version": 1,
            },
        )
    with pytest.raises(KeyError):
        soar.approve(store, limited, run["id"])
    # The creator loses only the book's index, while the case remains readable.
    access.set_for_user(store, actor("admin_other"), "admin_a", ["public"])
    with pytest.raises(KeyError):
        soar.approve(store, actor("admin_other"), run["id"])


def test_old_private_revision_remains_scoped_after_generic_update(response_case):
    store, _, _, _, body = response_case
    public_case(store)
    book = soar.save(store, actor(), definition(body))
    run = soar.start_run(
        store, actor(), book["id"], "public-case", "frozen-old-revision"
    )
    soar.save(
        store,
        actor(),
        {
            "name": "Now generic",
            "version": 1,
            "steps": [
                {
                    "id": "note",
                    "action": {"type": "add_note", "note": "Public future definition"},
                }
            ],
        },
        book["id"],
    )
    access.set_for_user(store, actor(), "analyst_a", ["public"])
    limited = actor("analyst_a", role="analyst")
    assert soar.get_playbook(store, limited, book["id"])["version"] == 2
    with pytest.raises(KeyError):
        soar.get_run(store, limited, run["id"])


def test_legacy_endpoint_revision_without_scope_is_fail_closed(response_case):
    store, _, _, _, body = response_case
    book = soar.save(store, actor(), definition(body))
    shared = generic(store)
    with store.control() as db:
        db.execute("DELETE FROM soar_playbook_scopes")
    access.set_for_user(store, actor(), "analyst_a", ["endpoint", "public"])
    limited = actor("analyst_a", role="analyst")
    assert [row["id"] for row in soar.list_playbooks(store, limited)] == [shared["id"]]
    with pytest.raises(KeyError):
        soar.get_playbook(store, limited, book["id"])
    assert soar.get_playbook(store, actor(), book["id"])["version"] == 1
    soar.save(store, actor(), definition(body, 1), book["id"])
    assert soar.get_playbook(store, limited, book["id"])["version"] == 2
