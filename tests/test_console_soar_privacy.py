"""Private workflow revisions stay private even on a visible public case.

Authenticated enrollment/evidence is real synthetic intake; historical linked
receipt rows are control-projection fixtures, never dispatched OS actions.
"""
# ruff: noqa: F811 -- Imported pytest fixtures are injected by argument name.

import time

import pytest

from sapientia import access, console_data, soar
from sapientia.storage import encode
from tests.test_agent_distribution import config, source_store  # noqa: F401
from tests.test_endpoint_response import response_case  # noqa: F401
from tests.test_soar_endpoint_acl import definition, public_case
from tests.test_xdr_bridge import actor


def summary(store, who):
    return console_data.summary(store, who, time.time() - 3600)


def test_private_playbook_pending_mode_hidden_on_authorized_public_case(response_case):
    store, _, _, _, body = response_case
    public_case(store)
    book = soar.save(store, actor(), definition(body))
    soar.start_run(store, actor(), book["id"], "public-case", "private-public")
    assert summary(store, actor())["cases"]["response_modes"]["awaiting_approval"] == 1
    access.set_for_user(store, actor(), "analyst_a", ["public"])
    value = summary(store, actor("analyst_a", role="analyst"))
    assert value["cases"]["total"] == 1
    assert value["cases"]["response_modes"]["awaiting_approval"] == 0
    assert value["cases"]["response_modes"]["unhandled"] == 1
    assert value["cases"]["recent"][0]["response_mode"] == "unhandled"


@pytest.mark.parametrize("legacy", [False, True])
def test_private_linked_receipts_and_endpoint_projection_not_reclassified_manual(
    response_case, legacy
):
    store, _, _, _, body = response_case
    public_case(store)
    book = soar.save(store, actor(), definition(body))
    run = soar.start_run(
        store, actor(), book["id"], "public-case", "private-completed-fixture"
    )
    now = time.time()
    # Seed only a historical control projection. No command is sent or executed.
    with store.control() as db:
        db.execute("UPDATE soar_runs SET state='completed' WHERE id=?", (run["id"],))
        db.execute(
            "UPDATE soar_steps SET state='completed' WHERE run_id=?", (run["id"],)
        )
        db.execute(
            "INSERT INTO case_action_receipts VALUES(?,?,?,?,?,?)",
            (
                "a",
                run["id"] + ":inspect",
                "public-case",
                "fixture",
                encode({"type": "add_note"}),
                now,
            ),
        )
        db.execute(
            "INSERT INTO endpoint_responses(id,tenant,incident_id,agent_id,host,index_name,requester,scope,request_id,request_digest,evidence_event_id,case_version,action,reason,state,created,expires) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "queued-projection-fixture",
                "a",
                "public-case",
                "projection-only-agent",
                "public-host",
                "public",
                "admin_a",
                '["public"]',
                "fixture",
                "fixture",
                "fixture",
                1,
                encode({"type": "inspect_file"}),
                "Synthetic control-only privacy projection",
                "queued",
                now,
                now + 60,
            ),
        )
        db.execute(
            "INSERT INTO endpoint_response_workflow VALUES(?,?,?)",
            ("queued-projection-fixture", run["id"], 0),
        )
        if legacy:
            db.execute(
                "DELETE FROM soar_playbook_scopes WHERE playbook_id=?", (book["id"],)
            )
    wide = summary(store, actor())
    assert wide["cases"]["response_actions"]["soar"] == 1
    assert wide["cases"]["endpoint_responses"]["requested"] == 1
    access.set_for_user(
        store,
        actor(),
        "analyst_a",
        ["public"] if not legacy else ["public", "endpoint"],
    )
    value = summary(store, actor("analyst_a", role="analyst"))
    assert value["cases"]["response_modes"]["completed"] == 0
    assert value["cases"]["response_actions"]["soar"] == 0
    assert value["cases"]["response_actions"]["manual"] == 0
    assert value["cases"]["endpoint_responses"]["requested"] == 0


def test_revision_scope_not_current_generic_book_scope_and_legacy_generic_visible(
    response_case,
):
    store, _, _, _, body = response_case
    public_case(store)
    book = soar.save(store, actor(), definition(body))
    soar.start_run(store, actor(), book["id"], "public-case", "old-private-revision")
    soar.save(
        store,
        actor(),
        {
            "name": "Generic next revision",
            "version": 1,
            "steps": [
                {"id": "note", "action": {"type": "add_note", "note": "Generic"}}
            ],
        },
        book["id"],
    )
    access.set_for_user(store, actor(), "analyst_a", ["public"])
    limited = actor("analyst_a", role="analyst")
    assert summary(store, limited)["cases"]["response_modes"]["awaiting_approval"] == 0
    soar.start_run(store, limited, book["id"], "public-case", "new-generic-revision")
    with store.control() as db:
        db.execute(
            "DELETE FROM soar_playbook_scopes WHERE playbook_id=? AND version=2",
            (book["id"],),
        )
    assert summary(store, limited)["cases"]["response_modes"]["awaiting_approval"] == 1
