"""Case closure invariants and approval CAS across an external dispatch."""
import time

import pytest

from sapientia import auth, casework, console_data, detections, principal, soar
from sapientia.storage import ConflictError, Settings, Store, encode


def user(name="maker"):
    return {
        "name": name,
        "tenant": "edge",
        "role": "analyst",
        "allowed_indexes": ["*"],
    }


@pytest.fixture
def edge(tmp_path):
    store = Store(Settings(tmp_path, min_free_bytes=0))
    for name in ("maker", "approver"):
        auth.create_user(
            store, name, "Synthetic-edge-only-password-2026", "analyst", "edge"
        )
    now = time.time()
    with store.control() as db:
        db.execute(
            "INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("case", "edge", "synthetic-host", "host", "Edge case", now, now, "new", "", 1),
        )
        db.execute(
            "INSERT INTO risk_contributions VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("fact", "edge", "case", "policy", "synthetic-host", "host", now, 10,
             encode({"severity": "medium"}), encode(["public"])),
        )
    yield store
    store.close()


def action(store, key, **data):
    return casework.act(store, user(), "case", {"request_id": key, "action": data})


def close(store, status):
    return action(store, "close", type="set_status", status=status, note="Reviewed")


def task_update(store, task_id, version, status):
    return casework.update_task(
        store, user(), "case", task_id,
        {"version": version, "status": status, "assignee": "", "due_at": None},
    )


@pytest.mark.parametrize("closed_status", ["resolved", "false_positive"])
def test_closed_case_rejects_new_unfinished_required_task_atomically(edge, closed_status):
    store = edge
    # The legacy case PATCH and the local action share the same closure guard.
    detections.update_incident(
        store, user(), "case",
        {"status": closed_status, "owner": "maker", "version": 1, "note": "Reviewed"},
    )
    with pytest.raises(ConflictError, match="reopen|closed"):
        action(store, "late-task", type="add_task", title="Required", mandatory=True)
    workspace = casework.workspace(store, user(), "case")
    assert workspace["incident"]["status"] == closed_status
    assert workspace["tasks"] == []
    with store.control() as db:
        assert db.execute(
            "SELECT count(*) FROM case_action_receipts WHERE action_key='late-task'"
        ).fetchone()[0] == 0
    # A rejected key can be used after explicitly reopening the incident.
    action(store, "reopen", type="set_status", status="triage", note="New work")
    action(store, "late-task", type="add_task", title="Required", mandatory=True)
    assert casework.workspace(store, user(), "case")["tasks"][0]["status"] == "open"


@pytest.mark.parametrize("closed_status", ["resolved", "false_positive"])
def test_required_task_reopen_requires_reopening_closed_case(edge, closed_status):
    store = edge
    task = action(store, "required-task", type="add_task", title="Required", mandatory=True)
    task_update(store, task["id"], 1, "done")
    if closed_status == "resolved":
        close(store, closed_status)
    else:
        detections.update_incident(
            store, user(), "case",
            {"status": closed_status, "owner": "", "version": 1, "note": "Reviewed"},
        )
    with pytest.raises(ConflictError, match="reopen|closed"):
        task_update(store, task["id"], 2, "open")
    workspace = casework.workspace(store, user(), "case")
    assert workspace["incident"]["status"] == closed_status
    assert workspace["tasks"][0]["status"] == "done"
    assert workspace["tasks"][0]["version"] == 2
    duplicate = action(store, "required-task", type="add_task", title="Required", mandatory=True)
    assert duplicate["duplicate"] and duplicate["id"] == task["id"]
    # Required work cannot be removed through cancellation either.
    with pytest.raises(ConflictError, match="required"):
        task_update(store, task["id"], 2, "cancelled")
    action(store, "reopen", type="set_status", status="triage", note="Recheck")
    task_update(store, task["id"], 2, "open")
    assert casework.workspace(store, user(), "case")["tasks"][0]["status"] == "open"


def test_closed_case_allows_optional_followup_and_legacy_task_completion(edge):
    store = edge
    required = action(store, "required", type="add_task", title="Required", mandatory=True)
    task_update(store, required["id"], 1, "done")
    close(store, "resolved")
    optional = action(store, "optional", type="add_task", title="Optional followup")
    task_update(store, optional["id"], 1, "cancelled")
    action(store, "note", type="add_note", note="Post-resolution review")
    # Repair an old-version inconsistent case without requiring it to remain open.
    with store.control() as db:
        db.execute("UPDATE case_tasks SET status='open' WHERE id=?", (required["id"],))
    task_update(store, required["id"], 2, "done")
    workspace = casework.workspace(store, user(), "case")
    assert workspace["incident"]["status"] == "resolved"
    assert {item["status"] for item in workspace["tasks"]} == {"done", "cancelled"}


class FakeWebhooks:
    fingerprint = "synthetic-config"

    def __init__(self):
        self.destinations = {"fixture": {}}

    @staticmethod
    def guaranteed(destination):
        return False


def approved_run(store, actions):
    saved = soar.save(store, user(), {
        "name": "Edge playbook", "version": 0,
        "steps": [{"id": "s" + str(i), "action": item} for i, item in enumerate(actions)],
    })
    run = soar.start_run(store, user(), saved["id"], "case", "run-request")
    soar.approve(store, user("approver"), run["id"])
    return run["id"]


@pytest.mark.parametrize("change", ["status", "owner"])
def test_webhook_ack_does_not_absorb_concurrent_incident_cas_change(edge, change):
    store = edge
    client = FakeWebhooks()

    def acknowledge_after_change(*args):
        detections.update_incident(
            store, user("approver"), "case",
            {"version": 1, "status": "false_positive" if change == "status" else "new",
             "owner": "approver" if change == "owner" else "", "note": "Changed in transit"},
        )
        return {"type": "webhook", "outcome": "acknowledged", "status_code": 200}

    client.send = acknowledge_after_change
    store.soar_webhooks = client
    run_id = approved_run(store, [
        {"type": "webhook", "destination": "fixture", "payload": {}},
        {"type": "set_status", "status": "resolved", "note": "Old approval"},
    ])
    assert soar.run_due(store) == 1
    acknowledged = soar.get_run(store, user(), run_id)
    assert acknowledged["steps"][0]["state"] == "completed"
    assert acknowledged["steps"][0]["result"]["outcome"] == "acknowledged"
    assert acknowledged["expected_incident_version"] == 1
    assert soar.run_due(store) == 1
    result = soar.get_run(store, user(), run_id)
    assert result["state"] == "failed"
    assert result["steps"][1]["state"] == "failed"
    incident = casework.workspace(store, user(), "case")["incident"]
    assert incident["version"] == 2
    assert incident["status"] == ("false_positive" if change == "status" else "new")
    assert incident["owner"] == ("approver" if change == "owner" else "")


def test_unchanged_webhook_then_local_actions_advance_own_version(edge):
    store = edge
    client = FakeWebhooks()
    client.send = lambda *args: {"type": "webhook", "outcome": "acknowledged", "status_code": 200}
    store.soar_webhooks = client
    run_id = approved_run(store, [
        {"type": "webhook", "destination": "fixture", "payload": {}},
        {"type": "set_status", "status": "triage", "note": "Reviewed"},
        {"type": "set_status", "status": "resolved", "note": "Finished"},
    ])
    for expected_version in (1, 2, 3):
        assert soar.run_due(store) == 1
        assert soar.get_run(store, user(), run_id)["expected_incident_version"] == expected_version
    assert soar.get_run(store, user(), run_id)["state"] == "completed"
    assert casework.workspace(store, user(), "case")["incident"]["status"] == "resolved"


def test_approved_playbook_cannot_add_required_work_to_closed_case(edge):
    store = edge
    close(store, "resolved")
    run_id = approved_run(store, [{"type": "add_task", "title": "Required", "mandatory": True}])
    assert soar.run_due(store) == 1
    assert soar.get_run(store, user(), run_id)["state"] == "failed"
    workspace = casework.workspace(store, user(), "case")
    assert workspace["incident"]["status"] == "resolved"
    assert workspace["tasks"] == []


def test_public_manual_action_cannot_claim_pending_soar_step_key(edge):
    store = edge
    note = {"type": "add_note", "note": "Reviewed"}
    saved = soar.save(store, user(), {
        "name": "Reserved key", "version": 0, "steps": [{"id": "note", "action": note}],
    })
    run = soar.start_run(store, user(), saved["id"], "case", "key-request")
    with pytest.raises(ValueError, match="reserved"):
        action(store, run["id"] + ":note", **note)
    assert casework.workspace(store, user(), "case")["notes"] == []
    assert soar.run_due(store) == 0
    soar.approve(store, user("approver"), run["id"])
    assert soar.run_due(store) == 1
    result = soar.get_run(store, user(), run["id"])
    assert result["state"] == "completed"
    assert not result["steps"][0]["result"]["duplicate"]


@pytest.mark.parametrize("same_content", [True, False])
def test_preupgrade_manual_receipt_collision_fails_closed(edge, same_content):
    store = edge
    note = {"type": "add_note", "note": "Approved note"}
    saved = soar.save(store, user(), {
        "name": "Old receipt", "version": 0, "steps": [{"id": "note", "action": note}],
    })
    run = soar.start_run(store, user(), saved["id"], "case", "old-key-request")
    # Simulate a manual receipt written by the previous version's public API.
    old_note = note if same_content else {"type": "add_note", "note": "Different manual note"}
    with principal.transaction(store, user(), ("analyst",), write=True) as (db, actor):
        receipt = casework.apply_action(db, store, actor, "case", old_note, run["id"] + ":note")
    soar.approve(store, user("approver"), run["id"])
    assert soar.run_due(store) == 1
    result = soar.get_run(store, user(), run["id"])
    assert result["state"] == "failed"
    assert result["steps"][0]["state"] == "failed"
    assert result["steps"][0]["result"] is None
    notes = casework.workspace(store, user(), "case")["notes"]
    assert len(notes) == 1 and notes[0]["id"] == receipt["id"]
    summary = console_data.summary(store, user(), time.time() - 3600)
    assert summary["cases"]["response_actions"]["soar"] == 0
    assert summary["cases"]["response_actions"]["unattributed"] == 1
    assert summary["cases"]["response_modes"]["attention"] == 1


def test_normal_manual_request_id_remains_idempotent(edge):
    store = edge
    original = action(store, "manual:review", type="add_note", note="Manual")
    repeated = action(store, "manual:review", type="add_note", note="Manual")
    assert repeated["duplicate"] and original["id"] == repeated["id"]
    summary = console_data.summary(store, user(), time.time() - 3600)
    assert summary["cases"]["response_actions"]["manual"] == 1
    assert summary["cases"]["response_actions"]["soar"] == 0
