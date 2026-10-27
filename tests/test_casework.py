import hashlib
import json
import time

import pytest

from sapientia import access, auth, casework, detections
from sapientia.storage import ConflictError, Settings, Store, encode


@pytest.fixture
def case(tmp_path):
    store = Store(Settings(tmp_path, min_free_bytes=0))
    for name, tenant, role in [
        ("analyst", "a", "analyst"),
        ("admin_a", "a", "admin"),
        ("viewer_a", "a", "viewer"),
        ("outsider", "b", "analyst"),
    ]:
        auth.create_user(store, name, "Synthetic-case-work-password-2026", role, tenant)
    actor = {
        "name": "analyst",
        "tenant": "a",
        "role": "analyst",
        "allowed_indexes": ["*"],
    }
    now = time.time()
    store.ingest(
        "a",
        [
            {
                "event_id": "case-event",
                "event_time": now - 2,
                "index": "public",
                "raw": {"user": "alice"},
            },
            {
                "event_id": "private-event",
                "event_time": now - 1,
                "index": "private",
                "message": "Restricted evidence",
            },
        ],
    )
    store.flush()
    detections.save(
        store,
        actor,
        {
            "name": "Case evidence",
            "entity_field": "raw.user",
            "window": 300,
            "steps": [
                {"filters": [{"field": "event_id", "op": "eq", "value": "case-event"}]}
            ],
        },
    )
    # The policy is scheduled at save time, after ingest/flush may have waited.
    assert detections.run_due(store, time.time() + 1) == 1
    incident_id = detections.incident_list(store, actor)[0]["id"]
    yield store, actor, incident_id
    store.close()


def act(store, actor, incident_id, key, **action):
    return casework.act(
        store, actor, incident_id, {"request_id": key, "action": action}
    )


def test_local_action_is_exactly_once_and_conflict_atomic(case):
    store, actor, incident_id = case
    first = act(
        store,
        actor,
        incident_id,
        "stable-note",
        type="add_note",
        note="Investigated original event",
    )
    retry = act(
        store,
        actor,
        incident_id,
        "stable-note",
        type="add_note",
        note="Investigated original event",
    )
    assert retry["id"] == first["id"] and retry["duplicate"]
    with pytest.raises(ConflictError):
        act(
            store,
            actor,
            incident_id,
            "stable-note",
            type="add_note",
            note="Different action",
        )
    workspace = casework.workspace(store, actor, incident_id)
    assert len(workspace["notes"]) == 1
    with store.control() as db:
        assert (
            db.execute(
                "SELECT count(*) FROM audit WHERE action='case.action'"
            ).fetchone()[0]
            == 1
        )


def test_required_tasks_gate_both_response_and_legacy_resolution(case):
    store, actor, incident_id = case
    task = act(
        store,
        actor,
        incident_id,
        "task",
        type="add_task",
        title="Verify compromise",
        mandatory=True,
        assignee="analyst",
    )
    with pytest.raises(ConflictError):
        act(
            store,
            actor,
            incident_id,
            "close",
            type="set_status",
            status="resolved",
            note="Finished",
        )
    with pytest.raises(ConflictError):
        detections.update_incident(
            store,
            actor,
            incident_id,
            {
                "status": "resolved",
                "owner": "analyst",
                "note": "Finished",
                "version": 1,
            },
        )
    with pytest.raises(ConflictError):
        casework.update_task(
            store,
            actor,
            incident_id,
            task["id"],
            {
                "version": 1,
                "status": "cancelled",
                "assignee": "analyst",
                "due_at": None,
            },
        )
    casework.update_task(
        store,
        actor,
        incident_id,
        task["id"],
        {"version": 1, "status": "done", "assignee": "analyst", "due_at": None},
    )
    with pytest.raises(ConflictError):
        casework.update_task(
            store,
            actor,
            incident_id,
            task["id"],
            {"version": 1, "status": "open", "assignee": "analyst", "due_at": None},
        )
    assert (
        act(
            store,
            actor,
            incident_id,
            "close",
            type="set_status",
            status="resolved",
            note="Evidence reviewed",
        )["status"]
        == "resolved"
    )


def test_case_assignee_and_current_permissions(case):
    store, actor, incident_id = case
    for name in ("outsider", "missing", "viewer_a"):
        with pytest.raises(ValueError):
            act(
                store,
                actor,
                incident_id,
                "assign-" + name,
                type="assign",
                assignee=name,
            )
    with pytest.raises(KeyError):
        casework.workspace(
            store, {"name": "outsider", "tenant": "b", "role": "analyst"}, incident_id
        )
    with pytest.raises(PermissionError):
        act(
            store,
            {"name": "viewer_a", "tenant": "a", "role": "viewer"},
            incident_id,
            "viewer",
            type="add_note",
            note="No",
        )
    admin = {"name": "admin_a", "tenant": "a", "role": "admin"}
    access.set_for_user(store, admin, "analyst", [])
    with pytest.raises(KeyError):
        casework.workspace(store, actor, incident_id)
    with store.control() as db:
        db.execute("UPDATE users SET disabled=1 WHERE name='analyst'")
    with pytest.raises(PermissionError):
        act(store, actor, incident_id, "revoked", type="add_note", note="No")


def test_private_bookmark_protects_case_context_and_export(case):
    store, actor, incident_id = case
    bookmark = casework.bookmark(
        store,
        actor,
        incident_id,
        {"event_id": "private-event", "label": "Additional evidence"},
    )
    assert not bookmark["duplicate"]
    assert casework.bookmark(
        store, actor, incident_id, {"event_id": "private-event", "label": "Retry"}
    )["duplicate"]
    limited = {**actor, "allowed_indexes": ["public"]}
    for operation in (casework.workspace, casework.export_case):
        with pytest.raises(KeyError):
            operation(store, limited, incident_id)
    with pytest.raises(KeyError):
        act(
            store,
            limited,
            incident_id,
            "limited",
            type="add_note",
            note="No hidden context",
        )
    exported = casework.export_case(store, actor, incident_id)
    digest = exported.pop("sha256")
    exported.pop("integrity_note")
    assert digest == hashlib.sha256(encode(exported).encode()).hexdigest()
    assert (
        json.loads(exported["bookmarks"][0]["event"])["message"]
        == "Restricted evidence"
    )


def test_workspace_sla_version_and_input_validation(case):
    store, actor, incident_id = case
    body = {
        "version": 0,
        "priority": "high",
        "due_at": time.time() - 1,
        "tags": ["identity", "review"],
    }
    assert casework.configure(store, actor, incident_id, body)["version"] == 1
    assert casework.workspace(store, actor, incident_id)["workspace"]["overdue"]
    with pytest.raises(ConflictError):
        casework.configure(store, actor, incident_id, body)
    with pytest.raises(ValueError):
        casework.configure(store, actor, incident_id, {**body, "due_at": float("nan")})
    with pytest.raises(ValueError):
        act(store, actor, incident_id, "unknown", type="run_shell", command="anything")
