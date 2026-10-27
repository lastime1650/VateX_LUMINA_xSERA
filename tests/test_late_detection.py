import json
import threading
import time

import pytest

from sapientia import access, auth, detections
from sapientia.storage import CapacityError, ConflictError, Settings, Store, encode


def user(name="maker", role="analyst", tenant="a", scope=None):
    return {
        "name": name,
        "role": role,
        "tenant": tenant,
        "allowed_indexes": ["*"] if scope is None else scope,
    }


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path, min_free_bytes=0))
    for name, role, tenant in [
        ("maker", "analyst", "a"),
        ("requester", "analyst", "a"),
        ("admin_a", "admin", "a"),
        ("viewer_a", "viewer", "a"),
        ("outsider", "analyst", "b"),
    ]:
        auth.create_user(
            value, name, "Synthetic-late-detection-password-2026", role, tenant
        )
    yield value
    value.close()


def policy(delay=0, cooldown=0, event_id=None):
    return {
        "name": "Late arrival",
        "entity_field": "raw.user",
        "window": 30,
        "interval": 30,
        "cooldown": cooldown,
        "evaluation_delay": delay,
        "steps": [
            {
                "filters": []
                if event_id is None
                else [{"field": "event_id", "op": "eq", "value": event_id}]
            }
        ],
    }


def schedule(store, definition, end):
    pid = detections.save(store, user(), definition)
    with store.control() as db:
        db.execute("UPDATE correlation_policies SET next_run=? WHERE id=?", (end, pid))
    return pid


def event(store, event_id, at, entity="alice", index="public", flush=True):
    store.ingest(
        "a",
        [
            {
                "event_id": event_id,
                "event_time": at,
                "index": index,
                "raw": {"user": entity},
            }
        ],
    )
    if flush:
        store.flush()


def facts(store):
    with store.control() as db:
        return [
            dict(r)
            for r in db.execute("SELECT * FROM risk_contributions ORDER BY at,id")
        ]


def cursor(store, pid):
    with store.control() as db:
        return dict(
            db.execute(
                "SELECT next_run,last_end,retry_at FROM correlation_policies WHERE id=?",
                (pid,),
            ).fetchone()
        )


@pytest.mark.parametrize("delay", [-1, 86401, True, 1.5, "60", []])
def test_delay_validation(delay):
    with pytest.raises(ValueError):
        detections.validate(policy(delay))


def test_delay_waits_admitted_queue_and_preserves_schedule_cursor(store):
    data_end = time.time()
    scheduled_end = data_end + 60
    pid = schedule(store, policy(delay=60), scheduled_end)
    event(store, "late-window", data_end - 10, flush=False)
    assert detections.run_due(store, scheduled_end) == 0
    assert cursor(store, pid)["next_run"] == scheduled_end
    store.flush()
    assert detections.run_due(store, scheduled_end + 2) == 1
    result = facts(store)
    assert len(result) == 1 and result[0]["at"] == data_end
    evidence = json.loads(result[0]["evidence"])
    assert evidence["window_end"] == data_end
    assert evidence["evaluation"] == {
        "mode": "scheduled",
        "scheduled_end": scheduled_end,
        "data_end": data_end,
        "evaluation_delay": 60,
        "policy_version": 1,
    }
    assert cursor(store, pid)["next_run"] == scheduled_end + 30
    assert cursor(store, pid)["last_end"] == data_end


def test_legacy_definition_has_zero_delay(store):
    end = time.time()
    definition = policy()
    definition.pop("evaluation_delay")
    pid = schedule(store, definition, end)
    with store.control() as db:
        legacy = json.loads(
            db.execute(
                "SELECT definition FROM correlation_policies WHERE id=?", (pid,)
            ).fetchone()[0]
        )
        legacy.pop("evaluation_delay")
        db.execute(
            "UPDATE correlation_policies SET definition=? WHERE id=?",
            (encode(legacy), pid),
        )
    event(store, "legacy", end - 2)
    assert detections.run_due(store, end + 1) == 1
    assert facts(store)[0]["at"] == end


def test_replay_recovers_late_event_without_cursor_advance_and_dedups(store):
    end = time.time() - 100
    pid = schedule(store, policy(), end)
    assert detections.run_due(store, end) == 1 and facts(store) == []
    before = cursor(store, pid)
    event(store, "arrived-after-scheduled-run", end - 5)
    result = detections.replay(store, user("requester"), pid, end, 1, "stable-request")
    assert result["emitted"] == 1 and result["matches"] == 1 and not result["duplicate"]
    assert cursor(store, pid) == before
    duplicate = detections.replay(
        store, user("requester"), pid, end, 1, "stable-request"
    )
    assert duplicate["id"] == result["id"] and duplicate["duplicate"]
    again = detections.replay(store, user("requester"), pid, end, 1, "separate-request")
    assert again["deduplicated"] == 1 and again["emitted"] == 0
    assert len(facts(store)) == 1 and facts(store)[0]["at"] == end
    with pytest.raises(ConflictError, match="different content"):
        detections.replay(store, user("requester"), pid, end - 1, 1, "stable-request")
    assert cursor(store, pid) == before


def test_replay_uses_exact_end_and_does_not_double_apply_delay(store):
    end = time.time() - 20
    pid = schedule(store, policy(delay=60), time.time() + 100)
    event(store, "explicit-window", end - 2)
    result = detections.replay(store, user(), pid, end, 1, "explicit")
    assert result["emitted"] == 1
    evidence = json.loads(facts(store)[0]["evidence"])
    assert evidence["window_end"] == end and evidence["evaluation"]["mode"] == "replay"


def test_historical_cooldown_uses_distance_and_incident_time_never_regresses(store):
    end = time.time() - 10
    pid = schedule(store, policy(cooldown=60), end + 1000)
    event(store, "latest", end - 1)
    assert detections.replay(store, user(), pid, end, 1, "latest")["emitted"] == 1
    event(store, "historical", end - 301)
    assert (
        detections.replay(store, user(), pid, end - 300, 1, "historical")["emitted"]
        == 1
    )
    event(store, "nearby", end - 31)
    result = detections.replay(store, user(), pid, end - 30, 1, "nearby")
    assert result["notification_throttled"] == 1 and result["emitted"] == 1
    assert len(facts(store)) == 3
    with store.control() as db:
        incidents = db.execute("SELECT * FROM incidents").fetchall()
        assert len(incidents) == 1 and incidents[0]["updated"] == end


@pytest.mark.parametrize(
    "bad_end", [True, 0, -1, "now", [], float("nan"), float("inf")]
)
def test_replay_time_validation(store, bad_end):
    with pytest.raises(ValueError):
        detections.replay(store, user(), "missing", bad_end, 1, "request")


@pytest.mark.parametrize(
    "version,request_id",
    [
        (True, "x"),
        (0, "x"),
        (1.1, "x"),
        (1, ""),
        (1, "x" * 65),
        (1, "한글"),
        (1, []),
        ([], "x"),
    ],
)
def test_replay_version_and_request_validation(store, version, request_id):
    with pytest.raises(ValueError):
        detections.replay(
            store, user(), "missing", time.time() - 1, version, request_id
        )


def test_replay_current_role_tenant_owner_and_result_scope(store):
    end = time.time() - 1
    pid = schedule(store, policy(), end + 1000)
    event(store, "public", end - 2, entity="public-entity")
    event(store, "private", end - 2, entity="private-entity", index="private")
    limited = user("requester", scope=["public"])
    result = detections.replay(store, limited, pid, end, 1, "limited")
    assert result["matches"] == 1 and result["scope"] == ["public"]
    assert {f["entity"] for f in facts(store)} == {"public-entity"}
    with pytest.raises(PermissionError):
        detections.replay(store, user("viewer_a", role="viewer"), pid, end, 1, "viewer")
    with pytest.raises(KeyError):
        detections.replay(store, user("outsider", tenant="b"), pid, end, 1, "outside")
    access.set_for_user(store, user("admin_a", role="admin"), "requester", [])
    with pytest.raises(PermissionError, match="scope"):
        detections.replay(store, limited, pid, end, 1, "limited")


@pytest.mark.parametrize("account", ["maker", "requester"])
@pytest.mark.parametrize("change", ["disabled", "must_change", "role", "scope"])
def test_replay_rechecks_current_accounts_before_atomic_emission(
    store, monkeypatch, account, change
):
    end = time.time() - 1
    pid = schedule(store, policy(), end + 1000)
    event(store, "race", end - 2)
    original = detections.evaluate

    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        if change == "scope":
            access.set_for_user(store, user("admin_a", role="admin"), account, [])
        else:
            with store.control() as db:
                db.execute(
                    "UPDATE users SET " + change + "=? WHERE name=?",
                    ("viewer" if change == "role" else 1, account),
                )
        return result

    monkeypatch.setattr(detections, "evaluate", changed)
    with pytest.raises(PermissionError):
        detections.replay(store, user("requester"), pid, end, 1, "race")
    assert facts(store) == []
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM correlation_replays").fetchone()[0] == 0


def test_policy_version_change_during_replay_cannot_emit(store, monkeypatch):
    end = time.time() - 1
    pid = schedule(store, policy(), end + 1000)
    event(store, "version-race", end - 2)
    original = detections.evaluate

    def change(*args, **kwargs):
        result = original(*args, **kwargs)
        detections.toggle(store, user(), pid, False, 1)
        return result

    monkeypatch.setattr(detections, "evaluate", change)
    with pytest.raises(ConflictError):
        detections.replay(store, user(), pid, end, 1, "version")
    assert facts(store) == []


def test_private_bookmark_hides_legacy_detail_feedback_and_prevents_reuse(store):
    end = time.time() - 1
    first = schedule(store, policy(event_id="first"), end + 1000)
    event(store, "first", end - 3)
    detections.replay(store, user(), first, end, 1, "first")
    old = facts(store)[0]["incident_id"]
    with store.control() as db:
        db.execute(
            "INSERT INTO case_bookmarks VALUES(?,?,?,?,?,?,?,?,?)",
            (
                "private-bookmark",
                "a",
                old,
                "private-event",
                "private",
                "Private",
                "maker",
                time.time(),
                encode({"message": "Private evidence"}),
            ),
        )
        db.execute(
            "INSERT INTO incident_feedback(tenant,incident_id,actor,at,status,note) VALUES(?,?,?,?,?,?)",
            (
                "a",
                old,
                "maker",
                time.time(),
                "triage",
                "Private context in reviewer feedback",
            ),
        )
    limited = user("requester", scope=["public"])
    assert detections.incident_list(store, limited) == []
    with pytest.raises(KeyError):
        detections.incident_detail(store, limited, old)
    second = schedule(store, policy(event_id="second"), end + 1000)
    event(store, "second", end - 2)
    assert detections.replay(store, limited, second, end, 1, "second")["emitted"] == 1
    assert len({f["incident_id"] for f in facts(store)}) == 2
    visible = detections.incident_list(store, limited)
    assert len(visible) == 1 and visible[0]["id"] != old


def test_scheduler_acl_revoke_after_evaluation_cannot_persist(store, monkeypatch):
    end = time.time()
    pid = schedule(store, policy(), end)
    event(store, "scheduled-race", end - 2)
    original = detections.evaluate

    def change(*args, **kwargs):
        result = original(*args, **kwargs)
        access.set_for_user(store, user("admin_a", role="admin"), "maker", [])
        return result

    monkeypatch.setattr(detections, "evaluate", change)
    assert detections.run_due(store, end + 1) == 0 and facts(store) == []
    assert cursor(store, pid)["next_run"] == end


def test_pending_queue_and_cancellation_do_not_emit(store):
    end = time.time() - 1
    pid = schedule(store, policy(), end + 1000)
    event(store, "pending", end - 2, flush=False)
    with pytest.raises(CapacityError, match="Indexing"):
        detections.replay(store, user(), pid, end, 1, "pending")
    store.flush()
    stop = threading.Event()
    stop.set()
    with pytest.raises(RuntimeError, match="cancelled"):
        detections.replay(store, user(), pid, end, 1, "cancelled", cancel=stop)
    assert facts(store) == []
