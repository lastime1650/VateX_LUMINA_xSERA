import copy
import json
from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sapientia.endpoint_agent.Agent.defense import SCHEMA, Defense, canonical
from sapientia.xdr_bridge import parse_event

NOW = 1800000000


@pytest.fixture
def setup(tmp_path):
    key = Ed25519PrivateKey.generate()
    config = {
        "host": "fixture-host",
        "tenant": "default",
        "agent_id": "fixture-agent",
        "index": "endpoint",
        "state_dir": str(tmp_path / "state"),
        "defense": {
            "enabled": True,
            "public_key": key.public_key().public_bytes_raw().hex(),
            "bundle_file": str(tmp_path / "policy.json"),
        },
        "response": {"enabled": True},
    }
    calls = []
    response = SimpleNamespace(
        Lock=lambda _: nullcontext(),
        execute=lambda *args: (
            calls.append(args)
            or {"success": True, "executed": True, "code": "fixture_effect"}
        ),
    )
    doc = {
        "schema": SCHEMA,
        "host": config["host"],
        "tenant": config["tenant"],
        "agent_id": config["agent_id"],
        "index": config["index"],
        "revision": 1,
        "issued_at": NOW - 60,
        "expires_at": NOW + 3600,
        "rules": [
            {
                "id": "fixture-rule",
                "enabled": True,
                "severity": "high",
                "action": "terminate_process",
                "conditions": [
                    {
                        "field": "process.command_line",
                        "op": "contains",
                        "value": "fixture-only-marker",
                    }
                ],
                "mitre": ["T1059"],
            }
        ],
    }
    event = {
        "id": "native-fixture-1",
        "data": {
            "@timestamp": "2027-01-15T08:00:00Z",
            "host": {"id": config["host"], "os": {"type": "windows"}},
            "process": {
                "guid": "fixture-process",
                "pid": 400,
                "start_identity": "windows:12345",
                "name": "fixture.exe",
                "command_line": "fixture-only-marker",
            },
            "event": {"action": "process_created"},
        },
    }

    def write(value=None):
        value = doc if value is None else value
        Path = __import__("pathlib").Path
        Path(config["defense"]["bundle_file"]).write_text(
            json.dumps(
                {"document": value, "signature": key.sign(canonical(value)).hex()}
            ),
            encoding="utf-8",
        )

    write()
    return config, doc, event, calls, response, write


def test_signed_local_policy_offline_effect_receipt_restart_and_wire(setup):
    config, _doc, event, calls, response, _ = setup
    d = Defense(config, response, clock=lambda: NOW)
    assert d.health()["state"] == "active"
    first = d.evaluate([event])
    assert len(first) == 1 and len(calls) == 1
    assert first[0]["data"]["local_defense"]["outcome"]["executed"] is True
    parse_event(first[0], "agent", "main", expected_host=config["host"])
    d.close()
    d = Defense(config, response, clock=lambda: NOW)
    assert d.evaluate([event]) == first
    assert len(calls) == 1
    d.close()


@pytest.mark.parametrize(
    "mutation",
    [
        "signature",
        "tenant",
        "host",
        "expiry",
        "future",
        "bool_revision",
        "unknown_operator",
        "missing_condition",
    ],
)
def test_invalid_or_unbound_policy_never_executes(setup, mutation):
    config, doc, event, calls, response, write = setup
    if mutation == "signature":
        config["defense"]["public_key"] = (
            Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
        )
    else:
        changes = {
            "tenant": {"tenant": "other"},
            "host": {"host": "other"},
            "expiry": {"expires_at": NOW - 1},
            "future": {"issued_at": NOW + 3600},
            "bool_revision": {"revision": True},
        }
        if mutation in changes:
            doc.update(changes[mutation])
        elif mutation == "unknown_operator":
            doc["rules"][0]["conditions"][0]["op"] = "execute_shell"
        else:
            doc["rules"][0]["conditions"] = []
        write(doc)
    d = Defense(config, response, clock=lambda: NOW)
    assert d.health()["state"] == "degraded"
    assert d.evaluate([event]) == [] and calls == []
    d.close()


def test_rollback_and_same_revision_mutation_rejected(setup):
    config, doc, event, calls, response, write = setup
    doc["revision"] = 2
    write(doc)
    d = Defense(config, response, clock=lambda: NOW)
    d.close()
    doc["revision"] = 1
    write(doc)
    d = Defense(config, response, clock=lambda: NOW)
    assert d.health()["state"] == "degraded"
    d.close()
    doc["revision"] = 2
    doc["rules"][0]["severity"] = "critical"
    write(doc)
    d = Defense(config, response, clock=lambda: NOW)
    assert d.evaluate([event]) == [] and calls == []
    d.close()


def test_exact_identity_required_and_safe_exception(setup):
    config, doc, event, calls, response, write = setup
    doc["rules"][0]["exceptions"] = [
        [{"field": "process.name", "op": "eq", "value": "good.exe"}]
    ]
    write(doc)
    d = Defense(config, response, clock=lambda: NOW)
    good = copy.deepcopy(event)
    good["data"]["process"]["name"] = "good.exe"
    assert d.evaluate([good]) == []
    event["data"]["process"].pop("start_identity")
    result = d.evaluate([event])
    assert (
        result[0]["data"]["local_defense"]["outcome"]["code"] == "identity_unavailable"
        and calls == []
    )
    d.close()


def test_crash_marker_becomes_unknown_and_never_replays(setup):
    config, doc, event, calls, response, _write = setup
    d = Defense(config, response, clock=lambda: NOW)
    import hashlib

    identifier = hashlib.sha256(
        canonical([d.digest, doc["rules"][0]["id"], event["id"]])
    ).hexdigest()
    digest = hashlib.sha256(canonical(event)).hexdigest()
    with d.db:
        d.db.execute(
            "INSERT INTO local_effects VALUES(?,'executing',NULL,?,?)",
            (identifier, NOW, digest),
        )
    d.close()
    d = Defense(config, response, clock=lambda: NOW)
    result = d.evaluate([event])
    assert result[0]["data"]["local_defense"]["outcome"]["executed"] is None
    assert calls == []
    d.close()


def test_source_content_conflict_disabled_policy_and_missing_fields(setup):
    config, _doc, event, calls, response, _write = setup
    d = Defense(config, response, clock=lambda: NOW)
    assert d.evaluate([event])
    changed = copy.deepcopy(event)
    changed["data"]["process"]["pid"] += 1
    assert d.evaluate([changed]) == [] and d.health()["state"] == "degraded"
    assert len(calls) == 1
    d.close()
    config["defense"]["enabled"] = False
    d = Defense(config, response, clock=lambda: NOW)
    assert d.health()["state"] == "disabled" and d.evaluate([event]) == []


def test_expiry_during_runtime_and_empty_spool(setup):
    config, doc, event, calls, response, _ = setup
    now = [NOW]
    d = Defense(config, response, clock=lambda: now[0])
    assert d.evaluate([]) == []
    now[0] = doc["expires_at"]
    assert d.health()["state"] == "expired" and d.evaluate([event]) == [] and not calls
    d.close()


def test_control_worker_update_is_verified_and_main_thread_reloads(setup):
    config, doc, event, calls, response, write = setup
    from concurrent.futures import ThreadPoolExecutor

    d = Defense(config, response, clock=lambda: NOW)
    doc["revision"] = 2
    doc["rules"][0]["action"] = "observe"
    write(doc)
    bundle = json.loads(
        __import__("pathlib")
        .Path(config["defense"]["bundle_file"])
        .read_text(encoding="utf-8")
    )
    # update does not access a SQLite connection created on another thread.
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert pool.submit(d.update, bundle).result() is True
    result = d.evaluate([event])
    assert (
        d.health()["revision"] == 2
        and result[0]["data"]["local_defense"]["outcome"]["code"] == "observed"
    )
    assert not calls
    d.close()


def test_invalid_control_update_preserves_existing_file(setup):
    config, _doc, _event, _calls, response, _write = setup
    d = Defense(config, response, clock=lambda: NOW)
    path = __import__("pathlib").Path(config["defense"]["bundle_file"])
    before = path.read_bytes()
    bundle = json.loads(before)
    bundle["document"]["revision"] = 2
    with pytest.raises(InvalidSignature):
        d.update(bundle)
    assert path.read_bytes() == before and d.health()["state"] == "active"
    d.close()


def test_unknown_local_effect_does_not_become_success(setup):
    config, _doc, event, _calls, response, _write = setup

    def failed(*args):
        raise OSError("fixture executor interrupted")

    response.execute = failed
    d = Defense(config, response, clock=lambda: NOW)
    result = d.evaluate([event])
    outcome = result[0]["data"]["local_defense"]["outcome"]
    assert outcome["executed"] is None and outcome["success"] is False
    assert d.evaluate([event]) == result
    assert d.health()["succeeded"] == 0
    d.close()


@pytest.mark.parametrize("field", ["agent_id", "index"])
def test_signed_policy_cannot_cross_enrollment_identity_or_index(setup, field):
    config, doc, event, calls, response, write = setup
    doc[field] = "different-bound-identity"
    write(doc)
    d = Defense(config, response, clock=lambda: NOW)
    assert d.health()["state"] == "degraded"
    assert d.evaluate([event]) == [] and not calls
    d.close()


def test_host_only_legacy_policy_requires_signed_reissue(setup):
    config, doc, event, calls, response, write = setup
    del doc["agent_id"], doc["index"]
    write(doc)
    d = Defense(config, response, clock=lambda: NOW)
    assert d.health()["state"] == "degraded"
    assert d.evaluate([event]) == [] and not calls
    d.close()


def test_oversized_batch_is_incomplete_but_next_valid_batch_works(setup):
    config, _doc, event, calls, response, _ = setup
    d = Defense(config, response, clock=lambda: NOW)
    stamp = d.bundle_stamp
    assert d.evaluate([event] * 2001) == [] and not calls
    assert d.health()["last_batch_coverage_incomplete"] is True
    assert d.health()["state"] == "degraded"
    assert len(d.evaluate([event])) == 1 and len(calls) == 1
    assert d.bundle_stamp == stamp
    assert d.health()["last_batch_coverage_incomplete"] is False
    assert d.health()["state"] == "active"
    d.close()


def test_cooperative_deadline_is_incomplete_but_does_not_latch_policy_error(
    setup, monkeypatch
):
    from sapientia.endpoint_agent.Agent import defense

    config, _doc, event, calls, response, _ = setup
    d = Defense(config, response, clock=lambda: NOW)
    times = iter([0.0, 3.0])
    monkeypatch.setattr(defense, "time", SimpleNamespace(monotonic=lambda: next(times)))
    assert d.evaluate([event]) == [] and not calls
    assert d.health()["last_batch_coverage_incomplete"] is True
    monkeypatch.setattr(defense, "time", SimpleNamespace(monotonic=lambda: 0.0))
    assert len(d.evaluate([event])) == 1 and len(calls) == 1
    assert d.health()["state"] == "active"
    d.close()


def test_output_bound_reports_partial_coverage_and_next_batch_remains_enabled(
    setup, monkeypatch
):
    from sapientia.endpoint_agent.Agent import defense

    config, _doc, event, calls, response, _ = setup
    d = Defense(config, response, clock=lambda: NOW)
    monkeypatch.setattr(defense, "time", SimpleNamespace(monotonic=lambda: 0.0))
    events = [dict(event, id="fixture-event-" + str(i)) for i in range(201)]
    assert len(d.evaluate(events)) == 200 and len(calls) == 200
    assert d.health()["last_batch_coverage_incomplete"] is True
    assert len(d.evaluate([events[-1]])) == 1 and len(calls) == 201
    assert d.health()["state"] == "active"
    d.close()


@pytest.mark.parametrize("bad_event", [None, "malformed", 1, [], True])
def test_malformed_event_object_is_skipped_without_breaking_later_events(
    setup, bad_event
):
    config, _doc, event, calls, response, _ = setup
    d = Defense(config, response, clock=lambda: NOW)
    malformed = copy.deepcopy(event)
    malformed["id"] = "malformed-event"
    malformed["data"]["event"] = bad_event
    results = d.evaluate([malformed, event])
    assert len(results) == 1 and len(calls) == 1
    assert results[0]["data"]["local_defense"]["source_event_id"] == event["id"]
    assert d.health()["state"] == "active"
    d.close()


def test_scalar_process_is_nonexecuting_identity_failure(setup):
    config, doc, event, calls, response, write = setup
    doc["rules"][0]["conditions"] = [
        {"field": "event.action", "op": "eq", "value": "process_created"}
    ]
    write(doc)
    event["data"]["process"] = None
    d = Defense(config, response, clock=lambda: NOW)
    result = d.evaluate([event])
    assert (
        result[0]["data"]["local_defense"]["outcome"]["code"] == "identity_unavailable"
    )
    assert not calls
    d.close()


def test_threaded_replacement_during_load_cannot_stamp_old_policy_as_current(
    setup, monkeypatch
):
    from concurrent.futures import ThreadPoolExecutor
    from pathlib import Path

    from sapientia.endpoint_agent.Agent import defense

    config, doc, event, calls, response, write = setup
    d = Defense(config, response, clock=lambda: NOW)
    doc["revision"] = 2
    doc["rules"][0]["action"] = "observe"
    write(doc)
    next_doc = copy.deepcopy(doc)
    next_doc["revision"] = 3
    next_doc["rules"][0]["enabled"] = False
    # Obtain the correctly signed next release without publishing it yet.
    write(next_doc)
    path = Path(config["defense"]["bundle_file"])
    bundle = json.loads(path.read_text(encoding="utf-8"))
    write(doc)
    old_validate = defense.validate
    replaced = []

    def racing_validate(document, configuration, now):
        validated = old_validate(document, configuration, now)
        if document["revision"] == 2 and not replaced:
            replaced.append(True)
            with ThreadPoolExecutor(max_workers=1) as pool:
                assert pool.submit(d.update, bundle).result() is True
        return validated

    monkeypatch.setattr(defense, "validate", racing_validate)
    first = d.evaluate([event])
    assert first[0]["data"]["local_defense"]["outcome"]["code"] == "observed"
    assert d.health()["revision"] == 2
    assert json.loads(path.read_text(encoding="utf-8"))["document"]["revision"] == 3
    assert d.evaluate([event]) == []
    assert d.health()["revision"] == 3 and not calls
    d.close()


def test_atomic_replacement_with_equal_mtime_still_reloads(setup):
    import os
    from pathlib import Path

    config, doc, event, calls, response, write = setup
    d = Defense(config, response, clock=lambda: NOW)
    path = Path(config["defense"]["bundle_file"])
    previous = path.stat()
    doc["revision"] = 2
    doc["rules"][0]["enabled"] = False
    write(doc)
    bundle = json.loads(path.read_text(encoding="utf-8"))
    # Restore the current release, then replace it atomically using update.
    original = copy.deepcopy(doc)
    original["revision"] = 1
    original["rules"][0]["enabled"] = True
    write(original)
    d._load()
    assert d.update(bundle) is True
    os.utime(path, ns=(previous.st_atime_ns, previous.st_mtime_ns))
    assert d.evaluate([event]) == []
    assert d.health()["revision"] == 2 and not calls
    d.close()
