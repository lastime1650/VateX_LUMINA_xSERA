"""Native harmless file effects; firewall is always mocked, never applied."""
# ruff: noqa: F811

import hashlib
import time
from pathlib import Path

import pytest

from sapientia import access, soar, soar_bindings, workflow_graph
from sapientia.endpoint_agent.Agent.core import response as executor
from sapientia.storage import ConflictError, encode
from tests.test_agent_distribution import config, source_store  # noqa: F401
from tests.test_endpoint_response import claim_ack, response_case  # noqa: F401
from tests.test_xdr_bridge import actor


@pytest.fixture
def local(tmp_path):
    # This fixture contains only a harmless file under an explicitly marked root.
    root = tmp_path / "files"
    root.mkdir(mode=0o700)
    (root / executor.MARKER).write_text(executor.MARKER_TEXT)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    from importlib import import_module

    operations = import_module(executor.__package__ + ".operations")
    (state / operations.MARKER).write_text(operations.MARKER_TEXT)
    sample = root / "harmless.txt"
    sample.write_bytes(b"synthetic reversible file content")
    target = {
        "type": "quarantine_file",
        "path": str(sample.resolve()),
        "sha256": hashlib.sha256(sample.read_bytes()).hexdigest(),
    }
    settings = {
        "enabled": True,
        "allow_quarantine": True,
        "allow_restore": True,
        "allow_investigation": True,
        "file_roots": [str(root.resolve())],
        "quarantine_dir": str(state.resolve()),
    }
    return sample, target, settings, operations


def test_native_quarantine_inspection_restore_no_overwrite(local):
    sample, target, settings, _ = local
    investigation = executor.execute(
        {**target, "type": "inspect_file"}, "HOST-01", settings
    )
    assert investigation["success"] and investigation["executed"] is False
    assert investigation["data"]["sha256"] == target["sha256"] and sample.exists()
    quarantined = executor.execute(target, "HOST-01", settings)
    assert quarantined["success"] and quarantined["executed"] and not sample.exists()
    restore = {
        **target,
        "type": "restore_file",
        "quarantine_id": quarantined["data"]["quarantine_id"],
    }
    sample.write_bytes(b"a concurrently created different file")
    assert not executor.execute(restore, "HOST-01", settings)["success"]
    assert sample.read_bytes() == b"a concurrently created different file"
    sample.unlink()
    assert executor.execute(restore, "HOST-01", settings)["success"]
    assert hashlib.sha256(sample.read_bytes()).hexdigest() == target["sha256"]
    assert not executor.execute(restore, "HOST-01", settings)["success"]


def test_native_artifact_is_bounded_local_not_raw_result(local):
    sample, target, settings, _ = local
    result = executor.execute(
        {**target, "type": "collect_artifact"}, "HOST-01", settings
    )
    assert result["success"] and result["executed"] is False
    artifact = Path(settings["quarantine_dir"]) / (
        result["data"]["artifact_id"] + ".bin"
    )
    assert artifact.read_bytes() == sample.read_bytes()
    assert "synthetic reversible" not in encode(result)


@pytest.mark.parametrize("kind", ["kernel", "services", "network"])
def test_critical_process_is_never_overridden_by_allowlist(tmp_path, kind):
    executable = tmp_path / (
        "services.exe"
        if kind == "services"
        else "sshd"
        if kind == "network"
        else "allowed.exe"
    )
    executable.write_bytes(b"synthetic, never executed")
    info = {
        "pid": 12345,
        "guid": "guid",
        "start_identity": "windows:1234",
        "executable": str(executable),
        "critical": kind == "kernel",
    }
    target = {"pid": 12345, "process_guid": "guid", "start_identity": "windows:1234"}
    with pytest.raises(PermissionError, match="protected"):
        executor._check_process(
            info, target, {"allowed_process_executables": [str(executable)]}
        )


def test_agent_state_cannot_be_investigated_even_under_marked_root(local):
    sample, target, settings, _ = local
    settings["_agent_state_dir"] = str(sample.parent)
    result = executor.execute({**target, "type": "inspect_file"}, "HOST-01", settings)
    assert result["success"] is False and result["executed"] is False


@pytest.mark.parametrize("change", ["disabled", "hash", "root", "optin"])
def test_native_quarantine_denies_before_effect(local, change):
    sample, target, settings, _ = local
    if change == "disabled":
        settings["enabled"] = False
    elif change == "hash":
        target["sha256"] = "0" * 64
    elif change == "root":
        settings["file_roots"] = []
    else:
        settings["allow_quarantine"] = False
    result = executor.execute(target, "HOST-01", settings)
    assert not result["success"] and result["executed"] is False and sample.exists()


def network(local, monkeypatch):
    _sample, _target, settings, operations = local
    settings.update(
        {
            "allow_host_isolation": True,
            "management_allowlist": ["192.0.2.1/32"],
            "management_endpoints": [{"ip": "192.0.2.1", "port": 443}],
            "_management_probe": lambda: {"server_time": time.time()},
        }
    )
    _, digest = operations.network_definition(settings)
    # Network effects and independent process guards are mocked together here;
    # native watchdog/fence qualification is a separate explicit host test.
    windows_guard = __import__("importlib").import_module(
        operations.__package__ + ".Windows.isolation_watchdog"
    )
    monkeypatch.setattr(
        windows_guard, "arm", lambda directory, identifier: __import__("os").getpid()
    )
    monkeypatch.setattr(
        operations,
        "_arm_watchdog",
        lambda directory, identifier: __import__("os").getpid(),
    )
    calls = []
    monkeypatch.setattr(
        operations,
        "_driver",
        lambda identifier, definition, release=False, deadline=None, **kwargs: (
            calls.append((identifier, release))
        ),
    )
    monkeypatch.setattr(
        operations, "_reachable", lambda definition, deadline=None: None
    )
    monkeypatch.setattr(operations, "_guard_matches", lambda *args: True)
    return (
        settings,
        operations,
        {"type": "isolate_host", "management_allowlist_digest": digest},
        calls,
    )


def test_mock_only_isolation_release_exact_receipt(local, monkeypatch):
    settings, _operations, target, calls = network(local, monkeypatch)
    result = executor.execute(target, "HOST-01", settings)
    assert result["success"] and len(calls) == 1
    release = {
        **target,
        "type": "release_host",
        "isolation_id": result["data"]["isolation_id"],
    }
    assert executor.execute(release, "HOST-01", settings)["success"]
    assert calls[0][0] == calls[1][0] and calls[1][1] is True


@pytest.mark.parametrize("rollback_fails", [False, True])
def test_mock_only_management_failure_rolls_back_or_unknown(
    local, monkeypatch, rollback_fails
):
    settings, operations, target, calls = network(local, monkeypatch)
    probes = iter([True, False, True])

    def probe():
        if not next(probes):
            raise OSError("Synthetic management channel loss")

    settings["_management_probe"] = probe

    def driver(identifier, definition, release=False, deadline=None, **kwargs):
        calls.append((identifier, release))
        if release and rollback_fails:
            raise OSError("Synthetic rollback failure")

    monkeypatch.setattr(operations, "_driver", driver)
    result = executor.execute(target, "HOST-01", settings)
    assert not result["success"] and calls[-1][1]
    assert result["executed"] is (None if rollback_fails else False)


def test_management_config_change_and_missing_probe_never_applies(local, monkeypatch):
    settings, _operations, target, calls = network(local, monkeypatch)
    target["management_allowlist_digest"] = "0" * 64
    assert not executor.execute(target, "HOST-01", settings)["success"] and calls == []
    _, target["management_allowlist_digest"] = _operations.network_definition(settings)
    settings.pop("_management_probe")
    assert not executor.execute(target, "HOST-01", settings)["success"] and calls == []


def playbook(response_case, *, condition=False):
    store, _service, _identity, incident, body = response_case
    endpoint = {
        "type": "endpoint_response",
        **{
            key: body[key]
            for key in ("agent_id", "evidence_event_id", "action", "reason")
        },
    }
    steps = [
        {"id": "effect", "action": endpoint},
        {
            "id": "resolve",
            "depends_on": ["effect"],
            "action": {
                "type": "set_status",
                "status": "resolved",
                "note": "Confirmed receipt before resolution",
            },
        },
    ]
    if condition:
        steps.insert(
            1,
            {
                "id": "false_branch",
                "depends_on": ["effect"],
                "when": {
                    "all": [
                        {
                            "step": "effect",
                            "field": "success",
                            "op": "eq",
                            "value": False,
                        }
                    ]
                },
                "action": {"type": "add_note", "note": "Must not execute this branch"},
            },
        )
    book = soar.save(
        store,
        actor(),
        {"name": "Endpoint receipt barrier", "version": 0, "steps": steps},
    )
    run = soar.start_run(store, actor(), book["id"], incident, "soar-response-test")
    soar.approve(store, actor("admin_other"), run["id"])
    return run


def test_soar_endpoint_waits_for_receipt_then_conditional_graph(response_case, monkeypatch):
    # Server protocol fixture only; no Agent executor or native OS action is invoked.
    monkeypatch.delenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", raising=False)
    store, service, identity, incident, _ = response_case
    run = playbook(response_case, condition=True)
    assert soar.run_due(store) == 1
    assert soar.get_run(store, actor(), run["id"])["state"] == "waiting"
    assert soar.run_due(store, time.time() + 2) == 0
    with store.control() as db:
        assert (
            db.execute(
                "SELECT status FROM incidents WHERE id=?", (incident,)
            ).fetchone()[0]
            == "new"
        )
        assert db.execute("SELECT count(*) FROM endpoint_responses").fetchone()[0] == 1
    command, receipt, ack = claim_ack(service, identity)
    assert ack["execute"] and command["id"]
    service.response_result(
        identity["credential"],
        {
            **receipt,
            "result": {
                "type": "terminate_process",
                "success": True,
                "executed": True,
                "code": "terminated",
                "detail": "Synthetic agent result fixture; no OS termination in this test",
            },
        },
    )
    for _ in range(3):
        assert soar.run_due(store, time.time() + 3) == 1
    result = soar.get_run(store, actor(), run["id"])
    assert result["state"] == "completed" and result["steps"][1]["state"] == "skipped"
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM case_notes").fetchone()[0] == 0
        assert (
            db.execute(
                "SELECT status FROM incidents WHERE id=?", (incident,)
            ).fetchone()[0]
            == "resolved"
        )


@pytest.mark.parametrize(
    "change", ["approver_disabled", "approver_scope", "case_version", "cancel"]
)
def test_soar_endpoint_rechecks_approval_at_agent_ack(response_case, change, monkeypatch):
    # Server protocol fixture only; no Agent executor or native OS action is invoked.
    monkeypatch.delenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", raising=False)
    store, service, identity, incident, _ = response_case
    run = playbook(response_case)
    soar.run_due(store)
    command = service.poll(identity["credential"], {})["command"]
    if change == "cancel":
        soar.cancel_run(store, actor(), run["id"])
    elif change == "approver_scope":
        access.set_for_user(store, actor(), "admin_other", [])
    else:
        with store.control() as db:
            if change == "case_version":
                db.execute(
                    "UPDATE incidents SET version=version+1 WHERE id=?", (incident,)
                )
            else:
                db.execute("UPDATE users SET disabled=1 WHERE name='admin_other'")
    import uuid

    ack = service.response_ack(
        identity["credential"],
        {
            "command_id": command["id"],
            "lease_token": command["lease_token"],
            "execution_id": uuid.uuid4().hex,
        },
    )
    assert ack["execute"] is False
    with store.control() as db:
        assert (
            db.execute(
                "SELECT status FROM incidents WHERE id=?", (incident,)
            ).fetchone()[0]
            == "new"
        )


def test_unknown_endpoint_result_stops_downstream_response_case(response_case, monkeypatch):
    # Server protocol fixture only; no Agent executor or native OS action is invoked.
    monkeypatch.delenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", raising=False)
    store, service, identity, incident, _ = response_case
    run = playbook(response_case)
    soar.run_due(store)
    _command, receipt, _ack = claim_ack(service, identity)
    service.response_result(
        identity["credential"],
        {
            **receipt,
            "result": {
                "type": "terminate_process",
                "success": False,
                "executed": None,
                "code": "unknown_after_restart",
                "detail": "Durable marker without receipt",
            },
        },
    )
    soar.run_due(store, time.time() + 2)
    assert soar.get_run(store, actor(), run["id"])["state"] == "unknown"
    with store.control() as db:
        assert (
            db.execute(
                "SELECT status FROM incidents WHERE id=?", (incident,)
            ).fetchone()[0]
            == "new"
        )


@pytest.mark.parametrize("fault", ["cycle", "missing", "condition_source"])
def test_graph_rejects_unsafe_dependencies(fault):
    steps = [
        {"id": "a", "depends_on": [], "action": {}},
        {"id": "b", "depends_on": ["a"], "action": {}},
    ]
    if fault == "cycle":
        steps[0]["depends_on"] = ["b"]
    elif fault == "missing":
        steps[1]["depends_on"] = ["not_exist"]
    else:
        steps[1]["when"] = {
            "all": [{"step": "b", "field": "success", "op": "eq", "value": True}]
        }
    with pytest.raises(ValueError):
        workflow_graph.order(steps)


def test_condition_does_not_confuse_bool_and_integer():
    assert not workflow_graph.matches(
        {"all": [{"step": "a", "field": "executed", "op": "eq", "value": 1}]},
        {"a": {"executed": True}},
    )
    assert not workflow_graph.matches(
        {"all": [{"step": "a", "field": "success", "op": "ne", "value": False}]},
        {"a": {"skipped": True}},
    )


def test_generic_raw_xdr_copy_is_metadata_only_not_response_evidence(response_case, monkeypatch):
    # Server protocol fixture only; no Agent executor or native OS action is invoked.
    monkeypatch.delenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", raising=False)
    from sapientia import casework, endpoint_response

    store, _service, _identity, incident, body = response_case
    actual = store.analytics_query(
        "SELECT event_id,event_time,source,sourcetype,host,severity,message,index_name,raw FROM events_all WHERE tenant=? LIMIT 1",
        ["a"],
    )["rows"][0]
    import json

    actual["raw"] = json.loads(actual["raw"])
    actual["index"] = actual.pop("index_name")
    actual["event_id"] = "generic-forged-endpoint"
    store.ingest("a", [actual], "generic-collector", allowed_indexes=["endpoint"])
    store.flush()
    casework.bookmark(
        store,
        actor(),
        incident,
        {"event_id": actual["event_id"], "label": "Synthetic generic copy"},
    )
    listing = endpoint_response.listing(store, actor(), incident)
    forged = next(
        row for row in listing["events"] if row["event_id"] == actual["event_id"]
    )
    assert forged["provenance"] == "unverified" and forged["response_eligible"] is False
    body.update(
        evidence_event_id=actual["event_id"],
        case_version=listing["case_version"],
        request_id="forged-source-rejected",
    )
    with pytest.raises(ValueError):
        endpoint_response.create(store, actor(), incident, body)
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM endpoint_responses").fetchone()[0] == 0


@pytest.mark.parametrize(
    "field", ["agent_id", "payload_digest", "receipt_digest", "received"]
)
def test_provenance_is_rechecked_between_claim_and_ack(response_case, field, monkeypatch):
    # Server protocol fixture only; no Agent executor or native OS action is invoked.
    monkeypatch.delenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", raising=False)
    import uuid

    from sapientia import endpoint_response

    store, service, identity, incident, body = response_case
    command = endpoint_response.create(store, actor(), incident, body)
    delivery = service.poll(identity["credential"], {})["command"]
    with store.control() as db:
        value = (
            "unrelated-agent"
            if field == "agent_id"
            else time.time() + 100
            if field == "received"
            else "0" * 64
        )
        db.execute(
            "UPDATE endpoint_event_receipts SET "
            + field
            + "=? WHERE tenant=? AND event_id=?",
            (value, "a", body["evidence_event_id"]),
        )
    ack = service.response_ack(
        identity["credential"],
        {
            "command_id": command["id"],
            "lease_token": delivery["lease_token"],
            "execution_id": uuid.uuid4().hex,
        },
    )
    assert ack["execute"] is False


@pytest.mark.parametrize("fault", ["dependencies", "field", "op", "action_type"])
def test_malformed_graph_and_action_types_are_validation_errors(fault):
    from sapientia import endpoint_response

    steps = [{"id": "a", "action": {}, "depends_on": []}]
    if fault == "dependencies":
        steps[0]["depends_on"] = [{}]
    elif fault == "action_type":
        with pytest.raises(ValueError):
            endpoint_response.action({"type": []}, "windows")
        return
    else:
        when = {"all": [{"step": "a", "field": "success", "op": "eq", "value": True}]}
        when["all"][0][fault] = []
        with pytest.raises(ValueError):
            workflow_graph.condition(when)
        return
    with pytest.raises(ValueError):
        workflow_graph.order(steps)


def test_workflow_cannot_adopt_preexisting_manual_command(response_case, monkeypatch):
    # Server protocol fixture only; no Agent executor or native OS action is invoked.
    monkeypatch.delenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", raising=False)
    from sapientia import endpoint_response

    store, _service, _identity, incident, body = response_case
    run = playbook(response_case)
    body["request_id"] = "soar-" + soar._digest([run["id"], "effect"])[:50]
    endpoint_response.create(store, actor(), incident, body)
    assert soar.run_due(store) == 1
    assert soar.get_run(store, actor(), run["id"])["state"] == "failed"


def test_typed_restore_reference_requires_its_exact_dependency(response_case):
    store, _service, _identity, _incident, body = response_case
    endpoint = {
        "type": "endpoint_response",
        **{key: body[key] for key in ("agent_id", "evidence_event_id", "reason")},
    }
    endpoint["action"] = {
        "type": "quarantine_file",
        "path": "C:\\PrivateQA\\synthetic.txt",
        "sha256": "a" * 64,
    }
    restore = {
        **endpoint,
        "action": {
            **endpoint["action"],
            "type": "restore_file",
            "quarantine_id": {"from_step": "q", "field": "data.quarantine_id"},
        },
    }
    definition = {
        "name": "Typed receipt reference",
        "version": 0,
        "steps": [
            {"id": "q", "action": endpoint},
            {"id": "restore", "depends_on": ["q"], "action": restore},
        ],
    }
    assert soar.save(store, actor(), definition)["version"] == 1
    definition["steps"][1]["depends_on"] = []
    with pytest.raises(ValueError, match="receipt source"):
        soar.validate(definition)


def test_prospective_binding_creates_pending_approval_only(response_case):
    store, _service, _identity, incident, _body = response_case
    book = soar.save(
        store,
        actor(),
        {
            "name": "Prospective case proposal",
            "version": 0,
            "steps": [
                {
                    "id": "note",
                    "action": {
                        "type": "add_note",
                        "note": "Independent approval required",
                    },
                }
            ],
        },
    )
    with store.control() as db:
        policy = db.execute(
            "SELECT id FROM correlation_policies WHERE tenant='a'"
        ).fetchone()[0]
    data = {
        "policy_id": policy,
        "playbook_id": book["id"],
        "enabled": True,
        "version": 0,
    }
    binding = soar_bindings.save(store, actor(), data)
    assert binding["approval_required"] and soar.run_due(store) == 0
    with store.control() as db:
        row = list(
            db.execute(
                "SELECT * FROM risk_contributions WHERE incident_id=? LIMIT 1",
                (incident,),
            ).fetchone()
        )
        row[0] = "new-risk-for-binding"
        db.execute("INSERT INTO risk_contributions VALUES(?,?,?,?,?,?,?,?,?,?)", row)
    assert soar.run_due(store) == 0
    runs = soar.list_runs(store, actor())["runs"]
    assert len(runs) == 1 and runs[0]["state"] == "pending_approval"
    assert soar.run_due(store) == 0 and len(soar.list_runs(store, actor())["runs"]) == 1
    with pytest.raises(ConflictError):
        soar_bindings.save(store, actor(), data)
