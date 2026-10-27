"""Mock process identities; real harmless temporary bytes and authenticated receipts.

No process execution/termination, firewall, production Store or native agent is used.
"""
# ruff: noqa: F811

import copy
import hashlib
import importlib
import json
import os
import stat
import time
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from sapientia import (
    access,
    agent_distribution,
    backup,
    casework,
    detections,
    endpoint_artifacts,
    endpoint_response,
    file_verdicts,
    yara_collection,
)
from sapientia.endpoint_agent.Agent.core import response as executor
from sapientia.storage import ConflictError
from tests.test_agent_distribution import config, enrolled, source_store  # noqa: F401
from tests.test_response_remediation import local  # noqa: F401
from tests.test_xdr_bridge import actor, event


@pytest.fixture
def image_case(source_store, config, local, monkeypatch):
    store = source_store
    sample, _target, settings, _ops = local
    sample.write_bytes(b"MZ-HARMLESS-NOT-EXECUTED\n" + b"static YARA collection fixture\n" * 100)
    image = importlib.import_module(executor.__package__ + ".process_artifact")
    settings.update(allow_process_artifact_collection=True, allowed_process_executables=[str(sample.resolve())])
    identity_info = {"pid": 12345, "guid": "fixture-live-incarnation", "start_identity": "windows:123456789" if os.name == "nt" else "linux:11111111-1111-1111-1111-111111111111:123456789", "executable": str(sample.resolve()), "critical": False}
    monkeypatch.setattr(executor, "inspect_process", lambda pid, host: copy.deepcopy(identity_info))
    monkeypatch.setattr(executor, "_protected", set)
    if os.name != "nt":
        original_stat = image.os.stat
        monkeypatch.setattr(image.os, "stat", lambda path, *args, **kwargs: original_stat(sample if str(path) == "/proc/12345/exe" else path, *args, **kwargs))
    service = agent_distribution.Distribution(store, config)
    enrolled_identity, _, _, _ = enrolled(service, platform="windows" if os.name == "nt" else "linux")
    original = event(host="HOST-01", pid=identity_info["pid"], guid=identity_info["guid"])
    original["id"] = "original-process-without-hash"
    original["data"]["@timestamp"] = datetime.now(UTC).isoformat()
    original["data"]["process"].update(executable=str(sample.resolve()), start_identity=identity_info["start_identity"])
    service.ingest(enrolled_identity["credential"], {"events": [original]})
    store.flush()
    detections.save(store, actor(), {"name": "Harmless process collection Case", "entity_field": "host", "window": 300,
        "steps": [{"filters": [{"field": "host", "op": "eq", "value": "HOST-01"}]}]})
    deadline = time.monotonic() + 10
    while not detections.incident_list(store, actor()) and time.monotonic() < deadline:
        detections.run_due(store, time.time() + 1)
    incidents = detections.incident_list(store, actor())
    assert len(incidents) == 1
    case_id = incidents[0]["id"]
    return SimpleNamespace(store=store, service=service, identity=enrolled_identity, sample=sample, settings=settings,
        image=image, process=identity_info, case_id=case_id)


def selection(lab, *, prepared=False, request_id="inspect-image"):
    values = yara_collection.targets(lab.store, actor(), lab.case_id)
    selected = next(item for item in values["items"] if item["eligible"] is prepared)
    return {"incident_id": lab.case_id, "event_id": selected["event_id"], "agent_id": selected["agent_id"],
        "case_version": values["case_version"], "request_id": request_id, "reason": "Explicit harmless process image review",
        "prepare_only": not prepared, "target_id": selected["id"]}


def execute(lab, command, tmp_path):
    def post(path, data):
        if path == "/api/agent/ack":
            return lab.service.response_ack(lab.identity["credential"], data)
        if path == "/api/agent/result":
            return lab.service.response_result(lab.identity["credential"], data)
        if path == "/api/agent/ingest":
            return lab.service.ingest(lab.identity["credential"], data)
        if path.endswith("/artifact"):
            return endpoint_response.artifact_upload(lab.store, lab.service, lab.identity["credential"], command["id"], data)
        raise AssertionError(path)
    agent = SimpleNamespace(identity=lab.identity, config={"index": "endpoint", "response": lab.settings}, _post=post)
    tmp_path.mkdir(exist_ok=True)
    ledger = executor.Ledger(tmp_path)
    try:
        try:
            ledger.handle(agent, lab.service.poll(lab.identity["credential"], {}))
        except TimeoutError:
            pass  # A bounded report turn may yield; its byte offset is durable.
        deadline = time.monotonic() + 45
        while ledger.pending() and time.monotonic() < deadline:
            try:
                ledger.report(agent, budget=5)
            except TimeoutError:
                continue
        assert not ledger.pending()
        return endpoint_response.get(lab.store, actor(), command["id"])
    finally:
        ledger.close()


def prepared_case(lab, tmp_path):
    original = yara_collection.targets(lab.store, actor(), lab.case_id)["items"][0]
    assert not original["eligible"] and original["needs_prepare"] and original["prepare_eligible"]
    command = yara_collection.request(lab.store, actor(), selection(lab))
    result = execute(lab, command, tmp_path / "prepare-ledger")
    assert result["state"] == "succeeded", result
    event_id = result["result"]["data"]["process_evidence_event_id"]
    lab.store.flush()
    values = yara_collection.targets(lab.store, actor(), lab.case_id)
    assert len(values["items"]) == 1 and values["items"][0]["sha256"] is None
    assert not any(item["event_id"] == event_id for item in values["items"])
    casework.bookmark(lab.store, actor(), lab.case_id, {"event_id": event_id, "label": "Explicit inspected executable original"})
    return event_id, result


def test_explicit_prepare_new_original_manual_case_membership_then_exact_artifact(image_case, tmp_path):
    lab = image_case
    before = lab.sample.read_bytes()
    event_id, inspection = prepared_case(lab, tmp_path)
    values = yara_collection.targets(lab.store, actor(), lab.case_id)
    target = next(item for item in values["items"] if item["event_id"] == event_id)
    assert target["eligible"] and target["sha256"] == hashlib.sha256(before).hexdigest()
    assert target["action"]["source"] == "process_executable"
    request = selection(lab, prepared=True, request_id="collect-image")
    command = yara_collection.request(lab.store, actor(), request)
    result = execute(lab, command, tmp_path / "collect-ledger")
    assert result["state"] == "succeeded" and result["result"]["executed"] is False
    artifact_id = result["result"]["data"]["server_artifact_id"]
    body, _, digest = endpoint_artifacts.download(lab.store, actor(), artifact_id)
    assert body == before == lab.sample.read_bytes() and digest == target["sha256"]
    assert inspection["result"]["data"]["source_response_command_id"] == inspection["id"]
    with lab.store.control() as db:
        assert db.execute("SELECT count(*) FROM endpoint_event_receipts").fetchone()[0] == 2
        assert db.execute("SELECT count(*) FROM soar_runs").fetchone()[0] == 0
        assert db.execute("SELECT count(*) FROM incidents").fetchone()[0] == 1


@pytest.mark.parametrize("field", ["path", "sha256", "action", "tenant"])
def test_request_never_accepts_arbitrary_user_file_or_cross_scope_fields(image_case, field):
    data = selection(image_case)
    data[field] = "/arbitrary/secret" if field == "path" else "forged"
    with pytest.raises(ValueError):
        yara_collection.request(image_case.store, actor(), data)


def test_target_revision_foreign_agent_acl_and_receipt_are_rechecked(image_case):
    lab = image_case
    data = selection(lab)
    with pytest.raises(ConflictError):
        yara_collection.request(lab.store, actor(), {**data, "case_version": data["case_version"] + 1})
    with pytest.raises(KeyError):
        yara_collection.request(lab.store, actor(), {**data, "agent_id": "another-host"})
    access.set_for_user(lab.store, actor(), "admin_other", [])
    with pytest.raises((KeyError, PermissionError)):
        yara_collection.targets(lab.store, actor("admin_other"), lab.case_id)
    with lab.store.control() as db:
        db.execute("DELETE FROM endpoint_event_receipts")
    assert not any(item["prepare_eligible"] for item in yara_collection.targets(lab.store, actor(), lab.case_id)["items"])


@pytest.mark.parametrize("fault", ["incarnation", "executable", "allowlist", "opt_in", "hash"])
def test_live_process_and_disk_hash_mismatch_never_spools_bytes(image_case, fault):
    lab = image_case
    target = {"type": "collect_artifact", "source": "process_executable", "pid": lab.process["pid"],
        "process_guid": lab.process["guid"], "start_identity": lab.process["start_identity"],
        "path": str(lab.sample.resolve()), "sha256": hashlib.sha256(lab.sample.read_bytes()).hexdigest(), "max_bytes": endpoint_artifacts.PROCESS_MAX_BYTES}
    if fault == "incarnation":
        lab.process["start_identity"] += "9"
    elif fault == "executable":
        lab.process["executable"] = str(lab.sample.parent / "missing.exe")
    elif fault == "allowlist":
        lab.settings["allowed_process_executables"] = []
    elif fault == "opt_in":
        lab.settings["allow_process_artifact_collection"] = False
    else:
        lab.sample.write_bytes(b"changed executable bytes")
    result = executor.execute(target, "HOST-01", lab.settings)
    assert not result["success"] and result["executed"] is False
    assert not list(lab.sample.parent.parent.rglob("ART-*.bin"))


def test_changed_process_after_file_read_fails_closed(image_case, monkeypatch):
    lab = image_case
    real = lab.image._read_windows if os.name == "nt" else lab.image._read_fd
    def changed(*args, **kwargs):
        result = real(*args, **kwargs)
        lab.process["guid"] = "new incarnation after file read"
        return result
    monkeypatch.setattr(lab.image, "_read_windows" if os.name == "nt" else "_read_fd", changed)
    target = yara_collection.targets(lab.store, actor(), lab.case_id)["items"][0]["prepare_action"]
    result = executor.execute(target, "HOST-01", lab.settings)
    assert not result["success"] and result["executed"] is False


def test_process_over_legacy_limit_transfers_backs_up_and_rejects_legacy_scan(image_case, tmp_path):
    lab = image_case
    lab.sample.write_bytes(b"MZ-harmless-large-fixture\n" + b"a" * (2 * 1024 * 1024))
    prepared_case(lab, tmp_path)
    command = yara_collection.request(lab.store, actor(), selection(lab, prepared=True, request_id="large-process"))
    result = execute(lab, command, tmp_path / "large-ledger")
    artifact_id = result["result"]["data"]["server_artifact_id"]
    content, _, digest = endpoint_artifacts.download(lab.store, actor(), artifact_id)
    assert len(content) > endpoint_artifacts.MAX_BYTES
    manifest = backup.backup_online(lab.store, tmp_path / "snapshot")
    relative = "response-artifacts/" + artifact_id + ".bin"
    assert manifest["sha256"][relative] == digest
    backup.restore(tmp_path / "snapshot", tmp_path / "restored")
    assert (tmp_path / "restored" / relative).read_bytes() == content
    with pytest.raises(ValueError, match="2 MiB"):
        file_verdicts.analyze_artifact(lab.store, actor(), artifact_id)
    with pytest.raises(ValueError, match="2 MiB"):
        file_verdicts.request_sandbox(lab.store, actor(), artifact_id, "provider")
    with lab.store.control() as db:
        altered = json.loads(db.execute("SELECT action FROM endpoint_responses WHERE id=?", (command["id"],)).fetchone()[0])
        altered.pop("source")
        db.execute("UPDATE endpoint_responses SET action=? WHERE id=?", (json.dumps(altered), command["id"]))
    with pytest.raises(ConflictError):
        endpoint_artifacts.download(lab.store, actor(), artifact_id)
    with pytest.raises(ValueError):
        backup.backup_online(lab.store, tmp_path / "tampered-snapshot")


def test_linked_process_image_and_invalid_byte_limits_are_rejected(image_case, tmp_path):
    lab = image_case
    linked = tmp_path / "second-link"
    os.link(lab.sample, linked)
    target = yara_collection.targets(lab.store, actor(), lab.case_id)["items"][0]["prepare_action"]
    assert not executor.execute(target, "HOST-01", lab.settings)["success"]
    for maximum in (0, True, endpoint_artifacts.PROCESS_MAX_BYTES + 1):
        with pytest.raises(ValueError):
            endpoint_response.action({"type": "collect_artifact", "source": "process_executable", "pid": 12345,
                "process_guid": "guid", "start_identity": lab.process["start_identity"], "path": str(lab.sample),
                "sha256": "a" * 64, "max_bytes": maximum}, "windows" if os.name == "nt" else "linux")


def test_lost_inspection_admission_reply_retries_same_new_original_without_reinspection(image_case, tmp_path, monkeypatch):
    lab = image_case
    command = yara_collection.request(lab.store, actor(), selection(lab))
    lost = []
    def post(path, data):
        if path == "/api/agent/ack":
            return lab.service.response_ack(lab.identity["credential"], data)
        if path == "/api/agent/ingest":
            result = lab.service.ingest(lab.identity["credential"], data)
            if not lost:
                lost.append(copy.deepcopy(data))
                raise ConnectionError("Synthetic lost reply after durable admission")
            assert data == lost[0]
            return result
        if path == "/api/agent/result":
            return lab.service.response_result(lab.identity["credential"], data)
        raise AssertionError(path)
    agent = SimpleNamespace(identity=lab.identity, config={"index": "endpoint", "response": lab.settings}, _post=post)
    directory = tmp_path / "restart-ledger"
    directory.mkdir()
    first = executor.Ledger(directory)
    try:
        with pytest.raises(ConnectionError):
            first.handle(agent, lab.service.poll(lab.identity["credential"], {}))
    finally:
        first.close()
    def never_again(*args, **kwargs):
        raise AssertionError("Completed inspection must not execute again")
    monkeypatch.setattr(executor, "inspect_process", never_again)
    second = executor.Ledger(directory)
    try:
        second.report(agent)
        assert not second.pending()
        assert endpoint_response.get(lab.store, actor(), command["id"])["state"] == "succeeded"
        with lab.store.control() as db:
            assert db.execute("SELECT count(*) FROM endpoint_event_receipts").fetchone()[0] == 2
    finally:
        second.close()


def test_collection_cli_opt_in_does_not_implicitly_enable_destructive_actions(tmp_path, monkeypatch):
    cli = importlib.import_module(executor.__package__ + ".cli")
    monkeypatch.setattr(cli, "_protected", lambda *args, **kwargs: None)
    executable = tmp_path / "harmless-image.bin"
    executable.write_bytes(b"MZ-not-executed")
    state = tmp_path / "private-state"
    state.mkdir()
    args = SimpleNamespace(allow_process_executable=[str(executable)], allow_process_instance=[], allow_file_root=[],
        allow_investigation=True, allow_process_artifact_collection=True, max_process_artifact_bytes=32 * 1024 * 1024,
        allow_quarantine=False, allow_restore=False, allow_host_isolation=False, quarantine_dir=None,
        allow_termination=False, allow_delete=False)
    policy = cli._enabled_response_policy({"state_dir": str(state), "host": "fixture"}, args)
    assert policy["allow_process_artifact_collection"] and policy["allow_investigation"]
    assert not policy["allow_process_termination"] and not policy["allow_file_delete"]
    capability = executor.capabilities({"response": policy})
    assert capability["process_artifact_collection"]["enabled"] and capability["process_artifact_collection"]["maximum_bytes"] == endpoint_artifacts.PROCESS_MAX_BYTES


@pytest.mark.parametrize("kind", ["symlink", "reparse"])
def test_link_or_reparse_metadata_fails_before_process_image_open(image_case, monkeypatch, kind):
    lab = image_case
    from pathlib import Path
    original = Path.lstat
    def metadata(path):
        value = original(path)
        if path == lab.sample:
            return SimpleNamespace(st_mode=stat.S_IFLNK if kind == "symlink" else value.st_mode,
                st_file_attributes=0x400 if kind == "reparse" else 0)
        return value
    monkeypatch.setattr(Path, "lstat", metadata)
    with pytest.raises(PermissionError, match="Symlink/reparse"):
        lab.image._path(str(lab.sample))


def test_changed_local_allowlist_symlink_cannot_silently_authorize_another_image(image_case, tmp_path, monkeypatch):
    from pathlib import Path
    lab = image_case
    alias = tmp_path / "previously-approved-image.exe"
    alias.write_bytes(b"old harmless executable")
    lab.settings["allowed_process_executables"] = [str(alias)]
    original_resolve, original_lstat = Path.resolve, Path.lstat
    def resolve(path, *args, **kwargs):
        return lab.sample if path == alias else original_resolve(path, *args, **kwargs)
    def lstat(path):
        return SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0x400) if path == alias else original_lstat(path)
    monkeypatch.setattr(Path, "resolve", resolve)
    monkeypatch.setattr(Path, "lstat", lstat)
    target = {"type": "inspect_process", "pid": lab.process["pid"], "process_guid": lab.process["guid"],
        "start_identity": lab.process["start_identity"], "path": str(lab.sample), "capture_executable_evidence": True}
    result = executor.execute(target, "HOST-01", lab.settings)
    assert not result["success"] and "Symlink/reparse" in result["detail"]
