"""Actual native read/local spool/server chunks, with no firewall execution."""
# ruff: noqa: F811

import base64
import hashlib
import os
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from sapientia import access, agent_distribution, detections, endpoint_artifacts, endpoint_response
from sapientia.endpoint_agent.Agent.core import response as executor
from sapientia.storage import ConflictError
from tests.test_agent_distribution import config, enrolled, source_store  # noqa: F401
from tests.test_deploy_release_security import private_installer_parent  # noqa: F401
from tests.test_response_remediation import local  # noqa: F401
from tests.test_xdr_bridge import actor, event


@pytest.mark.skipif(os.name != "nt", reason="Native managed-directory DACL verification")
def test_artifact_directory_new_and_repeated_safe_pass_entire_installer_preflight(
    private_installer_parent,
):
    from tools import deploy_release as deploy

    root = deploy._prepare_destination(private_installer_parent / "artifact-managed")
    deploy.atomic(root / "deployment.json", {"schema": deploy.STATE_SCHEMA, "profile": "cpu-observe"})
    data = deploy.private_directory(root, "data/current")
    store = SimpleNamespace(path=data)
    directory = endpoint_artifacts._directory(store)
    security = deploy._WindowsAcl()
    initial = security.require_private(directory, root=True)
    assert initial["owner"] == security.current
    (directory / "inert.bin").write_bytes(b"harmless synthetic artifact")
    assert endpoint_artifacts._directory(store) == directory
    assert security.inspect(directory) == initial
    with deploy.operation(root):
        for path in (directory, directory / "inert.bin"):
            security.require_private(path)


@pytest.mark.skipif(os.name != "nt", reason="Native managed-directory DACL verification")
@pytest.mark.parametrize("inherit_only", [False, True])
def test_artifact_directory_existing_unsafe_is_never_repaired(
    private_installer_parent, inherit_only,
):
    from tools import deploy_release as deploy
    from tests.test_deploy_release_security import set_owned_test_dacl

    root = deploy._prepare_destination(
        private_installer_parent / ("artifact-unsafe-future" if inherit_only else "artifact-unsafe")
    )
    directory = root / "response-artifacts"
    directory.mkdir(mode=0o700)
    (directory / "preserved.bin").write_bytes(b"preserve")
    security = deploy._WindowsAcl()
    flags = "OICIIO" if inherit_only else "OICI"
    set_owned_test_dacl(
        directory, f"(A;OICI;FA;;;{security.current})(A;OICI;FA;;;SY)(A;{flags};GR;;;WD)"
    )
    before = security.inspect(directory)
    with pytest.raises(PermissionError, match="another account access"):
        endpoint_artifacts._directory(SimpleNamespace(path=root))
    assert security.inspect(directory) == before
    assert (directory / "preserved.bin").read_bytes() == b"preserve"


@pytest.mark.skipif(os.name != "nt", reason="Native managed-directory DACL verification")
def test_artifact_directory_creation_race_keeps_existing_acl_unchanged(
    private_installer_parent, monkeypatch,
):
    from tools import deploy_release as deploy
    from tests.test_deploy_release_security import set_owned_test_dacl

    root = deploy._prepare_destination(private_installer_parent / "artifact-race")
    target = root / "response-artifacts"
    security, observed = deploy._WindowsAcl(), []
    mkdir = Path.mkdir

    def race(path, *args, **kwargs):
        if path == target:
            mkdir(path, mode=0o700)
            set_owned_test_dacl(
                path, f"(A;OICI;FA;;;{security.current})(A;OICI;FA;;;SY)(A;OICI;GR;;;WD)"
            )
            observed.append(security.inspect(path))
            raise FileExistsError("Synthetic simultaneous artifact creator")
        return mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", race)
    with pytest.raises(PermissionError, match="another account access"):
        endpoint_artifacts._directory(SimpleNamespace(path=root))
    assert security.inspect(target) == observed[0]


def test_artifact_directory_permission_failure_writes_no_binary(tmp_path, monkeypatch):
    from sapientia import backup

    def deny(path, **options):
        assert options == {"created": True} and not any(path.iterdir())
        raise PermissionError("Synthetic artifact permission failure")

    monkeypatch.setattr(backup, "_private_directory", deny)
    with pytest.raises(PermissionError, match="artifact permission failure"):
        endpoint_artifacts._directory(SimpleNamespace(path=tmp_path))
    assert not list((tmp_path / "response-artifacts").iterdir())


@pytest.fixture
def artifact_case(source_store, config, local):
    store = source_store
    sample, target, settings, _ = local
    service = agent_distribution.Distribution(store, config)
    identity, _, _, _ = enrolled(service)
    now = time.time()
    row = event(host="HOST-01", pid=123, guid="synthetic-guid")
    row["data"]["@timestamp"] = datetime.fromtimestamp(now - 1, UTC).isoformat()
    row["data"]["file"] = {
        "path": str(sample.resolve()),
        "hash": {"sha256": target["sha256"]},
    }
    service.ingest(identity["credential"], {"events": [row]})
    store.flush()
    detections.save(
        store,
        actor(),
        {
            "name": "Synthetic artifact scope",
            "entity_field": "host",
            "window": 300,
            "steps": [{"filters": [{"field": "host", "op": "eq", "value": "HOST-01"}]}],
        },
    )
    # Admission and policy save can take over one second on a busy host.
    # Evaluate after the actual save time so fixture setup always runs a due policy.
    assert detections.run_due(store, time.time() + 1) == 1
    incident = detections.incident_list(store, actor())[0]["id"]
    listing = endpoint_response.listing(store, actor(), incident)
    request = {
        "agent_id": identity["agent_id"],
        "evidence_event_id": listing["events"][0]["event_id"],
        "case_version": listing["case_version"],
        "request_id": "collect-native-fixture",
        "reason": "Harmless scoped fixture artifact",
        "action": {**target, "type": "collect_artifact"},
    }
    command = endpoint_response.create(store, actor(), incident, request)
    return store, service, identity, command, sample, settings


def claim(artifact_case):
    _store, service, identity, _command, _sample, _settings = artifact_case
    delivery = service.poll(identity["credential"], {})
    command = delivery["command"]
    receipt = {"lease_token": command["lease_token"], "execution_id": uuid.uuid4().hex}
    assert service.response_ack(
        identity["credential"], {**receipt, "command_id": command["id"]}
    )["execute"]
    return command, receipt


def chunk(receipt, content, offset=0, body=None):
    body = content[offset : offset + 32768] if body is None else body
    return {
        **receipt,
        "offset": offset,
        "total_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "chunk_sha256": hashlib.sha256(body).hexdigest(),
        "body_base64": base64.b64encode(body).decode(),
    }


def test_real_local_artifact_ledger_upload_download_exact_bytes(
    artifact_case, tmp_path
):
    store, service, identity, requested, sample, settings = artifact_case
    directory = tmp_path / "ledger"
    directory.mkdir()
    delivery = service.poll(identity["credential"], {})

    def post(path, data):
        if path == "/api/agent/ack":
            return service.response_ack(identity["credential"], data)
        if path == "/api/agent/result":
            return service.response_result(identity["credential"], data)
        if path.endswith("/artifact"):
            return endpoint_response.artifact_upload(
                store, service, identity["credential"], requested["id"], data
            )
        raise AssertionError("Unexpected adapter request")

    agent = SimpleNamespace(
        identity=identity,
        config={"index": "endpoint", "response": settings},
        _post=post,
    )
    ledger = executor.Ledger(directory)
    try:
        assert ledger.handle(agent, delivery) == requested["id"]
        assert ledger.pending() == []
        result = endpoint_response.get(store, actor(), requested["id"])
        assert result["state"] == "succeeded" and result["result"]["executed"] is False
        identifier = result["result"]["data"]["server_artifact_id"]
        body, _filename, sha = endpoint_response.artifact_download(
            store, actor(), identifier
        )
        assert body == sample.read_bytes() and sha == hashlib.sha256(body).hexdigest()
        access.set_for_user(store, actor(), "admin_other", [])
        with pytest.raises(KeyError):
            endpoint_response.artifact_download(store, actor("admin_other"), identifier)
        with pytest.raises(KeyError):
            endpoint_response.artifact_download(
                store, actor("admin_b", "b"), identifier
            )
    finally:
        ledger.close()


def test_incomplete_upload_is_not_downloadable_and_chunks_are_idempotent(artifact_case):
    store, service, identity, _requested, sample, _settings = artifact_case
    command, receipt = claim(artifact_case)
    content = sample.read_bytes()
    first = chunk(receipt, content, body=content[:5])
    first_result = endpoint_response.artifact_upload(
        store, service, identity["credential"], command["id"], first
    )
    assert first_result["complete"] is False
    with pytest.raises(ConflictError):
        endpoint_response.artifact_download(store, actor(), first_result["artifact_id"])
    assert endpoint_response.artifact_upload(
        store, service, identity["credential"], command["id"], first
    )["duplicate"]
    with pytest.raises(ConflictError):
        endpoint_response.artifact_upload(
            store,
            service,
            identity["credential"],
            command["id"],
            chunk(receipt, content, body=b"XXXXX"),
        )
    complete = endpoint_response.artifact_upload(
        store,
        service,
        identity["credential"],
        command["id"],
        chunk(receipt, content, offset=5),
    )
    assert (
        complete["complete"]
        and endpoint_response.artifact_download(
            store, actor(), complete["artifact_id"]
        )[0]
        == content
    )
    assert endpoint_response.artifact_upload(
        store, service, identity["credential"], command["id"], first
    )["duplicate"]


@pytest.mark.parametrize(
    "fault", ["offset", "hash", "tenant", "lease", "scope", "total", "base64"]
)
def test_artifact_binding_and_bounds_fail_closed(artifact_case, fault):
    store, service, identity, _requested, sample, _settings = artifact_case
    command, receipt = claim(artifact_case)
    data = chunk(receipt, sample.read_bytes())
    credential = identity["credential"]
    if fault == "offset":
        data["offset"] = 1
    elif fault == "hash":
        data["sha256"] = "0" * 64
    elif fault == "tenant":
        credential = "unknown-agent-token"
    elif fault == "lease":
        data["lease_token"] = "a" * 40
    elif fault == "scope":
        access.set_for_user(store, actor(), "admin_a", [])
    elif fault == "total":
        data["total_bytes"] = 2 * 1024 * 1024 + 1
    else:
        data["body_base64"] = "!invalid!"
    with pytest.raises((ValueError, PermissionError, KeyError, ConflictError)):
        endpoint_response.artifact_upload(
            store, service, credential, command["id"], data
        )


def test_artifact_success_cannot_omit_remote_transfer(artifact_case):
    _store, service, identity, _requested, sample, _settings = artifact_case
    command, receipt = claim(artifact_case)
    with pytest.raises(ConflictError, match="completed"):
        service.response_result(
            identity["credential"],
            {
                "command_id": command["id"],
                **receipt,
                "result": {
                    "success": True,
                    "executed": False,
                    "type": "collect_artifact",
                    "code": "investigated",
                    "detail": "Locally collected only",
                    "data": {"bytes": sample.stat().st_size},
                },
            },
        )


def test_artifact_durable_offset_resumes_after_report_budget(
    local, tmp_path, monkeypatch
):
    sample, _target, settings, _operations = local
    sample.write_bytes(b"synthetic transfer fixture" * 4096)
    requested = {"id": "RSP-" + "1" * 32}
    # Fake transport advances a clock to exercise interrupted multi-chunk
    # delivery. This is a unit proof, not a TLS performance qualification.
    directory = tmp_path / "resume-ledger"
    directory.mkdir()
    artifact = executor.execute(
        {
            "type": "collect_artifact",
            "path": str(sample.resolve()),
            "sha256": hashlib.sha256(sample.read_bytes()).hexdigest(),
        },
        "HOST-01",
        settings,
    )
    ledger = executor.Ledger(directory)
    try:
        clock = [0.0]
        monotonic = SimpleNamespace(monotonic=lambda: clock[0], time=time.time)
        monkeypatch.setattr(executor, "time", monotonic)
        with ledger.db:
            ledger.db.execute(
                "INSERT INTO executions VALUES(?,?,?,?,?,'complete',?,0)",
                (
                    requested["id"],
                    "digest",
                    "0" * 32,
                    "lease",
                    "collect_artifact",
                    executor.canonical(artifact),
                ),
            )
            ledger.db.execute(
                "INSERT INTO execution_transport VALUES(?,?,0,NULL)",
                (requested["id"], time.time() + 200),
            )
        calls = []

        def post(path, data):
            calls.append(path)
            if path.endswith("/artifact"):
                clock[0] += 6
                received = data["offset"] + len(base64.b64decode(data["body_base64"]))
                return {
                    "artifact_id": "ART-" + "1" * 32,
                    "received": received,
                    "sha256": artifact["data"]["sha256"],
                    "complete": received == sample.stat().st_size,
                }
            return {"state": "succeeded"}

        agent = SimpleNamespace(config={"response": settings}, _post=post)
        with pytest.raises(TimeoutError):
            ledger.report(agent, budget=10)
        prefix = ledger.db.execute(
            "SELECT * FROM execution_transport WHERE id=?", (requested["id"],)
        ).fetchone()
        assert (
            prefix["artifact_offset"] == 65536 and prefix["artifact_server_id"] is None
        )
        ledger.report(agent, budget=10)
        row = ledger.db.execute(
            "SELECT * FROM execution_transport WHERE id=?", (requested["id"],)
        ).fetchone()
        assert (
            row["artifact_offset"] == sample.stat().st_size
            and row["artifact_server_id"] == "ART-" + "1" * 32
        )
        assert len(calls) == 4 and ledger.pending()
        ledger.report(agent, budget=10)
        assert len(calls) == 5 and not ledger.pending()
    finally:
        ledger.close()


def test_expired_partial_artifact_stays_undownloadable(artifact_case):
    store, service, identity, _requested, sample, _settings = artifact_case
    command, receipt = claim(artifact_case)
    first = endpoint_response.artifact_upload(
        store,
        service,
        identity["credential"],
        command["id"],
        chunk(receipt, sample.read_bytes(), body=sample.read_bytes()[:3]),
    )
    with store.control() as db:
        db.execute(
            "UPDATE endpoint_responses SET expires=? WHERE id=?",
            (time.time() - 1, command["id"]),
        )
    service.poll(identity["credential"], {})
    with store.control() as db:
        assert (
            db.execute(
                "SELECT state FROM endpoint_artifacts WHERE id=?",
                (first["artifact_id"],),
            ).fetchone()[0]
            == "unknown"
        )
    with pytest.raises(ConflictError):
        endpoint_response.artifact_download(store, actor(), first["artifact_id"])
