# ruff: noqa: F811 -- Imported pytest fixtures are injected by argument name.
"""Native producer fixtures and durable client protocol; no native sensors/actions."""

import hashlib
import io
import json
import secrets
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
import zipfile
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from sapientia import access, pipeline, xdr_bridge
from sapientia import agent_distribution as ad
from sapientia import endpoint_response as er
from sapientia.cluster import Recorder
from sapientia.endpoint_agent.Agent import core
from sapientia.endpoint_agent.Agent.Windows import collector as windows
from sapientia.storage import ConflictError, encode
from tests.test_agent_distribution import config, deployed, source_store  # noqa: F401
from tests.test_endpoint_response import response_case  # noqa: F401
from tests.test_xdr_bridge import actor, event
from tests.signing_support import release_signer, local_agent_development_config  # noqa: F401

pytestmark = pytest.mark.usefixtures("release_signer")


@pytest.mark.parametrize("platform", ["windows", "linux"])
def test_downloaded_package_dispatcher_imports_its_firewall_guard_without_native_effects(
    tmp_path, platform
):
    payload, _, _ = ad.package(platform)
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        assert "Agent/firewall_guard.py" in archive.namelist()
        manifest = json.loads(archive.read("manifest.json"))
        assert (
            hashlib.sha256(archive.read("Agent/firewall_guard.py")).hexdigest()
            == manifest["files"]["Agent/firewall_guard.py"]
        )
        archive.extractall(tmp_path)
    probe = tmp_path / "probe.py"
    probe.write_text(
        """import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace
root = Path(__file__).parent
spec = importlib.util.spec_from_file_location("downloaded_agent", root / "Agent/__init__.py", submodule_search_locations=[str(root / "Agent")])
package = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = package
spec.loader.exec_module(package)
from downloaded_agent import operations, firewall_guard
assert Path(firewall_guard.__file__).resolve() == (root / "Agent/firewall_guard.py").resolve()
class GuardReached(Exception):
    pass
def verified():
    raise GuardReached()
firewall_guard.verify = verified
operations._windows_cancel_path = lambda *args, **kwargs: "not-executed-private-fence"
operations.os = SimpleNamespace(name="nt", environ={})
try:
    operations._driver("a" * 32, {"allowlist": []})
except GuardReached:
    pass
else:
    raise AssertionError("Packaged dispatcher did not reach its own mandatory guard")
""",
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(probe)],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr


def xml(record, code=1, fields=None, timestamp="2026-10-12T00:00:00Z"):
    namespace = "http://schemas.microsoft.com/win/2004/08/events/event"
    root = ET.Element("{" + namespace + "}Event")
    system = ET.SubElement(root, "{" + namespace + "}System")
    for name, value in (("EventRecordID", record), ("EventID", code)):
        ET.SubElement(system, "{" + namespace + "}" + name).text = str(value)
    ET.SubElement(system, "{" + namespace + "}TimeCreated", SystemTime=timestamp)
    data = ET.SubElement(root, "{" + namespace + "}EventData")
    for name, value in (fields or {}).items():
        ET.SubElement(data, "{" + namespace + "}Data", Name=name).text = value
    return root


@pytest.fixture
def sensor():
    item = windows.WindowsCollector.__new__(windows.WindowsCollector)
    item.cursors, item.providers, item.provider_processes = {}, {}, {}
    item.last_rows, item.seen = {}, set()
    item.tcp_seen, item.tcp_epochs = set(), {}
    item.host_name, item.emit_initial, item.initialized = "fixture", True, False
    item.cursor_path = None
    return item


def channel(
    monkeypatch, records, expected_channel="Microsoft-Windows-Sysmon/Operational"
):
    def query(name, count=100, after=None, record_id=None):
        if name != expected_channel:
            return []
        if record_id is not None:
            return [
                r
                for r in records
                if int(r.findtext("{*}System/{*}EventRecordID")) == record_id
            ]
        if after is None:
            return records[-count:]
        return [
            r for r in records if int(r.findtext("{*}System/{*}EventRecordID")) > after
        ][:count]

    monkeypatch.setattr(windows, "_xml_events", query)


@pytest.mark.parametrize("code", [1, 3, 5, 6, 7, 8, 10, 11, 13, 14, 22, 23, 25, 26])
def test_windows_xml_producer_matches_server_typed_contract(sensor, monkeypatch, code):
    fields = {
        "ProcessId": "0x2a",
        "ParentProcessId": "7",
        "ProcessGuid": "fixture-guid",
        "SourcePort": "443",
        "DestinationPort": "1234",
        "SourceIp": "127.0.0.1",
        "DestinationIp": "::1",
        "Image": r"C:\fixture\test.exe",
        "ParentImage": "",
        "QueryName": "",
        "Hashes": "SHA256=" + "a" * 64,
    }
    channel(monkeypatch, [xml(1, code, fields)])
    produced = sensor._log_events("HOST")
    assert len(produced) == 1
    parsed = xdr_bridge.parse_event(
        produced[0], "agent", "endpoint", expected_host="HOST"
    )
    data = parsed["raw"]["xdr"]["data"]
    assert data["event"]["code"] == str(code)
    assert data["process"]["pid"] == 42
    assert data["source"]["port"] == 443
    assert "name" not in data["process"]["parent"]


@pytest.mark.parametrize(
    "code",
    [4688, 4689, 4657, 4663, 5156, 5157, 4624, 4625, 4648, 4768, 4769, 1116, 1117],
)
def test_security_and_defender_native_xml_match_server_contract(
    sensor, monkeypatch, code
):
    name = (
        "Security" if code >= 4000 else "Microsoft-Windows-Windows Defender/Operational"
    )
    fields = {
        "NewProcessId": "0x2a",
        "IpAddress": "127.0.0.1",
        "IpPort": "443",
        "TargetUserName": "fixture-user",
        "ProcessName": "",
        "ObjectName": "-",
    }
    channel(monkeypatch, [xml(1, code, fields)], name)
    produced = sensor._log_events("HOST")
    assert len(produced) == 1
    xdr_bridge.parse_event(produced[0], "agent", "endpoint", expected_host="HOST")
    assert produced[0]["data"]["event"]["code"] == str(code)


def test_preupgrade_poisoned_windows_spool_repairs_before_delivery(client):
    old = event("legacy", host="HOST")
    old["data"].update(
        agent={"collector": "windows-event-log"}, source={"port": "443", "ip": "-"}
    )
    old["data"]["event"]["code"] = 1
    old["data"]["process"].update(pid="0x2a", parent={"pid": "", "name": ""})
    client.queue.add(old)
    repaired = client.queue.peek()[0][1]
    assert repaired["id"] == "legacy" and repaired["data"]["process"]["pid"] == 42
    assert repaired["data"]["agent"]["legacy_wire_repaired"]
    xdr_bridge.parse_event(repaired, "agent", "endpoint", expected_host="HOST")
    assert client.queue.peek()[0][1] == repaired


def test_channel_clear_same_record_id_has_new_epoch_and_event_id(sensor, monkeypatch):
    records = [xml(1, fields={"ProcessGuid": "old"})]
    channel(monkeypatch, records)
    old = sensor._log_events("HOST")[0]
    records[:] = [
        xml(1, fields={"ProcessGuid": "new"}, timestamp="2026-10-12T00:01:00Z")
    ]
    new = sensor._log_events("HOST")[0]
    assert old["id"] != new["id"]
    assert new["data"]["agent"]["channel_epoch"] == 1


def test_pid_reuse_does_not_enrich_historical_log(sensor, monkeypatch):
    birth = (
        int(datetime(2026, 10, 12, tzinfo=UTC).timestamp() * 10_000_000)
        + 116444736000000000
    )
    sensor.last_rows = {
        "42:new": {
            "pid": 42,
            "birth": birth,
            "name": "test.exe",
            "executable": r"C:\test.exe",
        }
    }
    records = [
        xml(
            1,
            fields={"ProcessId": "42", "Image": r"C:\test.exe", "ProcessGuid": "old"},
            timestamp="2026-10-11T00:00:00Z",
        )
    ]
    channel(monkeypatch, records)
    assert "start_identity" not in sensor._log_events("HOST")[0]["data"]["process"]
    records.append(
        xml(
            2,
            fields={
                "ProcessId": "42",
                "Image": r"C:\test.exe",
                "ProcessGuid": "current",
            },
        )
    )
    data = sensor._log_events("HOST")[0]["data"]
    assert data["process"]["start_identity"] == "windows:" + str(birth)
    assert data["agent"]["provider_process_guid"] == "current"
    assert data["process"]["guid"] != "current"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "Transport", lambda *a, **k: None)
    settings = {
        "state_dir": str(tmp_path / "state"),
        "endpoint_url": "https://fixture",
        "ca_file": "fixture",
        "tenant": "a",
        "host": "HOST",
        "index": "endpoint",
    }
    identity = {
        "agent_id": "fixture-agent",
        "credential": "fixture-secret-only",
        "tenant": "a",
        "host": "HOST",
        "index": "endpoint",
    }
    core.atomic_json(Path(settings["state_dir"]) / "identity.json", identity)
    item = core.Agent(local_agent_development_config(settings), type("Collector", (), {"collect": lambda *a: []})())
    yield item
    item.queue.close()


def test_defense_uses_saved_enrollment_scope_not_configured_index(
    tmp_path, monkeypatch
):
    import importlib

    defense = importlib.import_module(core.response.__package__ + ".defense")

    captured = []
    monkeypatch.setattr(core, "Transport", lambda *a, **k: None)
    monkeypatch.setattr(
        defense,
        "Defense",
        lambda config, _: (
            captured.append(config) or SimpleNamespace(close=lambda: None)
        ),
    )
    settings = {
        "state_dir": str(tmp_path / "state"),
        "endpoint_url": "https://fixture",
        "ca_file": "fixture",
        "tenant": "a",
        "host": "HOST",
        "index": "caller-index",
        "agent_id": "caller-agent",
    }
    identity = {
        "agent_id": "enrolled-agent",
        "credential": "fixture-secret-only",
        "tenant": "a",
        "host": "HOST",
        "index": "enrolled-index",
    }
    core.atomic_json(Path(settings["state_dir"]) / "identity.json", identity)
    item = core.Agent(local_agent_development_config(settings), SimpleNamespace(collect=list))
    try:
        assert captured[0]["agent_id"] == identity["agent_id"]
        assert captured[0]["index"] == identity["index"]
        assert settings["index"] == "caller-index"
    finally:
        item.defense.close()
        item.queue.close()


def test_legacy_identity_without_index_collects_but_cannot_assert_defense_scope(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(core, "Transport", lambda *a, **k: None)
    settings = {
        "state_dir": str(tmp_path / "state"),
        "endpoint_url": "https://fixture",
        "ca_file": "fixture",
        "tenant": "a",
        "host": "HOST",
        "index": "caller-index",
    }
    identity = {
        "agent_id": "legacy-agent",
        "credential": "fixture-secret-only",
        "tenant": "a",
        "host": "HOST",
    }
    core.atomic_json(Path(settings["state_dir"]) / "identity.json", identity)
    item = core.Agent(local_agent_development_config(settings), SimpleNamespace(collect=list))
    try:
        assert item.defense.config["index"] is None
        assert item.defense.health()["state"] == "disabled"
        item.queue.add_many([{"id": "legacy-spool", "data": {"host": {"id": "HOST"}}}])
        assert item.queue.size() == 1
    finally:
        item.defense.close()
        item.queue.close()


def receipt(rows, **changes):
    body = {
        "durable": True,
        "accepted": len(rows),
        "duplicate": 0,
        "results": [{"id": row["id"], "quarantined": False} for row in rows],
    }
    body.update(changes)
    return body


@pytest.mark.parametrize(
    "change",
    [
        "wrong_id",
        "durable",
        "boolean_count",
        "negative_count",
        "wrong_total",
        "malformed_result",
        "missing_flag",
    ],
)
def test_invalid_ack_never_removes_local_events(client, change):
    rows = [event("one", host="HOST")]
    client.queue.add_many(rows)
    body = receipt(rows)
    if change == "wrong_id":
        body["results"][0]["id"] = "different"
    elif change == "durable":
        body["durable"] = False
    elif change == "boolean_count":
        body["accepted"] = True
    elif change == "negative_count":
        body.update(accepted=-1, duplicate=2)
    elif change == "wrong_total":
        body["accepted"] = 2
    elif change == "malformed_result":
        body["results"] = [None]
    else:
        body["results"][0].pop("quarantined")
    client._post = lambda *a: body
    with pytest.raises(RuntimeError):
        client.flush()
    assert client.queue.size() == 1


def test_durable_quarantine_preserved_without_poisoning_next_batch(client):
    rows = [event("one", host="HOST")]
    client.queue.add_many(rows)
    body = receipt(rows, quarantined=1)
    body["results"][0]["quarantined"] = True
    client._post = lambda *a: body
    assert client.flush() == 1
    assert client.queue.size() == 0 and client.queue.quarantine_size() == 1
    client.queue.add_many([event("two", host="HOST")])
    client._post = lambda _r, data: receipt(data["events"])
    assert client.flush() == 1


def test_ingest_failure_still_calls_heartbeat_and_response(client):
    called = []
    client.collector.collect = lambda *a: [event("one", host="HOST")]

    def post(route, _body):
        called.append(route)
        if route.endswith("ingest"):
            raise RuntimeError("fixture admission failure")
        return {}

    client._post = post
    client.poll = lambda: called.append("response")
    client.run(once=True)
    assert "/api/agent/heartbeat" in called and "response" in called
    queue = core.Queue(client.directory / "pending.sqlite3")
    try:
        assert queue.size() == 1
    finally:
        queue.close()


def test_control_worker_runs_while_collection_is_blocked(client):
    collecting, polled, release = (
        threading.Event(),
        threading.Event(),
        threading.Event(),
    )

    def collect(*a):
        collecting.set()
        release.wait(2)
        return []

    client.queue.close()
    holder = []

    def run():
        agent = core.Agent(client.config, type("Collector", (), {"collect": collect})())
        agent._post = lambda *a: {}
        agent.poll = polled.set
        holder.append(agent)
        agent.run()

    worker = threading.Thread(target=run)
    worker.start()
    try:
        assert collecting.wait(1) and polled.wait(1)
    finally:
        if holder:
            holder[0].stop.set()
        release.set()
        worker.join(3)
    assert not worker.is_alive() and not holder[0]._control_thread.is_alive()


def test_unexpected_control_failure_is_explicit_and_requests_stop(client):
    def broken(*args):
        raise TypeError("fixture unexpected control bug")

    client._control_cycle = broken
    client._control_loop()
    assert client.stop.is_set() and client._control_fatal == "TypeError"
    assert client.errors["control_worker"] == "TypeError"


@pytest.mark.parametrize("failure", [RuntimeError, ValueError])
def test_heartbeat_failure_never_blocks_receipts_or_renewal(client, failure):
    called = []
    client.identity["expires_at"] = time.time() + 1
    client._provider_health = {"oversized": "fixture" * 1000}
    client.queue.add_many([event("durable-pending", host="HOST")])

    def post(route, body):
        called.append("heartbeat")
        assert route == "/api/agent/heartbeat"
        raise failure("fixture heartbeat503 or oversized health400")

    class Transport:
        def post(self, route, body, credential):
            called.append("renew")
            return {
                **client.identity,
                "index": "endpoint",
                "credential": secrets.token_urlsafe(40),
                "expires_at": time.time() + 90 * 86400,
            }

    client._post, client.transport = post, Transport()
    client.poll = lambda: called.append("receipt-poll")
    client._control_cycle(0, 0)
    assert called == ["heartbeat", "receipt-poll", "renew"]
    assert client.queue.size() == 1 and client.errors["heartbeat"] == failure.__name__
    assert "response" not in client.errors and "credential" not in client.errors


def test_recovery_same_proof_returns_same_credential_ciphertext_only(
    source_store, config
):
    service = ad.Distribution(source_store, config)
    _, token, _ = deployed(service)
    key = secrets.token_urlsafe(32)
    body = {"enrollment_token": token, "version": "v1", "recovery_key": key}
    first = service.enroll(body)
    assert service.enroll(body) == first
    with source_store.control() as db:
        saved = db.execute(
            "SELECT recovery_digest,response FROM endpoint_enrollment_recovery"
        ).fetchone()
        assert key not in saved["recovery_digest"] and first[
            "credential"
        ].encode() not in ad._encrypted_bytes(saved["response"])
    with pytest.raises(PermissionError):
        service.enroll({**body, "recovery_key": secrets.token_urlsafe(32)})
    with pytest.raises(PermissionError):
        service.enroll({"enrollment_token": token, "version": "v1"})
    access.set_for_user(source_store, actor(), "admin_a", [])
    with pytest.raises(PermissionError):
        service.enroll(body)


def test_enrollment_crash_after_server_commit_reuses_durable_proof(
    source_store, config, tmp_path, monkeypatch
):
    service = ad.Distribution(source_store, config)
    _, token, _ = deployed(service)
    settings = {
        "state_dir": str(tmp_path / "client"),
        "endpoint_url": config["endpoint_url"],
        "ca_file": "fixture",
        "tenant": "a",
        "host": "HOST-01",
        "index": "endpoint",
    }
    lost = [True]

    class Transport:
        def __init__(self, *a):
            pass

        def post(self, _route, data):
            result = service.enroll(data)
            if lost.pop() if lost else False:
                raise ConnectionError("fixture lost response")
            return result

    monkeypatch.setattr(core, "Transport", Transport)
    with pytest.raises(ConnectionError):
        core.enroll(settings, token)
    recovery = Path(settings["state_dir"]) / "enrollment-recovery.json"
    assert recovery.exists()
    assert core.enroll(settings, token)["host"] == "HOST-01"
    assert not recovery.exists()
    with source_store.control() as db:
        assert db.execute("SELECT count(*) FROM endpoint_agents").fetchone()[0] == 1


def test_queue_cycle_bound_is_atomic_and_full_sync(tmp_path):
    queue = core.Queue(tmp_path / "pending.sqlite3", max_pending=1)
    try:
        assert queue.db.execute("PRAGMA synchronous").fetchone()[0] == 2
        with pytest.raises(RuntimeError):
            queue.add_many([event("one"), event("two")])
        assert queue.size() == 0
        queue.max_pending, queue.max_bytes = 100, 10
        with pytest.raises(RuntimeError):
            queue.add_many([event("unicode", host="한글")])
        assert queue.size() == 0
    finally:
        queue.close()


def test_cursor_checkpoint_failure_keeps_committed_spool_and_rolls_back_source(client):
    rolled = []

    class Collector:
        def begin_cycle(self):
            pass

        def collect(self, host):
            return [event("one", host=host)]

        def checkpoint(self):
            raise OSError("fixture checkpoint fsync failure")

        def rollback(self):
            rolled.append(True)

    client.collector = Collector()
    with pytest.raises(OSError):
        client._collect_cycle()
    assert rolled and client.queue.size() == 1
    client.queue.close()
    reopened = core.Queue(client.directory / "pending.sqlite3")
    try:
        assert reopened.peek()[0][0] == "one"
    finally:
        reopened.close()


@pytest.mark.parametrize("condition", ["expired", "revoked", "disabled"])
def test_enrollment_recovery_fails_closed_after_revocation(
    source_store, config, condition
):
    service = ad.Distribution(source_store, config)
    _, token, _ = deployed(service)
    body = {
        "enrollment_token": token,
        "version": "v1",
        "recovery_key": secrets.token_urlsafe(32),
    }
    registered = service.enroll(body)
    with source_store.control() as db:
        if condition == "expired":
            db.execute("UPDATE endpoint_enrollment_recovery SET expires=0")
        elif condition == "revoked":
            db.execute(
                "UPDATE endpoint_agents SET revoked=1 WHERE id=?",
                (registered["agent_id"],),
            )
        else:
            db.execute("UPDATE users SET disabled=1 WHERE name='admin_a'")
    with pytest.raises(PermissionError):
        service.enroll(body)


def test_rotation_invalidates_old_general_bearer_and_same_proof_recovers(
    source_store, config
):
    service = ad.Distribution(source_store, config)
    _, token, _ = deployed(service)
    first = service.enroll({"enrollment_token": token, "version": "v1"})
    proof = {"recovery_key": secrets.token_urlsafe(32)}
    rotated = service.renew(first["credential"], proof)
    assert rotated["agent_id"] == first["agent_id"]
    assert ad._secret(rotated["credential"]) != ad._secret(first["credential"])
    assert ad._secret(
        service.renew(first["credential"], proof)["credential"]
    ) == ad._secret(rotated["credential"])
    for callback, body in [
        (service.poll, {}),
        (service.ingest, {"events": [event("one", host="HOST-01")]}),
        (service.heartbeat, {"health": {}}),
    ]:
        with pytest.raises(PermissionError):
            callback(first["credential"], body)
    with pytest.raises(PermissionError):
        service.renew(first["credential"], {"recovery_key": secrets.token_urlsafe(32)})
    with pytest.raises(ConflictError):
        service.renew(
            rotated["credential"], {"recovery_key": secrets.token_urlsafe(32)}
        )
    with source_store.control() as db:
        db.execute("UPDATE endpoint_credential_recovery SET expires=0")
    with pytest.raises(PermissionError):
        service.renew(first["credential"], proof)
    access.set_for_user(source_store, actor(), "admin_a", [])
    with pytest.raises(PermissionError):
        service.renew(rotated["credential"], proof)


@pytest.mark.parametrize("state", ["claimed", "started", "unknown"])
def test_rotation_defers_all_unreported_effects(response_case, state, monkeypatch):
    store, service, identity, incident, body = response_case
    # Pure database schema fixture; this test never polls or dispatches an executor.
    with monkeypatch.context() as command_schema:
        command_schema.delenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", raising=False)
        created = er.create(store, actor(), incident, body)
    with store.control() as db:
        db.execute(
            "UPDATE endpoint_responses SET state=?,execution_id=? WHERE id=?",
            (state, None if state == "claimed" else "fixture-execution", created["id"]),
        )
    with pytest.raises(ConflictError):
        service.renew(
            identity["credential"], {"recovery_key": secrets.token_urlsafe(32)}
        )
    assert service.heartbeat(identity["credential"], {"health": {}})


def test_rotation_reply_or_identity_write_failure_recovers_without_spool_loss(
    source_store, config, client, monkeypatch
):
    service = ad.Distribution(source_store, config)
    _, token, _ = deployed(service)
    original = service.enroll({"enrollment_token": token, "version": "v1"})
    client.identity = original
    client.config.update(host="HOST-01", tenant="a", index="endpoint")
    client.queue.add_many([event("still-pending", host="HOST-01")])

    class Transport:
        def post(self, _route, body, credential):
            return service.renew(credential, body)

    client.transport = Transport()
    atomic = core.atomic_json
    broken = [True]

    def write(path, value):
        if Path(path) == client.identity_path and broken.pop() if broken else False:
            raise OSError("fixture identity fsync failure")
        return atomic(path, value)

    monkeypatch.setattr(core, "atomic_json", write)
    with pytest.raises(OSError):
        client.renew()
    assert client.directory.joinpath("credential-recovery.json").exists()
    assert client.queue.size() == 1
    result = client.renew()
    assert result["agent_id"] == original["agent_id"] and client.queue.size() == 1
    assert not client.directory.joinpath("credential-recovery.json").exists()
    assert json.loads(client.identity_path.read_text())["expires_at"] > time.time()


def test_recovery_ciphertext_is_json_safe_in_replicated_control_transactions(
    source_store, config
):
    captured = []

    class Proxy:
        def __getattr__(self, key):
            return getattr(source_store, key)

        @contextmanager
        def control(self, local=False):
            with source_store.control(local=True) as db:
                recorder = Recorder(db)
                yield recorder
                # Same serialization seam as the quorum journal; no NATS or
                # cluster/network is started by this fixture.
                captured.append(json.loads(json.dumps(recorder.statements)))

    service = ad.Distribution(Proxy(), config)
    _, token, _ = deployed(service)
    body = {
        "enrollment_token": token,
        "version": "v1",
        "recovery_key": secrets.token_urlsafe(32),
    }
    registered = service.enroll(body)
    rotated = service.renew(
        registered["credential"], {"recovery_key": secrets.token_urlsafe(32)}
    )
    assert rotated["agent_id"] == registered["agent_id"]
    statements = [statement for transaction in captured for statement in transaction]
    encrypted_inserts = [
        s
        for s in statements
        if s["sql"].startswith("INSERT INTO endpoint_") and "recovery" in s["sql"]
    ]
    assert len(encrypted_inserts) == 2
    assert all(
        isinstance(s["params"][-1], str) and isinstance(s["params"][-2], str)
        for s in encrypted_inserts
    )


def test_agent_origin_binds_final_stored_payload_and_durable_receipt(
    source_store, config
):
    service = ad.Distribution(source_store, config)
    _, token, _ = deployed(service)
    identity = service.enroll({"enrollment_token": token, "version": "v1"})
    pipeline.save(
        source_store,
        actor(),
        "endpoint-redaction",
        {
            "version": 0,
            "definition": {
                "source": "aegis-xdr",
                "enabled": True,
                "redact_fields": ["raw.xdr.data.process.command_line"],
            },
        },
    )
    row = event("native-origin", host="HOST-01")
    row["data"]["process"]["command_line"] = "fixture sensitive command"
    assert service.ingest(identity["credential"], {"events": [row]})["accepted"] == 1
    source_store.flush()
    with source_store.control() as db:
        proof = dict(db.execute("SELECT * FROM endpoint_event_receipts").fetchone())
        receipt = db.execute(
            "SELECT digest,received FROM receipts WHERE tenant='a' AND event_id=?",
            (proof["event_id"],),
        ).fetchone()
        assert (
            proof["receipt_digest"] == receipt["digest"]
            and proof["received"] == receipt["received"]
        )
    stored = source_store.analytics_query(
        "SELECT event_id,event_time,source,sourcetype,host,severity,message,raw,index_name,received FROM events_all WHERE tenant=?",
        ["a"],
        max_rows=1,
    )["rows"][0]
    received = stored.pop("received")
    stored["index"] = stored.pop("index_name")
    stored["raw"] = json.loads(stored["raw"])
    assert (
        proof["payload_digest"] == hashlib.sha256(encode(stored).encode()).hexdigest()
    )
    assert proof["received"] == received and proof["agent_id"] == identity["agent_id"]
    assert "fixture sensitive command" not in encode(stored)
    assert service.ingest(identity["credential"], {"events": [row]})["duplicate"] == 1


def test_generic_event_cannot_be_promoted_by_agent_retry_and_batch_rolls_back(
    source_store, config
):
    service = ad.Distribution(source_store, config)
    _, token, _ = deployed(service)
    identity = service.enroll({"enrollment_token": token, "version": "v1"})
    generic = event("generic-original", host="HOST-01")
    source_store.ingest(
        "a",
        [xdr_bridge.parse_event(generic, "agent", "endpoint")],
        "generic-collector",
        allowed_indexes=["endpoint"],
    )
    with pytest.raises(PermissionError):
        service.ingest(
            identity["credential"],
            {"events": [event("fresh-before-generic", host="HOST-01"), generic]},
        )
    with source_store.control() as db:
        assert (
            db.execute("SELECT count(*) FROM endpoint_event_receipts").fetchone()[0]
            == 0
        )
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM queue").fetchone()[0] == 1


def test_retired_admission_receipt_removes_native_proof_and_generic_reuse_stays_untrusted(
    source_store, config
):
    service = ad.Distribution(source_store, config)
    _, token, _ = deployed(service)
    identity = service.enroll({"enrollment_token": token, "version": "v1"})
    row = event("retired-origin", host="HOST-01")
    service.ingest(identity["credential"], {"events": [row]})
    with source_store.control() as db:
        identifier = db.execute(
            "SELECT event_id FROM endpoint_event_receipts"
        ).fetchone()[0]
        db.execute("DELETE FROM queue WHERE tenant='a' AND event_id=?", (identifier,))
        db.execute(
            "DELETE FROM receipts WHERE tenant='a' AND event_id=?", (identifier,)
        )
        assert (
            db.execute("SELECT count(*) FROM endpoint_event_receipts").fetchone()[0]
            == 0
        )
    source_store.ingest(
        "a",
        [xdr_bridge.parse_event(row, "agent", "endpoint")],
        "generic-collector",
        allowed_indexes=["endpoint"],
    )
    with pytest.raises(PermissionError):
        service.ingest(identity["credential"], {"events": [row]})
