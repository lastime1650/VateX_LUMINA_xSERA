# ruff: noqa: F811 -- Imported pytest fixtures are injected by argument name.
"""Detection continuity contracts; fixture sensors, no native effects or hosts."""

import copy
import hashlib
import threading
import time
from pathlib import Path

import pytest

from sapientia.endpoint_agent.Agent import core
from sapientia.endpoint_agent.Agent.defense import Defense
from sapientia.endpoint_agent.Agent.Windows import collector as windows
from sapientia.xdr_bridge import parse_event
from tests.test_agent_remediation import channel, client, sensor, xml  # noqa: F401
from tests.test_endpoint_defense import NOW, setup  # noqa: F401
from tests.test_linux_collector_remediation import collector  # noqa: F401
from tests.signing_support import local_agent_development_config


def agent_for(queue, defense, config):
    agent = core.Agent.__new__(core.Agent)
    agent.queue, agent.defense, agent.config = queue, defense, config
    agent.kernel_prevention = None
    agent.identity = {"host": config["host"]}
    return agent


def paused_transport_run(config, collector, progressed):
    transmitting, release = threading.Event(), threading.Event()
    errors, holders = [], []

    def run():
        try:
            agent = core.Agent(local_agent_development_config(config), collector)

            def post(route, _body):
                if route.endswith("ingest"):
                    transmitting.set()
                    release.wait(6)
                    raise RuntimeError("fixture paused transport")
                return {}

            agent._post, agent.poll = post, lambda: None
            holders.append(agent)
            agent.run()
        except Exception as error:  # noqa: BLE001 -- fixture must surface any worker failure to the test thread.
            errors.append(error)

    worker = threading.Thread(target=run)
    worker.start()
    try:
        assert transmitting.wait(3)
        assert progressed.wait(3)
        assert not release.is_set()
    finally:
        if holders:
            holders[0].stop.set()
        release.set()
        worker.join(8)
    assert not worker.is_alive() and not errors
    assert not holders[0]._capture_thread.is_alive()
    assert not holders[0]._evaluation_thread.is_alive()
    return holders[0]


def test_capture_worker_makes_progress_while_transmission_is_blocked(client):
    progressed, captured = threading.Event(), []
    client.queue.close()

    class Collector:
        def collect(self, host):
            captured.append(True)
            if len(captured) >= 2:
                progressed.set()
            return [
                {
                    "id": "capture-" + str(len(captured)),
                    "data": {
                        "host": {"id": host},
                        "event": {"action": "process_observed"},
                    },
                }
            ]

    paused_transport_run(
        dict(client.config, collect_interval_seconds=1), Collector(), progressed
    )
    queue = core.Queue(Path(client.config["state_dir"]) / "pending.sqlite3")
    try:
        assert queue.size() >= 2
    finally:
        queue.close()


def test_local_rule_evaluation_makes_progress_while_transmission_is_blocked(
    setup, monkeypatch
):
    config, document, event, _calls, _response, write = setup
    document["issued_at"], document["expires_at"] = time.time() - 60, time.time() + 3600
    write(document)
    config = dict(
        config,
        endpoint_url="https://fixture",
        ca_file="fixture",
        collect_interval_seconds=1,
    )
    identity = {
        **{key: config[key] for key in ("tenant", "host", "index", "agent_id")},
        "credential": "owned-fixture-only",
    }
    core.atomic_json(Path(config["state_dir"]) / "identity.json", identity)
    monkeypatch.setattr(core, "Transport", lambda *a, **k: None)
    progressed, calls = threading.Event(), []

    def execute(*_args):
        calls.append(True)
        if len(calls) >= 2:
            progressed.set()
        return {"success": True, "executed": True, "code": "fixture_only"}

    monkeypatch.setattr(core.response, "execute", execute)

    class Collector:
        count = 0

        def collect(self, _host):
            self.count += 1
            return [dict(event, id="evaluate-" + str(self.count))]

    paused_transport_run(config, Collector(), progressed)
    assert len(calls) >= 2


def test_procfs_long_command_retains_observed_suffix_and_explicit_fidelity(
    tmp_path, monkeypatch
):
    from sapientia.endpoint_agent.Agent.Linux import collector as module

    proc = tmp_path / "proc"
    target = proc / "42"
    target.mkdir(parents=True)
    (target / "stat").write_text(
        "42 (owned) " + " ".join(["S", "1", *["0"] * 17, "100", "0", "0"])
    )
    command = "x" * 4096 + " OBSERVED-SUFFIX " + "x" * 6000
    (target / "cmdline").write_bytes(command.encode())
    (target / "status").write_text("Uid:\t0\t0\t0\t0\n")
    monkeypatch.setattr(
        module, "Path", lambda value: proc if value == "/proc" else Path(value)
    )
    monkeypatch.setattr(module.os, "readlink", lambda _path: "/owned/exe")
    row = module.LinuxCollector.__new__(module.LinuxCollector)._rows()[0]
    assert "OBSERVED-SUFFIX" in row["command_line"]
    assert len(row["command_line"]) == 8192
    assert row["command_line_original_length"] == len(command)
    assert row["command_line_sha256"] == hashlib.sha256(command.encode()).hexdigest()
    assert row["command_line_truncated"] is True
    assert row["command_line_raw_bytes"] == len(command.encode())
    assert (
        row["command_line_raw_sha256"] == hashlib.sha256(command.encode()).hexdigest()
    )
    assert row["command_line_decode_replacement"] is False


def test_procfs_non_utf8_arguments_keep_raw_hash_and_replacement_evidence(
    tmp_path, monkeypatch
):
    from sapientia.endpoint_agent.Agent.Linux import collector as module

    proc = tmp_path / "proc"
    target = proc / "42"
    target.mkdir(parents=True)
    (target / "stat").write_text(
        "42 (owned) " + " ".join(["S", "1", *["0"] * 17, "100", "0", "0"])
    )
    raw = b"owned\x00\xffobserved-argument"
    (target / "cmdline").write_bytes(raw)
    (target / "status").write_text("Uid:\t0\t0\t0\t0\n")
    monkeypatch.setattr(
        module, "Path", lambda value: proc if value == "/proc" else Path(value)
    )
    monkeypatch.setattr(module.os, "readlink", lambda _path: "/owned/exe")
    row = module.LinuxCollector.__new__(module.LinuxCollector)._rows()[0]
    assert "observed-argument" in row["command_line"]
    assert row["command_line_raw_bytes"] == len(raw)
    assert row["command_line_raw_sha256"] == hashlib.sha256(raw).hexdigest()
    assert row["command_line_decode_replacement"] is True


def test_rule_tail_resumes_durably_after_restart_without_duplicate_effects(
    setup, tmp_path
):
    config, document, event, calls, response, write = setup
    rule = document["rules"][0]
    document["rules"] = [dict(rule, id="rule-" + str(i)) for i in range(256)]
    write(document)
    defense = Defense(config, response, clock=lambda: NOW)
    path = tmp_path / "queue.sqlite3"
    queue = core.Queue(path, 1000)
    queue.add_many([event], evaluate=True)
    agent_for(queue, defense, config)._evaluation_cycle()
    assert len(calls) == 200
    assert queue.evaluation_peek()[2] == 200
    assert queue.evaluation_size() == 1
    queue.close()
    defense.close()
    queue = core.Queue(path, 1000)
    defense = Defense(config, response, clock=lambda: NOW)
    try:
        agent_for(queue, defense, config)._evaluation_cycle()
        assert len(calls) == 256
        assert queue.evaluation_size() == 0
        assert queue.size() == 257  # Original plus each distinct rule result.
    finally:
        queue.close()
        defense.close()


def test_policy_revision_change_restarts_work_at_new_signed_revision(setup):
    config, document, event, calls, response, write = setup
    defense = Defense(config, response, clock=lambda: NOW)
    old_digest = defense.digest
    updated = copy.deepcopy(document)
    updated["revision"] = 2
    write(updated)
    result = defense.evaluate_resumable(event, cursor=256, policy_digest=old_digest)
    assert result["complete"] is True and len(result["events"]) == 1
    assert result["events"][0]["data"]["local_defense"]["revision"] == 2
    assert len(calls) == 1
    defense.close()


def test_expired_policy_work_is_retained_without_effect(setup, tmp_path):
    config, _document, event, calls, response, _write = setup
    defense = Defense(config, response, clock=lambda: NOW + 7200)
    queue = core.Queue(tmp_path / "queue.sqlite3")
    try:
        queue.add_many([event], evaluate=True)
        agent_for(queue, defense, config)._evaluation_cycle()
        assert queue.evaluation_size() == 1 and calls == []
    finally:
        queue.close()
        defense.close()


def test_output_commit_failure_replay_does_not_repeat_destructive_effect(
    setup, tmp_path, monkeypatch
):
    config, _document, event, calls, response, _write = setup
    defense = Defense(config, response, clock=lambda: NOW)
    queue = core.Queue(tmp_path / "queue.sqlite3")
    queue.add_many([event], evaluate=True)
    original = queue.evaluation_settle
    monkeypatch.setattr(
        queue,
        "evaluation_settle",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("fixture fsync")),
    )
    with pytest.raises(OSError):
        agent_for(queue, defense, config)._evaluation_cycle()
    assert len(calls) == 1 and queue.evaluation_size() == 1
    monkeypatch.setattr(queue, "evaluation_settle", original)
    agent_for(queue, defense, config)._evaluation_cycle()
    assert len(calls) == 1 and queue.evaluation_size() == 0
    queue.close()
    defense.close()


def test_capture_reserve_keeps_local_work_and_originals_durable_above_transport_mark(
    setup, tmp_path
):
    config, _document, event, _calls, response, _write = setup
    queue = core.Queue(tmp_path / "queue.sqlite3", max_pending=1, capture_reserve=2)
    defense = Defense(config, response, clock=lambda: NOW)
    agent = agent_for(queue, defense, config)
    seen = []

    class Collector:
        def collect(self, host):
            seen.append(host)
            return [dict(event, id="capture-second")]

    agent.collector = Collector()
    queue.add_many([event])
    agent._collect_cycle()
    assert seen == [config["host"]] and queue.size() == 2
    assert queue.evaluation_size() == 1
    agent._evaluation_cycle()
    assert queue.evaluation_size() == 0 and queue.size() == 3
    queue.close()
    defense.close()


def test_hard_capture_or_evaluation_bound_rolls_back_entire_source_cycle(
    setup, tmp_path
):
    _config, _document, event, _calls, _response, _write = setup
    queue = core.Queue(tmp_path / "queue.sqlite3", max_pending=1, capture_reserve=1)
    try:
        with pytest.raises(RuntimeError):
            queue.add_many([dict(event, id=str(i)) for i in range(3)], evaluate=True)
        assert queue.size() == queue.evaluation_size() == 0
    finally:
        queue.close()


def test_durable_evaluation_identity_conflict_is_rejected(setup, tmp_path):
    _config, _document, event, _calls, _response, _write = setup
    queue = core.Queue(tmp_path / "queue.sqlite3")
    try:
        queue.add_many([event], evaluate=True)
        altered = copy.deepcopy(event)
        altered["data"]["process"]["name"] = "other.exe"
        with pytest.raises(ValueError, match="identity content conflict"):
            queue.add_many([altered], evaluate=True)
        assert queue.evaluation_peek()[1] == event
    finally:
        queue.close()


def test_same_immutable_native_record_retry_preserves_first_enrichment_after_delivery(
    setup, tmp_path
):
    config, _document, event, calls, response, _write = setup
    event["data"]["agent"] = {"source_record_sha256": "a" * 64, "collector": "auditd"}
    defense = Defense(config, response, clock=lambda: NOW)
    queue = core.Queue(tmp_path / "queue.sqlite3")
    try:
        queue.add_many([event], evaluate=True)
        agent_for(queue, defense, config)._evaluation_cycle()
        assert len(calls) == 1
        queue.remove([key for key, _ in queue.peek(100)])
        altered = copy.deepcopy(event)
        altered["data"]["process"]["command_line"] = (
            "later enrichment with same immutable source record"
        )
        queue.add_many([altered], evaluate=True)
        assert queue.evaluation_peek()[1] == event
        agent_for(queue, defense, config)._evaluation_cycle()
        assert len(calls) == 1 and queue.evaluation_size() == 0
    finally:
        queue.close()
        defense.close()


@pytest.mark.parametrize(
    "original,current", [("a" * 64, "b" * 64), ("x" * 64, "x" * 64)]
)
def test_native_record_retry_requires_matching_real_sha256(
    setup, tmp_path, original, current
):
    _config, _document, event, _calls, _response, _write = setup
    event["data"]["agent"] = {"source_record_sha256": original}
    queue = core.Queue(tmp_path / "queue.sqlite3")
    try:
        queue.add_many([event], evaluate=True)
        altered = copy.deepcopy(event)
        altered["data"]["agent"]["source_record_sha256"] = current
        altered["data"]["process"]["name"] = "changed"
        with pytest.raises(ValueError, match="identity content conflict"):
            queue.add_many([altered], evaluate=True)
        assert queue.evaluation_peek()[1] == event
    finally:
        queue.close()


def test_concurrent_capture_writers_serialize_capacity_decision(setup, tmp_path):
    _config, _document, event, _calls, _response, _write = setup
    path = tmp_path / "queue.sqlite3"
    initial = core.Queue(path, max_pending=2)
    initial.close()
    barrier, outcomes = threading.Barrier(2), []

    def writer(prefix):
        queue = core.Queue(path, max_pending=2)
        try:
            barrier.wait(timeout=3)
            try:
                queue.add_many(
                    [dict(event, id=prefix + str(i)) for i in range(2)], evaluate=True
                )
            except RuntimeError:
                outcomes.append("bounded")
            else:
                outcomes.append("accepted")
        finally:
            queue.close()

    workers = [threading.Thread(target=writer, args=(prefix,)) for prefix in ("a", "b")]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(6)
    assert all(not worker.is_alive() for worker in workers)
    assert sorted(outcomes) == ["accepted", "bounded"]
    queue = core.Queue(path, max_pending=2)
    try:
        assert queue.size() == queue.evaluation_size() == 2
    finally:
        queue.close()


def test_sysmon_running_does_not_suppress_independent_network_observation(
    sensor, monkeypatch
):
    sensor.sysmon_available, sensor._sysmon_check_at, sensor.event_log = (
        True,
        10**12,
        True,
    )
    monkeypatch.setattr(sensor, "_process_events", lambda _: [])
    monkeypatch.setattr(sensor, "_log_events", lambda *a, **k: [])
    monkeypatch.setattr(
        sensor, "_tcp_events", lambda _: [{"id": "fallback", "data": {}}]
    )
    assert sensor.collect("HOST")[0]["id"] == "fallback"
    health = sensor.provider_health()["sysmon_capabilities"]
    assert health["service_running"] and health["network_fallback_retained"]
    assert health["configuration_verified"] is False


def test_cross_provider_flow_group_needs_native_incarnation_never_pid_alone(sensor):
    def data(start, guid="native-guid"):
        return {
            "host": {"id": "HOST"},
            "process": {"pid": 42, "guid": guid, "start_identity": start},
            "event": {"action": "network_connection"},
            "network": {"protocol": "tcp"},
            "source": {"ip": "2001:db8::1", "port": 40000},
            "destination": {"ip": "2001:0db8:0:0:0:0:0:2", "port": 443},
        }

    fallback, provider = data("windows:100"), data("windows:100")
    sensor._flow_fidelity(fallback)
    sensor._flow_fidelity(provider)
    assert (
        fallback["agent"]["potential_flow_group"]
        == provider["agent"]["potential_flow_group"]
    )
    assert (
        fallback["agent"]["count_semantics"]
        == "sensor_observations_not_unique_connections"
    )
    assert fallback["agent"]["native_socket_generation"] == "unavailable"
    reused = data("windows:200")
    sensor._flow_fidelity(reused)
    assert (
        reused["agent"]["potential_flow_group"]
        != fallback["agent"]["potential_flow_group"]
    )
    unbound = data(None, "provider-guid-not-verified")
    sensor._flow_fidelity(unbound)
    assert "potential_flow_group" not in unbound["agent"]
    assert (
        unbound["agent"]["cross_provider_process_identity"]
        == "unverified_alias_no_flow_group"
    )


def test_noisy_first_channels_cannot_starve_defender_or_security(sensor, monkeypatch):
    tables = {
        windows.CODE_INTEGRITY_CHANNEL: [xml(i, 3077) for i in range(1, 21)],
        "Microsoft-Windows-Sysmon/Operational": [
            xml(
                i,
                1,
                {"ProcessGuid": str(i), "ProcessId": "42", "Image": r"C:\owned.exe"},
            )
            for i in range(1, 21)
        ],
        "Security": [xml(1, 4625)],
        "Microsoft-Windows-Windows Defender/Operational": [xml(1, 1116)],
    }

    def query(name, count=100, after=None, record_id=None):
        rows = tables.get(name, [])
        if record_id is not None:
            return [
                row
                for row in rows
                if int(row.findtext("{*}System/{*}EventRecordID")) == record_id
            ]
        return (
            rows[-count:]
            if after is None
            else [
                row
                for row in rows
                if int(row.findtext("{*}System/{*}EventRecordID")) > after
            ][:count]
        )

    monkeypatch.setattr(windows, "_xml_events", query)
    produced = sensor._log_events("HOST", limit=10)
    providers = {item["data"]["event"]["provider"] for item in produced}
    assert "Security" in providers
    assert "Microsoft-Windows-Windows Defender/Operational" in providers
    assert len(produced) <= 10
    assert sensor.providers[windows.CODE_INTEGRITY_CHANNEL]["backlog"] is True


@pytest.mark.parametrize(
    "code,text,number,total",
    [
        (4103, "observed-command", None, None),
        (4104, "owned-script", "1", "1"),
        (4104, "fragment", "1", "2"),
        (4104, "x" * 10000, "1", "1"),
    ],
)
def test_powershell_observation_preserves_fragment_fidelity_without_invented_identity(
    sensor, monkeypatch, code, text, number, total
):
    fields = {"ScriptBlockText": text, "ScriptBlockId": "owned-block"}
    if number is not None:
        fields.update(MessageNumber=number, MessageTotal=total)
    channel(
        monkeypatch, [xml(1, code, fields)], "Microsoft-Windows-PowerShell/Operational"
    )
    produced = sensor._log_events("HOST")[0]
    core.bound_entity_strings(produced)
    parsed = parse_event(produced, "agent", "endpoint", expected_host="HOST")
    data = parsed["raw"]["xdr"]["data"]
    block = data["powershell"]
    assert block["script_block"] == text[:8192]
    assert block["sha256"] == hashlib.sha256(text.encode()).hexdigest()
    assert block["original_length"] == len(text)
    assert block["complete"] == (number == total == "1" and len(text) <= 8192)
    assert data.get("process", {}).get("guid") is None
    assert data["agent"]["process_response_eligible"] is False


def test_unbound_security_preserves_analysis_metadata_but_no_effect_identity(
    sensor, monkeypatch
):
    channel(
        monkeypatch,
        [
            xml(
                1,
                4689,
                {
                    "ProcessId": "42",
                    "ProcessName": r"C:\owned\observed.exe",
                    "CommandLine": "owned marker",
                },
            )
        ],
        "Security",
    )
    produced = sensor._log_events("HOST")[0]
    data = parse_event(produced, "agent", "endpoint", expected_host="HOST")["raw"][
        "xdr"
    ]["data"]
    assert data["process"]["name"] == "observed.exe"
    assert data["process"]["command_line"] == "owned marker"
    assert not any(
        data["process"].get(key) for key in ("guid", "pid", "start_identity")
    )
    assert data["windows_event"]["observed_process"]["pid"] == 42


@pytest.mark.parametrize(
    "event_epoch,executable,bind",
    [
        (100.0, "/owned/exe", True),
        (20.5, "/owned/exe", False),
        (101.0, "/owned/exe", False),
        (100.0, "/other/exe", False),
    ],
)
def test_linux_audit_join_requires_incarnation_time_and_image_not_pid_alone(
    collector, event_epoch, executable, bind
):
    collector.boot_time, collector.clock_ticks = 0, 100
    collector._audit_observed_at = 100
    collector._audit_rows = {
        42: {
            "pid": 42,
            "ppid": 1,
            "start": 2000,
            "name": "owned",
            "executable": "/owned/exe",
        }
    }
    lines = []
    for serial in (1, 2):
        lines += [
            f'type=SYSCALL msg=audit({event_epoch}:{serial}): arch=c000003e syscall=257 success=yes pid=42 exe="{executable}" comm="owned"\n',
            f"type=EOE msg=audit({event_epoch}:{serial}):\n",
        ]
    collector.audit_log_path.write_text("".join(lines))
    events = collector._audit_events("HOST")
    identities = {item["data"]["process"]["guid"] for item in events}
    assert len(identities) == (1 if bind else 2)
    for item in events:
        assert item["data"]["agent"]["process_response_eligible"] is False
        assert "start_identity" not in item["data"]["process"]
        assert item["data"]["audit"]["process_identity"] == (
            "temporally_verified_live_incarnation" if bind else "audit-record-only"
        )


def test_startup_process_inventory_is_not_fabricated_creation(collector, monkeypatch):
    collector.boot_time, collector.clock_ticks, collector.emit_initial = 0, 100, False
    collector.emit_startup_inventory, collector.snapshot_epoch = True, "fixture-start"
    row = {
        "pid": 42,
        "ppid": 1,
        "start": 2000,
        "name": "owned",
        "command_line": "owned",
    }
    monkeypatch.setattr(collector, "_rows", lambda: [row])
    monkeypatch.setattr(collector, "_tcp_rows", lambda *_: [])
    monkeypatch.setattr(collector, "_journal_events", lambda *_: [])
    monkeypatch.setattr(collector, "_audit_events", lambda *_: [])
    first = collector.collect("HOST")
    assert first[0]["data"]["event"]["action"] == "process_observed"
    assert first[0]["data"]["event"]["module"] == "inventory"
    assert first[0]["data"]["agent"]["observed_process_start_time"].startswith("1970-")
    assert collector.collect("HOST") == []


def test_windows_startup_inventory_uses_observation_time(sensor, monkeypatch):
    sensor.emit_initial, sensor.emit_startup_inventory, sensor.snapshot_epoch = (
        False,
        True,
        "fixture-start",
    )
    row = {
        "pid": 42,
        "ppid": 1,
        "birth": 116444736000000000,
        "name": "owned.exe",
        "executable": r"C:\owned.exe",
    }
    monkeypatch.setattr(windows, "_process_rows", lambda: [row])
    first = sensor._process_events("HOST")
    assert first[0]["data"]["event"]["action"] == "process_observed"
    assert first[0]["data"]["agent"]["observed_process_start_time"].startswith("1970-")
    assert sensor._process_events("HOST") == []


def test_audit_command_line_truncation_is_explicit_with_original_hash(collector):
    argument = "x" * 10000
    collector.audit_log_path.write_text(
        f'type=SYSCALL msg=audit(100:1): arch=c000003e syscall=59 success=yes pid=42 exe="/owned/exe"\ntype=EXECVE msg=audit(100:1): argc=1 a0="{argument}"\ntype=EOE msg=audit(100:1):\n'
    )
    item = collector._audit_events("HOST")[0]["data"]
    assert len(item["process"]["command_line"]) == 8192
    assert item["agent"]["command_line_truncated"] is True
    assert item["agent"]["command_line_original_length"] == len(argument)
    assert (
        item["agent"]["command_line_sha256"]
        == hashlib.sha256(argument.encode()).hexdigest()
    )
