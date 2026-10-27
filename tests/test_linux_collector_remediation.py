"""Linux source fixtures only; never invokes native collectors or journalctl."""

import os
import time

import pytest

from sapientia.endpoint_agent.Agent.Linux import collector as module


@pytest.fixture
def collector(tmp_path):
    item = module.LinuxCollector.__new__(module.LinuxCollector)
    item.audit_log_path = tmp_path / "audit.log"
    item.audit_log_path.write_bytes(b"")
    item.audit_offset = 0
    item.audit_inode = None
    item.audit_generation = "initial"
    item.boot_id = "fixture-boot"
    item.hostname = "fixture-host"
    item.provider_status = {}
    item.seen, item.initialized, item.last_rows, item.sockets = set(), False, {}, set()
    item.journal_cursor, item.journal_path, item.audit_state_path = None, None, None
    return item


def records(serial, arch="c000003e", syscall="59", eoe=True):
    prefix = f"msg=audit(1700000000.123:{serial})"
    text = f'type=SYSCALL {prefix}: arch={arch} syscall={syscall} pid=123 comm="test" exe="/bin/test"\n'
    if eoe:
        text += f"type=EOE {prefix}:\n"
    return text.encode()


def test_every_serial_delivered_across_pages(collector):
    collector.audit_log_path.write_bytes(b"".join(records(i) for i in range(900)))
    delivered = []
    for _ in range(4):
        delivered.extend(collector._audit_events("host", limit=300))
    assert len(delivered) == 900
    assert len({event["id"] for event in delivered}) == 900
    assert collector.audit_offset == collector.audit_log_path.stat().st_size


def test_partial_serial_and_partial_line_replayed(collector):
    first = records(1, eoe=False)
    collector.audit_log_path.write_bytes(
        first + b"type=EOE msg=audit(1700000000.123:1)"
    )
    assert collector._audit_events("host") == []
    assert collector.audit_offset == 0
    with collector.audit_log_path.open("ab") as stream:
        stream.write(b":\n")
    assert len(collector._audit_events("host")) == 1


def test_boundary_without_eoe_is_not_lost(collector):
    collector.audit_log_path.write_bytes(records(1, eoe=False) + records(2))
    os.utime(collector.audit_log_path, (time.time() - 3, time.time() - 3))
    first = collector._audit_events("host", limit=1)
    second = collector._audit_events("host", limit=1)
    assert len(first) == len(second) == 1
    assert first[0]["id"] != second[0]["id"]


def test_interleaved_serials_preserve_late_exec_and_path(collector):
    first = records(1, eoe=False)
    second = records(2, eoe=False)
    collector.audit_log_path.write_bytes(
        first
        + second
        + b'type=EXECVE msg=audit(1700000000.123:1): argc=1 a0="late-exec"\n'
        + b"type=EOE msg=audit(1700000000.123:1):\n"
        + b"type=EOE msg=audit(1700000000.123:2):\n"
    )
    events = collector._audit_events("host")
    assert len(events) == 2
    assert events[0]["data"]["process"]["command_line"] == "late-exec"
    assert collector.audit_offset == collector.audit_log_path.stat().st_size


def test_copytruncate_regrown_source_resets_anchor(collector):
    collector.audit_log_path.write_bytes(records(1))
    old = collector._audit_events("host")[0]
    collector.audit_log_path.write_bytes(records(2) + records(3))
    events = collector._audit_events("host")
    assert len(events) == 2
    assert all(row["id"] != old["id"] for row in events)


def test_audit_timestamp_and_hex_arguments_preserve_source_order(collector):
    collector.audit_log_path.write_bytes(
        records(1, eoe=False)
        + b'type=EXECVE msg=audit(1700000000.123:1): argc=3 a10="ten" a2=74776f a1="one"\n'
        + b"type=EOE msg=audit(1700000000.123:1):\n"
    )
    data = collector._audit_events("host")[0]["data"]
    assert data["process"]["command_line"] == "one two ten"
    assert ".123" in data["@timestamp"]


def test_checkpoint_rollback_restart_replays_only_durable_missing_page(
    collector, tmp_path
):
    collector.audit_state_path = tmp_path / "audit-cursor.json"
    collector.audit_log_path.write_bytes(records(1) + records(2))
    collector.begin_cycle()
    first = collector._audit_events("host", limit=1)
    collector.rollback()
    again = collector._audit_events("host", limit=1)
    assert first[0]["id"] == again[0]["id"]
    collector.checkpoint()
    saved = __import__("json").loads(collector.audit_state_path.read_text())
    assert saved["offset"] == collector.audit_offset and saved["anchor"]
    assert len(collector._audit_events("host")) == 1


def test_rotation_drains_unread_old_file(collector):
    collector.audit_log_path.write_bytes(records(1) + records(2))
    first = collector._audit_events("host", limit=1)
    collector.audit_log_path.rename(collector.audit_log_path.with_suffix(".log.1"))
    collector.audit_log_path.write_bytes(records(3))
    second = collector._audit_events("host", limit=1)
    third = collector._audit_events("host", limit=1)
    assert len({item[0]["id"] for item in (first, second, third)}) == 3


@pytest.mark.parametrize(
    "arch,syscall,action",
    [
        ("c000003e", "59", "process_created"),
        ("c00000b7", "221", "process_created"),
        ("40000003", "11", "process_created"),
        ("c00000b7", "35", "file_deleted"),
        ("unknown", "59", None),
        ("c00000b7", "59", None),
    ],
)
def test_syscalls_use_record_architecture(collector, arch, syscall, action):
    collector.audit_log_path.write_bytes(records(1, arch, syscall))
    events = collector._audit_events("host")
    if action is None:
        assert events[0]["data"]["event"]["action"] == "audit_syscall_unclassified"
    else:
        assert events[0]["data"]["event"]["action"] == action
        assert events[0]["data"]["audit"]["arch"] == arch


def test_journal_deadline_terminates_without_readline(collector, monkeypatch):
    class Pipe:
        def fileno(self):
            return 123

        def close(self):
            pass

    class Process:
        stdout = Pipe()
        returncode = None
        terminated = False

        def poll(self):
            return self.returncode

        def terminate(self):
            self.terminated = True

        def wait(self, timeout):
            self.returncode = -15

    class Selector:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def register(self, *args):
            pass

        def select(self, timeout):
            return []

    process = Process()
    monkeypatch.setattr(module.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(module.selectors, "DefaultSelector", Selector)
    monkeypatch.setattr(module.os, "set_blocking", lambda *args: None)
    times = iter([0, 0, 6])
    monkeypatch.setattr(module.time, "monotonic", lambda: next(times))
    assert collector._journal_output(["fixture"], 300) == []
    assert process.terminated
    assert collector.provider_health()["journald"]["status"] == "degraded"
