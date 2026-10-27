"""Permission decisions and failure bounds; native Linux runs are separate evidence."""

import copy
import hashlib
import json
import os
import queue
import struct
import threading
import time
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sapientia.endpoint_agent.Agent import kernel_prevention as module
from sapientia.endpoint_agent.Agent import response
from sapientia.endpoint_agent.Agent.defense import SCHEMA, Defense, canonical
from sapientia.xdr_bridge import parse_event

NOW = 1800000000
EXECUTABLE = "/opt/fixture-watched/owned-payload"
DIGEST = hashlib.sha256(b"qualification-owned-payload").hexdigest()


@pytest.fixture
def signed(tmp_path):
    key = Ed25519PrivateKey.generate()
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    config = {
        "host": "fixture-linux",
        "tenant": "default",
        "agent_id": "fixture-agent",
        "index": "endpoint",
        "state_dir": str(state),
        "defense": {
            "enabled": False,
            "public_key": key.public_key().public_bytes_raw().hex(),
            "bundle_file": str(tmp_path / "signed.json"),
        },
        "kernel_prevention": {
            "enabled": True,
            "directories": ["/opt/fixture-watched"],
            "rule_ids": ["deny-owned-hash"],
            "decision_timeout_ms": 100,
        },
    }
    doc = {
        "schema": SCHEMA,
        **{field: config[field] for field in ("tenant", "host", "agent_id", "index")},
        "revision": 1,
        "issued_at": NOW - 60,
        "expires_at": NOW + 3600,
        "rules": [
            {
                "id": "deny-owned-hash",
                "enabled": True,
                "action": "terminate_process",
                "severity": "critical",
                "conditions": [
                    {
                        "field": "file.hash.sha256",
                        "op": "eq",
                        "value": DIGEST,
                        "ignore_case": False,
                    },
                    {
                        "field": "process.executable",
                        "op": "eq",
                        "value": EXECUTABLE,
                        "ignore_case": False,
                    },
                ],
                "mitre": ["T1204.002"],
            }
        ],
    }

    def write(document=None):
        document = doc if document is None else document
        path = Path(config["defense"]["bundle_file"])
        path.write_text(
            json.dumps(
                {"document": document, "signature": key.sign(canonical(document)).hex()}
            ),
            encoding="utf-8",
        )
        if os.name != "nt":
            path.chmod(0o600)

    write()
    return config, doc, key, write


class FakeBackend:
    """Never qualifies as kernel support: only the native tests may make that claim."""

    native = False

    def __init__(self):
        self.events = queue.Queue()
        self.answers = []
        self.closed = False

    def open(self, directories, _response):
        self.directories = directories

    def read(self, timeout):
        try:
            item = self.events.get(timeout=timeout)
        except queue.Empty:
            return []
        if isinstance(item, Exception):
            raise item
        return [item]

    def respond(self, fd, allow):
        self.answers.append((fd, allow, time.monotonic()))

    def close(self):
        self.closed = True


def wait_for(predicate, seconds=3):
    deadline = time.monotonic() + seconds
    while not predicate() and time.monotonic() < deadline:
        time.sleep(0.005)
    assert predicate()


def guard_for(signed, monkeypatch, hasher=None):
    config, _doc, _key, _write = signed
    backend = FakeBackend()
    monkeypatch.setattr(
        module,
        "hash_open_executable",
        hasher or (lambda *_args: (EXECUTABLE, DIGEST, (10, 20))),
    )
    monkeypatch.setattr(
        module,
        "process_identity",
        lambda pid, _host: {
            "pid": pid,
            "guid": f"native-attempt-{pid}",
            "start_identity": "linux:fixture-boot:100",
            "executable": "/usr/bin/fixture-caller",
        },
    )
    guard = module.KernelPrevention(
        config, response, backend_factory=lambda: backend, clock=lambda: NOW
    )
    guard.start()
    return guard, backend


def emit(backend, tmp_path, pid=400):
    path = tmp_path / ("owned-executable-" + str(pid))
    path.write_bytes(b"qualification-owned-payload")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    backend.events.put((module.FAN_OPEN_EXEC_PERM, fd, pid))
    return fd


def test_signed_hash_denial_is_permission_reply_and_valid_telemetry(
    signed, monkeypatch, tmp_path
):
    guard, backend = guard_for(signed, monkeypatch)
    try:
        fd = emit(backend, tmp_path)
        wait_for(lambda: len(backend.answers) == 1)
        assert backend.answers[0][0:2] == (fd, False)
        event = guard.drain_events()[0]
        assert event["data"]["event"]["action"] == "execution_denied"
        assert event["data"]["kernel_prevention"]["phase"] == "before_executable_open"
        assert event["data"]["kernel_prevention"]["reason"] == "signed_hash_match"
        assert event["data"]["kernel_prevention"]["kernel_response_confirmed"] is True
        assert "process" not in event["data"]
        assert event["data"]["kernel_prevention"]["target_image_created"] is False
        assert event["data"]["kernel_prevention"]["initiator"]["pid"] == 400
        parse_event(event, "agent", "endpoint", expected_host="fixture-linux")
        assert (
            guard.health()["kernel_permission_denial"] is False
        )  # Mocks cannot certify the kernel.
        assert guard.health()["reactive_user_mode"] is False
    finally:
        guard.close()
    assert backend.closed
    assert guard.status()["enabled"] is True and guard.status()["state"] == "stopped"
    assert guard.status()["kernel_permission_denial"] is False
    with pytest.raises(OSError):
        os.fstat(fd)


def test_unknown_benign_hash_is_allowed(signed, monkeypatch, tmp_path):
    guard, backend = guard_for(
        signed, monkeypatch, lambda *_args: (EXECUTABLE, "0" * 64, (10, 20))
    )
    try:
        emit(backend, tmp_path)
        wait_for(lambda: len(backend.answers) == 1)
        assert backend.answers[0][1] is True
        assert (
            guard.drain_events()[0]["data"]["kernel_prevention"]["reason"]
            == "no_signed_hash_match"
        )
    finally:
        guard.close()


@pytest.mark.parametrize(
    "field,value",
    [
        ("event.module", "security"),
        ("event.provider", "forged.provider"),
        ("event.action", "process_created"),
        ("agent.collector", "procfs"),
        ("agent.process_identity_kind", "native_process"),
    ],
)
def test_no_identity_exception_for_wrong_permission_observation_marker(
    signed, monkeypatch, tmp_path, field, value
):
    guard, backend = guard_for(signed, monkeypatch)
    try:
        emit(backend, tmp_path)
        wait_for(lambda: len(backend.answers) == 1)
        event = guard.drain_events()[0]
        group, name = field.split(".")
        event["data"][group][name] = value
        with pytest.raises(ValueError, match="process.guid"):
            parse_event(event, "agent", "endpoint", expected_host="fixture-linux")
    finally:
        guard.close()


def test_gone_initiator_is_absent_instead_of_invented_native_process(
    signed, monkeypatch, tmp_path
):
    guard, backend = guard_for(signed, monkeypatch)
    monkeypatch.setattr(module, "process_identity", lambda *_args: None)
    try:
        emit(backend, tmp_path)
        wait_for(lambda: len(backend.answers) == 1)
        event = guard.drain_events()[0]
        assert "process" not in event["data"]
        assert "initiator" not in event["data"]["kernel_prevention"]
        parse_event(event, "agent", "endpoint", expected_host="fixture-linux")
    finally:
        guard.close()


def test_attempting_process_identity_matches_native_response_canonical_values(
    monkeypatch,
):
    boot, pid, ticks, host = (
        "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
        1234,
        "987654",
        "fixture-host",
    )
    columns = ["S", "1", *(["0"] * 17), ticks]

    def native_read(path, **_kwargs):
        return (
            boot
            if str(path).endswith("boot_id")
            else "1234 (a caller with ) parenthesis) " + " ".join(columns)
        )

    monkeypatch.setattr(module.Path, "read_text", native_read)
    monkeypatch.setattr(module.os, "readlink", lambda _path: "/usr/bin/actual-caller")
    identity = module.process_identity(pid, host)
    assert identity["start_identity"] == f"linux:{boot}:{ticks}"
    assert identity["guid"] == str(
        __import__("uuid").uuid5(
            __import__("uuid").NAMESPACE_OID, host + ":" + f"{boot}:{pid}:{ticks}"
        )
    )
    assert identity["pid"] == pid and identity["executable"] == "/usr/bin/actual-caller"


def test_hash_exception_denies_instead_of_running_or_hanging(
    signed, monkeypatch, tmp_path
):
    def failed(*_args):
        raise PermissionError("opened inode changed")

    guard, backend = guard_for(signed, monkeypatch, failed)
    try:
        emit(backend, tmp_path)
        wait_for(lambda: len(backend.answers) == 1)
        assert backend.answers[0][1] is False
        assert (
            guard.drain_events()[0]["data"]["kernel_prevention"]["reason"]
            == "identity_or_hash_error"
        )
    finally:
        guard.close()


def test_slow_hash_is_denied_at_deadline_and_late_allow_cannot_replay(
    signed, monkeypatch, tmp_path
):
    started, release = threading.Event(), threading.Event()

    def slow(*_args):
        started.set()
        release.wait(2)
        return EXECUTABLE, "0" * 64, (10, 20)

    guard, backend = guard_for(signed, monkeypatch, slow)
    try:
        emit(backend, tmp_path)
        assert started.wait(1)
        wait_for(lambda: len(backend.answers) == 1)
        assert backend.answers[0][1] is False
        assert guard.status()["deadline_denied"] == 1
        release.set()
        time.sleep(0.1)
        assert len(backend.answers) == 1
    finally:
        release.set()
        guard.close()


def test_policy_changed_during_hash_cannot_allow_old_policy(
    signed, monkeypatch, tmp_path
):
    started, release = threading.Event(), threading.Event()

    def slow(*_args):
        started.set()
        release.wait(2)
        return EXECUTABLE, "0" * 64, (10, 20)

    guard, backend = guard_for(signed, monkeypatch, slow)
    try:
        emit(backend, tmp_path)
        assert started.wait(1)
        with guard.lock:
            guard.snapshot = None
        release.set()
        wait_for(lambda: len(backend.answers) == 1)
        assert backend.answers[0][1] is False
        assert (
            guard.drain_events()[0]["data"]["kernel_prevention"]["reason"]
            == "policy_changed_during_decision"
        )
    finally:
        release.set()
        guard.close()


def test_expired_policy_denies_without_hash(signed, monkeypatch, tmp_path):
    calls = []
    guard, backend = guard_for(signed, monkeypatch, lambda *_args: calls.append(1))
    try:
        with guard.lock:
            guard.snapshot = {**guard.snapshot, "expires_at": NOW - 1}
        emit(backend, tmp_path)
        wait_for(lambda: len(backend.answers) == 1)
        assert backend.answers[0][1] is False and calls == []
        assert (
            guard.drain_events()[0]["data"]["kernel_prevention"]["reason"]
            == "policy_invalid_or_expired"
        )
    finally:
        guard.close()


def test_bounded_overload_denies_and_audit_overflow_is_visible(
    signed, monkeypatch, tmp_path
):
    release = threading.Event()

    def slow(*_args):
        release.wait(2)
        return EXECUTABLE, DIGEST, (10, 20)

    signed[0]["kernel_prevention"]["decision_timeout_ms"] = 2000
    guard, backend = guard_for(signed, monkeypatch, slow)
    try:
        for pid in range(400, 400 + module.MAX_PENDING + 5):
            emit(backend, tmp_path, pid)
        wait_for(lambda: guard.status()["overload_denied"] >= 5)
        assert len(guard.pending) <= module.MAX_PENDING
        assert guard.jobs.maxsize == module.MAX_PENDING
        assert (
            sum(t.name.startswith("lumina-kernel-hash-") for t in guard.threads)
            == module.WORKERS
        )
        assert (
            guard.status()["crash_behavior"]
            == "kernel_allows_outstanding_requests_on_listener_death"
        )
        for _ in range(module.MAX_AUDIT + 1):
            guard._record(400, False, "test", guard.snapshot)
        assert guard.status()["audit_dropped"] > 0
    finally:
        release.set()
        guard.close()


def test_kernel_overflow_and_listener_failure_never_claim_full_coverage(
    signed, monkeypatch
):
    guard, backend = guard_for(signed, monkeypatch)
    try:
        backend.events.put((module.FAN_Q_OVERFLOW, -1, 0))
        wait_for(lambda: guard.status()["queue_overflow"] == 1)
        assert guard.status()["state"] == "degraded"
        backend.events.put(OSError("listener broke"))
        wait_for(lambda: not guard.running)
        assert backend.closed and guard.status()["state"] == "degraded"
        assert guard.status()["kernel_permission_denial"] is False
    finally:
        guard.close()


def test_disabled_does_not_call_any_native_api(tmp_path):
    guard = module.KernelPrevention(
        {"state_dir": str(tmp_path)},
        response,
        backend_factory=lambda: pytest.fail("native init while disabled"),
    )
    assert guard.start() is False
    assert guard.status()["state"] == "disabled"
    assert guard.status()["enabled"] is False
    guard.close()


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/usr/bin",
        "/proc/owned",
        "relative",
        "/opt/a/../b",
        "/opt/a//b",
        "/opt/owned/",
        "/etc/owned",
    ],
)
def test_unsafe_directory_settings_rejected(path):
    with pytest.raises(ValueError):
        module.validate_settings(
            {"enabled": True, "directories": [path], "rule_ids": ["r"]}
        )


@pytest.mark.parametrize("value", [None, [], [[]], [1], ["/opt/owned", "/opt/owned"]])
def test_malformed_directory_lists_rejected(value):
    with pytest.raises(ValueError):
        module.validate_settings(
            {"enabled": True, "directories": value, "rule_ids": ["r"]}
        )


@pytest.mark.parametrize("timeout", [True, 0, 49, 2001, "100"])
def test_timeout_type_and_bounds(timeout):
    with pytest.raises(ValueError):
        module.validate_settings(
            {
                "enabled": True,
                "directories": ["/opt/owned"],
                "rule_ids": ["r"],
                "decision_timeout_ms": timeout,
            }
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "disabled",
        "observe",
        "exceptions",
        "contains",
        "ignore_case",
        "extra_condition",
        "outside_scope",
        "missing_rule",
    ],
)
def test_no_implicit_or_approximate_rule_promotion(signed, mutation):
    config, doc, _key, _write = signed
    candidate = copy.deepcopy(doc)
    rule = candidate["rules"][0]
    if mutation == "disabled":
        rule["enabled"] = False
    elif mutation == "observe":
        rule["action"] = "observe"
    elif mutation == "exceptions":
        rule["exceptions"] = [copy.deepcopy(rule["conditions"])]
    elif mutation == "contains":
        rule["conditions"][1]["op"] = "contains"
    elif mutation == "ignore_case":
        rule["conditions"][1].pop("ignore_case")
    elif mutation == "extra_condition":
        rule["conditions"].append({"field": "process.name", "op": "eq", "value": "x"})
    elif mutation == "outside_scope":
        rule["conditions"][1]["value"] = "/usr/bin/owned"
    else:
        candidate["rules"] = []
    with pytest.raises(ValueError):
        module.project_rules(
            candidate,
            config["kernel_prevention"]["directories"],
            frozenset(config["kernel_prevention"]["rule_ids"]),
        )


def projection(signed):
    config, _doc, _key, _write = signed
    directories, ids, _timeout, _maximum = module.validate_settings(
        config["kernel_prevention"]
    )
    return module.SignedProjection(
        config, directories, ids, response, clock=lambda: NOW
    )


def test_signed_projection_antirollback_survives_new_instance(signed):
    _config, doc, _key, write = signed
    doc["revision"] = 2
    write()
    assert projection(signed).load()["revision"] == 2
    doc["revision"] = 1
    write()
    with pytest.raises(ValueError, match="rollback"):
        projection(signed).load()
    doc["revision"] = 2
    doc["rules"][0]["severity"] = "high"
    write()
    with pytest.raises(ValueError, match="same-revision"):
        projection(signed).load()


def signed_bundle(signed):
    return json.loads(
        Path(signed[0]["defense"]["bundle_file"]).read_text(encoding="utf-8")
    )


def test_kernel_only_policy_cache_never_enables_reactive_ledger_or_effects(signed):
    config, _doc, _key, _write = signed
    bundle = signed_bundle(signed)
    Path(config["defense"]["bundle_file"]).unlink()
    d = Defense(config, response, clock=lambda: NOW)
    assert d.health()["state"] == "disabled"
    assert d.update(bundle, cache_only=True) is True
    assert d.settings["enabled"] is False and d.db is None and d.policy is None
    assert d.evaluate([]) == []
    assert not (Path(config["state_dir"]) / "defense.sqlite3").exists()
    assert (Path(config["state_dir"]) / "kernel-policy.sqlite3").is_file()
    assert projection(signed).load()["revision"] == 1
    d.close()


def test_kernel_cache_antirollback_and_same_revision_conflict_survive_disabled_restart(
    signed,
):
    config, doc, _key, write = signed
    doc["revision"] = 2
    write()
    latest = signed_bundle(signed)
    d = Defense(config, response, clock=lambda: NOW)
    d.update(latest, cache_only=True)
    d.close()
    doc["revision"] = 1
    write()
    older = signed_bundle(signed)
    Path(config["defense"]["bundle_file"]).write_text(
        json.dumps(latest), encoding="utf-8"
    )
    d = Defense(config, response, clock=lambda: NOW)
    with pytest.raises(ValueError, match="rollback"):
        d.update(older, cache_only=True)
    doc["revision"] = 2
    doc["rules"][0]["severity"] = "high"
    write()
    conflict = signed_bundle(signed)
    with pytest.raises(ValueError, match="same-revision"):
        d.update(conflict, cache_only=True)
    assert d.db is None and d.policy is None
    d.close()


def test_kernel_cache_requires_explicit_local_optin_and_valid_pinned_signature(signed):
    config, _doc, _key, _write = signed
    bundle = signed_bundle(signed)
    config["kernel_prevention"]["enabled"] = False
    d = Defense(config, response, clock=lambda: NOW)
    assert d.update(bundle) is False
    with pytest.raises(PermissionError, match="opt-in"):
        d.update(bundle, cache_only=True)
    config["kernel_prevention"]["enabled"] = True
    d.settings["public_key"] = "0" * 64
    with pytest.raises(InvalidSignature):
        d.update(bundle, cache_only=True)
    d.settings["public_key"] = None
    with pytest.raises(ValueError, match="Pinned"):
        d.update(bundle, cache_only=True)
    assert not (Path(config["state_dir"]) / "kernel-policy.sqlite3").exists()
    d.close()


def test_kernel_cache_reads_previous_reactive_highwater_without_mutating_effect_ledger(
    signed,
):
    config, doc, _key, write = signed
    config["defense"]["enabled"] = True
    doc["revision"] = 2
    write()
    active = Defense(config, response, clock=lambda: NOW)
    assert active.policy["revision"] == 2
    active.close()
    reactive = Path(config["state_dir"]) / "defense.sqlite3"
    original = hashlib.sha256(reactive.read_bytes()).hexdigest()
    config["defense"]["enabled"] = False
    doc["revision"] = 1
    write()
    inactive = Defense(config, response, clock=lambda: NOW)
    with pytest.raises(ValueError, match="rollback"):
        inactive.update(signed_bundle(signed), cache_only=True)
    assert hashlib.sha256(reactive.read_bytes()).hexdigest() == original
    assert inactive.db is None and inactive.policy is None
    inactive.close()
    doc["revision"] = 2
    doc["rules"][0]["severity"] = "high"
    write()
    with pytest.raises(ValueError, match="same-revision"):
        inactive.update(signed_bundle(signed), cache_only=True)


@pytest.mark.parametrize("binding", ["host", "tenant", "agent_id", "index"])
def test_signed_projection_binding_rejected(signed, binding):
    _config, doc, _key, write = signed
    doc[binding] = "another"
    write()
    with pytest.raises(ValueError, match="binding"):
        projection(signed).load()


def test_bad_signature_duplicate_json_and_expiry_rejected(signed):
    config, doc, _key, write = signed
    path = Path(config["defense"]["bundle_file"])
    bundle = json.loads(path.read_text(encoding="utf-8"))
    bundle["signature"] = "0" * 128
    path.write_text(json.dumps(bundle), encoding="utf-8")
    with pytest.raises(InvalidSignature):
        projection(signed).load()
    write()
    text = path.read_text(encoding="utf-8")
    path.write_text(
        text.replace('"document":', '"document": {}, "document":', 1), encoding="utf-8"
    )
    with pytest.raises(ValueError, match="Duplicate"):
        projection(signed).load()
    doc["expires_at"] = NOW - 1
    write()
    with pytest.raises(ValueError, match="expired"):
        projection(signed).load()


def test_same_mtime_atomic_bundle_replace_reverifies_new_policy(signed):
    config, doc, key, _write = signed
    first = projection(signed).load()
    path = Path(config["defense"]["bundle_file"])
    old_time = path.stat().st_mtime_ns
    doc["revision"] = 2
    body = json.dumps({"document": doc, "signature": key.sign(canonical(doc)).hex()})
    temp = path.with_suffix(".replacement")
    temp.write_text(body, encoding="utf-8")
    os.utime(temp, ns=(old_time, old_time))
    os.replace(temp, path)
    latest = projection(signed).load()
    assert latest["revision"] == 2 and latest["digest"] != first["digest"]


def metadata(mask=module.FAN_OPEN_EXEC_PERM, fd=100, version=3, length=24):
    return module.METADATA.pack(length, version, 0, 24, mask, fd, 400)


def test_metadata_abi_multiple_and_extended_records():
    assert module.METADATA.size == 24 and module.RESPONSE.size == 8
    assert module.parse_metadata(metadata() + metadata(module.FAN_Q_OVERFLOW, -1)) == [
        (module.FAN_OPEN_EXEC_PERM, 100, 400),
        (module.FAN_Q_OVERFLOW, -1, 400),
    ]
    assert module.parse_metadata(metadata(length=28) + b"abcd") == [
        (module.FAN_OPEN_EXEC_PERM, 100, 400)
    ]


@pytest.mark.parametrize(
    "blob",
    [
        b"short",
        metadata(version=2),
        metadata(length=23),
        metadata(length=100),
        struct.pack("=I", 0) + metadata()[4:],
    ],
)
def test_metadata_bad_abi_never_unbounded_walk(blob):
    with pytest.raises(ValueError):
        module.parse_metadata(blob)


def test_native_backend_rejects_non_linux_without_touching_policy(monkeypatch):
    monkeypatch.setattr(module.platform, "system", lambda: "Windows")
    with pytest.raises(OSError, match="requires Linux"):
        module.FanotifyBackend()


def test_native_backend_rejects_kernel_without_execution_permission_api(monkeypatch):
    monkeypatch.setattr(module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(module.platform, "release", lambda: "4.19.0")
    with pytest.raises(OSError, match="5.0"):
        module.FanotifyBackend()


def test_live_hash_checks_kernel_fd_and_size_deadline_change(tmp_path, monkeypatch):
    path = tmp_path / "ordinary"
    path.write_bytes(b"native-open-fd")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    # Real opened bytes/inode; only Linux path syscalls are adapted on Windows.
    virtual_path = "/opt/fixture-owned-executable"
    native_stat = os.stat
    monkeypatch.setattr(module.os, "readlink", lambda _name: virtual_path)
    monkeypatch.setattr(
        module.os,
        "stat",
        lambda name, *args, **kwargs: native_stat(
            path if name == virtual_path else name, *args, **kwargs
        ),
    )
    monkeypatch.setattr(
        module.os,
        "pread",
        lambda target, count, offset: (
            os.lseek(target, offset, os.SEEK_SET),
            os.read(target, count),
        )[1],
        raising=False,
    )
    try:
        filename, digest, identity = module.hash_open_executable(
            fd, 1024, time.monotonic() + 1
        )
        assert (
            filename == virtual_path
            and digest == hashlib.sha256(path.read_bytes()).hexdigest()
        )
        assert identity == (path.stat().st_dev, path.stat().st_ino)
        with pytest.raises(PermissionError, match="size bound"):
            module.hash_open_executable(fd, 1, time.monotonic() + 1)
        with pytest.raises(TimeoutError):
            module.hash_open_executable(fd, 1024, time.monotonic() - 1)
        monkeypatch.setattr(
            module.os, "readlink", lambda _name: virtual_path + " (deleted)"
        )
        with pytest.raises(PermissionError, match="path identity"):
            module.hash_open_executable(fd, 1024, time.monotonic() + 1)
    finally:
        os.close(fd)
