"""Read-only memory metadata contracts; injected inspection/query, no host reads."""

import ctypes
from types import SimpleNamespace

import pytest

from sapientia.endpoint_agent.Agent import memory_observability as module
from sapientia.endpoint_agent.Agent.defense import Defense
from sapientia.xdr_bridge import parse_event


def identity(pid, _host):
    return {
        "pid": pid,
        "guid": "native-process-guid",
        "start_identity": "windows:12345",
        "executable": "/owned/fixture.exe",
    }


def reader(_pid, _deadline, _limit):
    return (
        [
            {
                "address": "0x10000",
                "size": 4096,
                "permissions": "rwx",
                "kind": "anonymous",
            }
        ],
        2,
        True,
    )


def test_default_disabled_has_no_process_or_memory_access():
    def forbidden(*_args):
        raise AssertionError("Native inspection was not authorized")

    provider = module.MemoryObservability({}, forbidden, reader=forbidden)
    assert provider.collect("HOST", [{"pid": 42}]) == []
    assert provider.status()["state"] == "disabled"
    assert provider.status()["memory_bytes_read"] is False


@pytest.mark.parametrize(
    "settings",
    [
        {"enabled": "true"},
        {"enabled": True, "max_processes": 65},
        {"enabled": True, "max_regions": 1025},
        {"enabled": True, "budget_ms": True},
        {"enabled": True, "budget_ms": 2001},
        {"enabled": True, "read_memory": True},
    ],
)
def test_nonexplicit_or_unbounded_policy_is_rejected(settings):
    with pytest.raises(ValueError):
        module.MemoryObservability(
            {"memory_observability": settings}, identity, reader=reader
        )


def test_verified_layout_is_unknown_low_confidence_and_never_effect_authorizing():
    provider = module.MemoryObservability(
        {"memory_observability": {"enabled": True}}, identity, reader=reader
    )
    event = provider.collect("HOST", [{"pid": 42}])[0]
    data = parse_event(event, "agent", "endpoint", expected_host="HOST")["raw"]["xdr"][
        "data"
    ]
    assert data["memory"]["rwx_region_count"] == 1
    assert data["memory"]["anonymous_executable_region_count"] == 1
    assert data["memory"]["malicious_verdict"] == "unknown"
    assert data["memory"]["confidence"] == "low"
    assert data["memory"]["read_process_memory"] is False
    assert data["agent"]["process_response_eligible"] is False
    assert not any(data["process"].get(key) for key in ("pid", "start_identity"))
    with pytest.raises(ValueError, match="identity"):
        Defense._target(None, data, "terminate_process")
    assert provider.collect("HOST", [{"pid": 42}]) == []


@pytest.mark.parametrize("changed", ["guid", "start_identity", "executable", "pid"])
def test_identity_change_between_map_reads_discards_observation(changed):
    calls = []

    def inspect(pid, host):
        result = identity(pid, host)
        if calls:
            result[changed] = "changed" if changed != "pid" else 43
        calls.append(True)
        return result

    provider = module.MemoryObservability(
        {"memory_observability": {"enabled": True}}, inspect, reader=reader
    )
    assert provider.collect("HOST", [{"pid": 42}]) == []
    assert provider.status()["identity_changed"] == 1


def test_access_denied_and_sampling_gap_are_visible_without_bypassing_protection():
    def denied(*_args):
        raise PermissionError("fixture PPL")

    provider = module.MemoryObservability(
        {"memory_observability": {"enabled": True, "max_processes": 1}},
        identity,
        reader=denied,
    )
    assert provider.collect("HOST", [{"pid": 42}, {"pid": 43}]) == []
    assert provider.status()["state"] == "degraded"
    assert provider.status()["inaccessible_or_invalid"] == 1
    assert provider.status()["sampling_truncated"] is True


def test_checkpoint_rollback_replays_same_observation_identity_and_timestamp():
    provider = module.MemoryObservability(
        {"memory_observability": {"enabled": True}}, identity, reader=reader
    )
    provider.begin_cycle()
    first = provider.collect("HOST", [{"pid": 42}])[0]
    provider.rollback()
    provider.begin_cycle()
    second = provider.collect("HOST", [{"pid": 42}])[0]
    assert first == second


def test_native_proc_maps_parser_distinguishes_jit_and_kernel_mapping_without_payload_reads(
    tmp_path, monkeypatch
):
    maps = tmp_path / "maps"
    maps.write_text(
        "1000-2000 rwxp 00000000 00:00 0\n2000-3000 r-xp 00000000 00:00 0 /memfd:owned (deleted)\n3000-4000 r-xp 00000000 00:00 0 [vdso]\n4000-5000 r-xp 00000000 00:00 1 /owned/lib.so\n"
    )
    monkeypatch.setattr(module, "Path", lambda _value: maps)
    regions, scanned, complete = module.linux_regions(42, 10**12, 512)
    assert scanned == 4 and complete
    assert len(regions) == 2
    assert [r["kind"] for r in regions] == ["anonymous", "anonymous"]
    limited, _scanned, complete = module.linux_regions(42, 10**12, 1)
    assert len(limited) == 1 and complete is False


def test_native_virtual_query_adapter_only_requests_query_rights_and_closes_handle(
    monkeypatch,
):
    calls = []

    def opened(access, _inherit, pid):
        calls.append(("open", access, pid))
        return 99

    def query(_handle, address, pointer, size):
        calls.append(("query",))
        info = ctypes.cast(
            pointer, ctypes.POINTER(module.MemoryBasicInformation)
        ).contents
        info.BaseAddress, info.RegionSize, info.State, info.Protect, info.Type = (
            int(address.value or 0),
            4096,
            0x1000,
            0x40,
            0x20000,
        )
        return size

    def closed(handle):
        calls.append(("close", handle))

    def architecture(_handle, process, native):
        ctypes.cast(process, ctypes.POINTER(module.wintypes.WORD)).contents.value = 0
        ctypes.cast(
            native, ctypes.POINTER(module.wintypes.WORD)
        ).contents.value = 0x8664
        return 1

    fake = SimpleNamespace(
        OpenProcess=opened,
        VirtualQueryEx=query,
        CloseHandle=closed,
        IsWow64Process2=architecture,
    )
    monkeypatch.setattr(module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(module.ctypes, "WinDLL", lambda *_a, **_k: fake)
    regions, scanned, complete = module.windows_regions(42, 10**12, 1)
    assert regions[0]["permissions"] == "rwx" and scanned == 1
    assert complete is False
    assert calls[0] == ("open", 0x0400, 42)
    assert calls[-1] == ("close", 99)
    assert not hasattr(fake, "ReadProcessMemory") and not hasattr(
        fake, "WriteProcessMemory"
    )
