"""Bounded isolated recovery probes. No running service is stopped or mutated.

Injected exceptions and reopened temporary stores test software contracts.
They are not power-loss, clustered HA, appliance/BSP or native firewall tests.
"""

import argparse
import json
import tempfile
import time
from pathlib import Path

from sapientia import access, action_runtime, auth, backup, connector_runtime, detections, effect_receipts, source_registry
from sapientia.storage import CapacityError, ConflictError, Settings, Store
from tools.simulation.loggers import generate


def _actor(name="requester"):
    return {"name": name, "tenant": "isolated-qa", "role": "admin", "allowed_indexes": ["*"]}


def _store(path):
    return Store(Settings(path, min_free_bytes=0, simulation_mode=True))


def _response_fixture(path):
    store = _store(path)
    for name in ("requester", "reviewer"):
        auth.create_user(store, name, "Isolated-software-probe-password-2026", "admin", "isolated-qa")
    source = source_registry.save(store, _actor(), {"index": "virtual_qa", "product": "windows",
        "account": "virtual-win-01", "realm": "virtual-lab", "credential_ref": "env:SAPIENTIA_CONNECTOR_VIRTUAL", "version": 0})
    events, _ = generate("windows", 1, base_time=time.time()-10)
    connector_runtime.intake(store, _actor(), source["id"], {"version": 1, "events": events,
        "cursor": "probe-1", "checkpoint_version": 0})
    store.flush()
    original = connector_runtime.decode(events[0], {**source, "index_name": source["index"]})["event_id"]
    detections.save(store, _actor(), {"name": "Isolated probe evidence", "entity_field": "host", "window": 300,
        "steps": [{"filters": [{"field": "event_id", "op": "eq", "value": original}]}]})
    if detections.run_due(store, time.time()+1) != 1:
        store.close()
        raise AssertionError("Probe did not create its evidence-bound Case")
    case = detections.incident_list(store, _actor())[0]
    action_runtime.create_asset(store, _actor(), {"source_id": source["id"], "asset_id": source["account"], "processes": {}})
    prepared = effect_receipts.prepare(store, _actor(), case["id"], {"case_version": case["version"],
        "source_id": source["id"], "source_version": source["version"], "event_ids": [original], "request_id": "isolated-probe",
        "action": "isolate_host", "target": {"asset_id": source["account"], "asset_version": 1, "lease_seconds": 30}})
    approved = effect_receipts.transition(store, _actor("reviewer"), prepared["id"], prepared["version"], "approved", {})
    return store, source, case, original, approved


def _must_refuse(call, exception):
    try:
        call()
    except exception:
        return True
    raise AssertionError("Expected authority/recovery fence did not refuse the operation")


def _journal_restart(path):
    store = _store(path)
    try:
        events = [{"event_id": "pending-"+str(n), "event_time": time.time()-10, "message": "Synthetic pending journal"} for n in range(12)]
        store.ingest("isolated-qa", events)
        store.close()
        store = _store(path)
        assert store.flush() == 12
        assert store.ingest("isolated-qa", events)["duplicate"] == 12
        assert store.search("isolated-qa", {"query": "* | stats count"})["rows"][0]["count"] == 12
        return {"durable_originals": 12, "duplicate_replay": 12, "lost_originals": 0}
    finally:
        store.close()


def _commit_seam(path):
    store = _store(path)
    try:
        store.ingest("isolated-qa", [{"event_id": "commit-seam", "message": "Injected exception, no process kill"}])
        def interruption():
            raise RuntimeError("Synthetic commit-seam interruption")
        _must_refuse(lambda: store.flush(after_commit=interruption), RuntimeError)
        store.close()
        store = _store(path)
        store.flush()
        assert store.health("isolated-qa")["pending"] == 0
        assert store.health("isolated-qa")["indexed"] == 1
        return {"interruption": "injected_exception_after_analytics_commit", "recovered_unique_originals": 1}
    finally:
        store.close()


def _capacity_recovery(path):
    store = _store(path)
    try:
        store.settings.max_queue = 1
        store.settings.max_tenant_queue = 1
        first, second = {"event_id": "capacity-first"}, {"event_id": "capacity-retry"}
        store.ingest("isolated-qa", [first])
        _must_refuse(lambda: store.ingest("isolated-qa", [second]), CapacityError)
        with store.control() as db:
            assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 1
        store.flush()
        assert store.ingest("isolated-qa", [second])["accepted"] == 1
        store.flush()
        store.settings.min_free_bytes = 10**18
        _must_refuse(lambda: store.ingest("isolated-qa", [{"event_id": "reserve-denied"}]), CapacityError)
        with store.control() as db:
            assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 2
        return {"backpressure_retry_preserved": True, "disk_reserve_fail_closed": True,
                "limits_changed_only_on_temporary_probe_store": True}
    finally:
        store.close()


def _exclusive_store(path):
    store = _store(path)
    try:
        _must_refuse(lambda: _store(path), RuntimeError)
        return {"second_writer_refused": True, "cluster_failover_tested": False}
    finally:
        store.close()


def _authority_revision(path, kind):
    store, source, _case, _original, approved = _response_fixture(path)
    try:
        if kind == "principal":
            access.set_for_user(store, _actor(), "reviewer", ["unrelated"])
        else:
            source_registry.save(store, _actor(), {key: source[key] for key in
                ("index", "product", "account", "realm", "credential_ref", "version")}, source["id"])
        _must_refuse(lambda: action_runtime.dispatch(store, _actor(), approved["id"], approved["version"]), (PermissionError, ConflictError))
        assert action_runtime.asset(store, _actor(), source["id"])["state"]["effect_count"] == 0
        return {"revision_kind": kind, "approved_stale_intent_refused": True, "virtual_effects": 0}
    finally:
        store.close()


def _response_restart(path):
    store, source, _case, _original, approved = _response_fixture(path / "uncertain")
    try:
        claim = effect_receipts.transition(store, _actor(), approved["id"], approved["version"], "dispatching", {})
        store.close()
        store = _store(path / "uncertain")
        unknown = action_runtime.recover_unknown(store, _actor(), approved["id"], claim["version"])
        _must_refuse(lambda: action_runtime.dispatch(store, _actor(), approved["id"], unknown["version"]), ConflictError)
        assert action_runtime.asset(store, _actor(), source["id"])["state"]["effect_count"] == 0
    finally:
        store.close()
    store, source, _case, _original, approved = _response_fixture(path / "confirmed")
    try:
        receipt = action_runtime.dispatch(store, _actor(), approved["id"], approved["version"])
        store.close()
        store = _store(path / "confirmed")
        retry = action_runtime.dispatch(store, _actor(), approved["id"], approved["version"])
        assert retry["duplicate"] and retry["artifact_digest"] == receipt["artifact_digest"]
        assert action_runtime.asset(store, _actor(), source["id"])["state"]["effect_count"] == 1
        return {"unknown_requires_review": True, "unknown_blind_retry_refused": True,
                "confirmed_lost_reply_replay_preserved": True, "duplicate_virtual_effects": 0}
    finally:
        store.close()


def _backup_roundtrip(path):
    store, source, case, original, approved = _response_fixture(path / "source")
    try:
        receipt = action_runtime.dispatch(store, _actor(), approved["id"], approved["version"])
        store.ingest("isolated-qa", [{"event_id": "pending-at-backup", "message": "Snapshot boundary"}])
        snapshot, restored = path / "snapshot", path / "restored"
        manifest = backup.backup_online(store, snapshot)
        backup.restore(snapshot, restored)
        clone = _store(restored)
        try:
            clone.flush()
            assert clone.health("isolated-qa")["indexed"] == 2
            assert detections.incident_detail(clone, _actor(), case["id"])["id"] == case["id"]
            replay = action_runtime.dispatch(clone, _actor(), approved["id"], approved["version"])
            assert replay["duplicate"] and replay["artifact_digest"] == receipt["artifact_digest"]
            with clone.control() as db:
                assert db.execute("SELECT event_id FROM source_event_receipts WHERE event_id=?", (original,)).fetchone()
                assert db.execute("SELECT count(*) FROM effect_receipt_history WHERE id=?", (approved["id"],)).fetchone()[0] == 5
                assert db.execute("SELECT count(*) FROM sessions").fetchone()[0] == 0
        finally:
            clone.close()
        # A damaged snapshot must fail before publishing a restore destination.
        control = snapshot / "control.sqlite3"
        with control.open("ab") as damaged:
            damaged.write(b"synthetic-integrity-failure")
        _must_refuse(lambda: backup.restore(snapshot, path / "must-not-publish"), ValueError)
        assert not (path / "must-not-publish").exists()
        return {"snapshot_online": manifest["online"], "Case_and_original_receipts_preserved": True,
                "virtual_effect_and_history_preserved": True, "sessions_cleared": True,
                "tampered_backup_rejected_before_publish": True}
    finally:
        store.close()


def qualify_operational(*, isolated=False, parent=None):
    """Create only owned temporary stores; caller cannot supply a live store."""
    if isolated is not True:
        raise ValueError("Explicit isolated operational qualification is required")
    probes = [("durable_admission_restart", _journal_restart),
              ("analytics_commit_interruption_recovery", _commit_seam),
              ("backpressure_and_disk_reserve_recovery", _capacity_recovery),
              ("exclusive_writer_ownership", _exclusive_store),
              ("permission_revision_before_dispatch", lambda path: _authority_revision(path, "principal")),
              ("source_revision_before_dispatch", lambda path: _authority_revision(path, "source")),
              ("virtual_response_restart_and_lost_reply", _response_restart),
              ("online_backup_restore_and_integrity", _backup_roundtrip)]
    checks = []
    with tempfile.TemporaryDirectory(prefix="xsera-operational-probes-", dir=parent) as temporary:
        root = Path(temporary)
        for name, probe in probes:
            started = time.monotonic()
            try:
                observed = probe(root / name)
                check = {"name": name, "passed": True, "observed": observed}
            except Exception as exc:  # Preserve independent check outcomes.
                check = {"name": name, "passed": False, "error_type": type(exc).__name__, "error": str(exc)[:400]}
            check["elapsed_seconds"] = time.monotonic()-started
            checks.append(check)
    return {"schema": "xsera.operational-recovery-lab.v1", "passed": all(check["passed"] for check in checks),
        "isolated": True, "synthetic": True, "native_effect": False,
        "host_os_or_network_mutated": False, "checks": checks,
        "limits": ["Exception injection and graceful temporary-store reopening, not hard power loss",
                   "Single-host software contracts, not broad HA/failover or fleet soak qualification",
                   "No IPv6, physical device, native prevention, BSP or Yocto image qualification"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--isolated", action="store_true", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    result = qualify_operational(isolated=args.isolated)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
