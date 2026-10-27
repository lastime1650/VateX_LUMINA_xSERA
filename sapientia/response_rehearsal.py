"""Evidence-bound response digital twin. Never imports a native OS executor."""

import secrets
import stat
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from . import (
    action_runtime,
    auth,
    connector_runtime,
    detections,
    effect_receipts,
    record_governance,
    release_manifest,
    source_registry,
)
from .storage import ConflictError, Settings, Store


def _actor(name="requester"):
    return {
        "name": name,
        "tenant": "ops-twin",
        "role": "admin",
        "allowed_indexes": ["*"],
    }


def _owned_fixture_path(path, root):
    raw_root = Path(root)
    info = raw_root.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("Twin fixture root cannot be a link")
    root, path = raw_root.resolve(strict=True), Path(path).resolve()
    if (
        not root.is_dir()
        or root.parent != Path(tempfile.gettempdir()).resolve()
        or not root.name.startswith("xsera-response-twin-")
        or any(root.iterdir())
        or path != root / "store"
        or path.exists()
    ):
        raise ValueError("Twin reserve requires a new owned temporary Store")
    return path


def _fixture(path, *, owned_root=None, min_free_percent=None):
    if min_free_percent is not None:
        if (
            type(min_free_percent) is not int
            or min_free_percent != 1
            or owned_root is None
        ):
            raise ValueError(
                "Only an explicit new owned twin fixture may use a diagnostic reserve"
            )
        path = _owned_fixture_path(path, owned_root)
    elif owned_root is not None:
        raise ValueError("Owned twin reserve must be explicit")
    store = Store(Settings(path, min_free_bytes=0, simulation_mode=True))
    try:
        if min_free_percent is not None:
            auth.create_user(
                store, "capacity-admin", secrets.token_urlsafe(32), "admin", "default"
            )
            record_governance.configure(
                store,
                {
                    "name": "capacity-admin",
                    "tenant": "default",
                    "role": "admin",
                    "allowed_indexes": ["*"],
                },
                {"version": 1, "min_free_percent": min_free_percent},
            )
        return _populate_fixture(store)
    except BaseException as failure:
        try:
            store.close()
        except BaseException as cleanup:
            failure.add_note(
                "Twin fixture cleanup also failed: " + type(cleanup).__name__
            )
            raise failure from cleanup
        raise


def _populate_fixture(store):
    for name in ("requester", "reviewer"):
        auth.create_user(store, name, secrets.token_urlsafe(32), "admin", "ops-twin")
    source = source_registry.save(
        store,
        _actor(),
        {
            "index": "ops_twin",
            "product": "windows",
            "account": "TWIN-HOST",
            "realm": "virtual-lab",
            "credential_ref": "env:SAPIENTIA_CONNECTOR_OPSTWIN",
            "version": 0,
        },
    )
    raw = {
        "id": "ops-twin-original",
        "data": {
            "@timestamp": datetime.fromtimestamp(time.time() - 10, UTC).isoformat(),
            "host": {"id": "TWIN-HOST", "os": {"type": "windows"}},
            "process": {
                "guid": "twin-process",
                "pid": 4242,
                "start_identity": "twin:one",
                "name": "benign.exe",
                "executable": "C:\\Twin\\benign.exe",
                "command_line": "benign synthetic activity",
            },
            "event": {"action": "process_created", "module": "process"},
            "agent": {"simulation": True},
        },
    }
    outcome = connector_runtime.intake(
        store,
        _actor(),
        source["id"],
        {"version": 1, "events": [raw], "cursor": "one", "checkpoint_version": 0},
    )
    original = outcome["event_ids"][0]
    store.flush()
    detections.save(
        store,
        _actor(),
        {
            "name": "Synthetic twin evidence",
            "entity_field": "host",
            "window": 300,
            "steps": [
                {"filters": [{"field": "event_id", "op": "eq", "value": original}]}
            ],
        },
    )
    if detections.run_due(store, time.time() + 1) != 1:
        raise AssertionError("Twin fixture did not create a Case")
    case = detections.incident_list(store, _actor())[0]
    action_runtime.create_asset(
        store,
        _actor(),
        {"source_id": source["id"], "asset_id": source["account"], "processes": {}},
    )
    return store, source, case, original


def _intent(store, source, case, original, action, extra):
    asset = action_runtime.asset(store, _actor(), source["id"])
    return effect_receipts.prepare(
        store,
        _actor(),
        case["id"],
        {
            "case_version": detections.incident_detail(store, _actor(), case["id"])[
                "version"
            ],
            "source_id": source["id"],
            "source_version": source["version"],
            "event_ids": [original],
            "request_id": "ops-twin:" + secrets.token_hex(10),
            "action": action,
            "target": {
                "asset_id": source["account"],
                "asset_version": asset["version"],
                **extra,
            },
        },
    )


def _execute(store, prepared):
    approved = effect_receipts.transition(
        store, _actor("reviewer"), prepared["id"], prepared["version"], "approved", {}
    )
    return action_runtime.dispatch(store, _actor(), approved["id"], approved["version"])


def _allows(asset, address, port):
    # Explicit policy model; no claim that any OS firewall or packet was tested.
    return not asset["effective_isolated"] or (address, port) == ("192.0.2.10", 443)


def _require(value, reason):
    if not value:
        raise AssertionError(reason)


def run():
    checks = []
    with tempfile.TemporaryDirectory(prefix="xsera-response-twin-") as temporary:
        path = Path(temporary) / "store"
        store, source, case, original = _fixture(
            path, owned_root=Path(temporary), min_free_percent=1
        )
        receipts = []
        try:
            prepared = _intent(
                store, source, case, original, "isolate_host", {"lease_seconds": 5}
            )
            try:
                effect_receipts.transition(
                    store, _actor(), prepared["id"], prepared["version"], "approved", {}
                )
            except (PermissionError, ConflictError):
                self_refused = True
            else:
                self_refused = False
            if not self_refused:
                raise AssertionError("Twin requester approved its own isolation")
            receipt = _execute(store, prepared)
            receipts.append(receipt)
            asset = action_runtime.asset(store, _actor(), source["id"])
            _require(asset["effective_isolated"], "Twin isolation was not effective")
            _require(
                _allows(asset, "192.0.2.10", 443)
                and not _allows(asset, "203.0.113.66", 443),
                "Twin management policy was not preserved",
            )
            checks.append(
                {
                    "name": "independent_approval_isolation_and_management_policy",
                    "passed": True,
                    "management_policy_model": True,
                    "actual_packet_test": False,
                }
            )
            store.close()
            store = Store(Settings(path, min_free_bytes=0, simulation_mode=True))
            asset = action_runtime.asset(store, _actor(), source["id"])
            _require(
                asset["state"]["isolation"]["id"] == receipt["id"]
                and asset["state"]["effect_count"] == 1,
                "Twin restart lost its exact owned effect",
            )
            checks.append(
                {
                    "name": "durable_twin_restart",
                    "passed": True,
                    "physical_os_reboot": False,
                }
            )
            expires = asset["state"]["isolation"]["expires"]
            while time.time() <= expires:
                time.sleep(min(0.1, max(0.001, expires - time.time() + 0.002)))
            asset = action_runtime.asset(store, _actor(), source["id"])
            _require(
                not asset["effective_isolated"] and _allows(asset, "203.0.113.66", 443),
                "Finite twin lease did not expire",
            )
            checks.append(
                {
                    "name": "real_time_finite_twin_lease_expiry",
                    "passed": True,
                    "lease_seconds": 5,
                    "durable_expiry": expires,
                }
            )
            cleared = _execute(
                store,
                _intent(
                    store,
                    source,
                    case,
                    original,
                    "release_host",
                    {"isolation_id": receipt["id"]},
                ),
            )
            receipts.append(cleared)
            # A second deliberate benign false-positive response is reversed
            # only by a separately approved exact owned recovery intent.
            mistaken = _execute(
                store,
                _intent(
                    store, source, case, original, "isolate_host", {"lease_seconds": 30}
                ),
            )
            receipts.append(mistaken)
            restored = _execute(
                store,
                _intent(
                    store,
                    source,
                    case,
                    original,
                    "release_host",
                    {"isolation_id": mistaken["id"]},
                ),
            )
            receipts.append(restored)
            final = action_runtime.asset(store, _actor(), source["id"])
            _require(
                not final["effective_isolated"]
                and final["state"]["isolation"] is None
                and final["state"]["effect_count"] == 4,
                "False-positive twin recovery was not verified",
            )
            with store.control() as db:
                _require(
                    db.execute("SELECT count(*) FROM endpoint_responses").fetchone()[0]
                    == 0,
                    "Native response rows unexpectedly exist",
                )
                history = [
                    dict(r)
                    for r in db.execute(
                        "SELECT id,version,actor,state FROM effect_receipt_history ORDER BY at,version"
                    )
                ]
            checks.append(
                {
                    "name": "false_positive_exact_owned_recovery_receipt",
                    "passed": True,
                    "final_effect_count": 4,
                    "recovery_receipt_id": restored["id"],
                }
            )
            return {
                "schema": "xsera.response-rehearsal.v1",
                "passed": True,
                "synthetic": True,
                "native_host_effects": 0,
                "fixture_policy": {
                    "min_free_percent": 1,
                    "scope": "new owned temporary simulation Store only",
                    "production_default_min_free_percent": record_governance.DEFAULT[
                        "min_free_percent"
                    ],
                },
                "checks": checks,
                "receipts": [
                    {
                        k: r[k]
                        for k in (
                            "id",
                            "state",
                            "action",
                            "artifact_digest",
                            "before_digest",
                            "after_digest",
                        )
                    }
                    for r in receipts
                ],
                "receipt_history": history,
                "final_state_digest": release_manifest.digest(final["state"]),
                "limitations": [
                    "Management connectivity is a digital-twin policy assertion, not a packet/firewall test",
                    "Restart reopens the temporary Store; physical OS reboot and real endpoint recovery are unavailable",
                    "No native host command or response executor was invoked",
                ],
            }
        finally:
            store.close()
