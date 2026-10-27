"""Actual twin protocol, elapsed lease, restart and approved recovery receipt."""

import hashlib
import shutil
import tempfile
from contextlib import closing
from pathlib import Path

import pytest

from sapientia import record_governance, response_rehearsal
from sapientia.locking import ProcessLock
from sapientia.storage import CapacityError, Settings, Store


def test_twin_preserves_management_policy_and_recovers_benign_false_positive():
    result = response_rehearsal.run()
    assert result["passed"] and result["native_host_effects"] == 0
    assert len(result["checks"]) == 4 and all(c["passed"] for c in result["checks"])
    assert len(result["receipts"]) == 4
    assert [r["action"] for r in result["receipts"]] == [
        "isolate_host",
        "release_host",
        "isolate_host",
        "release_host",
    ]
    assert len({r["id"] for r in result["receipts"]}) == 4
    for receipt in result["receipts"]:
        history = [h for h in result["receipt_history"] if h["id"] == receipt["id"]]
        assert [h["state"] for h in history] == [
            "prepared",
            "approved",
            "dispatching",
            "reported",
            "confirmed",
        ]
        assert history[0]["actor"] != history[1]["actor"]
    assert result["checks"][2]["lease_seconds"] == 5
    assert result["checks"][0]["actual_packet_test"] is False
    assert result["fixture_policy"]["min_free_percent"] == 1
    assert result["fixture_policy"]["production_default_min_free_percent"] == 20


@pytest.mark.parametrize("stage", ["configure", "intake", "case", "asset"])
def test_fixture_failure_closes_actual_store_and_preserves_original_error(
    monkeypatch, stage
):
    failure = CapacityError("Injected owned twin preparation failure")
    captured = []

    def fail(store, *_args, **_kwargs):
        captured.append(store)
        raise failure

    component, method = {
        "configure": (response_rehearsal.record_governance, "configure"),
        "intake": (response_rehearsal.connector_runtime, "intake"),
        "case": (response_rehearsal.detections, "run_due"),
        "asset": (response_rehearsal.action_runtime, "create_asset"),
    }[stage]
    monkeypatch.setattr(component, method, fail)
    with tempfile.TemporaryDirectory(prefix="xsera-response-twin-") as temporary:
        root, path = Path(temporary), Path(temporary) / "store"
        with pytest.raises(CapacityError) as error:
            response_rehearsal._fixture(path, owned_root=root, min_free_percent=1)
        assert error.value is failure and len(captured) == 1
        with closing(ProcessLock(path / "service.lock")):
            pass
        reopened = Store(Settings(path, min_free_bytes=0, simulation_mode=True))
        try:
            assert reopened.record_policy["min_free_percent"] == (
                20 if stage == "configure" else 1
            )
            with reopened.control(local=True) as db:
                assert (
                    db.execute("SELECT count(*) FROM endpoint_responses").fetchone()[0]
                    == 0
                )
        finally:
            reopened.close()
        assert path.resolve() == root.resolve() / "store"
        shutil.rmtree(path)
        assert not path.exists()
    assert record_governance.DEFAULT["min_free_percent"] == 20


def test_fixture_preserves_preparation_error_if_close_reports_secondary_error(
    monkeypatch,
):
    failure = CapacityError("Owned fixture primary failure")
    actual_close = Store.close

    def close_then_fail(store):
        actual_close(store)
        raise RuntimeError("Injected error after real resource close")

    def fail(*_args, **_kwargs):
        raise failure

    with tempfile.TemporaryDirectory(prefix="xsera-response-twin-") as temporary:
        root, path = Path(temporary), Path(temporary) / "store"
        with monkeypatch.context() as patch:
            patch.setattr(response_rehearsal.connector_runtime, "intake", fail)
            patch.setattr(Store, "close", close_then_fail)
            with pytest.raises(CapacityError) as error:
                response_rehearsal._fixture(path, owned_root=root, min_free_percent=1)
        assert error.value is failure
        assert "cleanup also failed: RuntimeError" in error.value.__notes__[0]
        with closing(ProcessLock(path / "service.lock")):
            pass
        reopened = Store(Settings(path, min_free_bytes=0, simulation_mode=True))
        reopened.close()


@pytest.mark.parametrize(
    "kind", ["existing", "foreign", "nonempty", "unclaimed", "untyped"]
)
def test_diagnostic_reserve_cannot_relax_existing_or_unowned_store(
    tmp_path, monkeypatch, kind
):
    with tempfile.TemporaryDirectory(prefix="xsera-response-twin-") as temporary:
        root, path = Path(temporary), Path(temporary) / "store"
        before = None
        if kind == "existing":
            store = Store(Settings(path, min_free_bytes=0, simulation_mode=True))
            assert store.record_policy["min_free_percent"] == 20
            store.close()
            before = hashlib.sha256((path / "control.sqlite3").read_bytes()).hexdigest()
        elif kind == "foreign":
            path = tmp_path / "foreign-store"
        elif kind == "nonempty":
            (root / "unrelated.txt").write_text("must remain unchanged")
        monkeypatch.setattr(
            response_rehearsal,
            "Store",
            lambda *_a, **_kw: pytest.fail("Must refuse before opening any Store"),
        )
        kwargs = {"owned_root": root, "min_free_percent": 1}
        if kind == "unclaimed":
            kwargs.pop("owned_root")
        elif kind == "untyped":
            kwargs["min_free_percent"] = True
        with pytest.raises(ValueError):
            response_rehearsal._fixture(path, **kwargs)
        if before:
            assert (
                hashlib.sha256((path / "control.sqlite3").read_bytes()).hexdigest()
                == before
            )
        elif kind == "nonempty":
            assert (root / "unrelated.txt").read_text() == "must remain unchanged"
            assert not path.exists()
        else:
            assert not path.exists()


def test_default_fixture_does_not_change_existing_store_reserve(monkeypatch):
    with tempfile.TemporaryDirectory(prefix="xsera-default-twin-") as temporary:
        path = Path(temporary) / "existing-store"
        store = Store(Settings(path, min_free_bytes=0, simulation_mode=True))
        assert store.record_policy["min_free_percent"] == 20
        store.close()
        failure = RuntimeError("Stop before populating an existing fixture")

        def stop(store):
            assert store.record_policy["min_free_percent"] == 20
            raise failure

        monkeypatch.setattr(response_rehearsal, "_populate_fixture", stop)
        with pytest.raises(RuntimeError) as error:
            response_rehearsal._fixture(path)
        assert error.value is failure
        reopened = Store(Settings(path, min_free_bytes=0, simulation_mode=True))
        assert reopened.record_policy["min_free_percent"] == 20
        reopened.close()
