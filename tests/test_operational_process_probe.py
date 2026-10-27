"""Owned child process failover and actual snapshot rollback proof."""

import hashlib
import shutil
import tempfile
from contextlib import closing
from pathlib import Path

import pytest

from sapientia import operational_process_probe, record_governance
from sapientia.locking import ProcessLock
from sapientia.storage import Settings, Store


def test_owned_process_lock_takeover_and_incompatible_candidate_rollback():
    result = operational_process_probe.run()
    assert result["passed"] and result["native_host_effects"] == 0
    assert len(result["checks"]) == 3
    assert result["checks"][0]["simultaneous_processes"] == 2
    assert result["checks"][1]["terminated_owned_processes"] == 1
    assert result["checks"][1]["automatic_production_failover"] is False
    assert result["checks"][2]["restored_originals"] == 1
    assert result["fixture_policy"]["min_free_percent"] == 1
    assert result["fixture_policy"]["production_default_min_free_percent"] == 20
    assert (
        result["fixture_policy"]["initialization_process"]
        == "parent before actual child startup"
    )


def test_owned_store_seed_persists_reserve_and_releases_real_process_lock():
    with tempfile.TemporaryDirectory(prefix="xsera-process-recovery-") as temporary:
        root, path = Path(temporary), Path(temporary) / "active-store"
        operational_process_probe._seed_owned_store(root, path)
        with closing(ProcessLock(path / "service.lock")):
            pass
        reopened = Store(Settings(path, min_free_bytes=0))
        try:
            assert reopened.record_policy["min_free_percent"] == 1
        finally:
            reopened.close()
        assert path.resolve() == root.resolve() / "active-store"
        shutil.rmtree(path)
        assert not path.exists()
    assert record_governance.DEFAULT["min_free_percent"] == 20


@pytest.mark.parametrize("kind", ["existing", "foreign", "nonempty", "wrong-prefix"])
def test_recovery_seed_refuses_any_existing_or_foreign_store(
    tmp_path, monkeypatch, kind
):
    prefix = (
        "unowned-recovery-" if kind == "wrong-prefix" else "xsera-process-recovery-"
    )
    with tempfile.TemporaryDirectory(prefix=prefix) as temporary:
        root, path = Path(temporary), Path(temporary) / "active-store"
        before = None
        if kind == "existing":
            store = Store(Settings(path, min_free_bytes=0))
            assert store.record_policy["min_free_percent"] == 20
            store.close()
            before = hashlib.sha256((path / "control.sqlite3").read_bytes()).hexdigest()
        elif kind == "foreign":
            path = tmp_path / "unowned-store"
        elif kind == "nonempty":
            (root / "unrelated.txt").write_text("preserve")
        monkeypatch.setattr(
            operational_process_probe,
            "Store",
            lambda *_a, **_kw: pytest.fail("Must refuse before any Store is opened"),
        )
        with pytest.raises(ValueError, match="new owned temporary"):
            operational_process_probe._seed_owned_store(root, path)
        if before:
            assert (
                hashlib.sha256((path / "control.sqlite3").read_bytes()).hexdigest()
                == before
            )
        else:
            assert not path.exists()


def test_failed_owned_policy_seed_closes_actual_store(monkeypatch):
    failure = RuntimeError("Injected owned reserve setup failure")

    def fail(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(operational_process_probe.record_governance, "configure", fail)
    with tempfile.TemporaryDirectory(prefix="xsera-process-recovery-") as temporary:
        root, path = Path(temporary), Path(temporary) / "active-store"
        with pytest.raises(RuntimeError) as error:
            operational_process_probe._seed_owned_store(root, path)
        assert error.value is failure
        with closing(ProcessLock(path / "service.lock")):
            pass
        reopened = Store(Settings(path, min_free_bytes=0))
        assert reopened.record_policy["min_free_percent"] == 20
        reopened.close()
