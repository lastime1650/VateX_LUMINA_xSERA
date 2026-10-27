"""Explicit 1% disk reserve for new pytest-owned functional fixture Stores.

Real disk measurements are always used. Only the initial policy of new Stores
under pytest's temporary directory changes; capacity tests may override it.
The product default and all stores outside pytest's directory remain unchanged.
"""
from pathlib import Path

import pytest

from tests.signing_support import (
    release_signer,  # noqa: F401 -- Non-autouse; production-package fixtures explicitly request it.
)


@pytest.fixture(autouse=True)
def owned_test_volume(monkeypatch, tmp_path_factory):
    from sapientia import record_governance
    from sapientia.storage import encode

    owned = tmp_path_factory.getbasetemp().resolve()
    original = record_governance.initialize

    def initialize(store):
        original(store)
        if not Path(store.path).resolve().is_relative_to(owned):
            return
        with store.control(local=True) as db:
            row = db.execute("SELECT version,definition FROM record_management_policy WHERE singleton=1").fetchone()
            if row["version"] == 1 and row["definition"] == encode(record_governance.DEFAULT):
                policy = {**store.record_policy, "min_free_percent": 1}
                db.execute("UPDATE record_management_policy SET definition=? WHERE singleton=1", (encode(policy),))
                store.record_policy = policy

    monkeypatch.setattr(record_governance, "initialize", initialize)
