"""Memory exhaustion is a sanitized resource failure, not an invalid query."""

import json
import logging
from types import SimpleNamespace

import duckdb
import httpx
import pytest
from fastapi.testclient import TestClient

from sapientia import api, auth, log_search
from sapientia.storage import Settings
from tools import log_qualification_diagnostics as diagnostics

PRIVATE = "private-query-value-must-not-appear"
MEMORY_DETAIL = "Query memory budget exceeded; narrow the time range or fields"


@pytest.fixture
def client(tmp_path):
    app = api.create_app(Settings(tmp_path, min_free_bytes=0), background=False)
    with TestClient(app) as value:
        auth.create_user(
            app.state.store, "admin", "Testing-only-password-2026", "admin", "default"
        )
        login = value.post(
            "/api/login",
            json={"name": "admin", "password": "Testing-only-password-2026"},
        )
        assert login.status_code == 200
        value.headers["X-CSRF-Token"] = login.json()["csrf"]
        yield value


def fail_with(exception):
    def fail(*_args, **_kwargs):
        raise exception

    return fail


def test_memory_response_and_warning_are_static_and_rate_limited(
    client, monkeypatch, caplog
):
    store = client.app.state.store
    monkeypatch.setattr(
        store, "search", fail_with(duckdb.OutOfMemoryException(PRIVATE))
    )
    clock = [0.0]
    monkeypatch.setattr(api, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    with caplog.at_level(logging.WARNING, logger="sapientia"):
        for _ in range(2):
            response = client.post("/api/search", json={"query": {}})
            assert response.status_code == 503
            assert response.json() == {
                "detail": MEMORY_DETAIL,
                "code": "query_memory_budget",
            }
            assert response.headers["Retry-After"] == "5"
            assert PRIVATE not in response.text
        warnings = [r for r in caplog.records if "query_memory_budget" in r.message]
        assert len(warnings) == 1
        clock[0] = 30.0
        assert client.post("/api/search", json={"query": {}}).status_code == 503
    warnings = [r for r in caplog.records if "query_memory_budget" in r.message]
    assert len(warnings) == 2
    assert all(
        r.getMessage() == "Query rejected: query_memory_budget" for r in warnings
    )
    assert all(r.exc_info is None for r in warnings)
    assert PRIVATE not in caplog.text


def test_snapshot_uses_same_memory_handler_without_publication(
    client, monkeypatch, caplog
):
    store = client.app.state.store
    with store.control(local=True) as db:
        before = db.execute("SELECT count(*) FROM log_snapshots").fetchone()[0]
    monkeypatch.setattr(
        log_search, "create", fail_with(duckdb.OutOfMemoryException(PRIVATE))
    )
    with caplog.at_level(logging.WARNING, logger="sapientia"):
        response = client.post("/api/logs/snapshots", json={"query": {}})
    assert response.status_code == 503
    assert response.json()["code"] == "query_memory_budget"
    with store.control(local=True) as db:
        assert db.execute("SELECT count(*) FROM log_snapshots").fetchone()[0] == before
    assert PRIVATE not in response.text and PRIVATE not in caplog.text


@pytest.mark.parametrize(
    "exception_type",
    [duckdb.BinderException, duckdb.IOException, duckdb.ParserException, duckdb.Error],
)
def test_other_duckdb_errors_remain_422_without_text_classification(
    client, monkeypatch, caplog, exception_type
):
    monkeypatch.setattr(
        client.app.state.store,
        "search",
        fail_with(exception_type("Out of Memory: " + PRIVATE)),
    )
    with caplog.at_level(logging.WARNING, logger="sapientia"):
        response = client.post("/api/search", json={"query": {}})
    assert response.status_code == 422
    assert "code" not in response.json()
    assert "query_memory_budget" not in caplog.text
    assert PRIVATE not in response.text and PRIVATE not in caplog.text


def test_diagnostic_memory_allowlist_does_not_copy_unknown_details():
    result = diagnostics.http_evidence(
        httpx.Response(
            503, json={"detail": MEMORY_DETAIL, "code": "query_memory_budget"}
        )
    )
    assert result["detail_code"] == "query_memory_budget"
    assert (
        diagnostics.error_type(duckdb.OutOfMemoryException(PRIVATE))
        == "OutOfMemoryException"
    )
    unknown = diagnostics.http_evidence(
        httpx.Response(503, json={"detail": PRIVATE, "code": "query_memory_budget"})
    )
    assert unknown["detail_code"] == "unrecognized_detail_omitted"
    assert PRIVATE not in json.dumps(unknown)
