"""Time-field typos fail before scanning; documented SPL aliases stay intact."""

import pytest

from sapientia.query import Query, QueryError
from sapientia.spl import SPLQuery
from tests.test_api import client, sign_in


@pytest.mark.parametrize("unknown", ["start", "end", "offset", "indexes", "timeout", "fields", "earliest_time", "<script>untrusted</script>"])
def test_unknown_outer_fields_are_bounded_clear_errors(unknown):
    with pytest.raises(QueryError, match="earliest/latest") as failure:
        Query.parse({"language": "spl", "query": "*", unknown: 1})
    assert unknown not in str(failure.value) and len(str(failure.value)) < 160


def test_direct_spl_parser_checks_language_and_large_outer_maps_before_compilation():
    with pytest.raises(QueryError, match="language must be spl"):
        SPLQuery.parse({"language": "json", "query": "*"})
    with pytest.raises(QueryError, match="earliest/latest"):
        SPLQuery.parse({"query": "*", **{str(n): 1 for n in range(200)}})


def test_documented_payload_defaults_and_field_aliases_are_preserved(monkeypatch):
    monkeypatch.setattr("sapientia.spl.time.time", lambda: 100000.)
    default = Query.parse({"query": "*"})
    assert default.earliest == 13600 and default.latest == 100000 and default.limit == 200
    supplied = SPLQuery.parse({"language": "spl", "query": "index=main | table _time, _indextime, _raw, index",
        "earliest": 0, "latest": 1000, "limit": 17})
    sql, args = supplied.compile("tenant-a", ["main"])
    assert args[:3] == ["tenant-a", 0, 1000]
    assert args[-1] == 17 and 'AS "_time"' in sql and 'AS "_raw"' in sql


def test_authenticated_api_time_typo_returns_400_before_query_and_without_search_audit(client, monkeypatch):
    sign_in(client)
    store = client.app.state.store
    def must_not_scan(*args, **kwargs):
        pytest.fail("An invalid time request reached the analytics scanner")
    monkeypatch.setattr(store, "analytics_query", must_not_scan)
    response = client.post("/api/search", json={"language": "spl", "query": "* | stats count", "start": 10, "end": 20})
    assert response.status_code == 400 and "earliest/latest" in response.text
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM audit WHERE action='search'").fetchone()[0] == 0


def test_api_respects_explicit_earliest_latest_and_builtin_field_aliases(client):
    sign_in(client)
    store = client.app.state.store
    store.ingest("default", [{"event_id": "within", "event_time": 100, "message": "selected"},
        {"event_id": "outside", "event_time": 200, "message": "excluded"}])
    store.flush()
    response = client.post("/api/search", json={"language": "spl", "query": "index=main | table event_id, _time",
        "earliest": 90, "latest": 110, "limit": 100})
    assert response.status_code == 200
    assert response.json()["rows"] == [{"event_id": "within", "_time": 100}]
