"""Hostile inputs stay data; collection tool lookup never uses CWD or PATH."""

import ctypes
import json
import ntpath
import os
from types import SimpleNamespace

import duckdb
import pytest

from sapientia.endpoint_agent.Agent.Windows import collector
from sapientia.query import Query, QueryError, column, index_predicate
from sapientia.spl import SPLQuery


@pytest.mark.parametrize(
    "value",
    ["raw.x'); DROP TABLE events_all;--", 'host";SELECT 1--', "tenant", "raw.a[0]"],
)
def test_public_identifier_grammar_rejects_sql_fragments(value):
    with pytest.raises(QueryError):
        column(value)
    with pytest.raises(QueryError):
        index_predicate([value + "'"])


@pytest.mark.parametrize("language", ["json", "spl"])
def test_sql_looking_literals_are_bound_and_cannot_cross_tenant_or_index(language):
    hostile = "x' OR 1=1; DROP TABLE events_all; --"
    if language == "json":
        query = Query.parse(
            {
                "language": "json",
                "earliest": 0,
                "latest": 100,
                "query": {
                    "filters": [{"field": "message", "op": "eq", "value": hostile}],
                    "fields": ["event_id"],
                },
            }
        )
    else:
        query = SPLQuery.parse(
            {
                "query": "search message=" + json.dumps(hostile) + " | table event_id",
                "earliest": 0,
                "latest": 100,
            }
        )
    sql, args = query.compile("a", allowed_indexes=["allowed"])
    assert any(
        isinstance(value, str) and value.lower() == hostile.lower() for value in args
    )
    assert hostile.lower() not in sql.lower()
    database = duckdb.connect(
        ":memory:", config={"enable_external_access": "false", "threads": "1"}
    )
    try:
        database.execute(
            "CREATE TABLE events_all(tenant VARCHAR,event_id VARCHAR,event_time DOUBLE,index_name VARCHAR,received DOUBLE,source VARCHAR,sourcetype VARCHAR,host VARCHAR,severity VARCHAR,message VARCHAR,raw VARCHAR)"
        )
        for tenant, index, identifier in (
            ("a", "allowed", "visible"),
            ("b", "allowed", "foreign"),
            ("a", "denied", "out-of-scope"),
        ):
            database.execute(
                "INSERT INTO events_all VALUES(?,?,1,?,1,'fixture','fixture','HOST','info',?,'{}')",
                [tenant, identifier, index, hostile],
            )
        rows = database.execute(sql, args).fetchall()
        assert rows == [("visible",)]
        assert database.execute("SELECT count(*) FROM events_all").fetchone()[0] == 3
    finally:
        database.close()


@pytest.mark.parametrize(
    "text",
    [
        '* | eval x=read_csv("private-file")',
        '* | eval x=read_parquet("private-file")',
        "* | eval x=1; DROP TABLE events_all",
        '* | table host"; DROP TABLE events_all; --',
        '* | where host="x" OR tenant="b"',
        "* | lookup ../../private.csv host OUTPUT token",
    ],
)
def test_spl_refuses_unregistered_execution_and_reserved_or_hostile_identifiers(text):
    with pytest.raises(QueryError):
        SPLQuery.parse({"query": text, "earliest": 0, "latest": 100})


def test_windows_collection_uses_fixed_system32_tools_even_with_hostile_cwd_and_path(
    tmp_path, monkeypatch
):
    commands = []

    def directory(buffer, _maximum):
        buffer.value = r"C:\VerifiedWindows\System32"
        return len(buffer.value)

    monkeypatch.setattr(
        ctypes,
        "WinDLL",
        lambda *_a, **_k: SimpleNamespace(GetSystemDirectoryW=directory),
        raising=False,
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setenv("SystemRoot", "C:/ParserFixtureWindows")

    def run(command, **_options):
        commands.append(command)
        return SimpleNamespace(
            returncode=0,
            stdout=b"RUNNING" if ntpath.basename(command[0]) == "sc.exe" else b"",
        )

    monkeypatch.setattr(collector.subprocess, "run", run)
    assert collector._xml_events("Security") == []
    value = collector.WindowsCollector.__new__(collector.WindowsCollector)
    value.providers = {}
    assert value._sysmon_running()
    assert value._tcp_events("fixture-host") == []
    root = (
        r"C:\VerifiedWindows\System32"
        if os.name == "nt"
        else r"C:\ParserFixtureWindows\System32"
    )
    assert [ntpath.basename(command[0]) for command in commands] == [
        "wevtutil.exe",
        "sc.exe",
        "netstat.exe",
    ]
    assert all(
        ntpath.normcase(ntpath.dirname(command[0]))
        == ntpath.normcase(ntpath.normpath(root))
        for command in commands
    )
    with pytest.raises(ValueError, match="Unsupported"):
        collector._system_tool("../../untrusted.exe")
