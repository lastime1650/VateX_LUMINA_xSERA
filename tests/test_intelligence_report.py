"""Artifact generator trust boundary and exact evidence linkage."""

import json
from pathlib import Path

import pytest

from tools.build_intelligence_report import build, junit_summary, normalize, sanitize


def test_deterministic_html_escapes_injected_script_and_redacts_secrets(tmp_path):
    evidence = {"source_version": "test-version", "password": "NEVER-EMBED-ME",
                "body": '{"api_token":"NESTED-SECRET","id":"visible"}',
                "note": '</script><script>alert("injection")</script>',
                "private_key": "-----BEGIN PRIVATE KEY----- HIDDEN-KEY",
                "simulation": {"events": [{"event_id": "e1", "device": "Windows", "sent_at": 1700000000}]},
                "signals": [{"id": "s1", "kind": "atomic", "event_ids": ["e1"]}],
                "cases": [{"id": "c1", "contributions": [{"evidence": {"event_ids": ["e1"], "analysis": {"signal_id": "s1"}}}]}]}
    supplied, junit = tmp_path/"evidence.json", tmp_path/"result.xml"
    supplied.write_text(json.dumps(evidence), encoding="utf-8")
    junit.write_text('<testsuites><testsuite><testcase name="pass" time="0.1"/><testcase name="skip"><skipped message="Optional framework"/></testcase><testcase name="fail"><failure message="assertion">known failure</failure></testcase></testsuite></testsuites>', encoding="utf-8")
    first, second = tmp_path/"first.html", tmp_path/"second.html"
    result = build(supplied, junit, first)
    build(supplied, junit, second)
    output = first.read_text(encoding="utf-8")
    assert first.read_bytes() == second.read_bytes()
    assert "NEVER-EMBED-ME" not in output and "NESTED-SECRET" not in output and "HIDDEN-KEY" not in output
    assert '</script><script>alert("injection")</script>' not in output
    assert "\\u003c/script\\u003e" in output
    assert result["tests"] == 3 and result["timeline_records"] == 1 and result["redacted_values"] == 3
    assert "cdn" not in output.lower() or "외부 CDN" in output
    summary = junit_summary(junit)
    assert (summary["passed"], summary["failed"], summary["skipped"], summary["error"]) == (1, 1, 1, 0)


def test_graph_only_uses_explicit_ids_and_no_guessed_shared_ip():
    evidence = {"signals": [{"id": "s1", "event_ids": '["e1"]', "story_id": "t1", "metadata": '{"incident_id":"c1"}'},
                            {"id": "s2", "event_ids": ["e2"], "host": "shared"}],
                "stories": [{"id": "t1"}],
                "cases": [{"id": "c1", "host": "shared", "evidence": {"event_ids": ["e1"]}}]}
    data = normalize(evidence, {"tests": 0})
    edges = {(item["from"], item["to"]) for item in data["graph"]["edges"]}
    assert ("event:e1", "signal:s1") in edges
    assert ("signal:s1", "case:c1") in edges
    assert ("signal:s1", "story:t1") in edges
    assert ("signal:s2", "case:c1") not in edges
    assert data["synthetic"] and not data["native_hardware"]


def test_junit_entities_and_inline_credentials_rejected_or_scrubbed(tmp_path):
    junit = tmp_path/"invalid.xml"
    junit.write_text('<!DOCTYPE testsuite [<!ENTITY secret "private">]><testsuite/>', encoding="utf-8")
    with pytest.raises(ValueError, match="DOCTYPE"):
        junit_summary(junit)
    assert sanitize("password='synthetic-test-secret'") == "[민감 정보 제거]"
    safe = {"automatic_endpoint_authorization": False, "credential_ref": "env:SAPIENTIA_CONNECTOR_VIRTUAL", "credential_available": True}
    assert sanitize(safe) == safe


def test_real_lab_aliases_preserve_case_ids_device_counts_and_cpu_times():
    supplied = {"simulation": {"devices": {"windows": {"sent": 50, "accepted": 50, "indexed": 50, "duplicate": 1}},
        "events": [{"event_id": "e", "event_time": 10}],
        "timeline": [{"event_id": "e", "device": "windows", "sent_at": 1700000000}],
        "signals": {"items": [{"id": "s", "event_ids": ["e"]}], "counts": {"atomic": 1}},
        "cases": [{"id": "c"}], "case_details": [{"id": "c", "evidence": {"event_ids": ["e"]}}],
        "ml_runtime": {"available": True}, "cpu_model": {"id": "m", "metrics": {"duration_ms": 100, "worker_wall_ms": 2000}},
        "ml_runs": [{"run_id": "r", "duration_ms": 1, "worker_wall_ms": 1500}],
        "full_shadow": {"replay": {"identical": True}}, "case_route": {"later_signal_attached_to_target": True}}}
    data = normalize(supplied, {"tests": 0})
    assert data["device_counts"][0]["sent"] == 50
    assert data["timeline"][0]["time"] == 1700000000
    assert data["signals"][0]["id"] == "s"
    assert data["cases"][0]["id"] == "c"
    assert any(edge["to"] == "case:c" for edge in data["graph"]["edges"])
    assert data["ml"]["runs"][0]["worker_wall_ms"] == 1500
    assert data["supplemental"]["shadow"]["replay"]["identical"]
