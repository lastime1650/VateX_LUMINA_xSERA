"""Reject malicious XML before policy compilation or provider processing."""
from types import SimpleNamespace

import pytest

from sapientia.endpoint_agent.Agent import windows_app_control as policy
from sapientia.endpoint_agent.Agent.Windows import collector


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16-le", "utf-16-be"])
def test_native_policy_rejects_dtd_entity_in_all_supported_xml_encodings(tmp_path, encoding):
    path = tmp_path / "unsafe.xml"
    xml = f'<?xml version="1.0" encoding="{encoding}"?><!DOCTYPE SiPolicy [<!ENTITY secret SYSTEM "file:///never-read">]><SiPolicy xmlns="{policy.NAMESPACE}">&secret;</SiPolicy>'
    path.write_bytes(xml.encode(encoding))
    with pytest.raises(ValueError, match="DTD|unsafe|Invalid"):
        policy._xml(path)


def test_event_provider_rejects_doctype_without_following_external_reference(monkeypatch):
    raw = b'<!DOCTYPE Event [<!ENTITY secret SYSTEM "file:///never-read">]><Event>&secret;</Event>'
    monkeypatch.setattr(collector.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout=raw))
    with pytest.raises(RuntimeError, match="malformed XML"):
        collector._xml_events("Security")


def test_event_provider_rejects_oversized_xml(monkeypatch):
    raw = b" " * (4 * 1024 * 1024 + 1)
    monkeypatch.setattr(collector.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout=raw))
    with pytest.raises(RuntimeError, match="malformed XML"):
        collector._xml_events("Security")
