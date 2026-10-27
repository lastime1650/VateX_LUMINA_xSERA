"""Real TLS admission binds a verified certificate to one tenant and index."""
import hashlib
import socket
import ssl

import pytest

from sapientia import auth, pipeline
from sapientia.syslog_input import SyslogReceiver, SyslogSettings
from tests.test_syslog_input import LINE, wait_until
from tests.test_syslog_input import store as store_fixture
from tests.test_syslog_input import tls_contexts as tls_fixture


@pytest.fixture
def store(tmp_path):
    yield from store_fixture.__wrapped__(tmp_path)


@pytest.fixture
def tls_contexts(tmp_path):
    return tls_fixture.__wrapped__(tmp_path)


def mutual(tls_contexts, tmp_path):
    server, client = tls_contexts
    pem = (tmp_path / "cert.pem").read_text()
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
    server.load_verify_locations(cafile=str(tmp_path / "cert.pem"))
    server.verify_mode = ssl.CERT_REQUIRED
    client.load_cert_chain(tmp_path / "cert.pem", tmp_path / "key.pem")
    return server, client, fingerprint


def transmit(receiver, context):
    with (socket.create_connection(receiver.address, timeout=2) as raw,
          context.wrap_socket(raw, server_hostname="localhost") as client):
        client.sendall(LINE + b"\n")
        wait_until(lambda: receiver.health()["received"] >= 1 or receiver.health()["transport_errors"] >= 1)


def test_real_certificate_exact_tenant_index_admission(store, tls_contexts, tmp_path):
    server, client, fingerprint = mutual(tls_contexts, tmp_path)
    binding = {fingerprint: {"tenant": "alpha", "index": "firewall"}}
    receiver = SyslogReceiver(store, SyslogSettings(port=0, transport="tls", ssl_context=server, peer_bindings=binding)).start()
    try:
        transmit(receiver, client)
        wait_until(lambda: receiver.health()["admitted"] == 1)
        assert receiver.health()["mutual_tls"] is True
        assert receiver.health()["certificate_bindings"] == 1
    finally:
        receiver.close()
    store.flush()
    result = store.search("alpha", {"query": "* | table index,raw", "earliest": 0, "latest": 2000000000})
    assert result["returned"] == 1
    assert result["rows"][0]["index"] == "firewall"
    assert fingerprint in result["rows"][0]["raw"]
    assert store.health("default")["indexed"] == 0


@pytest.mark.parametrize("missing_certificate", [True, False])
def test_missing_or_unmapped_identity_is_not_admitted(store, tls_contexts, tmp_path, missing_certificate):
    server, client, fingerprint = mutual(tls_contexts, tmp_path)
    context = ssl.create_default_context(cafile=str(tmp_path / "cert.pem")) if missing_certificate else client
    binding = {fingerprint if missing_certificate else "0"*64: {"tenant": "alpha", "index": "firewall"}}
    receiver = SyslogReceiver(store, SyslogSettings(port=0, transport="tls", ssl_context=server, peer_bindings=binding)).start()
    try:
        try:
            transmit(receiver, context)
        except (ssl.SSLError, ConnectionError):
            pass
        wait_until(lambda: receiver.health()["transport_errors"] >= 1)
        assert receiver.health()["admitted"] == 0
    finally:
        receiver.close()


def test_parser_route_cannot_escape_cert_scope_or_poison_queue(store, tls_contexts, tmp_path):
    server, client, fingerprint = mutual(tls_contexts, tmp_path)
    auth.create_user(store, "administrator", "Testing-only-password-2026", "admin", "alpha")
    pipeline.save(store, {"name": "administrator", "tenant": "alpha", "role": "admin"}, "route", {"version": 0, "definition": {"source": "syslog", "route_index": "private"}})
    receiver = SyslogReceiver(store, SyslogSettings(port=0, transport="tls", ssl_context=server, peer_bindings={fingerprint: {"tenant": "alpha", "index": "firewall"}})).start()
    try:
        transmit(receiver, client)
        wait_until(lambda: receiver.health()["dropped_invalid"] >= 1)
        assert receiver.health()["admitted"] == 0
        assert receiver.health()["queued"] == 0
    finally:
        receiver.close()
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM receipts").fetchone()[0] == 0


def test_bindings_require_verified_tls(tls_contexts):
    server, _ = tls_contexts
    with pytest.raises(ValueError, match="mutual TLS"):
        SyslogSettings(transport="tls", ssl_context=server, peer_bindings={"0"*64: {"tenant": "a", "index": "main"}})
