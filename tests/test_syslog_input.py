import ipaddress
import socket
import ssl
import threading
import time
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sapientia.storage import CapacityError, Settings, Store
from sapientia.syslog_input import SyslogReceiver, SyslogSettings

LINE = b"<34>1 2003-10-11T22:14:15.003Z host app 123 ID - denied"


@pytest.fixture
def store(tmp_path):
    value = Store(Settings(tmp_path / "store", min_free_bytes=0))
    yield value
    value.close()


def wait_until(predicate, timeout=4):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    assert predicate(), "Syslog operation did not complete before timeout"


@pytest.mark.parametrize("transport", ["tcp", "udp"])
def test_real_loopback_receipt_repeats_timestamp_tenant_and_close(store, transport):
    receiver = SyslogReceiver(
        store, SyslogSettings(port=0, tenant="a", transport=transport)
    ).start()
    try:
        if transport == "tcp":
            with socket.create_connection(receiver.address, timeout=2) as client:
                # Framing must survive packet splits and preserve identical real events.
                framed = str(len(LINE)).encode() + b" " + LINE
                client.sendall(framed[:4])
                client.sendall(framed[4:] + LINE + b"\n")
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.sendto(LINE, receiver.address)
                client.sendto(LINE, receiver.address)
        wait_until(lambda: receiver.health()["admitted"] == 2)
    finally:
        receiver.close()
    assert not receiver.health()["listening"]
    store.flush()
    rows = store.search(
        "a",
        {
            "query": "* | table event_id,event_time,raw",
            "earliest": 0,
            "latest": 2000000000,
        },
    )["rows"]
    assert len(rows) == 2 and len({r["event_id"] for r in rows}) == 2
    assert all(r["event_time"] == pytest.approx(1065910455.003) for r in rows)
    assert all('"collector_peer":"127.0.0.1"' in r["raw"] for r in rows)
    assert store.health("b")["indexed"] == 0
    # Listener close owns only its sockets and threads, never the caller's Store.
    assert store.ingest("a", [{"event_id": "still-open"}])["accepted"] == 1


def test_udp_cef_and_invalid_datagrams_are_counted(store):
    receiver = SyslogReceiver(
        store, {"port": 0, "transport": "udp", "tenant": "a", "max_line_bytes": 256}
    ).start()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.sendto(
                b"CEF:0|Vendor|Firewall|1|42|Blocked|9|src=10.0.0.1", receiver.address
            )
            client.sendto(b"not syslog", receiver.address)
            client.sendto(b"x" * 300, receiver.address)
        wait_until(lambda: receiver.health()["received"] == 3)
        wait_until(lambda: receiver.health()["admitted"] == 1)
        assert receiver.health()["dropped_invalid"] == 1
        assert receiver.health()["dropped_oversized"] == 1
    finally:
        receiver.close()
    store.flush()
    assert store.search("a", {"query": "sourcetype=cef | table severity,host"})[
        "rows"
    ] == [{"severity": "critical", "host": "127.0.0.1"}]


def test_tcp_does_not_ingest_partial_eof_and_preserves_valid_before_oversized(store):
    receiver = SyslogReceiver(
        store, SyslogSettings(port=0, tenant="a", transport="tcp", max_line_bytes=256)
    ).start()
    try:
        with socket.create_connection(receiver.address, timeout=2) as client:
            client.sendall(LINE)
        wait_until(lambda: receiver.health()["dropped_invalid"] == 1)
        with socket.create_connection(receiver.address, timeout=2) as client:
            client.sendall(LINE + b"\n999999 ")
        wait_until(lambda: receiver.health()["dropped_oversized"] == 1)
        wait_until(lambda: receiver.health()["admitted"] == 1)
    finally:
        receiver.close()
    assert receiver.health()["received"] == 1


class GatedStore:
    def __init__(self):
        self.open = threading.Event()
        self.batches = []
        self.calls = []

    def ingest(self, tenant, events, actor):
        self.calls.append([e["event_id"] for e in events])
        if not self.open.is_set():
            raise CapacityError("synthetic capacity")
        self.batches.extend(events)
        return {"accepted": len(events), "duplicate": 0}


def test_udp_queue_full_has_drop_counters_and_retry_keeps_event_id():
    store = GatedStore()
    receiver = SyslogReceiver(store, SyslogSettings(port=0, queue_size=1)).start()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.sendto(LINE, receiver.address)
            wait_until(lambda: receiver.health()["capacity_retries"] >= 1)
            for _ in range(10):
                client.sendto(LINE, receiver.address)
        wait_until(lambda: receiver.health()["received"] == 11)
        assert receiver.health()["dropped_queue"] == 9
        assert receiver.health()["queued"] == 1
        first_id = store.calls[0]
        store.open.set()
        wait_until(lambda: receiver.health()["admitted"] == 2)
        assert first_id == store.calls[1]
        assert receiver.health()["duplicate"] == 0
    finally:
        store.open.set()
        receiver.close()


def test_tcp_queue_backpressure_does_not_drop_complete_events():
    store = GatedStore()
    receiver = SyslogReceiver(
        store, SyslogSettings(port=0, queue_size=1, transport="tcp")
    ).start()
    try:
        with socket.create_connection(receiver.address, timeout=2) as client:
            client.sendall((LINE + b"\n") * 5)
            wait_until(lambda: receiver.health()["capacity_retries"] >= 1)
            store.open.set()
            wait_until(lambda: receiver.health()["admitted"] == 5)
        assert receiver.health()["dropped_queue"] == 0
        assert len({event["event_id"] for event in store.batches}) == 5
    finally:
        store.open.set()
        receiver.close()


def test_failed_drain_is_explicit_and_worker_stops():
    store = GatedStore()
    receiver = SyslogReceiver(store, SyslogSettings(port=0)).start()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.sendto(LINE, receiver.address)
    wait_until(lambda: receiver.health()["capacity_retries"] >= 1)
    with pytest.raises(RuntimeError, match="Store must remain open"):
        receiver.close(timeout=0.1)
    assert receiver.health()["dropped_shutdown"] == 1
    assert not receiver._worker.is_alive()


@pytest.fixture
def tls_contexts(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_2
    server.load_cert_chain(cert_path, key_path)
    client = ssl.create_default_context(cafile=str(cert_path))
    return server, client


def test_real_tls_verified_loopback_listener(store, tls_contexts):
    server, client_context = tls_contexts
    receiver = SyslogReceiver(
        store, SyslogSettings(port=0, tenant="a", transport="tls", ssl_context=server)
    ).start()
    try:
        with (
            socket.create_connection(receiver.address, timeout=2) as raw,
            client_context.wrap_socket(raw, server_hostname="localhost") as client,
        ):
            client.sendall(LINE + b"\n")
            wait_until(lambda: receiver.health()["admitted"] == 1)
    finally:
        receiver.close()
    assert receiver.health()["transport_errors"] == 0


@pytest.mark.parametrize(
    "settings",
    [
        {"transport": "tls"},
        {"port": -1},
        {"port": True},
        {"queue_size": 0},
        {"max_line_bytes": 1000000},
        {"max_connections": 1000},
        {"tenant": "other tenant"},
    ],
)
def test_invalid_listener_settings_fail_before_binding(settings):
    with pytest.raises(ValueError):
        SyslogSettings(**settings)
