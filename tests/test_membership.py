import concurrent.futures
import hashlib
import json
import ssl
import threading
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from sapientia import __version__
from sapientia.api import create_app
from sapientia.auth import create_user
from sapientia.membership import Membership, PRODUCT, PROTOCOL, origin, request_peer
from sapientia.storage import CapacityError, ConflictError, Settings, Store

PASSWORD = "Appliance-link-secret-for-test-only"
WHO = {"name": "admin", "tenant": "default"}


@pytest.fixture
def fleet(tmp_path):
    stores = [Store(Settings(tmp_path / str(i), min_free_bytes=0)) for i in range(5)]
    nodes = []

    def transport(address, path, data=None, pin=None):
        node = nodes[int(address.split("node")[1].split(".")[0])]
        if path == "/api/cluster/peer/join":
            return node.accept(data)
        return node.peer_status(data)

    nodes.extend(Membership(s, transport) for s in stores)
    yield nodes
    for store in stores:
        store.close()


def master(node):
    return node.create(
        WHO, {"name": "SOC", "address": "https://node0.test", "password": PASSWORD}
    )


def join(node, number, peer=0):
    return node.join(
        WHO,
        {
            "address": f"https://node{number}.test",
            "peer": f"https://node{peer}.test",
            "password": PASSWORD,
        },
    )


def payload(number):
    return {
        "product": PRODUCT,
        "version": __version__,
        "protocol": PROTOCOL,
        "node_id": str(uuid.uuid4()),
        "address": f"https://device{number}.test",
        "certificate_pin": None,
        "password": PASSWORD,
    }


def test_five_appliances_and_slave_redirect(fleet):
    assert master(fleet[0])["role"] == "Master"
    assert join(fleet[1], 1)["role"] == "Slave 1"
    assert join(fleet[2], 2, peer=1)["role"] == "Slave 2"
    assert join(fleet[3], 3, peer=2)["role"] == "Slave 3"
    assert join(fleet[4], 4, peer=1)["role"] == "Slave 4"
    status = fleet[1].refresh()
    assert len(status["members"]) == 5
    assert [m["ordinal"] for m in status["members"]] == list(range(5))
    assert status["master_url"] == "https://node0.test"
    assert not status["data_replication_ready"]
    assert "credential" not in json.dumps(status)
    assert "password" not in json.dumps(status)
    assert Membership(fleet[1].store, fleet[1].transport).status()["role"] == "Slave 1"


def test_concurrent_authoritative_ranks_and_retry(fleet):
    master(fleet[0])
    requests = [payload(i) for i in range(8)]
    with concurrent.futures.ThreadPoolExecutor(8) as executor:
        results = list(executor.map(fleet[0].accept, requests))
    assert sorted(v["ordinal"] for v in results) == list(range(1, 9))
    retry = fleet[0].accept(requests[0])
    assert retry["ordinal"] == results[0]["ordinal"]
    assert len(fleet[0].status()["members"]) == 9
    with pytest.raises(ConflictError):
        fleet[0].accept({**requests[0], "address": "https://changed.test"})


def test_version_identity_and_password_are_required(fleet):
    master(fleet[0])
    for field, value in [
        ("version", "99.0.0"),
        ("product", "other"),
        ("protocol", 999),
    ]:
        with pytest.raises(ConflictError):
            fleet[0].accept({**payload(1), field: value})
    with pytest.raises(ValueError):
        fleet[0].accept({**payload(1), "password": "wrong-password-long-enough"})
    with pytest.raises(ValueError):
        fleet[0].accept({**payload(1), "node_id": "a" * 36})
    with pytest.raises(ConflictError):
        master(fleet[0])


def test_master_outage_never_promotes_slave(fleet):
    master(fleet[0])
    join(fleet[1], 1)

    def unavailable(*args, **kwargs):
        raise CapacityError("Master offline")

    fleet[1].transport = unavailable
    with pytest.raises(CapacityError):
        fleet[1].accept(payload(2))
    with pytest.raises(CapacityError):
        fleet[1].refresh()
    assert fleet[1].status()["role"] == "Slave 1"
    assert len(fleet[0].status()["members"]) == 2


def test_master_commit_file_crash_recovery(fleet, monkeypatch):
    import sapientia.membership as membership

    real_write = membership.atomic_json

    def failed_write(*args):
        raise OSError("simulated interrupted rename")

    monkeypatch.setattr(membership, "atomic_json", failed_write)
    with pytest.raises(OSError):
        master(fleet[0])
    monkeypatch.setattr(membership, "atomic_json", real_write)
    recovered = Membership(fleet[0].store, fleet[0].transport)
    assert recovered.status()["role"] == "Master"
    assert len(recovered.status()["members"]) == 1


def test_slave_join_retry_after_persistence_failure(fleet, monkeypatch):
    import sapientia.membership as membership

    master(fleet[0])
    real_write = membership.atomic_json

    def failed_write(*args):
        raise OSError("simulated disk error")

    monkeypatch.setattr(membership, "atomic_json", failed_write)
    with pytest.raises(OSError):
        join(fleet[1], 1)
    assert fleet[1].status()["role"] == "Standalone"
    monkeypatch.setattr(membership, "atomic_json", real_write)
    assert join(fleet[1], 1)["role"] == "Slave 1"
    assert len(fleet[0].status()["members"]) == 2


def test_member_credentials_cannot_read_other_group(fleet):
    master(fleet[0])
    join(fleet[1], 1)
    request = {k: fleet[1].node[k] for k in ("group_id", "node_id", "credential")}
    with pytest.raises(ValueError):
        fleet[0].peer_status({**request, "credential": "x" * 64})
    with pytest.raises(ConflictError):
        fleet[0].peer_status({**request, "group_id": "a" * 32})
    assert len(fleet[0].peer_status(request)["members"]) == 2


def test_join_preserves_local_events_and_credentials(fleet):
    master(fleet[0])
    store = fleet[1].store
    create_user(store, "existing", PASSWORD)
    store.ingest(
        "default", [{"event_id": "keep", "message": "preserve local evidence"}]
    )
    store.flush()
    join(fleet[1], 1)
    assert store.search("default", {"query": "search *"})["returned"] == 1
    with store.control() as db:
        assert db.execute("SELECT name FROM users").fetchone()[0] == "existing"


@pytest.mark.parametrize(
    "address",
    [
        "http://192.168.1.2:8443",
        "https://user:secret@node.test",
        "https://node.test/api",
        "https://node.test?x=1",
        "https://node.test#x",
        "https://node.test:0",
    ],
)
def test_unsafe_peer_addresses_rejected(address):
    with pytest.raises(ValueError):
        origin(address)


def test_canonical_origins():
    assert origin("https://NODE.test:443/") == "https://node.test"
    assert origin("http://[::1]:8787/") == "http://[::1]:8787"


def test_offline_backup_preserves_master_identity(tmp_path):
    from sapientia.backup import backup, restore

    data = tmp_path / "source"
    store = Store(Settings(data, min_free_bytes=0))
    membership = Membership(store)
    expected = master(membership)
    store.close()
    manifest = backup(data, tmp_path / "backup")
    assert "node-membership.json" in manifest["sha256"]
    restore(tmp_path / "backup", tmp_path / "restored")
    store = Store(Settings(tmp_path / "restored", min_free_bytes=0))
    try:
        recovered = Membership(store).status()
        assert recovered["node_id"] == expected["node_id"]
        assert recovered["group_id"] == expected["group_id"]
        assert recovered["role"] == "Master"
    finally:
        store.close()


def test_certificate_pin_checked_before_sending_secret(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    keyfile, certfile = tmp_path / "key.pem", tmp_path / "cert.pem"
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        address = "https://127.0.0.1:" + str(server.server_port)
        with pytest.raises(CapacityError):
            request_peer(address, "/join", {"password": PASSWORD}, "0" * 64)
        assert not received
        pin = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
        assert request_peer(address, "/join", {"password": PASSWORD}, pin) == {
            "ok": True
        }
        assert len(received) == 1
    finally:
        server.shutdown()
        server.server_close()
        worker.join(2)


def test_membership_admin_csrf_and_tenant_boundaries(tmp_path):
    app = create_app(Settings(tmp_path, min_free_bytes=0), background=False)
    with TestClient(app) as client:
        assert client.get("/api/cluster").status_code == 401
        assert client.get("/api/cluster/discovery").json()["mode"] == "standalone"
        create_user(app.state.store, "admin", PASSWORD)
        login = client.post(
            "/api/login", json={"name": "admin", "password": PASSWORD}
        ).json()
        data = {"name": "SOC", "address": "https://master.test", "password": PASSWORD}
        assert client.post("/api/cluster/master", json=data).status_code == 403
        client.headers["X-CSRF-Token"] = login["csrf"]
        assert client.post("/api/cluster/master", json=data).json()["role"] == "Master"
        create_user(app.state.store, "other_admin", PASSWORD, "admin", "other")
        login = client.post(
            "/api/login", json={"name": "other_admin", "password": PASSWORD}
        ).json()
        client.headers["X-CSRF-Token"] = login["csrf"]
        assert client.get("/api/cluster").status_code == 403
        create_user(app.state.store, "viewer", PASSWORD, "viewer")
        login = client.post(
            "/api/login", json={"name": "viewer", "password": PASSWORD}
        ).json()
        client.headers["X-CSRF-Token"] = login["csrf"]
        assert client.post("/api/cluster/master", json=data).status_code == 403
