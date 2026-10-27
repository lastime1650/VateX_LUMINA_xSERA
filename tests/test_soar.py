import datetime
import http.server
import ipaddress
import json
import queue
import ssl
import threading
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sapientia import access, auth, casework, soar
from sapientia.storage import CapacityError, ConflictError, Settings, Store, encode


def user(name="maker", scope=None, tenant="a", role="analyst"):
    return {
        "name": name,
        "tenant": tenant,
        "role": role,
        "allowed_indexes": ["*"] if scope is None else scope,
    }


@pytest.fixture
def case(tmp_path):
    store = Store(Settings(tmp_path / "data", min_free_bytes=0))
    soar.initialize(store)
    for name, tenant, role in [
        ("maker", "a", "analyst"),
        ("approver", "a", "analyst"),
        ("admin_a", "a", "admin"),
        ("viewer_a", "a", "viewer"),
        ("outsider", "b", "analyst"),
    ]:
        auth.create_user(store, name, "Synthetic-soar-password-2026", role, tenant)
    with store.control() as db:
        db.execute(
            "INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                "incident-a",
                "a",
                "alice",
                "raw.user",
                "Synthetic incident",
                time.time(),
                time.time(),
                "new",
                "",
                1,
            ),
        )
        db.execute(
            "INSERT INTO risk_contributions VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                "fact-a",
                "a",
                "incident-a",
                "policy-a",
                "alice",
                "raw.user",
                time.time(),
                30,
                encode({"event_ids": ["e1"]}),
                encode(["public"]),
            ),
        )
    yield store, "incident-a"
    store.close()


def book(*actions, version=0):
    return {
        "name": "Investigate and respond",
        "version": version,
        "steps": [
            {"id": "s" + str(n), "action": action, "retry_base": 1}
            for n, action in enumerate(
                actions or ({"type": "add_note", "note": "Evidence reviewed"},)
            )
        ],
    }


def run(case, definition=None, approve=True, request_id="request-a"):
    store, incident = case
    playbook = soar.save(store, user(), definition or book())
    item = soar.start_run(store, user(), playbook["id"], incident, request_id)
    if approve:
        soar.approve(store, user("approver"), item["id"])
    return playbook, item


def counts(store):
    with store.control() as db:
        return tuple(
            db.execute(
                "SELECT (SELECT count(*) FROM case_notes),(SELECT count(*) FROM case_action_receipts)"
            ).fetchone()
        )


def test_independent_approval_and_idempotent_request(case):
    store, incident = case
    playbook, item = run(case, approve=False)
    assert soar.run_due(store) == 0 and counts(store) == (0, 0)
    with pytest.raises(PermissionError, match="independent"):
        soar.approve(store, user(), item["id"])
    with pytest.raises(PermissionError):
        soar.approve(store, user("viewer_a", role="viewer"), item["id"])
    with pytest.raises(KeyError):
        soar.approve(store, user("outsider", tenant="b"), item["id"])
    assert soar.start_run(store, user(), playbook["id"], incident, "request-a")[
        "duplicate"
    ]
    with pytest.raises(ConflictError):
        soar.start_run(store, user(), playbook["id"], "different", "request-a")
    approved = soar.approve(store, user("approver"), item["id"])
    assert len(approved["approval_digest"]) == 64
    assert soar.run_due(store) == 1
    assert soar.get_run(store, user(), item["id"])["state"] == "completed"
    assert soar.run_due(store) == 0 and counts(store) == (1, 1)


def test_immutable_revision_and_local_workplan(case):
    store, incident = case
    definition = book(
        {
            "type": "add_task",
            "title": "Check evidence",
            "assignee": "maker",
            "mandatory": True,
        },
        {"type": "add_note", "note": "Checked original evidence"},
        {"type": "set_status", "status": "triage", "note": "Human review approved"},
    )
    playbook, item = run(case, definition)
    soar.save(
        store,
        user(),
        book({"type": "add_note", "note": "Different future revision"}, version=1),
        playbook["id"],
    )
    with pytest.raises(ConflictError):
        soar.save(store, user(), book(version=0), playbook["id"])
    for _ in range(3):
        assert soar.run_due(store) == 1
    result = soar.get_run(store, user(), item["id"])
    assert result["revision"] == 1 and result["state"] == "completed"
    assert all(
        s["state"] == "completed" and s["attempts"] == 1 for s in result["steps"]
    )
    workspace = casework.workspace(store, user(), incident)
    assert (
        workspace["tasks"][0]["mandatory"]
        and workspace["incident"]["status"] == "triage"
    )
    assert workspace["notes"][0]["note"] == "Checked original evidence"


@pytest.mark.parametrize("account", ["maker", "approver"])
@pytest.mark.parametrize("change", ["disabled", "role", "must_change", "scope"])
def test_execution_rechecks_both_active_principals(case, account, change):
    store, _ = case
    _, item = run(case)
    if change == "scope":
        access.set_for_user(store, user("admin_a", role="admin"), account, [])
    else:
        with store.control() as db:
            db.execute(
                "UPDATE users SET " + change + "=? WHERE name=?",
                ("viewer" if change == "role" else 1, account),
            )
    assert soar.run_due(store) == 1 and counts(store) == (0, 0)
    assert (
        soar.get_run(store, user("admin_a", role="admin"), item["id"])["state"]
        == "failed"
    )


def test_current_read_scope_private_evidence_and_snapshot_change(case):
    store, incident = case
    _, item = run(case, approve=False)
    with store.control() as db:
        db.execute(
            "INSERT INTO case_bookmarks VALUES(?,?,?,?,?,?,?,?,?)",
            (
                "bookmark-private",
                "a",
                incident,
                "p1",
                "private",
                "Private artifact",
                "maker",
                time.time(),
                encode({"message": "private"}),
            ),
        )
    with pytest.raises(KeyError):
        soar.get_run(store, user(scope=["public"]), item["id"])
    assert soar.list_runs(store, user(scope=["public"]))["runs"] == []
    with pytest.raises(ConflictError, match="changed"):
        soar.approve(store, user("approver"), item["id"])
    _, fresh = run(case, request_id="request-b")
    access.set_for_user(store, user("admin_a", role="admin"), "maker", ["public"])
    assert soar.run_due(store) == 1
    assert (
        soar.get_run(store, user("admin_a", role="admin"), fresh["id"])["state"]
        == "failed"
    )
    assert counts(store) == (0, 0)


def test_changed_incident_or_approval_digest_fails_closed(case):
    store, incident = case
    run(case)
    with store.control() as db:
        db.execute("UPDATE incidents SET version=version+1 WHERE id=?", (incident,))
    assert soar.run_due(store) == 1 and counts(store) == (0, 0)
    _, next_item = run(case, request_id="request-b")
    with store.control() as db:
        db.execute(
            "UPDATE soar_runs SET approval_digest='tampered' WHERE id=?",
            (next_item["id"],),
        )
    assert soar.run_due(store) == 1 and counts(store) == (0, 0)


def test_atomic_crash_rollback_and_restart(case, monkeypatch):
    store, _ = case
    _, item = run(case)
    original = soar._finish

    class Crash(BaseException):
        pass

    def crash(*args):
        raise Crash()

    monkeypatch.setattr(soar, "_finish", crash)
    with pytest.raises(Crash):
        soar.run_due(store)
    assert counts(store) == (0, 0)
    monkeypatch.setattr(soar, "_finish", original)
    settings = store.settings
    store.close()
    reopened = Store(settings)
    soar.initialize(reopened)
    try:
        assert soar.run_due(reopened) == 1
        assert soar.get_run(reopened, user(), item["id"])["state"] == "completed"
        assert counts(reopened) == (1, 1)
    finally:
        reopened.close()


def test_retry_backoff_and_cancellation(case, monkeypatch):
    store, _ = case
    _, item = run(case)
    original = casework.apply_action
    monkeypatch.setattr(
        casework,
        "apply_action",
        lambda *args: (_ for _ in ()).throw(CapacityError("synthetic capacity")),
    )
    now = time.time() + 1
    assert soar.run_due(store, now) == 1
    result = soar.get_run(store, user(), item["id"])
    assert result["state"] == "retry" and result["steps"][0]["attempts"] == 1
    assert soar.run_due(store, now + 0.5) == 0
    monkeypatch.setattr(casework, "apply_action", original)
    assert soar.run_due(store, now + 1.1) == 1 and counts(store) == (1, 1)
    _, other = run(case, request_id="request-b")
    soar.cancel_run(store, user("approver"), other["id"])
    assert soar.run_due(store, now + 20) == 0
    assert soar.get_run(store, user(), other["id"])["state"] == "cancelled"
    stop = threading.Event()
    stop.set()
    _, third = run(case, request_id="request-c")
    assert soar.run_due(store, now + 30, cancel=stop) == 0
    assert soar.get_run(store, user(), third["id"])["state"] == "queued"


def test_required_task_blocks_resolution_and_no_partial_action(case):
    store, _ = case
    _, item = run(
        case,
        book(
            {"type": "add_task", "title": "Required", "mandatory": True},
            {"type": "set_status", "status": "resolved", "note": "Cannot skip task"},
        ),
    )
    soar.run_due(store)
    soar.run_due(store)
    result = soar.get_run(store, user(), item["id"])
    assert result["state"] == "failed" and result["steps"][0]["state"] == "completed"
    assert result["steps"][1]["result"] is None


def test_limits_and_external_default_disabled(case):
    store, incident = case
    for definition in (
        book(*([{"type": "add_note", "note": "a"}] * 17)),
        book({"type": "arbitrary_shell", "command": "none"}),
        book({"type": "add_note", "note": "a" * 8001}),
    ):
        with pytest.raises(ValueError):
            soar.save(store, user(), definition)
    playbook = soar.save(
        store,
        user(),
        book({"type": "webhook", "destination": "disabled", "payload": {}}),
    )
    with pytest.raises(ValueError, match="not enabled"):
        soar.start_run(store, user(), playbook["id"], incident, "external-default-off")
    with pytest.raises(ValueError):
        soar.Webhooks(
            {
                "allow_hosts": ["127.0.0.1"],
                "destinations": {
                    "a": {
                        "url": "http://127.0.0.1",
                        "secret_env": "SOAR_FIXTURE_SECRET",
                        "idempotency_guaranteed": False,
                    }
                },
            }
        )


@pytest.fixture
def tls_peer(tmp_path, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Local SOAR fixture")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "fixture-cert.pem", tmp_path / "fixture-key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    calls, behavior = [], {"status": 200, "delay": 0}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            payload = self.rfile.read(int(self.headers["Content-Length"]))
            calls.append(
                {
                    "key": self.headers.get("Idempotency-Key"),
                    "payload": json.loads(payload),
                    "authenticated": self.headers.get("Authorization")
                    == "Bearer " + "s" * 48,
                }
            )
            time.sleep(behavior["delay"])
            try:
                self.send_response(behavior["status"])
                if behavior["status"] == 302:
                    self.send_header("Location", "https://excluded.invalid/")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")
            except OSError:
                pass

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_path, key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("SOAR_FIXTURE_SECRET", "s" * 48)
    config = {
        "allow_hosts": ["127.0.0.1"],
        "destinations": {
            "fixture": {
                "url": "https://127.0.0.1:" + str(server.server_port) + "/action",
                "secret_env": "SOAR_FIXTURE_SECRET",
                "idempotency_guaranteed": False,
            }
        },
    }
    yield config, ssl.create_default_context(cafile=str(cert_path)), calls, behavior
    server.shutdown()
    server.server_close()
    thread.join(2)


def test_configured_https_action_and_bounded_result(case, tls_peer):
    store, _ = case
    config, context, calls, _ = tls_peer
    store.soar_webhooks = soar.Webhooks(config, allow_loopback=True, context=context)
    _, item = run(
        case,
        book(
            {"type": "webhook", "destination": "fixture", "payload": {"case": "test"}}
        ),
    )
    assert soar.run_due(store) == 1
    result = soar.get_run(store, user(), item["id"])
    assert result["state"] == "completed" and result["steps"][0]["attempts"] == 1
    assert calls[0]["authenticated"] and calls[0]["key"] == item["id"] + ":s0"
    assert result["steps"][0]["result"]["status_code"] == 200
    assert "s" * 48 not in encode(result)


@pytest.mark.parametrize("mode", ["redirect", "timeout", "crash"])
def test_unknown_external_outcome_never_unsafe_replays(case, tls_peer, mode):
    store, _ = case
    config, context, calls, behavior = tls_peer
    store.soar_webhooks = soar.Webhooks(config, allow_loopback=True, context=context)
    _, item = run(
        case, book({"type": "webhook", "destination": "fixture", "payload": {}})
    )
    if mode == "crash":
        with store.control() as db:
            db.execute(
                "UPDATE soar_runs SET state='sending',next_run=0 WHERE id=?",
                (item["id"],),
            )
            db.execute(
                "UPDATE soar_steps SET state='sending',attempts=1,lease_until=0,attempt_token='prior-crash' WHERE run_id=?",
                (item["id"],),
            )
    else:
        behavior["status"] = 302 if mode == "redirect" else 200
        behavior["delay"] = 0.4 if mode == "timeout" else 0
    assert soar.run_due(store, budget=0.15 if mode == "timeout" else 1) == 1
    assert soar.get_run(store, user(), item["id"])["state"] == "unknown"
    assert soar.run_due(store, time.time() + 100) == 0
    assert len(calls) == (0 if mode == "crash" else 1)


def test_peer_idempotency_contract_allows_same_key_retry(case, tls_peer):
    store, _ = case
    config, context, calls, behavior = tls_peer
    config["destinations"]["fixture"]["idempotency_guaranteed"] = True
    store.soar_webhooks = soar.Webhooks(config, allow_loopback=True, context=context)
    _, item = run(
        case, book({"type": "webhook", "destination": "fixture", "payload": {}})
    )
    behavior["status"] = 500
    now = time.time() + 1
    assert soar.run_due(store, now) == 1
    assert soar.get_run(store, user(), item["id"])["state"] == "retry"
    behavior["status"] = 200
    assert soar.run_due(store, now + 2) == 1
    assert calls[0]["key"] == calls[1]["key"]
    assert soar.get_run(store, user(), item["id"])["state"] == "completed"


def test_webhook_config_change_and_private_network_fail_closed(case, tls_peer):
    store, _ = case
    config, context, calls, _ = tls_peer
    store.soar_webhooks = soar.Webhooks(config, context=context)
    _, item = run(
        case, book({"type": "webhook", "destination": "fixture", "payload": {}})
    )
    soar.run_due(store)
    assert soar.get_run(store, user(), item["id"])["state"] == "failed" and calls == []
    store.soar_webhooks = soar.Webhooks(config, allow_loopback=True, context=context)
    _, second = run(
        case,
        book({"type": "webhook", "destination": "fixture", "payload": {}}),
        request_id="request-b",
    )
    store.soar_webhooks = soar.Webhooks()
    soar.run_due(store)
    assert (
        soar.get_run(store, user(), second["id"])["state"] == "failed" and calls == []
    )


def test_dns_deadline_has_bounded_background_resolvers(monkeypatch):
    config = {
        "allow_hosts": ["fixture.invalid"],
        "destinations": {
            "fixture": {
                "url": "https://fixture.invalid/action",
                "secret_env": "SOAR_FIXTURE_SECRET",
                "idempotency_guaranteed": False,
            }
        },
    }
    client = soar.Webhooks(config)
    monkeypatch.setenv("SOAR_FIXTURE_SECRET", "s" * 48)
    stop, calls = threading.Event(), []

    def stalled(*args, **kwargs):
        calls.append(1)
        stop.wait(1)
        raise OSError("synthetic DNS unavailable")

    monkeypatch.setattr(soar.socket, "getaddrinfo", stalled)
    try:
        for _ in range(2):
            with pytest.raises(queue.Empty):
                client.send("fixture", b"{}", "stable", 0.02)
        with pytest.raises(CapacityError, match="DNS quota"):
            client.send("fixture", b"{}", "stable", 0.02)
        assert len(calls) == 2
    finally:
        stop.set()


@pytest.mark.parametrize("status", [[], {}, 1, None])
def test_malformed_action_status_is_validation_error(status):
    with pytest.raises(ValueError):
        soar.validate(book({"type": "set_status", "status": status, "note": "invalid"}))


def test_cancellation_after_dispatch_preserves_ack_and_stops_next_step(
    case, tls_peer, monkeypatch
):
    store, _ = case
    config, context, _, _ = tls_peer
    store.soar_webhooks = soar.Webhooks(config, allow_loopback=True, context=context)
    _, item = run(
        case,
        book(
            {"type": "webhook", "destination": "fixture", "payload": {}},
            {"type": "add_note", "note": "Must not run after cancellation"},
        ),
    )

    def acknowledge_after_cancel(*args):
        soar.cancel_run(store, user("approver"), item["id"])
        return {"type": "webhook", "outcome": "acknowledged", "status_code": 200}

    monkeypatch.setattr(store.soar_webhooks, "send", acknowledge_after_cancel)
    assert soar.run_due(store) == 1
    result = soar.get_run(store, user(), item["id"])
    assert result["state"] == "cancelled" and result["steps"][0]["state"] == "completed"
    assert result["steps"][1]["state"] == "cancelled" and counts(store) == (0, 0)
