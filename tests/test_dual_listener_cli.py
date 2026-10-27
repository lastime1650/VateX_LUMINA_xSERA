"""Two bounded listeners share one app lifespan; no service or real ports used."""

import argparse
import asyncio
import ssl
import sys
from contextlib import asynccontextmanager, contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import ClassVar

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sapientia import __main__ as cli


def arguments(monkeypatch, *options):
    monkeypatch.setattr(sys, "argv", ["lumina-xsera", "serve", *options])


@pytest.mark.parametrize(
    "options",
    [
        ["--port", "0"],
        ["--port", "65536"],
        ["--cert", "missing"],
        ["--key", "missing"],
        ["--agent-port", "8788"],
        ["--agent-cert", "missing"],
        ["--agent-key", "missing"],
        ["--agent-host", "127.0.0.1"],
        ["--agent-port", "8787", "--agent-cert", "missing", "--agent-key", "missing"],
        ["--agent-port", "65536", "--agent-cert", "missing", "--agent-key", "missing"],
        ["--host", ""],
        ["--host", "bad host"],
        ["--agent-host", ""],
        ["--host", "0.0.0.0"],
    ],
)
def test_invalid_listener_configuration_never_creates_store(monkeypatch, options):
    from sapientia import api

    def forbidden(*args):
        pytest.fail("Invalid configuration opened the Store")

    monkeypatch.setattr(api, "create_app", forbidden)
    arguments(monkeypatch, *options)
    with pytest.raises(SystemExit) as stopped:
        cli.main()
    assert stopped.value.code == 2


def test_invalid_or_missing_local_tls_files_rejected_without_store(
    monkeypatch, tmp_path
):
    from sapientia import api

    monkeypatch.setattr(api, "create_app", lambda *a: pytest.fail("Store opened"))
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    for exists in (False, True):
        if exists:
            cert.write_text("not a certificate", encoding="utf-8")
            key.write_text("not a private key", encoding="utf-8")
        arguments(
            monkeypatch,
            "--agent-port",
            "8788",
            "--agent-cert",
            str(cert),
            "--agent-key",
            str(key),
        )
        with pytest.raises(SystemExit) as stopped:
            cli.main()
        assert stopped.value.code == 2


def test_tls_validation_loads_fresh_matching_local_chain_and_rejects_wrong_key(
    tmp_path,
):
    # This fixture is created only for local SSL parsing, never a running server,
    # operator CA, old QA certificate, or enrollment credential.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-cli-test")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    cert, private = tmp_path / "fresh-cert.pem", tmp_path / "fresh-key.pem"
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    parser = argparse.ArgumentParser()
    context = cli._tls_context(parser, str(cert), str(private), "Synthetic TLS")
    assert context.protocol == ssl.PROTOCOL_TLS_SERVER
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private.write_bytes(
        other.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(SystemExit) as stopped:
        cli._tls_context(parser, str(cert), str(private), "Synthetic TLS")
    assert stopped.value.code == 2


def test_legacy_single_listener_keeps_single_uvicorn_run(monkeypatch):
    from sapientia import api

    captured = {}

    def create(settings):
        captured["settings"] = settings
        captured["created"] = captured.get("created", 0) + 1
        return "one-app"

    monkeypatch.setattr(api, "create_app", create)
    monkeypatch.setitem(
        sys.modules,
        "uvicorn",
        SimpleNamespace(
            run=lambda app, **options: captured.update(app=app, options=options)
        ),
    )
    arguments(monkeypatch)
    cli.main()
    assert captured["created"] == 1 and captured["app"] == "one-app"
    assert (
        captured["options"]["host"] == "127.0.0.1"
        and captured["options"]["port"] == 8787
    )
    assert (
        captured["options"]["workers"] == 1
        and captured["options"]["proxy_headers"] is False
    )
    assert captured["options"]["ssl_certfile"] is None


@pytest.mark.parametrize("agent_host", [None, "0.0.0.0"])
def test_dual_dispatch_constructs_one_app_and_separate_tls_options(
    monkeypatch, agent_host
):
    from sapientia import api

    captured, tls = {"created": 0}, object()

    def create(settings):
        captured["created"] += 1
        return "one-app"

    monkeypatch.setattr(api, "create_app", create)
    monkeypatch.setattr(
        cli, "_tls_context", lambda parser, cert, key, label: tls if cert else None
    )
    monkeypatch.setattr(
        cli,
        "run_listeners",
        lambda app, gui, agent: captured.update(app=app, gui=gui, agent=agent),
    )
    monkeypatch.setitem(
        sys.modules,
        "uvicorn",
        SimpleNamespace(run=lambda *a, **k: pytest.fail("Single runner used twice")),
    )
    options = [
        "--agent-port",
        "8788",
        "--agent-cert",
        "synthetic-cert",
        "--agent-key",
        "synthetic-key",
    ]
    if agent_host is not None:
        options += ["--agent-host", agent_host]
    arguments(monkeypatch, *options)
    cli.main()
    assert captured["created"] == 1
    assert captured["gui"]["port"] == 8787 and captured["agent"]["port"] == 8788
    assert captured["gui"]["ssl_certfile"] is None
    assert captured["agent"]["host"] == (agent_host or "127.0.0.1")
    assert captured["agent"]["ssl_context_factory"](None, None) is tls
    assert all(
        captured[name]["workers"] == 1 and captured[name]["proxy_headers"] is False
        for name in ("gui", "agent")
    )


def mocked_runner(monkeypatch, behavior="normal", *, fail_bind=False):
    observations = {
        "entered": 0,
        "closed": 0,
        "signals": 0,
        "started": [],
        "cancelled": [],
        "sockets": [],
    }

    class Socket:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    class Config:
        def __init__(self, app, **options):
            self.app, self.options = app, options

        def bind_socket(self):
            if fail_bind and self.options["port"] == 8788:
                raise SystemExit(3)
            sock = Socket()
            observations["sockets"].append(sock)
            return sock

    class Server:
        instances: ClassVar[list] = []

        def __init__(self, config):
            self.config = config
            self.should_exit = False
            self.force_exit = False
            self.instances.append(self)

        @contextmanager
        def capture_signals(self):
            observations["signals"] += 1
            yield

        def handle_exit(self, sig, frame):
            self.should_exit = True

        async def serve(self, sockets):
            assert observations["entered"] == 1
            if self.config.options["port"] == 8788:
                from sapientia.api import AgentPlane

                assert (
                    isinstance(self.config.app, AgentPlane)
                    and self.config.app.app is app
                )
            else:
                assert self.config.app is app
            assert self.config.options["lifespan"] == "off"
            assert len(sockets) == 1
            port = self.config.options["port"]
            observations["started"].append(port)
            try:
                if port == 8787:
                    await asyncio.sleep(0)
                    if behavior == "both_wait":
                        while not self.should_exit:
                            await asyncio.sleep(0)
                        return
                    if behavior == "signal":
                        self.handle_exit(15, None)
                        assert all(server.should_exit for server in self.instances)
                    elif behavior == "failure":
                        raise RuntimeError("synthetic listener failure")
                    elif behavior == "exit":
                        raise SystemExit(7)
                    elif behavior == "outer_cancel":
                        raise asyncio.CancelledError()
                    return
                if behavior == "slow":
                    await asyncio.Event().wait()
                while not self.should_exit:
                    await asyncio.sleep(0)
            except asyncio.CancelledError:
                observations["cancelled"].append(port)
                raise

    @asynccontextmanager
    async def lifespan(instance):
        assert instance is app
        observations["entered"] += 1
        yield  # Deliberately mirrors legacy app's normal-only post-yield close.
        observations["closed"] += 1

    app = SimpleNamespace(router=SimpleNamespace(lifespan_context=lifespan))
    monkeypatch.setitem(
        sys.modules, "uvicorn", SimpleNamespace(Config=Config, Server=Server)
    )
    return app, observations, Server


@pytest.mark.parametrize(
    "behavior,error",
    [
        ("normal", None),
        ("signal", None),
        ("failure", RuntimeError),
        ("exit", SystemExit),
        ("outer_cancel", asyncio.CancelledError),
    ],
)
def test_one_lifecycle_on_normal_signal_and_every_listener_error(
    monkeypatch, behavior, error
):
    app, observed, server = mocked_runner(monkeypatch, behavior)
    if error:
        with pytest.raises(error):
            cli.run_listeners(app, {"port": 8787}, {"port": 8788})
    else:
        cli.run_listeners(app, {"port": 8787}, {"port": 8788})
    assert observed["entered"] == observed["closed"] == 1
    assert observed["signals"] == 1
    assert set(observed["started"]) == {8787, 8788}
    assert all(item.should_exit for item in server.instances)
    assert all(sock.closed for sock in observed["sockets"])


def test_second_socket_bind_failure_closes_first_and_one_lifecycle(monkeypatch):
    app, observed, _ = mocked_runner(monkeypatch, fail_bind=True)
    with pytest.raises(SystemExit) as stopped:
        cli.run_listeners(app, {"port": 8787}, {"port": 8788})
    assert stopped.value.code == 3
    assert observed["entered"] == observed["closed"] == 1
    assert not observed["started"] and all(sock.closed for sock in observed["sockets"])


def test_slow_listener_is_cancelled_after_bounded_cooperative_join(monkeypatch):
    app, observed, _ = mocked_runner(monkeypatch, "slow")
    monkeypatch.setattr(cli, "LISTENER_GRACE_SECONDS", -0.99)
    with pytest.raises(asyncio.CancelledError):
        cli.run_listeners(app, {"port": 8787}, {"port": 8788})
    assert observed["cancelled"] == [8788]
    assert observed["entered"] == observed["closed"] == 1
    assert all(sock.closed for sock in observed["sockets"])


def test_partial_runtime_start_failure_closes_once_without_second_store(monkeypatch):
    observations = []

    @asynccontextmanager
    async def broken(instance):
        raise RuntimeError("synthetic partial start")
        yield

    app = SimpleNamespace(
        router=SimpleNamespace(lifespan_context=broken),
        state=SimpleNamespace(
            runtime=SimpleNamespace(close=lambda: observations.append("runtime")),
            store=SimpleNamespace(close=lambda: observations.append("store")),
        ),
    )
    with pytest.raises(RuntimeError, match="partial start"):
        cli.run_listeners(app, {"port": 8787}, {"port": 8788})
    assert observations == ["runtime", "store"]


def test_coordinator_cancellation_stops_pair_before_closing_single_lifecycle(
    monkeypatch,
):
    app, observed, servers = mocked_runner(monkeypatch, "both_wait")

    async def exercise():
        task = asyncio.create_task(
            cli._run_listeners(app, [{"port": 8787}, {"port": 8788}])
        )
        while len(observed["started"]) != 2:
            await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(exercise())
    assert observed["entered"] == observed["closed"] == 1
    assert all(server.should_exit for server in servers.instances)
    assert all(sock.closed for sock in observed["sockets"])
