import argparse
import asyncio
import getpass
import json
import ssl
import sys
import time
from contextlib import contextmanager
from pathlib import Path

from .storage import Settings, Store

LISTENER_GRACE_SECONDS = 5


def _tls_context(parser, certificate, key, label):
    if bool(certificate) != bool(key):
        parser.error(label + " requires a complete certificate/key pair")
    if not certificate:
        return None
    if not Path(certificate).is_file() or not Path(key).is_file():
        parser.error(label + " certificate/key must be existing local files")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        # The CLI has no interactive private-key password protocol. Never let
        # OpenSSL block a service startup on an implicit password prompt.
        context.load_cert_chain(certificate, key, password=lambda: "")
    except (OSError, ssl.SSLError, ValueError):
        parser.error(label + " certificate/key pair is invalid or unsupported")
    return context


async def _run_listeners(app, listener_options):
    """One app lifespan for both listeners; no second Store or scheduler.

    Uvicorn's bounded connection grace is shared with a bounded cooperative
    task join. Existing runtime/native IO shutdown safeguards are unchanged.
    """
    import uvicorn

    class ManagedServer(uvicorn.Server):
        @contextmanager
        def capture_signals(self):
            # The coordinator owns one signal context for the entire pair.
            yield

    failure = None
    entered = False
    try:
        async with app.router.lifespan_context(app):
            entered = True
            sockets, tasks, servers = [], [], []
            try:
                from .api import AgentPlane

                for number, options in enumerate(listener_options):
                    listener_app = AgentPlane(app) if number == 1 else app
                    config = uvicorn.Config(listener_app, lifespan="off", **options)
                    servers.append(ManagedServer(config))
                    sockets.append(config.bind_socket())
                handlers = [server.handle_exit for server in servers]

                def stop_pair(sig, frame):
                    for handler in handlers:
                        handler(sig, frame)

                servers[0].handle_exit = stop_pair

                async def serve_one(server, sock):
                    try:
                        await server.serve(sockets=[sock])
                    except BaseException as exc:  # noqa: BLE001 - Contain startup SystemExit/cancellation; preserve and rethrow after one lifecycle cleanup.
                        return exc
                    return None

                with uvicorn.Server.capture_signals(servers[0]):
                    try:
                        tasks = [
                            asyncio.create_task(serve_one(server, sock))
                            for server, sock in zip(servers, sockets)
                        ]
                        done, _ = await asyncio.wait(
                            tasks, return_when=asyncio.FIRST_COMPLETED
                        )
                        for task in tasks:
                            if task in done and task.result() is not None:
                                failure = task.result()
                                break
                    finally:
                        for server in servers:
                            server.should_exit = True
                        if tasks:
                            _, pending = await asyncio.wait(
                                tasks, timeout=LISTENER_GRACE_SECONDS + 1
                            )
                            for task in pending:
                                task.cancel()
                            if pending:
                                _, remaining = await asyncio.wait(pending, timeout=1)
                                if remaining:
                                    raise RuntimeError(
                                        "Listener task did not stop within its cooperative shutdown budget"
                                    )
                            # Retrieve every result, including cancellation/startup
                            # failures, without allowing one to skip lifespan close.
                            for task in tasks:
                                result = task.result()
                                if failure is None and result is not None:
                                    failure = result
            except BaseException as exc:  # noqa: BLE001 - Suppress inside lifespan so legacy app cleanup after yield always runs; rethrow below.
                if failure is None:
                    failure = exc
            finally:
                for sock in sockets:
                    sock.close()
    except BaseException:
        # Failed lifespan entry can have partially started workers. Runtime's
        # existing guard prevents closing a database while a worker is alive.
        if not entered:
            app.state.runtime.close()
            app.state.store.close()
        raise
    if failure is not None:
        raise failure


def run_listeners(app, gui_options, agent_options):
    asyncio.run(_run_listeners(app, [gui_options, agent_options]))


def archive_operation(function, *args, **kwargs):
    from .archive_sink import ArchiveFetchError, ArchivePublishError

    try:
        return function(*args, **kwargs)
    except (ArchivePublishError, ArchiveFetchError) as exc:
        print(
            json.dumps({"error": str(exc), "report": exc.report}, indent=2),
            file=sys.stderr,
        )
        raise SystemExit(1) from None


def main():
    parser = argparse.ArgumentParser(
        prog="xsera", description="Vatex xSERA XDR"
    )
    parser.add_argument("--data", type=Path, default=Path("data"))
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8787)
    serve.add_argument("--cert")
    serve.add_argument("--key")
    serve.add_argument(
        "--agent-port",
        type=int,
        help="Optional dedicated TLS listener sharing the GUI app and Store",
    )
    serve.add_argument("--agent-host", help="TLS listener binding; defaults to --host")
    serve.add_argument("--agent-cert")
    serve.add_argument("--agent-key")
    serve.add_argument("--cluster", type=Path)
    serve.add_argument("--oidc-config", type=Path)
    serve.add_argument("--federation-config", type=Path)
    serve.add_argument("--qualification-keys", type=Path,
                       help="Externally provisioned public keys for independently signed qualification receipts")
    serve.add_argument("--query-workers", type=int, default=4)
    serve.add_argument("--query-timeout", type=float, default=15)
    serve.add_argument("--memory-limit", default="512MB")
    serve.add_argument("--fts-budget-gib", type=int, default=8)
    serve.add_argument("--reserve-gib", type=float, default=1)
    serve.add_argument("--max-queue", type=int, default=100000)
    serve.add_argument("--max-tenant-queue", type=int, default=25000)
    serve.add_argument("--indexing-batch", type=int, default=5000)
    serve.add_argument("--indexing-budget", type=float, default=0.25)
    serve.add_argument("--indexing-idle", type=float, default=0.25)
    serve.add_argument("--syslog-host", default="127.0.0.1")
    serve.add_argument("--syslog-port", type=int)
    serve.add_argument(
        "--syslog-transport", choices=["udp", "tcp", "tls"], default="tls"
    )
    serve.add_argument("--syslog-tenant", default="default")
    serve.add_argument("--syslog-cert")
    serve.add_argument("--syslog-key")
    serve.add_argument(
        "--syslog-client-ca",
        help="Require and verify client certificates against this CA",
    )
    serve.add_argument(
        "--syslog-peer-bindings",
        type=Path,
        help="JSON SHA256 certificate fingerprint -> exact tenant/index",
    )
    serve.add_argument(
        "--appliance-setup",
        action="store_true",
        help="Allow first administrator enrollment over direct HTTPS on a trusted management network",
    )
    user = sub.add_parser("create-user")
    user.add_argument("name")
    user.add_argument("--tenant", default="default")
    user.add_argument("--role", choices=["admin", "analyst", "viewer"], default="admin")
    sub.add_parser("status")
    fulltext = sub.add_parser(
        "rebuild-fts",
        help="Rebuild the complete local full-text index with the service stopped",
    )
    fulltext.add_argument("--max-seconds", type=int, default=7200)
    fulltext.add_argument("--fts-budget-gib", type=int, default=8)
    fulltext.add_argument("--memory-limit", default="512MB")
    repack = sub.add_parser(
        "repack-logs",
        help="Rewrite oversized Parquet row groups with the service stopped",
    )
    repack.add_argument("--max-files", type=int, default=8)
    repack.add_argument("--max-seconds", type=float, default=60)
    repack.add_argument("--memory-limit", default="512MB")
    repack.add_argument("--reserve-gib", type=float, default=1)
    snapshot = sub.add_parser("backup")
    snapshot.add_argument("destination", type=Path)
    snapshot.add_argument("--encrypt", action="store_true")
    snapshot.add_argument(
        "--legacy-encryption",
        action="store_true",
        help="Use the legacy single-file encrypted format",
    )
    snapshot.add_argument(
        "--archive-config",
        type=Path,
        help="Publish encrypted bundle to a versioned S3 Object Lock bucket",
    )
    recovery = sub.add_parser("restore")
    recovery.add_argument("source", type=Path)
    recovery.add_argument("--encrypted", action="store_true")
    publish = sub.add_parser(
        "archive-publish",
        help="Publish an existing encrypted format-2 bundle to S3 Object Lock",
    )
    publish.add_argument("source", type=Path)
    publish.add_argument("--config", type=Path, required=True)
    fetch = sub.add_parser(
        "archive-fetch",
        help="Fetch pinned S3 Object Lock versions as an encrypted local bundle",
    )
    fetch.add_argument("commit_key")
    fetch.add_argument("destination", type=Path)
    fetch.add_argument("--config", type=Path, required=True)
    fetch.add_argument(
        "--commit-version",
        help="Pin the exact commit object version recorded at publication",
    )
    args = parser.parse_args()
    if args.command == "serve":
        if (
            not args.host
            or not args.host.strip()
            or any(ord(c) < 33 for c in args.host)
        ):
            parser.error("Invalid GUI host")
        if args.agent_host is not None and (
            not args.agent_host
            or not args.agent_host.strip()
            or any(ord(c) < 33 for c in args.agent_host)
        ):
            parser.error("Invalid agent host")
        if not 1 <= args.port <= 65535:
            parser.error("Invalid GUI port")
        gui_tls = _tls_context(parser, args.cert, args.key, "GUI TLS")
        agent_options_present = any(
            value is not None
            for value in (
                args.agent_port,
                args.agent_host,
                args.agent_cert,
                args.agent_key,
            )
        )
        agent_tls = None
        if agent_options_present:
            if args.agent_port is None or not args.agent_cert or not args.agent_key:
                parser.error(
                    "Agent listener requires --agent-port, --agent-cert and --agent-key"
                )
            if not 1 <= args.agent_port <= 65535 or args.agent_port == args.port:
                parser.error("Agent port must be valid and distinct from GUI port")
            agent_tls = _tls_context(
                parser, args.agent_cert, args.agent_key, "Agent TLS"
            )
        if (
            not 1 <= args.query_workers <= 32
            or not 1 <= args.query_timeout <= 120
            or not 1 <= args.fts_budget_gib <= 1024
            or not 1 <= args.reserve_gib <= 1024
            or not 1 <= args.max_tenant_queue <= args.max_queue <= 10000000
            or not 1 <= args.indexing_batch <= 100000
            or not 0.01 <= args.indexing_budget <= 5
            or not 0.01 <= args.indexing_idle <= 5
        ):
            parser.error("Invalid worker, queue or indexing capacity setting")
        syslog_config = None
        if args.syslog_port is not None:
            if not 0 <= args.syslog_port <= 65535:
                parser.error("Invalid Syslog port")
            if (
                args.syslog_host not in {"127.0.0.1", "localhost", "::1"}
                and args.syslog_transport != "tls"
            ):
                parser.error("Remote Syslog binding requires TLS")
            context = None
            if args.syslog_transport == "tls":
                if not args.syslog_cert or not args.syslog_key:
                    parser.error("TLS Syslog requires --syslog-cert and --syslog-key")
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.load_cert_chain(args.syslog_cert, args.syslog_key)
                if args.syslog_client_ca:
                    context.load_verify_locations(cafile=args.syslog_client_ca)
                    context.verify_mode = ssl.CERT_REQUIRED
            if args.syslog_peer_bindings and not args.syslog_client_ca:
                parser.error("Syslog certificate bindings require --syslog-client-ca")
            if args.syslog_client_ca and args.syslog_transport != "tls":
                parser.error("Syslog client CA requires TLS transport")
            peer_bindings = None
            if args.syslog_peer_bindings:
                if args.syslog_peer_bindings.stat().st_size > 65536:
                    parser.error("Syslog peer bindings exceed 64 KiB")
                peer_bindings = json.loads(
                    args.syslog_peer_bindings.read_text(encoding="utf-8")
                )
            syslog_config = {
                "host": args.syslog_host,
                "port": args.syslog_port,
                "transport": args.syslog_transport,
                "tenant": args.syslog_tenant,
                "ssl_context": context,
                "peer_bindings": peer_bindings,
            }
        if args.host not in {"127.0.0.1", "::1", "localhost"} and not (
            args.cert and args.key
        ):
            parser.error(
                "Remote binding requires --cert and --key; loopback HTTP is local development only"
            )
        import uvicorn

        from .api import create_app

        # One writer/scheduler process. Scaling uvicorn workers is not supported.
        app = create_app(
            Settings(
                args.data,
                cluster=args.cluster,
                appliance_setup=args.appliance_setup,
                oidc=args.oidc_config,
                federation=args.federation_config,
                qualification_keys=args.qualification_keys,
                workers=args.query_workers,
                query_timeout=args.query_timeout,
                memory_limit=args.memory_limit,
                fts_max_bytes=args.fts_budget_gib * 1024**3,
                min_free_bytes=int(args.reserve_gib * 1024**3),
                max_queue=args.max_queue,
                max_tenant_queue=args.max_tenant_queue,
                indexing_batch=args.indexing_batch,
                indexing_budget=args.indexing_budget,
                indexing_idle=args.indexing_idle,
                syslog=syslog_config,
            )
        )
        gui_options = {
            "host": args.host,
            "port": args.port,
            "workers": 1,
            "proxy_headers": False,
            "ssl_certfile": args.cert,
            "ssl_keyfile": args.key,
            "limit_concurrency": 64,
            "timeout_keep_alive": 5,
        }
        if gui_tls is not None:
            gui_options["ssl_context_factory"] = lambda config, default: gui_tls
        if agent_tls is None:
            uvicorn.run(app, **gui_options)
        else:
            # One process, one lifespan. URL/public CA distribution remains an
            # explicit operator environment configuration, never inferred here.
            gui_options["timeout_graceful_shutdown"] = LISTENER_GRACE_SECONDS
            agent_options = {
                **gui_options,
                "host": args.agent_host or args.host,
                "port": args.agent_port,
                "ssl_certfile": args.agent_cert,
                "ssl_keyfile": args.agent_key,
                "ssl_context_factory": lambda config, default: agent_tls,
            }
            run_listeners(app, gui_options, agent_options)
    elif args.command == "rebuild-fts":
        if not 1 <= args.max_seconds <= 86400 or not 1 <= args.fts_budget_gib <= 1024:
            parser.error("Invalid full-text disk budget or rebuild duration")
        data = args.data.resolve()
        if (
            not (data / "control.sqlite3").is_file()
            or not (data / "events.duckdb").is_file()
        ):
            parser.error(
                "Full-text rebuild requires an existing initialized data directory"
            )
        from . import log_search

        store = Store(
            Settings(
                data,
                memory_limit=args.memory_limit,
                fts_max_bytes=args.fts_budget_gib * 1024**3,
            )
        )
        try:
            result = log_search.rebuild(store, time.monotonic() + args.max_seconds)
            print(json.dumps(result, indent=2))
        finally:
            store.close()
    elif args.command == "repack-logs":
        if (
            not 1 <= args.max_files <= 64
            or not 0.01 <= args.max_seconds <= 3600
            or not 1 <= args.reserve_gib <= 1024
        ):
            parser.error("Invalid log repack file, time or disk reserve limit")
        data = args.data.resolve()
        if (
            not (data / "control.sqlite3").is_file()
            or not (data / "events.duckdb").is_file()
        ):
            parser.error("Log repack requires an existing initialized data directory")
        store = Store(
            Settings(
                data,
                memory_limit=args.memory_limit,
                min_free_bytes=int(args.reserve_gib * 1024**3),
            )
        )
        try:
            result = store.segments.repack(
                max_files=args.max_files, max_seconds=args.max_seconds
            )
            print(json.dumps(result, indent=2))
        finally:
            store.close()
        if not result["complete"]:
            raise SystemExit(2)
    elif args.command in {"backup", "restore"}:
        from .backup import backup, backup_encrypted, restore, restore_encrypted

        encrypted = (
            (args.encrypt or args.legacy_encryption)
            if args.command == "backup"
            else args.encrypted
        )
        if (
            args.command == "backup"
            and args.archive_config
            and (not encrypted or args.legacy_encryption)
        ):
            parser.error("Remote Object Lock publishing requires --encrypt format 2")
        if encrypted:
            passphrase = getpass.getpass("Backup passphrase (12+ characters): ")
            if args.command == "backup" and passphrase != getpass.getpass(
                "Repeat backup passphrase: "
            ):
                parser.error("Backup passphrases do not match")
            if args.command == "backup" and not args.legacy_encryption:
                import tempfile

                from .backup import _private_directory
                from .backup_stream import encrypt_snapshot

                with tempfile.TemporaryDirectory(prefix="xsera-backup-") as work:
                    _private_directory(Path(work), created=True)
                    consistent = Path(work) / "snapshot"
                    backup(args.data, consistent)
                    result = encrypt_snapshot(consistent, args.destination, passphrase)
            elif (
                args.command == "restore"
                and args.source.is_dir()
                and (args.source / "header.json").is_file()
            ):
                from .backup_stream import restore_bundle

                result = restore_bundle(args.source, args.data, passphrase)
            else:
                result = (
                    backup_encrypted(args.data, args.destination, passphrase)
                    if args.command == "backup"
                    else restore_encrypted(args.source, args.data, passphrase)
                )
        else:
            result = (
                backup(args.data, args.destination)
                if args.command == "backup"
                else restore(args.source, args.data)
            )

        if args.command == "backup" and args.archive_config:
            from .archive_sink import publish_bundle

            if args.archive_config.stat().st_size > 65536:
                parser.error("Archive configuration exceeds 64 KiB")
            result["archive"] = archive_operation(
                publish_bundle,
                args.destination,
                json.loads(args.archive_config.read_text(encoding="utf-8")),
            )
        print(
            json.dumps(
                result,
                indent=2,
            )
        )
    elif args.command in {"archive-publish", "archive-fetch"}:
        from .archive_sink import fetch_bundle, publish_bundle

        if args.config.stat().st_size > 65536:
            parser.error("Archive configuration exceeds 64 KiB")
        config = json.loads(args.config.read_text(encoding="utf-8"))
        result = (
            archive_operation(publish_bundle, args.source, config)
            if args.command == "archive-publish"
            else archive_operation(
                fetch_bundle,
                config,
                args.commit_key,
                args.destination,
                commit_version=args.commit_version,
            )
        )
        print(json.dumps(result, indent=2))
    else:
        store = Store(Settings(args.data))
        try:
            if args.command == "create-user":
                from .auth import create_user

                password = getpass.getpass("Password (12+ characters): ")
                if password != getpass.getpass("Repeat password: "):
                    parser.error("Passwords do not match")
                create_user(
                    store,
                    args.name,
                    password,
                    args.role,
                    args.tenant,
                    actor="local-operator",
                )
                print("User created. Stop CLI before starting the service.")
            else:
                print(json.dumps(store.health("default"), indent=2))
        finally:
            store.close()


if __name__ == "__main__":
    main()
