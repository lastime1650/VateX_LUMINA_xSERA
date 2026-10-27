"""Explicit loopback console QA using a fresh, marked synthetic-only store.

Run ``python tools/qa_console_server.py --role admin --port 8788``.
The generated login is ephemeral QA data. No live data is opened or imported.
"""

import argparse
import json
import os
import secrets
import sys
import tempfile
import time
from pathlib import Path

import uvicorn

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sapientia import xdr_bridge
from sapientia.api import create_app
from sapientia.auth import create_user
from sapientia.runtime import run_due, save_rule
from sapientia.storage import Settings
from tools.qa_console_seed import seed


def qa_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("QA port must be an integer") from None
    if not 1024 <= port <= 65535 or port == 8787:
        raise argparse.ArgumentTypeError(
            "QA port must be 1024..65535, excluding live 8787"
        )
    return port


def build(role="admin"):
    """Create fresh synthetic state before any Runtime background thread starts."""
    if role not in {"admin", "analyst", "viewer"}:
        raise ValueError("QA role must be admin, analyst or viewer")
    directory = Path(tempfile.mkdtemp(prefix="sapientia-console-qa-"))
    (directory / ".qa-synthetic-only").touch()
    app = create_app(Settings(directory, min_free_bytes=0))
    # A QA browser can never contact an operator-configured remote XDR server.
    app.state.xdr_bridge = xdr_bridge.Bridge()
    store = app.state.store
    try:
        name, password = "qa_" + role, secrets.token_urlsafe(24)
        create_user(store, name, password, role)
        seeder = name
        if role != "admin":
            seeder = "qa_fixture_admin"
            create_user(store, seeder, secrets.token_urlsafe(24), "admin")
        actor = {
            "tenant": "default",
            "name": seeder,
            "role": "admin",
            "allowed_indexes": ["*"],
        }
        now = time.time()
        store.ingest(
            "default",
            [
                {
                    "event_id": f"synthetic-console-{i}",
                    "event_time": now - 60 - i,
                    "source": [
                        "QA · Network",
                        "QA · Endpoint",
                        "QA · Identity",
                        "QA · Application",
                    ][i % 4],
                    "host": f"qa-host-{i % 20:02d}",
                    "severity": "high" if i % 5 == 0 else "info",
                    "message": "SYNTHETIC UI QA — "
                    + ("Sign-in denied" if i % 5 == 0 else "Connection allowed"),
                    "raw": {"test": {"synthetic": True}, "bytes": i * 1024},
                }
                for i in range(600)
            ],
        )
        store.flush()
        scenario = seed(store, actor)
        save_rule(
            store,
            actor,
            {
                "name": "QA · High severity signals",
                "query": {"query": "search severity=high"},
                "interval": 300,
                "lookback": 3600,
                "threshold": 3,
            },
        )
        run_due(store, now + 30)
        return app, {
            "name": name,
            "password": password,
            "directory": str(directory),
            "scenario": scenario,
        }
    except BaseException:
        app.state.runtime.close()
        store.close()
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--role", choices=["admin", "analyst", "viewer"], default="admin"
    )
    parser.add_argument("--port", type=qa_port, default=8788)
    args = parser.parse_args(argv)
    # This process is an isolated QA launcher; no operator XDR configuration is
    # loaded even when the calling shell has its production environment set.
    os.environ.pop("SAPIENTIA_XDR_CONFIG", None)
    app, details = build(args.role)
    try:
        print("QA_LOGIN", details["name"], details["password"], flush=True)
        print("QA_DATA", details["directory"], flush=True)
        print("QA_SCENARIO", json.dumps(details["scenario"]), flush=True)
        print("QA_URL", f"http://127.0.0.1:{args.port}", flush=True)
        uvicorn.run(app, host="127.0.0.1", port=args.port, proxy_headers=False)
    finally:
        if not app.state.store.closed:
            app.state.runtime.close()
            app.state.store.close()


if __name__ == "__main__":
    main()
