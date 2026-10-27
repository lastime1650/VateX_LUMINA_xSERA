"""Isolated UI QA server. Does not populate the user's default data directory."""

import argparse
import secrets
import sys
import tempfile
import time
from pathlib import Path

import uvicorn

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sapientia import detections
from sapientia.api import create_app
from sapientia.auth import create_user
from sapientia.runtime import run_due, save_rule
from sapientia.storage import Settings

parser = argparse.ArgumentParser()
parser.add_argument("--role", choices=["admin", "analyst", "viewer"], default="viewer")
args = parser.parse_args()
directory = Path(tempfile.mkdtemp(prefix="sapientia-ui-qa-"))
app = create_app(Settings(directory, min_free_bytes=0))
store = app.state.store
password = secrets.token_urlsafe(20)
name = "qa_" + args.role
create_user(store, name, password, args.role)
create_user(store, "qa-seeder", secrets.token_urlsafe(24), "analyst")
now = time.time()
store.ingest(
    "default",
    [
        {
            "event_id": f"qa-{i}",
            "event_time": now - 60 - i,
            "source": [
                "Palo Alto · QA",
                "CrowdStrike · QA",
                "Entra ID · QA",
                "VATEX · QA",
            ][i % 4],
            "host": f"qa-host-{i % 20:02d}",
            "severity": "high" if i % 5 == 0 else "info",
            "message": "SYNTHETIC UI QA — "
            + ("Repeated sign-in denied" if i % 5 == 0 else "Connection allowed"),
            "raw": {"synthetic": True, "bytes": i * 1024},
        }
        for i in range(600)
    ],
)
store.flush()
store.ingest(
    "default",
    [
        {
            "event_id": f"qa-chain-{i}",
            "event_time": now - 10 + i,
            "source": "SYNTHETIC UI QA",
            "host": "qa-host-00",
            "raw": {
                "user": "qa-investigation",
                "action": "login_failed" if i < 3 else "login_success",
            },
        }
        for i in range(4)
    ],
)
store.flush()
actor = {
    "tenant": "default",
    "name": "qa-seeder",
    "role": "analyst",
    "allowed_indexes": ["*"],
}
detections.save(
    store,
    actor,
    {
        "name": "QA · Repeated failure followed by success",
        "entity_field": "raw.user",
        "window": 900,
        "interval": 30,
        "cooldown": 900,
        "risk_score": 55,
        "severity": "high",
        "mitre": ["T1110", "T1078"],
        "steps": [
            {
                "name": "Three failures",
                "filters": [
                    {"field": "raw.action", "op": "eq", "value": "login_failed"}
                ],
                "min_count": 3,
            },
            {
                "name": "Then success",
                "filters": [
                    {"field": "raw.action", "op": "eq", "value": "login_success"}
                ],
            },
        ],
    },
)
detections.run_due(store, now + 1)
save_rule(
    store,
    {"tenant": "default", "name": "qa-seeder"},
    {
        "name": "QA · High severity signals",
        "query": {"query": "search severity=high"},
        "interval": 300,
        "lookback": 3600,
        "threshold": 3,
    },
)
run_due(store, now + 30)
print("QA_LOGIN", name, password, flush=True)
print("QA_DATA", directory, flush=True)
uvicorn.run(app, host="127.0.0.1", port=8788, proxy_headers=False)
