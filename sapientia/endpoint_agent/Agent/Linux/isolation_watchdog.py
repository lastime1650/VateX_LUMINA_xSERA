"""Independent finite Linux isolation lease; removes one exact owned nft table.

No shell, global firewall flush, remote input, or agent credentials are accepted.
The parent arms this protected process before applying a network effect.
"""

import argparse
import json
import math
import os
import platform
import re
import sys
import time
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from Agent import operations
else:
    from .. import operations


def watch(directory, identifier):
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise PermissionError(
            "Native Linux root is required for the isolation watchdog"
        )
    if not isinstance(identifier, str) or not re.fullmatch(r"[0-9a-f]{32}", identifier):
        raise ValueError("Exact internal isolation receipt identity required")
    _directory, db = operations._state({"quarantine_dir": str(directory)})
    try:
        row = db.execute("SELECT * FROM isolation WHERE id=?", (identifier,)).fetchone()
        if not row or row["state"] not in {"preparing", "isolated"}:
            raise PermissionError("Active durable isolation receipt required")
        expires = row["expires"]
        if type(expires) not in (int, float) or not math.isfinite(expires):
            raise PermissionError("Finite durable isolation expiry required")
        remaining = expires - time.time()
        if not 0 < remaining <= 3600:
            raise PermissionError("Isolation lease is expired or exceeds the bound")
        with db:
            changed = db.execute(
                "UPDATE isolation SET guard_pid=? WHERE id=? AND guard_pid IS NULL AND state IN ('preparing','isolated')",
                (os.getpid(), identifier),
            ).rowcount
        if changed != 1:
            raise PermissionError("Another isolation safety guard owns this receipt")
        # The monotonic deadline cannot be extended by a wall clock rollback.
        deadline = time.monotonic() + remaining
        print(
            json.dumps({"isolation_id": identifier, "ready": True, "pid": os.getpid()}),
            flush=True,
        )
        while True:
            row = db.execute(
                "SELECT * FROM isolation WHERE id=?", (identifier,)
            ).fetchone()
            if not row or row["state"] not in {"preparing", "isolated"}:
                return
            if time.monotonic() >= deadline or time.time() >= expires:
                operations._expire_isolation(db, row)
                return
            time.sleep(min(0.5, max(0.01, deadline - time.monotonic())))
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(
        description="Protected local isolation safety lease"
    )
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--isolation-id", required=True)
    args = parser.parse_args()
    watch(args.state_dir, args.isolation_id)


if __name__ == "__main__":
    main()
