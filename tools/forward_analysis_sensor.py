"""Read-only JSON-lines forwarder for an explicitly reviewed sensor binding.

It reads a selected existing log; it never installs a sensor, captures packets,
changes audit policy or issues endpoint responses. A local xSERA user session
and CSRF token are used; credentials are read only from the named environment.
"""

import argparse
import hashlib
import http.cookiejar
import json
import os
import ssl
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote, urlparse
from urllib.request import (
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
    build_opener,
)


def read_one(
    path, offset, binding, kind=None, expected_identity=None, expected_anchor=None
):
    """Return an exact bounded complete line; incomplete tail is never ACKed."""
    with Path(path).open("rb") as stream:
        metadata = os.fstat(stream.fileno())
        identity = f"{metadata.st_dev}:{metadata.st_ino}"
        if expected_identity is not None and expected_identity != identity:
            offset = 0
        if offset > metadata.st_size:
            offset = 0
        if offset and expected_anchor is not None:
            stream.seek(max(0, offset - 64))
            if (
                hashlib.sha256(stream.read(min(64, offset))).hexdigest()
                != expected_anchor
            ):
                offset = 0
        stream.seek(offset)
        line = stream.readline(48 * 1024 + 1)
        if len(line) > 48 * 1024:
            raise ValueError("Sensor line exceeds 48 KiB; not skipped")
        if not line or not line.endswith(b"\n"):
            return None
        end = stream.tell()
        stream.seek(max(0, end - 64))
        anchor = hashlib.sha256(stream.read(min(64, end))).hexdigest()
    record = json.loads(line)
    if not isinstance(record, dict):
        raise ValueError("Sensor log line must be a JSON object")  # noqa: TRY004 - source format errors use ValueError consistently.
    key = hashlib.sha256(
        (binding + ":" + identity + ":" + str(offset) + ":").encode() + line
    ).hexdigest()
    item = {"id": "sensor:" + key, "log": record, **({"kind": kind} if kind else {})}
    return {
        "identity": identity,
        "offset": end,
        "anchor": anchor,
        "event": item,
        "cursor": "jsonl:"
        + hashlib.sha256(
            (binding + ":" + identity + ":" + str(end) + ":" + anchor).encode()
        ).hexdigest(),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--endpoint", required=True, help="Explicit HTTPS xSERA server base URL"
    )
    parser.add_argument("--binding", required=True)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument(
        "--state", required=True, type=Path, help="Owned local cursor state path"
    )
    parser.add_argument("--username", required=True)
    parser.add_argument("--password-env", default="XSERA_SENSOR_PASSWORD")
    parser.add_argument("--ca-file")
    parser.add_argument("--zeek-kind", choices=("conn", "dns", "http", "ssl", "notice"))
    parser.add_argument(
        "--allow-loopback-http",
        action="store_true",
        help="Only for an explicitly owned loopback test server",
    )
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=float, default=1)
    args = parser.parse_args(argv)
    parsed = urlparse(args.endpoint)
    if (
        parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        parser.error(
            "Use only a server origin without credentials, path, query or fragment"
        )
    if parsed.scheme != "https" and not (
        args.allow_loopback_http
        and parsed.scheme == "http"
        and parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    ):
        parser.error("HTTPS is required; loopback HTTP requires its explicit test flag")
    if not 0.1 <= args.interval <= 60:
        parser.error("interval must be 0.1..60 seconds")
    password = os.environ.get(args.password_env)
    if not password:
        parser.error("The named password environment variable is unavailable")
    context = ssl.create_default_context(cafile=args.ca_file)

    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            raise ValueError("Sensor forwarding endpoint redirects are forbidden")

    opener = build_opener(
        HTTPCookieProcessor(http.cookiejar.CookieJar()),
        HTTPSHandler(context=context),
        NoRedirect(),
    )
    csrf = None

    def request(path, data=None):
        headers = {"Content-Type": "application/json"}
        if csrf:
            headers["X-CSRF-Token"] = csrf
        req = Request(
            args.endpoint.rstrip("/") + path,
            data=json.dumps(data).encode() if data is not None else None,
            headers=headers,
        )
        with opener.open(req, timeout=30) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024:
                raise ValueError("Server response exceeds bound")
            return json.loads(raw)

    login = request("/api/login", {"name": args.username, "password": password})
    csrf = login["csrf"]
    try:
        binding = next(
            (
                r
                for r in request("/api/analysis/sensors/sources")["items"]
                if r["id"] == args.binding
            ),
            None,
        )
        if not binding or binding["effective_state"] != "active":
            raise ValueError("Explicit reviewed active sensor binding required")
        state = json.loads(args.state.read_text()) if args.state.exists() else {}
        if state and (
            state.get("binding") != args.binding
            or state.get("endpoint") != args.endpoint
        ):
            raise ValueError("Cursor state belongs to another server or binding")
        checkpoint, offset = binding["checkpoint_version"], state.get("offset", 0)
        while True:
            current = args.log.stat()
            identity = f"{current.st_dev}:{current.st_ino}"
            if state.get("identity") not in (None, identity):
                offset = 0
            line = read_one(
                args.log,
                offset,
                args.binding,
                args.zeek_kind,
                state.get("identity"),
                state.get("anchor"),
            )
            if line:
                result = request(
                    "/api/analysis/sensors/sources/" + quote(args.binding, safe="") + "/intake",
                    {
                        "version": binding["version"],
                        "events": [line["event"]],
                        "cursor": line["cursor"],
                        "checkpoint_version": checkpoint,
                    },
                )
                if (
                    result.get("durable") is not True
                    or result.get("cursor_committed") is not True
                ):
                    raise ValueError("Durable admission ACK is required")
                checkpoint, offset = result["checkpoint_version"], line["offset"]
                state = {
                    "binding": args.binding,
                    "endpoint": args.endpoint,
                    "identity": line["identity"],
                    "offset": offset,
                    "anchor": line["anchor"],
                    "checkpoint_version": checkpoint,
                }
                args.state.parent.mkdir(parents=True, exist_ok=True)
                temporary = args.state.with_name(args.state.name + ".pending")
                temporary.write_text(json.dumps(state), encoding="utf-8")
                if os.name != "nt":
                    temporary.chmod(0o600)
                temporary.replace(args.state)
                print(
                    json.dumps(
                        {
                            "event_ids": result["event_ids"],
                            "mode": result["mode"],
                            "checkpoint_version": checkpoint,
                        }
                    )
                )
            if args.once:
                break
            if not line:
                time.sleep(args.interval)
    finally:
        try:
            request("/api/logout", {})
        except (OSError, ValueError, HTTPError):
            pass


if __name__ == "__main__":
    main()
