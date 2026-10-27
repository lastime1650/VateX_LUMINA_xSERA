"""File-side adapters. Transport never disables TLS validation or follows redirects."""

import argparse
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path


def parse_line(line, kind, source, event_id):
    if kind == "json":
        event = json.loads(line)
        if not isinstance(event, dict):
            raise ValueError("JSON record must be an object")
        event.setdefault("event_id", event_id)
        event.setdefault("source", source)
        return event
    if kind == "syslog":
        # RFC5424 envelope subset; retain raw for unsupported structured-data syntax.
        match = re.match(r"^<(\d{1,3})>(\d+) (\S+) (\S+) (\S+) (\S+) (\S+) (.*)$", line)
        if not match or int(match[1]) > 191:
            raise ValueError("Expected RFC5424 syslog envelope")
        severity = [
            "critical",
            "critical",
            "high",
            "high",
            "medium",
            "info",
            "info",
            "debug",
        ][int(match[1]) % 8]
        event = {
            "event_id": event_id,
            "source": source,
            "sourcetype": "syslog:rfc5424",
            "host": match[4],
            "severity": severity,
            "message": match[8],
            "raw": {
                "line": line,
                "pri": int(match[1]),
                "application": match[5],
                "source_timestamp": match[3],
            },
        }
        timestamp = match[3]
        if timestamp != "-":
            if not re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?"
                r"(?:Z|[+-]\d{2}:\d{2})",
                timestamp,
            ):
                raise ValueError("Syslog timestamp must be timezone-aware RFC3339")
            try:
                parsed = datetime.fromisoformat(timestamp)
                event["event_time"] = parsed.timestamp()
            except (ValueError, OverflowError, OSError) as exc:
                raise ValueError("Invalid syslog timestamp") from exc
        return event
    if kind == "cef":
        pieces = re.split(r"(?<!\\)\|", line, maxsplit=7)
        if len(pieces) != 8 or not pieces[0].startswith("CEF:"):
            raise ValueError("Expected CEF header and extension")
        try:
            level = int(pieces[6])
        except ValueError:
            raise ValueError("CEF adapter currently requires numeric severity")
        if not 0 <= level <= 10:
            raise ValueError("CEF severity must be 0..10")
        return {
            "event_id": event_id,
            "source": source,
            "sourcetype": "cef",
            "severity": "critical"
            if level >= 9
            else "high"
            if level >= 7
            else "medium"
            if level >= 4
            else "low",
            "message": pieces[5],
            "raw": {
                "line": line,
                "vendor": pieces[1],
                "product": pieces[2],
                "signature": pieces[4],
                "extension": pieces[7],
            },
        }
    raise ValueError("Unknown adapter")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Send NDJSON/RFC5424/CEF lines with stable IDs and durable file offset"
    )
    parser.add_argument("file", type=Path)
    parser.add_argument("--format", choices=["json", "syslog", "cef"], default="json")
    parser.add_argument("--source", required=True)
    parser.add_argument("--url", default="http://127.0.0.1:8787")
    parser.add_argument("--checkpoint", type=Path, required=True)
    args = parser.parse_args()
    checkpoint_temp = args.checkpoint.with_suffix(args.checkpoint.suffix + ".tmp")
    if args.file.resolve() in {args.checkpoint.resolve(), checkpoint_temp.resolve()}:
        parser.error("Checkpoint and its temporary file must not overwrite the input")
    from urllib.parse import urlsplit

    url = urlsplit(args.url)
    if (
        url.username
        or url.password
        or url.query
        or url.fragment
        or url.path not in {"", "/"}
        or url.scheme not in {"http", "https"}
    ):
        parser.error("Use an origin URL without credentials, query or path")
    if url.scheme == "http" and url.hostname not in {"localhost", "127.0.0.1", "::1"}:
        parser.error("Remote ingestion requires HTTPS")
    token = os.environ.get("SAPIENTIA_INGEST_TOKEN")
    if not token:
        parser.error(
            "Set SAPIENTIA_INGEST_TOKEN; never pass tokens in command-line arguments"
        )
    state = (
        json.loads(args.checkpoint.read_text())
        if args.checkpoint.exists()
        else {"offset": 0, "path": str(args.file.resolve()), "prefix": ""}
    )
    if state["path"] != str(args.file.resolve()):
        parser.error("Checkpoint belongs to a different file")
    opener = urllib.request.build_opener(NoRedirect())
    with args.file.open("rb") as stream:
        # Verify all acknowledged prefix bytes; fail closed on rotation or changed input.
        hasher = hashlib.sha256()
        remaining = state["offset"]
        while remaining:
            block = stream.read(min(1048576, remaining))
            if not block:
                parser.error(
                    "Input truncated; choose a new checkpoint for rotated file"
                )
            hasher.update(block)
            remaining -= len(block)
        if state["offset"] and hasher.hexdigest() != state["prefix"]:
            parser.error("Acknowledged input changed; choose a new checkpoint")
        while True:
            offset = stream.tell()
            line = stream.readline(65537)
            if not line:
                break
            if len(line) > 65536:
                raise ValueError(f"Line at offset {offset} exceeds 64 KiB")
            eid = hashlib.sha256(
                f"{args.source}:{args.file.resolve()}:{offset}:".encode() + line
            ).hexdigest()
            event = parse_line(
                line.decode("utf-8").rstrip("\r\n"), args.format, args.source, eid
            )
            request = urllib.request.Request(
                args.url.rstrip("/") + "/api/v1/events",
                data=json.dumps({"events": [event]}, allow_nan=False).encode(),
                headers={
                    "Authorization": "Bearer " + token,
                    "Content-Type": "application/json",
                },
            )
            for attempt in range(5):
                try:
                    with opener.open(request, timeout=30) as response:
                        ack = json.load(response)
                        if response.status != 202 or not ack.get("durable"):
                            raise ValueError("No durable acknowledgment")
                    break
                except urllib.error.HTTPError as exc:
                    if exc.code not in {429, 503} or attempt == 4:
                        raise
                    time.sleep(min(2**attempt, 16))
            hasher.update(line)
            state.update(offset=stream.tell(), prefix=hasher.hexdigest())
            args.checkpoint.parent.mkdir(parents=True, exist_ok=True)
            temporary = args.checkpoint.with_suffix(args.checkpoint.suffix + ".tmp")
            with temporary.open("w", encoding="utf-8") as output:
                json.dump(state, output)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, args.checkpoint)
    print("File delivery completed; acknowledged offset:", state["offset"])


if __name__ == "__main__":
    main()
