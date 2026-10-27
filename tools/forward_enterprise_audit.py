"""Trigger the configured server's read-only Microsoft audit collector.

Cloud OAuth secrets stay in the xSERA server environment. This client holds an
authenticated xSERA session only in memory and prints bounded status/counts.
"""

import argparse
import datetime
import http.cookiejar
import ipaddress
import json
import os
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def server_url(value):
    try:
        parts = urllib.parse.urlsplit(value)
        if any(ord(char) < 33 for char in value) or parts.username or parts.password or parts.query or parts.fragment or parts.path not in ("", "/") or not parts.hostname or parts.port is not None and not 1 <= parts.port <= 65535 or "\\" in value:
            raise ValueError()
        if parts.scheme != "https" and (parts.scheme != "http" or not ipaddress.ip_address(parts.hostname).is_loopback):
            raise ValueError()
        return value.rstrip("/")
    except ValueError:
        raise argparse.ArgumentTypeError("Use verified HTTPS, or literal loopback HTTP, with no URL credentials/path") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=server_url, default="http://127.0.0.1:8000")
    parser.add_argument("--source", required=True)
    parser.add_argument("--username", default=os.environ.get("XSERA_AUDIT_USERNAME"))
    parser.add_argument("--start", help="UTC ISO timestamp; default one hour before end")
    parser.add_argument("--end", help="UTC ISO timestamp; default current UTC")
    parser.add_argument("--content-type", choices=("Audit.AzureActiveDirectory", "Audit.Exchange", "Audit.SharePoint", "Audit.General", "DLP.All"))
    parser.add_argument("--status-only", action="store_true")
    options = parser.parse_args(argv)
    password = os.environ.get("XSERA_AUDIT_PASSWORD")
    if not options.username or not password:
        print(json.dumps({"status": "unavailable", "reason": "xsera_session_credentials_not_configured"}))
        return 3
    csrf = None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def request(path, data=None):
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if csrf:
            headers["X-CSRF-Token"] = csrf
        payload = json.dumps(data).encode() if data is not None else None
        with opener.open(urllib.request.Request(options.server + path, data=payload, headers=headers), timeout=70) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError("response_limit")
            return json.loads(raw.decode("utf8"))
    try:
        session = request("/api/login", {"name": options.username, "password": password})
        csrf = session.get("csrf")
        if not isinstance(csrf, str) or not 1 <= len(csrf) <= 512 or any(ord(char) < 33 for char in csrf):
            raise ValueError("session_unavailable")
        status_path = "/api/ops/enterprise/sources/" + urllib.parse.quote(options.source, safe="") + "/collector"
        status = request(status_path)
        if options.status_only or status.get("available") is not True:
            print(json.dumps({key: status.get(key) for key in ("source_id", "product", "source_version", "checkpoint_version", "available", "reason", "cloud_live_tested")}, ensure_ascii=False))
            return 0 if status.get("available") else 3
        now = datetime.datetime.now(datetime.UTC)
        end = options.end or now.isoformat().replace("+00:00", "Z")
        start = options.start or (now - datetime.timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        data = {"source_version": status["source_version"], "checkpoint_version": status["checkpoint_version"], "start": start, "end": end, "content_type": options.content_type or "Audit.Exchange" if status["product"] == "m365_audit" else None}
        result = request(status_path + "/collect", data)
        public = {key: result.get(key) for key in ("source_id", "product", "status", "reason", "checkpoint_version", "cursor_committed", "requests", "pages", "fetched_records", "durable_records", "admitted_batches", "duration_ms", "complete", "cloud_live_tested", "live_vendor_attempted", "live_vendor_completed", "host_effects", "retry_after_seconds")}
        print(json.dumps(public, ensure_ascii=False))
        return 0 if result.get("status") == "completed" and result.get("complete") is True else 2
    except urllib.error.HTTPError as exc:
        print(json.dumps({"status": "unavailable", "reason": "xsera_http_error", "http_status": exc.code}))
        return 2
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, TypeError, KeyError, AttributeError):
        print(json.dumps({"status": "unavailable", "reason": "xsera_connection_or_reply_invalid"}))
        return 2
    finally:
        password = None
        if csrf:
            try:
                request("/api/logout", {})
            except (urllib.error.URLError, TimeoutError, OSError, ValueError, TypeError):
                pass


if __name__ == "__main__":
    raise SystemExit(main())
