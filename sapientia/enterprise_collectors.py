"""Read-only, tenant-pinned Microsoft audit collectors with durable admission.

Cloud credentials remain in the registered server environment reference. OAuth
is sent only to the configured Microsoft tenant endpoint; token claims are not
decoded or treated as an independent source of tenant authority.
"""

import datetime
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from . import (
    connector_runtime,
    enterprise_adapters,
    principal,
    release_manifest,
    source_registry,
)
from .storage import ConflictError, encode

MAX_BYTES = 4 * 1024 * 1024
MAX_REQUESTS = 20
MAX_PAGES = 8
MAX_EVENTS = 1000
WALL_SECONDS = 60
CONTENT_TYPES = ("Audit.AzureActiveDirectory", "Audit.Exchange", "Audit.SharePoint", "Audit.General", "DLP.All")


@dataclass(frozen=True)
class Reply:
    status: int
    headers: dict
    body: object


class CollectorFault(Exception):
    def __init__(self, code, state="error", retry_after=None):
        super().__init__(code)
        self.code, self.state, self.retry_after = code, state, retry_after


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_https(method, url, headers, payload, timeout):
    """No redirects or implicit environment proxy; never return error bodies."""
    request = urllib.request.Request(url, data=payload, headers=headers, method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            chunks, total, expires = [], 0, time.monotonic() + timeout
            read = getattr(response, "read1", response.read)
            while True:
                if time.monotonic() >= expires:
                    raise CollectorFault("response_read_deadline", "timeout")
                chunk = read(min(65536, MAX_BYTES + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_BYTES:
                    raise CollectorFault("response_bytes_exceeded", "partial")
            raw = b"".join(chunks)
            try:
                value = json.loads(raw.decode("utf8"), parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            except (ValueError, UnicodeDecodeError, RecursionError):
                raise CollectorFault("invalid_vendor_json") from None
            return Reply(response.status, dict(response.headers), value)
    except urllib.error.HTTPError as exc:
        reply = Reply(exc.code, {"Retry-After": (exc.headers or {}).get("Retry-After", "")}, None)
        exc.close()
        return reply
    except (TimeoutError, urllib.error.URLError, OSError):
        raise CollectorFault("vendor_connection_unavailable", "unavailable") from None


def _source(store, who, identifier, version=None, roles=("admin", "analyst", "viewer")):
    with principal.transaction(store, who, roles) as (db, actor):
        row = source_registry.visible(db, actor, identifier)
        if row["state"] != "active" or row["product"] not in {"entra_signin", "m365_audit"}:
            raise ValueError("Active Microsoft audit source required")
        if version is not None and row["version"] != version:
            raise ConflictError("Enterprise source version changed")
        if not enterprise_adapters.GUID.fullmatch(row["account"]):
            raise ValueError("Registered Microsoft account must be the tenant GUID")
        definition = json.loads(row["definition"])
        if not isinstance(definition, dict) or definition.get("index") != row["index_name"] or any(definition.get(key) != row[key] for key in ("product", "account", "realm", "credential_ref")):
            raise ConflictError("Enterprise source canonical contract changed")
        owner = principal.current(db, {"tenant": actor["tenant"], "name": row["owner"], "role": "analyst"}, ("admin", "analyst"))
        if not principal.contains(owner["allowed_indexes"], [row["index_name"]]):
            raise PermissionError("Current enterprise source owner scope unavailable")
        checkpoint = db.execute("SELECT cursor,version FROM connector_checkpoints WHERE tenant=? AND source_id=?", (actor["tenant"], identifier)).fetchone()
        return actor, dict(row), dict(checkpoint) if checkpoint else {"cursor": None, "version": 0}


def _credentials(source, environment):
    reference = source["credential_ref"]
    if not re.fullmatch(r"env:SAPIENTIA_CONNECTOR_[A-Z0-9_]{1,128}", reference):
        raise CollectorFault("credential_configuration_invalid", "unavailable")
    raw = environment.get(reference[4:])
    if raw is None:
        raise CollectorFault("credential_not_configured", "unavailable")
    try:
        if not isinstance(raw, str) or len(raw.encode()) > 16384:
            raise ValueError()
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) - {"tenant_id", "client_id", "client_secret", "publisher_id"} or not {"tenant_id", "client_id", "client_secret"} <= set(value):
            raise ValueError()
        if any(not isinstance(value.get(key), str) or not enterprise_adapters.GUID.fullmatch(value[key]) for key in ("tenant_id", "client_id")):
            raise ValueError()
        if value["tenant_id"].lower() != source["account"].lower():
            raise CollectorFault("credential_tenant_mismatch", "unavailable")
        secret = value["client_secret"]
        if not isinstance(secret, str) or not 1 <= len(secret) <= 4096 or any(ord(char) < 32 for char in secret):
            raise ValueError()
        if source["product"] == "m365_audit" and (not isinstance(value.get("publisher_id"), str) or not enterprise_adapters.GUID.fullmatch(value["publisher_id"])):
            raise ValueError()
        return value
    except (ValueError, TypeError, RecursionError):
        raise CollectorFault("credential_configuration_invalid", "unavailable") from None


def status(store, who, identifier):
    _actor, source, checkpoint = _source(store, who, identifier)
    try:
        _credentials(source, os.environ)
        available, reason = True, "configured_not_live_verified"
    except CollectorFault as exc:
        available, reason = False, exc.code
    return {"source_id": identifier, "product": source["product"], "source_version": source["version"], "checkpoint_version": checkpoint["version"], "available": available, "reason": reason, "cloud_live_tested": False, "read_only_vendor_api": True, "subscription_creation": False, "content_types": list(CONTENT_TYPES) if source["product"] == "m365_audit" else [], "limits": {"request_bytes": MAX_BYTES, "requests": MAX_REQUESTS, "pages": MAX_PAGES, "events": MAX_EVENTS, "wall_seconds": WALL_SECONDS, "window_seconds": 86400}, "national_clouds_supported": False}


def _url(value, tenant, kind, publisher=None):
    if not isinstance(value, str) or not 1 <= len(value) <= 8192 or any(ord(char) < 32 for char in value) or "\\" in value:
        raise CollectorFault("unsafe_vendor_url")
    try:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme != "https" or parsed.port not in (None, 443) or parsed.username or parsed.password or parsed.fragment:
            raise ValueError()
        path = urllib.parse.unquote(parsed.path)
        if any(part in {".", ".."} for part in path.split("/")) or "\\" in path or "%" in path or path != parsed.path:
            raise ValueError()
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
        if len(pairs) > 8 or len({key for key, _ in pairs}) != len(pairs):
            raise ValueError()
        query = dict(pairs)
        if kind == "graph":
            if parsed.hostname != "graph.microsoft.com" or path != "/v1.0/auditLogs/signIns" or set(query) - {"$top", "$filter", "$skiptoken"}:
                raise ValueError()
        else:
            roots = ["/api/" + version + "/" + tenant + "/activity/feed/" for version in ("v1.0", "v1")]
            root = next((root for root in roots if path.startswith(root)), None)
            if parsed.hostname != "manage.office.com" or not root:
                raise ValueError()
            relative = path[len(root):]
            if kind == "subscriptions" and relative != "subscriptions/list" or kind == "content" and relative != "subscriptions/content" or kind == "blob" and (not relative.startswith("audit/") or not relative[6:] or "/" in relative[6:]):
                raise ValueError()
            allowed = {"PublisherIdentifier"} | ({"contentType", "startTime", "endTime", "nextPage"} if kind == "content" else set())
            if set(query) - allowed or "PublisherIdentifier" in query and query["PublisherIdentifier"].lower() != publisher.lower():
                raise ValueError()
            query["PublisherIdentifier"] = publisher
            value = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), ""))
    except (ValueError, TypeError, AttributeError):
        raise CollectorFault("unsafe_vendor_url") from None
    return value


def collect(store, who, identifier, data, *, http=None, environment=None):
    keys = {"source_version", "checkpoint_version", "start", "end", "content_type"}
    if not isinstance(data, dict) or set(data) != keys or type(data["source_version"]) is not int or data["source_version"] < 1 or type(data["checkpoint_version"]) is not int or data["checkpoint_version"] < 0:
        raise ValueError("Exact enterprise source/checkpoint/window/content_type required")
    start, end = enterprise_adapters.timestamp(data["start"]), enterprise_adapters.timestamp(data["end"])
    if not 0 < end - start <= 86400 or end > time.time() + 300:
        raise ValueError("UTC collection window must be positive, at most 24 hours, without a future end")
    actor, source, checkpoint = _source(store, who, identifier, data["source_version"], ("admin", "analyst"))
    if checkpoint["version"] != data["checkpoint_version"]:
        raise ConflictError("Enterprise checkpoint changed")
    if source["product"] == "m365_audit":
        if not isinstance(data["content_type"], str) or data["content_type"] not in CONTENT_TYPES or start < time.time() - 7 * 86400:
            raise ValueError("Office audit requires an allowed content type and a window within seven days")
    elif data["content_type"] is not None:
        raise ValueError("Entra sign-in does not accept Office content_type")
    started = time.monotonic()
    counters = {"requests": 0, "pages": 0, "fetched_records": 0, "durable_records": 0, "admitted_batches": 0}
    result = {"source_id": identifier, "product": source["product"], "status": "completed", "reason": None, "checkpoint_version": checkpoint["version"], "cursor_committed": False, "read_only_vendor_api": True, "cloud_live_tested": False, "live_vendor_attempted": False, "live_vendor_completed": False, "transport": "microsoft_https" if http is None else "protocol_fixture", "host_effects": 0, "complete": False}
    transport = request_https if http is None else http
    credential = None
    def current():
        try:
            person, fresh, _checkpoint = _source(store, who, identifier, source["version"], ("admin", "analyst"))
        except (ValueError, KeyError, ConflictError):
            raise PermissionError("Enterprise source authority changed") from None
        if person != actor or any(fresh[key] != source[key] for key in ("owner", "account", "realm", "credential_ref", "product", "index_name", "definition")):
            raise PermissionError("Enterprise source authority changed")
    def request(method, url, headers, payload=None):
        current()
        remaining = WALL_SECONDS - (time.monotonic() - started)
        if remaining <= 0:
            raise CollectorFault("collection_deadline", "timeout")
        if counters["requests"] >= MAX_REQUESTS:
            raise CollectorFault("request_limit", "partial")
        counters["requests"] += 1
        result["live_vendor_attempted"] = http is None
        reply = transport(method, url, headers, payload, min(10, remaining))
        if not isinstance(reply, Reply) or type(reply.status) is not int or not isinstance(reply.headers, dict):
            raise CollectorFault("invalid_transport_reply")
        if reply.status == 429:
            retry = next((value for key, value in reply.headers.items() if key.lower() == "retry-after"), "")
            retry = min(300, int(retry)) if isinstance(retry, str) and retry.isdigit() else None
            raise CollectorFault("vendor_rate_limited", "rate_limited", retry)
        if reply.status in {401, 403}:
            raise CollectorFault("vendor_authorization_unavailable", "unavailable")
        if 300 <= reply.status < 400:
            raise CollectorFault("vendor_redirect_refused")
        if reply.status != 200:
            raise CollectorFault("vendor_http_error")
        try:
            if len(encode(reply.body).encode()) > MAX_BYTES:
                raise CollectorFault("response_bytes_exceeded", "partial")
        except (ValueError, TypeError, RecursionError):
            raise CollectorFault("invalid_vendor_json") from None
        return reply
    def admit(events, marker):
        if not events:
            return
        if not isinstance(events, list) or counters["fetched_records"] + len(events) > MAX_EVENTS:
            raise CollectorFault("event_limit", "partial")
        # Entire batch is validated before its first source receipt/checkpoint.
        for event in events:
            try:
                enterprise_adapters.decode(event, source)
            except PermissionError:
                raise CollectorFault("vendor_tenant_mismatch") from None
        counters["fetched_records"] += len(events)
        current()
        cursor = "enterprise:" + release_manifest.digest([source["product"], start, end, data["content_type"], marker, events])
        saved = connector_runtime.intake(store, who, identifier, {"version": source["version"], "events": events, "cursor": cursor, "checkpoint_version": result["checkpoint_version"]})
        if not saved.get("cursor_committed"):
            raise CollectorFault("durable_admission_unconfirmed")
        result["checkpoint_version"] = saved["checkpoint_version"]
        result["cursor_committed"] = True
        counters["durable_records"] += len(saved["event_ids"])
        counters["admitted_batches"] += 1
    def page():
        if counters["pages"] >= MAX_PAGES:
            raise CollectorFault("page_limit", "partial")
        counters["pages"] += 1
    try:
        credential = _credentials(source, os.environ if environment is None else environment)
        tenant = credential["tenant_id"].lower()
        token_url = "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/token"
        scope = "https://graph.microsoft.com/.default" if source["product"] == "entra_signin" else "https://manage.office.com/.default"
        token = request("POST", token_url, {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}, urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": credential["client_id"], "client_secret": credential["client_secret"], "scope": scope}).encode())
        if not isinstance(token.body, dict) or not isinstance(token.body.get("access_token"), str) or not 1 <= len(token.body["access_token"]) <= 16384 or token.body.get("token_type", "").lower() != "bearer" or any(not 33 <= ord(char) <= 126 for char in token.body["access_token"]):
            raise CollectorFault("invalid_oauth_token_reply")
        headers = {"Authorization": "Bearer " + token.body["access_token"], "Accept": "application/json"}
        seen = set()
        if source["product"] == "entra_signin":
            filter_text = "createdDateTime ge " + data["start"] + " and createdDateTime le " + data["end"]
            url = "https://graph.microsoft.com/v1.0/auditLogs/signIns?" + urllib.parse.urlencode({"$top": 250, "$filter": filter_text})
            while url:
                page()
                url = _url(url, tenant, "graph")
                if url in seen:
                    raise CollectorFault("pagination_cycle")
                seen.add(url)
                reply = request("GET", url, headers)
                if not isinstance(reply.body, dict) or not isinstance(reply.body.get("value"), list) or len(reply.body["value"]) > 250 or any(not isinstance(record, dict) for record in reply.body["value"]):
                    raise CollectorFault("invalid_graph_page")
                next_url = reply.body.get("@odata.nextLink")
                if next_url is not None:
                    next_url = _url(next_url, tenant, "graph")
                    query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(next_url).query))
                    if "$filter" in query and query["$filter"] != filter_text or "$top" in query and (not query["$top"].isdigit() or not 1 <= int(query["$top"]) <= 250):
                        raise CollectorFault("pagination_window_changed")
                events = [{"tenant_id": tenant, "record": record} for record in reply.body["value"]]
                if any(not start <= enterprise_adapters.timestamp(event["record"].get("createdDateTime")) <= end for event in events):
                    raise CollectorFault("graph_record_outside_requested_window")
                admit(events, release_manifest.digest(url))
                url = next_url
        else:
            publisher = credential["publisher_id"].lower()
            root = "https://manage.office.com/api/v1.0/" + tenant + "/activity/feed/"
            subscriptions = request("GET", _url(root + "subscriptions/list", tenant, "subscriptions", publisher), headers).body
            if not isinstance(subscriptions, list) or len(subscriptions) > 32 or any(not isinstance(item, dict) for item in subscriptions):
                raise CollectorFault("invalid_subscription_list")
            if not any(item.get("contentType") == data["content_type"] and item.get("status") == "enabled" for item in subscriptions):
                raise CollectorFault("subscription_required", "unavailable")
            utc = lambda value: datetime.datetime.fromtimestamp(value, datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S")
            url = root + "subscriptions/content?" + urllib.parse.urlencode({"contentType": data["content_type"], "startTime": utc(start), "endTime": utc(end)})
            blob_ids = set()
            while url:
                page()
                url = _url(url, tenant, "content", publisher)
                if url in seen:
                    raise CollectorFault("pagination_cycle")
                seen.add(url)
                reply = request("GET", url, headers)
                if not isinstance(reply.body, list) or len(reply.body) > 32 or any(not isinstance(item, dict) for item in reply.body):
                    raise CollectorFault("invalid_content_list")
                next_url = next((value for key, value in reply.headers.items() if key.lower() == "nextpageuri"), None)
                if next_url is not None:
                    next_url = _url(next_url, tenant, "content", publisher)
                    query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(next_url).query))
                    if any(query.get(key) != expected for key, expected in {"contentType": data["content_type"], "startTime": utc(start), "endTime": utc(end)}.items()):
                        raise CollectorFault("pagination_window_changed")
                for item in reply.body:
                    if item.get("contentType") != data["content_type"] or not isinstance(item.get("contentId"), str) or not 1 <= len(item["contentId"]) <= 1024:
                        raise CollectorFault("invalid_content_reference")
                    if item["contentId"] in blob_ids:
                        raise CollectorFault("duplicate_content_reference")
                    blob_ids.add(item["contentId"])
                    blob_url = _url(item.get("contentUri"), tenant, "blob", publisher)
                    if urllib.parse.urlsplit(blob_url).path.rsplit("/", 1)[-1] != item["contentId"]:
                        raise CollectorFault("content_identifier_mismatch")
                    blob = request("GET", blob_url, headers).body
                    if not isinstance(blob, list) or any(not isinstance(record, dict) for record in blob):
                        raise CollectorFault("invalid_content_blob")
                    admit(blob, item["contentId"])
                url = next_url
        result["complete"] = True
        result["live_vendor_completed"] = http is None
    except CollectorFault as exc:
        result.update(status=exc.state, reason=exc.code, retry_after_seconds=exc.retry_after)
    except (PermissionError, ConflictError, KeyError):
        result.update(status="authority_changed", reason="source_or_checkpoint_authority_changed")
    except (ValueError, TypeError, AttributeError, RecursionError):
        result.update(status="error", reason="invalid_vendor_record_or_reply")
    finally:
        credential = None
    return {**result, **counters, "duration_ms": round((time.monotonic() - started) * 1000, 3)}
