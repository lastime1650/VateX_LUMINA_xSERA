"""Opt-in JSON federation over statically trusted, independently scoped peers.

This is bounded query fan-out/reduction, not automatic sharding or cluster enrollment.
Dedicated pairwise environment secrets authenticate this endpoint; ingest tokens do not.
"""

import hashlib
import hmac
import http.client
import json
import math
import os
import re
import secrets
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlsplit

from .query import ALIASES, Query, column, index_predicate
from .storage import CapacityError, encode

PEER_PATH = "/api/federation/peer/search"
NAME = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
MAX_BODY = 256 * 1024
MAX_RESPONSE = 2 * 1024 * 1024
MAX_NUMERIC = 2**53 - 1


@dataclass
class FederatedQuery(Query):
    aggregates: list = field(default_factory=list)
    minimum_sequences: dict = field(default_factory=dict)


class FederationError(ValueError):
    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.status_code = status_code


@contextmanager
def _deadline_lock(lock, deadline):
    if not lock.acquire(timeout=max(0, deadline - time.monotonic())):
        raise FederationError("Federation control lock deadline exceeded", 504)
    try:
        yield
    finally:
        lock.release()


def initialize(store):
    # Replay protection is node-local and persists across application restarts.
    with store.control(local=True) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS federation_nonces(
            key_id TEXT NOT NULL,nonce TEXT NOT NULL,expires REAL NOT NULL,
            PRIMARY KEY(key_id,nonce))""")
        db.execute(
            "CREATE INDEX IF NOT EXISTS federation_nonce_expiry ON federation_nonces(expires)"
        )
        db.execute(
            "CREATE TABLE IF NOT EXISTS federation_identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),dataset_id TEXT NOT NULL)"
        )
        db.execute(
            "INSERT OR IGNORE INTO federation_identity VALUES(1,?)",
            ("node_" + secrets.token_hex(16),),
        )


def load_config(path):
    path = Path(path).resolve()
    if path.stat().st_size > 65536:
        raise FederationError("Federation configuration exceeds 64 KiB")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise FederationError("Federation configuration must be an object")
    for peer in value.get("peers", []):
        if peer.get("ca_file"):
            peer["ca_file"] = str((path.parent / peer["ca_file"]).resolve())
    return value


def _names(values, label):
    if (
        not isinstance(values, list)
        or len(values) > 256
        or any(not isinstance(x, str) or not NAME.fullmatch(x) for x in values)
    ):
        raise FederationError(label + " must contain at most 256 exact names")
    return sorted(set(values))


def _secret(item):
    variable = item.get("secret_env")
    if not isinstance(variable, str) or not re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]{0,127}", variable
    ):
        raise FederationError("A dedicated federation secret_env is required")
    value = os.environ.get(variable, "")
    if (
        not 32 <= len(value) <= 512
        or not value.isascii()
        or any(ord(char) <= 32 or ord(char) >= 127 for char in value)
    ):
        raise FederationError(
            "Federation environment secrets must contain 32..512 printable ASCII bytes without whitespace"
        )
    return value


def _scope(requested, configured):
    if not isinstance(requested, list):
        raise FederationError("An explicit index scope list is required", 403)
    index_predicate(requested)
    return (
        list(configured)
        if requested == ["*"]
        else sorted(set(requested) & set(configured))
    )


def signed_headers(key_id, secret, body, stamp=None, nonce=None):
    stamp = str(int(time.time() if stamp is None else stamp))
    nonce = secrets.token_hex(24) if nonce is None else nonce
    message = "\n".join(
        ("POST", PEER_PATH, key_id, stamp, nonce, hashlib.sha256(body).hexdigest())
    ).encode()
    return {
        "authorization": "Bearer " + secret,
        "content-type": "application/json",
        "x-sapientia-key": key_id,
        "x-sapientia-time": stamp,
        "x-sapientia-nonce": nonce,
        "x-sapientia-signature": hmac.new(
            secret.encode(), message, hashlib.sha256
        ).hexdigest(),
    }


class Federation:
    def __init__(self, store, config):
        self.store = store
        if not isinstance(config, dict) or set(config) - {
            "peers",
            "grants",
            "allow_loopback_http",
            "include_local",
            "local_name",
            "timeout",
            "max_results",
            "max_groups",
            "concurrency",
            "clock_skew",
            "max_distinct",
            "local_dataset_id",
            "local_replica_set",
            "local_indexes",
        }:
            raise FederationError("Unknown federation configuration property")
        self.timeout = config.get("timeout", 10)
        self.max_results = config.get("max_results", 1000)
        self.max_groups = config.get("max_groups", 1000)
        self.max_distinct = config.get("max_distinct", 10000)
        self.clock_skew = config.get("clock_skew", 60)
        concurrency = config.get("concurrency", 2)
        if (
            isinstance(self.timeout, bool)
            or not isinstance(self.timeout, (int, float))
            or not math.isfinite(self.timeout)
            or not 0.1 <= self.timeout <= 30
        ):
            raise FederationError("Federation timeout must be 0.1..30 seconds")
        for value, maximum, label in (
            (self.max_results, 1000, "max_results"),
            (self.max_groups, 1000, "max_groups"),
            (self.max_distinct, 10000, "max_distinct"),
            (concurrency, 8, "concurrency"),
            (self.clock_skew, 120, "clock_skew"),
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise FederationError(label + " is outside its supported bounds")
        self.include_local = config.get("include_local", True)
        loopback = config.get("allow_loopback_http", False)
        if type(self.include_local) is not bool or type(loopback) is not bool:
            raise FederationError("Federation switches must be booleans")
        self.local_name = config.get("local_name", "local")
        if not isinstance(self.local_name, str) or not NAME.fullmatch(self.local_name):
            raise FederationError("Invalid local federation node name")
        replica = self.store.replica
        with store.control(local=True) as db:
            default_dataset = db.execute(
                "SELECT dataset_id FROM federation_identity WHERE singleton=1"
            ).fetchone()[0]
        self.dataset_id = config.get(
            "local_dataset_id",
            "cluster_" + replica.config["cluster_id"] if replica else default_dataset,
        )
        self.replica_set = config.get(
            "local_replica_set", replica.config["cluster_id"] if replica else None
        )
        self.local_indexes = (
            _names(config["local_indexes"], "Local indexes")
            if "local_indexes" in config
            else None
        )
        if not isinstance(self.dataset_id, str) or not NAME.fullmatch(self.dataset_id):
            raise FederationError("Invalid local dataset identity")
        if self.replica_set != (replica.config["cluster_id"] if replica else None):
            raise FederationError(
                "Local replica_set must match the configured quorum journal"
            )
        peers, grants = config.get("peers", []), config.get("grants", [])
        if (
            not isinstance(peers, list)
            or len(peers) + int(self.include_local) > 8
            or not isinstance(grants, list)
            or len(grants) > 32
        ):
            raise FederationError(
                "Federation supports at most 8 queried nodes and 32 incoming grants"
            )
        self.peers, self.grants = [], {}
        names = {self.local_name} if self.include_local else set()
        for item in peers:
            if not isinstance(item, dict) or set(item) - {
                "name",
                "url",
                "key_id",
                "secret_env",
                "ca_file",
                "tenants",
                "indexes",
                "dataset_id",
                "replica_set",
                "preference",
                "min_sequence",
            }:
                raise FederationError("Invalid federation peer properties")
            name, key_id = item.get("name"), item.get("key_id")
            if (
                not isinstance(name, str)
                or not NAME.fullmatch(name)
                or name in names
                or not isinstance(key_id, str)
                or not NAME.fullmatch(key_id)
            ):
                raise FederationError(
                    "Peer names must be unique; key IDs must be exact names"
                )
            names.add(name)
            dataset_id, replica_set = item.get("dataset_id"), item.get("replica_set")
            for identity in (dataset_id, replica_set):
                if identity is not None and (
                    not isinstance(identity, str) or not NAME.fullmatch(identity)
                ):
                    raise FederationError("Invalid peer dataset/replica identity")
            if replica_set is not None and dataset_id is None:
                raise FederationError("A replica_set requires an explicit dataset_id")
            preference, minimum = (
                item.get("preference", 100),
                item.get("min_sequence", 0),
            )
            if (
                type(preference) is not int
                or not 0 <= preference <= 1000
                or type(minimum) is not int
                or not 0 <= minimum <= 2**63 - 1
            ):
                raise FederationError("Invalid replica preference or minimum sequence")
            parsed = urlsplit(item.get("url", ""))
            if (
                parsed.scheme not in {"https", "http"}
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
            ):
                raise FederationError("Peer URL must be a static HTTPS origin")
            if parsed.scheme == "http" and not (
                loopback and parsed.hostname in {"127.0.0.1", "::1"}
            ):
                raise FederationError(
                    "HTTP federation is restricted to explicit literal-loopback test configuration"
                )
            context = None
            if parsed.scheme == "https":
                ca_file = item.get("ca_file")
                context = (
                    ssl.create_default_context(cafile=ca_file)
                    if ca_file
                    else ssl.create_default_context()
                )
            self.peers.append(
                {
                    "name": name,
                    "host": parsed.hostname,
                    "port": parsed.port,
                    "https": parsed.scheme == "https",
                    "context": context,
                    "key_id": key_id,
                    "secret": _secret(item),
                    "tenants": _names(item.get("tenants"), "Peer tenants"),
                    "indexes": _names(item.get("indexes"), "Peer indexes"),
                    "dataset_id": dataset_id,
                    "replica_set": replica_set,
                    "preference": preference,
                    "min_sequence": minimum,
                    "addresses": socket.getaddrinfo(
                        parsed.hostname,
                        parsed.port or (443 if parsed.scheme == "https" else 80),
                        type=socket.SOCK_STREAM,
                        proto=socket.IPPROTO_TCP,
                    ),
                }
            )
        for item in grants:
            if not isinstance(item, dict) or set(item) - {
                "key_id",
                "secret_env",
                "tenants",
                "indexes",
            }:
                raise FederationError("Invalid incoming federation grant")
            key_id = item.get("key_id")
            if (
                not isinstance(key_id, str)
                or not NAME.fullmatch(key_id)
                or key_id in self.grants
            ):
                raise FederationError("Incoming key IDs must be unique exact names")
            self.grants[key_id] = {
                "secret": _secret(item),
                "tenants": _names(item.get("tenants"), "Grant tenants"),
                "indexes": _names(item.get("indexes"), "Grant indexes"),
            }
        self.slots = threading.BoundedSemaphore(concurrency)
        declarations = {}
        if self.include_local:
            declarations[self.dataset_id] = self.replica_set
        for peer in self.peers:
            identifier = peer["dataset_id"]
            if identifier is not None:
                if identifier in declarations and (
                    not peer["replica_set"]
                    or declarations[identifier] != peer["replica_set"]
                ):
                    raise FederationError(
                        "Conflicting replica declarations for one dataset"
                    )
                declarations[identifier] = peer["replica_set"]
        replica_datasets = {}
        for identifier, replica_set in declarations.items():
            if replica_set is not None:
                if (
                    replica_set in replica_datasets
                    and replica_datasets[replica_set] != identifier
                ):
                    raise FederationError(
                        "One full replica_set cannot declare multiple datasets"
                    )
                replica_datasets[replica_set] = identifier

    def _parse(self, payload):
        if not isinstance(payload, dict) or payload.get("language") != "json":
            raise FederationError(
                "Federation supports bounded JSON filters/aggregates only; SPL is unsupported"
            )
        payload = dict(payload)
        minimum = payload.pop("minimum_sequences", {})
        if (
            not isinstance(minimum, dict)
            or len(minimum) > 8
            or any(
                not isinstance(k, str)
                or not NAME.fullmatch(k)
                or type(v) is not int
                or not 0 <= v <= 2**63 - 1
                for k, v in minimum.items()
            )
        ):
            raise FederationError(
                "minimum_sequences requires at most 8 dataset/nonnegative sequence pairs"
            )
        body = payload.get("query", {})
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except ValueError as exc:
                raise FederationError("Invalid JSON query") from exc
        if not isinstance(body, dict):
            raise FederationError("Expected a JSON query object")
        body = dict(body)
        aggregates = body.pop("aggregates", [])
        if not isinstance(aggregates, list) or len(aggregates) > 8:
            raise FederationError("At most 8 aggregate definitions are supported")
        groups = body.get("group_by")
        if groups is not None and (
            not isinstance(groups, list)
            or len(groups) > 3
            or any(not isinstance(x, str) for x in groups)
        ):
            raise FederationError("At most 3 grouping fields are supported")
        aliases = {ALIASES.get(x, x) for x in groups or []}
        validated = []
        for metric in aggregates:
            if not isinstance(metric, dict) or set(metric) - {"op", "field", "as"}:
                raise FederationError("Invalid aggregate definition")
            op, target, alias = metric.get("op"), metric.get("field"), metric.get("as")
            if (
                not isinstance(op, str)
                or op not in {"count", "sum", "avg", "min", "max", "distinct"}
                or not isinstance(alias, str)
                or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", alias)
                or alias.startswith("__")
                or alias in ALIASES
                or alias in aliases
            ):
                raise FederationError("Aggregate operation/unique alias is invalid")
            if op == "count":
                if target is not None:
                    raise FederationError("count counts events and takes no field")
            else:
                target = (
                    ALIASES.get(target, target) if isinstance(target, str) else target
                )
                column(target)
                if target == "raw" or (
                    op != "distinct"
                    and not target.startswith("raw.")
                    and target not in {"event_time", "received"}
                ):
                    raise FederationError(
                        "Numeric aggregates require event_time, received or a numeric raw scalar"
                    )
            aliases.add(alias)
            validated.append({"op": op, "field": target, "as": alias})
        requested_sort = body.get("sort")
        if requested_sort is not None and not isinstance(requested_sort, str):
            raise FederationError("Aggregate sort must be a field or alias string")
        if aggregates:
            body.setdefault("group_by", [])
            body["sort"] = (
                "count"  # Validate filters/group fields using the shared compiler.
            )
        payload["query"] = body
        parsed = Query.parse(payload)
        query = FederatedQuery(
            **vars(parsed), aggregates=validated, minimum_sequences=minimum
        )
        if aggregates:
            query.sort = requested_sort or aggregates[0]["as"]
            if query.sort not in aliases:
                raise FederationError(
                    "Aggregate sort must be an aggregate alias or grouped field"
                )
        query.fields = [ALIASES.get(x, x) for x in query.fields]
        query.group_by = (
            None
            if query.group_by is None
            else [ALIASES.get(x, x) for x in query.group_by]
        )
        query.sort = ALIASES.get(query.sort, query.sort)
        if query.group_by is None and query.sort not in {"event_time", "received"}:
            raise FederationError(
                "Federated event ordering supports event_time or received only"
            )
        if query.limit > self.max_results:
            raise FederationError("Federated result limit exceeds configured maximum")
        return query

    @staticmethod
    def _payload(query):
        payload = {
            "language": "json",
            "earliest": query.earliest,
            "latest": query.latest,
            "limit": query.limit,
            "query": {
                "filters": query.filters,
                "text": query.text,
                "fields": query.fields,
                "group_by": query.group_by,
                "sort": query.sort,
                "descending": query.descending,
            },
        }
        if query.aggregates:
            payload["query"]["aggregates"] = query.aggregates
        return payload

    def status(self):
        return {
            "enabled": True,
            "dataset_id": self.dataset_id,
            "replica_set": self.replica_set,
            "local_name": self.local_name,
            "include_local": self.include_local,
            "local_scope_configured": self.local_indexes is not None,
            "peers": [
                {
                    k: p[k]
                    for k in (
                        "name",
                        "dataset_id",
                        "replica_set",
                        "preference",
                        "min_sequence",
                    )
                }
                for p in self.peers
            ],
            "aggregates": ["count", "sum", "avg", "min", "max", "distinct"],
            "limits": {
                "nodes": 8,
                "groups": self.max_groups,
                "distinct_pairs": self.max_distinct,
                "results": self.max_results,
                "response_bytes": MAX_RESPONSE,
                "timeout_seconds": self.timeout,
            },
            "routing": "one deterministic ready reader per dataset, explicit replica fallback",
            "consistency": "quorum barrier per replicated dataset; no atomic cross-dataset snapshot",
            "automatic_sharding": False,
            "automatic_membership": False,
            "peer_dns": "operator hostnames resolved and cached at configuration startup; restart to refresh",
        }

    @staticmethod
    def _distinct_token(token):
        value = json.loads(token, parse_int=Decimal, parse_float=Decimal)
        if isinstance(value, Decimal):
            sign, digits, exponent = value.as_tuple()
            digits = list(digits)
            if not any(digits):
                return "number:0"
            while digits and digits[-1] == 0:
                digits.pop()
                exponent += 1
            return "number:" + encode([sign, digits, exponent])
        return ("bool:" if isinstance(value, bool) else "string:") + encode(value)

    @staticmethod
    def _numeric(target):
        col = column(target)
        if target.startswith("raw."):
            return (
                "CASE WHEN json_type(raw, '$."
                + target[4:]
                + "') IN ('BIGINT','UBIGINT','DOUBLE') THEN try_cast("
                + col
                + " AS DOUBLE) END"
            )
        return col

    def _aggregate_node(self, connection, query, tenant, indexes):
        # The shared compiler supplies the complete authorized WHERE predicate.
        base = replace(
            query, aggregates=[], fields=["event_id"], group_by=None, sort="event_time"
        )
        sql, params = base.compile(tenant, allowed_indexes=indexes)
        source, where = sql.split(" FROM ", 1)[1].split(" WHERE ", 1)
        if source not in {"events", "events_all"}:
            raise FederationError("Unsupported analytical event relation")
        where = where.rsplit(" ORDER BY ", 1)[0]
        params = params[:-1]
        groups = query.group_by or []
        numeric_fields = {
            metric["field"]
            for metric in query.aggregates
            if metric["op"] in {"sum", "avg", "min", "max"}
        }
        if numeric_fields:
            checks = [
                "(abs("
                + self._numeric(target)
                + f")>{MAX_NUMERIC} OR NOT isfinite("
                + self._numeric(target)
                + "))"
                for target in sorted(numeric_fields)
            ]
            connection.execute(
                "SELECT 1 FROM "
                + source
                + " WHERE "
                + where
                + " AND ("
                + " OR ".join(checks)
                + ") LIMIT 1",
                params,
            )
            if connection.fetchone():
                raise FederationError(
                    "Numeric input exceeds the finite exact-integer profile (+/- 2^53-1)",
                    413,
                )
        projected = [column(x) + ' AS "' + x + '"' for x in groups]
        selections = [*projected, "count(*) AS __n"]
        for number, metric in enumerate(query.aggregates):
            if metric["op"] in {"sum", "avg", "min", "max"}:
                numeric = self._numeric(metric["field"])
                function = "sum" if metric["op"] == "avg" else metric["op"]
                selections.extend(
                    [
                        f"{function}({numeric}) AS __m{number}",
                        f"count({numeric}) AS __c{number}",
                    ]
                )
                if metric["op"] in {"sum", "avg"} and metric["field"].startswith(
                    "raw."
                ):
                    integer = (
                        "json_type(raw, '$."
                        + metric["field"][4:]
                        + "') IN ('BIGINT','UBIGINT')"
                    )
                    selections.extend(
                        [
                            f"count(*) FILTER (WHERE {integer}) AS __i{number}",
                            f"sum(try_cast({column(metric['field'])} AS HUGEINT)) FILTER (WHERE {integer}) AS __s{number}",
                        ]
                    )
        suffix = " GROUP BY " + ",".join(column(x) for x in groups) if groups else ""
        connection.execute(
            "SELECT "
            + ",".join(selections)
            + " FROM "
            + source
            + " WHERE "
            + where
            + suffix
            + " LIMIT ?",
            [*params, self.max_groups + 1],
        )
        columns = [x[0] for x in connection.description]
        records = [dict(zip(columns, row)) for row in connection.fetchall()]
        if len(records) > self.max_groups:
            raise FederationError(
                "Exact federation aggregation exceeds group cap; narrow filters", 413
            )
        rows, lookup = [], {}
        for record in records:
            row = {x: record[x] for x in groups}
            row["__metrics"] = {}
            for number, metric in enumerate(query.aggregates):
                op = metric["op"]
                value = (
                    {"count": record["__n"]}
                    if op == "count"
                    else {"values": []}
                    if op == "distinct"
                    else {
                        "value": record[f"__m{number}"],
                        "count": record[f"__c{number}"],
                    }
                )
                if (
                    op in {"sum", "avg"}
                    and metric["field"].startswith("raw.")
                    and value["count"]
                    and record[f"__i{number}"] == value["count"]
                ):
                    value["value"] = record[f"__s{number}"]
                if (
                    op in {"sum", "avg", "min", "max"}
                    and value["value"] is not None
                    and not math.isfinite(value["value"])
                ):
                    raise FederationError(
                        "Numeric aggregate overflow; narrow the request", 413
                    )
                row["__metrics"][metric["as"]] = value
            rows.append(row)
            lookup[encode([row[x] for x in groups])] = row
        pairs = 0
        for metric in query.aggregates:
            if metric["op"] != "distinct":
                continue
            target = metric["field"]
            if target.startswith("raw."):
                path = "$." + target[4:]
                value_sql = "CAST(json_extract(raw, '" + path + "') AS VARCHAR)"
                valid = (
                    "json_type(raw, '"
                    + path
                    + "') IN ('VARCHAR','BOOLEAN','BIGINT','UBIGINT','DOUBLE')"
                )
            else:
                value_sql = "CAST(to_json(" + column(target) + ") AS VARCHAR)"
                valid = column(target) + " IS NOT NULL"
            connection.execute(
                "SELECT DISTINCT "
                + ",".join([*projected, value_sql + " AS __value"])
                + " FROM "
                + source
                + " WHERE "
                + where
                + " AND "
                + valid
                + " LIMIT ?",
                [*params, self.max_distinct + 1],
            )
            columns = [x[0] for x in connection.description]
            values = [dict(zip(columns, row)) for row in connection.fetchall()]
            pairs += len(values)
            if pairs > self.max_distinct:
                raise FederationError(
                    "Exact distinct aggregation exceeds value/group pair cap", 413
                )
            for value in values:
                key = encode([value[x] for x in groups])
                lookup[key]["__metrics"][metric["as"]]["values"].append(
                    self._distinct_token(value["__value"])
                )
        return rows

    def _node(self, query, tenant, indexes, deadline, min_sequence=0):
        deadline = min(deadline, time.monotonic() + self.store.settings.query_timeout)
        min_sequence = max(
            min_sequence, query.minimum_sequences.get(self.dataset_id, 0)
        )
        try:
            readiness = (
                self.store.replica.read_barrier(
                    min_sequence,
                    tenant=tenant,
                    allowed_indexes=indexes,
                    timeout=max(0.001, deadline - time.monotonic()),
                )
                if self.store.replica
                else {"ready": True, "applied_sequence": 0, "quorum_verified": False}
            )
        except (CapacityError, RuntimeError) as exc:
            raise FederationError(
                "Replica is not ready for a fenced read: " + str(exc), 503
            ) from exc
        if not self.store.replica and min_sequence:
            raise FederationError(
                "Standalone dataset cannot satisfy a journal sequence fence", 409
            )
        try:
            with self.store.segment_lock.read(deadline=deadline):
                self.store.segments.ensure_readable(deadline=deadline)
                return self._execute_node(query, tenant, indexes, deadline, readiness)
        except FederationError:
            raise
        except RuntimeError as exc:
            raise FederationError(
                "Federated segment read unavailable",
                504 if time.monotonic() >= deadline else 502,
            ) from exc

    def _execute_node(self, query, tenant, indexes, deadline, readiness):
        fields = (
            list(dict.fromkeys([*query.fields, "event_id", query.sort]))
            if query.group_by is None
            else query.fields
        )
        local = replace(query, fields=fields)
        sql, params = (
            (None, None)
            if query.aggregates
            else local.compile(tenant, allowed_indexes=indexes)
        )
        if query.group_by is None:
            # Each node must use the same stable tie-breaker for exact global top-K.
            sql = sql.rsplit(" LIMIT ?", 1)[0] + ", event_id ASC LIMIT ?"
        elif not query.aggregates:
            params[-1] = self.max_groups + 1
        if not self.store.query_slots.acquire(blocking=False):
            raise FederationError("Peer search concurrency exhausted", 503)
        connection = self.store.analytics.cursor()
        timer = threading.Timer(
            max(0.001, deadline - time.monotonic()), connection.interrupt
        )
        timer.daemon = True
        try:
            if time.monotonic() >= deadline:
                raise FederationError("Federated query deadline exceeded", 504)
            timer.start()
            if query.aggregates:
                connection.execute("BEGIN TRANSACTION")
                rows = self._aggregate_node(connection, query, tenant, indexes)
            else:
                connection.execute(sql, params)
                columns = [x[0] for x in connection.description]
                rows = [dict(zip(columns, row)) for row in connection.fetchall()]
            if time.monotonic() >= deadline:
                raise FederationError("Federated query deadline exceeded", 504)
            if query.group_by is not None and len(rows) > self.max_groups:
                raise FederationError(
                    "Exact federation aggregation exceeds group cap; narrow filters",
                    413,
                )
            value = {
                "rows": rows,
                "access_scope": indexes,
                "complete": True,
                "kind": "aggregate"
                if query.aggregates
                else "count"
                if query.group_by is not None
                else "events",
                "dataset_id": self.dataset_id,
                "replica_set": self.replica_set,
                "node_id": self.store.replica.config["node_id"]
                if self.store.replica
                else self.local_name,
                "ready": readiness["ready"],
                "applied_sequence": readiness["applied_sequence"],
                "quorum_verified": readiness["quorum_verified"],
            }
            if len(encode(value).encode()) > MAX_RESPONSE:
                raise FederationError("Peer response exceeds 2 MiB; narrow fields", 413)
            return value
        except FederationError:
            raise
        except Exception as exc:
            raise FederationError(
                "Peer analytics unavailable (" + type(exc).__name__ + ")",
                504 if time.monotonic() >= deadline else 502,
            ) from exc
        finally:
            timer.cancel()
            if timer.ident is not None:
                timer.join(timeout=1)
            connection.close()
            self.store.query_slots.release()

    def _authenticate(self, body, headers, deadline=None):
        deadline = deadline or time.monotonic() + self.timeout
        if not isinstance(body, bytes) or len(body) > MAX_BODY:
            raise FederationError("Federation request exceeds 256 KiB", 413)
        values = {str(k).lower(): str(v) for k, v in headers.items()}
        key_id = values.get("x-sapientia-key", "")
        grant = self.grants.get(key_id)
        if not grant:
            raise FederationError("Federation peer authentication failed", 401)
        stamp, nonce = (
            values.get("x-sapientia-time", ""),
            values.get("x-sapientia-nonce", ""),
        )
        if not re.fullmatch(r"[0-9]{1,12}", stamp) or not re.fullmatch(
            r"[a-f0-9]{32,64}", nonce
        ):
            raise FederationError("Invalid federation timestamp or nonce", 401)
        now = time.time()
        if abs(now - int(stamp)) > self.clock_skew:
            raise FederationError("Expired federation request", 401)
        expected = signed_headers(key_id, grant["secret"], body, stamp, nonce)
        if not hmac.compare_digest(
            values.get("authorization", "").encode(), expected["authorization"].encode()
        ) or not hmac.compare_digest(
            values.get("x-sapientia-signature", "").encode(),
            expected["x-sapientia-signature"].encode(),
        ):
            raise FederationError("Federation peer authentication failed", 401)
        with (
            _deadline_lock(self.store.write_lock, deadline),
            self.store.control(local=True) as db,
        ):
            db.execute(
                "PRAGMA busy_timeout="
                + str(max(1, int((deadline - time.monotonic()) * 1000)))
            )
            db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "DELETE FROM federation_nonces WHERE rowid IN (SELECT rowid FROM federation_nonces WHERE expires<? LIMIT 1000)",
                (now,),
            )
            if db.execute(
                "SELECT 1 FROM federation_nonces WHERE key_id=? AND nonce=?",
                (key_id, nonce),
            ).fetchone():
                raise FederationError("Federation request replay rejected", 409)
            if (
                db.execute("SELECT count(*) FROM federation_nonces").fetchone()[0]
                >= 10000
            ):
                raise FederationError("Federation replay guard capacity reached", 503)
            db.execute(
                "INSERT INTO federation_nonces VALUES(?,?,?)",
                (key_id, nonce, now + self.clock_skew * 2 + 1),
            )
        return key_id, grant

    def handle_peer(self, body, headers):
        started = time.monotonic()
        if not isinstance(body, bytes) or len(body) > MAX_BODY:
            raise FederationError("Federation request exceeds 256 KiB", 413)
        try:
            request = json.loads(body)
        except (ValueError, RecursionError):
            request = None
        budget = request.get("budget_ms") if isinstance(request, dict) else None
        deadline = started + min(
            self.timeout,
            budget / 1000
            if type(budget) is int and 1 <= budget <= 30000
            else self.timeout,
        )
        key_id, grant = self._authenticate(body, headers, deadline)
        if request is None:
            raise FederationError("Invalid federation JSON")
        if (
            not isinstance(request, dict)
            or not {"version", "recipient", "tenant", "allowed_indexes", "payload"}
            <= set(request)
            or set(request)
            - {
                "version",
                "recipient",
                "tenant",
                "allowed_indexes",
                "payload",
                "dataset_id",
                "replica_set",
                "min_sequence",
                "budget_ms",
            }
            or request["version"] != 1
            or request["recipient"] != key_id
        ):
            raise FederationError("Invalid federation request envelope")
        tenant = request["tenant"]
        if tenant not in grant["tenants"]:
            raise FederationError("Federation grant does not permit this tenant", 403)
        requested = request["allowed_indexes"]
        if requested == ["*"]:
            raise FederationError("Peer requests must specify exact index names", 403)
        indexes = _scope(requested, grant["indexes"])
        declared = request.get("dataset_id")
        if declared is not None and (
            declared != self.dataset_id
            or request.get("replica_set") != self.replica_set
            or indexes != sorted(set(requested))
        ):
            raise FederationError(
                "Peer dataset/replica or exact grant scope fence mismatch", 409
            )
        minimum, budget_ms = (
            request.get("min_sequence", 0),
            request.get("budget_ms", int(self.timeout * 1000)),
        )
        if (
            type(minimum) is not int
            or not 0 <= minimum <= 2**63 - 1
            or type(budget_ms) is not int
            or not 1 <= budget_ms <= 30000
        ):
            raise FederationError("Invalid peer sequence fence or deadline")
        query = self._parse(request["payload"])
        result = self._node(
            query,
            tenant,
            indexes,
            deadline,
            minimum,
        )
        context = (
            self.store.replica.control(deadline=deadline)
            if self.store.replica
            else self.store.control(local=True)
        )
        with _deadline_lock(self.store.write_lock, deadline), context as db:
            db.execute(
                "PRAGMA busy_timeout="
                + str(max(1, int((deadline - time.monotonic()) * 1000)))
            )
            db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
            self.store.audit(
                db,
                tenant,
                "federation:" + key_id,
                "federation.peer_search",
                {"scope": indexes, "rows": len(result["rows"]), "kind": result["kind"]},
            )
        if time.monotonic() >= deadline:
            raise FederationError("Peer audit deadline exceeded", 504)
        return result

    def _remote(self, peer, query, tenant, indexes, deadline):
        body = encode(
            {
                "version": 1,
                "recipient": peer["key_id"],
                "tenant": tenant,
                "allowed_indexes": indexes,
                "payload": self._payload(query),
                "dataset_id": peer["dataset_id"],
                "replica_set": peer["replica_set"],
                "min_sequence": max(
                    peer["min_sequence"],
                    query.minimum_sequences.get(peer["dataset_id"], 0),
                ),
                "budget_ms": max(
                    1, min(30000, int((deadline - time.monotonic()) * 1000))
                ),
            }
        ).encode()
        headers = signed_headers(peer["key_id"], peer["secret"], body)
        remaining = max(0.001, deadline - time.monotonic())
        connection = (
            http.client.HTTPSConnection(
                peer["host"], peer["port"], timeout=remaining, context=peer["context"]
            )
            if peer["https"]
            else http.client.HTTPConnection(
                peer["host"], peer["port"], timeout=remaining
            )
        )

        def connect_resolved(_address, timeout, _source_address=None):
            # DNS is resolved once from operator configuration, outside request
            # deadlines. TCP uses cached numeric addresses; TLS still verifies
            # the configured hostname/SNI through HTTPSConnection.connect().
            last = None
            addresses = peer["addresses"]
            for number, (family, kind, protocol, _canonical, address) in enumerate(
                addresses
            ):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Federation connect deadline exceeded")
                sock = socket.socket(family, kind, protocol)
                try:
                    sock.settimeout(min(timeout, remaining) / (len(addresses) - number))
                    sock.connect(address)
                    return sock
                except OSError as exc:
                    last = exc
                    sock.close()
            raise last or OSError("No configured peer addresses")

        connection._create_connection = connect_resolved
        try:
            # http.client follows neither redirects nor environment proxy settings.
            connection.request("POST", PEER_PATH, body=body, headers=headers)
            transport = connection.sock
            transport.settimeout(max(0.001, deadline - time.monotonic()))
            response = connection.getresponse()
            if response.status != 200:
                raise FederationError(
                    "Federation peer "
                    + peer["name"]
                    + " rejected the query (HTTP "
                    + str(response.status)
                    + ")",
                    response.status if response.status in {409, 413, 503, 504} else 502,
                )
            content = bytearray()
            while True:
                if time.monotonic() >= deadline:
                    raise FederationError("Federation peer deadline exceeded", 504)
                transport.settimeout(max(0.001, deadline - time.monotonic()))
                chunk = response.read1(min(65536, MAX_RESPONSE + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > MAX_RESPONSE:
                    raise FederationError("Federation peer response exceeds 2 MiB", 502)
            value = json.loads(content)
            if (
                not isinstance(value, dict)
                or value.get("complete") is not True
                or value.get("kind")
                != (
                    "aggregate"
                    if query.aggregates
                    else "count"
                    if query.group_by is not None
                    else "events"
                )
            ):
                raise FederationError(
                    "Federation peer returned an incomplete response", 502
                )
            rows = value.get("rows")
            scope = value.get("access_scope")
            if (
                not isinstance(rows, list)
                or len(rows) > (1000 if query.group_by is not None else query.limit)
                or any(not isinstance(row, dict) for row in rows)
            ):
                raise FederationError(
                    "Federation peer response schema/cap violation", 502
                )
            if not isinstance(scope, list) or set(scope) - set(indexes):
                raise FederationError(
                    "Federation peer exceeded requested index scope", 502
                )
            if (
                not isinstance(value.get("dataset_id"), str)
                or not NAME.fullmatch(value["dataset_id"])
                or value.get("ready") is not True
                or type(value.get("applied_sequence")) is not int
                or value["applied_sequence"] < 0
            ):
                raise FederationError(
                    "Federation peer readiness/identity schema violation", 502
                )
            replica_set = value.get("replica_set")
            if replica_set is not None and (
                not isinstance(replica_set, str) or not NAME.fullmatch(replica_set)
            ):
                raise FederationError(
                    "Federation peer replica identity schema violation", 502
                )
            if peer["dataset_id"] is not None and (
                value["dataset_id"] != peer["dataset_id"]
                or value.get("replica_set") != peer["replica_set"]
                or sorted(scope) != sorted(indexes)
            ):
                raise FederationError(
                    "Federation peer dataset/replica/scope fence mismatch", 409
                )
            minimum = max(
                peer["min_sequence"],
                query.minimum_sequences.get(value["dataset_id"], 0),
            )
            if value["applied_sequence"] < minimum or (
                value.get("replica_set") is not None
                and value.get("quorum_verified") is not True
            ):
                raise FederationError(
                    "Federation peer is stale or lacks a quorum read fence", 503
                )
            return value
        except FederationError:
            raise
        except Exception as exc:
            raise FederationError(
                "Federation peer "
                + peer["name"]
                + " unavailable ("
                + type(exc).__name__
                + ")",
                502,
            ) from exc
        finally:
            connection.close()

    def _dataset(self, candidates, query, tenant, deadline):
        attempts = []
        ordered = sorted(
            candidates, key=lambda x: (x[1]["preference"] if x[1] else 0, x[0])
        )
        last_error = None
        for number, (name, peer, indexes) in enumerate(ordered):
            if time.monotonic() >= deadline:
                raise FederationError("Federated dataset deadline exceeded", 504)
            try:
                attempt_deadline = time.monotonic() + (deadline - time.monotonic()) / (
                    len(ordered) - number
                )
                part = (
                    self._node(query, tenant, indexes, attempt_deadline)
                    if peer is None
                    else self._remote(peer, query, tenant, indexes, attempt_deadline)
                )
                return name, {**part, "attempts": attempts}
            except FederationError as exc:
                last_error = exc
                attempts.append({"name": name, "status": exc.status_code})
                if exc.status_code not in {502, 503, 504}:
                    raise
        raise FederationError(
            "No ready replica for dataset ("
            + str(last_error)
            + "); attempts="
            + encode(attempts),
            503,
        )

    def _reduce_metrics(self, query, parts):
        groups, reduced, pair_count = query.group_by or [], {}, 0
        expected = {x["as"] for x in query.aggregates}
        for _, part in parts:
            for row in part["rows"]:
                if (
                    any(x not in row for x in groups)
                    or not isinstance(row.get("__metrics"), dict)
                    or set(row["__metrics"]) != expected
                ):
                    raise FederationError("Invalid partial aggregate schema", 502)
                key = encode([row[x] for x in groups])
                if key not in reduced:
                    reduced[key] = {"group": {x: row[x] for x in groups}, "metrics": {}}
                    if len(reduced) > self.max_groups:
                        raise FederationError(
                            "Exact global aggregation exceeds group cap; narrow filters",
                            413,
                        )
                metrics = reduced[key]["metrics"]
                for metric in query.aggregates:
                    alias, op = metric["as"], metric["op"]
                    value = row["__metrics"][alias]
                    if not isinstance(value, dict):
                        raise FederationError("Invalid partial aggregate", 502)
                    if op == "distinct":
                        values = value.get("values")
                        if (
                            set(value) != {"values"}
                            or not isinstance(values, list)
                            or len(values) > self.max_distinct
                            or any(not isinstance(x, str) for x in values)
                        ):
                            raise FederationError("Invalid exact distinct partial", 502)
                        union = metrics.setdefault(alias, set())
                        before = len(union)
                        union.update(values)
                        pair_count += len(union) - before
                        if pair_count > self.max_distinct:
                            raise FederationError(
                                "Exact global distinct exceeds value/group pair cap",
                                413,
                            )
                        continue
                    count = value.get("count")
                    if (
                        type(count) is not int
                        or count < 0
                        or set(value)
                        != ({"count"} if op == "count" else {"value", "count"})
                    ):
                        raise FederationError("Invalid partial aggregate count", 502)
                    if op == "count":
                        metrics[alias] = metrics.get(alias, 0) + count
                        continue
                    number = value["value"]
                    if (
                        number is not None
                        and (
                            type(number) not in (int, float)
                            or not math.isfinite(number)
                        )
                    ) or (count == 0) != (number is None):
                        raise FederationError("Invalid partial numeric aggregate", 502)
                    state = metrics.setdefault(alias, [None, 0])
                    if number is not None:
                        if state[0] is None:
                            state[0] = number
                        elif op in {"sum", "avg"}:
                            state[0] += number
                        elif op == "min":
                            state[0] = min(state[0], number)
                        else:
                            state[0] = max(state[0], number)
                        if not math.isfinite(state[0]):
                            raise FederationError(
                                "Global numeric aggregate overflow", 413
                            )
                        state[1] += count
        rows = []
        for item in reduced.values():
            row = dict(item["group"])
            for metric in query.aggregates:
                alias, op = metric["as"], metric["op"]
                value = item["metrics"][alias]
                row[alias] = (
                    len(value)
                    if op == "distinct"
                    else value
                    if op == "count"
                    else value[0] / value[1]
                    if op == "avg" and value[1]
                    else value[0]
                )
                if (
                    op in {"sum", "avg", "min", "max"}
                    and row[alias] is not None
                    and abs(row[alias]) > MAX_NUMERIC
                ):
                    raise FederationError(
                        "Global numeric result exceeds the finite exact-integer profile (+/- 2^53-1)",
                        413,
                    )
            rows.append(row)
        return rows, [*groups, *(x["as"] for x in query.aggregates)]

    def search(self, who, payload, allowed_indexes):
        query = self._parse(payload)
        if not isinstance(who, dict) or not isinstance(who.get("tenant"), str):
            raise FederationError("Authenticated tenant required", 403)
        index_predicate(allowed_indexes)
        if allowed_indexes is None:
            raise FederationError(
                "An explicit authenticated index scope is required", 403
            )
        if not self.slots.acquire(blocking=False):
            raise FederationError("Federation concurrency exhausted", 503)
        deadline, parts = time.monotonic() + self.timeout, []
        try:
            work = []
            if self.include_local:
                work.append(
                    (
                        self.local_name,
                        None,
                        _scope(allowed_indexes, self.local_indexes)
                        if self.local_indexes is not None
                        else allowed_indexes,
                    )
                )
            for peer in self.peers:
                if who["tenant"] in peer["tenants"]:
                    work.append(
                        (peer["name"], peer, _scope(allowed_indexes, peer["indexes"]))
                    )
            if not work:
                raise FederationError("No configured nodes permit this tenant", 403)
            datasets = {}
            for candidate in work:
                name, peer, indexes = candidate
                identifier = self.dataset_id if peer is None else peer["dataset_id"]
                key = ("dataset", identifier) if identifier else ("legacy_peer", name)
                candidates = datasets.setdefault(key, [])
                if candidates and candidates[0][2] != indexes:
                    raise FederationError(
                        "Replica candidates must have identical effective index scopes",
                        409,
                    )
                candidates.append(candidate)
            with ThreadPoolExecutor(
                max_workers=len(datasets), thread_name_prefix="sapientia-federation"
            ) as pool:
                futures = [
                    pool.submit(
                        self._dataset, candidates, query, who["tenant"], deadline
                    )
                    for candidates in datasets.values()
                ]
                for future in futures:
                    try:
                        parts.append(
                            (
                                *future.result(
                                    timeout=max(0.001, deadline - time.monotonic())
                                ),
                            )
                        )
                    except FederationError:
                        raise
                    except Exception as exc:
                        raise FederationError(
                            "Federation failed without returning partial results ("
                            + type(exc).__name__
                            + ")",
                            504
                            if isinstance(exc, TimeoutError)
                            or time.monotonic() >= deadline
                            else 502,
                        ) from exc
            if time.monotonic() >= deadline:
                raise FederationError("Federated query deadline exceeded", 504)
            unique = {}
            replica_datasets = {}
            for name, part in sorted(
                parts, key=lambda x: (-x[1]["applied_sequence"], x[0])
            ):
                identifier = part["dataset_id"]
                replica_set = part.get("replica_set")
                if replica_set is not None:
                    if (
                        replica_set in replica_datasets
                        and replica_datasets[replica_set] != identifier
                    ):
                        raise FederationError(
                            "Full replica set returned conflicting dataset identities",
                            409,
                        )
                    replica_datasets[replica_set] = identifier
                if identifier in unique:
                    prior = unique[identifier][1]
                    if (
                        not part.get("replica_set")
                        or prior.get("replica_set") != part["replica_set"]
                        or prior["access_scope"] != part["access_scope"]
                    ):
                        raise FederationError(
                            "Conflicting dataset identities/scopes from federation peers",
                            409,
                        )
                    continue
                unique[identifier] = (name, part)
            parts = list(unique.values())
            if query.aggregates:
                rows, columns = self._reduce_metrics(query, parts)
                rows.sort(
                    key=lambda row: encode([row.get(field) for field in query.group_by])
                )
                present = [row for row in rows if row.get(query.sort) is not None]
                absent = [row for row in rows if row.get(query.sort) is None]
                present.sort(key=lambda row: row[query.sort], reverse=query.descending)
                rows = (present + absent)[: query.limit]
            elif query.group_by is not None:
                reduced = {}
                for _, part in parts:
                    for row in part["rows"]:
                        try:
                            key, count = (
                                tuple(row[field] for field in query.group_by),
                                row["count"],
                            )
                            if type(count) is not int or count < 0:
                                raise ValueError()
                        except (KeyError, ValueError) as exc:
                            raise FederationError(
                                "Invalid partial count from federation peer", 502
                            ) from exc
                        reduced[key] = reduced.get(key, 0) + count
                        if len(reduced) > self.max_groups:
                            raise FederationError(
                                "Exact global aggregation exceeds group cap; narrow filters",
                                413,
                            )
                rows = [
                    {**dict(zip(query.group_by, key)), "count": count}
                    for key, count in reduced.items()
                ]
                columns = [*query.group_by, "count"]
                rows.sort(
                    key=lambda row: encode([row.get(field) for field in query.group_by])
                )
                present = [row for row in rows if row.get(query.sort) is not None]
                absent = [row for row in rows if row.get(query.sort) is None]
                present.sort(key=lambda row: row[query.sort], reverse=query.descending)
                rows = (present + absent)[: query.limit]
            else:
                rows = []
                identities = set()
                for name, part in parts:
                    for row in part["rows"]:
                        if (
                            not isinstance(row.get("event_id"), str)
                            or not isinstance(row.get(query.sort), (int, float))
                            or not math.isfinite(row[query.sort])
                        ):
                            raise FederationError(
                                "Invalid event identity or ordering field from peer",
                                502,
                            )
                        identity = (part["dataset_id"], row["event_id"])
                        if identity in identities:
                            raise FederationError(
                                "Duplicate node/event identity from peer", 502
                            )
                        identities.add(identity)
                        rows.append(
                            {
                                **row,
                                "_node": name,
                                "_federated_id": part["dataset_id"]
                                + ":"
                                + row["event_id"],
                            }
                        )
                rows.sort(key=lambda row: (row["_node"], row["event_id"]))
                rows.sort(key=lambda row: row[query.sort], reverse=query.descending)
                columns = [*query.fields, "_node", "_federated_id"]
                rows = [
                    {field: row.get(field) for field in columns}
                    for row in rows[: query.limit]
                ]
            result = {
                "columns": columns,
                "rows": rows,
                "returned": len(rows),
                "limit": query.limit,
                "at_limit": len(rows) == query.limit,
                "complete": True,
                "nodes": [
                    {
                        "name": name,
                        "access_scope": part["access_scope"],
                        "dataset_id": part["dataset_id"],
                        "replica_set": part.get("replica_set"),
                        "applied_sequence": part["applied_sequence"],
                        "attempts": part.get("attempts", []),
                    }
                    for name, part in parts
                ],
                "pagination": "bounded global top-K; no full-result cursor",
                "aggregation": "full filtered indexed windows; exact typed distinct; exact integer sums, finite DOUBLE mixed/fractional arithmetic; +/-2^53-1 numeric input/result bound; numeric strings excluded",
                "consistency": "one ready reader per dataset; replicated datasets require quorum barriers; no cross-dataset atomic snapshot",
                "elapsed_ms": round(
                    (self.timeout - (deadline - time.monotonic())) * 1000, 2
                ),
            }
            if len(encode(result).encode()) > MAX_RESPONSE:
                raise FederationError("Global federation result exceeds 2 MiB", 413)
            return result
        finally:
            self.slots.release()
