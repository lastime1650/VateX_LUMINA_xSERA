"""Versioned tenant correlation content, executable fixtures and atomic rollout.

Version 1 deliberately requires one exact index per package. Every deployed
step receives that index filter; a broader owner ACL cannot broaden its scope.
Fixtures use bound JSON in a CTE shadowing events, never the tenant's live data.
Live prerequisite checks prove recent field presence, not detection efficacy.
"""

import hashlib
import json
import math
import re
import time
import uuid

from . import detections, principal
from .access import validate as validate_indexes
from .query import Query, column
from .sigma_rules import preview_sigma
from .storage import CapacityError, ConflictError, encode, normalize

NAME = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
SOURCE = re.compile(r"[A-Za-z0-9_.:-]{1,80}\Z")
EDIT = ("admin", "analyst")
MAX_PACKAGE = 1024 * 1024
__all__ = ["preview_sigma"]


def initialize(store):
    with store.control(local=True) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS content_packages(
          tenant TEXT NOT NULL,name TEXT NOT NULL,owner TEXT NOT NULL,
          latest_revision TEXT NOT NULL,active_revision TEXT,version INTEGER NOT NULL,
          created REAL NOT NULL,updated REAL NOT NULL,PRIMARY KEY(tenant,name));
        CREATE TABLE IF NOT EXISTS content_revisions(
          tenant TEXT NOT NULL,name TEXT NOT NULL,revision TEXT NOT NULL,
          payload TEXT NOT NULL,actor TEXT NOT NULL,created REAL NOT NULL,
          PRIMARY KEY(tenant,name,revision));
        CREATE TABLE IF NOT EXISTS content_tests(
          tenant TEXT NOT NULL,name TEXT NOT NULL,revision TEXT NOT NULL,
          result TEXT NOT NULL,actor TEXT NOT NULL,scope TEXT NOT NULL,at REAL NOT NULL,
          PRIMARY KEY(tenant,name,revision));
        CREATE TABLE IF NOT EXISTS content_policy_map(
          tenant TEXT NOT NULL,name TEXT NOT NULL,rule_key TEXT NOT NULL,
          policy_id TEXT NOT NULL UNIQUE,revision TEXT NOT NULL,
          PRIMARY KEY(tenant,name,rule_key));
        CREATE TABLE IF NOT EXISTS content_rollouts(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,name TEXT NOT NULL,
          revision TEXT NOT NULL,previous TEXT,action TEXT NOT NULL,
          actor TEXT NOT NULL,created REAL NOT NULL);
        CREATE INDEX IF NOT EXISTS content_rollout_revision ON content_rollouts(tenant,name,revision);
        """)


def _name(name):
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise ValueError(
            "Content names require a lowercase letter followed by at most 63 lowercase letters, digits, '-' or '_'"
        )
    return name


def _bounded_json(body):
    try:
        serialized = json.dumps(body, allow_nan=False, ensure_ascii=False)
    except (TypeError, ValueError, RecursionError):
        raise ValueError("Package must be finite bounded JSON") from None
    if len(serialized.encode()) > MAX_PACKAGE:
        raise ValueError("Content package exceeds 1 MiB")


def validate(body):
    """Canonicalize the supported correlation package schema without I/O."""
    _bounded_json(body)
    if (
        not isinstance(body, dict)
        or set(body)
        != {"schema_version", "name", "title", "prerequisites", "rules", "fixtures"}
        or type(body["schema_version"]) is not int
        or body["schema_version"] != 1
    ):
        raise ValueError("Expected v1 correlation content package fields")
    name = _name(body["name"])
    if not isinstance(body["title"], str) or not 1 <= len(body["title"]) <= 120:
        raise ValueError("Package title requires 1..120 characters")
    prereq = body["prerequisites"]
    if not isinstance(prereq, dict) or set(prereq) != {"indexes", "sources"}:
        raise ValueError("Prerequisites require indexes and sources")
    indexes = validate_indexes(prereq["indexes"])
    if len(indexes) != 1 or indexes == ["*"]:
        raise ValueError(
            "Package v1 requires exactly one concrete index; multi-index policies are unsupported"
        )
    sources = prereq["sources"]
    if not isinstance(sources, list) or not 1 <= len(sources) <= 8:
        raise ValueError("Declare 1..8 source prerequisites")
    canonical_sources, categories = [], set()
    for source in sources:
        if not isinstance(source, dict) or set(source) != {
            "category",
            "sourcetypes",
            "required_fields",
        }:
            raise ValueError(
                "Source prerequisite requires category, sourcetypes and required_fields"
            )
        category = _name(source["category"])
        types, fields = source["sourcetypes"], source["required_fields"]
        if (
            category in categories
            or not isinstance(types, list)
            or not 1 <= len(types) <= 8
            or any(not isinstance(x, str) or not SOURCE.fullmatch(x) for x in types)
        ):
            raise ValueError(
                "Source categories must be unique; supply 1..8 bounded sourcetypes"
            )
        if not isinstance(fields, list) or not 1 <= len(fields) <= 12:
            raise ValueError("Source requires 1..12 scalar fields")
        for item in fields:
            if column(item) == "raw":
                raise ValueError("Required fields must be scalar")
        categories.add(category)
        canonical_sources.append(
            {
                "category": category,
                "sourcetypes": sorted(set(types)),
                "required_fields": sorted(set(fields)),
            }
        )
    rules = body["rules"]
    if not isinstance(rules, list) or not 1 <= len(rules) <= 20:
        raise ValueError("Package requires 1..20 correlation rules")
    canonical_rules, rule_keys = [], set()
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != {"key", "policy"}:
            raise ValueError("Rule requires key and correlation policy")
        key = _name(rule["key"])
        if key in rule_keys:
            raise ValueError("Duplicate rule key")
        definition = detections.validate(rule["policy"])
        for step in definition["steps"]:
            if len(step["filters"]) >= 20:
                raise ValueError(
                    "Leave one filter slot for mandatory package index scope"
                )
        canonical_rules.append({"key": key, "policy": definition})
        rule_keys.add(key)
    fixtures = body["fixtures"]
    if not isinstance(fixtures, list) or not 2 <= len(fixtures) <= 12:
        raise ValueError("Provide 2..12 positive/negative fixtures")
    canonical_fixtures, fixture_names, event_count = [], set(), 0
    for fixture in fixtures:
        if not isinstance(fixture, dict) or set(fixture) != {
            "name",
            "end",
            "events",
            "expect",
        }:
            raise ValueError("Fixture requires name, end, events and expect")
        title = _name(fixture["name"])
        end, events, expected = fixture["end"], fixture["events"], fixture["expect"]
        if (
            title in fixture_names
            or isinstance(end, bool)
            or not isinstance(end, (int, float))
            or not math.isfinite(end)
            or end <= 0
        ):
            raise ValueError(
                "Fixture names must be unique and end a positive finite epoch"
            )
        if (
            not isinstance(events, list)
            or len(events) > 100
            or not isinstance(expected, dict)
            or set(expected) != rule_keys
        ):
            raise ValueError(
                "Each fixture accepts <=100 events and exact entity expectations for every rule"
            )
        normalized, event_ids = [], set()
        for i, event in enumerate(events):
            if not isinstance(event, dict) or "event_time" not in event:
                raise ValueError("Fixture events require explicit event_time")
            item = dict(event)
            item.setdefault("event_id", f"fixture:{title}:{i}")
            item.setdefault("index", indexes[0])
            item = normalize(item)
            if item["index"] != indexes[0] or item["event_id"] in event_ids:
                raise ValueError(
                    "Fixture event index must match package and IDs must be unique"
                )
            event_ids.add(item["event_id"])
            normalized.append(item)
        expectations = {}
        for key, values in expected.items():
            if (
                not isinstance(values, list)
                or len(values) > 100
                or any(not isinstance(x, str) or not 1 <= len(x) <= 256 for x in values)
                or len(values) != len(set(values))
            ):
                raise ValueError(
                    "Fixture expectations require unique bounded entity strings"
                )
            expectations[key] = sorted(values)
        event_count += len(events)
        fixture_names.add(title)
        canonical_fixtures.append(
            {
                "name": title,
                "end": float(end),
                "events": normalized,
                "expect": expectations,
            }
        )
    if event_count > 400:
        raise ValueError("Package fixture budget is 400 events")
    for key in rule_keys:
        expected_sets = [f["expect"][key] for f in canonical_fixtures]
        if not any(expected_sets) or not any(not x for x in expected_sets):
            raise ValueError(
                "Every rule requires positive and negative fixture assertions"
            )
    result = {
        "schema_version": 1,
        "name": name,
        "title": body["title"],
        "prerequisites": {"indexes": indexes, "sources": canonical_sources},
        "rules": canonical_rules,
        "fixtures": canonical_fixtures,
    }
    _bounded_json(result)
    return result


def _revision(body):
    return hashlib.sha256(encode(body).encode()).hexdigest()


def _authorized(db, actor, name, revision=None):
    _name(name)
    if revision is not None and (
        not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{64}", revision)
    ):
        raise ValueError("Revision must be an exact SHA256")
    package = db.execute(
        "SELECT * FROM content_packages WHERE tenant=? AND name=?",
        (actor["tenant"], name),
    ).fetchone()
    if not package:
        raise KeyError("Content package is unavailable")
    revision = revision or package["latest_revision"]
    row = db.execute(
        "SELECT * FROM content_revisions WHERE tenant=? AND name=? AND revision=?",
        (actor["tenant"], name, revision),
    ).fetchone()
    if not row:
        raise KeyError("Content revision is unavailable")
    payload = json.loads(row["payload"])
    if _revision(payload) != revision:
        raise ConflictError("Content revision checksum does not match")
    if not principal.contains(
        actor["allowed_indexes"], payload["prerequisites"]["indexes"]
    ):
        raise PermissionError("Content package requires indexes outside current access")
    return dict(package), dict(row), payload


def save(store, who, body, expected_version=0):
    body = validate(body)
    if type(expected_version) is not int or expected_version < 0:
        raise ValueError("expected_version must be a nonnegative integer")
    revision, now = _revision(body), time.time()
    with principal.transaction(store, who, EDIT, write=True) as (db, actor):
        tenant, name = actor["tenant"], body["name"]
        if not principal.contains(
            actor["allowed_indexes"], body["prerequisites"]["indexes"]
        ):
            raise PermissionError("Package index is outside current access")
        old = db.execute(
            "SELECT * FROM content_packages WHERE tenant=? AND name=?", (tenant, name)
        ).fetchone()
        if expected_version != (old["version"] if old else 0):
            raise ConflictError("Content package changed; reload its version")
        # Durable inventory/history has no lifetime record-count ceiling.
        if old:
            _, _, previous_payload = _authorized(db, actor, name)
            if (
                previous_payload["prerequisites"]["indexes"]
                != body["prerequisites"]["indexes"]
            ):
                raise ConflictError(
                    "Package index scope is immutable; create a separately named package"
                )
        exists = db.execute(
            "SELECT 1 FROM content_revisions WHERE tenant=? AND name=? AND revision=?",
            (tenant, name, revision),
        ).fetchone()
        if not exists:
            # Durable inventory/history has no lifetime record-count ceiling.
            db.execute(
                "INSERT INTO content_revisions VALUES(?,?,?,?,?,?)",
                (tenant, name, revision, encode(body), actor["name"], now),
            )
        version = expected_version + 1
        if old:
            db.execute(
                "UPDATE content_packages SET latest_revision=?,version=?,updated=? WHERE tenant=? AND name=?",
                (revision, version, now, tenant, name),
            )
        else:
            db.execute(
                "INSERT INTO content_packages VALUES(?,?,?,?,NULL,?,?,?)",
                (tenant, name, actor["name"], revision, version, now, now),
            )
        store.audit(
            db,
            tenant,
            actor["name"],
            "content.save",
            {"name": name, "revision": revision, "version": version},
        )
        tested = db.execute(
            "SELECT result FROM content_tests WHERE tenant=? AND name=? AND revision=?",
            (tenant, name, revision),
        ).fetchone()
        state = (
            "active"
            if old and old["active_revision"] == revision
            else "tested"
            if tested and json.loads(tested["result"])["passed"]
            else "draft"
        )
    return {"name": name, "revision": revision, "version": version, "state": state}


def get(store, who, name, revision=None):
    with principal.transaction(store, who) as (db, actor):
        package, row, payload = _authorized(db, actor, name, revision)
        tested = db.execute(
            "SELECT * FROM content_tests WHERE tenant=? AND name=? AND revision=?",
            (actor["tenant"], name, row["revision"]),
        ).fetchone()
        history = db.execute(
            "SELECT revision,actor,created FROM content_revisions WHERE tenant=? AND name=? ORDER BY created DESC",
            (actor["tenant"], name),
        ).fetchall()
        rollouts = db.execute(
            "SELECT revision,previous,action,actor,created FROM content_rollouts WHERE tenant=? AND name=? ORDER BY created DESC",
            (actor["tenant"], name),
        ).fetchall()
    result = json.loads(tested["result"]) if tested else None
    return {
        **package,
        "revision": row["revision"],
        "payload": payload,
        "state": "active"
        if package["active_revision"] == row["revision"]
        else "tested"
        if result and result["passed"]
        else "draft",
        "test": result,
        "history": [dict(r) for r in history],
        "rollouts": [dict(r) for r in rollouts],
    }


def list_for(store, who):
    with principal.transaction(store, who) as (db, actor):
        rows = db.execute(
            "SELECT p.*,r.payload FROM content_packages p JOIN content_revisions r ON r.tenant=p.tenant AND r.name=p.name AND r.revision=p.latest_revision WHERE p.tenant=? ORDER BY p.name",
            (actor["tenant"],),
        ).fetchall()
        result = []
        for row in rows:
            payload = json.loads(row["payload"])
            if principal.contains(
                actor["allowed_indexes"], payload["prerequisites"]["indexes"]
            ):
                result.append(
                    {k: v for k, v in dict(row).items() if k != "payload"}
                    | {
                        "title": payload["title"],
                        "prerequisites": payload["prerequisites"],
                        "rule_count": len(payload["rules"]),
                        "mitre": sorted(
                            {t for r in payload["rules"] for t in r["policy"]["mitre"]}
                        ),
                    }
                )
    return result


def _scoped(policy, index):
    policy = json.loads(encode(policy))
    for step in policy["steps"]:
        step["filters"].append({"field": "index", "op": "eq", "value": index})
    return detections.validate(policy)


class _FixtureStore:
    def __init__(self, store, tenant, events):
        self.store = store
        self.settings = store.settings
        self.events = [
            {
                **e,
                "tenant": tenant,
                "received": e["event_time"],
                "index_name": e["index"],
            }
            for e in events
        ]

    def search(self, tenant, payload, allowed_indexes=None, cancel=None):
        query = Query.parse(payload)
        sql, args = query.compile(tenant, allowed_indexes=allowed_indexes)
        result = self.analytics_query(sql, args, max_rows=query.limit, cancel=cancel)
        return {**result, "at_limit": result["returned"] == query.limit}

    def analytics_query(self, sql, args, *, max_rows=1000, cancel=None, timeout=None):
        # Shadow the same logical relation used by both query compilers. This
        # keeps executable fixtures isolated from hot and sealed live events.
        prefix = """WITH events_all AS (SELECT value->>'tenant' AS tenant,value->>'event_id' AS event_id,
        TRY_CAST(value->>'event_time' AS DOUBLE) AS event_time,TRY_CAST(value->>'received' AS DOUBLE) AS received,
        value->>'source' AS source,value->>'sourcetype' AS sourcetype,value->>'host' AS host,
        value->>'severity' AS severity,value->>'message' AS message,value->>'raw' AS raw,
        value->>'index_name' AS index_name FROM json_each(?)) """
        statement = (
            prefix.rstrip() + "," + sql[5:] if sql.startswith("WITH ") else prefix + sql
        )
        return self.store.analytics_query(
            statement,
            [encode(self.events), *args],
            max_rows=max_rows,
            cancel=cancel,
            timeout=timeout,
        )


def test(store, who, name, revision=None):
    with principal.transaction(store, who, EDIT) as (db, actor):
        _, row, payload = _authorized(db, actor, name, revision)
    revision = row["revision"]
    results = []
    started = time.monotonic()
    for fixture in payload["fixtures"]:
        fixture_store = _FixtureStore(store, actor["tenant"], fixture["events"])
        for rule in payload["rules"]:
            if time.monotonic() - started > 5:
                raise CapacityError("Fixture execution budget exceeded")
            matched = detections.evaluate(
                fixture_store,
                actor["tenant"],
                _scoped(rule["policy"], payload["prerequisites"]["indexes"][0]),
                fixture["end"],
                actor["allowed_indexes"],
            )
            observed = sorted(m["entity"] for m in matched)
            expected = fixture["expect"][rule["key"]]
            results.append(
                {
                    "fixture": fixture["name"],
                    "rule": rule["key"],
                    "expected": expected,
                    "observed": observed,
                    "passed": observed == expected,
                }
            )
    result = {
        "revision": revision,
        "passed": all(r["passed"] for r in results),
        "assertions": results,
        "fixture_only": True,
        "tested_at": time.time(),
    }
    with principal.transaction(store, who, EDIT, write=True) as (db, fresh):
        if fresh != actor:
            raise PermissionError("Permissions changed during fixture execution")
        _authorized(db, fresh, name, revision)
        db.execute(
            "INSERT INTO content_tests VALUES(?,?,?,?,?,?,?) ON CONFLICT(tenant,name,revision) DO UPDATE SET result=excluded.result,actor=excluded.actor,scope=excluded.scope,at=excluded.at",
            (
                actor["tenant"],
                name,
                revision,
                encode(result),
                actor["name"],
                encode(actor["allowed_indexes"]),
                result["tested_at"],
            ),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "content.test",
            {
                "name": name,
                "revision": revision,
                "passed": result["passed"],
                "assertions": len(results),
            },
        )
    return result


def coverage(store, who, name, revision=None, lookback=86400):
    if type(lookback) is not int or not 60 <= lookback <= 604800:
        raise ValueError("Coverage lookback must be 60..604800 seconds")
    with principal.transaction(store, who) as (db, actor):
        _, row, payload = _authorized(db, actor, name, revision)
    now = time.time()
    statements, args = [], []
    for source in payload["prerequisites"]["sources"]:
        conditions = [
            "(" + column(f) + " IS NOT NULL AND CAST(" + column(f) + " AS VARCHAR)<>'')"
            for f in source["required_fields"]
        ]
        statements.append(
            "SELECT ? AS category,count(*) AS events,COALESCE(sum(CASE WHEN "
            + " AND ".join(conditions)
            + " THEN 1 ELSE 0 END),0) AS complete_events FROM events_all WHERE tenant=? AND index_name=? AND event_time>=? AND event_time<? AND sourcetype IN ("
            + ",".join("?" for _ in source["sourcetypes"])
            + ")"
        )
        args.extend(
            [
                source["category"],
                actor["tenant"],
                payload["prerequisites"]["indexes"][0],
                now - lookback,
                now,
                *source["sourcetypes"],
            ]
        )
    rows = store.analytics_query(" UNION ALL ".join(statements), args, max_rows=8)[
        "rows"
    ]
    principal.recheck(store, actor)
    return {
        "revision": row["revision"],
        "lookback": lookback,
        "at": now,
        "ready": all(r["complete_events"] > 0 for r in rows),
        "sources": rows,
        "meaning": "Recent required-field presence on the declared exact index; not semantic efficacy or complete attack coverage",
        "mitre": sorted(
            {tag for r in payload["rules"] for tag in r["policy"]["mitre"]}
        ),
    }


def _activate(store, who, name, revision, expected_active, action):
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{64}", revision):
        raise ValueError("An exact revision SHA256 is required")
    if expected_active is not None and (
        not isinstance(expected_active, str)
        or not re.fullmatch(r"[0-9a-f]{64}", expected_active)
    ):
        raise ValueError("expected_active must be null or an exact revision SHA256")
    with principal.transaction(store, who, ("admin",)) as (db, actor):
        _authorized(db, actor, name, revision)
    check = coverage(store, who, name, revision)
    if not check["ready"]:
        raise ValueError(
            "Live source/field prerequisites are missing; inspect coverage before publishing"
        )
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        package, _, payload = _authorized(db, actor, name, revision)
        if package["active_revision"] != expected_active:
            raise ConflictError(
                "Active content revision changed; reload before rollout"
            )
        if (
            action == "content.rollback"
            and not db.execute(
                "SELECT 1 FROM content_rollouts WHERE tenant=? AND name=? AND revision=? LIMIT 1",
                (actor["tenant"], name, revision),
            ).fetchone()
        ):
            raise ValueError(
                "Rollback requires a previously activated revision; publish a tested draft instead"
            )
        tested = db.execute(
            "SELECT result FROM content_tests WHERE tenant=? AND name=? AND revision=?",
            (actor["tenant"], name, revision),
        ).fetchone()
        if not tested or not json.loads(tested["result"])["passed"]:
            raise ValueError(
                "Publish requires passing fixture assertions for this exact revision"
            )
        old = db.execute(
            "SELECT * FROM content_policy_map WHERE tenant=? AND name=?",
            (actor["tenant"], name),
        ).fetchall()
        previous = {r["rule_key"]: r for r in old}
        new_count = sum(r["key"] not in previous for r in payload["rules"])
        current_count = db.execute(
            "SELECT count(*) FROM correlation_policies WHERE tenant=?",
            (actor["tenant"],),
        ).fetchone()[0]
        # Durable inventory/history has no lifetime record-count ceiling.
        now, ids = time.time(), []
        for entry in old:
            db.execute(
                "UPDATE correlation_policies SET enabled=0,version=version+1 WHERE id=? AND tenant=?",
                (entry["policy_id"], actor["tenant"]),
            )
        for rule in payload["rules"]:
            policy_id = (
                previous[rule["key"]]["policy_id"]
                if rule["key"] in previous
                else str(uuid.uuid4())
            )
            policy = _scoped(rule["policy"], payload["prerequisites"]["indexes"][0])
            db.execute(
                """INSERT INTO correlation_policies(id,tenant,owner,name,definition,enabled,next_run) VALUES(?,?,?,?,?,?,?)
              ON CONFLICT(id) DO UPDATE SET owner=excluded.owner,name=excluded.name,definition=excluded.definition,
              enabled=excluded.enabled,next_run=excluded.next_run,retry_at=0,failures=0,last_end=NULL,error=NULL,version=correlation_policies.version+1""",
                (
                    policy_id,
                    actor["tenant"],
                    actor["name"],
                    policy["name"],
                    encode(policy),
                    int(policy["enabled"]),
                    now,
                ),
            )
            db.execute(
                "INSERT INTO content_policy_map VALUES(?,?,?,?,?) ON CONFLICT(tenant,name,rule_key) DO UPDATE SET revision=excluded.revision",
                (actor["tenant"], name, rule["key"], policy_id, revision),
            )
            ids.append(policy_id)
        db.execute(
            "UPDATE content_packages SET active_revision=?,version=version+1,updated=? WHERE tenant=? AND name=?",
            (revision, now, actor["tenant"], name),
        )
        db.execute(
            "INSERT INTO content_rollouts VALUES(?,?,?,?,?,?,?,?)",
            (
                str(uuid.uuid4()),
                actor["tenant"],
                name,
                revision,
                expected_active,
                action,
                actor["name"],
                now,
            ),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            action,
            {
                "name": name,
                "previous": expected_active,
                "revision": revision,
                "policy_ids": ids,
                "coverage": check,
            },
        )
    return {
        "name": name,
        "revision": revision,
        "version": package["version"] + 1,
        "state": "active",
        "policy_ids": ids,
        "coverage": check,
    }


def publish(store, who, name, revision, expected_active=None):
    return _activate(store, who, name, revision, expected_active, "content.publish")


def rollback(store, who, name, revision, expected_active=None):
    return _activate(store, who, name, revision, expected_active, "content.rollback")


def export_package(store, who, name, revision=None):
    value = get(store, who, name, revision)
    return {
        "revision": value["revision"],
        "package": value["payload"],
        "format": "sapientia-correlation-content-v1",
    }


def dry_run(store, who, body):
    payload = validate(body)
    with principal.transaction(store, who, EDIT) as (_, actor):
        if not principal.contains(
            actor["allowed_indexes"], payload["prerequisites"]["indexes"]
        ):
            raise PermissionError("Package index is outside current access")
    return {
        "revision": _revision(payload),
        "package": payload,
        "changed": False,
        "publishable": False,
        "requirements": [
            "Save immutable revision",
            "Pass positive and negative fixture assertions",
            "Verify recent live source/field prerequisites",
            "Administrator publishes with expected_active revision",
        ],
        "mitre": sorted(
            {tag for r in payload["rules"] for tag in r["policy"]["mitre"]}
        ),
    }


list_packages = list_for
export = export_package
