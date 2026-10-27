"""Ordered, explainable multi-source detections and evidence-backed entity risk.

No inferred AI scores: policy weights, time decay and source event identifiers
are exposed. Candidate limits fail visibly instead of silently missing matches.
"""

import base64
import hashlib
import json
import math
import re
import sqlite3
import time
import uuid
from collections import defaultdict
from contextlib import contextmanager

from .query import ALIASES, Query, column
from .storage import CapacityError, ConflictError, encode

STATES = {"new", "triage", "resolved", "false_positive"}
MAX_EVIDENCE_BYTES = 512 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
QUERY_BUDGET_SECONDS = 2.0


def initialize(store):
    with store.control(local=True) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS correlation_policies(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,name TEXT NOT NULL,
          definition TEXT NOT NULL,enabled INTEGER NOT NULL,next_run REAL NOT NULL,
          retry_at REAL NOT NULL DEFAULT 0,failures INTEGER NOT NULL DEFAULT 0,
          last_end REAL,error TEXT,version INTEGER NOT NULL DEFAULT 1);
        CREATE INDEX IF NOT EXISTS correlation_due ON correlation_policies(enabled,retry_at,next_run);
        CREATE TABLE IF NOT EXISTS incidents(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,entity TEXT NOT NULL,entity_field TEXT NOT NULL,
          name TEXT NOT NULL,created REAL NOT NULL,updated REAL NOT NULL,status TEXT NOT NULL,
          owner TEXT NOT NULL DEFAULT '',version INTEGER NOT NULL DEFAULT 1);
        CREATE INDEX IF NOT EXISTS incident_entities ON incidents(tenant,entity_field,entity,updated);
        CREATE TABLE IF NOT EXISTS risk_contributions(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,incident_id TEXT NOT NULL,policy_id TEXT NOT NULL,
          entity TEXT NOT NULL,entity_field TEXT NOT NULL,at REAL NOT NULL,weight INTEGER NOT NULL,
          evidence TEXT NOT NULL,indexes TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS risk_entities ON risk_contributions(tenant,at,entity_field,entity);
        CREATE INDEX IF NOT EXISTS risk_policy_entity ON risk_contributions(policy_id,entity,at);
        CREATE INDEX IF NOT EXISTS risk_incident ON risk_contributions(incident_id);
        CREATE TABLE IF NOT EXISTS incident_feedback(
          id INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT NOT NULL,incident_id TEXT NOT NULL,
          actor TEXT NOT NULL,at REAL NOT NULL,status TEXT NOT NULL,note TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS incidents_recent ON incidents(tenant,updated DESC,id DESC);
        CREATE INDEX IF NOT EXISTS risk_entity_evidence ON risk_contributions(tenant,entity_field,entity,at DESC,id DESC);
        CREATE INDEX IF NOT EXISTS incident_feedback_recent ON incident_feedback(tenant,incident_id,at DESC,id DESC);
        CREATE TABLE IF NOT EXISTS incident_episodes(
          incident_id TEXT PRIMARY KEY,tenant TEXT NOT NULL,episode_key TEXT NOT NULL,
          grade TEXT NOT NULL,basis TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS incident_episode_lookup
          ON incident_episodes(tenant,episode_key,incident_id);
        CREATE TABLE IF NOT EXISTS correlation_window_progress(
          policy_id TEXT NOT NULL,version INTEGER NOT NULL,data_end REAL NOT NULL,
          tenant TEXT NOT NULL,window_start REAL NOT NULL,scope TEXT NOT NULL,
          entity_after TEXT,terminal_after TEXT,revision INTEGER NOT NULL DEFAULT 0,
          pages INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(policy_id,version,data_end));
        CREATE TABLE IF NOT EXISTS correlation_replays(
          id TEXT PRIMARY KEY,tenant TEXT NOT NULL,actor TEXT NOT NULL,request_id TEXT NOT NULL,
          policy_id TEXT NOT NULL,version INTEGER NOT NULL,window_end REAL NOT NULL,
          definition_digest TEXT NOT NULL,scope TEXT NOT NULL,result TEXT NOT NULL,created REAL NOT NULL,
          UNIQUE(tenant,actor,request_id));
        CREATE TABLE IF NOT EXISTS policy_activation_gates(policy_id TEXT PRIMARY KEY,
          template_id TEXT NOT NULL,index_name TEXT NOT NULL,definition_digest TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS template_readiness(tenant TEXT NOT NULL,template_id TEXT NOT NULL,
          index_name TEXT NOT NULL,definition_digest TEXT NOT NULL,result TEXT NOT NULL,updated REAL NOT NULL,
          PRIMARY KEY(tenant,template_id,index_name));
        """)
    from .detection_automation import initialize as initialize_automation

    initialize_automation(store)


def journal_indexed(store, db, indexed_rows):
    """Atomic local ACK hook; rows are original queue seq/tenant/event_id/payload/received."""
    from .detection_automation import journal_indexed as journal_late

    journal_late(store, db, indexed_rows)


def validate(data):
    keys = {
        "name",
        "entity_field",
        "window",
        "interval",
        "cooldown",
        "risk_score",
        "severity",
        "mitre",
        "steps",
        "enabled",
        "evaluation_delay",
        "late_recovery",
        "relation",
        "case_grouping",
    }
    if not isinstance(data, dict) or set(data) - keys:
        raise ValueError("Unknown correlation policy property")
    name = data.get("name")
    if not isinstance(name, str) or not 1 <= len(name) <= 120:
        raise ValueError("Policy name requires 1..120 characters")
    entity = data.get("entity_field", "host")
    if not isinstance(entity, str):
        raise ValueError("entity_field must be a field name")  # noqa: TRY004 - API validation uses ValueError.
    entity_column = column(entity)
    if entity_column in {"raw", "message", "event_id", "event_time", "received"}:
        raise ValueError("Choose a scalar entity field such as host or raw.user")
    result = {"name": name, "entity_field": entity}
    if "case_grouping" in data:
        if not isinstance(data["case_grouping"], str) or data["case_grouping"] not in {"legacy_hypothesis", "require_exact_identity"}:
            raise ValueError("Case grouping must be legacy_hypothesis or require_exact_identity")
        result["case_grouping"] = data["case_grouping"]
    for key, default, low, high in [
        ("window", 900, 30, 604800),
        ("interval", 30, 30, 86400),
        ("cooldown", 900, 0, 604800),
        ("risk_score", 40, 1, 100),
        ("evaluation_delay", 0, 0, 86400),
        ("late_recovery", 900, 0, 86400),
    ]:
        value = data.get(key, default)
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f"{key} must be an integer in {low}..{high}")
        result[key] = value
    if result["interval"] > result["window"]:
        raise ValueError("interval must not exceed window")
    result["enabled"] = data.get("enabled", True)
    if type(result["enabled"]) is not bool:
        raise ValueError("enabled must be boolean")
    result["severity"] = data.get("severity", "high")
    if not isinstance(result["severity"], str) or result["severity"] not in {
        "info",
        "low",
        "medium",
        "high",
        "critical",
    }:
        raise ValueError("Invalid severity")
    tags = data.get("mitre", [])
    if (
        not isinstance(tags, list)
        or len(tags) > 16
        or any(
            not isinstance(x, str) or not re.fullmatch(r"T\d{4}(?:\.\d{3})?", x)
            for x in tags
        )
    ):
        raise ValueError("mitre must contain up to 16 technique IDs")
    result["mitre"] = sorted(set(tags))
    relation = data.get("relation")
    if relation is not None:
        if (
            not isinstance(relation, dict)
            or set(relation) != {"mode", "field"}
            or not isinstance(relation["mode"], str)
            or relation["mode"] not in {"same_value", "parent_guid"}
        ):
            raise ValueError(
                "Relation requires same_value or parent_guid and explicit field"
            )
        column(relation["field"])
        if not relation["field"].startswith("raw."):
            raise ValueError("Relation identity must be an explicit raw scalar field")
        if (
            relation["mode"] == "parent_guid"
            and relation["field"] != "raw.xdr.data.process.guid"
        ):
            raise ValueError("parent_guid relation uses raw.xdr.data.process.guid")
        result["relation"] = dict(relation)
    steps = data.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= 8:
        raise ValueError("A correlation requires 1..8 ordered steps")
    result["steps"] = []
    for position, step in enumerate(steps):
        if not isinstance(step, dict) or set(step) - {
            "name",
            "filters",
            "text",
            "min_count",
            "within_seconds",
            "exclusions",
        }:
            raise ValueError(
                "Step accepts name, filters, text, min_count and within_seconds"
            )
        title = step.get("name", "Match")
        count = step.get("min_count", 1)
        if (
            not isinstance(title, str)
            or not 1 <= len(title) <= 80
            or type(count) is not int
            or not 1 <= count <= 100
        ):
            raise ValueError("Step name 1..80 and min_count 1..100 required")
        item = {
            "name": title,
            "filters": step.get("filters", []),
            "text": step.get("text", ""),
            "min_count": count,
        }
        exclusions = step.get("exclusions", [])
        if (
            not isinstance(exclusions, list)
            or len(exclusions) > 8
            or any(
                not isinstance(group, list) or not 1 <= len(group) <= 8
                for group in exclusions
            )
        ):
            raise ValueError("Step exclusions require up to8 AND groups of1..8 filters")
        for group in exclusions:
            Query.parse(
                {"language": "json", "query": {"filters": group, "fields": [entity]}}
            )
        if exclusions:
            item["exclusions"] = exclusions
        if "within_seconds" in step:
            within = step["within_seconds"]
            if (
                position == 0
                or type(within) is not int
                or not 1 <= within <= result["window"]
                or count != 1
            ):
                raise ValueError(
                    "within_seconds requires a following single-event step and 1..window seconds"
                )
            item["within_seconds"] = within
        Query.parse(
            {
                "language": "json",
                "query": {
                    "filters": item["filters"],
                    "text": item["text"],
                    "fields": [entity],
                },
            }
        )
        result["steps"].append(item)
    if any("within_seconds" in step for step in result["steps"]) and any(
        step["min_count"] != 1 for step in result["steps"]
    ):
        raise ValueError(
            "Timed correlation currently requires min_count=1 in every step"
        )
    if relation and any(step["min_count"] != 1 for step in result["steps"]):
        raise ValueError("Related correlation requires min_count=1 for all steps")
    if len(encode(result).encode()) > 32768:
        raise ValueError("Correlation policy exceeds 32 KiB")
    return result


def save(store, who, data, *, activation_gate=None):
    from . import principal

    definition = validate(data)
    policy_id = str(uuid.uuid4())
    with principal.transaction(store, who, ("admin", "analyst"), write=True) as (
        db,
        actor,
    ):
        # Durable inventory/history has no lifetime record-count ceiling.
        db.execute(
            "INSERT INTO correlation_policies(id,tenant,owner,name,definition,enabled,next_run) VALUES(?,?,?,?,?,?,?)",
            (
                policy_id,
                actor["tenant"],
                actor["name"],
                definition["name"],
                encode(definition),
                int(definition["enabled"]),
                time.time(),
            ),
        )
        if activation_gate is not None:
            template_id, index = activation_gate
            db.execute(
                "INSERT INTO policy_activation_gates VALUES(?,?,?,?)",
                (
                    policy_id,
                    template_id,
                    index,
                    hashlib.sha256(encode(definition).encode()).hexdigest(),
                ),
            )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "correlation.create",
            {"id": policy_id, "name": definition["name"]},
        )
    return policy_id


def list_policies(store, who):
    from . import principal

    with principal.transaction(store, who) as (db, actor):
        rows = db.execute(
            "SELECT * FROM correlation_policies WHERE tenant=? ORDER BY name",
            (actor["tenant"],),
        ).fetchall()
    return [{**dict(r), "definition": json.loads(r["definition"])} for r in rows]


def toggle(store, who, policy_id, enabled, version):
    from . import principal

    if type(enabled) is not bool or type(version) is not int:
        raise ValueError("enabled boolean and version integer required")
    with principal.transaction(store, who, ("admin", "analyst"), write=True) as (
        db,
        actor,
    ):
        if enabled:
            gate = db.execute(
                "SELECT * FROM policy_activation_gates WHERE policy_id=?", (policy_id,)
            ).fetchone()
            if gate:
                readiness = db.execute(
                    "SELECT * FROM template_readiness WHERE tenant=? AND template_id=? AND index_name=?",
                    (actor["tenant"], gate["template_id"], gate["index_name"]),
                ).fetchone()
                if (
                    not readiness
                    or readiness["definition_digest"] != gate["definition_digest"]
                ):
                    raise ConflictError(
                        "Run exact template telemetry and labelled fixture readiness before enabling"
                    )
                checks = json.loads(readiness["result"])
                if not checks["telemetry_prerequisites_observed"] or not checks.get(
                    "fixture_validation", {}
                ).get("passed"):
                    raise ConflictError(
                        "Template prerequisites or positive/benign fixture assertions are not satisfied"
                    )
        row = db.execute(
            "UPDATE correlation_policies SET enabled=?,version=version+1 WHERE id=? AND tenant=? AND version=?",
            (int(enabled), policy_id, actor["tenant"], version),
        )
        if not row.rowcount:
            raise ConflictError("Policy changed or is unavailable")
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "correlation.toggle",
            {"id": policy_id, "enabled": enabled},
        )


def _timed_chain(steps, streams, entity, budget):
    """Find a complete path, retrying later starts when an earlier one expires.

    Timed chains currently contain one distinct event per step. The shared
    visit/deadline bound fails the complete evaluation instead of returning a
    misleading partial match list.
    """
    ordered = [
        sorted(stream[entity], key=lambda row: (row["event_time"], row["event_id"]))
        for stream in streams
    ]

    def visit(position, previous, used, evidence):
        if position == len(steps):
            return used, evidence
        step = steps[position]
        upper = (
            previous + step["within_seconds"] if "within_seconds" in step else math.inf
        )
        for event in ordered[position]:
            budget["visited"] += 1
            cancel = budget["cancel"]
            if (
                budget["visited"] > 10000
                or time.monotonic() >= budget["deadline"]
                or (cancel is not None and cancel.is_set())
            ):
                raise CapacityError(
                    "Timed correlation candidate/deadline/cancellation bound reached; no partial evaluation emitted"
                )
            if event["event_time"] < previous or event["event_id"] in used:
                continue
            if event["event_time"] > upper:
                break
            found = visit(
                position + 1,
                event["event_time"],
                used | {event["event_id"]},
                [
                    *evidence,
                    {
                        "step": step["name"],
                        "matched": 1,
                        "events": [event],
                        **(
                            {"within_seconds": step["within_seconds"]}
                            if "within_seconds" in step
                            else {}
                        ),
                    },
                ],
            )
            if found is not None:
                return found
        return None

    return visit(0, -1.0, set(), [])


def _step_source(tenant, definition, step, end, scope, fields, position=0):
    filters = list(step["filters"])
    if definition.get("relation"):
        filters.append(
            {
                "field": definition["relation"]["field"],
                "op": "regex",
                "value": "(?s)^.+$",
            }
        )
        if definition["relation"]["mode"] == "parent_guid" and position > 0:
            filters.append(
                {
                    "field": "raw.xdr.data.process.parent.guid",
                    "op": "regex",
                    "value": "(?s)^.+$",
                }
            )
    query = Query.parse(
        {
            "language": "json",
            "earliest": max(0, end - definition["window"]),
            "latest": end,
            "limit": 1000,
            "query": {
                "filters": filters,
                "text": step["text"],
                "fields": list(
                    dict.fromkeys(
                        [
                            *[
                                field
                                for field in fields
                                if not field.startswith("raw.")
                            ],
                            "raw",
                        ]
                    )
                ),
                "sort": "event_time",
                "descending": False,
            },
        }
    )
    sql, args = query.compile(tenant, allowed_indexes=scope)
    # Only the server-owned JSON compiler's terminal ordering/result limit is removed.
    sql, args = sql.rsplit(" ORDER BY ", 1)[0], args[:-1]
    projections = []
    relation_fields = (
        {
            definition.get("relation", {}).get("field"),
            "raw.xdr.data.process.parent.guid",
        }
        if definition.get("relation")
        else set()
    )
    for field in fields:
        if (
            field.startswith("raw.")
            and field != definition["entity_field"]
            and field not in relation_fields
        ):
            # Retain original JSON scalar types for trusted=false versus "false".
            path = "$." + field[4:]
            expression = (
                "CASE WHEN json_type(raw,'"
                + path
                + "') IN ('VARCHAR','BOOLEAN','BIGINT','UBIGINT','DOUBLE','NULL') THEN json_extract(raw,'"
                + path
                + "') ELSE NULL END"
            )
            projections.append(expression + ' AS "' + field + '"')
        else:
            expression = column(field)
            projections.append(
                expression + (' AS "' + field + '"' if field.startswith("raw.") else "")
            )
    sql = "SELECT " + ",".join(projections) + " FROM (" + sql + ") source"
    for group in step.get("exclusions", []):
        excluded = Query.parse(
            {
                "language": "json",
                "earliest": max(0, end - definition["window"]),
                "latest": end,
                "query": {"filters": group, "fields": ["event_id"]},
            }
        )
        exclusion_sql, exclusion_args = excluded.compile(tenant, allowed_indexes=scope)
        exclusion_sql = exclusion_sql.rsplit(" ORDER BY ", 1)[0]
        sql = (
            "SELECT f.* FROM ("
            + sql
            + ") f WHERE NOT EXISTS(SELECT 1 FROM ("
            + exclusion_sql
            + ") excluded WHERE excluded.event_id=f.event_id)"
        )
        args.extend(exclusion_args[:-1])
    return sql, args


def _chain_mode(definition):
    return (
        any("within_seconds" in step for step in definition["steps"])
        or bool(definition.get("relation"))
        or (
            len(definition["steps"]) > 1
            and all(step["min_count"] == 1 for step in definition["steps"])
        )
    )


def _event_struct(alias, fields):
    keys = list(
        dict.fromkeys(ALIASES.get(field, field) for field in fields if field != "raw")
    )
    prefix = alias + "." if alias else ""
    return (
        "struct_pack("
        + ",".join('"' + key + '":=' + prefix + '"' + key + '"' for key in keys)
        + ")"
    )


class _Streams(list):
    has_more = False
    after = None


class _Matches(list):
    has_more = False
    after = None


def candidate_page(
    store,
    tenant,
    definition,
    end,
    scope,
    after=None,
    inclusive=False,
    cancel=None,
    limit=16,
):
    """Stable entity-key paging, not an arbitrary first-event sample."""
    step = definition["steps"][0]
    sql, args = _step_source(
        tenant, definition, step, end, scope, ["event_id", definition["entity_field"]]
    )
    name = (
        "index_name"
        if definition["entity_field"] == "index"
        else '"' + definition["entity_field"] + '"'
    )
    predicate = (
        f"{name} IS NOT NULL AND length(CAST({name} AS VARCHAR)) BETWEEN 1 AND 256"
    )
    if after is not None:
        predicate += f" AND CAST({name} AS VARCHAR){'>=' if inclusive else '>'}?"
        args.append(after)
    rows = store.analytics_query(
        f"SELECT CAST({name} AS VARCHAR) AS entity FROM ({sql}) s WHERE {predicate} "
        "GROUP BY entity HAVING count(*)>=? ORDER BY entity LIMIT ?",
        [*args, step["min_count"], limit],
        cancel=cancel,
        max_rows=limit,
    )["rows"]
    return [row["entity"] for row in rows]


def _exact_streams(
    store,
    tenant,
    definition,
    end,
    scope,
    fields,
    cancel,
    entities=None,
    chain_after=None,
    scheduler_page=False,
):
    """Exact source counts with bounded per-entity evidence, never a global event sample."""
    entity_name = '"' + definition["entity_field"] + '"'
    if definition["entity_field"] == "index":
        entity_name = "index_name"
    timed = _chain_mode(definition)
    sources, params = [], []
    for position, step in enumerate(definition["steps"]):
        sql, args = _step_source(tenant, definition, step, end, scope, fields, position)
        sources.append(
            f"s{position} AS (SELECT *,CAST({entity_name} AS VARCHAR) AS __entity FROM ({sql}) filtered WHERE {entity_name} IS NOT NULL AND length(CAST({entity_name} AS VARCHAR)) BETWEEN 1 AND 256"
            + (
                f" AND CAST({entity_name} AS VARCHAR) IN (SELECT value->>'$' FROM json_each(?))"
                if entities is not None
                else ""
            )
            + ")"
        )
        params.extend(args)
        if entities is not None:
            params.append(encode(entities))
    if timed:
        # Relational paths retain all starts in DuckDB; one deterministic complete path
        # per distinct terminal event is selected after joins. Native query slots/memory/deadline still apply.
        aliases = [f"e{i}" for i in range(len(sources))]
        selected = ",".join(
            f"to_json({_event_struct(a, fields)}) AS event{i}"
            for i, a in enumerate(aliases)
        )
        joins = "s0 e0"
        relation = definition.get("relation")
        for i in range(1, len(sources)):
            conditions = [
                f"e{i}.__entity=e0.__entity",
                f"e{i}.event_time>=e{i - 1}.event_time",
            ]
            conditions += [f"e{i}.event_id<>e{j}.event_id" for j in range(i)]
            if "within_seconds" in definition["steps"][i]:
                conditions.append(
                    f"e{i}.event_time<=e{i - 1}.event_time+{definition['steps'][i]['within_seconds']}"
                )
            if relation:
                field = '"' + relation["field"] + '"'
                conditions.append(f"e0.{field} IS NOT NULL AND e0.{field}<>''")
                if relation["mode"] == "same_value":
                    conditions.append(f"e{i}.{field}=e0.{field} AND e{i}.host=e0.host")
                else:
                    conditions.append(
                        f'e{i}."raw.xdr.data.process.parent.guid"=e{i - 1}.{field} AND e{i}.host=e0.host'
                    )
            joins += f" JOIN s{i} e{i} ON " + " AND ".join(conditions)
        ordering = ",".join(f"{a}.event_time,{a}.event_id" for a in aliases)
        terminal = aliases[-1]
        sql = (
            "WITH "
            + ",".join(sources)
            + f" SELECT e0.__entity AS entity,{terminal}.event_id AS terminal_id,{selected} FROM {joins} QUALIFY row_number() OVER(PARTITION BY e0.__entity,{terminal}.event_id ORDER BY {ordering})=1"
        )
        if chain_after is not None:
            sql = f"SELECT * FROM ({sql}) paths WHERE entity>? OR (entity=? AND terminal_id>?)"
            params.extend([chain_after[0], chain_after[0], chain_after[1]])
        maximum = 128 if scheduler_page else 1000
        sql += " ORDER BY entity,terminal_id LIMIT " + str(maximum + 1)
        result = store.analytics_query(sql, params, cancel=cancel, max_rows=maximum + 1)
        if result["returned"] > maximum and not scheduler_page:
            raise CapacityError(
                "Correlation preview path limit reached; scheduled evaluation pages all paths"
            )
        streams = _Streams(defaultdict(list) for _ in sources)
        streams.has_more = result["returned"] > maximum
        selected_rows = result["rows"][:maximum]
        if selected_rows:
            streams.after = (
                selected_rows[-1]["entity"],
                selected_rows[-1]["terminal_id"],
            )
        for row in selected_rows:
            path = encode([row["entity"], row["terminal_id"]])
            for i in range(len(streams)):
                event = json.loads(row[f"event{i}"])
                event["index"] = event.pop("index_name")
                event[definition["entity_field"]] = row["entity"]
                streams[i][path].append(event)
        return streams
    if len(sources) > 1:
        # Earliest min-count consumption is complete only when shared events do
        # not compete at equal timestamps. Explicitly reject that source shape
        # rather than emit a sampled/greedy false negative or invent a tie order.
        members = " UNION ALL ".join(
            f"SELECT __entity,event_time,event_id,{i} AS step FROM s{i}"
            for i in range(len(sources))
        )
        ambiguity = store.analytics_query(
            "WITH "
            + ",".join(sources)
            + ",members AS ("
            + members
            + "),identities AS (SELECT __entity,event_time,event_id,count(DISTINCT step) AS memberships FROM members GROUP BY __entity,event_time,event_id) SELECT __entity FROM identities GROUP BY __entity,event_time HAVING count(*)>1 AND max(memberships)>1 LIMIT 1",
            params,
            cancel=cancel,
            max_rows=1,
        )
        if ambiguity["rows"]:
            raise ValueError(
                "Untimed multi-count steps with overlapping equal-timestamp events are unsupported; use distinct source predicates or explicit min_count=1 chains"
            )
    streams, previous = [], None
    params = []
    # The native ambiguity check establishes deterministic greedy min-count semantics.
    for i, step in enumerate(definition["steps"]):
        source, args = _step_source(tenant, definition, step, end, scope, fields, i)
        eligible = f"SELECT *,CAST({entity_name} AS VARCHAR) AS __entity FROM ({source}) f WHERE {entity_name} IS NOT NULL AND length(CAST({entity_name} AS VARCHAR)) BETWEEN 1 AND 256"
        if entities is not None:
            eligible += f" AND CAST({entity_name} AS VARCHAR) IN (SELECT value->>'$' FROM json_each(?))"
            args.append(encode(entities))
        if previous is not None:
            eligible = f"SELECT f.* FROM ({eligible}) f JOIN json_each(?) p ON f.__entity=json_extract_string(p.value,'$.entity') WHERE f.event_time>=CAST(json_extract(p.value,'$.after') AS DOUBLE) AND NOT EXISTS(SELECT 1 FROM json_each(p.value,'$.used') u WHERE u.value->>'$'=f.event_id)"
            args.append(encode(previous))
        sql = (
            "WITH eligible AS ("
            + eligible
            + f"),totals AS (SELECT __entity,count(*) AS total,to_json(list(DISTINCT index_name ORDER BY index_name)) AS basis_indexes FROM eligible GROUP BY __entity),ranked AS (SELECT *,row_number() OVER(PARTITION BY __entity ORDER BY event_time,event_id) AS rn FROM eligible) SELECT __entity AS entity,max(total) AS total,any_value(basis_indexes) AS basis_indexes,to_json(list({_event_struct('', fields)} ORDER BY event_time,event_id)) AS events FROM ranked JOIN totals USING(__entity) WHERE rn<=? GROUP BY __entity HAVING count(*)=? ORDER BY entity LIMIT 1001"
        )
        result = store.analytics_query(
            sql,
            [*args, step["min_count"], step["min_count"]],
            cancel=cancel,
            max_rows=1001,
        )
        if result["returned"] > 1000:
            raise CapacityError(
                "Correlation entity limit reached; no partial evaluation"
            )
        grouped = defaultdict(list)
        prior = {p["entity"]: p for p in previous or []}
        previous = []
        for row in result["rows"]:
            events = json.loads(row["events"])
            for event in events:
                event["index"] = event.pop("index_name")
                event[definition["entity_field"]] = row["entity"]
            events[0]["__eligible_count"] = row["total"]
            events[0]["__basis_indexes"] = json.loads(row["basis_indexes"])
            grouped[row["entity"]] = events
            previous.append(
                {
                    "entity": row["entity"],
                    "after": events[-1]["event_time"],
                    "used": prior.get(row["entity"], {}).get("used", [])
                    + [e["event_id"] for e in events],
                }
            )
        streams.append(grouped)
        if not previous:
            streams.extend(
                defaultdict(list)
                for _ in range(len(definition["steps"]) - len(streams))
            )
            break
    return streams


def evaluate(
    store,
    tenant,
    definition,
    end,
    allowed_indexes,
    cancel=None,
    *,
    entities=None,
    chain_after=None,
    scheduler_page=False,
):
    """Ordered event-time chains, optionally constrained by per-step gaps."""
    if not math.isfinite(end) or end <= 0:
        raise ValueError("Invalid correlation window")
    entity_field = definition["entity_field"]
    fields = list(
        dict.fromkeys(
            [
                "event_id",
                "event_time",
                "received",
                "index",
                "host",
                "source",
                "severity",
                "raw.xdr.data.process.guid",
                "raw.xdr.data.session.id",
                "raw.security.process_guid",
                "raw.security.session_id",
                "raw.xdr.data.process.executable",
                "raw.xdr.data.process.command_line",
                "raw.xdr.data.process.hash.sha256",
                "raw.xdr.data.process.code_signature.subject_name",
                "raw.xdr.data.process.code_signature.trusted",
                "raw.xdr.data.process.parent.guid",
                "raw.xdr.data.user.name",
                "raw.security.process",
                "raw.security.user",
                "raw.xdr.data.event.timestamp_precision_seconds",
                "raw.xdr.data.event.clock_quality",
                "raw.xdr.data.event.sequence",
                "raw.xdr.data.host.boot_id",
                entity_field,
            ]
        )
    )
    if definition.get("relation"):
        fields.extend(
            [definition["relation"]["field"], "raw.xdr.data.process.parent.guid"]
        )
        fields = list(dict.fromkeys(fields))
    fields = list(
        dict.fromkeys(
            [
                *fields,
                *[
                    condition["field"]
                    for step in definition["steps"]
                    for condition in step["filters"]
                    if condition["field"] != "raw"
                    and not (condition["op"] == "exists" and not condition.get("value"))
                ],
            ]
        )
    )
    streams = _exact_streams(
        store,
        tenant,
        definition,
        end,
        allowed_indexes,
        fields,
        cancel,
        entities=entities,
        chain_after=chain_after,
        scheduler_page=scheduler_page,
    )
    candidates = set(streams[0])
    for stream in streams[1:]:
        candidates.intersection_update(stream)
    matches = _Matches()
    matches.has_more = getattr(streams, "has_more", False)
    matches.after = getattr(streams, "after", None)
    timed = _chain_mode(definition)
    budget = {
        "visited": 0,
        "deadline": time.monotonic()
        + min(10, getattr(getattr(store, "settings", None), "query_timeout", 10)),
        "cancel": cancel,
    }
    for entity in sorted(candidates):
        previous, used, evidence = -1.0, set(), []
        if timed:
            chain = _timed_chain(definition["steps"], streams, entity, budget)
            if chain is not None:
                used, evidence = chain
        for step, stream in [] if timed else zip(definition["steps"], streams):
            selected = []
            for event in sorted(
                stream[entity], key=lambda r: (r["event_time"], r["event_id"])
            ):
                if event["event_time"] >= previous and event["event_id"] not in used:
                    selected.append(event)
                    if len(selected) == step["min_count"]:
                        break
            if len(selected) < step["min_count"]:
                break
            used.update(r["event_id"] for r in selected)
            previous = selected[-1]["event_time"]
            eligible_count = selected[0].pop("__eligible_count", len(selected))
            basis_indexes = selected[0].pop(
                "__basis_indexes", sorted({event["index"] for event in selected})
            )
            evidence.append(
                {
                    "step": step["name"],
                    "matched": len(selected),
                    "eligible_event_count": eligible_count,
                    "candidate_indexes": basis_indexes,
                    "events": selected,
                }
            )
        if len(evidence) == len(definition["steps"]):
            matches.append(
                {
                    "entity": evidence[0]["events"][0][entity_field]
                    if timed
                    else entity,
                    "entity_field": entity_field,
                    "steps": evidence,
                    "event_ids": sorted(used),
                    "indexes": sorted(
                        {
                            index
                            for step in evidence
                            for index in step.get(
                                "candidate_indexes",
                                [r["index"] for r in step["events"]],
                            )
                        }
                    ),
                    "window_start": max(0, end - definition["window"]),
                    "window_end": end,
                    "risk_weight": definition["risk_score"],
                    "severity": definition["severity"],
                    "mitre": definition["mitre"],
                    "relation": definition.get("relation"),
                    "chain_selection": "canonical complete path per distinct terminal event; alternative starts retained in native joins"
                    if timed
                    else "exact ordered threshold evidence",
                    "explanation": "Distinct events satisfied all steps in timestamp order for the same entity."
                    + (
                        " Native distinct-ID chain selection checked alternative starts; any configured gap is inclusive from the preceding step event."
                        if timed
                        else ""
                    ),
                }
            )
    if any(len(encode(match).encode()) > MAX_EVIDENCE_BYTES for match in matches):
        raise CapacityError(
            "Correlation evidence exceeds 512 KiB; reduce step counts or window"
        )
    if len(encode(matches).encode()) > MAX_RESPONSE_BYTES:
        raise CapacityError(
            "Correlation preview exceeds 2 MiB; narrow entity scope or window"
        )
    return matches


def _episode(match):
    """Do not invent causality. Shared exact identity gives an episode, else explicit host fallback."""
    events = [row for step in match.get("steps", []) for row in step.get("events", [])]

    def identity(row, left, right):
        value = row.get(left) or row.get(right)
        return value if isinstance(value, str) and 0 < len(value) <= 256 else None

    sessions = {
        identity(row, "raw.xdr.data.session.id", "raw.security.session_id")
        for row in events
    }
    sessions.discard(None)
    sessions.discard("")
    processes = {
        identity(row, "raw.xdr.data.process.guid", "raw.security.process_guid")
        for row in events
    }
    processes.discard(None)
    processes.discard("")
    shared_session = len(sessions) == 1 and all(
        identity(row, "raw.xdr.data.session.id", "raw.security.session_id")
        for row in events
    )
    shared_process = len(processes) == 1 and all(
        identity(row, "raw.xdr.data.process.guid", "raw.security.process_guid")
        for row in events
    )
    relation = match.get("relation") or {}
    basis = None
    if relation.get("mode") == "parent_guid" and events:
        root = events[0].get(relation.get("field", "raw.xdr.data.process.guid"))
        if isinstance(root, str) and 0 < len(root) <= 256:
            basis = ["process_lineage", root]
    elif (
        relation.get("field") in {"raw.xdr.data.session.id", "raw.security.session_id"}
        and shared_session
    ):
        # An intentionally session-scoped rule keeps its declared grouping.
        basis = ["session", next(iter(sessions))]
    elif shared_process:
        # A shared logon session is not a campaign. Independent process-scoped
        # chains and adapter evidence remain separate even under one login.
        basis = ["process", next(iter(processes))]
    elif shared_session:
        basis = ["session", next(iter(sessions))]
    if basis:
        key = hashlib.sha256(
            encode([match["entity_field"], match["entity"], *basis]).encode()
        ).hexdigest()
        return {"key": key, "grade": "exact_reported_identity", "basis": basis}
    key = hashlib.sha256(
        encode(["legacy_entity", match["entity_field"], match["entity"]]).encode()
    ).hexdigest()
    return {
        "key": key,
        "grade": "entity_time_hypothesis",
        "basis": ["entity_only", match["entity_field"], match["entity"]],
    }


def temporal_assessment(match):
    """State uncertainty without mistaking transport latency for measured clock skew.

    A causal process/session relation can support association, but never attests
    clock synchronization. Timestamp order alone across sensors cannot authorize
    automatic destructive response. Unknown precision is explicit, not zero.
    """
    events = [row for step in match.get("steps", []) for row in step.get("events", [])]
    times = [row.get("event_time") for row in events]
    numeric = lambda value: type(value) in (int, float) and math.isfinite(value)
    lags = [
        row["received"] - row["event_time"]
        for row in events
        if numeric(row.get("received")) and numeric(row.get("event_time"))
    ]
    identities = {(row.get("host"), row.get("source")) for row in events}
    causal = bool(match.get("relation"))
    tied = any(times[i] == times[i - 1] for i in range(1, len(times)))
    precisions = [
        row.get("raw.xdr.data.event.timestamp_precision_seconds") for row in events
    ]
    known_precision = all(
        numeric(value) and 0 <= value <= 86400 for value in precisions
    ) and bool(events)
    close = (
        any(
            abs(times[i] - times[i - 1]) <= max(precisions[i], precisions[i - 1])
            for i in range(1, len(times))
        )
        if known_precision
        else False
    )
    reasons = []
    if len(identities) > 1 and len(events) > 1:
        reasons.append("cross_source_clock_alignment_not_independently_attested")
    if tied and not causal:
        reasons.append("equal_timestamps_do_not_establish_causality")
    if close and not causal:
        reasons.append("reported_precision_cannot_resolve_event_order")
    if any(lag < 0 for lag in lags):
        reasons.append("event_time_after_admission_time")
    if any(not numeric(value) for value in times):
        reasons.append("invalid_or_missing_event_time")
    return {
        "ordering_basis": "reported_event_time",
        "timestamp_ties": tied,
        "causal_relation_required_by_policy": causal,
        "cross_source": len(identities) > 1,
        "reported_precision_seconds": precisions if known_precision else None,
        "reported_clock_quality": sorted(
            {
                str(row["raw.xdr.data.event.clock_quality"])[:128]
                for row in events
                if row.get("raw.xdr.data.event.clock_quality") is not None
            }
        ),
        "independent_clock_attestation": False,
        "arrival_lag_seconds": {"min": min(lags), "max": max(lags), "count": len(lags)}
        if lags
        else None,
        "arrival_lag_is_clock_skew_measurement": False,
        "uncertainty_reasons": reasons,
        "automation_eligible": not reasons,
        "scope": "temporal eligibility only; current target identity and response authorization are separate gates",
    }


def _owner_actor(db, policy, scope=None):
    from . import principal

    who = {"name": policy["owner"], "tenant": policy["tenant"], "role": "analyst"}
    if scope is not None:
        who["allowed_indexes"] = scope
    actor = principal.current(db, who, ("admin", "analyst"))
    if scope is not None and not principal.contains(actor["allowed_indexes"], scope):
        raise PermissionError("Detection owner index permissions changed")
    return actor


def _owner_scope(store, name, tenant):
    with store.control() as db:
        return _owner_actor(db, {"owner": name, "tenant": tenant})["allowed_indexes"]


class _Until:
    def __init__(self, cancel, deadline):
        self.cancel, self.deadline = cancel, deadline

    def is_set(self):
        return (
            time.monotonic() >= self.deadline
            or self.cancel is not None
            and (self.cancel() if callable(self.cancel) else self.cancel.is_set())
        )


def page_deadline(store, cancel):
    """A finite exact page may finish; the iteration budget gates starting another.

    Cancelling every page at a shorter poll interval causes permanent starvation
    on otherwise valid native queries. Native query time/memory/slot bounds and
    the total page deadline still apply; no partial page is committed.
    """
    seconds = min(15.0, max(1.0, float(getattr(store.settings, "query_timeout", 10))))
    return _Until(cancel, time.monotonic() + seconds)


def prepare_window_page(store, policy, definition, end, scope, cancel=None):
    """Read one exact partition; ACK can invalidate its durable cursor by revision."""
    with store.write_lock, store.control() as db:
        db.execute(
            "INSERT INTO correlation_window_progress(policy_id,version,data_end,tenant,window_start,scope) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(policy_id,version,data_end) DO NOTHING",
            (
                policy["id"],
                policy["version"],
                end,
                policy["tenant"],
                max(0, end - definition["window"]),
                encode(scope),
            ),
        )
        progress = dict(
            db.execute(
                "SELECT * FROM correlation_window_progress WHERE policy_id=? AND version=? AND data_end=?",
                (policy["id"], policy["version"], end),
            ).fetchone()
        )
        if progress["scope"] != encode(scope):
            db.execute(
                "UPDATE correlation_window_progress SET scope=?,entity_after=NULL,terminal_after=NULL,revision=revision+1 "
                "WHERE policy_id=? AND version=? AND data_end=?",
                (encode(scope), policy["id"], policy["version"], end),
            )
            progress = dict(
                db.execute(
                    "SELECT * FROM correlation_window_progress WHERE policy_id=? AND version=? AND data_end=?",
                    (policy["id"], policy["version"], end),
                ).fetchone()
            )
    entities = candidate_page(
        store,
        policy["tenant"],
        definition,
        end,
        scope,
        progress["entity_after"],
        progress["terminal_after"] is not None,
        cancel,
        limit=16,
    )
    matches = (
        evaluate(
            store,
            policy["tenant"],
            definition,
            end,
            scope,
            cancel,
            entities=entities,
            scheduler_page=True,
            chain_after=(progress["entity_after"], progress["terminal_after"])
            if progress["terminal_after"] is not None
            else None,
        )
        if entities
        else _Matches()
    )
    return {
        "progress": progress,
        "entities": entities,
        "matches": matches,
        "complete": not getattr(matches, "has_more", False) and len(entities) < 16,
    }


def commit_window_page(db, page):
    """Caller owns emission transaction; cursor advances iff its exact revision is current."""
    p = page["progress"]
    current = db.execute(
        "SELECT revision,scope,entity_after,terminal_after FROM correlation_window_progress WHERE policy_id=? AND version=? AND data_end=?",
        (p["policy_id"], p["version"], p["data_end"]),
    ).fetchone()
    if not current or any(
        current[key] != p[key]
        for key in ("revision", "scope", "entity_after", "terminal_after")
    ):
        raise ConflictError(
            "Indexed input or partition cursor changed during evaluation"
        )
    if page["complete"]:
        db.execute(
            "DELETE FROM correlation_window_progress WHERE policy_id=? AND version=? AND data_end=?",
            (p["policy_id"], p["version"], p["data_end"]),
        )
        return True
    after = (
        page["matches"].after
        if page["matches"].has_more
        else (page["entities"][-1], None)
    )
    db.execute(
        "UPDATE correlation_window_progress SET entity_after=?,terminal_after=?,pages=pages+1 WHERE policy_id=? AND version=? AND data_end=?",
        (*after, p["policy_id"], p["version"], p["data_end"]),
    )
    return False


def _emit_matches(
    db,
    store,
    policy,
    definition,
    matches,
    end,
    *,
    mode,
    scheduled_end,
    actor,
    guard,
    cancel=None,
):
    """One shared transactional emitter for scheduling and explicit replay.

    Contributions are dated by the evaluated event window, not ingestion or
    replay time. Fingerprints stay policy/entity/event-ID based across windows.
    Cooldown throttles notifications within the absolute time distance. Distinct
    original evidence still reaches a Case, including out-of-order replays.
    """
    from . import principal

    result = {
        "matches": len(matches),
        "emitted": 0,
        "deduplicated": 0,
        "cooldown_suppressed": 0,
        "governance_suppressed": 0,
        "notification_throttled": 0,
        "cooldown_mode": "notification_only_distinct_evidence_preserved",
    }
    cooldown_clause, cooldown_grants = _scope(guard)
    snapshot_stages = []
    for step in definition.get("steps", []):
        fields = {
            condition["field"]
            for condition in step.get("filters", [])
            if not (condition["op"] == "exists" and not condition.get("value"))
        }
        fields.add(definition["entity_field"])
        if definition.get("relation"):
            fields.add(definition["relation"]["field"])
            if definition["relation"]["mode"] == "parent_guid" and snapshot_stages:
                fields.add("raw.xdr.data.process.parent.guid")
        types = {}
        for condition in step.get("filters", []):
            if condition["op"].startswith("typed_") and "value" in condition:
                value = condition["value"]
                if condition["op"] == "typed_in" and isinstance(value, str):
                    value = json.loads(value)[0]
                types[condition["field"]] = (
                    "boolean"
                    if type(value) is bool
                    else "number"
                    if type(value) in (int, float)
                    else "string"
                    if isinstance(value, str)
                    else "null"
                )
        if definition.get("relation"):
            types[definition["relation"]["field"]] = "string"
            if definition["relation"]["mode"] == "parent_guid" and snapshot_stages:
                types["raw.xdr.data.process.parent.guid"] = "string"
        snapshot_stages.append(
            {
                "name": step.get("name"),
                "required_fields": sorted(fields),
                "required_field_types": types,
            }
        )
    policy_snapshot = {
        "version": policy["version"],
        "definition_digest": hashlib.sha256(encode(definition).encode()).hexdigest(),
        "entity_field": definition["entity_field"],
        "relation": definition.get("relation"),
        "stages": snapshot_stages,
        "prerequisites_available": bool(snapshot_stages),
        "scope": "immutable declaration prerequisites; actual sensor coverage remains separate",
    }
    for match in matches:
        if cancel is not None and cancel.is_set():
            raise CapacityError("Detection emission cancelled or budget exhausted")
        if not principal.contains(guard["allowed_indexes"], match["indexes"]):
            raise PermissionError("Match index scope is unavailable")
        evidence = {
            **match,
            "temporal": temporal_assessment(match),
            "policy_snapshot": policy_snapshot,
            "evaluation": {
                "mode": mode,
                "scheduled_end": scheduled_end,
                "data_end": end,
                "evaluation_delay": definition.get("evaluation_delay", 0),
                "policy_version": policy["version"],
            },
        }
        if len(encode(evidence).encode()) > MAX_EVIDENCE_BYTES:
            raise CapacityError("Correlation evidence exceeds 512 KiB")
        fingerprint = hashlib.sha256(
            encode([policy["id"], match["entity"], match["event_ids"]]).encode()
        ).hexdigest()
        if db.execute(
            "SELECT 1 FROM risk_contributions WHERE id=?", (fingerprint,)
        ).fetchone():
            result["deduplicated"] += 1
            continue
        from . import detection_governance, detector_ops

        if not db.execute("SELECT 1 FROM correlation_policies WHERE id=? AND tenant=?",(policy["id"],policy["tenant"])).fetchone():
            detector_ops.register(db,policy,definition,guard,mode)
        governed = detection_governance._govern_candidate(db, store, guard, policy, match)
        if not governed["allowed"]:
            result["governance_suppressed"] += 1
            continue
        throttled = (
            definition["cooldown"]
            and match.get("severity") != "critical"
            and db.execute(
                "SELECT 1 FROM risk_contributions r WHERE r.tenant=? AND r.policy_id=? AND r.entity=? AND r.at>? AND r.at<? AND ("
                + cooldown_clause
                + ") LIMIT 1",
                (
                    policy["tenant"],
                    policy["id"],
                    match["entity"],
                    end - definition["cooldown"],
                    end + definition["cooldown"],
                    *cooldown_grants,
                ),
            ).fetchone()
        )
        if throttled:
            result["cooldown_suppressed"] += 1
            result["notification_throttled"] += 1
        evidence["notification"] = {
            "throttled": bool(throttled),
            "critical_bypass": match.get("severity") == "critical",
            "distinct_evidence_preserved": True,
        }
        episode = _episode(match)
        evidence["episode"] = episode
        strict_grouping = definition.get("case_grouping") == "require_exact_identity"
        evidence["case_quality"] = {
            "schema": "xsera.case-association-quality.v1", "association_grade": episode["grade"],
            "entity_time_hypothesis": episode["grade"] == "entity_time_hypothesis",
            "reported_identity_only": episode["grade"] == "exact_reported_identity",
            "causality_proven": False, "independent_sensor_attestation": False,
            "response_authorized": False, "require_exact_identity": strict_grouping,
            "explanation": "Entity and nearby source time support an analyst hypothesis only" if episode["grade"] == "entity_time_hypothesis" else "Reported process/session identity supports association; it does not independently prove causality",
        }
        from . import case_intelligence

        identity_missing = strict_grouping and episode["grade"] != "exact_reported_identity"
        routing = case_intelligence.route(db, guard, match, episode, end) if not identity_missing else {"incident_id": None, "blocked_case_ids": []}
        nearby = db.execute(
            "SELECT i.id FROM incidents i WHERE i.tenant=? AND i.entity_field=? AND i.entity=? AND i.status IN ('new','triage') AND i.updated>=? AND i.updated<=? "
            "AND (EXISTS(SELECT 1 FROM incident_episodes e WHERE e.incident_id=i.id AND e.tenant=i.tenant AND e.episode_key=?) "
            "OR (?='entity_time_hypothesis' AND NOT EXISTS(SELECT 1 FROM incident_episodes e WHERE e.incident_id=i.id))) ORDER BY i.updated DESC LIMIT 100",
            (
                policy["tenant"],
                match["entity_field"],
                match["entity"],
                end - 86400,
                end + 86400,
                episode["key"],
                episode["grade"],
            ),
        ).fetchall()
        incident = None
        if routing.get("incident_id"):
            principal.incident(db, guard, routing["incident_id"])
            incident = (routing["incident_id"],)
        for candidate in ([] if identity_missing else nearby):
            if incident or candidate["id"] in routing.get("blocked_case_ids", []):
                continue
            if case_intelligence.frozen(db, policy["tenant"], candidate["id"]):
                continue
            try:
                principal.incident(db, guard, candidate["id"])
            except KeyError:
                continue
            incident = candidate
            break
        incident_id = incident[0] if incident else str(uuid.uuid4())
        if not incident:
            db.execute(
                "INSERT INTO incidents(id,tenant,entity,entity_field,name,created,updated,status) VALUES(?,?,?,?,?,?,?,'new')",
                (
                    incident_id,
                    policy["tenant"],
                    match["entity"],
                    match["entity_field"],
                    policy["name"],
                    end,
                    end,
                ),
            )
        else:
            # Historical replay must not move a current incident backwards.
            db.execute(
                "UPDATE incidents SET updated=max(updated,?),version=version+1 WHERE id=?",
                (end, incident_id),
            )
        db.execute(
            "INSERT INTO incident_episodes VALUES(?,?,?,?,?) ON CONFLICT(incident_id) DO NOTHING",
            (
                incident_id,
                policy["tenant"],
                episode["key"],
                episode["grade"],
                encode(episode["basis"]),
            ),
        )
        if len(encode(evidence).encode()) > MAX_EVIDENCE_BYTES:
            raise CapacityError(
                "Correlation evidence exceeds 512 KiB after episode enrichment"
            )
        db.execute(
            "INSERT INTO risk_contributions VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                fingerprint,
                policy["tenant"],
                incident_id,
                policy["id"],
                match["entity"],
                match["entity_field"],
                end,
                definition["risk_score"],
                encode(evidence),
                encode(match["indexes"]),
            ),
        )
        from . import pipeline_slo

        pipeline_slo.journal_case(
            store,
            db,
            policy["tenant"],
            incident_id,
            policy["id"],
            match["event_ids"],
            match["indexes"],
        )
        store.audit(
            db,
            policy["tenant"],
            actor,
            "incident.evidence",
            {
                "incident_id": incident_id,
                "policy_id": policy["id"],
                "fingerprint": fingerprint,
                "events": len(match["event_ids"]),
                "risk_weight": definition["risk_score"],
                "mode": mode,
                "data_end": end,
                "scheduled_end": scheduled_end,
            },
        )
        result["emitted"] += 1
    return result


def run_due(store, now=None, cancel=None, budget=1.0):
    now = time.time() if now is None else now
    if (
        isinstance(now, bool)
        or not isinstance(now, (int, float))
        or not math.isfinite(now)
        or now <= 0
    ):
        raise ValueError("Invalid scheduler time")
    if (
        isinstance(budget, bool)
        or not isinstance(budget, (int, float))
        or not math.isfinite(budget)
        or not 0.01 <= budget <= 30
    ):
        raise ValueError("Detection budget must be .01..30 seconds")
    deadline = time.monotonic() + budget
    iteration = _Until(cancel, deadline)
    with store.control() as db:
        policies = db.execute(
            """SELECT * FROM (
          SELECT *,row_number() OVER (PARTITION BY tenant ORDER BY next_run,id) AS tenant_rank
          FROM correlation_policies WHERE enabled=1 AND next_run<=? AND retry_at<=?)
          ORDER BY tenant_rank,next_run,id LIMIT 20""",
            (now, now),
        ).fetchall()
    completed = 0
    for policy in policies:
        if iteration.is_set():
            break
        signal = page_deadline(store, cancel)
        scheduled_end = policy["next_run"]
        try:
            with store.control() as db:
                pending = db.execute(
                    "SELECT 1 FROM queue WHERE tenant=? AND received<=? LIMIT 1",
                    (policy["tenant"], scheduled_end),
                ).fetchone()
            if pending:
                with store.write_lock, store.control() as db:
                    db.execute(
                        "UPDATE correlation_policies SET retry_at=? WHERE id=? AND next_run=? AND version=?",
                        (now + 2, policy["id"], scheduled_end, policy["version"]),
                    )
                continue
            definition = json.loads(policy["definition"])
            data_end = scheduled_end - definition.get("evaluation_delay", 0)
            scope = _owner_scope(store, policy["owner"], policy["tenant"])
            page = prepare_window_page(
                store, policy, definition, data_end, scope, signal
            )
            matches = page["matches"]
            if signal.is_set():
                raise CapacityError("Detection cancelled or budget exhausted")
            with store.write_lock, store.control() as db:
                db.set_progress_handler(
                    lambda page_signal=signal: int(page_signal.is_set()), 1000
                )
                db.execute("BEGIN IMMEDIATE")
                current = db.execute(
                    "SELECT * FROM correlation_policies WHERE id=?", (policy["id"],)
                ).fetchone()
                if (
                    not current
                    or not current["enabled"]
                    or current["next_run"] != scheduled_end
                    or current["version"] != policy["version"]
                    or current["definition"] != policy["definition"]
                ):
                    continue
                owner = _owner_actor(db, current, scope)
                if signal.is_set():
                    raise CapacityError("Detection cancelled or budget exhausted")
                _emit_matches(
                    db,
                    store,
                    current,
                    definition,
                    matches,
                    data_end,
                    mode="scheduled",
                    scheduled_end=scheduled_end,
                    actor="correlation-engine",
                    guard=owner,
                    cancel=signal,
                )
                finished = commit_window_page(db, page)
                if finished:
                    db.execute(
                        "UPDATE correlation_policies SET next_run=?,last_end=?,retry_at=0,failures=0,error=NULL WHERE id=?",
                        (
                            scheduled_end + definition["interval"],
                            data_end,
                            policy["id"],
                        ),
                    )
                else:
                    db.execute(
                        "UPDATE correlation_policies SET retry_at=0,failures=0,error=NULL WHERE id=?",
                        (policy["id"],),
                    )
            completed += int(finished)
        except Exception as exc:  # noqa: BLE001 - Persist each policy failure without stopping other tenants.
            failures = min(policy["failures"] + 1, 16)
            with store.write_lock, store.control() as db:
                db.execute(
                    "UPDATE correlation_policies SET failures=?,retry_at=?,error=? WHERE id=? AND next_run=? AND version=?",
                    (
                        failures,
                        now + min(3600, 5 * 2 ** (failures - 1)),
                        type(exc).__name__ + ": " + str(exc)[:300],
                        policy["id"],
                        scheduled_end,
                        policy["version"],
                    ),
                )
    return completed


def replay(store, who, policy_id, end, version, request_id, cancel=None):
    """Explicit bounded replay at an exact event-time end, with durable receipt.

    `end` is already the desired data-window end; evaluation_delay is not applied
    twice. Replay never moves next_run/last_end. It uses the intersection of the
    requester and live policy owner's grants and rechecks both before emission.
    """
    from . import principal

    if (
        isinstance(end, bool)
        or not isinstance(end, (int, float))
        or not math.isfinite(end)
        or not 0 < end <= time.time()
    ):
        raise ValueError("Replay end must be positive epoch seconds no later than now")
    if type(version) is not int or version < 1:
        raise ValueError("A positive policy version is required")
    if not isinstance(request_id, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", request_id
    ):
        raise ValueError("request_id requires 1..64 ASCII identifier characters")
    deadline = time.monotonic() + 5
    signal = _Until(cancel, deadline)
    with principal.transaction(store, who, ("admin", "analyst")) as (db, actor):
        policy = db.execute(
            "SELECT * FROM correlation_policies WHERE id=? AND tenant=?",
            (policy_id, actor["tenant"]),
        ).fetchone()
        if not policy:
            raise KeyError("Policy not found")
        owner = _owner_actor(db, policy)
        old = db.execute(
            "SELECT * FROM correlation_replays WHERE tenant=? AND actor=? AND request_id=?",
            (actor["tenant"], actor["name"], request_id),
        ).fetchone()
        if old:
            if (
                old["policy_id"] != policy_id
                or old["version"] != version
                or old["window_end"] != end
            ):
                raise ConflictError(
                    "Replay request_id already used with different content"
                )
            old_scope = json.loads(old["scope"])
            if not principal.contains(
                actor["allowed_indexes"], old_scope
            ) or not principal.contains(owner["allowed_indexes"], old_scope):
                raise PermissionError("Replay result scope is no longer authorized")
            return {**json.loads(old["result"]), "duplicate": True}
        if policy["version"] != version:
            raise ConflictError("Policy version changed")
        scope = principal.intersection(
            actor["allowed_indexes"], owner["allowed_indexes"]
        )
        definition = json.loads(policy["definition"])
        definition_digest = hashlib.sha256(policy["definition"].encode()).hexdigest()
        if db.execute(
            "SELECT 1 FROM queue WHERE tenant=? AND received<=? LIMIT 1",
            (actor["tenant"], time.time()),
        ).fetchone():
            raise CapacityError(
                "Indexing is pending; retry replay after admitted events are indexed"
            )
    matches = evaluate(store, actor["tenant"], definition, end, scope, cancel=signal)
    if signal.is_set():
        raise CapacityError("Replay cancelled or five-second budget exhausted")
    with principal.transaction(store, actor, ("admin", "analyst"), write=True) as (
        db,
        fresh,
    ):
        current = db.execute(
            "SELECT * FROM correlation_policies WHERE id=? AND tenant=?",
            (policy_id, fresh["tenant"]),
        ).fetchone()
        if (
            not current
            or current["version"] != version
            or current["definition"] != policy["definition"]
            or current["owner"] != policy["owner"]
        ):
            raise ConflictError("Policy changed during replay")
        _owner_actor(db, current, scope)
        if not principal.contains(fresh["allowed_indexes"], scope):
            raise PermissionError("Requester index permissions changed during replay")
        old = db.execute(
            "SELECT * FROM correlation_replays WHERE tenant=? AND actor=? AND request_id=?",
            (fresh["tenant"], fresh["name"], request_id),
        ).fetchone()
        if old:
            if (
                old["policy_id"] != policy_id
                or old["version"] != version
                or old["window_end"] != end
                or old["definition_digest"] != definition_digest
                or json.loads(old["scope"]) != scope
            ):
                raise ConflictError("Concurrent replay request content changed")
            return {**json.loads(old["result"]), "duplicate": True}
        # Durable inventory/history has no lifetime record-count ceiling.
        if signal.is_set():
            raise CapacityError("Replay cancelled or five-second budget exhausted")
        result = {
            "id": str(uuid.uuid4()),
            "policy_id": policy_id,
            "version": version,
            "end": end,
            "duplicate": False,
            "scope": scope,
            "definition_digest": definition_digest,
        }
        result.update(
            _emit_matches(
                db,
                store,
                current,
                definition,
                matches,
                end,
                mode="replay",
                scheduled_end=None,
                actor=fresh["name"],
                guard={**fresh, "allowed_indexes": scope},
                cancel=signal,
            )
        )
        db.execute(
            "INSERT INTO correlation_replays VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                result["id"],
                fresh["tenant"],
                fresh["name"],
                request_id,
                policy_id,
                version,
                end,
                definition_digest,
                encode(scope),
                encode(result),
                time.time(),
            ),
        )
        store.audit(
            db,
            fresh["tenant"],
            fresh["name"],
            "correlation.replay",
            {
                "id": result["id"],
                "policy_id": policy_id,
                "version": version,
                "end": end,
                "matches": result["matches"],
                "emitted": result["emitted"],
                "scope": scope,
            },
        )
        return result


@contextmanager
def _budget(db, write=False):
    deadline = time.monotonic() + QUERY_BUDGET_SECONDS
    db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
    try:
        # Authorization and its evidence page must see one SQLite snapshot, so
        # a concurrent private contribution cannot appear after the ACL check.
        if not db.in_transaction:
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        yield
    except sqlite3.OperationalError as exc:
        if "interrupted" in str(exc).lower():
            raise CapacityError(
                "Intelligence query deadline exceeded; narrow the request"
            ) from None
        raise
    finally:
        db.set_progress_handler(None, 0)


def _scope(who, alias="r"):
    from .access import validate as validate_scope

    scope = validate_scope(who.get("allowed_indexes", []))
    if scope == ["*"]:
        return "1=1", []
    if not scope:
        return "0=1", []
    slots = ",".join("?" for _ in scope)
    return (
        f"json_valid({alias}.indexes) AND json_type({alias}.indexes)='array' AND json_array_length({alias}.indexes)>0 AND NOT EXISTS(SELECT 1 FROM json_each({alias}.indexes) j WHERE j.type!='text' OR j.value NOT IN ({slots}))",
        scope,
    )


def _bookmark_access(db, who, alias="i"):
    from .access import validate as validate_scope

    scope = validate_scope(who.get("allowed_indexes", []))
    if (
        scope == ["*"]
        or not db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='case_bookmarks'"
        ).fetchone()
    ):
        return "1=1", []
    slots = ",".join("?" for _ in scope) or "NULL"
    return (
        f"NOT EXISTS(SELECT 1 FROM case_bookmarks b WHERE b.tenant={alias}.tenant AND b.incident_id={alias}.id AND b.index_name NOT IN ({slots}))",
        scope,
    )


def _cursor(value):
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or len(value) > 512
        or not re.fullmatch(r"[A-Za-z0-9_-]+", value)
    ):
        raise ValueError("Invalid evidence cursor")
    try:
        at, identifier = json.loads(
            base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        )
        if (
            isinstance(at, bool)
            or not isinstance(at, (int, float))
            or not -1e12 <= at <= 1e12
            or not math.isfinite(at)
            or not isinstance(identifier, str)
            or not 1 <= len(identifier) <= 128
        ):
            raise ValueError()
        return at, identifier
    except (ValueError, TypeError, UnicodeError):
        raise ValueError("Invalid evidence cursor") from None


def _encode_cursor(row):
    return (
        base64.urlsafe_b64encode(encode([row["at"], row["id"]]).encode())
        .rstrip(b"=")
        .decode()
    )


def _page(db, where, args, cursor=None, count=20):
    if type(count) is not int or not 1 <= count <= 20:
        raise ValueError("Evidence count must be 1..20")
    total = db.execute(
        "SELECT count(*) FROM risk_contributions r JOIN incidents i ON i.id=r.incident_id WHERE "
        + where,
        args,
    ).fetchone()[0]
    position = _cursor(cursor)
    page_where, page_args = where, list(args)
    if position is not None:
        page_where += " AND (r.at<? OR (r.at=? AND r.id<?))"
        page_args.extend([position[0], position[0], position[1]])
    identifiers = db.execute(
        "SELECT r.id,length(CAST(r.evidence AS BLOB)) AS evidence_bytes FROM risk_contributions r JOIN incidents i ON i.id=r.incident_id WHERE "
        + page_where
        + " ORDER BY r.at DESC,r.id DESC LIMIT ?",
        [*page_args, count + 1],
    ).fetchall()
    if any(row["evidence_bytes"] > MAX_EVIDENCE_BYTES for row in identifiers[:count]):
        raise CapacityError("Stored correlation evidence exceeds 512 KiB")
    identifiers = [row["id"] for row in identifiers]
    wanted = identifiers[:count]
    rows = (
        db.execute(
            "SELECT r.*,i.status FROM risk_contributions r JOIN incidents i ON i.id=r.incident_id WHERE r.tenant=? AND r.id IN ("
            + ",".join("?" for _ in wanted)
            + ") ORDER BY r.at DESC,r.id DESC",
            [args[0], *wanted],
        ).fetchall()
        if wanted
        else []
    )
    selected, size = [], 0
    for row in rows[:count]:
        # Historical oversized evidence must fail visibly rather than allocating
        # an unlimited JSON tree. New evaluations enforce this before persistence.
        if len(row["evidence"].encode()) > MAX_EVIDENCE_BYTES:
            raise CapacityError("Stored correlation evidence exceeds 512 KiB")
        item = {
            **dict(row),
            "evidence": json.loads(row["evidence"]),
            "indexes": json.loads(row["indexes"]),
        }
        from . import contribution_verdicts

        item["adjudication"] = contribution_verdicts.classification(db, row)
        item["classification"] = item["adjudication"]["classification"]
        item_size = len(encode(item).encode())
        if selected and size + item_size > 768 * 1024:
            break
        selected.append(item)
        size += item_size
    return {
        "contributions": selected,
        "total_count": total,
        "page_count": len(selected),
        "next_cursor": _encode_cursor(selected[-1])
        if selected and len(identifiers) > len(selected)
        else None,
    }


def _authorize_incident(db, who, incident_id):
    bookmark_clause, bookmark_grants = _bookmark_access(db, who)
    incident = db.execute(
        "SELECT i.* FROM incidents i WHERE i.id=? AND i.tenant=? AND ("
        + bookmark_clause
        + ")",
        [incident_id, who["tenant"], *bookmark_grants],
    ).fetchone()
    if not incident:
        raise KeyError("Incident not found")
    clause, grants = _scope(who)
    row = db.execute(
        "SELECT count(*) AS total,coalesce(sum(CASE WHEN ("
        + clause
        + ") THEN 0 ELSE 1 END),0) AS denied FROM risk_contributions r WHERE r.incident_id=? AND r.tenant=?",
        [*grants, incident_id, who["tenant"]],
    ).fetchone()
    if row["denied"]:
        raise KeyError("Incident not found")
    if not row["total"]:
        from . import contribution_verdicts

        contribution_verdicts.authorize_archived_scope(db, who, incident_id)
    return dict(incident), row["total"]


def contributions(store, who, since, incident_id=None, cursor=None, count=20):
    """Bounded evidence page; all pages retain tenant and current index filters."""
    clause, grants = _scope(who)
    where, args = (
        f"r.tenant=? AND r.at>=? AND ({clause})",
        [who["tenant"], since, *grants],
    )
    if incident_id:
        where += " AND r.incident_id=?"
        args.append(incident_id)
    with store.control() as db, _budget(db):
        if incident_id:
            _authorize_incident(db, who, incident_id)
        return _page(db, where, args, cursor, count)


def entity_risk(store, who, now=None, half_life=86400):
    now = time.time() if now is None else now
    if (
        isinstance(now, bool)
        or not isinstance(now, (int, float))
        or not -1e12 <= now <= 1e12
        or not math.isfinite(now)
        or isinstance(half_life, bool)
        or not isinstance(half_life, (int, float))
        or not 1 <= half_life <= 604800
    ):
        raise ValueError("Invalid risk calculation time or half life")
    clause, grants = _scope(who)
    from . import contribution_verdicts

    where = f"r.tenant=? AND r.at>=? AND r.at<=? AND i.status!='false_positive' AND ({clause}) AND ({contribution_verdicts.active_predicate('r')})"
    args = [who["tenant"], now - 7 * 86400, now, *grants]
    result, sample_bytes = [], 0
    with store.control() as db, _budget(db):
        db.create_function(
            "risk_decay",
            2,
            lambda at, weight: weight * 2 ** (-max(0, now - at) / half_life),
            deterministic=True,
        )

        def dependency(value, identifier):
            ids = json.loads(value).get("event_ids", [])
            if (
                not isinstance(ids, list)
                or not ids
                or any(not isinstance(v, str) for v in ids)
            ):
                return "legacy:" + identifier
            return hashlib.sha256(encode(sorted(set(ids))).encode()).hexdigest()

        db.create_function("evidence_dependency", 2, dependency, deterministic=True)
        rows = db.execute(
            "WITH evidence AS (SELECT r.entity_field,r.entity,evidence_dependency(r.evidence,r.id) AS dependency,"
            "max(risk_decay(r.at,r.weight)) AS term,count(*) AS n,max(r.at) AS last_seen "
            "FROM risk_contributions r JOIN incidents i ON i.id=r.incident_id WHERE "
            + where
            + " GROUP BY r.entity_field,r.entity,dependency) SELECT entity_field,entity,sum(term) AS score,sum(n) AS contribution_count,count(*) AS independent_event_sets,max(last_seen) AS last_seen FROM evidence GROUP BY entity_field,entity ORDER BY min(100,score) DESC,entity,entity_field",
            args,
        ).fetchall()
        for row in rows:
            from . import evidence_dependencies
            adjustment = evidence_dependencies.adjusted(db.execute(
                "SELECT r.id,r.evidence,risk_decay(r.at,r.weight) AS term FROM risk_contributions r JOIN incidents i ON i.id=r.incident_id WHERE " + where + " AND r.entity_field=? AND r.entity=?",
                [*args,row["entity_field"],row["entity"]],
            ))
            terms = []
            if sample_bytes < 1024 * 1024:
                samples = db.execute(
                    "SELECT r.id,r.incident_id,r.policy_id,r.at,r.weight,json_array_length(r.evidence,'$.event_ids') AS event_count,(SELECT json_group_array(value) FROM (SELECT value FROM json_each(r.evidence,'$.event_ids') LIMIT 20)) AS event_ids FROM risk_contributions r JOIN incidents i ON i.id=r.incident_id WHERE "
                    + where
                    + " AND r.entity_field=? AND r.entity=? ORDER BY r.at DESC,r.id DESC LIMIT 20",
                    [*args, row["entity_field"], row["entity"]],
                ).fetchall()
                for sample in samples:
                    term = {
                        "contribution_id": sample["id"],
                        "incident_id": sample["incident_id"],
                        "policy_id": sample["policy_id"],
                        "at": sample["at"],
                        "weight": sample["weight"],
                        "decayed_weight": round(
                            sample["weight"]
                            * 2 ** (-max(0, now - sample["at"]) / half_life),
                            4,
                        ),
                        "event_ids": json.loads(sample["event_ids"]),
                        "event_count": sample["event_count"],
                        "event_ids_truncated": sample["event_count"] > 20,
                    }
                    size = len(encode(term).encode())
                    if sample_bytes + size > 1024 * 1024:
                        break
                    terms.append(term)
                    sample_bytes += size
            result.append(
                {
                    "entity": row["entity"],
                    "entity_field": row["entity_field"],
                    "risk_score": round(min(100, adjustment["score"]), 2),
                    "uncapped_score": adjustment["score"],
                    "identical_set_score_before_overlap_adjustment": row["score"],
                    "last_seen": row["last_seen"],
                    "contribution_count": row["contribution_count"],
                    "contributions": terms,
                    "sample_truncated": len(terms) < row["contribution_count"],
                    "sample_limit": 20,
                    "independent_event_sets": adjustment["groups"],
                    "distinct_original_sets": adjustment["distinct_sets"],
                    "statistical_independence_proven": False,
                    "malicious_probability": None,
                    "dependency_adjustment": "Highest decayed weight per connected group of overlapping original IDs or declared dependent anomaly pages",
                    "formula": "min(100, sum(max(weight * 2^(-age_seconds / half_life_seconds)) per connected original-evidence group))",
                    "half_life_seconds": half_life,
                    "score_basis": "All authorized contributions in the seven-day window; displayed terms are a sample.",
                }
            )
    result.sort(key=lambda r: (-r["risk_score"],r["entity"],r["entity_field"]))
    return result


def entity_evidence(store, who, entity_field, entity, cursor=None, count=20, now=None):
    now = time.time() if now is None else now
    if (
        not isinstance(entity_field, str)
        or not isinstance(entity, str)
        or len(entity) > 256
        or isinstance(now, bool)
        or not isinstance(now, (int, float))
        or not 0 <= now <= 1e12
    ):
        raise ValueError("Invalid entity evidence request")
    clause, grants = _scope(who)
    from . import contribution_verdicts

    where = f"r.tenant=? AND r.entity_field=? AND r.entity=? AND r.at>=? AND r.at<=? AND i.status!='false_positive' AND ({clause}) AND ({contribution_verdicts.active_predicate('r')})"
    with store.control() as db, _budget(db):
        return _page(
            db,
            where,
            [who["tenant"], entity_field, entity, now - 7 * 86400, now, *grants],
            cursor,
            count,
        )


def incident_list(store, who):
    clause, grants = _scope(who)
    with store.control() as db, _budget(db):
        bookmark_clause, bookmark_grants = _bookmark_access(db, who)
        rows = db.execute(
            "SELECT i.*,(SELECT count(*) FROM risk_contributions r WHERE r.incident_id=i.id AND r.tenant=i.tenant) AS contribution_count FROM incidents i WHERE i.tenant=? AND EXISTS(SELECT 1 FROM risk_contributions r WHERE r.incident_id=i.id AND r.tenant=i.tenant) AND NOT EXISTS(SELECT 1 FROM risk_contributions r WHERE r.incident_id=i.id AND r.tenant=i.tenant AND NOT ("
            + clause
            + ")) AND ("
            + bookmark_clause
            + ") ORDER BY i.updated DESC,i.id DESC",
            [who["tenant"], *grants, *bookmark_grants],
        ).fetchall()
    return [dict(row) for row in rows]


def incident_detail(store, who, incident_id, cursor=None, count=3):
    with store.control() as db, _budget(db):
        incident, total = _authorize_incident(db, who, incident_id)
        page = _page(
            db,
            "r.tenant=? AND r.incident_id=?",
            [who["tenant"], incident_id],
            cursor,
            count,
        )
        feedback = db.execute(
            "SELECT actor,at,status,note FROM incident_feedback WHERE incident_id=? AND tenant=? ORDER BY at DESC,id DESC",
            (incident_id, who["tenant"]),
        ).fetchall()
        feedback_total = db.execute(
            "SELECT count(*) FROM incident_feedback WHERE incident_id=? AND tenant=?",
            (incident_id, who["tenant"]),
        ).fetchone()[0]
    rows = page["contributions"]
    timeline = sorted(
        [
            {"policy_id": r["policy_id"], "step": step["step"], **event}
            for r in rows
            for step in r["evidence"]["steps"]
            for event in step["events"]
        ],
        key=lambda x: (x["event_time"], x["event_id"]),
    )
    selected_feedback, feedback_bytes = [], 0
    for row in feedback:
        item = dict(row)
        size = len(encode(item).encode())
        selected_feedback.append(item)
        feedback_bytes += size
    result = {
        **incident,
        **page,
        "contribution_count": total,
        "timeline": timeline,
        "timeline_scope": "Current contribution page",
        "feedback": selected_feedback,
        "feedback_limit": None,
        "feedback_total_count": feedback_total,
        "feedback_truncated": len(selected_feedback) < feedback_total,
    }
    return result


def update_incident(store, who, incident_id, data):
    if who.get("role") not in {"admin", "analyst"}:
        raise PermissionError("Incident editing requires analyst or administrator")
    if (
        set(data) != {"status", "owner", "version", "note"}
        or data["status"] not in STATES
        or not isinstance(data["owner"], str)
        or len(data["owner"]) > 64
        or type(data["version"]) is not int
        or not isinstance(data["note"], str)
        or len(data["note"]) > 2000
    ):
        raise ValueError("Expected status, owner, version and note")
    with store.write_lock, store.control() as db, _budget(db, write=True):
        # Reserve the writer before authorizing: a concurrent detection must
        # not add private evidence between the scope check and feedback write.
        from . import casework, principal

        who = principal.current(db, who, ("admin", "analyst"))
        principal.incident(db, who, incident_id)
        if data["status"] in {"resolved", "false_positive"}:
            casework.require_resolution(db, who, incident_id)
        from . import contribution_verdicts

        contribution_verdicts.require_case_adjudication(
            db, who, incident_id, data["status"]
        )
        row = db.execute(
            "UPDATE incidents SET status=?,owner=?,version=version+1,updated=? WHERE id=? AND tenant=? AND version=?",
            (
                data["status"],
                data["owner"],
                time.time(),
                incident_id,
                who["tenant"],
                data["version"],
            ),
        )
        if not row.rowcount:
            raise ConflictError("Incident changed; refresh before editing")
        db.execute(
            "INSERT INTO incident_feedback(tenant,incident_id,actor,at,status,note) VALUES(?,?,?,?,?,?)",
            (
                who["tenant"],
                incident_id,
                who["name"],
                time.time(),
                data["status"],
                data["note"],
            ),
        )
        store.audit(
            db,
            who["tenant"],
            who["name"],
            "incident.feedback",
            {"id": incident_id, **data},
        )
