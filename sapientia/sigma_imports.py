"""Versioned Sigma import custody and reviewed native policy deployment."""

import hashlib
import json
import time
import uuid

from . import (
    access,
    content_notices,
    intelligence,
    migrations,
    principal,
    release_manifest,
    sigma_backend,
)
from .storage import ConflictError, encode, normalize

EDIT = ("admin", "analyst")
MAX_SOURCE_BYTES = 65536
MAX_PAYLOAD_BYTES = 512 * 1024


def initialize(store):
    migrations.apply_store(
        store,
        "sigma_imports",
        [
            "CREATE TABLE IF NOT EXISTS sigma_imports(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,editor TEXT NOT NULL,indexes TEXT NOT NULL,revision INTEGER NOT NULL,state TEXT NOT NULL,body TEXT NOT NULL,updated REAL NOT NULL)",
            "CREATE TABLE IF NOT EXISTS sigma_import_revisions(id TEXT NOT NULL,tenant TEXT NOT NULL,revision INTEGER NOT NULL,payload TEXT NOT NULL,source_sha256 TEXT NOT NULL,actor TEXT NOT NULL,created REAL NOT NULL,PRIMARY KEY(tenant,id,revision))",
            "CREATE TABLE IF NOT EXISTS sigma_import_history(seq INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT NOT NULL,id TEXT NOT NULL,revision INTEGER NOT NULL,action TEXT NOT NULL,actor TEXT NOT NULL,body TEXT NOT NULL,created REAL NOT NULL)",
            "CREATE TABLE IF NOT EXISTS sigma_import_bindings(policy_id TEXT PRIMARY KEY,tenant TEXT NOT NULL,import_id TEXT NOT NULL,revision INTEGER NOT NULL,policy_version INTEGER NOT NULL,definition_digest TEXT NOT NULL,validation_digest TEXT NOT NULL,updated REAL NOT NULL)",
            "CREATE INDEX IF NOT EXISTS sigma_import_binding_owner ON sigma_import_bindings(tenant,import_id)",
        ],
    )
    migrations.apply_store(store, "sigma_imports", [
        "CREATE TABLE IF NOT EXISTS sigma_import_deployments(tenant TEXT NOT NULL,import_id TEXT NOT NULL,policy_version INTEGER NOT NULL,revision INTEGER NOT NULL,policy_id TEXT NOT NULL,row_snapshot TEXT NOT NULL,body TEXT NOT NULL,snapshot_digest TEXT NOT NULL,active INTEGER NOT NULL,created REAL NOT NULL,PRIMARY KEY(tenant,import_id,policy_version))",
        "CREATE UNIQUE INDEX IF NOT EXISTS sigma_import_one_deployment ON sigma_import_deployments(tenant,import_id) WHERE active=1",
        "CREATE TABLE IF NOT EXISTS native_correlation_state(policy_id TEXT PRIMARY KEY,version INTEGER NOT NULL,last_seq INTEGER NOT NULL,status TEXT NOT NULL,detail TEXT NOT NULL,updated REAL NOT NULL)",
    ], version=2)
    # Additive upgrade: preserve the already reviewed 0.18 deployment unchanged.
    with store.control(local=True) as db:
        for binding in db.execute("SELECT b.* FROM sigma_import_bindings b WHERE NOT EXISTS(SELECT 1 FROM sigma_import_deployments d WHERE d.tenant=b.tenant AND d.import_id=b.import_id)").fetchall():
            row = db.execute("SELECT * FROM sigma_imports WHERE tenant=? AND id=?", (binding["tenant"], binding["import_id"])).fetchone()
            if row and row["state"] == "active" and row["revision"] == binding["revision"]:
                _snapshot(db, row, json.loads(row["body"]), binding["policy_id"], binding["policy_version"])


def _snapshot(db, row, body, policy_id, policy_version):
    custody = {key: row[key] for key in ("id", "tenant", "owner", "editor", "indexes", "revision")}
    digest = release_manifest.digest({"row": custody, "body": body})
    db.execute("UPDATE sigma_import_deployments SET active=0 WHERE tenant=? AND import_id=?", (row["tenant"], row["id"]))
    db.execute("INSERT INTO sigma_import_deployments VALUES(?,?,?,?,?,?,?,?,1,?)", (row["tenant"], row["id"], policy_version, row["revision"], policy_id, encode(custody), encode(body), digest, time.time()))


def _deployment(db, actor, identifier, policy_version=None):
    where, values = ("active=1", []) if policy_version is None else ("policy_version=?", [policy_version])
    deployed = db.execute("SELECT * FROM sigma_import_deployments WHERE tenant=? AND import_id=? AND " + where, (actor["tenant"], identifier, *values)).fetchone()
    if not deployed:
        raise ConflictError("Approved Sigma deployment snapshot unavailable")
    row, body = json.loads(deployed["row_snapshot"]), json.loads(deployed["body"])
    if not isinstance(row, dict) or not isinstance(body, dict) or release_manifest.digest({"row": row, "body": body}) != deployed["snapshot_digest"]:
        raise ConflictError("Sigma deployment snapshot integrity changed")
    if row.get("tenant") != actor["tenant"] or row.get("id") != identifier or row.get("revision") != deployed["revision"] or body.get("native_policy_id") != deployed["policy_id"] or body.get("native_policy_version") != deployed["policy_version"]:
        raise ConflictError("Sigma deployment identity differs")
    if not principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
        raise KeyError("Sigma deployment unavailable in complete current scope")
    original = db.execute("SELECT payload,source_sha256 FROM sigma_import_revisions WHERE tenant=? AND id=? AND revision=?", (actor["tenant"], identifier, row["revision"])).fetchone()
    if not original or json.loads(original["payload"]) != body.get("payload") or original["source_sha256"] != body.get("source_sha256") or hashlib.sha256(body["payload"]["source_text"].encode()).hexdigest() != body["source_sha256"]:
        raise ConflictError("Sigma deployed original revision changed")
    return row, body, deployed


def assert_native_editable(db, actor, identifier):
    if db.execute(
        "SELECT 1 FROM sigma_import_bindings WHERE tenant=? AND policy_id=?",
        (actor["tenant"], identifier),
    ).fetchone():
        raise ConflictError(
            "Managed Sigma policies must be edited and reviewed through their import revision"
        )


def validate_native_binding(db, actor, row, definition):
    binding = db.execute(
        "SELECT * FROM sigma_import_bindings WHERE tenant=? AND policy_id=?",
        (actor["tenant"], row["id"]),
    ).fetchone()
    if binding is None:
        return
    _validate_binding(db, actor, row, definition, binding)


def signal_metadata(db, actor, row, definition):
    """Server-derived provenance after current binding verification; no writes."""
    binding = db.execute(
        "SELECT * FROM sigma_import_bindings WHERE tenant=? AND policy_id=?",
        (actor["tenant"], row["id"]),
    ).fetchone()
    if binding is None:
        return {}
    _validate_binding(db, actor, row, definition, binding)
    _, body, _ = _deployment(db, actor, binding["import_id"])
    return {
        "sigma_import": {
            "import_id": binding["import_id"],
            "revision": binding["revision"],
            "source_sha256": body["source_sha256"],
            "native_definition_digest": binding["definition_digest"],
            "validation_digest": binding["validation_digest"],
            "content_notices": content_notices.bundle([
                {**body["converted"]["source_notice"], "import_id": binding["import_id"], "revision": binding["revision"]}
            ]) if "source_notice" in body["converted"] else None,
        }
    }


def _fields(body, expected):
    if not isinstance(body, dict) or set(body) != set(expected):
        raise ValueError("Expected fields: " + ", ".join(sorted(expected)))
    return body


def _text(value, name, maximum=120):
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or any(ord(char) < 32 for char in value)
    ):
        raise ValueError("Bounded " + name + " required")
    return value


def _unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate Sigma document key")
        result[key] = value
    return result


def _decode(text, kind):
    if (
        not isinstance(text, str)
        or not 1 <= len(text.encode("utf-8")) <= MAX_SOURCE_BYTES
        or "\x00" in text
    ):
        raise ValueError("Sigma source requires 1..65536 UTF-8 bytes without NUL")
    if kind == "json":
        try:
            rule = json.loads(
                text,
                object_pairs_hook=_unique_object,
                parse_constant=lambda _: (_ for _ in ()).throw(
                    ValueError("Finite Sigma JSON required")
                ),
            )
        except (json.JSONDecodeError, RecursionError) as exc:
            raise ValueError("Invalid bounded Sigma JSON") from exc
    elif kind == "yaml":
        try:
            import yaml
        except ImportError:
            raise ValueError(
                "PyYAML runtime unavailable; install sigma-analysis extra"
            ) from None

        class Loader(yaml.SafeLoader):
            pass

        Loader.yaml_implicit_resolvers = {
            key: [
                (tag, pattern)
                for tag, pattern in values
                if tag != "tag:yaml.org,2002:timestamp"
            ]
            for key, values in Loader.yaml_implicit_resolvers.items()
        }

        def mapping(loader, node, deep=False):
            if any(
                not isinstance(key, yaml.ScalarNode)
                or key.tag != "tag:yaml.org,2002:str"
                or key.value == "<<"
                for key, _ in node.value
            ):
                raise ValueError(
                    "Sigma YAML requires plain string keys; merge keys are forbidden"
                )
            return _unique_object(
                [
                    (
                        loader.construct_object(key, deep=deep),
                        loader.construct_object(value, deep=deep),
                    )
                    for key, value in node.value
                ]
            )

        Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
        try:
            depth = 0
            for nodes, event in enumerate(yaml.parse(text, Loader=Loader), start=1):
                if (
                    nodes > 4096
                    or isinstance(event, yaml.AliasEvent)
                    or getattr(event, "anchor", None)
                ):
                    raise ValueError(
                        "Sigma YAML aliases, anchors or excessive structure are forbidden"
                    )
                if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                    depth += 1
                elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                    depth -= 1
                if depth > 16:
                    raise ValueError("Sigma YAML structure exceeds depth 16")
            # Loader subclasses SafeLoader, rejects aliases/merges/duplicate keys,
            # and has already passed the 64 KiB/4096-event/depth-16 budget.
            rule = yaml.load(text, Loader=Loader)  # nosec B506
        except (yaml.YAMLError, RecursionError) as exc:
            raise ValueError("Invalid or multi-document Sigma YAML") from exc
    else:
        raise ValueError("Sigma format must be json or yaml")
    if not isinstance(rule, dict):
        raise ValueError("Exactly one Sigma rule object is required")  # noqa: TRY004 - HTTP validation uses ValueError.
    sigma_backend._bounded(rule)
    return rule


def _payload(body):
    keys = {
        "expected_revision",
        "name",
        "format",
        "source_text",
        "indexes",
        "field_mapping",
        "logsource_mapping",
        "source_contracts",
        "severity",
        "case_adapter",
        "fixtures",
    }
    _fields(body, keys)
    if type(body["expected_revision"]) is not int or body["expected_revision"] < 0:
        raise ValueError("Nonnegative expected_revision required")
    try:
        if len(encode(body).encode()) > MAX_PAYLOAD_BYTES:
            raise ValueError("Sigma import payload exceeds 512 KiB")
    except (TypeError, RecursionError):
        raise ValueError("Finite bounded import JSON required") from None
    indexes = access.validate(body["indexes"])
    if not 1 <= len(indexes) <= 8 or "*" in indexes:
        raise ValueError("Sigma import requires 1..8 exact indexes")
    rule = _decode(body["source_text"], body["format"])
    if not isinstance(body["field_mapping"], dict) or not isinstance(
        body["logsource_mapping"], dict
    ):
        raise ValueError("Explicit field and logsource mapping objects required")  # noqa: TRY004 - HTTP validation uses ValueError.
    contracts = body["source_contracts"]
    if not isinstance(contracts, list) or not 1 <= len(contracts) <= 8:
        raise ValueError("1..8 registered source contracts required")
    for item in contracts:
        _fields(item, {"source_id", "version"})
        _text(item["source_id"], "source ID", 256)
        if type(item["version"]) is not int or item["version"] < 1:
            raise ValueError("Exact positive source version required")
    if len({item["source_id"] for item in contracts}) != len(contracts):
        raise ValueError("Duplicate source contracts")
    if not isinstance(body["severity"], str) or body["severity"] not in intelligence.SEVERITIES:
        raise ValueError("Unsupported native severity")
    from .detection_automation import validate_case_adapter

    adapter = validate_case_adapter(body["case_adapter"])
    fixtures = body["fixtures"]
    if not isinstance(fixtures, list) or not 2 <= len(fixtures) <= 32:
        raise ValueError("2..32 positive and negative fixtures required")
    canonical = []
    for item in fixtures:
        if "correlation" in rule:
            _fields(item, {"name", "events", "expect"})
            _text(item["name"], "fixture name")
            if type(item["expect"]) is not bool or not isinstance(item["events"], list) or not 1 <= len(item["events"]) <= 32:
                raise ValueError("Correlation fixture needs a Boolean expectation and 1..32 scoped events")
            events = []
            for sample in item["events"]:
                _fields(sample, {"source_id", "event"})
                if sample["source_id"] not in {contract["source_id"] for contract in contracts} or not isinstance(sample["event"], dict) or not {"event_id", "event_time", "index"} <= set(sample["event"]):
                    raise ValueError("Correlation fixture requires explicit registered source and normalized event")
                event = normalize(sample["event"])
                if event["index"] not in indexes:
                    raise ValueError("Correlation fixture index outside scope")
                events.append({"source_id": sample["source_id"], "event": event})
            if len({sample["event"]["event_id"] for sample in events}) != len(events):
                raise ValueError("Correlation fixture original IDs must be unique")
            canonical.append({**item, "events": events})
            continue
        _fields(item, {"name", "source_id", "event", "expect"})
        _text(item["name"], "fixture name")
        if type(item["expect"]) is not bool or item["source_id"] not in {
            contract["source_id"] for contract in contracts
        }:
            raise ValueError(
                "Fixture requires a Boolean expectation and declared source ID"
            )
        if not isinstance(item["event"], dict) or not {
            "event_id",
            "event_time",
            "index",
        } <= set(item["event"]):
            raise ValueError(
                "Fixture requires an explicit normalized event ID/time/index"
            )
        event = normalize(item["event"])
        if event["index"] not in indexes:
            raise ValueError("Fixture index outside import scope")
        canonical.append({**item, "event": event})
    if len({f["name"] for f in canonical}) != len(canonical) or "correlation" not in rule and len(
        {f["event"]["event_id"] for f in canonical}
    ) != len(canonical):
        raise ValueError("Fixture names and event IDs must be unique")
    if {item["expect"] for item in canonical} != {True, False}:
        raise ValueError("At least one positive and one negative fixture are required")
    return {
        **{
            key: body[key]
            for key in keys
            - {"expected_revision", "fixtures", "indexes", "case_adapter"}
        },
        "name": _text(body["name"], "import name"),
        "indexes": sorted(indexes),
        "case_adapter": adapter,
        "fixtures": canonical,
    }


def _pins(db, actor, payload):
    from . import source_registry

    result = []
    for wanted in payload["source_contracts"]:
        row = source_registry.visible(db, actor, wanted["source_id"])
        if (
            row["state"] != "active"
            or row["version"] != wanted["version"]
            or row["index_name"] not in payload["indexes"]
        ):
            raise ConflictError(
                "Declared source is revoked, changed, or outside exact indexes"
            )
        source_owner = principal.current(
            db,
            {"tenant": actor["tenant"], "name": row["owner"], "role": "analyst"},
            EDIT,
        )
        if not principal.contains(source_owner["allowed_indexes"], [row["index_name"]]):
            raise PermissionError("Current source owner scope unavailable")
        definition = json.loads(row["definition"])
        if (
            any(
                definition.get(key) != row[key]
                for key in ("product", "account", "realm", "credential_ref")
            )
            or definition.get("index") != row["index_name"]
        ):
            raise ConflictError(
                "Registered source metadata differs from its canonical contract"
            )
        result.append(
            {
                "source_id": row["id"],
                "version": row["version"],
                "index": row["index_name"],
                "owner": row["owner"],
                "definition_sha256": release_manifest.digest(definition),
                "source_contract_sha256": release_manifest.digest(
                    {
                        key: row[key]
                        for key in (
                            "id",
                            "owner",
                            "index_name",
                            "product",
                            "account",
                            "realm",
                            "credential_ref",
                            "definition",
                            "version",
                            "state",
                        )
                    }
                ),
                "definition": {
                    **definition,
                    "id": row["id"],
                    "version": row["version"],
                },
            }
        )
    if {pin["index"] for pin in result} != set(payload["indexes"]):
        raise ValueError("Every declared index requires a registered source contract")
    return sorted(result, key=lambda pin: pin["source_id"])


def _row(db, actor, identifier, expected=None):
    row = db.execute(
        "SELECT * FROM sigma_imports WHERE tenant=? AND id=?",
        (actor["tenant"], identifier),
    ).fetchone()
    if not row or not principal.contains(
        actor["allowed_indexes"], json.loads(row["indexes"])
    ):
        raise KeyError("Sigma import not found in complete current scope")
    if expected is not None and (
        type(expected) is not int or row["revision"] != expected
    ):
        raise ConflictError("Sigma import revision changed")
    body = json.loads(row["body"])
    if (
        not isinstance(body, dict)
        or not isinstance(body.get("payload"), dict)
        or not isinstance(body.get("source_sha256"), str)
    ):
        raise ConflictError("Sigma import metadata shape is invalid")
    original = db.execute(
        "SELECT * FROM sigma_import_revisions WHERE tenant=? AND id=? AND revision=?",
        (actor["tenant"], identifier, row["revision"]),
    ).fetchone()
    if (
        not original
        or json.loads(original["payload"]) != body["payload"]
        or original["source_sha256"] != body["source_sha256"]
    ):
        raise ConflictError("Sigma immutable import revision differs")
    if (
        hashlib.sha256(body["payload"]["source_text"].encode()).hexdigest()
        != body["source_sha256"]
    ):
        raise ConflictError("Sigma original source SHA256 differs")
    return row, body


def _participants(db, row):
    participants = {}
    for key in ("owner", "editor"):
        person = principal.current(
            db, {"name": row[key], "tenant": row["tenant"], "role": "analyst"}, EDIT
        )
        if not principal.contains(
            person["allowed_indexes"], json.loads(row["indexes"])
        ):
            raise PermissionError(
                "Current Sigma " + key + " complete scope unavailable"
            )
        participants[key] = person
    return participants


def _record(store, db, actor, row, body, state, action):
    now = time.time()
    db.execute(
        "UPDATE sigma_imports SET body=?,state=?,updated=? WHERE tenant=? AND id=? AND revision=?",
        (encode(body), state, now, actor["tenant"], row["id"], row["revision"]),
    )
    details = {
        "validate": body.get("validation"),
        "review": body.get("review"),
        "convert": body.get("converted"),
        "retire": body.get("retirement"),
    }
    event = {
        "state": state,
        "source_sha256": body["source_sha256"],
        "converted_sha256": body.get("converted_sha256"),
        "validation_digest": body.get("validation", {}).get("digest"),
        "review_digest": body.get("review", {}).get("digest"),
        "native_policy_id": body.get("native_policy_id"),
        "detail": details.get(action),
    }
    db.execute(
        "INSERT INTO sigma_import_history(tenant,id,revision,action,actor,body,created) VALUES(?,?,?,?,?,?,?)",
        (
            actor["tenant"],
            row["id"],
            row["revision"],
            action,
            actor["name"],
            encode(event),
            now,
        ),
    )
    store.audit(
        db,
        actor["tenant"],
        actor["name"],
        "sigma.import." + action,
        {"id": row["id"], "revision": row["revision"], **event},
    )


def _disable_native(db, tenant, identifier):
    for row in db.execute(
        "SELECT policy_id FROM sigma_import_bindings WHERE tenant=? AND import_id=?",
        (tenant, identifier),
    ):
        db.execute(
            "UPDATE intelligence_policies SET state='disabled',approver=NULL,approval_digest=NULL,updated=? WHERE tenant=? AND id=?",
            (time.time(), tenant, row["policy_id"]),
        )


def save(store, who, data, identifier=None, *, mapping_approval=None):
    payload = _payload(data)
    with principal.transaction(store, who, EDIT, write=True) as (db, actor):
        if not principal.contains(actor["allowed_indexes"], payload["indexes"]):
            raise PermissionError("Sigma import indexes outside current authority")
        old, previous = (
            _row(db, actor, identifier, data["expected_revision"])
            if identifier
            else (None, None)
        )
        if old and old["owner"] != actor["name"] and actor["role"] != "admin":
            raise PermissionError("Only Sigma import owner or administrator may edit")
        if not old and data["expected_revision"] != 0:
            raise ConflictError("New Sigma imports require expected_revision 0")
        pins = _pins(db, actor, payload)
        identifier, revision = (
            identifier or "SIGMA-" + uuid.uuid4().hex,
            (old["revision"] if old else 0) + 1,
        )
        now = time.time()
        body = {
            "payload": payload,
            "source_sha256": hashlib.sha256(
                payload["source_text"].encode()
            ).hexdigest(),
            "source_pins": pins,
            "native_policy_id": previous.get("native_policy_id") if previous else None,
        }
        if mapping_approval is not None:
            body["mapping_approval"] = {**mapping_approval, "approved_by": actor["name"], "approved_at": now}
        # A working draft has no authority over the separately approved deployment.
        db.execute(
            "INSERT INTO sigma_imports VALUES(?,?,?,?,?,?,?, ?,?) ON CONFLICT(id) DO UPDATE SET editor=excluded.editor,indexes=excluded.indexes,revision=excluded.revision,state=excluded.state,body=excluded.body,updated=excluded.updated",
            (
                identifier,
                actor["tenant"],
                old["owner"] if old else actor["name"],
                actor["name"],
                encode(payload["indexes"]),
                revision,
                "imported",
                encode(body),
                now,
            ),
        )
        db.execute(
            "INSERT INTO sigma_import_revisions VALUES(?,?,?,?,?,?,?)",
            (
                identifier,
                actor["tenant"],
                revision,
                encode(payload),
                body["source_sha256"],
                actor["name"],
                now,
            ),
        )
        row, body = _row(db, actor, identifier)
        _record(store, db, actor, row, body, "imported", "save")
    return get(store, who, identifier)


def _converted(db, actor, row, body, *, require_parser=True):
    from . import native_predicates

    converted = body.get("converted")
    if not isinstance(converted, dict) or release_manifest.digest(
        converted
    ) != body.get("converted_sha256"):
        raise ConflictError("Convert this exact Sigma revision first")
    if _pins(db, actor, body["payload"]) != body["source_pins"]:
        raise ConflictError(
            "Sigma source contracts changed; save and revalidate a new revision"
        )
    if converted.get("source_sha256") != body["source_sha256"] or converted.get(
        "payload_digest"
    ) != release_manifest.digest(body["payload"]):
        raise ConflictError(
            "Converted Sigma payload differs from its immutable revision"
        )
    from . import native_correlations
    native = converted.get("native_policy")
    if (not isinstance(native, dict) or (native.get("kind") == "atomic" and native.get("condition_contract") != native_predicates.CONTRACT_DIGEST) or (native.get("kind") == "composite" and native.get("correlation_contract") != native_correlations.CONTRACT_DIGEST)):
        raise ConflictError("Native evaluator changed; reconvert and review")
    if native.get("kind") == "composite":
        intelligence._parents_current(db, actor["tenant"], native, actor)
    if require_parser and (
        converted["parser_version"] != sigma_backend.status().get("version")
        or converted.get("converter_sha256")
        != release_manifest.hash_file(sigma_backend.__file__)
    ):
        raise ConflictError("Upstream Sigma parser changed; reconvert and review")
    _participants(db, row)
    return converted


def convert(store, who, identifier, expected_revision):
    with principal.transaction(store, who, EDIT, write=True) as (db, actor):
        row, body = _row(db, actor, identifier, expected_revision)
        if row["state"] in {"active", "approved", "retired"}:
            raise ConflictError(
                "Save a new revision before reconverting an approved/active/retired import"
            )
        _participants(db, row)
        if _pins(db, actor, body["payload"]) != body["source_pins"]:
            raise ConflictError("Save a new revision for changed source contracts")
        payload = body["payload"]
        decoded = _decode(payload["source_text"], payload["format"])
        if "correlation" in decoded:
            native, preview = _convert_correlation(db, actor, payload, decoded)
        else:
            native, preview = _convert_atomic(payload, body, decoded)
        converted = {
            "source_sha256": body["source_sha256"],
            "payload_digest": release_manifest.digest(payload),
            "canonical_source_sha256": release_manifest.digest(decoded),
            "converter_sha256": release_manifest.hash_file(sigma_backend.__file__),
            "import_contract_version": 2,
            "mapping_sha256": release_manifest.digest({"field_mapping": payload["field_mapping"], "logsource_mapping": payload["logsource_mapping"]}),
            "parser_version": preview["upstream"]["version"],
            "profile": sigma_backend.PROFILE,
            "native_ir_version": 1,
            "native_policy": native,
            "native_definition_digest": release_manifest.digest(native),
            "query_preview": preview["query"],
            "limitations": preview["limitations"],
            "source_notice": content_notices.sigma_source(decoded, body["source_sha256"]),
        }
        body.update(converted=converted, converted_sha256=release_manifest.digest(converted))
        body.pop("validation", None)
        body.pop("review", None)
        _record(store, db, actor, row, body, "converted", "convert")
    return get(store, who, identifier)


def _convert_atomic(payload, body, decoded):
        preview = sigma_backend.native_preview(
            {
                "profile": sigma_backend.PROFILE,
                "rule": decoded,
                "field_mapping": payload["field_mapping"],
                "logsource_mapping": payload["logsource_mapping"],
            }
        )
        guards = [
            {
                "op": "and",
                "args": [
                    {
                        "op": "eq",
                        "field": "projection.source_id",
                        "value": pin["source_id"],
                    },
                    {
                        "op": "eq",
                        "field": "projection.source_version",
                        "value": pin["version"],
                    },
                    {"op": "eq", "field": "event.index_name", "value": pin["index"]},
                ],
            }
            for pin in body["source_pins"]
        ]
        tree = {
            "version": 1,
            "root": {
                "op": "and",
                "args": [
                    {"op": "or", "args": guards},
                    preview["native_condition_tree"]["root"],
                ],
            },
        }
        native = intelligence._definition(
            {
                "name": payload["name"],
                "kind": "atomic",
                "enabled": True,
                "indexes": payload["indexes"],
                "severity": payload["severity"],
                "confidence_grade": "reviewed_sigma_rule",
                "window": 300,
                "case_adapter": payload["case_adapter"],
                "condition_tree": tree,
            }
        )
        return native, preview


def _convert_correlation(db, actor, payload, decoded):
    import re

    from . import native_correlations
    if set(decoded) - {"title", "name", "id", "description", "status", "author", "date", "modified", "references", "tags", "falsepositives", "level", "license", "correlation"}:
        raise ValueError("Unsupported Sigma correlation document field")
    if not isinstance(decoded.get("title"), str) or not 1 <= len(decoded["title"]) <= 120:
        raise ValueError("Bounded correlation title required")
    value = decoded["correlation"]
    if not isinstance(value, dict) or set(value) - {"type", "rules", "group-by", "timespan", "condition", "aliases", "generate"}:
        raise ValueError("Unknown Sigma correlation option")
    if value.get("type") not in native_correlations.TYPES:
        raise ValueError("Unsupported Sigma correlation/aggregation type")
    references, grouping = value.get("rules"), value.get("group-by")
    if not isinstance(references, list) or not 1 <= len(references) <= 8 or any(not isinstance(item, str) or not item for item in references) or len(set(references)) != len(references):
        raise ValueError("1..8 distinct named/ID Sigma references required")
    if not isinstance(grouping, list) or not 1 <= len(grouping) <= 4 or any(not isinstance(item, str) for item in grouping):
        raise ValueError("1..4 explicit Sigma group-by fields required")
    span = value.get("timespan")
    if not isinstance(span, str) or not re.fullmatch(r"[1-9][0-9]{0,5}[smhd]", span):
        raise ValueError("Sigma timespan supports bounded integer s/m/h/d")
    seconds = int(span[:-1]) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[span[-1]]
    if not 1 <= seconds <= 86400:
        raise ValueError("Sigma timespan must be 1..86400 seconds")
    if "generate" in value and type(value["generate"]) is not bool:
        raise ValueError("Boolean generate required")
    # References are existing independently activated base imports, retained as
    # native atomic policies. generate does not hide or revoke those approvals.
    if value.get("generate") is False:
        raise ValueError("generate:false cannot suppress existing active base rules; omit it or use true")
    try:
        from sigma.correlations import SigmaCorrelationRule
        from sigma.exceptions import SigmaError
    except ImportError:
        raise ValueError("pySigma correlation parser unavailable") from None
    try:
        SigmaCorrelationRule.from_dict(decoded)
    except (SigmaError, TypeError, KeyError, ValueError) as exc:
        raise ValueError("Invalid Sigma correlation: " + str(exc)[:400]) from None
    resolved = {}
    for item in db.execute("SELECT import_id FROM sigma_import_deployments WHERE tenant=? AND active=1", (actor["tenant"],)).fetchall():
        try:
            _, body, _ = _deployment(db, actor, item["import_id"])
            source_rule = _decode(body["payload"]["source_text"], body["payload"]["format"])
            names = {source_rule.get("id"), source_rule.get("name")} - {None}
            if names.intersection(references):
                native = db.execute("SELECT * FROM intelligence_policies WHERE tenant=? AND id=?", (actor["tenant"], body["native_policy_id"])).fetchone()
                _, definition = intelligence._authority(db, native)
                if definition["kind"] != "atomic":
                    raise ValueError("Correlation chaining is not supported by this native profile")
                if not principal.contains(payload["indexes"], definition["indexes"]):
                    raise PermissionError("Correlation must declare complete parent index scopes")
                parent_contracts = {(pin["source_id"], pin["version"]) for pin in body["source_pins"]}
                if not parent_contracts <= {(pin["source_id"], pin["version"]) for pin in payload["source_contracts"]}:
                    raise ValueError("Correlation must explicitly pin every parent source contract")
                for name in names.intersection(references):
                    if name in resolved:
                        raise ValueError("Ambiguous Sigma reference; use a unique original ID")
                    resolved[name] = (native, definition)
        except KeyError:
            continue  # Hidden imports cannot become a name-discovery oracle.
    if set(resolved) != set(references):
        raise ValueError("Every Sigma reference requires one currently approved atomic import in complete scope")
    identifiers = [resolved[name][0]["id"] for name in references]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("Several references resolve to the same native rule")
    aliases = value.get("aliases", {})
    if not isinstance(aliases, dict) or set(aliases) - set(grouping):
        raise ValueError("Aliases must name explicit grouping fields")
    def mapped(field, reference):
        alias = aliases.get(field)
        if alias is not None:
            if not isinstance(alias, dict) or set(alias) != set(references):
                raise ValueError("Every field alias needs every referenced rule")
            field = alias[reference]
        if not isinstance(field, str) or field not in payload["field_mapping"]:
            raise ValueError("Explicit mapping missing for correlation field " + str(field))
        target = payload["field_mapping"][field]
        target = target if target.startswith("raw.") else "event." + target.removeprefix("event.")
        return native_correlations._path(target)
    threshold, value_field = None, None
    if value["type"] in {"event_count", "value_count"}:
        condition = value.get("condition")
        expected = {"field"} if value["type"] == "value_count" else set()
        if not isinstance(condition, dict) or len(set(condition) - expected) != 1:
            raise ValueError("One positive count comparison required")
        op = next(iter(set(condition) - expected))
        threshold = {"op": op, "value": condition[op]}
        if value["type"] == "value_count":
            value_field = {resolved[reference][0]["id"]: mapped(condition.get("field"), reference) for reference in references}
    elif "condition" in value:
        raise ValueError("Temporal threshold/extended expressions unsupported; all referenced rules required")
    if payload["logsource_mapping"]:
        raise ValueError("Correlation uses parent source contracts; logsource_mapping must be empty")
    inputs = [{"rule_id": identifier, "kind": "atomic"} for identifier in identifiers]
    correlation = {"version": 1, "type": value["type"], "group_by": [{"name": name, "fields": {resolved[reference][0]["id"]: mapped(name, reference) for reference in references}} for name in grouping], "value_field": value_field, "condition": threshold, "clock": "reported_event_time", "window_semantics": "sliding_inclusive"}
    correlation = native_correlations.validate(correlation, inputs, seconds)
    native = intelligence._definition({"name": payload["name"], "kind": "composite", "enabled": True, "indexes": payload["indexes"], "severity": payload["severity"], "confidence_grade": "reviewed_sigma_correlation", "window": seconds, "case_adapter": payload["case_adapter"], "inputs": inputs, "join_on": "entity", "minimum_independent_groups": 1, "ordered": False, "clock_policy": "reported", "correlation": correlation})
    native["input_revisions"] = {row["id"]: {"version": row["version"], "definition_digest": release_manifest.digest(definition)} for row, definition in resolved.values()}
    preview = {"upstream": {"version": sigma_backend.status()["version"]}, "query": {"type": "native_composite_json", "query": encode(native)}, "limitations": ["Supported subset: positive event_count/value_count and all-rule temporal/temporal_ordered", "Existing independently active base rules remain enabled", "Sliding inclusive reported-event-time windows; temporal_ordered uses strictly increasing timestamps", "Missing/null/structured group fields are excluded; counts deduplicate original IDs", "At most 256 retained parents and 32 parents/originals per window; overflow is coverage_exceeded", "No absence/upper-bound counts, chaining, metric aggregation, extended conditions, or legacy pipe aggregation"]}
    return native, preview


def _fixture_observed(db, actor, converted, fixture, pins):
    from . import native_correlations
    from .security_schema import project
    definition = converted["native_policy"]
    if definition["kind"] == "atomic":
        event, pin = fixture["event"], pins[fixture["source_id"]]
        if event["index"] != pin["index"]:
            raise ValueError("Fixture source/index contract mismatch")
        record = {**event, "index_name": event["index"], "received": event["event_time"]}
        return intelligence._atomic_matches({"event": record, "raw": record["raw"], "projection": project(event, pin["definition"])}, definition)
    parents, records = [], {}
    base = []
    for selector in definition["inputs"]:
        row = db.execute("SELECT * FROM intelligence_policies WHERE tenant=? AND id=?", (actor["tenant"], selector["rule_id"])).fetchone()
        _, parent_definition = intelligence._authority(db, row)
        base.append((row["id"], parent_definition))
    for sample in fixture["events"]:
        event, pin = sample["event"], pins[sample["source_id"]]
        if event["index"] != pin["index"]:
            raise ValueError("Correlation fixture source/index contract mismatch")
        record = {**event, "index_name": event["index"], "received": event["event_time"]}
        records[event["event_id"]] = record
        context = {"event": record, "raw": record["raw"], "projection": project(event, pin["definition"])}
        for rule_id, parent_definition in base:
            if intelligence._atomic_matches(context, parent_definition):
                parents.append({"id": rule_id + ":" + event["event_id"], "rule_id": rule_id, "kind": "atomic", "event_ids": [event["event_id"]]})
    entries = native_correlations.entries(definition, parents, records)
    groups = {encode(item["group"]): item["group"] for item in entries}
    for group in groups.values():
        selected = [item for item in entries if item["group"] == group]
        for end in {item["time"] for item in selected}:
            if native_correlations.evaluate(definition, [item for item in selected if end - definition["window"] <= item["time"] <= end]):
                return True
    return False


def validate(store, who, identifier, expected_revision):

    with principal.transaction(store, who, EDIT) as (db, actor):
        row, body = _row(db, actor, identifier, expected_revision)
        if row["state"] not in {"converted", "validated", "validation_failed"}:
            raise ConflictError(
                "Validate the converted draft revision before independent review"
            )
        converted = _converted(db, actor, row, body)
    started, assertions = time.monotonic(), []
    pins = {pin["source_id"]: pin for pin in body["source_pins"]}
    for fixture in body["payload"]["fixtures"]:
        if time.monotonic() - started > 5:
            raise ValueError("Sigma fixture validation exceeded five seconds")
        with principal.transaction(store, who, EDIT) as (db, current):
            if current != actor:
                raise PermissionError("Fixture validation authority changed")
            observed = _fixture_observed(db, current, converted, fixture, pins)
        assertions.append(
            {
                "name": fixture["name"],
                "expected": fixture["expect"],
                "observed": observed,
                "passed": observed == fixture["expect"],
            }
        )
    result = {
        "revision": row["revision"],
        "converted_sha256": body["converted_sha256"],
        "fixtures_digest": release_manifest.digest(body["payload"]["fixtures"]),
        "assertions": assertions,
        "passed": all(item["passed"] for item in assertions),
        "fixture_only": True,
        "native_definition_digest": converted["native_definition_digest"],
        "tested_by": actor["name"],
        "tested_scope": actor["allowed_indexes"],
        "tested_at": time.time(),
    }
    result["digest"] = release_manifest.digest(result)
    with principal.transaction(store, who, EDIT, write=True) as (db, current):
        fresh, saved = _row(db, current, identifier, expected_revision)
        if (
            current != actor
            or fresh["state"] not in {"converted", "validated", "validation_failed"}
            or saved.get("converted_sha256") != body["converted_sha256"]
        ):
            raise ConflictError(
                "Sigma authority or conversion changed during fixture validation"
            )
        _converted(db, current, fresh, saved)
        saved["validation"] = result
        saved.pop("review", None)
        _record(
            store,
            db,
            current,
            fresh,
            saved,
            "validated" if result["passed"] else "validation_failed",
            "validate",
        )
    return get(store, who, identifier)


def _validated(db, actor, row, body, *, require_parser=True):
    converted = _converted(db, actor, row, body, require_parser=require_parser)
    result = body.get("validation", {})
    if (
        not isinstance(result, dict)
        or result.get("passed") is not True
        or result.get("revision") != row["revision"]
        or result.get("converted_sha256") != body["converted_sha256"]
    ):
        raise ConflictError(
            "Passing native fixtures for this exact Sigma conversion are required"
        )
    if (
        result.get("digest")
        != release_manifest.digest(
            {key: value for key, value in result.items() if key != "digest"}
        )
        or result.get("fixtures_digest")
        != release_manifest.digest(body["payload"]["fixtures"])
        or result.get("native_definition_digest")
        != converted["native_definition_digest"]
    ):
        raise ConflictError("Sigma validation evidence changed")
    return result


def review(store, who, identifier, data):
    _fields(data, {"expected_revision", "approve", "reason"})
    if type(data["approve"]) is not bool:
        raise ValueError("Boolean review decision required")
    reason = _text(data["reason"], "review reason", 2000)
    with principal.transaction(store, who, EDIT, write=True) as (db, actor):
        row, body = _row(db, actor, identifier, data["expected_revision"])
        if row["state"] != "validated":
            raise ConflictError(
                "Only this validated draft revision may be independently reviewed"
            )
        validation = _validated(db, actor, row, body)
        if actor["name"] in {row["owner"], row["editor"]}:
            raise PermissionError(
                "An independent current reviewer other than import owner/editor is required"
            )
        result = {
            "revision": row["revision"],
            "reviewer": actor["name"],
            "reviewer_scope": actor["allowed_indexes"],
            "approve": data["approve"],
            "reason": reason,
            "converted_sha256": body["converted_sha256"],
            "validation_digest": validation["digest"],
            "reviewed_at": time.time(),
        }
        result["digest"] = release_manifest.digest(result)
        body["review"] = result
        _record(
            store,
            db,
            actor,
            row,
            body,
            "approved" if data["approve"] else "rejected",
            "review",
        )
    return get(store, who, identifier)


def _approved(db, actor, row, body, *, require_parser=True):
    validation = _validated(db, actor, row, body, require_parser=require_parser)
    review = body.get("review", {})
    if (
        not isinstance(review, dict)
        or review.get("approve") is not True
        or review.get("revision") != row["revision"]
        or review.get("converted_sha256") != body["converted_sha256"]
        or review.get("validation_digest") != validation["digest"]
    ):
        raise ConflictError(
            "Independent approval must pin this exact tested Sigma conversion"
        )
    if review.get("digest") != release_manifest.digest(
        {key: value for key, value in review.items() if key != "digest"}
    ):
        raise ConflictError("Sigma review evidence changed")
    reviewer = principal.current(
        db,
        {"tenant": row["tenant"], "name": review["reviewer"], "role": "analyst"},
        EDIT,
    )
    if reviewer["name"] in {row["owner"], row["editor"]} or not principal.contains(
        reviewer["allowed_indexes"], json.loads(row["indexes"])
    ):
        raise PermissionError(
            "Current independent Sigma reviewer complete scope is unavailable"
        )
    return reviewer


def activate(store, who, identifier, expected_revision):
    with principal.transaction(store, who, EDIT, write=True) as (db, actor):
        row, body = _row(db, actor, identifier, expected_revision)
        if row["state"] != "approved":
            raise ConflictError(
                "Activate only the exact independently approved Sigma revision"
            )
        reviewer = _approved(db, actor, row, body)
        owner = _participants(db, row)["owner"]
        previous = db.execute(
            "SELECT * FROM sigma_import_bindings WHERE tenant=? AND import_id=?",
            (actor["tenant"], identifier),
        ).fetchone()
        native = {
            key: value
            for key, value in body["converted"]["native_policy"].items()
            if key not in {"condition_contract", "correlation_contract", "input_revisions"}
        }
        native["version"] = previous["policy_version"] if previous else 0
        saved = intelligence.activate_imported_in_transaction(
            store,
            db,
            owner,
            reviewer,
            native,
            previous["policy_id"] if previous else None,
        )
        if saved["definition_digest"] != body["converted"]["native_definition_digest"]:
            raise ConflictError("Native evaluator changed since conversion validation")
        db.execute(
            "INSERT INTO sigma_import_bindings VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(policy_id) DO UPDATE SET revision=excluded.revision,policy_version=excluded.policy_version,definition_digest=excluded.definition_digest,validation_digest=excluded.validation_digest,updated=excluded.updated",
            (
                saved["id"],
                actor["tenant"],
                identifier,
                row["revision"],
                saved["version"],
                saved["definition_digest"],
                body["validation"]["digest"],
                time.time(),
            ),
        )
        body.update(
            native_policy_id=saved["id"], native_policy_version=saved["version"]
        )
        _snapshot(db, row, body, saved["id"], saved["version"])
        _record(store, db, actor, row, body, "active", "activate")
    return get(store, who, identifier)


def _validate_binding(db, actor, row, definition, binding):
    imported, body, deployed = _deployment(db, actor, binding["import_id"])
    if (
        imported["revision"] != binding["revision"]
        or deployed["policy_version"] != binding["policy_version"]
        or row["version"] != binding["policy_version"]
        or release_manifest.digest(definition) != binding["definition_digest"]
    ):
        raise ConflictError(
            "Imported native policy is not the exact active tested Sigma revision"
        )
    reviewer = _approved(db, actor, imported, body, require_parser=False)
    expected_approval = release_manifest.digest(
        {
            "id": row["id"],
            "version": row["version"],
            "definition": definition,
            "approver": reviewer["name"],
        }
    )
    if (
        row["state"] != "active"
        or not definition.get("enabled")
        or row["approval_digest"] != expected_approval
    ):
        raise ConflictError("Sigma native approval is unavailable or changed")
    if (
        row["owner"] != imported["owner"]
        or row["approver"] != reviewer["name"]
        or body.get("native_policy_id") != row["id"]
        or body.get("native_policy_version") != row["version"]
        or binding["validation_digest"] != body["validation"]["digest"]
        or binding["definition_digest"] != body["converted"]["native_definition_digest"]
    ):
        raise ConflictError("Sigma native owner/reviewer/definition binding differs")


def retire(store, who, identifier, data):
    _fields(data, {"expected_revision", "reason"})
    reason = _text(data["reason"], "retirement reason", 2000)
    with principal.transaction(store, who, EDIT, write=True) as (db, actor):
        row, body = _row(db, actor, identifier, data["expected_revision"])
        if row["owner"] != actor["name"] and actor["role"] != "admin":
            raise PermissionError(
                "Only owner or administrator may retire a Sigma import"
            )
        _disable_native(db, actor["tenant"], identifier)
        db.execute("UPDATE sigma_import_deployments SET active=0 WHERE tenant=? AND import_id=?", (actor["tenant"], identifier))
        body["retirement"] = {
            "reason": reason,
            "actor": actor["name"],
            "at": time.time(),
        }
        _record(store, db, actor, row, body, "retired", "retire")
    return get(store, who, identifier)


def _deployment_public(db, actor, identifier):
    result = []
    for item in db.execute("SELECT * FROM sigma_import_deployments WHERE tenant=? AND import_id=? ORDER BY policy_version DESC", (actor["tenant"], identifier)):
        custody = json.loads(item["row_snapshot"])
        if not principal.contains(actor["allowed_indexes"], json.loads(custody["indexes"])):
            continue
        body = json.loads(item["body"])
        result.append({"revision": item["revision"], "policy_id": item["policy_id"], "policy_version": item["policy_version"], "active": bool(item["active"]), "created": item["created"], "source_sha256": body["source_sha256"], "native_definition_digest": body["converted"]["native_definition_digest"], "validation_digest": body["validation"]["digest"], "snapshot_digest": item["snapshot_digest"]})
    return {"active_deployment": next((item for item in result if item["active"]), None), "deployments": result, "working_draft_separate": True}


def rollback(store, who, identifier, data):
    _fields(data, {"expected_revision", "expected_policy_version", "target_policy_version", "reason"})
    reason = _text(data["reason"], "rollback reason", 2000)
    if any(type(data[key]) is not int or data[key] < 1 for key in ("expected_policy_version", "target_policy_version")):
        raise ValueError("Exact positive deployment versions required")
    with principal.transaction(store, who, EDIT, write=True) as (db, actor):
        head, _head_body = _row(db, actor, identifier, data["expected_revision"])
        if head["owner"] != actor["name"] and actor["role"] != "admin":
            raise PermissionError("Only owner or administrator may roll back a Sigma deployment")
        current = db.execute("SELECT * FROM sigma_import_bindings WHERE tenant=? AND import_id=?", (actor["tenant"], identifier)).fetchone()
        if not current or current["policy_version"] != data["expected_policy_version"]:
            raise ConflictError("Current Sigma deployment changed")
        _current_row, _current_body, active = _deployment(db, actor, identifier)
        if active["policy_version"] != current["policy_version"]:
            raise ConflictError("Current active Sigma deployment changed")
        old_row, body, target = _deployment(db, actor, identifier, data["target_policy_version"])
        if target["active"]:
            raise ConflictError("Select a previous independently approved deployment")
        # Rollback reuses reviewed native IR, and does not require a parser installation.
        reviewer = _approved(db, actor, old_row, body, require_parser=False)
        owner = _participants(db, old_row)["owner"]
        native = {key: value for key, value in body["converted"]["native_policy"].items() if key not in {"condition_contract", "correlation_contract", "input_revisions"}}
        native["version"] = current["policy_version"]
        saved = intelligence.activate_imported_in_transaction(store, db, owner, reviewer, native, current["policy_id"])
        if saved["definition_digest"] != body["converted"]["native_definition_digest"]:
            raise ConflictError("Rollback parent or native evaluator contract changed; convert a new draft")
        body.update(native_policy_id=saved["id"], native_policy_version=saved["version"])
        db.execute("UPDATE sigma_import_bindings SET revision=?,policy_version=?,definition_digest=?,validation_digest=?,updated=? WHERE tenant=? AND import_id=?", (old_row["revision"], saved["version"], saved["definition_digest"], body["validation"]["digest"], time.time(), actor["tenant"], identifier))
        _snapshot(db, old_row, body, saved["id"], saved["version"])
        store.audit(db, actor["tenant"], actor["name"], "sigma.import.rollback", {"id": identifier, "target_policy_version": target["policy_version"], "policy_version": saved["version"], "revision": old_row["revision"], "reason": reason})
        db.execute("INSERT INTO sigma_import_history(tenant,id,revision,action,actor,body,created) VALUES(?,?,?,?,?,?,?)", (actor["tenant"], identifier, old_row["revision"], "rollback", actor["name"], encode({"target_policy_version": target["policy_version"], "policy_version": saved["version"], "reason": reason}), time.time()))
    return get(store, who, identifier)


def _public(row, body):
    return {
        "id": row["id"],
        "owner": row["owner"],
        "editor": row["editor"],
        "revision": row["revision"],
        "state": row["state"],
        "indexes": json.loads(row["indexes"]),
        "updated": row["updated"],
        "name": body["payload"]["name"],
        "parser_version": body.get("converted", {}).get("parser_version"),
        **body,
    }


def get(store, who, identifier):
    with principal.transaction(store, who) as (db, actor):
        row, body = _row(db, actor, identifier)
        history = [
            {**dict(item), "body": json.loads(item["body"])}
            for item in db.execute(
                "SELECT revision,action,actor,body,created FROM sigma_import_history WHERE tenant=? AND id=? ORDER BY seq",
                (actor["tenant"], identifier),
            )
        ]
        return {**_public(row, body), "history": history, **_deployment_public(db, actor, identifier)}


def listing(store, who):
    with principal.transaction(store, who) as (db, actor):
        return {
            "items": [
                {**_public(row, json.loads(row["body"])), **_deployment_public(db, actor, row["id"])}
                for row in db.execute(
                    "SELECT * FROM sigma_imports WHERE tenant=? ORDER BY updated DESC,id",
                    (actor["tenant"],),
                )
                if principal.contains(
                    actor["allowed_indexes"], json.loads(row["indexes"])
                )
            ]
        }


def _observed_samples(store, who, identifier, expected_revision):
    from . import evidence_scope
    with principal.transaction(store, who, EDIT) as (db, actor):
        row, body = _row(db, actor, identifier, expected_revision)
        _participants(db, row)
        if _pins(db, actor, body["payload"]) != body["source_pins"]:
            raise ConflictError("Observed-schema source contracts changed")
        ids = []
        owners = {}
        for pin in body["source_pins"]:
            for item in db.execute("SELECT event_id FROM source_event_receipts WHERE tenant=? AND source_id=? AND source_version=? AND index_name=? ORDER BY received DESC,event_id LIMIT 16", (actor["tenant"], pin["source_id"], pin["version"], pin["index"])):
                if len(ids) >= 32:
                    break
                ids.append(item["event_id"])
                owners[item["event_id"]] = pin["source_id"]
    samples = []
    for event_id in ids:
        try:
            record = evidence_scope.originals(store, actor, [event_id])[event_id]
            samples.append({"source_id": owners[event_id], "event": {"event_id": record["event_id"], "event_time": record["event_time"], "index": record["index_name"], "host": record["host"], "source": record["source"], "sourcetype": record["sourcetype"], "severity": record["severity"], "message": record["message"], "raw": record["raw"]}})
        except KeyError:
            continue  # Expired telemetry is not a schema assertion.
    with principal.transaction(store, who, EDIT) as (db, current):
        fresh, saved = _row(db, current, row["id"], expected_revision)
        if current != actor or saved["source_pins"] != body["source_pins"] or _pins(db, current, saved["payload"]) != saved["source_pins"]:
            raise ConflictError("Observed-schema authority changed during inspection")
    return dict(fresh), saved, samples


def mapping_suggestions(store, who, identifier, expected_revision):
    import re
    row, body, samples = _observed_samples(store, who, identifier, expected_revision)
    schema = {}
    def visit(value, path, depth=0):
        if depth > 8 or len(schema) >= 256:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                if isinstance(key, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", key) and key not in {"label", "ground_truth", "scenario_label", "expected_detected"}:
                    visit(child, path + "." + key, depth + 1)
        elif type(value) in (str, int, float, bool) or value is None:
            entry = schema.setdefault(path, {"types": set(), "observations": 0})
            entry["types"].add(type(value).__name__)
            entry["observations"] += 1
    for sample in samples:
        for key in ("host", "source", "sourcetype", "severity", "message", "event_time"):
            visit(sample["event"][key], key)
        visit(sample["event"]["raw"], "raw")
    observed = [{"path": path, "types": sorted(value["types"]), "observations": value["observations"]} for path, value in sorted(schema.items())]
    decoded = _decode(body["payload"]["source_text"], body["payload"]["format"])
    fields = set(body["payload"]["field_mapping"])
    def sigma_fields(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(key, str):
                    fields.add(key.split("|")[0])
        elif isinstance(node, list):
            for value in node:
                sigma_fields(value)
    for name, selection in decoded.get("detection", {}).items():
        if name != "condition":
            sigma_fields(selection)
    aliases = {"CommandLine": ["command_line", "command", "process.command_line", "cmdline"], "Image": ["process_path", "image", "executable", "process.executable"], "User": ["user", "username", "user_name"], "TargetUserName": ["target_user", "user", "username"], "EventID": ["EventID", "event_id", "eventid"], "SourceIp": ["src_ip", "source_ip", "source.ip"], "DestinationIp": ["dst_ip", "dest_ip", "destination.ip"], "ProcessId": ["process_id", "pid"], "ObjectName": ["object", "target", "file_path"], "Computer": ["host"]}
    compact = lambda value: re.sub(r"[^a-z0-9]", "", value.lower())
    changes = {}
    for field in sorted(fields):
        current = body["payload"]["field_mapping"].get(field)
        if current in schema:
            continue
        names = aliases.get(field, []) + [field]
        exact = [path for path in schema if compact(path.split(".")[-1]) == compact(field)]
        choices = exact or [path for path in schema if any(compact(path.removeprefix("raw.")) == compact(name) or compact(path.split(".")[-1]) == compact(name) for name in names)]
        if len(choices) == 1:
            changes[field] = choices[0]
    result = {"revision": row["revision"], "state": "proposal" if changes else "manual_required", "changes": changes, "observed_schema": observed, "sample_count": len(samples), "source_contract_digest": release_manifest.digest(body["source_pins"]), "automatic_apply": False, "explicit_approval_required": True, "scope": "current-authorized-retained-source-receipts-only"}
    result["proposal_digest"] = release_manifest.digest(result)
    return result


def apply_mapping(store, who, identifier, data):
    _fields(data, {"expected_revision", "proposal_digest", "approve"})
    if data["approve"] is not True:
        raise ValueError("Explicit mapping proposal approval required")
    proposal = mapping_suggestions(store, who, identifier, data["expected_revision"])
    if proposal["proposal_digest"] != data["proposal_digest"] or not proposal["changes"]:
        raise ConflictError("Mapping observations/proposal changed or require manual mapping")
    value = get(store, who, identifier)
    payload = {**value["payload"], "expected_revision": data["expected_revision"], "field_mapping": {**value["payload"]["field_mapping"], **proposal["changes"]}}
    return save(store, who, payload, identifier, mapping_approval={"proposal_digest": proposal["proposal_digest"], "source_contract_digest": proposal["source_contract_digest"], "changes": proposal["changes"], "sample_count": proposal["sample_count"]})


def fixture_candidates(store, who, identifier, expected_revision):
    import copy
    row, body, samples = _observed_samples(store, who, identifier, expected_revision)
    with principal.transaction(store, who, EDIT) as (db, actor):
        fresh, saved = _row(db, actor, identifier, expected_revision)
        converted = _converted(db, actor, fresh, saved)
        pins = {pin["source_id"]: pin for pin in saved["source_pins"]}
        supplied = copy.deepcopy(body["payload"]["fixtures"])
        proposed = list(supplied)
        if converted["native_policy"]["kind"] == "atomic":
            proposed.extend({"name": "observed-" + str(index), **sample, "expect": False} for index, sample in enumerate(samples))
            for index, sample in enumerate(supplied[:8]):
                item = copy.deepcopy(sample)
                item["event"]["raw"] = {}
                item["name"] = "cleared-" + str(index)
                proposed.append(item)
                for key, value in sample["event"]["raw"].items():
                    if type(value) not in (str, bool, int, float):
                        continue
                    item = copy.deepcopy(sample)
                    item["event"]["raw"][key] = "harmless-fixture-value" if isinstance(value, str) else not value if type(value) is bool else 0
                    item["name"] = "mutated-" + str(len(proposed))
                    proposed.append(item)
        else:
            for index, sample in enumerate(supplied[:8]):
                item = copy.deepcopy(sample)
                item["name"] = "shortened-" + str(index)
                item["events"] = item["events"][:1]
                proposed.append(item)
                item = copy.deepcopy(sample)
                item["name"] = "cleared-" + str(index)
                for event in item["events"]:
                    event["event"]["raw"] = {}
                proposed.append(item)
        found = {True: [], False: []}
        started = time.monotonic()
        for index, candidate in enumerate(proposed[:96]):
            if time.monotonic() - started > 5:
                break
            value = copy.deepcopy(candidate)
            value["name"] = "generated-" + str(index)
            events = value.get("events", [{"event": value.get("event")}])
            for offset, event in enumerate(events):
                event["event"]["event_id"] = "sigma-generated-" + str(index) + "-" + str(offset)
            observed = _fixture_observed(db, actor, converted, value, pins)
            value["expect"] = observed
            if len(found[observed]) < 4:
                found[observed].append(value)
        candidates = found[True] + found[False]
        return {"revision": row["revision"], "state": "candidates" if all(found.values()) else "manual_required", "fixtures": candidates if all(found.values()) else [], "positive_count": len(found[True]), "negative_count": len(found[False]), "native_definition_digest": converted["native_definition_digest"], "actual_native_validator": True, "fixture_only": True, "automatic_save": False, "requires_new_revision_and_independent_review": True, "reason": None if all(found.values()) else "Could not prove both classes from bounded candidates; prepare manual fixtures"}


def status():
    from . import native_predicates

    return {
        "backend": sigma_backend.status(),
        "native_ir_version": 1,
        "condition_contract": native_predicates.CONTRACT_DIGEST,
        "workflow": ["imported", "converted", "validated", "approved", "active"],
        "formats": ["json", "yaml"],
        "source_registry_url": "/api/v2/sources",
        "native_execution": True,
        "independent_review_required": True,
        "automatic_endpoint_authorization": False,
        "separate_active_deployment": True,
        "atomic_deploy_and_rollback": True,
        "correlation_types": ["event_count", "value_count", "temporal", "temporal_ordered"],
        "unsupported_correlation": ["absence_or_upper_bound_counts", "chaining", "extended_conditions", "metric_aggregation", "legacy_pipe_aggregation"],
        "limits": {
            "source_bytes": MAX_SOURCE_BYTES,
            "payload_bytes": MAX_PAYLOAD_BYTES,
            "fixtures": 32,
            "positive_and_negative_required": True,
            "source_contracts": 8,
            "native_nodes": 512,
            "native_depth": 20,
            "regex_characters": 512,
            "fixture_seconds": 5,
        },
    }
