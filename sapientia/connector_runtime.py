"""Receipt-before-checkpoint product intake; no arbitrary URL or secret execution."""

import json
import time

from . import fortigate, migrations, pipeline, principal, source_registry, xdr_bridge
from .storage import ConflictError, encode

FORMATS = {"fortigate": "fortigate", "cisco_asa": "cisco_asa", "windows": "agent", "linux": "agent", "cloudtrail": "cloudtrail", "json": "json",
           "entra_signin": "entra_signin", "m365_audit": "m365_audit",
           **{name: name for name in ("suricata", "zeek", "falco", "tetragon", "osquery")}}


def initialize(store):
    migrations.apply_store(store, "connectors", [
        "CREATE TABLE IF NOT EXISTS connector_checkpoints(source_id TEXT PRIMARY KEY,tenant TEXT NOT NULL,cursor TEXT NOT NULL,version INTEGER NOT NULL,updated REAL NOT NULL)",
        "CREATE TABLE IF NOT EXISTS source_event_receipts(tenant TEXT NOT NULL,event_id TEXT NOT NULL,source_id TEXT NOT NULL,source_version INTEGER NOT NULL,index_name TEXT NOT NULL,receipt_digest TEXT NOT NULL,received REAL NOT NULL,PRIMARY KEY(tenant,event_id))"])
    migrations.apply_store(store, "connectors", ["ALTER TABLE source_event_receipts ADD COLUMN source_definition TEXT"], version=2)


def decode(item, source):
    if source["product"] in {"entra_signin", "m365_audit"}:
        from . import enterprise_adapters
        return enterprise_adapters.decode(item, source)
    if source["product"] in {"suricata", "zeek", "falco", "tetragon", "osquery"}:
        from . import sensor_adapters
        return sensor_adapters.decode(item, source)
    if source["product"] == "fortigate":
        result = fortigate.envelope(item, source["index_name"])
        if result["raw"]["fortigate"]["devid"] != source["account"]:
            raise PermissionError("FortiGate device differs from registered authority")
        return result
    if source["product"] == "cisco_asa":
        from .collector_plugins.cisco_asa import envelope
        return envelope(item, source["index_name"], source["account"])
    if source["product"] in {"windows", "linux"}:
        return xdr_bridge.parse_event(item, "agent", source["index_name"], expected_host=source["account"])
    if source["product"] == "cloudtrail":
        from .collector_plugins.aws_cloudtrail import envelope
        return envelope(item, source["index_name"], source["account"])
    if source["product"] == "json":
        from .storage import normalize
        if item.get("index", source["index_name"]) != source["index_name"]:
            raise PermissionError("Source index is server-bound")
        result=normalize({**item, "index": source["index_name"]})
        from . import security_schema

        security_schema.project(result,dict(source))
        return result
    raise ValueError("Product parser is unavailable")


def intake(store, who, identifier, data):
    if not isinstance(data, dict) or set(data) != {"version", "events", "cursor", "checkpoint_version"} or not isinstance(data["events"], list) or not 1 <= len(data["events"]) <= 1000 or type(data["version"]) is not int or type(data["checkpoint_version"]) is not int or data["checkpoint_version"] < 0:
        raise ValueError("Bounded source version/events/cursor required")
    if not isinstance(data["cursor"], str) or not 1 <= len(data["cursor"]) <= 1024:
        raise ValueError("Bounded source cursor required")
    with store.write_lock:
        with principal.transaction(store, who, ("admin", "analyst")) as (db, actor):
            source = source_registry.visible(db, actor, identifier)
            if source["state"] != "active" or source["version"] != data["version"]:
                raise ConflictError("Source version/authority changed")
            source = dict(source)
            records = [decode(item, source) for item in data["events"]]
            policies = pipeline.for_ingest(db, actor["tenant"])
            for record in records:
                routed, _ = pipeline.apply(record, policies.get(record["source"]))
                if routed["index"] != source["index_name"]:
                    raise PermissionError("Source parser route differs from authority")

        def authorize(db):
            current = principal.current(db, actor, ("admin", "analyst"))
            fresh = source_registry.visible(db, current, identifier)
            if fresh["state"] != "active" or fresh["version"] != source["version"]:
                raise PermissionError("Source revoked during admission")
            return [fresh["index_name"]]

        def admitted(db, durable_records, incoming_ids, received):
            new_ids = {r[1] for r in durable_records}
            for event_id in set(incoming_ids):
                receipt = db.execute("SELECT * FROM receipts WHERE tenant=? AND event_id=?", (actor["tenant"], event_id)).fetchone()
                old = db.execute("SELECT * FROM source_event_receipts WHERE tenant=? AND event_id=?", (actor["tenant"], event_id)).fetchone()
                if not receipt:
                    raise PermissionError("Source requires an admission receipt")
                if old:
                    if old["source_id"] != identifier or old["receipt_digest"] != receipt["digest"]:
                        raise ConflictError("Event belongs to a different source")
                elif event_id not in new_ids:
                    raise PermissionError("Existing generic event cannot acquire source authority")
                else:
                    authority = {"id": identifier, "version": source["version"], **{k: source[k] for k in ("product", "account", "realm")}}
                    db.execute("INSERT INTO source_event_receipts VALUES(?,?,?,?,?,?,?,?)", (actor["tenant"], event_id, identifier, source["version"], source["index_name"], receipt["digest"], receipt["received"], encode(authority)))
            from . import source_delivery_slo
            source_delivery_slo.observe_in_transaction(db, source, [json.loads(row[2]) for row in durable_records], new_ids, received)
            old_cursor = db.execute("SELECT version FROM connector_checkpoints WHERE source_id=?", (identifier,)).fetchone()
            current_cursor = db.execute("SELECT cursor FROM connector_checkpoints WHERE source_id=?", (identifier,)).fetchone()
            current_version = old_cursor[0] if old_cursor else 0
            if current_cursor and current_cursor[0] == data["cursor"]:
                if new_ids:
                    raise ConflictError("Same checkpoint cursor contains new source records")
                return
            if current_version != data["checkpoint_version"]:
                raise ConflictError("Connector checkpoint changed; do not regress cursor")
            version = old_cursor[0] + 1 if old_cursor else 1
            db.execute("INSERT INTO connector_checkpoints VALUES(?,?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET cursor=excluded.cursor,version=excluded.version,updated=excluded.updated", (identifier, actor["tenant"], data["cursor"], version, received))

        authorize.on_admitted = admitted
        result = store.ingest(actor["tenant"], records, actor["name"], [source["index_name"]], authorize)
        with store.control() as db:
            checkpoint = db.execute("SELECT version FROM connector_checkpoints WHERE source_id=?", (identifier,)).fetchone()[0]
        return {**result, "cursor_committed": True, "checkpoint_version": checkpoint, "source_id": identifier, "event_ids": [r["event_id"] for r in records], "native_capture_proven": False}
