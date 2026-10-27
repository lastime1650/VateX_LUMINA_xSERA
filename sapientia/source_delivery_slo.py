"""Receipt-backed delivery coverage; missing capture is never invented as zero.

Sequence gaps use explicitly configured source sequence/epoch fields. They are
provisional missing sequence numbers, recover when late originals arrive, and
remain distinct from independently unverified sensor-reported drop counters.
"""

import json
import re
import time

from . import migrations, principal, source_registry
from .storage import ConflictError, encode


def initialize(store):
    migrations.apply_store(
        store,
        "source_delivery_slo",
        [
            "CREATE TABLE IF NOT EXISTS source_delivery_policies(source_id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,revision INTEGER NOT NULL,definition TEXT NOT NULL,stats TEXT NOT NULL,updated REAL NOT NULL)",
        ],
    )


def _path(value):
    return (
        value is None
        or isinstance(value, str)
        and re.fullmatch(r"raw(?:\.[A-Za-z0-9_@-]{1,80}){1,8}", value)
    )


def save(store, who, identifier, data):
    fields = {
        "expected_revision",
        "source_version",
        "sequence_path",
        "epoch_path",
        "max_silence_seconds",
        "max_gap",
        "max_reported_drop",
    }
    if (
        not isinstance(data, dict)
        or set(data) != fields
        or any(
            type(data[k]) is not int or data[k] < 0
            for k in (
                "expected_revision",
                "source_version",
                "max_gap",
                "max_reported_drop",
            )
        )
        or type(data["max_silence_seconds"]) is not int
        or not 1 <= data["max_silence_seconds"] <= 86400
    ):
        raise ValueError("Exact bounded delivery SLO fields required")
    if (
        not _path(data["sequence_path"])
        or not _path(data["epoch_path"])
        or bool(data["sequence_path"]) != bool(data["epoch_path"])
    ):
        raise ValueError("Sequence and epoch require explicit paired raw scalar paths")
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        source = source_registry.visible(db, actor, identifier)
        if source["state"] != "active" or source["version"] != data["source_version"]:
            raise ConflictError("Source authority changed")
        old = db.execute(
            "SELECT * FROM source_delivery_policies WHERE source_id=?", (identifier,)
        ).fetchone()
        if (old["revision"] if old else 0) != data["expected_revision"]:
            raise ConflictError("Delivery policy revision changed")
        revision = data["expected_revision"] + 1
        definition = {k: v for k, v in data.items() if k != "expected_revision"}
        stats = {
            "observed_unique": 0,
            "sequence_observed": 0,
            "missing_sequence": 0,
            "invalid_sequence": 0,
            "duplicate_sequence": 0,
            "out_of_order": 0,
            "coverage_exhausted": False,
            "epochs": {},
        }
        db.execute(
            "INSERT INTO source_delivery_policies VALUES(?,?,?,?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET owner=excluded.owner,revision=excluded.revision,definition=excluded.definition,stats=excluded.stats,updated=excluded.updated",
            (
                identifier,
                actor["tenant"],
                actor["name"],
                revision,
                encode(definition),
                encode(stats),
                time.time(),
            ),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "source.delivery.policy",
            {"source_id": identifier, "revision": revision},
        )
        return {
            "source_id": identifier,
            "revision": revision,
            "definition": definition,
            "measurement_starts_now": True,
        }


def _field(record, path):
    value = record
    for name in path.split("."):
        if not isinstance(value, dict) or name not in value:
            return None
        value = value[name]
    return value


def observe_in_transaction(db, source, records, new_ids, received):
    """Called only inside receipt admission TX; duplicate retries do not count."""
    row = db.execute(
        "SELECT * FROM source_delivery_policies WHERE source_id=? AND tenant=?",
        (source["id"], source["tenant"]),
    ).fetchone()
    if not row:
        return
    definition, stats = json.loads(row["definition"]), json.loads(row["stats"])
    if definition["source_version"] != source["version"]:
        return
    seen = set()
    for record in records:
        identifier = record["event_id"]
        if identifier not in new_ids or identifier in seen:
            continue
        seen.add(identifier)
        stats["observed_unique"] += 1
        if not definition["sequence_path"]:
            continue
        sequence, epoch = (
            _field(record, definition["sequence_path"]),
            _field(record, definition["epoch_path"]),
        )
        if sequence is None or epoch is None:
            stats["missing_sequence"] += 1
            continue
        if (
            type(sequence) is not int
            or not 0 <= sequence <= 2**53
            or not isinstance(epoch, str)
            or not 1 <= len(epoch) <= 128
        ):
            stats["invalid_sequence"] += 1
            continue
        if epoch not in stats["epochs"]:
            if len(stats["epochs"]) >= 16:
                stats["coverage_exhausted"] = True
                continue
            stats["epochs"][epoch] = {"first": sequence, "high": sequence, "gaps": []}
            stats["sequence_observed"] += 1
            continue
        state = stats["epochs"][epoch]
        if sequence > state["high"]:
            if sequence > state["high"] + 1:
                if len(state["gaps"]) >= 128:
                    stats["coverage_exhausted"] = True
                    continue
                state["gaps"].append([state["high"] + 1, sequence - 1])
            state["high"] = sequence
            stats["sequence_observed"] += 1
        else:
            stats["out_of_order"] += 1
            for position, (low, high) in enumerate(state["gaps"]):
                if low <= sequence <= high:
                    replacement = ([[low, sequence - 1]] if low < sequence else []) + (
                        [[sequence + 1, high]] if sequence < high else []
                    )
                    if len(state["gaps"]) + len(replacement) - 1 > 128:
                        stats["coverage_exhausted"] = True
                        break
                    state["gaps"][position : position + 1] = replacement
                    stats["sequence_observed"] += 1
                    break
            else:
                if sequence < state["first"]:
                    # Initial boundary is unknown; earlier records extend it
                    # without claiming a missing prefix before observation.
                    if state["first"] - sequence > 1:
                        if len(state["gaps"]) >= 128:
                            stats["coverage_exhausted"] = True
                            continue
                        state["gaps"].append([sequence + 1, state["first"] - 1])
                    state["first"] = sequence
                    stats["sequence_observed"] += 1
                else:
                    stats["duplicate_sequence"] += 1
    db.execute(
        "UPDATE source_delivery_policies SET stats=?,updated=? WHERE source_id=?",
        (encode(stats), received, source["id"]),
    )


def listing(store, who, now=None):
    now = time.time() if now is None else now
    with principal.transaction(store, who) as (db, actor):
        items = []
        for source in db.execute(
            "SELECT * FROM source_registry WHERE tenant=? ORDER BY id",
            (actor["tenant"],),
        ).fetchall():
            if not principal.contains(actor["allowed_indexes"], [source["index_name"]]):
                continue
            source_registry.visible(db, actor, source["id"])
            receipt = db.execute(
                "SELECT count(*),max(received) FROM source_event_receipts WHERE tenant=? AND source_id=?",
                (actor["tenant"], source["id"]),
            ).fetchone()
            row = db.execute(
                "SELECT * FROM source_delivery_policies WHERE source_id=?",
                (source["id"],),
            ).fetchone()
            definition = json.loads(row["definition"]) if row else None
            stats = json.loads(row["stats"]) if row else None
            gaps = (
                sum(
                    high - low + 1
                    for epoch in stats["epochs"].values()
                    for low, high in epoch["gaps"]
                )
                if stats
                else None
            )
            reports = db.execute(
                "SELECT h.body,h.created FROM analysis_sensor_health h JOIN analysis_sensor_sources s ON s.id=h.binding_id AND s.tenant=h.tenant WHERE s.source_id=? AND h.tenant=? ORDER BY h.id DESC LIMIT 1",
                (source["id"], actor["tenant"]),
            ).fetchone()
            reported = (
                {**json.loads(reports["body"]), "reported_at": reports["created"]}
                if reports
                else None
            )
            reasons = []
            if not row:
                reasons.append("slo_not_configured")
            elif definition["source_version"] != source["version"]:
                reasons.append("source_contract_changed")
            else:
                if (
                    receipt[1] is None
                    or now - receipt[1] > definition["max_silence_seconds"]
                ):
                    reasons.append("source_silence")
                if (
                    stats["coverage_exhausted"]
                    or stats["invalid_sequence"]
                    or stats["missing_sequence"]
                ):
                    reasons.append("sequence_coverage_incomplete")
                if gaps > definition["max_gap"]:
                    reasons.append("sequence_gap_budget_exceeded")
                if (
                    reported
                    and reported.get("dropped", 0) > definition["max_reported_drop"]
                ):
                    reasons.append("reported_drop_budget_exceeded")
            items.append(
                {
                    "source_id": source["id"],
                    "source_version": source["version"],
                    "source_state": source["state"],
                    "index": source["index_name"],
                    "server_receipts": receipt[0],
                    "last_received": receipt[1],
                    "revision": row["revision"] if row else 0,
                    "definition": definition,
                    "counters": stats,
                    "provisional_sequence_gaps": gaps
                    if definition and definition["sequence_path"]
                    else None,
                    "sensor_reported": reported,
                    "sequence_measurement": "explicit_authenticated_source_field"
                    if definition and definition["sequence_path"]
                    else "unavailable_no_sequence_contract",
                    "pre_capture_loss": "unavailable_not_observable",
                    "state": "degraded" if reasons else "within_configured_budget",
                    "reasons": reasons,
                }
            )
        return {
            "items": items,
            "total": len(items),
            "drop_counters_independently_verified": False,
        }
