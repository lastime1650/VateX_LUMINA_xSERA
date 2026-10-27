"""Reviewed CPU GRU models over immutable, source-scoped ordered originals.

Labels belong to an explicitly reviewed manifest. Feature extraction reads only
persisted original telemetry. Calibration and independent holdout are separate;
forward scores are uncalibrated model outputs, never response authority.
"""
import hashlib
import json
import math
import time
import uuid

from . import cpu_ml, cpu_ml_runtime, evidence_scope, migrations, principal
from . import cpu_sequence_features as features
from .cpu_model_memo import (
    authority_memo as authority_memo,  # noqa: PLC0414 - public transaction helper re-export.
)
from .cpu_model_memo import content_model, decoded_model
from .entities import exact_indexes
from .storage import CapacityError, ConflictError, encode

EDITORS = ("admin", "analyst")
MODEL_SCHEMA = "xsera.cpu-gru-sequence.v1"
FEATURE_SCHEMA = features.FEATURE_SCHEMA
FEATURES = features.FEATURES
FEATURE_CONTRACT_DIGEST = features.FEATURE_CONTRACT_DIGEST
MAX_SCENARIOS = 4096
ARCHITECTURE = {"type": "gru", "input": len(FEATURES), "hidden": 24, "layers": 1, "bidirectional": False, "max_steps": 32}


def _digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def initialize(store):
    migrations.apply_store(store, "cpu_sequence", [
        "CREATE TABLE IF NOT EXISTS cpu_sequence_models(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,name TEXT NOT NULL,revision INTEGER NOT NULL,indexes TEXT NOT NULL,created REAL NOT NULL,definition TEXT NOT NULL,snapshot TEXT NOT NULL,digest TEXT NOT NULL,metrics TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS cpu_sequence_models_scope ON cpu_sequence_models(tenant,name,revision)",
        "CREATE TABLE IF NOT EXISTS cpu_sequence_reviews(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,model_id TEXT NOT NULL,reviewer TEXT NOT NULL,at REAL NOT NULL,notes TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS cpu_sequence_active(tenant TEXT NOT NULL,name TEXT NOT NULL,model_id TEXT NOT NULL,review_id TEXT NOT NULL,updated REAL NOT NULL,PRIMARY KEY(tenant,name))",
        "CREATE TABLE IF NOT EXISTS cpu_sequence_runs(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,model_id TEXT NOT NULL,indexes TEXT NOT NULL,created REAL NOT NULL,shadow INTEGER NOT NULL,result TEXT NOT NULL)",
        "CREATE INDEX IF NOT EXISTS cpu_sequence_runs_scope ON cpu_sequence_runs(tenant,model_id,created)",
        "CREATE TABLE IF NOT EXISTS cpu_sequence_evaluations(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,model_id TEXT NOT NULL,indexes TEXT NOT NULL,created REAL NOT NULL,holdout_digest TEXT NOT NULL,result TEXT NOT NULL)",
    ])
    from . import cpu_ml_lifecycle
    cpu_ml_lifecycle.initialize(store)


def _source_context(db, actor, source_id, owner_cache=None):
    row = db.execute("SELECT * FROM source_registry WHERE tenant=? AND id=?", (actor["tenant"], source_id)).fetchone()
    if not row or row["state"] != "active" or not principal.contains(actor["allowed_indexes"], [row["index_name"]]):
        raise PermissionError("Current authenticated sequence source unavailable")
    owner_cache = {} if owner_cache is None else owner_cache
    owner = owner_cache.get(row["owner"])
    if owner is None:
        owner = owner_cache[row["owner"]] = principal.current(db, {"name": row["owner"], "tenant": actor["tenant"], "role": "analyst"}, EDITORS)
    if not principal.contains(owner["allowed_indexes"], [row["index_name"]]):
        raise PermissionError("Sequence source owner scope revoked")
    return {key: row[key] for key in ("id", "version", "index_name", "product", "account", "realm", "owner")}


def _sources_current(db, actor, expected):
    wanted = {}
    for context in expected:
        if context["id"] in wanted and wanted[context["id"]] != context:
            raise ConflictError("Inconsistent frozen source authority")
        wanted[context["id"]] = context
    identifiers = list(wanted)
    owners = {}
    for start in range(0, len(identifiers), 1000):
        found = {row["id"]: row for row in db.execute(
            "SELECT * FROM source_registry WHERE tenant=? AND id IN (SELECT value FROM json_each(?))",
            (actor["tenant"], encode(identifiers[start:start+1000])))}
        if set(found) != set(identifiers[start:start+1000]):
            raise PermissionError("Current authenticated sequence source unavailable")
        for identifier, row in found.items():
            if row["state"] != "active" or not principal.contains(actor["allowed_indexes"], [row["index_name"]]):
                raise PermissionError("Current authenticated sequence source unavailable")
            if row["owner"] not in owners:
                owners[row["owner"]] = principal.current(db, {"name": row["owner"], "tenant": actor["tenant"], "role": "analyst"}, EDITORS)
            if not principal.contains(owners[row["owner"]]["allowed_indexes"], [row["index_name"]]):
                raise PermissionError("Sequence source owner scope revoked")
            current = {key: row[key] for key in ("id", "version", "index_name", "product", "account", "realm", "owner")}
            if current != wanted[identifier]:
                raise ConflictError("Sequence source authority changed; candidate review required")


def _fetch(store, actor, identifiers, indexes):
    if not principal.contains(actor["allowed_indexes"], indexes):
        raise PermissionError("Sequence source scope exceeds current permissions")
    rows = {}
    contexts = {}
    owners = {}
    for start in range(0, len(identifiers), 128):
        # Original raw JSON can be several KiB per event. Preserve the Store's
        # 2-MiB query result boundary instead of weakening it for model input.
        ids = identifiers[start:start+128]
        found = store.analytics_query(
            "SELECT event_id,event_time,host,source,sourcetype,index_name,raw,received FROM events_all "
            "WHERE tenant=? AND index_name IN (SELECT unnest(?)) AND event_id IN (SELECT unnest(?)) ORDER BY event_id",
            [actor["tenant"], indexes, ids], max_rows=len(ids), timeout=10)["rows"]
        if {row["event_id"] for row in found} != set(ids):
            raise KeyError("Sequence original unavailable in declared index scope")
        with store.control() as db:
            if principal.current(db, actor) != actor:
                raise PermissionError("Sequence source permissions changed")
            receipts = {row["event_id"]: dict(row) for row in db.execute(
                "SELECT event_id,digest,received FROM receipts WHERE tenant=? AND event_id IN (SELECT value FROM json_each(?))", (actor["tenant"], encode(ids)))}
            source_proofs = {row["event_id"]: dict(row) for row in db.execute(
                "SELECT * FROM source_event_receipts WHERE tenant=? AND event_id IN (SELECT value FROM json_each(?))", (actor["tenant"], encode(ids)))}
            for row in found:
                receipt, proof = receipts.get(row["event_id"]), source_proofs.get(row["event_id"])
                if not receipt or receipt["received"] != row["received"] or not proof or receipt["digest"] != proof["receipt_digest"]:
                    raise ConflictError("Authenticated sequence receipt unavailable or changed")
                context = contexts.get(proof["source_id"])
                if context is None:
                    context = contexts[proof["source_id"]] = _source_context(db, actor, proof["source_id"], owners)
                authority = json.loads(proof["source_definition"])
                if context["version"] != authority.get("version") or context["index_name"] != row["index_name"]:
                    raise ConflictError("Sequence source was revised; original context is stale")
                original_digest = _digest(row)
                row = dict(row)
                row["raw"] = json.loads(row["raw"]) if isinstance(row["raw"], str) else row["raw"]
                row.update(source_context=context, admission_digest=receipt["digest"], record_digest=original_digest)
                rows[row["event_id"]] = row
    return rows, contexts


def _window(actor, identifiers, rows):
    selected = [rows[item] for item in identifiers]
    vectors = features.vectors(selected)
    identities, hosts = set(), set()
    for row in selected:
        context = row["source_context"]
        host_id = features.get(row["raw"], "xdr.data.host.id")
        boot_id = features.get(row["raw"], "xdr.data.host.boot_id")
        if not isinstance(host_id, str) or not host_id or not isinstance(boot_id, str) or not boot_id:
            raise ValueError("Sequence requires an explicit source-reported host id and boot id")
        from .identity_resolver import identity_text
        if not identity_text(host_id) or not identity_text(boot_id):
            raise ValueError("Masked or invalid source-reported host/boot identities cannot define a sequence")
        host_id, boot_id = evidence_scope.text(host_id, "host identity"), evidence_scope.text(boot_id, "boot identity")
        user = features.get(row["raw"], "xdr.data.user.id")
        session = features.get(row["raw"], "xdr.data.user.session_id")
        if session is None:
            session = features.get(row["raw"], "xdr.data.authentication.session_id")
        container = features.get(row["raw"], "xdr.data.container.id")
        namespace = features.get(row["raw"], "xdr.data.container.namespace")
        if any(value is not None and not identity_text(value) for value in (user, session, container, namespace)):
            raise ValueError("Masked or invalid user/session/container identities cannot define a sequence")
        optional_identity = tuple(evidence_scope.text(value, "reported sequence identity") if value is not None else None for value in (user, session, container, namespace))
        identities.add((context["id"], context["version"], row["index_name"], context["account"], context["realm"], host_id, boot_id, *optional_identity))
        hosts.add(row["host"])
    if len(identities) != 1 or len(hosts) != 1:
        raise ValueError("A sequence cannot join indexes, sources, hosts or boot incarnations")
    source_id, source_version, index, account, realm, host_id, boot_id, user, session, container, namespace = next(iter(identities))
    provenance = [{**evidence_scope.reference(row), "source_id": source_id, "source_version": source_version} for row in selected]
    return {"event_ids": identifiers, "features": vectors, "feature_digest": _digest(vectors),
            "entity_key": _digest([actor["tenant"], index, source_id, account, realm, host_id, boot_id, user, session, container, namespace]),
            "source_id": source_id, "source_version": source_version, "source_context": selected[0]["source_context"], "indexes": [index],
            "host": next(iter(hosts)), "start": selected[0]["event_time"], "end": selected[-1]["event_time"],
            "provenance": provenance, "ordering_basis": "strictly increasing source-reported event_time", "causality_proven": False}


def inspect_sequences(store, who, sequences, indexes=None):
    if not isinstance(sequences, list) or not 1 <= len(sequences) <= MAX_SCENARIOS:
        raise ValueError("1..4096 explicitly identified sequences required")
    identifiers, windows = [], []
    for item in sequences:
        if not isinstance(item, dict) or not isinstance(item.get("event_ids"), list) or not 2 <= len(item["event_ids"]) <= 32:
            raise ValueError("Each sequence requires 2..32 original IDs")
        ids = [evidence_scope.text(value, "sequence original ID") for value in item["event_ids"]]
        if len(set(ids)) != len(ids):
            raise ValueError("A sequence cannot repeat an original ID")
        windows.append(ids)
        identifiers.extend(ids)
    if sum(len(ids)*len(FEATURES) for ids in windows) > 2_000_000:
        raise CapacityError("Sequence inputs exceed two million feature values")
    with principal.transaction(store, who) as (_, actor):
        indexes = exact_indexes(indexes if indexes is not None else actor["allowed_indexes"])
    rows, _contexts = _fetch(store, actor, list(dict.fromkeys(identifiers)), indexes)
    return [_window(actor, ids, rows) for ids in windows]


def _dataset(data):
    prepared = {}
    scenario_ids, event_ids = set(), set()
    for split, minimum in (("training", 32), ("calibration", 16), ("holdout", 16)):
        items = data.get(split)
        if not isinstance(items, list) or not minimum <= len(items) <= MAX_SCENARIOS:
            raise ValueError(f"{split} requires {minimum}..4096 reviewed scenarios")
        prepared[split] = []
        for item in items:
            if not isinstance(item, dict) or set(item)-{"scenario_id", "event_ids", "label", "family", "host_group", "split"} or not {"scenario_id", "event_ids", "label", "family", "host_group"} <= set(item):
                raise ValueError("Exact external scenario manifest fields required")
            scenario_id = evidence_scope.text(item["scenario_id"], "scenario ID", 128)
            family = evidence_scope.text(item["family"], "family", 128)
            host = evidence_scope.text(item["host_group"], "host group")
            label = item["label"]
            if type(label) is str:
                label = {"normal": 0, "attack": 1}.get(label)
            if type(label) is not int or label not in (0, 1):
                raise ValueError("External reviewed label must be normal/attack or 0/1")
            ids = item["event_ids"]
            if not isinstance(ids, list) or not 2 <= len(ids) <= 32:
                raise ValueError("Each reviewed scenario needs 2..32 ordered originals")
            ids = [evidence_scope.text(value, "scenario original ID") for value in ids]
            if scenario_id in scenario_ids or len(ids) != len(set(ids)) or event_ids.intersection(ids):
                raise ValueError("Scenario and original IDs must be distinct across all splits")
            scenario_ids.add(scenario_id)
            event_ids.update(ids)
            prepared[split].append({"scenario_id": scenario_id, "family": family, "host_group": host, "label": label, "event_ids": ids})
        if {item["label"] for item in prepared[split]} != {0, 1}:
            raise ValueError("Every dataset partition requires reviewed normal and attack scenarios")
    if len(scenario_ids) > MAX_SCENARIOS or len(event_ids)*len(FEATURES) > 2_000_000:
        raise CapacityError("Reviewed sequence dataset exceeds bounded tensor budget")
    for left, right in (("training", "calibration"), ("training", "holdout"), ("calibration", "holdout")):
        for key in ("family", "host_group"):
            if {item[key] for item in prepared[left]} & {item[key] for item in prepared[right]}:
                raise ValueError("Dataset family and host groups must be disjoint across partitions")
    return prepared


def _recheck(db, actor, windows, sources):
    identifiers = {p["event_id"]: p for window in windows for p in window["provenance"]}
    ids = list(identifiers)
    for offset in range(0, len(ids), 1000):
        current = {row["event_id"]: row for row in db.execute("SELECT event_id,digest,received FROM receipts WHERE tenant=? AND event_id IN (SELECT value FROM json_each(?))", (actor["tenant"], encode(ids[offset:offset+1000])))}
        for identifier in ids[offset:offset+1000]:
            expected, row = identifiers[identifier], current.get(identifier)
            if not row or row["digest"] != expected["admission_digest"] or row["received"] != expected["received"]:
                raise ConflictError("Sequence originals changed or were retired during execution")
    _sources_current(db, actor, [*sources, *[window["source_context"] for window in windows]])


def confusion(scores, labels, threshold):
    predicted = [score >= threshold for score in scores]
    tp = sum(p and y == 1 for p, y in zip(predicted, labels))
    fp = sum(p and y == 0 for p, y in zip(predicted, labels))
    fn = sum(not p and y == 1 for p, y in zip(predicted, labels))
    tn = sum(not p and y == 0 for p, y in zip(predicted, labels))
    precision, recall = tp/(tp+fp) if tp+fp else 0., tp/(tp+fn) if tp+fn else 0.
    return {"samples": len(labels), "true_positive": tp, "false_positive": fp, "false_negative": fn, "true_negative": tn,
            "precision": precision, "recall": recall, "false_positive_rate": fp/(fp+tn) if fp+tn else 0.,
            "accuracy": (tp+tn)/len(labels), "f1": 2*precision*recall/(precision+recall) if precision+recall else 0.,
            "threshold": threshold, "probability_calibrated": False, "synthetic_or_reviewed_label_benchmark_only": True}


def _public(db, row, *, memo=None):
    if memo is None:
        definition, snapshot, definition_digest = content_model("sequence", row)
    else:
        definition, snapshot, definition_digest = decoded_model(db, memo, "sequence", row)
    active = db.execute("SELECT 1 FROM cpu_sequence_active WHERE tenant=? AND model_id=?", (row["tenant"], row["id"])).fetchone() is not None
    assessment = db.execute("SELECT id,result FROM cpu_sequence_evaluations WHERE tenant=? AND model_id=? AND holdout_digest=? ORDER BY created DESC LIMIT 1", (row["tenant"], row["id"], definition["holdout_digest"])).fetchone()
    assessment_data = json.loads(assessment["result"]) if assessment else None
    from . import cpu_ml_lifecycle
    retired = cpu_ml_lifecycle.retirement(db, row["tenant"], "sequence", row["id"])
    return {"id": row["id"], "model_id": row["id"], "model_family": "sequence", "retired": retired is not None, "retirement": retired, "name": row["name"], "revision": row["revision"],
            "digest": row["digest"], "definition_digest": definition_digest, "feature_contract_digest": FEATURE_CONTRACT_DIGEST,
            "indexes": json.loads(row["indexes"]), "owner": row["owner"], "created": row["created"], "active": active,
            "feature_schema": FEATURE_SCHEMA, "features": list(FEATURES), "architecture": ARCHITECTURE,
            "threshold": snapshot["threshold"], "metrics": json.loads(row["metrics"]), "split_summary": definition["split_summary"],
            "assessment_id": assessment["id"] if assessment else None, "holdout_metrics": assessment_data["metrics"] if assessment else None,
            "assessment": {key: assessment_data[key] for key in ("assessment_id", "metrics", "unordered_baseline_metrics", "order_sensitivity_mean_abs_delta", "input_tensor_shape", "padded_steps", "duration_ms", "worker_wall_ms", "worker_reused", "independent_family_host_time_partition", "holdout_used_for_threshold")} if assessment_data else None,
            "probability_calibrated": False, "automatic_response_authorized": False}


def _load(db, actor, identifier, require_review=False, *, memo=None):
    if principal.current(db, actor) != actor:
        raise PermissionError("Sequence model caller permissions changed")
    row = db.execute("SELECT * FROM cpu_sequence_models WHERE tenant=? AND id=?", (actor["tenant"], identifier)).fetchone()
    if not row or not principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
        raise KeyError("Sequence model not found in complete current scope")
    from . import cpu_ml_lifecycle
    cpu_ml_lifecycle.assert_not_retired(db, actor["tenant"], "sequence", identifier)
    owner = principal.current(db, {"name": row["owner"], "tenant": actor["tenant"], "role": "analyst"}, EDITORS)
    if not principal.contains(owner["allowed_indexes"], json.loads(row["indexes"])):
        raise PermissionError("Sequence model owner scope revoked")
    if memo is None:
        definition, snapshot, _ = content_model("sequence", row)
    else:
        definition, snapshot, _ = decoded_model(db, memo, "sequence", row)
    if "dataset_binding" in definition:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ml_dataset_model_links'").fetchone():
            raise ConflictError("Dataset model binding storage unavailable")
        from .ml_datasets import validate_model_binding
        validate_model_binding(db, actor, identifier, "sequence", dict(definition["dataset_binding"]))
    if snapshot.get("schema") != MODEL_SCHEMA or snapshot.get("feature_schema") != FEATURE_SCHEMA or definition.get("architecture") != ARCHITECTURE or definition.get("feature_contract_digest") != FEATURE_CONTRACT_DIGEST:
        raise ConflictError("Sequence architecture or feature contract is unsupported")
    for key in ("threshold", "pooled_threshold"):
        if type(snapshot.get(key)) not in (int, float) or not math.isfinite(snapshot[key]) or not 0 <= snapshot[key] <= 1:
            raise ConflictError("Sequence threshold is invalid")
    _sources_current(db, actor, definition["sources"])
    if require_review:
        review = db.execute("SELECT r.* FROM cpu_sequence_active a JOIN cpu_sequence_reviews r ON r.id=a.review_id WHERE a.tenant=? AND a.model_id=?", (actor["tenant"], identifier)).fetchone()
        if not review or review["reviewer"] == row["owner"]:
            raise PermissionError("Independent active sequence model approval required")
        reviewer = principal.current(db, {"name": review["reviewer"], "tenant": actor["tenant"], "role": "analyst"}, EDITORS)
        if not principal.contains(reviewer["allowed_indexes"], json.loads(row["indexes"])):
            raise PermissionError("Sequence model reviewer scope revoked")
    return row, definition, snapshot


def train(store, who, data, *, _publication_check=None):
    allowed = {"name", "indexes", "training", "calibration", "holdout", "epochs", "reviewed_dataset"}
    if not isinstance(data, dict) or set(data)-allowed or data.get("reviewed_dataset") is not True:
        raise ValueError("Explicit reviewed external sequence dataset acknowledgement required")
    name = evidence_scope.text(data.get("name"), "sequence model name", 128)
    indexes = exact_indexes(data.get("indexes"))
    epochs = evidence_scope.integer(data.get("epochs", 30), "sequence epochs", 1, 60)
    dataset = _dataset(data)
    with principal.transaction(store, who, EDITORS) as (_, actor):
        if not principal.contains(actor["allowed_indexes"], indexes):
            raise PermissionError("Sequence training scope exceeds current permissions")
    if not cpu_ml.runtime_status()["available"]:
        return {"status": "unavailable", "compatibility": "시스템에서 호환되지 않음"}
    all_items = [item for split in dataset.values() for item in split]
    windows = inspect_sequences(store, actor, all_items, indexes)
    offsets, frozen, actual = 0, {}, {}
    for split, items in dataset.items():
        selected = windows[offsets:offsets+len(items)]
        offsets += len(items)
        if any(window["host"] != item["host_group"] for window, item in zip(selected, items)):
            raise ValueError("Manifest host group must equal each original's actual host")
        actual[split] = selected
        frozen[split] = [{**item, "feature_digest": window["feature_digest"], "entity_key": window["entity_key"], "start": window["start"], "end": window["end"], "provenance": window["provenance"]} for item, window in zip(items, selected)]
    if max(w["end"] for w in actual["training"]) >= min(w["start"] for w in actual["calibration"]) or max(w["end"] for w in actual["calibration"]) >= min(w["start"] for w in actual["holdout"]):
        raise ValueError("Training, calibration and holdout time ranges must be strictly disjoint and ordered")
    outcome = cpu_ml_runtime.request({"operation": "sequence_train", "feature_count": len(FEATURES),
        "training": [w["features"] for w in actual["training"]], "training_labels": [i["label"] for i in dataset["training"]],
        "calibration": [w["features"] for w in actual["calibration"]], "calibration_labels": [i["label"] for i in dataset["calibration"]], "epochs": epochs}, timeout=120)
    if outcome.get("worker_error"):
        return {"status": "unavailable", "compatibility": "시스템에서 호환되지 않음", "reason": outcome["reason"]}
    sources = {window["source_id"]: window["source_context"] for window in windows}
    metrics = {**outcome["metrics"], "worker_wall_ms": outcome["worker_wall_ms"], "worker_reused": outcome["worker_reused"],
        "runtime_limits": outcome.get("runtime_limits"),
        "calibration": confusion(outcome["calibration_scores"], [i["label"] for i in dataset["calibration"]], outcome["threshold"]),
        "unordered_baseline_calibration": confusion(outcome["pooled_calibration_scores"], [i["label"] for i in dataset["calibration"]], outcome["pooled_threshold"])}
    definition = {"name": name, "indexes": indexes, "architecture": ARCHITECTURE, "feature_contract_digest": FEATURE_CONTRACT_DIGEST,
        "framework_version": outcome["framework_version"], "seed": 81213, "epochs": epochs, "reviewed_dataset": True,
        "threshold_selection": "maximum calibration F1, then minimum false positives; midpoint of the identical-prediction calibration score interval; no holdout selection",
        "dataset": frozen, "dataset_digest": _digest(frozen), "holdout_digest": _digest(frozen["holdout"]), "sources": list(sources.values()),
        "split_summary": {split: {"scenarios": len(items), "normal": sum(i["label"] == 0 for i in items), "attack": sum(i["label"] == 1 for i in items), "families": sorted({i["family"] for i in items}), "hosts": len({i["host_group"] for i in items})} for split, items in dataset.items()}}
    snapshot = {"schema": MODEL_SCHEMA, "feature_schema": FEATURE_SCHEMA, **{key: outcome[key] for key in ("weights", "pooled_weights", "threshold", "pooled_threshold")}}
    digest = _digest({"definition": definition, "snapshot": snapshot})
    with principal.transaction(store, actor, EDITORS, write=True) as (db, fresh):
        if fresh != actor:
            raise PermissionError("Sequence training permissions changed")
        _recheck(db, fresh, windows, definition["sources"])
        revision = db.execute("SELECT coalesce(max(revision),0)+1 FROM cpu_sequence_models WHERE tenant=? AND name=?", (actor["tenant"], name)).fetchone()[0]
        identifier = str(uuid.uuid4())
        if _publication_check is not None:
            definition["dataset_binding"] = _publication_check(db, fresh, identifier)
            digest = _digest({"definition": definition, "snapshot": snapshot})
        db.execute("INSERT INTO cpu_sequence_models VALUES(?,?,?,?,?,?,?,?,?,?,?)", (identifier, actor["tenant"], actor["name"], name, revision, encode(indexes), time.time(), encode(definition), encode(snapshot), digest, encode(metrics)))
        db.executemany("INSERT OR IGNORE INTO record_case_evidence_refs VALUES(?,?,?,?)", [(actor["tenant"], event_id, "cpu_sequence_model", identifier) for event_id in {p["event_id"] for w in windows for p in w["provenance"]}])
        store.audit(db, actor["tenant"], actor["name"], "cpu_sequence.train", {"model_id": identifier, "digest": digest, "revision": revision, "scenarios": len(all_items), "holdout_unseen": True})
        return {"status": "completed", **_public(db, db.execute("SELECT * FROM cpu_sequence_models WHERE id=?", (identifier,)).fetchone())}


def evaluate(store, who, model_id):
    with principal.transaction(store, who, EDITORS) as (db, actor):
        row, definition, snapshot = _load(db, actor, model_id)
    items = definition["dataset"]["holdout"]
    windows = inspect_sequences(store, actor, items, json.loads(row["indexes"]))
    if any(w["feature_digest"] != item["feature_digest"] or w["provenance"] != item["provenance"] for w, item in zip(windows, items)):
        raise ConflictError("Independent held-out original/feature snapshot changed")
    outcome = cpu_ml_runtime.request({"operation": "sequence_infer", "feature_count": len(FEATURES), "weights": snapshot["weights"], "pooled_weights": snapshot["pooled_weights"], "sequences": [w["features"] for w in windows]}, timeout=30)
    if outcome.get("worker_error"):
        return {"status": "unavailable", "compatibility": "시스템에서 호환되지 않음", "reason": outcome["reason"]}
    labels = [i["label"] for i in items]
    result = {"status": "completed", "model_id": model_id, "digest": row["digest"], "revision": row["revision"],
        "holdout_digest": definition["holdout_digest"], "metrics": confusion(outcome["scores"], labels, snapshot["threshold"]),
        "unordered_baseline_metrics": confusion(outcome["pooled_scores"], labels, snapshot["pooled_threshold"]),
        "order_sensitivity_mean_abs_delta": outcome["order_sensitivity_mean_abs_delta"],
        "input_tensor_shape": outcome["input_tensor_shape"], "padded_steps": outcome["padded_steps"],
        "duration_ms": outcome["duration_ms"], "worker_wall_ms": outcome["worker_wall_ms"], "worker_reused": outcome["worker_reused"],
        "runtime_limits": outcome.get("runtime_limits"),
        "scenarios": [{"scenario_id": item["scenario_id"], "family": item["family"], "label": item["label"], "event_ids": item["event_ids"], "score": score, "predicted_attack": score >= snapshot["threshold"]} for item, score in zip(items, outcome["scores"])],
        "independent_family_host_time_partition": True, "holdout_used_for_threshold": False, "automatic_response_authorized": False}
    with principal.transaction(store, actor, EDITORS, write=True) as (db, fresh):
        if fresh != actor:
            raise PermissionError("Sequence assessment permissions changed")
        current, _, _ = _load(db, fresh, model_id)
        if current["digest"] != row["digest"]:
            raise ConflictError("Sequence model changed during independent assessment")
        _recheck(db, fresh, windows, definition["sources"])
        identifier = result["assessment_id"] = str(uuid.uuid4())
        db.execute("INSERT INTO cpu_sequence_evaluations VALUES(?,?,?,?,?,?,?,?)", (identifier, actor["tenant"], actor["name"], model_id, row["indexes"], time.time(), definition["holdout_digest"], encode(result)))
        store.audit(db, actor["tenant"], actor["name"], "cpu_sequence.evaluate", {"assessment_id": identifier, "model_id": model_id, "holdout_digest": definition["holdout_digest"], "metrics": result["metrics"]})
    return result


def activate(store, who, model_id, notes):
    notes = evidence_scope.text(notes, "independent sequence review notes", 2000)
    with principal.transaction(store, who, EDITORS, write=True) as (db, actor):
        row, definition, _ = _load(db, actor, model_id)
        if row["owner"] == actor["name"]:
            raise PermissionError("Sequence model creator cannot approve their own model")
        if not db.execute("SELECT 1 FROM cpu_sequence_evaluations WHERE tenant=? AND model_id=? AND holdout_digest=?", (actor["tenant"], model_id, definition["holdout_digest"])).fetchone():
            raise ConflictError("Independent held-out assessment required before activation")
        review_id = str(uuid.uuid4())
        db.execute("INSERT INTO cpu_sequence_reviews VALUES(?,?,?,?,?,?)", (review_id, actor["tenant"], model_id, actor["name"], time.time(), notes))
        db.execute("INSERT INTO cpu_sequence_active VALUES(?,?,?,?,?) ON CONFLICT(tenant,name) DO UPDATE SET model_id=excluded.model_id,review_id=excluded.review_id,updated=excluded.updated", (actor["tenant"], row["name"], model_id, review_id, time.time()))
        from . import intelligence_sequence
        intelligence_sequence.activate_model(db, row)
        store.audit(db, actor["tenant"], actor["name"], "cpu_sequence.activate", {"model_id": model_id, "digest": row["digest"], "review_id": review_id})
        return _public(db, row)


def rollback(store, who, model_id, notes):
    return activate(store, who, model_id, notes)


def disable(store, who, model_id):
    with principal.transaction(store, who, EDITORS, write=True) as (db, actor):
        _row, _, _ = _load(db, actor, model_id)
        db.execute("DELETE FROM cpu_sequence_active WHERE tenant=? AND model_id=?", (actor["tenant"], model_id))
        from . import intelligence_sequence
        intelligence_sequence.stop_model(db, model_id, "Model explicitly disabled under current full-scope authority")
        store.audit(db, actor["tenant"], actor["name"], "cpu_sequence.disable", {"model_id": model_id})
        return {"model_id": model_id, "active": False}


def frozen_features(records):
    """Trusted replay helper; callers must freeze and validate original scope."""
    return features.vectors(records)


def frozen_infer(definition, snapshot, digest, sequences):
    """Pure tensor evaluation from an already-authorized frozen model context.

    No live Store, activation lookup, run row, Case or evidence ref is touched.
    The returned fields exclude clocks/PIDs so replay hashes are deterministic.
    This helper is deliberately not an HTTP route for caller-supplied tensors.
    """
    if _digest({"definition": definition, "snapshot": snapshot}) != digest:
        raise ConflictError("Frozen sequence model digest mismatch")
    if definition.get("architecture") != ARCHITECTURE or definition.get("feature_contract_digest") != FEATURE_CONTRACT_DIGEST or snapshot.get("schema") != MODEL_SCHEMA or snapshot.get("feature_schema") != FEATURE_SCHEMA:
        raise ConflictError("Frozen sequence feature/architecture contract is unsupported")
    if not isinstance(sequences, list) or not 1 <= len(sequences) <= 256:
        raise ValueError("1..256 bounded frozen sequence tensors required")
    answer = cpu_ml_runtime.request({"operation": "sequence_infer", "feature_count": len(FEATURES), "weights": snapshot["weights"], "sequences": sequences}, timeout=20)
    if answer.get("worker_error"):
        raise CapacityError("Frozen sequence CPU runtime unavailable: "+answer["reason"])
    return {key: answer[key] for key in ("scores", "input_tensor_shape", "padded_steps", "device", "threads")}


def run_due(store, now=None, cancel=None, budget=.25, max_runs=16):
    from . import cpu_ml_lifecycle
    return cpu_ml_lifecycle.run_due(store, now, cancel, budget, max_runs)


def model_pin(store, db, actor, model_id, *, memo=None):
    fresh = principal.current(db, actor)
    if fresh != actor:
        raise PermissionError("Sequence publication permissions changed")
    row, _, _ = _load(db, fresh, model_id, True, memo=memo)
    return _public(db, row, memo=memo)


def validate_publication(store, db, actor, model_id, digest, revision, *, memo=None):
    if not db.in_transaction:
        raise ConflictError("Sequence publication requires the caller's reserved transaction")
    if type(revision) is not int or revision < 1 or not isinstance(digest, str) or len(digest) != 64:
        raise ValueError("Exact immutable sequence revision and SHA-256 digest required")
    fresh = principal.current(db, actor, EDITORS)
    if fresh != actor:
        raise PermissionError("Sequence publication permissions changed")
    result = model_pin(store, db, actor, model_id, memo=memo)
    if type(revision) is not int or result["revision"] != revision or result["digest"] != digest:
        raise ConflictError("Sequence prediction belongs to a different immutable model revision")
    return result


def compatible_models(store, who, indexes):
    indexes = exact_indexes(indexes)
    with principal.transaction(store, who) as (db, actor):
        if not principal.contains(actor["allowed_indexes"], indexes):
            raise PermissionError("Sequence model scope exceeds current permissions")
        results = []
        for pointer in db.execute("SELECT model_id FROM cpu_sequence_active WHERE tenant=? ORDER BY updated DESC,name", (actor["tenant"],)).fetchall():
            try:
                row, _, _ = _load(db, actor, pointer["model_id"], True)
                if principal.contains(json.loads(row["indexes"]), indexes):
                    results.append(_public(db, row))
            except (KeyError, PermissionError, ConflictError):
                continue
        return results


def list_models(store, who):
    with principal.transaction(store, who) as (db, actor):
        output = []
        for row in db.execute("SELECT * FROM cpu_sequence_models WHERE tenant=? ORDER BY created DESC", (actor["tenant"],)):
            if principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
                output.append(_public(db, row))
        return output


def infer_sequences(store, who, sequences, *, model_id=None, shadow=False):
    if type(shadow) is not bool or not isinstance(sequences, list) or not 1 <= len(sequences) <= 256:
        raise ValueError("Boolean shadow and 1..256 original sequence windows required")
    with principal.transaction(store, who) as (db, actor):
        if model_id is None:
            pointers = db.execute("SELECT model_id FROM cpu_sequence_active WHERE tenant=? ORDER BY updated DESC", (actor["tenant"],)).fetchall()
            for pointer in pointers:
                try:
                    row, definition, snapshot = _load(db, actor, pointer[0], True)
                    model_id = row["id"]
                    break
                except (KeyError, PermissionError, ConflictError):
                    continue
            else:
                return {"status": "no_active_model", "results": []}
        else:
            row, definition, snapshot = _load(db, actor, model_id, not shadow)
    windows = inspect_sequences(store, actor, sequences, json.loads(row["indexes"]))
    outcome = cpu_ml_runtime.request({"operation": "sequence_infer", "feature_count": len(FEATURES), "weights": snapshot["weights"], "sequences": [w["features"] for w in windows]}, timeout=20)
    if outcome.get("worker_error"):
        return {"status": "unavailable", "compatibility": "시스템에서 호환되지 않음", "results": [], "reason": outcome["reason"]}
    if len(outcome["scores"]) != len(windows):
        raise ConflictError("Sequence prediction count differs from original windows")
    results = [{**{key: window[key] for key in ("event_ids", "entity_key", "source_id", "source_version", "indexes", "host", "start", "end", "provenance", "feature_digest")},
        "model_id": model_id, "model_family": "sequence", "revision": row["revision"], "digest": row["digest"],
        "features": {"sequence_steps": len(window["event_ids"]), "feature_schema": FEATURE_SCHEMA, "feature_contract_digest": FEATURE_CONTRACT_DIGEST,
                     "input_dimensions": 3, "padded_step_masked": True, "event_kinds": [next((name[5:] for name, value in zip(FEATURES, step) if name.startswith("kind_") and value == 1), "other") for step in window["features"]]},
        "score": score, "threshold": snapshot["threshold"], "anomaly": score >= snapshot["threshold"], "shadow": shadow,
        "probability_calibrated": False, "malicious_probability": False, "automatic_response_authorized": False} for window, score in zip(windows, outcome["scores"])]
    answer = {"status": "completed", "results": results, "model_id": model_id, "digest": row["digest"], "revision": row["revision"], "model_family": "sequence", "shadow": shadow,
        "runtime_limits": outcome.get("runtime_limits"),
        **{key: outcome[key] for key in ("duration_ms", "worker_wall_ms", "worker_pid", "worker_generation", "worker_reused", "input_tensor_shape", "padded_steps")}, "device": "cpu"}
    with principal.transaction(store, actor, write=True) as (db, fresh):
        if fresh != actor:
            raise PermissionError("Sequence inference permissions changed")
        current, _, _ = _load(db, fresh, model_id, not shadow)
        if current["digest"] != row["digest"]:
            raise ConflictError("Sequence model changed during inference")
        _recheck(db, fresh, windows, definition["sources"])
        identifier = answer["run_id"] = str(uuid.uuid4())
        db.execute("INSERT INTO cpu_sequence_runs VALUES(?,?,?,?,?,?,?,?)", (identifier, actor["tenant"], actor["name"], model_id, row["indexes"], time.time(), int(shadow), encode(answer)))
        from . import cpu_ml_lifecycle
        cpu_ml_lifecycle.record_run(db, actor, "sequence", identifier, answer)
        store.audit(db, actor["tenant"], actor["name"], "cpu_sequence.infer", {"run_id": identifier, "model_id": model_id, "windows": len(results), "anomalies": sum(r["anomaly"] for r in results), "shadow": shadow})
    return answer


def register(app, store, runtime, who, body):
    from fastapi import Request
    from starlette.concurrency import run_in_threadpool

    @app.get("/api/v3/ml/sequences/models")
    def listing(request: Request):
        return list_models(store, who(request))

    @app.post("/api/v3/ml/sequences/models", status_code=201)
    async def training(request: Request):
        return await run_in_threadpool(train, store, who(request, EDITORS), await body(request))

    @app.post("/api/v3/ml/sequences/models/{model_id}/evaluate")
    async def assessing(model_id: str, request: Request):
        return await run_in_threadpool(evaluate, store, who(request, EDITORS), model_id)

    @app.get("/api/v3/ml/sequences/models/{model_id}/assessment")
    def assessment(model_id: str, request: Request):
        with principal.transaction(store, who(request)) as (db, actor):
            row = db.execute("SELECT * FROM cpu_sequence_models WHERE tenant=? AND id=?", (actor["tenant"], model_id)).fetchone()
            if not row or not principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
                raise KeyError("Sequence assessment not found in complete current scope")
            return _public(db, row)["assessment"]

    @app.post("/api/v3/ml/sequences/models/{model_id}/activate")
    async def approving(model_id: str, request: Request):
        data = await body(request)
        if not isinstance(data, dict) or set(data) != {"notes"}:
            raise ValueError("Independent review notes required")
        return activate(store, who(request, EDITORS), model_id, data["notes"])

    @app.post("/api/v3/ml/sequences/models/{model_id}/rollback")
    async def reverting(model_id: str, request: Request):
        data = await body(request)
        if not isinstance(data, dict) or set(data) != {"notes"}:
            raise ValueError("Independent rollback review notes required")
        return rollback(store, who(request, EDITORS), model_id, data["notes"])

    @app.post("/api/v3/ml/sequences/models/{model_id}/disable")
    def disabling(model_id: str, request: Request):
        return disable(store, who(request, EDITORS), model_id)

    @app.post("/api/v3/ml/sequences/models/{model_id}/infer")
    async def inference(model_id: str, request: Request):
        data = await body(request)
        if not isinstance(data, dict) or set(data)-{"sequences", "shadow"} or "sequences" not in data:
            raise ValueError("Exact original sequence windows and optional shadow boolean required")
        return await run_in_threadpool(infer_sequences, store, who(request), data["sequences"], model_id=model_id, shadow=data.get("shadow", False))
