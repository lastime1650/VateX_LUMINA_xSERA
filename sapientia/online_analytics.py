"""Reviewed River HST baseline and ADWIN drift observer, CPU only.

Predictive baselines are frozen after normal-data review. Untrusted live
telemetry never retrains a model; drift creates a candidate-review signal.
"""

import importlib.metadata
import ipaddress
import json
import math
import threading
import time
import uuid
from collections import OrderedDict

from . import evidence_scope, intelligence, migrations, principal, release_manifest
from .storage import CapacityError, ConflictError, encode

SCHEMA = "xsera.online-analytics.v1"
FEATURE_CONTRACT_DIGEST = release_manifest.digest(
    {
        "schema": SCHEMA,
        "feature_spec": "bounded-numeric-10-v1",
        "implementation": release_manifest.hash_file(__file__),
    }
)
_cache = OrderedDict()
_cache_lock = threading.RLock()


def initialize(store):
    migrations.apply_store(
        store,
        "online_analytics",
        [
            "CREATE TABLE IF NOT EXISTS online_analytics_models(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,name TEXT NOT NULL,indexes TEXT NOT NULL,revision INTEGER NOT NULL,state TEXT NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL,reviewer TEXT,reason TEXT,updated REAL NOT NULL)",
            "CREATE TABLE IF NOT EXISTS online_analytics_runs(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,model_id TEXT NOT NULL,indexes TEXT NOT NULL,created REAL NOT NULL,anomaly INTEGER NOT NULL,drift INTEGER NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL,compact INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS online_analytics_state(model_id TEXT PRIMARY KEY,cursor INTEGER NOT NULL,scores TEXT NOT NULL,updated REAL NOT NULL,error TEXT)",
            "CREATE TABLE IF NOT EXISTS online_analytics_outbox(seq INTEGER PRIMARY KEY AUTOINCREMENT,tenant TEXT NOT NULL,event_id TEXT NOT NULL,index_name TEXT NOT NULL,received REAL NOT NULL,UNIQUE(tenant,event_id,received))",
            "CREATE INDEX IF NOT EXISTS online_analytics_due ON online_analytics_outbox(tenant,seq)",
        ],
    )


def backend_status():
    try:
        from river import anomaly, drift

        if not callable(anomaly.HalfSpaceTrees) or not callable(drift.ADWIN):
            raise ImportError("Compatible River HST and ADWIN required")  # noqa: TRY004 - dependency capability check.
        return {
            "available": True,
            "version": importlib.metadata.version("river"),
            "algorithms": ["HalfSpaceTrees", "ADWIN"],
            "predictive_baseline_updates": "reviewed-normal-data-only",
            "pickle_loading": False,
        }
    except ImportError:
        return {
            "available": False,
            "version": None,
            "reason": "Install pinned online-analysis extra",
            "algorithms": ["HalfSpaceTrees", "ADWIN"],
        }


def _text(value):
    return value if isinstance(value, str) else ""


def features(record):
    raw = record.get("raw", {})
    data = (
        raw.get("xdr", {}).get("data", {}) if isinstance(raw.get("xdr"), dict) else {}
    )
    data = data if isinstance(data, dict) else {}

    def obj(key):
        return data.get(key, {}) if isinstance(data.get(key), dict) else {}

    security = raw.get("security", {}) if isinstance(raw.get("security"), dict) else {}
    proc = obj("process")
    file = obj("file")
    network = obj("network")
    event = obj("event")
    dest = obj("destination")
    action = _text(event.get("action") or security.get("action")).lower()
    command = _text(proc.get("command_line"))
    name = _text(proc.get("name"))
    port = dest.get("port", security.get("dest_port"))
    port = port if type(port) is int and 0 <= port <= 65535 else 0
    destination = dest.get("ip", security.get("dest_ip"))
    try:
        public = not ipaddress.ip_address(destination).is_private
    except (ValueError, TypeError):
        public = False
    # No labels, scenario IDs, event identifiers, source product or truth fields.
    return {
        "command_length": min(len(command), 2048) / 2048,
        "name_length": min(len(name), 128) / 128,
        "command_tokens": min(len(command.split()), 64) / 64,
        "file_path_length": min(len(_text(file.get("path"))), 512) / 512,
        "destination_port": port / 65535,
        "public_destination": float(public),
        "has_parent": float(isinstance(proc.get("parent"), dict)),
        "process_activity": float("process" in action or "exec" in action),
        "file_activity": float("file" in action),
        "network_activity": float(
            bool(network) or "network" in action or "connect" in action
        ),
    }


def _hash(value):
    return release_manifest.digest(value)


def _ids(value, minimum=1):
    if (
        not isinstance(value, list)
        or not minimum <= len(value) <= 32
        or any(not isinstance(v, str) or not 1 <= len(v) <= 256 for v in value)
        or len(set(value)) != len(value)
    ):
        raise ValueError(f"{minimum}..32 unique original IDs required")
    return value


def _references(records):
    return [
        evidence_scope.reference(r)
        for r in sorted(records.values(), key=lambda r: r["event_id"])
    ]


def _authenticated(db, actor, records):
    for record in records.values():
        source = intelligence._projection(db, actor["tenant"], record)
        if not source:
            raise PermissionError(
                "Authenticated source receipt required for online baseline"
            )
        source_owner = db.execute(
            "SELECT owner FROM source_registry WHERE tenant=? AND id=?",
            (actor["tenant"], source["source_id"]),
        ).fetchone()
        if not source_owner:
            raise PermissionError("Registered online source required")
        owner = principal.current(
            db,
            {
                "name": source_owner["owner"],
                "tenant": actor["tenant"],
                "role": "analyst",
            },
            ("admin", "analyst"),
        )
        if not principal.contains(owner["allowed_indexes"], [record["index_name"]]):
            raise PermissionError("Online source owner scope revoked")


def _estimator(snapshot):
    from river import anomaly

    key = _hash(snapshot)
    with _cache_lock:
        if key in _cache:
            _cache.move_to_end(key)
            return _cache[key]
        estimator = anomaly.HalfSpaceTrees(n_trees=8, height=4, window_size=8, seed=17)
        for vector in snapshot["normal_vectors"]:
            estimator.learn_one(vector)
        _cache[key] = estimator
        while len(_cache) > 8:
            _cache.popitem(last=False)
        return estimator


def drift_scores(history, new_scores):
    from river import drift

    detector = drift.ADWIN(delta=0.01, clock=1, min_window_length=8, grace_period=32)
    for score in history[-512:]:
        detector.update(score)
    detected = False
    for score in new_scores:
        if (
            type(score) not in (float, int)
            or not math.isfinite(score)
            or not 0 <= score <= 1
        ):
            raise ValueError("Finite anomaly score required")
        detector.update(score)
        detected |= bool(detector.drift_detected)
    return detected, (history + list(new_scores))[-512:]


def train(store, who, data):
    if (
        not isinstance(data, dict)
        or set(data) != {"name", "indexes", "normal_event_ids"}
        or not isinstance(data["name"], str)
        or not 1 <= len(data["name"]) <= 120
    ):
        raise ValueError("name,indexes,normal_event_ids required")
    ids = _ids(data["normal_event_ids"], 16)
    with principal.transaction(store, who, ("admin",)) as (db, actor):
        indexes = data["indexes"]
        if (
            not isinstance(indexes, list)
            or not indexes
            or indexes == ["*"]
            or not principal.contains(actor["allowed_indexes"], indexes)
        ):
            raise PermissionError("Explicit baseline indexes required")
    if not backend_status()["available"]:
        return {"status": "unavailable", **backend_status()}
    records = evidence_scope.originals(store, actor, ids)
    if sorted({r["index_name"] for r in records.values()}) != sorted(set(indexes)):
        raise ValueError("Training originals must exactly cover declared indexes")
    with principal.transaction(store, actor, ("admin",)) as (db, actor):
        _authenticated(db, actor, records)
    snapshot = {
        "schema": SCHEMA,
        "normal_vectors": [
            features(r)
            for r in sorted(
                records.values(), key=lambda r: (r["event_time"], r["event_id"])
            )
        ],
        "feature_contract_digest": FEATURE_CONTRACT_DIGEST,
        "normal_originals": _references(records),
        "river_version": backend_status()["version"],
        "parameters": {"trees": 8, "height": 4, "window_size": 8, "seed": 17},
        "labels": "operator-asserted-normal-awaiting-peer-review",
    }
    estimator = _estimator(snapshot)
    scores = [float(estimator.score_one(x)) for x in snapshot["normal_vectors"]]
    snapshot["threshold"] = min(0.995, max(0.6, max(scores) + 0.1))
    identifier = "ON-" + uuid.uuid4().hex
    with (
        store.segment_lock.read(deadline=time.monotonic() + 3),
        principal.transaction(store, actor, ("admin",), write=True) as (db, actor),
    ):
        evidence_scope.recheck(db, actor, records)
        _authenticated(db, actor, records)
        if (
            db.execute(
                "SELECT count(*) FROM online_analytics_models WHERE tenant=? AND state!='retired'",
                (actor["tenant"],),
            ).fetchone()[0]
            >= 64
        ):
            raise CapacityError("Retire an old online baseline before creating another")
        db.execute(
            "INSERT INTO online_analytics_models VALUES(?,?,?,?,?,1,'pending_review',?,?,NULL,NULL,?)",
            (
                identifier,
                actor["tenant"],
                actor["name"],
                data["name"],
                encode(sorted(set(indexes))),
                encode(snapshot),
                _hash(snapshot),
                time.time(),
            ),
        )
        db.execute(
            "INSERT INTO online_analytics_state VALUES(?,0,'[]',?,NULL)",
            (identifier, time.time()),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "online.baseline.train",
            {
                "id": identifier,
                "normal_originals": len(ids),
                "version": snapshot["river_version"],
            },
        )
    return {
        "id": identifier,
        "state": "pending_review",
        "revision": 1,
        "name": data["name"],
        "indexes": sorted(set(indexes)),
        "threshold": snapshot["threshold"],
        "normal_events": len(ids),
    }


def _model(db, actor, identifier, active=False):
    row = db.execute(
        "SELECT * FROM online_analytics_models WHERE tenant=? AND id=?",
        (actor["tenant"], identifier),
    ).fetchone()
    if not row or not principal.contains(
        actor["allowed_indexes"], json.loads(row["indexes"])
    ):
        raise KeyError("Online baseline not found")
    snapshot = json.loads(row["body"])
    if _hash(snapshot) != row["digest"]:
        raise ConflictError("Online baseline integrity mismatch")
    if snapshot.get("feature_contract_digest") != FEATURE_CONTRACT_DIGEST:
        raise ConflictError("Online feature contract changed; review a new baseline")
    if active and row["state"] != "active":
        raise PermissionError("Independently reviewed baseline required")
    for name in [row["owner"]] + ([row["reviewer"]] if active else []):
        user = principal.current(
            db, {"name": name, "tenant": actor["tenant"], "role": "admin"}, ("admin",)
        )
        if not principal.contains(user["allowed_indexes"], json.loads(row["indexes"])):
            raise PermissionError("Online baseline owner/reviewer scope revoked")
    if active and row["reviewer"] == row["owner"]:
        raise PermissionError("Independent baseline review required")
    for ref in snapshot["normal_originals"]:
        proof = db.execute(
            "SELECT digest FROM receipts WHERE tenant=? AND event_id=?",
            (actor["tenant"], ref["event_id"]),
        ).fetchone()
        if not proof or proof["digest"] != ref["admission_digest"]:
            raise ConflictError("Normal training original changed")
        source = db.execute(
            "SELECT s.source_version,r.version,r.state,r.owner,r.index_name FROM source_event_receipts s JOIN source_registry r ON r.id=s.source_id AND r.tenant=s.tenant WHERE s.tenant=? AND s.event_id=?",
            (actor["tenant"], ref["event_id"]),
        ).fetchone()
        if not source or source[0] != source[1] or source[2] != "active":
            raise PermissionError("Normal baseline source revoked")
        source_owner = principal.current(
            db,
            {"name": source["owner"], "tenant": actor["tenant"], "role": "analyst"},
            ("admin", "analyst"),
        )
        if not principal.contains(
            source_owner["allowed_indexes"], [source["index_name"]]
        ):
            raise PermissionError("Normal source owner scope revoked")
    return row, snapshot


def review(store, who, identifier, data):
    if (
        not isinstance(data, dict)
        or set(data) != {"expected_revision", "approve", "reason"}
        or type(data["approve"]) is not bool
        or not isinstance(data["reason"], str)
        or not 5 <= len(data["reason"]) <= 1000
    ):
        raise ValueError("Independent baseline review required")
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        row, _ = _model(db, actor, identifier)
        if row["state"] == "retired":
            raise ConflictError("Retired baseline cannot be reactivated")
        if row["owner"] == actor["name"]:
            raise PermissionError("Independent reviewer required")
        if (
            type(data["expected_revision"]) is not int
            or data["expected_revision"] != row["revision"]
        ):
            raise ConflictError("Baseline revision changed")
        state = "active" if data["approve"] else "disabled"
        if row["state"] != "pending_review":
            if row["state"] == state and row["reviewer"] == actor["name"]:
                return {
                    "id": identifier,
                    "state": state,
                    "revision": row["revision"],
                    "duplicate": True,
                }
            raise ConflictError("Create a new baseline for a fresh review")
        db.execute(
            "UPDATE online_analytics_models SET state=?,reviewer=?,reason=?,updated=? WHERE id=?",
            (state, actor["name"], data["reason"], time.time(), identifier),
        )
        cursor = db.execute(
            "SELECT coalesce(max(seq),0) FROM online_analytics_outbox WHERE tenant=?",
            (actor["tenant"],),
        ).fetchone()[0]
        db.execute(
            "UPDATE online_analytics_state SET cursor=?,scores='[]',updated=?,error=NULL WHERE model_id=?",
            (cursor, time.time(), identifier),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "online.baseline.review",
            {"id": identifier, "state": state, "reason": data["reason"]},
        )
        return {"id": identifier, "state": state, "revision": row["revision"]}


def retire(store, who, identifier, reason):
    if not isinstance(reason, str) or not 5 <= len(reason) <= 1000:
        raise ValueError("Retirement reason required")
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        row, _ = _model(db, actor, identifier)
        db.execute(
            "UPDATE online_analytics_models SET state='retired',updated=? WHERE id=?",
            (time.time(), identifier),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "online.baseline.retire",
            {"id": identifier, "reason": reason, "digest": row["digest"]},
        )
        return {"id": identifier, "state": "retired", "history_preserved": True}


def analyze(store, who, data, *, next_cursor=None):
    if not isinstance(data, dict) or set(data) != {"model_id", "event_ids"}:
        raise ValueError("model_id and event_ids required")
    ids = _ids(data["event_ids"])
    if not backend_status()["available"]:
        return {"status": "unavailable", **backend_status()}
    with principal.transaction(store, who, ("admin", "analyst")) as (db, actor):
        row, snapshot = _model(db, actor, data["model_id"], True)
        state = db.execute(
            "SELECT * FROM online_analytics_state WHERE model_id=?", (row["id"],)
        ).fetchone()
        old_cursor = state["cursor"]
        history = json.loads(state["scores"])
    records = evidence_scope.originals(store, actor, ids)
    if not principal.contains(
        json.loads(row["indexes"]), sorted({r["index_name"] for r in records.values()})
    ):
        raise PermissionError("Original outside baseline scope")
    estimator = _estimator(snapshot)
    scores = [float(estimator.score_one(features(records[eid]))) for eid in ids]
    live = next_cursor is not None
    drift, history = drift_scores(history, scores) if live else (False, history)
    anomaly = any(score >= snapshot["threshold"] for score in scores)
    run = {
        "schema": SCHEMA,
        "id": "ON-RUN-" + uuid.uuid4().hex,
        "tenant": actor["tenant"],
        "owner": actor["name"],
        "model_id": row["id"],
        "model_digest": row["digest"],
        "revision": row["revision"],
        "indexes": json.loads(row["indexes"]),
        "event_ids": ids,
        "originals": _references(records),
        "scores": scores,
        "threshold": snapshot["threshold"],
        "anomaly": anomaly,
        "drift": drift,
        "mode": "live" if live else "shadow",
        "created": time.time(),
        "status": "completed",
        "frozen_baseline": True,
        "automatic_training": False,
        "malicious_probability": None,
        "signal_id": None,
    }
    with (
        store.segment_lock.read(deadline=time.monotonic() + 3),
        principal.transaction(store, actor, ("admin", "analyst"), write=True) as (
            db,
            actor,
        ),
    ):
        fresh, _ = _model(db, actor, row["id"], True)
        if fresh["digest"] != row["digest"]:
            raise ConflictError("Baseline changed during inference")
        evidence_scope.recheck(db, actor, records)
        _authenticated(db, actor, records)
        latest = db.execute(
            "SELECT cursor,scores FROM online_analytics_state WHERE model_id=?",
            (row["id"],),
        ).fetchone()
        if latest["cursor"] != old_cursor or latest["scores"] != state["scores"]:
            raise ConflictError("Concurrent online stream update; retry")
        if live and (anomaly or drift):
            signal = intelligence.publish_in_transaction(
                store,
                db,
                actor,
                {
                    "event_ids": ids,
                    "kind": "finding",
                    "rule_id": ("online:drift:" if drift else "online:anomaly:")
                    + row["id"],
                    "rule_revision": row["revision"],
                    "definition_digest": row["digest"],
                    "features": {
                        "online_anomaly_score": max(scores),
                        "distribution_drift": drift,
                        "model_family": "river_hst_adwin",
                        "frozen_baseline": True,
                    },
                    "severity": "medium" if anomaly else "low",
                    "confidence_grade": "reviewed_online_baseline_change",
                    "metadata": {
                        "online_run_id": run["id"],
                        "model_id": row["id"],
                        "automatic_endpoint_authorization": False,
                    },
                },
            )
            run["signal_id"] = signal["id"]
        db.execute(
            "INSERT INTO online_analytics_runs VALUES(?,?,?,?,?,?,?,?,?,0)",
            (
                run["id"],
                actor["tenant"],
                row["id"],
                row["indexes"],
                run["created"],
                int(anomaly),
                int(drift),
                encode(run),
                _hash(run),
            ),
        )
        if live:
            db.execute(
                "UPDATE online_analytics_state SET cursor=?,scores=?,updated=?,error=NULL WHERE model_id=?",
                (next_cursor, encode(history), time.time(), row["id"]),
            )
        # Permanently retain run identity and input hashes; release bulky normal
        # score details beyond the recent working set, never live findings.
        normal = [
            r[0]
            for r in db.execute(
                "SELECT id FROM online_analytics_runs WHERE tenant=? AND model_id=? AND anomaly=0 AND drift=0 AND compact=0 ORDER BY created DESC LIMIT -1 OFFSET 128",
                (actor["tenant"], row["id"]),
            )
        ]
        for identifier in normal:
            previous = db.execute(
                "SELECT body,digest FROM online_analytics_runs WHERE id=?",
                (identifier,),
            ).fetchone()
            old = json.loads(previous["body"])
            hold = db.execute(
                "SELECT hold FROM policies WHERE tenant=?", (actor["tenant"],)
            ).fetchone()
            case_ref = db.execute(
                "SELECT 1 FROM record_case_evidence_refs WHERE tenant=? AND event_id IN(SELECT value FROM json_each(?)) AND kind IN('bookmark','contribution') LIMIT 1",
                (actor["tenant"], encode(old["event_ids"])),
            ).fetchone()
            if hold and hold[0] or case_ref:
                continue
            old_scores = old.pop("scores")
            old["score_summary"] = {"min": min(old_scores), "max": max(old_scores)}
            old["details_compacted"] = True
            old["full_run_digest"] = previous["digest"]
            db.execute(
                "UPDATE online_analytics_runs SET body=?,digest=?,compact=1 WHERE id=?",
                (encode(old), _hash(old), identifier),
            )
        return run


def validate_parent(store, db, actor, body, memo=None):
    try:
        if not isinstance(body, dict) or not isinstance(body.get("metadata"), dict):
            return False
        identifier = body["metadata"].get("online_run_id")
        row = db.execute(
            "SELECT * FROM online_analytics_runs WHERE tenant=? AND id=?",
            (actor["tenant"], identifier),
        ).fetchone()
        if not row or row["compact"]:
            return False
        run = json.loads(row["body"])
        model, _ = _model(db, actor, row["model_id"], True)
        for ref in run["originals"]:
            receipt = db.execute(
                "SELECT digest,received FROM receipts WHERE tenant=? AND event_id=?",
                (actor["tenant"], ref["event_id"]),
            ).fetchone()
            source = db.execute(
                "SELECT s.source_version,r.version,r.state,r.owner,r.index_name FROM source_event_receipts s JOIN source_registry r ON r.id=s.source_id AND r.tenant=s.tenant WHERE s.tenant=? AND s.event_id=?",
                (actor["tenant"], ref["event_id"]),
            ).fetchone()
            if (
                not receipt
                or receipt["digest"] != ref["admission_digest"]
                or receipt["received"] != ref["received"]
            ):
                return False
            if (
                not source
                or source[0] != source[1]
                or source["state"] != "active"
                or source["index_name"] != ref["index_name"]
            ):
                return False
            owner = principal.current(
                db,
                {"name": source["owner"], "tenant": actor["tenant"], "role": "analyst"},
                ("admin", "analyst"),
            )
            if not principal.contains(owner["allowed_indexes"], [ref["index_name"]]):
                return False
        expected_rule = (
            "online:drift:" if run["drift"] else "online:anomaly:"
        ) + model["id"]
        return (
            _hash(run) == row["digest"]
            and body.get("kind") == "finding"
            and body.get("mode") == "live"
            and run["signal_id"] == body["id"]
            and run.get("mode") == "live"
            and sorted(run["event_ids"]) == sorted(body["event_ids"])
            and body["rule_id"] == expected_rule
            and body["rule_revision"] == model["revision"]
            and body["definition_digest"] == model["digest"]
            and (run["anomaly"] or run["drift"])
            and body["metadata"].get("model_id") == model["id"]
            and body["features"]
            == {
                "online_anomaly_score": max(run["scores"]),
                "distribution_drift": run["drift"],
                "model_family": "river_hst_adwin",
                "frozen_baseline": True,
            }
        )
    except (KeyError, PermissionError, ValueError, ConflictError):
        return False


def journal_indexed(store, db, indexed_rows):
    scopes = {}
    for row in indexed_rows:
        tenant = row["tenant"]
        if tenant not in scopes:
            scopes[tenant] = [
                set(json.loads(r[0]))
                for r in db.execute(
                    "SELECT indexes FROM online_analytics_models WHERE tenant=? AND state='active'",
                    (tenant,),
                )
            ]
        payload = (
            json.loads(row["payload"])
            if isinstance(row["payload"], str)
            else row["payload"]
        )
        index = payload.get("index", payload.get("index_name", "main"))
        if any(index in s for s in scopes[tenant]):
            db.execute(
                "INSERT OR IGNORE INTO online_analytics_outbox(tenant,event_id,index_name,received) VALUES(?,?,?,?)",
                (tenant, row["event_id"], index, row["received"]),
            )


def run_due(store, cancel=None, maximum=32):
    with store.control() as db:
        rows = [
            dict(r)
            for r in db.execute(
                "SELECT m.*,s.cursor FROM online_analytics_models m JOIN online_analytics_state s ON s.model_id=m.id WHERE m.state='active' AND EXISTS(SELECT 1 FROM online_analytics_outbox o WHERE o.tenant=m.tenant AND o.seq>s.cursor AND o.index_name IN(SELECT value FROM json_each(m.indexes))) ORDER BY s.updated,m.id LIMIT 8"
            )
        ]
    results = []
    for model in rows:
        if cancel is not None and cancel.is_set():
            break
        with store.control() as db:
            pending = [
                dict(r)
                for r in db.execute(
                    "SELECT * FROM online_analytics_outbox WHERE tenant=? AND seq>? AND index_name IN (SELECT value FROM json_each(?)) ORDER BY seq LIMIT ?",
                    (
                        model["tenant"],
                        model["cursor"],
                        model["indexes"],
                        min(32, maximum),
                    ),
                )
            ]
        if not pending:
            continue
        try:
            actor = {"name": model["owner"], "tenant": model["tenant"], "role": "admin"}
            with principal.transaction(store, actor, ("admin",)) as (db, current):
                _model(db, current, model["id"], True)
            valid = []
            for event in pending:
                try:
                    records = evidence_scope.originals(
                        store, current, [event["event_id"]]
                    )
                    with principal.transaction(store, current, ("admin",)) as (
                        db,
                        current,
                    ):
                        evidence_scope.recheck(db, current, records)
                        _authenticated(db, current, records)
                except (PermissionError, KeyError, ConflictError, ValueError) as exc:
                    if valid:
                        break
                    # One unauthenticated/expired original cannot poison the
                    # live cursor forever. Keep a durable exclusion, never a
                    # score or drift update, and revalidate the model authority.
                    with principal.transaction(
                        store, current, ("admin",), write=True
                    ) as (db, current):
                        fresh, _ = _model(db, current, model["id"], True)
                        state = db.execute(
                            "SELECT cursor FROM online_analytics_state WHERE model_id=?",
                            (model["id"],),
                        ).fetchone()
                        if state["cursor"] != model["cursor"]:
                            raise ConflictError("Concurrent exclusion; retry")
                        excluded = {
                            "schema": SCHEMA,
                            "id": "ON-RUN-" + uuid.uuid4().hex,
                            "tenant": model["tenant"],
                            "owner": model["owner"],
                            "model_id": model["id"],
                            "model_digest": fresh["digest"],
                            "indexes": json.loads(model["indexes"]),
                            "event_ids": [event["event_id"]],
                            "created": time.time(),
                            "status": "excluded",
                            "mode": "live",
                            "anomaly": False,
                            "drift": False,
                            "reason": type(exc).__name__ + ": " + str(exc)[:300],
                            "signal_id": None,
                        }
                        db.execute(
                            "INSERT INTO online_analytics_runs VALUES(?,?,?,?,?,0,0,?,?,1)",
                            (
                                excluded["id"],
                                model["tenant"],
                                model["id"],
                                model["indexes"],
                                excluded["created"],
                                encode(excluded),
                                _hash(excluded),
                            ),
                        )
                        db.execute(
                            "UPDATE online_analytics_state SET cursor=?,updated=?,error=? WHERE model_id=?",
                            (
                                event["seq"],
                                time.time(),
                                excluded["reason"],
                                model["id"],
                            ),
                        )
                        store.audit(
                            db,
                            model["tenant"],
                            model["owner"],
                            "online.original.excluded",
                            {
                                "model_id": model["id"],
                                "run_id": excluded["id"],
                                "event_id": event["event_id"],
                                "reason": excluded["reason"],
                            },
                        )
                    break
                valid.append(event)
            pending = valid
            if not pending:
                continue
            # The frozen outbox admission generation is checked before scoring.
            with store.control() as db:
                for event in pending:
                    receipt = db.execute(
                        "SELECT received FROM receipts WHERE tenant=? AND event_id=?",
                        (model["tenant"], event["event_id"]),
                    ).fetchone()
                    if not receipt or receipt[0] != event["received"]:
                        raise ConflictError(
                            "Online outbox admission generation changed"
                        )
            results.append(
                analyze(
                    store,
                    actor,
                    {
                        "model_id": model["id"],
                        "event_ids": [r["event_id"] for r in pending],
                    },
                    next_cursor=pending[-1]["seq"],
                )
            )
        except (
            PermissionError,
            KeyError,
            ConflictError,
            ValueError,
            CapacityError,
        ) as exc:
            with store.control() as db:
                db.execute(
                    "UPDATE online_analytics_state SET updated=?,error=? WHERE model_id=?",
                    (
                        time.time(),
                        type(exc).__name__ + ": " + str(exc)[:300],
                        model["id"],
                    ),
                )
                if isinstance(exc, PermissionError):
                    db.execute(
                        "UPDATE online_analytics_models SET state='suspended' WHERE id=?",
                        (model["id"],),
                    )
    with store.control() as db:
        for tenant in {row["tenant"] for row in rows}:
            frontier = db.execute(
                "SELECT min(s.cursor) FROM online_analytics_state s JOIN online_analytics_models m ON m.id=s.model_id WHERE m.tenant=? AND m.state='active'",
                (tenant,),
            ).fetchone()[0]
            if frontier is not None:
                db.execute(
                    "DELETE FROM online_analytics_outbox WHERE seq IN (SELECT seq FROM online_analytics_outbox WHERE tenant=? AND seq<=? ORDER BY seq LIMIT 256)",
                    (tenant, frontier),
                )
    return {
        "processed": sum(len(r.get("event_ids", [])) for r in results),
        "runs": results,
    }


def protected_ids(db, tenant, ids):
    if not ids:
        return set()
    protected = {
        r[0]
        for r in db.execute(
            "SELECT o.event_id FROM online_analytics_outbox o JOIN online_analytics_state s ON o.seq>s.cursor JOIN online_analytics_models m ON m.id=s.model_id WHERE o.tenant=? AND m.tenant=o.tenant AND m.state='active' AND o.event_id IN (SELECT value FROM json_each(?))",
            (tenant, encode(ids)),
        )
    }
    for row in db.execute(
        "SELECT body FROM online_analytics_models WHERE tenant=? AND state!='retired'",
        (tenant,),
    ):
        protected.update(
            set(ids) & {r["event_id"] for r in json.loads(row[0])["normal_originals"]}
        )
    return protected


def list_models(store, who):
    with principal.transaction(store, who) as (db, actor):
        return {
            "items": [
                {
                    "id": r["id"],
                    "name": r["name"],
                    "owner": r["owner"],
                    "reviewer": r["reviewer"],
                    "state": r["state"],
                    "revision": r["revision"],
                    "indexes": json.loads(r["indexes"]),
                    "digest": r["digest"],
                    "threshold": json.loads(r["body"])["threshold"],
                    "stream": {
                        "cursor": r["cursor"],
                        "updated": r["stream_updated"],
                        "error": r["stream_error"],
                    },
                }
                for r in db.execute(
                    "SELECT m.*,s.cursor,s.updated AS stream_updated,s.error AS stream_error FROM online_analytics_models m LEFT JOIN online_analytics_state s ON s.model_id=m.id WHERE tenant=? ORDER BY m.updated DESC",
                    (actor["tenant"],),
                )
                if principal.contains(
                    actor["allowed_indexes"], json.loads(r["indexes"])
                )
            ]
        }


def list_runs(store, who):
    with principal.transaction(store, who) as (db, actor):
        return {
            "items": [
                json.loads(r["body"])
                for r in db.execute(
                    "SELECT * FROM online_analytics_runs WHERE tenant=? ORDER BY created DESC LIMIT 100",
                    (actor["tenant"],),
                )
                if principal.contains(
                    actor["allowed_indexes"], json.loads(r["indexes"])
                )
            ]
        }


def status(store, who):
    return {
        "backend": backend_status(),
        "models": list_models(store, who)["items"],
        "live_telemetry_training": False,
        "recent_normal_details": 128,
        "score_history": 512,
        "automatic_endpoint_authorization": False,
    }


def register(app, store, runtime, who, body):
    from fastapi import Request
    from starlette.concurrency import run_in_threadpool

    @app.get("/api/online-analytics/status")
    async def get_status(request: Request):
        return await run_in_threadpool(status, store, who(request))

    @app.get("/api/online-analytics/models")
    async def models(request: Request):
        return await run_in_threadpool(list_models, store, who(request))

    @app.post("/api/online-analytics/models", status_code=201)
    async def fit(request: Request):
        return await run_in_threadpool(
            train, store, who(request, ("admin",)), await body(request)
        )

    @app.post("/api/online-analytics/models/{identifier}/review")
    async def approve(identifier: str, request: Request):
        return await run_in_threadpool(
            review, store, who(request, ("admin",)), identifier, await body(request)
        )

    @app.post("/api/online-analytics/models/{identifier}/retire")
    async def disable(identifier: str, request: Request):
        data = await body(request)
        if not isinstance(data, dict) or set(data) != {"reason"}:
            raise ValueError("Retirement reason required")
        return await run_in_threadpool(
            retire, store, who(request, ("admin",)), identifier, data["reason"]
        )

    @app.get("/api/online-analytics/runs")
    async def runs(request: Request):
        return await run_in_threadpool(list_runs, store, who(request))

    @app.post("/api/online-analytics/runs", status_code=201)
    async def infer(request: Request):
        return await run_in_threadpool(
            analyze, store, who(request, ("admin", "analyst")), await body(request)
        )
