"""Durable reviewed research-run -> common ML signal bridge.

Publication is retried independently from model cursor commits. The same
immutable run deterministically yields the same signal and grants no response.
"""

import json
import time

from . import (
    evidence_scope,
    intelligence,
    migrations,
    principal,
    release_manifest,
    research_behavior,
)
from .storage import CapacityError, ConflictError


def initialize(store):
    migrations.apply_store(
        store,
        "advanced_intelligence",
        [
            "CREATE TABLE IF NOT EXISTS advanced_research_publications(run_id TEXT PRIMARY KEY,tenant TEXT NOT NULL,signal_id TEXT,state TEXT NOT NULL,error TEXT,attempted REAL NOT NULL)",
        ],
    )


def _data(run):
    scores = [r["edge_anomaly_score"] for r in run["results"]]
    data = {
        "event_ids": run["event_ids"],
        "kind": "ml",
        "mode": "live",
        "rule_id": "ml:research:" + run["model_id"],
        "rule_revision": run["model_revision"],
        "model_digest": run["model_digest"],
        "definition_digest": run["model_digest"],
        "context_digest": release_manifest.digest(
            ["research-run", run["id"], release_manifest.digest(run)]
        ),
        "features": {
            "research_anomaly_score": max(scores),
            "model_family": "research_edge",
            "research_anomalous_events": sum(
                bool(r["anomaly"]) for r in run["results"]
            ),
            "causal_summary_paths": len(run["graph"].get("summary_paths", [])),
            "long_horizon_sketch_distance": run["graph"]
            .get("sketch", {})
            .get("distance_from_prior", 0),
        },
        "severity": "high",
        "confidence_grade": "reviewed_cpu_relation_anomaly",
        "metadata": {
            "research_run_id": run["id"],
            "graph_digest": release_manifest.digest(run["graph"]),
            "paper_reproduction_claim": False,
            "automatic_endpoint_authorization": False,
        },
    }
    decision = run["decision"]
    if run.get('long_evidence'):
        data['metadata']['evidence_manifest'] = run['long_evidence']
    if decision.get("fusion_contract_digest"):
        data["features"].update(
            {
                "research_fusion_score": decision["score"],
                "research_fusion_threshold": decision["threshold"],
                **{
                    "research_component_" + key: value
                    for key, value in decision["components"].items()
                },
            }
        )
        data["confidence_grade"] = "reviewed_cpu_fused_behavior_anomaly"
        data["metadata"].update(
            {
                "decision_method": decision["method"],
                "fusion_contract_digest": decision["fusion_contract_digest"],
                "fusion_reasons": decision["reasons"],
                "fusion_ablation": decision["ablation"],
            }
        )
    return data


def _verified(store, db, actor, identifier, memo=None):
    row = db.execute(
        "SELECT r.owner,r.indexes,m.indexes AS model_indexes "
        "FROM research_behavior_runs r LEFT JOIN research_behavior_models m "
        "ON m.tenant=r.tenant AND m.id=r.model_id WHERE r.tenant=? AND r.id=?",
        (actor["tenant"], identifier),
    ).fetchone()
    if (
        not row
        or row["model_indexes"] is None
        or not principal.contains(actor["allowed_indexes"], json.loads(row["indexes"]))
        or not principal.contains(actor["allowed_indexes"], json.loads(row["model_indexes"]))
    ):
        raise KeyError("Research run not in complete current scope")
    owner = principal.current(
        db,
        {"name": row["owner"], "tenant": actor["tenant"], "role": "analyst"},
        ("admin", "analyst"),
    )
    return research_behavior.validate_publication(
        store, db, owner, identifier, memo=memo
    )


def _association(store, db, actor, original_ids, fallback):
    """Same reported-flow association, freshly batch-projected in this TX."""
    from . import identity_resolver

    records = research_behavior._originals(store, actor, original_ids, db=db)
    for record in sorted(
        records.values(), key=lambda r: (r["event_time"], r["event_id"]), reverse=True
    ):
        projection = record["projection"]
        if projection and projection.get("flow"):
            key = identity_resolver.relation_key(store, actor, projection, "flow")
            if key:
                return key
    return fallback


def validate_signal(store, db, actor, data, memo=None):
    if not isinstance(data, dict) or not isinstance(data.get("metadata"), dict):
        raise ValueError("Typed research run metadata required")  # noqa: TRY004 - API validation uses HTTP 400.
    identifier = data["metadata"].get("research_run_id")
    if not isinstance(identifier, str):
        raise ValueError("Exact research run binding required")  # noqa: TRY004 - API validation uses HTTP 400.
    run = _verified(store, db, actor, identifier, memo=memo)
    expected = _data(run)
    expected_entity = _association(
        store,
        db,
        actor,
        run["event_ids"],
        release_manifest.digest([actor["tenant"], "research", identifier]),
    )
    if data.get("entity_key") != expected_entity:
        raise ConflictError(
            "Research signal entity differs from its exact original association"
        )
    for key in (
        "kind",
        "mode",
        "event_ids",
        "rule_id",
        "rule_revision",
        "model_digest",
        "definition_digest",
        "context_digest",
        "features",
        "metadata",
        "severity",
        "confidence_grade",
    ):
        value = data.get(key)
        if (
            sorted(value) if key == "event_ids" and isinstance(value, list) else value
        ) != (sorted(expected[key]) if key == "event_ids" else expected[key]):
            raise ConflictError("Research signal differs from immutable run: " + key)
    return run


def validate_parent(store, db, actor, body, memo=None):
    try:
        validate_signal(
            store,
            db,
            actor,
            body,
            memo=memo.get("research") if memo is not None else None,
        )
        row = db.execute(
            "SELECT signal_id,state FROM advanced_research_publications WHERE tenant=? AND run_id=?",
            (actor["tenant"], body["metadata"]["research_run_id"]),
        ).fetchone()
        return bool(
            row and row["state"] == "published" and row["signal_id"] == body["id"]
        )
    except (KeyError, PermissionError, ValueError, ConflictError):
        return False


def publish_run(store, who, identifier):
    with (
        store.segment_lock.read(deadline=time.monotonic() + 10),
        principal.transaction(store, who, ("admin", "analyst"), write=True) as (
            db,
            actor,
        ),
        intelligence._authority_memo(db) as memo,
    ):
        row=db.execute('SELECT body FROM research_behavior_runs WHERE tenant=? AND id=?',(actor['tenant'],identifier)).fetchone()
        if not row:raise KeyError('Research run unavailable')
        # These scoped raw IDs are a read hint only. _verified below still
        # checks the immutable run, current owner, live review and every proof.
        body=json.loads(row['body'])
        raw_ids=body.get('event_ids')
        if not isinstance(raw_ids,list) or not 1<=len(raw_ids)<=32:
            raise ConflictError('Bounded research original hint required')
        descriptor=body.get('long_evidence')
        if isinstance(descriptor,dict) and isinstance(descriptor.get('snapshot_id'),str):
            snapshot=db.execute('SELECT body,digest,indexes FROM research_horizon_snapshots WHERE tenant=? AND id=? AND length(body)<=?',
                (actor['tenant'],descriptor['snapshot_id'],8*1024*1024)).fetchone()
            if (snapshot and snapshot['digest']==descriptor.get('digest')
                and principal.contains(actor['allowed_indexes'],json.loads(snapshot['indexes']))):
                long_proofs=json.loads(snapshot['body']).get('originals',[])
                if not isinstance(long_proofs,list) or len(long_proofs)>1024:
                    raise ConflictError('Bounded research long hint required')
                raw_ids=list(dict.fromkeys(raw_ids+[proof['event_id'] for proof in long_proofs]))
        with evidence_scope.prefetch_transaction(store,db,[(actor,raw_ids)]):
            run = _verified(store, db, actor, identifier, memo=memo['research'])
            data = _data(run)
            # A reported flow is an association for cross-sensor confirmation.
            # It does not become verified process/socket ownership.
            data["entity_key"] = _association(
                store,
                db,
                actor,
                run["event_ids"],
                release_manifest.digest([actor["tenant"], "research", identifier]),
            )
            signal = intelligence.publish_in_transaction(store, db, actor, data, memo=memo)
            db.execute(
                "INSERT INTO advanced_research_publications VALUES(?,?,?,'published',NULL,?) ON CONFLICT(run_id) DO UPDATE SET signal_id=excluded.signal_id,state='published',error=NULL,attempted=excluded.attempted",
                (identifier, actor["tenant"], signal["id"], time.time()),
            )
            return signal


def run_due(store, cancel=None, maximum=16):
    with store.control() as db:
        rows = [
            dict(r)
            for r in db.execute(
                "SELECT r.id,r.tenant,r.owner FROM research_behavior_runs r LEFT JOIN advanced_research_publications p ON p.run_id=r.id WHERE r.mode='live' AND json_extract(r.body,'$.decision.publishable')=1 AND (p.run_id IS NULL OR (p.state='pending' AND p.attempted<?)) ORDER BY r.created,r.id LIMIT ?",
                (time.time() - 30, min(32, maximum)),
            )
        ]
    published = excluded = 0
    for row in rows:
        if cancel is not None and cancel.is_set():
            break
        try:
            publish_run(
                store,
                {"name": row["owner"], "tenant": row["tenant"], "role": "analyst"},
                row["id"],
            )
            published += 1
        except (
            KeyError,
            PermissionError,
            ValueError,
            ConflictError,
            CapacityError,
        ) as exc:
            state = "pending" if isinstance(exc, CapacityError) else "excluded"
            with store.control() as db:
                db.execute(
                    "INSERT INTO advanced_research_publications VALUES(?,?,NULL,?,?,?) ON CONFLICT(run_id) DO UPDATE SET state=excluded.state,error=excluded.error,attempted=excluded.attempted",
                    (
                        row["id"],
                        row["tenant"],
                        state,
                        type(exc).__name__ + ": " + str(exc)[:500],
                        time.time(),
                    ),
                )
            excluded += 1
    return {"published": published, "excluded": excluded}
