"""Private pure replay proof reuse inside one immutable publication transaction.

Permissions are not memoized. Each reuse reads the current model/review through
the caller and rechecks every raw admission, source pin and owner. The opaque
proof only avoids copying/projecting/replaying the same raw facts a second time.
"""

import json
from dataclasses import dataclass

from . import evidence_scope

_KEY = object()


@dataclass(frozen=True)
class _Proof:
    store: object
    db: object
    actor: tuple
    binding: object
    run_body: str
    run_digest: str
    model_snapshot: str
    model_pin: tuple
    originals: tuple
    long_row: object


def _actor(actor):
    return actor["tenant"], actor["name"], actor["role"], tuple(actor["allowed_indexes"])


def _pin(model):
    return tuple(model.get(key) for key in ("id", "digest", "revision", "state", "review_mode", "reviewer", "reviewed", "indexes", "owner"))


def _long_row(db, actor, run):
    descriptor = run.get("long_evidence")
    if descriptor is None:
        return None
    row = db.execute("SELECT * FROM research_horizon_snapshots WHERE tenant=? AND id=?",
                     (actor["tenant"], descriptor["snapshot_id"])).fetchone()
    return dict(row) if row is not None else None


def reuse(store, db, actor, row, run, model, memo):
    if not isinstance(memo, dict) or not db.in_transaction:
        return False
    entries = memo.get(_KEY)
    proof = entries.get((run["id"], _actor(actor))) if isinstance(entries, dict) else None
    if (type(proof) is not _Proof or proof.store is not store or proof.db is not db
            or proof.actor != _actor(actor)
            or proof.run_body != row["body"] or proof.run_digest != row["digest"]
            or proof.model_snapshot != model["snapshot"] or proof.model_pin != _pin(model)
            or proof.long_row != _long_row(db, actor, run)):
        return False
    # Existing guarded raw prefetch remains the only raw reuse authority.
    # A new prefetch/transaction, even for identical IDs, has a different token.
    binding = evidence_scope._prefetched_reference_guard(store, db, actor, proof.originals)
    if binding is None or binding is not proof.binding:
        return False
    from . import research_behavior

    research_behavior._verify_sources(db, actor, proof.originals, required=True)
    if proof.long_row is not None:
        # Do not trust a caller-mutable string-keyed pure-result cache as the
        # source of a later closure. Recreate it from the pinned row bytes.
        memo["long-verified:" + run["id"]] = (None, json.loads(proof.long_row["body"]))
    return True


def remember(store, db, actor, row, run, model, memo, long_body=None):
    if not isinstance(memo, dict) or not db.in_transaction:
        return
    proofs = {proof["event_id"]: proof for proof in (long_body or {}).get("originals", [])}
    proofs.update({proof["event_id"]: proof for proof in run["originals"]})
    originals = tuple(proofs[key] for key in sorted(proofs))
    binding = evidence_scope._prefetched_reference_guard(store, db, actor, originals)
    if binding is None:
        return
    # Store independent proof dictionaries: a returned run or a caller's pure
    # result cannot mutate the subsequent authority comparison.
    originals = tuple({**proof, "source_authority": dict(proof["source_authority"])
                       if isinstance(proof.get("source_authority"), dict) else None}
                      for proof in originals)
    entries = memo.setdefault(_KEY, {})
    if not isinstance(entries, dict):
        return
    if len(entries) >= 8:
        entries.pop(next(iter(entries)))
    entries[(run["id"], _actor(actor))] = _Proof(
        store, db, _actor(actor), binding, row["body"], row["digest"],
        model["snapshot"], _pin(model), originals, _long_row(db, actor, run),
    )
