"""Independently reviewed bounded operational rehearsals with durable receipts."""

import json
import threading
import time
import uuid

from . import access, migrations, principal, release_manifest
from .storage import CapacityError, ConflictError, encode

KINDS = {"response_twin", "recovery_process", "integrity_bootstrap"}
_RUNNER = threading.Lock()


def initialize(store):
    migrations.apply_store(
        store,
        "ops_qualification",
        [
            "CREATE TABLE IF NOT EXISTS ops_qualification_plans(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,owner TEXT NOT NULL,editor TEXT NOT NULL,indexes TEXT NOT NULL,revision INTEGER NOT NULL,state TEXT NOT NULL,definition TEXT NOT NULL,digest TEXT NOT NULL,review TEXT,created REAL NOT NULL,updated REAL NOT NULL)",
            "CREATE TABLE IF NOT EXISTS ops_qualification_runs(id TEXT PRIMARY KEY,tenant TEXT NOT NULL,plan_id TEXT NOT NULL,revision INTEGER NOT NULL,indexes TEXT NOT NULL,requester TEXT NOT NULL,state TEXT NOT NULL,body TEXT NOT NULL,created REAL NOT NULL,updated REAL NOT NULL)",
            "CREATE INDEX IF NOT EXISTS ops_qualification_scope ON ops_qualification_runs(tenant,created DESC)",
        ],
    )


def _visible(db, actor, identifier):
    row = db.execute(
        "SELECT * FROM ops_qualification_plans WHERE tenant=? AND id=?",
        (actor["tenant"], identifier),
    ).fetchone()
    if not row or not principal.contains(
        actor["allowed_indexes"], json.loads(row["indexes"])
    ):
        raise KeyError("Operational plan not found")
    return row


def _public(row):
    return {
        **dict(row),
        "indexes": json.loads(row["indexes"]),
        "definition": json.loads(row["definition"]),
        "review": json.loads(row["review"]) if row["review"] else None,
    }


def _revision(row, value):
    if type(value) is not int or value != row["revision"]:
        raise ConflictError("Operational plan revision changed")


def save(store, who, data, identifier=None):
    if (
        not isinstance(data, dict)
        or set(data) != {"name", "indexes", "kind", "expected_revision"}
        or not isinstance(data["name"], str)
        or not 1 <= len(data["name"]) <= 120
        or not isinstance(data["kind"], str)
        or data["kind"] not in KINDS
        or type(data["expected_revision"]) is not int
        or data["expected_revision"] < 0
    ):
        raise ValueError("Exact bounded name,indexes,kind,expected_revision required")
    indexes = access.validate(data["indexes"])
    if not indexes or indexes == ["*"] or len(indexes) > 8:
        raise ValueError("Operational plan requires 1..8 exact indexes")
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        if not principal.contains(actor["allowed_indexes"], indexes):
            raise PermissionError("Operational indexes exceed current scope")
        old = _visible(db, actor, identifier) if identifier else None
        if (old["revision"] if old else 0) != data["expected_revision"]:
            raise ConflictError("Operational plan revision changed")
        identifier, revision, now = (
            identifier or "OPS-" + uuid.uuid4().hex,
            data["expected_revision"] + 1,
            time.time(),
        )
        definition = {
            "name": data["name"],
            "indexes": sorted(indexes),
            "kind": data["kind"],
            "scope": "owned_temporary_software_rehearsal",
            "native_host_effects": 0,
            "contract": 1,
        }
        if data["kind"] == "integrity_bootstrap":
            from . import release_integrity

            definition["signer_key_id"] = release_integrity.public_identity()["key_id"]
        db.execute(
            "INSERT INTO ops_qualification_plans VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET editor=excluded.editor,indexes=excluded.indexes,revision=excluded.revision,state='pending',definition=excluded.definition,digest=excluded.digest,review=NULL,updated=excluded.updated",
            (
                identifier,
                actor["tenant"],
                old["owner"] if old else actor["name"],
                actor["name"],
                encode(indexes),
                revision,
                "pending",
                encode(definition),
                release_manifest.digest(definition),
                None,
                old["created"] if old else now,
                now,
            ),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "ops.plan.save",
            {"id": identifier, "revision": revision},
        )
        return _public(_visible(db, actor, identifier))


def _participant(db, row, name):
    actor = principal.current(
        db, {"name": name, "tenant": row["tenant"], "role": "admin"}, ("admin",)
    )
    if not principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
        raise PermissionError("Operational participant scope changed")
    return actor


def review(store, who, identifier, data):
    if (
        not isinstance(data, dict)
        or set(data) != {"expected_revision", "approve", "reason"}
        or type(data["approve"]) is not bool
        or not isinstance(data["reason"], str)
        or not 3 <= len(data["reason"]) <= 1000
    ):
        raise ValueError("Exact review revision,approve,reason required")
    with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
        row = _visible(db, actor, identifier)
        _revision(row, data["expected_revision"])
        if actor["name"] in {row["owner"], row["editor"]}:
            raise PermissionError("Independent operational reviewer required")
        for name in {row["owner"], row["editor"]}:
            _participant(db, row, name)
        if row["state"] != "pending":
            raise ConflictError("Only the pending exact plan revision can be reviewed")
        review_data = {
            "reviewer": actor["name"],
            "approve": data["approve"],
            "reason": data["reason"],
            "digest": row["digest"],
            "revision": row["revision"],
            "at": time.time(),
        }
        db.execute(
            "UPDATE ops_qualification_plans SET state=?,review=?,updated=? WHERE id=?",
            (
                "approved" if data["approve"] else "rejected",
                encode(review_data),
                time.time(),
                identifier,
            ),
        )
        store.audit(
            db,
            actor["tenant"],
            actor["name"],
            "ops.plan.review",
            {"id": identifier, "revision": row["revision"], "approve": data["approve"]},
        )
        return _public(_visible(db, actor, identifier))


def _authority(db, actor, row):
    review_data = json.loads(row["review"]) if row["review"] else {}
    if (
        row["state"] != "approved"
        or review_data.get("approve") is not True
        or review_data.get("digest") != row["digest"]
        or review_data.get("revision") != row["revision"]
        or release_manifest.digest(json.loads(row["definition"])) != row["digest"]
        or review_data.get("reviewer") in {row["owner"], row["editor"]}
    ):
        raise ConflictError("Exact independently approved operational plan required")
    for name in {row["owner"], row["editor"], review_data["reviewer"]}:
        _participant(db, row, name)
    definition = json.loads(row["definition"])
    if definition["kind"] == "integrity_bootstrap":
        from . import release_integrity

        if release_integrity.public_identity()["key_id"] != definition["signer_key_id"]:
            raise ConflictError("Configured signer changed after operational approval")
    if not principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
        raise PermissionError("Operational caller scope changed")
    return review_data


def run(store, who, identifier, data):
    if not isinstance(data, dict) or set(data) != {"expected_revision"}:
        raise ValueError("Exact expected_revision required")
    if not _RUNNER.acquire(blocking=False):
        raise CapacityError("One bounded operational rehearsal may run at a time")
    run_id, began = "OPSRUN-" + uuid.uuid4().hex, time.time()
    try:
        with principal.transaction(store, who, ("admin",), write=True) as (db, actor):
            row = _visible(db, actor, identifier)
            _revision(row, data["expected_revision"])
            approved = _authority(db, actor, row)
            snapshot = dict(row)
            receipt = {
                "id": run_id,
                "plan_id": identifier,
                "revision": row["revision"],
                "plan_digest": row["digest"],
                "review_digest": release_manifest.digest(approved),
                "requester": actor["name"],
                "reviewer": approved["reviewer"],
                "native_host_effects": 0,
                "scope": "owned_temporary_software_rehearsal",
            }
            db.execute(
                "INSERT INTO ops_qualification_runs VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    run_id,
                    actor["tenant"],
                    identifier,
                    row["revision"],
                    row["indexes"],
                    actor["name"],
                    "running",
                    encode(receipt),
                    began,
                    began,
                ),
            )
            store.audit(
                db,
                actor["tenant"],
                actor["name"],
                "ops.run.begin",
                {"id": run_id, "plan_id": identifier},
            )
        try:
            kind = json.loads(snapshot["definition"])["kind"]
            if kind == "response_twin":
                from . import response_rehearsal

                result = response_rehearsal.run()
            elif kind == "recovery_process":
                from . import operational_process_probe

                result = operational_process_probe.run()
            else:
                from . import release_integrity

                result = {
                    "passed": True,
                    "native_host_effects": 0,
                    "trust_file": release_integrity.trust_export(
                        json.loads(snapshot["definition"])["signer_key_id"],
                        {
                            "plan_id": identifier,
                            "revision": snapshot["revision"],
                            "plan_digest": snapshot["digest"],
                            "requester": snapshot["owner"],
                            "editor": snapshot["editor"],
                            "reviewer": approved["reviewer"],
                            "review_digest": release_manifest.digest(approved),
                        },
                    ),
                    "checks": [
                        {
                            "name": "independent_reviewed_exact_configured_signer_export",
                            "passed": True,
                        }
                    ],
                    "limitations": [
                        "Public trust export requires manual out-of-band fingerprint validation and local provisioning; no automatic self-trust",
                        "Manifest signing is not OS code signing or hardware remote attestation",
                    ],
                }
            state = "completed" if result.get("passed") is True else "failed"
        except Exception as exc:  # noqa: BLE001 -- Preserve a failed durable receipt for every independent probe failure.
            result = {
                "passed": False,
                "error_type": type(exc).__name__,
                "error": "Operational probe failed; inspect private service diagnostics",
                "native_host_effects": 0,
            }
            state = "failed"
        receipt.update(
            result=result,
            completed=time.time(),
            elapsed_seconds=time.time() - began,
            result_digest=release_manifest.digest(result),
        )
        # Work occurs only in disposable Stores. If an approval is revoked
        # during execution, preserve the receipt but never declare qualified.
        with store.write_lock, store.control() as db:
            try:
                current_actor = principal.current(db, actor, ("admin",))
                current = _visible(db, current_actor, identifier)
                _revision(current, snapshot["revision"])
                if current["digest"] != snapshot["digest"]:
                    raise ConflictError("Operational plan changed during run")
                _authority(db, current_actor, current)
            except (PermissionError, KeyError, ConflictError, OSError, ValueError):
                state = "authority_changed"
            if state == "authority_changed" and "trust_file" in result:
                result = {
                    "passed": False,
                    "native_host_effects": 0,
                    "reason": "signer_or_approval_authority_changed",
                }
                receipt.update(
                    result=result, result_digest=release_manifest.digest(result)
                )
            receipt["state"] = state
            receipt["qualified"] = state == "completed" and result.get("passed") is True
            db.execute(
                "UPDATE ops_qualification_runs SET state=?,body=?,updated=? WHERE id=?",
                (state, encode(receipt), time.time(), run_id),
            )
            store.audit(
                db,
                snapshot["tenant"],
                actor["name"],
                "ops.run.receipt",
                {
                    "id": run_id,
                    "state": state,
                    "result_digest": receipt["result_digest"],
                },
            )
        return get_run(store, who, run_id)
    finally:
        _RUNNER.release()


def plans(store, who):
    with principal.transaction(store, who) as (db, actor):
        return {
            "items": [
                _public(r)
                for r in db.execute(
                    "SELECT * FROM ops_qualification_plans WHERE tenant=? ORDER BY updated DESC LIMIT 100",
                    (actor["tenant"],),
                )
                if principal.contains(
                    actor["allowed_indexes"], json.loads(r["indexes"])
                )
            ]
        }


def runs(store, who):
    with principal.transaction(store, who) as (db, actor):
        return {
            "items": [
                json.loads(r["body"]) | {"state": r["state"]}
                for r in db.execute(
                    "SELECT * FROM ops_qualification_runs WHERE tenant=? ORDER BY created DESC LIMIT 100",
                    (actor["tenant"],),
                )
                if principal.contains(
                    actor["allowed_indexes"], json.loads(r["indexes"])
                )
            ]
        }


def get_run(store, who, identifier):
    with principal.transaction(store, who) as (db, actor):
        row = db.execute(
            "SELECT * FROM ops_qualification_runs WHERE id=? AND tenant=?",
            (identifier, actor["tenant"]),
        ).fetchone()
        if not row or not principal.contains(
            actor["allowed_indexes"], json.loads(row["indexes"])
        ):
            raise KeyError("Operational run not found")
        return json.loads(row["body"]) | {"state": row["state"]}


def status(store, who):
    with principal.transaction(store, who):
        return {
            "schema": "xsera.ops-qualification.v1",
            "kinds": sorted(KINDS),
            "independent_review_required": True,
            "native_host_effects": 0,
            "scope": "owned temporary Store and Python-process software rehearsal",
            "concurrent_runs": 1,
            "external_qualification": {
                "physical_device": "unavailable_not_tested",
                "os_code_signing_certification": "unavailable_not_performed",
                "physical_reboot": "unavailable_not_tested",
                "distributed_ha": "unavailable_not_tested",
                "yocto_bsp": "unavailable_not_tested",
            },
        }
