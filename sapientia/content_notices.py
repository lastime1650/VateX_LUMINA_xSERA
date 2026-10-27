"""Attribution snapshots for detection content, not a grant of third-party rights.

Callers must perform their normal complete evidence/ancestry authority checks.
This module never reads original telemetry or treats client metadata as proof.
Historical license snapshots survive rule retirement and parser removal.
"""

import json

from . import principal, release_manifest
from .storage import CapacityError, ConflictError, encode

SCHEMA = "xsera.content-notices.v1"
MAX_NOTICES = 8192
MAX_BYTES = 8 * 1024 * 1024
ENGINE_NOTICES = {
    "capa": ("Apache-2.0", "https://github.com/mandiant/capa", "https://github.com/mandiant/capa/blob/master/LICENSE.txt"),
    "floss": ("Apache-2.0", "https://github.com/mandiant/flare-floss", "https://github.com/mandiant/flare-floss/blob/master/LICENSE.txt"),
    "speakeasy": ("MIT", "https://github.com/mandiant/speakeasy", "https://github.com/mandiant/speakeasy/blob/master/LICENSE.txt"),
    "clamav": ("GPL-2.0 (upstream COPYING; inspect installed component notices)", "https://github.com/Cisco-Talos/clamav", "https://github.com/Cisco-Talos/clamav/blob/main/COPYING.txt"),
    "cape": ("GPL-3.0-only", "https://github.com/kevoreilly/CAPEv2", "https://github.com/kevoreilly/CAPEv2/blob/master/LICENSE"),
}


class NoticeHistoryUnavailable(KeyError):
    """An attribution signal was pruned; distinct from current scope denial."""


def bundle(items=(), *, complete=True):
    """Deduplicate exact notices; never silently truncate author attribution."""
    unique = {}
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("Typed detection content notice required")  # noqa: TRY004 - consistent protected API validation contract.
        unique[release_manifest.digest(item)] = item
        if len(unique) > MAX_NOTICES:
            raise CapacityError("Detection attribution exceeds the bounded export budget")
    result = {"schema": SCHEMA, "items": [unique[key] for key in sorted(unique)], "complete": bool(complete)}
    if len(encode(result).encode()) > MAX_BYTES:
        raise CapacityError("Detection attribution exceeds the bounded export byte budget")
    return {**result, "digest": release_manifest.digest(result)}


def merge(*bundles):
    return bundle((item for value in bundles for item in value.get("items", [])),
                  complete=all(value.get("complete") is True for value in bundles))


def yara_matches(matches, *, complete=True):
    notices = []
    for match in matches:
        notices.append({
            "kind": "yara_rule", "rule_id": match.get("rule_id", ""),
            "rule_name": match.get("rule", ""), "revision": match.get("revision"),
            "author": match.get("author", ""), "authors": match.get("authors", []),
            "license": match.get("license") or "unspecified",
            "license_url": match.get("license_url", ""),
            "source_url": match.get("upstream_url", ""),
            "repository": match.get("repository", ""), "commit": match.get("commit", ""),
            "source_sha256": match.get("source_sha256", ""),
            "license_file": match.get("license_file", ""),
            "rights_basis": "source_metadata_not_independent_legal_clearance",
        })
    return bundle(notices, complete=complete)


def sigma_source(decoded, source_sha256):
    """Preserve supported original metadata unchanged in the reviewed conversion."""
    return {"kind": "sigma_rule", "title": decoded.get("title", ""),
            "rule_name": decoded.get("name", decoded.get("id", "")),
            "author": decoded.get("author", ""),
            "license": decoded.get("license") or "unspecified",
            "references": decoded.get("references", []),
            "source_sha256": source_sha256,
            "rights_basis": "imported_metadata_not_a_redistribution_grant"}


def engine(engine, *, version=None, rule_digest=None):
    license_name, upstream, license_url = ENGINE_NOTICES[engine]
    return {"kind": "optional_analysis_engine", "engine": engine, "version": version,
            "license": license_name, "source_url": upstream, "license_url": license_url,
            "rule_digest": rule_digest, "bundled_runtime": False,
            "rights_basis": "upstream_program_license_resources_and_guest_os_require_separate_review"}


def _body_equal(left, right):
    # Publisher/list serializers add these display-only fields. Never use them
    # as notice/evidence authority; compare every other persisted field exactly.
    display = {"story_id", "duplicate", "originals", "originals_currently_available", "recorded_story_id"}
    return {k: v for k, v in left.items() if k not in display} == {k: v for k, v in right.items() if k not in display}


def for_signal(db, actor, signal, *, memo=None):
    """Return notices from exact persisted run/deployment ancestry, with no raw reads.

    `memo` is optional and transaction-local only. Every call still checks the
    current principal and each traversed signal's complete current index scope.
    This helper does not confer evidence access or validate detection accuracy.
    """
    actor = principal.current(db, actor)
    if not isinstance(signal, dict) or not isinstance(signal.get("id"), str):
        raise ValueError("An exact persisted signal is required for attribution")  # noqa: TRY004 - consistent protected API validation contract.
    results, visited, stack = [], set(), [(signal, 0)]
    complete = True
    while stack:
        supplied, depth = stack.pop()
        if not isinstance(supplied, dict):
            raise ConflictError("Detection attribution signal structure differs")
        if depth > 8:
            raise CapacityError("Detection attribution ancestry budget exceeded")
        identifier = supplied.get("id")
        if identifier in visited:
            continue
        if len(visited) >= 4096:
            raise CapacityError("Detection attribution ancestry budget exceeded")
        row = db.execute("SELECT body,indexes FROM intelligence_signals WHERE tenant=? AND id=?", (actor["tenant"], identifier)).fetchone()
        if not row:
            raise NoticeHistoryUnavailable("Detection attribution signal history unavailable")
        if not principal.contains(actor["allowed_indexes"], json.loads(row["indexes"])):
            raise KeyError("Detection attribution unavailable in complete current scope")
        body = json.loads(row["body"])
        if not isinstance(body, dict) or not _body_equal(body, supplied):
            raise ConflictError("Detection attribution signal identity differs")
        visited.add(identifier)
        rule = body.get("rule_id", "")
        metadata = body.get("metadata", {})
        features = body.get("features", {})
        if not isinstance(metadata, dict) or not isinstance(features, dict) or not isinstance(rule, str):
            raise ConflictError("Detection attribution signal metadata differs")
        if rule == "yara:binary":
            if not isinstance(metadata.get("yara_run_id"), str) or not 1 <= len(metadata["yara_run_id"]) <= 256:
                raise ConflictError("YARA attribution requires an exact run identity")
            run_row = db.execute("SELECT body FROM yara_runs WHERE tenant=? AND id=?", (actor["tenant"], metadata.get("yara_run_id"))).fetchone()
            run = json.loads(run_row[0]) if run_row else None
            if not isinstance(run, dict) or run.get("id") != metadata.get("yara_run_id") or run.get("status") != "completed" or run.get("signal_id") != identifier or sorted(run.get("event_ids", [])) != sorted(body.get("event_ids", [])) or run.get("sha256") != body.get("features", {}).get("artifact_sha256"):
                raise ConflictError("YARA attribution is not bound to this run and signal")
            value = yara_matches(run.get("matches", []), complete=not run.get("matches_truncated", False))
            results.extend(value["items"])
            complete &= value["complete"]
        elif rule.startswith("analysis-engine:"):
            if not isinstance(metadata.get("analysis_engine_run_id"), str) or not 1 <= len(metadata["analysis_engine_run_id"]) <= 256:
                raise ConflictError("Engine attribution requires an exact run identity")
            run_row = db.execute("SELECT body FROM analysis_engine_runs WHERE tenant=? AND id=?", (actor["tenant"], metadata.get("analysis_engine_run_id"))).fetchone()
            run = json.loads(run_row[0]) if run_row else None
            if not isinstance(run, dict) or run.get("id") != metadata.get("analysis_engine_run_id") or run.get("status") != "completed" or run.get("signal_id") != identifier or run.get("engine") not in ENGINE_NOTICES or rule != "analysis-engine:" + run["engine"] or run.get("sha256") != body.get("features", {}).get("artifact_sha256") or sorted(run.get("event_ids", [])) != sorted(body.get("event_ids", [])):
                raise ConflictError("Engine attribution is not bound to this run and signal")
            results.append(engine(run["engine"], version=run.get("engine_version"), rule_digest=run.get("rule_digest")))
            results.extend(run.get("content_notices", {}).get("items", []))
        elif body.get("kind") in {"atomic", "composite"}:
            deployed = db.execute("SELECT * FROM sigma_import_deployments WHERE tenant=? AND policy_id=? AND policy_version=?", (actor["tenant"], rule, body.get("rule_revision"))).fetchone()
            if deployed:
                from . import sigma_imports
                _, imported, _ = sigma_imports._deployment(db, actor, deployed["import_id"], policy_version=deployed["policy_version"])
                converted = imported.get("converted", {})
                if body.get("definition_digest") != converted.get("native_definition_digest") or release_manifest.digest(converted) != imported.get("converted_sha256"):
                    raise ConflictError("Sigma attribution native definition differs")
                notice = converted.get("source_notice")
                if notice is None:
                    # Legacy JSON imports need no optional parser at read time.
                    payload = imported["payload"]
                    try:
                        decoded = json.loads(payload["source_text"])
                    except ValueError:
                        decoded = None
                    notice = sigma_source(decoded, imported["source_sha256"]) if isinstance(decoded, dict) else {"kind": "sigma_rule", "source_sha256": imported["source_sha256"], "license": "unspecified", "rights_basis": "legacy_original_source_retained_metadata_not_extracted"}
                    if decoded is None:
                        complete = False
                results.append({**notice, "import_id": deployed["import_id"], "revision": deployed["revision"]})
        parents = body.get("parent_signal_ids", [])
        if not isinstance(parents, list) or len(parents) > 32 or any(not isinstance(value, str) for value in parents):
            raise ConflictError("Detection attribution parent list differs")
        for parent_id in parents:
            parent = db.execute("SELECT body FROM intelligence_signals WHERE tenant=? AND id=?", (actor["tenant"], parent_id)).fetchone()
            if not parent:
                raise NoticeHistoryUnavailable("Detection attribution parent history unavailable")
            stack.append((json.loads(parent[0]), depth + 1))
    return bundle(results, complete=complete)


def _case_snapshot(value, contribution_id, signal_id):
    if not isinstance(value, dict) or set(value) != {"schema", "items", "complete", "digest"} or value.get("schema") != SCHEMA or not isinstance(value.get("items"), list) or type(value.get("complete")) is not bool:
        raise ConflictError("Historical Case attribution snapshot structure differs")
    canonical = bundle(value["items"], complete=value["complete"])
    if canonical != value:
        raise ConflictError("Historical Case attribution snapshot digest differs")
    return bundle([{**item, "preservation_basis": "historical_case_contribution_snapshot",
                    "contribution_id": contribution_id, "source_signal_id": signal_id}
                   for item in value["items"]], complete=False)


def for_case(db, actor, incident_id, contributions):
    """Retain direct artifact-run and contribution notices in an authorized Case.

    Case/index authority is checked in the supplied transaction. Missing signal
    history never silently erases a previously captured attribution snapshot;
    such snapshots are explicitly historical and incomplete for reconstruction.
    No original telemetry, external URL or sample bytes are read here.
    """
    actor = principal.current(db, actor)
    principal.incident(db, actor, incident_id)
    values = []
    for contribution in contributions:
        if contribution.get("tenant") != actor["tenant"] or contribution.get("incident_id") != incident_id or not principal.contains(actor["allowed_indexes"], json.loads(contribution["indexes"])):
            raise KeyError("Complete Case attribution scope unavailable")
        evidence = json.loads(contribution["evidence"])
        analysis = evidence.get("analysis", {}) if isinstance(evidence, dict) else None
        if not isinstance(analysis, dict):
            raise ConflictError("Case attribution evidence structure differs")
        identifier = analysis.get("signal_id")
        if not identifier:
            continue
        saved = db.execute("SELECT body FROM intelligence_signals WHERE tenant=? AND id=?", (actor["tenant"], identifier)).fetchone()
        if saved:
            try:
                values.append(for_signal(db, actor, json.loads(saved[0])))
                continue
            except NoticeHistoryUnavailable:
                pass
        if "content_notices" in analysis:
            values.append(_case_snapshot(analysis["content_notices"], contribution["id"], identifier))
        else:
            values.append(bundle(complete=False))
    for table in ("yara_runs", "analysis_engine_runs"):
        # Table is one of two fixed internal literals; all values remain bound.
        rows = db.execute("SELECT id,index_name,body FROM " + table + " WHERE tenant=? AND incident_id=? ORDER BY created,id LIMIT 513", (actor["tenant"], incident_id)).fetchall()  # nosec B608
        if len(rows) > 512:
            raise CapacityError("Case attribution has more than 512 analysis runs; use scoped run exports")
        for row in rows:
            if not principal.contains(actor["allowed_indexes"], [row["index_name"]]):
                raise KeyError("Complete attached analysis attribution scope unavailable")
            run = json.loads(row["body"])
            if not isinstance(run, dict) or run.get("id") != row["id"] or run.get("incident_id") != incident_id:
                raise ConflictError("Case-attached analysis run identity differs")
            if run.get("status") != "completed":
                continue
            identifier = run.get("signal_id")
            if identifier:
                saved = db.execute("SELECT body FROM intelligence_signals WHERE tenant=? AND id=?", (actor["tenant"], identifier)).fetchone()
                if saved:
                    signal = json.loads(saved[0])
                    expected = "yara:binary" if table == "yara_runs" else "analysis-engine:" + str(run.get("engine"))
                    key = "yara_run_id" if table == "yara_runs" else "analysis_engine_run_id"
                    if not isinstance(signal, dict) or signal.get("rule_id") != expected or not isinstance(signal.get("metadata"), dict) or signal["metadata"].get(key) != run["id"]:
                        raise ConflictError("Case analysis signal is not bound to the attached run")
                    try:
                        values.append(for_signal(db, actor, signal))
                        continue
                    except NoticeHistoryUnavailable:
                        pass
            # A completed scan may deliberately emit no signal. Its immutable
            # persisted Case attachment still needs the supplied match authors.
            if table == "yara_runs":
                values.append(yara_matches(run.get("matches", []), complete=not identifier and not run.get("matches_truncated", False)))
            elif run.get("engine") in ENGINE_NOTICES:
                values.append(merge(bundle([engine(run["engine"], version=run.get("engine_version"), rule_digest=run.get("rule_digest"))], complete=not identifier), bundle(run.get("content_notices", {}).get("items", []))))
    return merge(*values)
