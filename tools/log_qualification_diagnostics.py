"""Bounded, read-only evidence for private synthetic qualification failures.

No response text, events, identities, credentials, paths or raw tracebacks are
copied. Only known error codes and explicitly selected scalar state are retained.
"""

import hashlib
import json
import math
import sqlite3
import threading
import time
from contextlib import closing
from pathlib import Path

DETAIL_CODES = {
    "Admission journal full; retry without changing event_id": "source_queue_full",
    "Tenant admission quota reached; retry stable event IDs": "tenant_queue_full",
    "Disk reserve reached; no events accepted": "source_disk_reserve",
    "Full-text pending journal full; indexing must catch up before source acknowledgement": "fts_journal_full",
    "Full-text journal disk reserve reached": "fts_journal_disk_reserve",
    "Full-text configured disk budget exceeded": "fts_disk_budget",
    "Full-text disk reserve reached": "fts_disk_reserve",
    "Full-text indexing deadline exceeded": "fts_deadline",
    "Search concurrency exhausted; retry later": "query_concurrency",
    "Query memory budget exceeded; narrow the time range or fields": "query_memory_budget",
    "Quorum acknowledgement unavailable; retry stable event IDs": "quorum_unavailable",
    "Quorum journal refused the transaction": "quorum_refused",
    "Replication catch-up unavailable": "replication_unavailable",
    "Retention of an event identity is pending; retry after recovery completes": "retention_pending",
    "Event identity remains retained without its admission receipt; reuse is unavailable": "retained_identity",
    "Log search deadline exceeded while waiting for storage": "snapshot_storage_deadline",
    "Log snapshot deadline exceeded; narrow the time range": "snapshot_deadline",
    "Full-text search deadline exceeded": "fts_search_deadline",
    "Tenant snapshot quota exhausted; close expired searches": "snapshot_tenant_quota",
    "Tenant snapshot quota exhausted during publication": "snapshot_tenant_quota",
    "Snapshot disk budget exceeded; narrow the time range": "snapshot_disk_budget",
    "Snapshot disk reserve reached": "snapshot_disk_reserve",
}
ERROR_CODES = {
    "capacity_error",
    "error",
    "missing_cache",
    "incomplete_cache",
    "incompatible_cache",
    "bootstrap_required",
    "indexing",
    "ready",
    "sqlite_interrupted",
    "sqlite_busy",
    "sqlite_error",
    "disk_quota",
    "disk_reserve",
    "journal_capacity",
    "deadline",
    "cache_conflict",
}
ERROR_TYPES = {
    "CapacityError",
    "ConflictError",
    "RuntimeError",
    "ValueError",
    "TimeoutError",
    "OperationalError",
    "DatabaseError",
    "InvalidInputException",
    "OutOfMemoryException",
    "IOException",
    "BinderException",
    "ParserException",
    "TransactionException",
    "PermissionError",
    "ReadTimeout",
    "WriteTimeout",
    "ConnectTimeout",
    "PoolTimeout",
    "ConnectError",
    "ReadError",
    "WriteError",
    "RemoteProtocolError",
    "HTTPStatusError",
}


def helper_identity():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def error_type(error):
    name = error if isinstance(error, str) else type(error).__name__
    return name if name in ERROR_TYPES else "other_error_type"


def error_code(value):
    return (
        value
        if value is None or isinstance(value, str) and value in ERROR_CODES
        else "unrecognized_error_code"
    )


def scalar_fields(value, fields):
    result = {}
    if not isinstance(value, dict):
        return result
    for key in fields:
        item = value.get(key)
        if (
            item is None
            or type(item) in (int, bool)
            or (type(item) is float and math.isfinite(item))
        ):
            result[key] = item
    return result


def http_evidence(response=None, transport_error=None):
    result = {
        "status": None if response is None else response.status_code,
        "transport_error": None
        if transport_error is None
        else error_type(transport_error),
        "detail_code": None,
    }
    if response is not None:
        try:
            if len(response.content) > 4096:
                result["detail_code"] = "oversized_detail_omitted"
            else:
                body = response.json()
                detail = body.get("detail") if isinstance(body, dict) else None
                result["detail_code"] = (
                    DETAIL_CODES.get(detail, "unrecognized_detail_omitted")
                    if isinstance(detail, str)
                    else "non_string_detail_omitted"
                )
        except Exception:  # noqa: BLE001 - Diagnostic parsing must never replace an admission failure.
            result["detail_code"] = "unreadable_detail_omitted"
    return result


def batch_summary(batch, acknowledged_before=0):
    sequences = [
        row.get("raw", {}).get("sequence")
        for row in batch
        if isinstance(row, dict) and isinstance(row.get("raw"), dict)
    ]
    sequences = [
        value for value in sequences if type(value) is int and 0 <= value < 50_002_000
    ]
    return {
        "batch_events": len(batch),
        "acknowledged_before": acknowledged_before,
        "minimum_sequence": min(sequences, default=None),
        "maximum_sequence": max(sequences, default=None),
    }


def encoded_batch_summary(body, count, acknowledged_before):
    try:
        return batch_summary(json.loads(body)["events"], acknowledged_before)
    except Exception:  # noqa: BLE001 - Malformed diagnostic input must not replace the HTTP failure.
        return {"batch_events": count, "acknowledged_before": acknowledged_before}


def local_snapshot(store, runtime, deadline):
    """Existing private QA files only; no Store initialization or write lock."""
    result = {
        "consistency": "Separate read-only point observations; not an atomic source/cache proof"
    }
    if time.monotonic() >= deadline:
        return {"observation_error": "diagnostic_deadline"}
    try:
        with closing(
            sqlite3.connect(
                Path(store.operational).resolve().as_uri() + "?mode=ro",
                uri=True,
                timeout=0.05,
            )
        ) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA query_only=ON")
            db.set_progress_handler(lambda: time.monotonic() >= deadline, 1000)
            row = db.execute(
                "SELECT indexed_documents,pending_documents,pending_bytes,applied_sequence,"
                "bootstrap_required,generation,purges,last_error,"
                "(SELECT count(*) FROM log_fts_inflight) AS inflight,"
                "(SELECT count(*) FROM queue) AS source_pending FROM log_fts_state WHERE singleton=1"
            ).fetchone()
            if row is not None:
                state = dict(row)
                result["control"] = scalar_fields(
                    state,
                    (
                        "indexed_documents",
                        "pending_documents",
                        "pending_bytes",
                        "applied_sequence",
                        "bootstrap_required",
                        "generation",
                        "purges",
                        "inflight",
                        "source_pending",
                    ),
                )
                result["control"]["last_error"] = error_code(state.get("last_error"))
    except sqlite3.Error as exc:
        result["control_observation_error"] = error_type(exc)
    health = runtime.health()
    result["runtime"] = scalar_fields(
        health,
        (
            "fulltext_worker_running",
            "last_tick",
            "indexed_total",
            "last_indexed",
            "last_batches",
            "oldest_pending_seconds",
        ),
    )
    for key in ("error", "fulltext_error"):
        result["runtime"][key] = (
            None if health.get(key) is None else error_type(health[key])
        )
    result["runtime"]["fulltext_error_code"] = error_code(
        health.get("fulltext_error_code")
    )
    cache = Path(store.path) / "log-search" / "terms.sqlite3"
    result["cache_exists"] = cache.is_file()
    if result["cache_exists"] and time.monotonic() < deadline:
        try:
            with closing(
                sqlite3.connect(
                    cache.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.05
                )
            ) as db:
                db.row_factory = sqlite3.Row
                db.set_progress_handler(lambda: time.monotonic() >= deadline, 1000)
                row = db.execute(
                    "SELECT format_version,applied_sequence,generation,purges,documents FROM metadata"
                ).fetchone()
                result["cache_metadata"] = scalar_fields(
                    dict(row) if row else {},
                    (
                        "format_version",
                        "applied_sequence",
                        "generation",
                        "purges",
                        "documents",
                    ),
                )
        except sqlite3.Error as exc:
            result["cache_observation_error"] = error_type(exc)
    return result


def combined_snapshot(store, runtime, client, deadline):
    result = local_snapshot(store, runtime, deadline)
    remaining = deadline - time.monotonic()
    if remaining > 0:
        try:
            result["public"] = public_snapshot(client, remaining)
        except Exception as exc:  # noqa: BLE001 - Preserve local evidence when an HTTP probe times out.
            result["public_observation_error"] = error_type(exc)
    return result


def public_snapshot(client, timeout):
    response = client.get("/api/logs/status", timeout=timeout)
    result = {"status": response.status_code, "http_timeout_seconds": timeout}
    if response.status_code == 200:
        state = response.json().get("search", {}).get("fulltext", {})
        result["fulltext"] = scalar_fields(
            state,
            (
                "ready",
                "pending_documents",
                "pending_bytes",
                "lag_seconds",
                "budget_bytes",
            ),
        )
        for key in ("state", "error"):
            result["fulltext"][key] = error_code(state.get(key))
    else:
        result["response"] = http_evidence(response)
    return result


class AdmissionEvidence:
    """At most64 rejected attempts and two snapshots, independent of retry policy."""

    def __init__(self, target, snapshot, budget_seconds=2):
        if (
            isinstance(budget_seconds, bool)
            or not isinstance(budget_seconds, (int, float))
            or not math.isfinite(budget_seconds)
            or not 0 < budget_seconds <= 2
        ):
            raise ValueError("Diagnostic deadline must be finite and at most2seconds")
        self.target, self.snapshot = target, snapshot
        self.budget_seconds = budget_seconds
        self.lock, self.causes = threading.Lock(), set()
        self.worker = None
        self.target.update(
            attempts=[],
            snapshots=[],
            dropped_attempts=0,
            attempt_limit=64,
            snapshot_limit=2,
            snapshot_budget_seconds=budget_seconds,
            timing_scope="First capacity snapshot is asynchronous; exhausted-retry snapshot runs only after the unchanged8-attempt policy has failed",
        )

    def observe(self, response, context, attempt, elapsed, transport_error=None):
        try:
            row = {
                **http_evidence(response, transport_error),
                **context,
                "attempt": attempt + 1,
                "request_seconds": elapsed,
            }
            with self.lock:
                rows = self.target["attempts"]
                if len(rows) == self.target["attempt_limit"]:
                    rows.pop(0)
                    self.target["dropped_attempts"] += 1
                rows.append(row)
            return row
        except Exception:  # noqa: BLE001 - Evidence failure never alters admission acceptance.
            return {"status": None, "detail_code": "diagnostic_observation_failed"}

    def capture(self, cause, context):
        try:
            with self.lock:
                if (
                    cause in self.causes
                    or len(self.causes) >= self.target["snapshot_limit"]
                ):
                    return
                self.causes.add(cause)
            if cause == "first_capacity":
                self.worker = threading.Thread(
                    target=self._capture,
                    args=(cause, dict(context)),
                    name="qa-admission-diagnostics",
                    daemon=True,
                )
                self.worker.start()
                return
            self._capture(cause, context)
        except Exception:  # noqa: BLE001 - Do not mask any original failure, even when starting evidence fails.
            return

    def _capture(self, cause, context):
        try:
            began = time.monotonic()
            row = {"cause": cause, **context, "budget_seconds": self.budget_seconds}
            try:
                row["observation"] = self.snapshot(
                    began + self.budget_seconds,
                    {**context, "diagnostic_cause": cause},
                )
            except Exception as exc:  # noqa: BLE001 - Preserve the original retry/HTTP failure.
                row["observation_error"] = error_type(exc)
            row["seconds"] = time.monotonic() - began
            with self.lock:
                self.target["snapshots"].append(row)
        except Exception:  # noqa: BLE001 - Do not mask any original failure, even when saving evidence fails.
            return

    def finish(self):
        """Join the sole owned diagnostic worker before service/report cleanup."""
        try:
            if self.worker is not None:
                self.worker.join(self.budget_seconds + 0.5)
            finished = self.worker is None or not self.worker.is_alive()
            with self.lock:
                self.target["background_snapshot_finished"] = finished
            return finished
        except Exception:  # noqa: BLE001 - Caller preserves the original failure and marks cleanup incomplete.
            return False
