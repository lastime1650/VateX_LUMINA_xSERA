"""Bounded cumulative HTTP/TLS log-scale qualification in a fresh private QA store.

No production URL or data path is accepted. A single producer sends stable
streamed batches; this is NOT a sustained EPS, concurrent-search or HA benchmark.
Only the harness-private lifecycle seam advances time. Existing product modules
and existing qualification tools are never changed.
"""

import argparse
import ctypes
import errno
import hashlib
import hmac
import json
import math
import os
import platform
import secrets
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from array import array
from contextlib import closing
from email.utils import parsedate_to_datetime
from pathlib import Path

import httpx

STAGE = Path(__file__).resolve().parents[1]
WORK = STAGE.parent
TASK = WORK.parent
if str(STAGE) not in sys.path:
    sys.path.insert(0, str(STAGE))

from tools import log_qualification_diagnostics as diagnostics
from tools.qualification import IsolatedService

TENANTS = ("default", "scale_other")
INDEXES = ("main", "endpoint", "firewall")
BODY_LIMIT = 1024 * 1024
BATCH_LIMIT = 1000
SEAL_INTERVAL = 500_000
CHECKPOINT_INTERVAL = 1_000_000
MILESTONES = (1_000_000, 5_000_000, 10_000_000, 25_000_000, 50_000_000)
RETRY_AFTER_LIMIT = 120
RESOURCE_DB_SECONDS = 2
REPORT_REPLACE_DELAYS = (0.05, 0.1, 0.2, 0.35)
MONITOR_OPERATIONS = {
    "client_open",
    "client_headers",
    "guard",
    "resource_http",
    "resource_status",
    "resource_decode",
    "resource_record",
    "resource_guard",
    "resource_persist",
    "admission_summary",
    "record_update",
    "record_save",
    "progress_read",
    "progress_print",
    "client_close",
}
MONITOR_ERROR_TYPES = diagnostics.ERROR_TYPES | {
    "ScaleFailure",
    "OSError",
    "BrokenPipeError",
    "JSONDecodeError",
    "TypeError",
    "KeyError",
    "AttributeError",
    "UnicodeError",
    "UnicodeEncodeError",
}
MONITOR_ERRNOS = {
    errno.EACCES,
    errno.EBUSY,
    errno.EIO,
    errno.ENOSPC,
    errno.EROFS,
    errno.ENOENT,
    errno.ENOMEM,
    errno.ETIMEDOUT,
    errno.EPIPE,
    errno.EINVAL,
}
MONITOR_WINERRORS = {5, 32, 33, 112, 1450, 1816}
MARKER = ".isolated-log-scale-qa.json"
PRIVATE_CONFIG = "private-scale-config.json"
STATS = (
    "count AS n, dc(event_id) AS distinct_ids, sum(raw.sequence) AS sequence_sum, "
    "min(raw.sequence) AS minimum_sequence, max(raw.sequence) AS maximum_sequence"
)


class ScaleFailure(RuntimeError):
    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


def check(condition, message, kind="integrity"):
    if not condition:
        raise ScaleFailure(kind, message)


def dumps(value):
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def atomic_json(path, value):
    """Publish a complete report; a failed replace retains the prior checkpoint."""
    pending = path.with_name(path.name + "." + uuid.uuid4().hex + ".pending")
    try:
        with pending.open("xb") as stream:
            stream.write(
                json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False).encode(
                    "utf-8"
                )
            )
            stream.flush()
            os.fsync(stream.fileno())
        for attempt in range(len(REPORT_REPLACE_DELAYS) + 1):
            try:
                os.replace(pending, path)
                break
            except OSError as exc:
                if getattr(exc, "winerror", None) not in {32, 33}:
                    raise
                if attempt == len(REPORT_REPLACE_DELAYS):
                    raise
                time.sleep(REPORT_REPLACE_DELAYS[attempt])
    finally:
        pending.unlink(missing_ok=True)


def monitor_error(operation, exc, status=None):
    """Only static phase/type names and allowlisted numeric error metadata."""
    name = type(exc).__name__
    result = {
        "operation": operation if operation in MONITOR_OPERATIONS else "unknown",
        "exception_type": name if name in MONITOR_ERROR_TYPES else "other_error_type",
    }
    for field, allowed in (("errno", MONITOR_ERRNOS), ("winerror", MONITOR_WINERRORS)):
        value = getattr(exc, field, None)
        if type(value) is int and value in allowed:
            result[field] = value
    if type(status) is int and 100 <= status <= 599:
        result["http_status"] = status
    return result


def validate_report_path(path, roots=None):
    roots = roots or (WORK, TASK / "outputs")
    path = path.absolute()
    check(not path.exists(), "Report must be a new file", "isolation")
    check(path.suffix == ".json", "Report must use .json", "isolation")
    resolved = path.resolve()
    check(
        any(resolved.is_relative_to(root.resolve()) for root in roots),
        "Report must stay in task work/ or outputs/",
        "isolation",
    )
    for parent in (path, *path.parents):
        check(
            not parent.is_symlink(),
            "Report path must not traverse symlinks",
            "isolation",
        )
    return resolved


def validate_directory(directory):
    directory = directory.absolute()
    check(
        not directory.is_symlink()
        and directory.resolve().parent == WORK.resolve()
        and directory.name.startswith("log-scale-qa-"),
        "Only a fresh marked private QA directory is valid",
        "isolation",
    )
    marker = json.loads((directory / MARKER).read_text(encoding="utf-8"))
    check(
        marker == {"schema": 1, "synthetic_only": True, "run_id": directory.name[13:]},
        "Invalid private QA marker",
        "isolation",
    )
    data = directory / "data"
    check(
        not data.is_symlink() and data.resolve().parent == directory.resolve(),
        "QA data must remain inside the generated directory",
        "isolation",
    )
    return directory.resolve()


def source_identity():
    paths = [STAGE / "pyproject.toml", STAGE / "requirements-lock.txt"]
    paths += sorted(
        path
        for path in (STAGE / "sapientia").rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix
        in {".py", ".json", ".txt", ".js", ".css", ".html", ".sh", ".ps1"}
    )
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(STAGE).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=STAGE,
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        "product_source_sha256": digest.hexdigest(),
        "product_files": len(paths),
        "git_head": head.stdout.strip() if head.returncode == 0 else None,
        "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "diagnostics_helper_sha256": diagnostics.helper_identity(),
        "definition": "Actual source/assets plus pyproject and requirements; no DB, credentials or Git blobs",
    }


def scope_for(sequence):
    return TENANTS[(sequence // 3) % 2], INDEXES[sequence % 3]


def progression(total, remainder, modulus=6):
    """Exact count and sum of ordinals in [0,total), without materializing IDs."""
    count = max(0, (total - 1 - remainder) // modulus + 1)
    return {
        "count": count,
        "sequence_sum": count * remainder + modulus * count * (count - 1) // 2,
        "minimum_sequence": remainder if count else None,
        "maximum_sequence": remainder + modulus * (count - 1) if count else None,
    }


def expected_scopes(total):
    return {(TENANTS[r // 3], INDEXES[r % 3]): progression(total, r) for r in range(6)}


def expected_sentinels(total, tenant):
    # Sentinel ordinals are k*997; 997 % 6 == 1, so k has the same scope remainder.
    sentinels = (total - 1) // 997 + 1 if total else 0
    return sum(
        progression(sentinels, r)["count"]
        for r in range(6)
        if TENANTS[r // 3] == tenant
    )


def exact_integer(value):
    if type(value) is int:
        result = value
    elif (
        type(value) is float
        and math.isfinite(value)
        and value.is_integer()
        or isinstance(value, str)
        and value.isdecimal()
    ):
        result = int(value)
    else:
        raise ScaleFailure(
            "integrity", "Aggregate returned a non-integral or missing value"
        )
    check(abs(result) <= 2**53 - 1, "Aggregate exceeded exact JSON numeric range")
    return result


def validate_aggregate(row, expected):
    actual = {
        key: exact_integer(
            0 if expected["count"] == 0 and row.get(column) is None else row.get(column)
        )
        for key, column in (
            ("count", "n"),
            ("distinct_ids", "distinct_ids"),
            ("sequence_sum", "sequence_sum"),
        )
    }
    check(
        actual["count"] == actual["distinct_ids"] == expected["count"],
        "Count/distinct mismatch",
    )
    check(
        actual["sequence_sum"] == expected["sequence_sum"],
        "Exact numeric sequence sum mismatch",
    )
    for key in ("minimum_sequence", "maximum_sequence"):
        value = row.get(key)
        parsed = None if value is None else exact_integer(value)
        check(
            parsed == expected[key],
            "Sequence range mismatch",
        )
        actual[key] = parsed
    return actual


def latency_summary(samples):
    values = sorted(samples)

    def at(fraction):
        return values[max(0, math.ceil(len(values) * fraction) - 1)] if values else None

    return {
        "samples": len(values),
        "p50_seconds": at(0.5),
        "p95_seconds": at(0.95),
        "p99_seconds": at(0.99),
        "max_seconds": values[-1] if values else None,
        "method": "nearest-rank; p99 sample count is disclosed, not a tail guarantee",
    }


def byte_summary(samples):
    value = latency_summary(samples)
    return {
        "samples": value["samples"],
        "method": "nearest-rank",
        **{
            key.replace("_seconds", "_bytes"): item
            for key, item in value.items()
            if key.endswith("_seconds")
        },
    }


def component_bytes(directory):
    """Physical metadata estimate; WAL/temp files can vanish during enumeration."""
    result = {
        "control_including_fts_journal": 0,
        "hot_duckdb": 0,
        "parquet_segments": 0,
        "fts_cache": 0,
        "other": 0,
    }
    for path in directory.rglob("*"):
        try:
            if not path.is_file():
                continue
            size = path.stat().st_size
        except FileNotFoundError:
            continue
        relative = path.relative_to(directory)
        if path.name.startswith("control.sqlite3"):
            key = "control_including_fts_journal"
        elif path.name.startswith("events.duckdb"):
            key = "hot_duckdb"
        elif relative.parts[0] == "log-segments":
            key = "parquet_segments"
        elif relative.parts[0] == "log-search":
            key = "fts_cache"
        else:
            key = "other"
        result[key] += size
    return result


def capacity_projection(
    components, initial, population, target, free_bytes, reserve_bytes
):
    growth = {
        key: max(0, value - initial.get(key, 0)) for key, value in components.items()
    }
    remaining = sum(growth.values()) / population * max(0, target - population)
    available = max(0, free_bytes - reserve_bytes)
    return {
        "population": population,
        "target": target,
        "physical_components": components,
        "physical_total_bytes": sum(components.values()),
        "observed_growth_bytes_per_event": {
            key: value / population for key, value in growth.items()
        },
        "remaining_linear_estimate_bytes": math.ceil(remaining),
        "available_above_reserve_bytes": available,
        "fits_linear_estimate": remaining <= available,
        "method": "Baseline-subtracted file-size metadata, including SQLite FTS journal/WAL; not compression or backup guarantee",
    }


def validate_fts_population(state, total):
    """Private QA scalar check; never expose global counts in a public route."""
    fields = (
        "indexed_documents",
        "pending_documents",
        "applied_sequence",
        "bootstrap_required",
        "inflight",
    )
    check(
        type(total) is int and total >= 0,
        "Invalid expected FTS population",
        "fts_population",
    )
    check(
        isinstance(state, dict)
        and all(type(state.get(key)) is int and state[key] >= 0 for key in fields),
        "FTS population observation requires nonnegative integer scalars",
        "fts_population",
    )
    observed = {key: state[key] for key in fields}
    check(
        observed["indexed_documents"] == total,
        "FTS indexed population differs from admitted population",
        "fts_population",
    )
    check(
        observed["pending_documents"]
        == observed["inflight"]
        == observed["bootstrap_required"]
        == 0,
        "FTS population observation is pending, fenced or requires bootstrap",
        "fts_population",
    )
    return {
        "passed": True,
        "expected_population": total,
        "observed": observed,
        "scope": "QA-only durable control counters after public readiness; not a cryptographic body proof",
    }


def read_fts_population(path, lock, timeout):
    """QA-only independent row counts; no Store/source walk or cache mutation."""
    check(
        isinstance(timeout, (int, float))
        and not isinstance(timeout, bool)
        and math.isfinite(timeout)
        and 0 < timeout <= 600,
        "Invalid actual FTS population observation deadline",
        "fts_population",
    )
    started = time.monotonic()
    deadline = started + timeout
    check(path.is_file(), "FTS cache is absent", "fts_population")
    acquired = lock.acquire(timeout=max(0, deadline - time.monotonic()))
    check(acquired, "Actual FTS population lock deadline exceeded", "fts_population")
    try:
        with closing(
            sqlite3.connect(
                path.resolve().as_uri() + "?mode=ro", uri=True, timeout=0.25
            )
        ) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("PRAGMA cache_size=-8192")
            db.execute("PRAGMA temp_store=FILE")
            db.set_progress_handler(lambda: time.monotonic() >= deadline, 1000)
            db.execute("BEGIN")
            # Reading the content shadow table is equivalent to virtual-table
            # COUNT only for this verified, normal internal-content FTS format.
            # External/contentless tables and unknown future formats fail closed.
            expected_schema = (
                "CREATE VIRTUAL TABLE terms USING fts5("
                "tenant UNINDEXED,event_id UNINDEXED,message,raw,"
                "tokenize='unicode61 remove_diacritics 2')"
            )
            schema = db.execute(
                "SELECT sql FROM sqlite_schema WHERE type='table' AND name='terms'"
            ).fetchone()
            check(
                schema is not None
                and isinstance(schema[0], str)
                and "".join(schema[0].split()).casefold()
                == "".join(expected_schema.split()).casefold()
                and [row[1] for row in db.execute("PRAGMA table_info(terms_content)")]
                == ["id", "c0", "c1", "c2", "c3"],
                "Actual FTS population requires the verified internal-content schema",
                "fts_population",
            )
            columns = {row[1]: row for row in db.execute("PRAGMA table_info(registry)")}
            check(
                all(
                    key in columns
                    and columns[key][2].upper() == "TEXT"
                    and columns[key][3] == 1
                    for key in ("tenant", "event_id", "index_name")
                )
                and columns["tenant"][5] == 1
                and columns["event_id"][5] == 2,
                "Actual FTS registry requires non-null identity and index columns",
                "fts_population",
            )
            terms_count = db.execute("SELECT count(*) FROM terms_content").fetchone()[0]
            # Registry PK begins with tenant. Grouping by that prefix streams in
            # key order instead of sorting50M tenant/index pairs in a temp Btree.
            grouped = db.execute(
                "SELECT tenant,count(*),"
                "count(*) FILTER(WHERE index_name=?),"
                "count(*) FILTER(WHERE index_name=?),"
                "count(*) FILTER(WHERE index_name=?) "
                "FROM registry GROUP BY tenant",
                INDEXES,
            ).fetchmany(len(TENANTS) + 1)
            # The extra tenant row makes an unknown scope visible to validation;
            # a passing observation has every actual group, with no second scan.
            registry_count = sum(row[1] for row in grouped)
            check(
                all(row[1] >= sum(row[2:5]) for row in grouped),
                "Actual FTS registry index counts exceed group population",
                "fts_population",
            )
            check(
                time.monotonic() < deadline,
                "Actual FTS population query deadline exceeded",
                "fts_population",
            )
            return {
                "registry_count": registry_count,
                "terms_count": terms_count,
                "tenants": [
                    {
                        "tenant": row[0],
                        "count": row[1],
                        "indexes": dict(zip(INDEXES, row[2:5], strict=True)),
                        "unknown_index_count": row[1] - sum(row[2:5]),
                    }
                    for row in grouped
                ],
                "seconds": time.monotonic() - started,
                "deadline_seconds": timeout,
                "method": "Read-only COUNT of verified internal-content FTS5 terms_content rows and summed actual PK-ordered registry tenant groups with filtered index counts; independent of cached metadata/control counters",
                "terms_population_relation": "terms_content (verified internal-content FTS5)",
                "registry_population_relation": "Sum of actual tenant group counts; extra/unknown groups fail validation",
            }
    except sqlite3.Error as exc:
        raise ScaleFailure(
            "fts_population", "Actual FTS population SQLite observation failed"
        ) from exc
    finally:
        lock.release()


def fts_observation_budget(configured, requested):
    """Private observer budget; never used for a product/search timeout."""
    if (
        isinstance(configured, bool)
        or not isinstance(configured, (int, float))
        or not math.isfinite(configured)
        or not 0 < configured <= 600
        or isinstance(requested, bool)
    ):
        raise ValueError("Invalid observation deadline")
    try:
        requested = float(requested)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("Invalid observation deadline") from None
    if not math.isfinite(requested) or requested <= 0:
        raise ValueError("Invalid observation deadline")
    return min(configured, requested)


def validate_actual_fts_population(observation, total):
    """Require actual cache populations and all six exact authorized QA scopes."""
    check(
        type(total) is int
        and total >= 0
        and isinstance(observation, dict)
        and all(
            type(observation.get(key)) is int and observation[key] == total
            for key in ("registry_count", "terms_count")
        ),
        "Actual FTS registry/terms population differs from expected population",
        "fts_population",
    )
    rows = observation.get("tenants")
    check(isinstance(rows, list), "Missing actual FTS scopes", "fts_population")
    expected = expected_scopes(total)
    expected_tenants = {
        tenant for (tenant, _), value in expected.items() if value["count"]
    }
    seen = set()
    for row in rows:
        check(
            isinstance(row, dict)
            and isinstance(row.get("tenant"), str)
            and row["tenant"] in expected_tenants
            and row["tenant"] not in seen,
            "Unexpected or duplicate actual FTS tenant scope",
            "fts_population",
        )
        tenant = row["tenant"]
        seen.add(tenant)
        indexes = row.get("indexes")
        check(
            isinstance(indexes, dict)
            and set(indexes) == set(INDEXES)
            and all(
                type(indexes[index]) is int
                and indexes[index] == expected[tenant, index]["count"]
                for index in INDEXES
            )
            and type(row.get("count")) is int
            and row["count"] == sum(indexes.values())
            and type(row.get("unknown_index_count")) is int
            and row["unknown_index_count"] == 0,
            "Actual FTS tenant/index counts differ from exact expected scopes",
            "fts_population",
        )
    check(seen == expected_tenants, "Missing actual FTS tenant", "fts_population")
    return {
        "passed": True,
        "expected_population": total,
        "observed": observation,
        "scope": "Independent actual SQLite registry group totals and verified internal-content FTS5 terms_content row population with six exact tenant/index counts; not a full-content or token correctness hash",
    }


def validate_sample_event(row, expected, expected_tenant, tenant, index):
    fields = (
        "event_id",
        "event_time",
        "sourcetype",
        "severity",
        "message",
        "host",
        "source",
    )
    check(
        expected_tenant == tenant
        and expected["index"] == index
        and row.get("index_name") == expected["index"]
        and all(row.get(field) == expected[field] for field in fields)
        and isinstance(row.get("raw"), dict)
        and all(
            key in row["raw"]
            and type(row["raw"][key]) is type(value)
            and row["raw"][key] == value
            for key, value in expected["raw"].items()
        ),
        "Export sample differs from independent deterministic input",
        "integrity",
    )


def fts_phase_verified(item):
    if not isinstance(item, dict):
        return False
    population = item.get("population")
    return (
        item.get("passed") is True
        and type(population) is int
        and population > 0
        and all(
            isinstance(item.get(key), dict)
            and item[key].get("passed") is True
            and type(item[key].get("expected_population")) is int
            and item[key]["expected_population"] == population
            for key in ("fts_population", "actual_fts_population")
        )
    )


def fts_is_qualified(results, requested_population):
    """A lower completed milestone never qualifies the requested population."""
    if type(requested_population) is not int or requested_population < 1:
        return False
    if not results or not all(fts_phase_verified(item) for item in results):
        return False
    phases = {item.get("phase") for item in results}
    target = [item for item in results if item["population"] == requested_population]
    return (
        all(item["population"] <= requested_population for item in results)
        and {"cold", "incremental"} <= phases
        and any(
            item.get("phase") in {"cold", "incremental", "capacity"} for item in target
        )
        and any(item.get("phase") == "after_restart" for item in target)
    )


def fts_qualification_summary(results, requested_population):
    verified = [item for item in results if fts_phase_verified(item)]
    return {
        "fts_qualified": fts_is_qualified(results, requested_population),
        "fts_recorded_phase_checks_passed": bool(results)
        and len(verified) == len(results),
        "fts_highest_verified_population": max(
            (item["population"] for item in verified), default=0
        ),
        "fts_required_population": requested_population,
        "fts_qualification_scope": "All recorded phases, cold+incremental, and exact requested population before and after restart; lower milestones are partial evidence only",
    }


def admission_retry_policy(args):
    mode = getattr(args, "admission_mode", "burst8")
    if mode == "burst8":
        return {
            "mode": "burst8",
            "max_attempts": 8,
            "retry_after_honored": False,
            "inter_request_sleep_seconds": 3.15,
            "final_failure_sleep_seconds": 0.8,
            "total_sleep_before_terminal_failure_seconds": 3.95,
            "client_durable_outbox": False,
        }
    return {
        "mode": mode,
        "max_attempts": args.admission_max_attempts,
        "batch_budget_seconds": args.admission_batch_seconds,
        "overall_budget_seconds": args.max_seconds,
        "retry_after_honored": True,
        "retry_after_max_seconds": RETRY_AFTER_LIMIT,
        "minimum_retry_seconds": 1,
        "fallback_seconds": [1, 2, 4, 8, 10],
        "wait_chunk_seconds": 0.25,
        "budget_scope": "Cooperative batch/overall deadlines and capped HTTP phase timeouts; not a hard native-I/O deadline",
        "client_durable_outbox": False,
    }


def admission_retry_delay(headers, attempt, wall_time):
    """Return bounded-input advice; never persist raw response header values."""
    values = headers.get_list("Retry-After") if headers is not None else []
    kind = "missing" if not values else "invalid"
    if len(values) == 1:
        raw = values[0]
        if raw and len(raw) <= 64 and raw.isascii():
            raw = raw.strip()
            if raw.isdecimal():
                return "delta", max(1, int(raw))
            if raw.endswith(" GMT"):
                try:
                    when = parsedate_to_datetime(raw)
                    if (
                        when.tzinfo is not None
                        and when.utcoffset().total_seconds() == 0
                    ):
                        delay = when.timestamp() - wall_time
                        if math.isfinite(delay):
                            return "http_date", max(1.0, delay)
                except (ValueError, TypeError, OverflowError, OSError):
                    pass
    return kind, min(10, 2 ** min(attempt, 4))


class Corpus:
    def __init__(self, profile, base_epoch, key):
        check(
            profile in {"small", "realistic"}, "Unknown corpus profile", "configuration"
        )
        check(
            len(key) == 32, "Private corpus key must contain 32 bytes", "configuration"
        )
        self.profile, self.base_epoch, self.key = profile, base_epoch, key

    def event(self, sequence):
        tenant, index = scope_for(sequence)
        raw = {"sequence": sequence, "synthetic": True, "profile": self.profile}
        event = {
            "event_id": f"scale_{tenant}_{sequence:09d}",
            "event_time": self.base_epoch + sequence % 3600,
            "index": index,
            "source": "qa-scale-" + index,
            "sourcetype": "qa:scale:" + self.profile,
            "host": "QA-"
            + str(sequence % (100_000 if self.profile == "realistic" else 100)),
            "severity": "high" if sequence % 997 == 0 else "info",
            "message": "synthetic scale sentinel"
            if sequence % 997 == 0
            else "synthetic ordinary activity",
            "raw": raw,
        }
        if self.profile == "realistic":
            token = hashlib.blake2b(
                sequence.to_bytes(8, "big"), key=self.key, digest_size=24
            ).hexdigest()
            raw.update(
                user="qa-user-" + str(sequence % 250_000),
                trace_id=token,
                src_ip=f"10.{sequence % 251}.{sequence // 251 % 251}.{1 + sequence // 63001 % 250}",
                destination={
                    "ip": "198.18."
                    + str(sequence % 256)
                    + "."
                    + str(sequence // 256 % 256),
                    "port": (443, 53, 22, 8443)[sequence % 4],
                },
                request_path="/synthetic/" + token[:20],
                status=(200, 401, 403, 500)[sequence % 4],
                platform=("windows", "linux", "firewall")[sequence % 3],
                schema_variant=sequence % 4,
                tags=["synthetic", "variant-" + str(sequence % 11)],
            )
            for number in range(sequence % 5):
                raw["custom_" + str(number)] = token[number : number + 12]
            raw["payload"] = ""
            target = 1024 + sequence % 385 - 192
            needed = max(0, target - len(dumps(event)))
            raw["payload"] = hashlib.shake_256(
                self.key + sequence.to_bytes(8, "big")
            ).hexdigest((needed + 1) // 2)[:needed]
        return tenant, event

    def batches(self, start, stop):
        buffers = {tenant: [] for tenant in TENANTS}
        sizes = {tenant: len(b'{"events":[]}') for tenant in TENANTS}
        for sequence in range(start, stop):
            tenant, event = self.event(sequence)
            encoded_size = len(dumps(event))
            extra = encoded_size + bool(buffers[tenant])
            if buffers[tenant] and (
                sizes[tenant] + extra > BODY_LIMIT
                or len(buffers[tenant]) >= BATCH_LIMIT
            ):
                yield tenant, dumps({"events": buffers[tenant]}), len(buffers[tenant])
                buffers[tenant], sizes[tenant] = [], len(b'{"events":[]}')
            check(
                encoded_size + len(b'{"events":[]}') <= BODY_LIMIT,
                "Individual synthetic event exceeds batch budget",
            )
            sizes[tenant] += encoded_size + bool(buffers[tenant])
            buffers[tenant].append(event)
        for tenant in TENANTS:
            if buffers[tenant]:
                yield tenant, dumps({"events": buffers[tenant]}), len(buffers[tenant])


def system_resources(directory):
    if os.name == "nt":
        from ctypes import wintypes

        class Memory(ctypes.Structure):
            _fields_ = [("length", wintypes.DWORD), ("load", wintypes.DWORD)] + [
                (name, ctypes.c_ulonglong)
                for name in (
                    "total_physical",
                    "available_physical",
                    "total_pagefile",
                    "available_pagefile",
                    "total_virtual",
                    "available_virtual",
                    "available_extended",
                )
            ]

        class ProcessMemory(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
                (name, ctypes.c_size_t)
                for name in (
                    "PeakWorkingSetSize",
                    "WorkingSetSize",
                    "QuotaPeakPagedPoolUsage",
                    "QuotaPagedPoolUsage",
                    "QuotaPeakNonPagedPoolUsage",
                    "QuotaNonPagedPoolUsage",
                    "PagefileUsage",
                    "PeakPagefileUsage",
                    "PrivateUsage",
                )
            ]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        memory, process = Memory(), ProcessMemory()
        memory.length, process.cb = ctypes.sizeof(memory), ctypes.sizeof(process)
        check(
            kernel.GlobalMemoryStatusEx(ctypes.byref(memory)),
            "Cannot observe available RAM",
            "telemetry",
        )
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ProcessMemory),
            wintypes.DWORD,
        ]
        check(
            psapi.GetProcessMemoryInfo(
                kernel.GetCurrentProcess(), ctypes.byref(process), process.cb
            ),
            "Cannot observe server RSS",
            "telemetry",
        )
        total, available, rss = (
            memory.total_physical,
            memory.available_physical,
            process.WorkingSetSize,
        )
    else:
        info = {
            line.split(":")[0]: int(line.split()[1]) * 1024
            for line in Path("/proc/meminfo").read_text().splitlines()
            if line.startswith(("MemTotal:", "MemAvailable:"))
        }
        total, available = info["MemTotal"], info["MemAvailable"]
        rss = int(Path("/proc/self/statm").read_text().split()[1]) * os.sysconf(
            "SC_PAGE_SIZE"
        )
    disk = shutil.disk_usage(directory)
    return {
        "server_pid": os.getpid(),
        "rss_bytes": rss,
        "available_ram_bytes": available,
        "total_ram_bytes": total,
        "disk_free_bytes": disk.free,
        "disk_total_bytes": disk.total,
    }


def guard_resources(sample, reserve_bytes, min_ram_bytes, max_rss_bytes):
    check(
        sample["disk_free_bytes"] > reserve_bytes,
        "Disk reserve reached",
        "capacity_disk",
    )
    check(
        sample["available_ram_bytes"] >= min_ram_bytes,
        "Available RAM guard reached",
        "capacity_ram",
    )
    check(
        sample["rss_bytes"] <= max_rss_bytes, "Server RSS guard reached", "capacity_rss"
    )


def private_config(directory):
    return json.loads(
        (validate_directory(directory) / PRIVATE_CONFIG).read_text(encoding="utf-8")
    )


def read_resource_snapshot(directory, operational, runtime):
    """Private QA observation; two-second cooperative DB budget, no source locks.

    SQLite busy/progress guards do not bound an OS filesystem stall. The HTTP
    caller retains its separate five-second timeout and any failure is fatal.
    """
    deadline = time.monotonic() + RESOURCE_DB_SECONDS
    sample = system_resources(directory)
    check(
        time.monotonic() < deadline,
        "Private resource observation deadline exceeded",
        "telemetry",
    )
    with closing(
        sqlite3.connect(
            Path(operational).resolve().as_uri() + "?mode=ro",
            uri=True,
            timeout=min(0.1, max(0, deadline - time.monotonic())),
        )
    ) as db:
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA query_only=ON")
            db.execute("PRAGMA busy_timeout=100")
            db.set_progress_handler(lambda: time.monotonic() >= deadline, 1000)
            db.execute("BEGIN")
            sample["pending"] = db.execute("SELECT count(*) FROM queue").fetchone()[0]
            sample["fts_state"] = dict(
                db.execute(
                    "SELECT indexed_documents,pending_documents,pending_bytes,applied_sequence,"
                    "bootstrap_required,generation,purges,last_error,"
                    "(SELECT count(*) FROM log_fts_inflight) AS inflight "
                    "FROM log_fts_state WHERE singleton=1"
                ).fetchone()
            )
        finally:
            db.set_progress_handler(None, 0)
            db.rollback()
    check(
        time.monotonic() < deadline,
        "Private resource observation deadline exceeded",
        "telemetry",
    )
    sample["fts_state"]["last_error"] = diagnostics.error_code(
        sample["fts_state"].get("last_error")
    )
    sample["indexer"] = runtime.health()
    return sample


async def resource_snapshot(directory, operational, runtime):
    from starlette.concurrency import run_in_threadpool

    return await run_in_threadpool(
        read_resource_snapshot, directory, operational, runtime
    )


def serve(directory):
    """Child-only shim; no public product code or production configuration is changed."""
    import asyncio

    import uvicorn
    from fastapi import HTTPException, Request
    from starlette.concurrency import run_in_threadpool

    from sapientia import auth, log_search
    from sapientia.api import create_app
    from sapientia.storage import Settings

    directory = validate_directory(directory)
    config = private_config(directory)
    check(
        type(config["port"]) is int
        and 1024 <= config["port"] <= 65535
        and config["port"] not in {8787, 8788, 8790, 8791},
        "Private QA listener must use an unreserved loopback port",
        "isolation",
    )
    for key in list(os.environ):
        if key.startswith("SAPIENTIA_"):
            os.environ.pop(key)
    settings = Settings(
        directory / "data",
        min_free_bytes=config["reserve_bytes"],
        query_timeout=config["query_timeout"],
        memory_limit="512MB",
        workers=4,
        fts_max_bytes=config["fts_max_bytes"],
    )
    app = create_app(settings, background=True)
    store, runtime = app.state.store, app.state.runtime
    with store.control(local=True) as db:
        existing = {row[0] for row in db.execute("SELECT name FROM users")}
    if not existing:
        for tenant in TENANTS:
            auth.create_user(
                store, "qa_" + tenant, config["passwords"][tenant], "admin", tenant
            )
    check(
        not existing or existing == {"qa_" + tenant for tenant in TENANTS},
        "Unexpected identities in QA store",
        "isolation",
    )
    token = config["control_token"].encode()

    def authorized(request):
        if not hmac.compare_digest(
            request.headers.get("X-QA-Control", "").encode(), token
        ):
            raise HTTPException(401, "QA control credential required")

    @app.get("/__qa/scale/resources")
    async def resources(request: Request):
        authorized(request)
        try:
            return await resource_snapshot(directory, store.operational, runtime)
        except (sqlite3.Error, ScaleFailure) as exc:
            raise HTTPException(
                503, "Private QA resource observation unavailable"
            ) from exc

    @app.get("/__qa/scale/admission-state")
    async def admission_state(request: Request):
        authorized(request)
        try:
            budget = float(request.headers.get("X-QA-Diagnostic-Budget", "2"))
            if not math.isfinite(budget) or not 0 < budget <= 2:
                raise ValueError("Invalid diagnostic deadline")
        except ValueError as exc:
            raise HTTPException(400, "Invalid diagnostic deadline") from exc
        return await run_in_threadpool(
            diagnostics.local_snapshot, store, runtime, time.monotonic() + budget
        )

    @app.post("/__qa/scale/seal")
    async def seal(request: Request):
        authorized(request)
        future = time.time() + 2 * 86400
        result = await run_in_threadpool(store.segments.seal, now=future, batch=100_000)
        return {
            **result,
            "simulated_future_epoch": future,
            "batch_per_partition": 100_000,
        }

    @app.get("/__qa/scale/fts-population")
    async def fts_population(request: Request):
        authorized(request)
        try:
            configured = config.get("fts_observation_timeout", config["query_timeout"])
            timeout = fts_observation_budget(
                configured,
                request.headers.get("X-QA-Observation-Budget", str(configured)),
            )
            # Dedicated phase observation, deliberately absent from15s polling.
            return await run_in_threadpool(
                read_fts_population,
                store.path / "log-search" / "terms.sqlite3",
                log_search._fts_lock(store),
                timeout,
            )
        except ValueError as exc:
            raise HTTPException(400, "Invalid observation deadline") from exc
        except ScaleFailure as exc:
            raise HTTPException(
                503, "Actual FTS population observation failed"
            ) from exc

    common = {
        "host": "127.0.0.1",
        "port": config["port"],
        "proxy_headers": False,
        "access_log": False,
        "ssl_certfile": str(directory / "test-cert.pem"),
        "ssl_keyfile": str(directory / "test-key.pem"),
        "timeout_graceful_shutdown": 20,
        "log_level": "error",
    }
    server = uvicorn.Server(uvicorn.Config(app, **common))

    async def run():
        task = asyncio.create_task(server.serve())
        try:
            while not (directory / "stop").exists():
                if task.done():
                    await task
                    raise RuntimeError("QA listener stopped unexpectedly")
                await asyncio.sleep(0.1)
        finally:
            server.should_exit = True
            await task

    asyncio.run(run())


class Service(IsolatedService):
    """Reuse the already qualified owned-Python-tree and released-file checks."""

    def __init__(self, directory, timeout):
        super().__init__(directory, "https", timeout)
        check(
            self.port not in {8787, 8788, 8790, 8791},
            "Reserved port selected",
            "isolation",
        )
        self.starts = []

    def start(self, remaining):
        started = time.monotonic()
        startup_budget = min(300, remaining)
        config = private_config(self.directory)
        config["port"] = self.port
        atomic_json(self.directory / PRIVATE_CONFIG, config)
        (self.directory / "stop").unlink(missing_ok=True)
        self.generation += 1
        start_record = {
            "generation": self.generation,
            "launcher_pid": None,
            "startup_seconds": 0.0,
            "passed": False,
            "harness_startup_ceiling_seconds": startup_budget,
            "ceiling_meaning": "Harness guard only; not a product recovery-time guarantee",
        }
        self.starts.append(start_record)
        self.log = (self.directory / "private-server.log").open("ab")
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("SAPIENTIA_")
        }
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-B",
                str(Path(__file__).resolve()),
                "--serve",
                str(self.directory),
            ],
            cwd=STAGE,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=self.log,
            stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        start_record["launcher_pid"] = self.process.pid
        deadline = started + startup_budget
        with self.client() as client:
            while time.monotonic() < deadline:
                start_record["startup_seconds"] = time.monotonic() - started
                check(
                    self.process.poll() is None,
                    "QA server exited during startup",
                    "startup",
                )
                try:
                    response = client.get(
                        "/api/bootstrap",
                        timeout=min(2, max(0.01, deadline - time.monotonic())),
                    )
                    if response.status_code == 200:
                        if os.name == "nt":
                            self._capture_windows_children()
                        start_record.update(
                            server_version=response.json()["version"],
                            startup_seconds=time.monotonic() - started,
                            passed=True,
                        )
                        return
                except httpx.TransportError:
                    pass
                time.sleep(0.1)
        start_record["startup_seconds"] = time.monotonic() - started
        raise ScaleFailure(
            "startup", "Fresh private TLS service did not start before its deadline"
        )

    def stop(self):
        forced = False
        if self.process is not None and self.process.poll() is None:
            (self.directory / "stop").write_text("stop\n", encoding="utf-8")
            try:
                self.process.wait(timeout=max(40, self.timeout + 30))
            except subprocess.TimeoutExpired:
                forced = True
        exit_code = self.process.poll() if self.process else None
        super().stop()
        if self.stop_checks:
            self.stop_checks[-1]["graceful_marker_shutdown"] = not forced
            self.stop_checks[-1]["exit_code_before_force"] = exit_code
        check(not forced, "QA service needed forced owned-tree termination", "shutdown")
        check(
            exit_code in (0, None), "QA service exited with a nonzero code", "shutdown"
        )


class Recorder:
    def __init__(self, target, initial):
        self.target, self.value = target, initial
        self.lock = threading.RLock()
        self.failure = None

    def update(self, **values):
        with self.lock:
            self.value.update(values)

    def append(self, key, value):
        with self.lock:
            self.value.setdefault(key, []).append(value)

    def save(self):
        with self.lock:
            atomic_json(self.target, self.value)

    def abort(self, exc):
        with self.lock:
            if self.failure is None:
                self.failure = exc


def observe_resources(record, sample, preserve=False, limit=16384):
    """Keep 15-second samples and extrema, including a guard-failing observation."""
    with record.lock:
        record.value["latest_resources"] = sample
        extrema = record.value.setdefault("resource_extrema", {})
        for field, operation in (
            ("rss_bytes", max),
            ("available_ram_bytes", min),
            ("disk_free_bytes", min),
        ):
            label = ("peak_" if operation is max else "minimum_") + field
            extrema[label] = operation(extrema.get(label, sample[field]), sample[field])
        values = record.value.setdefault("resource_samples", [])
        if (
            preserve
            or not values
            or sample["elapsed_seconds"] - values[-1]["elapsed_seconds"] >= 15
        ):
            values.append(sample)
            if len(values) > limit:
                del values[0]
                record.value["resource_samples_older_dropped"] = (
                    record.value.get("resource_samples_older_dropped", 0) + 1
                )


class Trial:
    def __init__(self, args, directory, recorder, config):
        self.args, self.directory, self.record, self.config = (
            args,
            directory,
            recorder,
            config,
        )
        self.started = time.monotonic()
        self.deadline = self.started + args.max_seconds
        self.service = Service(directory, args.query_timeout)
        self.clients = {}
        self.control = None
        self.monitor = None
        self.monitor_stop = threading.Event()
        self.paused = threading.Event()
        self.attempt_latency, self.batch_latency = array("d"), array("d")
        self.metrics = {
            "unique_original_events_acked": 0,
            "accepted_acks": 0,
            "duplicate_acks": 0,
            "capacity_retries": 0,
            "transport_retries": 0,
            "http_requests": 0,
            "wire_request_bytes_including_retries": 0,
            "original_wire_bytes": 0,
            "generator_seconds": 0.0,
            "admission_seconds": 0.0,
        }
        if args.admission_mode == "server_backoff":
            self.metrics.update(
                retry_wait_seconds=0.0,
                retry_waits=0,
                retry_after_classifications={
                    key: 0
                    for key in (
                        "delta",
                        "http_date",
                        "missing",
                        "invalid",
                        "out_of_policy",
                    )
                },
                maximum_batch_attempts=0,
                late_ack_batches=0,
            )
        self.corpus = Corpus(
            args.profile, config["base_epoch"], bytes.fromhex(config["corpus_key"])
        )
        self.source = source_identity()
        self.completed, self.last_sealed, self.fts_success_at = 0, 0, None
        self.record.value["admission_diagnostics"] = {}
        self.evidence = diagnostics.AdmissionEvidence(
            self.record.value["admission_diagnostics"], self.admission_snapshot
        )
        if args.admission_mode == "server_backoff":
            self.record.value["admission_diagnostics"]["timing_scope"] = (
                "First capacity snapshot is asynchronous; terminal admission snapshot follows the explicitly bounded server_backoff policy; attempt evidence is capped independently"
            )

    def guard(self):
        if self.record.failure:
            raise self.record.failure
        check(
            time.monotonic() < self.deadline,
            "Qualification wall-clock work budget exhausted",
            "time_budget",
        )

    def request(self, client, method, path, **kwargs):
        self.guard()
        timeout = min(self.args.query_timeout + 5, self.deadline - time.monotonic())
        started = time.monotonic()
        try:
            response = client.request(
                method, path, timeout=max(0.01, timeout), **kwargs
            )
        except httpx.TransportError as exc:
            self.observe_http_failure(method, path, started, transport_error=exc)
            raise ScaleFailure(
                "transport", f"{method} {path.split('?')[0]} transport failure"
            ) from None
        if response.status_code >= 400:
            self.observe_http_failure(method, path, started, response=response)
        return response

    def actual_fts_population_request(self):
        """Full-population verification has a separate, reported work budget."""
        self.guard()
        started = time.monotonic()
        remaining = self.deadline - started
        budget = min(self.args.fts_observation_timeout, remaining)
        path = "/__qa/scale/fts-population"
        try:
            response = self.control.get(
                path,
                headers={"X-QA-Observation-Budget": str(budget)},
                timeout=max(0.01, min(budget + 5, remaining)),
            )
        except httpx.TransportError as exc:
            self.observe_http_failure("GET", path, started, transport_error=exc)
            raise ScaleFailure(
                "transport", "Actual FTS population transport failure"
            ) from None
        if response.status_code >= 400:
            self.observe_http_failure("GET", path, started, response=response)
        check(
            response.status_code == 200,
            f"Actual FTS population returned HTTP {response.status_code}",
            "http",
        )
        self.guard()
        return response.json()

    def observe_http_failure(
        self, method, path, started, response=None, transport_error=None
    ):
        # Parse only the response already received; no extra request or producer pause.
        observation = diagnostics.http_evidence(response, transport_error)
        with self.record.lock:
            target = self.record.value.setdefault(
                "http_failures", {"observations": [], "dropped": 0, "limit": 64}
            )
            rows = target["observations"]
            if len(rows) >= target["limit"]:
                rows.pop(0)
                target["dropped"] += 1
            rows.append(
                {
                    "stage": self.record.value.get("stage"),
                    "method": method,
                    "path": path.split("?")[0],
                    "elapsed_seconds": time.monotonic() - started,
                    **observation,
                }
            )

    def expect(self, client, method, path, expected=200, **kwargs):
        response = self.request(client, method, path, **kwargs)
        check(
            response.status_code == expected,
            f"{method} {path.split('?')[0]} returned HTTP {response.status_code}",
            "http",
        )
        return response

    def connect(self):
        self.service.start(max(0.01, self.deadline - time.monotonic()))
        self.record.update(service_starts=list(self.service.starts))
        for tenant in TENANTS:
            client = self.service.client()
            result = self.expect(
                client,
                "POST",
                "/api/login",
                json={
                    "name": "qa_" + tenant,
                    "password": self.config["passwords"][tenant],
                },
            ).json()
            client.headers["X-CSRF-Token"] = result["csrf"]
            issued = self.expect(
                client,
                "POST",
                "/api/tokens",
                json={"name": "isolated-scale", "allowed_indexes": list(INDEXES)},
            ).json()
            collector = self.service.client()
            collector.headers.update(
                {
                    "Authorization": "Bearer " + issued["token"],
                    "Content-Type": "application/json",
                }
            )
            self.clients[tenant] = (client, collector)
        self.control = self.service.client()
        self.control.headers["X-QA-Control"] = self.config["control_token"]
        self.resource_check(preserve=True)

    def resource_check(self, client=None, preserve=False, operation=None):
        operation = operation or (lambda *args: None)
        client = client or self.control
        operation("resource_http")
        response = client.get("/__qa/scale/resources", timeout=5)
        operation("resource_status", response.status_code)
        check(
            response.status_code == 200,
            "Private QA resource observation failed",
            "telemetry",
        )
        operation("resource_decode", response.status_code)
        sample = response.json()
        sample["elapsed_seconds"] = time.monotonic() - self.started
        sample["acknowledged_original_events"] = self.metrics[
            "unique_original_events_acked"
        ]
        sample["service_generation"] = self.service.generation
        operation("resource_record", response.status_code)
        observe_resources(self.record, sample, preserve)
        try:
            operation("resource_guard", response.status_code)
            guard_resources(
                sample,
                self.config["reserve_bytes"],
                self.args.min_free_ram_mib * 1024**2,
                self.args.max_rss_gib * 1024**3,
            )
        except ScaleFailure as exc:
            observe_resources(self.record, sample, preserve=True)
            self.record.abort(exc)
            operation("resource_persist", response.status_code)
            try:
                self.record.save()
            except Exception as save_exc:  # noqa: BLE001 - Preserve the first resource breach even when checkpoint persistence fails.
                self.record.update(
                    monitor_persist_failure=monitor_error("record_save", save_exc)
                )
            operation("resource_guard", response.status_code)
            raise
        return sample

    def monitoring(self):
        while not self.monitor_stop.wait(15):
            phase, status = "client_open", None
            primary = None

            def operation(value, response_status=None):
                nonlocal phase, status
                phase = value
                status = response_status

            try:
                with self.service.client() as client:
                    try:
                        self._monitor_sample(client, operation)
                    except Exception as exc:
                        primary = (phase, exc, status)
                        raise
                    finally:
                        operation("client_close")
                if primary is not None:
                    raise primary[1]
            except Exception as exc:  # noqa: BLE001 - Persist sanitized telemetry failures for the whole client lifetime.
                if primary is not None:
                    if exc is not primary[1]:
                        self.record.update(
                            monitor_close_failure=monitor_error("client_close", exc)
                        )
                    phase, exc, status = primary
                self.record.abort(
                    exc
                    if isinstance(exc, ScaleFailure)
                    else ScaleFailure(
                        "telemetry", "Resource monitor could not continue"
                    )
                )
                self.record.update(monitor_failure=monitor_error(phase, exc, status))
                try:
                    self.record.save()
                except Exception as save_exc:  # noqa: BLE001 - Keep fatal state in memory without an unhandled secret-bearing traceback.
                    self.record.update(
                        monitor_persist_failure=monitor_error("record_save", save_exc)
                    )
                return

    def _monitor_sample(self, client, operation):
        operation("client_headers")
        client.headers["X-QA-Control"] = self.config["control_token"]
        operation("guard")
        self.guard()
        if not self.paused.is_set():
            self.resource_check(client, preserve=True, operation=operation)
        operation("admission_summary")
        summary = self.admission_summary()
        operation("record_update")
        self.record.update(
            elapsed_seconds=time.monotonic() - self.started,
            admission=summary,
        )
        operation("record_save")
        self.record.save()
        operation("progress_read")
        with self.record.lock:
            latest = self.record.value.get("latest_resources", {})
            stage = self.record.value.get("stage")
        operation("progress_print")
        print(
            json.dumps(
                {
                    "stage": stage,
                    "acknowledged": self.metrics["unique_original_events_acked"],
                    "elapsed_seconds": time.monotonic() - self.started,
                    "pending": latest.get("pending"),
                    "rss_bytes": latest.get("rss_bytes"),
                    "available_ram_bytes": latest.get("available_ram_bytes"),
                    "disk_free_bytes": latest.get("disk_free_bytes"),
                }
            ),
            flush=True,
        )

    def admission_summary(self):
        return {
            **self.metrics,
            "retry_policy": admission_retry_policy(self.args),
            "request_latency": latency_summary(self.attempt_latency),
            "batch_ack_latency_including_retries": latency_summary(self.batch_latency),
        }

    def admission_snapshot(self, deadline, context):
        deadline = min(deadline, self.deadline)
        result = {}
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {"observation_error": "diagnostic_deadline"}
        result["private_http_timeout_seconds"] = remaining
        try:
            response = self.control.get(
                "/__qa/scale/admission-state",
                timeout=remaining,
                headers={"X-QA-Diagnostic-Budget": str(remaining)},
            )
            if response.status_code == 200:
                result["private"] = response.json()
            else:
                result["private_response"] = diagnostics.http_evidence(response)
        except Exception as exc:  # noqa: BLE001 - Keep the original retry failure.
            result["private_observation_error"] = diagnostics.error_type(exc)
        remaining = deadline - time.monotonic()
        if remaining > 0:
            try:
                result["public"] = diagnostics.public_snapshot(
                    self.clients[context["tenant"]][0], remaining
                )
            except Exception as exc:  # noqa: BLE001 - Public status may be busy while indexing.
                result["public_observation_error"] = diagnostics.error_type(exc)
        return result

    def admit(self, tenant, body, count, original=True):
        if getattr(self.args, "admission_mode", "burst8") == "server_backoff":
            return self.admit_server_backoff(tenant, body, count, original)
        check(len(body) <= BODY_LIMIT and count <= BATCH_LIMIT, "Batch bound violated")
        began = time.monotonic()
        context = None
        for attempt in range(8):
            self.guard()
            request_started = time.monotonic()
            try:
                response = self.clients[tenant][1].post(
                    "/api/v1/events",
                    content=body,
                    timeout=max(
                        0.01,
                        min(
                            self.args.query_timeout + 5,
                            self.deadline - time.monotonic(),
                        ),
                    ),
                )
            except httpx.TransportError as exc:
                self.metrics["transport_retries"] += 1
                response = None
                context = context or {
                    "tenant": tenant,
                    **diagnostics.encoded_batch_summary(
                        body,
                        count,
                        self.metrics["unique_original_events_acked"],
                    ),
                }
                self.evidence.observe(
                    None, context, attempt, time.monotonic() - request_started, exc
                )
            finally:
                self.attempt_latency.append(time.monotonic() - request_started)
                self.metrics["http_requests"] += 1
                self.metrics["wire_request_bytes_including_retries"] += len(body)
            if response is not None and response.status_code == 202:
                try:
                    ack = response.json()
                except ValueError:
                    raise ScaleFailure(
                        "integrity", "Durable admission receipt mismatch"
                    ) from None
                check(
                    isinstance(ack, dict)
                    and ack.get("durable") is True
                    and type(ack.get("accepted")) is int
                    and type(ack.get("duplicate")) is int
                    and ack["accepted"] >= 0
                    and ack["duplicate"] >= 0
                    and ack["accepted"] + ack["duplicate"] == count,
                    "Durable admission receipt mismatch",
                )
                self.metrics["accepted_acks"] += ack["accepted"]
                self.metrics["duplicate_acks"] += ack["duplicate"]
                if original:
                    self.metrics["unique_original_events_acked"] += count
                    self.metrics["original_wire_bytes"] += len(body)
                self.batch_latency.append(time.monotonic() - began)
                return ack
            if response is not None:
                context = context or {
                    "tenant": tenant,
                    **diagnostics.encoded_batch_summary(
                        body,
                        count,
                        self.metrics["unique_original_events_acked"],
                    ),
                }
                self.evidence.observe(
                    response, context, attempt, time.monotonic() - request_started
                )
                self.evidence.capture(
                    "first_capacity"
                    if response.status_code in {429, 503}
                    else "admission_failed",
                    context,
                )
                check(
                    response.status_code in {429, 503},
                    f"Ingestion returned HTTP {response.status_code}",
                    "http",
                )
                self.metrics["capacity_retries"] += 1
                self.resource_check()
            time.sleep(min(0.8, 0.05 * 2**attempt))
        self.evidence.capture(
            "admission_failed", context or {"tenant": tenant, "batch_events": count}
        )
        try:
            self.record.save()
        except OSError:
            pass  # Preserve admission_retry; the final report save remains mandatory.
        raise ScaleFailure(
            "admission_retry", "Stable-body admission retry budget exhausted"
        )

    def admission_guard(self, batch_deadline):
        self.guard()
        check(
            not self.monitor_stop.is_set(),
            "Qualification admission cancelled",
            "interrupted",
        )
        check(
            time.monotonic() < batch_deadline,
            "Stable-body admission batch budget exhausted",
            "admission_retry_budget",
        )

    def wait_admission_retry(self, due, batch_deadline):
        self.admission_guard(batch_deadline)
        check(
            due < batch_deadline,
            "Retry-After or fallback wait exceeds remaining admission budget",
            "admission_retry_budget",
        )
        started = time.monotonic()
        if started < due:
            self.metrics["retry_waits"] += 1
        try:
            while True:
                self.admission_guard(batch_deadline)
                remaining = due - time.monotonic()
                if remaining <= 0:
                    return
                time.sleep(min(0.25, remaining))
        finally:
            self.metrics["retry_wait_seconds"] += time.monotonic() - started

    def admit_server_backoff(self, tenant, body, count, original=True):
        """Optional HTTP advice scheduling, without a durable client outbox."""
        check(len(body) <= BODY_LIMIT and count <= BATCH_LIMIT, "Batch bound violated")
        began = time.monotonic()
        batch_deadline = min(self.deadline, began + self.args.admission_batch_seconds)
        context = {
            "tenant": tenant,
            **diagnostics.encoded_batch_summary(
                body, count, self.metrics["unique_original_events_acked"]
            ),
        }
        try:
            for attempt in range(self.args.admission_max_attempts):
                self.admission_guard(batch_deadline)
                self.metrics["maximum_batch_attempts"] = max(
                    self.metrics["maximum_batch_attempts"], attempt + 1
                )
                request_started = time.monotonic()
                response = None
                try:
                    response = self.clients[tenant][1].post(
                        "/api/v1/events",
                        content=body,
                        timeout=max(
                            0.01,
                            min(
                                self.args.query_timeout + 5,
                                batch_deadline - request_started,
                            ),
                        ),
                    )
                except httpx.TransportError as exc:
                    self.metrics["transport_retries"] += 1
                    self.evidence.observe(
                        None, context, attempt, time.monotonic() - request_started, exc
                    )
                finally:
                    received = time.monotonic()
                    received_wall = time.time()
                    self.attempt_latency.append(received - request_started)
                    self.metrics["http_requests"] += 1
                    self.metrics["wire_request_bytes_including_retries"] += len(body)
                if response is not None and response.status_code == 202:
                    try:
                        ack = response.json()
                    except ValueError:
                        raise ScaleFailure(
                            "integrity", "Durable admission receipt mismatch"
                        ) from None
                    check(
                        isinstance(ack, dict)
                        and ack.get("durable") is True
                        and type(ack.get("accepted")) is int
                        and type(ack.get("duplicate")) is int
                        and ack["accepted"] >= 0
                        and ack["duplicate"] >= 0
                        and ack["accepted"] + ack["duplicate"] == count,
                        "Durable admission receipt mismatch",
                    )
                    self.metrics["accepted_acks"] += ack["accepted"]
                    self.metrics["duplicate_acks"] += ack["duplicate"]
                    if original:
                        self.metrics["unique_original_events_acked"] += count
                        self.metrics["original_wire_bytes"] += len(body)
                    self.batch_latency.append(received - began)
                    if received >= batch_deadline:
                        self.metrics["late_ack_batches"] += 1
                        raise ScaleFailure(
                            "admission_retry_budget",
                            "Durable ACK arrived after admission budget",
                        )
                    self.admission_guard(batch_deadline)
                    return ack
                if response is not None:
                    self.evidence.observe(
                        response, context, attempt, received - request_started
                    )
                    self.evidence.capture(
                        "first_capacity"
                        if response.status_code in {429, 503}
                        else "admission_failed",
                        context,
                    )
                    check(
                        response.status_code in {429, 503},
                        f"Ingestion returned HTTP {response.status_code}",
                        "http",
                    )
                    self.metrics["capacity_retries"] += 1
                    self.resource_check()
                if attempt + 1 == self.args.admission_max_attempts:
                    break
                kind, delay = admission_retry_delay(
                    response.headers if response is not None else None,
                    attempt,
                    received_wall,
                )
                self.metrics["retry_after_classifications"][kind] += 1
                if delay > RETRY_AFTER_LIMIT:
                    self.metrics["retry_after_classifications"]["out_of_policy"] += 1
                    raise ScaleFailure(
                        "admission_retry_advice",
                        "Retry-After exceeds bounded admission advice policy",
                    )
                self.wait_admission_retry(received + delay, batch_deadline)
            raise ScaleFailure(
                "admission_retry", "Stable-body admission attempt budget exhausted"
            )
        except ScaleFailure:
            self.evidence.capture("admission_failed", context)
            try:
                self.record.save()
            except OSError:
                pass  # Preserve the terminal cause; the final report save remains mandatory.
            raise

    def drain(self):
        began = time.monotonic()
        while True:
            self.guard()
            sample = self.resource_check()
            if sample["pending"] == 0:
                return {
                    "seconds": time.monotonic() - began,
                    "pending": 0,
                    "observation": "Harness-private read-only SQLite queue count; not an HTTP search assertion",
                }
            time.sleep(0.25)

    def assert_source(self):
        current = source_identity()
        check(
            current["product_source_sha256"] == self.source["product_source_sha256"]
            and current["harness_sha256"] == self.source["harness_sha256"]
            and current["diagnostics_helper_sha256"]
            == self.source["diagnostics_helper_sha256"],
            "Frozen product or scale harness bytes changed",
            "source_changed",
        )

    def integrity(self, total, reason):
        began = time.monotonic()
        wanted = expected_scopes(total)
        rows_out, numeric_out, tenant_out = [], [], []
        for tenant in TENANTS:
            client = self.clients[tenant][0]
            base = {
                "language": "spl",
                "earliest": self.config["base_epoch"],
                "latest": self.config["base_epoch"] + 3600,
            }
            global_row = self.expect(
                client,
                "POST",
                "/api/search",
                json={**base, "query": "search * | stats " + STATS},
            ).json()["rows"]
            check(len(global_row) == 1, "Tenant aggregate row count mismatch")
            tenant_scopes = [wanted[(tenant, index)] for index in INDEXES]
            aggregate_expected = {
                "count": sum(x["count"] for x in tenant_scopes),
                "sequence_sum": sum(x["sequence_sum"] for x in tenant_scopes),
                "minimum_sequence": min(
                    (x["minimum_sequence"] for x in tenant_scopes if x["count"]),
                    default=None,
                ),
                "maximum_sequence": max(
                    (x["maximum_sequence"] for x in tenant_scopes if x["count"]),
                    default=None,
                ),
            }
            tenant_out.append(
                {
                    "tenant": tenant,
                    **validate_aggregate(global_row[0], aggregate_expected),
                }
            )
            grouped = self.expect(
                client,
                "POST",
                "/api/search",
                json={**base, "query": "search * | stats " + STATS + " by index_name"},
            ).json()["rows"]
            check(
                {row["index_name"] for row in grouped}
                == {index for index in INDEXES if wanted[(tenant, index)]["count"]},
                "Unexpected or missing tenant/index scope",
            )
            for row in grouped:
                result = validate_aggregate(row, wanted[(tenant, row["index_name"])])
                rows_out.append(
                    {"tenant": tenant, "index": row["index_name"], **result}
                )
            # JSON numeric predicates reject numeric strings/boolean values;
            # namespace coverage proves cross-tenant event-ID sets are disjoint.
            typed = self.expect(
                client,
                "POST",
                "/api/search",
                json={
                    "language": "json",
                    "earliest": base["earliest"],
                    "latest": base["latest"],
                    "query": {
                        "filters": [
                            {"field": "raw.sequence", "op": "number_gte", "value": 0},
                            {
                                "field": "raw.sequence",
                                "op": "number_lt",
                                "value": total,
                            },
                            {
                                "field": "event_id",
                                "op": "regex",
                                "value": "^scale_" + tenant + "_",
                            },
                        ],
                        "group_by": ["index_name"],
                        "sort": "count",
                    },
                },
            ).json()["rows"]
            actual = {row["index_name"]: exact_integer(row["count"]) for row in typed}
            check(
                actual
                == {
                    index: wanted[(tenant, index)]["count"]
                    for index in INDEXES
                    if wanted[(tenant, index)]["count"]
                },
                "Stored sequence type or disjoint tenant-ID namespace mismatch",
            )
            numeric_out.append(
                {
                    "tenant": tenant,
                    "typed_numeric_and_namespace_count": sum(actual.values()),
                    "indexes": actual,
                }
            )
        check(
            sum(row["count"] for row in rows_out) == total,
            "Global scoped count mismatch",
        )
        check(
            sum(row["distinct_ids"] for row in rows_out) == total,
            "Global disjoint distinct mismatch",
        )
        check(
            sum(row["sequence_sum"] for row in rows_out) == total * (total - 1) // 2,
            "Global exact sum mismatch",
        )
        result = {
            "passed": True,
            "population": total,
            "reason": reason,
            "scope_rows": rows_out,
            "tenant_global_rows": tenant_out,
            "numeric_type_coverage": numeric_out,
            "seconds": time.monotonic() - began,
            "HTTP_search_requests": 6,
            "global_count": sum(row["count"] for row in tenant_out),
            "global_distinct_ids": sum(row["distinct_ids"] for row in tenant_out),
            "sequence_sum": sum(row["sequence_sum"] for row in tenant_out),
            "global_sequence_min": min(
                (row["minimum_sequence"] for row in tenant_out if row["count"]),
                default=None,
            ),
            "global_sequence_max": max(
                (row["maximum_sequence"] for row in tenant_out if row["count"]),
                default=None,
            ),
            "numeric_sum_note": "Stored numeric JSON verified; generated integers and total below 2^53; no int(float()) truncation",
            "distinct_note": "Exact per-tenant distinct plus exact index scopes; checked disjoint stored tenant-ID namespaces",
            "proof_scope": "Full-population aggregate and identifier consistency checks only; not an independent cryptographic full-content proof",
            "full_population_cryptographic_content_hash": "not_tested",
        }
        self.record.append("integrity_checks", result)
        return result

    def seal(self):
        began, sealed = time.monotonic(), 0
        while True:
            result = self.expect(self.control, "POST", "/__qa/scale/seal").json()
            sealed += exact_integer(result["sealed_events"])
            if not result["sealed_events"]:
                break
        check(
            sealed == self.completed - self.last_sealed,
            "Sealed history population mismatch",
        )
        new_after_history = self.last_sealed > 0 and self.completed > self.last_sealed
        record = {
            "population": self.completed,
            "sealed_this_pause": sealed,
            "sealed_total": self.completed,
            "batch_per_partition": 100_000,
            "seconds": time.monotonic() - began,
            "clock": "Explicit QA-only now=wall clock+2 days; received clock, no actual aging claim",
            "new_ingest_after_prior_sealed_history": new_after_history,
        }
        self.last_sealed = self.completed
        self.record.append("sealing", record)

    def fts(self, total, requested_phase):
        began = time.monotonic()
        result = {
            "phase": requested_phase,
            "population": total,
            "passed": False,
            "status": "not_completed",
            "scope": "Full Store FTS index with bounded rare-hit snapshots",
            "per_query_timeout_seconds": self.args.query_timeout,
            "actual_population_observation_budget_seconds": self.args.fts_observation_timeout,
            "actual_population_observation_scope": "QA-only full row population proof; separate from interactive query/readiness budgets",
            "interactive_15_second_profile": self.args.query_timeout == 15,
            "incremental_prerequisite": self.fts_success_at is not None
            and total > self.fts_success_at,
        }
        snapshots = []
        try:
            wait_started = time.monotonic()
            ready_deadline = min(
                self.deadline, wait_started + self.args.fts_ready_timeout
            )
            while True:
                statuses = []
                for tenant in TENANTS:
                    status = self.expect(
                        self.clients[tenant][0], "GET", "/api/logs/status"
                    ).json()
                    fulltext = status.get("search", {}).get("fulltext")
                    if not isinstance(fulltext, dict):
                        result.update(
                            status="readiness_contract_unavailable",
                            error_kind="fts_not_qualified",
                        )
                        return
                    statuses.append(
                        {
                            "tenant": tenant,
                            **{
                                key: fulltext.get(key)
                                for key in (
                                    "state",
                                    "ready",
                                    "pending_documents",
                                    "pending_bytes",
                                    "lag_seconds",
                                    "budget_bytes",
                                    "error",
                                )
                            },
                        }
                    )
                result["last_readiness"] = statuses
                result["ready_wait_seconds"] = time.monotonic() - wait_started
                if all(item["ready"] is True for item in statuses):
                    break
                if any(
                    item["state"] in {"capacity_error", "bootstrap_required", "error"}
                    for item in statuses
                ):
                    result.update(
                        status="readiness_"
                        + next(
                            item["state"]
                            for item in statuses
                            if item["state"]
                            in {"capacity_error", "bootstrap_required", "error"}
                        ),
                        error_kind="fts_not_ready",
                    )
                    return
                if time.monotonic() >= ready_deadline:
                    result.update(
                        status="readiness_timeout", error_kind="fts_not_ready"
                    )
                    return
                time.sleep(min(2, max(0.01, ready_deadline - time.monotonic())))
            observation = self.resource_check(preserve=True).get("fts_state")
            result["fts_population"] = {
                "passed": False,
                "expected_population": total,
                "observed": observation,
            }
            result["fts_population"] = validate_fts_population(observation, total)
            proof_started = time.monotonic()
            result["actual_fts_population"] = {
                "passed": False,
                "expected_population": total,
                "scope": "Independent actual SQLite rows, not cached counters",
            }
            try:
                actual = self.actual_fts_population_request()
                result["actual_fts_population"]["observed"] = actual
                result["actual_fts_population"] = validate_actual_fts_population(
                    actual, total
                )
            finally:
                result["actual_population_observation_wall_seconds"] = (
                    time.monotonic() - proof_started
                )
            interactive = time.monotonic()
            for tenant in TENANTS:
                client = self.clients[tenant][0]
                response = self.request(
                    client,
                    "POST",
                    "/api/logs/snapshots",
                    json={
                        "query": {
                            "earliest": self.config["base_epoch"],
                            "latest": self.config["base_epoch"] + 3600,
                        },
                        "fulltext": '"synthetic scale sentinel"',
                    },
                )
                if response.status_code != 201:
                    result.update(
                        status="HTTP_" + str(response.status_code),
                        error_kind="fts_capacity_deadline_or_query_failure",
                    )
                    return
                snapshot = response.json()
                snapshots.append((client, snapshot["id"]))
                check(
                    snapshot["rows"] == expected_sentinels(total, tenant)
                    and not snapshot["truncated"],
                    "FTS rare-hit count mismatch",
                )
            result["interactive_query_seconds"] = time.monotonic() - interactive
            result.update(
                passed=True,
                status="passed",
                matched_events=sum(expected_sentinels(total, t) for t in TENANTS),
            )
            if (
                requested_phase == "incremental"
                and not result["incremental_prerequisite"]
            ):
                result.update(
                    passed=False,
                    status="cold_retry_not_incremental",
                    error_kind="incremental_not_qualified",
                )
            else:
                self.fts_success_at = total
        except ScaleFailure as exc:
            if exc.kind in {
                "capacity_disk",
                "capacity_ram",
                "capacity_rss",
                "source_changed",
                "time_budget",
            }:
                raise
            result.update(status="failed", error_kind=exc.kind)
        finally:
            try:
                for client, identifier in snapshots:
                    self.expect(client, "DELETE", "/api/logs/snapshots/" + identifier)
            except Exception:
                result.update(passed=False, cleanup_failed=True)
                raise
            finally:
                result["seconds"] = time.monotonic() - began
                self.record.append("fts", result)
                self.record.save()

    def export_sample(self):
        sample_count = min(100_000, self.completed)
        seen, results = bytearray(sample_count), []
        began = time.monotonic()
        for tenant in TENANTS:
            for index in INDEXES:
                wanted = expected_scopes(sample_count)[tenant, index]["count"]
                if not wanted:
                    continue
                client = self.clients[tenant][0]
                snapshot = self.expect(
                    client,
                    "POST",
                    "/api/logs/snapshots",
                    expected=201,
                    json={
                        "query": {
                            "earliest": self.config["base_epoch"],
                            "latest": self.config["base_epoch"] + 3600,
                            "query": {
                                "filters": [
                                    {"field": "index", "op": "eq", "value": index},
                                    {
                                        "field": "raw.sequence",
                                        "op": "number_gte",
                                        "value": 0,
                                    },
                                    {
                                        "field": "raw.sequence",
                                        "op": "number_lt",
                                        "value": sample_count,
                                    },
                                ]
                            },
                        }
                    },
                ).json()
                digest, position, rows, size = hashlib.sha256(), 0, 0, 0
                try:
                    check(
                        snapshot["rows"] == wanted and not snapshot["truncated"],
                        "Bounded export sample snapshot mismatch",
                    )
                    while True:
                        response = self.expect(
                            client,
                            "GET",
                            f"/api/logs/snapshots/{snapshot['id']}/export",
                            params={"after": position, "limit": 5000},
                        )
                        check(
                            exact_integer(response.headers.get("X-Total-Rows"))
                            == wanted,
                            "Sample total changed",
                        )
                        check(
                            response.headers.get("X-Snapshot-SHA256")
                            == snapshot["sha256_ndjson"],
                            "Sample digest metadata changed",
                        )
                        digest.update(response.content)
                        size += len(response.content)
                        for line in response.content.splitlines():
                            row = json.loads(line)
                            sequence = row["raw"]["sequence"]
                            check(
                                type(sequence) is int
                                and 0 <= sequence < sample_count
                                and not seen[sequence],
                                "Sample repeated, untyped or out-of-range sequence",
                            )
                            expected_tenant, expected = self.corpus.event(sequence)
                            validate_sample_event(
                                row, expected, expected_tenant, tenant, index
                            )
                            seen[sequence] = 1
                            rows += 1
                        next_after = response.headers.get("X-Next-After")
                        if not next_after:
                            break
                        check(
                            exact_integer(next_after) > position,
                            "Sample export cursor did not advance",
                        )
                        position = exact_integer(next_after)
                    check(
                        rows == wanted
                        and digest.hexdigest() == snapshot["sha256_ndjson"],
                        "Sample page SHA/count mismatch",
                    )
                    results.append(
                        {
                            "tenant": tenant,
                            "index": index,
                            "rows": rows,
                            "bytes": size,
                            "sha256": digest.hexdigest(),
                        }
                    )
                finally:
                    self.expect(
                        client, "DELETE", "/api/logs/snapshots/" + snapshot["id"]
                    )
        check(sum(seen) == sample_count, "Bounded sample omitted an expected event")
        self.record.update(
            export_integrity_sample={
                "passed": True,
                "rows": sample_count,
                "partitions": results,
                "seconds": time.monotonic() - began,
                "coverage": "First up to 100k deterministic ordinals only; NOT a full population export",
                "independent_input_fields_verified": True,
                "input_fields_verified": [
                    "event_id",
                    "event_time",
                    "sourcetype",
                    "severity",
                    "message",
                    "host",
                    "source",
                    "index_name (input index)",
                    "all collector-provided raw keys; additive derived keys allowed",
                ],
                "system_fields_not_independently_predicted": ["received"],
                "digest_scope": "Server-frozen snapshot SHA256 versus concatenated HTTP pages: transport and snapshot consistency, not an independent full-population input hash",
                "full_population_export": "not_tested",
                "full_population_cryptographic_content_hash": "not_tested",
            }
        )

    def disconnect(self):
        for pair in self.clients.values():
            for client in pair:
                client.close()
        self.clients.clear()
        if self.control:
            self.control.close()
            self.control = None

    def run(self):
        self.record.update(source=self.source, stage="start-private-TLS-service")
        self.record.save()
        self.connect()
        self.initial_components = component_bytes(self.directory / "data")
        self.monitor = threading.Thread(
            target=self.monitoring, name="log-scale-resource-monitor", daemon=True
        )
        self.monitor.start()
        initial_profile_sizes = [
            len(dumps(self.corpus.event(i)[1])) for i in range(1000)
        ]
        self.record.update(
            profile_measurement={
                "sample_events": 1000,
                "event_json_bytes": byte_summary(initial_profile_sizes),
                "mean_event_json_bytes": sum(initial_profile_sizes)
                / len(initial_profile_sizes),
                "estimated_uncompressed_input_event_bytes": self.args.events
                * sum(initial_profile_sizes)
                / len(initial_profile_sizes),
                "generator": "small fixed compact envelope"
                if self.args.profile == "small"
                else "approx1KiB variable-size/key-count envelope; up to100k hosts/250k users, unique traces/paths and keyed pseudorandom payload",
                "no_compression_or_physical_capacity_guarantee": True,
            }
        )
        while self.completed < self.args.events:
            boundary = min(
                self.args.events,
                ((self.completed // SEAL_INTERVAL) + 1) * SEAL_INTERVAL,
            )
            self.record.update(
                stage="single-producer-durable-admission",
                submitting_from=self.completed,
                submitting_until=boundary,
            )
            iterator = iter(self.corpus.batches(self.completed, boundary))
            ingest_started = time.monotonic()
            while True:
                self.guard()
                generated = time.monotonic()
                try:
                    tenant, body, count = next(iterator)
                except StopIteration:
                    break
                self.metrics["generator_seconds"] += time.monotonic() - generated
                self.admit(tenant, body, count)
            self.metrics["admission_seconds"] += time.monotonic() - ingest_started
            self.completed = boundary
            self.record.update(stage="drain-and-seal", population=self.completed)
            self.record.append("drains", {"population": self.completed, **self.drain()})
            self.seal()
            self.assert_source()
            if self.completed == min(SEAL_INTERVAL, self.args.events):
                self.fts(self.completed, "cold")
            if self.completed in MILESTONES or self.completed == self.args.events:
                self.record.update(stage="HTTP-full-population-integrity")
                self.integrity(self.completed, "major_milestone")
                if self.completed > SEAL_INTERVAL:
                    self.fts(
                        self.completed,
                        "incremental" if self.completed == 1_000_000 else "capacity",
                    )
            if (
                self.completed % CHECKPOINT_INTERVAL == 0
                or self.completed == self.args.events
            ):
                resources = self.resource_check(preserve=True)
                projection = capacity_projection(
                    component_bytes(self.directory / "data"),
                    self.initial_components,
                    self.completed,
                    self.args.events,
                    resources["disk_free_bytes"],
                    self.config["reserve_bytes"],
                )
                self.record.append("capacity_projections", projection)
                self.record.append(
                    "checkpoints",
                    {
                        "population": self.completed,
                        "queue_empty_before_seal": True,
                        "sealed_total": self.last_sealed,
                        "elapsed_seconds": time.monotonic() - self.started,
                        "full_HTTP_integrity_performed": self.completed in MILESTONES
                        or self.completed == self.args.events,
                    },
                )
                if (
                    self.args.profile == "realistic"
                    and self.completed >= CHECKPOINT_INTERVAL
                ):
                    self.record.save()
                    check(
                        projection["fits_linear_estimate"],
                        "Preflight estimate from measured realistic bytes projects beyond disk reserve; target not attempted, not proof of actual target-capacity exhaustion",
                        "environment_capacity_projection",
                    )
            self.record.update(admission=self.admission_summary())
            self.record.save()
        self.record.update(stage="bounded-100k-export-integrity-sample")
        self.export_sample()
        replay_tenant, replay_body, replay_count = next(
            self.corpus.batches(0, min(1000, self.completed))
        )
        replay = self.admit(replay_tenant, replay_body, replay_count, original=False)
        check(
            replay["accepted"] == 0 and replay["duplicate"] == replay_count,
            "Stable duplicate replay changed stored population",
        )
        self.record.update(stable_replay={"passed": True, "events": replay_count})
        self.record.update(stage="clean-restart-and-HTTP-integrity")
        restart_started = time.monotonic()
        self.paused.set()
        self.disconnect()
        self.service.stop()
        self.connect()
        restart_to_authenticated_seconds = time.monotonic() - restart_started
        self.paused.clear()
        self.integrity(self.completed, "after_clean_service_restart")
        self.fts(self.completed, "after_restart")
        self.record.update(
            restart={
                "passed": True,
                "kind": "clean process restart; no power-loss/HA claim",
                "stop_to_authenticated_ready_seconds": restart_to_authenticated_seconds,
                "stop_through_integrity_and_fts_seconds": time.monotonic()
                - restart_started,
                "startup_only_seconds": self.service.starts[-1]["startup_seconds"],
                "scope": "Measured graceful stop, same-host process startup, authentication and separately identified checks; not HA/RTO qualification",
            }
        )
        self.assert_source()
        resources = self.resource_check(preserve=True)
        live_bytes = sum(component_bytes(self.directory / "data").values())
        self.record.update(
            full_scale_backup={
                "status": "not_tested",
                "live_data_directory_bytes": live_bytes,
                "disk_free_bytes": resources["disk_free_bytes"],
                "reserve_bytes": self.config["reserve_bytes"],
                "one_extra_live_size_copy_fits_above_reserve": resources[
                    "disk_free_bytes"
                ]
                - self.config["reserve_bytes"]
                >= live_bytes,
                "note": "Preflight estimate only; plaintext snapshot+encrypted bundle+separate restore peak not qualified",
            },
            storage_integrity_passed=True,
            source_unchanged_during_run=True,
            stage="work-complete",
        )

    def close(self):
        failures = []
        if getattr(self, "source", None) is not None:
            try:
                current = source_identity()
                source_unchanged = (
                    current["product_source_sha256"]
                    == self.source["product_source_sha256"]
                )
                harness_unchanged = all(
                    current[key] == self.source[key]
                    for key in ("harness_sha256", "diagnostics_helper_sha256")
                )
                self.record.update(
                    source_unchanged_during_run=source_unchanged,
                    harness_unchanged_during_run=harness_unchanged,
                )
                if not source_unchanged or not harness_unchanged:
                    failures.append(
                        ScaleFailure(
                            "source_changed",
                            "Frozen product or qualification helper bytes changed",
                        )
                    )
            except Exception as exc:  # noqa: BLE001 - Cleanup still stops all owned work after an identity check failure.
                failures.append(exc)
        evidence = getattr(self, "evidence", None)
        if evidence is not None and not evidence.finish():
            failures.append(
                ScaleFailure(
                    "shutdown", "Owned diagnostic worker did not finish before cleanup"
                )
            )
        self.monitor_stop.set()
        if self.monitor:
            self.monitor.join(8)
            if self.monitor.is_alive():
                failures.append(
                    ScaleFailure("shutdown", "Resource monitor did not stop")
                )
        try:
            self.disconnect()
        except Exception as exc:  # noqa: BLE001 - Always attempt to stop the owned server.
            failures.append(exc)
        try:
            self.service.stop()
        except Exception as exc:  # noqa: BLE001 - Persist failed cleanup instead of hiding it.
            failures.append(exc)
        checks = self.service.stop_checks
        released = bool(
            checks
            and checks[-1].get("owned_process_exited") is True
            and checks[-1].get("listener_closed") is True
            and checks[-1].get("database_handle_released") is not False
        )
        self.record.update(
            shutdown={
                "passed": not failures and released,
                "service_stop_checks": checks,
                "server_retained": False if released else None,
                "release_verified": released,
            },
            admission=self.admission_summary(),
            service_starts=list(self.service.starts),
        )
        if failures:
            raise failures[0]
        if self.record.failure:
            raise self.record.failure


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=1_000_000)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument(
        "--profile", choices=("small", "realistic"), default="realistic"
    )
    parser.add_argument("--reserve-gib", type=float, default=10.0)
    parser.add_argument("--query-timeout", type=int, choices=(15, 120), default=120)
    parser.add_argument("--max-seconds", type=int, default=7200)
    parser.add_argument("--min-free-ram-mib", type=int, default=512)
    parser.add_argument("--max-rss-gib", type=float, default=4.0)
    parser.add_argument("--fts-budget-gib", type=float, default=8.0)
    parser.add_argument("--fts-ready-timeout", type=int, default=600)
    parser.add_argument("--fts-observation-timeout", type=int, default=120)
    parser.add_argument(
        "--admission-mode", choices=("burst8", "server_backoff"), default="burst8"
    )
    parser.add_argument("--admission-batch-seconds", type=float, default=300.0)
    parser.add_argument("--admission-max-attempts", type=int, default=64)
    args = parser.parse_args(argv)
    if (
        not 1 <= args.events <= 50_000_000
        or not math.isfinite(args.reserve_gib)
        or args.reserve_gib < 10
    ):
        parser.error("events must be1..50M and disk reserve must be at least10GiB")
    if (
        not 30 <= args.max_seconds <= 172800
        or args.min_free_ram_mib < 256
        or not math.isfinite(args.max_rss_gib)
        or args.max_rss_gib <= 0
    ):
        parser.error("Invalid bounded time or RAM/RSS guard")
    if not math.isfinite(args.fts_budget_gib) or not 1 <= args.fts_budget_gib <= 1024:
        parser.error("FTS disk budget must be1..1024GiB")
    if not 1 <= args.fts_ready_timeout <= args.max_seconds:
        parser.error("FTS readiness budget must be1..max-seconds")
    if not 1 <= args.fts_observation_timeout <= 600:
        parser.error("FTS full-population observation budget must be1..600seconds")
    if (
        not math.isfinite(args.admission_batch_seconds)
        or not 1 <= args.admission_batch_seconds <= 600
        or not 1 <= args.admission_max_attempts <= 64
    ):
        parser.error("Admission batch seconds must be1..600 and attempts1..64")
    return args


def main(argv=None):
    # --serve is accepted only for a validated private marker under this task.
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) == 2 and arguments[0] == "--serve":
        serve(Path(arguments[1]))
        return 0
    args = parse_args(arguments)
    target = validate_report_path(args.report)
    target.parent.mkdir(parents=True, exist_ok=True)
    initial = {
        "schema": "lumina.log-scale.qualification.v1",
        "passed": False,
        "storage_integrity_passed": False,
        "full_population_cryptographic_content_hash": "not_tested",
        "population_validation_scope": "Full count/distinct/typed sum/range/scope checks plus separate up-to100k original-field sample; no independent full-population content hash",
        "synthetic_only": True,
        "live_accessed": False,
        "stage": "preflight",
        "requested_events": args.events,
        "profile": args.profile,
        "started_at_epoch": time.time(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "settings": vars(args)
        | {
            "report": target.name,
            "memory_limit": "512MB",
            "query_workers": 4,
            "max_batch_events": BATCH_LIMIT,
            "max_request_body_bytes": BODY_LIMIT,
            "seal_every_events": SEAL_INTERVAL,
            "seal_batch_per_partition": 100_000,
            "full_integrity_milestones": [n for n in MILESTONES if n <= args.events],
            "resource_sample_seconds": 15,
            "TLS_verified": True,
            "admission_retry_policy": admission_retry_policy(args),
        },
        "limitations": [
            "Single producer, periodic drain/seal/check pauses; no sustained EPS or concurrent search SLO claim",
            "Fresh private single-host synthetic store, no production data or external endpoints",
            "Lifecycle uses explicit simulated future now; no actual30day aging claim",
            "Export validates up to100k inputs, not the complete50M content",
            "environment_capacity_projection is an observed-growth preflight estimate; stopping does not prove actual target-capacity exhaustion",
            "FTS disk budget is explicit (default8GiB); snapshot2GiB cap is unchanged; failures remain visible",
            "Full-scale backup, physical host failure and native HA not qualified",
            "Wall-clock work budget excludes separately measured graceful shutdown; cleanup may force owned-child termination and fail",
            "Admission retry mode is explicit: burst8 is unchanged; optional server_backoff honors bounded HTTP advice without a durable client outbox or native-agent schedule claim",
            "fts_observation_timeout is a separate QA full-population verification budget; it does not increase any product query/search/readiness timeout",
        ],
    }
    initial["settings"].pop("report")
    record = Recorder(target, initial)
    record.save()
    trial = None
    started = time.monotonic()
    try:
        reserve = int(args.reserve_gib * 1024**3)
        guard_resources(
            system_resources(WORK),
            reserve,
            args.min_free_ram_mib * 1024**2,
            args.max_rss_gib * 1024**3,
        )
        directory = WORK / ("log-scale-qa-" + uuid.uuid4().hex)
        from tools.qualify_security_flow import private_directory

        private_directory(directory)
        atomic_json(
            directory / MARKER,
            {"schema": 1, "synthetic_only": True, "run_id": directory.name[13:]},
        )
        # Fixed within the run and kept private: ambiguous ACK retries never
        # regenerate timestamps, event IDs, payloads or collection credentials.
        config = {
            "base_epoch": math.floor((time.time() - 30 * 86400) / 86400) * 86400
            + 12 * 3600,
            "corpus_key": secrets.token_hex(32),
            "control_token": secrets.token_urlsafe(40),
            "passwords": {tenant: secrets.token_urlsafe(32) for tenant in TENANTS},
            "reserve_bytes": reserve,
            "query_timeout": args.query_timeout,
            "fts_observation_timeout": args.fts_observation_timeout,
            "fts_max_bytes": int(args.fts_budget_gib * 1024**3),
        }
        atomic_json(directory / PRIVATE_CONFIG, config)
        trial = Trial(args, directory, record, config)
        trial.run()
    except KeyboardInterrupt:
        record.update(
            failure={
                "kind": "interrupted",
                "message": "Qualification interrupted; accepted prefix is recorded",
            }
        )
    except Exception as exc:  # noqa: BLE001 - Save failures without secret-bearing exception contents.
        record.update(
            failure={
                "kind": exc.kind
                if isinstance(exc, ScaleFailure)
                else type(exc).__name__,
                "message": str(exc)
                if isinstance(exc, ScaleFailure)
                else "Operation failed; inspect private QA files locally",
            }
        )
    finally:
        if trial:
            try:
                trial.close()
            except Exception as exc:  # noqa: BLE001 - Cleanup failures must make the report fail.
                record.update(
                    cleanup_failure={
                        "kind": exc.kind
                        if isinstance(exc, ScaleFailure)
                        else type(exc).__name__,
                        "message": "QA cleanup or resource monitor failed; this run cannot pass",
                    }
                )
        with record.lock:
            fts = record.value.get("fts", [])
            fts_summary = fts_qualification_summary(fts, args.events)
            fts_passed = fts_summary["fts_qualified"]
            record.value.update(
                **fts_summary,
                elapsed_seconds=time.monotonic() - started,
                finished_at_epoch=time.time(),
            )
            record.value["passed"] = bool(
                record.value["storage_integrity_passed"]
                and fts_passed
                and record.value.get("shutdown", {}).get("passed")
                and not record.value.get("failure")
                and not record.value.get("cleanup_failure")
            )
            record.value["stage"] = (
                "complete"
                if record.value["passed"]
                else "failed_or_partially_qualified"
            )
        record.save()
        print(
            json.dumps(
                {
                    "passed": record.value["passed"],
                    "storage_integrity_passed": record.value[
                        "storage_integrity_passed"
                    ],
                    "fts_qualified": record.value["fts_qualified"],
                    "report": str(target),
                }
            ),
            flush=True,
        )
    return 0 if record.value["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
