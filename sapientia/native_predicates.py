"""Bounded native JSON Boolean conditions. Regex execution is DuckDB RE2.

No external rule framework participates in live evaluation. Missing values and
explicit JSON null are deliberately distinct for the key-presence operator.
"""

import json
import math
import re
import threading
from functools import lru_cache

import duckdb

from . import release_manifest

VERSION = 1
MAX_NODES = 512
MAX_DEPTH = 20
MAX_TEXT_BYTES = 65536
PATH = re.compile(r"(?:event|projection|raw)(?:\.[A-Za-z_][A-Za-z0-9_]{0,63}){1,9}\Z")
FORBIDDEN = {"label", "ground_truth", "scenario_label", "expected_detected"}
CONTRACT_DIGEST = release_manifest.digest(
    {
        "version": VERSION,
        "implementation": release_manifest.hash_file(__file__),
        "regex": "DuckDB RE2",
        "numeric": "finite int/float; bool separate",
        "exists": "key-presence-including-null",
        "max_text_bytes": MAX_TEXT_BYTES,
    }
)
_lock = threading.RLock()
_connection = None
_MISSING = object()


def _db():
    global _connection
    if _connection is None:
        _connection = duckdb.connect(
            ":memory:",
            config={
                "threads": 1,
                "memory_limit": "32MB",
                "enable_external_access": False,
            },
        )
    return _connection


def _boolean_query(sql, parameters):
    try:
        with _lock:
            return bool(_db().execute(sql, parameters).fetchone()[0])
    except duckdb.Error as exc:
        raise ValueError(
            "Native scalar evaluation exceeded its execution contract"
        ) from exc


@lru_cache(maxsize=512)
def _pattern(pattern):
    if not isinstance(pattern, str) or not 1 <= len(pattern) <= 512:
        raise ValueError("Native RE2 pattern requires 1..512 characters")
    if any(ord(char) < 32 for char in pattern):
        raise ValueError("Native RE2 pattern contains controls")
    try:
        with _lock:
            _db().execute("SELECT regexp_matches('', ?)", [pattern]).fetchone()
    except duckdb.Error as exc:
        raise ValueError("Invalid native RE2 expression") from exc
    return pattern


def _path(value):
    if not isinstance(value, str) or not PATH.fullmatch(value):
        raise ValueError(
            "Native condition requires an event/projection/raw scalar path"
        )
    if set(value.split(".")) & FORBIDDEN:
        raise ValueError("Evaluation labels cannot be detector input")
    return value


def _scalar(value):
    if type(value) not in (str, int, float, bool):
        raise ValueError("Native condition requires a typed scalar")
    if isinstance(value, str) and len(value.encode("utf-8")) > 2048:
        raise ValueError("Native condition text exceeds 2048 bytes")
    if type(value) in (int, float) and (
        abs(value) > 1e100 or type(value) is float and not math.isfinite(value)
    ):
        raise ValueError("Native condition requires a bounded finite number")
    return value


def validate(tree):
    if (
        not isinstance(tree, dict)
        or set(tree) != {"version", "root"}
        or type(tree["version"]) is not int
        or tree["version"] != VERSION
    ):
        raise ValueError("Expected native condition_tree version 1 and root")
    try:
        encoded = json.dumps(tree, allow_nan=False, ensure_ascii=False)
    except (ValueError, TypeError, RecursionError):
        raise ValueError("Native condition must be finite bounded JSON") from None
    if len(encoded.encode("utf-8")) > 32768:
        raise ValueError("Native condition exceeds 32 KiB")
    visited = 0

    def node(value, depth):
        nonlocal visited
        visited += 1
        if visited > MAX_NODES or depth > MAX_DEPTH:
            raise ValueError("Native condition exceeds node/depth limits")
        if not isinstance(value, dict) or not isinstance(value.get("op"), str):
            raise ValueError("Typed native condition node required")  # noqa: TRY004 - API validation uses HTTP 400.
        op = value["op"]
        if op in ("and", "or"):
            if (
                set(value) != {"op", "args"}
                or not isinstance(value["args"], list)
                or not 1 <= len(value["args"]) <= 32
            ):
                raise ValueError("Native Boolean args require 1..32 nodes")
            return {"op": op, "args": [node(item, depth + 1) for item in value["args"]]}
        if op == "not":
            if set(value) != {"op", "arg"}:
                raise ValueError("Native NOT requires exactly one arg")
            return {"op": op, "arg": node(value["arg"], depth + 1)}
        keys = {
            "regex": {"op", "field", "pattern"},
            "field_eq": {"op", "field", "other", "case_sensitive"},
            "is_null": {"op", "field"},
            "exists": {"op", "field", "value"},
            **{
                key: {"op", "field", "value"}
                for key in ("eq", "gt", "gte", "lt", "lte")
            },
        }
        if op not in keys or set(value) != keys[op]:
            raise ValueError("Unsupported native condition operator or fields")
        field = _path(value["field"])
        if op == "regex":
            return {"op": op, "field": field, "pattern": _pattern(value["pattern"])}
        if op == "field_eq":
            if type(value["case_sensitive"]) is not bool:
                raise ValueError("Typed field comparison case_sensitive required")
            return {
                "op": op,
                "field": field,
                "other": _path(value["other"]),
                "case_sensitive": value["case_sensitive"],
            }
        if op == "is_null":
            return {"op": op, "field": field}
        wanted = _scalar(value["value"])
        if op == "exists" and type(wanted) is not bool:
            raise ValueError("Native exists requires a boolean")
        if op in ("gt", "gte", "lt", "lte") and type(wanted) not in (int, float):
            raise ValueError("Native ordered comparison requires a number")
        return {"op": op, "field": field, "value": wanted}

    return {"version": VERSION, "root": node(tree["root"], 0)}


def _resolve(context, path):
    value = context
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return _MISSING
        value = value[part]
    if isinstance(value, str) and len(value.encode("utf-8")) > MAX_TEXT_BYTES:
        # Raising, rather than returning false, also prevents NOT from turning
        # an unevaluated oversized scalar into a positive detection.
        raise ValueError("Native predicate input scalar exceeds 64 KiB")
    return value


def _number(value):
    if type(value) not in (int, float):
        return False
    if abs(value) > 1e100 or type(value) is float and not math.isfinite(value):
        raise ValueError("Native predicate input numeric value exceeds contract")
    return True


def _equal(left, right, case_sensitive=True):
    if _number(left) and _number(right):
        return left == right
    if type(left) is not type(right) or type(left) not in (str, bool):
        return False
    if isinstance(left, str) and not case_sensitive:
        return _boolean_query("SELECT lower(?) = lower(?)", [left, right])
    return left == right


@lru_cache(maxsize=128)
def _validated(encoded):
    return validate(json.loads(encoded))


def matches(context, tree):
    # Cache only immutable definitions; never cache an event or a verdict.
    checked = _validated(
        json.dumps(tree, sort_keys=True, ensure_ascii=False, allow_nan=False)
    )

    def visit(node):
        op = node["op"]
        if op in ("and", "or"):
            # Evaluate all bounded leaves, including branches that would short
            # circuit, so invalid input cannot be masked under NOT/OR.
            values = [visit(item) for item in node["args"]]
            return all(values) if op == "and" else any(values)
        if op == "not":
            return not visit(node["arg"])
        actual = _resolve(context, node["field"])
        if op == "exists":
            return (actual is not _MISSING) == node["value"]
        if op == "is_null":
            return actual is _MISSING or actual is None
        if op == "regex":
            if not isinstance(actual, str):
                return False
            return _boolean_query(
                "SELECT regexp_matches(?, ?)", [actual, node["pattern"]]
            )
        if op == "field_eq":
            return _equal(
                actual, _resolve(context, node["other"]), node["case_sensitive"]
            )
        wanted = node["value"]
        if op == "eq":
            return _equal(actual, wanted)
        if not _number(actual):
            return False
        if op == "gt":
            return actual > wanted
        if op == "gte":
            return actual >= wanted
        if op == "lt":
            return actual < wanted
        return actual <= wanted

    return visit(checked["root"])
