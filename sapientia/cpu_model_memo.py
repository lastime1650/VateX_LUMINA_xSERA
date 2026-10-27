"""Pure immutable CPU content reuse and one reserved-transaction memo.

The bounded process LRU stores decoded model content and hashes only. No
authorization result is cached. Every authoritative loader rereads the full raw
model row and independently checks current principal/source/review state.
"""
import hashlib
import json
import re
import sqlite3
import threading
from collections import OrderedDict

from .storage import ConflictError, encode

MAX_MODELS = 16
MAX_RAW_BYTES = 32 * 1024 * 1024
_content_lock = threading.RLock()
_content_entries = OrderedDict()
_content_bytes = _content_hits = _content_misses = 0


def _immutable(*args, **kwargs):
    raise TypeError("Memoized model definitions and weights are immutable")


class _FrozenDict(dict):
    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = __ior__ = _immutable


class _FrozenList(list):
    __setitem__ = __delitem__ = append = clear = extend = insert = pop = remove = reverse = sort = __iadd__ = __imul__ = _immutable


def _freeze(value):
    if isinstance(value, dict):
        return _FrozenDict((key, _freeze(item)) for key, item in value.items())
    if isinstance(value, list):
        return _FrozenList(_freeze(item) for item in value)
    return value


def _raw_identity(row):
    return tuple(row[name] for name in ("id", "tenant", "owner", "name", "revision", "indexes", "created", "definition", "snapshot", "digest"))


def content_model(family, row):
    """Reuse only hash-verified immutable content after full fresh RAW equality.

    This helper grants no scope, model activation, source or reviewer authority.
    Its callers must run those current checks on every use, including cache hits.
    """
    global _content_bytes, _content_hits, _content_misses
    if family not in {"sequence", "autoencoder"}:
        raise ValueError("Supported immutable CPU model family required")
    key, raw = (family, row["tenant"], row["id"]), _raw_identity(row)
    with _content_lock:
        previous = _content_entries.get(key)
        if previous is not None and previous["raw"] == raw:
            _content_hits += 1
            _content_entries.move_to_end(key)
            return previous["definition"], previous["snapshot"], previous["definition_digest"]
        _content_misses += 1
        definition, snapshot = json.loads(row["definition"]), json.loads(row["snapshot"])
        digest = hashlib.sha256(encode({"definition": definition, "snapshot": snapshot}).encode()).hexdigest()
        if digest != row["digest"]:
            raise ConflictError("Immutable CPU model hash mismatch")
        definition_digest = hashlib.sha256(encode(definition).encode()).hexdigest()
        definition, snapshot = _freeze(definition), _freeze(snapshot)
        amount = len(row["definition"].encode()) + len(row["snapshot"].encode())
        if previous is not None:
            _content_bytes -= previous["bytes"]
            del _content_entries[key]
        if amount <= MAX_RAW_BYTES:
            while _content_entries and (len(_content_entries) >= MAX_MODELS or _content_bytes+amount > MAX_RAW_BYTES):
                _, removed = _content_entries.popitem(last=False)
                _content_bytes -= removed["bytes"]
            _content_entries[key] = {"raw": raw, "definition": definition, "snapshot": snapshot,
                                     "definition_digest": definition_digest, "bytes": amount}
            _content_bytes += amount
        return definition, snapshot, definition_digest


def content_cache_status():
    with _content_lock:
        return {"kind": "immutable_content_only", "authorization_cached": False,
                "entries": len(_content_entries), "raw_bytes": _content_bytes,
                "max_entries": MAX_MODELS, "max_raw_bytes": MAX_RAW_BYTES,
                "hits": _content_hits, "misses": _content_misses}


def clear_content_cache():
    """Drop pure content for controlled shutdown/testing, never alter a Store."""
    global _content_bytes, _content_hits, _content_misses
    with _content_lock:
        _content_entries.clear()
        _content_bytes = _content_hits = _content_misses = 0


def _boundary(statement):
    head = statement.lstrip()
    while head.startswith(("--", "/*")):
        marker = "\n" if head.startswith("--") else "*/"
        end = head.find(marker, 2)
        if end < 0:
            return False
        head = head[end+len(marker):].lstrip()
    first = re.match(r"[A-Za-z]+", head)
    return bool(first and first[0].upper() in {"BEGIN", "COMMIT", "END", "ROLLBACK"})


class _ModelMemo:
    def __init__(self, db):
        self._db = db
        self._active = False
        self._entered = False
        self._entries = {}
        self._bytes = 0

    def _invalidate(self):
        self._active = False
        self._entries.clear()
        self._bytes = 0

    def _trace(self, statement):
        if _boundary(statement):
            self._invalidate()

    def __enter__(self):
        if self._entered or not self._db.in_transaction:
            raise ConflictError("CPU model memo requires one caller-reserved transaction")
        # This writes no rows but ensures a reserved write lock, even if a
        # trusted caller accidentally began a deferred read transaction.
        self._db.execute("UPDATE schema_version SET version=version WHERE 0")
        self._entered = self._active = True
        # The owned Store uses no other SQLite trace callback. This context is
        # deliberately the only trace owner until it exits.
        self._db.set_trace_callback(self._trace)
        return self

    def __exit__(self, *exc):
        self._invalidate()
        try:
            self._db.set_trace_callback(None)
        except sqlite3.ProgrammingError:
            pass

    def _require(self, db):
        if self._db is not db or not self._active or not db.in_transaction:
            self._invalidate()
            raise ConflictError("CPU model memo cannot cross connection or transaction boundaries")

    def model(self, db, family, row):
        self._require(db)
        if family not in {"sequence", "autoencoder"}:
            raise ValueError("Supported immutable CPU model family required")
        key = family, row["tenant"], row["id"]
        raw = _raw_identity(row)
        previous = self._entries.get(key)
        if previous is not None and previous["raw"] == raw:
            return previous["definition"], previous["snapshot"], previous["definition_digest"]
        definition, snapshot, definition_digest = content_model(family, row)
        amount = len(row["definition"].encode()) + len(row["snapshot"].encode())
        if previous is not None:
            self._bytes -= previous["bytes"]
            del self._entries[key]
        if amount <= MAX_RAW_BYTES:
            while self._entries and (len(self._entries) >= MAX_MODELS or self._bytes+amount > MAX_RAW_BYTES):
                removed = self._entries.pop(next(iter(self._entries)))
                self._bytes -= removed["bytes"]
            self._entries[key] = {"raw": raw, "definition": definition, "snapshot": snapshot,
                                  "definition_digest": definition_digest, "bytes": amount}
            self._bytes += amount
        return definition, snapshot, definition_digest


def authority_memo(db):
    """Enter inside a reserved write transaction; never share across scopes."""
    return _ModelMemo(db)


def decoded_model(db, memo, family, row):
    if not isinstance(memo, _ModelMemo):
        raise ValueError("Opaque reserved-transaction CPU model memo required")  # noqa: TRY004 - protected callers handle validation errors as ValueError.
    return memo.model(db, family, row)
