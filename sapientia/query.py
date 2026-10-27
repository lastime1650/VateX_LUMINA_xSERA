"""Bounded SPL subset / JSON query compiler. Never executes user SQL or Python."""

import json
import math
import re
import shlex
import time
from dataclasses import dataclass, field

FIELDS = {
    "event_id",
    "event_time",
    "received",
    "source",
    "sourcetype",
    "host",
    "severity",
    "message",
    "raw",
    "index_name",
}
ALIASES = {
    "_time": "event_time",
    "_indextime": "received",
    "_raw": "raw",
    "index": "index_name",
}
OPS = {"eq": "=", "ne": "!=", "gt": ">", "gte": ">=", "lt": "<", "lte": "<="}
TYPED_OPS = {
    "typed_eq": "=",
    "number_gte": ">=",
    "number_gt": ">",
    "number_lte": "<=",
    "number_lt": "<",
}


def validate_regex(pattern):
    """Conservative RE2 subset: no lookaround, backrefs or user-defined flags.

    Regex execution is DuckDB RE2 (linear matching), never Python re.search.
    Python only checks the grammar here; braces and character classes are
    deliberately excluded from this small public profile.
    """
    if not isinstance(pattern, str) or not 1 <= len(pattern) <= 1024:
        raise QueryError("Regex must be 1..1024 characters")
    body = pattern
    for flag in ("(?i)", "(?s)", "(?i)"):
        body = body.removeprefix(flag)
    if "(?" in body:
        raise QueryError("Regex lookaround and inline groups are unsupported")
    if re.search(r"(?<!\\)[*+?][*+?]", body):
        raise QueryError(
            "Regex possessive, lazy and repeated quantifiers are unsupported"
        )
    escaped = False
    for char in body:
        if escaped:
            if char.isalnum() or ord(char) < 32:
                raise QueryError(
                    "Regex character escapes and backreferences are unsupported"
                )
            escaped = False
        elif char == "\\":
            escaped = True
        elif char in "[]{}" or ord(char) < 32:
            raise QueryError(
                "Regex classes, quantifier braces and control characters are unsupported"
            )
    if escaped:
        raise QueryError("Invalid trailing regex escape")
    try:
        re.compile(pattern)
    except (re.error, RecursionError):
        raise QueryError("Invalid regular expression") from None
    return pattern


class QueryError(ValueError):
    pass


def index_predicate(allowed_indexes):
    """Compile a server-owned exact index scope; never accept query wildcards."""
    if allowed_indexes is None:
        return "TRUE", []
    if not isinstance(allowed_indexes, list) or len(allowed_indexes) > 256:
        raise QueryError("Index scope must be a list of at most 256 names")
    for name in allowed_indexes:
        if not isinstance(name, str) or (
            name != "*" and not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name)
        ):
            raise QueryError("Invalid allowed index name")
    if "*" in allowed_indexes:
        if allowed_indexes != ["*"]:
            raise QueryError("Wildcard index scope must contain only '*'")
        return "TRUE", []
    names = list(dict.fromkeys(allowed_indexes))
    if not names:
        return "FALSE", []
    return "index_name IN (" + ",".join("?" for _ in names) + ")", names


def column(name):
    if not isinstance(name, str):
        raise QueryError("Field name must be a string")
    name = ALIASES.get(name, name)
    if re.fullmatch(r"raw(?:\.[A-Za-z_][A-Za-z0-9_]{0,63}){1,8}", name):
        return "json_extract_string(raw, '$." + name[4:] + "')"
    if name not in FIELDS:
        raise QueryError(f"Unsupported field: {name}")
    return name


def split_pipeline(text):
    chunks, start, quote, escaped = [], 0, None, False
    for i, char in enumerate(text):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "|":
            chunks.append(text[start:i].strip())
            start = i + 1
    if quote:
        raise QueryError("Unterminated quoted string")
    chunks.append(text[start:].strip())
    return chunks


@dataclass
class Query:
    filters: list = field(default_factory=list)
    text: str = ""
    earliest: float = 0
    latest: float = 0
    fields: list = field(
        default_factory=lambda: [
            "event_time",
            "event_id",
            "source",
            "host",
            "severity",
            "message",
        ]
    )
    group_by: list | None = None
    sort: str = "event_time"
    descending: bool = True
    limit: int = 200

    @classmethod
    def parse(cls, payload):
        if isinstance(payload, dict) and payload.get("language", "spl") == "spl":
            from .spl import SPLQuery

            return SPLQuery.parse(payload)
        if not isinstance(payload, dict) or set(payload) - {
            "language",
            "query",
            "earliest",
            "latest",
            "limit",
        }:
            raise QueryError("Expected language, query, earliest, latest, limit")
        now = time.time()
        try:
            q = cls(
                earliest=float(payload.get("earliest", now - 86400)),
                latest=float(payload.get("latest", now)),
                limit=int(payload.get("limit", 200)),
            )
        except (TypeError, ValueError, OverflowError) as exc:
            raise QueryError("Invalid time or limit") from exc
        if (
            not all(math.isfinite(x) for x in [q.earliest, q.latest])
            or q.earliest < 0
            or q.earliest >= q.latest
        ):
            raise QueryError("Time range must be finite and earliest < latest")
        if not 1 <= q.limit <= 1000:
            raise QueryError("Limit must be 1..1000")
        body = payload.get("query", "")
        language = payload.get("language", "spl")
        if language == "json":
            if isinstance(body, str):
                try:
                    body = json.loads(body)
                except ValueError as exc:
                    raise QueryError("Invalid JSON query") from exc
            if not isinstance(body, dict) or set(body) - {
                "filters",
                "text",
                "fields",
                "group_by",
                "sort",
                "descending",
            }:
                raise QueryError("Unknown JSON query key")
            q.filters = body.get("filters", [])
            q.text = body.get("text", "")
            q.fields = body.get("fields", q.fields)
            q.group_by = body.get("group_by")
            q.sort = body.get(
                "sort", "count" if q.group_by is not None else "event_time"
            )
            q.descending = body.get("descending", True)
        elif language == "spl":
            if not isinstance(body, str) or len(body) > 8192:
                raise QueryError("SPL must be at most 8192 characters")
            seen_transform = False
            parts = split_pipeline(body)
            for n, part in enumerate(parts):
                if not part and n == 0:
                    continue
                try:
                    tokens = shlex.split(part)
                except ValueError as exc:
                    raise QueryError(str(exc)) from exc
                if not tokens:
                    raise QueryError("Empty pipeline command")
                command = tokens.pop(0)
                if n == 0 and command not in {
                    "search",
                    "stats",
                    "table",
                    "fields",
                    "head",
                    "sort",
                }:
                    tokens.insert(0, command)
                    command = "search"
                if command == "search":
                    if seen_transform:
                        raise QueryError("search must precede result transforms")
                    for term in tokens:
                        if term == "*":
                            continue
                        if term in {"OR", "NOT", "AND"} or any(
                            c in term for c in "()`"
                        ):
                            raise QueryError(
                                "Boolean operators, macros and functions are not supported in search"
                            )
                        if "=" in term:
                            k, v = term.split("=", 1)
                            if k == "index":
                                if v not in {"main", "*"}:
                                    raise QueryError(
                                        "Only the main logical index is currently supported"
                                    )
                                continue
                            if "*" in v:
                                raise QueryError(
                                    "Use JSON contains for substring matching; wildcards are unsupported"
                                )
                            q.filters.append({"field": k, "op": "eq", "value": v})
                        else:
                            q.text += (" " if q.text else "") + term
                elif command == "stats":
                    if (
                        seen_transform
                        or not tokens
                        or tokens[0] != "count"
                        or (len(tokens) > 1 and tokens[1] != "by")
                    ):
                        raise QueryError(
                            "Supported aggregation: stats count [by field,...]"
                        )
                    q.group_by = [
                        x for x in re.split(r"[\s,]+", " ".join(tokens[2:])) if x
                    ]
                    if len(tokens) > 1 and not q.group_by:
                        raise QueryError("stats count by requires grouping fields")
                    q.sort = "count"
                    seen_transform = True
                elif command in {"table", "fields"}:
                    if seen_transform:
                        raise QueryError("Only one table/stats transform is supported")
                    q.fields = [x for x in re.split(r"[\s,]+", " ".join(tokens)) if x]
                    seen_transform = True
                elif command == "head":
                    if n != len(parts) - 1:
                        raise QueryError("head must be the final pipeline command")
                    if (
                        len(tokens) != 1
                        or not tokens[0].isdigit()
                        or not 1 <= int(tokens[0]) <= 1000
                    ):
                        raise QueryError("head requires a limit in 1..1000")
                    q.limit = min(q.limit, int(tokens[0]))
                elif command == "sort":
                    if len(tokens) != 1:
                        raise QueryError(
                            "sort requires one field, optionally prefixed with -"
                        )
                    q.descending = tokens[0].startswith("-")
                    q.sort = tokens[0].lstrip("-+")
                else:
                    raise QueryError(f"Unsupported SPL command: {command}")
        else:
            raise QueryError("language must be spl or json")
        q.validate()
        return q

    def validate(self):
        if not isinstance(self.filters, list) or len(self.filters) > 20:
            raise QueryError("At most 20 filters")
        if (
            not isinstance(self.text, str)
            or len(self.text) > 2048
            or not isinstance(self.descending, bool)
        ):
            raise QueryError("Invalid text or descending value")
        for f in self.filters:
            if not isinstance(f, dict) or set(f) != {"field", "op", "value"}:
                raise QueryError("Filter requires field/op/value")
            column(f["field"])
            if (
                not isinstance(f["op"], str)
                or f["op"]
                not in {*OPS, *TYPED_OPS, "contains", "regex", "exists", "typed_in"}
                or not isinstance(f["value"], (str, int, float))
                or isinstance(f["value"], bool)
            ):
                raise QueryError("Invalid filter operation or scalar")
            if (
                len(str(f["value"])) > 2048
                or (isinstance(f["value"], float) and not math.isfinite(f["value"]))
                or (type(f["value"]) is int and abs(f["value"]) > 2**63 - 1)
            ):
                raise QueryError("Invalid filter value")
            if f["op"] == "regex":
                validate_regex(f["value"])
            if f["op"] in TYPED_OPS or f["op"] in {"exists", "typed_in"}:
                if not f["field"].startswith("raw."):
                    raise QueryError("Typed operations require a raw JSON field")
                if f["op"] == "exists" and (
                    type(f["value"]) is not int or f["value"] not in (0, 1)
                ):
                    raise QueryError("exists requires 0 or 1")
                if f["op"].startswith("number_") and type(f["value"]) not in (
                    int,
                    float,
                ):
                    raise QueryError("Numeric operation requires a number")
                if (
                    f["op"] in TYPED_OPS
                    and type(f["value"]) in (int, float)
                    and abs(f["value"]) > 2**53 - 1
                ):
                    raise QueryError(
                        "Typed numeric constants must be within the exact integer range of DOUBLE"
                    )
                if f["op"] == "typed_in":
                    try:
                        values = json.loads(f["value"])
                    except (ValueError, TypeError):
                        raise QueryError(
                            "typed_in requires a JSON scalar array"
                        ) from None
                    if (
                        not isinstance(values, list)
                        or not 1 <= len(values) <= 32
                        or not (
                            all(type(x) is str for x in values)
                            or all(
                                type(x) in (int, float)
                                and abs(x) <= 2**53 - 1
                                and math.isfinite(x)
                                for x in values
                            )
                        )
                    ):
                        raise QueryError(
                            "typed_in requires 1..32 uniformly string or number values"
                        )
        for fields in [self.fields, self.group_by if self.group_by is not None else []]:
            if (
                not isinstance(fields, list)
                or len(fields) > 12
                or any(not isinstance(x, str) for x in fields)
            ):
                raise QueryError("Invalid field list")
            for name in fields:
                column(name)
        if not self.fields:
            raise QueryError("At least one result field required")
        if self.group_by is not None:
            if len(self.group_by) > 3:
                raise QueryError("At most 3 grouping fields")
            if self.sort != "count" and column(self.sort) not in [
                column(x) for x in self.group_by
            ]:
                raise QueryError("Aggregation sort must be count or a grouped field")
        else:
            column(self.sort)

    def compile(self, tenant, allowed_indexes=None, lookup_tables=None):
        where = ["tenant = ?", "event_time >= ?", "event_time < ?"]
        params = [tenant, self.earliest, self.latest]
        scope, scope_args = index_predicate(allowed_indexes)
        where.append(scope)
        params.extend(scope_args)
        for f in self.filters:
            col = column(f["field"])
            if f["op"] == "regex":
                if f["field"].startswith("raw."):
                    path = "$." + f["field"][4:]
                    where.append("json_type(raw, ?) = 'VARCHAR'")
                    params.append(path)
                where.append(f"regexp_matches(CAST({col} AS VARCHAR), ?)")
                params.append(f["value"])
            elif f["op"] == "exists":
                path = "$." + f["field"][4:]
                predicate = (
                    "(json_type(raw, ?) IS NOT NULL AND json_type(raw, ?) <> 'NULL')"
                )
                where.append(predicate if f["value"] else "NOT " + predicate)
                params.extend([path, path])
            elif f["op"] == "typed_in":
                values = json.loads(f["value"])
                numeric = type(values[0]) in (int, float)
                where.append(
                    "json_type(raw, ?) "
                    + ("IN ('BIGINT','UBIGINT','DOUBLE')" if numeric else "= 'VARCHAR'")
                )
                params.append("$." + f["field"][4:])
                if numeric:
                    col = f"try_cast({col} AS DOUBLE)"
                where.append(col + " IN (" + ",".join("?" for _ in values) + ")")
                params.extend(values)
            elif f["op"] in TYPED_OPS:
                path = "$." + f["field"][4:]
                numeric = type(f["value"]) in (int, float)
                where.append(
                    "json_type(raw, ?) "
                    + ("IN ('BIGINT','UBIGINT','DOUBLE')" if numeric else "= 'VARCHAR'")
                )
                params.append(path)
                if numeric:
                    col = f"try_cast({col} AS DOUBLE)"
                where.append(f"{col} {TYPED_OPS[f['op']]} ?")
                params.append(f["value"])
            elif f["op"] == "contains":
                where.append(f"contains(CAST({col} AS VARCHAR), ?)")
                params.append(str(f["value"]))
            else:
                if f["field"].startswith("raw.") and isinstance(
                    f["value"], (int, float)
                ):
                    col = f"try_cast({col} AS DOUBLE)"
                where.append(f"{col} {OPS[f['op']]} ?")
                params.append(f["value"])
        if self.text:
            where.append(
                "(contains(lower(COALESCE(message,'')),lower(?)) OR "
                "contains(lower(COALESCE(raw,'')),lower(?)))"
            )
            params.extend([self.text, self.text])
        group = [column(x) for x in (self.group_by or [])]

        def projected(name):
            return column(name) + (
                ' AS "' + name + '"' if name.startswith("raw.") else ""
            )

        if self.group_by is None:
            select = ", ".join(projected(x) for x in self.fields)
            suffix = ""
        else:
            select = ", ".join(
                [*(projected(x) for x in (self.group_by or [])), "count(*) AS count"]
            )
            suffix = " GROUP BY " + ", ".join(group) if group else ""
        sort = "count" if self.sort == "count" else column(self.sort)
        sql = f"SELECT {select} FROM events_all WHERE {' AND '.join(where)}{suffix} ORDER BY {sort} {'DESC' if self.descending else 'ASC'} LIMIT ?"
        return sql, [*params, self.limit]
