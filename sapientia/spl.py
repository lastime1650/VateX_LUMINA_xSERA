"""Typed, bounded SPL pipeline compiler. User text is never executable SQL.

Every literal is bound; command/function names select reviewed implementations.
The compatibility manifest reports coverage rather than treating command names
as proof of complete Splunk semantic compatibility.
"""

import json
import math
import re
import shlex
import time
from dataclasses import dataclass
from functools import lru_cache

import duckdb

from .query import QueryError, index_predicate, split_pipeline

NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,127}\Z")
BASE = {
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
PAYLOAD_FIELDS = frozenset({"language", "query", "earliest", "latest", "limit"})
NUMERIC = {"event_time", "received", "_time", "_indextime"}
COMMANDS = {
    "search",
    "where",
    "eval",
    "stats",
    "eventstats",
    "streamstats",
    "table",
    "fields",
    "rename",
    "sort",
    "head",
    "tail",
    "reverse",
    "dedup",
    "bin",
    "bucket",
    "timechart",
    "top",
    "rare",
    "fillnull",
    "rex",
    "regex",
    "spath",
    "makeresults",
    "lookup",
}
COMMUTATIVE_AGGREGATES = {
    "count",
    "sum",
    "avg",
    "mean",
    "min",
    "max",
    "median",
    "dc",
    "distinct_count",
    "stdev",
    "stdevp",
    "var",
    "varp",
}


def ident(name):
    if (
        not isinstance(name, str)
        or not NAME.fullmatch(name)
        or name.lower() == "tenant"
        or name.startswith("__")
    ):
        raise QueryError("Invalid or reserved field name")
    return '"' + name + '"'


@dataclass
class SQL:
    text: str
    args: list


def compose(template, *pieces):
    return SQL(
        template.format(*(p.text for p in pieces)), [a for p in pieces for a in p.args]
    )


def literal(value):
    return SQL("?", [value])


@lru_cache(maxsize=256)
def validate_regex(pattern):
    """Use the execution engine's RE2 parser with bound text and no file access."""
    if not isinstance(pattern, str) or len(pattern) > 2048:
        raise QueryError("Regex pattern must be a string of at most 2048 characters")
    con = duckdb.connect(
        ":memory:",
        config={"enable_external_access": "false", "threads": "1"},
    )
    try:
        con.execute("SELECT regexp_matches('', ?)", [pattern]).fetchone()
    except duckdb.Error as exc:
        raise QueryError("Invalid or unsupported RE2 pattern") from exc
    finally:
        con.close()


def split_top(text, delimiter=","):
    result, start, depth, quote, escape = [], 0, 0, None, False
    for i, c in enumerate(text):
        if escape:
            escape = False
        elif c == "\\":
            escape = True
        elif quote:
            if c == quote:
                quote = None
        elif c in "\"'":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth < 0:
                raise QueryError("Unbalanced expression")
        elif c == delimiter and depth == 0:
            result.append(text[start:i].strip())
            start = i + 1
    if quote or depth:
        raise QueryError("Unbalanced expression")
    result.append(text[start:].strip())
    return result


TOKEN = re.compile(
    r"""\s*(?:(?P<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|(?P<number>(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)|(?P<name>[A-Za-z_][A-Za-z0-9_.]*)|(?P<operator>!=|<=|>=|<>|==|[=<>+*/%().,\-]))"""
)


def unquote(text):
    if text.startswith('"'):
        try:
            return json.loads(text)
        except ValueError as exc:
            raise QueryError("Invalid quoted value") from exc
    return re.sub(r"\\(.)", r"\1", text[1:-1])


class Expression:
    def __init__(self, text, resolver):
        if len(text) > 8192:
            raise QueryError("Expression too long")
        self.tokens = []
        pos = 0
        while pos < len(text.rstrip()):
            match = TOKEN.match(text, pos)
            if not match:
                raise QueryError(f"Invalid expression near character {pos}")
            self.tokens.append((match.lastgroup, match.group(match.lastgroup)))
            pos = match.end()
        if len(self.tokens) > 1024:
            raise QueryError("Expression token budget exceeded")
        self.at, self.depth, self.resolver = 0, 0, resolver

    def peek(self):
        return self.tokens[self.at][1].upper() if self.at < len(self.tokens) else ""

    def take(self, expected=None):
        if self.at >= len(self.tokens):
            raise QueryError("Incomplete expression")
        token = self.tokens[self.at]
        if expected and token[1].upper() != expected:
            raise QueryError(f"Expected {expected}")
        self.at += 1
        return token

    def parse(self):
        result = self.expr()
        if self.at != len(self.tokens):
            raise QueryError("Unexpected expression token")
        return result

    def expr(self, minimum=0):
        self.depth += 1
        if self.depth > 40:
            raise QueryError("Expression nesting budget exceeded")
        kind, text = self.take()
        if text == "(":
            left = self.expr()
            self.take(")")
        elif text.upper() == "NOT" or text in {"-", "+"}:
            left = compose("(" + text.upper() + " {})", self.expr(60))
        elif kind == "string":
            left = literal(unquote(text))
        elif kind == "number":
            value = float(text) if any(c in text for c in ".eE") else int(text)
            if not math.isfinite(value) or abs(value) > 1e100:
                raise QueryError("Numeric literal outside supported range")
            left = literal(value)
        elif kind == "name":
            if self.peek() == "(":
                self.take("(")
                args = []
                if self.peek() != ")":
                    while True:
                        args.append(self.expr())
                        if self.peek() != ",":
                            break
                        self.take(",")
                self.take(")")
                left = self.function(text.lower(), args)
            elif text.lower() in {"true", "false", "null"}:
                left = literal(
                    {"true": True, "false": False, "null": None}[text.lower()]
                )
            else:
                left = self.resolver(text)
        else:
            raise QueryError("Expected field, function or literal")
        precedence = {
            "OR": 10,
            "AND": 20,
            "=": 30,
            "==": 30,
            "!=": 30,
            "<>": 30,
            ">": 30,
            "<": 30,
            ">=": 30,
            "<=": 30,
            "LIKE": 30,
            "IN": 30,
            "+": 40,
            "-": 40,
            ".": 40,
            "*": 50,
            "/": 50,
            "%": 50,
        }
        while self.peek() in precedence and precedence[self.peek()] >= minimum:
            op = self.take()[1].upper()
            if op == "IN":
                self.take("(")
                items = [self.expr()]
                while self.peek() == ",":
                    self.take(",")
                    items.append(self.expr())
                self.take(")")
                if len(items) > 100:
                    raise QueryError("IN list exceeds 100 values")
                left = SQL(
                    "(" + left.text + " IN (" + ",".join(i.text for i in items) + "))",
                    left.args + [a for i in items for a in i.args],
                )
                continue
            right = self.expr(precedence[op] + 1)
            if op == ".":
                left = compose(
                    "(CAST({} AS VARCHAR) || CAST({} AS VARCHAR))", left, right
                )
            elif op in {"+", "-", "*", "/", "%"}:
                if op in {"/", "%"}:
                    left = compose(
                        "(TRY_CAST({} AS DOUBLE) "
                        + op
                        + " NULLIF(TRY_CAST({} AS DOUBLE),0))",
                        left,
                        right,
                    )
                else:
                    left = compose(
                        "(TRY_CAST({} AS DOUBLE) " + op + " TRY_CAST({} AS DOUBLE))",
                        left,
                        right,
                    )
            else:
                left = compose(
                    "({} " + ("=" if op == "==" else op) + " {})", left, right
                )
        self.depth -= 1
        return left

    def function(self, name, args):
        if name == "jsontype":
            if (
                len(args) != 2
                or args[0].text != ident("raw")
                or args[0].args
                or args[1].text != "?"
                or len(args[1].args) != 1
                or not isinstance(args[1].args[0], str)
                or not re.fullmatch(
                    r"\$\.[A-Za-z_][A-Za-z0-9_]{0,63}(?:\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,4}",
                    args[1].args[0],
                )
            ):
                raise QueryError(
                    "jsontype requires original raw and a literal bounded field path"
                )
            return compose("json_type({}, {})", *args)
        if name in {"match", "replace"}:
            if len(args) < 2 or args[1].text != "?" or len(args[1].args) != 1:
                raise QueryError("Regex functions require a literal pattern")
            validate_regex(args[1].args[0])
        if name == "mvindex" and len(args) == 2:
            # SPL is zero-based for positive indexes and -1 means the last item.
            return compose(
                "list_extract({},CASE WHEN TRY_CAST({} AS INTEGER)<0 "
                "THEN TRY_CAST({} AS INTEGER) ELSE TRY_CAST({} AS INTEGER)+1 END)",
                args[0],
                args[1],
                args[1],
                args[1],
            )
        specs = {
            "lower": (1, 1, "lower(CAST({0} AS VARCHAR))"),
            "upper": (1, 1, "upper(CAST({0} AS VARCHAR))"),
            "len": (1, 1, "length(CAST({0} AS VARCHAR))"),
            "abs": (1, 1, "abs(TRY_CAST({0} AS DOUBLE))"),
            "ceil": (1, 1, "ceil(TRY_CAST({0} AS DOUBLE))"),
            "ceiling": (1, 1, "ceil(TRY_CAST({0} AS DOUBLE))"),
            "floor": (1, 1, "floor(TRY_CAST({0} AS DOUBLE))"),
            "sqrt": (1, 1, "sqrt(TRY_CAST({0} AS DOUBLE))"),
            "pow": (2, 2, "power(TRY_CAST({0} AS DOUBLE),TRY_CAST({1} AS DOUBLE))"),
            "tonumber": (1, 1, "TRY_CAST({0} AS DOUBLE)"),
            "tostring": (1, 1, "CAST({0} AS VARCHAR)"),
            "isnull": (1, 1, "({0} IS NULL)"),
            "isnotnull": (1, 1, "({0} IS NOT NULL)"),
            "null": (0, 0, "NULL"),
            "true": (0, 0, "TRUE"),
            "false": (0, 0, "FALSE"),
            "if": (3, 3, "CASE WHEN {0} THEN {1} ELSE {2} END"),
            "substr": (
                2,
                3,
                "substr(CAST({0} AS VARCHAR),CAST({1} AS INTEGER){extra})",
            ),
            "round": (1, 2, "round(TRY_CAST({0} AS DOUBLE){extra})"),
            "trim": (1, 2, "trim(CAST({0} AS VARCHAR){extra})"),
            "ltrim": (1, 2, "ltrim(CAST({0} AS VARCHAR){extra})"),
            "rtrim": (1, 2, "rtrim(CAST({0} AS VARCHAR){extra})"),
            "replace": (3, 3, "regexp_replace(CAST({0} AS VARCHAR),{1},{2},'g')"),
            "match": (2, 2, "regexp_matches(CAST({0} AS VARCHAR),{1})"),
            "split": (2, 2, "string_split(CAST({0} AS VARCHAR),{1})"),
            "mvcount": (1, 1, "array_length({0})"),
            "strftime": (2, 2, "strftime(to_timestamp(TRY_CAST({0} AS DOUBLE)),{1})"),
            "strptime": (2, 2, "epoch(try_strptime(CAST({0} AS VARCHAR),{1}))"),
            "md5": (1, 1, "md5(CAST({0} AS VARCHAR))"),
            "sha256": (1, 1, "sha256(CAST({0} AS VARCHAR))"),
        }
        if name == "now" and not args:
            return literal(time.time())
        if name in {"coalesce", "min", "max"}:
            if not 1 <= len(args) <= 32:
                raise QueryError("Function argument budget exceeded")
            target = {"min": "least", "max": "greatest"}.get(name, name)
            return SQL(
                target + "(" + ",".join(a.text for a in args) + ")",
                [v for a in args for v in a.args],
            )
        if name == "case":
            if not args or len(args) % 2 or len(args) > 32:
                raise QueryError("case requires condition,value pairs")
            return SQL(
                "CASE "
                + " ".join(
                    "WHEN " + a.text + " THEN " + b.text
                    for a, b in zip(args[::2], args[1::2])
                )
                + " ELSE NULL END",
                [v for a in args for v in a.args],
            )
        spec = specs.get(name)
        if not spec or not spec[0] <= len(args) <= spec[1]:
            raise QueryError("Unsupported function or argument count: " + name)
        template = spec[2]
        if "{extra}" in template:
            base = 2 if name == "substr" else 1
            template = template.replace(
                "{extra}", ",{" + str(base) + "}" if len(args) > base else ""
            )
        return SQL(
            template.format(*(a.text for a in args)), [v for a in args for v in a.args]
        )


SEARCH_TOKEN = re.compile(
    r"""\s*("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|!=|<=|>=|[()=<>]|[^\s()=<>!]+)"""
)


class Predicate:
    """Search has OR-before-AND precedence; where/eval use conventional precedence."""

    def __init__(self, text, resolver):
        self.tokens = [m.group(1) for m in SEARCH_TOKEN.finditer(text)]
        if len(self.tokens) > 512:
            raise QueryError("Search token budget exceeded")
        self.at, self.depth, self.resolver = 0, 0, resolver

    def peek(self):
        return self.tokens[self.at] if self.at < len(self.tokens) else ""

    def take(self):
        value = self.peek()
        if not value:
            raise QueryError("Incomplete search predicate")
        self.at += 1
        return value

    def parse(self):
        if not self.tokens:
            return SQL("TRUE", [])
        result = self.and_expr()
        if self.peek():
            raise QueryError("Unexpected search token")
        return result

    def and_expr(self):
        left = self.or_expr()
        while self.peek() and self.peek() != ")":
            if self.peek().upper() == "AND":
                self.take()
            left = compose("({} AND {})", left, self.or_expr())
        return left

    def or_expr(self):
        left = self.atom()
        while self.peek().upper() == "OR":
            self.take()
            left = compose("({} OR {})", left, self.atom())
        return left

    def atom(self):
        self.depth += 1
        if self.depth > 40:
            raise QueryError("Search nesting budget exceeded")
        token = self.take()
        if token.upper() == "NOT":
            result = compose("(NOT COALESCE({},FALSE))", self.atom())
        elif token == "(":
            result = self.and_expr()
            if self.take() != ")":
                raise QueryError("Unbalanced search predicate")
        elif self.peek() in {"=", "!=", "<", ">", "<=", ">="}:
            op = self.take()
            text = self.take()
            quoted = text.startswith(('"', "'"))
            value = unquote(text) if quoted else text
            field = self.resolver(token)
            if value == "*" and op in {"=", "!="}:
                result = compose(
                    "({} IS " + ("NOT " if op == "=" else "") + "NULL)", field
                )
            elif "*" in value and op in {"=", "!="}:
                pattern = (
                    value.replace("\\", "\\\\")
                    .replace("%", "\\%")
                    .replace("_", "\\_")
                    .replace("*", "%")
                )
                result = compose(
                    "(CAST({} AS VARCHAR) "
                    + ("NOT " if op == "!=" else "")
                    + "ILIKE {} ESCAPE '\\')",
                    field,
                    literal(pattern),
                )
            else:
                if not quoted and re.fullmatch(r"[+-]?\d+(?:\.\d+)?", value):
                    value = float(value)
                    field = compose("TRY_CAST({} AS DOUBLE)", field)
                elif op in {"=", "!="}:
                    field = compose("lower(CAST({} AS VARCHAR))", field)
                    value = value.lower()
                result = compose("({} " + op + " {})", field, literal(value))
        elif token == "*":
            result = SQL("TRUE", [])
        elif token.upper() in {"OR", "AND", ")"} or any(
            x in token for x in ("`", ";", "[", "]")
        ):
            raise QueryError("Invalid search predicate")
        else:
            text = unquote(token) if token.startswith(('"', "'")) else token
            matches = []
            for name in ("message", "raw"):
                try:
                    expression = self.resolver(name)
                except QueryError:
                    continue
                matches.append(
                    compose(
                        "contains(lower(COALESCE(CAST({} AS VARCHAR),'')),lower({}))",
                        expression,
                        literal(text),
                    )
                )
            if not matches:
                raise QueryError("Text search requires message or raw")
            result = SQL(
                "(" + " OR ".join(m.text for m in matches) + ")",
                [a for m in matches for a in m.args],
            )
        self.depth -= 1
        return result


def fields(text):
    try:
        names = shlex.split(text.replace(",", " "))
    except ValueError as exc:
        raise QueryError("Invalid field list") from exc
    if not names or len(names) > 64:
        raise QueryError("Expected 1..64 fields")
    for name in names:
        ident(name)
    return names


def span_seconds(text):
    m = re.fullmatch(r"([1-9][0-9]{0,6})(ms|s|m|h|d|w)?", text)
    if not m:
        raise QueryError("Invalid bucket span")
    return (
        int(m[1])
        * {None: 1, "ms": 0.001, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[
            m[2]
        ]
    )


def lookup_spec(text):
    """One exact key and explicit bounded output fields; no external definitions."""
    try:
        tokens = shlex.split(text.replace(",", " "))
    except ValueError as exc:
        raise QueryError("Invalid lookup syntax") from exc
    if len(tokens) < 4:
        raise QueryError(
            "lookup requires name key [AS event_field] OUTPUT[NEW] columns"
        )
    name, key, at = tokens[0], tokens[1], 2
    for value in (name, key):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", value):
            raise QueryError("Lookup table and key must be simple identifiers")
        ident(value)
    event_field = key
    if tokens[at].upper() == "AS":
        if len(tokens) <= at + 2:
            raise QueryError("Lookup AS requires an event field")
        event_field, at = tokens[at + 1], at + 2
    ident(event_field)
    mode = tokens[at].upper()
    if mode not in {"OUTPUT", "OUTPUTNEW"}:
        raise QueryError("Lookup requires explicit OUTPUT or OUTPUTNEW")
    at += 1
    outputs = []
    while at < len(tokens):
        column = tokens[at]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", column):
            raise QueryError("Invalid lookup output column")
        ident(column)
        target, at = column, at + 1
        if at < len(tokens) and tokens[at].upper() == "AS":
            if at + 1 >= len(tokens):
                raise QueryError("Lookup output AS requires a field")
            target, at = tokens[at + 1], at + 2
        ident(target)
        outputs.append((column, target))
    if not 1 <= len(outputs) <= 16 or len({target for _, target in outputs}) != len(
        outputs
    ):
        raise QueryError("Lookup requires 1..16 unique output fields")
    return name, key, event_field, mode, outputs


class SPLQuery:
    def __init__(self, body, earliest, latest, limit):
        self.body, self.earliest, self.latest, self.limit = (
            body,
            earliest,
            latest,
            limit,
        )
        self.group_by = None
        self.commands = []
        for i, part in enumerate(split_pipeline(body)):
            if not part and i == 0:
                continue
            if not part:
                raise QueryError("Empty pipeline command")
            cmd, _, rest = part.partition(" ")
            cmd = cmd.lower()
            if i == 0 and cmd not in COMMANDS:
                cmd, rest = "search", part
            if cmd not in COMMANDS:
                raise QueryError("Unsupported SPL command: " + cmd)
            self.commands.append((cmd, rest.strip()))
        if len(self.commands) > 32:
            raise QueryError("Pipeline exceeds 32 commands")
        self._validating = True
        try:
            self.compile("__validation__")
        finally:
            self._validating = False

    @classmethod
    def parse(cls, payload):
        if not isinstance(payload, dict) or len(payload)>len(PAYLOAD_FIELDS) or set(payload)-PAYLOAD_FIELDS:
            raise QueryError("Expected language, query, earliest, latest, limit; time bounds use earliest/latest")
        if payload.get("language", "spl") != "spl":
            raise QueryError("SPL query language must be spl")
        body = payload.get("query", "")
        if not isinstance(body, str) or len(body) > 32768 or "`" in body:
            raise QueryError(
                "SPL text exceeds budget or contains an unregistered macro"
            )
        now = time.time()
        start, end, limit = (
            payload.get("earliest", now - 86400),
            payload.get("latest", now),
            payload.get("limit", 200),
        )
        if (
            any(
                isinstance(x, bool)
                or not isinstance(x, (int, float))
                or not math.isfinite(x)
                for x in (start, end)
            )
            or not 0 <= start < end
        ):
            raise QueryError("Time range must be finite and earliest < latest")
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise QueryError("Limit must be 1..1000")
        return cls(body, float(start), float(end), limit)

    def compile(self, tenant, allowed_indexes=None, lookup_tables=None):
        if lookup_tables is not None and not isinstance(lookup_tables, dict):
            raise QueryError("Managed lookup snapshots must be a mapping")
        available = set(BASE)
        aliases = dict(ALIASES)
        transformed = False
        args = [tenant, self.earliest, self.latest]
        scope, scope_args = index_predicate(allowed_indexes)
        args.extend(scope_args)

        def source_cte(order):
            return (
                "q0 AS (SELECT *,"
                + order
                + " AS __order FROM events_all WHERE tenant=? AND event_time>=? AND event_time<? AND "
                + scope
                + ")"
            )

        ctes = [source_cte("row_number() OVER (ORDER BY event_time DESC,event_id)")]
        previous = "q0"
        visible = ["event_time", "event_id", "source", "host", "severity", "message"]

        def resolve(name):
            ident(name)
            actual = aliases.get(name, name)
            if actual in available:
                return SQL(ident(actual), [])
            if not transformed and "raw" in available:
                path = name.removeprefix("raw.")
                if not re.fullmatch(
                    r"[A-Za-z_][A-Za-z0-9_]{0,63}(?:\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,4}",
                    path,
                ):
                    raise QueryError("Invalid JSON field path")
                return SQL("json_extract_string(raw, ?)", ["$." + path])
            raise QueryError("Field unavailable after transform: " + name)

        def add(select, fragment_args=()):
            nonlocal previous
            name = "q" + str(len(ctes))
            ctes.append(name + " AS (" + select.replace("@input", previous) + ")")
            args.extend(fragment_args)
            previous = name

        def aggregate(text, window=None, *, functions=None):
            match = re.fullmatch(
                r"(?i)(count|sum|avg|mean|min|max|median|dc|distinct_count|values|list|first|last|latest|earliest|stdev|stdevp|var|varp)(?:\((.*)\))?(?:\s+as\s+([A-Za-z_][A-Za-z0-9_.]*))?",
                text.strip(),
            )
            if not match:
                raise QueryError("Invalid or unsupported aggregate: " + text)
            function, field, label = match.groups()
            function = function.lower()
            label = label or (function + ("(" + field + ")" if field else ""))
            # Aggregate-generated default labels may contain parentheses; quote internally.
            if match[3]:
                ident(label)
            label_sql = '"' + label.replace('"', '""') + '"'
            if field and field.lower().startswith("eval(") and field.endswith(")"):
                expression = Expression(field[5:-1], resolve).parse()
                if function != "count":
                    expression = compose(
                        "CASE WHEN {} THEN 1 ELSE NULL END", expression
                    )
            elif field and field != "*":
                expression = resolve(field.strip())
            else:
                expression = None
            if function == "count":
                result = (
                    SQL("count(*)", [])
                    if expression is None
                    else compose(
                        "count_if({})"
                        if field.lower().startswith("eval(")
                        else "count({})",
                        expression,
                    )
                )
            else:
                if expression is None:
                    raise QueryError("Aggregate requires a field")
                if function in {"latest", "earliest"}:
                    result = compose(
                        "arg_" + ("max" if function == "latest" else "min") + "({},{})",
                        expression,
                        resolve("event_time"),
                    )
                elif function in {"dc", "distinct_count"}:
                    result = compose("count(DISTINCT {})", expression)
                elif function in {"values", "list"}:
                    result = compose(
                        "list("
                        + ("DISTINCT " if function == "values" else "")
                        + "{}) FILTER (WHERE {} IS NOT NULL)",
                        expression,
                        expression,
                    )
                elif function == "median":
                    # SPL1's even-cardinality median is the upper middle value,
                    # unlike SPL2/DuckDB's interpolated mathematical median.
                    result = compose(
                        "quantile_disc(TRY_CAST({} AS DOUBLE),0.5000000000000001)",
                        expression,
                    )
                elif function in {"min", "max"}:
                    # SPL orders numeric values before text, including mixed fields.
                    # Return the original field type so later eval casts still work.
                    numeric = compose(
                        "CASE WHEN isfinite(TRY_CAST({} AS DOUBLE)) "
                        "THEN TRY_CAST({} AS DOUBLE) ELSE NULL END",
                        expression,
                        expression,
                    )
                    key = compose(
                        "struct_pack(is_text := ({} IS NULL),number_value := {},"
                        "text_value := CAST({} AS VARCHAR))",
                        numeric,
                        numeric,
                        expression,
                    )
                    result = compose("arg_" + function + "({},{})", expression, key)
                else:
                    target = {
                        "mean": "avg",
                        "stdev": "stddev_samp",
                        "stdevp": "stddev_pop",
                        "var": "var_samp",
                        "varp": "var_pop",
                    }.get(function, function)
                    if function not in {"first", "last", "min", "max"}:
                        expression = compose("TRY_CAST({} AS DOUBLE)", expression)
                    result = compose(target + "({})", expression)
            if window is not None:
                result = compose("{} OVER ({})", result, window)
            if functions is not None:
                functions.append(function)
            return SQL(result.text + " AS " + label_sql, result.args), label

        for position, (cmd, rest) in enumerate(self.commands):
            if cmd == "search":
                predicate = Predicate(rest, resolve).parse()
                add("SELECT * FROM @input WHERE " + predicate.text, predicate.args)
            elif cmd in {"where", "regex"}:
                if cmd == "where":
                    expression = Expression(rest, resolve).parse()
                else:
                    m = re.fullmatch(
                        r'([A-Za-z_][A-Za-z0-9_.]*)\s*(!=|=)\s*("(?:\\.|[^"\\])*")',
                        rest,
                    )
                    if not m:
                        raise QueryError('regex requires field="pattern"')
                    pattern = unquote(m[3])
                    validate_regex(pattern)
                    expression = compose(
                        ("NOT " if m[2] == "!=" else "")
                        + "regexp_matches(CAST({} AS VARCHAR),{})",
                        resolve(m[1]),
                        literal(pattern),
                    )
                add("SELECT * FROM @input WHERE " + expression.text, expression.args)
            elif cmd == "eval":
                for assignment in split_top(rest):
                    m = re.fullmatch(
                        r"([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.+)", assignment, re.DOTALL
                    )
                    if not m:
                        raise QueryError("eval requires field=expression")
                    name = m[1]
                    target = aliases.get(name, name)
                    ident(target)
                    expression = Expression(m[2], resolve).parse()
                    exclude = (
                        " EXCLUDE (" + ident(target) + ")"
                        if target in available
                        else ""
                    )
                    add(
                        "SELECT *"
                        + exclude
                        + ","
                        + expression.text
                        + " AS "
                        + ident(target)
                        + " FROM @input",
                        expression.args,
                    )
                    available.add(target)
                    if target not in visible:
                        visible.append(target)
            elif cmd == "lookup":
                from .lookups import validated_snapshot

                name, key, event_field, mode, outputs = lookup_spec(rest)
                input_value = resolve(event_field)
                table = (lookup_tables or {}).get(name)
                if table is None and self._validating:
                    table = {
                        "key": key,
                        "rows": [],
                        "columns": list(
                            dict.fromkeys([key, *(column for column, _ in outputs)])
                        ),
                    }
                if not isinstance(table, dict):
                    raise QueryError("Managed lookup unavailable: " + name)
                if table.get("key") != key:
                    raise QueryError(
                        "Lookup match field must be its managed unique key"
                    )
                try:
                    rows, columns = validated_snapshot(table)
                except QueryError:
                    raise
                except (ValueError, TypeError, OverflowError) as exc:
                    raise QueryError("Invalid managed lookup snapshot") from exc
                if any(column not in columns for column, _ in outputs):
                    raise QueryError("Lookup output column unavailable")
                table_parts = ["json_extract_string(value,?) AS __key"]
                table_args = ["$." + key]
                projections, projection_args, replaced = [], [], []
                targets = [aliases.get(output, output) for _, output in outputs]
                if len(set(targets)) != len(targets):
                    raise QueryError("Duplicate aliased lookup output field")
                for number, (column, output) in enumerate(outputs):
                    target = aliases.get(output, output)
                    ident(target)
                    table_parts.append(
                        "json_extract_string(value,?) AS __value" + str(number)
                    )
                    table_args.append("$." + column)
                    try:
                        old = resolve(output)
                    except QueryError:
                        old = SQL("NULL", [])
                    lookup_value = "l.__value" + str(number)
                    if mode == "OUTPUTNEW":
                        expression = (
                            "coalesce(CAST("
                            + old.text
                            + " AS VARCHAR),"
                            + lookup_value
                            + ")"
                        )
                    else:
                        expression = (
                            "CASE WHEN l.__key IS NULL THEN CAST("
                            + old.text
                            + " AS VARCHAR) ELSE "
                            + lookup_value
                            + " END"
                        )
                    projections.append(expression + " AS " + ident(target))
                    projection_args.extend(old.args)
                    if target in available:
                        replaced.append(target)
                exclude = (
                    " EXCLUDE (" + ",".join(ident(n) for n in replaced) + ")"
                    if replaced
                    else ""
                )
                table_sql = "SELECT " + ",".join(table_parts) + " FROM json_each(?)"
                add(
                    "SELECT i.*"
                    + exclude
                    + ","
                    + ",".join(projections)
                    + " FROM @input AS i LEFT JOIN ("
                    + table_sql
                    + ") AS l ON CAST("
                    + input_value.text
                    + " AS VARCHAR)=l.__key",
                    [
                        *projection_args,
                        *table_args,
                        json.dumps(
                            rows,
                            ensure_ascii=False,
                            allow_nan=False,
                            separators=(",", ":"),
                        ),
                        *input_value.args,
                    ],
                )
                available.update(targets)
                visible += [target for target in targets if target not in visible]
            elif cmd in {"stats", "eventstats", "streamstats", "timechart"}:
                text = rest
                bucket = None
                if cmd == "timechart":
                    m = re.match(r"span=(\S+)\s+", text)
                    bucket = span_seconds(m[1]) if m else 60
                    if m:
                        text = text[m.end() :]
                    e = resolve("event_time")
                    add(
                        "SELECT *,floor(" + e.text + "/?)*? AS __bucket FROM @input",
                        e.args + [bucket, bucket],
                    )
                    available.add("__bucket")
                window_count, current = None, True
                if cmd == "streamstats":
                    while True:
                        m = re.match(r"(window|current)=(\S+)\s+", text)
                        if not m:
                            break
                        if m[1] == "window":
                            if not m[2].isdigit() or not 1 <= int(m[2]) <= 100000:
                                raise QueryError("streamstats window must be 1..100000")
                            window_count = int(m[2])
                        elif m[2] not in {"true", "false"}:
                            raise QueryError("current must be true or false")
                        else:
                            current = m[2] == "true"
                        text = text[m.end() :]
                by_match = re.search(r"(?i)\s+by\s+", text)
                group = fields(text[by_match.end() :]) if by_match else []
                agg_text = text[: by_match.start()] if by_match else text
                # Commas outside function arguments or spaces between aggregate terms.
                terms = split_top(agg_text)
                if len(terms) == 1:
                    terms = re.split(
                        r"\s+(?=(?:count|sum|avg|mean|min|max|median|dc|distinct_count|values|list|first|last|latest|earliest|stdev|stdevp|var|varp)(?:\(|\s|$))",
                        agg_text.strip(),
                        flags=re.IGNORECASE,
                    )
                if not 1 <= len(terms) <= 32:
                    raise QueryError("Expected 1..32 aggregates")
                group_expressions = [resolve(x) for x in group]
                if bucket:
                    group = ["_time", *group]
                    group_expressions = [SQL('"__bucket"', []), *group_expressions]
                if cmd in {"eventstats", "streamstats"}:
                    partition = SQL(
                        "PARTITION BY " + ",".join(e.text for e in group_expressions)
                        if group
                        else "",
                        [a for e in group_expressions for a in e.args],
                    )
                    if cmd == "streamstats":
                        preceding = (
                            str(window_count - 1) if window_count else "UNBOUNDED"
                        )
                        if not current and window_count:
                            preceding = str(window_count)
                        partition = SQL(
                            partition.text
                            + " ORDER BY __order ROWS BETWEEN "
                            + preceding
                            + " PRECEDING AND "
                            + ("CURRENT ROW" if current else "1 PRECEDING"),
                            partition.args,
                        )
                    aggregates = [aggregate(t, partition) for t in terms]
                    names = [n for _, n in aggregates]
                    replaced = [n for n in names if n in available]
                    exclude = (
                        " EXCLUDE (" + ",".join(ident(n) for n in replaced) + ")"
                        if replaced
                        else ""
                    )
                    add(
                        "SELECT *"
                        + exclude
                        + ","
                        + ",".join(e.text for e, _ in aggregates)
                        + " FROM @input",
                        [a for e, _ in aggregates for a in e.args],
                    )
                    available.update(names)
                    visible += [n for n in names if n not in visible]
                else:
                    functions = []
                    aggregates = [aggregate(t, functions=functions) for t in terms]
                    if (
                        cmd == "stats"
                        and all(
                            prefix in {"search", "where", "regex"}
                            for prefix, _ in self.commands[:position]
                        )
                        and all(f in COMMUTATIVE_AGGREGATES for f in functions)
                    ):
                        # Filters preserve the source row set, and this stats discards
                        # source order before establishing its own output order.
                        ctes[0] = source_cte("0::BIGINT")
                    projection = [
                        SQL(e.text + " AS " + ident(n), e.args)
                        for n, e in zip(group, group_expressions)
                    ] + [e for e, _ in aggregates]
                    suffix = (
                        " GROUP BY " + ",".join(str(i + 1) for i in range(len(group)))
                        if group
                        else ""
                    )
                    add(
                        "SELECT "
                        + ",".join(e.text for e in projection)
                        + " FROM @input"
                        + suffix,
                        [a for e in projection for a in e.args],
                    )
                    visible = group + [n for _, n in aggregates]
                    if len(set(visible)) != len(visible):
                        raise QueryError("Duplicate aggregate output field")
                    available, aliases, transformed = set(visible), {}, True
                    self.group_by = group
                    # Formerly tied groups had no defined relative order. Retain the
                    # primary order and make ties stable for downstream commands.
                    ordered = [
                        ident(group[0]) + " ASC NULLS LAST"
                        if bucket
                        else '"' + visible[-1].replace('"', '""') + '" DESC NULLS LAST'
                    ]
                    ordered.extend(
                        ident(name) + " ASC NULLS LAST"
                        for name in (group[1:] if bucket else group)
                    )
                    add(
                        "SELECT *,row_number() OVER (ORDER BY "
                        + ",".join(ordered)
                        + ") AS __order FROM @input"
                    )
            elif cmd in {"table", "fields"}:
                remove = cmd == "fields" and rest.startswith("-")
                names = fields(
                    rest[1:].strip() if rest.startswith(("-", "+")) else rest
                )
                if remove:
                    names = [
                        n
                        for n in visible
                        if n not in names and aliases.get(n, n) not in names
                    ]
                    if not names:
                        raise QueryError("Cannot remove all result fields")
                expressions = [resolve(n) for n in names]
                add(
                    "SELECT "
                    + ",".join(
                        e.text + " AS " + ident(n) for n, e in zip(names, expressions)
                    )
                    + ",__order FROM @input",
                    [a for e in expressions for a in e.args],
                )
                visible, available, aliases, transformed = names, set(names), {}, True
            elif cmd == "rename":
                pairs = split_top(rest)
                renames = {}
                for pair in pairs:
                    m = re.fullmatch(
                        r"(?i)([A-Za-z_][A-Za-z0-9_.]*)\s+as\s+([A-Za-z_][A-Za-z0-9_.]*)",
                        pair,
                    )
                    if not m:
                        raise QueryError("rename requires old AS new pairs")
                    old, new = m.groups()
                    resolve(old)
                    ident(new)
                    old = aliases.get(old, old)
                    if old not in available:
                        raise QueryError("rename source must be a materialized field")
                    if new in available and new != old:
                        raise QueryError("rename destination already exists")
                    renames[old] = new
                add(
                    "SELECT * RENAME ("
                    + ",".join(ident(a) + " AS " + ident(b) for a, b in renames.items())
                    + ") FROM @input"
                )
                available = {renames.get(n, n) for n in available}
                visible = [renames.get(n, n) for n in visible]
                aliases = {a: b for a, b in aliases.items() if b not in renames}
            elif cmd == "sort":
                sort_text = rest.strip()
                count = 10000
                m = re.match(r"(?:limit=)?(\d+)\s+", sort_text, re.IGNORECASE)
                if m:
                    count = int(m[1])
                    if count > 1000000:
                        raise QueryError("sort count budget exceeded")
                    sort_text = sort_text[m.end() :]
                reverse_sort = bool(
                    re.search(r"\s+(?:d|desc)$", sort_text, re.IGNORECASE)
                )
                if reverse_sort:
                    sort_text = re.sub(
                        r"\s+(?:d|desc)$", "", sort_text, flags=re.IGNORECASE
                    )
                tokens = [x for x in re.split(r"[,\s]+", sort_text) if x]
                direction = "+"
                names = []
                for token in tokens:
                    if token in {"+", "-"}:
                        direction = token
                    else:
                        names.append(
                            token if token.startswith(("+", "-")) else direction + token
                        )
                if tokens and tokens[-1] in {"+", "-"}:
                    raise QueryError("sort direction requires a field")
                if not 1 <= len(names) <= 16:
                    raise QueryError("sort requires 1..16 fields")
                expressions = []
                for n in names:
                    field = n[1:]
                    option = re.fullmatch(
                        r"(?i)(num|str|auto)\(([A-Za-z_][A-Za-z0-9_.]*)\)", field
                    )
                    e = resolve(option[2] if option else field)
                    if option and option[1].lower() != "auto":
                        e = SQL(
                            "TRY_CAST("
                            + e.text
                            + " AS "
                            + ("DOUBLE" if option[1].lower() == "num" else "VARCHAR")
                            + ")",
                            e.args,
                        )
                    expressions.append(
                        SQL(
                            e.text
                            + (" DESC" if n.startswith("-") != reverse_sort else " ASC")
                            + " NULLS LAST",
                            e.args,
                        )
                    )
                order = ",".join(e.text for e in expressions) + ",__order"
                add(
                    "SELECT * EXCLUDE (__order),row_number() OVER (ORDER BY "
                    + order
                    + ") AS __order FROM @input",
                    [a for e in expressions for a in e.args],
                )
                if count:
                    add("SELECT * FROM @input WHERE __order<=?", [count])
            elif cmd in {"head", "tail"}:
                text = rest or "10"
                if not text.isdigit() or not 1 <= int(text) <= 1000000:
                    raise QueryError(cmd + " requires 1..1000000")
                amount = int(text)
                if position == len(self.commands) - 1:
                    self.limit = min(self.limit, amount)
                add(
                    "SELECT * FROM @input ORDER BY __order "
                    + ("DESC" if cmd == "tail" else "ASC")
                    + " LIMIT ?",
                    [amount],
                )
                if cmd == "tail":
                    add(
                        "SELECT * EXCLUDE (__order),row_number() OVER (ORDER BY __order DESC) AS __order FROM @input"
                    )
            elif cmd == "reverse":
                if rest:
                    raise QueryError("reverse takes no arguments")
                add(
                    "SELECT * EXCLUDE (__order),row_number() OVER (ORDER BY __order DESC) AS __order FROM @input"
                )
            elif cmd == "dedup":
                names = fields(rest)
                expressions = [resolve(n) for n in names]
                add(
                    "SELECT * FROM @input QUALIFY row_number() OVER (PARTITION BY "
                    + ",".join(e.text for e in expressions)
                    + " ORDER BY __order)=1",
                    [a for e in expressions for a in e.args],
                )
            elif cmd in {"bin", "bucket"}:
                m = re.fullmatch(
                    r"(?:span=(\S+)\s+)?([A-Za-z_][A-Za-z0-9_.]*)(?:\s+span=(\S+))?",
                    rest,
                )
                if not m or not (m[1] or m[3]):
                    raise QueryError("bin requires field span=value")
                value = span_seconds(m[1] or m[3])
                name = aliases.get(m[2], m[2])
                e = resolve(m[2])
                exclude = " EXCLUDE (" + ident(name) + ")" if name in available else ""
                add(
                    "SELECT *"
                    + exclude
                    + ",floor(TRY_CAST("
                    + e.text
                    + " AS DOUBLE)/?)*? AS "
                    + ident(name)
                    + " FROM @input",
                    e.args + [value, value],
                )
                available.add(name)
                if name not in visible:
                    visible.append(name)
            elif cmd in {"top", "rare"}:
                m = re.match(r"(\d+)\s+", rest)
                count = int(m[1]) if m else 10
                if not 1 <= count <= 1000:
                    raise QueryError("top/rare count must be 1..1000")
                names = fields(rest[m.end() :] if m else rest)
                expressions = [resolve(n) for n in names]
                add(
                    "SELECT "
                    + ",".join(
                        e.text + " AS " + ident(n) for n, e in zip(names, expressions)
                    )
                    + ",count(*) AS count FROM @input GROUP BY "
                    + ",".join(str(i + 1) for i in range(len(names))),
                    [a for e in expressions for a in e.args],
                )
                add(
                    "SELECT *,100.0*count/sum(count) OVER () AS percent,row_number() OVER (ORDER BY count "
                    + ("ASC" if cmd == "rare" else "DESC")
                    + ") AS __order FROM @input"
                )
                add("SELECT * FROM @input WHERE __order<=?", [count])
                visible, available, aliases, transformed = (
                    names + ["count", "percent"],
                    set(names + ["count", "percent"]),
                    {},
                    True,
                )
                self.group_by = names
            elif cmd == "fillnull":
                m = re.match(r'(?:value=("(?:\\.|[^"\\])*"|\S+)\s*)?(.*)', rest)
                value = m[1] or "0"
                value = unquote(value) if value.startswith(('"', "'")) else value
                names = fields(m[2]) if m[2] else list(visible)
                for name in names:
                    target = aliases.get(name, name)
                    e = resolve(name)
                    exclude = (
                        " EXCLUDE (" + ident(target) + ")"
                        if target in available
                        else ""
                    )
                    add(
                        "SELECT *"
                        + exclude
                        + ",coalesce(CAST("
                        + e.text
                        + " AS VARCHAR),?) AS "
                        + ident(target)
                        + " FROM @input",
                        e.args + [value],
                    )
                    available.add(target)
                    if target not in visible:
                        visible.append(target)
            elif cmd == "rex":
                m = re.fullmatch(
                    r'(?:field=([A-Za-z_][A-Za-z0-9_.]*)\s+)?("(?:\\.|[^"\\])*")', rest
                )
                if not m:
                    raise QueryError(
                        'rex requires [field=field] "named capture pattern"'
                    )
                pattern = unquote(m[2])
                validate_regex(pattern.replace("(?<", "(?P<"))
                try:
                    compiled = re.compile(pattern.replace("(?<", "(?P<"))
                except re.error as exc:
                    raise QueryError("Invalid capture pattern") from exc
                if not compiled.groupindex or len(compiled.groupindex) > 32:
                    raise QueryError("rex requires 1..32 named capture groups")
                # DuckDB executes RE2; Python's parser only discovers capture numbering.
                for name, number in compiled.groupindex.items():
                    ident(name)
                    e = resolve(m[1] or "message")
                    exclude = (
                        " EXCLUDE (" + ident(name) + ")" if name in available else ""
                    )
                    add(
                        "SELECT *"
                        + exclude
                        + ",nullif(regexp_extract(CAST("
                        + e.text
                        + " AS VARCHAR),?,?), '') AS "
                        + ident(name)
                        + " FROM @input",
                        e.args + [pattern.replace("(?<", "(?P<"), number],
                    )
                    available.add(name)
                    if name not in visible:
                        visible.append(name)
            elif cmd == "spath":
                options = {}
                for token in shlex.split(rest):
                    key, sep, value = token.partition("=")
                    if not sep or key not in {"input", "path", "output"}:
                        raise QueryError("spath requires input/path/output options")
                    options[key] = value
                path = options.get("path", "")
                name = options.get("output", path)
                if not re.fullmatch(
                    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){0,4}", path
                ):
                    raise QueryError("spath currently requires a bounded object path")
                ident(name)
                e = resolve(options.get("input", "raw"))
                exclude = " EXCLUDE (" + ident(name) + ")" if name in available else ""
                add(
                    "SELECT *"
                    + exclude
                    + ",json_extract_string(TRY_CAST("
                    + e.text
                    + " AS JSON),?) AS "
                    + ident(name)
                    + " FROM @input",
                    e.args + ["$." + path],
                )
                available.add(name)
                if name not in visible:
                    visible.append(name)
            elif cmd == "makeresults":
                if position != 0:
                    raise QueryError("makeresults must be the generating command")
                m = re.fullmatch(r"(?:count=([0-9]+))?", rest)
                if not m or not 1 <= int(m[1] or 1) <= 100000:
                    raise QueryError("makeresults count must be 1..100000")
                add(
                    "SELECT ?::DOUBLE AS event_time,'{}'::VARCHAR AS raw,row_number() OVER () AS __order FROM range(?)",
                    [self.latest, int(m[1] or 1)],
                )
                available, visible, aliases, transformed = (
                    {"event_time", "raw"},
                    ["event_time"],
                    dict(ALIASES),
                    False,
                )
        if len(ctes) > 160:
            raise QueryError("Compiled pipeline budget exceeded")
        # Parenthesized aggregate-generated labels are already compiler-owned.
        projection = []
        final_args = []
        for name in visible:
            if name in available:
                projection.append('"' + name.replace('"', '""') + '"')
            else:
                e = resolve(name)
                projection.append(e.text + " AS " + ident(name))
                final_args.extend(e.args)
        sql = (
            "WITH "
            + ",\n".join(ctes)
            + " SELECT "
            + ",".join(projection)
            + " FROM "
            + previous
            + " ORDER BY __order LIMIT ?"
        )
        return sql, args + final_args + [self.limit]
