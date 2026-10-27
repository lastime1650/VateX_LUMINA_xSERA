"""Explicit JSON Sigma subset -> bounded SPL; never silently discard semantics.

Not a general Sigma backend. The default scalar profile rejects advanced
semantics; bounded-json-v2 enables explicitly typed scalar alternatives and
quantified selections. Preview remains a query, not an ordered correlation
policy: converting OR/NOT into flat policy filters is lossy.
"""

import json
import math
import re

from .query import Query, column

MAX_BYTES = 65536
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")


def _scalar(value):
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise ValueError(  # noqa: TRY004 - HTTP validation consistently uses ValueError.
            "Sigma selection values must be scalar strings/numbers; lists/null are unsupported"
        )
    if isinstance(value, str):
        if len(value) > 1024 or any(ord(c) < 32 for c in value):
            raise ValueError(
                "Sigma strings exceed bounds or contain control characters"
            )
        if "*" in value or "?" in value:
            raise ValueError(
                "Sigma wildcard semantics are unsupported; use explicit modifiers"
            )
    elif abs(value) > 1e100 or not math.isfinite(value):
        raise ValueError("Sigma numeric value outside supported range")
    return value


def _leaf(source, value, mapping, extended=False):
    pieces = source.split("|")
    if len(pieces) > 2 or pieces[0] not in mapping:
        raise ValueError(
            "Every Sigma field requires an explicit mapping and at most one modifier"
        )
    target = mapping[pieces[0]]
    if column(target) == "raw":
        raise ValueError("Sigma requires an explicit scalar field, not the raw object")
    kind = (
        "jsontype(_raw," + json.dumps("$." + target.removeprefix("raw.")) + ")"
        if target.startswith("raw.")
        else None
    )
    modifier = pieces[1] if len(pieces) == 2 else "equals"
    if extended and isinstance(value, list):
        if (
            modifier == "exists"
            or not 1 <= len(value) <= 32
            or any(isinstance(v, (list, dict)) for v in value)
        ):
            raise ValueError("Sigma lists require 1..32 scalar alternatives")
        return "(" + " OR ".join(_leaf(source, v, mapping, True) for v in value) + ")"
    if extended and modifier == "exists":
        if type(value) is not bool:
            raise ValueError("Sigma exists modifier requires a boolean")
        if kind:
            if not value:
                return "coalesce((isnull(" + kind + ") OR " + kind + '="NULL"),false())'
            return (
                "coalesce(("
                + " OR ".join(
                    kind + "=" + json.dumps(t)
                    for t in ("VARCHAR", "BIGINT", "UBIGINT", "DOUBLE", "BOOLEAN")
                )
                + "),false())"
            )
        return ("isnotnull(" if value else "isnull(") + target + ")"
    if extended and value is None and modifier == "equals":
        return "isnull(" + target + ")"
    if extended and isinstance(value, str):
        if len(value) > 1024 or any(ord(c) < 32 for c in value):
            raise ValueError("Sigma string exceeds bounds")
        if re.search(r"\\[*?]", value):
            raise ValueError("Ambiguous escaped wildcard semantics are unsupported")
    else:
        value = _scalar(value)
    if modifier not in {"equals", "contains", "startswith", "endswith"}:
        raise ValueError("Unsupported Sigma modifier: " + modifier)
    if isinstance(value, str):
        pattern = "(?i)" + ("^" if modifier in {"equals", "startswith"} else "")
        pattern += (
            re.escape(value).replace(r"\*", ".*").replace(r"\?", ".")
            if extended
            else re.escape(value)
        )
        pattern += "$" if modifier in {"equals", "endswith"} else ""
        matched = (
            "coalesce(match("
            + target
            + ","
            + json.dumps(pattern, ensure_ascii=False)
            + "),false())"
        )
        return (
            "coalesce((" + kind + '="VARCHAR" AND ' + matched + "),false())"
            if kind
            else matched
        )
    if modifier != "equals":
        raise ValueError("String modifiers require string values")
    matched = "coalesce((tonumber(" + target + ")=" + str(value) + "),false())"
    if extended and kind:
        numeric = (
            "("
            + " OR ".join(
                kind + "=" + json.dumps(t) for t in ("BIGINT", "UBIGINT", "DOUBLE")
            )
            + ")"
        )
        return "coalesce((" + numeric + " AND " + matched + "),false())"
    return matched


class _Condition:
    def __init__(self, text, selections, extended=False):
        if not isinstance(text, str) or not 1 <= len(text) <= 2048:
            raise ValueError("Sigma condition must contain 1..2048 characters")
        self.tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[()]|\S", text)
        if len(self.tokens) > 128:
            raise ValueError("Sigma condition token budget exceeded")
        self.at = 0
        self.depth = 0
        self.selections = selections
        self.extended = extended

    def peek(self):
        return self.tokens[self.at].lower() if self.at < len(self.tokens) else ""

    def take(self):
        if self.at >= len(self.tokens):
            raise ValueError("Incomplete Sigma condition")
        token = self.tokens[self.at]
        self.at += 1
        return token

    def parse(self):
        result = self.expr()
        if self.at != len(self.tokens):
            raise ValueError(
                "Unsupported Sigma condition; only named selections, AND/OR/NOT and parentheses are supported"
            )
        return result

    def expr(self, precedence=0):
        self.depth += 1
        if self.depth > 20:
            raise ValueError("Sigma condition nesting budget exceeded")
        token = self.take()
        if self.extended and (token.lower() == "all" or token.isdigit()):
            if self.take().lower() != "of":
                raise ValueError("Sigma quantified condition requires of")
            pattern = self.take()
            if self.peek() == "*":
                self.take()
                pattern += "*"
            selected = (
                list(self.selections)
                if pattern.lower() == "them"
                else [name for name in self.selections if name.startswith(pattern[:-1])]
                if pattern.endswith("*")
                else [pattern]
                if pattern in self.selections
                else []
            )
            count = len(selected) if token.lower() == "all" else int(token)
            if not selected or not 1 <= count <= len(selected):
                raise ValueError("Sigma quantified selection set/count is invalid")
            left = (
                "("
                + "+".join("if(" + self.selections[name] + ",1,0)" for name in selected)
                + ">="
                + str(count)
                + ")"
            )
        elif token.lower() == "not":
            left = "(NOT " + self.expr(3) + ")"
        elif token == "(":
            left = self.expr()
            if self.take() != ")":
                raise ValueError("Unbalanced Sigma condition")
        elif token in self.selections:
            left = self.selections[token]
        else:
            raise ValueError(
                "Unknown selection or unsupported Sigma condition: " + token
            )
        while (
            self.peek() in {"and", "or"}
            and {"or": 1, "and": 2}[self.peek()] >= precedence
        ):
            op = self.take().lower()
            right = self.expr({"or": 1, "and": 2}[op] + 1)
            left = "(" + left + " " + op.upper() + " " + right + ")"
        self.depth -= 1
        return left


def preview_sigma(body):
    """Accept {rule: JSON Sigma object, field_mapping: explicit source->field}."""
    if isinstance(body,dict) and body.get('profile')=='pysigma-json-v3':
        from . import sigma_backend
        return sigma_backend.preview(body)
    if (
        not isinstance(body, dict)
        or set(body) - {"rule", "field_mapping", "logsource_mapping", "profile"}
        or not {"rule", "field_mapping"} <= set(body)
    ):
        raise ValueError("Expected Sigma rule and explicit field_mapping")
    try:
        encoded = json.dumps(body, allow_nan=False, ensure_ascii=False)
    except (TypeError, ValueError, RecursionError):
        raise ValueError("Sigma input must be finite bounded JSON") from None
    if len(encoded.encode()) > MAX_BYTES:
        raise ValueError("Sigma input exceeds 64 KiB")
    rule, mapping = body["rule"], body["field_mapping"]
    profile = body.get("profile", "scalar-v1")
    if not isinstance(profile, str) or profile not in {"scalar-v1", "bounded-json-v2"}:
        raise ValueError("Unknown Sigma semantic profile")
    extended = profile == "bounded-json-v2"
    keys = {
        "title",
        "id",
        "description",
        "status",
        "author",
        "date",
        "modified",
        "references",
        "tags",
        "logsource",
        "detection",
        "falsepositives",
        "level",
        "fields",
    }
    if (
        not isinstance(rule, dict)
        or set(rule) - keys
        or not isinstance(rule.get("title"), str)
        or not 1 <= len(rule["title"]) <= 120
    ):
        raise ValueError(
            "Unsupported Sigma rule properties or missing bounded title; correlations are unsupported"
        )
    if not isinstance(mapping, dict) or not 1 <= len(mapping) <= 32:
        raise ValueError("Provide 1..32 explicit field mappings")
    for name, target in mapping.items():
        if (
            not isinstance(name, str)
            or not NAME.fullmatch(name)
            or name.lower() in {"and", "or", "not", "condition"}
        ):
            raise ValueError("Invalid Sigma mapping field")
        column(target)
    logsource = rule.get("logsource", {})
    if (
        not isinstance(logsource, dict)
        or set(logsource) - {"category", "product", "service"}
        or any(
            not isinstance(v, str) or not 1 <= len(v) <= 80 for v in logsource.values()
        )
    ):
        raise ValueError(
            "Unsupported Sigma logsource; supply category/product/service metadata only"
        )
    scope_mapping = body.get("logsource_mapping", {})
    if not isinstance(scope_mapping, dict) or set(scope_mapping) != set(logsource):
        raise ValueError(
            "Every Sigma logsource criterion requires an explicit logsource_mapping; source scope is never discarded"
        )
    source_leaves = []
    for item in scope_mapping.values():
        if not isinstance(item, dict) or set(item) != {"field", "value"}:
            raise ValueError(
                "Logsource mapping requires explicit field/value for each criterion"
            )
        source_leaves.append(
            _leaf("source_scope", item["value"], {"source_scope": item["field"]})
        )
    detection = rule.get("detection")
    if (
        not isinstance(detection, dict)
        or not 2 <= len(detection) <= 17
        or "condition" not in detection
    ):
        raise ValueError("Sigma detection requires condition and 1..16 selections")
    selections = {}
    for name, values in detection.items():
        if name == "condition":
            continue
        if (
            not isinstance(name, str)
            or not NAME.fullmatch(name)
            or name.lower() in {"and", "or", "not", "timeframe"}
        ):
            raise ValueError("Unsupported Sigma selection name/timeframe")
        if not isinstance(values, dict) or not 1 <= len(values) <= 16:
            raise ValueError(
                "Sigma selections must be 1..16 field maps; lists are unsupported"
            )
        leaves = []
        for source, value in values.items():
            if not isinstance(source, str):
                raise ValueError("Sigma selection field must be text")  # noqa: TRY004 - API validation.
            leaves.append(_leaf(source, value, mapping, extended))
        selections[name] = "(" + " AND ".join(leaves) + ")"
    predicate = _Condition(detection["condition"], selections, extended).parse()
    if source_leaves:
        predicate = "(" + " AND ".join([*source_leaves, predicate]) + ")"
    query = "search * | where " + predicate
    # Parse and compile with the actual bounded compiler and RE2 validator.
    Query.parse({"language": "spl", "query": query}).compile(
        "validation", allowed_indexes=[]
    )
    return {
        "title": rule["title"],
        "query": {"language": "spl", "query": query},
        "logsource": logsource,
        "field_mapping": dict(mapping),
        "logsource_mapping": scope_mapping,
        "query_only": True,
        "profile": profile,
        "semantic_ir": {
            "version": 2 if extended else 1,
            "selections": detection,
            "field_mapping": dict(mapping),
            "predicate": predicate,
        },
        "semantics": "Named scalar selections; fields within selection AND; explicit AND/OR/NOT; string match case-insensitive; missing selection fields are false before NOT.",
        "limitations": [
            "JSON input only",
            "No fieldref, aggregation, correlations, array-valued source fields or arbitrary regex; v1 additionally rejects lists/wildcards/null/exists/n-of",
            "v2 lists are OR alternatives; */? are whole-string wildcard symbols; exists means non-null scalar, null includes missing; v2 raw numeric equality requires a JSON number, v1 retains explicit tonumber coercion",
            "Every logsource criterion requires an explicit field/value mapping; mappings are operator-provided source semantics",
            "Query preview cannot be published as a flat-filter correlation policy without semantic loss",
        ],
    }
