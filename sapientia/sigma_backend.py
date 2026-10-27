"""Bounded pySigma AST backend for xSERA scalar JSON query semantics.

Upstream parses modifiers and boolean selections. This backend visits the typed
AST, never turns a boolean query into a lossy flat-filter correlation policy.
"""

import importlib.metadata
import json
import math
import re

from .query import Query, column

PROFILE = "pysigma-json-v3"
MODIFIERS = {
    "contains",
    "startswith",
    "endswith",
    "all",
    "cased",
    "re",
    "i",
    "m",
    "s",
    "exists",
    "gt",
    "gte",
    "lt",
    "lte",
    "fieldref",
}


def status():
    try:
        from sigma.rule import SigmaRule

        if not callable(SigmaRule.from_dict):
            raise ImportError("Compatible pySigma rule parser required")  # noqa: TRY004 - dependency capability check.
        return {
            "available": True,
            "version": importlib.metadata.version("pysigma"),
            "profile": PROFILE,
            "backend": "xsera-bounded-scalar-json",
            "general_sigma_backend": False,
        }
    except ImportError:
        return {
            "available": False,
            "version": None,
            "profile": PROFILE,
            "reason": "Install the pinned sigma-analysis extra",
            "general_sigma_backend": False,
        }


def _bounded(value):
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False)
    except (ValueError, TypeError, RecursionError):
        raise ValueError("Finite JSON required") from None
    if len(encoded.encode("utf-8")) > 65536:
        raise ValueError("Sigma input exceeds 64 KiB")
    stack = [(value, 0)]
    nodes = 0
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if depth > 16 or nodes > 2048:
            raise ValueError("Sigma structure exceeds bounds")
        if isinstance(node, (list, dict)):
            if len(node) > 32:
                raise ValueError("Sigma container exceeds 32 entries")
            stack.extend(
                (item, depth + 1)
                for item in (node.values() if isinstance(node, dict) else node)
            )
        elif isinstance(node, str) and (
            len(node) > 2048 or any(ord(c) < 32 for c in node)
        ):
            raise ValueError("Sigma text exceeds bounds or contains controls")
    return encoded


def _target(mapping, field):
    if field not in mapping:
        raise ValueError("Explicit mapping missing for " + str(field))
    target = mapping[field]
    if column(target) == "raw":
        raise ValueError("Scalar field mapping required")
    return target


def _kind(target):
    return (
        "jsontype(_raw," + json.dumps("$." + target.removeprefix("raw.")) + ")"
        if target.startswith("raw.")
        else None
    )


def _typed(target, predicate, types):
    kind = _kind(target)
    if kind:
        allowed = " OR ".join(kind + "=" + json.dumps(t) for t in types)
        predicate = "((" + allowed + ") AND " + predicate + ")"
    return "coalesce((" + predicate + "),false())"


def preview(body):
    from . import sigma_rules

    if (
        not isinstance(body, dict)
        or set(body) - {"rule", "field_mapping", "logsource_mapping", "profile"}
        or not {"rule", "field_mapping"} <= set(body)
    ):
        raise ValueError("Expected rule and explicit field_mapping")
    _bounded(body)
    mapping = body["field_mapping"]
    rule = body["rule"]
    if not isinstance(mapping, dict) or not 1 <= len(mapping) <= 32:
        raise ValueError("1..32 explicit field mappings required")
    for field in mapping:
        if not isinstance(field, str) or not sigma_rules.NAME.fullmatch(field):
            raise ValueError("Invalid mapped Sigma field")
        _target(mapping, field)
    if (
        not isinstance(rule, dict)
        or not isinstance(rule.get("title"), str)
        or not 1 <= len(rule["title"]) <= 120
    ):
        raise ValueError("Bounded Sigma title required")
    allowed = {
        "title",
        "name",
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
        "license",
    }
    if set(rule) - allowed:
        raise ValueError(
            "Unsupported Sigma document; correlation documents require an explicit correlation policy"
        )
    detection = rule.get("detection")
    if not isinstance(detection, dict) or not 2 <= len(detection) <= 17:
        raise ValueError("1..16 named selections required")
    for name, selection in detection.items():
        if name == "condition":
            continue
        if (
            not isinstance(name, str)
            or not sigma_rules.NAME.fullmatch(name)
            or name.lower() == "timeframe"
        ):
            raise ValueError("Unsupported detection selection")
        alternatives = selection if isinstance(selection, list) else [selection]
        for alternative in alternatives:
            if not isinstance(alternative, dict) or not alternative:
                raise ValueError("Selections require scalar field maps")
            for key, value in alternative.items():
                if not isinstance(key, str):
                    raise ValueError("Field name required")  # noqa: TRY004 - API validation uses HTTP 400.
                parts = key.split("|")
                _target(mapping, parts[0])
                if set(parts[1:]) - MODIFIERS:
                    raise ValueError("Unsupported Sigma modifier")
                if "re" in parts and (not isinstance(value, str) or len(value) > 512):
                    raise ValueError("Regex requires <=512 characters")
    logsource = rule.get("logsource", {})
    if (
        not isinstance(logsource, dict)
        or set(logsource) - {"category", "product", "service"}
        or any(
            not isinstance(v, str) or not 1 <= len(v) <= 80 for v in logsource.values()
        )
    ):
        raise ValueError("Typed category/product/service logsource required")
    scopes = body.get("logsource_mapping", {})
    if not isinstance(scopes, dict) or set(scopes) != set(logsource):
        raise ValueError("Every logsource criterion requires an explicit mapping")
    source_leaves = []
    for value in scopes.values():
        if not isinstance(value, dict) or set(value) != {"field", "value"}:
            raise ValueError("Explicit logsource field/value required")
        source_leaves.append(
            sigma_rules._leaf(
                "source_scope", value["value"], {"source_scope": value["field"]}
            )
        )
    try:
        from sigma import conditions as c
        from sigma import types as t
        from sigma.rule import SigmaRule
    except ImportError:
        raise ValueError(
            "pySigma runtime unavailable; install sigma-analysis extra"
        ) from None
    from sigma.exceptions import SigmaError

    try:
        parsed = SigmaRule.from_dict(rule)
    except (SigmaError, ValueError, TypeError) as exc:
        raise ValueError("pySigma rejected rule: " + str(exc)[:400]) from None
    visited = 0

    def visit(node, depth=0):
        nonlocal visited
        visited += 1
        if depth > 20 or visited > 512:
            raise ValueError("Sigma normalized AST exceeds budget")
        if isinstance(node, (c.ConditionAND, c.ConditionOR)):
            return (
                "("
                + (" AND " if isinstance(node, c.ConditionAND) else " OR ").join(
                    visit(x, depth + 1) for x in node.args
                )
                + ")"
            )
        if isinstance(node, c.ConditionNOT):
            return "(NOT " + visit(node.args[0], depth + 1) + ")"
        if not isinstance(node, c.ConditionFieldEqualsValueExpression):
            raise ValueError("Unsupported non-field Sigma AST node")  # noqa: TRY004 - API validation uses HTTP 400.
        target = _target(mapping, node.field)
        value = node.value
        if isinstance(value, t.SigmaExists):
            kind = _kind(target)
            predicate = (
                ("isnotnull(" + kind + ")" if value.exists else "isnull(" + kind + ")")
                if kind
                else ("isnotnull(" if value.exists else "isnull(") + target + ")"
            )
            return predicate
        if isinstance(value, t.SigmaNull):
            return "isnull(" + target + ")"
        if isinstance(value, t.SigmaFieldReference):
            if value.starts_with or value.ends_with:
                raise ValueError("Modified field references are unsupported")
            other = _target(mapping, value.field)
            kinds = [_kind(target), _kind(other)]
            if not all(kinds):
                raise ValueError(
                    "Field references require two typed raw JSON scalar fields"
                )
            numeric = lambda k: (
                "("
                + " OR ".join(
                    k + "=" + json.dumps(t) for t in ("BIGINT", "UBIGINT", "DOUBLE")
                )
                + ")"
            )
            text = (
                "("
                + kinds[0]
                + '="VARCHAR" AND '
                + kinds[1]
                + '="VARCHAR" AND lower('
                + target
                + ")=lower("
                + other
                + "))"
            )
            numbers = (
                "("
                + numeric(kinds[0])
                + " AND "
                + numeric(kinds[1])
                + " AND tonumber("
                + target
                + ")=tonumber("
                + other
                + "))"
            )
            boolean = (
                "("
                + kinds[0]
                + '="BOOLEAN" AND '
                + kinds[1]
                + '="BOOLEAN" AND lower('
                + target
                + ")=lower("
                + other
                + "))"
            )
            return (
                "coalesce((" + text + " OR " + numbers + " OR " + boolean + "),false())"
            )
        if isinstance(value, t.SigmaRegularExpression):
            flags = "".join(sorted(value.sigma_to_re_flag[x] for x in value.flags))
            pattern = ("(?" + flags + ")" if flags else "") + str(value.regexp)
            return _typed(
                target,
                "match(" + target + "," + json.dumps(pattern, ensure_ascii=False) + ")",
                ["VARCHAR"],
            )
        if isinstance(value, t.SigmaString):
            pieces = []
            for part in value.s:
                if part == t.SpecialChars.WILDCARD_MULTI:
                    pieces.append(".*")
                elif part == t.SpecialChars.WILDCARD_SINGLE:
                    pieces.append(".")
                elif isinstance(part, str):
                    pieces.append(re.escape(part))
                else:
                    raise ValueError("Unsupported expanded string token")
            cased = type(value).__name__ == "SigmaCasedString"
            pattern = ("" if cased else "(?i)") + "^" + "".join(pieces) + "$"
            return _typed(
                target,
                "match(" + target + "," + json.dumps(pattern, ensure_ascii=False) + ")",
                ["VARCHAR"],
            )
        if isinstance(value, t.SigmaBool):
            return _typed(
                target,
                "lower("
                + target
                + ")="
                + json.dumps("true" if value.to_plain() else "false"),
                ["BOOLEAN"],
            )
        if isinstance(value, (t.SigmaNumber, t.SigmaCompareExpression)):
            number = (
                value.number
                if isinstance(value, t.SigmaNumber)
                else value.number.number
            )
            if (
                type(number) not in (int, float)
                or not math.isfinite(number)
                or abs(number) > 1e100
            ):
                raise ValueError("Finite numeric Sigma value required")
            operation = (
                "="
                if isinstance(value, t.SigmaNumber)
                else {"GT": ">", "GTE": ">=", "LT": "<", "LTE": "<="}.get(value.op.name)
            )
            if operation is None:
                raise ValueError("Unsupported numeric comparison")
            return _typed(
                target,
                "tonumber(" + target + ")" + operation + str(number),
                ["BIGINT", "UBIGINT", "DOUBLE"],
            )
        raise ValueError("Unsupported typed Sigma value: " + type(value).__name__)

    conditions = parsed.detection.parsed_condition
    if not 1 <= len(conditions) <= 8:
        raise ValueError("1..8 Sigma conditions required")
    predicate = (
        "(" + " OR ".join(visit(condition.parsed) for condition in conditions) + ")"
    )
    if source_leaves:
        predicate = "(" + " AND ".join([*source_leaves, predicate]) + ")"
    query = "search * | where " + predicate
    Query.parse({"language": "spl", "query": query}).compile(
        "validation", allowed_indexes=[]
    )
    return {
        "title": rule["title"],
        "query": {"language": "spl", "query": query},
        "query_only": True,
        "profile": PROFILE,
        "logsource": logsource,
        "field_mapping": dict(mapping),
        "logsource_mapping": scopes,
        "upstream": status(),
        "semantic_ir": {"version": 3, "predicate": predicate, "nodes": visited},
        "semantics": "pySigma typed AST; scalar JSON string matching case-insensitive unless cased; raw exists tests key presence including explicit null; raw numeric/bool matching preserves JSON types",
        "limitations": [
            "Explicit source and field mappings required",
            "Source arrays are not searched as scalar values",
            "No aggregation/correlation documents or unsupported modifier fallback",
            "RE2-compatible bounded regex only",
            "Preview is not a published or approved detection policy",
        ],
    }


def native_preview(body):
    """Convert the same validated typed AST into a native Boolean condition tree.

    The SPL preview is retained for inspection, but is never parsed to construct
    a policy. Unsupported scalar casts are rejected rather than changing meaning.
    """
    result = preview(body)
    from sigma import conditions as c
    from sigma import types as t
    from sigma.rule import SigmaRule

    from . import native_predicates
    from .query import ALIASES

    mapping = body["field_mapping"]
    parsed = SigmaRule.from_dict(body["rule"])

    def target(field):
        value = _target(mapping, field)
        value = ALIASES.get(value, value)
        return value if value.startswith("raw.") else "event." + value

    def many(op, nodes):
        return nodes[0] if len(nodes) == 1 else {"op": op, "args": nodes}

    def regex(field, pattern):
        if field in {"event.event_time", "event.received"}:
            raise ValueError(
                "Native string matching requires a string/raw JSON field; numeric envelope casts are unsupported"
            )
        return {"op": "regex", "field": field, "pattern": pattern}

    def visit(node):
        if isinstance(node, (c.ConditionAND, c.ConditionOR)):
            return many(
                "and" if isinstance(node, c.ConditionAND) else "or",
                [visit(item) for item in node.args],
            )
        if isinstance(node, c.ConditionNOT):
            return {"op": "not", "arg": visit(node.args[0])}
        if not isinstance(node, c.ConditionFieldEqualsValueExpression):
            raise ValueError("Unsupported native Sigma AST node")  # noqa: TRY004 - HTTP validation uses ValueError.
        field, value = target(node.field), node.value
        if isinstance(value, t.SigmaExists):
            return {"op": "exists", "field": field, "value": value.exists}
        if isinstance(value, t.SigmaNull):
            return {"op": "is_null", "field": field}
        if isinstance(value, t.SigmaFieldReference):
            return {
                "op": "field_eq",
                "field": field,
                "other": target(value.field),
                "case_sensitive": False,
            }
        if isinstance(value, t.SigmaRegularExpression):
            flags = "".join(
                sorted(value.sigma_to_re_flag[item] for item in value.flags)
            )
            return regex(
                field, ("(?" + flags + ")" if flags else "") + str(value.regexp)
            )
        if isinstance(value, t.SigmaString):
            pieces = []
            for part in value.s:
                if part == t.SpecialChars.WILDCARD_MULTI:
                    pieces.append(".*")
                elif part == t.SpecialChars.WILDCARD_SINGLE:
                    pieces.append(".")
                elif isinstance(part, str):
                    pieces.append(re.escape(part))
                else:
                    raise ValueError("Unsupported native Sigma string token")
            return regex(
                field,
                ("" if type(value).__name__ == "SigmaCasedString" else "(?i)")
                + "^"
                + "".join(pieces)
                + "$",
            )
        if isinstance(value, t.SigmaBool):
            if not field.startswith("raw."):
                raise ValueError(
                    "Boolean Sigma values require an explicitly typed raw JSON field"
                )
            return {"op": "eq", "field": field, "value": value.to_plain()}
        if isinstance(value, (t.SigmaNumber, t.SigmaCompareExpression)):
            if not field.startswith("raw.") and field not in {
                "event.event_time",
                "event.received",
            }:
                raise ValueError(
                    "Numeric Sigma values cannot cast a string envelope field"
                )
            number = (
                value.number
                if isinstance(value, t.SigmaNumber)
                else value.number.number
            )
            op = (
                "eq"
                if isinstance(value, t.SigmaNumber)
                else {"GT": "gt", "GTE": "gte", "LT": "lt", "LTE": "lte"}[value.op.name]
            )
            return {"op": op, "field": field, "value": number}
        raise ValueError("Unsupported native Sigma scalar type")

    nodes = []
    for value in body.get("logsource_mapping", {}).values():
        name = ALIASES.get(value["field"], value["field"])
        field = name if name.startswith("raw.") else "event." + name
        wanted = value["value"]
        if (
            not isinstance(wanted, str)
            and not field.startswith("raw.")
            and field not in {"event.event_time", "event.received"}
        ):
            raise ValueError(
                "Numeric logsource mapping cannot cast a string envelope field"
            )
        nodes.append(
            regex(field, "(?i)^" + re.escape(wanted) + "$")
            if isinstance(wanted, str)
            else {"op": "eq", "field": field, "value": wanted}
        )
    nodes.append(
        many(
            "or",
            [
                visit(condition.parsed)
                for condition in parsed.detection.parsed_condition
            ],
        )
    )
    tree = native_predicates.validate({"version": 1, "root": many("and", nodes)})
    return {**result, "native_condition_tree": tree, "native_ir_version": 1}
