"""Small acyclic workflow graph and literal, typed conditions; no expressions."""

import re

IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


def condition(value):
    if (
        not isinstance(value, dict)
        or set(value) != {"all"}
        or not isinstance(value["all"], list)
        or not 1 <= len(value["all"]) <= 8
    ):
        raise ValueError("Condition requires 1..8 literal all predicates")
    for item in value["all"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"step", "field", "op", "value"}
            or not IDENTIFIER.fullmatch(str(item["step"]))
        ):
            raise ValueError("Condition requires step,field,op,value")
        if not isinstance(item["field"], str) or not isinstance(item["op"], str):
            raise ValueError("Condition field and operator must be text")  # noqa: TRY004 -- Malformed JSON is HTTP 400.
        if item["field"] not in {
            "success",
            "executed",
            "code",
            "type",
            "data.quarantine_id",
            "data.artifact_id",
            "data.isolation_id",
            "data.bytes",
        } or item["op"] not in {"eq", "ne"}:
            raise ValueError("Unsupported condition field or operator")
        if item["value"] is not None and type(item["value"]) not in {str, bool, int}:
            raise ValueError("Condition requires a bounded scalar")
        if isinstance(item["value"], str) and len(item["value"]) > 256:
            raise ValueError("Condition value exceeds bound")
    return value


def order(steps):
    names = {step["id"] for step in steps}
    for i, step in enumerate(steps):
        dependencies = step.get("depends_on", [] if i == 0 else [steps[i - 1]["id"]])
        if (
            not isinstance(dependencies, list)
            or len(dependencies) > 16
            or any(not isinstance(item, str) for item in dependencies)
            or len(set(dependencies)) != len(dependencies)
            or any(
                not isinstance(item, str) or item not in names or item == step["id"]
                for item in dependencies
            )
        ):
            raise ValueError("Dependencies require unique existing nonself step IDs")
        step["depends_on"] = dependencies
        target = step.get("action", {}).get("action", {})
        for key in ("quarantine_id", "isolation_id"):
            if (
                isinstance(target.get(key), dict)
                and target[key].get("from_step") not in dependencies
            ):
                raise ValueError("Typed receipt source must be a direct dependency")
        if "when" in step:
            condition(step["when"])
            if any(item["step"] not in dependencies for item in step["when"]["all"]):
                raise ValueError("Condition source must be a direct dependency")
    result, remaining = [], list(steps)
    while remaining:
        ready = next(
            (
                step
                for step in remaining
                if set(step["depends_on"]) <= {item["id"] for item in result}
            ),
            None,
        )
        if ready is None:
            raise ValueError("Workflow dependency cycle is forbidden")
        result.append(ready)
        remaining.remove(ready)
    return result


def matches(when, results):
    if when is None:
        return True
    for item in when["all"]:
        actual = results.get(item["step"], {})
        for part in item["field"].split("."):
            if not isinstance(actual, dict) or part not in actual:
                return False  # Missing/skipped output cannot satisfy even a negative condition.
            actual = actual[part]
        # bool and int are different JSON scalar types, including True versus 1.
        equal = type(actual) is type(item["value"]) and actual == item["value"]
        if (item["op"] == "eq" and not equal) or (item["op"] == "ne" and equal):
            return False
    return True
