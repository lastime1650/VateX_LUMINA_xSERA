"""Isolated, offline YARA source compilation and immutable-byte scanning.

Invoked with Python -I. No sample is executed and no include/module can be
loaded from submitted rule text. The parent owns wall time and input budgets.
"""

import base64
import json
import re
import sys


def execute(request):
    try:
        import yara
    except ImportError:
        return {
            "status": "unavailable",
            "matches": [],
            "error": "yara-python runtime unavailable",
        }
    sources = request.get("sources")
    if (
        not isinstance(sources, dict)
        or not 1 <= len(sources) <= 4096
        or sum(len(s.encode("utf-8")) for s in sources.values() if isinstance(s, str))
        > 16 * 1024 * 1024
    ):
        raise ValueError("Bounded source namespaces required")
    for namespace, source in sources.items():
        if (
            not isinstance(namespace, str)
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", namespace)
            or not isinstance(source, str)
            or not 1 <= len(source.encode("utf-8")) <= 32768
            or re.search(r"\b(?:include|import)\b", source)
            or any(ord(c) < 32 and c not in "\n\r\t" for c in source)
        ):
            raise ValueError(
                "YARA includes, imports and invalid source bytes are disabled"
            )
    try:
        rules = yara.compile(sources=sources, includes=False, error_on_warning=True)
    except yara.Error as exc:
        return {
            "status": "failed",
            "matches": [],
            "error": str(exc)[:1000],
            "phase": "compile",
        }
    count = sum(1 for _ in rules)
    if request.get("operation") == "validate":
        return {
            "status": "completed",
            "matches": [],
            "rule_count": count,
            "version": yara.__version__,
        }
    if request.get("operation") != "scan":
        raise ValueError("Unsupported YARA worker operation")
    body = base64.b64decode(request["body"], validate=True)
    if len(body) > 32 * 1024 * 1024:
        raise ValueError("Sample exceeds the immutable-byte scan budget")
    try:
        matched = rules.match(data=body, timeout=5)
    except yara.TimeoutError:
        return {
            "status": "timeout",
            "matches": [],
            "phase": "scan",
            "rule_count": count,
        }
    except yara.Error as exc:
        return {
            "status": "failed",
            "matches": [],
            "phase": "scan",
            "error": str(exc)[:1000],
            "rule_count": count,
        }
    return {
        "status": "completed",
        "matches": [
            {
                "namespace": item.namespace,
                "rule": item.rule,
                "tags": list(item.tags)[:32],
                "author": item.meta.get("author", ""),
                "license": item.meta.get("license", ""),
                "source_url": item.meta.get("reference", item.meta.get("source", "")),
                "license_url": item.meta.get("license_url", ""),
            }
            for item in matched[:256]
        ],
        "match_count": len(matched),
        "matches_truncated": len(matched) > 256,
        "rule_count": count,
        "version": yara.__version__,
    }


if __name__ == "__main__":
    try:
        result = execute(json.load(sys.stdin))
    except Exception as exc:  # noqa: BLE001 -- the isolated worker always emits a bounded failure receipt.
        result = {"status": "failed", "matches": [], "error": str(exc)[:1000]}
    print(json.dumps(result, ensure_ascii=True))
