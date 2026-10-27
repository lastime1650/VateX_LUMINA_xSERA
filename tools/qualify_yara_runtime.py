"""Offline real optional YARA checks; samples are never executed."""

import argparse
import json
import time
from pathlib import Path

from sapientia import file_verdicts as verdicts


def qualify():
    import yara

    source = 'rule LuminaHarmlessMarker { strings: $a = "LUMINA_HARMLESS_YARA_010" condition: $a }'
    matched = verdicts.yara_scan(source, b"LUMINA_HARMLESS_YARA_010")
    benign = verdicts.yara_scan(source, b"Different harmless bytes")
    malformed = verdicts.yara_scan("rule invalid { condition: }", b"harmless")
    deadline = verdicts.yara_scan(source, b"harmless", timeout=0.01)
    rejected = []
    for forbidden in (
        'include "private.pem"',
        'import "pe"\nrule forbidden { condition: true }',
    ):
        try:
            verdicts.yara_scan(forbidden, b"harmless")
        except ValueError:
            rejected.append(True)
        else:
            rejected.append(False)
    signature = {
        "id": "owned-marker",
        "name": "Harmless qualification marker",
        "kind": "yara",
        "value": source,
        "verdict": "suspicious",
        "source": "Explicit local qualification",
    }
    evaluated = verdicts.evaluate_signatures(b"LUMINA_HARMLESS_YARA_010", [signature])
    assert matched == {"status": "completed", "matches": ["LuminaHarmlessMarker"]}, (
        matched
    )
    assert benign == {"status": "completed", "matches": []}, benign
    assert malformed["status"] == "failed", malformed
    assert deadline["status"] == "timeout", deadline
    assert all(rejected), rejected
    assert evaluated["verdict"] == "suspicious" and not evaluated["sample_executed"], (
        evaluated
    )
    return {
        "passed": True,
        "yara_version": yara.__version__,
        "sample_executed": False,
        "actual_engine": True,
        "checks": {
            "positive": matched,
            "benign": benign,
            "syntax_error": malformed,
            "outer_deadline": deadline,
            "include_and_module_rejected": rejected,
            "managed_verdict": evaluated,
        },
        "finished": time.time(),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = qualify()
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                key: result[key]
                for key in (
                    "passed",
                    "yara_version",
                    "actual_engine",
                    "sample_executed",
                )
            }
        )
    )
