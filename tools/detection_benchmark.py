"""Frozen-detector accuracy accounting through the actual xSERA Case pipeline.

The bundled public synthetic corpus is a qualification baseline, not independent
zero-day certification. The runner never executes payload commands or submits
telemetry to a server. It requires a new, explicit data directory and retains it
for review. Ground-truth labels never enter the detector's event payload.
"""

import argparse
import copy
import hashlib
import json
import math
import platform
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sapientia import auth, detections, rule_templates, xdr_bridge
from sapientia.storage import Settings, Store, encode

DEFAULT_CORPUS = ROOT / "tests" / "fixtures" / "detection_accuracy_v1.json"
DEFAULT_TEMPLATES = [
    "R-WIN-001",
    "R-WIN-002",
    "R-WIN-003",
    "R-LNX-001",
    "R-LNX-002",
    "R-LNX-003",
]
MAX_CASES = 1000
MAX_EVENTS = 10000


def digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


def source_snapshot():
    names = [
        *[
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "sapientia").rglob("*.py")
        ],
        "tools/detection_benchmark.py",
        *["sapientia/catalogs/" + name for name in rule_templates.PACKS],
        "sapientia/catalogs/provenance.json",
    ]
    result = {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in sorted(names)
    }
    return {"files": result, "aggregate_sha256": digest(result)}


def proportion(successes, denominator):
    """Wilson 95% binomial interval, explicitly undefined for no observations."""
    if (
        type(successes) is not int
        or type(denominator) is not int
        or not 0 <= successes <= denominator
    ):
        raise ValueError("Metric requires integer counts 0 <= successes <= denominator")
    if not denominator:
        return {
            "numerator": successes,
            "denominator": 0,
            "value": None,
            "wilson_95_interval": None,
        }
    z = 1.959963984540054
    p = successes / denominator
    scale = 1 + z * z / denominator
    center = (p + z * z / (2 * denominator)) / scale
    radius = (
        z * math.sqrt(p * (1 - p) / denominator + z * z / (4 * denominator**2)) / scale
    )
    return {
        "numerator": successes,
        "denominator": denominator,
        "value": p,
        "wilson_95_interval": [max(0.0, center - radius), min(1.0, center + radius)],
    }


def metrics(rows, *, actual_unique_cases_created=None):
    counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for row in rows:
        if (
            row["label"] not in {"malicious", "benign"}
            or type(row["detected"]) is not bool
        ):
            raise ValueError(
                "Metrics require exact binary ground truth and detection flags"
            )
        key = (
            ("tp" if row["detected"] else "fn")
            if row["label"] == "malicious"
            else ("fp" if row["detected"] else "tn")
        )
        counts[key] += 1
    if actual_unique_cases_created is not None and (
        type(actual_unique_cases_created) is not int or actual_unique_cases_created < 0
    ):
        raise ValueError("Persisted unique Case count requires a nonnegative integer")
    attack_rows = [row for row in rows if row["label"] == "malicious"]
    attributed = sum(row.get("case_count", 0) for row in rows)
    attack_attributed = sum(row.get("case_count", 0) for row in attack_rows)
    identified = all("case_ids" in row for row in rows)
    unique_cases = (
        len({identifier for row in rows for identifier in row.get("case_ids", [])})
        if identified
        else None
    )
    attack_unique_cases = (
        len(
            {
                identifier
                for row in attack_rows
                for identifier in row.get("case_ids", [])
            }
        )
        if all("case_ids" in row for row in attack_rows)
        else None
    )
    return {
        "opportunity_unit": "one labeled scenario attributed by original event identity; explicit host_group may share a synthetic host",
        "count": len(rows),
        **counts,
        "precision": proportion(counts["tp"], counts["tp"] + counts["fp"]),
        "recall": proportion(counts["tp"], counts["tp"] + counts["fn"]),
        "false_positive_rate": proportion(counts["fp"], counts["fp"] + counts["tn"]),
        "specificity": proportion(counts["tn"], counts["fp"] + counts["tn"]),
        "case_count": actual_unique_cases_created
        if actual_unique_cases_created is not None
        else unique_cases,
        "actual_unique_cases_created": actual_unique_cases_created,
        "case_attribution_count": attributed,
        "legacy_case_attribution_count": attributed,
        "case_count_scope": "all persisted distinct Case rows in the offline test store"
        if actual_unique_cases_created is not None
        else "distinct Case IDs attributed to these opportunities"
        if identified
        else "unknown: input rows have no Case identities",
        "attack_case_fragmentation": {
            "attacks": len(attack_rows),
            "case_count": attack_unique_cases,
            "case_attribution_count": attack_attributed,
            "legacy_case_attribution_count": attack_attributed,
            "mean_cases_per_attack": attack_attributed / len(attack_rows)
            if attack_rows
            else None,
            "meaning": "Each attack-to-Case attribution contributes to the mean; shared Cases count once in case_count",
        },
        "interpretation": "Finite supplied scenarios; no enterprise endpoint-day denominator or independent zero-day claim.",
    }


def load_corpus(path):
    body = Path(path).read_bytes()
    if len(body) > 2 * 1024 * 1024:
        raise ValueError("Corpus exceeds 2 MiB")
    data = json.loads(body)
    encode(data)  # Reject NaN/infinity anywhere before creating any test state.
    if (
        not isinstance(data, dict)
        or set(data) != {"schema", "id", "provenance", "cases"}
        or data["schema"] != "xsera.detection-corpus.v1"
    ):
        raise ValueError("Unsupported corpus schema")
    if not isinstance(data["provenance"], dict) or not isinstance(data["id"], str):
        raise ValueError("Corpus provenance and ID are required")  # noqa: TRY004 - CLI input validation uses ValueError.
    cases = data["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError("Corpus requires 1..1000 labeled scenarios")
    identifiers, total = set(), 0
    for row in cases:
        required = {
            "id",
            "split",
            "label",
            "sensor_mode",
            "twin_group",
            "description",
            "techniques",
            "events",
        }
        if (
            not isinstance(row, dict)
            or not required <= set(row)
            or set(row) - required - {"host_group"}
        ):
            raise ValueError("Scenario requires exact metadata and events fields")
        for key in ("id", "sensor_mode", "twin_group", "description"):
            if not isinstance(row[key], str) or not 1 <= len(row[key]) <= 2000:
                raise ValueError("Scenario metadata must be bounded nonempty strings")
        if (
            row["id"] in identifiers
            or row["split"] not in {"calibration", "holdout"}
            or row["label"] not in {"malicious", "benign"}
        ):
            raise ValueError("Duplicate scenario or invalid split/ground-truth label")
        identifiers.add(row["id"])
        if "host_group" in row and (
            not isinstance(row["host_group"], str)
            or not 1 <= len(row["host_group"]) <= 128
        ):
            raise ValueError("Optional host_group must be a bounded opaque identifier")
        if not isinstance(row["techniques"], list) or any(
            not isinstance(tag, str) for tag in row["techniques"]
        ):
            raise ValueError("Techniques must be an explicit list")
        events = row["events"]
        if not isinstance(events, list) or not 1 <= len(events) <= 100:
            raise ValueError("Each scenario requires 1..100 bounded event envelopes")
        for event in events:
            if (
                not isinstance(event, dict)
                or set(event) != {"offset_seconds", "data"}
                or type(event["offset_seconds"]) not in {int, float}
                or not math.isfinite(event["offset_seconds"])
                or not -600 <= event["offset_seconds"] <= 0
                or not isinstance(event["data"], dict)
            ):
                raise ValueError(
                    "Event requires offset -600..0 and a typed data object"
                )
            if _ground_truth_keys(event["data"]):
                raise ValueError("Ground-truth metadata must not enter telemetry")
        total += len(events)
    if total > MAX_EVENTS:
        raise ValueError("Corpus exceeds 10000 events")
    return data, hashlib.sha256(body).hexdigest()


def _ground_truth_keys(value):
    if isinstance(value, dict):
        return bool(
            {"ground_truth", "label", "split", "twin_group", "benchmark"} & set(value)
        ) or any(_ground_truth_keys(item) for item in value.values())
    return isinstance(value, list) and any(_ground_truth_keys(item) for item in value)


def freeze_detectors(templates=None, policies_path=None):
    if templates and policies_path:
        raise ValueError("Choose templates or a frozen policy file")
    if policies_path:
        body = Path(policies_path).read_bytes()
        if len(body) > 1024 * 1024:
            raise ValueError("Detector file exceeds 1 MiB")
        raw = json.loads(body)
        if (
            not isinstance(raw, dict)
            or set(raw) != {"schema", "policies"}
            or raw["schema"] != "xsera.benchmark-detectors.v1"
        ):
            raise ValueError("Unsupported frozen detector schema")
        rows = raw["policies"]
    else:
        identifiers = templates or DEFAULT_TEMPLATES
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("Duplicate detector template ID")
        rows = []
        for identifier in identifiers:
            detail = rule_templates.detail(identifier)
            if not detail["supported"]:
                raise ValueError("Unsupported detector template: " + identifier)
            rows.append(
                {
                    "id": identifier,
                    "definition": rule_templates._policy(
                        detail["original"], "benchmark"
                    ),
                }
            )
    if not isinstance(rows, list) or not 1 <= len(rows) <= 20:
        raise ValueError("Benchmark requires 1..20 frozen detectors")
    result = []
    for row in rows:
        if (
            not isinstance(row, dict)
            or set(row) != {"id", "definition"}
            or not isinstance(row["id"], str)
        ):
            raise ValueError("Each frozen detector requires id and definition")
        definition = detections.validate(copy.deepcopy(row["definition"]))
        definition["enabled"] = True  # Only in this newly created offline test store.
        for step in definition["steps"]:
            for condition in [
                *step["filters"],
                *[f for group in step.get("exclusions", []) for f in group],
            ]:
                if condition["field"] == "event_id" or any(
                    part in condition["field"].split(".")
                    for part in (
                        "ground_truth",
                        "benchmark",
                        "label",
                        "split",
                        "twin_group",
                    )
                ):
                    raise ValueError(
                        "A benchmark detector cannot filter ground-truth metadata or fixture event IDs"
                    )
        result.append({"id": row["id"], "definition": definition})
    if len({row["id"] for row in result}) != len(result):
        raise ValueError("Duplicate frozen detector ID")
    return result


def run_benchmark(
    corpus_path, data_root, *, templates=None, policies_path=None, expected_freeze=None
):
    """Measure actual detection/Case outcomes; labels never tune or enter rules."""
    before = source_snapshot()
    detectors = freeze_detectors(templates, policies_path)
    frozen = {
        "sources": before,
        "detectors": detectors,
        "detector_sha256": digest(detectors),
    }
    if expected_freeze is not None and frozen != expected_freeze:
        raise ValueError(
            "Detector/code snapshot differs from the supplied pre-evaluation freeze"
        )
    # Read labels only after definitions and code hashes are frozen in memory.
    corpus, corpus_hash = load_corpus(corpus_path)
    destination = Path(data_root).resolve()
    if destination.exists():
        raise ValueError(
            "Benchmark data-root must be a new explicit directory; existing data is never reused"
        )
    destination.mkdir(parents=True, exist_ok=False)
    (destination / ".qa-synthetic-only").write_text(
        "synthetic-only\n", encoding="utf-8"
    )
    (destination / "detector-freeze.json").write_text(
        json.dumps(frozen, indent=2), encoding="utf-8"
    )
    store = Store(Settings(destination, min_free_bytes=0, workers=2))
    actor = {
        "name": "benchmark-operator",
        "tenant": "benchmark",
        "role": "admin",
        "allowed_indexes": ["*"],
    }
    auth.create_user(
        store,
        actor["name"],
        "Synthetic-only-accuracy-benchmark-2026!",
        "admin",
        actor["tenant"],
    )
    base = time.time() - 5
    event_count, outcomes, errors = 0, [], []
    source_owners = {}
    policy_ids = {}
    started = time.perf_counter()
    try:
        for number, scenario in enumerate(corpus["cases"]):
            host = "benchmark-host-" + (
                hashlib.sha256(scenario["host_group"].encode()).hexdigest()[:20]
                if "host_group" in scenario
                else str(number).zfill(5)
            )
            envelopes = []
            for position, frame in enumerate(scenario["events"]):
                data = copy.deepcopy(frame["data"])
                data.setdefault("host", {})["id"] = host
                data["@timestamp"] = datetime.fromtimestamp(
                    base + frame["offset_seconds"], UTC
                ).isoformat()
                envelopes.append(
                    {
                        "id": hashlib.sha256(
                            f"{number}:{position}".encode()
                        ).hexdigest(),
                        "data": data,
                    }
                )
            try:
                for envelope in envelopes:
                    normalized = xdr_bridge.parse_event(envelope, "agent", "benchmark")
                    source_owners[normalized["event_id"]] = number
                xdr_bridge.intake(
                    store,
                    actor,
                    {"format": "agent", "index": "benchmark", "events": envelopes},
                )
                event_count += len(envelopes)
                error = None
            except (ValueError, PermissionError) as exc:
                error = type(exc).__name__ + ": " + str(exc)
                errors.append(
                    {"scenario_id": scenario["id"], "stage": "intake", "error": error}
                )
            outcomes.append(
                {key: value for key, value in scenario.items() if key != "events"}
                | {
                    "host": host,
                    "intake_error": error,
                    "case_count": 0,
                    "detected": False,
                    "matched_detector_ids": [],
                    "reported_techniques": [],
                    "case_ids": [],
                }
            )
        while store.flush():
            pass
        for detector in detectors:
            policy_id = detections.save(store, actor, detector["definition"])
            policy_ids[policy_id] = detector["id"]
        completed = detections.run_due(store, time.time() + 1, budget=30)
        with store.control() as db:
            policies = [
                dict(row)
                for row in db.execute(
                    "SELECT id,error,failures FROM correlation_policies ORDER BY id"
                )
            ]
            cases = [
                dict(row)
                for row in db.execute(
                    "SELECT id,entity,entity_field FROM incidents WHERE tenant=?",
                    (actor["tenant"],),
                )
            ]
            contributions = [
                dict(row)
                for row in db.execute(
                    "SELECT incident_id,policy_id,evidence FROM risk_contributions WHERE tenant=?",
                    (actor["tenant"],),
                )
            ]
            actual_case_count = db.execute(
                "SELECT count(*) FROM incidents WHERE tenant=?", (actor["tenant"],)
            ).fetchone()[0]
        case_contributions = {}
        case_hosts = {}
        for case in cases:
            if case["entity_field"] != "host" or case["entity"] not in {
                row["host"] for row in outcomes
            }:
                errors.append(
                    {
                        "stage": "case-attribution",
                        "error": "Case did not bind a ground-truth host",
                    }
                )
                continue
            case_hosts[case["id"]] = case["entity"]
        for contribution in contributions:
            host = case_hosts.get(contribution["incident_id"])
            if host is None:
                continue
            evidence = json.loads(contribution["evidence"])
            owners = {
                source_owners[identifier]
                for identifier in evidence.get("event_ids", [])
                if identifier in source_owners
            }
            if not owners:
                errors.append(
                    {
                        "stage": "evidence-attribution",
                        "error": "Case evidence has no original corpus event identity",
                    }
                )
            case_contributions.setdefault(contribution["incident_id"], set()).update(
                owners
            )
            for owner in owners:
                target = outcomes[owner]
                target["case_ids"].append(contribution["incident_id"])
                target["matched_detector_ids"].append(
                    policy_ids[contribution["policy_id"]]
                )
                target["reported_techniques"].extend(evidence.get("mitre", []))
        for row in outcomes:
            row["case_ids"] = sorted(set(row["case_ids"]))
            row["case_count"] = len(row["case_ids"])
            row["detected"] = row["case_count"] > 0
            row["matched_detector_ids"] = sorted(set(row["matched_detector_ids"]))
            row["reported_techniques"] = sorted(set(row["reported_techniques"]))
            row["expected_technique_detected"] = sorted(
                set(row["techniques"]) & set(row["reported_techniques"])
            )
        for policy in policies:
            if policy["error"]:
                errors.append(
                    {
                        "stage": "detector",
                        "detector_id": policy_ids[policy["id"]],
                        "error": policy["error"],
                    }
                )
        after = source_snapshot()
        integrity = not errors and before == after and completed == len(detectors)
        groups = {}
        for key in ("split", "sensor_mode"):
            groups[key] = {
                value: metrics([row for row in outcomes if row[key] == value])
                for value in sorted({row[key] for row in outcomes})
            }
        report = {
            "schema": "xsera.detection-accuracy-report.v1",
            "created_utc": datetime.now(UTC).isoformat(),
            "corpus_id": corpus["id"],
            "corpus_sha256": corpus_hash,
            "corpus_provenance": corpus["provenance"],
            "detector_freeze": frozen,
            "source_after": after,
            "source_unchanged": before == after,
            "harness_integrity_passed": integrity,
            "completed_detectors": completed,
            "event_count": event_count,
            "scenario_count": len(outcomes),
            "metrics": metrics(outcomes, actual_unique_cases_created=actual_case_count),
            "actual_unique_cases_created": actual_case_count,
            "case_count_source": "SELECT count(*) FROM incidents WHERE tenant='benchmark' in the newly created offline store",
            "strata": groups,
            "outcomes": outcomes,
            "errors": errors,
            "cross_scenario_cases": [
                {
                    "case_id": case_id,
                    "scenario_ids": sorted(outcomes[number]["id"] for number in owners),
                    "meaning": "One Case contains evidence from separate labeled scenarios; assess intended episode grouping.",
                }
                for case_id, owners in sorted(case_contributions.items())
                if len(owners) > 1
            ],
            "wall_seconds": time.perf_counter() - started,
            "execution": {
                "python": platform.python_version(),
                "platform": platform.platform(),
                "server_started": False,
                "sample_commands_executed": False,
                "native_sensor_exercised": False,
                "data_root": str(destination),
            },
            "limits": [
                "The bundled corpus is public synthetic qualification, not an independent hidden holdout.",
                "Declared sensor modes represent event-schema strata; this offline runner does not exercise native collection.",
                "Malicious labels are supplied evaluation truth, not payload fields or conclusions inferred from Resolved status.",
                "No unseen malware family, novel vulnerability, sustained endpoint-day cohort or same-condition commercial comparator is measured.",
                "Non-perfect observed detection precision/recall is reported, not silently converted to a passing accuracy claim.",
            ],
        }
        return report
    finally:
        store.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--data-root", type=Path)
    parser.add_argument("--template", action="append", dest="templates")
    parser.add_argument("--policies", type=Path)
    parser.add_argument("--freeze", type=Path)
    parser.add_argument("--write-freeze", type=Path)
    args = parser.parse_args(argv)
    if args.write_freeze:
        if args.freeze or args.output or args.data_root or args.write_freeze.exists():
            parser.error(
                "write-freeze requires a new snapshot path and no evaluation/output/data-root flags"
            )
        before = source_snapshot()
        definitions = freeze_detectors(args.templates, args.policies)
        if source_snapshot() != before:
            raise ValueError("Detector sources changed while creating the freeze")
        snapshot = {
            "sources": before,
            "detectors": definitions,
            "detector_sha256": digest(definitions),
        }
        args.write_freeze.parent.mkdir(parents=True, exist_ok=True)
        args.write_freeze.write_text(
            json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(
            json.dumps(
                {
                    "freeze_path": str(args.write_freeze.resolve()),
                    "detector_sha256": snapshot["detector_sha256"],
                    "corpus_read": False,
                }
            )
        )
        return 0
    if not args.output or not args.data_root:
        parser.error("evaluation requires output and a new explicit data-root")
    expected = (
        json.loads(args.freeze.read_text(encoding="utf-8")) if args.freeze else None
    )
    report = run_benchmark(
        args.corpus,
        args.data_root,
        templates=args.templates,
        policies_path=args.policies,
        expected_freeze=expected,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False),
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "harness_integrity_passed": report["harness_integrity_passed"],
                "metrics": report["metrics"],
                "output": str(args.output.resolve()),
            },
            ensure_ascii=False,
        )
    )
    return 0 if report["harness_integrity_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
