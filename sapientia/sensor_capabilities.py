"""Sensor assertions and qualification remain distinct; never infer lost events."""

import math

STATES = {"ready", "degraded", "error", "unsupported", "unknown"}
COUNTERS = {"selected", "captured", "spooled", "dropped", "reset", "backlog"}


def provider(value):
    if not isinstance(value, dict) or set(value) - {"state", "epoch", "sequence", "counters", "clock", "mode", "coverage"}:
        raise ValueError("Unknown provider health property")
    if value.get("state") not in STATES:
        raise ValueError("Explicit provider state required")
    counts = value.get("counters", {})
    if not isinstance(counts, dict) or set(counts) - COUNTERS or any(type(n) is not int or n < 0 or n > 2**63-1 for n in counts.values()):
        raise ValueError("Nonnegative typed counters required")
    for key in ("epoch", "mode", "coverage"):
        if key in value and (not isinstance(value[key], str) or len(value[key]) > 256):
            raise ValueError("Bounded provider metadata required")
    if "sequence" in value and (type(value["sequence"]) is not int or not 0 <= value["sequence"] < 2**63):
        raise ValueError("Typed provider sequence required")
    clock = value.get("clock")
    if clock is not None:
        if not isinstance(clock, dict) or set(clock) != {"offset_low", "offset_high", "precision"} or any(type(n) not in (int, float) or not math.isfinite(n) for n in clock.values()) or clock["offset_low"] > clock["offset_high"] or clock["precision"] < 0:
            raise ValueError("Measured clock interval required")
    result = dict(value)
    if counts.get("dropped", 0) or counts.get("backlog", 0) or counts.get("reset", 0):
        result["state"] = "degraded" if value["state"] == "ready" else value["state"]
    result.update(assertion_grade="agent_reported", native_capture_proven=False,
                  clock_grade="unknown" if clock is None else "reported_interval")
    return result


def prerequisites(requirements, providers):
    if not isinstance(requirements, list) or len(requirements) > 64 or not isinstance(providers, dict):
        raise ValueError("Bounded prerequisites required")
    missing = []
    for name in requirements:
        if not isinstance(name, str) or not 1 <= len(name) <= 128:
            raise ValueError("Provider name required")
        state = providers.get(name)
        if state is None or provider(state)["state"] != "ready":
            missing.append(name)
    return {"ready": not missing, "missing_or_degraded": sorted(set(missing)), "capture_certified": False}
