"""Third-party HTTP adapters preserve source records and bind tenant to the key."""

import json
import math


def hec(payload):
    values = payload if isinstance(payload, list) else [payload]
    if not 1 <= len(values) <= 1000:
        raise ValueError("HEC batch requires 1..1000 events")
    records = []
    for value in values:
        if (
            not isinstance(value, dict)
            or "event" not in value
            or set(value)
            - {"event", "time", "host", "source", "sourcetype", "index", "fields"}
        ):
            raise ValueError("Invalid HEC event envelope")
        fields = value.get("fields", {})
        if not isinstance(fields, dict):
            raise ValueError("HEC fields must be an object")
        source = value["event"]
        record = {
            "source": value.get("source", "hec"),
            "sourcetype": value.get("sourcetype", "hec:json"),
            "host": value.get("host", "unknown"),
            "index": value.get("index", "main"),
            "message": source
            if isinstance(source, str)
            else json.dumps(source, ensure_ascii=False, separators=(",", ":")),
            "raw": {"event": source, "fields": fields},
        }
        if "time" in value:
            timestamp = value["time"]
            if isinstance(timestamp, bool):
                raise ValueError("HEC time must be epoch seconds")
            try:
                timestamp = float(timestamp)
            except (TypeError, ValueError):
                raise ValueError("HEC time must be epoch seconds")
            if not math.isfinite(timestamp):
                raise ValueError("HEC time must be finite")
            record["event_time"] = timestamp
        if "vatex_event_id" in fields:
            record["event_id"] = fields["vatex_event_id"]
        records.append(record)
    return records


def otlp_value(value, depth=0):
    if depth > 12:
        raise ValueError("OTLP AnyValue nesting exceeds 12")
    if not isinstance(value, dict) or len(value) != 1:
        raise ValueError("Invalid OTLP AnyValue")
    kind, item = next(iter(value.items()))
    if kind in {"stringValue", "bytesValue"}:
        if not isinstance(item, str):
            raise ValueError("OTLP string/bytes value must be a string")
        if kind == "bytesValue":
            import base64
            import binascii

            try:
                base64.b64decode(item, validate=True)
            except (ValueError, binascii.Error):
                raise ValueError("Invalid OTLP base64 bytes")
        return item
    if kind == "boolValue":
        if type(item) is not bool:
            raise ValueError("OTLP boolean value required")
        return item
    if kind in {"intValue", "doubleValue"}:
        if isinstance(item, bool) or not isinstance(item, (str, int, float)):
            raise ValueError("Invalid OTLP numeric value")
        try:
            result = int(item) if kind == "intValue" else float(item)
        except (ValueError, TypeError, OverflowError):
            raise ValueError("Invalid OTLP numeric value")
        if (kind == "intValue" and not -(2**63) <= result < 2**63) or (
            kind == "doubleValue" and not math.isfinite(result)
        ):
            raise ValueError("OTLP numeric value out of range")
        return result
    if kind == "arrayValue":
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("values", []), list)
            or len(item.get("values", [])) > 128
        ):
            raise ValueError("Invalid OTLP array value")
        return [otlp_value(v, depth + 1) for v in item.get("values", [])]
    if kind == "kvlistValue":
        if not isinstance(item, dict):
            raise ValueError("Invalid OTLP key-value list")
        return attributes(item.get("values", []), depth + 1)
    raise ValueError("Unknown OTLP AnyValue type")


def attributes(values, depth=0):
    if not isinstance(values, list) or len(values) > 128:
        raise ValueError("OTLP attribute budget exceeded")
    result = {}
    for value in values:
        if (
            not isinstance(value, dict)
            or set(value) != {"key", "value"}
            or not isinstance(value["key"], str)
        ):
            raise ValueError("Invalid OTLP attribute")
        if not 1 <= len(value["key"]) <= 256 or value["key"] in result:
            raise ValueError("OTLP attribute key must be unique and 1..256 characters")
        result[value["key"]] = otlp_value(value["value"], depth)
    return result


def otlp(payload):
    if not isinstance(payload, dict) or set(payload) != {"resourceLogs"}:
        raise ValueError("OTLP JSON requires resourceLogs")
    if (
        not isinstance(payload["resourceLogs"], list)
        or len(payload["resourceLogs"]) > 1000
    ):
        raise ValueError("OTLP resourceLogs must be a bounded list")
    records = []
    for resource in payload["resourceLogs"]:
        if (
            not isinstance(resource, dict)
            or not isinstance(resource.get("resource", {}), dict)
            or not isinstance(resource.get("scopeLogs", []), list)
        ):
            raise ValueError("Invalid OTLP resource log")
        metadata = attributes(resource.get("resource", {}).get("attributes", []))
        for scope in resource.get("scopeLogs", []):
            if (
                not isinstance(scope, dict)
                or not isinstance(scope.get("scope", {}), dict)
                or not isinstance(scope.get("logRecords", []), list)
            ):
                raise ValueError("Invalid OTLP scope log")
            for log in scope.get("logRecords", []):
                if not isinstance(log, dict):
                    raise ValueError("Invalid OTLP log record")
                details = attributes(log.get("attributes", []))
                try:
                    level = int(log.get("severityNumber", 0))
                    nanos = int(log.get("timeUnixNano", "0"))
                except (ValueError, TypeError, OverflowError):
                    raise ValueError("Invalid OTLP severityNumber/timeUnixNano")
                if (
                    isinstance(log.get("severityNumber"), bool)
                    or isinstance(log.get("timeUnixNano"), bool)
                    or not 0 <= nanos < 2**64
                ):
                    raise ValueError("Invalid OTLP severityNumber/timeUnixNano")
                if not 0 <= level <= 24:
                    raise ValueError("OTLP severityNumber must be 0..24")
                value = otlp_value(log.get("body", {"stringValue": ""}))
                record = {
                    "source": str(metadata.get("service.name", "otlp")),
                    "sourcetype": "otlp:json",
                    "host": str(metadata.get("host.name", "unknown")),
                    "severity": "critical"
                    if level >= 21
                    else "high"
                    if level >= 17
                    else "medium"
                    if level >= 13
                    else "info"
                    if level >= 9
                    else "debug",
                    "message": value
                    if isinstance(value, str)
                    else json.dumps(value, ensure_ascii=False, separators=(",", ":")),
                    "raw": {
                        "resource": metadata,
                        "attributes": details,
                        "scope": scope.get("scope", {}),
                        "record": log,
                    },
                }
                if nanos:
                    record["event_time"] = nanos / 1e9
                if "vatex.event_id" in details:
                    record["event_id"] = str(details["vatex.event_id"])
                records.append(record)
                if len(records) > 1000:
                    raise ValueError("OTLP batch exceeds 1000 records")
    if not records:
        raise ValueError("OTLP batch is empty")
    return records
