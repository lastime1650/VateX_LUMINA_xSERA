"""CloudTrail 1.x bounded record decoder, without AWS retrieval/integrity claims.

Recipient account is an admission authority. Caller account and STS session issuer
remain separate reported identities, including legitimate cross-account calls.
Large records exceeding Store's current 64 KiB envelope fail rather than truncate.
"""

import copy
import datetime
import ipaddress
import re

from ..storage import encode, normalize


def field(record, name, pattern):
    value = record.get(name)
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise ValueError("Invalid CloudTrail " + name)
    return value


def envelope(record, index, recipient):
    if not isinstance(record, dict) or len(encode(record).encode("utf-8")) > 65536:
        raise ValueError("Bounded individual CloudTrail record required")
    field(record, "eventVersion", r"1\.[0-9]{1,3}")
    event_id = field(record, "eventID", r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
    account = field(record, "recipientAccountId", r"[0-9]{12}")
    if account != recipient:
        raise PermissionError("CloudTrail recipient differs from registered authority")
    service = field(record, "eventSource", r"[A-Za-z0-9_.-]{1,128}")
    action = field(record, "eventName", r"[A-Za-z0-9_.:-]{1,128}")
    region = field(record, "awsRegion", r"[a-z0-9-]{1,64}")
    timestamp = field(record, "eventTime", r"[0-9T:.+Z-]{1,64}")
    try:
        parsed = datetime.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() != datetime.timedelta(0):
            raise ValueError
        event_time = parsed.timestamp()
    except (ValueError, OverflowError):
        raise ValueError("UTC CloudTrail eventTime required") from None
    identity = record.get("userIdentity")
    if not isinstance(identity, dict) or not isinstance(identity.get("type"), str) or not 1 <= len(identity["type"]) <= 64:
        raise ValueError("Explicit CloudTrail caller identity required")
    sec = {"action": action, "outcome": "failure" if record.get("errorCode") else "observed"}
    caller = identity.get("arn") or identity.get("principalId")
    if isinstance(caller, str) and 1 <= len(caller) <= 1024:
        sec["user"] = caller
    try:
        address = ipaddress.ip_address(record.get("sourceIPAddress"))
        if not address.is_unspecified:
            sec["src_ip"] = str(address)
    except (ValueError, TypeError):
        pass  # AWS service/internal names are reported strings, not guessed IPs.
    raw = {"cloudtrail": copy.deepcopy(record), "security": sec}
    return normalize({"event_id": "cloudtrail:"+account+":"+event_id.lower(), "event_time": event_time,
                      "index": index, "source": "cloudtrail", "sourcetype": "aws:cloudtrail",
                      "host": account+":"+region, "severity": "info",
                      "message": service+" "+action, "raw": raw})
