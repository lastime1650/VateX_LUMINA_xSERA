"""Bounded ASA connection/deny decoder with explicit direction and provenance."""

import ipaddress
import math
import re
import time

from ..storage import normalize

PREFIX = re.compile(r"(?:^|\s)%ASA-(?P<severity>[0-7])-(?P<code>\d{6}):\s*(?P<body>.*)\Z")
BUILT = re.compile(r"Built (?P<direction>inbound|outbound) (?P<protocol>TCP|UDP) connection (?P<session>\d+) for (?P<if1>[A-Za-z0-9_.-]+):(?P<ip1>[0-9a-fA-F:.]+)/(?P<port1>\d+) \((?P<nat1>[0-9a-fA-F:.]+)/(?P<natport1>\d+)\) to (?P<if2>[A-Za-z0-9_.-]+):(?P<ip2>[0-9a-fA-F:.]+)/(?P<port2>\d+) \((?P<nat2>[0-9a-fA-F:.]+)/(?P<natport2>\d+)\)(?: .*)?\Z")
DENY = re.compile(r"Deny (?P<protocol>tcp|udp) src (?P<src_if>[A-Za-z0-9_.-]+):(?P<src_ip>[0-9a-fA-F:.]+)/(?P<src_port>\d+) dst (?P<dest_if>[A-Za-z0-9_.-]+):(?P<dest_ip>[0-9a-fA-F:.]+)/(?P<dest_port>\d+)(?: .*)?\Z")
MAPPING = "cisco-asa-connection-v1"


def ip(value):
    address = ipaddress.ip_address(value)
    if address.is_unspecified:
        raise ValueError("Unspecified ASA endpoint is not an identity")
    return str(address)


def port(value):
    value = int(value)
    if not 1 <= value <= 65535:
        raise ValueError("ASA port outside supported range")
    return value


def envelope(item, index, device):
    if not isinstance(item, dict) or set(item) != {"id", "log", "event_time"} or not isinstance(item["log"], str) or not 1 <= len(item["log"]) <= 32768:
        raise ValueError("ASA requires id,log,event_time")
    if type(item["event_time"]) not in (int, float) or not math.isfinite(item["event_time"]) or not 0 <= item["event_time"] <= time.time() + 86400:
        raise ValueError("Finite ASA source timestamp required")
    match = PREFIX.search(item["log"])
    if not match:
        raise ValueError("ASA message prefix required")
    code, body = match["code"], match["body"]
    parsed = {"message_id": code, "device": device}
    if code in {"302013", "302015"}:
        fields = BUILT.fullmatch(body)
        if not fields or (code == "302013" and fields["protocol"] != "TCP") or (code == "302015" and fields["protocol"] != "UDP"):
            raise ValueError("Unsupported ASA connection grammar")
        first, second = (2, 1) if fields["direction"] == "outbound" else (1, 2)
        security = {"src_ip": ip(fields[f"ip{first}"]), "src_port": port(fields[f"port{first}"]),
                    "dest_ip": ip(fields[f"ip{second}"]), "dest_port": port(fields[f"port{second}"]),
                    "action": "network_connection", "outcome": "observed", "protocol": fields["protocol"].lower(),
                    "session_id": fields["session"]}
        parsed.update(fields.groupdict())
        parsed["direction"] = fields["direction"]
        for i in (1, 2):
            ip(fields[f"nat{i}"])
            port(fields[f"natport{i}"])
    elif code == "106023":
        fields = DENY.fullmatch(body)
        if not fields:
            raise ValueError("Unsupported ASA deny grammar")
        security = {"src_ip": ip(fields["src_ip"]), "src_port": port(fields["src_port"]),
                    "dest_ip": ip(fields["dest_ip"]), "dest_port": port(fields["dest_port"]),
                    "action": "network_connection", "outcome": "blocked", "protocol": fields["protocol"]}
        parsed.update(fields.groupdict())
    else:
        raise ValueError("ASA message ID not qualified by this parser")
    security.update(schema="sapientia-security", version=1, mapping=MAPPING,
                    provenance={k: ["raw.cisco_asa"] for k in security})
    return normalize({"event_id": item["id"], "event_time": item["event_time"], "index": index,
                      "source": "cisco_asa", "sourcetype": "cisco:asa", "host": device,
                      "severity": "medium" if int(match["severity"]) <= 4 else "info",
                      "message": item["log"], "raw": {"cisco_asa": parsed, "security": security}})
