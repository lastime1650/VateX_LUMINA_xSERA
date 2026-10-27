"""Run synthetic, non-persistent searches against installed Splunk and LUMINA."""

import base64
import json
import os
from pathlib import Path
import re
import ssl
import tempfile
import time
import urllib.parse
import urllib.request

from sapientia.spl import COMMANDS
from sapientia.storage import Store, Settings


CASES = [
    "| makeresults count=6 | streamstats count AS n | sort - n | table n",
    "| makeresults count=6 | streamstats count AS n | sort limit=3 - num(n) | table n",
    "| makeresults count=6 | streamstats count AS n | eval k=n%2 | sort - k, +n | table k,n",
    "| makeresults count=6 | streamstats count AS n | sort n desc | table n",
    "| makeresults count=6 | streamstats count AS n | table n",
    "| makeresults count=6 | streamstats count AS n | eval bytes=n*10 | stats count AS n,sum(bytes) AS total,avg(bytes) AS average",
    '| makeresults count=6 | streamstats count AS n | eval severity=if(n<=3,"high","low") | stats count by severity | sort severity',
    "| makeresults count=6 | streamstats count AS n | eval doubled=tonumber(n)*2 | where doubled>=8 | table n,doubled",
    "| makeresults count=6 | streamstats count AS n | head 2 | stats count",
    "| makeresults count=6 | streamstats count AS n | sort 0 -n | head 3 | table n",
    "| makeresults count=6 | streamstats count AS n | streamstats window=2 sum(n) AS rolling | table n,rolling",
    '| makeresults count=6 | streamstats count AS n | eval group=if(n<=3,"A","B") | eventstats count AS peers by group | table n,group,peers',
    '| makeresults count=6 | streamstats count AS n | eval group=if(n<=3,"A","B") | dedup group | table group',
    '| makeresults count=6 | streamstats count AS n | eval tag=upper("vatex") | rename tag AS product | table n,product',
    '| makeresults count=3 | streamstats count AS n | eval x=case(n=1,"one",n=2,"two",true(),"other") | table n,x',
    "| makeresults count=6 | streamstats count AS n | stats count(eval(n>3)) AS high,dc(n) AS distinct,median(n) AS middle",
    "| makeresults count=3 | streamstats count AS n | eval x=round(pow(n,2),0) | table n,x",
    '| makeresults count=3 | streamstats count AS n | eval line="src=10.0.0.1" | rex field=line "src=(?<src>[0-9.]+)" | table n,src',
    '| makeresults count=3 | streamstats count AS n | eval missing=null() | fillnull value="unknown" missing | table n,missing',
    "| makeresults count=6 | streamstats count AS n | reverse | table n",
    "| makeresults count=6 | streamstats count AS n | tail 2 | table n",
]


def canonical(value):
    if isinstance(value, dict):
        return {k: canonical(v) for k, v in value.items() if not k.startswith("__")}
    if isinstance(value, list):
        return [canonical(v) for v in value]
    if isinstance(value, str):
        if re.fullmatch(r"-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?", value):
            return round(float(value), 6)
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return round(float(value), 6)
    return value


def splunk_search(query):
    # Trust the installed local Splunk CA. Hostname differs from the loopback
    # address; chain validation remains required against that explicit CA.
    context = ssl.create_default_context(
        cafile=r"C:\Program Files\Splunk\etc\auth\cacert.pem"
    )
    context.check_hostname = False
    credentials = (
        os.environ["SAPIENTIA_REFERENCE_USER"]
        + ":"
        + os.environ["SAPIENTIA_REFERENCE_PASSWORD"]
    ).encode()
    request = urllib.request.Request(
        "https://127.0.0.1:8089/services/search/jobs/export",
        data=urllib.parse.urlencode(
            {"search": query, "output_mode": "json", "preview": "false"}
        ).encode(),
        headers={"Authorization": "Basic " + base64.b64encode(credentials).decode()},
    )
    with urllib.request.urlopen(request, context=context, timeout=30) as response:
        messages = [
            json.loads(line)
            for line in response.read().decode().splitlines()
            if line.strip()
        ]
    errors = [
        m
        for m in messages
        if "messages" in m and any(x.get("type") == "ERROR" for x in m["messages"])
    ]
    if errors:
        raise RuntimeError(json.dumps(errors))
    return [
        m["result"] for m in messages if "result" in m and not m.get("preview", False)
    ]


def main():
    report = {
        "reference": "Installed Splunk Enterprise 10.0.0",
        "kind": "synthetic-query differential",
        "time": time.time(),
        "cases": [],
        "full_spl_compatible": False,
    }
    with tempfile.TemporaryDirectory(prefix="sapientia-spl-conformance-") as directory:
        store = Store(Settings(Path(directory), min_free_bytes=0))
        try:
            for query in CASES:
                case = {"query": query}
                try:
                    reference = splunk_search(query)
                    actual = store.search("default", {"query": query, "limit": 1000})[
                        "rows"
                    ]
                    case.update(
                        reference=reference,
                        actual=actual,
                        passed=canonical(reference) == canonical(actual),
                    )
                except Exception as exc:
                    case.update(
                        passed=False, error=type(exc).__name__ + ": " + str(exc)
                    )
                report["cases"].append(case)
                print(("PASS " if case["passed"] else "FAIL ") + query, flush=True)
        finally:
            store.close()
    bnf = Path(r"C:\Program Files\Splunk\etc\system\default\searchbnf.conf").read_text(
        encoding="utf-8"
    )
    reference_commands = sorted(
        set(re.findall(r"(?m)^\[([A-Za-z0-9_]+)-command\]", bnf))
    )
    report["command_inventory"] = {
        "reference_total": len(reference_commands),
        "implemented_command_names": sorted(COMMANDS),
        "not_implemented": sorted(set(reference_commands) - COMMANDS),
        "note": "Command-name coverage is not semantic or option compatibility",
    }
    report["passed"] = sum(c["passed"] for c in report["cases"])
    report["total"] = len(report["cases"])
    Path("reports/spl-differential.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(
        json.dumps({k: report[k] for k in ("passed", "total", "full_spl_compatible")})
    )
    raise SystemExit(0 if report["passed"] == report["total"] else 1)


if __name__ == "__main__":
    main()
