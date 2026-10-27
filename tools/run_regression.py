"""Full collected pytest suite in isolated file groups; preserve every result."""
import argparse
import collections
import json
import os
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",required=True)
    parser.add_argument("--workers",type=int,default=3,choices=(1,2,3,4))
    parser.add_argument("--history",help="Prior complete JUnit XML for duration balancing")
    args=parser.parse_args()
    output=Path(args.output).resolve()
    if output==ROOT or output==ROOT/"data" or (ROOT/"data") in output.parents:
        raise ValueError("Regression output must be an isolated directory")
    output.mkdir(parents=True,exist_ok=True)
    run=Path(tempfile.mkdtemp(prefix="regression-",dir=output))
    collect=subprocess.run([sys.executable,"-m","pytest","--collect-only","-q"],cwd=ROOT,capture_output=True,text=True,encoding="utf-8")
    (run/"collection.txt").write_text(collect.stdout+collect.stderr,encoding="utf-8")
    if collect.returncode:
        raise RuntimeError("Full suite collection failed; see collection.txt")
    counts=collections.Counter(line.split("::",1)[0].replace("\\","/") for line in collect.stdout.splitlines() if line.startswith("tests/") and "::" in line)
    if not counts:
        raise RuntimeError("No collected tests; refusing an empty regression success")
    durations=collections.Counter()
    if args.history:
        history=ET.parse(args.history).getroot()
        for case in history.iter("testcase"):
            name=case.get("classname","").replace(".","/")+".py"
            durations[name]+=max(.01,float(case.get("time","0")))
    costs={name:max(float(count),durations.get(name,0)) for name,count in counts.items()}
    groups=[[] for _ in range(args.workers)]
    weights=[0]*args.workers
    for name,count in sorted(counts.items(),key=lambda i:(-costs[i[0]],i[0])):
        group=min(range(args.workers),key=lambda n:weights[n])
        groups[group].append(name); weights[group]+=costs[name]
    from sapientia import release_manifest
    source=release_manifest.build()
    (run/"source-manifest.json").write_text(json.dumps(source,indent=2),encoding="utf-8")
    began=time.time()
    print(json.dumps({"run":str(run),"collected":sum(counts.values()),"files":len(counts),"groups_estimated_work":weights,"source_digest":source["source_digest"]}),flush=True)
    def execute(n):
        log=run/f"group-{n+1}.log"
        command=[sys.executable,"-m","pytest",*sorted(groups[n]),"-q","-p","tools.regression_observer","--tb=short","--junitxml="+str(run/f"group-{n+1}.xml"),"--basetemp="+str(run/f"temp-{n+1}")]
        with log.open("w",encoding="utf-8") as sink:
            result=subprocess.run(command,cwd=ROOT,stdout=sink,stderr=subprocess.STDOUT,env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1"})
        return {"group":n+1,"exit_code":result.returncode,"expected":sum(counts[f] for f in groups[n]),"log":str(log)}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results=list(pool.map(execute,range(args.workers)))
    merged=ET.Element("testsuites")
    actual=0
    for n in range(args.workers):
        document=ET.parse(run/f"group-{n+1}.xml").getroot()
        suites=list(document) if document.tag=="testsuites" else [document]
        for suite in suites:
            actual+=len(list(suite.iter("testcase")))
            merged.append(suite)
    ET.ElementTree(merged).write(output/"regression.xml",encoding="utf-8",xml_declaration=True)
    unchanged=release_manifest.build()["source_digest"]==source["source_digest"]
    summary={"collected":sum(counts.values()),"reported":actual,"files":len(counts),"complete":actual==sum(counts.values()),"passed":actual==sum(counts.values()) and unchanged and all(r["exit_code"]==0 for r in results),"source_digest":source["source_digest"],"source_unchanged":unchanged,"workers":args.workers,"started":began,"finished":time.time(),"groups":results,"run_directory":str(run)}
    (output/"regression-summary.json").write_text(json.dumps(summary,indent=2),encoding="utf-8")
    print(json.dumps(summary),flush=True)
    return 0 if summary["passed"] else 1


if __name__=="__main__":
    raise SystemExit(main())
