"""Frozen-source, complete-collection regression receipts in fresh owned folders.

Never enumerates system Temp, uses production data, removes files or reuses a
pytest basetemp. All tests are collected; failures, skips, deselections and source
changes prevent certification. Source hashes and actual pytest PID/phase IDs
are recorded independently of the launcher.
"""

import argparse
import collections
import concurrent.futures
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

PLUGIN = r'''
import json,os,sys,time
from pathlib import Path
ROOT=Path(os.environ['XSERA_QA_RECEIPT_ROOT'])
PID=os.getpid
PPID=os.getppid
REPORTS=[]
DESELECTED=[]
def save(name,value):
    (ROOT/name).write_text(json.dumps(value,ensure_ascii=True,indent=2)+'\n',encoding='utf-8')
def pytest_sessionstart(session):
    save('actual-process.json',{'pid':PID(),'parent_pid':PPID(),'python':sys.executable,'argv':sys.argv,'cwd':str(Path.cwd()),'started':time.time()})
def pytest_collection_finish(session):
    save('collected.json',[item.nodeid for item in session.items])
def pytest_deselected(items):
    DESELECTED.extend(item.nodeid for item in items)
def pytest_runtest_logreport(report):
    REPORTS.append({'id':report.nodeid,'when':report.when,'outcome':report.outcome,'wasxfail':getattr(report,'wasxfail',None),'duration':report.duration,'pid':PID(),'parent_pid':PPID()})
def pytest_sessionfinish(session,exitstatus):
    save('phase-reports.json',REPORTS)
    save('deselected.json',DESELECTED)
    save('session-finish.json',{'pid':PID(),'parent_pid':PPID(),'exitstatus':int(exitstatus),'finished':time.time(),'sapientia_source':getattr(sys.modules.get('sapientia'),'__file__',None)})
'''


def dump(path, data):
    path.write_text(json.dumps(data, ensure_ascii=True, indent=2)+"\n",encoding="utf-8")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources(root):
    command=["git","-c","core.quotepath=false","ls-files","-z","--cached","--others","--exclude-standard"]
    names=subprocess.check_output(command,cwd=root).decode("utf-8").split("\0")
    result={}
    for name in sorted(set(filter(None,names))):
        p=root/name
        if not p.resolve().is_relative_to(root.resolve()):
            raise ValueError("Source manifest path escapes checkout")
        if p.is_file():
            result[name]=sha(p)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root",type=Path,required=True)
    parser.add_argument("--work-root",type=Path,required=True)
    parser.add_argument("--parts",type=int,default=4)
    parser.add_argument("--workers",type=int,default=2)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    task=root.parent.parent
    output=args.output_root.resolve();work=args.work_root.resolve()
    if not output.is_relative_to(task/"outputs") or not work.is_relative_to(task/"work"):
        raise ValueError("Regression folders must stay within this task outputs/work")
    if output.exists() or work.exists():
        raise ValueError("Use fresh output/work folders; existing folders are never deleted")
    if not 1<=args.parts<=16 or not 1<=args.workers<=4:
        raise ValueError("Use 1..16 parts and 1..4 workers")
    output.mkdir(parents=True);work.mkdir(parents=True)
    (work/".qa-synthetic-only").write_text("synthetic-only\n",encoding="utf-8")
    plugin=output/"xsera_strict_receipts.py";plugin.write_text(PLUGIN,encoding="utf-8")
    before=sources(root);dump(output/"source-before.json",before)
    runtime_paths = {"python_launcher": Path(sys.executable), "nats_server": root/"vendor/nats/nats-server.exe"}
    runtime_before = {name: {"path": str(path), "sha256": sha(path)} for name, path in runtime_paths.items() if path.is_file()}
    dump(output/"runtime-before.json", runtime_before)
    environment={**os.environ,"PYTHONIOENCODING":"utf-8","PYTHONUTF8":"1",
                 "PYTHONPATH":str(output)+os.pathsep+str(root)}
    # Do not inherit selectors/plugin injection that can silently redefine the
    # denominator before collection. The configured tests directory is explicit.
    removed = [key for key in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS") if key in environment]
    for key in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS"):
        environment.pop(key, None)
    dump(output/"collection-scope.json", {"test_root": str(root/"tests"),
         "config": str(root/"pyproject.toml"), "removed_environment_names": removed,
         "selection": "all tests, explicit root, no inherited pytest selectors"})
    collection=output/"collection";collection.mkdir()
    collect_env={**environment,"XSERA_QA_RECEIPT_ROOT":str(collection)}
    with (collection/"collection.log").open("wb") as log:
        collected_run=subprocess.run([sys.executable,"-m","pytest","tests","-c","pyproject.toml","--collect-only","-q","-p","xsera_strict_receipts"],cwd=root,env=collect_env,stdout=log,stderr=subprocess.STDOUT,check=False)
    if collected_run.returncode or not (collection/"collected.json").is_file():
        dump(output/"summary.json",{"passed":False,"stage":"collection","exit_code":collected_run.returncode})
        raise SystemExit(1)
    expected=json.loads((collection/"collected.json").read_text())
    if len(expected)!=len(set(expected)):
        raise ValueError("Duplicate collection node IDs")
    modules=sorted({node.split("::",1)[0] for node in expected})
    # Greedy balance by collected count, not a partial -k selection.
    counts=collections.Counter(node.split("::",1)[0] for node in expected)
    groups=[[] for _ in range(args.parts)];loads=[0]*args.parts
    for module in sorted(modules,key=lambda x:(-counts[x],x)):
        position=min(range(args.parts),key=loads.__getitem__)
        groups[position].append(module);loads[position]+=counts[module]
    started=time.time()
    dump(output/"progress.json",{"started_utc":datetime.now(UTC).isoformat(),"expected_tests":len(expected),"modules":len(modules),"loads":loads,"completed":[]})

    def run_part(number, group):
        receipt=output/f"part-{number}";receipt.mkdir()
        basetemp=work/f"part-{number}"
        if basetemp.exists():
            raise ValueError("Refusing pytest's implicit deletion of existing basetemp")
        command=[sys.executable,"-m","pytest",*sorted(group),"-c","pyproject.toml","-q","-p","xsera_strict_receipts",
                 "--basetemp="+str(basetemp),"--junitxml="+str(receipt/"results.xml")]
        dump(receipt/"invocation.json",{"argv":command,"launcher_pid":os.getpid(),"modules":sorted(group),"expected_count":sum(counts[m] for m in group)})
        env={**environment,"XSERA_QA_RECEIPT_ROOT":str(receipt)}
        begin=time.time()
        with (receipt/"pytest.log").open("wb") as log:
            process=subprocess.Popen(command,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT)
            dump(receipt/"launcher-child.json",{"child_pid":process.pid,"parent_pid":os.getpid()})
            exit_code=process.wait()
        reports=json.loads((receipt/"phase-reports.json").read_text()) if (receipt/"phase-reports.json").exists() else []
        ids=json.loads((receipt/"collected.json").read_text()) if (receipt/"collected.json").exists() else []
        actual=json.loads((receipt/"actual-process.json").read_text()) if (receipt/"actual-process.json").exists() else {}
        finish=json.loads((receipt/"session-finish.json").read_text()) if (receipt/"session-finish.json").exists() else {}
        call_ids=[r["id"] for r in reports if r["when"]=="call"]
        bad=[r for r in reports if r["outcome"]!="passed" or r["wasxfail"]]
        deselected=json.loads((receipt/"deselected.json").read_text()) if (receipt/"deselected.json").exists() else ["missing_session_finish"]
        # Windows venv python.exe is a launcher whose child runs pytest. Bind
        # that child to this exact launcher rather than assuming equal PIDs.
        same_process = actual.get("pid")==finish.get("pid") and actual.get("parent_pid")==finish.get("parent_pid") and (
            actual.get("pid")==process.pid and actual.get("parent_pid")==os.getpid()
            or os.name=="nt" and actual.get("parent_pid")==process.pid
        ) and all(r["pid"]==actual.get("pid") and r["parent_pid"]==actual.get("parent_pid") for r in reports)
        summary={"part":number,"exit_code":exit_code,"duration_seconds":round(time.time()-begin,3),"collected_count":len(ids),"executed_count":len(call_ids),"nonpassing_phases":bad,"deselected":deselected,"collection_execution_equal":sorted(ids)==sorted(call_ids),"same_process_proven":same_process,"actual_source_root":actual.get("cwd"),"imported_source":finish.get("sapientia_source"),"collected":ids,"executed":call_ids}
        summary["passed"]=not exit_code and not bad and not deselected and summary["collection_execution_equal"] and summary["same_process_proven"] and actual.get("cwd")==str(root) and Path(finish.get("sapientia_source") or "").resolve()==(root/"sapientia/__init__.py").resolve()
        dump(receipt/"summary.json",summary)
        return summary

    completed=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures=[pool.submit(run_part,i+1,g) for i,g in enumerate(groups) if g]
        for future in concurrent.futures.as_completed(futures):
            completed.append(future.result())
            dump(output/"progress.json",{"expected_tests":len(expected),"completed":[{k:r[k] for k in ("part","passed","collected_count","executed_count","duration_seconds")} for r in completed],"elapsed_seconds":round(time.time()-started,3)})
    after=sources(root);dump(output/"source-after.json",after)
    runtime_after = {name: {"path": str(path), "sha256": sha(path)} for name, path in runtime_paths.items() if path.is_file()}
    dump(output/"runtime-after.json", runtime_after)
    changed=sorted(k for k in before.keys()|after.keys() if before.get(k)!=after.get(k))
    all_collected=[node for r in completed for node in r["collected"]]
    all_executed=[node for r in completed for node in r["executed"]]
    equal=sorted(expected)==sorted(all_collected)==sorted(all_executed)
    summary={"schema":"xsera.frozen.strict.regression.v1","completed_utc":datetime.now(UTC).isoformat(),"source_file_count":len(before),"changed_source_paths":changed,"source_unchanged":not changed,"expected_tests":len(expected),"executed_tests":len(all_executed),"module_count":len(modules),"global_collection_execution_equal":equal,"no_duplicate_execution":len(all_executed)==len(set(all_executed)),"parts":[{k:v for k,v in r.items() if k not in {"collected","executed"}} for r in sorted(completed,key=lambda r:r["part"])],"plugin_sha256":sha(plugin),"script_sha256":sha(Path(__file__).resolve()),"duration_seconds":round(time.time()-started,3),"scope":"Unit/integration regression, not commercial accuracy or novel exploit certification"}
    summary["runtime_inputs_unchanged"] = runtime_before == runtime_after
    summary["passed"]=not changed and equal and summary["runtime_inputs_unchanged"] and summary["no_duplicate_execution"] and all(r["passed"] for r in completed)
    dump(output/"summary.json",summary)
    print(json.dumps({k:v for k,v in summary.items() if k!="parts"},ensure_ascii=True),flush=True)
    raise SystemExit(0 if summary["passed"] else 1)


if __name__=="__main__":
    main()
