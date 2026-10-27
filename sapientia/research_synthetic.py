"""Seeded labelled laboratory corpus. Labels never enter admitted event fields."""

import random

from .research_behavior_graph import digest


def generate(scenario_count=1200,seed=20261016):
    if type(scenario_count) is not int or not 1000<=scenario_count<=1400:raise ValueError("1000..1400 synthetic scenarios required")
    if type(seed) is not int or not 0<=seed<2**31:raise ValueError("Bounded integer seed required")
    rng=random.Random(seed);events=[];scenarios=[];training=min(256,scenario_count//5);validation=min(64,scenario_count//20)
    tools={"training":("editor.exe","browser.exe","service.exe","python.exe"),"validation":("notepad.exe","chrome.exe","svchost.exe","pypy.exe"),"test":("nano","firefox.exe","systemd","python3.exe")}
    normal_actions=("file_read","network_connect","file_write","process_create")
    for i in range(scenario_count):
        split="training" if i<training else "validation" if i<training+validation else "test"
        local=i if split=="training" else i-training if split=="validation" else i-training-validation
        attack=split=="test" and local%2==1;variant=(local//2)%4;role=0 if attack else local%4
        count=4 if split!="test" else 12
        # Separate reported-time epochs; scenarios on distinct hosts may overlap.
        start={"training":1500000000,"validation":1600000000,"test":1700000000}[split]+local*1000
        ids=[];times=[];device=f"synthetic-{seed}-{split}-{local}";process=f"incarnation-{local}"
        cadence=rng.choice((1,2,3));profile=rng.choice(("standard","team","offline","backup","review","scheduled","interactive","local"))
        extension=rng.choice((".txt",".docx",".pdf",".csv"));attack_gap=rng.randint(500,8000);long_gap=rng.randint(30000,50000)
        for j in range(count):
            action=("file_read" if j%2==0 else "file_write") if role==0 else normal_actions[role]
            at=start+j*cadence;image="C:/Apps/"+tools[split][role]
            file_path="C:/Docs/workload"+extension if role==0 else "" if role==1 else "C:/Service/state.conf" if role==2 else "C:/Tasks/job.py"
            command=tools[split][role]+(" https://internal/" if role==1 else " --daily-task" if role>=2 else " workload"+extension)+" --profile "+profile
            dest="10.2.3.4" if role==1 else "";port=443 if role==1 else 0
            if attack and variant==0 and j==count-1:action="network_connect" # relation mismatch
            if attack and variant==1 and j==count-1:at+=attack_gap # same semantic relation, new cadence
            if attack and variant==2:action="file_read" # unchanged feature semantics, altered long-run action ratio
            if attack and variant==3:
                at=start+j*long_gap;action="file_read"
            if not attack and split=="test":
                at=start+j*7200 # sparse normal coverage across 22 hours
            incarnation=f"{process}-{j}" if (not attack and split=="test") or (attack and variant in {0,2,3}) else process
            eid=f"synthetic-{seed}-{i}-{j}";ids.append(eid);times.append(at)
            raw={"device_uid":device,"boot_id":"synthetic-boot","process_guid":incarnation,"process_start_identity":"start-"+incarnation,
                "image":image,"command_line":command,"action":action,"file_path":file_path,"file_sha256":digest([seed,i,j,"safe-text-fixture"]),"dest_ip":dest,"dest_port":port,
                "xdr":{"data":{"host":{"id":device,"boot_id":"synthetic-boot"},"process":{"guid":incarnation,"start_identity":"start-"+incarnation,"executable":image,"command_line":command},"file":{"path":file_path}}}}
            events.append({"event_id":eid,"event_time":at,"index":"public","host":device,"raw":raw})
        scenarios.append({"id":f"scenario-{seed}-{i}","split":split,"family":f"{split}-"+(f"attack-mechanism-{variant}" if attack else f"benign-tool-{role}"),"campaign":f"{split}-campaign-{local%13}","label":"attack" if attack else "normal","event_ids":ids,"observation_seconds":max(1,max(times)-min(times))})
    return {"name":f"CPU multihorizon synthetic {seed}/{scenario_count}","origin":"synthetic","description":"Seeded safe text-only laboratory telemetry; distinct host/tool-family/campaign/time split. Test attack mechanisms are withheld. Roles and benign semantics overlap by design and are audited. No real endpoint capture or actual field performance claim.","scenarios":scenarios},events


def build(store,who,data):
    from . import connector_runtime, principal, research_evaluation, source_registry
    if not isinstance(data,dict) or set(data)!={"scenario_count","seed"}:raise ValueError("Synthetic build requires scenario_count/seed")
    with principal.transaction(store,who,("admin",)) as (_,actor):pass
    manifest,events=generate(data["scenario_count"],data["seed"])
    source=source_registry.save(store,actor,{"index":"public","product":"json","account":f"synthetic-{data['seed']}","realm":"explicit-synthetic-lab","credential_ref":"env:SAPIENTIA_CONNECTOR_RESEARCH_SYNTHETIC","version":0})
    for offset in range(0,len(events),500):
        connector_runtime.intake(store,actor,source["id"],{"version":1,"events":events[offset:offset+500],"cursor":f"synthetic-{data['seed']}-{offset}","checkpoint_version":offset//500})
    while store.flush():pass
    dataset=research_evaluation.save_dataset(store,actor,manifest)
    return {"dataset":dataset,"source":source,"event_count":len(events),"scenario_count":len(manifest["scenarios"]),"corpus_digest":digest({"manifest":manifest,"events":events}),"real_endpoint_commands":0}
