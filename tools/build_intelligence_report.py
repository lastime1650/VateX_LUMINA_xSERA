"""Build a deterministic, offline Korean report from supplied execution evidence.

Usage: python tools/build_intelligence_report.py --evidence result.json
       --junit regression.xml --output report.html
No telemetry generation, private-file inspection or live-service action occurs.
"""

import argparse
import datetime as dt
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

SECRET = re.compile(r"(?:^|[_ -])(password|passphrase|secret|token|credentials?|private[_ -]?key|api[_ -]?key|authorization|cookies?|csrf)(?:$|[_ -])", re.I)
PRIVATE = re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----|(?i:authorization\s*:\s*bearer\s+\S+)")
INLINE_SECRET = re.compile(r"\b(?:password|passphrase|api[_ -]?key|access[_ -]?token|secret)\b[\"']?\s*[:=]\s*[\"']?[^\s,;}\]]+", re.I)


def sanitize(value, counter=None):
    """Remove secret values while preserving all non-secret supplied evidence."""
    counter = [0] if counter is None else counter
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            reference = str(key).lower() == "credential_ref" and isinstance(child, str) and child.startswith("env:")
            # Authorization/credential presence booleans are policy evidence,
            # not secrets. Preserve false/true/null and explicit env references.
            if SECRET.search(str(key)) and not (child is None or isinstance(child, bool) or reference):
                counter[0] += 1
                result[str(key)] = "[민감 정보 제거]"
            else:
                result[str(key)] = sanitize(child, counter)
        return result
    if isinstance(value, list):
        return [sanitize(child, counter) for child in value]
    if isinstance(value, str):
        nested = _decode(value)
        if isinstance(nested, (dict, list)):
            return json.dumps(sanitize(nested, counter), ensure_ascii=False, separators=(",", ":"))
        if PRIVATE.search(value) or INLINE_SECRET.search(value):
            counter[0] += 1
            return "[민감 정보 제거]"
    return value


def _decode(value):
    if isinstance(value, str) and value[:1] in {"[", "{"}:
        try:
            return json.loads(value)
        except ValueError:
            pass
    return value


def record(value):
    if not isinstance(value, dict):
        return {"value": value}
    result = dict(value)
    body = _decode(result.get("body"))
    if isinstance(body, dict):
        result = {**body, **result}
    for key in ("evidence", "event_ids", "parent_signal_ids", "features", "metadata", "analysis", "contributions"):
        if key in result:
            result[key] = _decode(result[key])
    return result


def rows(value):
    value = _decode(value)
    if isinstance(value, list):
        return [record(item) for item in value]
    if isinstance(value, dict):
        for key in ("items", "rows", "results", "events", "signals", "stories", "cases", "models", "runs"):
            if isinstance(value.get(key), list):
                return [record(item) for item in value[key]]
    return []


def junit_summary(path):
    data = Path(path).read_bytes()
    if len(data) > 32 * 1024 * 1024 or re.search(br"<!\s*(?:DOCTYPE|ENTITY)\b", data, re.I):
        raise ValueError("JUnit must be bounded XML without DOCTYPE/entities")
    root = ET.fromstring(data)
    cases = []
    for item in root.iter("testcase"):
        failed, error, skipped = item.find("failure"), item.find("error"), item.find("skipped")
        status = "failed" if failed is not None else "error" if error is not None else "skipped" if skipped is not None else "passed"
        detail = failed if failed is not None else error if error is not None else skipped
        try:
            seconds = float(item.get("time", "0"))
        except ValueError:
            seconds = None
        cases.append({"name": item.get("name", ""), "classname": item.get("classname", ""),
                      "status": status, "seconds": seconds,
                      "message": detail.get("message", "") if detail is not None else "",
                      "detail": (detail.text or "") if detail is not None else ""})
    return {"tests": len(cases), **{name: sum(case["status"] == name for case in cases) for name in ("passed", "failed", "error", "skipped")},
            "testcase_seconds_sum": sum(case["seconds"] or 0 for case in cases), "cases": cases,
            "input_sha256": hashlib.sha256(data).hexdigest(),
            "count_basis": "JUnit testcase records; skipped includes explicitly recorded xfail"}


def _stamp(value):
    if type(value) in (int, float):
        return value
    if isinstance(value, str):
        try:
            value = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            if value.tzinfo is not None:
                return value.timestamp()
        except ValueError:
            pass
    return None


def _device(event):
    direct = event.get("device") or event.get("vendor") or event.get("device_type")
    if direct:
        return str(direct)
    text = " ".join(str(event.get(key, "")) for key in ("source", "sourcetype", "host")).lower()
    for key, name in (("windows", "Windows"), ("linux", "Linux"), ("forti", "FortiGate"), ("cisco", "Cisco")):
        if key in text:
            return name
    return str(event.get("source") or event.get("host") or "분류 미제공")


def _event_ids(value):
    found = set()
    if isinstance(value, dict):
        for key, child in value.items():
            child = _decode(child)
            if key == "event_ids" and isinstance(child, list):
                found.update(item for item in child if isinstance(item, str))
            elif key == "event_id" and isinstance(child, str):
                found.add(child)
            elif isinstance(child, (dict, list)):
                found.update(_event_ids(child))
    elif isinstance(value, list):
        for child in value:
            found.update(_event_ids(child))
    return sorted(found)


def _pick_list(evidence, key):
    alias = "case_details" if key == "cases" else key
    candidate = rows(evidence.get(alias)) or rows(evidence.get(key))
    if candidate:
        return candidate
    for name in ("simulation", "results", "intelligence"):
        container = evidence.get(name, {})
        if isinstance(container, dict) and (rows(container.get(alias)) or rows(container.get(key))):
            return rows(container.get(alias)) or rows(container[key])
    return []


def normalize(evidence, junit):
    simulation = evidence.get("simulation", {})
    simulation = simulation if isinstance(simulation, dict) else {"value": simulation}
    events = rows(simulation.get("timeline")) or rows(evidence.get("timeline")) or _pick_list(evidence, "events")
    timeline = []
    for event in events:
        moment, basis = None, None
        for key in ("sent_at", "sent", "received", "event_time", "at", "timestamp", "elapsed_seconds", "elapsed"):
            moment = _stamp(event.get(key))
            if moment is not None:
                basis = key
                break
        if moment is not None:
            timeline.append({"device": _device(event), "time": moment, "time_basis": basis,
                             "id": event.get("event_id", event.get("id", "")), "record": event})
    signals, stories, cases = (_pick_list(evidence, key) for key in ("signals", "stories", "cases"))
    graph = {"nodes": [], "edges": []}
    nodes, edges = {}, set()

    def node(identifier, kind, label, detail):
        nodes[identifier] = {"id": identifier, "kind": kind, "label": str(label), "detail": detail}

    def edge(source, target, relation):
        if source in nodes and target in nodes:
            edges.add((source, target, relation))

    event_records = {str(event.get("event_id", event.get("id", ""))): event for event in events}
    originals = set(_event_ids(signals)+_event_ids(cases))
    for identifier in sorted(originals):
        node("event:"+identifier, "event", identifier, event_records.get(identifier, {"event_id": identifier, "note": "원본 ID 참조만 제공됨"}))
    for signal in signals:
        identifier = str(signal.get("id", signal.get("signal_id", "")))
        if identifier:
            node("signal:"+identifier, "signal", str(signal.get("kind") or "Signal")+" · "+identifier[:12], signal)
    for story in stories:
        identifier = str(story.get("id", story.get("story_id", "")))
        if identifier:
            node("story:"+identifier, "story", identifier[:16], story)
    for case in cases:
        identifier = str(case.get("id", case.get("incident_id", "")))
        if identifier:
            node("case:"+identifier, "case", str(case.get("title") or case.get("name") or "Case")+" · "+identifier[:12], case)
    for signal in signals:
        identifier = str(signal.get("id", signal.get("signal_id", "")))
        for event_id in _event_ids(signal):
            edge("event:"+event_id, "signal:"+identifier, "원본 근거")
        for parent in signal.get("parent_signal_ids", []) if isinstance(signal.get("parent_signal_ids"), list) else []:
            edge("signal:"+parent, "signal:"+identifier, "부모 신호")
        if signal.get("story_id"):
            edge("signal:"+identifier, "story:"+str(signal["story_id"]), "기록된 Story 연결")
        metadata = signal.get("metadata", {})
        incident = signal.get("incident_id") or (metadata.get("incident_id") if isinstance(metadata, dict) else None)
        if incident:
            edge("signal:"+identifier, "case:"+str(incident), "기록된 Case 연결")
    for case in cases:
        identifier = str(case.get("id", case.get("incident_id", "")))
        for event_id in _event_ids(case):
            edge("event:"+event_id, "case:"+identifier, "Case 원본 근거")
        contributions = rows(case.get("contributions"))
        for contribution in contributions:
            proof = contribution.get("evidence", {})
            analysis = _decode(proof.get("analysis", {})) if isinstance(proof, dict) else {}
            if isinstance(analysis, dict):
                if analysis.get("signal_id"):
                    edge("signal:"+str(analysis["signal_id"]), "case:"+identifier, "Case 기여의 신호 ID")
                if analysis.get("story_id"):
                    edge("story:"+str(analysis["story_id"]), "case:"+identifier, "Case 기여의 Story ID")
    order = {"event": 0, "signal": 1, "story": 2, "case": 3}
    graph["nodes"] = sorted(nodes.values(), key=lambda n: (order[n["kind"]], n["id"]))
    graph["edges"] = [{"from": source, "to": target, "relation": relation} for source, target, relation in sorted(edges)]
    def supplied(key):
        return evidence.get(key, simulation.get(key))
    ml = supplied("ml")
    if ml is None:
        ml = {key: supplied(field) for key, field in (("runtime", "ml_runtime"), ("model", "cpu_model"), ("runs", "ml_runs"), ("jobs", "ml_jobs"), ("live_anomalies", "live_ml_anomalies")) if supplied(field) is not None}
    supplemental = {
        "shadow": supplied("shadow") or supplied("full_shadow"),
        "ueba": supplied("ueba") or {key: supplied(field) for key, field in (("baseline", "ueba_baseline"), ("evaluation", "ueba_evaluation")) if supplied(field) is not None},
        "case_regroup": supplied("case_regroup") or {key: supplied(field) for key, field in (("route", "case_route"), ("proposals", "case_proposals")) if supplied(field) is not None},
    }
    device_counts = supplied("devices")
    device_counts = [{"device": key, **(value if isinstance(value, dict) else {"value": value})} for key, value in sorted(device_counts.items())] if isinstance(device_counts, dict) else rows(device_counts)
    return {"evidence": evidence, "junit": junit, "simulation": simulation, "timeline": timeline,
            "signals": signals, "stories": stories, "cases": cases, "graph": graph,
            "ml": ml, "supplemental": supplemental, "device_counts": device_counts,
            "checks": rows(evidence.get("checks")) or rows(simulation.get("checks")),
            "native_hardware": False, "synthetic": True}


CSS = r"""
:root{color-scheme:light;--ink:#14283e;--muted:#607389;--blue:#1559a0;--bg:#edf3f8;--line:#d9e3ed;--ok:#11745a;--bad:#a93141;--warn:#8e6517}*{box-sizing:border-box}body{margin:0;background:var(--bg);font:15px/1.65 system-ui,-apple-system,'Malgun Gothic',sans-serif;color:var(--ink)}header{background:#13283e;color:white;padding:42px max(24px,calc((100vw - 1220px)/2));border-bottom:6px solid #52c4b5}header .eyebrow{color:#91d7d0;font-size:12px;font-weight:700;letter-spacing:2px}h1{font-size:clamp(24px,4vw,39px);line-height:1.35;margin:9px 0 14px}header p{max-width:880px;color:#cfdfed;margin:0}nav{display:flex;flex-wrap:wrap;gap:9px;padding:14px 0}nav a{color:#eaf5ff;text-decoration:none;border:1px solid #45617b;border-radius:6px;padding:4px 10px;font-size:12px}.layout{max-width:1268px;margin:auto;padding:25px 24px 60px}section{background:white;padding:24px;border:1px solid var(--line);border-radius:12px;margin:0 0 22px;scroll-margin-top:15px}h2{font-size:22px;margin:0 0 7px}h3{font-size:16px;margin:20px 0 7px}.lead{color:var(--muted);margin:0 0 17px}.tag{display:inline-block;border-radius:5px;padding:3px 9px;font-size:12px;font-weight:650;background:#e7eef7;margin-right:5px}.tag.ok{background:#e4f4ed;color:var(--ok)}.tag.bad{background:#fce7e9;color:var(--bad)}.tag.warn{background:#fff2d8;color:var(--warn)}.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}.metric{border:1px solid var(--line);border-left:4px solid var(--blue);padding:16px;border-radius:8px;min-width:0}.metric span{font-size:12px;color:var(--muted);display:block}.metric strong{display:block;font-size:29px;line-height:1.3;margin:5px 0}.metric small{font-size:11px;color:var(--muted)}.notice{background:#f1f7fd;border-left:4px solid #2773b6;padding:12px 15px;border-radius:4px;font-size:13px}.notice.warn{background:#fff8e9;border-color:#bb8320}.grid{display:grid;grid-template-columns:1fr 1fr;gap:17px}.field{overflow-wrap:anywhere;font-size:12px}.field b{display:block;color:var(--muted);font-weight:500}table{border-collapse:collapse;width:100%;font-size:13px}th{text-align:left;background:#eff5fa;color:#415b74}th,td{padding:10px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}td.num{text-align:right;font-variant-numeric:tabular-nums}.table-scroll{overflow:auto}.controls{display:flex;gap:9px;flex-wrap:wrap;margin:14px 0}input,select,button{font:inherit;border:1px solid #b8cada;border-radius:6px;padding:7px 10px;background:white;color:var(--ink)}input[type=search]{min-width:210px;flex:1}button{cursor:pointer;background:#eaf2fa}button:hover{background:#d5e8fa}.mono,pre{font-family:Consolas,'Liberation Mono',monospace}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px;line-height:1.55;background:#f4f7fb;padding:15px;max-height:550px;overflow:auto;margin:10px 0;border-radius:7px}.chart{width:100%;overflow:auto;border:1px solid var(--line);border-radius:8px;background:#f9fcfe}.chart svg{display:block;min-width:650px;width:100%}.chart text{font-family:inherit}.timeline-dot{cursor:pointer}.timeline-dot:hover{stroke:#17283b;stroke-width:2}.graph-node{cursor:pointer}.graph-node:hover rect{stroke:#152f4b;stroke-width:2}.graph-node.selected rect{stroke:#0c6399;stroke-width:3}.graph-edge{opacity:.23}.graph-edge.highlight{opacity:1;stroke-width:2.5}.graph-legend{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--muted);padding:12px 0}.swatch{width:10px;height:10px;border-radius:2px;display:inline-block;margin-right:5px}.split{display:grid;grid-template-columns:1fr;gap:15px}.split>div,.grid>div{min-width:0}#graph{max-height:650px}#graph svg{min-width:1100px}.graph-print{display:none}.details-empty{font-size:13px;color:var(--muted);padding:15px;background:#f4f7fb}.test-row button{font-size:11px;padding:3px 6px}.test-detail{display:none}.test-detail.open{display:table-row}.phase{padding:15px;border:1px solid var(--line);border-radius:8px;margin:9px 0}.phase b{display:block}.phase p{margin:5px 0;color:var(--muted);font-size:13px}.appendix details{border-bottom:1px solid var(--line);padding:9px 0}summary{cursor:pointer;font-weight:650}footer{font-size:12px;color:var(--muted);padding:0 7px}.empty{padding:15px;background:#f5f8fb;border-radius:6px;color:var(--muted)}.small{font-size:12px;color:var(--muted)}.hidden{display:none!important}@media(max-width:850px){.grid,.split{grid-template-columns:1fr}section{padding:18px}.layout{padding:18px 12px}header{padding:28px 20px}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.metric strong{font-size:25px}}@media print{.graph-print{display:block}#graph,#graph-detail,#graph-summary,.graph-legend{display:none}#operations details{display:none}body{background:white;font-size:10pt}header{padding:20px;color:#12253b;background:white;border-bottom:3px solid #52c4b5}header p,header .eyebrow{color:#415b74}nav,.controls,button{display:none}.layout{max-width:none;padding:14px 0}section{break-inside:avoid;border-radius:0;margin-bottom:15px;padding:16px}.split,.grid{grid-template-columns:1fr}.chart svg{min-width:0}.chart{overflow:visible}pre{max-height:none;font-size:8pt}.test-detail{display:none!important}a{color:inherit}.appendix details:not([open]){display:none}}
"""

SCRIPT = r"""
const DATA=JSON.parse(document.getElementById('report-data').textContent);
const $=id=>document.getElementById(id);
const el=(tag,text,cls)=>{const x=document.createElement(tag);if(text!==undefined)x.textContent=text;if(cls)x.className=cls;return x};
const pretty=x=>JSON.stringify(x,null,2);
const show=(id,value)=>{const x=$(id);x.replaceChildren(el('pre',pretty(value)))};
const badge=(value)=>{let status=String(value??'미제공').toLowerCase(),label=value??'미제공',cls='warn';if(['true','passed','pass','completed','ok','supported'].includes(status)){label='통과';cls='ok'}else if(['false','failed','fail','error'].includes(status)){label='실패';cls='bad'}else if(['skipped','skip'].includes(status))label='건너뜀';else if(['unavailable','unsupported'].includes(status))label='지원 불가';return el('span',String(label),'tag '+cls)};
const localTime=n=>n>1000000000?new Date(n*1000).toLocaleString('ko-KR',{timeZone:'Asia/Seoul',hour12:false}):Number(n).toFixed(3)+'초';
function table(container,headers,items,render){const t=el('table'),head=el('tr');headers.forEach(h=>head.append(el('th',h)));const th=el('thead');th.append(head);t.append(th);const b=el('tbody');items.forEach((item,index)=>{const row=el('tr');render(row,item,index);b.append(row)});t.append(b);container.append(t)}
function overview(){const r=DATA.junit,e=DATA.evidence;[['회귀 테스트',r.tests,'JUnit testcase 실기록'],['통과',r.passed,'실패 '+r.failed+' · 오류 '+r.error],['건너뜀',r.skipped,'xfail 등 JUnit skipped 포함'],['분석 신호',DATA.signals.length,'제공된 실제 Signal 레코드'],['Story',DATA.stories.length,'제공된 실제 Story 레코드'],['Case',DATA.cases.length,'제공된 실제 Case 레코드']].forEach(([name,note,detail])=>{const c=el('div',undefined,'metric');c.append(el('span',name),el('strong',String(note)),el('small',detail));$('metrics').append(c)});$('version').textContent=e.source_version??e.version??'미제공';$('source-hash').textContent=e.source_hash??e.source_digest??'미제공';$('junit-hash').textContent=r.input_sha256;const changes=e.changes??e.phases;if(Array.isArray(changes)){changes.forEach((p,i)=>{const x=el('div',undefined,'phase');x.append(el('b',String(p.title??p.name??('단계 '+(i+1)))));if(typeof p==='string')x.append(el('p',p));else x.append(el('pre',pretty(p)));$('phases').append(x)})}else if(changes!==undefined)show('phases',changes);else $('phases').append(el('p','개발 범위 상세 근거가 제공되지 않았습니다.','empty'))}
function checks(){if(!DATA.checks.length){$('check-list').append(el('p','정형 검증 항목이 제공되지 않았습니다. 전체 근거 부록을 확인하세요.','empty'));return}table($('check-list'),['검증 항목','결과','근거'],DATA.checks,(tr,x)=>{tr.append(el('td',x.name??x.title??x.id??'항목'));const status=el('td');status.append(badge(x.passed??x.status??x.result));tr.append(status,el('td',typeof x.detail==='string'?x.detail:pretty(x.detail??x.evidence??x.reason??'')))})}
const colors=['#236ca8','#14a082','#a572bd','#d09427','#c25a70'];
const svgEl=(tag,attrs={})=>{const x=document.createElementNS('http://www.w3.org/2000/svg',tag);Object.entries(attrs).forEach(([k,v])=>x.setAttribute(k,v));return x};
function timeline(){if(DATA.device_counts.length)table($('device-counts'),['장비','전송','수락','색인','중복 재전송'],DATA.device_counts,(tr,x)=>tr.append(el('td',String(x.device??'미제공')),el('td',String(x.sent??'미제공'),'num'),el('td',String(x.accepted??'미제공'),'num'),el('td',String(x.indexed??'미제공'),'num'),el('td',String(x.duplicate??'미제공'),'num')));const values=DATA.timeline;if(!values.length){$('timeline').append(el('p','장비별 실제 전송 시각 레코드가 없어 타임라인을 그리지 않았습니다.','empty'));return}const devices=[...new Set(values.map(x=>x.device))].sort(),width=1000,height=80+devices.length*62,left=120,right=40,low=Math.min(...values.map(x=>x.time)),high=Math.max(...values.map(x=>x.time)),range=Math.max(high-low,0.001),s=svgEl('svg',{viewBox:`0 0 ${width} ${height}`,role:'img','aria-label':'실제 기록된 장비별 전송 타임라인'});devices.forEach((name,i)=>{const y=42+i*62,t=svgEl('text',{x:10,y:y+5,'font-size':13,fill:'#415b74'});t.textContent=name;s.append(t,svgEl('line',{x1:left,y1:y,x2:width-right,y2:y,stroke:'#dce5ee'}))});for(let i=0;i<5;i++){const at=low+range*i/4,x=left+(width-left-right)*i/4,t=svgEl('text',{x,y:height-22,'text-anchor':i===0?'start':i===4?'end':'middle','font-size':10,fill:'#607389'});t.textContent=localTime(at);s.append(t,svgEl('line',{x1:x,y1:20,x2:x,y2:height-40,stroke:'#e5edf4','stroke-dasharray':'3 3'}))}values.forEach(item=>{const i=devices.indexOf(item.device),x=left+(item.time-low)/range*(width-left-right),y=42+i*62,d=svgEl('circle',{cx:x,cy:y,r:4,fill:colors[i%colors.length],class:'timeline-dot',tabindex:0}),title=svgEl('title');title.textContent=item.device+' · '+localTime(item.time)+' · '+item.id;d.append(title);d.addEventListener('click',()=>show('timeline-detail',item));d.addEventListener('keydown',ev=>{if(ev.key==='Enter')show('timeline-detail',item)});s.append(d)});$('timeline').append(s);$('timeline-summary').textContent=values.length+'개의 실제 시각 레코드 · '+devices.length+'개 장비 구분 · '+(high-low).toFixed(3)+'초 창 · 점을 선택하면 원본 기록 확인';show('simulation-data',DATA.simulation)}
function graph(){const all=DATA.graph;const kinds=['event','signal','story','case'],names={event:'원본 근거',signal:'Signal',story:'Story',case:'Case'},palette={event:'#b7cde1',signal:'#91d4c6',story:'#c4b1dc',case:'#f2d18c'};let focus=null;const draw=()=>{const query=$('graph-search').value.toLowerCase(),filter=$('graph-kind').value;let matches=all.nodes.filter(n=>(!filter||n.kind===filter)&&(!query||pretty(n).toLowerCase().includes(query)));if(query){const exact=matches.filter(n=>n.id.toLowerCase().includes(query));if(exact.length)matches=exact}const selected=new Set(matches.map(n=>n.id)),roots=new Set(selected);if(query||filter){all.edges.forEach(e=>{if(roots.has(e.from)||roots.has(e.to)){selected.add(e.from);selected.add(e.to)}});matches=all.nodes.filter(n=>selected.has(n.id))}const limits=120,visible=[],chosen=new Set();for(const kind of kinds){for(const n of matches.filter(n=>n.kind===kind).slice(0,30)){visible.push(n);chosen.add(n.id)}}for(const n of matches){if(visible.length>=limits)break;if(!chosen.has(n.id)){visible.push(n);chosen.add(n.id)}}const ids=new Set(visible.map(n=>n.id)),edges=all.edges.filter(e=>ids.has(e.from)&&ids.has(e.to)),grouped=kinds.map(k=>visible.filter(n=>n.kind===k)),height=Math.max(160,...grouped.map(g=>g.length*45+70)),width=1100,s=svgEl('svg',{viewBox:`0 0 ${width} ${height}`,role:'img','aria-label':'실제 ID 참조로 구성한 근거와 신호 사건 연결 그래프'}),positions={};grouped.forEach((g,col)=>{const t=svgEl('text',{x:25+col*270,y:25,'font-size':14,'font-weight':700,fill:'#354e67'});t.textContent=names[kinds[col]]+' ('+g.length+')';s.append(t);g.forEach((n,i)=>positions[n.id]={x:25+col*270,y:42+i*45,w:220,h:31})});edges.forEach(e=>{const a=positions[e.from],b=positions[e.to],line=svgEl('path',{d:`M${a.x+a.w},${a.y+15} C${a.x+a.w+35},${a.y+15} ${b.x-35},${b.y+15} ${b.x},${b.y+15}`,fill:'none',stroke:'#45758f','stroke-width':1,class:'graph-edge'+(focus&&(e.from===focus||e.to===focus)?' highlight':'')});const t=svgEl('title');t.textContent=e.relation;line.append(t);s.append(line)});visible.forEach(n=>{const p=positions[n.id],g=svgEl('g',{class:'graph-node'+(focus===n.id?' selected':''),tabindex:0}),rect=svgEl('rect',{x:p.x,y:p.y,width:p.w,height:p.h,rx:5,fill:palette[n.kind],stroke:'#afc4d4'}),t=svgEl('text',{x:p.x+10,y:p.y+20,'font-size':11,fill:'#14283e'});t.textContent=n.label.length>29?n.label.slice(0,29)+'…':n.label;const title=svgEl('title');title.textContent=n.id;g.append(rect,t,title);const select=()=>{focus=n.id;show('graph-detail',{...n,connections:all.edges.filter(e=>e.from===n.id||e.to===n.id)});draw()};g.addEventListener('click',select);g.addEventListener('keydown',ev=>{if(ev.key==='Enter')select()});s.append(g)});$('graph').replaceChildren(s);$('graph-summary').textContent='제공된 노드 '+all.nodes.length+'개 · 연결 '+all.edges.length+'개 / 현재 표시 '+visible.length+'개'+(matches.length>limits?' · 화면은 120개까지 표시, 검색으로 범위를 좁히세요. 전체는 부록에 포함.':'')};$('graph-search').addEventListener('input',draw);$('graph-kind').addEventListener('change',draw);draw()}
function ml(){const m=DATA.ml??{};show('ml-data',m);const models=Array.isArray(m.models)?m.models:Array.isArray(m.model)?m.model:m.model?[m.model]:[],runs=Array.isArray(m.runs)?m.runs:Array.isArray(m.inference_runs)?m.inference_runs:[];if(models.length)table($('ml-models'),['모델·버전','검증·학습','임계값·무결성'],models,(tr,x)=>{tr.append(el('td',(x.name??x.id??'모델')+' / revision '+(x.revision??'미제공')),el('td',pretty(x.metrics??{})),el('td','threshold '+(x.threshold??'미제공')+'\ndigest '+(x.digest??'미제공')))});if(runs.length)table($('ml-runs'),['실행','텐서 계산 ms','전체 worker ms','상태'],runs,(tr,x)=>tr.append(el('td',x.id??x.run_id??x.model_id??'실행'),el('td',String(x.duration_ms??x.metrics?.duration_ms??'미제공'),'num'),el('td',String(x.worker_wall_ms??x.metrics?.worker_wall_ms??'미제공'),'num'),el('td',x.status??'미제공')));if(!models.length&&!runs.length)$('ml-models').append(el('p','정형 모델·실행 목록이 제공되지 않았습니다. 아래 ML 원본 근거를 확인하세요.','empty'))}
function regress(){const cases=DATA.junit.cases;let limit=200;const render=()=>{const q=$('test-search').value.toLowerCase(),status=$('test-status').value,filtered=cases.filter(x=>(!status||x.status===status)&&(!q||pretty(x).toLowerCase().includes(q)));$('test-list').replaceChildren();table($('test-list'),['테스트','상태','초','상세'],filtered.slice(0,limit),(tr,x,i)=>{tr.className='test-row';tr.append(el('td',x.classname+' :: '+x.name));const s=el('td');s.append(badge(x.status));tr.append(s,el('td',x.seconds===null?'미제공':x.seconds.toFixed(3),'num'));const d=el('td'),b=el('button','근거 보기');b.addEventListener('click',()=>show('test-detail',{...x}));d.append(b);tr.append(d)});$('test-summary').textContent=filtered.length+'개 일치 / '+Math.min(filtered.length,limit)+'개 표시 · 모든 testcase는 내장 JSON에 포함'};$('test-search').addEventListener('input',()=>{limit=200;render()});$('test-status').addEventListener('change',()=>{limit=200;render()});$('more-tests').addEventListener('click',()=>{limit+=200;render()});render()}
function appendix(){Object.entries(DATA.evidence).forEach(([key,value])=>{const d=el('details'),s=el('summary',key);d.append(s,el('pre',pretty(value)));$('appendix').append(d)});const d=el('details');d.append(el('summary','정규화한 전체 그래프 ID/연결'),el('pre',pretty(DATA.graph)));$('appendix').append(d);$('redactions').textContent=String(DATA.redactions);$('evidence-hash').textContent=DATA.input_sha256}

function operational(key,data){const target=$(key+'-data'),summary=[];if(key==='shadow'){const c=data.comparison??data,r=data.replay??{};summary.push(['고정 원본',c.event_count??c.baseline?.execution?.frozen_events??'미제공'],['비교 상태',c.status??'미제공'],['재실행 동일',r.identical??'미제공'],['운영 효과',c.live_effects??'미제공'],['실행 context hash',c.context_digest??'미제공'],['결과 hash',c.result_digest??'미제공']);if(Array.isArray(c.limitations)){const note=el('p',c.limitations.join(' · '),'notice');target.append(note)}}else if(key==='ueba'){const b=data.baseline??{},r=data.evaluation??data;summary.push(['학습 집단 준비',b.ready??'미제공'],['학습 이벤트',b.training_events??'미제공'],['평가 이벤트',r.events??'미제공'],['제공된 이상 기록',Array.isArray(r.anomalies)?r.anomalies.length:'미제공'],['신호 발행',r.published??'미제공'],['자동 대응 권한',r.response_authorized??'미제공']);if(Array.isArray(r.anomalies)&&r.anomalies.length)table(target,['개체','특징','관찰값','임계값'],r.anomalies,(tr,a)=>tr.append(el('td',String(a.entity??'미제공')),el('td',String(a.feature??'미제공')),el('td',String(a.value??'미제공'),'num'),el('td',String(a.threshold??'미제공'),'num')))}else{const r=data.route??data;summary.push(['병합 원래 Case',r.source_id??'미제공'],['병합 대상 Case',r.target_id??'미제공'],['후속 신호의 대상 편입',r.later_signal_attached_to_target??'미제공'],['원래 조사 기록 보존',r.movement?.original_notes_tasks_holds_and_response_receipts_retained??'미제공'],['후속 원본 ID',r.later_event_id??'미제공'],['제공된 자동 재편 제안',Array.isArray(data.proposals?.items)?data.proposals.items.length:'미제공'])}const grid=el('div',undefined,'grid');for(const [name,value]of summary){const field=el('div',undefined,'field');field.append(el('b',name),el('span',String(value)));grid.append(field)}target.prepend(grid);const details=el('details');details.append(el('summary','전체 원본 근거 펼치기'),el('pre',pretty(data)));target.append(details)}
function graphPrint(){const selected=DATA.signals.filter(s=>s.kind!=='observation');$('graph-print').append(el('p','인쇄용 연결 근거: 관찰 신호를 제외한 제공 기록 '+selected.length+'개. 모든 그래프와 원본은 HTML에서 검색할 수 있습니다.','small'));table($('graph-print'),['Signal ID','종류','원본 수','명시된 Case ID'],selected,(tr,s)=>{const cases=[...new Set(DATA.graph.edges.filter(e=>e.from==='signal:'+s.id&&e.to.startsWith('case:')).map(e=>e.to.slice(5)))];tr.append(el('td',String(s.id)),el('td',String(s.kind)),el('td',String(Array.isArray(s.event_ids)?s.event_ids.length:'미제공'),'num'),el('td',cases.length?cases.join(', '):'명시된 참조 없음'))})}

overview();checks();timeline();graph();ml();regress();appendix();graphPrint();for(const key of ['shadow','ueba','case_regroup']){if(DATA.supplemental[key]&&Object.keys(DATA.supplemental[key]).length)operational(key,DATA.supplemental[key]);else $(key+'-data').append(el('p','정형 근거가 제공되지 않았습니다. 전체 근거 부록에서 관련 항목을 확인하세요.','empty'))}document.getElementById('print').addEventListener('click',()=>window.print());
"""


def build(evidence_path, junit_path, output_path):
    raw = Path(evidence_path).read_bytes()
    if len(raw) > 64 * 1024 * 1024:
        raise ValueError("Evidence JSON exceeds 64 MiB")
    evidence = json.loads(raw)
    if not isinstance(evidence, dict):
        raise ValueError("Evidence JSON requires a top-level object")
    count = [0]
    data = normalize(sanitize(evidence, count), sanitize(junit_summary(junit_path), count))
    data.update(redactions=count[0], input_sha256=hashlib.sha256(raw).hexdigest())
    packed = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    packed = packed.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    document = """<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; font-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'"><title>VATEX xSERA 차세대 아키텍처 · 적용과 검증 보고서</title><style>__CSS__</style></head>
<body><header><div class="eyebrow">VATEX · xSERA INTELLIGENCE ENGINE</div><h1>차세대 아키텍처 적용과 검증<br>올인원 실행 보고서</h1><p>소스 변경, 전면 회귀 테스트, 가상 텔레메트리 전송, 신호 결합과 사건 생성, CPU 인공지능을 실행 근거로 함께 확인합니다. 모든 수치와 연결은 입력으로 제공된 실제 기록에서만 계산했습니다.</p><nav><a href="#overview">결과</a><a href="#changes">적용 범위</a><a href="#validation">검증</a><a href="#transmission">전송</a><a href="#relationships">근거 연결</a><a href="#ml">CPU ML</a><a href="#operations">분석 운영</a><a href="#regression">회귀</a><a href="#yocto">Yocto</a><a href="#appendix-section">전체 근거</a></nav></header>
<main class="layout"><section id="overview"><h2>실행 결과와 검증 범위</h2><p class="lead">실제 센서를 대체한 Python 가상 로그 시뮬레이션입니다. native hardware = false, synthetic = true.</p><div id="metrics" class="metrics"></div><div class="grid" style="margin-top:17px"><div class="field"><b>대상 소스 버전</b><span id="version"></span></div><div class="field mono"><b>소스 manifest hash</b><span id="source-hash"></span></div></div><p class="notice warn">이 보고서는 소프트웨어 회귀와 합성 로그 처리의 결과입니다. 실제 장비의 센서 손실률, 미지 공격 탐지율, 상용 환경의 정밀도나 하드웨어 OS 자격을 입증하지 않습니다.</p><button id="print">인쇄 / PDF 저장</button></section>
<section id="changes"><h2>다섯 단계 적용 범위</h2><p class="lead">수집·신원·재분석 → 공통 Signal·Story → Composite·Case 연속성 → UEBA → CPU ML. 구체적인 변경 내역은 제출된 근거를 그대로 표시합니다.</p><div id="phases"></div></section>
<section id="validation"><h2>실행 검증과 예외</h2><p class="lead">통과, 실패, 건너뜀, 지원 불가를 구분합니다. 입력에 결과가 없으면 미제공으로 표시합니다.</p><div id="check-list" class="table-scroll"></div></section>
<section id="transmission"><h2>장비별 실제 전송 타임라인</h2><p class="lead">각 점은 제공된 전송·수신·이벤트 시각 중 실제 존재하는 필드를 사용합니다. 클릭해 시간 기준과 원본 레코드를 확인하세요.</p><div id="device-counts" class="table-scroll"></div><div id="timeline" class="chart"></div><p id="timeline-summary" class="small"></p><div class="grid"><div id="timeline-detail" class="details-empty">타임라인의 점을 선택하세요.</div><details><summary>시뮬레이션 요약 근거</summary><div id="simulation-data"></div></details></div></section>
<section id="relationships"><h2>원본 근거 · Signal · Story · Case 연결</h2><p class="lead">명시적으로 기록된 ID 참조만 연결합니다. 같은 IP·사용자·시각이나 근거 중첩만으로 인과 관계 또는 사건 귀속을 만들어내지 않습니다.</p><div class="controls"><input id="graph-search" type="search" placeholder="ID, 규칙, 특징, 호스트 검색" aria-label="그래프 검색"><select id="graph-kind" aria-label="그래프 종류"><option value="">전체 종류</option value="event">원본 근거</option><option value="signal">Signal</option><option value="story">Story</option><option value="case">Case</option></select></div><div class="split"><div><div id="graph" class="chart"></div><p id="graph-summary" class="small"></p><div class="graph-legend"><span><i class="swatch" style="background:#b7cde1"></i>원본</span><span><i class="swatch" style="background:#91d4c6"></i>신호</span><span><i class="swatch" style="background:#c4b1dc"></i>스토리</span><span><i class="swatch" style="background:#f2d18c"></i>사건</span></div></div><div id="graph-print" class="graph-print"></div><div id="graph-detail" class="details-empty">노드를 선택하면 특징, 원본 ID, 버전, 연결 근거를 확인할 수 있습니다.</div></div></section>
<section id="ml"><h2>CPU 기반 PyTorch ML</h2><p class="lead">학습·검증·추론이 실제 실행된 경우 해당 근거와 시간을 표시합니다. 호환 불가 결과도 숨기지 않습니다.</p><p class="notice">모델은 정상 검토 집단의 특징 재구성 오차를 측정합니다. 이상 점수는 악성 확률이 아닙니다. 텐서 계산 시간과 Python·PyTorch 로딩을 포함한 worker 전체 시간을 분리해서 읽어야 합니다. 학습 원본과 holdout의 분리, 모델 hash, 독립 승인과 철회는 운영 판단의 기반입니다.</p><div id="ml-models" class="table-scroll"></div><div id="ml-runs" class="table-scroll"></div><details><summary>ML 실행 원본 근거</summary><div id="ml-data"></div></details></section>
<section id="operations"><h2>재분석 · 행위 분석 · Case 재편</h2><p class="lead">Shadow 실행의 운영 사건 영향, UEBA 특징, 병합·분리 이후 편입 결과를 제공된 실측 기록으로 확인합니다.</p><h3>Historical Replay / Shadow Mode</h3><div id="shadow-data"></div><h3>추가 UEBA 특징</h3><div id="ueba-data"></div><h3>Case 연속성과 재편</h3><div id="case_regroup-data"></div></section>
<section id="regression"><h2>전면 회귀 테스트</h2><p class="lead">JUnit testcase 기록을 직접 집계했습니다. 목록 검색과 상태 필터로 실패·오류·건너뜀의 사유를 확인할 수 있습니다.</p><div class="controls"><input id="test-search" type="search" placeholder="테스트 이름 또는 사유 검색" aria-label="테스트 검색"><select id="test-status" aria-label="테스트 상태"><option value="">전체 상태</option><option value="passed">통과</option><option value="failed">실패</option><option value="error">오류</option><option value="skipped">건너뜀</option></select><button id="more-tests">200개 더 표시</button></div><p id="test-summary" class="small"></p><div id="test-list" class="table-scroll"></div><div id="test-detail"></div><p class="field mono"><b>JUnit 입력 SHA-256</b><span id="junit-hash"></span></p></section>
<section id="yocto"><h2>향후 Yocto Project 기반 xSERA OS</h2><p class="lead">현재 적용은 CPU 전용 분석 경계, JSON 모델, 선택적 의존성과 검증 계약을 준비한 단계입니다. OS 이미지나 BSP를 빌드·자격 검증했다는 의미는 아닙니다.</p><div class="grid"><div><h3>재사용 가능한 현재 계약</h3><p>GPU 없이 동작하는 고정 구조 모델, 원본·특징·모델 hash, 독립 승인, worker 실행 제한, 호환 불가 시 분석 계속, 상태 기록과 rollback을 유지합니다.</p></div><div><h3>실제 OS 개발에서 확인할 항목</h3><p>MACHINE/BSP, CPU ISA, glibc·Python ABI, 메모리·저장소, PyTorch CPU recipe와 offline wheelhouse, 라이선스/SBOM, 권한·CPU·메모리 제한, 부팅·전원 손실·업데이트·철회 및 센서 손실을 타깃 장비에서 검증해야 합니다.</p></div></div><p class="small">참고: <a href="https://pytorch.org/get-started/locally/">PyTorch 공식 설치</a> · <a href="https://download.pytorch.org/whl/cpu/torch/">공식 CPU wheel</a> · <a href="https://docs.yoctoproject.org/current/dev-manual/index.html">Yocto 개발 지침</a>. 링크는 참고 문서이며 보고서 표시를 위해 네트워크에 연결하지 않습니다.</p></section>
<section id="appendix-section" class="appendix"><h2>전체 실행 근거 부록</h2><p class="lead">제공된 모든 JSON 항목을 펼쳐 볼 수 있습니다. password, token, private key 등 민감 값 <span id="redactions"></span>개를 제거했습니다. 정형 화면에서 생략된 상세 레코드도 이 부록에 보존합니다.</p><div id="appendix"></div><p class="field mono"><b>제출된 evidence JSON 원본 SHA-256</b><span id="evidence-hash"></span></p></section><footer>단일 HTML · 오프라인 CSS/JavaScript · 외부 CDN/분석 추적 없음 · 합성 입력 기반 검증 · 시각은 Asia/Seoul로 표시</footer></main>
<script id="report-data" type="application/json">__DATA__</script><script>__SCRIPT__</script></body></html>"""
    document = document.replace("__CSS__", CSS).replace("__DATA__", packed).replace("__SCRIPT__", SCRIPT)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document, encoding="utf-8", newline="\n")
    return {"output": str(path.resolve()), "tests": data["junit"]["tests"], "signals": len(data["signals"]),
            "cases": len(data["cases"]), "timeline_records": len(data["timeline"]), "redacted_values": count[0]}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build offline Korean xSERA execution report")
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--junit", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    print(json.dumps(build(args.evidence, args.junit, args.output), ensure_ascii=False))


if __name__ == "__main__":
    main()
