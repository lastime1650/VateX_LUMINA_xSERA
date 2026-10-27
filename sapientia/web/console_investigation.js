/* Evidence-backed ATT&CK context and explicit endpoint response. */
(() => {
  'use strict';
  const V = window.Vatex;
  if (!V) return;
  const h = V.h, enc = encodeURIComponent;
  const severityLabels = {critical:'치명적',high:'높음',medium:'보통',low:'낮음',info:'정보',unknown:'미분류'};
  const commandLabels = {queued:'전송 대기',claimed:'에이전트 수신',running:'실행 중',started:'실행 중',succeeded:'실제 동작 확인',failed:'실패',unknown:'결과 확인 필요',expired:'만료',cancelled:'취소'};
  const actionLabels = {terminate_process:'프로세스 종료',delete_file:'파일 삭제',inspect_process:'프로세스 조사',inspect_file:'파일 조사',collect_artifact:'증거 파일 수집',quarantine_file:'파일 격리',restore_file:'격리 파일 복원',isolate_host:'호스트 격리',release_host:'호스트 격리 해제'};
  const when = seconds => Number.isFinite(Number(seconds)) && seconds ? new Date(Number(seconds)*1000).toLocaleString('ko-KR') : '—';
  const asArray = value => Array.isArray(value) ? value : [];
  const button = (text, action, attrs='', kind='') => `<button type="button" class="iv-btn ${kind}" data-iv="${h(action)}" ${attrs}>${h(text)}</button>`;
  const field = (label,name,val='',attrs='',type='text') => `<label class="iv-field"><span>${h(label)}</span><input type="${type}" name="${h(name)}" value="${h(val??'')}" ${attrs}></label>`;
  const options = (items,current) => items.map(([val,label])=>`<option value="${h(val)}" ${String(val)===String(current)?'selected':''}>${h(label)}</option>`).join('');
  const select = (label,name,items,current='') => `<label class="iv-field"><span>${h(label)}</span><select name="${h(name)}">${options(items,current)}</select></label>`;
  const note = (text,warning=false) => `<div class="iv-note ${warning?'iv-warning':''}">${h(text)}</div>`;
  const empty = (title,detail='') => `<div class="iv-empty"><strong>${h(title)}</strong>${h(detail)}</div>`;
  const error = text => `<div class="iv-error" role="alert">${h(text)}</div>`;
  const value = (host,name) => host.querySelector(`[name="${name}"]`)?.value??'';
  const canRespond = () => ['admin','analyst'].includes(V.session()?.role);
  const details = rows => `<dl class="iv-detail">${rows.map(([label,val])=>`<dt>${h(label)}</dt><dd>${h(val??'—')}</dd>`).join('')}</dl>`;
  function techniqueId(value) { return typeof value==='string' && /^T\d{4}(?:\.\d{3})?$/.test(value) ? value : null; }
  function techniquesOf(context) {
    return asArray(context?.techniques).map(item=>typeof item==='string'?{id:item}:item).filter(item=>techniqueId(item?.id));
  }
  function scoreOf(context) {
    const score = context?.threat_score;
    return typeof score==='number' && Number.isFinite(score) && score>=0 && score<=100 ? score : null;
  }
  function header(context) {
    if (!context) return `<div class="iv-case">${note('전체 사건의 탐지 근거를 확인하는 중입니다.')}</div>`;
    if (context._error) return `<div class="iv-case">${error(`사건 위험/ATT&CK 근거를 불러오지 못했습니다: ${context._error}`)}</div>`;
    const severity = Object.hasOwn(severityLabels,context.severity)?context.severity:'unknown';
    const score = scoreOf(context), mapped = techniquesOf(context), definition = context.score_definition;
    const scoreText = typeof definition === 'string' ? definition : definition?.id === 'case-evidence-max-v1' ? '전체 사건 근거의 정책 위험 기여도 중 최댓값입니다. 중복 근거는 점수를 더하지 않습니다. 공격 확률이나 MITRE 기술 점수가 아닙니다.' : typeof definition?.meaning === 'string' ? definition.meaning : '서버가 계산한 사건 근거 점수입니다. 공격 확률이나 호스트 차단 성공률이 아닙니다.';
    return `<div class="iv-case iv-hero"><section class="iv-tile"><small>CASE EVIDENCE SEVERITY</small><div class="iv-severity" data-level="${h(severity)}">${h(severityLabels[severity])}</div><p class="iv-explain">전체 사건에 저장된 탐지 근거의 심각도입니다. MITRE 기술의 심각도가 아닙니다.</p></section><section class="iv-tile"><small>THREAT SCORE</small><div class="iv-score"><strong>${score===null?'—':h(Number(score.toFixed(1)))}</strong><span>/ 100</span></div><p class="iv-explain">${h(scoreText)}</p><small class="iv-score-provenance">산출 ${h(when(context.generated_at))}</small></section><section class="iv-tile"><small>ENTERPRISE ATT&CK EVIDENCE</small><div class="iv-hero-count">${mapped.length}<span class="iv-explain">개 기술 연결</span></div><div class="iv-scope-list">${mapped.slice(0,8).map(item=>`<span>${h(item.id)}</span>`).join('')||'<span>연결된 기술 없음</span>'}</div><p class="iv-explain">탐지 정책에 선언되어 사건 근거로 저장된 매핑입니다. 미관측 기술도 전체 매트릭스에서 확인합니다.</p></section></div>`;
  }
  async function loadContext(scope,id) {
    try { return await scope.get(`/api/incidents/${enc(id)}/attack-context`); }
    catch (err) { if(err.name==='AbortError') throw err; return {_error:err.message}; }
  }
  function dialog(scope,title,html,onSubmit,label='확인') {
    const node=document.createElement('dialog');node.className='wf-modal';
    node.innerHTML=`<form class="wf-modal-form"><header><div><span class="iv-kicker">CASE EVIDENCE</span><h3>${h(title)}</h3></div><button type="button" class="wf-icon-btn" data-iv-close aria-label="닫기">×</button></header><div class="wf-modal-body">${html}</div><footer><button type="button" class="iv-btn" data-iv-close>닫기</button>${onSubmit?`<button type="submit" class="iv-btn iv-btn-primary">${h(label)}</button>`:''}</footer></form>`;
    const close=()=>{node.close();node.remove();};
    node.addEventListener('click',event=>{if(event.target.closest('[data-iv-close]'))close();});
    node.addEventListener('cancel',event=>{event.preventDefault();close();});
    node.querySelector('form').addEventListener('submit',event=>{event.preventDefault();if(onSubmit)scope.run(async()=>{if(await onSubmit(node)!==false)close();},node.querySelector('[type="submit"]'));});
    document.body.append(node);scope.track(()=>{if(node.isConnected)close();});node.showModal();return node;
  }
  function matrixModel(catalog,context,filters={}) {
    const mapped=new Set(techniquesOf(context).map(item=>item.id)),q=String(filters.search||'').toLowerCase();
    const visible=asArray(catalog.techniques).filter(item=>(!filters.mapped||mapped.has(item.id))&&(!filters.platform||asArray(item.platforms).includes(filters.platform))&&(!q||`${item.id} ${item.name}`.toLowerCase().includes(q)));
    return asArray(catalog.tactics).slice().sort((a,b)=>a.order-b.order).map(tactic=>({tactic,items:visible.filter(item=>asArray(item.tactics).includes(tactic.id)||asArray(item.tactics).includes(tactic.shortname)).map(item=>({...item,mapped:mapped.has(item.id)}))}));
  }
  async function loadCatalog(scope,alive=scope.alive) {
    let offset=0,total=Infinity,result={tactics:[],techniques:[]};
    while(offset<total&&offset<2000){
      if(!alive())throw new DOMException('View closed','AbortError');
      const page=await scope.get(`/api/attack/catalog?offset=${offset}&limit=100`);
      if(!Number.isInteger(page.total)||page.total<0||!Array.isArray(page.techniques))throw new Error('ATT&CK 카탈로그 응답을 확인할 수 없습니다.');
      if(offset===0)result={...page,techniques:[]};
      total=page.total;result.techniques.push(...page.techniques);
      if(!page.techniques.length&&offset<total)throw new Error('ATT&CK 카탈로그가 전체 목록 전에 중단되었습니다.');
      offset+=page.techniques.length;
    }
    result.truncated=offset<total;result.total=total;return result;
  }
  async function mountMatrix(host,{scope,context}) {
    host.innerHTML='<div class="iv-loading">Enterprise ATT&CK 카탈로그를 불러오는 중…</div>';
    let active=true,catalog;
    const alive=()=>active&&scope.alive()&&host.isConnected;
    try{catalog=await loadCatalog(scope,alive);}catch(err){if(alive())host.innerHTML=error(err.message);return()=>{active=false;};}
    if(!alive())return()=>{active=false;};
    const platforms=[...new Set(catalog.techniques.flatMap(item=>asArray(item.platforms)))].sort();
    host.innerHTML=`<section class="iv-panel"><div class="iv-panel-head"><div><span class="iv-kicker">ENTERPRISE ATT&CK MATRIX</span><h3>근거에 연결된 공격 기술</h3><p>강조된 셀만 이 사건에 저장된 탐지 정책의 기술 매핑입니다.</p></div><span class="iv-muted">${h(catalog.version||'')} · ${h(catalog.domain||'enterprise-attack')}</span></div>${context?._error?error(context._error):''}${asArray(context?.warnings).map(text=>note(text,true)).join('')}<div class="iv-toolbar">${field('기술 검색','mitre_search','','placeholder="T1059 또는 기술명"')}${select('플랫폼','mitre_platform',[['','모든 플랫폼'],...platforms.map(p=>[p,p])])}<label class="iv-check"><input type="checkbox" name="mitre_mapped">사건에 연결된 기술만</label></div><div class="iv-catalog-count" data-matrix-count></div><div class="iv-matrix-scroll" tabindex="0" role="region" aria-label="Enterprise ATT&CK 매트릭스 · 좌우 스크롤"><div class="iv-matrix" data-matrix></div></div>${note('MITRE ATT&CK는 기술별 심각도나 위협 점수를 제공하지 않습니다. 이 화면의 사건 심각도와 점수는 별도의 실제 탐지 근거에서 산출합니다. 매핑은 공격 성공 또는 인과관계의 증거가 아닙니다.')}${catalog.truncated?note(`카탈로그 ${catalog.total}개 중 최대2000개까지만 조회했습니다.`,true):''}</section>`;
    function paint(){const model=matrixModel(catalog,context,{search:value(host,'mitre_search'),platform:value(host,'mitre_platform'),mapped:!!host.querySelector('[name="mitre_mapped"]').checked});host.querySelector('[data-matrix]').innerHTML=model.map(({tactic,items})=>`<section class="iv-tactic"><div class="iv-tactic-head"><strong>${h(tactic.name)}</strong><small>${h(tactic.id)} · 연결 ${items.filter(x=>x.mapped).length}/${items.length}</small></div>${items.map(item=>`<button type="button" class="iv-tech" data-technique="${h(item.id)}" data-mapped="${item.mapped}" data-sub="${!!item.is_subtechnique}"><b>${h(item.id)}</b>${h(item.name)}</button>`).join('')}</section>`).join('');host.querySelector('[data-matrix-count]').textContent=`${catalog.techniques.length}개 기술 카탈로그 · 사건 연결 ${techniquesOf(context).length}개 · 전술별 중복 표기 가능`;}
    const filter=()=>paint();const click=event=>{const btn=event.target.closest('[data-technique]');if(!btn)return;const item=catalog.techniques.find(t=>t.id===btn.dataset.technique),evidence=techniquesOf(context).find(t=>t.id===item.id);dialog(scope,`${item.id} · ${item.name}`,details([['사건 근거 매핑',evidence?'연결됨':'없음'],['전술',item.tactics.join(', ')],['플랫폼',item.platforms.join(', ')],['근거 기여 수',evidence?.contribution_count??'—']])+`<p class="iv-description">${h(item.description||'공식 기술 설명은 아래 링크에서 확인하세요.')}</p>${typeof item.url==='string'&&item.url.startsWith('https://attack.mitre.org/')?`<a class="iv-link" href="${h(item.url)}" target="_blank" rel="noopener noreferrer">MITRE 공식 기술 문서 열기</a>`:''}`+(evidence?note('이 연결은 사건에 저장된 정책 메타데이터입니다. 독립적인 ATT&CK 판정이나 기술별 심각도가 아닙니다.'):''));};
    host.addEventListener('input',filter);host.addEventListener('change',filter);host.addEventListener('click',click);paint();
    return()=>{active=false;host.removeEventListener('input',filter);host.removeEventListener('change',filter);host.removeEventListener('click',click);catalog=null;};
  }
  function targetAction(event,type,context={}) {
    if(event?.response_eligible!==true)return null;
    if(context.agent&&event.verified_agent_id!==context.agent.id)return null;
    if(['terminate_process','inspect_process'].includes(type)){
      const proc=event?.process;
      if(!proc||typeof proc.guid!=='string'||!proc.guid||!Number.isInteger(proc.pid)||proc.pid<=0||typeof proc.start_identity!=='string'||!proc.start_identity)return null;
      return {type,process_guid:proc.guid,pid:proc.pid,start_identity:proc.start_identity};
    }
    if(['delete_file','inspect_file','collect_artifact','quarantine_file','restore_file'].includes(type)){
      const file=event?.file;
      if(!file||typeof file.path!=='string'||!(/^[A-Za-z]:\\/.test(file.path)||file.path.startsWith('/'))||typeof file.sha256!=='string'||!/^[0-9a-fA-F]{64}$/.test(file.sha256))return null;
      const action={type,path:file.path,sha256:file.sha256};
      if(type==='restore_file'){
        const prior=asArray(context.commands).find(c=>c.agent_id===context.agent?.id&&c.action?.type==='quarantine_file'&&c.action.path===file.path&&c.action.sha256.toLowerCase()===file.sha256.toLowerCase()&&/^[0-9a-f]{32}$/.test(c.result?.data?.quarantine_id||''));
        if(!prior)return null;action.quarantine_id=prior.result.data.quarantine_id;
      }
      return action;
    }
    if(['isolate_host','release_host'].includes(type)){
      const digest=context.agent?.response_reported?.management_allowlist_digest;
      if(!/^[0-9a-f]{64}$/.test(digest||''))return null;
      const action={type,management_allowlist_digest:digest};
      if(type==='release_host'){
        const prior=asArray(context.commands).find(c=>c.agent_id===context.agent?.id&&c.action?.type==='isolate_host'&&/^[0-9a-f]{32}$/.test(c.result?.data?.isolation_id||''));
        if(!prior)return null;action.isolation_id=prior.result.data.isolation_id;
      }
      return action;
    }
    return null;
  }
  function actionTargetRows(action,event){
    if(['terminate_process','inspect_process'].includes(action?.type))return [['프로세스',event?.process?.name],['실행 파일',event?.process?.executable],['PID',action.pid],['GUID',action.process_guid],['시작 신원',action.start_identity]];
    if(['isolate_host','release_host'].includes(action?.type))return [['대상 호스트',event?.host],['관리 통신 허용 목록 SHA256',action.management_allowlist_digest],...(action.isolation_id?[['격리 영수증',action.isolation_id]]:[])];
    return [['대상 절대 경로',action?.path],['원본 SHA256',action?.sha256],...(action?.quarantine_id?[['격리 영수증',action.quarantine_id]]:[])];
  }
  function commandOutcome(command){
    const result=command?.result;
    if(command?.state==='succeeded'&&!(result?.success===true&&(result?.executed===true||(['inspect_process','inspect_file','collect_artifact'].includes(command?.action?.type)&&result?.executed===false))))return {state:'unknown',label:'성공 근거 확인 필요'};
    return {state:command?.state||'unknown',label:command?.state==='succeeded'&&result?.executed===false?'조사 / 증거 수집 완료':commandLabels[command?.state]||command?.state||'상태 미확인'};
  }
  async function mountResponse(host,{scope,incident}){
    let active=true,data=null,requestBody='',requestId='';
    const alive=()=>active&&scope.alive()&&host.isConnected;
    if(!canRespond()){host.innerHTML=note('실제 장비 대응과 명령 기록은 분석가 또는 관리자 권한이 필요합니다.');return()=>{active=false;};}
    const route=`/api/incidents/${enc(incident.id)}/agent-response`;
    host.innerHTML='<div class="iv-loading">사건 근거와 일치하는 장비 및 대응 상태를 확인하는 중…</div>';
    const eventFor=(agentId,eventId)=>asArray(data?.events).find(event=>event.event_id===eventId&&asArray(data?.agents).some(agent=>agent.id===agentId&&agent.host===event.host&&agent.index===event.index_name));
    function resultHTML(command,controls=true){const outcome=commandOutcome(command),result=command.result;return `<article class="iv-command"><div class="iv-command-top"><strong>${h(actionLabels[command.action?.type]||command.action?.type)} · ${h(command.host)}</strong><span class="iv-state" data-state="${h(outcome.state)}">${h(outcome.label)}</span></div><small>${h(command.id)} · 요청 ${h(command.requester)} · ${h(when(command.created))}</small>${details(actionTargetRows(command.action,{host:command.host}))}${result?details([['OS 동작 실행',result.executed===true?'실제 동작 실행 확인':result.executed===false?'실행하지 않음':'실행 여부 불명'],['결과 코드',result.code],['상세',result.detail]]):note('서버 대기/수신 상태는 실제 OS 동작 완료를 뜻하지 않습니다.')}${command.error?error(command.error):''}${result?.data?details(Object.entries(result.data).map(([key,value])=>[key,typeof value==='object'?JSON.stringify(value):value])):''}${result?.data?.server_artifact_id?`<a class="iv-link" href="/api/endpoint-artifacts/${enc(result.data.server_artifact_id)}/download">검증된 증거 파일 다운로드</a>`:''}${controls?`<div class="iv-actions">${button('최신 결과 확인','response-detail',`data-id="${h(command.id)}"`)}${['queued','claimed'].includes(command.state)?button('전송 취소','response-cancel',`data-id="${h(command.id)}"`,'iv-btn-danger'):''}</div>`:''}</article>`;}
    function paint(){
      const agents=asArray(data.agents);
      host.innerHTML=`<section class="iv-panel"><div class="iv-panel-head"><div><span class="iv-kicker">MANUAL ENDPOINT RESPONSE</span><h3>근거를 확인하고 장비에 수동 대응</h3><p>대상 장비와 원본 근거를 선택한 뒤 최종 확인을 거쳐 요청합니다.</p></div><div class="iv-actions"><a class="iv-btn" href="#yara?tab=collection&amp;incident_id=${enc(incident.id)}">YARA 바이너리 분석</a>${button('상태 새로 고침','response-refresh')}</div></div><div class="iv-response-flow"><span>Manual · 분석가 확인</span><i>→</i><span>Response · 정확한 대상 요청</span><i>→</i><span>Agent · 로컬 허용 검사</span><i>→</i><span>실제 OS 결과</span></div>${note('프로세스 종료는 한 번의 종료이며 영구 실행 차단은 아닙니다. 파일 삭제는 되돌릴 수 없고 격리는 별도 복원 영수증을 사용합니다. 호스트 격리는 관리 서버 통신을 확인한 뒤 적용하며 장비 로컬에서 해당 동작과 정확한 대상이 허용되어야 합니다.',true)}${agents.length?`<div class="iv-form-grid">${select('근거 호스트·인덱스와 일치하는 장비','response_agent',agents.map(agent=>[agent.id,`${agent.host} · ${agent.platform} · ${agent.index}`]))}${select('대응 동작','response_type',asArray(data.actions).filter(type=>Object.hasOwn(actionLabels,type)).map(type=>[type,actionLabels[type]]))}<div class="iv-wide" data-response-agent-info></div><div class="iv-wide">${select('저장된 원본 근거','response_event',[['','근거 선택']])}</div><div class="iv-wide" data-response-target></div><label class="iv-field iv-wide"><span>조치 사유</span><textarea name="response_reason" required maxlength="1000" placeholder="확인한 근거와 조치 사유를 적으세요."></textarea></label></div><div class="iv-actions iv-reason">${button('정확한 대상 확인 후 요청','response-confirm','','iv-btn-danger')}</div>`:empty('대응 가능한 등록 장비가 없습니다','사건 근거의 호스트·인덱스와 일치하는 실제 등록 장비가 있어야 합니다.')}${data.events_truncated?note(`원본 근거 목록은 최대${data.events_limit}개입니다. 추가 근거가 있어 현재 목록은 제한됩니다.`,true):''}${note(`요청 유효기간 ${data.ttl_seconds??300}초. 명령 성공은 에이전트가 실제 OS 효과를 확인한 경우에만 표시합니다. 이 조치가 사건을 자동 해결 상태로 바꾸지는 않습니다.`)}</section><section class="iv-panel"><div class="iv-panel-head"><h3>장비 대응 명령과 결과</h3><span class="iv-muted">${asArray(data.commands).length}개 표시</span></div><div class="iv-command-list">${asArray(data.commands).map(command=>resultHTML(command)).join('')||empty('요청한 장비 대응이 없습니다')}</div>${data.commands_truncated?note(`최근 최대${data.commands_limit}개 명령만 표시합니다.`,true):''}</section>`;
      if(agents.length)updateTarget(false);
    }
    function updateTarget(preserve){
      const agent=asArray(data.agents).find(item=>item.id===value(host,'response_agent')),type=value(host,'response_type'),eventSelect=host.querySelector('[name="response_event"]'),old=preserve?eventSelect.value:'';
      const events=asArray(data.events).filter(event=>event.host===agent?.host&&event.index_name===agent?.index&&targetAction(event,type,{commands:data.commands,agent}));
      eventSelect.innerHTML=options([['','원본 근거를 선택하세요'],...events.map(event=>[event.event_id,`${when(event.event_time)} · ${['terminate_process','inspect_process'].includes(type)?`${event.process.name||'프로세스'} · PID ${event.process.pid}`:event.file?.path||event.host}`])],events.some(event=>event.event_id===old)?old:'');
      const reported=agent?.response_reported,enabled=reported?.enabled===true&&asArray(reported.actions).includes(type);
      host.querySelector('[data-response-agent-info]').innerHTML=note(`${agent?.host||'—'} · 마지막 접촉 ${when(agent?.last_seen)} · 에이전트 보고: ${reported?.enabled===true?'대응 활성':'대응 비활성/미보고'}. 이 보고는 실제 동작 완료의 증거가 아닙니다.`,!enabled);
      const event=eventFor(agent?.id,eventSelect.value),target=targetAction(event,type,{commands:data.commands,agent});
      host.querySelector('[data-response-target]').innerHTML=target?details([['원천 확인','에이전트 인증 수집 · 서버 원본 증명 확인'],...actionTargetRows(target,event)]):note(events.length?'원본 근거를 선택하면 정확한 대상이 표시됩니다.':'이 장비·동작에 필요한 원본 신원이 없습니다. 프로세스는 GUID·PID·시작 신원, 파일은 절대 경로·SHA256이 모두 필요합니다.');
      host.querySelector('[data-iv="response-confirm"]').disabled=!enabled||!target;
    }
    async function load(){try{const fresh=await scope.get(route);if(!alive())return;data=fresh;paint();}catch(err){if(alive())host.innerHTML=error(`장비 대응 정보를 불러오지 못했습니다: ${err.message}`);}}
    async function confirm(){
      const agent=asArray(data.agents).find(item=>item.id===value(host,'response_agent')),event=eventFor(agent?.id,value(host,'response_event')),action=targetAction(event,value(host,'response_type'),{commands:data.commands,agent}),reason=value(host,'response_reason').trim();
      if(!agent||!event||!action)throw new Error('정확한 장비와 원본 근거를 선택하세요.');
      if(!reason||reason.length>1000)throw new Error('조치 사유를1~1000자로 입력하세요.');
      const body={agent_id:agent.id,evidence_event_id:event.event_id,case_version:data.case_version,reason,action};
      const bodyText=JSON.stringify(body);if(requestBody!==bodyText){requestBody=bodyText;requestId=crypto.randomUUID();}
      const targetRows=actionTargetRows(action,event);
      dialog(scope,`${actionLabels[action.type]} · 최종 확인`,note(({terminate_process:'정확한 프로세스 인스턴스를 한 번 종료합니다. 작업이 중단될 수 있습니다.',delete_file:'파일을 실제 삭제합니다. 삭제는 되돌릴 수 없습니다.',quarantine_file:'파일을 보호된 격리 저장소로 이동합니다. 복원에는 결과 영수증이 필요합니다.',restore_file:'확인한 격리 영수증과 SHA256으로 원본 파일을 복원합니다.',isolate_host:'호스트 네트워크를 격리합니다. 관리 서버 통신 확인과 로컬 허용이 필요합니다.',release_host:'확인한 격리 영수증의 소유 규칙만 해제합니다.',collect_artifact:'허용된 증거 파일을 수집해 이 서버로 전달합니다.',inspect_process:'정확한 실행 인스턴스 정보를 읽기 전용으로 조사합니다.',inspect_file:'원본 SHA256과 파일 정보를 읽기 전용으로 조사합니다.'})[action.type],true)+`<div class="iv-confirm-target"><strong>요청할 정확한 대상</strong>${details([['장비',`${agent.host} (${agent.id})`],['인덱스',agent.index],['근거 이벤트',event.event_id],...targetRows,['조치 사유',reason]])}</div><label class="iv-check"><input type="checkbox" name="confirm_response" required>대상과 결과를 확인했으며 실제 장비 동작을 요청합니다.</label>`,async node=>{
        if(!node.querySelector('[name="confirm_response"]').checked)throw new Error('정확한 대상과 실제 동작을 확인해 주세요.');
        const command=await scope.send(route,{...body,request_id:requestId});requestBody='';requestId='';if(!alive())return;V.notify(`장비 대응 요청을 기록했습니다: ${commandLabels[command.state]||command.state}. 실제 결과를 확인하세요.`);await load();
      },'실제 장비에 요청');
    }
    const change=event=>{if(['response_agent','response_type','response_event'].includes(event.target.name))updateTarget(event.target.name==='response_event');};
    const click=event=>{const btn=event.target.closest('[data-iv]');if(!btn)return;scope.run(async()=>{const action=btn.dataset.iv;if(action==='response-refresh')await load();if(action==='response-confirm')await confirm();if(action==='response-cancel'){await scope.send(`/api/agent-responses/${enc(btn.dataset.id)}/cancel`,{});await load();V.notify('취소 결과를 기록했습니다. 이미 실행된 효과는 되돌리지 않습니다.');}if(action==='response-detail'){const command=await scope.get(`/api/agent-responses/${enc(btn.dataset.id)}`);if(alive())dialog(scope,'장비 대응의 최신 결과',resultHTML(command,false)+details([['원본 근거',command.evidence_event_id],['조치 사유',command.reason],['시작',when(command.started)],['완료',when(command.finished)]]));}},btn);};
    host.addEventListener('change',change);host.addEventListener('click',click);await load();
    return()=>{active=false;data=null;requestBody='';requestId='';host.removeEventListener('change',change);host.removeEventListener('click',click);};
  }
  function viewScope(container){const controller=new AbortController(),identity=`${V.session()?.name}|${V.session()?.tenant}`;let active=true;const cleanup=[];const scope={container,alive:()=>active&&identity===`${V.session()?.name}|${V.session()?.tenant}`,get:async path=>{const result=await V.api(path,{signal:controller.signal});if(!scope.alive())throw new DOMException('View closed','AbortError');return result;},send:async(path,body,method='POST')=>{if(!scope.alive())throw new DOMException('View closed','AbortError');const result=await V.post(path,body,method);if(!scope.alive())throw new DOMException('View closed','AbortError');return result;},track:fn=>cleanup.push(fn),async run(fn,trigger){if(trigger?.disabled)return;if(trigger)trigger.disabled=true;try{return await fn();}catch(err){if(scope.alive()&&err.name!=='AbortError')V.notify(err.message);}finally{if(trigger?.isConnected)trigger.disabled=false;}},close(){active=false;controller.abort();cleanup.splice(0).forEach(fn=>fn());container.replaceChildren();}};return scope;}
  async function mountHold(host,{scope,incident,onChange}) {
    const route='/api/logs/cases/'+enc(incident.id)+'/hold'; let active=true,data;
    const alive=()=>active&&scope.alive()&&host.isConnected;
    async function load(){data=await scope.get(route);if(!alive())return;
      const allowed=V.session()?.role==='admin';
      host.innerHTML=`<section class="iv-panel"><div class="iv-panel-head"><div><span class="iv-kicker">ORIGINAL EVIDENCE PRESERVATION</span><h3>사건 원본 로그 보존</h3><p>현재 사건 근거의 원본을 자동 보존 삭제에서 제외합니다.</p></div>${button('상태 새로 고침','hold-refresh')}</div>${details([['현재 사건 근거',data.evidence_count+'개'],['원본 확인',data.originals_available+'개'],['현재 근거 중 보존',data.held_current_evidence+'개'],['아직 보존하지 않은 근거',data.unheld_current_evidence+'개'],['원본 누락',data.missing_originals+'개'],['사건 버전',data.version]])}${asArray(data.indexes).length?details(data.indexes.map(i=>[i.index,i.held+'개 보존'])):''}${note('보존은 지금 연결된 근거에 적용됩니다. 추가 근거가 생기면 다시 보존하세요. 로컬 보존 정책이며 외부 불변 저장소 잠금과는 별개입니다.')}${data.missing_originals?note('일부 원본이 이미 삭제되어 전체 근거를 보존할 수 없습니다. 저장된 북마크만으로 원본 보존을 대신하지 않습니다.',true):''}<div class="iv-actions">${allowed?button('현재 근거 보존','hold-apply',data.missing_originals||!data.evidence_count?'disabled':'','iv-btn-primary')+button('보존 해제','hold-release',data.active?'':'disabled'):'<span class="iv-muted">보존 변경은 관리자 권한이 필요합니다.</span>'}</div></section>`;
    }
    const click=e=>{const b=e.target.closest('[data-iv]');if(!b)return;scope.run(async()=>{
      if(b.dataset.iv==='hold-refresh')return load();
      if(!['hold-apply','hold-release'].includes(b.dataset.iv))return;
      const release=b.dataset.iv==='hold-release',version=data.version;
      dialog(scope,release?'사건 원본 보존 해제':'현재 사건 근거 보존',`<p>${h(release?'보존 해제 후에는 설정된 수명주기에 따라 원본이 삭제될 수 있습니다.':'현재 원본 '+data.evidence_count+'개를 보존합니다.')}</p>${field('변경 사유','hold_reason','','required maxlength="1000"')}`,async node=>{
        await scope.send(route,{version,reason:value(node,'hold_reason').trim()},release?'DELETE':'PUT');await load();V.notify(release?'사건 원본 보존을 해제했습니다.':'현재 사건 원본을 보존했습니다.');if(onChange)await onChange();
      },release?'보존 해제':'원본 보존');
    },b);};
    host.addEventListener('click',click);await load();
    return()=>{active=false;data=null;host.removeEventListener('click',click);};
  }
  function policyPreviewHTML(policy){
    if(!policy)return '';
    const conditionValue=filter=>{if(filter.op==='typed_in'){try{return JSON.parse(filter.value).map(item=>`${typeof item==='number'?'숫자':'문자'}: ${String(item)}`).join(' · ');}catch(_){return '목록 값 확인 필요';}}return String(filter.value);};
    return `<section class="iv-panel"><h3>실제 가져올 정책 조건</h3>${details([['연결 기준',policy.entity_field],['시간 범위',`${policy.window}초`],['실행 간격',`${policy.interval}초`],['중복 알림 대기',`${policy.cooldown}초`],['기본 실행 상태','비활성']])}${asArray(policy.steps).map((step,index)=>`<article class="iv-command"><strong>${index+1}. ${h(step.name)}</strong><p>최소 ${h(step.min_count)}개${step.within_seconds?` · 직전 단계 이후 ${h(step.within_seconds)}초 이내`:''}</p><div class="wf-table-wrap"><table class="wf-table"><thead><tr><th>원본 필드</th><th>비교</th><th>값</th></tr></thead><tbody>${asArray(step.filters).map(filter=>`<tr><td>${h(filter.field)}</td><td>${h(filter.op)}</td><td>${h(filter.field==='index'?'가져오기에서 선택할 정확한 인덱스':conditionValue(filter))}</td></tr>`).join('')}</tbody></table></div></article>`).join('')}</section>`;
  }
  async function templates(container){
    const scope=viewScope(container);let page=null,summary=null,offset=0;const limit=50;
    container.innerHTML=`<div class="iv-page"><section class="iv-panel"><div class="iv-panel-head"><div><span class="iv-kicker">DETECTION LIBRARY</span><h3>탐지 템플릿 라이브러리</h3><p>소스 조건과 변환 범위를 확인하고 비활성 정책으로 가져옵니다.</p></div></div><div class="iv-toolbar">${field('템플릿 검색','template_search','','placeholder="기술, 이름, 소스"')}${select('플랫폼','template_platform',[['','모든 플랫폼'],['windows','Windows'],['linux','Linux']])}${select('변환 지원','template_supported',[['','모두'],['true','정책 변환 가능'],['false','미지원']])}${button('검색','template-search','','iv-btn-primary')}</div><div data-template-summary></div>${note('라이브러리는 원본 탐지 의도의 제한된 변환입니다. 가져오기는 예약 실행이 꺼진 초안을 만듭니다. 실제 로그 필드·인덱스·오탐과 누락을 검토하고 테스트한 뒤 별도로 활성화하세요.')}<div data-template-results></div></section></div>`;
    async function load(){container.querySelector('[data-template-results]').innerHTML='<div class="iv-loading">템플릿을 불러오는 중…</div>';const query=new URLSearchParams({offset:String(offset),limit:String(limit)});for(const [name,key]of [['template_search','search'],['template_platform','platform'],['template_supported','supported']])if(value(container,name))query.set(key,value(container,name));[page,summary]=await Promise.all([scope.get('/api/rule-templates?'+query),summary?Promise.resolve(summary):scope.get('/api/rule-templates/summary').catch(()=>null)]);if(!scope.alive())return;if(summary)container.querySelector('[data-template-summary]').innerHTML=details([['전체 라이브러리',`${summary.total}개`],['정책 변환 가능',`${summary.supported}개`],['미지원',`${summary.unsupported}개`],['테넌트 정책 한도',`${summary.policy_limit_per_tenant}개`],['ATT&CK 카탈로그',summary.catalog_version]]);const items=asArray(page.items);container.querySelector('[data-template-results]').innerHTML=`<div class="iv-catalog-count">전체 ${h(page.total)}개 · ${h(items.length?offset+1:0)}–${h(offset+items.length)} 표시</div><div class="iv-template-grid">${items.map(item=>`<article class="iv-template-card"><div class="iv-template-tags"><span>${h(item.platform)}</span><span>${h(item.pack)}</span><span>${item.supported?'정책 변환 가능':'변환 미지원'}</span></div><h3>${h(item.name)}</h3><p>${h(item.description||'')}</p><div class="iv-template-tags">${asArray(item.mitre).map(id=>`<span>${h(id)}</span>`).join('')}</div><div class="iv-actions">${button('조건과 근거 보기','template-open',`data-id="${h(item.id)}"`)}${button('실제 로그 검증','template-verify',`data-id="${h(item.id)}" ${!item.supported||!canRespond()?'disabled':''}`)}${button('비활성 정책으로 가져오기','template-import',`data-id="${h(item.id)}" ${!item.supported||!canRespond()?'disabled':''}`,'iv-btn-primary')}</div></article>`).join('')||empty('조건에 맞는 템플릿이 없습니다')}</div><div class="iv-pagination"><span>가져오기는 정책을 실행하지 않습니다.</span><div class="iv-actions">${button('이전','template-prev',offset?'':'disabled')}${button('다음','template-next',offset+items.length<page.total?'':'disabled')}</div></div>`;}
    async function open(id,apply){const item=await scope.get('/api/rule-templates/'+enc(id));if(!scope.alive())return;const unsupported=asArray(item.unsupported_reasons),adaptation=asArray(item.adaptation_notes);const html=details([['원본 분류',item.kind],['플랫폼',item.platform],['패키지',item.pack],['정책 심각도',severityLabels[item.severity]||item.severity],['MITRE 기술',asArray(item.mitre).join(', ')],['변환',item.supported?'정책 변환 가능':'미지원'],['원본 기본 실행 상태',item.source_default_enabled===true?'활성':item.source_default_enabled===false?'비활성':'미제공'],['현장 센서·필드 검증',item.telemetry_verified===true?'서버 표기 검증됨':'미검증 · 실제 로그로 확인 필요'],['원본 실행 의미와 동일',item.source_semantics_equal===true?'서버 표기 동일':'동일하지 않음 · 명시된 제한 변환']])+`<p class="iv-description">${h(item.description||'')}</p>`+policyPreviewHTML(item.policy_preview)+adaptation.map(text=>note(text)).join('')+unsupported.map(text=>note(text,true)).join('')+(apply?`<div class="iv-form-grid">${field('적용할 정확한 인덱스','template_index','','required maxlength="64" pattern="[A-Za-z0-9_-]{1,64}"')}</div><label class="iv-check"><input type="checkbox" name="accept_adaptation" required>변환 한계와 실제 필드 검토가 필요함을 확인했습니다.</label>`:'');dialog(scope,item.name,html,apply?async node=>{if(!node.querySelector('[name="accept_adaptation"]').checked)throw new Error('변환 범위를 확인해 주세요.');const result=await scope.send(`/api/rule-templates/${enc(id)}/apply`,{index:value(node,'template_index'),accept_adaptation:true});if(result.enabled!==false)throw new Error('가져온 정책의 비활성 상태를 확인하지 못했습니다. 정책 화면에서 상태를 확인하세요.');V.notify('비활성 정책으로 가져왔습니다. 실제 로그로 검증한 뒤 활성화하세요.');V.navigate('policies');}:null,'비활성 초안 만들기');}
    async function verify(id){
      const item=await scope.get('/api/rule-templates/'+enc(id));if(!scope.alive())return;
      const node=dialog(scope,`${item.name} · 실제 로그 검증`,note('권한이 있는 원본 로그를 양성·정상 사례로 구분해 검증합니다. 이 사례의 정밀도·재현율이며 전체 공격이나 센서 보장을 의미하지 않습니다.')+`<div class="iv-form-grid">${field('정확한 인덱스','verify_index','','required pattern="[A-Za-z0-9_-]{1,64}"')}${field('조회 시작','verify_start','','required','datetime-local')}${field('조회 종료','verify_end','','required','datetime-local')}<label class="iv-field iv-wide"><span>탐지해야 할 이벤트 ID · 한 줄에 하나, 최대100개</span><textarea name="verify_positive" required rows="4"></textarea></label><label class="iv-field iv-wide"><span>정상 이벤트 ID · 한 줄에 하나, 최대100개</span><textarea name="verify_negative" required rows="4"></textarea></label></div><div data-readiness-result></div>`,async host=>{
        const ids=name=>value(host,name).split(/\s+/).filter(Boolean);const positive=ids('verify_positive'),negative=ids('verify_negative');
        if(!positive.length||!negative.length||positive.length>100||negative.length>100)throw new Error('양성·정상 이벤트 ID를 각각1~100개 입력하세요.');
        const result=await scope.send(`/api/rule-templates/${enc(id)}/readiness`,{index:value(host,'verify_index'),earliest:new Date(value(host,'verify_start')).getTime()/1000,latest:new Date(value(host,'verify_end')).getTime()/1000,positive_event_ids:positive,negative_event_ids:negative});
        const metrics=result.fixture_validation||{};host.querySelector('[data-readiness-result]').innerHTML=details([['사례 검증',metrics.passed?'통과':'실패 / 준비 필요'],['정밀도',metrics.precision],['재현율',metrics.recall],['오탐',metrics.false_positives??metrics.false_positive],['누락',metrics.false_negatives??metrics.false_negative],['필수 필드 관측',result.telemetry_prerequisites_observed?'충족':'미충족']])+details(Object.entries(result.field_present_events||{}).map(([name,count])=>[name,count+'개 관측']))+asArray(result.unobserved_fields).map(name=>note('미관측 필드: '+name,true)).join('');return false;
      },'사례 검증 실행');
      const local=date=>new Date(date.getTime()-date.getTimezoneOffset()*60000).toISOString().slice(0,16);node.querySelector('[name="verify_start"]').value=local(new Date(Date.now()-3600000));node.querySelector('[name="verify_end"]').value=local(new Date((Math.floor(Date.now()/60000)+1)*60000));
    }
    const click=event=>{const btn=event.target.closest('[data-iv]');if(!btn)return;scope.run(async()=>{const action=btn.dataset.iv;if(action==='template-search'){offset=0;await load();}if(action==='template-prev'){offset=Math.max(0,offset-limit);await load();}if(action==='template-next'){offset+=limit;await load();}if(action==='template-verify')await verify(btn.dataset.id);if(action==='template-open'||action==='template-import')await open(btn.dataset.id,action==='template-import');},btn);};container.addEventListener('click',click);scope.track(()=>container.removeEventListener('click',click));scope.track(()=>{page=null;});await scope.run(load);return()=>scope.close();
  }
  window.VatexInvestigation={header,loadContext,mountMatrix,mountResponse,mountHold,scoreOf,matrixModel,techniquesOf,targetAction,actionTargetRows,commandOutcome,policyPreviewHTML};
  V.register('templates',{title:'탐지 라이브러리',render:templates});
})();
