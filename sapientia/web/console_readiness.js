/* Operational qualification and authenticated enterprise telemetry workflows. */
(() => {
  'use strict';
  const V=window.Vatex;if(!V)return;
  const h=V.h,enc=encodeURIComponent,arr=v=>Array.isArray(v)?v:[];
  const kinds=[['response_twin','가상 대응 · 격리와 해제 복구'],['recovery_process','소프트웨어 장애 전환 · 백업 복원'],['integrity_bootstrap','외부 서명키 신뢰 등록 검토']];
  const split=v=>String(v||'').split(/[\s,]+/).filter(Boolean);
  const detail=value=>`<pre class="analysis-research-json">${h(JSON.stringify(value,null,2))}</pre>`;
  const btn=(action,id,label)=>`<button data-ready="${action}" data-id="${h(id)}">${h(label)}</button>`;
  function form(d){return Object.fromEntries(new FormData(d.querySelector('form')));}
  V.register('readiness',{title:'운영 검증 · 수집 품질',async render(el){
    let alive=true;
    const identity=()=>JSON.stringify([V.session()?.name,V.session()?.tenant,V.session()?.role,V.session()?.allowed_indexes]);
    const admittedIdentity=identity();
    const ensure=()=>{if(!alive||identity()!==admittedIdentity)throw Error('계정 또는 권한이 바뀌었습니다. 화면을 다시 여세요.');};
    const api=async(...args)=>{ensure();const result=await V.api(...args);ensure();return result;};
    const post=async(...args)=>{ensure();const result=await V.post(...args);ensure();return result;};
    const admin=V.session()?.role==='admin';
    const [status,plans,runs,slo,sources,pipe,integrity]=await Promise.all([
      api('/api/ops/qualification/status'),api('/api/ops/qualification/plans'),api('/api/ops/qualification/runs'),
      api('/api/ops/source-slo'),api('/api/v2/sources'),api('/api/ops/pipeline'),
      admin?api('/api/ops/integrity/status'):Promise.resolve({state:'관리자 조회'})]);
    if(!alive)return;
    const ps=arr(plans.items||plans),rs=arr(runs.items||runs),ss=arr(sources.items||sources);
    el.innerHTML=`<div class="inline-help">CPU 기반으로 분석합니다. 이 화면의 대응 시험은 별도 가상 장비에서 실행되며 실제 호스트 차단 명령을 보내지 않습니다. 실장비 인증·실서비스 연결 결과는 별도 검증이 필요합니다.</div>
    <div class="panel"><div class="panel-head"><h2>처리 흐름과 수집 품질</h2>${btn('refresh','','새로고침')}</div><p>색인 대기 ${h(pipe.queue?.events)}건 · 가장 오래된 대기 ${h(pipe.queue?.oldest_age_seconds?.toFixed(2))}초</p>${V.table(['수집원','서버 원본 영수증','상태','잠정 시퀀스 누락','수집 전 손실'],arr(slo.items).map(s=>[s.source_id,s.server_receipts,s.state,s.provisional_sequence_gaps??'시퀀스 계약 없음',s.pre_capture_loss]))}<details><summary>단계별 측정 결과 · 누락 표본 포함</summary>${detail(pipe.analysis?.metrics)}${detail(pipe.pipeline)}</details>${admin?ss.map(s=>btn('slo',s.id,`${s.product} 수집 품질 기준 설정`)).join(''):''}</div>
    <div class="panel"><div class="panel-head"><h2>운영 시험 계획 · 독립 승인</h2>${admin?btn('plan','','계획 추가'):''}</div><p>계획 작성자와 다른 관리자가 같은 개정을 검토한 뒤 실행할 수 있습니다. 검토 후 계획이나 권한이 바뀌면 다시 승인해야 합니다.</p>${ps.length?`<div class="table-scroll"><table><thead><tr><th>계획</th><th>종류</th><th>개정 · 상태</th><th>작업</th></tr></thead><tbody>${ps.map(p=>`<tr><td>${h(p.definition?.name)}</td><td>${h(kinds.find(k=>k[0]===p.definition?.kind)?.[1]||p.definition?.kind)}</td><td>${h(p.revision)} · ${h(p.state)}</td><td>${admin?btn('edit',p.id,'수정')+btn('review',p.id,'검토')+btn('run',p.id,'시험 실행'):''}</td></tr>`).join('')}</tbody></table></div>`:V.empty('등록된 시험 계획이 없습니다','가상 대응 또는 소프트웨어 복구 계획을 추가하세요.')}<details><summary>외부 서명 신뢰 상태</summary>${detail(integrity)}<p>공개 신뢰키는 에이전트 패키지 밖에 배포합니다. 패키지에 포함된 키를 자동으로 신뢰하지 않습니다.</p></details></div>
    <div class="panel"><h2>시험 기록</h2>${rs.length?rs.map(r=>`<div class="list-card"><div class="list-main"><strong>${h(r.id)}</strong><small>${h(r.state)} · ${V.date(r.updated||r.created)}</small></div>${btn('result',r.id,'결과 보기')}</div>`).join(''):V.empty('아직 실행한 시험이 없습니다')}</div>
    <div class="panel"><div class="panel-head"><h2>클라우드 · 사용자 · 메일 원본</h2>${admin?btn('source','','수집원 등록'):''}</div><p>Microsoft Entra 로그인, Microsoft 365 감사 및 AWS CloudTrail 원본을 등록된 테넌트·계정에 묶어 수집합니다. 이름이나 IP만으로 사용자 신원을 합치지 않습니다.</p>${ss.filter(s=>['entra_signin','m365_audit','cloudtrail'].includes(s.product)).map(s=>`<div class="list-card"><div class="list-main"><strong>${h(s.product)} · ${h(s.account)}</strong><small>${h(s.index)} · ${h(s.realm)} · ${h(s.state)}</small></div>${s.state==='active'?btn('intake',s.id,'원본 가져오기')+(admin&&s.product!=='cloudtrail'?btn('collect',s.id,'서비스에서 수집'):'')+btn('starter',s.id,'기본 탐지 초안 생성'):''}</div>`).join('')||V.empty('기업 서비스 수집원이 없습니다','실제 API 연결 자격 증명이 없으면 원본 파일로 수집 경로를 시험할 수 있습니다.')}</div>`;
    el.onclick=async e=>{const b=e.target.closest('[data-ready]');if(!b)return;const action=b.dataset.ready,id=b.dataset.id,p=ps.find(x=>x.id===id),s=ss.find(x=>x.id===id);b.disabled=true;
      try{
        ensure();
        if(action==='refresh'){await V.navigate('readiness');return;}
        if(action==='plan'||action==='edit')V.dialog({title:'운영 시험 계획',content:`<form>${V.field('계획 이름','name',p?.definition?.name||'','text','required maxlength="120"')}${V.field('허용 인덱스 · 쉼표 구분','indexes',(p?.indexes||['main']).join(', '),'text','required')}${V.select('시험 종류','kind',kinds,p?.definition?.kind||'response_twin')}</form>`,onSave:async d=>{const f=form(d);await post('/api/ops/qualification/plans'+(p?'/'+enc(p.id):''),{name:f.name,indexes:split(f.indexes),kind:f.kind,expected_revision:p?.revision||0},p?'PUT':'POST');await V.navigate('readiness');}});
        if(action==='review')V.dialog({title:'개정 '+p.revision+' 독립 검토',content:`<p>${h(p.definition?.name)} · ${h(p.owner)} 작성</p>${detail(p.definition)}<form>${V.select('검토 결과','approve',[['true','승인'],['false','거절']],'true')}${V.field('검토 근거','reason','','text','required minlength="3" maxlength="1000"')}</form>`,onSave:async d=>{const f=form(d);await post('/api/ops/qualification/plans/'+enc(id)+'/review',{expected_revision:p.revision,approve:f.approve==='true',reason:f.reason});await V.navigate('readiness');}});
        if(action==='run'){const result=await post('/api/ops/qualification/plans/'+enc(id)+'/run',{expected_revision:p.revision});if(alive)V.dialog({title:'운영 시험 결과',content:detail(result)});}
        if(action==='result'){const result=await api('/api/ops/qualification/runs/'+enc(id));if(alive)V.dialog({title:'운영 시험 기록',content:detail(result)});}
        if(action==='slo'){const current=arr(slo.items).find(x=>x.source_id===id),v=current?.definition||{};V.dialog({title:'서버 영수증 · 시퀀스 품질 기준',content:`<form>${V.field('최대 수신 공백 · 초','silence',v.max_silence_seconds||300,'number','required min="1" max="86400"')}${V.field('허용 잠정 누락 번호 수','gap',v.max_gap||0,'number','required min="0"')}${V.field('센서 보고 드롭 허용 수','drop',v.max_reported_drop||0,'number','required min="0"')}${V.field('시퀀스 원본 경로 · 선택','sequence',v.sequence_path||'')}${V.field('재시작 epoch 원본 경로 · 선택','epoch',v.epoch_path||'')}<p>시퀀스·epoch는 함께 설정합니다. 시퀀스가 없으면 누락률을 0으로 표시하지 않습니다.</p></form>`,onSave:async d=>{const f=form(d);await post('/api/ops/source-slo/'+enc(id),{expected_revision:current?.revision||0,source_version:s.version,sequence_path:f.sequence||null,epoch_path:f.epoch||null,max_silence_seconds:Number(f.silence),max_gap:Number(f.gap),max_reported_drop:Number(f.drop)},'PUT');await V.navigate('readiness');}});}
        if(action==='collect'){
          const info=await api('/api/ops/enterprise/sources/'+enc(id)+'/collector');
          if(!info.available){V.dialog({title:'서비스 수집 설정 상태',content:detail(info)});return;}
          const end=new Date(),start=new Date(end.getTime()-3600000);
          V.dialog({title:'기업 서비스 읽기 전용 수집',content:`<p>기존 서비스의 감사 원본만 조회합니다. 서비스 구독을 만들거나 변경하지 않습니다. 각 페이지의 영수증이 저장된 뒤 체크포인트를 진행합니다.</p><form>${V.field('시작 UTC','start',start.toISOString(),'text','required')}${V.field('종료 UTC','end',end.toISOString(),'text','required')}${V.field('현재 체크포인트 개정','checkpoint_version',info.checkpoint_version,'number','required min="0"')}${V.select('감사 콘텐츠','content_type',s.product==='m365_audit'?[['Audit.Exchange','Exchange'],['Audit.AzureActiveDirectory','Azure AD'],['Audit.General','General']]:[['signin','Entra sign-in']])}</form>`,onSave:async d=>{const f=form(d);const result=await post('/api/ops/enterprise/sources/'+enc(id)+'/collector/collect',{source_version:s.version,checkpoint_version:Number(f.checkpoint_version),start:f.start,end:f.end,content_type:s.product==='m365_audit'?f.content_type:null});V.dialog({title:'서비스 수집 결과',content:detail(result)});}});
        }
        if(action==='source')V.dialog({title:'기업 서비스 수집원 등록',content:`<form>${V.select('서비스','product',[['entra_signin','Microsoft Entra 로그인'],['m365_audit','Microsoft 365 감사'],['cloudtrail','AWS CloudTrail']])}${V.field('대상 테넌트 GUID 또는 AWS 계정','account','','text','required')}${V.field('인덱스','index','enterprise','text','required')}${V.field('관리 영역','realm','virtual-lab','text','required')}${V.field('환경 변수 참조','credential_ref','env:SAPIENTIA_CONNECTOR_ENTERPRISE','text','required')}</form>`,onSave:async d=>{await post('/api/v2/sources',{...form(d),version:0});await V.navigate('readiness');}});
        if(action==='intake')V.dialog({title:'인증 수집원 원본 가져오기',content:`<p>Entra는 각 항목에 tenant_id와 record 원본이 필요합니다. Microsoft 365와 CloudTrail은 개별 원본 객체 배열을 사용합니다.</p><form><label>원본 JSON 배열<textarea name="events" rows="10" required>[]</textarea></label>${V.field('재전송 시 유지할 커서','cursor','','text','required maxlength="1024"')}${V.field('현재 체크포인트 개정','checkpoint',0,'number','required min="0"')}</form>`,onSave:async d=>{const f=form(d);const result=await post('/api/v2/sources/'+enc(id)+'/intake',{version:s.version,events:JSON.parse(f.events),cursor:f.cursor,checkpoint_version:Number(f.checkpoint)});V.notify(`원본 ${result.accepted}건 영수증 저장 · 중복 ${result.duplicate}건`);await V.navigate('readiness');}});
        if(action==='starter'){const definition=await api('/api/ops/enterprise/sources/'+enc(id)+'/starter');V.dialog({title:'기본 탐지 초안 확인',content:`<p>보고된 위험 로그인 또는 관리 변경을 조사 대상으로 올립니다. 악성 확정 규칙이 아니므로 예외·대상을 검토하세요. 저장 후 탐지 관리에서 다른 분석가의 승인이 필요합니다.</p>${detail(definition)}`,onSave:async()=>{await post('/api/v3/intelligence/policies',definition);V.notify('탐지 초안을 저장했습니다. 독립 검토 후 활성화하세요.');await V.navigate('intelligence');}});}
      }catch(err){V.notify(err.message);}finally{if(b.isConnected)b.disabled=false;}
    };
    return()=>{alive=false;el.onclick=null;};
  }});
})();
