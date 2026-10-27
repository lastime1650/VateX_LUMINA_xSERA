/* Native endpoint enrollment and distribution. Secrets remain in one-time ZIPs. */
(() => {
  'use strict';
  const V=window.Vatex, h=V.h, enc=encodeURIComponent;
  const platforms={windows:{label:'Windows',mark:'⊞'},linux:{label:'Linux',mark:'◈'}};
  const role=()=>V.session()?.role;
  const admin=()=>role()==='admin';
  const canDownload=()=>['admin','analyst'].includes(role());
  const date=v=>v?new Date(Number(v)*1000).toLocaleString('ko-KR'):'—';
  const state=v=>({pending:'등록 대기',active:'등록됨',online:'연결됨',offline:'연결 지연',stale:'연결 지연',owner_permission_revoked:'소유자 권한 철회',revoked:'폐기됨',expired:'만료됨',registered:'등록 완료'})[v]||v||'미확인';
  const textList=v=>(Array.isArray(v)?v:[v]).filter(Boolean).map(x=>h(typeof x==='string'?x:JSON.stringify(x))).join(' · ');
  async function mount(root,{signal}={}) {
    let alive=true,status,deployments=[],agents=[],historyBounded=false,defenseCleanup;
    root.className='endpoint-fleet';
    root.innerHTML='<div class="loading">에이전트 배포 정보를 확인하는 중</div>';
    const controller=new AbortController(),abort=()=>controller.abort();
    if(signal?.aborted)abort();else signal?.addEventListener('abort',abort,{once:true});
    const opts={signal:controller.signal};
    async function binary(path,platform,method='GET') {
      const response=await V.api(path,{...opts,method,responseType:'binary',...(method==='POST'?{body:'{}'}:{})});
      if(!alive)return;
      const bytes=response.bytes;if(bytes.byteLength>32*1024*1024)throw Error('예상한 패키지 크기를 초과했습니다.');
      const expected=response.headers.get('X-Package-SHA256');
      if(!expected||!/^[a-f0-9]{64}$/.test(expected))throw Error('패키지 검증 해시가 없습니다.');
      if(!crypto.subtle)throw Error('이 브라우저는 패키지 해시 검증을 지원하지 않습니다. HTTPS 또는 로컬 콘솔을 사용하세요.');
      const actual=[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(b=>b.toString(16).padStart(2,'0')).join('');
      if(actual!==expected)throw Error('패키지 SHA-256이 일치하지 않습니다. 다운로드를 중단했습니다.');
      const given=/filename="([A-Za-z0-9_.-]{1,120})"/.exec(response.headers.get('Content-Disposition')||'')?.[1];
      const name=given||`sera-endpoint-${platform}.zip`,url=URL.createObjectURL(new Blob([bytes],{type:'application/zip'}));
      const link=document.createElement('a');link.href=url;link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
      const result=root.querySelector('[data-download-result]');if(result)result.textContent=`${name} · SHA-256 확인 완료`;
      V.notify('검증된 에이전트 패키지를 다운로드했습니다. 압축 안의 설치 안내를 확인하세요.');
    }
    function draw() {
      const packages=status.generic_packages||[];
      root.innerHTML=`${historyBounded?'<div class="notice">활성 장비·유효한 등록 요청을 우선 표시하며, 각 목록은 최대 1,000개입니다. 이전 이력 일부는 표시하지 않습니다.</div>':''}<section class="panel endpoint-downloads"><div class="panel-head"><h2>엔드포인트 에이전트<small>운영체제별 설치 · 장비별 인증 · 수집 근거</small></h2><button type="button" data-fleet-refresh>연결 상태 새로고침</button></div><div class="endpoint-package-grid">${Object.entries(platforms).map(([platform,p])=>{const pkg=packages.find(x=>x.platform===platform);return `<article class="endpoint-package"><span class="endpoint-platform" aria-hidden="true">${p.mark}</span><div><h3>${p.label}</h3><p>Python ${h(status.python_minimum||'3.10')}+ · 소스 런타임 ZIP</p><small>${textList(pkg?.prerequisites||status.prerequisites?.[platform])||'Python 설치 및 해당 운영체제 필요'}</small></div><button type="button" class="primary" data-generic="${platform}" ${!canDownload()||!pkg?'disabled':''}>${p.label} 에이전트 다운로드</button><details><summary>패키지 정보</summary><p>${textList(pkg?.collections||status.collections?.[platform])||'읽기 전용 수집'}</p><p>${textList(pkg?.limits||status.limits)}</p><code class="endpoint-digest">SHA-256 ${h(pkg?.sha256||'미제공')}</code></details></article>`;}).join('')}</div><p class="field-note" data-download-result role="status">공통 설치본은 등록 키를 포함하지 않습니다. 장비 연결에는 등록용 설치본이 필요합니다.${!canDownload()?' 다운로드는 분석가·관리자 권한이 필요합니다.':''}</p></section><section class="panel endpoint-enrollment"><div class="panel-head"><h2>장비 등록<small>수집 대상 호스트와 인덱스를 서버에서 고정합니다.</small></h2>${admin()?`<button type="button" data-create-deployment ${!status.deployment_enabled?'disabled':''}>+ 등록용 설치본 만들기</button>`:''}</div><div class="sequence"><div>① 운영체제·호스트·인덱스 선택</div><span aria-hidden="true">→</span><div>② 등록용 설치본 다운로드</div><span aria-hidden="true">→</span><div>③ 장비에서 설치 · 첫 등록</div></div>${status.deployment_enabled?`<div class="endpoint-server"><span class="dot"></span><span>등록 서버</span><code>${h(status.endpoint_url)}</code></div>`:`<div class="notice">서버의 HTTPS 주소와 공개 CA 인증서를 설정하면 장비별 등록용 설치본을 만들 수 있습니다.${status.reason?`<details><summary>설정 상태</summary><p>${h(status.reason)}</p></details>`:''}</div>`}${!admin()?'<p class="field-note">관리자가 등록용 설치본을 생성합니다.</p>':''}<div class="endpoint-table-scroll"><table><thead><tr><th>등록 요청</th><th>호스트 · 인덱스</th><th>만료</th><th>상태</th><th>설치본</th></tr></thead><tbody>${deployments.map(d=>`<tr><td>${h(platforms[d.platform]?.label||d.platform)}<small>${h(String(d.id).slice(0,12))}</small></td><td>${h(d.host)}<small>${h(d.index)}</small></td><td>${date(d.expires_at)}</td><td>${h(state(d.status))}</td><td><button type="button" data-deployment="${h(d.id)}" data-platform="${h(d.platform)}" ${!admin()||d.status!=='pending'||Number(d.expires_at)<=Date.now()/1000?'disabled':''}>등록용 ZIP 다운로드</button></td></tr>`).join('')||'<tr><td colspan="5" class="muted">표시할 등록 요청이 없습니다.</td></tr>'}</tbody></table></div><p class="field-note">등록 키는 짧은 유효기간과 한 번의 등록에만 사용합니다. 설치본은 비밀 등록 키를 포함하므로 해당 장비에만 전달하세요. 첫 등록 전 재다운로드하면 이전 키가 교체됩니다. 장비 대응은 사건의 근거와 로컬 허용 설정을 확인합니다. 등록 폐기는 자격증명 폐기이며 OS 격리 해제와는 별개입니다.</p></section><section class="panel"><div class="panel-head"><h2>등록된 장비<small>현재 테넌트와 인덱스 권한으로 조회한 장비</small></h2><span class="badge">${agents.length}개 표시</span></div>${agents.length?`<div class="endpoint-table-scroll"><table><thead><tr><th>장비</th><th>운영체제</th><th>수집 인덱스</th><th>상태</th><th>마지막 통신</th><th>기능</th>${admin()?'<th>등록 관리</th>':''}</tr></thead><tbody>${agents.map(a=>`<tr><td><button type="button" class="subtle" data-endpoint-host="${h(a.host)}">${h(a.host)}</button><small>${h(a.version||'버전 미확인')}</small></td><td>${h(platforms[a.platform]?.label||a.platform)}</td><td>${h(a.index)}</td><td>${V.badge(['active','online'].includes(a.status)?'enabled':'info',state(a.status))}</td><td>${date(a.last_seen)}</td><td>${textList(a.collections)||'읽기 전용 수집'}</td>${admin()?`<td><button type="button" class="danger" data-revoke-agent="${h(a.id)}" ${a.status==='revoked'?'disabled':''}>등록 폐기</button></td>`:''}</tr>`).join('')}</tbody></table></div>`:V.empty('등록된 에이전트가 없습니다','등록용 설치본을 장비에 설치하면 인증된 수집 상태가 표시됩니다.')}</section>`;
    }
    async function refresh() {
      const tasks=[V.api('/api/xdr/agents/distribution',opts),V.api('/api/xdr/agents',opts),admin()?V.api('/api/xdr/agents/deployments',opts):Promise.resolve({deployments:[]})];
      const results=await Promise.all(tasks);if(!alive)return;
      [status]=results;historyBounded=!!(results[1].truncated||results[2].truncated);agents=results[1].agents||[];deployments=Array.isArray(results[2])?results[2]:results[2].deployments||[];defenseCleanup?.();draw();const defenseRoot=document.createElement('div');root.append(defenseRoot);if(window.VatexDefense&&['admin','analyst'].includes(V.session()?.role))defenseCleanup=await window.VatexDefense.mount(defenseRoot,{agents,signal:controller.signal});
    }
    function create() {
      const form=document.createElement('form');form.innerHTML=`<div class="form-grid">${V.select('운영체제','platform',[['windows','Windows'],['linux','Linux']],'windows')}${V.field('호스트 식별자','host','','text','required pattern="[A-Za-z0-9][A-Za-z0-9_.-]{0,127}" maxlength="128"')}${V.field('수집 인덱스','index','endpoint','text','required pattern="[A-Za-z0-9_-]{1,64}"')}${V.field('첫 등록 유효기간 (분)','ttl','15','number','required min="1" max="60" step="1"')}</div><p class="field-note">호스트 식별자는 해당 설치본을 사용할 장비에 고정됩니다. 등록·수집 권한은 현재 관리자 권한과 선택한 인덱스를 다시 확인합니다. 설치본을 만드는 것만으로 로그를 수집하지 않습니다.</p>`;
      const d=V.dialog({title:'장비 등록용 설치본 만들기',content:form,onSave:async()=>{const f=form.elements;const created=await V.post('/api/xdr/agents/deployments',{platform:f.platform.value,host:f.host.value.trim(),index:f.index.value.trim(),ttl_seconds:Number(f.ttl.value)*60});await refresh();V.notify(`${created.host} 등록 요청을 만들었습니다. 목록에서 등록용 ZIP을 다운로드하세요.`);}});d.querySelector('[data-save]').textContent='등록 요청 만들기';
    }
    root.addEventListener('click',async event=>{
      const b=event.target.closest('[data-generic],[data-deployment],[data-create-deployment],[data-fleet-refresh],[data-revoke-agent],[data-endpoint-host]');if(!b)return;
      try {
        if(b.dataset.generic){b.disabled=true;try{await binary('/api/xdr/agents/packages/'+enc(b.dataset.generic),b.dataset.generic);}finally{if(alive)b.disabled=!canDownload();}}
        else if(b.dataset.deployment){b.disabled=true;try{await binary('/api/xdr/agents/deployments/'+enc(b.dataset.deployment)+'/package',b.dataset.platform,'POST');await refresh();}finally{if(alive&&b.isConnected)b.disabled=false;}}
        else if(b.hasAttribute('data-create-deployment'))create();
        else if(b.hasAttribute('data-fleet-refresh')){b.disabled=true;try{await refresh();}finally{if(alive&&b.isConnected)b.disabled=false;}}
        else if(b.dataset.endpointHost){V.navigate('xdr',{host:b.dataset.endpointHost});}
        else if(b.dataset.revokeAgent){const target=agents.find(a=>a.id===b.dataset.revokeAgent);V.dialog({title:'장비 등록 폐기',content:`<p><strong>${h(target?.host)}</strong>의 수집 자격증명을 폐기합니다.</p><p class="field-note">폐기 후 새 이벤트 전송이 거부됩니다. 이미 저장된 조사 근거는 보존됩니다.</p>`,onSave:async()=>{await V.post('/api/xdr/agents/'+enc(b.dataset.revokeAgent),{},'DELETE');await refresh();V.notify('장비 등록을 폐기했습니다.');}});}
      }catch(error){if(error.name!=='AbortError')V.notify(error.message);}
    });
    try{await refresh();}catch(error){if(error.name!=='AbortError'&&alive)root.innerHTML=V.empty('에이전트 배포 정보를 불러오지 못했습니다',error.message);}
    return()=>{alive=false;defenseCleanup?.();controller.abort();signal?.removeEventListener('abort',abort);root.replaceChildren();};
  }
  window.VatexAgents={mount};
})();
