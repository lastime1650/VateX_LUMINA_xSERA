/* Log storage lifecycle and complete, scoped log exports. */
(() => {
  'use strict';
  const V = window.Vatex;
  if (!V) return;
  const h = V.h, enc = encodeURIComponent;
  const fmt = n => new Intl.NumberFormat('ko-KR').format(Number(n) || 0);
  const bytes = n => (Number(n) / 1048576).toFixed(1) + ' MiB';
  const field = (label, name, value='', type='text', attrs='') => `<label>${h(label)}<input name="${h(name)}" type="${type}" value="${h(value)}" ${attrs}></label>`;
  const date = n => new Date(n*1000).toLocaleString('ko-KR');
  function saveBlob(name, data) {
    const url = URL.createObjectURL(new Blob([data], {type:'application/x-ndjson'}));
    const link = document.createElement('a'); link.href=url; link.download=name; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  V.register('logmanage', {title:'로그 관리', async render(container) {
    const abort = new AbortController(), options={signal:abort.signal};
    let state, snapshot=null, after=0, next=null, busy=false;
    const admin = V.session().role === 'admin';
    const localTime = n => {const d=new Date(n*1000);return new Date(d-d.getTimezoneOffset()*60000).toISOString().slice(0,16);};
    const now=Date.now()/1000;
    container.innerHTML=`<div class="log-platform">
      <section class="panel"><div class="panel-head"><div><div class="eyebrow">LOG DATA PLATFORM</div><h2>저장부터 장기 보존까지</h2></div><button data-reload>상태 새로고침</button></div><div class="log-tiers" data-tiers></div><p class="muted">시간·인덱스별 분할 파일을 모든 저장 단계에서 함께 검색합니다. 전환 기준은 로그 수신 시각입니다.</p></section>
      <div class="log-workspace"><section class="panel"><div class="panel-head"><h2>전체 로그 검색 · 내보내기</h2></div><form data-search class="log-form">
        ${field('시작 시각','start',localTime(now-86400),'datetime-local','required')}${field('종료 시각','end',localTime(now+60),'datetime-local','required')}
        ${field('인덱스','index','','text','placeholder="허용된 전체 인덱스"')}${field('호스트','host','','text','placeholder="모든 호스트"')}
        ${field('소스','source','','text','placeholder="모든 소스"')}${field('전문 검색','fulltext','','text','placeholder="예: powershell AND credential" maxlength="1024"')}
        <div class="log-form-actions"><button class="primary" type="submit">검색 스냅샷 만들기</button><span class="muted">수집 중에도 고정된 결과를 끝까지 조회합니다.</span></div></form><div data-fulltext-status role="status" aria-live="polite"></div><div data-progress role="status"></div><div data-results></div></section>
      <section class="panel"><div class="panel-head"><h2>인덱스 수명주기</h2></div><div data-policies></div>${admin?`<form data-policy class="log-form">${field('인덱스 이름','policy_index','main','text','required pattern="[A-Za-z0-9_-]{1,64}"')}${field('Warm 전환 · 수신 후 일','hot_days',1,'number','required min="1" max="3647"')}${field('Cold 전환 · 수신 후 일','warm_days',7,'number','required min="2" max="3648"')}${field('Archive 전환 · 수신 후 일','cold_days',30,'number','required min="3" max="3649"')}${field('만료 삭제 · 수신 후 일','retention_days',90,'number','required min="4" max="3650"')}<label class="adm-check"><input name="hold" type="checkbox">자동 삭제 중지 · 보존 잠금</label><div class="log-form-actions"><button class="primary" type="submit">정책 저장</button><button type="button" data-maintain>지금 저장 단계 적용</button></div></form>`:'<p class="muted">보존 정책은 관리자가 변경합니다.</p>'}</section></div>
      <section class="panel"><div class="panel-head"><h2>검색 보관함 · 복구</h2></div><div data-snapshots></div>${admin && V.session().tenant==='default'?`<form data-backup-form class="log-form">${field('백업 암호','passphrase','','password','required minlength="12" maxlength="1024" autocomplete="new-password"')}${field('암호 확인','repeat','','password','required minlength="12" maxlength="1024" autocomplete="new-password"')}<div class="log-form-actions"><button type="submit" class="primary">서비스 실행 중 암호화 백업</button><span class="muted">암호는 서버에 저장하지 않습니다. 복원할 때 필요합니다.</span></div></form>`:''}<div data-backup-result role="status"></div><p class="muted">검색 스냅샷은 만료 시 삭제됩니다. 원본 로그의 보존 삭제가 발생하면 관련 파생 검색을 무효화합니다.</p></section>
      <div class="log-error error" role="alert" data-error hidden></div></div>`;
    const error = err => {if(err.name==='AbortError')return;const el=container.querySelector('[data-error]');el.hidden=false;el.textContent=err.message;};
    const val = (root,name) => root.elements[name].value.trim();
    const task = async fn => {if(busy)return;busy=true;container.querySelector('[data-error]').hidden=true;try{await fn();}catch(e){error(e);}finally{busy=false;}};
    async function reload() {
      state=await V.api('/api/logs/status',options);
      const tiers=state.storage.tiers;
      const ft=state.search.fulltext;
      if(ft){
        const name={ready:'준비 완료',indexing:'증분 색인 중',bootstrap_required:'초기 구축 필요',capacity_error:'저장 용량 확인 필요',error:'색인 점검 필요'}[ft.state]||'상태 확인 필요';
        const help=ft.state==='bootstrap_required'?'기존 로그의 전문 검색 색인을 구축해야 합니다. 서버 운영자에게 초기 구축을 요청하세요.':ft.state==='capacity_error'?'색인 저장 예산과 디스크 여유 공간을 확인하세요.':!ft.ready?'색인 준비 중에도 기간·인덱스·호스트로 로그를 검색할 수 있습니다.':'';
        container.querySelector('[data-fulltext-status]').innerHTML=`<div class="list-card"><div class="list-main"><strong>전문 검색 · ${h(name)}</strong><small>${fmt(ft.pending_documents)}건 대기 · 지연 ${fmt(Math.ceil(Number(ft.lag_seconds)||0))}초 · 저장 예산 ${(Number(ft.budget_bytes)/1073741824).toFixed(1)} GiB</small>${help?`<small>${h(help)}</small>`:''}</div></div>`;
      }
      container.querySelector('[data-tiers]').innerHTML=['hot','warm','cold','archive'].map((tier,i)=>`<div class="log-tier log-tier-${tier}"><span>${['HOT','WARM','COLD','ARCHIVE'][i]}</span><strong>${fmt(tiers[tier]?.events)}</strong><small>이벤트 · ${fmt(tiers[tier]?.segments)}개 분할 파일</small>${tier==='hot'?'<small>활성 데이터베이스</small>':`<small>${bytes(tiers[tier]?.bytes)}</small>`}</div>`).join('');
      container.querySelector('[data-policies]').innerHTML=state.policies.length?`<div class="table-wrap"><table><thead><tr><th>인덱스</th><th>전환 · 일</th><th>삭제 · 일</th><th>보존</th></tr></thead><tbody>${state.policies.map(p=>`<tr><td><button data-edit-policy="${h(p.index_name)}">${h(p.index_name)}</button></td><td>${p.hot_days} → ${p.warm_days} → ${p.cold_days}</td><td>${p.retention_days}</td><td>${p.hold?'잠금':'기간 적용'}</td></tr>`).join('')}</tbody></table></div>`:'<p class="muted">별도 정책이 없으면 기본 전환 일정과 테넌트 보존 기간을 적용합니다.</p>';
      container.querySelector('[data-snapshots]').innerHTML=state.search.snapshots.length?state.search.snapshots.map(s=>`<div class="list-card"><div class="list-main"><strong>${fmt(s.row_count)}개 이벤트</strong><small>${date(s.created)} · 만료 ${date(s.expires)} · ${bytes(s.bytes)}</small></div><button data-open="${h(s.id)}" data-count="${s.row_count}">열기</button><button data-close-snapshot="${h(s.id)}">삭제</button></div>`).join(''):'<p class="muted">저장된 검색 스냅샷이 없습니다.</p>';
    }
    async function show(position=0) {
      const page=await V.api('/api/logs/snapshots/'+enc(snapshot.id)+'?after='+position+'&limit=100',options);after=position;next=page.next_after;
      container.querySelector('[data-results]').innerHTML=`<div class="panel-head"><strong>전체 ${fmt(page.total)}건 · ${fmt(page.returned?position+1:0)}–${fmt(position+page.returned)}</strong><div class="row"><button data-page-save>현재 페이지 저장</button><button data-export-all>전체 파일 저장</button><button data-next ${next===null?'disabled':''}>다음 100건 →</button></div></div><div class="table-wrap"><table><thead><tr><th>발생 시각</th><th>인덱스 · 소스</th><th>호스트</th><th>심각도</th><th>메시지</th></tr></thead><tbody>${page.rows.map(r=>`<tr><td>${h(date(r.event_time))}</td><td>${h(r.index_name)}<small>${h(r.source)}</small></td><td>${h(r.host)}</td><td>${h(r.severity)}</td><td>${h(r.message)}</td></tr>`).join('')}</tbody></table></div><small class="muted">NDJSON SHA-256: ${h(page.sha256_ndjson)}</small>`;
    }
    container.querySelector('[data-search]').addEventListener('submit',e=>{e.preventDefault();task(async()=>{
      const form=e.currentTarget, filters=[];
      for(const key of ['index','host','source'])if(val(form,key))filters.push({field:key,op:'eq',value:val(form,key)});
      container.querySelector('[data-progress]').textContent='검색 결과를 고정하고 있습니다…';
      snapshot=await V.post('/api/logs/snapshots',{query:{language:'json',earliest:new Date(val(form,'start')).getTime()/1000,latest:new Date(val(form,'end')).getTime()/1000,query:{filters}},fulltext:val(form,'fulltext')});
      container.querySelector('[data-progress]').textContent=fmt(snapshot.rows)+'건 준비 완료 · 검색 후 수집된 로그는 다음 검색에 포함됩니다.';
      await show();await reload();
    });});
    container.querySelector('[data-policy]')?.addEventListener('submit',e=>{e.preventDefault();task(async()=>{
      const f=e.currentTarget,index=val(f,'policy_index'),old=state.policies.find(p=>p.index_name===index), data={version:old?.version||0,hold:f.elements.hold.checked};
      for(const key of ['hot_days','warm_days','cold_days','retention_days'])data[key]=Number(val(f,key));
      await V.post('/api/logs/indexes/'+enc(index)+'/lifecycle',data,'PUT');await reload();V.notify('인덱스 보존 정책을 저장했습니다.');
    });});
    container.querySelector('[data-backup-form]')?.addEventListener('submit',e=>{e.preventDefault();task(async()=>{
      const form=e.currentTarget, passphrase=form.elements.passphrase.value;
      if(passphrase!==form.elements.repeat.value)throw new Error('백업 암호가 일치하지 않습니다.');
      container.querySelector('[data-backup-result]').textContent='온라인 스냅샷을 암호화하고 있습니다…';
      try{const result=await V.post('/api/logs/backups',{passphrase});container.querySelector('[data-backup-result]').textContent='암호화 백업 완료 · '+result.id+' · '+fmt(result.files)+'개 파일 · '+fmt(result.chunks)+'개 암호화 조각';}finally{form.reset();}
    });});
    container.addEventListener('click',e=>{const b=e.target.closest('button');if(!b||(b.type==='submit'&&b.form))return;
      if(b.dataset.editPolicy!==undefined){const p=state.policies.find(p=>p.index_name===b.dataset.editPolicy), f=container.querySelector('[data-policy]');if(f&&p){f.elements.policy_index.value=p.index_name;for(const key of ['hot_days','warm_days','cold_days','retention_days'])f.elements[key].value=p[key];f.elements.hold.checked=p.hold;}return;}
      task(async()=>{
        if(b.hasAttribute('data-reload'))await reload();
        if(b.hasAttribute('data-maintain')){const f=container.querySelector('[data-policy]');await V.post('/api/logs/maintenance',{index_name:val(f,'policy_index')});await reload();V.notify('저장 단계 적용을 완료했습니다.');}
        if(b.dataset.open){snapshot={id:b.dataset.open,rows:Number(b.dataset.count)};await show();}
        if(b.dataset.closeSnapshot){await V.post('/api/logs/snapshots/'+enc(b.dataset.closeSnapshot),{},'DELETE');if(snapshot?.id===b.dataset.closeSnapshot){snapshot=null;container.querySelector('[data-results]').replaceChildren();}await reload();}
        if(b.hasAttribute('data-next')&&next!==null)await show(next);
        if(b.hasAttribute('data-page-save')){const data=await V.api('/api/logs/snapshots/'+enc(snapshot.id)+'/export?after='+after+'&limit=100',{...options,responseType:'binary'});saveBlob('xsera-'+snapshot.id+'-'+after+'.ndjson',data.bytes);}
        if(b.hasAttribute('data-export-all')){
          if(!window.showSaveFilePicker){const link=document.createElement('a');link.href='/api/logs/snapshots/'+enc(snapshot.id)+'/download';link.download='xsera-'+snapshot.id+'.ndjson';link.click();container.querySelector('[data-progress]').textContent='전체 파일 다운로드를 시작했습니다. 다운로드 완료 상태와 표시된 SHA-256을 확인하세요.';return;}
          const handle=await window.showSaveFilePicker({suggestedName:'xsera-'+snapshot.id+'.ndjson'}), writer=await handle.createWritable();let cursor=0,done=0;
          try{do{const result=await V.api('/api/logs/snapshots/'+enc(snapshot.id)+'/export?after='+cursor+'&limit=1000',{...options,responseType:'binary'});await writer.write(result.bytes);const value=result.headers.get('X-Next-After');cursor=value?Number(value):null;done=cursor??snapshot.rows;container.querySelector('[data-progress]').textContent=fmt(done)+' / '+fmt(snapshot.rows)+'건 저장 중…';}while(cursor!==null);await writer.close();container.querySelector('[data-progress]').textContent='전체 로그 파일 저장 완료';}catch(err){await writer.abort();throw err;}
        }
      });
    });
    try{await reload();}catch(e){error(e);}
    return ()=>abort.abort();
  }});
})();
