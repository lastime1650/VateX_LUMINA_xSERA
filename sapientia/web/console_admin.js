/* Platform and account administration. No polling, synthetic metrics or secret persistence. */
(() => {
  'use strict';
  const V = window.Vatex;
  if (!V) return;
  const h = V.h, enc = encodeURIComponent;
  const session = () => V.session() || {};
  const admin = () => session().role === 'admin';
  const operator = () => admin() && session().tenant === 'default';
  const analyst = () => ['admin', 'analyst'].includes(session().role);
  const number = value => value === null || value === undefined ? '—' : new Intl.NumberFormat('ko-KR', {maximumFractionDigits: 1}).format(value);
  const date = value => value ? new Date(Number(value) * 1000).toLocaleString('ko-KR') : '—';
  const bytes = value => value === null || value === undefined ? '—' : Number(value) >= 1073741824 ? (Number(value) / 1073741824).toFixed(2) + ' GiB' : (Number(value) / 1048576).toFixed(1) + ' MiB';
  const field = (label, name, value = '', type = 'text', attrs = '') => `<label class="adm-field"><span>${h(label)}</span><input name="${h(name)}" value="${h(value ?? '')}" type="${h(type)}" ${attrs}></label>`;
  const select = (label, name, options, current) => `<label class="adm-field"><span>${h(label)}</span><select name="${h(name)}">${options.map(([value, text]) => `<option value="${h(value)}" ${String(value) === String(current) ? 'selected' : ''}>${h(text)}</option>`).join('')}</select></label>`;
  const check = (label, name, checked = false) => `<label class="adm-check"><input type="checkbox" name="${h(name)}" ${checked ? 'checked' : ''}><span>${h(label)}</span></label>`;
  const button = (text, action, attrs = '', primary = false) => `<button type="button" class="adm-button ${primary ? 'adm-primary' : ''}" data-adm="${h(action)}" ${attrs}>${h(text)}</button>`;
  const value = (root, name) => root.querySelector(`[name="${name}"]`)?.value || '';
  const checked = (root, name) => !!root.querySelector(`[name="${name}"]`)?.checked;
  const pill = (text, tone = 'neutral') => `<span class="adm-pill adm-${tone}">${h(text)}</span>`;
  const empty = (heading, detail = '') => `<div class="adm-empty">${V.icon('empty')}<strong>${h(heading)}</strong><p>${h(detail)}</p></div>`;
  const note = text => `<p class="adm-note">${h(text)}</p>`;
  const card = (eyebrow, title, content, action = '') => `<section class="adm-card"><header><div><span class="adm-eyebrow">${h(eyebrow)}</span><h2>${h(title)}</h2></div>${action}</header>${content}</section>`;
  const stat = (label, val, detail = '') => `<div class="adm-stat"><span>${h(label)}</span><strong>${h(val)}</strong><small>${h(detail)}</small></div>`;
  const table = (heads, rows) => rows.length ? `<div class="adm-table-scroll"><table class="adm-table"><thead><tr>${heads.map(x => `<th>${h(x)}</th>`).join('')}</tr></thead><tbody>${rows.map(row => `<tr>${row.map(x => `<td>${x ?? '—'}</td>`).join('')}</tr>`).join('')}</tbody></table></div>` : empty('표시할 기록이 없습니다');
  const kv = rows => `<dl class="adm-kv">${rows.map(([key, val]) => `<div><dt>${h(key)}</dt><dd>${h(val ?? '—')}</dd></div>`).join('')}</dl>`;
  const roleOptions = [['viewer', '조회자'], ['analyst', '분석가'], ['admin', '관리자']];

  function scope(container) {
    const controller = new AbortController(), dialogs = new Set();
    const identity = `${session().name}|${session().tenant}`;
    let active = true;
    const alive = () => active && identity === `${session().name}|${session().tenant}`;
    return {
      container, alive,
      get: path => V.api(path, {signal: controller.signal}),
      set(html) { if (alive()) container.innerHTML = `<div class="adm-page">${html}</div>`; },
      dialog(options) {
        if (!alive()) return null;
        const original = options.onSave;
        const d = V.dialog({...options, onSave: original ? root => {
          if (!alive()) throw new Error('작업 화면이 변경되었습니다. 다시 열어 주세요.');
          return original(root);
        } : undefined});
        // Forms in a dialog must never perform a browser GET containing fields.
        d.addEventListener('submit', event => { event.preventDefault(); d.querySelector('[data-save]')?.click(); });
        dialogs.add(d);
        d.addEventListener('close', () => { d.querySelectorAll('input[type="password"],[name="setup-secret"]').forEach(input => { input.value = ''; }); dialogs.delete(d); }, {once: true});
        return d;
      },
      cleanup() {
        active = false;
        controller.abort();
        container.querySelectorAll('[name="issued-token"]').forEach(input => { input.value = ''; });
        for (const d of dialogs) { d.close(); d.remove(); }
        dialogs.clear();
      }
    };
  }

  function errorPanel(error) {
    return `<div class="adm-error" role="alert">${h(error?.message || '상태를 불러오지 못했습니다.')}</div>`;
  }

  function analyticsSummary(health) {
    const status = health.analytics_status || {}, state = status.state;
    const known = ['ready', 'cached', 'stale'].includes(state);
    const stale = state === 'stale';
    const measured = Number.isFinite(status.measured_at) && status.measured_at > 0 ? date(status.measured_at) : '측정 시각 미제공';
    const age = Number.isFinite(status.age_seconds) && status.age_seconds >= 0 ? number(status.age_seconds) + '초 전' : '경과 시간 미제공';
    const label = stale ? '이전 성공 집계' : state === 'cached' ? '최근 성공 집계' : '집계 완료';
    const detail = known ? `${label} · ${measured} · ${age}` : '분석 집계 불가 · 0건을 뜻하지 않습니다.';
    const metric = value => known && Number.isFinite(value) && value >= 0 ? number(value) + (stale ? ' (이전)' : '') : '집계 불가';
    const indexed = metric(health.indexed), sources = metric(health.source_count);
    return {indexed, sources, detail,
      pipeline: indexed === '집계 불가' ? '보존 이벤트 집계 불가' : `${stale ? '이전 집계 · ' : ''}${number(health.indexed)}개 보존`};
  }

  async function operations(container) {
    const s = scope(container);
    let cluster;
    async function load() {
      const paths = ['/api/health', '/api/federation/status'];
      if (analyst()) paths.push('/api/operations');
      if (operator()) paths.push('/api/cluster');
      const results = await Promise.allSettled(paths.map(s.get));
      if (!s.alive()) return;
      const data = {}, errors = {};
      results.forEach((r, i) => { if (r.status === 'fulfilled') data[paths[i]] = r.value; else errors[paths[i]] = r.reason; });
      const health = data['/api/health'], op = data['/api/operations'], federation = data['/api/federation/status'];
      cluster = data['/api/cluster'];
      const analytics = health ? analyticsSummary(health) : null;
      const queue = health ? `<div class="adm-stats">${stat('분석 저장 완료', analytics.indexed, '현재 테넌트 · 허용 인덱스 · ' + analytics.detail)}${stat('영속 대기열', number(health.pending), bytes(health.pending_bytes))}${stat('가장 오래된 대기', number(health.oldest_pending_seconds) + '초', '미처리 수집 이벤트')}${stat('관측 수집원', analytics.sources, '보존 중인 허용 이벤트 · ' + analytics.detail)}</div><div class="adm-pipeline"><div>${V.icon('data')}<strong>수집</strong><small>인증 · 승인된 데이터</small></div><span>→</span><div>${V.icon('operations')}<strong>영속 대기열</strong><small>${h(number(health.pending))}개 대기</small></div><span>→</span><div>${V.icon('logs')}<strong>분석 저장소</strong><small>${h(analytics.pipeline)}</small></div></div>` : errorPanel(errors['/api/health']);
      const worker = op ? `${kv([['인덱서 마지막 실행', date(op.indexer?.last_tick)], ['스케줄러 마지막 실행', date(op.indexer?.scheduler_tick)], ['실행 대기 탐지 창', number(op.scheduler?.due_windows)], ['재시도 유예 규칙', number(op.scheduler?.deferred_rules)], ['오류 규칙', number(op.scheduler?.failing_rules)], ['최근 탐지 성공', date(op.scheduler?.last_success)]])}${op.node_metrics_visible ? kv([['노드 최근 인덱싱 EPS', number(op.indexer?.indexed_eps)], ['노드 프로세스 누적 인덱싱', number(op.indexer?.indexed_total)]]) : note('노드 전체 처리량은 전체 인덱스 권한을 가진 default 테넌트 관리자에게 표시됩니다.')}${[op.indexer?.error, op.indexer?.scheduler_error, op.indexer?.detection_error].filter(Boolean).map(x => `<div class="adm-error">${h(x)}</div>`).join('')}` : analyst() ? errorPanel(errors['/api/operations']) : note('상세 스케줄러 운영 정보는 분석가와 관리자가 조회할 수 있습니다.');
      const syslog = op?.syslog;
      const input = !syslog ? note('Syslog 상태 정보가 제공되지 않았습니다.') : syslog.restricted ? note('Syslog는 노드 전체 상태입니다. 해당 운영 권한이 필요합니다.') : `${pill(syslog.enabled ? syslog.listening ? '리스너 실행 중' : '리스너 중지' : '설정되지 않음', syslog.enabled && syslog.listening ? 'good' : syslog.enabled ? 'bad' : 'neutral')}${kv([['전송', syslog.transport?.toUpperCase()], ['수신 주소', syslog.address?.join(':')], ['수집 테넌트', syslog.tenant], ['수신 프레임', number(syslog.received)], ['영속 승인 이벤트', number(syslog.admitted)], ['수신 내부 대기', number(syslog.queued)], ['연결 수', number(syslog.connections)], ['크기 초과 폐기', number(syslog.dropped_oversized)], ['파싱 실패 폐기', number(syslog.dropped_invalid)], ['대기열 폐기', number(syslog.dropped_queue)]])}${syslog.last_error ? errorPanel({message: syslog.last_error}) : ''}${note('노드 리스너가 제공하는 프로세스 수명 기준 카운터입니다. UDP 전달은 보장되지 않습니다.')}`;
      let topology;
      if (!operator()) topology = empty('장비 가입 토폴로지', 'default 테넌트 관리자에게 표시됩니다. 검색 연합과 데이터 복제 상태는 별도입니다.');
      else if (!cluster) topology = errorPanel(errors['/api/cluster']);
      else {
        const nodes = cluster.members || [];
        const root = nodes.find(x => Number(x.ordinal) === 0);
        const children = nodes.filter(x => Number(x.ordinal) !== 0);
        const node = (n, label) => `<div class="adm-node">${V.icon('operations')}<span>${h(label)}</span><strong>${h(n?.url || (n?.node_id || cluster.node_id)?.slice(0, 16))}</strong><small>${h(n?.state || (cluster.mode === 'standalone' ? '단독 장비' : '등록됨'))}</small></div>`;
        topology = `<div class="adm-topology">${node(root, cluster.role || 'Standalone')}${children.length ? `<div class="adm-branches">${children.slice(0, 24).map(n => node(n, 'Slave ' + n.ordinal)).join('')}</div>` : ''}</div>${children.length > 24 ? note(`Slave ${children.length}개 중 24개 표시`) : ''}${kv([['장비 모드', cluster.mode], ['그룹', cluster.name || cluster.group_id], ['가입 상태 동기화', date(cluster.membership_last_sync)]])}${note('연결선은 장비 가입 관계입니다. 가입 완료만으로 로그·계정·정책 복제가 활성화되지 않습니다.')}`;
      }
      const replica = cluster?.replication || health?.cluster;
      const replication = replica ? `${pill(replica.error ? '동기화 확인 필요' : '복제 설정됨', replica.error ? 'bad' : 'good')}${kv([['실제 복제 모드', replica.mode], ['적용 시퀀스', number(replica.applied_sequence)], ['마지막 동기화', date(replica.last_sync)], ['구성 복제 수', number(replica.replicas)], ['오류', replica.error || '보고된 오류 없음']])}` : `${pill('데이터 복제 미구성')}${note('장비 가입과 데이터 복제는 각각 구성합니다. 상태 정보 없이 고가용성이나 장애 복구 준비 완료로 표시하지 않습니다.')}`;
      const fed = federation ? `${pill(federation.enabled ? '검색 연합 설정됨' : '검색 연합 미구성', federation.enabled ? 'good' : 'neutral')}${note('검색 연합은 구성된 원격 노드의 허용 범위 검색입니다. 장비 가입이나 전체 데이터 복제 상태를 뜻하지 않습니다.')}${federation.enabled ? button('연합 로그 검색', 'federated-search') : ''}` : errorPanel(errors['/api/federation/status']);
      const rules = op?.rules || [];
      s.set(`<div class="adm-heading"><div><span class="adm-eyebrow">PLATFORM OBSERVABILITY</span><h2>수집부터 탐지까지, 현재 상태</h2><p>측정된 대기열과 실행 기록을 확인합니다. ${h(date(Date.now() / 1000))} 조회</p></div>${button('상태 새로고침', 'refresh')}</div>${card('DATA PLANE', '데이터 처리 흐름', queue)}<div class="adm-grid">${card('RUNTIME', '인덱서 · 스케줄러', worker)}${card('INPUT LISTENER', 'Syslog 수신', input)}${card('MEMBERSHIP', '장비 가입 토폴로지', topology, operator() && cluster?.mode === 'standalone' ? `<div class="adm-actions">${button('Master 생성', 'master')}${button('Slave 가입', 'join')}</div>` : operator() && cluster ? button('가입 상태 동기화', 'cluster-refresh') : '')}${card('REPLICATION', '데이터 복제', replication)}${card('FEDERATED SEARCH', '노드 간 검색', fed)}${card('NODE STORAGE', '물리 저장소', health ? `<div class="adm-stats adm-two">${stat('노드 데이터 파일', bytes(health.storage_bytes), '노드 전체 데이터 디렉터리')}${stat('파일시스템 여유', bytes(health.disk_free_bytes), '노드 전체 볼륨')}</div>${note('물리 사용량은 논리 인덱스별 이벤트 바이트와 다른 측정값입니다.')}` : errorPanel(errors['/api/health']))}</div>${analyst() ? card('SCHEDULED DETECTIONS', '규칙 실행 상태', table(['탐지 규칙', '상태', '최근 성공', '소요 시간', '재시도'], rules.map(r => [h(r.name), pill(r.state || '미실행', r.failures ? 'bad' : 'neutral'), h(date(r.last_success)), r.duration_ms == null ? '—' : h(number(r.duration_ms)) + ' ms', h(date(r.retry_at))])) + note('운영 API가 제공하는 최대 200개 규칙 실행 목록입니다. 전체 실패 수는 위 스케줄러 집계에서 확인합니다.')) : ''}`);
    }
    async function action(event) {
      const b = event.target.closest('[data-adm]');
      if (!b || b.disabled) return;
      b.disabled = true;
      try {
        if (b.dataset.adm === 'refresh') await load();
        if (b.dataset.adm === 'federated-search') V.navigate('logs', {federation: '1'});
        if (b.dataset.adm === 'cluster-refresh') { await V.post('/api/cluster/refresh', {}); await load(); }
        if (['master', 'join'].includes(b.dataset.adm)) {
          const master = b.dataset.adm === 'master';
          s.dialog({title: master ? 'Master 장비 생성' : 'Slave 장비 가입', content: `<form class="adm-form">${master ? field('그룹 이름', 'name', '', 'text', 'required maxlength="80"') : field('가입 대상 장비 HTTPS 주소', 'peer', '', 'url', 'required placeholder="https://siem.example:8443"') + field('가입 대상 인증서 SHA256 지문', 'peer_pin', '', 'text', 'required minlength="64" maxlength="95"')}${field('이 장비의 HTTPS 주소', 'address', location.origin, 'url', 'required')}${field('이 장비 인증서 SHA256 지문', 'certificate_pin', '', 'text', 'required minlength="64" maxlength="95"')}${field('공유 가입 비밀번호', 'password', '', 'password', 'required minlength="16" maxlength="128" autocomplete="new-password"')}${note('가입 제어면을 구성합니다. 데이터 복제는 별도 구성입니다. 이미 가입한 장비의 자격 증명 복구는 운영자 복구 절차를 사용합니다.')}</form>`, onSave: async d => {
            const data = {address: value(d, 'address'), certificate_pin: value(d, 'certificate_pin'), password: value(d, 'password')};
            if (master) data.name = value(d, 'name'); else { data.peer = value(d, 'peer'); data.peer_pin = value(d, 'peer_pin'); }
            await V.post(master ? '/api/cluster/master' : '/api/cluster/join', data);
            await load(); V.notify('장비 가입 구성을 저장했습니다.');
          }});
        }
      } catch (error) { if (s.alive() && error.name !== 'AbortError') V.notify(error.message); }
      finally { b.disabled = false; }
    }
    container.addEventListener('click', action);
    await load();
    return () => { container.removeEventListener('click', action); s.cleanup(); };
  }

  async function settings(container, params = {}) {
    const s = scope(container);
    let users = [], tokens = [], audit = [], health, mfa, integrity;
    const tabs = [['account', '내 계정'], ...(admin() && !session().must_change ? [['users', '사용자 · 권한'], ['tokens', '수집 키'], ['retention', '데이터 보존'], ['audit', '감사 기록']] : [])];
    const tab = tabs.some(([id]) => id === params.tab) ? params.tab : 'account';
    const header = () => `<div class="adm-tabs" role="navigation" aria-label="설정 영역">${tabs.map(([id, label]) => `<button type="button" data-adm="tab" data-tab="${id}" aria-current="${tab === id ? 'page' : 'false'}" class="${tab === id ? 'active' : ''}">${h(label)}</button>`).join('')}</div>`;
    async function load() {
      let content = '';
      if (tab === 'account') {
        mfa = session().must_change ? {enabled: !!session().mfa_enabled} : await s.get('/api/me/mfa');
        const current = session();
        content = `<div class="adm-grid">${card('YOUR IDENTITY', '작업 공간 계정', `<div class="adm-identity"><span>${h(current.name?.slice(0, 1).toUpperCase())}</span><div><h2>${h(current.name)}</h2><small>${h(current.tenant)} · ${h(current.role)}</small></div></div>${kv([['로그인 이름', current.name], ['테넌트', current.tenant], ['역할', current.role], ['허용 인덱스', current.allowed_indexes?.join(', ') || '접근 불가']])}`)}${card('ACCOUNT SECURITY', '비밀번호 · 다중 인증', `${current.must_change ? '<div class="adm-error">계속하려면 초기 비밀번호를 변경하세요.</div>' : ''}<div class="adm-security-row"><div><strong>비밀번호</strong><p>현재 비밀번호를 확인하고 새 비밀번호를 설정합니다.</p></div>${button('변경', 'password')}</div><div class="adm-security-row"><div><strong>인증 앱 코드</strong><p>${current.must_change ? '초기 비밀번호를 변경한 뒤 다중 인증을 관리할 수 있습니다.' : mfa.enabled ? '일회용 6자리 코드로 계정을 보호하고 있습니다.' : '인증 앱을 연결해 추가 인증을 사용하세요.'}</p></div>${pill(mfa.enabled ? '사용 중' : '미사용', mfa.enabled ? 'good' : 'neutral')}${current.must_change ? '' : button(mfa.enabled ? '해제' : '연결', mfa.enabled ? 'mfa-disable' : 'mfa-enroll')}</div>${note('비밀번호 또는 다중 인증을 변경하면 현재 세션이 종료되고 다시 로그인해야 합니다.')}`)}</div>`;
      }
      if (tab === 'users') {
        users = await s.get('/api/users');
        content = card('WORKSPACE ACCESS', '사용자와 권한', table(['사용자', '역할', '계정 상태', '다중 인증', '권한 관리'], users.map(u => [h(u.name), h(roleOptions.find(([r]) => r === u.role)?.[1] || u.role), pill(u.disabled ? '비활성' : u.must_change ? '비밀번호 변경 필요' : '활성', u.disabled ? 'bad' : 'good'), pill(u.mfa_enabled ? '사용' : '미사용', u.mfa_enabled ? 'good' : 'neutral'), `<div class="adm-actions">${button('계정', 'user-edit', `data-name="${h(u.name)}"`)}${button('인덱스', 'indexes', `data-name="${h(u.name)}"`)}</div>`])) + note('이 테넌트의 사용자만 표시합니다. 계정 또는 인덱스 권한 변경 시 해당 사용자의 기존 세션이 해제됩니다.'), button('사용자 추가', 'user-create', '', true));
      }
      if (tab === 'tokens') {
        tokens = await s.get('/api/tokens');
        content = card('INGEST CREDENTIALS', '수집 전용 키', table(['이름', '쓰기 인덱스', '발급자', '상태', '발급', '만료', '관리'], tokens.map(t => [h(t.name), h((t.allowed_indexes||[]).join(', ')||'—'), h(t.issuer||'미확인'), t.legacy_requires_rotation?pill('high','재발급 필요'):pill(t.scope||'ingest'), h(date(t.created)), h(date(t.expires)), button('폐기', 'token-revoke', `data-id="${h(t.id)}" data-name="${h(t.name)}"`)])) + note('키 원문은 발급 직후 한 번 표시합니다. 지정한 인덱스에만 기록하며 발급자의 현재 권한과 계정 상태를 확인합니다.'), button('수집 키 발급', 'token-create', '', true));
      }
      if (tab === 'retention') {
        health = await s.get('/api/health');
        content = card('DATA LIFECYCLE', '테넌트 보존 정책', `<div class="adm-stats adm-two">${stat('이벤트 보존', number(health.retention_days) + '일', '수신 시각 기준')}${stat('자동 삭제 보류', health.legal_hold ? '사용' : '미사용', '현재 테넌트 정책')}</div>${note('정책은 시간 단위 유지보수에서 적용됩니다. 보존 기간을 줄이면 기준보다 오래된 이벤트가 다음 유지보수에서 삭제될 수 있습니다. 자동 삭제 보류는 자동 정리만 중단합니다.')}`, button('정책 변경', 'retention-edit'));
      }
      if (tab === 'audit') {
        audit = await s.get('/api/audit');
        content = `${card('ACCOUNTABILITY', '테넌트 감사 기록', `<label class="adm-audit-filter">기록 내 검색<input name="audit-filter" placeholder="사용자 또는 작업 이름"></label><div data-audit-table></div>${note('현재 테넌트의 최신 200개 기록입니다. default 관리자는 알 수 없는 사용자 로그인 실패의 인증 영역 기록도 확인할 수 있습니다.')}`, button('새로고침', 'refresh'))}${operator() ? card('INTEGRITY EVIDENCE', '감사 체인 검증', `<div data-integrity>${note('로컬 해시 체인은 독립적인 불변 저장소가 아닙니다. 내려받은 체크포인트를 별도로 보호하고 나중에 대조할 수 있습니다.')}</div><div class="adm-actions">${button('로컬 체인 검증', 'integrity')}${button('체크포인트 내보내기', 'checkpoint')}${button('체크포인트 대조', 'checkpoint-verify')}</div>`) : ''}`;
      }
      s.set(header() + content);
      if (tab === 'audit') drawAudit('');
    }
    function drawAudit(filter) {
      if (!s.alive()) return;
      const target = container.querySelector('[data-audit-table]');
      if (!target) return;
      const text = filter.toLowerCase();
      target.innerHTML = table(['시각', '사용자', '작업', '시퀀스', '상세'], audit.filter(a => `${a.actor} ${a.action}`.toLowerCase().includes(text)).map(a => [h(date(a.at)), h(a.actor), h(a.action), h(a.seq), button('기록 보기', 'audit-detail', `data-seq="${h(a.seq)}"`)]));
    }
    function showIntegrity(result) {
      integrity = result;
      const target = container.querySelector('[data-integrity]');
      if (target && s.alive()) target.innerHTML = `${pill(result.valid ? '체인 검증 통과' : '검증 실패', result.valid ? 'good' : 'bad')}${kv([['검증 기록 수', number(result.count)], ['마지막 시퀀스', number(result.sequence)], ['외부 체크포인트 일치', result.checkpoint_verified ? '확인' : '대조하지 않음']])}${result.errors?.length ? table(['시퀀스', '사유'], result.errors.map(e => [h(e.sequence), h(e.reason)])) : ''}${note('로컬 해시 체인 검증 결과입니다. 독립적인 WORM 보장이나 운영 체제 관리자의 변조 방지 기능은 아닙니다.')}`;
    }
    function relogin(message) { V.notify(message); location.reload(); }
    async function action(event) {
      const b = event.target.closest('[data-adm]');
      if (!b || b.disabled) return;
      b.disabled = true;
      try {
        const act = b.dataset.adm;
        if (act === 'tab') { V.navigate('settings', {tab: b.dataset.tab}); return; }
        if (act === 'refresh') await load();
        if (act === 'password') s.dialog({title: '비밀번호 변경', content: `<form class="adm-form">${field('현재 비밀번호', 'current', '', 'password', 'required autocomplete="current-password" maxlength="128"')}${field('새 비밀번호', 'password', '', 'password', 'required minlength="12" maxlength="128" autocomplete="new-password"')}${field('새 비밀번호 확인', 'confirm', '', 'password', 'required minlength="12" maxlength="128" autocomplete="new-password"')}${mfa?.enabled ? field('인증 앱 코드', 'otp', '', 'text', 'required pattern="[0-9]{6}" maxlength="6" inputmode="numeric" autocomplete="one-time-code"') : ''}</form>`, onSave: async d => {
          if (value(d, 'password') !== value(d, 'confirm')) throw new Error('새 비밀번호가 일치하지 않습니다.');
          await V.post('/api/me/password', {current: value(d, 'current'), password: value(d, 'password'), otp: value(d, 'otp') || undefined});
          relogin('비밀번호를 변경했습니다. 다시 로그인하세요.');
        }});
        if (act === 'mfa-enroll') {
          let enrolled = false;
          s.dialog({title: '인증 앱 연결', content: `<form class="adm-form">${field('현재 비밀번호 확인', 'password', '', 'password', 'required maxlength="128" autocomplete="current-password"')}${note('다음 단계에서 연결 키를 인증 앱에 직접 등록하고 6자리 코드를 확인합니다. 연결 키를 외부 QR 서비스로 전송하지 않습니다.')}</form>`, onSave: async d => {
            if (!enrolled) {
              const enrollment = await V.post('/api/me/mfa/enroll', {password: value(d, 'password')});
              if (!s.alive()) return true;
              enrolled = true;
              d.querySelector('.dialog-body').innerHTML = `<form class="adm-form">${note('인증 앱에서 계정 추가 → 설정 키 직접 입력을 선택하세요. 시간 기반 TOTP, 6자리, 30초를 사용합니다.')}${field('연결 키 · 이 화면에서만 확인', 'setup-secret', enrollment.secret, 'text', 'readonly autocomplete="off" spellcheck="false"')}${field('인증 앱의 현재 코드', 'otp', '', 'text', 'required pattern="[0-9]{6}" maxlength="6" inputmode="numeric" autocomplete="one-time-code"')}${note('연결 확인은 10분 안에 완료하세요.')}</form>`;
              d.querySelector('[data-save]').textContent = '연결 확인';
              return false;
            }
            await V.post('/api/me/mfa/confirm', {otp: value(d, 'otp')});
            relogin('다중 인증을 연결했습니다. 인증 코드로 다시 로그인하세요.');
          }});
        }
        if (act === 'mfa-disable') s.dialog({title: '다중 인증 해제', content: `<form class="adm-form">${field('현재 비밀번호', 'password', '', 'password', 'required maxlength="128" autocomplete="current-password"')}${field('현재 인증 앱 코드', 'otp', '', 'text', 'required pattern="[0-9]{6}" maxlength="6" inputmode="numeric" autocomplete="one-time-code"')}</form>`, onSave: async d => {
          await V.post('/api/me/mfa/disable', {password: value(d, 'password'), otp: value(d, 'otp')});
          relogin('다중 인증을 해제했습니다. 다시 로그인하세요.');
        }});
        if (act === 'user-create') s.dialog({title: '테넌트 사용자 추가', content: `<form class="adm-form">${field('사용자 이름', 'name', '', 'text', 'required minlength="3" maxlength="64" autocomplete="off"')}${select('역할', 'role', roleOptions, 'viewer')}${field('초기 비밀번호', 'password', '', 'password', 'required minlength="12" maxlength="128" autocomplete="new-password"')}${note('사용자는 처음 로그인한 뒤 비밀번호를 변경해야 합니다. 생성 후 인덱스 권한을 설정하세요.')}</form>`, onSave: async d => {
          await V.post('/api/users', {name: value(d, 'name'), role: value(d, 'role'), password: value(d, 'password')});
          await load(); V.notify('사용자를 추가했습니다.');
        }});
        if (act === 'user-edit') {
          const user = users.find(x => x.name === b.dataset.name);
          if (!user) return;
          s.dialog({title: `${user.name} 계정 관리`, content: `<form class="adm-form">${select('역할', 'role', roleOptions, user.role)}${check('계정 비활성화', 'disabled', !!user.disabled)}${note('저장하면 해당 사용자의 기존 세션이 종료됩니다. 마지막 활성 관리자는 비활성화하거나 강등할 수 없습니다.')}</form>`, onSave: async d => {
            await V.post('/api/users/' + enc(user.name), {role: value(d, 'role'), disabled: checked(d, 'disabled')}, 'PATCH');
            if (user.name === session().name) location.reload(); else { await load(); V.notify('계정 권한을 변경했습니다.'); }
          }});
        }
        if (act === 'indexes') {
          const user = b.dataset.name, grant = await s.get('/api/users/' + enc(user) + '/indexes');
          const mode = grant.allowed_indexes?.includes('*') ? 'all' : grant.allowed_indexes?.length ? 'exact' : 'none';
          const d = s.dialog({title: `${user} 인덱스 접근`, content: `<form class="adm-form">${select('접근 범위', 'mode', [['all', '모든 인덱스'], ['exact', '지정한 인덱스'], ['none', '모든 인덱스 차단']], mode)}<label class="adm-field"><span>허용할 정확한 인덱스 이름</span><textarea name="indexes" rows="4" placeholder="main, authentication, endpoint">${h(mode === 'exact' ? grant.allowed_indexes.join(', ') : '')}</textarea></label>${note('대소문자를 구분하는 정확한 이름을 쉼표 또는 줄바꿈으로 입력하세요. 인덱스 접근 변경 시 기존 세션이 종료됩니다.')}</form>`, onSave: async root => {
            const selected = value(root, 'mode');
            const indexes = selected === 'all' ? ['*'] : selected === 'none' ? [] : value(root, 'indexes').split(/[,\n]/).map(x => x.trim()).filter(Boolean);
            if (selected === 'exact' && (!indexes.length || indexes.some(x => !/^[A-Za-z0-9_-]{1,64}$/.test(x)) || new Set(indexes).size !== indexes.length)) throw new Error('중복 없이 유효한 정확한 인덱스 이름을 입력하세요.');
            await V.post('/api/users/' + enc(user) + '/indexes', {allowed_indexes: indexes}, 'PUT');
            if (user === session().name) location.reload(); else V.notify('인덱스 접근 범위를 변경했습니다.');
          }});
          const update = () => { const text = d.querySelector('[name="indexes"]'); text.disabled = value(d, 'mode') !== 'exact'; text.required = !text.disabled; };
          d.querySelector('[name="mode"]').addEventListener('change', update); update();
        }
        if (act === 'token-create') s.dialog({title: '수집 전용 키 발급', content: `<form class="adm-form">${field('키 이름', 'name', '', 'text', 'required maxlength="80"')}${field('유효 기간 · 일', 'days', 90, 'number', 'required min="1" max="365" step="1"')}${field('쓰기 허용 인덱스 · 쉼표로 구분', 'write_indexes', 'main', 'text', 'required')}${note('키는 한 번만 표시되며 현재 테넌트의 이벤트 수집에 사용됩니다.')}</form>`, onSave: async d => {
          const issued = await V.post('/api/tokens', {name: value(d, 'name'), lifetime_days: Number(value(d, 'days')), allowed_indexes:value(d,'write_indexes').split(',').map(x=>x.trim()).filter(Boolean)});
          await load();
          if (!s.alive()) return;
          const panel = document.createElement('aside');
          panel.className = 'adm-secret-panel';
          panel.innerHTML = `<strong>수집 키가 발급되었습니다</strong><p>이 화면을 닫으면 다시 조회할 수 없습니다. 안전하게 보관하세요.</p><label>발급된 키<input name="issued-token" type="password" readonly autocomplete="off" spellcheck="false"></label><div class="adm-actions">${button('복사', 'token-copy')}${button('원문 보기', 'token-show')}${button('표시 닫기', 'token-dismiss')}</div>`;
          panel.querySelector('input').value = issued.token;
          container.querySelector('.adm-page').prepend(panel);
        }});
        if (act === 'token-show') { const input = b.closest('.adm-secret-panel').querySelector('input'); input.type = input.type === 'password' ? 'text' : 'password'; b.textContent = input.type === 'password' ? '원문 보기' : '원문 숨기기'; }
        if (act === 'token-copy') {
          const input = b.closest('.adm-secret-panel').querySelector('input');
          if (navigator.clipboard?.writeText) { await navigator.clipboard.writeText(input.value); V.notify('수집 키를 복사했습니다.'); } else { input.type = 'text'; input.select(); V.notify('키를 선택했습니다. 복사 단축키를 사용하세요.'); }
        }
        if (act === 'token-dismiss') { const panel = b.closest('.adm-secret-panel'); panel.querySelector('input').value = ''; panel.remove(); }
        if (act === 'token-revoke') s.dialog({title: '수집 키 폐기', content: note(`${b.dataset.name} 키를 폐기하면 이 키를 사용하는 수집기의 새 요청이 거절됩니다.`), onSave: async () => { await V.post('/api/tokens/' + enc(b.dataset.id), {}, 'DELETE'); await load(); V.notify('수집 키를 폐기했습니다.'); }});
        if (act === 'retention-edit') s.dialog({title: '데이터 보존 정책', content: `<form class="adm-form">${field('보존 기간 · 일', 'days', health.retention_days, 'number', 'required min="1" max="3650" step="1"')}${check('자동 이벤트 삭제 보류', 'hold', health.legal_hold)}${note('기간을 줄이면 다음 시간 단위 유지보수에서 오래된 이벤트가 삭제될 수 있습니다. 보류 설정은 자동 삭제를 중지하며 독립적인 불변 저장소를 제공하지 않습니다.')}</form>`, onSave: async d => {
          await V.post('/api/policy', {days: Number(value(d, 'days')), hold: checked(d, 'hold')}, 'PUT');
          await load(); V.notify('테넌트 보존 정책을 저장했습니다.');
        }});
        if (act === 'audit-detail') {
          const row = audit.find(x => String(x.seq) === b.dataset.seq);
          if (!row) return;
          let detail;
          try { detail = JSON.parse(row.detail); } catch { detail = {detail: row.detail}; }
          s.dialog({title: '감사 기록 #' + row.seq, content: kv([['시각', date(row.at)], ['사용자', row.actor], ['작업', row.action], ['다이제스트', row.digest], ...Object.entries(detail).map(([key, val]) => [key, typeof val === 'object' ? JSON.stringify(val) : val])])});
        }
        if (act === 'integrity') showIntegrity(await s.get('/api/audit/integrity'));
        if (act === 'checkpoint') {
          const checkpoint = await V.post('/api/audit/checkpoint', {});
          if (s.alive()) { V.download('vatex-audit-checkpoint-' + checkpoint.sequence + '.json', checkpoint); V.notify('체크포인트를 내려받았습니다. 데이터 디렉터리와 별도로 보호하세요.'); }
        }
        if (act === 'checkpoint-verify') s.dialog({title: '보관한 감사 체크포인트 대조', content: '<form class="adm-form"><label class="adm-field"><span>체크포인트 파일</span><input name="checkpoint" type="file" accept=".json,application/json" required></label></form>', onSave: async d => {
          const file = d.querySelector('[name="checkpoint"]').files[0];
          if (!file || file.size > 8192) throw new Error('8 KiB 이하의 체크포인트 파일을 선택하세요.');
          let checkpoint;
          try { checkpoint = JSON.parse(await file.text()); } catch { throw new Error('유효한 체크포인트 파일이 아닙니다.'); }
          showIntegrity(await V.post('/api/audit/verify', checkpoint));
        }});
      } catch (error) { if (s.alive() && error.name !== 'AbortError') V.notify(error.message); }
      finally { b.disabled = false; }
    }
    const filter = event => { if (event.target.name === 'audit-filter') drawAudit(event.target.value); };
    container.addEventListener('click', action);
    container.addEventListener('input', filter);
    await load();
    return () => { container.removeEventListener('click', action); container.removeEventListener('input', filter); s.cleanup(); integrity = undefined; };
  }

  V.register('operations', {title: '플랫폼 운영', render: operations});
  V.register('settings', {title: '설정 및 계정', render: settings});
})();
