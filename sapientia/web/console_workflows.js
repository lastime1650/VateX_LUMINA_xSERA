/* Analyst workflows. All mutations are explicit; no timers or synthetic telemetry. */
(() => {
  'use strict';
  const V = window.Vatex;
  if (!V) return;
  const h = V.h;
  const enc = encodeURIComponent;
  const copy = value => JSON.parse(JSON.stringify(value));
  const now = () => Math.floor(Date.now() / 1000);
  const uuid = () => crypto.randomUUID();
  const split = value => String(value || '').split(/[,\n]/).map(x => x.trim()).filter(Boolean);
  const date = value => value ? new Date(Number(value) * 1000).toLocaleString('ko-KR') : '—';
  const localDate = value => value ? new Date(Number(value) * 1000 - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 19) : '';
  const epoch = value => value ? Math.floor(new Date(value).getTime() / 1000) : null;
  const short = value => String(value || '').slice(0, 12);
  const session = () => V.session() || {};
  const editable = () => ['admin', 'analyst'].includes(session().role);
  const admin = () => session().role === 'admin';
  const statuses = {new: '신규', triage: '분석 중', resolved: '해결', false_positive: '오탐', open: '진행 전', done: '완료', cancelled: '취소', pending_approval: '승인 대기', queued: '실행 대기', running: '실행 중', waiting: '엔드포인트 결과 대기', skipped: '조건 불일치 · 건너뜀', completed: '완료', failed: '실패', retry: '재시도 대기', sending: '전송 중', unknown: '결과 확인 필요', true_positive: '확인된 위협', expected_activity: '예상된 정상 활동'};
  const severities = ['critical', 'high', 'medium', 'low', 'info'];
  const labels = {critical: '치명적', high: '높음', medium: '보통', low: '낮음', info: '정보'};
  const pill = (value, label) => `<span class="wf-pill wf-tone-${h(value || 'neutral')}">${h(label || statuses[value] || labels[value] || value || '미분류')}</span>`;
  const button = (label, action, attrs = '', kind = '') => `<button type="button" class="wf-btn ${kind}" data-action="${h(action)}" ${attrs}>${h(label)}</button>`;
  const field = (label, name, value = '', attrs = '', type = 'text') => `<label class="wf-field"><span>${h(label)}</span><input type="${type}" name="${h(name)}" value="${h(value ?? '')}" ${type === 'datetime-local' ? 'step="1"' : ''} ${attrs}></label>`;
  const area = (label, name, value = '', attrs = '') => `<label class="wf-field wf-wide"><span>${h(label)}</span><textarea name="${h(name)}" ${attrs}>${h(value ?? '')}</textarea></label>`;
  const options = (values, current, captions = {}) => values.map(value => `<option value="${h(value)}" ${String(value) === String(current) ? 'selected' : ''}>${h(captions[value] || value)}</option>`).join('');
  const select = (label, name, values, current, captions = {}, attrs = '') => `<label class="wf-field"><span>${h(label)}</span><select name="${h(name)}" ${attrs}>${options(values, current, captions)}</select></label>`;
  const check = (label, name, checked = false, attrs = '') => `<label class="wf-check"><input type="checkbox" name="${h(name)}" ${checked ? 'checked' : ''} ${attrs}><span>${h(label)}</span></label>`;
  const value = (root, name) => root.querySelector(`[name="${name}"]`)?.value ?? '';
  const checked = (root, name) => !!root.querySelector(`[name="${name}"]`)?.checked;
  const number = (root, name) => Number(value(root, name));
  const note = text => `<div class="wf-note">${h(text)}</div>`;
  const empty = (title, text = '') => `<div class="wf-empty"><div class="wf-empty-mark">◇</div><strong>${h(title)}</strong><p>${h(text)}</p></div>`;
  const errorBox = message => `<div class="wf-error" role="alert">${h(message)}</div>`;
  const title = (eyebrow, heading, text, actions = '') => `<div class="wf-heading"><div><span class="wf-eyebrow">${h(eyebrow)}</span><h2>${h(heading)}</h2><p>${h(text)}</p></div><div class="wf-actions">${actions}</div></div>`;
  const table = (heads, rows) => rows.length ? `<div class="wf-table-wrap"><table class="wf-table"><thead><tr>${heads.map(x => `<th>${h(x)}</th>`).join('')}</tr></thead><tbody>${rows.map(row => `<tr>${row.map(x => `<td>${x ?? '—'}</td>`).join('')}</tr>`).join('')}</tbody></table></div>` : empty('표시할 항목이 없습니다');
  const stats = items => `<div class="wf-stats">${items.map(([label, val, text]) => `<div><span>${h(label)}</span><strong>${h(val)}</strong>${text ? `<small>${h(text)}</small>` : ''}</div>`).join('')}</div>`;
  const flow = (items, type = 'sequence') => `<div class="wf-flow" aria-label="${h(type)}">${items.map((item, i) => `${i ? '<svg class="wf-flow-arrow" viewBox="0 0 40 20" aria-hidden="true"><path d="M2 10H34M28 4l6 6-6 6"/></svg>' : ''}<div class="wf-flow-node"><span>${String(i + 1).padStart(2, '0')}</span><strong>${h(item.title)}</strong><small>${h(item.text || '')}</small></div>`).join('')}</div>`;
  function describe(data) {
    if (data === null || data === undefined) return '<span class="wf-muted">—</span>';
    if (typeof data !== 'object') return h(data);
    if (Array.isArray(data)) return data.length ? `<div class="wf-tags">${data.map(x => typeof x === 'object' ? `<div class="wf-subcard">${describe(x)}</div>` : `<span>${h(x)}</span>`).join('')}</div>` : '—';
    return `<dl class="wf-kv">${Object.entries(data).map(([key, val]) => `<div><dt>${h(key)}</dt><dd>${describe(val)}</dd></div>`).join('')}</dl>`;
  }
  function scopeFor(container) {
    const controller = new AbortController();
    const identity = `${session().name || ''}|${session().tenant || ''}`;
    let active = true;
    const disposers = [];
    const scope = {
      container,
      alive: () => active && identity === `${session().name || ''}|${session().tenant || ''}`,
      async get(path) { const result = await V.api(path, {signal: controller.signal}); if (!scope.alive()) throw new DOMException('View closed', 'AbortError'); return result; },
      async send(path, body, method = 'POST') { if (!scope.alive()) throw new DOMException('View closed', 'AbortError'); const result = await V.post(path, body, method); if (!scope.alive()) throw new DOMException('View closed', 'AbortError'); return result; },
      set(html) { if (scope.alive()) container.innerHTML = `<div class="wf-page">${html}</div>`; },
      track(fn) { disposers.push(fn); },
      on(type, fn) { container.addEventListener(type, fn); disposers.push(() => container.removeEventListener(type, fn)); },
      async run(fn, trigger) {
        if (trigger?.disabled) return;
        if (trigger) trigger.disabled = true;
        try { return await fn(); } catch (err) { if (scope.alive() && err.name !== 'AbortError') { V.notify(err.message || String(err)); const loading = container.querySelector('.wf-loading,.loading'); if (loading) loading.outerHTML = errorBox(err.message || String(err)); } }
        finally { if (trigger?.isConnected) trigger.disabled = false; }
      },
      close() { active = false; controller.abort(); disposers.splice(0).forEach(fn => fn()); container.replaceChildren(); }
    };
    return scope;
  }
  function actions(scope, handler) {
    scope.on('click', event => {
      const btn = event.target.closest('[data-action]');
      if (!btn || !scope.container.contains(btn)) return;
      event.preventDefault();
      scope.run(() => handler(btn.dataset.action, btn, event), btn);
    });
  }
  function modal(scope, heading, html, save, label = '저장', mount) {
    if (!scope.alive()) return null;
    const dialog = document.createElement('dialog');
    dialog.className = 'wf-modal';
    dialog.innerHTML = `<form class="wf-modal-form"><header><div><span class="wf-eyebrow">WORKFLOW</span><h3>${h(heading)}</h3></div><button type="button" class="wf-icon-btn" data-close aria-label="닫기">×</button></header><div class="wf-modal-body">${html}</div><footer><button type="button" class="wf-btn" data-close>취소</button>${save ? `<button class="wf-btn wf-primary" type="submit">${h(label)}</button>` : ''}</footer></form>`;
    document.body.append(dialog);
    let dispose = () => {};
    const close = () => { dispose(); dialog.close(); dialog.remove(); };
    scope.track(() => { if (dialog.isConnected) close(); });
    dialog.addEventListener('click', event => { if (event.target.closest('[data-close]')) close(); });
    dialog.addEventListener('cancel', event => { event.preventDefault(); close(); });
    dialog.querySelector('form').addEventListener('submit', event => {
      event.preventDefault();
      if (save) scope.run(async () => { if (await save(dialog) !== false) close(); }, dialog.querySelector('[type="submit"]'));
    });
    if (mount) dispose = mount(dialog) || (() => {});
    dialog.showModal();
    return dialog;
  }
  function stableRequest() {
    let serialized = '', id = '';
    const request = body => { const next = JSON.stringify(body); if (next !== serialized) { serialized = next; id = uuid(); } return id; };
    request.clear = () => { serialized = ''; id = ''; };
    return request;
  }

  const filterOps = ['eq', 'ne', 'gt', 'gte', 'lt', 'lte', 'contains', 'regex', 'typed_eq', 'exists', 'number_gt', 'number_gte', 'number_lt', 'number_lte'];
  const opLabels = {eq: '같음', ne: '다름', gt: '초과', gte: '이상', lt: '미만', lte: '이하', contains: '포함', regex: '정규식 일치', typed_eq: '원본 유형과 값 일치', exists: '원본 필드 존재 · 1/0', number_gt: '원본 숫자 초과', number_gte: '원본 숫자 이상', number_lt: '원본 숫자 미만', number_lte: '원본 숫자 이하', typed_in: '원본 값 목록에 포함'};
  function freshPolicy() {
    return {name: '', entity_field: 'raw.security.user', window: 900, interval: 30, evaluation_delay: 0, cooldown: 900, risk_score: 40, severity: 'medium', mitre: [], enabled: false, steps: [{name: '인증 실패', min_count: 3, text: '', filters: [{field: 'raw.security.outcome', op: 'eq', value: 'failure'}]}]};
  }
  function policyBuilder(host, definition) {
    let model = {...freshPolicy(), ...copy(definition || {})};
    function filterRow(filter, index) {
      const retained = filter.op === 'typed_in' || !filterOps.includes(filter.op);
      let display = filter.value;
      if (filter.op === 'typed_in') { try { display = JSON.parse(filter.value).map(item => `${typeof item === 'number' ? '숫자' : '문자'}: ${String(item)}`).join(' · '); } catch (_) { display = '목록 조건을 확인할 수 없습니다'; } }
      return `<div class="wf-filter-row" data-filter="${index}">${field('이벤트 필드', 'field', filter.field, 'required placeholder="raw.security.outcome"')}${select('조건', 'op', retained ? [...filterOps, filter.op] : filterOps, filter.op, opLabels, retained ? 'disabled' : '')}${select('값 유형', 'value_type', ['string', 'number'], typeof filter.value === 'number' ? 'number' : 'string', {string: '문자', number: '숫자'}, retained ? 'disabled' : '')}${retained ? `<label class="wf-field"><span>보존된 조건 값</span><output>${h(display)}</output><small>원본 조건과 유형을 유지합니다. 변경하려면 이 조건을 삭제하고 새 조건을 추가하세요.</small></label>` : field('비교 값', 'value', filter.value)}<button type="button" class="wf-icon-btn wf-danger" data-builder="filter-remove" aria-label="조건 삭제">×</button></div>`;
    }
    function read() {
      return {
        name: value(host, 'policy_name').trim(), entity_field: value(host, 'entity_field').trim(),
        window: number(host, 'window'), interval: number(host, 'interval'), evaluation_delay: number(host, 'evaluation_delay'),
        cooldown: number(host, 'cooldown'), risk_score: number(host, 'risk_score'), severity: value(host, 'severity'),
        mitre: split(value(host, 'mitre')), enabled: checked(host, 'enabled'),
        steps: [...host.querySelectorAll('[data-step]')].map((node, stepIndex) => ({
          name: value(node, 'step_name').trim(), min_count: number(node, 'min_count'), text: value(node, 'step_text'),
          ...(value(node, 'within_seconds').trim() ? {within_seconds: number(node, 'within_seconds')} : {}),
          filters: [...node.querySelectorAll('[data-filter]')].map((row, filterIndex) => {
            const previous = model.steps[stepIndex]?.filters?.[filterIndex];
            if (previous && (previous.op === 'typed_in' || !filterOps.includes(previous.op))) return {...copy(previous), field: value(row, 'field').trim()};
            const v = value(row, 'value');
            if (value(row, 'value_type') === 'number' && (!v.trim() || !Number.isFinite(Number(v)))) throw new Error('숫자 조건에 유효한 값을 입력하세요.');
            const op = value(row, 'op'), typed = value(row, 'value_type') === 'number' ? Number(v) : v;
            if (op === 'exists' && ![0, 1].includes(typed)) throw new Error('존재 조건은 숫자 유형의 1 또는 0을 사용하세요.');
            if (op.startsWith('number_') && typeof typed !== 'number') throw new Error('원본 숫자 비교에는 숫자 값 유형을 선택하세요.');
            return {field: value(row, 'field').trim(), op, value: typed};
          })
        }))
      };
    }
    function paint() {
      host.innerHTML = `<div class="wf-grid wf-grid-3">${field('정책 이름', 'policy_name', model.name, 'required maxlength="120"')}${field('연결할 엔터티 필드', 'entity_field', model.entity_field, 'required placeholder="raw.security.user"')}${select('심각도', 'severity', severities, model.severity, labels)}${field('분석 시간 범위 · 초', 'window', model.window, 'required min="30" max="604800"', 'number')}${field('실행 간격 · 초', 'interval', model.interval, 'required min="30" max="86400"', 'number')}${field('늦은 이벤트 대기 · 초', 'evaluation_delay', model.evaluation_delay, 'required min="0" max="86400"', 'number')}${field('중복 알림 대기 · 초', 'cooldown', model.cooldown, 'required min="0" max="604800"', 'number')}${field('위험 기여도 · 1–100', 'risk_score', model.risk_score, 'required min="1" max="100"', 'number')}${field('MITRE 기법 · 쉼표로 구분', 'mitre', (model.mitre || []).join(', '), 'placeholder="T1110, T1078"')}</div><div class="wf-form-line">${check('저장 후 예약 실행 활성화', 'enabled', model.enabled)}<span class="wf-muted">처음에는 비활성 상태로 검증하는 것을 권장합니다.</span></div>${flow(model.steps.map(step => ({title: step.name || '새 단계', text: `${step.min_count || 1}개 이상 · 순서대로 일치`})), '상관 분석 순서')}<div class="wf-section-title"><h3>이벤트 단계</h3><button type="button" class="wf-btn" data-builder="step-add">+ 단계 추가</button></div>${model.steps.map((step, i) => `<section class="wf-step" data-step="${i}"><div class="wf-step-heading"><span class="wf-step-number">${i + 1}</span><strong>같은 엔터티의 다음 이벤트</strong><div class="wf-actions"><button type="button" class="wf-icon-btn" data-builder="step-up" ${i === 0 ? 'disabled' : ''} aria-label="단계 위로">↑</button><button type="button" class="wf-icon-btn" data-builder="step-down" ${i === model.steps.length - 1 ? 'disabled' : ''} aria-label="단계 아래로">↓</button><button type="button" class="wf-icon-btn wf-danger" data-builder="step-remove" ${model.steps.length === 1 ? 'disabled' : ''} aria-label="단계 삭제">×</button></div></div><div class="wf-grid wf-grid-3">${field('단계 이름', 'step_name', step.name, 'required maxlength="80"')}${field('최소 이벤트 수', 'min_count', step.min_count || 1, 'required min="1" max="100"', 'number')}${field('추가 자유 검색어', 'step_text', step.text || '', 'maxlength="2048"')}${i > 0 ? field('직전 단계 후 제한 · 초 / 비우면 전체 범위', 'within_seconds', step.within_seconds ?? '', `min="1" max="${h(model.window)}" step="1"`, 'number') : ''}</div><div class="wf-filter-label">모든 조건을 만족하는 이벤트</div>${(step.filters || []).map(filterRow).join('')}<button type="button" class="wf-btn wf-small" data-builder="filter-add">+ 조건 추가</button></section>`).join('')}${note('단계는 시간 순서대로 서로 다른 이벤트와 일치합니다. 동일 엔터티 필드를 사용하며, 조건들은 AND로 결합됩니다. 단계 시간 제한을 쓰면 모든 단계의 최소 이벤트 수는 1이어야 합니다. 시간 범위와 계정의 인덱스 권한이 적용됩니다.')}`;
    }
    const listener = event => {
      const btn = event.target.closest('[data-builder]');
      if (!btn || !host.contains(btn)) return;
      event.preventDefault();
      try {
        model = read();
        const index = Number(btn.closest('[data-step]')?.dataset.step || 0), step = model.steps[index];
        switch (btn.dataset.builder) {
          case 'step-add': if (model.steps.length >= 8) throw new Error('최대 8개 단계까지 지원합니다.'); model.steps.push({name: '새 단계', min_count: 1, filters: [], text: ''}); break;
          case 'step-remove': if (model.steps.length > 1) model.steps.splice(index, 1); break;
          case 'step-up': [model.steps[index - 1], model.steps[index]] = [step, model.steps[index - 1]]; break;
          case 'step-down': [model.steps[index + 1], model.steps[index]] = [step, model.steps[index + 1]]; break;
          case 'filter-add': if (step.filters.length >= 20) throw new Error('단계마다 조건은 최대 20개입니다.'); step.filters.push({field: 'source', op: 'eq', value: ''}); break;
          case 'filter-remove': step.filters.splice(Number(btn.closest('[data-filter]').dataset.filter), 1); break;
        }
        paint();
      } catch (err) { V.notify(err.message); }
    };
    host.addEventListener('click', listener);
    paint();
    return {read, destroy: () => host.removeEventListener('click', listener)};
  }

  async function policies(container) {
    const scope = scopeFor(container);
    let policies = [], templates = [], builder = null;
    const replayRequest = stableRequest();
    async function load() {
      scope.set(title('DETECTION ENGINEERING', '상관 분석 정책', '이벤트를 순서대로 연결하고 실제 데이터로 확인합니다.', button('새 정책', 'policy-new', '', 'wf-primary')) + '<div class="wf-loading">정책을 불러오는 중…</div>');
      [policies, templates] = await Promise.all([scope.get('/api/detections'), scope.get('/api/detections/templates')]);
      if (!scope.alive()) return;
      scope.set(title('DETECTION ENGINEERING', '상관 분석 정책', '이벤트를 순서대로 연결하고 실제 데이터로 확인합니다.', button('새 정책', 'policy-new', '', 'wf-primary')) + stats([['정책', policies.length], ['예약 실행 중', policies.filter(p => p.enabled).length], ['실행 오류', policies.filter(p => p.error).length]]) + `<div class="wf-two-column"><section class="wf-panel"><div class="wf-section-title"><h3>등록 정책</h3>${button('새로 고침', 'policy-refresh')}</div>${policies.length ? policies.map(policy => `<article class="wf-list-card"><div class="wf-card-top"><div><strong>${h(policy.name || policy.definition?.name)}</strong><small>${h(policy.definition?.entity_field || '')} · ${h(policy.owner)}</small></div>${pill(policy.enabled ? 'healthy' : 'neutral', policy.enabled ? '활성' : '비활성')}</div>${flow((policy.definition?.steps || []).map(s => ({title: s.name, text: `${s.min_count || 1}개 이상`})))}<div class="wf-tags">${pill(policy.definition?.severity)}${(policy.definition?.mitre || []).map(x => `<span>${h(x)}</span>`).join('')}</div>${policy.error ? errorBox(policy.error) : ''}<div class="wf-card-footer"><small>최근 평가 ${date(policy.last_end)} · v${h(policy.version)}</small><div class="wf-actions">${button('상세 / 복제', 'policy-open', `data-id="${h(policy.id)}"`)}${editable() ? button(policy.enabled ? '중지' : '활성화', 'policy-toggle', `data-id="${h(policy.id)}"`) + button('과거 구간 재평가', 'policy-replay', `data-id="${h(policy.id)}"`) : ''}</div></div></article>`).join('') : empty('상관 정책이 없습니다', '새 정책을 만들거나 오른쪽 템플릿에서 시작하세요.')}</section><aside class="wf-panel"><div class="wf-section-title"><h3>시작 템플릿</h3></div>${templates.map((template, i) => `<article class="wf-template"><span class="wf-eyebrow">ORDERED SEQUENCE</span><strong>${h(template.definition.name)}</strong><p>${h(template.definition.entity_field)} · ${template.definition.steps.length}단계</p>${button('이 템플릿 사용', 'policy-template', `data-index="${i}"`)}</article>`).join('')}${note('템플릿을 열어도 저장하거나 실행하지 않습니다. 미리보기는 탐지 결과를 저장하지 않으며, 재평가는 실제 탐지 결과를 기록합니다.')}</aside></div><section id="wf-policy-editor"></section>`);
    }
    function edit(definition, existing) {
      builder?.destroy();
      const host = container.querySelector('#wf-policy-editor');
      host.innerHTML = `<div class="wf-panel wf-editor-panel"><div class="wf-section-title"><div><span class="wf-eyebrow">POLICY BUILDER</span><h3>${existing ? '정책에서 새 정책 만들기' : '새 상관 정책'}</h3></div>${button('편집 닫기', 'policy-close')}</div>${existing ? note('기존 정책은 변경하지 않습니다. 수정한 정의를 새 정책으로 저장합니다. 버전 단위 전환이 필요하면 콘텐츠 패키지를 사용하세요.') : ''}<form data-form="policy"><div class="wf-policy-builder"></div><div class="wf-editor-toolbar">${field('평가 구간 종료', 'preview_end', localDate(now()), 'required', 'datetime-local')}<button type="submit" class="wf-btn" name="intent" value="preview">실제 데이터 미리보기</button><button type="submit" class="wf-btn wf-primary" name="intent" value="save">새 정책 저장</button></div></form><div class="wf-result"></div></div>`;
      builder = policyBuilder(host.querySelector('.wf-policy-builder'), {...definition, enabled: false});
      host.scrollIntoView({behavior: 'smooth', block: 'start'});
    }
    actions(scope, async (action, btn) => {
      const policy = policies.find(item => item.id === btn.dataset.id);
      if (action === 'policy-refresh') return load();
      if (action === 'policy-new') return edit(freshPolicy());
      if (action === 'policy-template') return edit(templates[Number(btn.dataset.index)].definition);
      if (action === 'policy-open') return edit(policy.definition, policy);
      if (action === 'policy-close') { builder?.destroy(); builder = null; container.querySelector('#wf-policy-editor').replaceChildren(); }
      if (action === 'policy-toggle') { await scope.send(`/api/detections/${enc(policy.id)}`, {enabled: !policy.enabled, version: policy.version}, 'PATCH'); V.notify('정책 실행 상태를 변경했습니다.'); await load(); }
      if (action === 'policy-replay') modal(scope, '과거 구간 재평가', note('선택한 구간에 정책을 다시 적용합니다. 일치하면 탐지 결과가 저장됩니다. 예약 실행의 늦은 이벤트 대기는 여기서 다시 적용하지 않습니다.') + field('평가 구간 종료', 'end', localDate(now()), 'required', 'datetime-local'), async dialog => {
        const body = {end: epoch(value(dialog, 'end')), version: policy.version};
        const result = await scope.send(`/api/detections/${enc(policy.id)}/replay`, {...body, request_id: replayRequest({id: policy.id, ...body})});
        replayRequest.clear();
        V.notify(`재평가 완료 · ${result.match_count ?? result.matches?.length ?? 0}개 일치`);
        await load();
      }, '탐지 결과 기록');
    });
    scope.on('submit', event => {
      if (!event.target.matches('[data-form="policy"]')) return;
      event.preventDefault();
      scope.run(async () => {
        const definition = builder.read();
        if (event.submitter?.value === 'save') { await scope.send('/api/detections', definition); V.notify('새 정책을 저장했습니다.'); await load(); }
        else {
          const result = await scope.send('/api/detections/preview', {definition, end: epoch(value(event.target, 'preview_end'))});
          if (scope.alive()) container.querySelector('#wf-policy-editor .wf-result').innerHTML = `<h3>미리보기 결과 ${pill('info', '저장하지 않음')}</h3>${stats([['일치 엔터티', result.match_count ?? result.matches?.length ?? 0]])}${describe(result.matches || [])}`;
        }
      }, event.submitter);
    });
    scope.track(() => builder?.destroy());
    await scope.run(load);
    return () => scope.close();
  }

  function actionDefaults(type) {
    if (type === 'endpoint_response') return {type, agent_id: '', evidence_event_id: '', reason: '', action: endpointTargetDefaults('inspect_process')};
    if (type === 'add_note') return {type, note: ''};
    if (type === 'add_task') return {type, title: '', description: '', assignee: '', mandatory: false, due_at: null};
    if (type === 'assign') return {type, assignee: ''};
    if (type === 'set_status') return {type, status: 'triage', note: ''};
    return {type: 'webhook', destination: '', payload: {}};
  }
  const actionNames = {add_note: '분석 메모', add_task: '작업 만들기', assign: '담당자 지정', set_status: '케이스 상태', webhook: '승인된 웹훅', endpoint_response: '엔드포인트 조사 / 대응'};
  const endpointNames = {inspect_process:'프로세스 조회', inspect_file:'파일 조회', collect_artifact:'증거 파일 수집 · 최대 2MiB', terminate_process:'정확한 프로세스 종료', quarantine_file:'파일 격리', restore_file:'격리 파일 복구', delete_file:'파일 삭제 · 복구 불가', isolate_host:'호스트 네트워크 격리', release_host:'호스트 격리 해제'};
  const outcomeFields = ['success','executed','code','type','data.quarantine_id','data.artifact_id','data.isolation_id','data.bytes'];
  function endpointTargetDefaults(type) {
    if (['inspect_process','terminate_process'].includes(type)) return {type,process_guid:'',pid:5,start_identity:''};
    if (['isolate_host','release_host'].includes(type)) return {type,management_allowlist_digest:'',...(type === 'release_host' ? {isolation_id:''} : {})};
    return {type,path:'',sha256:'',...(type === 'restore_file' ? {quarantine_id:''} : {})};
  }
  function endpointFields(action, dependencies = []) {
    const target = action.action || endpointTargetDefaults('inspect_process'), kind = target.type;
    let details = '';
    if (['inspect_process','terminate_process'].includes(kind)) details = field('프로세스 GUID','target_guid',target.process_guid,'required maxlength="256"') + field('PID · 5 이상','target_pid',target.pid,'required min="5" max="4294967295" step="1"','number') + field('시작 식별자','target_start',target.start_identity,'required maxlength="128" placeholder="windows:FILETIME 또는 linux:boot-id:ticks"');
    else if (['isolate_host','release_host'].includes(kind)) details = field('관리 통신 허용 목록 해시','target_management_digest',target.management_allowlist_digest,'required pattern="[0-9a-f]{64}" maxlength="64"');
    else details = field('정규화된 절대 파일 경로','target_path',target.path,'required maxlength="512"') + field('증거 파일 SHA256','target_sha',target.sha256,'required pattern="[A-Fa-f0-9]{64}" maxlength="64"');
    const receiptKey = kind === 'restore_file' ? 'quarantine_id' : kind === 'release_host' ? 'isolation_id' : null;
    if (receiptKey) {
      const receipt = target[receiptKey], reference = receipt && typeof receipt === 'object';
      details += select('복구 영수증 입력','receipt_mode',['literal','step'],reference ? 'step' : 'literal',{literal:'확정 영수증 ID',step:'의존 단계의 확인된 결과'});
      details += reference ? select('영수증을 제공한 의존 단계','receipt_step',dependencies,receipt.from_step,{},'required') : field('확정 영수증 ID','receipt_literal',receipt || '',`required pattern="${receiptKey === 'quarantine_id' ? 'Q-' : ''}[0-9a-f]{32}"`);
    }
    return `<div class="wf-grid">${field('등록된 에이전트 ID','endpoint_agent',action.agent_id,'required maxlength="256"')}${field('케이스 근거 이벤트 ID','endpoint_evidence',action.evidence_event_id,'required maxlength="256"')}${select('엔드포인트 동작','endpoint_kind',Object.keys(endpointNames),kind,endpointNames)}${details}</div>${area('조사 / 대응 사유','endpoint_reason',action.reason,'required maxlength="1000"')}${note('등록 에이전트의 서버 검증 근거만 사용합니다. 별도의 로컬 허용 정책이 필요하며 OS 결과를 받기 전에는 다음 단계를 진행하지 않습니다. 호스트 격리는 실제 네트워크 시험을 완료한 기능으로 표시하지 않습니다.')}`;
  }
  function readEndpoint(host) {
    const kind = value(host,'endpoint_kind'), target = {type:kind};
    if (!Object.hasOwn(endpointNames,kind)) throw new Error('지원하는 엔드포인트 동작을 선택하세요.');
    if (['inspect_process','terminate_process'].includes(kind)) Object.assign(target,{process_guid:value(host,'target_guid').trim(),pid:number(host,'target_pid'),start_identity:value(host,'target_start').trim()});
    else if (['isolate_host','release_host'].includes(kind)) target.management_allowlist_digest = value(host,'target_management_digest').trim();
    else Object.assign(target,{path:value(host,'target_path').trim(),sha256:value(host,'target_sha').trim()});
    const key = kind === 'restore_file' ? 'quarantine_id' : kind === 'release_host' ? 'isolation_id' : null;
    if (key) target[key] = value(host,'receipt_mode') === 'step' ? {from_step:value(host,'receipt_step'),field:`data.${key}`} : value(host,'receipt_literal').trim();
    return {type:'endpoint_response',agent_id:value(host,'endpoint_agent').trim(),evidence_event_id:value(host,'endpoint_evidence').trim(),reason:value(host,'endpoint_reason'),action:target};
  }
  function scalarCondition(type, text) {
    if (type === 'null') return null;
    if (type === 'boolean') { if (!['true','false'].includes(text)) throw new Error('참/거짓 조건에는 true 또는 false를 입력하세요.'); return text === 'true'; }
    if (type === 'number') { if (!text.trim() || !Number.isSafeInteger(Number(text))) throw new Error('결과 숫자 조건에는 안전한 정수를 입력하세요.'); return Number(text); }
    if (text.length > 256) throw new Error('조건 값은 최대 256자입니다.');
    return text;
  }
  function graphFields(step, steps, position) {
    const dependencies = step.depends_on ?? (position ? [steps[position-1].id] : []);
    const predicates = step.when?.all || [];
    return `<details class="wf-details" open><summary>의존성과 실행 조건</summary><div class="wf-form-line">${steps.filter(item=>item.id !== step.id).map(item=>check(`${item.id} 완료 후 실행`,'step_dep',dependencies.includes(item.id),`value="${h(item.id)}"`)).join('') || '<span class="wf-muted">의존할 다른 단계가 없습니다.</span>'}</div>${predicates.map((item,index)=>`<div class="wf-filter-row" data-outcome="${index}">${select('결과를 확인할 의존 단계','condition_step',dependencies,item.step,{},'required')}${select('확인할 결과','condition_field',outcomeFields,item.field)}${select('비교','condition_op',['eq','ne'],item.op,{eq:'같음',ne:'다름'})}${select('값 유형','condition_type',['string','number','boolean','null'],item.value === null ? 'null' : typeof item.value,{string:'문자',number:'정수',boolean:'참/거짓',null:'null'})}${field('비교 값','condition_value',item.value === null ? '' : String(item.value),'maxlength="256"')}<button type="button" class="wf-icon-btn wf-danger" data-action="condition-remove" data-index="${index}" aria-label="실행 조건 삭제">×</button></div>`).join('')}${button('+ 결과 조건','condition-add')}${note('모든 조건이 참인 경우 실행합니다. 없는 결과나 건너뛴 단계의 값은 조건을 충족하지 않습니다. 의존 관계는 비순환이어야 하며 실제 실행은 순서대로 처리됩니다.')}</details>`;
  }
  function readGraph(host) {
    const dependencies = [...host.querySelectorAll('[name="step_dep"]')].filter(item=>item.checked).map(item=>item.value);
    const predicates = [...host.querySelectorAll('[data-outcome]')].map(row=>({step:value(row,'condition_step'),field:value(row,'condition_field'),op:value(row,'condition_op'),value:scalarCondition(value(row,'condition_type'),value(row,'condition_value'))}));
    if (predicates.some(item=>!dependencies.includes(item.step))) throw new Error('조건은 선택한 의존 단계의 결과만 사용할 수 있습니다.');
    return {depends_on:dependencies,...(predicates.length ? {when:{all:predicates}} : {})};
  }
  function bindingPanel(books, policies, response) {
    const policyNames=Object.fromEntries(policies.map(item=>[item.id,item.name || item.definition?.name || item.id]));
    const bookNames=Object.fromEntries(books.map(item=>[item.id,item.name]));
    return `<section class="wf-panel"><div class="wf-section-title"><h3>정책 → 플레이북 승인 제안</h3>${button('+ 연결 만들기','binding-new',books.length && policies.length ? '' : 'disabled')}</div>${note('새 탐지 근거에 대해 승인 대기 실행을 제안합니다. 기본은 비활성이며 연결을 켜도 독립 승인은 생략하지 않습니다. 고정된 엔드포인트와 근거 ID가 포함된 플레이북은 케이스에 맞는지 승인 전에 검토하세요.')}${table(['정책','플레이북 / 고정 리비전','소유자','상태','오류',''],(response.bindings || []).map(item=>[h(policyNames[item.policy_id] || item.policy_id),`${h(bookNames[item.playbook_id] || item.playbook_id)} · v${h(item.revision)}`,h(item.owner),pill(item.enabled ? 'healthy' : 'neutral',item.enabled ? '승인 제안 활성' : '비활성'),item.error ? errorBox(item.error) : '—',button('연결 수정','binding-edit',`data-id="${h(item.id)}"`)]))}</section>`;
  }
  function renameReferences(steps, old, next) {
    if (old === next) return;
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/.test(next) || steps.some(item=>item.id !== old && item.id === next)) throw new Error('단계 식별자는 유효하고 고유해야 합니다.');
    for (const item of steps) {
      if (item.depends_on) item.depends_on = item.depends_on.map(id=>id === old ? next : id);
      for (const condition of item.when?.all || []) if (condition.step === old) condition.step = next;
      for (const key of ['quarantine_id','isolation_id']) if (item.action?.action?.[key]?.from_step === old) item.action.action[key].from_step = next;
    }
  }
  function scalarRows(object) {
    return Object.entries(object || {}).filter(([, val]) => val === null || typeof val !== 'object').map(([key, val]) => ({key, val, type: val === null ? 'null' : typeof val}));
  }
  function pairsHTML(rows, cls = 'wf-pair') {
    return rows.map((row, index) => `<div class="${cls} wf-pair-row" data-pair="${index}">${field('필드', 'pair_key', row.key, 'required')}${select('유형', 'pair_type', ['string', 'number', 'boolean', 'null'], row.type, {string: '문자', number: '숫자', boolean: '참/거짓', null: '비어 있음'})}${field('값', 'pair_value', row.val === null ? '' : String(row.val), 'placeholder="직접 입력한 값만 사용"')}<button type="button" class="wf-icon-btn wf-danger" data-pair-remove aria-label="필드 삭제">×</button></div>`).join('');
  }
  function readPairs(host) {
    const result = {};
    for (const row of host.querySelectorAll('[data-pair]')) {
      const key = value(row, 'pair_key').trim(), raw = value(row, 'pair_value'), type = value(row, 'pair_type');
      if (!key || ['__proto__', 'constructor', 'prototype'].includes(key) || Object.hasOwn(result, key)) throw new Error('필드 이름은 비어 있지 않은 고유한 이름이어야 합니다.');
      if (type === 'number' && (!raw.trim() || !Number.isFinite(Number(raw)))) throw new Error('숫자 값이 올바르지 않습니다.');
      if (type === 'boolean' && !['true', 'false'].includes(raw)) throw new Error('참/거짓 값은 true 또는 false를 입력하세요.');
      result[key] = type === 'number' ? Number(raw) : type === 'boolean' ? raw === 'true' : type === 'null' ? null : raw;
    }
    return result;
  }
  function actionFields(action, dependencies = []) {
    if (action.type === 'endpoint_response') return endpointFields(action, dependencies);
    if (action.type === 'add_note') return area('메모 내용', 'action_note', action.note, 'required maxlength="8000"');
    if (action.type === 'add_task') return `<div class="wf-grid">${field('작업 제목', 'action_title', action.title, 'required')}${field('담당 계정', 'action_assignee', action.assignee)}${field('마감 시간', 'action_due', localDate(action.due_at), '', 'datetime-local')}${check('완료해야 케이스를 종료할 수 있는 필수 작업', 'action_mandatory', action.mandatory)}</div>${area('작업 설명', 'action_description', action.description)}`;
    if (action.type === 'assign') return field('담당 계정', 'action_assignee', action.assignee, 'required');
    if (action.type === 'set_status') return `<div class="wf-grid">${select('변경할 상태', 'action_status', ['new', 'triage', 'resolved'], action.status, statuses)}${field('변경 사유', 'action_note', action.note, 'required')}</div>`;
    const nested = Object.entries(action.payload || {}).filter(([, val]) => val && typeof val === 'object');
    return field('서버에 등록된 전송 대상 이름', 'action_destination', action.destination, 'required placeholder="approved-ticketing"') + note('서버 관리자가 허용한 HTTPS 대상만 사용할 수 있습니다. URL과 자격 증명은 입력하지 않습니다. 아래 값은 고정된 내용이며 이벤트 변수를 치환하지 않습니다.') + `<div class="wf-payload-pairs">${pairsHTML(scalarRows(action.payload))}</div><button type="button" class="wf-btn wf-small" data-pair-add>+ 전송 필드 추가</button>${nested.length ? note(`가져온 중첩 필드 ${nested.map(([key]) => key).join(', ')}는 원본 그대로 유지합니다. 단순 필드와 같은 이름으로 덮어쓸 수 없습니다.`) : ''}`;
  }
  function readAction(host, previous) {
    const type = previous.type;
    if (type === 'endpoint_response') return readEndpoint(host);
    if (type === 'add_note') return {type, note: value(host, 'action_note')};
    if (type === 'add_task') return {type, title: value(host, 'action_title'), description: value(host, 'action_description'), assignee: value(host, 'action_assignee'), mandatory: checked(host, 'action_mandatory'), due_at: epoch(value(host, 'action_due'))};
    if (type === 'assign') return {type, assignee: value(host, 'action_assignee')};
    if (type === 'set_status') return {type, status: value(host, 'action_status'), note: value(host, 'action_note')};
    const nested = Object.fromEntries(Object.entries(previous.payload || {}).filter(([, val]) => val && typeof val === 'object'));
    const fields = readPairs(host);
    if (Object.keys(fields).some(key => Object.hasOwn(nested, key))) throw new Error('보존된 중첩 필드와 같은 이름은 사용할 수 없습니다.');
    return {type, destination: value(host, 'action_destination'), payload: {...nested, ...fields}};
  }
  function bindPairs(host) {
    const listener = event => {
      if (event.target.closest('[data-pair-remove]')) { event.preventDefault(); event.target.closest('[data-pair]').remove(); }
      if (event.target.closest('[data-pair-add]')) {
        event.preventDefault();
        host.querySelector('.wf-payload-pairs').insertAdjacentHTML('beforeend', pairsHTML([{key: '', val: '', type: 'string'}]));
      }
    };
    host.addEventListener('click', listener);
    return () => host.removeEventListener('click', listener);
  }
  async function playbooks(container, params = {}) {
    const scope = scopeFor(container);
    let books = [], runs = [], policies = [], bindings = [], book = null, selected = 0, model = {name: '', version: 0, steps: []};
    const startRequest = stableRequest();
    function readEditor(skipAction = false) {
      const root = container.querySelector('#wf-playbook-editor');
      if (!root) return;
      model.name = value(root, 'book_name');
      const step = model.steps[selected], props = root.querySelector('.wf-node-properties');
      if (step && props) {
        const next = value(props, 'step_id').trim(), old = step.id;
        const graph = readGraph(props);
        step.depends_on = graph.depends_on; if (graph.when) step.when = graph.when; else delete step.when;
        renameReferences(model.steps,old,next);
        step.id = next; step.max_attempts = number(props, 'max_attempts'); step.retry_base = number(props, 'retry_base');
        if (!skipAction) step.action = readAction(props, step.action);
      }
    }
    function paintEditor() {
      const root = container.querySelector('#wf-playbook-editor');
      const step = model.steps[selected];
      root.innerHTML = `<section class="wf-panel wf-editor-panel"><div class="wf-section-title"><div><span class="wf-eyebrow">VISUAL PLAYBOOK</span><h3>${book ? '플레이북 수정' : '새 플레이북'}</h3></div><div class="wf-actions">${button('편집 닫기', 'book-close')}${button('정의 저장', 'book-save', '', 'wf-primary')}</div></div>${field('플레이북 이름', 'book_name', model.name, 'required maxlength="120"')}<div class="wf-playbook-canvas"><aside class="wf-palette"><span class="wf-eyebrow">동작 추가</span>${Object.entries(actionNames).map(([type, label]) => button(`+ ${label}`, 'book-add', `data-type="${type}"`)).join('')}</aside><div class="wf-node-track"><div class="wf-start-node">사용자 실행 요청</div><div class="wf-vertical-line"></div><div class="wf-approval-node">독립된 다른 분석가의 승인</div>${model.steps.map((item, index) => `<div class="wf-vertical-line"></div><button type="button" class="wf-automation-node ${selected === index ? 'is-selected' : ''}" data-action="book-select" data-index="${index}"><span class="wf-step-number">${index + 1}</span><div><strong>${h(actionNames[item.action.type])}</strong><small>${h(item.id)} · ${h((item.depends_on || []).join(', ') || '독립 단계')}</small>${item.when ? '<small>확인된 결과 조건 적용</small>' : ''}</div></button>`).join('')}<div class="wf-vertical-line"></div><div class="wf-end-node">실행 기록 보관</div></div><aside class="wf-node-properties">${step ? `<div class="wf-section-title"><h3>${h(actionNames[step.action.type])}</h3><div class="wf-actions">${button('↑', 'book-up', selected ? '' : 'disabled')}${button('↓', 'book-down', selected < model.steps.length - 1 ? '' : 'disabled')}${button('삭제', 'book-remove', '', 'wf-danger')}</div></div>${field('단계 식별자', 'step_id', step.id, 'required pattern="[A-Za-z0-9][A-Za-z0-9_.-]{0,63}"')}${actionFields(step.action,step.depends_on ?? (selected ? [model.steps[selected-1].id] : []))}${graphFields(step,model.steps,selected)}<details class="wf-details"><summary>재시도 설정</summary><div class="wf-grid">${field('최대 시도 횟수', 'max_attempts', step.max_attempts ?? 3, 'required min="1" max="5"', 'number')}${field('재시도 기본 대기 · 초', 'retry_base', step.retry_base ?? 5, 'required min="1" max="300"', 'number')}</div></details>` : empty('동작을 추가하세요', '왼쪽 동작을 눌러 순서대로 구성합니다.')}</aside></div>${note('저장은 실행하지 않습니다. 케이스에 실행을 요청한 뒤 요청자와 다른 활성 분석가 또는 관리자가 승인해야 합니다. 웹훅은 별도의 서버 설정이 필요하며 결과 불명 상태는 직접 확인해야 합니다.')}</section>`;
    }
    async function load() {
      [books, runs, policies, bindings] = await Promise.all([scope.get('/api/playbooks'), scope.get('/api/playbook-runs'), scope.get('/api/detections'), scope.get('/api/playbook-bindings')]);
      if (!scope.alive()) return;
      scope.set(title('RESPONSE AUTOMATION', '플레이북', '승인을 거쳐 케이스 작업을 일관된 순서로 실행합니다.', button('새 플레이북', 'book-new', '', 'wf-primary')) + stats([['플레이북', books.length], ['승인 대기', (runs.runs || []).filter(r => r.state === 'pending_approval').length], ['표시된 실행', (runs.runs || []).length, runs.truncated ? '최근 100개 · 추가 기록 있음' : '권한이 있는 실행']]) + `<section class="wf-panel"><div class="wf-section-title"><h3>자동화 정의</h3>${button('새로 고침', 'book-refresh')}</div><div class="wf-card-grid">${books.map(item => `<article class="wf-list-card"><div class="wf-card-top"><div><span class="wf-eyebrow">APPROVAL REQUIRED</span><strong>${h(item.name)}</strong><small>v${h(item.version)} · ${h(item.owner)}</small></div></div><p class="wf-muted">수정 ${date(item.updated)}</p><div class="wf-actions">${button('편집', 'book-open', `data-id="${h(item.id)}"`)}${button('케이스에 실행 요청', 'book-start', `data-id="${h(item.id)}"`, 'wf-primary')}</div></article>`).join('') || empty('등록된 플레이북이 없습니다', '분석 메모, 작업, 담당자와 상태 변경을 조합하세요.')}</div></section><div id="wf-playbook-editor"></div>${bindingPanel(books,policies,bindings)}<section class="wf-panel"><div class="wf-section-title"><h3>실행 기록</h3><span class="wf-muted">${runs.truncated ? '최근 100개' : '최근 권한 범위 내 기록'}</span></div>${table(['실행', '케이스', '요청자 / 승인자', '상태', '수정', ''], (runs.runs || []).map(run => [h(short(run.id)), `<button class="wf-link" data-action="book-case" data-id="${h(run.incident_id)}">${h(short(run.incident_id))}</button>`, `${h(run.requested_by)} / ${h(run.approved_by || '—')}`, pill(run.state), h(date(run.updated)), button('상세', 'run-open', `data-id="${h(run.id)}"`)]))}</section>`);
    }
    async function openRun(id) {
      const run = await scope.get(`/api/playbook-runs/${enc(id)}`);
      if (!scope.alive()) return;
      modal(scope, '플레이북 실행', stats([['상태', statuses[run.state] || run.state], ['요청자', run.requested_by], ['승인자', run.approved_by || '—']]) + (run.snapshot?.evidence?.temporally_uncertain_contributions ? note(`시간·인과관계 불확실 근거 ${run.snapshot.evidence.temporally_uncertain_contributions}개: 실제 이벤트와 대상 장비를 직접 검토한 뒤 독립 승인하세요.`) : '') + (run.snapshot?.evidence?.inactive_adjudicated_contributions ? note(`오탐·예상 행위로 분류된 근거 ${run.snapshot.evidence.inactive_adjudicated_contributions}개가 있습니다. 활성 위협 근거를 확인하세요.`) : '') + flow((run.steps || []).map(step => ({title: actionNames[step.action?.type] || step.step_id, text: `${statuses[step.state] || step.state} · 시도 ${step.attempts}`}))) + (run.error ? errorBox(run.error) : '') + `<div class="wf-actions">${run.state === 'pending_approval' && run.requested_by !== session().name ? button('이 실행 승인', 'modal-run-approve', `data-id="${h(id)}"`, 'wf-primary') : ''}${!['completed', 'failed', 'cancelled', 'unknown'].includes(run.state) ? button('실행 취소 요청', 'modal-run-cancel', `data-id="${h(id)}"`, 'wf-danger') : ''}</div>${run.state === 'pending_approval' && run.requested_by === session().name ? note('본인이 요청한 실행은 승인할 수 없습니다. 다른 활성 분석가 또는 관리자가 승인해야 합니다.') : ''}${table(['단계', '동작', '상태', '결과'], (run.steps || []).map(step => [h(step.step_id), h(actionNames[step.action?.type] || step.action?.type), pill(step.state), step.error ? errorBox(step.error) : describe(step.result)]))}<details class="wf-details"><summary>승인 시점의 범위와 정의</summary>${describe({requested_scope: run.requested_scope, approved_scope: run.approved_scope, definition: run.definition})}</details>`, null, '', dialog => {
        const listener = event => {
          const btn = event.target.closest('[data-action]');
          if (!btn) return;
          scope.run(async () => {
            await scope.send(`/api/playbook-runs/${enc(id)}/${btn.dataset.action === 'modal-run-approve' ? 'approve' : 'cancel'}`, {});
            dialog.close(); dialog.remove(); await load(); V.notify('실행 상태를 변경했습니다.');
          }, btn);
        };
        dialog.addEventListener('click', listener);
        return () => dialog.removeEventListener('click', listener);
      });
    }
    actions(scope, async (action, btn) => {
      if (action === 'book-refresh') return load();
      if (action === 'book-case') return V.navigate('cases', {id: btn.dataset.id});
      if (action === 'book-new') { book = null; model = {name: '', version: 0, steps: []}; selected = 0; paintEditor(); container.querySelector('#wf-playbook-editor').scrollIntoView({behavior: 'smooth'}); }
      if (action === 'book-open') { book = await scope.get(`/api/playbooks/${enc(btn.dataset.id)}`); model = {...copy(book.definition), version: book.version}; model.steps.forEach((item,index)=>{item.depends_on ??= index ? [model.steps[index-1].id] : [];}); selected = 0; if (scope.alive()) { paintEditor(); container.querySelector('#wf-playbook-editor').scrollIntoView({behavior: 'smooth'}); } }
      if (action === 'book-close') container.querySelector('#wf-playbook-editor').replaceChildren();
      if (action === 'book-select') { readEditor(); selected = Number(btn.dataset.index); paintEditor(); }
      if (action === 'book-add') { readEditor(); if (model.steps.length >= 16) throw new Error('최대 16개 동작을 지원합니다.'); model.steps.push({id: `step-${uuid().slice(0, 8)}`, action: actionDefaults(btn.dataset.type), depends_on: model.steps.length ? [model.steps.at(-1).id] : [], max_attempts: 3, retry_base: 5}); selected = model.steps.length - 1; paintEditor(); }
      if (action === 'book-up' || action === 'book-down') { readEditor(); const target = selected + (action === 'book-up' ? -1 : 1); [model.steps[selected], model.steps[target]] = [model.steps[target], model.steps[selected]]; selected = target; paintEditor(); }
      if (action === 'book-remove') { readEditor(); const id = model.steps[selected].id; if (model.steps.some(item=>item !== model.steps[selected] && item.depends_on?.includes(id))) throw new Error('다른 단계의 의존성을 먼저 해제해야 이 단계를 삭제할 수 있습니다.'); model.steps.splice(selected, 1); selected = Math.max(0, selected - 1); paintEditor(); }
      if (action === 'condition-add') { readEditor(); const step = model.steps[selected]; if (!step.depends_on.length) throw new Error('먼저 의존할 단계를 선택하세요.'); step.when ??= {all:[]}; if (step.when.all.length >= 8) throw new Error('실행 조건은 최대 8개입니다.'); step.when.all.push({step:step.depends_on[0],field:'success',op:'eq',value:true}); paintEditor(); }
      if (action === 'condition-remove') { readEditor(); const step=model.steps[selected]; step.when.all.splice(Number(btn.dataset.index),1); if (!step.when.all.length) delete step.when; paintEditor(); }
      if (action === 'binding-new' || action === 'binding-edit') {
        const existing = action === 'binding-edit' ? bindings.bindings.find(item=>item.id === btn.dataset.id) : null;
        const policyNames = Object.fromEntries(policies.map(item=>[item.id,item.name || item.definition?.name || item.id]));
        const bookNames = Object.fromEntries(books.map(item=>[item.id,item.name]));
        modal(scope,'정책 → 플레이북 승인 제안',select('상관 정책','binding_policy',policies.map(item=>item.id),existing?.policy_id || policies[0]?.id,policyNames,`required ${existing ? 'disabled' : ''}`)+select('플레이북 · 현재 리비전에 고정','binding_book',books.map(item=>item.id),existing?.playbook_id || books[0]?.id,bookNames,'required')+check('새 근거가 생긴 케이스에 승인 대기 실행 제안','binding_enabled',!!existing?.enabled)+note('이 선택은 자동 승인이 아닙니다. 이미 존재하는 근거를 소급 적용하지 않으며, 요청자와 다른 활성 분석가의 승인이 필요합니다. 플레이북 리비전이나 권한이 달라지면 연결은 중지됩니다. 정책과 플레이북 소유자 또는 테넌트 관리자 권한이 필요합니다.'),async dialog=>{await scope.send('/api/playbook-bindings',{policy_id:value(dialog,'binding_policy'),playbook_id:value(dialog,'binding_book'),enabled:checked(dialog,'binding_enabled'),version:existing?.version || 0}); V.notify('승인 제안 연결을 저장했습니다.'); await load();},'연결 저장');
      }
      if (action === 'book-save') { readEditor(); const root = container.querySelector('#wf-playbook-editor'); const invalid = [...root.querySelectorAll('input,select,textarea')].find(el => !el.checkValidity()); if (invalid) { invalid.reportValidity(); return; } await scope.send(book ? `/api/playbooks/${enc(book.id)}` : '/api/playbooks', model, book ? 'PUT' : 'POST'); V.notify('플레이북 정의를 저장했습니다.'); await load(); }
      if (action === 'book-start') {
        modal(scope, '케이스에 실행 요청', field('케이스 식별자', 'incident_id', params.incident_id || '', 'required') + note('이 작업은 승인 대기 중인 실행을 만듭니다. 승인 전에는 동작을 실행하지 않습니다.'), async dialog => {
          const body = {incident_id: value(dialog, 'incident_id').trim()};
          const result = await scope.send(`/api/playbooks/${enc(btn.dataset.id)}/runs`, {...body, request_id: startRequest({book: btn.dataset.id, ...body})});
          startRequest.clear();
          V.notify('승인 대기 실행을 만들었습니다.'); await load(); await openRun(result.id);
        }, '승인 요청');
      }
      if (action === 'run-open') return openRun(btn.dataset.id);
    });
    scope.on('click', event => {
      if (event.target.closest('[data-pair-remove]')) event.target.closest('[data-pair]').remove();
      if (event.target.closest('[data-pair-add]')) container.querySelector('.wf-payload-pairs').insertAdjacentHTML('beforeend', pairsHTML([{key: '', val: '', type: 'string'}]));
    });
    scope.on('change', event => {
      const name = event.target.name;
      if (!['endpoint_kind','receipt_mode','step_dep'].includes(name)) return;
      scope.run(()=>{
        const step=model.steps[selected], root=container.querySelector('#wf-playbook-editor'), props=root.querySelector('.wf-node-properties');
        if (name === 'endpoint_kind') {
          readEditor(true);
          const kind=value(props,'endpoint_kind');
          const outer={agent_id:value(props,'endpoint_agent'),evidence_event_id:value(props,'endpoint_evidence'),reason:value(props,'endpoint_reason')};
          step.action={type:'endpoint_response',...outer,action:endpointTargetDefaults(kind)};
          paintEditor(); return;
        }
        if (name === 'receipt_mode') {
          readEditor(true);
          const key=step.action.action.type === 'restore_file' ? 'quarantine_id' : 'isolation_id';
          step.action=readEndpoint(props);
          step.action.action[key]=value(props,'receipt_mode') === 'step' ? {from_step:step.depends_on?.[0] || '',field:`data.${key}`} : '';
          paintEditor(); return;
        }
        readEditor(); paintEditor();
      });
    });
    await scope.run(load);
    if (params.run_id) await scope.run(() => openRun(params.run_id));
    return () => scope.close();
  }

  async function cases(container, params = {}) {
    const scope = scopeFor(container);
    let rows = [], findingRows = [], incident = null, workspace = null, runs = [], attackContext = null, enhancementCleanup = null, openGeneration = 0, tab = params.tab || 'overview', cursor = null, cursors = [], listMode = 'cases';
    function closeEnhancement() { if (enhancementCleanup) enhancementCleanup(); enhancementCleanup = null; }
    const actionRequest = stableRequest();
    const severityOf = item => item.severity || (item.contributions || []).map(c => c.evidence?.severity).filter(Boolean).sort((a, b) => severities.indexOf(a) - severities.indexOf(b))[0] || '';
    const listTabs = mode => `<div class="wf-tabs" role="tablist"><button type="button" role="tab" aria-selected="${mode === 'cases'}" class="${mode === 'cases' ? 'active' : ''}" data-action="case-mode" data-mode="cases">상관 분석 케이스</button><button type="button" role="tab" aria-selected="${mode === 'findings'}" class="${mode === 'findings' ? 'active' : ''}" data-action="case-mode" data-mode="findings">저장 검색 탐지 결과</button></div>`;
    function filteredCards() {
      const query = value(container, 'case_search').toLowerCase(), status = value(container, 'case_status'), severity = value(container, 'case_severity');
      const selected = rows.filter(row => (!status || row.status === status) && (!severity || (severity === 'unknown' ? !severityOf(row) : severityOf(row) === severity)) && (!query || `${row.name} ${row.entity} ${row.owner} ${row.id}`.toLowerCase().includes(query)));
      const host = container.querySelector('#wf-case-cards');
      if (!host) return;
      host.innerHTML = selected.length ? selected.map(row => `<article class="wf-case-card"><div class="wf-card-top"><div class="wf-tags">${pill(severityOf(row))}${pill(row.status)}</div><small>${h(short(row.id))}</small></div><button class="wf-case-title" data-action="case-open" data-id="${h(row.id)}">${h(row.name)}</button><div class="wf-case-entity"><span>${h(row.entity_field)}</span><strong>${h(row.entity)}</strong></div><div class="wf-card-footer"><span>${h(row.contribution_count)}개 탐지 근거</span><span>${h(row.owner || '미할당')}</span></div><div class="wf-card-footer"><small>수정 ${date(row.updated)}</small>${button('케이스 열기 →', 'case-open', `data-id="${h(row.id)}"`)}</div></article>`).join('') : empty('조건에 맞는 케이스가 없습니다', '필터를 조정하거나 새로운 탐지 결과를 기다리세요.');
      container.querySelector('#wf-case-count').textContent = `${selected.length}개 표시`;
    }
    async function list() {
      closeEnhancement();
      openGeneration++;
      listMode = 'cases';
      incident = null;
      scope.set(title('INVESTIGATION WORKSPACE', '케이스', '탐지 근거에서 조사, 작업과 승인된 대응으로 이어집니다.', button('새로 고침', 'case-refresh')) + '<div class="wf-loading">케이스를 불러오는 중…</div>');
      rows = await scope.get('/api/incidents');
      const readiness = editable() ? await scope.get('/api/detection-readiness').catch(() => null) : null;
      if (!scope.alive()) return;
      scope.set(title('INVESTIGATION WORKSPACE', '케이스', '탐지 근거에서 조사, 작업과 승인된 대응으로 이어집니다.', button('새로 고침', 'case-refresh')) + stats([['조회된 케이스', rows.length, '최근 수정순 · 최대 200개'], ['신규', rows.filter(r => r.status === 'new').length, '조회 목록 기준'], ['분석 중', rows.filter(r => r.status === 'triage').length, '조회 목록 기준'], ['해결', rows.filter(r => r.status === 'resolved').length, '조회 목록 기준']]) + listTabs('cases') + (readiness?.state === 'onboarding_required' ? note('자동 탐지 준비가 필요합니다. 등록 에이전트와 활성 분석을 확인하고 검증된 관찰 정책부터 설정하세요.') + `<div class="wf-actions"><button data-route="agents">에이전트 연결</button><button data-route="analysis">분석 정책 설정</button></div>` : '') + `<div class="wf-filter-bar">${field('케이스 검색', 'case_search', '', 'placeholder="제목, 엔터티, 담당자"')}${select('상태', 'case_status', ['', 'new', 'triage', 'resolved', 'false_positive'], '', {'': '모든 상태', ...statuses})}${select('심각도', 'case_severity', ['', ...severities, 'unknown'], '', {'': '모든 심각도', ...labels, unknown: '미분류'})}<span id="wf-case-count" class="wf-muted"></span></div><div class="wf-case-grid" id="wf-case-cards"></div>${note('근거 전체에 접근 가능한 최근 수정순 최대 200개 케이스입니다. 심각도는 서버가 제공한 최근 탐지 근거를 사용하고, 제공되지 않은 값은 미분류로 표시합니다.')}`);
      if (severities.includes(params.severity)) container.querySelector('[name="case_severity"]').value = params.severity;
      if (['new', 'triage', 'resolved', 'false_positive'].includes(params.status)) container.querySelector('[name="case_status"]').value = params.status;
      filteredCards();
      try {
        const summary = await scope.get('/api/console/summary');
        if (!scope.alive() || incident || listMode !== 'cases') return;
        const recent = summary.cases?.recent || [];
        rows = rows.map(row => ({...row, severity: recent.find(item => item.id === row.id)?.severity || row.severity}));
        filteredCards();
      } catch (_) { /* Optional severity enrichment never gates case workflows. */ }
    }
    function paintFindings() {
      const query = value(container, 'finding_search').toLowerCase(), status = value(container, 'finding_status');
      const selected = findingRows.filter(row => (!status || row.status === status) && (!query || `${row.name} ${row.owner} ${row.id}`.toLowerCase().includes(query)));
      container.querySelector('#wf-findings-table').innerHTML = table(['탐지 결과', '상태', '담당', '생성', ''], selected.map(row => [`<strong>${h(row.name)}</strong><small>${h(short(row.id))}</small>`, pill(row.status), h(row.owner || '미할당'), h(date(row.created)), button('근거 검토', 'finding-open', `data-id="${h(row.id)}"`)]));
    }
    async function findingsList() {
      closeEnhancement();
      openGeneration++;
      incident = null; listMode = 'findings';
      findingRows = await scope.get('/api/findings');
      if (!scope.alive()) return;
      scope.set(title('SAVED SEARCH FINDINGS', '저장 검색 탐지 결과', '예약 검색에서 임계값을 만족한 결과와 저장된 샘플을 검토합니다.', button('새로 고침', 'case-refresh')) + listTabs('findings') + `<section class="wf-panel"><div class="wf-filter-bar">${field('탐지 결과 검색', 'finding_search', '', 'placeholder="이름, 담당, 식별자"')}${select('상태', 'finding_status', ['', 'new', 'triage', 'resolved', 'false_positive'], '', {'': '모든 상태', ...statuses})}</div><div id="wf-findings-table"></div>${note('최신 200개 후보 중 현재 계정이 근거 범위에 접근할 수 있는 결과를 표시합니다. 저장 검색 결과는 상관 분석 케이스와 별도로 관리하며, 샘플은 최대 10개입니다.')}</section>`);
      paintFindings();
    }
    async function open(id, nextCursor = null) {
      const generation = ++openGeneration;
      cursor = nextCursor;
      const values = await Promise.all([scope.get(`/api/incidents/${enc(id)}${cursor ? `?cursor=${enc(cursor)}` : ''}`), scope.get(`/api/incidents/${enc(id)}/workspace`), editable() ? scope.get(`/api/playbook-runs?incident_id=${enc(id)}`) : Promise.resolve({runs: []}), window.VatexInvestigation ? window.VatexInvestigation.loadContext(scope,id) : Promise.resolve(null)]);
      if (!scope.alive() || generation !== openGeneration) return;
      [incident, workspace] = values;
      runs = values[2];
      attackContext = values[3];
      if (attackContext && !attackContext._error) incident.severity = attackContext.severity;
      if (scope.alive()) paintDetail();
    }
    function paging() {
      return `<div class="wf-pagination"><span>현재 근거 페이지 · ${h(incident.page_count ?? incident.contributions?.length ?? 0)}개 / 전체 ${h(incident.contribution_count)}개</span><div class="wf-actions">${button('이전', 'case-prev', cursors.length ? '' : 'disabled')}${button('다음', 'case-next', incident.next_cursor ? '' : 'disabled')}</div></div>`;
    }
    function verdictControls(contribution) {
      const verdict = contribution.adjudication || {classification: 'unknown', version: 0};
      const grade = contribution.evidence?.case_quality?.association_grade || contribution.evidence?.episode?.grade;
      const association = grade === 'exact_reported_identity' ? '보고된 프로세스·세션 식별자로 연결' : grade === 'entity_time_hypothesis' ? '같은 개체와 가까운 시각으로 연결한 분석 가설' : '연결 근거 확인 필요';
      return `<div class="wf-tags">${pill(verdict.classification, statuses[verdict.classification])}${verdict.stale ? pill('unknown', '판정 이후 증거 변경 · 재검토 필요') : ''}${editable() ? button('이 근거 판정', 'case-verdict', `data-id="${h(contribution.id)}"`) : ''}</div><p class="wf-muted">${h(association)} · 원인 관계와 실제 수집 환경은 별도 확인</p>${verdict.reason ? `<p class="wf-muted">${h(verdict.reason)}</p>` : ''}`;
    }
    function overview() {
      const w = workspace.workspace;
      return `<div class="wf-two-column"><section class="wf-panel"><div class="wf-section-title"><h3>조사 개요</h3>${editable() ? button('상태 / 담당자 변경', 'case-edit') : ''}</div><dl class="wf-kv"><div><dt>연결 기준</dt><dd>${h(incident.entity_field)} · ${h(incident.entity)}</dd></div><div><dt>담당자</dt><dd>${h(incident.owner || '미할당')}</dd></div><div><dt>생성 / 수정</dt><dd>${date(incident.created)} / ${date(incident.updated)}</dd></div><div><dt>우선순위</dt><dd>${pill(w.priority)} ${w.overdue ? pill('critical', '기한 초과') : ''}</dd></div><div><dt>마감</dt><dd>${date(w.due_at)}</dd></div><div><dt>태그</dt><dd><div class="wf-tags">${w.tags.map(t => `<span>${h(t)}</span>`).join('') || '—'}</div></dd></div></dl>${editable() ? button('우선순위와 마감 편집', 'case-configure') : ''}<div class="wf-section-title"><h3>근거 정책</h3></div>${(incident.contributions || []).map(contribution => `<article class="wf-subcard"><div class="wf-card-top"><strong>${h(contribution.evidence?.policy_name || contribution.policy_id)}</strong>${pill(contribution.evidence?.severity)}</div><small>${date(contribution.at)} · 위험 기여 ${h(contribution.weight)}</small>${verdictControls(contribution)}${flow((contribution.evidence?.steps || []).map(step => ({title: step.step, text: `${step.matched ?? step.events?.length ?? 0}개 이벤트`})))}</article>`).join('')}${paging()}</section><aside class="wf-panel"><div class="wf-section-title"><h3>분석 메모</h3>${editable() ? button('+ 메모', 'case-note') : ''}</div>${workspace.notes.map(item => `<article class="wf-note-card"><div><strong>${h(item.actor)}</strong><small>${date(item.at)}</small></div><p>${h(item.note)}</p></article>`).join('') || empty('분석 메모가 없습니다')}${workspace.notes_truncated ? note(`최근 100개 메모를 표시합니다. 전체 ${workspace.notes_total}개입니다.`) : ''}<div class="wf-section-title"><h3>이벤트 북마크</h3>${editable() ? button('+ 북마크', 'case-bookmark') : ''}</div>${workspace.bookmarks.map(item => `<div class="wf-bookmark"><strong>${h(item.label || item.event_id)}</strong><small>${h(item.index_name)} · ${h(item.event_id)}</small></div>`).join('') || '<p class="wf-muted">북마크가 없습니다.</p>'}</aside></div>`;
    }
    function timeline() {
      return `<section class="wf-panel"><div class="wf-section-title"><h3>탐지 근거 타임라인</h3><span class="wf-muted">현재 근거 페이지의 이벤트</span></div>${(incident.timeline || []).map((event, index) => `<article class="wf-timeline-item"><div class="wf-timeline-dot"></div><time>${date(event.event_time)}</time><div class="wf-timeline-content"><div class="wf-card-top"><strong>${h(event.step)}</strong>${pill(event.severity)}</div><p>${h(event.host || '')} ${event.source ? `· ${h(event.source)}` : ''}</p><div class="wf-tags"><span>${h(event.index || event.index_name || '')}</span><span>${h(short(event.event_id))}</span></div>${button('이벤트 근거 보기', 'case-event', `data-index="${index}"`)}</div></article>`).join('') || empty('현재 페이지에 이벤트가 없습니다')}${paging()}${note('시간순 이벤트 목록입니다. 페이지를 넘기면 해당 탐지 근거의 이벤트를 표시합니다. 일부 이벤트 필드는 저장된 최소 근거만 포함할 수 있습니다.')}</section>`;
    }
    function graph() {
      const nodes = [{id: 'entity', type: 'entity', name: incident.entity, label: incident.entity}], edges = [], seen = new Set();
      (incident.contributions || []).forEach((contribution, ci) => {
        const policyId = `policy-${ci}`;
        nodes.push({id: policyId, type: 'policy', name: contribution.evidence?.policy_name || short(contribution.policy_id), label: contribution.evidence?.policy_name || short(contribution.policy_id)});
        edges.push({source: 'entity', target: policyId, relation: '탐지 근거', label: '탐지 근거'});
        (contribution.evidence?.steps || []).forEach(step => (step.events || []).forEach(event => {
          const id = `event-${event.event_id}`;
          if (!seen.has(id)) { seen.add(id); nodes.push({id, type: 'event', name: event.host || short(event.event_id), label: event.host || short(event.event_id)}); }
          edges.push({source: policyId, target: id, relation: step.step, label: step.step});
        }));
      });
      return `<section class="wf-panel"><div class="wf-section-title"><h3>케이스 근거 관계</h3><span class="wf-muted">현재 페이지 · ${seen.size}개 고유 이벤트</span></div><div class="wf-case-graph">${V.graphSVG(nodes, edges, {height: 420, label: '케이스에 저장된 정책과 이벤트 근거'})}</div>${note('선은 케이스에 저장된 엔터티, 탐지 정책과 이벤트의 근거 관계를 뜻합니다. 네트워크 연결이나 인과관계를 나타내지 않습니다. 현재 근거 페이지에 한정됩니다.')}${paging()}</section>`;
    }
    function tasks() {
      return `<section class="wf-panel"><div class="wf-section-title"><h3>조사 작업</h3>${editable() ? button('+ 작업 추가', 'case-task', '', 'wf-primary') : ''}</div>${workspace.tasks.map(task => `<article class="wf-task"><div><div class="wf-tags">${pill(task.status)}${task.mandatory ? pill('high', '필수') : ''}${task.due_at && task.due_at < now() && task.status !== 'done' ? pill('critical', '기한 초과') : ''}</div><strong>${h(task.title)}</strong><p>${h(task.description)}</p><small>${h(task.assignee || '미할당')} · 마감 ${date(task.due_at)}</small></div>${editable() ? button('업데이트', 'case-task-edit', `data-id="${h(task.id)}"`) : ''}</article>`).join('') || empty('작업이 없습니다', '필수 작업은 완료해야 케이스를 종료할 수 있습니다.')}${note('필수 작업이 완료되지 않으면 해결 또는 오탐으로 종료할 수 없습니다. 작업 취소와 완료 상태는 기록에 남습니다.')}</section>`;
    }
    function executions() {
      return `<section class="wf-panel"><div class="wf-section-title"><h3>승인 및 실행 기록</h3>${editable() ? button('플레이북 실행 요청', 'case-playbook', '', 'wf-primary') : ''}</div>${table(['실행', '요청자', '승인자', '상태', '수정', ''], (runs.runs || []).map(run => [h(short(run.id)), h(run.requested_by), h(run.approved_by || '—'), pill(run.state), h(date(run.updated)), button('실행 검토', 'case-run', `data-id="${h(run.id)}"`)]))}${runs.truncated ? note('최근 권한 범위 내 100개 실행을 표시합니다.') : ''}${note('플레이북 실행에는 요청자와 다른 활성 분석가 또는 관리자의 승인이 필요합니다. 실행 검토에서 단계별 결과와 승인 범위를 확인하세요.')}</section>`;
    }
    function paintDetail() {
      closeEnhancement();
      const tabs = [['overview', '개요'], ['attack', 'ATT&CK 매트릭스'], ['timeline', '타임라인'], ['graph', '근거 그래프'], ['hold','원본 보존'], ['tasks', `작업 ${workspace.tasks.filter(t => t.status !== 'done').length}`], ['response', '수동 대응'], ['executions', '실행 기록']];
      const extra = ['attack','response','hold'].includes(tab) ? '<div data-case-investigation></div>' : null;
      scope.set(title('CASE INVESTIGATION', incident.name, `${incident.entity_field} · ${incident.entity}`, button('← 케이스 목록', 'case-list') + button('내보내기', 'case-export') + button('새로 고침', 'case-detail-refresh') + (editable() ? button('근거 분리', 'case-split') + button('케이스 병합', 'case-merge') : '') + button('분리·병합 이력', 'case-movements')) + `<div class="wf-case-summary"><div class="wf-tags">${pill(incident.status)}${pill(severityOf(incident))}<span>${h(incident.id)}</span></div><span>${h(incident.contribution_count)}개 탐지 근거 · v${h(incident.version)}</span></div>${window.VatexInvestigation?window.VatexInvestigation.header(attackContext):''}<div class="wf-tabs" role="tablist">${tabs.map(([name, label]) => `<button type="button" role="tab" aria-selected="${tab === name}" class="${tab === name ? 'active' : ''}" data-action="case-tab" data-tab="${name}">${h(label)}</button>`).join('')}</div><div class="wf-tab-content">${extra ?? ({overview, timeline, graph, tasks, executions}[tab] || overview)()}</div>`);
      const host = container.querySelector('[data-case-investigation]'), extension = window.VatexInvestigation;
      if (host && extension) {
        const mount = tab === 'attack' ? extension.mountMatrix : tab === 'hold' ? extension.mountHold : extension.mountResponse;
        if (mount) scope.run(async () => {
          const cleanup = await mount(host,{scope,context:attackContext,incident,onChange:()=>open(incident.id,cursor)});
          if (!scope.alive() || !host.isConnected) cleanup?.(); else enhancementCleanup = cleanup;
        });
        else host.innerHTML = note('수동 대응 화면을 준비 중입니다.');
      }
    }
    async function act(action) {
      await scope.send(`/api/incidents/${enc(incident.id)}/actions`, {request_id: actionRequest({id: incident.id, action}), action});
      actionRequest.clear();
      V.notify('케이스 작업을 기록했습니다.'); await open(incident.id, cursor);
    }
    actions(scope, async (action, btn) => {
      if (action === 'case-refresh') return listMode === 'findings' && !incident ? findingsList() : incident ? open(incident.id, cursor) : list();
      if (action === 'case-list') { cursors = []; return list(); }
      if (action === 'case-mode') return btn.dataset.mode === 'findings' ? findingsList() : list();
      if (action === 'finding-open') {
        const finding = findingRows.find(row => row.id === btn.dataset.id);
        let evidence; try { evidence = typeof finding.evidence === 'string' ? JSON.parse(finding.evidence) : finding.evidence; } catch (_) { throw new Error('저장된 근거를 읽을 수 없습니다.'); }
        const samples = evidence.sample || [], keys = [...new Set(samples.flatMap(row => Object.keys(row)))].slice(0, 12);
        modal(scope, '저장 검색 탐지 근거', `<h3>${h(finding.name)}</h3>${stats([['평가 시작', date(evidence.earliest)], ['평가 종료', date(evidence.latest)], ['최소 일치 결과', evidence.matched_at_least ?? '—']])}${table(keys, samples.map(row => keys.map(key => describe(row[key]))))}${editable() ? `<div class="wf-grid">${select('상태', 'finding_status_edit', ['new', 'triage', 'resolved', 'false_positive'], finding.status, statuses)}${field('담당 값', 'finding_owner', finding.owner)}</div>` : ''}<details class="wf-details"><summary>전체 저장 근거와 접근 범위</summary>${describe(evidence)}</details>`, editable() ? async dialog => { await scope.send(`/api/findings/${enc(finding.id)}`, {status: value(dialog, 'finding_status_edit'), owner: value(dialog, 'finding_owner'), version: finding.version}, 'PATCH'); await findingsList(); V.notify('탐지 결과를 업데이트했습니다.'); } : null);
      }
      if (action === 'case-open') { cursors = []; tab = 'overview'; return open(btn.dataset.id); }
      if (action === 'case-tab') { tab = btn.dataset.tab; paintDetail(); }
      if (action === 'case-detail-refresh') return open(incident.id, cursor);
      if (action === 'case-next') { cursors.push(cursor); return open(incident.id, incident.next_cursor); }
      if (action === 'case-prev') return open(incident.id, cursors.pop());
      if (action === 'case-export') return V.download(`case-${incident.id}.json`, await scope.get(`/api/incidents/${enc(incident.id)}/export`));
      if (action === 'case-verdict') {
        const contribution = incident.contributions.find(c => c.id === btn.dataset.id);
        if (!contribution) throw Error('현재 페이지에서 근거를 찾을 수 없습니다.');
        const current = contribution.adjudication || {classification: 'unknown', version: 0};
        return modal(scope, '개별 탐지 근거 판정', note('이 근거만 판정합니다. 다른 실제 악성 근거는 계속 활성 상태로 남습니다.') + select('분류', 'classification', ['unknown', 'true_positive', 'expected_activity', 'false_positive'], current.classification, statuses) + area('판정 근거', 'reason', '', 'required maxlength="2000"'), async dialog => {
          await scope.send(`/api/incidents/${enc(incident.id)}/contributions/${enc(contribution.id)}/verdict`, {classification: value(dialog, 'classification'), reason: value(dialog, 'reason'), version: current.version}, 'PUT');
          await open(incident.id, cursor); V.notify('개별 근거 판정을 기록했습니다.');
        });
      }
      if (action === 'case-split') {
        return modal(scope, '독립 사건으로 근거 분리', note('현재 페이지에서 이동할 근거를 선택합니다. 원래 사건에 적어도 한 개의 근거를 남겨야 합니다. 이벤트와 판정 ID는 복제하지 않습니다.') + (incident.contributions || []).map(c => check(c.evidence?.policy_name || c.policy_id, 'selected_contribution', false, `value="${h(c.id)}"`)).join('') + area('분리 이유', 'reason', '', 'required maxlength="2000"'), async dialog => {
          const ids = [...dialog.querySelectorAll('[name="selected_contribution"]:checked')].map(n => n.value);
          const result = await scope.send(`/api/incidents/${enc(incident.id)}/split`, {version: incident.version, reason: value(dialog, 'reason'), contribution_ids: ids});
          cursor = null; cursors = []; await open(result.target_id); V.notify('선택한 근거를 독립 사건으로 이동했습니다.');
        }, '분리 실행');
      }
      if (action === 'case-merge') {
        const targets = (await scope.get('/api/incidents')).filter(c => c.id !== incident.id && ['new','triage'].includes(c.status));
        if (!targets.length) throw Error('병합할 열린 케이스가 없습니다.');
        return modal(scope, '연관 사건으로 병합', note('근거 ID를 이동합니다. 원래 사건의 메모·작업·대응 이력은 보존되며, 원래 필수 작업도 병합 사건의 해결 조건에 포함됩니다.') + select('대상 사건', 'target_id', targets.map(c=>c.id), targets[0].id, Object.fromEntries(targets.map(c=>[c.id,c.name]))) + area('연관성 근거', 'reason', '', 'required maxlength="2000"'), async dialog => {
          const target = targets.find(c => c.id === value(dialog, 'target_id'));
          const result = await scope.send(`/api/incidents/${enc(incident.id)}/merge`, {version: incident.version, target_id: target.id, target_version: target.version, reason: value(dialog, 'reason')});
          cursor = null; cursors = []; await open(result.target_id); V.notify('근거를 병합하고 원래 조사 기록을 보존했습니다.');
        }, '병합 실행');
      }
      if (action === 'case-movements') {
        const history = await scope.get(`/api/incidents/${enc(incident.id)}/movements`);
        return modal(scope, '사건 분리·병합 이력', table(['작업','원래 사건','대상 사건','담당·시간','연관성 근거'], history.items.map(r=>[h(r.kind === 'split' ? '분리' : '병합'), h(r.source_id), h(r.target_id), `${h(r.actor)} · ${date(r.at)}`, h(r.reason)])) + (history.truncated ? note('최근 200개 이력 범위입니다.') : ''), null);
      }
      if (action === 'case-edit') modal(scope, '상태와 담당자 변경', `<div class="wf-grid">${select('케이스 상태', 'status', ['new', 'triage', 'resolved', 'false_positive'], incident.status, statuses)}${field('담당 계정', 'owner', incident.owner || '')}</div>${area('변경 사유', 'note', '', 'required maxlength="2000"')}`, async dialog => {
        await scope.send(`/api/incidents/${enc(incident.id)}`, {status: value(dialog, 'status'), owner: value(dialog, 'owner'), note: value(dialog, 'note'), version: incident.version}, 'PATCH'); await open(incident.id, cursor); V.notify('케이스 상태를 변경했습니다.');
      });
      if (action === 'case-configure') modal(scope, '조사 우선순위', `<div class="wf-grid">${select('우선순위', 'priority', ['critical', 'high', 'medium', 'low'], workspace.workspace.priority, labels)}${field('마감 시간', 'due_at', localDate(workspace.workspace.due_at), '', 'datetime-local')}${field('태그 · 쉼표로 구분', 'tags', workspace.workspace.tags.join(', '))}</div>`, async dialog => {
        await scope.send(`/api/incidents/${enc(incident.id)}/workspace`, {version: workspace.workspace.version, priority: value(dialog, 'priority'), due_at: epoch(value(dialog, 'due_at')), tags: split(value(dialog, 'tags'))}, 'PUT'); await open(incident.id, cursor);
      });
      if (action === 'case-note') modal(scope, '분석 메모 추가', actionFields(actionDefaults('add_note')), dialog => act(readAction(dialog, actionDefaults('add_note'))), '메모 기록');
      if (action === 'case-task') modal(scope, '조사 작업 추가', actionFields(actionDefaults('add_task')), dialog => act(readAction(dialog, actionDefaults('add_task'))), '작업 추가');
      if (action === 'case-task-edit') {
        const task = workspace.tasks.find(item => item.id === btn.dataset.id);
        modal(scope, '조사 작업 업데이트', `<div class="wf-grid">${select('상태', 'task_status', task.mandatory ? ['open', 'done'] : ['open', 'done', 'cancelled'], task.status, statuses)}${field('담당 계정', 'task_assignee', task.assignee)}${field('마감 시간', 'task_due', localDate(task.due_at), '', 'datetime-local')}</div>${task.mandatory ? note('필수 작업은 취소할 수 없습니다.') : ''}`, async dialog => {
          await scope.send(`/api/incidents/${enc(incident.id)}/tasks/${enc(task.id)}`, {version: task.version, status: value(dialog, 'task_status'), assignee: value(dialog, 'task_assignee'), due_at: epoch(value(dialog, 'task_due'))}, 'PATCH'); await open(incident.id, cursor);
        });
      }
      if (action === 'case-event') {
        const event = incident.timeline[Number(btn.dataset.index)];
        modal(scope, '저장된 이벤트 근거', describe(event) + (editable() ? `<div class="wf-grid">${field('북마크 제목', 'label', event.step)}${field('이벤트 식별자', 'event_id', event.event_id, 'readonly')}</div>` : ''), editable() ? async dialog => {
          await scope.send(`/api/incidents/${enc(incident.id)}/bookmarks`, {event_id: event.event_id, label: value(dialog, 'label')}); V.notify('이벤트를 북마크했습니다.'); await open(incident.id, cursor);
        } : null, '북마크 저장');
      }
      if (action === 'case-bookmark') modal(scope, '이벤트 북마크', `<div class="wf-grid">${field('이벤트 식별자', 'event_id', '', 'required')}${field('표시 제목', 'label')}</div>` + note('실제로 저장되어 있고 접근 권한이 있는 이벤트만 추가됩니다.'), async dialog => {
        await scope.send(`/api/incidents/${enc(incident.id)}/bookmarks`, {event_id: value(dialog, 'event_id'), label: value(dialog, 'label')}); await open(incident.id, cursor);
      });
      if (action === 'case-playbook') return V.navigate('playbooks', {incident_id: incident.id});
      if (action === 'case-run') return V.navigate('playbooks', {run_id: btn.dataset.id, incident_id: incident.id});
    });
    scope.on('input', event => { if (event.target.name === 'case_search' && !incident) filteredCards(); if (event.target.name === 'finding_search') paintFindings(); });
    scope.on('change', event => { if (['case_status', 'case_severity'].includes(event.target.name) && !incident) filteredCards(); if (event.target.name === 'finding_status') paintFindings(); });
    function graphDetails(event) {
      const node = event.target.closest('[data-graph-node]');
      if (!node || !node.closest('.wf-case-graph') || !incident) return;
      if (event.type === 'keydown' && !['Enter', ' '].includes(event.key)) return;
      event.preventDefault();
      const id = node.dataset.graphNode;
      if (id === 'entity') modal(scope, '케이스 엔터티', describe({entity_field: incident.entity_field, entity: incident.entity, incident_id: incident.id}), null);
      else if (id.startsWith('policy-')) modal(scope, '탐지 정책 근거', describe(incident.contributions[Number(id.slice(7))]), null);
      else if (id.startsWith('event-')) modal(scope, '이벤트 근거', describe(incident.timeline.find(row => row.event_id === id.slice(6))), null);
    }
    scope.on('click', graphDetails);
    scope.on('keydown', graphDetails);
    scope.track(() => { closeEnhancement(); rows = []; findingRows = []; incident = null; workspace = null; runs = []; attackContext = null; actionRequest.clear(); });
    await scope.run(() => params.id ? open(params.id) : params.view === 'findings' ? findingsList() : list());
    return () => scope.close();
  }

  function rawScalars(raw, prefix = 'raw', depth = 0) {
    const rows = [];
    Object.entries(raw || {}).forEach(([key, val]) => {
      if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(key) || ['__proto__', 'constructor', 'prototype'].includes(key)) return;
      const path = `${prefix}.${key}`;
      if (val === null || typeof val !== 'object') rows.push({key: path, val, type: val === null ? 'null' : typeof val});
      else if (!Array.isArray(val) && depth < 4) rows.push(...rawScalars(val, path, depth + 1));
    });
    return rows;
  }
  function rawSet(raw, path, val, remove = false) {
    if (!/^raw(?:\.[A-Za-z_][A-Za-z0-9_]{0,63}){1,5}$/.test(path) || path.split('.').some(part => ['__proto__', 'constructor', 'prototype'].includes(part))) throw new Error('raw로 시작하는 안전한 필드 경로를 입력하세요. 예: raw.security.user');
    const keys = path.split('.').slice(1);
    let node = raw;
    for (const key of keys.slice(0, -1)) {
      if (!Object.hasOwn(node, key)) node[key] = {};
      if (node[key] === null || typeof node[key] !== 'object' || Array.isArray(node[key])) throw new Error('기존 값과 중첩 필드 경로가 충돌합니다.');
      node = node[key];
    }
    if (remove) delete node[keys.at(-1)];
    else node[keys.at(-1)] = val;
  }
  function eventEditor(host, event, {index = 'main', source = 'example-json', compact = false} = {}) {
    const original = copy(event || {event_time: now(), index, source, sourcetype: 'json', host: 'example-host', severity: 'info', message: '', raw: {}});
    const initial = rawScalars(original.raw);
    host.innerHTML = `<div class="wf-grid wf-grid-3">${field('이벤트 시간', 'event_time', localDate(original.event_time), 'required', 'datetime-local')}${field('인덱스', 'event_index', original.index || index, 'required')}${field('소스', 'event_source', original.source || source, 'required')}${field('소스 유형', 'event_sourcetype', original.sourcetype || 'json')}${field('호스트', 'event_host', original.host || '')}${select('이벤트 심각도', 'event_severity', severities, original.severity || 'info', labels)}</div>${area('원본 메시지', 'event_message', original.message || '', compact ? 'rows="2"' : 'rows="4"')}<div class="wf-section-title"><h4>구조화된 이벤트 필드</h4><button type="button" class="wf-btn wf-small" data-event-pair-add>+ 필드 추가</button></div><div class="wf-event-pairs">${pairsHTML(initial)}</div>${note('필드 경로는 raw로 시작합니다. 가져온 배열과 깊은 중첩 값은 원본 그대로 보존합니다. 예제 데이터만 입력하고 실제 자격 증명은 사용하지 마세요.')}`;
    const listener = e => {
      if (e.target.closest('[data-pair-remove]')) { e.preventDefault(); e.target.closest('[data-pair]').remove(); }
      if (e.target.closest('[data-event-pair-add]')) { e.preventDefault(); host.querySelector('.wf-event-pairs').insertAdjacentHTML('beforeend', pairsHTML([{key: 'raw.', val: '', type: 'string'}])); }
    };
    host.addEventListener('click', listener);
    return {
      read() {
        const raw = copy(original.raw || {});
        initial.forEach(row => rawSet(raw, row.key, null, true));
        Object.entries(readPairs(host.querySelector('.wf-event-pairs'))).forEach(([path, val]) => rawSet(raw, path, val));
        const result = {...original, event_time: value(host, 'event_time') === localDate(original.event_time) ? original.event_time : epoch(value(host, 'event_time')), index: value(host, 'event_index'), source: value(host, 'event_source'), sourcetype: value(host, 'event_sourcetype'), host: value(host, 'event_host'), severity: value(host, 'event_severity'), message: value(host, 'event_message'), raw};
        if (!result.event_id) delete result.event_id;
        return result;
      },
      destroy: () => host.removeEventListener('click', listener)
    };
  }
  function mappingRows(mappings) {
    return Object.entries(mappings || {}).map(([target, origin]) => `<div class="wf-mapping-row">${field('읽을 필드', 'map_origin', origin, 'required placeholder="raw.parsed.user"')}<span class="wf-map-arrow">→</span>${field('저장할 필드', 'map_target', target, 'required placeholder="raw.user"')}<button type="button" class="wf-icon-btn wf-danger" data-map-remove aria-label="매핑 삭제">×</button></div>`).join('');
  }
  async function data(container, params = {}) {
    const scope = scopeFor(container);
    let tab = params.tab || 'parsers', parsers = [], monitors = [], quarantine = {rows: []}, errors = {}, offset = 0, offsets = [], eventForm = null;
    async function load() {
      const results = await Promise.allSettled([scope.get('/api/parsers'), scope.get('/api/source-monitors'), scope.get(`/api/quarantine?offset=${offset}&count=10`)]);
      if (!scope.alive()) return;
      errors = {};
      ['parsers', 'monitors', 'quarantine'].forEach((name, i) => { if (results[i].status === 'rejected') errors[name] = results[i].reason.message; });
      parsers = results[0].status === 'fulfilled' ? results[0].value : [];
      monitors = results[1].status === 'fulfilled' ? results[1].value : [];
      quarantine = results[2].status === 'fulfilled' ? results[2].value : {rows: []};
      paint();
    }
    function paint() {
      eventForm?.destroy(); eventForm = null;
      scope.set(title('DATA PIPELINE', '데이터와 품질', '필드를 정리하고 수집 상태와 격리된 이벤트를 확인합니다.', button('새로 고침', 'data-refresh')) + stats([['파서 정책', parsers.length], ['소스 모니터', monitors.length], ['격리 이벤트', quarantine.total_count ?? '—']]) + `<div class="wf-tabs" role="tablist">${[['parsers', '파서와 필드 매핑'], ['monitors', '수집 상태'], ['quarantine', '격리와 재처리']].map(([key, text]) => `<button role="tab" aria-selected="${tab === key}" class="${tab === key ? 'active' : ''}" data-action="data-tab" data-tab="${key}">${text}</button>`).join('')}</div>${errors[tab] ? errorBox(errors[tab]) : ''}${tab === 'parsers' ? parserList() : tab === 'monitors' ? monitorList() : quarantineList()}<div id="wf-data-editor"></div>`);
    }
    function parserList() {
      return `<section class="wf-panel"><div class="wf-section-title"><h3>소스별 처리 정책</h3>${button('파서 만들기', 'parser-new', '', 'wf-primary')}</div>${flow([{title: '이벤트 입력', text: '소스와 유형 확인'}, {title: '메시지 해석', text: '선택적 JSON 해석'}, {title: '마스킹과 매핑', text: '명시적으로 지정한 필드'}, {title: '검증과 라우팅', text: '검색 저장 또는 격리'}])}${table(['정책', '소스', '상태', '버전', '수정', ''], parsers.map(parser => [h(parser.name), h(parser.source), pill(parser.enabled ? 'healthy' : 'neutral', parser.enabled ? '활성' : '비활성'), h(parser.version), h(date(parser.updated)), button('정책 열기', 'parser-open', `data-name="${h(parser.name)}"`)]))}${note('파서 설정은 테넌트의 모든 인덱스 권한이 필요하고 저장은 관리자만 할 수 있습니다. 원본 보존과 민감 정보 제거의 범위를 직접 선택하세요.')}</section>`;
    }
    function monitorList() {
      return `<section class="wf-panel"><div class="wf-section-title"><h3>소스 모니터</h3>${button('모니터 만들기', 'monitor-new', '', 'wf-primary')}</div><div class="wf-card-grid">${monitors.map(item => `<article class="wf-list-card"><div class="wf-card-top"><div><strong>${h(item.name)}</strong><small>${h(item.definition.source)} · ${h(item.definition.indexes.join(', '))}</small></div>${pill(item.result?.status || 'neutral', item.result ? (item.result.status === 'healthy' ? '정상' : '확인 필요') : '미평가')}</div>${stats([['최근 이벤트', item.result?.recent_events ?? '—'], ['최대 도착 지연 · 초', item.result?.max_arrival_lag_seconds === null || item.result?.max_arrival_lag_seconds === undefined ? '—' : Math.round(item.result.max_arrival_lag_seconds)]])}<div class="wf-tags">${(item.result?.issues || []).map(issue => `<span class="wf-warning">${h({silent: '수집 중단', lagging: '도착 지연', incomplete: '필수 필드 누락', future_timestamps: '미래 시간'}[issue] || issue)}</span>`).join('')}</div><div class="wf-card-footer"><small>${item.enabled ? '예약 평가 활성' : '예약 평가 비활성'} · ${date(item.last_run)}</small><div class="wf-actions">${button('설정', 'monitor-open', `data-id="${h(item.id)}"`)}${button('지금 평가', 'monitor-evaluate', `data-id="${h(item.id)}"`)}</div></div>${item.result ? `<details class="wf-details"><summary>실제 측정값</summary>${describe(item.result)}</details>` : ''}</article>`).join('') || empty('소스 모니터가 없습니다', '수집 지연과 필수 필드 누락 기준을 설정하세요.')}</div>${note('수집 상태는 운영 지표입니다. 공격 탐지 또는 소스 연결 성공을 의미하지 않습니다. 모니터를 저장할 때까지 예약 평가가 활성화되지 않습니다.')}</section>`;
    }
    function quarantineList() {
      return `<section class="wf-panel"><div class="wf-section-title"><h3>격리된 이벤트</h3>${admin() ? button('선택한 이벤트 재처리', 'quarantine-replay', '', 'wf-primary') : ''}</div>${table(['선택', '이벤트 / 소스', '격리 이유', '정책', '시도', ''], quarantine.rows.map((row, i) => [`<input type="checkbox" class="wf-quarantine-select" value="${h(row.event_id)}" aria-label="이벤트 ${h(row.event_id)} 선택">`, `<strong>${h(short(row.event_id))}</strong><small>${h(row.source)} · ${h(row.index_name)}<br>${date(row.received)}</small>`, h(row.reason), `${h(row.policy_name)} · v${h(row.policy_version)}`, h(row.attempts), button('내용 보기', 'quarantine-open', `data-index="${i}"`)]))}<div class="wf-pagination"><span>${quarantine.total_count ? `${offset + 1}–${offset + quarantine.rows.length} / ${quarantine.total_count}개` : '격리된 이벤트 없음'}</span><div class="wf-actions">${button('이전', 'quarantine-prev', offsets.length ? '' : 'disabled')}${button('다음', 'quarantine-next', quarantine.next_offset === null || quarantine.next_offset === undefined ? 'disabled' : '')}</div></div>${note('재처리는 현재 정책으로 이미 마스킹된 격리 사본을 다시 검사합니다. 제거된 값은 복구하지 않으며, 재처리 큐에 들어간 뒤 인덱싱되어야 검색할 수 있습니다.')}</section>`;
    }
    function editParser(parser) {
      const definition = parser?.definition || {source: '', sourcetype: '', route_index: '', mappings: {'raw.user': 'raw.parsed.user'}, redact_fields: ['raw.parsed.password', 'message'], required_fields: ['raw.user'], decode_message_json: true, on_failure: 'quarantine', enabled: false};
      const host = container.querySelector('#wf-data-editor');
      host.innerHTML = `<section class="wf-panel wf-editor-panel"><div class="wf-section-title"><div><span class="wf-eyebrow">PARSER BUILDER</span><h3>${parser ? '처리 정책 편집' : '새 처리 정책'}</h3></div>${button('닫기', 'data-editor-close')}</div><form data-form="parser"><div class="wf-grid wf-grid-3">${field('정책 식별자', 'parser_name', parser?.name || '', `required pattern="[a-z][a-z0-9_-]{0,63}" ${parser ? 'readonly' : ''} placeholder="auth-json"`)}${field('정확한 소스 이름', 'source', definition.source, 'required placeholder="example-json"')}${field('소스 유형 · 비워 두면 유지', 'sourcetype', definition.sourcetype || '')}${field('저장 인덱스 · 비워 두면 유지', 'route_index', definition.route_index || '')}${select('검증 실패 처리', 'on_failure', ['quarantine', 'reject'], definition.on_failure, {quarantine: '격리하여 보관', reject: '수집 거부'})}</div><div class="wf-form-line">${check('메시지를 JSON으로 해석', 'decode', definition.decode_message_json)}${check('정책 활성화', 'parser_enabled', definition.enabled)}</div><div class="wf-section-title"><h3>필드 매핑</h3>${button('+ 매핑 추가', 'parser-map-add')}</div><div class="wf-mappings">${mappingRows(definition.mappings)}</div><div class="wf-grid">${area('마스킹할 필드 · 한 줄에 하나', 'redact_fields', definition.redact_fields.join('\n'), 'rows="3" placeholder="raw.parsed.password\nmessage"')}${area('필수 필드 · 한 줄에 하나', 'required_fields', definition.required_fields.join('\n'), 'rows="3" placeholder="raw.user"')}</div>${note('중첩 필드만 마스킹하면 같은 값이 원본 메시지 문자열에 남을 수 있습니다. 메시지에도 민감 값이 있으면 message를 함께 지정하세요. message 마스킹은 원본 메시지 전체를 제거합니다.')}<details class="wf-details" open><summary>예제 이벤트로 미리보기</summary><div class="wf-preview-event"></div></details><div class="wf-editor-toolbar"><button class="wf-btn" type="submit" name="intent" value="preview">변환 미리보기</button>${admin() ? '<button class="wf-btn wf-primary" type="submit" name="intent" value="save">정책 저장</button>' : ''}<span class="wf-muted">미리보기는 수집하거나 저장하지 않습니다.</span></div></form><div class="wf-result"></div></section>`;
      eventForm?.destroy();
      eventForm = eventEditor(host.querySelector('.wf-preview-event'), {event_time: now(), index: definition.route_index || 'main', source: definition.source || 'example-json', sourcetype: definition.sourcetype || 'json', host: 'example-host', severity: 'info', message: '{"user":"example-user","password":"example-only"}', raw: {}});
      host.dataset.version = parser?.version || 0;
      host.scrollIntoView({behavior: 'smooth'});
    }
    function parserDefinition(form) {
      const mappings = {};
      for (const row of form.querySelectorAll('.wf-mapping-row')) {
        const target = value(row, 'map_target').trim(), origin = value(row, 'map_origin').trim();
        if (['__proto__', 'constructor', 'prototype'].includes(target) || Object.hasOwn(mappings, target)) throw new Error('중복되는 매핑 대상은 사용할 수 없습니다.');
        mappings[target] = origin;
      }
      return {source: value(form, 'source').trim(), sourcetype: value(form, 'sourcetype').trim() || null, route_index: value(form, 'route_index').trim() || null, mappings, redact_fields: split(value(form, 'redact_fields')), required_fields: split(value(form, 'required_fields')), decode_message_json: checked(form, 'decode'), on_failure: value(form, 'on_failure'), enabled: checked(form, 'parser_enabled')};
    }
    function editMonitor(monitor) {
      const d = monitor?.definition || {name: '', source: '', indexes: ['main'], required_fields: [], max_silence: 300, max_lag: 300, window: 3600, interval: 60, enabled: false};
      modal(scope, monitor ? '수집 상태 모니터 수정' : '수집 상태 모니터 만들기', `<div class="wf-grid">${field('모니터 이름', 'monitor_name', d.name, 'required maxlength="120"')}${field('정확한 소스 이름', 'monitor_source', d.source, 'required')}${field('인덱스 · 쉼표로 구분', 'monitor_indexes', d.indexes.join(', '), 'required')}${field('필수 필드 · 쉼표로 구분', 'monitor_fields', d.required_fields.join(', '))}${field('허용 수집 중단 · 초', 'max_silence', d.max_silence, 'required min="30" max="604800"', 'number')}${field('허용 도착 지연 · 초', 'max_lag', d.max_lag, 'required min="1" max="604800"', 'number')}${field('관측 시간 범위 · 초', 'monitor_window', d.window, 'required min="60" max="604800"', 'number')}${field('평가 간격 · 초', 'monitor_interval', d.interval, 'required min="30" max="86400"', 'number')}</div>${check('예약 평가 활성화', 'monitor_enabled', d.enabled)}`, async dialog => {
        const definition = {name: value(dialog, 'monitor_name'), source: value(dialog, 'monitor_source'), indexes: split(value(dialog, 'monitor_indexes')), required_fields: split(value(dialog, 'monitor_fields')), max_silence: number(dialog, 'max_silence'), max_lag: number(dialog, 'max_lag'), window: number(dialog, 'monitor_window'), interval: number(dialog, 'monitor_interval'), enabled: checked(dialog, 'monitor_enabled')};
        await scope.send(monitor ? `/api/source-monitors/${enc(monitor.id)}` : '/api/source-monitors', {version: monitor?.version || 0, definition}, monitor ? 'PUT' : 'POST'); V.notify('수집 모니터를 저장했습니다.'); await load();
      });
    }
    actions(scope, async (action, btn) => {
      if (action === 'data-refresh') return load();
      if (action === 'data-tab') { tab = btn.dataset.tab; paint(); }
      if (action === 'data-editor-close') { eventForm?.destroy(); eventForm = null; container.querySelector('#wf-data-editor').replaceChildren(); }
      if (action === 'parser-new') editParser(null);
      if (action === 'parser-open') editParser(parsers.find(item => item.name === btn.dataset.name));
      if (action === 'parser-map-add') container.querySelector('.wf-mappings').insertAdjacentHTML('beforeend', mappingRows({'raw.': 'raw.'}));
      if (action === 'monitor-new') editMonitor(null);
      if (action === 'monitor-open') editMonitor(monitors.find(item => item.id === btn.dataset.id));
      if (action === 'monitor-evaluate') { const result = await scope.send(`/api/source-monitors/${enc(btn.dataset.id)}/evaluate`, {}); V.notify(result.status === 'healthy' ? '현재 측정값이 기준 이내입니다.' : '확인이 필요한 수집 상태가 있습니다.'); await load(); }
      if (action === 'quarantine-open') modal(scope, '격리된 이벤트 사본', describe(quarantine.rows[Number(btn.dataset.index)]), null);
      if (action === 'quarantine-next') { offsets.push(offset); offset = quarantine.next_offset; await load(); }
      if (action === 'quarantine-prev') { offset = offsets.pop() || 0; await load(); }
      if (action === 'quarantine-replay') {
        const event_ids = [...container.querySelectorAll('.wf-quarantine-select:checked')].map(input => input.value);
        if (!event_ids.length) throw new Error('재처리할 이벤트를 선택하세요.');
        modal(scope, '선택 이벤트 재처리', note(`${event_ids.length}개 이벤트를 현재 처리 정책으로 다시 검사합니다. 기존에 마스킹된 정보는 복구할 수 없습니다.`), async () => {
          const result = await scope.send('/api/quarantine/replay', {event_ids});
          await load(); V.notify(`${result.queued}개 큐 등록 · ${result.still_quarantined.length}개 계속 격리`);
          if (result.still_quarantined.length) modal(scope, '재처리 후 확인할 이벤트', describe(result.still_quarantined), null);
        }, '재처리 요청');
      }
    });
    scope.on('click', event => { if (event.target.closest('[data-map-remove]')) event.target.closest('.wf-mapping-row').remove(); });
    scope.on('submit', event => {
      if (!event.target.matches('[data-form="parser"]')) return;
      event.preventDefault();
      scope.run(async () => {
        const definition = parserDefinition(event.target);
        if (event.submitter?.value === 'save') {
          await scope.send(`/api/parsers/${enc(value(event.target, 'parser_name'))}`, {version: Number(container.querySelector('#wf-data-editor').dataset.version), definition}, 'PUT');
          V.notify('처리 정책을 저장했습니다.'); await load();
        } else {
          const result = await scope.send('/api/parsers/preview', {definition, event: eventForm.read()});
          if (scope.alive()) container.querySelector('#wf-data-editor .wf-result').innerHTML = `<div class="wf-section-title"><h3>변환 결과</h3>${pill(result.errors.length ? 'high' : 'healthy', result.errors.length ? '검증 실패' : '검증 통과')}</div>${result.errors.length ? errorBox(result.errors.join(' · ')) : ''}${describe(result.event)}${note('예제 변환 결과이며 검색 저장소에 기록하지 않았습니다.')}`;
        }
      }, event.submitter);
    });
    scope.track(() => eventForm?.destroy());
    await scope.run(load);
    return () => scope.close();
  }

  function canonical(value) {
    if (Array.isArray(value)) return value.map(canonical);
    if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
    return value;
  }
  function examplePackage() {
    const end = now(), policy = {...freshPolicy(), name: '인증 실패 예제', steps: [{name: '실패 이벤트', min_count: 1, text: '', filters: [{field: 'raw.security.outcome', op: 'eq', value: 'failure'}]}]};
    const event = {event_time: end - 60, source: 'example-auth', sourcetype: 'example_auth', host: 'example-host', index: 'main', severity: 'info', message: 'Content fixture only', raw: {user: 'example-user', action: 'login_failed'}};
    return {schema_version: 1, name: '', title: '', prerequisites: {indexes: ['main'], sources: [{category: 'authentication', sourcetypes: ['example_auth'], required_fields: ['raw.security.user']}]}, rules: [{key: 'authentication_failure', policy}], fixtures: [{name: 'positive', end, events: [event], expect: {authentication_failure: ['example-user']}}, {name: 'negative', end, events: [{...copy(event), raw: {user: 'example-user', action: 'login_success'}}], expect: {authentication_failure: []}}]};
  }
  function sourceRows(sources) {
    return sources.map((source, index) => `<div class="wf-source-row" data-source="${index}">${field('소스 범주', 'category', source.category, 'required pattern="[a-z][a-z0-9_-]{0,63}"')}${field('소스 유형 · 쉼표 구분', 'sourcetypes', source.sourcetypes.join(', '), 'required')}${field('필수 필드 · 쉼표 구분', 'required', source.required_fields.join(', '), 'required')}<button type="button" class="wf-icon-btn wf-danger" data-source-remove aria-label="소스 범주 삭제">×</button></div>`).join('');
  }
  async function content(container) {
    const scope = scopeFor(container);
    let packages = [], info = null, draft = null, testResult = null, fixtureEditors = [];
    async function load() {
      packages = await scope.get('/api/content/packages');
      if (!scope.alive()) return;
      scope.set(title('DETECTION CONTENT', '콘텐츠 패키지', '정책, 필수 데이터와 재현 가능한 테스트를 하나의 버전으로 관리합니다.', button('파일 가져오기', 'content-import') + button('새 패키지', 'content-new', '', 'wf-primary')) + stats([['패키지', packages.length], ['활성 리비전 있음', packages.filter(p => p.active_revision).length], ['등록 규칙', packages.reduce((n, p) => n + p.rule_count, 0)]]) + `<section class="wf-panel"><div class="wf-section-title"><h3>패키지 라이브러리</h3>${button('새로 고침', 'content-refresh')}</div><div class="wf-card-grid">${packages.map(item => `<article class="wf-list-card"><div class="wf-card-top"><div><span class="wf-eyebrow">${h(item.name)}</span><strong>${h(item.title)}</strong></div>${pill(item.active_revision ? 'healthy' : 'neutral', item.active_revision ? '활성 리비전 있음' : '초안')}</div><div class="wf-tags"><span>${h(item.prerequisites.indexes[0])}</span><span>${h(item.rule_count)}개 규칙</span>${item.mitre.map(tag => `<span>${h(tag)}</span>`).join('')}</div><p class="wf-muted">최신 ${h(short(item.latest_revision))} · v${h(item.version)}</p>${button('패키지 열기', 'content-open', `data-name="${h(item.name)}"`)}</article>`).join('') || empty('콘텐츠 패키지가 없습니다', '정책과 양성·음성 예제 이벤트를 함께 정의하세요.')}</div>${note('현재 패키지는 순서형 상관 정책을 지원합니다. 테스트는 격리된 예제 이벤트에 실행하고, 실제 소스의 필수 필드 존재 여부를 별도로 확인합니다. 전체 공격 탐지 성능이나 Sigma 전체 호환을 보증하지 않습니다.')}</section><div id="wf-content-editor"></div><input id="wf-content-file" type="file" accept=".json,application/json" hidden>`);
      draft = null; info = null;
    }
    async function open(name, revision) {
      info = await scope.get(`/api/content/packages/${enc(name)}${revision ? `?revision=${enc(revision)}` : ''}`);
      if (!scope.alive()) return;
      draft = copy(info.payload); testResult = info.test; paintEditor();
    }
    function readMeta() {
      const host = container.querySelector('#wf-content-editor');
      if (!draft || !host.querySelector('[name="package_name"]')) return;
      draft.name = value(host, 'package_name').trim(); draft.title = value(host, 'package_title').trim();
      draft.prerequisites.indexes = [value(host, 'package_index').trim()];
      draft.prerequisites.sources = [...host.querySelectorAll('[data-source]')].map(node => ({category: value(node, 'category').trim(), sourcetypes: split(value(node, 'sourcetypes')), required_fields: split(value(node, 'required'))}));
    }
    function paintEditor() {
      const host = container.querySelector('#wf-content-editor');
      if (!scope.alive() || !host) return;
      const revision = info?.revision;
      host.innerHTML = `<section class="wf-panel wf-editor-panel"><div class="wf-section-title"><div><span class="wf-eyebrow">VERSIONED PACKAGE</span><h3>${info ? h(draft.title) : '새 패키지'}</h3></div><div class="wf-actions">${info ? button('내보내기', 'content-export') : ''}${button('편집 닫기', 'content-close')}</div></div>${flow([{title: '초안', text: '규칙과 소스 정의'}, {title: '예제 검증', text: '양성·음성 실제 실행'}, {title: '라이브 필드 확인', text: '선언한 소스의 관측'}, {title: '게시 또는 롤백', text: '관리자의 명시적 전환'}])}${info ? `<div class="wf-revision-bar"><div><small>열린 리비전</small><code>${h(short(revision))}</code>${pill(info.state)}</div><div><small>현재 활성</small><code>${h(short(info.active_revision) || '없음')}</code></div>${select('저장된 리비전', 'revision', info.history.map(row => row.revision), revision, Object.fromEntries(info.history.map(row => [row.revision, `${short(row.revision)} · ${date(row.created)}`])), 'data-revision-select')}</div>` : note('아래 규칙과 이벤트는 테스트용 편집 예제입니다. 저장 전에는 서버에 기록되지 않습니다. 규칙의 예약 실행은 기본 비활성 상태입니다.')}<form data-form="content"><div class="wf-grid wf-grid-3">${field('패키지 식별자', 'package_name', draft.name, `required pattern="[a-z][a-z0-9_-]{0,63}" ${info ? 'readonly' : ''} placeholder="authentication-pack"`)}${field('패키지 제목', 'package_title', draft.title, 'required maxlength="120"')}${field('적용할 단일 인덱스', 'package_index', draft.prerequisites.indexes[0], `required ${info ? 'readonly' : ''}`)}</div><div class="wf-section-title"><h3>필수 소스와 필드</h3>${button('+ 소스 범주', 'content-source-add')}</div><div class="wf-package-sources">${sourceRows(draft.prerequisites.sources)}</div><div class="wf-section-title"><h3>상관 정책 규칙</h3>${button('+ 규칙', 'content-rule-add')}</div>${draft.rules.map((rule, index) => `<article class="wf-subcard"><div class="wf-card-top"><div><strong>${h(rule.policy.name)}</strong><small>${h(rule.key)} · ${h(rule.policy.entity_field)}</small></div><div class="wf-actions">${pill(rule.policy.enabled ? 'healthy' : 'neutral', rule.policy.enabled ? '게시 시 예약 활성' : '게시 시 예약 비활성')}${button('편집', 'content-rule-edit', `data-index="${index}"`)}${button('삭제', 'content-rule-delete', `data-index="${index}"`, 'wf-danger')}</div></div>${flow(rule.policy.steps.map(step => ({title: step.name, text: `${step.min_count || 1}개 이상`})))}<div class="wf-tags">${pill(rule.policy.severity)}${rule.policy.mitre.map(tag => `<span>${h(tag)}</span>`).join('')}</div></article>`).join('')}<div class="wf-section-title"><h3>재현 가능한 예제 테스트</h3>${button('+ 테스트', 'content-fixture-add')}</div><div class="wf-card-grid">${draft.fixtures.map((fixture, index) => `<article class="wf-fixture-card"><div class="wf-card-top"><strong>${h(fixture.name)}</strong><span>${fixture.events.length}개 예제 이벤트</span></div><small>평가 종료 ${date(fixture.end)}</small><div class="wf-tags">${draft.rules.map(rule => `<span>${h(rule.key)}: ${(fixture.expect[rule.key] || []).length}개 엔터티 기대</span>`).join('')}</div><div class="wf-actions">${button('이벤트와 기대 결과 편집', 'content-fixture-edit', `data-index="${index}"`)}${button('삭제', 'content-fixture-delete', `data-index="${index}"`, 'wf-danger')}</div></article>`).join('')}</div>${note('각 규칙에 일치하는 양성 테스트와 일치하지 않는 음성 테스트가 모두 필요합니다. 기대 결과는 엔터티 값의 정확한 집합입니다. 예제 이벤트는 실제 수집 저장소에 넣지 않습니다.')}<div class="wf-editor-toolbar"><button type="submit" class="wf-btn" name="intent" value="validate">구조와 권한 확인</button><button type="submit" class="wf-btn wf-primary" name="intent" value="save">불변 리비전 저장</button>${revision ? button('저장된 리비전 테스트', 'content-test') + button('라이브 소스 확인', 'content-coverage') : ''}</div></form><div class="wf-content-results">${testResult ? renderTest(testResult) : ''}</div>${info && admin() ? `<div class="wf-rollout"><div><strong>정책 전환</strong><p>테스트와 실제 소스 조건을 만족한 저장 리비전을 게시합니다. 예약 실행 여부는 각 규칙의 설정을 따릅니다.</p></div><div class="wf-actions">${button('이 리비전 게시', 'content-publish', info.active_revision === info.revision ? 'disabled' : '', 'wf-primary')}${button('이 리비전으로 롤백', 'content-rollback', info.active_revision === info.revision || !info.rollouts.some(row => row.revision === info.revision) ? 'disabled' : '')}</div></div>` : ''}${info ? `<details class="wf-details"><summary>전환 기록</summary>${table(['리비전', '이전 리비전', '작업', '사용자', '시간'], info.rollouts.map(row => [h(short(row.revision)), h(short(row.previous) || '—'), h(row.action), h(row.actor), h(date(row.created))]))}</details>` : ''}</section>`;
      host.scrollIntoView({behavior: 'smooth', block: 'start'});
    }
    function renderTest(result) {
      return `<div class="wf-section-title"><h3>저장 리비전의 예제 테스트 결과</h3>${pill(result.passed ? 'healthy' : 'critical', result.passed ? '통과' : '실패')}</div>${table(['테스트', '규칙', '기대 엔터티', '관측 엔터티', '결과'], (result.assertions || []).map(assertion => [h(assertion.fixture), h(assertion.rule), h(assertion.expected.join(', ') || '없음'), h(assertion.observed.join(', ') || '없음'), pill(assertion.passed ? 'healthy' : 'critical', assertion.passed ? '통과' : '실패')]))}${note('예제 이벤트만 실행한 결과입니다. 실제 환경의 탐지율과 오탐률을 측정한 결과가 아닙니다.')}`;
    }
    function requireSaved() {
      readMeta();
      if (!info || JSON.stringify(canonical(draft)) !== JSON.stringify(canonical(info.payload))) throw new Error('수정한 내용을 먼저 불변 리비전으로 저장하세요. 테스트와 게시에는 저장된 정의만 사용합니다.');
    }
    function editRule(index) {
      readMeta();
      const previous = index === null ? null : draft.rules[index], rule = previous ? copy(previous) : {key: '', policy: freshPolicy()};
      let builder;
      modal(scope, previous ? '패키지 규칙 편집' : '규칙 추가', field('규칙 식별자', 'rule_key', rule.key, 'required pattern="[a-z][a-z0-9_-]{0,63}"') + '<div class="wf-package-policy"></div>', dialog => {
        const key = value(dialog, 'rule_key').trim();
        if (draft.rules.some((row, i) => i !== index && row.key === key)) throw new Error('규칙 식별자는 고유해야 합니다.');
        const next = {key, policy: builder.read()};
        if (previous) draft.rules[index] = next; else draft.rules.push(next);
        draft.fixtures.forEach(fixture => { const expected = previous ? fixture.expect[previous.key] || [] : []; if (previous) delete fixture.expect[previous.key]; fixture.expect[key] = expected; });
        paintEditor();
      }, '규칙 반영', dialog => { builder = policyBuilder(dialog.querySelector('.wf-package-policy'), rule.policy); return builder.destroy; });
    }
    function editFixture(index) {
      readMeta();
      const previous = index === null ? null : draft.fixtures[index];
      const fixture = previous ? copy(previous) : {name: '', end: now(), events: [], expect: Object.fromEntries(draft.rules.map(rule => [rule.key, []]))};
      let dialog, listener;
      function eventsHTML() {
        return fixture.events.map((event, ei) => `<article class="wf-subcard"><div class="wf-card-top"><div><strong>${h(event.source || event.sourcetype)}</strong><small>${date(event.event_time)} · ${h(event.host || '')}</small></div><div class="wf-actions"><button type="button" class="wf-btn" data-fixture-event="edit" data-index="${ei}">편집</button><button type="button" class="wf-btn wf-danger" data-fixture-event="delete" data-index="${ei}">삭제</button></div></div><div class="wf-tags"><span>${h(event.index)}</span><span>${h(event.sourcetype || '')}</span></div><p class="wf-message-preview">${h(event.message || '(구조화된 필드 이벤트)')}</p></article>`).join('') || empty('예제 이벤트를 추가하세요');
      }
      dialog = modal(scope, previous ? '예제 테스트 편집' : '예제 테스트 추가', `<div class="wf-grid">${field('테스트 식별자', 'fixture_name', fixture.name, 'required pattern="[a-z][a-z0-9_-]{0,63}"')}${field('분석 종료 시간', 'fixture_end', localDate(fixture.end), 'required', 'datetime-local')}</div><div class="wf-section-title"><h3>예제 이벤트</h3><button type="button" class="wf-btn" data-fixture-event="add">+ 이벤트</button></div><div class="wf-fixture-events">${eventsHTML()}</div><div class="wf-section-title"><h3>기대 엔터티</h3></div>${draft.rules.map((rule, ri) => area(`${rule.key} · 한 줄에 엔터티 하나, 음성 테스트는 비움`, `expect_${ri}`, (fixture.expect[rule.key] || []).join('\n'), 'rows="2"')).join('')}${note('이 예제의 모든 이벤트는 패키지의 단일 인덱스에 속해야 합니다. 정책 시간 범위 안의 이벤트가 기대한 엔터티와 일치하는지 실제 분석기로 검사합니다.')}`, node => {
        fixture.name = value(node, 'fixture_name').trim();
        if (draft.fixtures.some((row, i) => i !== index && row.name === fixture.name)) throw new Error('테스트 식별자는 고유해야 합니다.');
        fixture.end = value(node, 'fixture_end') === localDate(fixture.end) ? fixture.end : epoch(value(node, 'fixture_end'));
        fixture.expect = Object.fromEntries(draft.rules.map((rule, ri) => [rule.key, value(node, `expect_${ri}`).split('\n').map(x => x.trim()).filter(Boolean)]));
        if (previous) draft.fixtures[index] = fixture; else draft.fixtures.push(fixture);
        paintEditor();
      }, '테스트 반영', node => {
        listener = event => {
          const btn = event.target.closest('[data-fixture-event]');
          if (!btn) return;
          event.preventDefault();
          if (btn.dataset.fixtureEvent === 'delete') { fixture.events.splice(Number(btn.dataset.index), 1); node.querySelector('.wf-fixture-events').innerHTML = eventsHTML(); return; }
          const ei = btn.dataset.fixtureEvent === 'add' ? null : Number(btn.dataset.index);
          const existing = ei === null ? null : fixture.events[ei];
          let editor;
          modal(scope, existing ? '예제 이벤트 편집' : '예제 이벤트 추가', '<div class="wf-fixture-event-editor"></div>', () => {
            const record = editor.read();
            if (record.index !== draft.prerequisites.indexes[0]) throw new Error('예제 이벤트는 패키지의 인덱스와 같아야 합니다.');
            if (ei === null) fixture.events.push(record); else fixture.events[ei] = record;
            node.querySelector('.wf-fixture-events').innerHTML = eventsHTML();
          }, '이벤트 반영', eventDialog => { editor = eventEditor(eventDialog.querySelector('.wf-fixture-event-editor'), existing, {index: draft.prerequisites.indexes[0], source: 'example-auth'}); fixtureEditors.push(editor); return editor.destroy; });
        };
        node.addEventListener('click', listener);
        return () => node.removeEventListener('click', listener);
      });
    }
    actions(scope, async (action, btn) => {
      if (action === 'content-refresh') return load();
      if (action === 'content-new') { info = null; testResult = null; draft = examplePackage(); paintEditor(); }
      if (action === 'content-open') return open(btn.dataset.name);
      if (action === 'content-close') { draft = null; info = null; container.querySelector('#wf-content-editor').replaceChildren(); }
      if (action === 'content-import') container.querySelector('#wf-content-file').click();
      if (action === 'content-source-add') { readMeta(); if (draft.prerequisites.sources.length >= 8) throw new Error('소스 범주는 최대 8개입니다.'); draft.prerequisites.sources.push({category: '', sourcetypes: [], required_fields: []}); paintEditor(); }
      if (action === 'content-rule-add') { if (draft.rules.length >= 20) throw new Error('규칙은 최대 20개입니다.'); editRule(null); }
      if (action === 'content-rule-edit') editRule(Number(btn.dataset.index));
      if (action === 'content-rule-delete') { readMeta(); const [rule] = draft.rules.splice(Number(btn.dataset.index), 1); draft.fixtures.forEach(f => delete f.expect[rule.key]); paintEditor(); }
      if (action === 'content-fixture-add') { if (draft.fixtures.length >= 12) throw new Error('테스트는 최대 12개입니다.'); editFixture(null); }
      if (action === 'content-fixture-edit') editFixture(Number(btn.dataset.index));
      if (action === 'content-fixture-delete') { readMeta(); draft.fixtures.splice(Number(btn.dataset.index), 1); paintEditor(); }
      if (action === 'content-test') { requireSaved(); testResult = await scope.send(`/api/content/packages/${enc(info.name)}/test`, {revision: info.revision}); if (scope.alive()) container.querySelector('.wf-content-results').innerHTML = renderTest(testResult); V.notify(testResult.passed ? '양성·음성 예제 테스트를 통과했습니다.' : '기대 결과와 다른 테스트가 있습니다.'); }
      if (action === 'content-coverage') {
        requireSaved(); const result = await scope.get(`/api/content/packages/${enc(info.name)}/coverage?revision=${enc(info.revision)}`);
        if (scope.alive()) container.querySelector('.wf-content-results').innerHTML = `<div class="wf-section-title"><h3>최근 24시간 필수 소스 확인</h3>${pill(result.ready ? 'healthy' : 'high', result.ready ? '필수 필드 관측' : '선행 조건 미충족')}</div>${table(['범주', '이벤트', '필수 필드가 있는 이벤트'], result.sources.map(source => [h(source.category), h(source.events), h(source.complete_events)]))}${note('선언한 인덱스와 소스 유형에서 필수 필드가 존재하는지 확인합니다. 탐지 의미, 공격 커버리지 또는 데이터 완전성을 보증하지 않습니다.')}`;
      }
      if (action === 'content-publish' || action === 'content-rollback') {
        requireSaved(); const name = info.name, revision = info.revision, expected_active = info.active_revision, verb = action === 'content-publish' ? 'publish' : 'rollback';
        modal(scope, verb === 'publish' ? '저장 리비전 게시' : '이전 활성 리비전으로 롤백', note(`${short(revision)} 리비전의 실제 상관 정책으로 원자적으로 전환합니다. ${draft.rules.filter(rule => rule.policy.enabled).length}개 규칙의 예약 실행이 활성화됩니다. 현재 활성 리비전이 바뀌었으면 요청은 거부됩니다.`), async () => { await scope.send(`/api/content/packages/${enc(name)}/${verb}`, {revision, expected_active}); V.notify('콘텐츠 정책을 전환했습니다.'); await open(name, revision); V.refreshOverview?.(); }, verb === 'publish' ? '정책 게시' : '롤백 적용');
      }
      if (action === 'content-export') return V.download(`${info.name}-${short(info.revision)}.json`, await scope.get(`/api/content/packages/${enc(info.name)}/export?revision=${enc(info.revision)}`));
    });
    scope.on('click', event => { if (event.target.closest('[data-source-remove]')) event.target.closest('[data-source]').remove(); });
    scope.on('change', event => {
      if (event.target.matches('[data-revision-select]')) scope.run(() => open(info.name, event.target.value));
      if (event.target.id === 'wf-content-file') scope.run(async () => {
        const file = event.target.files[0]; event.target.value = '';
        if (!file) return;
        if (file.size > 1024 * 1024) throw new Error('패키지 파일은 1MiB 이하여야 합니다.');
        let parsed; try { parsed = JSON.parse(await file.text()); } catch (_) { throw new Error('올바른 JSON 패키지 파일을 선택하세요.'); }
        const result = await scope.send('/api/content/dry-run', parsed.package || parsed);
        const existing = packages.find(item => item.name === result.package.name);
        info = existing ? await scope.get(`/api/content/packages/${enc(existing.name)}`) : null;
        draft = copy(result.package); testResult = null;
        if (scope.alive()) { paintEditor(); V.notify('파일 구조와 권한을 확인했습니다. 저장하기 전에는 변경하지 않습니다.'); }
      });
    });
    scope.on('submit', event => {
      if (!event.target.matches('[data-form="content"]')) return;
      event.preventDefault();
      scope.run(async () => {
        readMeta();
        if (event.submitter?.value === 'save') {
          const result = await scope.send('/api/content/packages', {package: draft, expected_version: info?.version || 0});
          V.notify('불변 콘텐츠 리비전을 저장했습니다.'); await open(result.name, result.revision);
        } else {
          const result = await scope.send('/api/content/dry-run', draft);
          if (scope.alive()) container.querySelector('.wf-content-results').innerHTML = `<div class="wf-section-title"><h3>구조와 권한 확인 완료</h3>${pill('healthy', '저장하지 않음')}</div>${stats([['리비전 해시', short(result.revision)], ['MITRE 기법', result.mitre.length]])}${note('구조와 인덱스 권한을 확인했습니다. 예제 테스트와 실제 소스 확인은 아직 실행하지 않았습니다.')}`;
        }
      }, event.submitter);
    });
    scope.track(() => { fixtureEditors.forEach(editor => editor.destroy()); fixtureEditors = []; draft = null; info = null; testResult = null; packages = []; });
    await scope.run(load);
    return () => scope.close();
  }

  V.register('cases', {title: '케이스', render: cases});
  V.register('playbooks', {title: '플레이북', render: playbooks});
  V.register('policies', {title: '상관 정책', render: policies});
  V.register('data', {title: '데이터와 품질', render: data});
  V.register('content', {title: '콘텐츠 패키지', render: content});
})();
