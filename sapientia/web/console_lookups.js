/* Managed, tenant-local lookup and threat-intelligence snapshots. */
(() => {
  'use strict';
  const V = window.Vatex;
  if (!V) return;
  const h = V.h, enc = encodeURIComponent;
  const kinds = {lookup: '일반 참조표', ip: 'IP 인텔리전스', domain: '도메인 인텔리전스', hash: '해시 인텔리전스'};
  const types = {string: '문자', number: '숫자', boolean: '참/거짓', null: '비어 있음', missing: '필드 없음'};
  const clone = value => JSON.parse(JSON.stringify(value));
  const date = value => value ? new Date(value * 1000).toLocaleString('ko-KR') : '만료 없음';
  const local = value => value ? new Date(value * 1000 - new Date(value * 1000).getTimezoneOffset() * 60000).toISOString().slice(0, 19) : '';
  const opts = (object, selected) => Object.entries(object).map(([key, label]) => `<option value="${h(key)}" ${key === selected ? 'selected' : ''}>${h(label)}</option>`).join('');
  const btn = (text, action, attrs = '', primary = false) => `<button type="button" class="lk-button ${primary ? 'lk-primary' : ''}" data-lk="${h(action)}" ${attrs}>${h(text)}</button>`;
  const field = (text, name, val = '', attrs = '', type = 'text') => `<label class="lk-field"><span>${h(text)}</span><input type="${type}" name="${h(name)}" value="${h(val ?? '')}" ${attrs}></label>`;
  const val = (root, name) => root.querySelector(`[name="${name}"]`)?.value ?? '';
  const validName = name => /^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(name) && !name.startsWith('__') && name.toLowerCase() !== 'tenant';
  function scalarType(row, key) {
    if (!Object.hasOwn(row, key)) return 'missing';
    const value = row[key];
    if (value === null) return 'null';
    if (typeof value === 'number' && (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value)))) return 'unsupported';
    return ['string', 'number', 'boolean'].includes(typeof value) ? typeof value : 'unsupported';
  }
  function parseCell(type, text) {
    if (type === 'missing') return {present: false};
    if (type === 'null') return {present: true, value: null};
    if (type === 'boolean') { if (!['true', 'false'].includes(text)) throw new Error('참/거짓 값은 true 또는 false를 입력하세요.'); return {present: true, value: text === 'true'}; }
    if (type === 'number') {
      const value = Number(text);
      if (!text.trim() || !Number.isFinite(value) || Math.abs(value) > 1e100 || (Number.isInteger(value) && !Number.isSafeInteger(value))) throw new Error('정확히 표현 가능한 유한 숫자를 입력하세요. 큰 정수는 이 편집기에서 저장할 수 없습니다.');
      return {present: true, value};
    }
    if (type !== 'string') throw new Error('지원되지 않는 셀 유형은 수정하거나 저장할 수 없습니다.');
    if (text.length > 4096) throw new Error('셀의 문자열은 4096자 이하여야 합니다.');
    return {present: true, value: text};
  }
  async function render(container, params = {}) {
    const controller = new AbortController(), identity = `${V.session()?.name}|${V.session()?.tenant}`;
    let alive = true, list = [], current = null, model = null, page = 0, query = '', readOnlyReason = '';
    const dialogs = new Set(), pageSize = 20;
    const isAdmin = () => V.session()?.role === 'admin';
    const active = () => alive && identity === `${V.session()?.name}|${V.session()?.tenant}`;
    const get = async path => { const data = await V.api(path, {signal: controller.signal}); if (!active()) throw new DOMException('View closed', 'AbortError'); return data; };
    const put = async (name, body) => { if (!active()) throw new DOMException('View closed', 'AbortError'); const data = await V.post(`/api/lookups/${enc(name)}`, body, 'PUT'); if (!active()) throw new DOMException('View closed', 'AbortError'); return data; };
    async function run(callback, button) {
      if (button?.disabled) return;
      if (button) button.disabled = true;
      try { return await callback(); } catch (error) { if (active() && error.name !== 'AbortError') { V.notify(error.message); const host = container.querySelector('.lk-error'); if (host) { host.hidden = false; host.textContent = error.message; } } }
      finally { if (button?.isConnected) button.disabled = false; }
    }
    function showDialog(title, content, onSave) {
      if (!active()) return;
      const d = V.dialog({title, content, onSave}); dialogs.add(d); d.addEventListener('close', () => dialogs.delete(d), {once: true}); return d;
    }
    function paint() {
      if (!active()) return;
      container.innerHTML = `<div class="lk-page"><div class="lk-heading"><div><span>MANAGED INTELLIGENCE</span><h2>참조표와 위협 인텔리전스</h2><p>테넌트 내부의 검증된 값을 검색 이벤트에 정확히 연결합니다.</p></div><div class="lk-actions">${btn('새로 고침', 'refresh')}${isAdmin() ? btn('+ 참조표 만들기', 'new', '', true) : ''}</div></div><div class="lk-error" role="alert" hidden></div><div class="lk-library">${list.length ? list.map(table => `<button type="button" class="lk-card ${model?.name === table.name ? 'active' : ''}" data-lk="open" data-name="${h(table.name)}"><div><strong>${h(table.name)}</strong><span class="lk-kind">${h(kinds[table.kind] || table.kind)}</span></div><p>${h(table.row_count)}행 · ${table.columns.length}열 · v${h(table.version)}</p><small class="${table.expired ? 'lk-expired' : ''}">${table.expired ? '만료됨 · ' : ''}${h(date(table.expires))}</small></button>`).join('') : '<div class="lk-empty"><strong>등록된 참조표가 없습니다</strong><p>관리자가 일반 참조표 또는 출처와 만료가 있는 인텔리전스 목록을 만들 수 있습니다.</p></div>'}</div><div id="lk-editor"></div><div class="lk-help">분석가와 관리자가 같은 테넌트의 표를 조회하고, 관리자만 저장합니다. 외부 피드를 자동 수집하거나 표에 있는 값만으로 공격을 확정하지 않습니다. 인덱스 권한은 검색 원본 이벤트에 별도로 적용됩니다.</div></div>`;
      if (model) paintEditor();
    }
    async function load(name) {
      list = await get('/api/lookups');
      if (name) { current = await get(`/api/lookups/${enc(name)}`); model = clone(current); page = 0; query = ''; }
      paint();
    }
    function unsupported() {
      if (!Array.isArray(model.columns) || !Array.isArray(model.rows) || model.columns.some(name => !validName(name))) return '현재 표의 스키마를 안전하게 편집할 수 없습니다.';
      if (model.rows.some(row => model.columns.some(column => scalarType(row, column) === 'unsupported'))) return '정확히 보존할 수 없는 값이 있습니다. 중첩 값 또는 브라우저 정밀도 밖의 정수는 읽기만 제공합니다. 이 표는 저장할 수 없습니다.';
      return '';
    }
    function paintEditor() {
      readOnlyReason = unsupported();
      const read = !isAdmin() || !!readOnlyReason, attr = read ? 'disabled' : '';
      container.querySelector('#lk-editor').innerHTML = `<section class="lk-panel"><div class="lk-panel-head"><div><span>TABLE EDITOR</span><h3>${h(model.name || '새 참조표')}</h3></div><div class="lk-actions">${btn('닫기', 'close')}${isAdmin() ? btn('표 저장', 'save', readOnlyReason ? 'disabled' : '', true) : ''}</div></div>${readOnlyReason ? `<div class="lk-help lk-warning">${h(readOnlyReason)}</div>` : ''}<form class="lk-form"><div class="lk-grid">${field('표 이름', 'table_name', model.name, `required pattern="[A-Za-z_][A-Za-z0-9_]{0,63}" ${current ? 'readonly' : ''} ${attr}`)}<label class="lk-field"><span>표 유형</span><select name="kind" ${attr}>${opts(kinds, model.kind)}</select></label><label class="lk-field"><span>고유한 문자열 키</span><select name="key" ${attr}>${opts(Object.fromEntries(model.columns.map(name => [name, name])), model.key)}</select></label>${field('만료 시간 · 인텔리전스는 필수', 'expires', local(model.expires), `${model.kind !== 'lookup' ? 'required' : ''} step="1" ${attr}`, 'datetime-local')}${field('출처 / provenance', 'provenance', model.provenance || '', `maxlength="512" ${model.kind !== 'lookup' ? 'required' : ''} ${attr}`)}</div><div class="lk-schema-heading"><h4>표의 열</h4>${!read ? btn('+ 열 추가', 'column-add') : ''}</div><div class="lk-schema">${model.columns.map((column, index) => `<div><code>${h(column)}</code>${column === model.key ? '<span>KEY</span>' : ''}${!read ? `<button type="button" data-lk="column-edit" data-index="${index}" aria-label="${h(column)} 열 이름 변경">편집</button>${column !== model.key ? `<button type="button" data-lk="column-delete" data-index="${index}" aria-label="${h(column)} 열 삭제">×</button>` : ''}` : ''}</div>`).join('')}</div><div class="lk-row-tools">${field('행 검색 · 모든 열', 'row_search', query, 'placeholder="지표 또는 설명 검색"')}<div class="lk-actions">${!read ? btn('+ 행 추가', 'row-add') : ''}<span class="lk-count"></span></div></div><div class="lk-row-table"></div><div class="lk-pagination"></div></form><div class="lk-help">문자·숫자·참/거짓·null·필드 없음은 각각 구분해 보존합니다. 키는 중복 없는 문자열이어야 합니다. IP는 IPv4/IPv6, 도메인은 정규화된 정확한 도메인, 해시는 MD5/SHA1/SHA256 16진수 값입니다. 인텔리전스는 confidence 0–100, 출처와 미래 만료 시간이 필요합니다.</div><div class="lk-limits">최대 10,000행 · 20열 · 2MiB · 테넌트당 100개 표. 저장은 버전을 확인하며 다른 사용자의 변경과 충돌하면 새로 고쳐야 합니다. 삭제 버튼은 저장 전 초안에서만 제거합니다.</div></section>`;
      paintRows();
    }
    function selectedRows() {
      return model.rows.map((row, index) => ({row, index})).filter(({row}) => !query || model.columns.some(column => Object.hasOwn(row, column) && String(row[column]).toLowerCase().includes(query.toLowerCase())));
    }
    function paintRows() {
      const matched = selectedRows(), read = !isAdmin() || !!readOnlyReason;
      page = Math.max(0, Math.min(page, Math.max(0, Math.ceil(matched.length / pageSize) - 1)));
      const rows = matched.slice(page * pageSize, (page + 1) * pageSize);
      container.querySelector('.lk-row-table').innerHTML = rows.length ? `<table><thead><tr><th>#</th>${model.columns.map(column => `<th>${h(column)}${column === model.key ? ' <small>KEY</small>' : ''}</th>`).join('')}${!read ? '<th></th>' : ''}</tr></thead><tbody>${rows.map(({row, index}) => `<tr data-row="${index}"><td>${index + 1}</td>${model.columns.map((column, ci) => {
        const type = scalarType(row, column), cell = Object.hasOwn(row, column) ? row[column] : '';
        if (read || type === 'unsupported') return `<td><span class="lk-cell-type">${h(types[type] || '정밀도 / 유형 제한')}</span><span class="lk-cell-read">${h(type === 'missing' ? '—' : type === 'null' ? 'null' : typeof cell === 'object' ? '[지원하지 않는 중첩 값]' : cell)}</span></td>`;
        return `<td data-column="${ci}"><select data-cell-type aria-label="${index + 1}행 ${h(column)} 유형" ${column === model.key ? 'disabled' : ''}>${opts(types, column === model.key ? 'string' : type)}</select><input data-cell-value aria-label="${index + 1}행 ${h(column)} 값" value="${h(type === 'null' || type === 'missing' ? '' : cell)}" ${column === model.key ? 'required' : ''} ${type === 'null' || type === 'missing' ? 'disabled' : ''} placeholder="${type === 'boolean' ? 'true 또는 false' : ''}" maxlength="4096"></td>`;
      }).join('')}${!read ? `<td>${btn('삭제', 'row-delete', `data-index="${index}"`)}</td>` : ''}</tr>`).join('')}</tbody></table>` : '<div class="lk-empty"><strong>표시할 행이 없습니다</strong><p>행을 추가하거나 검색 조건을 조정하세요.</p></div>';
      container.querySelector('.lk-count').textContent = `${matched.length}개 일치 / 전체 ${model.rows.length}행`;
      container.querySelector('.lk-pagination').innerHTML = `<span>페이지 ${page + 1} / ${Math.max(1, Math.ceil(matched.length / pageSize))} · 20행씩 표시</span><div class="lk-actions">${btn('이전', 'previous', page ? '' : 'disabled')}${btn('다음', 'next', (page + 1) * pageSize < matched.length ? '' : 'disabled')}</div>`;
    }
    function sync() {
      if (!model || !isAdmin() || readOnlyReason) return;
      const form = container.querySelector('.lk-form');
      if (!form) return;
      model.name = val(form, 'table_name').trim(); model.key = val(form, 'key'); model.kind = val(form, 'kind'); model.provenance = val(form, 'provenance');
      const inputDate = val(form, 'expires'); model.expires = inputDate === local(model.expires) ? model.expires : inputDate ? new Date(inputDate).getTime() / 1000 : null;
      for (const rowNode of form.querySelectorAll('[data-row]')) {
        const row = model.rows[Number(rowNode.dataset.row)];
        for (const cellNode of rowNode.querySelectorAll('[data-column]')) {
          const column = model.columns[Number(cellNode.dataset.column)], type = cellNode.querySelector('[data-cell-type]').value;
          const cell = parseCell(type, cellNode.querySelector('[data-cell-value]').value);
          if (cell.present) row[column] = cell.value; else delete row[column];
        }
      }
    }
    async function action(name, button) {
      if (name === 'refresh') { current = null; model = null; return load(); }
      if (name === 'open') return load(button.dataset.name);
      if (name === 'new') { current = null; model = {name: '', key: 'indicator', columns: ['indicator', 'label'], rows: [], kind: 'lookup', provenance: '', expires: null, version: 0}; page = 0; query = ''; return paint(); }
      if (name === 'close') { current = null; model = null; return paint(); }
      sync();
      if (name === 'previous' || name === 'next') { page += name === 'previous' ? -1 : 1; return paintRows(); }
      if (!isAdmin() || readOnlyReason) throw new Error('이 표는 현재 계정에서 편집할 수 없습니다.');
      if (name === 'row-add') { if (model.rows.length >= 10000) throw new Error('행은 최대 10,000개입니다.'); const row = Object.fromEntries([[model.key, '']]); if (model.kind !== 'lookup') row.confidence = null; model.rows.push(row); query = ''; container.querySelector('[name=row_search]').value = ''; page = Math.floor((model.rows.length - 1) / pageSize); return paintRows(); }
      if (name === 'row-delete') { model.rows.splice(Number(button.dataset.index), 1); return paintRows(); }
      if (name === 'column-delete') {
        const column = model.columns[Number(button.dataset.index)];
        if (model.kind !== 'lookup' && ['confidence', 'provenance'].includes(column)) throw new Error('인텔리전스의 confidence와 provenance 열은 유지해야 합니다.');
        return showDialog('열 삭제 검토', `<p>${h(column)} 열의 모든 값이 초안에서 제거됩니다. 저장 전에는 서버에 적용하지 않습니다.</p>`, () => { model.columns = model.columns.filter(name => name !== column); model.rows.forEach(row => delete row[column]); paintEditor(); });
      }
      if (name === 'column-add' || name === 'column-edit') {
        const old = name === 'column-edit' ? model.columns[Number(button.dataset.index)] : null;
        if (!old && model.columns.length >= 20) throw new Error('열은 최대 20개입니다.');
        return showDialog(old ? '열 이름 편집' : '열 추가', `<form>${field('열 식별자', 'column', old || '', 'required pattern="[A-Za-z_][A-Za-z0-9_]{0,63}"')}</form>`, dialog => {
          const next = val(dialog, 'column').trim(); if (!validName(next) || model.columns.some(column => column === next && column !== old)) throw new Error('예약되지 않은 고유한 열 이름을 입력하세요.');
          if (model.kind !== 'lookup' && ['confidence', 'provenance'].includes(old) && next !== old) throw new Error('인텔리전스의 confidence와 provenance 이름은 유지해야 합니다.');
          if (old) { model.columns = model.columns.map(column => column === old ? next : column); model.rows.forEach(row => { if (Object.hasOwn(row, old)) { const value = row[old]; delete row[old]; row[next] = value; } }); if (model.key === old) model.key = next; } else model.columns.push(next);
          paintEditor();
        });
      }
      if (name === 'save') {
        if (!container.querySelector('.lk-form').reportValidity()) return;
        if (!validName(model.name) || !validName(model.key)) throw new Error('표와 키 이름은 예약되지 않은 식별자여야 합니다.');
        const saved = await put(model.name, {key: model.key, columns: model.columns, rows: model.rows, kind: model.kind, provenance: model.provenance, expires: model.expires, version: current?.version || 0});
        current = saved; model = clone(saved); list = await get('/api/lookups'); paint(); V.notify('참조표 스냅샷을 저장했습니다.');
      }
    }
    const onClick = event => { const button = event.target.closest('[data-lk]'); if (button && container.contains(button)) { event.preventDefault(); run(() => action(button.dataset.lk, button), button); } };
    const onChange = event => run(() => {
      if (event.target.matches('[data-cell-type]')) { const cell = event.target.closest('[data-column]'), input = cell.querySelector('[data-cell-value]'); input.disabled = ['null', 'missing'].includes(event.target.value); input.placeholder = event.target.value === 'boolean' ? 'true 또는 false' : ''; }
      if (event.target.name === 'kind') {
        sync();
        if (model.kind !== 'lookup') { const required = ['confidence', 'provenance'].filter(column => !model.columns.includes(column)); if (model.columns.length + required.length > 20) throw new Error('인텔리전스 필수 열을 추가할 공간이 없습니다.'); model.columns.push(...required); }
        paintEditor();
      }
      if (event.target.name === 'key') { sync(); model.rows.forEach(row => { if (Object.hasOwn(row, model.key) && typeof row[model.key] !== 'string') throw new Error('키는 문자열 값을 가진 열이어야 합니다.'); }); paintEditor(); }
    });
    const onInput = event => { if (event.target.name === 'row_search') run(() => { sync(); query = event.target.value; page = 0; paintRows(); }); };
    const onSubmit = event => { if (event.target.matches('.lk-form')) event.preventDefault(); };
    container.addEventListener('click', onClick); container.addEventListener('change', onChange); container.addEventListener('input', onInput); container.addEventListener('submit', onSubmit);
    container.innerHTML = '<div class="lk-page"><div class="lk-error" role="alert" hidden></div><p>참조표를 불러오는 중…</p></div>';
    await run(() => load(params.name));
    return () => { alive = false; controller.abort(); dialogs.forEach(dialog => { dialog.close(); dialog.remove(); }); dialogs.clear(); container.removeEventListener('click', onClick); container.removeEventListener('change', onChange); container.removeEventListener('input', onInput); container.removeEventListener('submit', onSubmit); container.replaceChildren(); list = []; current = null; model = null; };
  }
  V.register('lookups', {title: '참조표와 인텔리전스', render});
})();
