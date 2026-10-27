/* Run the actual current console operations renderer without a server or DOM. */
'use strict';
const assert = require('node:assert/strict');
const {test} = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '..', 'sapientia', 'web', 'console_admin.js'), 'utf8');
const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));

async function renderHealth(health) {
  const routes = {};
  const container = {innerHTML: '', addEventListener() {}, removeEventListener() {}, querySelectorAll() { return []; }};
  const V = {
    h: escape, icon: () => '', session: () => ({name: 'viewer', role: 'viewer', tenant: 'a'}),
    register: (name, route) => { routes[name] = route; },
    api: async target => {
      if (target === '/api/health') return health;
      if (target === '/api/federation/status') return {enabled: false};
      throw new Error('Unexpected API in viewer operations fixture');
    },
  };
  vm.runInNewContext(source, {window: {Vatex: V}, AbortController, Intl, Date}, {timeout: 1000});
  const cleanup = await routes.operations.render(container);
  const result = container.innerHTML;
  cleanup();
  return result;
}

function health(state, indexed, sourceCount) {
  return {
    indexed, source_count: sourceCount, pending: 11, pending_bytes: 1024,
    oldest_pending_seconds: 2, storage_bytes: 4096, disk_free_bytes: 1024 ** 3,
    analytics_status: {state, measured_at: 1700000000, age_seconds: 42.5},
  };
}

test('unavailable aggregate is not rendered as zero, while independently measured queue remains visible', async () => {
  const html = await renderHealth(health('unavailable', null, null));
  assert.match(html, /분석 저장 완료<\/span><strong>집계 불가<\/strong>/);
  assert.match(html, /관측 수집원<\/span><strong>집계 불가<\/strong>/);
  assert.match(html, /보존 이벤트 집계 불가/);
  assert.match(html, /0건을 뜻하지 않습니다/);
  assert.match(html, /영속 대기열<\/span><strong>11<\/strong>/);
  assert.doesNotMatch(html, />0개 보존</);
});

test('stale values are explicitly previous successful measurements with original time and age', async () => {
  const html = await renderHealth(health('stale', 123, 7));
  assert.match(html, /분석 저장 완료<\/span><strong>123 \(이전\)<\/strong>/);
  assert.match(html, /관측 수집원<\/span><strong>7 \(이전\)<\/strong>/);
  assert.match(html, /이전 성공 집계/);
  assert.match(html, /42\.5초 전/);
  assert.ok(html.includes(escape(new Date(1700000000 * 1000).toLocaleString('ko-KR'))));
  assert.match(html, /이전 집계 · 123개 보존/);
});

test('successful measured zero remains a valid zero and cached age remains disclosed', async () => {
  const ready = await renderHealth(health('ready', 0, 0));
  assert.match(ready, /분석 저장 완료<\/span><strong>0<\/strong>/);
  assert.match(ready, /관측 수집원<\/span><strong>0<\/strong>/);
  assert.match(ready, /0개 보존/);
  assert.doesNotMatch(ready, /집계 불가/);
  const cached = await renderHealth(health('cached', 9, 1));
  assert.match(cached, /최근 성공 집계/);
  assert.match(cached, /42\.5초 전/);
  assert.doesNotMatch(cached, /9 \(이전\)/);
});

test('unknown status and malformed number fields fail visible without rendering raw diagnostics', async () => {
  const input = health('unavailable', null, null);
  input.analytics_status.error = '<img src=x onerror=alert(1)> C:\\private\\credentials.json';
  input.analytics_status.measured_at = '<script>secret</script>';
  const html = await renderHealth(input);
  assert.doesNotMatch(html, /credentials|onerror|<script>|secret/);
  assert.match(html, /집계 불가/);
  assert.doesNotMatch(await renderHealth(health('future_unknown', 999, 888)), /999개 보존/);
  assert.match(await renderHealth(health('ready', '123', -1)), /분석 저장 완료<\/span><strong>집계 불가<\/strong>/);
});
