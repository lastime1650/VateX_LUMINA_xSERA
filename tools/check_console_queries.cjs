'use strict';
// Targeted DOM mock: executes the production editor without a browser or server.
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const assert = require('node:assert/strict');
const source = fs.readFileSync(path.resolve(__dirname, '../sapientia/web/console.js'), 'utf8');
const start = source.indexOf(' function queryEditor(initial={})');
const finish = source.indexOf(' function bars(', start);
assert(start > 0 && finish > start);
const decode = text => String(text).replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
const escape = text => String(text ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
function attrs(text) {
  const result = {};
  for (const match of text.matchAll(/([\w-]+)(?:=(?:"([^"]*)"|'([^']*)'))?/g)) result[match[1]] = decode(match[2] ?? match[3] ?? '');
  return result;
}
class Control {
  constructor(attributes, body = '', tag = 'input') {
    this.attributes = attributes; this.name = attributes.name; this.disabled = false; this.required = Object.hasOwn(attributes, 'required');
    this.hidden = false; this.dataset = Object.fromEntries(Object.entries(attributes).filter(([key]) => key.startsWith('data-')).map(([key, val]) => [key.slice(5), val]));
    this.classList = {toggle() {}};
    this.value = tag === 'textarea' ? decode(body) : attributes.value || '';
    if (tag === 'select') {
      const opts = [...body.matchAll(/<option([^>]*)>(.*?)<\/option>/gs)].map(match => attrs(match[1]));
      this.value = (opts.find(option => Object.hasOwn(option, 'selected')) || opts[0] || {}).value || '';
    }
  }
  hasAttribute(name) { return Object.hasOwn(this.attributes, name); }
  closest() { return this; }
}
function controls(html) {
  return [...html.matchAll(/<(input|select|textarea)\b([^>]*)(?:>([\s\S]*?)<\/\1>|>)/g)].map(match => new Control(attrs(match[2]), match[3], match[1]));
}
class FilterRow {
  constructor(attributes, html) { this.dataset = {filter: attrs(attributes)['data-filter']}; this.controls = controls(html); }
  querySelector(selector) {
    const named = selector.match(/^\[name=['"]?([^'"\]]+)['"]?\]$/);
    return this.controls.find(control => named ? control.name === named[1] : control.hasAttribute(selector.slice(1, -1)));
  }
}
class EditorRoot {
  constructor() {
    this.parts = Object.fromEntries(['data-visual', 'data-spl', 'data-custom-group', 'data-projection'].map(key => [key, {hidden: false}]));
    this.rows = [];
    const self = this;
    this.parts['data-filters'] = {set innerHTML(html) { self.rows = [...html.matchAll(/<div class="filter-row"([^>]*)>([\s\S]*?)<\/div>/g)].map(match => new FilterRow(match[1], match[2])); }};
    this.modes = ['visual', 'spl'].map(mode => new Control({'data-mode': mode}));
  }
  set innerHTML(html) { this.markup = html; this.controls = controls(html); }
  querySelector(selector) {
    const named = selector.match(/^\[name=['"]?([^'"\]]+)['"]?\]$/);
    return named ? this.controls.find(control => control.name === named[1]) : this.parts[selector.slice(1, -1)];
  }
  querySelectorAll(selector) {
    if (selector === '[data-filter]') return this.rows;
    if (selector === '[data-mode]') return this.modes;
    if (selector.startsWith('[data-visual]')) return this.controls.filter(control => !['spl', 'result_limit'].includes(control.name)).concat(this.rows.flatMap(row => row.controls));
    throw new Error(`Unhandled mock selector ${selector}`);
  }
}
const context = {
  structuredClone, Object, Number, JSON, Error,
  document: {createElement: () => new EditorRoot()},
  h: escape,
  field: (label, name, val = '', type = 'text', extra = '') => `<label>${escape(label)}<input name="${name}" value="${escape(val)}" type="${type}" ${extra}></label>`,
  select: (label, name, opts, val = '') => `<label>${escape(label)}<select name="${name}">${opts.map(option => `<option value="${escape(option[0])}" ${String(option[0]) === String(val) ? 'selected' : ''}>${escape(option[1])}</option>`).join('')}</select></label>`,
  period: () => ({start: 100, end: 200}),
  notify: () => {}
};
vm.createContext(context);
vm.runInContext(source.slice(start, finish) + '\nthis.queryEditor = queryEditor;', context);
const create = initial => context.queryEditor(initial);
const plain = value => JSON.parse(JSON.stringify(value));
const passed = [];
function test(name, callback) { callback(); passed.push(name); }
test('numeric filters retain numeric semantics; numeric-looking strings retain strings', () => {
  const root = create({language: 'json', query: {filters: [{field: 'raw.bytes', op: 'gt', value: 10}, {field: 'raw.code', op: 'eq', value: '001'}]}});
  assert.deepEqual(plain(root.read().query.filters), [{field: 'raw.bytes', op: 'gt', value: 10}, {field: 'raw.code', op: 'eq', value: '001'}]);
});
test('custom multi-field aggregation, projection, sorting and result limit survive edit', () => {
  const initial = {language: 'json', limit: 777, query: {text: 'needle', filters: [], group_by: ['host', 'raw.security.user'], fields: ['raw.security.user'], sort: 'host', descending: false}};
  const result = create(initial).read();
  assert.deepEqual(plain(result.query), initial.query); assert.equal(result.limit, 777);
});
test('JSON string query body is parsed and preserved', () => {
  const body = {filters: [{field: 'received', op: 'gte', value: 42}], fields: ['event_id'], sort: 'received', descending: false};
  const result = create({language: 'json', query: JSON.stringify(body)}).read();
  assert.deepEqual(plain(result.query), {...body, text: ''});
});
test('omitted language follows backend default SPL and preserves pipeline', () => {
  const result = create({query: 'search source="lab" | stats count by host', limit: 350}).read();
  assert.equal(result.language, 'spl'); assert.equal(result.query, 'search source="lab" | stats count by host'); assert.equal(result.limit, 350);
});
test('global count group_by empty array remains distinct from no aggregation', () => {
  const result = create({language: 'json', query: {group_by: [], sort: 'count'}}).read();
  assert.deepEqual(plain(result.query.group_by), []); assert.equal(result.query.sort, 'count');
});
test('hidden visual required controls are disabled in SPL mode and restored', () => {
  const root = create({language: 'json', query: {filters: [{field: 'raw.bytes', op: 'eq', value: 12}]}});
  root.rows[0].querySelector('[data-field]').value = '';
  root.onclick({target: root.modes[1]});
  assert(root.rows[0].controls.every(control => control.disabled)); assert.equal(root.querySelector('[name=spl]').disabled, false);
  assert.equal(root.querySelector('[name=fields]').disabled, true);
  root.onclick({target: root.modes[0]});
  assert(root.rows[0].controls.every(control => !control.disabled)); assert.equal(root.querySelector('[name=spl]').disabled, true);
});
test('invalid numeric filter fails before submission', () => {
  const root = create({language: 'json', query: {filters: [{field: 'raw.bytes', op: 'gt', value: 12}]}});
  root.rows[0].querySelector('[data-value]').value = 'not-number'; assert.throws(() => root.read(), /숫자/);
});
test('malformed imported JSON fails closed', () => { assert.throws(() => create({language: 'json', query: '{bad'}).read(), /JSON/); });
test('changing analysis sets a valid default sort without losing existing projection', () => {
  const root = create({language: 'json', query: {fields: ['event_id'], sort: 'event_time'}});
  root.querySelector('[name=group]').value = 'host'; root.onchange({target: root.querySelector('[name=group]')});
  const result = root.read(); assert.equal(result.query.sort, 'count'); assert.deepEqual(plain(result.query.fields), ['event_id']); assert.deepEqual(plain(result.query.group_by), ['host']);
});
const barsStart = source.indexOf(' function bars('), barsEnd = source.indexOf(" register('logs'", barsStart);
Object.assign(context, {fmt: String, table: () => 'table'});
vm.runInContext(source.slice(barsStart, barsEnd) + '\nthis.bars = bars;', context);
test('bar labels use original non-count column indexes', () => {
  const rendered = context.bars({columns: ['count', 'host'], rows: [[3, 'alpha']]});
  assert(rendered.includes('<strong>alpha</strong>')); assert(!rendered.includes('<strong>3</strong>'));
});
test('actual API dictionary rows render grouped labels and counts', () => {
  const rendered = context.bars({columns: ['source', 'count'], rows: [{source: 'collector-a', count: 17}, {source: 'collector-b', count: 4}]});
  assert(rendered.includes('<strong>collector-a</strong>')); assert(rendered.includes('<span>17</span>'));
  assert(rendered.includes('<strong>collector-b</strong>')); assert(!rendered.includes('<strong>전체 이벤트</strong>'));
});
test('dictionary count-first bars keep original key association', () => {
  const rendered = context.bars({columns: ['count', 'host'], rows: [{count: 3, host: 'alpha'}]});
  assert(rendered.includes('<strong>alpha</strong>')); assert(rendered.includes('<span>3</span>'));
});
test('event object conversion supports actual dictionary and legacy array rows', () => {
  const columns = ['event_id', 'source', 'message', 'raw'];
  const actual = {event_id: 'fixture-1', source: 'collector-a', message: 'Fixture message', raw: {user: 'fixture-user'}};
  assert.deepEqual(plain(context.resultObject(columns, actual)), actual);
  assert.deepEqual(plain(context.resultObject(columns, columns.map(key => actual[key]))), actual);
});
test('dashboard number cell reads dictionary count and empty result fallback', () => {
  const columns = ['source', 'count'];
  assert.equal(context.resultCells(columns, {source: 'collector-a', count: 23})[columns.indexOf('count')], 23);
  assert.equal(context.resultCells(columns, {})[columns.indexOf('count')] ?? 0, 0);
});
const report = {passed: passed.length, assertions: passed, fixture_only: true, production_data: false};
if (process.argv[2]) fs.writeFileSync(path.resolve(process.argv[2]), JSON.stringify(report, null, 2));
process.stdout.write(JSON.stringify(report, null, 2) + '\n');
