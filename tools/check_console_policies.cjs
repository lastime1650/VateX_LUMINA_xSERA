'use strict';
// Exercise the production policy builder against a small dependency-free DOM mock.
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(path.resolve(__dirname,'../sapientia/web/console_workflows.js'),'utf8');
const helpers=source.slice(source.indexOf('  const h = V.h;'),source.indexOf('  function scopeFor('));
const builder=source.slice(source.indexOf('  const filterOps = '),source.indexOf('  async function policies('));
const decode=s=>String(s).replace(/&quot;/g,'"').replace(/&#39;/g,"'").replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&');
const escape=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const attrs=s=>Object.fromEntries([...s.matchAll(/([\w-]+)(?:=(?:"([^"]*)"|'([^']*)'))?/g)].map(m=>[m[1],decode(m[2]??m[3]??'')]));
function controls(html){return [...html.matchAll(/<(input|select|textarea)\b([^>]*)(?:>([\s\S]*?)<\/\1>|>)/g)].map(m=>{const a=attrs(m[2]),opts=m[1]==='select'?[...m[3].matchAll(/<option([^>]*)>/g)].map(o=>attrs(o[1])):[];return {...a,name:a.name,value:m[1]==='select'?(opts.find(o=>Object.hasOwn(o,'selected'))||opts[0]||{}).value||'':m[1]==='textarea'?decode(m[3]):a.value||'',checked:Object.hasOwn(a,'checked')};});}
class Row{
  constructor(html){this.controls=controls(html);}
  querySelector(selector){return this.controls.find(c=>c.name===selector.match(/^\[name="([^"]+)"\]$/)?.[1]);}
}
class Host extends Row{
  constructor(){super('');this.handlers={};}
  set innerHTML(html){this.markup=html;this.controls=controls(html);this.steps=[...html.matchAll(/<section class="wf-step" data-step="(\d+)">([\s\S]*?)<\/section>/g)].map(m=>{const row=new Row(m[2]);row.filters=[...m[2].matchAll(/<div class="wf-filter-row" data-filter="(\d+)">([\s\S]*?)<\/div>/g)].map(f=>new Row(f[2]));row.querySelectorAll=selector=>{assert.equal(selector,'[data-filter]');return row.filters;};return row;});}
  querySelectorAll(selector){assert.equal(selector,'[data-step]');return this.steps;}
  addEventListener(name,handler){this.handlers[name]=handler;}
  removeEventListener(name){delete this.handlers[name];}
  contains(){return true;}
}
const sandbox={V:{h:escape,session:()=>({role:'analyst'}),notify(){}},URLSearchParams,Date,Number,crypto:{randomUUID:()=> 'mock-id'}};
vm.runInNewContext(helpers+'\n'+builder+'\nglobalThis.buildPolicy=policyBuilder;',sandbox);
const plain=x=>JSON.parse(JSON.stringify(x)),tests=[];
function check(name,fn){fn();tests.push({name,passed:true});}
const definition={name:'Imported template',entity_field:'host',window:300,interval:30,evaluation_delay:0,cooldown:300,risk_score:70,severity:'high',mitre:['T1059.001'],enabled:false,steps:[{name:'First',min_count:1,text:'',filters:[{field:'raw.xdr.data.command_line',op:'regex',value:'(?i)(?s) -enc '},{field:'raw.xdr.schema',op:'typed_eq',value:'aegis.endpoint.v1'},{field:'raw.xdr.data.pid',op:'number_gte',value:3}]},{name:'Follow-up',min_count:1,text:'',within_seconds:120,filters:[{field:'raw.xdr.data.kind',op:'typed_in',value:'[ "file", "network" ]'},{field:'raw.xdr.data.process',op:'exists',value:1}]}]};
function open(data=definition){const host=new Host(),editor=sandbox.buildPolicy(host,data);return {host,editor};}
check('imported_regex_typed_operations_and_timed_step_roundtrip',()=>{const {editor}=open();assert.deepEqual(plain(editor.read()),definition);});
check('typed_members_preserve_original_string_representation',()=>{const {host,editor}=open();assert.equal(editor.read().steps[1].filters[0].value,'[ "file", "network" ]');assert(host.markup.includes('문자: file · 문자: network'));assert(!host.markup.includes('value="[ &quot;file&quot;'));});
check('numeric_and_numeric_string_values_remain_distinct',()=>{const item=plain(definition);item.steps[0].filters=[{field:'raw.value',op:'typed_eq',value:'3'},{field:'raw.value',op:'typed_eq',value:3}];assert.deepEqual(plain(open(item).editor.read().steps[0].filters),item.steps[0].filters);});
check('empty_string_predicate_is_valid_and_not_hidden_required',()=>{const item=plain(definition);item.steps[0].filters=[{field:'raw.value',op:'typed_eq',value:''}];const {host,editor}=open(item);assert.equal(editor.read().steps[0].filters[0].value,'');assert(!Object.hasOwn(host.steps[0].filters[0].querySelector('[name="value"]'),'required'));});
check('explicit_timed_step_can_be_removed_without_coercing_zero',()=>{const {host,editor}=open();host.steps[1].querySelector('[name="within_seconds"]').value='';assert(!Object.hasOwn(editor.read().steps[1],'within_seconds'));assert(!Object.hasOwn(editor.read().steps[0],'within_seconds'));});
check('step_time_limit_edits_are_numeric',()=>{const {host,editor}=open();host.steps[1].querySelector('[name="within_seconds"]').value='60';assert.equal(editor.read().steps[1].within_seconds,60);});
check('invalid_numeric_value_fails_closed',()=>{const {host,editor}=open();host.steps[0].filters[2].querySelector('[name="value"]').value='NaN';assert.throws(()=>editor.read(),/숫자 조건/);});
check('exists_requires_numeric_zero_or_one',()=>{const {host,editor}=open();host.steps[1].filters[1].querySelector('[name="value"]').value='2';assert.throws(()=>editor.read(),/존재 조건/);});
check('unknown_future_predicate_is_preserved_not_changed_to_equality',()=>{const item=plain(definition);item.steps[0].filters=[{field:'raw.value',op:'future_op',value:'literal'}];assert.deepEqual(plain(open(item).editor.read().steps[0].filters),item.steps[0].filters);});
const result={passed:true,checks:tests.length,tests};if(process.argv[2])fs.writeFileSync(path.resolve(process.argv[2]),JSON.stringify(result,null,2));console.log(`${tests.length} passed`);
