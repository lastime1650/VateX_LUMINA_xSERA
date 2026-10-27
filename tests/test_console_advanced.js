'use strict';
const assert=require('node:assert/strict');
const {test}=require('node:test');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'..','sapientia','web','console_advanced.js'),'utf8');
const escape=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function context(api=async()=>[]){
  let session={name:'admin',tenant:'a',role:'admin'};
  const routes={};
  const window={Vatex:{h:escape,fmt:String,date:String,badge:(v,s)=>escape(s),empty:(t,n)=>`<p>${escape(t)} ${escape(n)}</p>`,select:()=>'',field:()=>'',register:(name,route)=>{routes[name]=route;},session:()=>session,api}};
  vm.runInNewContext(source,{window,AbortController,Date,DOMException,URLSearchParams,Intl},{timeout:1000});
  return {models:window.VatexAdvanced,routes,setSession:value=>{session=value;}};
}

test('IP temporal visual fields serialize as structured backend properties',()=>{
  const {models}=context();
  const data=models.identityPayload({kind:'ip',lookup:'10.0.0.1',entity_id:'asset',session_id:'session',valid_from:'2026-10-13T10:00:00Z',valid_until:'2026-10-13T11:00:00Z',reason:'actual DHCP'},[{event_id:'event',fields:{'raw.ip':'10.0.0.1'}}],3);
  assert.equal(data.kind,'ip');assert.equal(data.version,3);assert.equal(data.valid_until-data.valid_from,3600);
  assert.equal(data.evidence[0].fields['raw.ip'],'10.0.0.1');assert.equal(typeof data.lookup,'string');
});
test('NAT visual fields preserve full tuple and translated session',()=>{
  const {models}=context();
  const data=models.identityPayload({kind:'nat',entity_id:'asset',src_ip:'203.0.113.1',src_port:'45000',dest_ip:'198.51.100.1',dest_port:'443',protocol:'tcp',translated:true,translated_src_ip:'10.0.0.1',translated_src_port:'50000',translated_dest_ip:'198.51.100.1',translated_dest_port:'443',translated_protocol:'tcp',valid_from:'2026-10-13T10:00:00Z',valid_until:'2026-10-13T10:01:00Z',reason:'exact NAT'},[]);
  assert.equal(data.lookup.src_port,45000);assert.equal(data.translated.src_port,50000);assert.equal(Object.keys(data.lookup).length,5);
});
test('bad date never silently becomes null in a configuration payload',()=>{
  const {models}=context();
  assert.throws(()=>models.identityPayload({kind:'ip',valid_from:'invalid',valid_until:'invalid'},[]),/유효한 시각/);
});
test('storm form preserves critical bypass and explicit expiry',()=>{
  const {models}=context();
  const data=models.governancePayload({kind:'storm',policy_id:'p',indexes:'public, endpoint',expires:'2026-10-13T11:00:00Z',reason:'bounded',max_per_window:'10',window_seconds:'60'});
  assert.equal(data.max_per_window,10);assert.deepEqual(Array.from(data.bypass_severities),['high','critical']);assert.ok(data.expires>0);assert.equal(data.conditions,undefined);
});
test('exception form emits exact condition structure rather than raw JSON text',()=>{
  const {models}=context(),conditions=[{field:'entity',op:'eq',value:'host'}];
  const data=models.governancePayload({kind:'exception',policy_id:'p',case_id:'case',indexes:'public',expires:'2026-10-13T11:00:00Z',reason:'maintenance'},conditions,2);
  assert.equal(data.case_id,'case');assert.equal(data.conditions,conditions);assert.equal(data.version,2);assert.equal(data.max_per_window,undefined);
});
test('asset risk and signature forms retain revision and source provenance',()=>{
  const {models}=context(),when='2026-10-13T11:00:00Z';
  const risk=models.riskPayload({expires:when,exposure:'internet',classification:'restricted',source:'scanner',reason:'known'},[{id:'CVE',cvss:9.1,known_exploited:true}],5);
  assert.equal(risk.version,5);assert.equal(risk.source,'scanner');assert.equal(risk.vulnerabilities[0].cvss,9.1);
  const sig=models.signaturePayload({name:'bundle',expires:when,indexes:'endpoint'},[{kind:'sha256',value:'a'.repeat(64)}],2);
  assert.equal(sig.version,2);assert.equal(sig.signatures[0].kind,'sha256');
});
test('source field picker excludes arrays and prototypes; retains scalar types',()=>{
  const {models}=context();
  const fields=models.scalarFields({event_id:'e',raw:{port:443,signed:false,list:['not scalar'],nested:{ip:'1.2.3.4'}}});
  assert.equal(fields.find(([name])=>name==='raw.port')[1],443);assert.equal(fields.find(([name])=>name==='raw.signed')[1],false);
  assert.ok(!fields.some(([name])=>name.includes('list')));assert.ok(!fields.some(([name])=>name.includes('__proto__')));
});
test('risk chart escapes all text and keeps operational priority distinct from probability',()=>{
  const {models}=context();
  const html=models.prioritySVG({score:'<img src=x onerror=alert(1)>',factors:{'<script>':{contribution:5}}});
  assert.ok(!html.includes('<script>'));assert.ok(!html.includes('<img'));assert.match(html,/악성 확률과 별도/);assert.match(html,/&lt;script&gt;/);
  assert.ok(!html.includes('style='));
});
test('empty percentiles remain visibly unmeasured and incomplete clocks remain explicit',()=>{
  const {models}=context();
  const stages=Object.fromEntries(['provider_to_received','received_to_indexed','indexed_to_case','case_to_effect'].map(k=>[k,{count:0,p95_seconds:null,p99_seconds:null}]));
  const html=models.sloFlow({stages,coverage_complete:false,event_count:1,missing_index_clocks:1,pending_index_events:0,provider_clock_skew_events:0});
  assert.match(html,/측정 범위가 불완전/);assert.match(html,/—/);assert.ok(!html.includes('0.000초'));
});
test('actual renderer escapes stored provenance and uses typed controls without JSON editor',async()=>{
  const api=async target=>{
    if(target.endsWith('/capabilities'))return {file_verdict:{yara_runtime_available:false}};
    if(target.endsWith('/identity'))return {items:[]};
    if(target.endsWith('/governance'))return [{id:'rule',kind:'storm',policy_id:'p',version:1,state:'pending',effective_state:'pending',requester:'another',expires:1,definition:{reason:'<img src=x onerror=alert(1)>'}}];
    return [];
  };
  const {routes}=context(api),root={innerHTML:'',isConnected:true};
  const cleanup=await routes.advanced.render(root);
  assert.ok(!root.innerHTML.includes('<img'));assert.match(root.innerHTML,/&lt;img/);assert.match(root.innerHTML,/원본 로그/);
  assert.ok(!root.innerHTML.includes('JSON 편집'));assert.match(root.innerHTML,/정체성 확인/);assert.match(root.innerHTML,/P95\/P99/);cleanup();
});
test('late data after tenant switch never draws into the new workspace',async()=>{
  const waits=[];
  const {routes,setSession}=context(target=>new Promise(resolve=>waits.push({target,resolve})));
  const root={innerHTML:'new workspace sentinel',isConnected:true};
  const rendering=routes.advanced.render(root);
  setSession({name:'admin',tenant:'b',role:'admin'});
  for(const {target,resolve} of waits)resolve(target.endsWith('/capabilities')?{file_verdict:{yara_runtime_available:false}}:target.endsWith('/identity')?{items:[]}:[]);
  const cleanup=await rendering;
  assert.equal(root.innerHTML,'new workspace sentinel');cleanup();
});
test('detached view does not draw late data and cleanup aborts requests',async()=>{
  const waits=[];let signal;
  const {routes}=context((target,opts)=>{signal=opts.signal;return new Promise(resolve=>waits.push({target,resolve}));});
  const root={innerHTML:'detached sentinel',isConnected:true};
  const rendering=routes.advanced.render(root);root.isConnected=false;
  for(const {target,resolve} of waits)resolve(target.endsWith('/capabilities')?{file_verdict:{yara_runtime_available:false}}:target.endsWith('/identity')?{items:[]}:[]);
  const cleanup=await rendering;assert.equal(root.innerHTML,'detached sentinel');cleanup();assert.equal(signal.aborted,true);
});
