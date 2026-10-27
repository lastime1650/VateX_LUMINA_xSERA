'use strict';
const assert=require('node:assert/strict');
const {test}=require('node:test');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'..','sapientia','web','console_analysis_research.js'),'utf8');
const escape=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function context(api=async()=>({items:[]}),role='admin'){
  let session={name:'operator',tenant:'a',role};const routes={},notices=[];
  const window={Vatex:{h:escape,api,register:(k,v)=>routes[k]=v,session:()=>session,empty:t=>`<p>${escape(t)}</p>`,notify:m=>notices.push(m)}};
  vm.runInNewContext(source,{window,AbortController,DOMException,TextEncoder,console},{timeout:1000});
  return {logic:window.VatexAnalysisResearch,routes,notices,setSession:s=>session=s};
}
const config={name:'Source',sensor:'osquery',index:'endpoint',account:'host',realm:'production',credential_ref:'env:SAPIENTIA_CONNECTOR_SENSOR',mode:'replay',create_case:true,alert_queries:'credential_query, persistence_query'};

test('existing analysis automation is preserved under a separate new route',()=>{
 const ctx=context();assert.ok(ctx.routes['analysis-research']);assert.equal(ctx.routes.analysis,undefined);
 assert.match(fs.readFileSync(path.join(__dirname,'..','sapientia','web','console_analysis.js'),'utf8'),/V\.register\('analysis'/);
});
test('source payload pins replay realm, exact index and reviewed query list',()=>{
 const {logic}=context(),result=logic.sourcePayload(config);
 assert.equal(result.realm,'virtual-lab');assert.equal(result.mode,'replay');assert.equal(result.create_case,true);
 assert.deepEqual(Array.from(result.alert_queries),['credential_query','persistence_query']);
 for(const change of [{sensor:'shell'},{mode:'certified'},{index:'*'},{index:'a,b'},{alert_queries:'same,same'}])assert.throws(()=>logic.sourcePayload({...config,...change}));
});
test('intake requires actual source JSON objects and durable checkpoint revision',()=>{
 const {logic}=context(),result=logic.intakePayload('[{"id":"stable","log":{"ts":1}}]',2,'source-offset',7);
 assert.equal(result.version,2);assert.equal(result.checkpoint_version,7);assert.equal(result.events[0].id,'stable');
 for(const value of ['[]','{}','not-json','[{"id":"x","log":[]}]','[{"log":{}}]'])assert.throws(()=>logic.intakePayload(value,1,'x',0));
 assert.throws(()=>logic.intakePayload('[{"id":"x","log":{}}]',1,'',0));
});
test('research training rejects leakage, absent normal review and invalid epochs',()=>{
 const {logic}=context(),fields={name:'normal',indexes:'endpoint',training_ids:Array.from({length:16},(_,i)=>'t'+i).join(','),validation_ids:Array.from({length:8},(_,i)=>'v'+i).join(','),epochs:60,normal_training_confirmed:true};
 const value=logic.trainingPayload(fields);assert.equal(value.training_ids.length,16);assert.equal(value.validation_ids.length,8);
 for(const change of [{normal_training_confirmed:false},{epochs:0},{epochs:121},{epochs:1.2},{validation_ids:'t1,v1,v2,v3,v4,v5,v6,v7'},{training_ids:'t,t'}])assert.throws(()=>logic.trainingPayload({...fields,...change}));
});
test('original list bounds and duplicates cannot become fabricated graph input',()=>{
 const {logic}=context();assert.deepEqual(Array.from(logic.eventIds('a,b\nc',1,3)),['a','b','c']);
 for(const value of ['','a,a','a,b,c,d','x'.repeat(257)])assert.throws(()=>logic.eventIds(value,1,3));
});
test('HTML from engine outputs and sensor fields is escaped, and unsafe links are inert',()=>{
 const {logic}=context(),html=logic.engineResult({id:'<script>',summary:{strings:['<img src=x onerror=attack()>']},status:'unavailable',error:'<svg onload=x>'});
 assert.ok(!html.includes('<script>'));assert.ok(!html.includes('<img'));assert.match(html,/&lt;script&gt;/);assert.match(html,/사용 불가/);
 assert.ok(!logic.safeLink('javascript:attack()','Paper').includes('href'));assert.match(logic.safeLink('https://example.org/?q="','Paper'),/&quot;/);
 const rows=logic.sourceRows([{id:'x',name:'<script>',state:'active',effective_state:'active',mode:'replay',owner:'operator'}],true,'operator').join('');
 assert.match(rows,/&lt;script&gt;/);assert.match(rows,/설치 검증: 미수행/);assert.ok(!rows.includes('data-ar-action="sensor-review"'));
});
test('sensor view loads real GET routes and no mutation on opening',async()=>{
 const calls=[],ctx=context(async(url,opts)=>{calls.push({url,opts});return url.endsWith('/catalog')?{items:[{id:'falco',name:'Falco',scope:'syscall',local_runtime_status:'unavailable'}]}:{items:[]};});
 const root={isConnected:true,innerHTML:''};const close=await ctx.routes['analysis-research'].render(root,{});
 assert.match(root.innerHTML,/외부 센서/);assert.match(root.innerHTML,/사용 불가/);assert.match(root.innerHTML,/센서 연결 만들기/);
 assert.deepEqual(calls.map(x=>x.url).sort(),['/api/analysis/sensors/catalog','/api/analysis/sensors/sources']);
 assert.ok(calls.every(x=>!x.opts.method));close();assert.ok(calls.every(x=>x.opts.signal.aborted));
});
test('viewer opens inventory without authoring or submitting actions',async()=>{
 const ctx=context(async()=>({items:[]}), 'viewer'),root={isConnected:true,innerHTML:''};
 await ctx.routes['analysis-research'].render(root,{});
 assert.ok(!root.innerHTML.includes('data-ar-action="sensor-new"'));
});
test('session changes reject in-flight results before repainting private data',async()=>{
 let release;const gate=new Promise(resolve=>release=resolve),ctx=context(async()=>{await gate;return {items:[{name:'PRIVATE'}]};}),root={isConnected:true,innerHTML:'initial'};
 const pending=ctx.routes['analysis-research'].render(root,{});ctx.setSession({name:'other',tenant:'b',role:'admin'});release();
 await assert.rejects(pending,/View closed/);assert.equal(root.innerHTML,'initial');
});
test('engine view displays absence honestly and retains explicit CAPE consent workflow',async()=>{
 const calls=[],ctx=context(async(url,opts)=>{calls.push(url);if(url.endsWith('/status'))return {engines:[{id:'cape',available:false,reason:'unconfigured',sample_execution:'sandbox'}]};return {items:[]};});
 const root={isConnected:true,innerHTML:''};await ctx.routes['analysis-research'].render(root,{tab:'engines'});
 assert.match(root.innerHTML,/사용 불가/);assert.match(root.innerHTML,/다른 관리자의 승인/);assert.match(root.innerHTML,/별도 CAPE 격리 환경/);
 assert.equal(calls.length,4);assert.ok(!root.innerHTML.includes('<form data-ar-scan>'));
});

test('Sigma JSON authoring pins the actual parser profile and explicit source mappings',()=>{
 const {logic}=context(),example=logic.sigmaSample(),fields=Object.fromEntries(Object.entries(example).map(([key,value])=>[key,JSON.stringify(value)]));
 const payload=logic.sigmaPayload(fields);assert.equal(payload.profile,'pysigma-json-v3');
 assert.equal(payload.rule.detection.condition,'process and command');assert.equal(payload.logsource_mapping.category.field,'sourcetype');
 assert.deepEqual(Object.keys(payload).sort(),['field_mapping','logsource_mapping','profile','rule']);
 for(const raw of ['[]','null','"string"','{broken'])assert.throws(()=>logic.sigmaPayload({...fields,rule:raw}));
 assert.throws(()=>logic.sigmaPayload({...fields,rule:JSON.stringify({title:'한'.repeat(23000)})}),/64 KiB/);
});

test('Sigma result escapes query, limitations and unsupported errors without execution controls',()=>{
 const {logic}=context(),html=logic.sigmaResult({profile:'pysigma-json-v3',query_only:true,query:{query:'search <script>bad()</script>'},limitations:['<img onerror=bad()>'],upstream:{version:'2.0.1'}});
 assert.match(html,/질의 미리보기만/);assert.match(html,/변환 제한/);assert.match(html,/&lt;script&gt;/);assert.ok(!html.includes('<script>'));assert.ok(!html.includes('<img'));
 const failure=logic.sigmaResult(null,'Unsupported <svg onload=x>');assert.match(failure,/변환되지 않음/);assert.match(failure,/&lt;svg/);assert.ok(!failure.includes('<svg'));
 assert.ok(!html.includes('type="submit"'));
});

test('legacy Sigma viewer deeplink is a read-only handoff to native rule management',async()=>{
 const calls=[],ctx=context(async(url,opts)=>{calls.push({url,opts});return {available:false};},'viewer'),root={isConnected:true,innerHTML:''};
 await ctx.routes['analysis-research'].render(root,{tab:'sigma'});
 assert.deepEqual(calls.map(x=>x.url),['/api/content/sigma/status']);assert.ok(calls.every(x=>!x.opts.method));
 assert.match(root.innerHTML,/기존 JSON 규칙 관리로 통합/);assert.match(root.innerHTML,/독립 승인/);assert.ok(!root.innerHTML.includes('<form data-ar-sigma>'));
 assert.ok(!root.innerHTML.includes('data-ar-tab="sigma"'));
});

test('legacy Sigma analyst deeplink has a handoff, without a duplicate authoring form',async()=>{
 const ctx=context(async()=>({available:true}),'analyst'),root={isConnected:true,innerHTML:''};
 await ctx.routes['analysis-research'].render(root,{tab:'sigma'});
 assert.match(root.innerHTML,/data-ar-action="sigma-manage"/);assert.ok(!root.innerHTML.includes('data-ar-sigma>'));
});

test('removed Sigma preview form cannot submit a legacy write',async()=>{
 const calls=[],ctx=context(async(url,opts)=>{calls.push({url,opts});return {available:true};},'analyst'),root={isConnected:true,innerHTML:''};
 await ctx.routes['analysis-research'].render(root,{tab:'sigma'});
 await root.onsubmit({target:{matches:s=>s==='[data-ar-sigma]'},preventDefault(){}});
 assert.ok(calls.every(x=>!x.opts.method));
});

test('manual online Shadow copy explicitly excludes operational ADWIN updates',async()=>{
 const ctx=context(async()=>({backend:{available:false},items:[],live_telemetry_training:false})),root={isConnected:true,innerHTML:''};
 await ctx.routes['analysis-research'].render(root,{tab:'online'});
 assert.match(root.innerHTML,/수동 Shadow/);assert.match(root.innerHTML,/ADWIN/);
});
