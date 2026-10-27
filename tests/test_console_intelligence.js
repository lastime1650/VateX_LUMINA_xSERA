'use strict';
const assert=require('node:assert/strict');
const {test}=require('node:test');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'..','sapientia','web','console_intelligence.js'),'utf8');
const escape=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function context(api=async()=>[],role='analyst'){
 let session={name:'analyst',tenant:'a',role};const routes={};
 const window={Vatex:{h:escape,fmt:String,date:String,empty:(title,note)=>`<p>${escape(title)} ${escape(note)}</p>`,table:(columns,rows)=>`<table>${rows.map(row=>`<tr>${row.map(value=>`<td>${escape(value)}</td>`).join('')}</tr>`).join('')}</table>`,register:(name,route)=>routes[name]=route,session:()=>session,api}};
 const dialogs=[];window.Vatex.dialog=options=>{dialogs.push(options);return {close(){},remove(){}};};window.Vatex.notify=()=>{};
 const document={createElement:()=>{const node={elements:{},isConnected:true};Object.defineProperty(node,'innerHTML',{set(value){this.html=value;for(const name of [...value.matchAll(/name="([^"]+)"/g)].map(item=>item[1]))this.elements[name]={value:'',checked:false};},get(){return this.html;}});return node;}};
 vm.runInNewContext(source,{window,document,AbortController,Date,DOMException,URLSearchParams,Intl},{timeout:1000});
 return {logic:window.VatexIntelligence,routes,dialogs,setSession:value=>session=value};
}
test('training uses actual original IDs and separates normal training from holdout',()=>{
 const {logic}=context(),records=Array.from({length:24},(_,i)=>({event_id:'real-'+i,index_name:i<16?'endpoint':'network'})),assignments=Object.fromEntries(records.map((row,i)=>[row.event_id,i<16?'training':'validation']));
 const payload=logic.trainPayload({name:'CPU',epochs:'30',confirmed:true},assignments,records);
 assert.equal(payload.training_ids.length,16);assert.equal(payload.validation_ids.length,8);assert.equal(payload.epochs,30);assert.equal(payload.normal_training_confirmed,true);
 assert.deepEqual(Array.from(payload.indexes),['endpoint','network']);assert.equal(payload.training_ids.some(id=>payload.validation_ids.includes(id)),false);
 assert.throws(()=>logic.trainPayload({name:'CPU',epochs:30,confirmed:true},{...assignments,invented:'training'},records),/현재 조회된 원본/);
 assert.throws(()=>logic.trainPayload({name:'CPU',epochs:30,confirmed:false},assignments,records),/검토/);
});
test('policy review displays fresh exact definition and pins and submits only after content confirmation',async()=>{
 const calls=[],old={id:'p',version:1,owner:'peer',state:'draft',kind:'composite',indexes:['network'],definition:{name:'Old definition',kind:'composite',inputs:[]}},fresh={...old,version:2,indexes:['endpoint','network'],definition:{name:'Current <script>definition</script>',kind:'composite',enabled:true,severity:'high',window:300,confidence_grade:'source_reported',join_on:'flow',ordered:true,clock_policy:'strict',minimum_independent_groups:2,inputs:[{rule_id:'ml:sequence:m',kind:'ml'},{rule_id:'parent',kind:'atomic'}],input_revisions:{parent:{version:4,definition_digest:'parent-digest'}},input_models:{'ml:sequence:m':{model_family:'sequence',revision:3,indexes:['endpoint'],digest:'model-digest'}},case_adapter:{entity_field:'host',risk_score:75,severity:'high',cooldown:300,case_grouping:'require_exact_identity',mitre:['T1071']}}};let reads=0;
 const api=async(url,options={})=>{calls.push({url,options});if(options.method)return {state:'active'};if(url.endsWith('/intelligence/policies'))return [++reads===1?old:fresh];if(url==='/api/content/sigma/imports')return {items:[]};if(url.includes('/signals?'))return {items:[],next_cursor:null};if(url.includes('/decisions?'))return {items:[],next_cursor:null};throw Error(url);};
 const {routes,dialogs}=context(api),root={innerHTML:'',isConnected:true};const cleanup=await routes.intelligence.render(root,{tab:'signals'});
 await root.onclick({target:{closest:()=>({dataset:{action:'policy-review',id:'p'},isConnected:true})}});
 assert.equal(dialogs.length,1);const form=dialogs[0].content;for(const value of ['endpoint, network','parent-digest','model-digest','ml:sequence:m','require_exact_identity','75'])assert.ok(form.innerHTML.includes(value));
 assert.ok(!form.innerHTML.includes('<script>'));assert.match(form.innerHTML,/현재 개정/);assert.match(form.innerHTML,/>2</);
 await assert.rejects(dialogs[0].onSave(),/먼저 확인/);assert.ok(calls.every(call=>!call.options.method));
 form.elements.reviewed.checked=true;form.elements.reason.value='Reviewed current scope and parents';await dialogs[0].onSave();
 const posted=calls.find(call=>call.options.method==='POST');assert.equal(posted.url,'/api/v3/intelligence/policies/p/review');assert.equal(JSON.parse(posted.options.body).version,2);cleanup();
});
test('typed policy and distribution review summaries retain scope, values and observed measurements',()=>{
 const {logic}=context(),html=logic.policyDetail({version:9,state:'draft',owner:'peer',indexes:['public'],definition:{name:'Observation',kind:'atomic',enabled:false,severity:'low',window:120,confidence_grade:'source_reported',filters:[{field:'raw.authentication.failed','op':'eq',value:false}],case_adapter:null}});
 for(const value of ['raw.authentication.failed','false','public','사용하지 않음','현재 개정'])assert.ok(html.includes(value));
 const distribution=logic.distributionDetail({name:'Normal model',revision:3,owner:'peer',indexes:['public'],digest:'exact-digest',threshold:0.7,metrics:{training_samples:16,validation_samples:8,validation_mse:0.25},features:['reported_count']});
 for(const value of ['exact-digest','16','8','0.25','보정된 악성 확률'])assert.ok(distribution.includes(value));
 assert.ok(!logic.distributionDetail({metrics:{}}).includes('undefined'));
});
test('insufficient training or invalid feature times never become plausible payloads',()=>{
 const {logic}=context();
 assert.throws(()=>logic.trainPayload({}, {}, []),/16개/);
 assert.throws(()=>logic.featurePayload({start:'invalid',end:'invalid'},['public']),/유효한 시각/);
 const payload=logic.featurePayload({name:'features',entity_field:'host',start:'2026-10-14T00:00:00Z',end:'2026-10-14T01:00:00Z',bucket:'60',samples:'20',buckets:'7',multiplier:'3',seasonality:'none',timezone:'Asia/Seoul'},['public']);
 assert.equal(payload.end-payload.start,3600);assert.equal(payload.min_buckets,7);assert.equal(payload.bucket_seconds,60);assert.equal(payload.timezone,'Asia/Seoul');
});
test('search adapter supports actual table rows and object rows',()=>{
 const {logic}=context();
 assert.equal(logic.resultRows({columns:['event_id','host'],rows:[['e','actual-host']]} )[0].host,'actual-host');
 assert.equal(logic.resultRows({columns:[],rows:[{event_id:'e'}]})[0].event_id,'e');
});
test('all stored signal text and HTML attributes are escaped',()=>{
 const {logic}=context(),html=logic.signalRows([{id:'"><img src=x>',kind:'atomic',rule_id:'<script>bad</script>',rule_revision:1,severity:'high',event_ids:['e'],confidence_grade:'<img onerror=x>',created:1}]);
 assert.ok(!html.includes('<script>'));assert.ok(!html.includes('<img'));assert.match(html,/&lt;script&gt;/);assert.match(html,/악성 확률/);
});
test('CPU compatibility remains explicit without fabricated accuracy or availability',()=>{
 const {logic}=context(),html=logic.modelStatus({available:false,reason:'<script>device error</script>'});
 assert.match(html,/시스템에서 호환되지 않음/);assert.ok(!html.includes('<script>'));assert.ok(!html.includes('%'));assert.match(html,/&lt;script&gt;/);
});
test('actual signal renderer exposes decisions, pages and independent review without JSON editor',async()=>{
 const api=async url=>url.includes('/signals')?{items:[{id:'signal',kind:'behavior',rule_id:'baseline',rule_revision:1,severity:'medium',event_ids:['e'],confidence_grade:'statistical_deviation',created:1}],next_cursor:100}:url.includes('/decisions')?{items:[{at:1,policy_id:'p',reason:'<img src=x>'}],next_cursor:null}:[{id:'p',definition:{name:'Real policy'},kind:'atomic',version:1,state:'draft',owner:'other'}];
 const {routes}=context(api),root={innerHTML:'',isConnected:true};const cleanup=await routes.intelligence.render(root);
 assert.match(root.innerHTML,/독립 검토/);assert.match(root.innerHTML,/다음 기록/);assert.match(root.innerHTML,/분석 결정/);assert.ok(!root.innerHTML.includes('JSON 편집'));assert.ok(!root.innerHTML.includes('<img'));cleanup();
});
test('viewer can inspect model state but has no training, activation or stop controls',async()=>{
 const {routes}=context(async url=>url.endsWith('/status')?{available:true,device:'cpu',framework:'pytorch'}:[{id:'m',name:'<img src=x>',revision:1,owner:'other',active:false,threshold:.01}],'viewer'),root={innerHTML:'',isConnected:true};
 const cleanup=await routes.intelligence.render(root,{tab:'models'});
 assert.ok(!root.innerHTML.includes('data-action="model-train"'));assert.ok(!root.innerHTML.includes('data-action="model-activate"'));assert.ok(!root.innerHTML.includes('data-action="model-disable"'));assert.ok(!root.innerHTML.includes('<img'));cleanup();
});
test('delayed old-tenant responses never overwrite the new workspace and cleanup aborts requests',async()=>{
 const waits=[];let signal;const {routes,setSession}=context((url,opts)=>{signal=opts.signal;return new Promise(resolve=>waits.push({url,resolve}));}),root={innerHTML:'new workspace',isConnected:true};
 const rendering=routes.intelligence.render(root);setSession({name:'analyst',tenant:'b',role:'analyst'});
 for(const wait of waits)wait.resolve(wait.url.includes('/policies')?[]:{items:[],next_cursor:null});
 const cleanup=await rendering;assert.equal(root.innerHTML,'new workspace');cleanup();assert.equal(signal.aborted,true);
});
test('HTML loads the complete view once and navigation includes its real route',()=>{
 const html=fs.readFileSync(path.join(__dirname,'..','sapientia','web','index.html'),'utf8'),nav=fs.readFileSync(path.join(__dirname,'..','sapientia','web','console.js'),'utf8');
 assert.equal((html.match(/console_intelligence\.js/g)||[]).length,1);assert.equal((html.match(/console_intelligence\.css/g)||[]).length,1);assert.match(nav,/'advanced','intelligence','content'/);assert.match(nav,/intelligence:'탐지 · 연결 분석'/);
});

function reviewedManifest(){
 const result={name:'Ordered CPU',indexes:['endpoint'],epochs:15,reviewed_dataset:true};
 for(const [split,count] of [['training',32],['calibration',16],['holdout',16]])result[split]=Array.from({length:count},(_,i)=>({scenario_id:`${split}-${i}`,family:`family-${split}`,host_group:`host-${split}-${i}`,label:i%2?'attack':'normal',event_ids:[`${split}-${i}-first`,`${split}-${i}-last`]}));
 return result;
}
test('sequence manifest requires independent UI review and preserves ordered exact originals',()=>{
 const {logic}=context(),manifest=reviewedManifest();
 const result=logic.sequencePayload(JSON.stringify(manifest),true,'Reviewed GRU','20');
 assert.equal(result.name,'Reviewed GRU');assert.equal(result.epochs,20);assert.equal(result.reviewed_dataset,true);
 assert.equal(result.holdout.length,16);assert.equal(result.holdout[0].event_ids[0],'holdout-0-first');
 assert.throws(()=>logic.sequencePayload(manifest,false),/검토/);
 assert.throws(()=>logic.sequencePayload({...manifest,weights:{layer:[1]}},true),/가중치/);
 assert.throws(()=>logic.sequencePayload({...manifest,code:'run()'},true),/코드/);
 assert.throws(()=>logic.sequencePayload({...manifest,indexes:['*']},true),/인덱스/);
 assert.throws(()=>logic.sequencePayload(manifest,true,'x','61'),/1–60/);
 const repeated=reviewedManifest();repeated.holdout[0].event_ids[0]=repeated.training[0].event_ids[0];
 assert.throws(()=>logic.sequencePayload(repeated,true),/중복/);
 const oneClass=reviewedManifest();oneClass.calibration.forEach(row=>row.label='normal');
 assert.throws(()=>logic.sequencePayload(oneClass,true),/정상·공격/);
});
test('sequence measured confusion and tensor metrics are escaped and unavailable stays unmeasured',()=>{
 const {logic}=context();
 const missing=logic.confusionView(null);assert.match(missing,/아직 측정 기록이 없습니다/);assert.ok(!missing.includes('<td>0</td>'));
 const html=logic.sequenceDetail({name:'<script>bad</script>',indexes:['<img src=x>'],revision:2,features:['<img onerror=x>'],metrics:{input_tensor_shape:[64,12,41],padded_steps:24,duration_ms:130},split_summary:{training:{scenarios:64,normal:32,attack:32,hosts:8}},assessment:{metrics:{samples:16,true_positive:7,false_negative:1,false_positive:2,true_negative:6,precision:.77,recall:.875},input_tensor_shape:[16,12,41],padded_steps:8,duration_ms:12,order_sensitivity_mean_abs_delta:.08}});
 assert.match(html,/64 × 12 × 41/);assert.match(html,/16 × 12 × 41/);assert.match(html,/130/);assert.match(html,/공격<\/td><td>7<\/td><td>1/);
 assert.match(html,/보정된 악성 확률이 아닙니다/);assert.ok(!html.includes('<script>'));assert.ok(!html.includes('<img'));assert.match(html,/&lt;script&gt;/);
});
test('model workspace fetches both real families and stream, guards retired/self activation controls',async()=>{
 const calls=[],api=async url=>{calls.push(url);if(url.endsWith('/ml/status'))return {available:true,device:'cpu'};if(url.endsWith('/ml/models'))return [{id:'ae',name:'distribution',owner:'other',revision:1,active:false}];if(url.endsWith('/sequences/models'))return [{id:'seq',name:'ordered',owner:'other',revision:2,active:false,assessment_id:'assessment',indexes:['endpoint']},{id:'retired',name:'retired row',owner:'other',revision:1,retired:true,active:false,indexes:['endpoint']},{id:'self',name:'own row',owner:'analyst',revision:1,active:false,indexes:['endpoint']}];return {states:[{model_id:'seq',cursor:30,updated:1}],window_events:12,idle_seconds:5};};
 const {routes}=context(api),root={innerHTML:'',isConnected:true};const cleanup=await routes.intelligence.render(root,{tab:'models'});
 for(const suffix of ['/ml/models','/ml/sequences/models','/ml/sequences/stream'])assert.ok(calls.some(url=>url.endsWith(suffix)));
 assert.match(root.innerHTML,/정상 분포 모델/);assert.match(root.innerHTML,/시간 순서 분류 모델/);assert.match(root.innerHTML,/실시간 시계열/);assert.match(root.innerHTML,/sequence-evaluate/);assert.match(root.innerHTML,/sequence-train/);
 assert.ok(root.innerHTML.includes('data-action="sequence-activate" data-id="seq"'));
 assert.ok(!root.innerHTML.includes('data-action="sequence-activate" data-id="self"'));
 assert.ok(!root.innerHTML.includes('data-action="sequence-retire" data-id="self"'));
 assert.ok(!root.innerHTML.includes('data-action="sequence-evaluate" data-id="retired"'));
 assert.ok(root.innerHTML.includes('data-action="sequence-detail" data-id="retired"'));cleanup();
});
test('viewer has no sequence lifecycle writes but can read stored model measurements',async()=>{
 const api=async url=>url.endsWith('/status')?{available:true}:url.endsWith('/stream')?{states:[]}:url.includes('/sequences/')?[{id:'seq',name:'GRU',owner:'other',revision:1,active:false,assessment_id:'a',indexes:['endpoint']}]:[];
 const {routes}=context(api,'viewer'),root={innerHTML:'',isConnected:true};const cleanup=await routes.intelligence.render(root,{tab:'models'});
 assert.ok(root.innerHTML.includes('data-action="sequence-detail"'));
 for(const action of ['sequence-train','sequence-evaluate','sequence-activate','sequence-disable','sequence-retire','model-retire'])assert.ok(!root.innerHTML.includes(`data-action="${action}"`));cleanup();
});
test('retired sequence detail reads retained public assessment without calling live-only endpoint',async()=>{
 const calls=[],api=async url=>{calls.push(url);if(url.endsWith('/status'))return {available:true};if(url.endsWith('/stream'))return {states:[]};if(url.endsWith('/sequences/models'))return [{id:'retired',name:'retired GRU',retired:true,active:false,indexes:['endpoint'],assessment_id:'historic',assessment:{metrics:{samples:16,true_positive:6,false_negative:2,false_positive:1,true_negative:7},input_tensor_shape:[16,12,41],duration_ms:12}}];return [];};
 const {routes,dialogs}=context(api,'viewer'),root={innerHTML:'',isConnected:true};const cleanup=await routes.intelligence.render(root,{tab:'models'});
 const control={dataset:{action:'sequence-detail',id:'retired'},isConnected:true,disabled:false};
 await root.onclick({target:{closest:()=>control}});
 assert.equal(dialogs.length,1);assert.match(dialogs[0].content,/16 × 12 × 41/);assert.match(dialogs[0].content,/공격/);
 assert.ok(!calls.some(url=>url.endsWith('/assessment')));assert.equal(control.disabled,false);cleanup();
});

test('detection notices retain escaped author license and source without executable links',()=>{
 const {logic}=context();
 const html=logic.noticeView({metadata:{content_notices:{complete:false,items:[{kind:'yara_rule',rule_name:'Example',author:'<img src=x onerror=bad()>',license:'DRL-1.1',source_url:'https://example.invalid/rule',license_url:'javascript:bad()'}]}}});
 assert.match(html,/DRL-1.1/);assert.match(html,/https:\/\/example.invalid\/rule/);assert.match(html,/&lt;img/);assert.doesNotMatch(html,/<img|href=/);assert.match(html,/일부 생략/);
 const sigma=logic.noticeView({metadata:{sigma_import:{content_notices:{complete:true,items:[{title:'Sigma',author:'Original Author',license:'MIT',references:['https://example.invalid/sigma']}]}}}});
 assert.match(sigma,/Original Author/);assert.match(sigma,/MIT/);assert.equal(logic.noticeView({metadata:{}}),'');
});
