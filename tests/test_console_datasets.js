'use strict';
const assert=require('node:assert/strict');
const {test}=require('node:test');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'..','sapientia','web','console_datasets.js'),'utf8');
const escape=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const decode=value=>String(value).replace(/&quot;/g,'"').replace(/&#39;/g,"'").replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&');
function fakeForm(){
 const node={elements:{},isConnected:true,querySelector:()=>null};
 Object.defineProperty(node,'innerHTML',{set(html){this.html=html;this.elements={};for(const match of html.matchAll(/<input\b([^>]+)>/g)){const attrs=match[1],name=attrs.match(/name="([^"]+)"/)?.[1];if(name)this.elements[name]={value:decode(attrs.match(/value="([^"]*)"/)?.[1]||''),checked:/\bchecked\b/.test(attrs),type:attrs.match(/type="([^"]+)"/)?.[1]||'text'};}for(const match of html.matchAll(/<select name="([^"]+)">([\s\S]*?)<\/select>/g)){const chosen=[...match[2].matchAll(/<option value="([^"]*)"([^>]*)>/g)];this.elements[match[1]]={value:decode((chosen.find(item=>item[2].includes('selected'))||chosen[0])?.[1]||'')};}for(const match of html.matchAll(/<textarea name="([^"]+)"[^>]*>([\s\S]*?)<\/textarea>/g))this.elements[match[1]]={value:decode(match[2])};},get(){return this.html;}});
 return node;
}
function context(api=async()=>[],role='admin'){
 let session={name:'operator',tenant:'a',role};const routes={},dialogs=[],notices=[];
 const window={Vatex:{h:escape,fmt:String,date:String,period:()=>({start:100,end:200}),empty:(title,note)=>`<p>${escape(title)} ${escape(note)}</p>`,table:(columns,rows)=>`<table>${rows.map(row=>`<tr>${row.map(item=>`<td>${escape(item)}</td>`).join('')}</tr>`).join('')}</table>`,field:(label,name,value='',type='text',extra='')=>`<label>${escape(label)}<input name="${escape(name)}" value="${escape(value)}" type="${type}" ${extra}></label>`,select:(label,name,items,value)=>`<label>${escape(label)}<select name="${name}">${items.map(item=>{const [key,title]=Array.isArray(item)?item:[item,item];return `<option value="${escape(key)}" ${String(key)===String(value)?'selected':''}>${escape(title)}</option>`;}).join('')}</select></label>`,register:(name,value)=>routes[name]=value,session:()=>session,api,notify:message=>notices.push(message),dialog:options=>{dialogs.push(options);return {close(){},remove(){},addEventListener(){}};}}};
 const document={createElement:()=>fakeForm()};
 const FormData=class{constructor(node){this.node=node;}entries(){return Object.entries(this.node.elements).filter(([,item])=>item.type!=='checkbox'||item.checked).map(([name,item])=>[name,item.type==='checkbox'?'on':item.value]);}};
 vm.runInNewContext(source,{window,document,FormData,AbortController,Date,DOMException,URLSearchParams,Intl,setTimeout},{timeout:1000});
 return {logic:window.VatexDatasets,routes,dialogs,notices,setSession:value=>session=value};
}
function dataset(overrides={}){return {id:'d',name:'Stored sequence',description:'reviewed',kind:'sequence',family:'sequence',indexes:['endpoint'],revision:3,state:'active',owner:'operator',counts:{samples:2,originals:4,training:2,calibration:0,holdout:0,normal:1,attack:1,templates:0},readiness:{ready:false,issues:['More heldout originals required']},usage:{models:[]},allowed_actions:{edit:true,remove:true,add_sample:true,edit_sample:true,remove_sample:true,validate:true,train:true,materialize:true},...overrides};}
function sample(overrides={}){return {id:'s',scenario_id:'Stored scenario',split:'training',label:'normal',family:'train-normal',host_group:'host-a',event_ids:['original-a','original-b'],event_count:2,mode:'originals',materialized:true,...overrides};}
function apiFor(item=dataset(),row=sample(),calls=[]){return async(url,opts={})=>{calls.push({url,opts});if(url.endsWith('/datasets/d'))return item;if(url.includes('/samples?'))return {items:[row],total:1,next_cursor:null,revision:item.revision};if(url.endsWith('/samples/s'))return {sample:row,revision:item.revision};if(url.endsWith('/status'))return {available:true,device:'cpu'};if(url.endsWith('/models'))return [];if(url.includes('/dataset-bundles'))return {items:[],installed_sample_counts:{}};if(url.includes('/datasets?'))return {items:[item],total:1,next_cursor:null};throw Error('Unexpected '+url);};}
test('dataset metadata carries exact scope and optimistic revision, never wildcard',()=>{
 const {logic}=context();const value=logic.metadataPayload({name:' reviewed ',description:'purpose',indexes:'endpoint, network'},7,'sequence');
 assert.equal(value.expected_revision,7);assert.equal(value.kind,'sequence');assert.deepEqual(Array.from(value.indexes),['endpoint','network']);assert.equal(value.name,'reviewed');
 assert.throws(()=>logic.metadataPayload({name:'x',indexes:'*'},0,'sequence'),/정확한/);assert.throws(()=>logic.metadataPayload({name:'x',indexes:'a,a'},0),/정확한/);
});
test('sample CRUD preserves split metadata and admits only bounded original reference shapes',()=>{
 const {logic}=context(),fields={scenario_id:'reviewed',split:'holdout',label:'attack',family:'heldout',host_group:'host'};
 const value=logic.samplePayload(fields,['a','b'],3,'sequence');assert.equal(value.expected_revision,3);assert.deepEqual(Array.from(value.sample.event_ids),['a','b']);assert.equal(value.sample.label,'attack');
 const template=logic.samplePayload(fields,[],3,'sequence',true);assert.ok(!Object.hasOwn(template.sample,'event_ids'));assert.ok(!Object.hasOwn(template.sample,'template_events'));
 assert.throws(()=>logic.samplePayload(fields,['a','a'],3,'sequence'),/실제 원본/);assert.throws(()=>logic.samplePayload(fields,['a'],3,'autoencoder'),/용도|정상/);
 const ae=logic.samplePayload({...fields,split:'calibration',label:'normal'},['a'],3,'autoencoder');assert.equal(ae.sample.event_ids.length,1);
});
test('training requires explicit review and retains family-specific maximum epochs',()=>{
 const {logic}=context();assert.throws(()=>logic.trainPayload({name:'m',epochs:30,reviewed:false},2,'sequence'),/검토/);
 const ae=logic.trainPayload({name:'normal',epochs:120,reviewed:true},2,'autoencoder');assert.equal(ae.normal_training_confirmed,true);assert.equal(ae.reviewed_dataset,true);assert.equal(ae.expected_revision,2);
 assert.throws(()=>logic.trainPayload({name:'sequence',epochs:61,reviewed:true},2,'sequence'),/반복/);
});
test('sample inference uses saved originals only, defaults shadow and excludes labels',()=>{
 const {logic}=context(),value=logic.inferencePayload([sample()], 'sequence');assert.equal(value.shadow,true);assert.deepEqual(Array.from(value.sequences[0].event_ids),['original-a','original-b']);assert.ok(!Object.hasOwn(value.sequences[0],'label'));
 assert.throws(()=>logic.inferencePayload([sample({mode:'template',event_ids:[],materialized:false})],'sequence'),/원본이 저장/);
 const ae=logic.inferencePayload([sample({event_ids:['a']}),sample({id:'b',event_ids:['a']})],'autoencoder');assert.equal(ae.event_ids.length,1);
});
test('current action flags, viewer role and admin-only materialization are all enforced in UI',()=>{
 const {logic}=context(),item=dataset();assert.equal(logic.can(item,'edit',{role:'viewer'}),false);assert.equal(logic.can(item,'materialize',{role:'analyst'}),false);assert.equal(logic.can(item,'materialize',{role:'admin'}),true);assert.equal(logic.can({...item,allowed_actions:{edit:false}},'edit',{role:'admin'}),false);
});
test('count/readiness/sample output escapes data and does not invent missing quantities',()=>{
 const {logic}=context();assert.match(logic.countsView({samples:0}),/>0</);assert.match(logic.countsView({}),/—/);
 assert.ok(!logic.readinessView({ready:false,issues:['<script>bad</script>']}).includes('<script>'));
 const html=logic.sampleRows([sample({scenario_id:'<img src=x>',host_group:'<script>bad</script>'})],new Set(),false);assert.ok(!html.includes('<img'));assert.ok(!html.includes('<script>'));
});
test('dataset list displays backend actual counts and never imports or materializes automatically',async()=>{
 const calls=[],{routes}=context(apiFor(dataset(),sample(),calls)),root={innerHTML:'',isConnected:true};const cleanup=await routes.datasets.render(root);
 assert.match(root.innerHTML,/저장된 학습 자료/);assert.match(root.innerHTML,/기본 학습 예제/);assert.match(root.innerHTML,/자동 등록하지 않음/);assert.equal(calls.length,2);assert.ok(calls.every(call=>!call.opts.method));cleanup();
});
test('detail consumes exact endpoints and wrapped sample response, has actual readiness and usage',async()=>{
 const calls=[],{routes,dialogs}=context(apiFor(dataset(),sample(),calls)),root={innerHTML:'',isConnected:true};const cleanup=await routes.datasets.render(root,{id:'d'});
 assert.ok(calls.some(call=>call.url==='/api/v3/ml/status'));assert.ok(!calls.some(call=>call.url.includes('/ml/ml/')));assert.match(root.innerHTML,/학습 준비 확인 필요/);
 const control={dataset:{datasetAction:'sample-detail',id:'s'},isConnected:true};await root.onclick({target:{closest:()=>control}});assert.equal(dialogs.length,1);assert.match(dialogs[0].content,/original-a/);assert.match(dialogs[0].title,/원본 근거/);cleanup();
});
test('viewer details never expose dataset write, sample CRUD or materialization actions',async()=>{
 const {routes}=context(apiFor(),'viewer'),root={innerHTML:'',isConnected:true};const cleanup=await routes.datasets.render(root,{id:'d'});
 for(const action of ['dataset-edit','dataset-remove','sample-new','sample-edit','sample-remove','materialize','train','validate','infer'])assert.ok(!root.innerHTML.includes(`data-dataset-action="${action}"`));cleanup();
});
test('real metadata ADD action POSTs canonical contract and refreshes persisted list',async()=>{
 const calls=[],base=apiFor(dataset(),sample(),calls),api=async(url,opts={})=>{if(opts.method==='POST'){calls.push({url,opts});assert.equal(url,'/api/v3/ml/datasets');const body=JSON.parse(opts.body);assert.equal(body.expected_revision,0);assert.equal(body.name,'new reviewed');assert.equal(body.kind,'sequence');return {dataset:dataset(),revision:1};}return base(url,opts);};
 const {routes,dialogs}=context(api),root={innerHTML:'',isConnected:true};const cleanup=await routes.datasets.render(root);
 const control={dataset:{datasetAction:'dataset-new',id:''},isConnected:true};await root.onclick({target:{closest:()=>control}});dialogs[0].content.elements.name.value='new reviewed';dialogs[0].content.elements.indexes.value='endpoint';await dialogs[0].onSave();assert.equal(calls.filter(call=>call.opts.method==='POST').length,1);cleanup();
});
test('sample version drift is surfaced before opening an edit form',async()=>{
 const calls=[],base=apiFor(dataset(),sample(),calls),api=async(url,opts)=>url.endsWith('/samples/s')?{sample:sample(),revision:4}:base(url,opts);
 const {routes,dialogs,notices}=context(api),root={innerHTML:'',isConnected:true};const cleanup=await routes.datasets.render(root,{id:'d'});
 const control={dataset:{datasetAction:'sample-edit',id:'s'},isConnected:true};await root.onclick({target:{closest:()=>control}});assert.equal(dialogs.length,0);assert.match(notices[0],/자료가 변경/);cleanup();
});
test('old tenant replies cannot overwrite a new workspace and cleanup cancels reads',async()=>{
 const waits=[];let signal;const {routes,setSession}=context((url,opts)=>{signal=opts.signal;return new Promise(resolve=>waits.push({url,resolve}));}),root={innerHTML:'new workspace',isConnected:true};const pending=routes.datasets.render(root);setSession({name:'operator',tenant:'b',role:'admin'});
 for(const wait of waits)wait.resolve(wait.url.includes('dataset-bundles')?{items:[],installed_sample_counts:{}}:{items:[],total:0,next_cursor:null});const cleanup=await pending;assert.equal(root.innerHTML,'new workspace');cleanup();assert.equal(signal.aborted,true);assert.equal(root.onclick,null);
});
test('new assets are included once and actual sidebar exposes dataset plus intelligence routes',()=>{
 const html=fs.readFileSync(path.join(__dirname,'..','sapientia','web','index.html'),'utf8'),nav=fs.readFileSync(path.join(__dirname,'..','sapientia','web','console.js'),'utf8');
 for(const asset of ['console_datasets.js','console_datasets.css','console_policy_editor.js'])assert.equal(html.split(asset).length-1,1);
 assert.match(nav,/\['MANAGE',\['data','datasets'/);assert.match(nav,/'analysis','advanced','intelligence','content'/);
});
test('sample edit and remove permissions are independent and template readiness is explained in Korean',()=>{
 const {logic}=context(),item=sample();
 const removeOnly=logic.sampleRows([item],new Set(),{edit:false,remove:true});
 assert.ok(!removeOnly.includes('data-dataset-action="sample-edit"'));assert.ok(removeOnly.includes('data-dataset-action="sample-remove"'));
 const editOnly=logic.sampleRows([item],new Set(),{edit:true,remove:false});
 assert.ok(editOnly.includes('data-dataset-action="sample-edit"'));assert.ok(!editOnly.includes('data-dataset-action="sample-remove"'));
 const hint=logic.readinessView({ready:false,issues:[{code:'templates_require_materialization',message:'Template drafts cannot train'}]});
 assert.match(hint,/등록 전 예제는 아직 학습할 수 없습니다/);assert.ok(!hint.includes('Template drafts'));
});
test('current resumable materialization job is surfaced and another owner cannot restart it',async()=>{
 const own=dataset({indexes:['ml_synthetic_demo'],usage:{models:[],materializations:[{id:'job-a',owner:'operator',resumable:true,state:'pending',position:8,total:96,current_revision:3,lease_remaining_seconds:0}]}}),first=context(apiFor(own)),root={innerHTML:'',isConnected:true};
 const cleanup=await first.routes.datasets.render(root,{id:'d'});assert.match(root.innerHTML,/예제 테스트 로그 저장 재개/);assert.match(root.innerHTML,/data-id="job-a"/);cleanup();
 const other=dataset({usage:{models:[],materializations:[{id:'job-b',owner:'peer',resumable:false,state:'running',position:8,total:96,lease_remaining_seconds:115}]}}),next=context(apiFor(other)),second={innerHTML:'',isConnected:true};const stop=await next.routes.datasets.render(second,{id:'d'});
 assert.match(second.innerHTML,/기존 저장 작업 확인 필요/);assert.match(second.innerHTML,/대기 115초/);assert.ok(!second.innerHTML.includes('data-id="job-b"'));
 await second.onclick({target:{closest:()=>({dataset:{datasetAction:'materialize',id:'job-b'},isConnected:true})}});assert.equal(next.dialogs.length,0);assert.match(next.notices[0],/작성자의 재개 가능한/);stop();
});
test('training waits for successful current validation and usage activation pointer stays qualified',async()=>{
 const item=dataset({usage:{models:[{id:'m',name:'Reviewed model',family:'sequence',dataset_revision:2,active:true}]}}),{routes}=context(apiFor(item)),root={innerHTML:'',isConnected:true};const cleanup=await routes.datasets.render(root,{id:'d'});
 assert.match(root.innerHTML,/data-dataset-action="train"[^>]*disabled/);assert.match(root.innerHTML,/활성 설정 · 실행 시 출처 재검증/);cleanup();
});
