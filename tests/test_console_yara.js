'use strict';
const assert=require('node:assert/strict');
const {test}=require('node:test');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const web=path.join(__dirname,'..','sapientia','web');
const source=fs.readFileSync(path.join(web,'console_yara.js'),'utf8');
const escape=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const decode=value=>String(value).replace(/&quot;/g,'"').replace(/&#39;/g,"'").replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&');
const plain=value=>JSON.parse(JSON.stringify(value));
function fields(html){
 const result={};
 for(const match of html.matchAll(/<input\b([^>]+)>/g)){const attr=match[1],name=attr.match(/name="([^"]+)"/)?.[1];if(name)result[name]={name,value:decode(attr.match(/value="([^"]*)"/)?.[1]||''),checked:/\bchecked\b/.test(attr),type:attr.match(/type="([^"]+)"/)?.[1]||'text'};}
 for(const match of html.matchAll(/<select name="([^"]+)">([\s\S]*?)<\/select>/g)){const options=[...match[2].matchAll(/<option value="([^"]*)"([^>]*)>/g)];result[match[1]]={name:match[1],value:decode((options.find(item=>item[2].includes('selected'))||options[0])?.[1]||'')};}
 for(const match of html.matchAll(/<textarea name="([^"]+)"[^>]*>([\s\S]*?)<\/textarea>/g))result[match[1]]={name:match[1],value:decode(match[2])};
 return result;
}
function fakeForm(){
 const node={isConnected:true,elements:{},sections:{},html:''};
 Object.defineProperty(node,'innerHTML',{set(html){this.html=html;this.elements=fields(html);},get(){return this.html;}});
 node.querySelector=selector=>{if(!node.sections[selector]){const child={html:'',hidden:false,textContent:''};Object.defineProperty(child,'innerHTML',{get(){return this.html;},set(value){this.html=value;}});node.sections[selector]=child;}return node.sections[selector];};
 node.querySelectorAll=selector=>selector==='[data-yara-string]'?[...node.querySelector('[data-yara-strings]').html.matchAll(/<div class="yara-string"[\s\S]*?(?=<div class="yara-string"|$)/g)].map(match=>{const parsed=fields(match[0]);return {querySelector:query=>parsed[query.match(/name="([^"]+)"/)?.[1]]};}):Object.values(node.elements);
 return node;
}
function context(api=async()=>[],role='admin',indexes=['*']){
 let session={name:'operator',tenant:'a',role,allowed_indexes:indexes};const routes={},dialogs=[],notices=[],downloads=[];
 const window={crypto:{randomUUID:()=> 'fixed-request-id'},Vatex:{h:escape,fmt:String,date:String,empty:(title,note)=>`<p>${escape(title)} ${escape(note)}</p>`,field:(label,name,value='',type='text',extra='')=>`<label>${escape(label)}<input name="${escape(name)}" value="${escape(value)}" type="${type}" ${extra}></label>`,select:(label,name,options,value)=>`<label>${escape(label)}<select name="${name}">${options.map(([key,title])=>`<option value="${escape(key)}" ${String(key)===String(value)?'selected':''}>${escape(title)}</option>`).join('')}</select></label>`,register:(name,value)=>routes[name]=value,session:()=>session,api,notify:message=>notices.push(message),download:(...value)=>downloads.push(value),dialog:options=>{dialogs.push(options);return {isConnected:true,close(){this.isConnected=false;if(typeof options.content==='object')options.content.isConnected=false;}};}}};
 vm.runInNewContext(source,{window,document:{createElement:fakeForm},AbortController,DOMException,URLSearchParams,Intl,Date,Math},{timeout:1000});
 return {logic:window.VatexYara,routes,dialogs,notices,downloads,setSession:value=>session=value};
}
const builtin=extra=>({id:'YC-a',name:'Reference rule',description:'Reference',source:'rule reference {condition: true}',origin:'builtin',indexes:['*'],revision:1,state:'active',effective_state:'active',enabled:true,requester:'release',rule_count:3,author:'Reference author',license:'MIT',...extra});
const artifact=extra=>({id:'artifact-a',state:'complete',incident_id:'case-a',index_name:'endpoint',name:'reference.bin',total_bytes:128,received:128,sha256:'a'.repeat(64),action:{type:'collect_artifact',source:'process_executable'},yara_job_state:'completed',yara_run_id:'run-a',...extra});
const run=extra=>({id:'run-a',artifact_id:'artifact-a',incident_id:'case-a',status:'completed',verdict:'unknown',matches:[],coverage_complete:true,selected_rule_count:1200,selected_file_count:400,...extra});
const target=extra=>({id:'target-a',target_id:'target-a',event_id:'original-a',agent_id:'agent-a',index:'endpoint',host:'host-a',process_guid:'guid-a',pid:23,start_identity:'start-a',path:'C:\\ref.exe',sha256:'a'.repeat(64),eligible:true,prepare_eligible:true,needs_prepare:false,...extra});
const command=extra=>({id:'command-a',incident_id:'case-a',evidence_event_id:'original-a',host:'host-a',requester:'operator',state:'succeeded',action:{type:'inspect_process'},result:{executed:true,code:'ok',data:{process_evidence_event_id:'new-original'}},...extra});
function apiFor(calls=[],overrides={}){return async(url,opts={})=>{
 calls.push({url,opts});if(overrides.handle){const value=await overrides.handle(url,opts);if(value!==undefined)return value;}
 if(opts.method)throw Error('Unexpected mutation '+url);
 if(url.endsWith('/status'))return {runtime_available:true,catalog:{rule_count:1200,file_count:400,private_helper_count:2,sources:[{id:'reference',rule_count:1200,license:'MIT'}]},rules:{total:400,active:400},max_artifact_bytes:33554432,...overrides.status};
 if(url.includes('/rules?'))return {items:[builtin()],total:400,offset:0,limit:100,...overrides.rules};
 if(url.endsWith('/rules/YC-a'))return builtin(overrides.rule);
 if(url.endsWith('/artifacts'))return {items:[artifact()],total:1,limit:200,...overrides.artifacts};
 if(url.endsWith('/runs'))return {items:[run()],total:1,limit:100,...overrides.runs};
 if(url.endsWith('/runs/run-a'))return run(overrides.run);
 if(url==='/api/incidents')return [{id:'case-a',title:'Reference Case'}];
 if(url.includes('/collection-targets?'))return {incident_id:'case-a',case_version:4,items:[target()],commands:[command()],max_process_bytes:33554432,...overrides.targets};
 if(url==='/api/agent-responses/command-a')return command(overrides.command);
 throw Error('Unexpected '+url);
};}
function control(action,id=''){const value={dataset:{yaraAction:action,id},isConnected:true,disabled:false};return {value,event:{target:{closest:selector=>selector==='[data-yara-action]'?value:null}}};}
const click=(root,action,id)=>root.onclick(control(action,id).event);
const rootNode=()=>({isConnected:true,innerHTML:''});

test('GUI builder retains typed text/hex modifiers, match/format and bounded disk file size',()=>{
 const {logic}=context(),value=logic.buildPayload({name:'safe_rule',description:'Reference',match:'any',format:'pe',max_bytes:33554432},[{kind:'text',value:'Reference',nocase:true,wide:true},{kind:'hex',value:'4D 5A ?? 00'}]);
 assert.equal(value.max_bytes,33554432);assert.equal(value.match,'any');assert.equal(value.format,'pe');assert.deepEqual(plain(value.strings[0]),{kind:'text',value:'Reference',nocase:true,wide:true});assert.deepEqual(plain(value.strings[1]),{kind:'hex',value:'4D 5A ?? 00'});
 for(const change of [{name:'한글'},{name:'1bad'},{match:'regex'},{format:'memory'},{max_bytes:33554433},{max_bytes:1.5}])assert.throws(()=>logic.buildPayload({...value,...change},value.strings));
 for(const strings of [[{kind:'text',value:'한글'}],[{kind:'text',value:'line\n'}],[{kind:'hex',value:'?? ??'}],[{kind:'hex',value:'GG'}],[{kind:'text',value:'x'.repeat(1025)}],[]])assert.throws(()=>logic.buildPayload(value,strings));
});
test('rule mutation pins revision and concrete custom scopes while builtin edit retains wildcard',()=>{
 const {logic}=context(),fields={name:' reviewed ',source:'rule a {condition: true}',indexes:'endpoint,network',enabled:true};
 assert.deepEqual(plain(logic.rulePayload(fields,3)),{name:'reviewed',description:'',source:fields.source,indexes:['endpoint','network'],enabled:true,expected_revision:3});
 assert.deepEqual(Array.from(logic.rulePayload(fields,1,true).indexes),['*']);
 assert.throws(()=>logic.rulePayload({...fields,indexes:'*'}),/정확한/);assert.throws(()=>logic.rulePayload({...fields,indexes:'a,a'}),/정확한/);assert.throws(()=>logic.rulePayload(fields,-1));assert.throws(()=>logic.rulePayload(fields,null,true));assert.throws(()=>logic.sourcePayload('x'.repeat(32769)));
});
test('collection payload derives only the selected original and revision, never arbitrary native action',()=>{
 const {logic}=context(),value=logic.collectionPayload({incident_id:'case-a',case_version:4},target(),{reason:'Read reference',path:'other',action:'kill'},'request-a');
 assert.deepEqual(plain(value),{incident_id:'case-a',event_id:'original-a',agent_id:'agent-a',case_version:4,request_id:'request-a',reason:'Read reference',target_id:'target-a'});
 assert.equal(logic.collectionPayload({incident_id:'case-a',case_version:4},target({eligible:false}),{prepare:true,reason:'Inspect reference'},'request-a').prepare_only,true);
 assert.throws(()=>logic.collectionPayload({incident_id:'case-a',case_version:4},target({eligible:false}),{reason:'Read'},'r'));assert.throws(()=>logic.collectionPayload({incident_id:'case-a',case_version:'4'},target(),{reason:'Read'},'r'));
});
test('compile availability and escaped results do not turn missing or partial inspection into clean',()=>{
 const {logic}=context();assert.equal(logic.validationOk({status:'completed'}),true);assert.equal(logic.validationOk({status:'unavailable',valid:true}),false);
 const validation=logic.validationView({status:'failed',error:'<script>bad</script>'});assert.ok(!validation.includes('<script>'));assert.match(logic.validationView({status:'unavailable'}),/런타임을 사용할 수 없습니다/);
 const output=logic.resultView(run({coverage_complete:false,status:'timeout',error:'<img src=x>',matches:[{rule:'<svg>',meta:{note:'<script>'}}]}));assert.ok(!output.includes('<img'));assert.ok(!output.includes('<svg>'));assert.match(output,/1200/);assert.match(output,/400/);assert.match(output,/미완료/);assert.match(output,/프로세스 메모리 검사 아님/);
 assert.match(logic.resultView(run()),/정상 판정이 아닙니다/);
});
test('viewer and scoped admin controls respect builtin wildcard and independent review semantics',()=>{
 const {logic}=context(),full={name:'operator',role:'admin',allowed_indexes:['*']},scoped={...full,allowed_indexes:['endpoint']};
 assert.match(logic.rulesView([builtin()],true,full),/data-yara-action="edit"/);const limited=logic.rulesView([builtin()],true,scoped);assert.match(limited,/data-yara-action="clone"/);assert.ok(!limited.includes('data-yara-action="edit"'));assert.ok(!logic.rulesView([builtin()],false,{role:'viewer'}).includes('data-yara-action="clone"'));
 assert.ok(!logic.rulesView([builtin({origin:'custom',state:'pending',requester:'operator'})],true,full).includes('data-yara-action="review"'));assert.match(logic.rulesView([builtin({origin:'custom',state:'pending',requester:'peer'})],true,full),/data-yara-action="review"/);
});
test('library reads actual catalog counts and pagination without automatic writes',async()=>{
 const calls=[],{routes}=context(apiFor(calls)),root=rootNode(),cleanup=await routes.yara.render(root);assert.equal(calls.length,2);assert.ok(calls.every(call=>!call.opts.method));assert.match(root.innerHTML,/1200/);assert.match(root.innerHTML,/400/);assert.match(root.innerHTML,/비공개 보조 포함/);await click(root,'next');assert.match(calls.at(-1).url,/offset=100/);cleanup();assert.equal(calls[0].opts.signal.aborted,true);assert.equal(root.onclick,null);
});
test('viewer deep link to scan returns read-only rule catalog',async()=>{
 const calls=[],{routes}=context(apiFor(calls),'viewer'),root=rootNode(),cleanup=await routes.yara.render(root,{tab:'scan'});assert.equal(calls.length,2);assert.ok(!root.innerHTML.includes('data-yara-tab="scan"'));assert.ok(!root.innerHTML.includes('data-yara-action="new"'));cleanup();
});
test('scan shows actual auto job status and fetches a historical result through the authorized detail endpoint',async()=>{
 const calls=[],{routes}=context(apiFor(calls,{runs:{items:[]}})),root=rootNode(),cleanup=await routes.yara.render(root,{tab:'scan',artifact_id:'artifact-a'});assert.ok(calls.some(call=>call.url==='/api/yara/runs/run-a'));assert.match(root.innerHTML,/파일 전송 · 자동 검사 상태/);assert.match(root.innerHTML,/128 \/ 128 bytes/);assert.match(root.innerHTML,/run-a/);assert.match(root.innerHTML,/1200/);assert.match(root.innerHTML,/정상 판정이 아닙니다/);cleanup();
});
test('manual scan POSTs only selected artifact, active rules and signal choice then uses persisted results',async()=>{
 const calls=[],api=apiFor(calls,{handle:(url,opts)=>url==='/api/yara/scans'&&opts.method==='POST'?run({signal_id:'finding-a',matches:[{rule:'reference'}]}):undefined}),{routes}=context(api),root=rootNode(),cleanup=await routes.yara.render(root,{tab:'scan'});
 const form={elements:{artifact_id:{value:'artifact-a'},selection:{value:'all'},emit_signal:{checked:true}}};await root.onsubmit({preventDefault(){},target:{closest:selector=>selector==='[data-yara-scan]'?form:null}});
 const sent=calls.find(call=>call.opts.method==='POST');assert.equal(sent.url,'/api/yara/scans');assert.deepEqual(JSON.parse(sent.opts.body),{artifact_id:'artifact-a',emit_signal:true});assert.match(root.innerHTML,/finding-a/);cleanup();
});
test('collection view exposes exact eligible targets and explicit new-original linking, never blocking actions',async()=>{
 const calls=[],{routes}=context(apiFor(calls)),root=rootNode(),cleanup=await routes.yara.render(root,{tab:'collection',incident_id:'case-a'});assert.match(root.innerHTML,/data-yara-action="collect"/);assert.match(root.innerHTML,/data-yara-action="attach"/);assert.match(root.innerHTML,/33554432/);assert.ok(!root.innerHTML.includes('data-yara-action="kill"'));assert.ok(calls.every(call=>!call.opts.method));
 const {logic}=context();assert.equal(logic.commandView(command({action:{type:'kill_process'}})),'');assert.match(logic.targetView([target({eligible:false,needs_prepare:true})]),/data-yara-action="prepare"/);cleanup();
});
test('collection confirmation sends frozen original identity and explicit readonly preparation flag',async()=>{
 const calls=[],api=apiFor(calls,{targets:{items:[target({eligible:false,needs_prepare:true})]},handle:(url,opts)=>url==='/api/yara/collections'&&opts.method==='POST'?command():undefined}),{routes,dialogs}=context(api),root=rootNode(),cleanup=await routes.yara.render(root,{tab:'collection',incident_id:'case-a'});await click(root,'prepare','target-a');assert.equal(calls.filter(call=>call.opts.method).length,0);dialogs[0].content.elements.reason.value='Inspect exact reference';await dialogs[0].onSave();
 const sent=calls.find(call=>call.opts.method==='POST');assert.equal(sent.url,'/api/yara/collections');assert.deepEqual(JSON.parse(sent.opts.body),{incident_id:'case-a',event_id:'original-a',agent_id:'agent-a',case_version:4,request_id:'fixed-request-id',reason:'Inspect exact reference',prepare_only:true,target_id:'target-a'});cleanup();
});
test('new original is read from server and bookmarked only after explicit confirmation',async()=>{
 const calls=[],api=apiFor(calls,{handle:(url,opts)=>url==='/api/search'?{rows:[{event_id:'new-original',host:'host-a',raw:{safe:'Reference'}}]}:url==='/api/incidents/case-a/bookmarks'?{id:'bookmark-a'}:undefined}),{routes,dialogs}=context(api),root=rootNode(),cleanup=await routes.yara.render(root,{tab:'collection',incident_id:'case-a'});await click(root,'attach','command-a');assert.equal(calls.filter(call=>call.url.endsWith('/bookmarks')).length,0);assert.match(dialogs[0].content.innerHTML,/new-original/);dialogs[0].content.elements.label.value='Reviewed hash-bearing original';await dialogs[0].onSave();const sent=calls.find(call=>call.url.endsWith('/bookmarks'));assert.deepEqual(JSON.parse(sent.opts.body),{event_id:'new-original',label:'Reviewed hash-bearing original'});cleanup();
});
test('advanced source must compile current bytes, preserves builtin wildcard and pins edit revision',async()=>{
 const calls=[],api=apiFor(calls,{handle:(url,opts)=>url.endsWith('/validate')?{status:'completed',rule_count:1}:url.endsWith('/rules/YC-a')&&opts.method==='PUT'?builtin({revision:2,state:'pending'}):undefined}),{routes,dialogs}=context(api),root=rootNode(),cleanup=await routes.yara.render(root);await click(root,'edit','YC-a');const dialog=dialogs[0],form=dialog.content;assert.equal(form.elements.indexes.value,'*');assert.equal(form.elements.indexes.readOnly,true);await assert.rejects(dialog.onSave(),/실제 YARA 컴파일/);await form.onclick({target:{closest:()=>({dataset:{yaraAction:'validate'},isConnected:true})}});await dialog.onSave();const sent=calls.find(call=>call.opts.method==='PUT');assert.deepEqual(JSON.parse(sent.opts.body).indexes,['*']);assert.equal(JSON.parse(sent.opts.body).expected_revision,1);cleanup();
});
test('source edit while compile is pending cannot mark changed bytes valid or permit save',async()=>{
 let resolve;const calls=[],api=apiFor(calls,{handle:(url,opts)=>url.endsWith('/validate')?new Promise(done=>resolve=done):undefined}),{routes,dialogs}=context(api),root=rootNode(),cleanup=await routes.yara.render(root);await click(root,'edit','YC-a');const form=dialogs[0].content,pending=form.onclick({target:{closest:()=>({dataset:{yaraAction:'validate'},isConnected:true})}});await Promise.resolve();form.elements.source.value='rule changed {condition: false}';form.oninput({target:{name:'source'}});resolve({status:'completed',rule_count:1});await pending;await assert.rejects(dialogs[0].onSave(),/실제 YARA 컴파일/);assert.ok(!form.querySelector('[data-yara-validation]').innerHTML.includes('실제 YARA 컴파일 완료'));cleanup();
});
test('builtin restore sends only the optimistic revision and does not invent a reason API field',async()=>{
 const calls=[],api=apiFor(calls,{rule:{revision:2},rules:{items:[builtin({revision:2})]},handle:(url,opts)=>url.endsWith('/restore')?builtin():undefined}),{routes,dialogs}=context(api),root=rootNode(),cleanup=await routes.yara.render(root);await click(root,'restore','YC-a');assert.ok(!dialogs[0].content.innerHTML.includes('name="reason"'));await dialogs[0].onSave();assert.deepEqual(JSON.parse(calls.find(call=>call.url.endsWith('/restore')).opts.body),{expected_revision:2});cleanup();
});
test('deleted custom rules can restore to peer review while untouched builtins hide restoration',async()=>{
 const calls=[],item=builtin({origin:'custom',state:'deleted',effective_state:'deleted',revision:3}),api=apiFor(calls,{rule:item,rules:{items:[item]},handle:(url,opts)=>url.endsWith('/restore')?{...item,state:'pending',revision:4}:undefined}),{routes,dialogs,logic,notices}=context(api),root=rootNode(),cleanup=await routes.yara.render(root);
 assert.match(root.innerHTML,/data-yara-action="restore"[^>]*>규칙 복원/);await click(root,'restore','YC-a');assert.match(dialogs[0].content.innerHTML,/독립 승인/);await dialogs[0].onSave();assert.deepEqual(JSON.parse(calls.find(call=>call.url.endsWith('/restore')).opts.body),{expected_revision:3});assert.match(notices.at(-1),/독립 검토 대기/);
 assert.ok(!logic.rulesView([builtin()],true,{name:'operator',role:'admin',allowed_indexes:['*']}).includes('data-yara-action="restore"'));cleanup();
});
test('tenant drift and detached views cannot paint old responses or keep an active controller',async()=>{
 const waiting=[];let signal;const {routes,setSession}=context((url,opts)=>{signal=opts.signal;return new Promise(resolve=>waiting.push(resolve));}),root=rootNode(),pending=routes.yara.render(root);setSession({name:'operator',tenant:'b',role:'admin',allowed_indexes:['*']});root.innerHTML='new tenant';waiting.forEach(resolve=>resolve({items:[],total:0}));const cleanup=await pending;assert.equal(root.innerHTML,'new tenant');assert.equal(signal.aborted,true);cleanup();
});
test('shell assets and Case link expose one actual YARA route with incident context',()=>{
 const html=fs.readFileSync(path.join(web,'index.html'),'utf8'),nav=fs.readFileSync(path.join(web,'console.js'),'utf8'),cases=fs.readFileSync(path.join(web,'console_investigation.js'),'utf8');for(const asset of ['console_yara.js','console_yara.css'])assert.equal(html.split(asset).length-1,1);assert.match(nav,/'intelligence','content','yara'/);assert.match(cases,/#yara\?tab=collection&amp;incident_id=\$\{enc\(incident.id\)\}/);
});
