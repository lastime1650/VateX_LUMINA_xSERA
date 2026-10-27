'use strict';
const assert=require('node:assert/strict');
const {test}=require('node:test');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const source=fs.readFileSync(path.join(__dirname,'..','sapientia','web','console_analysis_research.js'),'utf8');
const runId='RBR-9bb9bc4dfe564035bbbdb72ebc9aa1b8';
const escape=value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const result={run_id:runId,publication:{state:'published',signal_id:'SIG-original'},signals:[{id:'SIG-derived',kind:'composite',rule_id:'policy'}],cases:[{id:'CASE-older',name:'Older <Case>',status:'open'}],evidence:{short_count:32,long_count:48,manifest_id:'snapshot'},complete:true};

async function mounted(trace=async()=>result){
 let session={name:'viewer',tenant:'a',role:'viewer',allowed_indexes:['public']};
 const routes={},dialogs=[],calls=[],navigation=[],notices=[];
 const node=tag=>({tagName:tag,innerHTML:'',isConnected:false,elements:tag==='form'?{run_id:{value:''}}:{}});
 const root={isConnected:true,innerHTML:'',querySelector:selector=>{assert.equal(selector,'[role="tabpanel"]');return {append:child=>{child.isConnected=true;}};}};
 const V={h:escape,session:()=>session,register:(name,value)=>routes[name]=value,empty:text=>`<p>${escape(text)}</p>`,notify:message=>notices.push(message),field:(label,name,value,type,extra)=>`<label>${escape(label)}<input name="${name}" value="${escape(value)}" ${extra||''}></label>`,select:()=>'',navigate:(name,params)=>navigation.push({name,params}),api:async(url,options)=>{calls.push({url,options});if(url.endsWith('/trace'))return trace(url,options);return {items:[],profiles:[]};},dialog:spec=>{const dialog={...spec,open:true,close(){this.open=false;if(typeof this.content==='object')this.content.isConnected=false;},remove(){this.close();}};if(typeof spec.content==='object')spec.content.isConnected=true;dialogs.push(dialog);return dialog;}};
 const window={Vatex:V},document={createElement:node};
 vm.runInNewContext(source,{window,document,AbortController,DOMException,TextEncoder,console},{timeout:1000});
 const cleanup=await routes['analysis-research'].render(root,{tab:'research'});
 const click=async(action,id='')=>{const target={dataset:{arAction:action,id},isConnected:true};await root.onclick({target:{closest:()=>target}});};
 const lookup=async()=>{await click('research-trace-lookup');return dialogs.at(-1);};
 return {root,dialogs,calls,navigation,notices,cleanup,click,lookup,logic:window.VatexAnalysisResearch,setSession:value=>session=value,traceCalls:()=>calls.filter(call=>call.url.endsWith('/trace'))};
}

test('viewer traces an older run absent from the recent list and follows real signal/Case routes',async()=>{
 const ctx=await mounted();assert.match(ctx.root.innerHTML,/실행 ID로 추적/);assert.match(ctx.root.innerHTML,/research-trace-lookup/);
 assert.equal(ctx.traceCalls().length,0);
 const input=await ctx.lookup();input.content.elements.run_id.value='  '+runId.toUpperCase()+'  ';await input.onSave();
 assert.equal(ctx.traceCalls().length,1);assert.equal(ctx.traceCalls()[0].url,'/api/research/runs/'+runId+'/trace');
 assert.ok(ctx.calls.every(call=>!call.options.method));
 const trace=ctx.dialogs.at(-1);assert.match(trace.content.innerHTML,/48/);assert.match(trace.content.innerHTML,/Older &lt;Case&gt;/);assert.ok(!trace.content.innerHTML.includes('Older <Case>'));
 const follow=(action,id)=>trace.content.onclick({target:{closest:()=>({dataset:{arAction:action,id}})}});
 follow('trace-case','CASE-older');follow('trace-signal','SIG-derived');
 assert.equal(JSON.stringify(ctx.navigation),JSON.stringify([{name:'cases',params:{id:'CASE-older'}},{name:'intelligence',params:{tab:'signals',signal:'SIG-derived'}}]));
 ctx.cleanup();follow('trace-case','CASE-older');assert.equal(ctx.navigation.length,2);
 assert.ok(ctx.calls.every(call=>call.options.signal.aborted));
});

test('run ID form rejects paths, missing IDs and malformed IDs before any request',async()=>{
 const ctx=await mounted(),input=await ctx.lookup();
 for(const bad of ['',runId+'/trace','RBR-'+('g'.repeat(32)),'../private','RBR-'+('a'.repeat(33))]){
  input.content.elements.run_id.value=bad;await assert.rejects(input.onSave(),/연구 실행 ID/);
 }
 assert.equal(ctx.traceCalls().length,0);ctx.cleanup();
});

for(const changed of [
 {name:'other',tenant:'b',role:'viewer',allowed_indexes:['public']},
 {name:'viewer',tenant:'a',role:'viewer',allowed_indexes:['private']},
 {name:'viewer',tenant:'a',role:'analyst',allowed_indexes:['public']},
])test('old trace form refuses a changed account, scope or role: '+JSON.stringify(changed),async()=>{
 const ctx=await mounted(),input=await ctx.lookup();input.content.elements.run_id.value=runId;ctx.setSession(changed);
 await assert.rejects(input.onSave(),error=>error.name==='AbortError');assert.equal(ctx.traceCalls().length,0);ctx.cleanup();
});

test('account change suppresses a delayed private trace response',async()=>{
 let release;const gate=new Promise(resolve=>release=resolve),ctx=await mounted(async()=>{await gate;return result;}),input=await ctx.lookup();
 input.content.elements.run_id.value=runId;const request=input.onSave();assert.equal(ctx.traceCalls().length,1);
 ctx.setSession({name:'other',tenant:'b',role:'viewer',allowed_indexes:['public']});release();
 await assert.rejects(request,error=>error.name==='AbortError');assert.equal(ctx.dialogs.length,1);assert.equal(ctx.navigation.length,0);ctx.cleanup();
});

test('closing a lookup form or cleaning up prevents its delayed result from opening',async()=>{
 let release;const gate=new Promise(resolve=>release=resolve),ctx=await mounted(async()=>{await gate;return result;}),input=await ctx.lookup();
 input.content.elements.run_id.value=runId;const pending=input.onSave();input.close();release();
 await assert.rejects(pending,error=>error.name==='AbortError');assert.equal(ctx.dialogs.length,1);
 ctx.cleanup();const count=ctx.traceCalls().length;await assert.rejects(input.onSave(),error=>error.name==='AbortError');assert.equal(ctx.traceCalls().length,count);
});

test('server denial does not reveal a trace or navigate and lookup stays read-only',async()=>{
 const ctx=await mounted(async()=>{throw Error('Research run unavailable');}),input=await ctx.lookup();
 input.content.elements.run_id.value=runId;await assert.rejects(input.onSave(),/unavailable/);
 assert.equal(ctx.dialogs.length,1);assert.equal(ctx.navigation.length,0);assert.ok(ctx.calls.every(call=>!call.options.method));ctx.cleanup();
});

test('recent-list trace action uses the same guarded result and navigation view',async()=>{
 const ctx=await mounted();await ctx.click('research-trace',runId);
 assert.equal(ctx.traceCalls()[0].url,'/api/research/runs/'+runId+'/trace');assert.match(ctx.dialogs.at(-1).content.innerHTML,/Case 열기/);ctx.cleanup();
});
