'use strict';
// Production views must not publish a late private response into another session.
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict');
const h=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const tests=[];
function setup(file,api){
  const views={},person={name:'operator',tenant:'qa',role:'admin'};
  const V={h,api,session:()=>person,register:(name,view)=>views[name]=view,date:String,badge:(state,text)=>h(text),empty:(title,detail)=>h(title)+' '+h(detail),notify(){}};
  const sandbox={window:{Vatex:V},AbortController,DOMException,Date,Number,URLSearchParams};
  vm.runInNewContext(fs.readFileSync(path.resolve(__dirname,'../sapientia/web/'+file),'utf8'),sandbox,{filename:file});
  return {views,person,sandbox};
}
async function check(name,fn){await fn();tests.push(name);}
(async()=>{
  await check('analysis_escapes_private_metadata_and_preserves_zero_metrics',async()=>{
    const {views}=setup('console_analysis.js',async()=>({schedules:[{id:'id',name:'<img src=x onerror=alert(1)>',kind:'intel',definition:{indexes:['private'],interval:30,lookback:60},failures:0,enabled:false}],late_recovery:{ranges:0,failures:0}}));
    const root={innerHTML:'',onclick:null};const cleanup=await views.analysis.render(root);
    assert(!root.innerHTML.includes('<img'));assert(root.innerHTML.includes('&lt;img'));assert(root.innerHTML.includes('0 대기 범위'));cleanup();assert.equal(root.onclick,null);
  });
  await check('late_analysis_response_is_not_published_after_tenant_switch',async()=>{
    let complete;const pending=new Promise(resolve=>complete=resolve),{views,person}=setup('console_analysis.js',()=>pending),root={innerHTML:'new-session',onclick:null};
    const render=views.analysis.render(root);person.tenant='another';complete({schedules:[],late_recovery:{ranges:0,failures:0}});const cleanup=await render;assert.equal(root.innerHTML,'new-session');cleanup();
  });
  await check('defense_analyst_cannot_offer_policy_mutation_and_labels_are_escaped',async()=>{
    const {sandbox,person}=setup('console_defense.js',async()=>({policies:[{id:'p',agent_id:'a',revision:1,digest:'a'.repeat(64),status:'pending_approval',owner:'other',document:{host:'<script>bad</script>',rules:[]}}]}));person.role='analyst';
    const root={innerHTML:'',onclick:null};const cleanup=await sandbox.window.VatexDefense.mount(root);assert(!root.innerHTML.includes('data-defense-new'));assert(!root.innerHTML.includes('data-defense-approve'));assert(!root.innerHTML.includes('<script>'));cleanup();
  });
  await check('late_defense_response_is_not_published_after_identity_switch',async()=>{
    let complete;const pending=new Promise(resolve=>complete=resolve),{sandbox,person}=setup('console_defense.js',()=>pending),root={innerHTML:'new-session',onclick:null};
    const mount=sandbox.window.VatexDefense.mount(root);person.name='new-operator';complete({policies:[]});const cleanup=await mount;assert.equal(root.innerHTML,'new-session');cleanup();assert.equal(root.onclick,null);
  });
  console.log(JSON.stringify({passed:tests.length,tests,fixture_only:true}));
})().catch(error=>{console.error(error);process.exitCode=1;});
