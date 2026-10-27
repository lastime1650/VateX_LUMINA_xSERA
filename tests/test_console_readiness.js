/* Exercise actual UI callbacks across tenant/role changes and collector setup. */
'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');

function harness(file, data={}){
  let session={name:'operator',tenant:'lab',role:'admin',allowed_indexes:['*']};
  const views={},dialogs=[],requests=[],notices=[],selections=[];
  const h=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const V={h,session:()=>session,register:(name,value)=>{views[name]=value;},api:async url=>{
    requests.push(['GET',url]);return data[url]??{items:[],queue:{events:0,oldest_age_seconds:0}};
  },post:async(url,body)=>{requests.push(['POST',url,body]);return {};},
  table:()=>'',empty:()=>'',field:()=>'',select:(...args)=>{selections.push(args);return '';},date:()=>'',notify:value=>notices.push(value),navigate:async()=>{},dialog:value=>dialogs.push(value)};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,'../sapientia/web',file),'utf8'),{window:{Vatex:V},Date,JSON,Number,String,Array,Error,encodeURIComponent,FormData:class{constructor(form){return (form.entries||[])[Symbol.iterator]();}}});
  const element={innerHTML:'',onclick:null};
  async function click(action,id=''){const b={dataset:{ready:action,rq:action,id},disabled:false,isConnected:true};await element.onclick({target:{closest:()=>b}});}
  return {views,dialogs,requests,notices,selections,element,click,setSession:next=>{session={...session,...next};}};
}

test('readiness opening is read-only and a stale plan dialog cannot mutate another tenant',async()=>{
  const x=harness('console_readiness.js');
  await x.views.readiness.render(x.element);
  assert(x.requests.every(r=>r[0]==='GET'));
  await x.click('plan');assert.equal(x.dialogs.length,1);
  x.setSession({tenant:'another'});
  await assert.rejects(x.dialogs[0].onSave({querySelector:()=>({})}),/계정 또는 권한/);
  assert.equal(x.requests.filter(r=>r[0]==='POST').length,0);
});

test('readiness collector displays missing credentials and never starts a vendor request',async()=>{
  const x=harness('console_readiness.js',{'/api/ops/enterprise/sources/source/collector':{available:false,reason:'credential_missing'}});
  await x.views.readiness.render(x.element);await x.click('collect','source');
  assert.equal(x.dialogs.length,1);assert.match(x.dialogs[0].content,/credential_missing/);
  assert.equal(x.requests.filter(r=>r[0]==='POST').length,0);
});

test('quality rendering never trains or promotes and revocation blocks an existing candidate form',async()=>{
  const x=harness('console_research_quality.js');
  await x.views['research-quality'].render(x.element);
  assert(x.requests.every(r=>r[0]==='GET'));
  await x.click('candidate');assert.equal(x.dialogs.length,1);
  x.setSession({role:'viewer'});
  await assert.rejects(x.dialogs[0].onSave({querySelector:()=>({})}),/계정 또는 권한/);
  assert.equal(x.requests.filter(r=>r[0]==='POST').length,0);
});

test('quality cleanup prevents a pending result from opening private details',async()=>{
  const x=harness('console_research_quality.js');
  const cleanup=await x.views['research-quality'].render(x.element);cleanup();
  assert.equal(x.element.onclick,null);
});

test('archived evaluation remains visible but cannot enter new training; archive uses independent explicit action',async()=>{
  const x=harness('console_research_quality.js',{'/api/research/evaluation/datasets':{items:[
    {id:'active',owner:'other',name:'Normal set',archived:false},
    {id:'archived',owner:'other',name:'Historical set',archived:true}
  ]}});
  await x.views['research-quality'].render(x.element);
  assert.match(x.element.innerHTML,/Historical set/);
  await x.click('train');
  assert.deepEqual(JSON.parse(JSON.stringify(x.selections[0][2])),[['active','Normal set']]);
  await x.click('archive-dataset','active');
  const archive=x.dialogs.at(-1);
  assert.match(archive.content,/생성자와 다른 분석가/);
  await archive.onSave({querySelector:()=>({entries:[['reason','Independent retention review']]})});
  assert.deepEqual(x.requests.filter(r=>r[0]==='POST').map(r=>[r[1],r[2].reason]),[
    ['/api/research/evaluation/datasets/active/archive','Independent retention review']
  ]);
});
