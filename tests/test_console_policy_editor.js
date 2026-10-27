'use strict';
const assert=require('node:assert/strict');
const {test}=require('node:test');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const root=path.join(__dirname,'..','sapientia','web');
const source=fs.readFileSync(path.join(root,'console_policy_editor.js'),'utf8');
const escape=value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const plain=value=>JSON.parse(JSON.stringify(value));
function logic(){
 const window={Vatex:{h:escape}};
 vm.runInNewContext(source,{window,AbortController,DOMException},{timeout:1000});
 return window.VatexPolicyEditor;
}
const atomic=changes=>({name:' Source observation ',kind:'atomic',indexes:'endpoint, network',severity:'low',window:'300',...changes});
const composite=changes=>atomic({kind:'composite',join_on:'flow',minimum_independent_groups:'2',clock_policy:'reported',...changes});
const inputs=[{rule_id:'ml:sequence:reviewed-model',kind:'ml'},{rule_id:'INT-source-context',kind:'atomic'}];

test('condition keeps strings, finite numbers and exact booleans distinct',()=>{
 const ui=logic();
 assert.deepEqual(plain(ui.condition('raw.security.port','eq','string','443')),{field:'raw.security.port',op:'eq',value:'443'});
 assert.equal(ui.condition('raw.security.port','gte','number','443').value,443);
 assert.equal(ui.condition('projection.process.guid','exists','boolean','false').value,false);
 assert.throws(()=>ui.condition('raw.port','gt','number','Infinity'),/숫자/);
 assert.throws(()=>ui.condition('raw.port','gt','number',''),/숫자/);
 assert.throws(()=>ui.condition('raw.available','exists','string','false'),/존재/);
 assert.throws(()=>ui.condition('raw.available','exists','boolean','False'),/true/);
});
test('ordered typed lists and existing mixed lists survive editing without string coercion',()=>{
 const ui=logic(),existing={field:'raw.port',op:'in',value:[443,'8443',false]};
 assert.deepEqual(plain(ui.condition('raw.port','in','number','443\n8443')).value,[443,8443]);
 assert.deepEqual(plain(ui.condition('raw.port','in','preserve','443\n8443\nfalse',existing)).value,[443,'8443',false]);
 assert.throws(()=>ui.condition('raw.port','in','string',''),/1–32/);
 assert.throws(()=>ui.condition('raw.port','in','string',Array(33).fill('x').join('\n')),/1–32/);
});
test('changing a preserved operator cannot produce a scalar list or an array scalar',()=>{
 const ui=logic();
 for(const [prior,op,raw] of [[{field:'raw.port',op:'eq',value:443},'in','443'],[{field:'raw.port',op:'in',value:[443,8443]},'eq','443\n8443']]){
  let result;
  try{result=ui.condition('raw.port',op,'preserve',raw,prior);}catch(error){assert.ok(error.message);continue;}
  if(op==='in')assert.ok(Array.isArray(result.value),'in must have a typed value list');
  else assert.ok(!Array.isArray(result.value),'scalar comparisons must not retain an old list');
 }
});
test('manifest truth and arbitrary object paths cannot become detector predicates',()=>{
 const ui=logic();
 for(const field of ['raw.label','event.ground_truth','projection.expected_detected','raw.context.scenario_label','label','weights.layer','raw.port;DROP_TABLE'])assert.throws(()=>ui.condition(field,'eq','string','attack'));
 assert.throws(()=>ui.condition('raw.command','regex','string','.*'));
});
test('a new policy defaults to disabled and no Case and retains exact version and scope',()=>{
 const ui=logic(),filters=[ui.condition('event.host','eq','string','reported-host')],payload=ui.policyPayload(atomic(),filters,[]);
 assert.equal(payload.name,'Source observation');assert.deepEqual(Array.from(payload.indexes),['endpoint','network']);
 assert.equal(payload.version,0);assert.equal(payload.enabled,false);assert.equal(payload.case_adapter,null);
 assert.equal(ui.policyPayload(atomic({enabled:true}),filters,[],7).version,7);
 assert.equal(ui.policyPayload(atomic({enabled:'true'}),filters,[]).enabled,false);
 for(const value of ['*','','endpoint,endpoint'])assert.throws(()=>ui.policyPayload(atomic({indexes:value}),filters,[]));
 for(const value of [NaN,Infinity,-1])assert.throws(()=>ui.policyPayload(atomic(),filters,[],value));
});
test('policy bounds reject impossible atomic conditions, windows and severity',()=>{
 const ui=logic(),filters=[ui.condition('event.host','eq','string','host')];
 for(const value of ['', 'x'.repeat(121)])assert.throws(()=>ui.policyPayload(atomic({name:value}),filters,[]));
 for(const value of [0,86401,NaN,1.5])assert.throws(()=>ui.policyPayload(atomic({window:value}),filters,[]));
 assert.throws(()=>ui.policyPayload(atomic({severity:'certain-malware'}),filters,[]));
 assert.throws(()=>ui.policyPayload(atomic(),[],[]));
 assert.throws(()=>ui.policyPayload(atomic(),Array(17).fill(filters[0]),[]));
});
test('composite payload preserves exact input order and finite nonoverlap group limits',()=>{
 const ui=logic(),ordered=ui.policyPayload(composite({ordered:true,clock_policy:'strict'}),[],inputs,3);
 assert.deepEqual(plain(ordered.inputs),inputs);assert.equal(ordered.ordered,true);assert.equal(ordered.clock_policy,'strict');
 assert.equal(ordered.minimum_independent_groups,2);assert.equal(ordered.version,3);assert.equal(ordered.case_adapter,null);
 for(const group of [0,3,NaN,1.5])assert.throws(()=>ui.policyPayload(composite({minimum_independent_groups:group}),[],inputs));
 assert.throws(()=>ui.policyPayload(composite(),[],[inputs[0]]));
 assert.throws(()=>ui.policyPayload(composite(),[],[inputs[0],inputs[0]]));
 assert.throws(()=>ui.policyPayload(composite(),[],Array.from({length:9},(_,i)=>({rule_id:'p'+i,kind:'atomic'}))));
 assert.throws(()=>ui.policyPayload(composite({join_on:'assumed-host'}),[],inputs));
 assert.throws(()=>ui.policyPayload(composite({clock_policy:'unknown-clock'}),[],inputs));
});
test('Case creation is explicit and does not carry device response authority',()=>{
 const ui=logic(),payload=ui.policyPayload(composite({create_case:true,enabled:true,entity_field:'host',risk_score:'75',cooldown:'300',mitre:'T1071, T1059',case_grouping:'require_exact_identity'}),[],inputs);
 assert.equal(payload.case_adapter.risk_score,75);assert.equal(payload.case_adapter.entity_field,'host');
 assert.deepEqual(Array.from(payload.case_adapter.mitre),['T1071','T1059']);assert.equal(payload.case_adapter.case_grouping,'require_exact_identity');
 assert.ok(!Object.hasOwn(payload,'automatic_response_authorized'));assert.ok(!Object.hasOwn(payload,'host_block'));
 assert.throws(()=>ui.policyPayload(composite({create_case:true,risk_score:101,cooldown:300}),[],inputs));
});
test('candidate list excludes this policy and inactive or retired models and uses exact family IDs',()=>{
 const ui=logic(),policies=[{id:'self',kind:'composite',state:'active',indexes:['endpoint'],definition:{name:'Own definition'}},{id:'parent',kind:'atomic',state:'active',indexes:['network'],definition:{name:'Actual parent'}},{id:'draft',kind:'atomic',state:'draft',indexes:['network'],definition:{name:'Needs review'}}],models=[{rule_id:'ml:ae',name:'Distribution',indexes:['endpoint'],active:true},{rule_id:'ml:sequence:seq',name:'Sequence',indexes:['endpoint'],active:true},{rule_id:'ml:off',name:'Off',active:false},{rule_id:'ml:old',name:'Retired',active:true,retired:true}];
 const options=plain(ui.candidates(policies,models,'self'));
 assert.ok(!options.some(item=>item.selector.rule_id==='self'));
 assert.deepEqual(options.filter(item=>item.kind==='ml').map(item=>item.selector.rule_id),['ml:ae','ml:sequence:seq']);
 assert.equal(options.find(item=>item.selector.rule_id==='draft').active,false);
 assert.deepEqual(options.find(item=>item.selector.rule_id==='parent').indexes,['network']);
});
test('warning text cannot create HTML tags or event handlers',()=>{
 const rendered=logic().warningsView(['<img src=x onerror=alert(1)>','\"</li><script>attack</script>']);
 assert.ok(!rendered.includes('<img'));assert.ok(!rendered.includes('<script>'));assert.match(rendered,/&lt;img/);assert.match(rendered,/&quot;/);
});
test('policy helper is loaded before the intelligence view once and the view uses both write routes',()=>{
 const html=fs.readFileSync(path.join(root,'index.html'),'utf8'),view=fs.readFileSync(path.join(root,'console_intelligence.js'),'utf8');
 assert.equal((html.match(/console_policy_editor\.js/g)||[]).length,1);
 assert.ok(html.indexOf('console_policy_editor.js')<html.indexOf('console_intelligence.js'));
 assert.match(view,/VatexPolicyEditor/);assert.match(view,/policy-new/);assert.match(view,/policy-edit/);
 assert.match(view,/'PUT'/);assert.match(view,/intelligence\/policies/);
 assert.match(source,/intelligence\/templates\//);assert.match(source,/alive\(\)/);
});
