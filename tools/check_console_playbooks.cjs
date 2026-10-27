'use strict';
// Production visual-form serializers, exercised with synthetic DOM controls.
// No browser/network/OS response/production data is used.
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(path.resolve(__dirname,'../sapientia/web/console_workflows.js'),'utf8');
const helpers=source.slice(source.indexOf('  const h = V.h;'),source.indexOf('  function scopeFor('));
const actions=source.slice(source.indexOf('  function actionDefaults('),source.indexOf('  async function playbooks('));
assert(actions.includes('function endpointFields') && actions.includes('function readGraph'));
const escape=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const decode=s=>String(s).replace(/&quot;/g,'"').replace(/&#39;/g,"'").replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&');
const attrs=s=>Object.fromEntries([...s.matchAll(/([\w-]+)(?:=(?:"([^"]*)"|'([^']*)'))?/g)].map(m=>[m[1],decode(m[2]??m[3]??'')]));
function controls(html){return [...html.matchAll(/<(input|select|textarea)\b([^>]*)(?:>([\s\S]*?)<\/\1>|>)/g)].map(m=>{const a=attrs(m[2]),options=m[1]==='select'?[...m[3].matchAll(/<option([^>]*)>/g)].map(o=>attrs(o[1])):[];return {...a,name:a.name,value:m[1]==='select'?(options.find(o=>Object.hasOwn(o,'selected'))||options[0]||{}).value||'':m[1]==='textarea'?decode(m[3]):a.value||'',checked:Object.hasOwn(a,'checked')};});}
class Host{
  constructor(html){this.html=html;this.controls=controls(html);this.rows=[...html.matchAll(/<div class="wf-filter-row" data-outcome="\d+">([\s\S]*?)<\/div>/g)].map(m=>new Host(m[1]));}
  querySelector(selector){return this.controls.find(control=>control.name===selector.match(/^\[name="([^"]+)"\]$/)?.[1]);}
  querySelectorAll(selector){if(selector==='[data-outcome]')return this.rows;const name=selector.match(/^\[name="([^"]+)"\]$/)?.[1];assert(name);return this.controls.filter(control=>control.name===name);}
}
const sandbox={V:{h:escape,session:()=>({role:'analyst'})},Date,Number,crypto:{randomUUID:()=> 'synthetic-id'}};
vm.runInNewContext(helpers+'\n'+actions+'\nglobalThis.forms={actionDefaults,endpointTargetDefaults,actionFields,readAction,graphFields,readGraph,renameReferences,scalarCondition,bindingPanel};',sandbox);
const forms=sandbox.forms,plain=value=>JSON.parse(JSON.stringify(value)),tests=[];
function test(name,callback){callback();tests.push({name,passed:true});}
const kinds=['inspect_process','inspect_file','collect_artifact','terminate_process','quarantine_file','restore_file','delete_file','isolate_host','release_host'];
for(const kind of kinds)test(`typed_${kind}_form_roundtrip`,()=>{
  const target=plain(forms.endpointTargetDefaults(kind));
  if(Object.hasOwn(target,'pid'))Object.assign(target,{pid:678,process_guid:'native-guid',start_identity:'windows:12345678'});
  if(Object.hasOwn(target,'path'))Object.assign(target,{path:'C:\\PrivateQA\\evidence.txt',sha256:'a'.repeat(64)});
  if(Object.hasOwn(target,'management_allowlist_digest'))target.management_allowlist_digest='b'.repeat(64);
  if(Object.hasOwn(target,'quarantine_id'))target.quarantine_id='Q-'+'1'.repeat(32);
  if(Object.hasOwn(target,'isolation_id'))target.isolation_id='2'.repeat(32);
  const action={type:'endpoint_response',agent_id:'registered-agent',evidence_event_id:'registered-evidence',reason:'Synthetic typed form',action:target};
  assert.deepEqual(plain(forms.readAction(new Host(forms.actionFields(action,['q'])),action)),action);
});
for(const [kind,key] of [['restore_file','quarantine_id'],['release_host','isolation_id']])test(`${kind}_typed_receipt_reference_roundtrip`,()=>{
  const target=plain(forms.endpointTargetDefaults(kind));Object.assign(target,kind==='restore_file'?{path:'/private/evidence',sha256:'a'.repeat(64)}:{management_allowlist_digest:'b'.repeat(64)});target[key]={from_step:'q',field:`data.${key}`};
  const action={type:'endpoint_response',agent_id:'agent',evidence_event_id:'evidence',reason:'Approved receipt dependency',action:target};
  assert.deepEqual(plain(forms.readAction(new Host(forms.actionFields(action,['q'])),action)),action);
});
test('multi_dependency_and_bool_integer_conditions_are_preserved',()=>{
  const step={id:'resolve',depends_on:['q','inspect'],when:{all:[{step:'q',field:'success',op:'eq',value:true},{step:'inspect',field:'data.bytes',op:'ne',value:0}]},action:{type:'add_note',note:'Condition met'}};
  const result=forms.readGraph(new Host(forms.graphFields(step,[{id:'q'},{id:'inspect'},step],2)));
  assert.deepEqual(plain(result),{depends_on:step.depends_on,when:step.when});
});
test('unchecked_dependency_cannot_silently_leave_outcome_reference',()=>{
  const step={id:'resolve',depends_on:['q'],when:{all:[{step:'q',field:'success',op:'eq',value:true}]},action:{}};
  const host=new Host(forms.graphFields(step,[{id:'q'},step],1));host.controls.find(control=>control.name==='step_dep').checked=false;
  assert.throws(()=>forms.readGraph(host),/의존 단계/);
});
test('step_rename_preserves_dependency_condition_and_restore_receipt_links',()=>{
  const steps=[{id:'q',depends_on:[],action:{type:'add_note'}},{id:'restore',depends_on:['q'],when:{all:[{step:'q',field:'success',op:'eq',value:true}]},action:{type:'endpoint_response',action:{type:'restore_file',quarantine_id:{from_step:'q',field:'data.quarantine_id'}}}}];
  forms.renameReferences(steps,'q','renamed');
  assert.deepEqual(steps[1].depends_on,['renamed']);assert.equal(steps[1].when.all[0].step,'renamed');assert.equal(steps[1].action.action.quarantine_id.from_step,'renamed');
});
test('duplicate_or_invalid_renames_fail_closed',()=>{const steps=[{id:'a'},{id:'b'}];assert.throws(()=>forms.renameReferences(steps,'a','b'));assert.throws(()=>forms.renameReferences(steps,'a','<script>'));});
test('false_string_and_false_boolean_do_not_merge',()=>{assert.equal(forms.scalarCondition('string','false'),'false');assert.equal(forms.scalarCondition('boolean','false'),false);assert.equal(forms.scalarCondition('null',''),null);});
test('fraction_unsafe_integer_and_invalid_boolean_conditions_rejected',()=>{for(const text of ['','1.5','9007199254740992','Infinity'])assert.throws(()=>forms.scalarCondition('number',text));assert.throws(()=>forms.scalarCondition('boolean','yes'));});
test('endpoint_text_is_escaped_no_arbitrary_JSON_editor',()=>{
  const action={type:'endpoint_response',agent_id:'"><script>bad</script>',evidence_event_id:'e',reason:'</textarea><img src=x onerror=bad()>',action:{type:'inspect_file',path:'C:\\PrivateQA\\file',sha256:'a'.repeat(64)}};
  const html=forms.actionFields(action);assert(!html.includes('<script>'));assert(!html.includes('<img '));assert(html.includes('&lt;script&gt;'));assert(!html.includes('name="raw_json"'));
});
test('binding_controls_require_available_policy_and_book_and_escape_labels',()=>{
  const html=forms.bindingPanel([{id:'b',name:'<img src=x>'}],[{id:'p',name:'policy'}],{bindings:[{id:'bind',policy_id:'p',playbook_id:'b',owner:'analyst',revision:3,enabled:0,error:null}]});
  assert(html.includes('data-action="binding-new"'));assert(html.includes('독립 승인'));assert(html.includes('&lt;img'));assert(!html.includes('<img '));assert(forms.bindingPanel([],[],{bindings:[]}).includes('data-action="binding-new" disabled'));
});
const result={passed:true,checks:tests.length,scope:'synthetic DOM controls executing actual production form serializers',browser_visual_qualification:false,operating_data:false,tests};
if(process.argv[2])fs.writeFileSync(path.resolve(process.argv[2]),JSON.stringify(result,null,2));
process.stdout.write(`${tests.length} passed\n`);
