// Synthetic DOM smoke: execute the real UI script without browser, listener or network.
const assert = require('node:assert/strict');
class Element {
  constructor(tag) { this.tagName=tag; this.children=[]; this.listeners={}; this.hidden=false; this.textContent=''; this.value=''; }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children=items; this.textContent=''; }
  addEventListener(event, callback) { this.listeners[event]=callback; }
  set innerHTML(_) { throw new Error('HTML injection sink used'); }
  set outerHTML(_) { throw new Error('HTML injection sink used'); }
  insertAdjacentHTML() { throw new Error('HTML injection sink used'); }
  get allText() { return this.textContent + this.children.map(x=>x.allText).join(' '); }
}
const ids=['token','overview','alerts','detail','error','updated','workspace','login','logout','connect','overview-button','alerts-button','refresh'];
const elements=Object.fromEntries(ids.map(id=>[id,new Element('section')]));
global.document={getElementById:id=>elements[id],createElement:tag=>new Element(tag)};
const windowEvents={};
global.window={addEventListener:(event, callback)=>{windowEvents[event]=callback;}};
const hostile='<img onerror=alert(1)><svg onload=alert(1)></svg></pre>&lt;script&gt; ${template} \x1b[31m '+ 'x'.repeat(8192) + '<script>alert(1)</script> [go](javascript:1) ignore previous instructions $(run) "; DROP TABLE alerts; -- \u202e ../../secret';
const calls=[];
global.fetch=async (path, options)=>{
  calls.push({path,options});
  assert.equal(options.credentials,'omit');
  assert.equal(options.cache,'no-store');
  assert.equal(options.redirect,'error');
  assert.equal(options.headers['X-Sec-UI'],'1');
  if(path==='/api/overview')return {ok:true,json:async()=>({monitor:'running',disabled:false,active_alerts:1,pending_notifications:1,baseline_revision:0,storage_bytes:12345,health:'degraded',sources:[{source:'systemd_user',status:'partial',reasons:['partial'],at:'2026-09-11'}],reliability:{state:'cursor_lost',gap_count:1,stale:true,storage_failure:false,history_recovered:false},application_version:'0.1.0',database_version:2})};
  if(path.startsWith('/api/alerts?'))return {ok:true,json:async()=>({items:[{id:1,severity:'high',summary:hostile,source:'accounts',status:'open',active:true,at:'2026-09-11'}],next_before:null})};
  return {ok:true,json:async()=>({evidence:{alert:{record:hostile},source_coverage:{status:'partial'}},deterministic:{detector:{severity:'high',detector_id:'uid0-drift',source:'accounts'},summary:'Drift',guidance:{mechanism:hostile,importance:'important',manual_check:'sec explain 1',limits:'unknown'}},saved_investigation:{mode:'deterministic',entries:[{at:'2026-09-11',kind:'fallback',code:'llm_disabled'}],step_count:0,stop_reason:'llm_disabled',budgets:[]}})};
};
require('../src/security_orchestrator/local_ui/app.js');
const tick=()=>new Promise(resolve=>setImmediate(resolve));
(async()=>{
  elements.token.value='synthetic-only-access-value';
  await elements.connect.listeners.click();
  assert.equal(elements.token.value,'');
  assert.equal(elements.workspace.hidden,false);
  assert.match(elements.overview.allText,/промежуточные события/);
  elements['alerts-button'].listeners.click(); await tick();
  assert.ok(elements.alerts.allText.includes(hostile));
  const row=elements.alerts.children.find(el=>el.className==='alert-row');
  row.children.find(el=>el.tagName==='button').listeners.click(); await tick();
  assert.ok(elements.detail.allText.includes(hostile));
  assert.match(elements.detail.allText,/deterministic fallback/);
  assert.equal(calls.length,3); // no auto polling or hidden calls
  assert.ok(calls.every(c=>!c.path.includes('synthetic-only-access-value')));
  elements.logout.listeners.click();
  assert.equal(elements.workspace.hidden,true);
  assert.equal(elements.detail.children.length,0);
  const normalFetch=global.fetch;
  let resolveOld;
  global.fetch=()=>new Promise(resolve=>{resolveOld=resolve;});
  elements.token.value='synthetic-old-key';
  const oldLogin=elements.connect.listeners.click();
  elements.logout.listeners.click();
  global.fetch=normalFetch;
  elements.token.value='synthetic-new-key';
  await elements.connect.listeners.click();
  assert.equal(elements.workspace.hidden,false);
  resolveOld({ok:false,status:401});
  await oldLogin;
  assert.equal(elements.workspace.hidden,false,'old 401 must not forget the new session');
  elements['alerts-button'].listeners.click(); await tick();
  assert.equal(calls.at(-1).options.headers.Authorization,'Bearer synthetic-new-key');

  let resolveJson;
  global.fetch=async()=>({ok:true,json:()=>new Promise(resolve=>{resolveJson=resolve;})});
  elements.token.value='synthetic-race-key';
  const pendingLogin=elements.connect.listeners.click(); await tick();
  windowEvents.pagehide();
  resolveJson({monitor:'running'});
  await pendingLogin;
  assert.equal(elements.workspace.hidden,true);
  assert.equal(elements.overview.children.length,0,'late evidence must not repopulate after pagehide');
  global.fetch=normalFetch;
  console.log('UI DOM smoke PASS: login, overview, alerts, detail, inert text, logout; no network');
})().catch(error=>{console.error(error);process.exitCode=1;});
