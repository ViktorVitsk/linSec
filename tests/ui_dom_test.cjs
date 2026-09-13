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
const ids=['token','overview','alerts','detail','error','updated','workspace','login','logout','connect','key-form','overview-button','alerts-button','refresh'];
const elements=Object.fromEntries(ids.map(id=>[id,new Element('section')]));
global.document={getElementById:id=>elements[id],createElement:tag=>new Element(tag)};
const windowEvents={};
const entries=[], historyWrites=[];
let position=-1;
const history={
  replaceState(state, title, url) {
    if(position<0) position=0;
    entries[position]={state:structuredClone(state),url};
    historyWrites.push(entries[position]);
  },
  pushState(state, title, url) {
    entries.splice(++position);
    entries.push({state:structuredClone(state),url});
    historyWrites.push(entries[position]);
  },
  async go(delta) {
    const next=position+delta;
    assert.ok(next>=0 && next<entries.length, 'navigation must remain in document');
    position=next;
    await windowEvents.popstate({state:structuredClone(entries[position].state)});
  }
};
global.window={history,addEventListener:(event, callback)=>{windowEvents[event]=callback;}};
// Verify native implicit Enter submission prerequisites in the shipped HTML.
const html=require('node:fs').readFileSync(require('node:path').join(__dirname,
  '../src/security_orchestrator/local_ui/index.html'),'utf8');
const form=html.match(/<form id="key-form"[^>]*>([\s\S]*?)<\/form>/)[1];
assert.match(form, /<input id="token" type="password"[^>]*>/);
assert.match(form, /<button id="connect" type="submit">/);
assert.doesNotMatch(form, /\b(?:action|name|formaction)=/);
async function submitKey() {
  let prevented=false;
  const pending=elements['key-form'].listeners.submit({preventDefault(){prevented=true;}});
  assert.equal(prevented,true,'native submission must be cancelled before any await');
  return pending;
}
const hostile='<img onerror=alert(1)><svg onload=alert(1)></svg></pre>&lt;script&gt; ${template} \x1b[31m '+ 'x'.repeat(8192) + '<script>alert(1)</script> [go](javascript:1) ignore previous instructions $(run) "; DROP TABLE alerts; -- \u202e ../../secret';
const calls=[];
global.fetch=async (path, options)=>{
  calls.push({path,options});
  assert.match(path,/^\/api\/(?:overview|alerts(?:\?limit=25(?:&before=[1-9][0-9]*)?|\/[1-9][0-9]*))$/);
  assert.equal(options.credentials,'omit');
  assert.equal(options.cache,'no-store');
  assert.equal(options.redirect,'error');
  assert.equal(options.headers['X-Sec-UI'],'1');
  if(path==='/api/overview')return {ok:true,json:async()=>({monitor:'running',disabled:false,active_alerts:1,pending_notifications:1,baseline_revision:0,storage_bytes:12345,health:'degraded',sources:[{source:'systemd_user',status:'partial',reasons:['partial'],at:'2026-09-11'}],reliability:{state:'cursor_lost',gap_count:1,stale:true,storage_failure:false,history_recovered:false},application_version:'0.1.0',database_version:2})};
  if(path.startsWith('/api/alerts?'))return {ok:true,json:async()=>({items:[{id:1,severity:'high',summary:hostile,source:'accounts',status:'open',active:true,at:'2026-09-11'}],next_before:path.includes('&before=')?null:1})};
  return {ok:true,json:async()=>({evidence:{alert:{record:hostile},source_coverage:{status:'partial'}},deterministic:{detector:{severity:'high',detector_id:'uid0-drift',source:'accounts'},summary:'Drift',guidance:{mechanism:hostile,importance:'important',manual_check:'sec explain 1',limits:'unknown'}},saved_investigation:{mode:'deterministic',entries:[{at:'2026-09-11',kind:'fallback',code:'llm_disabled'}],step_count:0,stop_reason:'llm_disabled',budgets:[]}})};
};
require('../src/security_orchestrator/local_ui/app.js');
const tick=()=>new Promise(resolve=>setImmediate(resolve));
(async()=>{
  elements.token.value='synthetic-only-access-value';
  await submitKey();
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
  assert.equal(entries.length,3);
  const detailPosition=position;
  await history.go(-1);
  assert.equal(elements.alerts.hidden,false);
  await history.go(-1);
  assert.equal(elements.overview.hidden,false);
  await history.go(1);
  await history.go(1);
  assert.equal(position,detailPosition);
  assert.equal(elements.detail.hidden,false);
  await elements.refresh.listeners.click();
  assert.equal(calls.at(-1).path,'/api/alerts/1');
  assert.equal(entries.length,3,'refresh does not push history');
  await history.go(-1);
  await elements.alerts.children.find(el=>el.textContent==='Следующая страница').listeners.click();
  assert.equal(calls.at(-1).path,'/api/alerts?limit=25&before=1');
  await elements.refresh.listeners.click();
  assert.equal(calls.at(-1).path,'/api/alerts?limit=25&before=1');
  await history.go(-1);
  assert.equal(calls.at(-1).path,'/api/alerts?limit=25');
  await history.go(1);
  assert.equal(calls.at(-1).path,'/api/alerts?limit=25&before=1');
  const length=entries.length;
  await elements['overview-button'].listeners.click();
  await elements['overview-button'].listeners.click();
  assert.equal(entries.length,length+1,'same screen does not push duplicate history');
  elements.logout.listeners.click();
  const loggedOutCalls=calls.length;
  await history.go(-1);
  await history.go(1);
  assert.equal(calls.length,loggedOutCalls,'history cannot restore a logged-out key');
  assert.equal(elements.workspace.hidden,true);
  assert.equal(elements.detail.children.length,0);
  const normalFetch=global.fetch;
  let resolveOld;
  global.fetch=()=>new Promise(resolve=>{resolveOld=resolve;});
  elements.token.value='synthetic-old-key';
  const oldLogin=submitKey();
  elements.logout.listeners.click();
  global.fetch=normalFetch;
  elements.token.value='synthetic-new-key';
  await submitKey();
  assert.equal(elements.workspace.hidden,false);
  resolveOld({ok:false,status:401});
  await oldLogin;
  assert.equal(elements.workspace.hidden,false,'old 401 must not forget the new session');
  assert.equal(elements.error.hidden,true,'old session errors must not reach the new session');
  elements['alerts-button'].listeners.click(); await tick();
  assert.equal(calls.at(-1).options.headers.Authorization,'Bearer synthetic-new-key');

  let resolveJson;
  global.fetch=async()=>({ok:true,json:()=>new Promise(resolve=>{resolveJson=resolve;})});
  elements.token.value='synthetic-race-key';
  const pendingLogin=submitKey(); await tick();
  windowEvents.pagehide();
  resolveJson({monitor:'running'});
  await pendingLogin;
  assert.equal(elements.workspace.hidden,true);
  assert.equal(elements.overview.children.length,0,'late evidence must not repopulate after pagehide');
  global.fetch=normalFetch;
  // A slow detail response must not overwrite the detail selected after Back.
  elements.token.value='synthetic-navigation-key';
  await submitKey();
  await elements['alerts-button'].listeners.click();
  const openDetail=()=>elements.alerts.children.find(el=>el.className==='alert-row')
    .children.find(el=>el.tagName==='button').listeners.click();
  let finishDetail;
  global.fetch=async()=>({ok:true,json:()=>new Promise(resolve=>{finishDetail=resolve;})});
  const oldDetail=openDetail(); await tick();
  global.fetch=normalFetch;
  await history.go(-1);
  await openDetail();
  const staleData=await (await normalFetch('/api/alerts/1',calls.at(-1).options)).json();
  staleData.deterministic.summary='stale-navigation-evidence';
  finishDetail(staleData);
  await oldDetail;
  assert.match(elements.detail.allText,/Предупреждение #1/);
  assert.ok(!elements.detail.allText.includes('stale-navigation-evidence'));
  assert.equal(elements.error.hidden,true,'stale navigation errors stay hidden');
  // A successful late JSON response must not repopulate any panel after logout.
  global.fetch=async()=>({ok:true,json:()=>new Promise(resolve=>{finishDetail=resolve;})});
  const lateRefresh=elements.refresh.listeners.click(); await tick();
  elements.logout.listeners.click();
  finishDetail(staleData);
  await lateRefresh;
  assert.equal(elements.workspace.hidden,true);
  assert.equal(elements.detail.children.length,0);
  global.fetch=normalFetch;
  elements.token.value='synthetic-final-key';
  await submitKey();
  // Unrecognized history state is never interpreted as a URL, ID or credential.
  await windowEvents.popstate({state:{page:'detail',id:hostile,token:'synthetic-injected-key'}});
  assert.equal(calls.at(-1).path,'/api/overview');
  global.fetch=async()=>({ok:false,status:401});
  await elements.refresh.listeners.click();
  assert.equal(elements.workspace.hidden,true);
  assert.match(elements.error.allText,/Ключ не принят/);
  global.fetch=normalFetch;
  for(const entry of historyWrites) {
    assert.equal(entry.url,'/','URL must contain no route, key, cursor or evidence');
    assert.ok(Number.isSafeInteger(entry.state),'only an opaque integer enters browser history');
  }
  assert.doesNotMatch(JSON.stringify(entries),/synthetic-|record|deterministic|accounts/);
  console.log('UI DOM PASS: native submit contract, history/back/forward/pagination, secret-free history, stale navigation/session/pagehide, logout/401, inert text; no network');
})().catch(error=>{console.error(error);process.exitCode=1;});
