// Source-level UI regression tests. Uses a tiny DOM mock, not a browser driver.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync('main.go', 'utf8');
const index = source.split('const indexHTML = `')[1].split('\nconst chartHTML')[0];
const script = index.split('<script>')[1].split('</script>')[0];
const chart = source.split('const chartHTML = `')[1].split('<script>')[1].split('</script>')[0];
new vm.Script(chart); // Chart JS syntax; actual rendering is checked in the browser.
function deferred(){let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b});return {promise,resolve,reject}}
const response = (data,ok=true) => ({ok,status:ok?200:500,json:async()=>data,headers:{get:()=>null}});
function harness(serverRows=[]){
  const elements=new Map();let closed=false;
  class Element{
    constructor(tag){this.tag=tag;this.children=[];this.style={};this.value='';this.disabled=false;this.text=''}
    set textContent(value){this.text=String(value);this.children=[]}
    get textContent(){return this.text+this.children.map(x=>x.textContent).join('')}
    appendChild(e){e.parent=this;this.children.push(e);return e}
    prepend(e){e.parent=this;this.children.unshift(e)}
    replaceChildren(){this.children=[];if(this.tag==='body')closed=true}
    showModal(){this.open=true}
    close(){this.open=false}
    get lastElementChild(){return this.children.at(-1)}
    remove(){this.parent.children.splice(this.parent.children.indexOf(this),1)}
  }
  for(const id of ['sel','selwrap','h','p','t','P','go','quit','hist','num','fill','save-note','history-note','config-note','select-all','delete-selected','refresh-history','undo-delete','prev-page','page-info','next-page','delete-note','delete-dialog','delete-summary','delete-items','confirm-delete'])elements.set(id,new Element(id));
  elements.get('p').value='5201';elements.get('t').value='10';elements.get('P').value='1';
  const calls=[],pending=[];
  const body=new Element('body');
  const context=vm.createContext({
    document:{getElementById:id=>closed?null:elements.get(id),createElement:tag=>new Element(tag),body},
    fetch:async(path,options)=>{
      if(path==='/session')return response({token:'token'});
      if(path==='/nodes')return response([{name:'<b>untrusted</b>',host:'example.com',port:5201}]);
      if(path==='/data')return response(serverRows.slice());
      calls.push({path,options});const d=deferred();pending.push(d);return d.promise;
    },
    URLSearchParams,requestAnimationFrame:fn=>{queueMicrotask(fn);return 1},cancelAnimationFrame:()=>{},confirm:()=>true,
  });
  vm.runInContext(script,context);
  return {context,elements,calls,pending,body,serverRows,ready:vm.runInContext('historyReady',context)};
}
const settle=()=>new Promise(resolve=>setImmediate(resolve));
const good={ok:true,mbps:123.4,saved:true,t:'2026-09-22 12:00:00'};
async function main(){
  const h=harness();await h.ready;await settle();
  const get=id=>h.elements.get(id);
  assert.equal(get('sel').children[0].textContent,'<b>untrusted</b> - example.com');
  assert.equal(get('sel').children[0].children.length,0);
  get('h').value='example.com';get('t').value='301';await h.context.run();
  assert.equal(h.calls.length,0);assert.match(get('num').textContent,/300/);
  get('t').value='1';get('sel').value='0';
  const first=h.context.run();await settle();await h.context.run();
  assert.equal(h.calls.length,1);assert.equal(get('h').disabled,true);
  get('h').value='changed.test';get('p').value='9999';get('P').value='9';
  h.serverRows.push({id:'record:1',t:good.t,target:'<b>untrusted</b>',ip:'example.com:5201',thr:'1',mbps:good.mbps});
  h.pending.shift().resolve(response(good));await first;
  const row=get('hist').children[0];
  assert.equal(row.children[2].textContent,'<b>untrusted</b>');assert.equal(row.children[2].title,'example.com:5201');
  assert.equal(row.children[3].textContent,'1');assert.equal(get('go').disabled,false);
  assert.match(h.calls[0].path,/host=example.com&port=5201&t=1&P=1/);
  assert.equal(h.calls[0].options.method,'POST');assert.equal(h.calls[0].options.headers['X-App-Token'],'token');
  // Completion while quit is pending, followed by quit failure, must unlock the UI.
  const running=h.context.run();await settle();const quitting=h.context.quit();await settle();
  h.pending.shift().resolve(response(good));await running;
  h.pending.shift().resolve(response({err:'temporary quit failure'},false));await quitting;
  assert.equal(get('go').disabled,false);assert.match(get('save-note').textContent,/退出失败/);
  // A result arriving after quit has removed the page must not access missing nodes.
  const late=h.context.run();await settle();const close=h.context.quit();await settle();
  const testReply=h.pending.shift(),quitReply=h.pending.shift();
  quitReply.resolve(response({ok:true}));await close;
  testReply.resolve(response({ok:false,err:'cancelled',saved:true}));await late;
  assert.match(h.body.textContent,/已请求退出/);
  const records=Array.from({length:101},(_,i)=>({id:'snapshot:'+i,t:good.t,target:'<b>row '+i+'</b>',ip:'example.com:5201',thr:'1',mbps:i}));
  const d=harness(records.slice());await d.ready;await settle();
  const el=id=>d.elements.get(id);
  assert.equal(el('hist').children.length,100);
  d.context.changePage(1);assert.equal(el('hist').children.length,1);
  d.context.requestDelete(['snapshot:0']);assert.equal(el('delete-dialog').open,true);
  assert.match(el('delete-items').textContent,/<b>row 0<\/b>/);
  d.context.cancelDelete();await d.context.confirmDelete();assert.equal(d.calls.length,0);
  d.context.changePage(-1);d.context.selectPage(true);
  d.context.requestDelete(vm.runInContext('[...selected]',d.context));
  const deleting=d.context.confirmDelete();await settle();
  assert.equal(el('go').disabled,true);
  const ids=JSON.parse(d.calls[0].options.body).ids;assert.equal(ids.length,100);
  assert(!ids.includes('snapshot:0'));assert.equal(d.calls[0].path,'/history/delete');
  d.serverRows.splice(1);d.pending.shift().resolve(response({ok:true,deleted:100,undo:'backup.csv',backup:'backups/deletions/backup.csv'}));await deleting;
  assert.equal(el('hist').children.length,1);assert.equal(el('undo-delete').disabled,false);
  assert.match(el('delete-note').textContent,/已删除 100/);
  const undoing=d.context.undoDelete();await settle();assert.equal(d.calls[1].path,'/history/undo');
  d.serverRows.splice(0,d.serverRows.length,...records);d.pending.shift().resolve(response({ok:true}));await undoing;
  assert.equal(el('hist').children.length,100);assert.equal(el('undo-delete').disabled,true);
  d.context.requestDelete(['snapshot:100']);const stale=d.context.confirmDelete();await settle();
  d.pending.shift().resolve(response({err:'记录已变化，请刷新'},false));await stale;
  assert.equal(el('hist').children.length,100);assert.match(el('delete-note').textContent,/记录已变化/);
  assert.equal(el('go').disabled,false);
  console.log('PASS: script syntax, text rendering, input bounds, duplicate submission, parameter snapshot, token POST, quit failure recovery, late result after exit');
  console.log('PASS: pagination, explicit delete confirmation, cancel, batch IDs, mutation lock, backup notice, undo, stale-selection error');
}
main().catch(error=>{console.error(error);process.exitCode=1});
