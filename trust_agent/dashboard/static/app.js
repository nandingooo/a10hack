const $=id=>document.getElementById(id);
const params=new URLSearchParams(location.hash.slice(1));
let access=params.get('access')||sessionStorage.getItem('airlock-access')||'';
if(params.has('access')){sessionStorage.setItem('airlock-access',access);history.replaceState(null,'',location.pathname);}
let runs=[],events=[],selected=null,busy=false,stateSession=null;
async function api(path,method='GET'){
  const response=await fetch(path,{method,headers:{Authorization:`Bearer ${access}`}});
  const data=await response.json();
  if(!response.ok){if(response.status===401)$('connect').hidden=false;throw new Error(data.error||'Controller request failed');}
  return data;
}
function node(tag,text,className){const el=document.createElement(tag);if(text!==undefined)el.textContent=text;if(className)el.className=className;return el;}
function badge(text,state){return node('span',text,`badge ${state||''}`);}
function outcome(e){return e.decision||e.execution_status||e.status||e.type;}
function showNotice(message,error=false){$('notice').textContent=message;$('notice').classList.toggle('error',error);}
function inspect(event){
 selected=event.seq;const detail=$('detail');detail.replaceChildren();
 const summary=node('div',undefined,'decision-summary');summary.append(badge(outcome(event).toUpperCase(),event.decision));
 summary.append(node('h3',event.rule||event.type),node('p',event.reason||`${event.execution_status||event.status||'Recorded'} · exposure ${event.exposure_status||'not applicable'}`));
 const tags=node('div',undefined,'tags');if(event.context){tags.append(badge(event.context.untrusted?'Untrusted context':'Trusted context',event.context.untrusted?'unknown':'allow'),badge(event.context.secret?'Secret context':'Public context',event.context.secret?'unknown':'allow'));}summary.append(tags);detail.append(summary);
 const heading=node('div',undefined,'evidence-heading');heading.append(node('h3','Supporting observations'),node('span',`${(event.evidence||[]).length} sources`,'resource'));detail.append(heading);
 const list=node('ol',undefined,'evidence-list');
 for(const source of event.evidence||[]){const item=node('li',undefined,'evidence-item');item.append(node('span',source.target||source.id,'resource'));const inferred=/infer|proposed|inflight|sandbox/.test(source.basis||'')||source.exposure_status==='unknown';item.append(node('p',`${inferred?'Inferred exposure':'Recorded exposure'} · ${(source.classification_reason||source.basis||'context').replaceAll('_',' ')}`));const labels=node('div',undefined,'tags');if(source.trust)labels.append(badge(source.trust,source.trust==='untrusted'?'unknown':'allow'));if(source.sensitivity)labels.append(badge(source.sensitivity,source.sensitivity==='secret'?'unknown':''));item.append(labels);list.append(item);}
 detail.append(list);if(!list.children.length)detail.append(node('p','This event has no supporting context observations.','resource'));
 if(event.policy_version)detail.append(node('p',`${event.policy_version} · ${event.latency_ms} ms · ${event.evidence_basis||'policy decision'}`,'resource'));
 renderTable();
}
function renderTable(){
 const query=$('search').value.toLowerCase(),filter=$('filter').value;
 const visible=events.filter(e=>(filter==='all'||e.decision===filter||e.type===filter)&&JSON.stringify([e.op,e.target,e.rule,e.type]).toLowerCase().includes(query));
 const body=$('events');body.replaceChildren();
 for(const event of visible){const row=node('tr');row.classList.toggle('selected',event.seq===selected);const date=new Date(event.ts*1000);row.append(node('td',date.toLocaleTimeString([],{hour12:false})));const cell=node('td');const action=node('button',event.op||event.type,'row-action');action.addEventListener('click',()=>inspect(event));action.setAttribute('aria-label',`Inspect ${event.op||event.type}: ${event.target||event.rule||''}`);cell.append(action,node('span',event.target||event.rule||event.exposure_status||'Session event','resource'));row.append(cell);const state=node('td');state.append(badge(outcome(event).toUpperCase(),event.decision));row.append(state);body.append(row);}
 $('empty').hidden=visible.length>0;$('event-count').textContent=`${events.length} events · ${events.filter(e=>e.decision==='block'||e.decision==='stop').length} denied actions`;
 if(!visible.length){$('empty').querySelector('h2').textContent=events.length?'No matching events':'No activity yet';$('empty').querySelector('p').textContent=events.length?'Change the search or decision filter to see more activity.':'Launch a managed task to see its attempted actions, results and policy evidence here.';}
}
async function refresh(){
 if(busy||!access)return;busy=true;
 try{const data=await api('/api/runs');runs=data.runs;const current=$('runs').value;$('runs').replaceChildren();for(const run of runs){const option=node('option',`${run.session_id.slice(0,12)} · ${run.status}`);option.value=run.session_id;$('runs').append(option);}if(current&&runs.some(r=>r.session_id===current))$('runs').value=current;
 const run=runs.find(r=>r.session_id===$('runs').value);$('stop').disabled=!run||run.status!=='RUNNING';$('run-status').textContent=run?.status||'No managed runs';$('run-status').className=`badge ${run?.status==='RUNNING'?'running':''}`;
 if(!run){$('runs').append(node('option','No managed runs'));events=[];renderTable();}else{if(stateSession!==run.session_id){events=[];selected=null;stateSession=run.session_id;}const cursor=events.length?events[events.length-1].seq:0;const data=await api(`/api/runs/${run.session_id}/events?after=${cursor}`);events.push(...data.events);renderTable();const choice=events.find(e=>e.seq===selected)||[...events].reverse().find(e=>e.decision==='block'||e.decision==='stop');if(choice)inspect(choice);}
 $('connection').textContent='Controller connected';$('connect').hidden=true;showNotice('Showing recorded events from the managed run.');
 }catch(error){$('connection').textContent='Connection interrupted';showNotice(`${error.message}. Use Refresh to retry.`,true);}finally{busy=false;}
}
$('connect').addEventListener('submit',event=>{event.preventDefault();access=$('key').value;sessionStorage.setItem('airlock-access',access);refresh();});
$('search').addEventListener('input',renderTable);$('filter').addEventListener('change',renderTable);
$('runs').addEventListener('change',()=>{selected=null;refresh();});$('refresh').addEventListener('click',refresh);
$('stop').addEventListener('click',async()=>{const session=$('runs').value;$('stop').disabled=true;$('stop').textContent='Stopping…';try{await api(`/api/runs/${session}/stop`,'POST');showNotice('STOP verified: the managed agent container has terminated.');await refresh();}catch(error){showNotice(`STOP could not be verified: ${error.message}`,true);}finally{$('stop').textContent='Stop run';}});
if(!access){$('connect').hidden=false;$('connection').textContent='Operator access required';}else refresh();
setInterval(refresh,2000);
