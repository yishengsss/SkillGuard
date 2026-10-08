import {api} from '../assets/api.mjs';import {sendAndConfirm} from '../assets/transactions.mjs';import {createFlow,selectCase,bindPrepared,clearCase,assertFlowPrepared,pruneFlow} from '../assets/decisionDraft.mjs';import {renderShell,tell,el,button,amount} from '../assets/shell.mjs';

/** 页面可见性判定（node 测试使用） */
export function canArbitrate(address,arbitrator,authenticated){return !!authenticated&&!!address&&!!arbitrator&&address.toLowerCase()===arbitrator.toLowerCase()}
export function legacySettlementNote(capabilities){return capabilities&&capabilities.arbitrationSupported?'':'旧合约适用旧结算规则：恶意押金直接付给审计者，没有冻结与独立仲裁。'}
/** 案件状态叙述；未匹配返回 null，由调用方决定展示方式（不允许写死给非案件结论）。 */
export function arbitrationStatusText(row){
  if(!row||typeof row.status==='undefined')return null;
  const case_=row.arbitration;
  if(row.status===5&&case_)return `暂定恶意，押金冻结 ${amount(case_.originalDepositWei??row.depositWei)} ${row.nativeSymbol||'wei'}；截止 ${new Date(case_.deadline*1000).toLocaleString()}`;
  if(row.status===5)return '暂定恶意，押金冻结中；本版本没有读取到仲裁案件信息。';
  if(row.status===6)return '仲裁已过期：押金已退还发布者，此版本不能安装。';
  if(row.status===4&&case_&&case_.finalReportHash)return '恶意结论已由独立仲裁确认（保留原报告与最终报告）。';
  return null;
}
/** 可领取余额描述（credits 全部来自合约读取；读取失败显示明确错误）。 */
export function fundsText(funds){if(!funds)return '无法读取可领取余额。';return funds.creditsWei==='0'?'没有可领取余额。':'可领取 '+funds.creditsWei+' wei。'}
/** 简单解析证据表（不引 DOM）。 */
export function parseEvidence(text){
  const rows=[];
  for(const line of String(text??'').split(/\r?\n/)){
    if(!line.trim())continue;
    const parts=line.split('|');
    if(parts.length<4)return null;
    rows.push({file:parts[0].trim(),line:parts[1].trim(),quote:parts[2].trim(),explanation:parts.slice(3).join('|').trim()});
  }
  return rows.length?rows:null;
}

async function init(){const {wallet,config,scope,requireWallet}=await renderShell('arbitration');
 let flow=createFlow();let selectedKey=null;let cache={};
 const summary=document.querySelector('#case-summary');
 function operator(){return wallet.state.authenticated&&wallet.state.address}
 function controls(){const allowed=operator()&&selectedKey;for(const id of ['resolve-safe','resolve-malicious','expire'])document.querySelector('#'+id).disabled=!allowed&&!canArbitrate(wallet.state.address,config.arbiter,wallet.state.authenticated)&&id!=='expire';}
 async function refresh(){try{
  const [cases,skills]=await Promise.all([api(scope('/api/arbitration/cases')),api(scope('/api/skills'))]);
  cache.cases=cases;cache.skills=skills;
  const list=document.querySelector('#cases');list.replaceChildren();
  if(!cases.length){list.append(el('p','当前部署没有暂定恶意案件（旧合约不会产生）。','muted'));return}
  for(const row of cases){const skill=skills.find(r=>r.key===row.key);const item=el('div',undefined,'skill-row');
   const open=el('a');open.href='#'+row.key;open.textContent=(skill?.name??row.key)+' · '+(arbitrationStatusText(row)?arbitrationStatusText(row):row.status);
   open.addEventListener('click',event=>{event.preventDefault();pick(row.key)});
   item.append(open);item.append(el('span','押金 '+row.depositWei+' wei','muted'));list.append(item)}
  flow=pruneFlow(flow,cases.map(r=>r.key));
  if(selectedKey&&!cases.some(r=>r.key===selectedKey)){selectedKey=null;summary.textContent='案件已处理，选择了空。';document.querySelector('#case-reports').replaceChildren()}
  controls();
 }catch(error){tell(error.message,true)}}
 async function pick(key){flow=selectCase(flow,key);selectedKey=key;
  const row=cache.cases?.find(r=>r.key===key);if(!row)return;
  const detail=await api(scope('/api/arbitration/cases/'+key));
  summary.textContent=arbitrationStatusText(row)?arbitrationStatusText(row):('状态 '+row.status);
  document.querySelector('#deadline-note').textContent=row.arbitration?('原报告哈希 '+row.arbitration.originalReportHash.slice(0,18)+'… · 截止 '+new Date(row.arbitration.deadline*1000).toLocaleString()):'';
  document.querySelector('#resolve-safe').disabled=!canArbitrate(wallet.state.address,detail.arbitration?.arbiter,wallet.state.authenticated);
  document.querySelector('#resolve-malicious').disabled=!canArbitrate(wallet.state.address,detail.arbitration?.arbiter,wallet.state.authenticated);
  const box=document.querySelector('#case-reports');
  box.textContent=JSON.stringify({originalReport:detail.originalReport,finalReport:detail.finalReport,source:detail.source??'只有独立仲裁钱包能读取源码'},null,2);
  controls();}
 async function runDecision(decision){
  const key=selectedKey;if(!key)throw Error('请先选择案件');
  flow=selectCase(flow,key);await requireWallet();
  const prepared=await api('/api/arbitration/prepare',{body:{action:'resolve',key,decision,reason:document.querySelector('#decision-reason').value,evidence:parseEvidence(document.querySelector('#decision-evidence').value)}});
  try{assertFlowPrepared(flow,key,prepared.id)}catch(error){flow=clearCase(flow);await api('/api/funds/prepare',{body:{action:'withdraw'}}).catch(()=>{});tell(error.message,true);return}
  flow=bindPrepared(flow,prepared.id);
  await sendAndConfirm(prepared,'/api/arbitration/confirm',tell);
  flow=clearCase(flow);await refresh();
 }
 document.querySelector('#resolve-safe').addEventListener('click',async()=>{try{await runDecision('safe')}catch(error){tell(error.message,true)}});
 document.querySelector('#resolve-malicious').addEventListener('click',async()=>{try{await runDecision('malicious')}catch(error){tell(error.message,true)}});
 async function funds(){if(!operator()){document.querySelector('#funds').textContent='连接钱包后读取 credits。';controls();return}
  const data=await api(scope('/api/funds',{address:wallet.state.address}));
  document.querySelector('#funds').textContent=data.arbitrationSupported===false?legacySettlementNote({arbitrationSupported:false}):fundsText(data);
  document.querySelector('#funds-legacy').textContent=legacySettlementNote(data);
  document.querySelector('#withdraw').disabled=!operator()||!data.creditsWei||data.creditsWei==='0';
  controls();}
 document.querySelector('#withdraw').addEventListener('click',async()=>{try{await requireWallet();const prepared=await api('/api/funds/prepare',{body:{action:'withdraw'}});await sendAndConfirm(prepared,'/api/funds/confirm',tell);await refresh();await funds()}catch(error){tell(error.message,true)}});
 document.querySelector('#expire').addEventListener('click',async()=>{try{if(!selectedKey)throw Error('请先选择到期案件');await requireWallet();const prepared=await api('/api/funds/prepare',{body:{action:'expire',key:selectedKey}});await sendAndConfirm(prepared,'/api/funds/confirm',tell);await refresh()}catch(error){tell(error.message,true)}});
 document.addEventListener('wallet-state',async()=>{flow=clearCase(flow);selectedKey=null;await funds().catch(()=>{});controls()});
 document.querySelector('#refresh-x')?.addEventListener?.('click',refresh);
 await Promise.allSettled([refresh(),funds()]);
}
if(typeof window!=='undefined'&&typeof document!=='undefined')init().catch(error=>tell(error.message,true));
