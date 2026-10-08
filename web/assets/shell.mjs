import {api,scoped} from './api.mjs';
import {createWallet} from './wallet.mjs';
import {useWallet,readPending,confirmPending} from './transactions.mjs';
export const statuses=['未登记','已登记','等待审计','已验证','恶意','暂定恶意（待仲裁）','仲裁已过期（押金已退还）'];
export const stageLabels={agent_started:'Agent 开始审计',agent_model_requested:'请求模型',agent_model_responded:'模型已响应',agent_tool_called:'Agent 调用只读工具',agent_completed:'Agent 完整审计完成',request_received:'收到链上请求',source_resolved:'已取得源码',hashes_verified:'源码哈希已核对',scan_completed:'规则扫描完成',report_saved:'报告已保存',waiting_human:'等待人工裁决',tx_intent:'原交易意图已保存',tx_broadcast:'已广播',receipt_confirmed:'链上回执已确认',audit_failed:'处理失败，可重试',source_failed:'来源不可用',recovery_conflict:'原交易恢复需人工处理'};
export function el(tag,text,cls){const node=document.createElement(tag);if(text!==undefined)node.textContent=text;if(cls)node.className=cls;return node}
export function tell(text,error=false){const node=document.querySelector('#notice');node.textContent=text;node.className='notice'+(error?' error':'');node.hidden=false}
export function short(address){return address?address.slice(0,6)+'…'+address.slice(-4):'未连接'}
export function amount(wei){const value=BigInt(wei);return (value/10n**18n)+'.'+(value%10n**18n).toString().padStart(18,'0').replace(/0+$/,'').padEnd(1,'0')}
export function button(text,action,cls=''){const node=el('button',text,cls);node.type='button';node.addEventListener('click',async()=>{node.disabled=true;try{await action()}catch(error){tell(error.message,true)}finally{node.disabled=false}});return node}
export function skillList(rows,container){container.replaceChildren();if(!rows.length){container.append(el('p','当前筛选没有技能。','empty'));return}for(const row of rows){const a=el('a',undefined,'skill-row');a.href='/skills/'+row.key;const title=el('div');title.append(el('strong',row.name),el('span','v'+row.version,'muted'));const meta=el('div');meta.append(el('span',short(row.publisher),'mono'),el('span',statuses[row.status]??String(row.status),'badge status-'+row.status));a.append(title,meta);container.append(a)}}
export async function renderShell(pageId){
 document.querySelectorAll('nav a').forEach(a=>{if(a.dataset.page===pageId)a.setAttribute('aria-current','page')});
 let config;try{config=await api('/api/config')}catch(error){tell(error.message,true);throw error}
 const network=document.querySelector('#network');network.textContent=config.ready?`${config.chainId===968?'BOT Testnet':'Anvil'} · #${config.chainId}`:'配置尚未就绪';
 if(!config.ready)tell(config.reason||'请先完成服务配置',true);
 const provider=globalThis.ethereum;
 const wallet=createWallet(provider,state=>{document.querySelector('#wallet-state').textContent=state.authenticated?short(state.address)+' · 已登录':state.address?short(state.address)+' · 待签名':'各角色连接自己的钱包';document.dispatchEvent(new CustomEvent('wallet-state',{detail:state}))});
 wallet.setScope(config);useWallet(wallet);
 document.querySelector('#connect').addEventListener('click',async()=>{try{await wallet.connect();await wallet.authenticate();const saved=readPending(wallet.state.address);if(saved&&saved.prepared.scopeRevision===config.revision){document.querySelector('#pending').replaceChildren(button('继续核验待确认交易',async()=>confirmPending(saved.prepared,saved.path,saved.hash,tell)))} }catch(error){tell(error.message,true)}});
 document.querySelector('#disconnect').addEventListener('click',()=>wallet.disconnect());
 const refresh=async()=>{const next=await api('/api/config');if(next.revision!==config.revision){wallet.setScope(next);config=next;tell('当前部署已改变，请刷新页面并重新签名登录。',true)}};
 document.addEventListener('visibilitychange',()=>{if(!document.hidden)refresh().catch(error=>tell(error.message,true))});
 return {config,wallet,scope:(path,extra)=>scoped(path,config,extra),requireWallet:async()=>{if(!wallet.state.authenticated){await wallet.connect();await wallet.authenticate()}}};
}
