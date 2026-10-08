import {api} from './api.mjs';
let activeWallet;
export function useWallet(wallet){activeWallet=wallet}
export function applyDeploymentConfirmation(prepared,result,storage=globalThis.localStorage){
 const index=['deploy_registry','deploy_license','wire_registry','wire_license'].indexOf(prepared.deploymentStep);
 if(index<0||result.status!=='confirmed')return null;
 const key='skillguard-deploy-'+prepared.scopeRevision+'-'+prepared.from.toLowerCase();
 const hashes=JSON.parse(storage.getItem(key)??'[]');
 if(hashes[index]&&hashes[index]!==result.txHash)throw Error('部署步骤已有另一笔回执，请核对本机向导记录');
 if(index>hashes.length)throw Error('部署步骤缺少前序回执，请恢复本机向导记录');
 hashes[index]=result.txHash;storage.setItem(key,JSON.stringify(hashes));return hashes;
}
export async function sendAndConfirm(prepared,confirmPath,onState=()=>{}){
 onState('等待钱包签名');let hash;
 try{hash=await activeWallet.send(prepared)}catch(error){if(error.txHash){savePending(prepared,confirmPath,error.txHash);onState('钱包已切换；交易可能已广播：'+error.txHash)}else if(error.code===4001&&confirmPath==='/api/auditor/confirm'){await api('/api/auditor/cancel',{body:{preparedId:prepared.id}}).catch(()=>{})}throw error}
 savePending(prepared,confirmPath,hash);onState('已广播，等待真实回执：'+hash);
 return confirmPending(prepared,confirmPath,hash,onState);
}
function savePending(prepared,path,hash){globalThis.localStorage?.setItem('skillguard-pending-'+prepared.from.toLowerCase(),JSON.stringify({prepared,path,hash}))}
export async function confirmPending(prepared,path,hash,onState=()=>{}){
 for(let attempt=0;attempt<60;attempt++){
  const result=await api(path,{body:{preparedId:prepared.id,txHash:hash}});
  if(result.status==='confirmed'){applyDeploymentConfirmation(prepared,result);globalThis.localStorage?.removeItem('skillguard-pending-'+prepared.from.toLowerCase());globalThis.document?.dispatchEvent(new CustomEvent('transaction-confirmed',{detail:{prepared,result}}));onState('已确认 · 区块 '+result.blockNumber);return result}
  if(result.status==='failed')throw Error(result.error||'链上交易回滚');
  onState('交易待确认：'+hash);await new Promise(resolve=>setTimeout(resolve,2000));
 }
 throw Error('回执仍未确认。重新连接原钱包后可继续核验，勿重复发送。');
}
export function readPending(address){try{return JSON.parse(globalThis.localStorage?.getItem('skillguard-pending-'+address.toLowerCase())??'null')}catch{return null}}
