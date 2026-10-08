import {api} from '../assets/api.mjs';import {sendAndConfirm,readPending} from '../assets/transactions.mjs';import {renderShell,tell,button,el} from '../assets/shell.mjs';
import {applyDeploymentConfirmation} from '../assets/transactions.mjs';
export {applyDeploymentConfirmation} from '../assets/transactions.mjs';
export function canAdmin(address,owner,authenticated){return !!authenticated&&!!address&&address.toLowerCase()===owner?.toLowerCase()}
export function roleDraftKey(revision,owner){return 'skillguard-roles-'+(revision??'none')+'-'+(owner??'none').toLowerCase()}
export function readRoleDraft(revision,owner,storage=globalThis.localStorage){try{return JSON.parse(storage?.getItem(roleDraftKey(revision,owner))??'null')??{arbiter:'',treasury:''}}catch{return {arbiter:'',treasury:''}}}
export function saveRoleDraft(revision,owner,draft,storage=globalThis.localStorage){storage?.setItem(roleDraftKey(revision,owner),JSON.stringify(draft))}
export function clearRoleDraft(revision,owner,storage=globalThis.localStorage){storage?.removeItem(roleDraftKey(revision,owner))}
export {canAdmin as canAdminWizard};
const STEPS_V2=[['deploy_registry','部署 Registry'],['deploy_license','部署 License'],['wire_registry','Registry 连接 License'],['wire_license','License 授予 Registry 铸造权限'],['configure_arbitration','第五步：锁定仲裁与公共资金角色']];
const STEPS_V1=STEPS_V2.slice(0,4);
async function init(){const {wallet,config,requireWallet}=await renderShell('admin');document.querySelector('#owner').textContent=config.owner??'部署 owner 尚未读取';document.querySelector('#revision').textContent=config.revision??'无部署';document.querySelector('#current').textContent=JSON.stringify({registry:config.registry,license:config.license,chainId:config.chainId},null,2);
 let hashes=[];const storageKey='skillguard-deploy-'+config.revision+'-'+(config.owner??'').toLowerCase();
 let steps=STEPS_V2;let roleConfigured=false;
 try{const roster=JSON.parse(config.runtimeRoles??'null');if(roster&&roster.arbitrationConfigured)roleConfigured=true}catch{}
 const roles=readRoleDraft(config.revision,config.owner);
 document.querySelector('#arbiter').value=roles.arbiter||'';document.querySelector('#treasury').value=roles.treasury||'';
 function syncHashes(){try{hashes=JSON.parse(localStorage.getItem(storageKey)??'[]')}catch{hashes=[]}}
 syncHashes();
 function paint(){syncHashes();
  const allowed=canAdmin(wallet.state.address,config.owner,wallet.state.authenticated);
  document.querySelector('#permission').textContent=allowed?'已确认当前 owner。每一步由你的钱包签名。':'只读。请连接当前合约 owner 钱包。';
  const draft=document.querySelector('#arbiter').value.trim();const treasuryDraft=document.querySelector('#treasury').value.trim();
  // 第五步只在 fresh wizard 恢复时才展示；hashes.length>4 且本机 roles 草稿丢失时禁止隐藏路径
  const showRoles=!roleConfigured&&hashes.length!==0||true;
  const target=document.querySelector('#deploy-steps');target.replaceChildren();
  steps.forEach(([step,label],index)=>{const li=el('li');li.append(el('strong',label));
   if(hashes[index]){li.append(el('p','已确认：'+hashes[index],'mono'))}
   else if(step==='configure_arbitration'){
    const action=button('准备并签名（锁定一次，不可更改）',async()=>{await requireWallet();
     const body={step,arbiter:document.querySelector('#arbiter').value.trim(),treasury:document.querySelector('#treasury').value.trim(),creationTxHashes:hashes.slice(0,2)};
     saveRoleDraft(config.revision,config.owner,{arbiter:body.arbiter,treasury:body.treasury});
     const prepared=await api('/api/admin/prepare',{body});
     document.querySelector('#estimate').textContent='此步 gas 估算：'+prepared.estimatedGas+'；费用估算：'+prepared.estimatedFee+' wei';
     const result=await sendAndConfirm(prepared,'/api/admin/confirm',tell);
     if(result.status==='confirmed'){hashes[index]=result.txHash;localStorage.setItem(storageKey,JSON.stringify(hashes));paint()}
    });
    action.disabled=!allowed||index!==hashes.length||!draft||!treasuryDraft;li.append(action);
    if(index!==hashes.length)li.append(el('p','前四步回执齐备后才能配置角色。','muted'))
   }else{
    const action=button('准备并签名',async()=>{await requireWallet();const prepared=await api('/api/admin/prepare',{body:{step,arbiter:document.querySelector('#arbiter').value.trim(),treasury:document.querySelector('#treasury').value.trim(),creationTxHashes:hashes.slice(0,2)}});document.querySelector('#estimate').textContent='此步 gas 估算：'+prepared.estimatedGas+'；费用估算：'+prepared.estimatedFee+' wei';const result=await sendAndConfirm(prepared,'/api/admin/confirm',tell);if(result.status==='confirmed'){hashes[index]=result.txHash;localStorage.setItem(storageKey,JSON.stringify(hashes));paint()}});
    action.disabled=!allowed||index!==hashes.length;li.append(action);
   }
   target.append(li)});
  const needRoles=steps===STEPS_V2;
  document.querySelector('#activate').disabled=!allowed||(needRoles?hashes.length!==5:hashes.length!==4);
  document.querySelector('#slash').disabled=!allowed;
  if(roleConfigured){document.querySelector('#roles-draft').querySelectorAll('input').forEach(i=>i.disabled=true)}
 }
 document.querySelector('#arbiter').addEventListener('input',paint);document.querySelector('#treasury').addEventListener('input',paint);
 document.addEventListener('wallet-state',paint);
 document.addEventListener('transaction-confirmed',event=>{if(event.detail.prepared.scopeRevision===config.revision&&event.detail.prepared.from.toLowerCase()===config.owner?.toLowerCase()){hashes=JSON.parse(localStorage.getItem(storageKey)??'[]');paint()}});
 document.addEventListener('wallet-state',event=>{if(!event.detail?.authenticated){clearRoleDraft(config.revision,config.owner);document.querySelector('#arbiter').value='';document.querySelector('#treasury').value=''}paint()});
 paint();
 document.querySelector('#activate').addEventListener('click',async()=>{try{await api('/api/admin/activate',{body:{revision:config.revision,txHashes:hashes}});localStorage.removeItem(storageKey);clearRoleDraft(config.revision,config.owner);wallet.setScope(null);tell('新部署已核验并激活。请刷新后重新登录。');document.querySelector('#activate').disabled=true}catch(error){tell(error.message,true)}});
 document.querySelector('#slash').addEventListener('click',async()=>{try{const prepared=await api('/api/admin/prepare',{body:{step:'slash_auditor',auditor:document.querySelector('#slash-address').value.trim()}});await sendAndConfirm(prepared,'/api/admin/confirm',tell)}catch(error){tell(error.message,true)}});
 document.querySelector('#clear-draft').addEventListener('click',()=>{hashes=[];localStorage.removeItem(storageKey);clearRoleDraft(config.revision,config.owner);document.querySelector('#arbiter').value='';document.querySelector('#treasury').value='';paint();tell('本机向导记录已清空。已经创建的链上合约仍保留。')});
}
if(typeof window!=='undefined'&&typeof document!=='undefined')init().catch(error=>tell(error.message,true));
