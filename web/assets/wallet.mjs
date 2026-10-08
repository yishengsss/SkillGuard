import {api as defaultApi,setWalletAddress} from './api.mjs';
export const loadViem=()=>import('https://esm.sh/viem@2.38.0');
const equal=(a,b)=>(a??'').toLowerCase()===(b??'').toLowerCase();
const hex=value=>'0x'+BigInt(value).toString(16);
const messageHex=text=>'0x'+Array.from(new TextEncoder().encode(text),b=>b.toString(16).padStart(2,'0')).join('');
export function createWallet(provider,onChange=()=>{},{api=defaultApi}={}){
 const state={address:null,chainId:null,authenticated:false,generation:0,scope:null};let pending=null;
 const changed=()=>{setWalletAddress(state.address);onChange({...state})};
 function invalidate(){state.generation++;state.authenticated=false;changed()}
 provider?.on?.('accountsChanged',accounts=>{state.address=accounts[0]??null;invalidate()});
 provider?.on?.('chainChanged',chain=>{state.chainId=Number(BigInt(chain));invalidate()});
 function assertCurrent(snapshot){if(snapshot.generation!==state.generation||!equal(snapshot.address,state.address)||snapshot.chainId!==state.chainId)throw Error('账户、网络或会话已改变，请重新操作')}
 async function check(snapshot){const [accounts,chain]=await Promise.all([provider.request({method:'eth_accounts'}),provider.request({method:'eth_chainId'})]);assertCurrent(snapshot);if(!equal(accounts[0],snapshot.address)||Number(BigInt(chain))!==snapshot.chainId){invalidate();throw Error('当前钱包账户或网络已改变')}}
 async function connect(){if(!provider)throw Error('未检测到钱包，请在支持钱包扩展的浏览器打开页面');const accounts=await provider.request({method:'eth_requestAccounts'});const chain=await provider.request({method:'eth_chainId'});state.address=accounts[0]??null;state.chainId=Number(BigInt(chain));invalidate();return {...state}}
 async function authenticate(){
  if(pending)await pending.catch(()=>{});
  pending=(async()=>{
   if(!state.address)await connect();if(![31337,968].includes(state.chainId))throw Error('请切换到 BOT 测试网或本地 Anvil');
   if(state.scope&&state.scope.chainId!==state.chainId)throw Error('钱包网络与当前部署不匹配');
   const snapshot={...state};await check(snapshot);
   const challenge=await api('/api/auth/challenge',{body:{address:snapshot.address},wallet:false});assertCurrent(snapshot);
   const signature=await provider.request({method:'personal_sign',params:[messageHex(challenge.message),snapshot.address]});await check(snapshot);
   const result=await api('/api/auth/verify',{body:{message:challenge.message,signature},wallet:false});
   try{await check(snapshot);if(!equal(result.address,snapshot.address))throw Error('签名账户不匹配')}
   catch(error){await api('/api/auth/logout',{body:{},wallet:false}).catch(()=>{});throw error}
   assertCurrent(snapshot);state.authenticated=true;changed();return result;
  })();
  try{return await pending}finally{pending=null}
 }
 async function send(prepared){
  const snapshot={...state};if(!state.authenticated||!equal(state.address,prepared.from))throw Error('请使用准备交易的钱包重新登录');
  if(prepared.chainId!==state.chainId||![31337,968].includes(state.chainId)||state.scope?.revision!==prepared.scopeRevision)throw Error('网络或部署作用域已改变');
  await check(snapshot);
  const tx={from:prepared.from,data:prepared.data,value:hex(prepared.value),gas:hex(prepared.estimatedGas),chainId:hex(prepared.chainId)};if(prepared.to)tx.to=prepared.to;
  const txHash=await provider.request({method:'eth_sendTransaction',params:[tx]});
  try{await check(snapshot)}catch(error){error.txHash=txHash;throw error}return txHash;
 }
 async function disconnect(){invalidate();state.address=null;changed();await api('/api/auth/logout',{body:{},wallet:false}).catch(()=>{})}
 function setScope(scope){if(state.scope?.revision!==scope?.revision){state.scope=scope;invalidate()}}
 return {state,connect,authenticate,send,disconnect,setScope};
}
