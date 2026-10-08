// This provider exists only on the isolated test server. All keys are public Anvil fixtures.
const config=await fetch('/__test_wallet').then(r=>r.json());
const listeners=new Map();let selected=Number(localStorage.getItem('role-test-account')??0),rejectNext=false,chain='0x7a69';
if(selected>=config.accounts.length)selected=0;
const banner=document.createElement('div');banner.style.cssText='position:sticky;top:0;z-index:10;background:#f5e7bb;padding:8px 20px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;font:12px sans-serif';
const label=document.createElement('span');label.textContent='隔离 Anvil · 公开测试钱包';banner.append(label);
const select=document.createElement('select');select.id='test-wallet-account';config.accounts.forEach((account,index)=>{const option=document.createElement('option');option.value=index;option.textContent=account.label+' · '+account.address.slice(0,8);select.append(option)});select.value=selected;banner.append(select);
const reject=document.createElement('button');reject.textContent='下次拒签';reject.id='test-reject';reject.onclick=()=>{rejectNext=true;reject.textContent='已设置下次拒签'};banner.append(reject);
const wrongChain=document.createElement('button');wrongChain.id='test-chain';wrongChain.textContent='测试切换网络';wrongChain.onclick=()=>{chain=chain==='0x7a69'?'0x1':'0x7a69';emit('chainChanged',chain)};banner.append(wrongChain);
document.body.prepend(banner);
function emit(event,value){for(const listener of listeners.get(event)??[])listener(value)}
select.onchange=()=>{selected=Number(select.value);localStorage.setItem('role-test-account',selected);emit('accountsChanged',[config.accounts[selected].address])};
async function rpc({method,params=[]}){const session=await fetch('/api/session').then(r=>r.json());const response=await fetch('/__test_rpc',{method:'POST',headers:{'Content-Type':'application/json','X-SkillGuard-Token':session.data.csrfToken},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params})});const payload=await response.json();if(payload.error)throw Error(payload.error.message??'isolated RPC failure');return payload.result}
globalThis.ethereum={on(event,listener){if(!listeners.has(event))listeners.set(event,[]);listeners.get(event).push(listener)},
 async request({method,params=[]}){
  if(method==='eth_requestAccounts'||method==='eth_accounts')return [config.accounts[selected].address];if(method==='eth_chainId')return chain;
  if(['personal_sign','eth_sendTransaction'].includes(method)){
   if(rejectNext){rejectNext=false;reject.textContent='下次拒签';throw Object.assign(Error('用户拒绝测试签名'),{code:4001})}
   if(chain!=='0x7a69')throw Error('测试钱包网络错误');
   const {privateKeyToAccount}=await import('https://esm.sh/viem@2.38.0/accounts');const account=privateKeyToAccount(config.accounts[selected].key);
   if(method==='personal_sign'){if(params[1].toLowerCase()!==account.address.toLowerCase())throw Error('测试签名者已改变');return account.signMessage({message:{raw:params[0]}})}
   const {createWalletClient,custom}=await import('https://esm.sh/viem@2.38.0');
   const client=createWalletClient({account,transport:custom({request:rpc}),chain:{id:31337,name:'Isolated Anvil',nativeCurrency:{name:'Ether',symbol:'ETH',decimals:18},rpcUrls:{default:{http:['/__test_rpc']}}}});
   const tx=params[0];if(tx.from.toLowerCase()!==account.address.toLowerCase())throw Error('测试交易账户已改变');return client.sendTransaction({to:tx.to,data:tx.data,value:BigInt(tx.value),gas:BigInt(tx.gas)});
  }
  return rpc({method,params});
 }};
