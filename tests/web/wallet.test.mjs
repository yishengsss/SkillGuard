import test from 'node:test';
import assert from 'node:assert/strict';
import {createWallet} from '../../web/assets/wallet.mjs';
const first='0x'+'11'.repeat(20),second='0x'+'22'.repeat(20);
function provider(){const listeners={};return {accounts:[first],chain:'0x7a69',on:(n,fn)=>listeners[n]=fn,
 changeAccounts(a){this.accounts=a;listeners.accountsChanged?.(a)},changeChain(c){this.chain=c;listeners.chainChanged?.(c)},
 async request({method}){if(method==='eth_requestAccounts'||method==='eth_accounts')return this.accounts;if(method==='eth_chainId')return this.chain;if(method==='personal_sign')return 'signature';if(method==='eth_sendTransaction')return '0x'+'ab'.repeat(32)}}}
function mockApi(){const calls=[];return Object.assign(async(path)=>{calls.push(path);return path.includes('challenge')?{message:'SIWE'}:{address:first}},{calls})}

test('no provider permits reading but gives a clear connect error',async()=>{
 const wallet=createWallet(null,()=>{}, {api:mockApi()});assert.equal(wallet.state.address,null);
 await assert.rejects(wallet.connect(),/钱包/);
});
for(const kind of ['account','chain'])test(`late signature after ${kind} change never restores session`,async()=>{
 const p=provider(),api=mockApi();let release;p.request=async({method})=>{
  if(method==='personal_sign')return new Promise(r=>release=r);
  return method==='eth_chainId'?p.chain:p.accounts;
 };
 const wallet=createWallet(p,()=>{},{api});await wallet.connect();
 const signing=wallet.authenticate();while(!release)await new Promise(r=>setImmediate(r));
 if(kind==='account')p.changeAccounts([second]);else p.changeChain('0x3c8');
 release('signature');await assert.rejects(signing,/账户|网络|会话/);
 assert.equal(wallet.state.authenticated,false);assert.ok(!api.calls.includes('/api/auth/verify'));
});

test('late server verification logs out instead of restoring old account',async()=>{
 const p=provider();let release;const calls=[];
 const api=async path=>{calls.push(path);if(path.endsWith('challenge'))return {message:'SIWE'};if(path.endsWith('verify'))return new Promise(r=>release=r);return {}};
 const wallet=createWallet(p,()=>{},{api});await wallet.connect();const signing=wallet.authenticate();
 while(!release)await new Promise(r=>setImmediate(r));p.changeAccounts([second]);release({address:first});
 await assert.rejects(signing,/账户|会话/);assert.equal(wallet.state.authenticated,false);assert.equal(calls.at(-1),'/api/auth/logout');
});

test('transaction uses decimal wei without precision loss and rejects wrong signer',async()=>{
 const p=provider(),api=mockApi();let sent;
 const original=p.request.bind(p);p.request=async request=>{if(request.method==='eth_sendTransaction'){sent=request.params[0];return '0x'+'ab'.repeat(32)}return original(request)};
 const wallet=createWallet(p,()=>{},{api});await wallet.connect();await wallet.authenticate();wallet.setScope({revision:'r',chainId:31337});await wallet.authenticate();
 const tx={from:first,to:second,data:'0x1234',value:'1000000000000000001',estimatedGas:'21000',chainId:31337,scopeRevision:'r'};
 await wallet.send(tx);assert.equal(BigInt(sent.value),1000000000000000001n);
 await assert.rejects(wallet.send({...tx,from:second}),/钱包/);
});
