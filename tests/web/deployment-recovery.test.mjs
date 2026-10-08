import test from 'node:test';import assert from 'node:assert/strict';
import {applyDeploymentConfirmation} from '../../web/pages/admin.mjs';
import {confirmPending} from '../../web/assets/transactions.mjs';
test('resumed deployment receipts advance the same draft exactly once',()=>{
 const values=new Map();const storage={getItem:k=>values.get(k)??null,setItem:(k,v)=>values.set(k,v)};
 const prepared={from:'0x123',scopeRevision:'revision',deploymentStep:'deploy_registry'};
 const result={status:'confirmed',txHash:'0xabc'};
 assert.deepEqual(applyDeploymentConfirmation(prepared,result,storage),['0xabc']);
 assert.deepEqual(applyDeploymentConfirmation(prepared,result,storage),['0xabc']);
 const wiring={...prepared,deploymentStep:'wire_registry'};
 storage.setItem('skillguard-deploy-revision-0x123',JSON.stringify(['0xabc','0xdef']));
 assert.deepEqual(applyDeploymentConfirmation(wiring,{...result,txHash:'0x456'},storage),['0xabc','0xdef','0x456']);
 assert.equal(applyDeploymentConfirmation({...prepared,scopeRevision:'other'},{status:'pending'},storage),null);
});
test('shared receipt recovery after reload persists wizard before deleting pending',async()=>{
 const values=new Map();globalThis.localStorage={getItem:k=>values.get(k)??null,setItem:(k,v)=>values.set(k,v),removeItem:k=>values.delete(k)};
 const prepared={id:'prepared',from:'0x123',scopeRevision:'reload',deploymentStep:'deploy_registry'};
 values.set('skillguard-pending-0x123',JSON.stringify({prepared,hash:'0xabc',path:'/api/admin/confirm'}));
 globalThis.fetch=async path=>({ok:true,json:async()=>({ok:true,data:path==='/api/session'?{csrfToken:'token'}:{status:'confirmed',txHash:'0xabc',blockNumber:1}})});
 await confirmPending(prepared,'/api/admin/confirm','0xabc');
 assert.deepEqual(JSON.parse(values.get('skillguard-deploy-reload-0x123')),['0xabc']);
 assert.equal(values.has('skillguard-pending-0x123'),false);
});
