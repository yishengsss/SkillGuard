import test from 'node:test';import assert from 'node:assert/strict';
import {publishArchive,requestAudit} from '../../web/pages/publish.mjs';

test('custom upload and register use returned package identity',async()=>{
 const calls=[];const api=async(path,options)=>{calls.push({path,options});if(path==='/api/packages')return {packageId:'custom',manifest:{name:'new'}};return {id:'prepared'}};
 let sent;const send=async prepared=>{sent=prepared;return {status:'confirmed'}};
 const bytes=new Uint8Array([1,2]);const result=await publishArchive(bytes,api,send);
 assert.equal(calls[0].options.zip,bytes);assert.equal(calls[1].options.body.packageId,'custom');assert.equal(sent.id,'prepared');assert.equal(result.preview.manifest.name,'new');
});

test('deposit rejection can be resumed separately without registering again',async()=>{
 const calls=[];const api=async(path,options)=>{calls.push({path,options});return {id:'deposit'}};
 await assert.rejects(requestAudit('key',api,async()=>{throw Error('rejected')}),/rejected/);
 await requestAudit('key',api,async()=>({status:'confirmed'}));
 assert.equal(calls.length,2);assert.ok(calls.every(c=>c.options.body.action==='request_audit'));
});
