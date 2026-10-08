import test from 'node:test';import assert from 'node:assert/strict';
import {canArbitrate,arbitrationStatusText,legacySettlementNote,fundsText,parseEvidence} from '../../web/pages/arbitration.mjs';
import {createFlow,selectCase,bindPrepared,clearCase,pruneFlow} from '../../web/assets/decisionDraft.mjs';
import {readRoleDraft,saveRoleDraft,clearRoleDraft,roleDraftKey} from '../../web/pages/admin.mjs';

const DEADLINE=Math.floor(1799000000);
const CASE={reporter:'0x111',originalReportHash:'0xabc',openedAt:1,deadline:DEADLINE,finalReportHash:'0x00'};
const BASE={name:'demo',key:'0x'+Buffer.alloc(32,1).toString('hex'),status:5,depositWei:'10000000000000000',nativeSymbol:'wei',arbitration:CASE};

test('pending and expired states get explicit labels',()=>{
  const pending=arbitrationStatusText(BASE);
  assert.match(pending,/暂定恶意/);assert.match(pending,/押金冻结/);
  const expired=arbitrationStatusText({...BASE,status:6});
  assert.match(expired,/仲裁已过期/);assert.match(expired,/不能安装/);
  assert.match(arbitrationStatusText({...BASE,status:4,arbitration:{...CASE,finalReportHash:'0x1'}}),/最终|确认|保留原报告/);
  assert.equal(arbitrationStatusText({...BASE,status:2}),null); // 非案件状态没有写死标签
});

test('legacy contracts show old settlement rule instead of frozen flow',()=>{
  assert.match(legacySettlementNote(null),/旧合约/);
  assert.match(legacySettlementNote({arbitrationSupported:false}),/旧结算规则/);
  assert.equal(legacySettlementNote({arbitrationSupported:true}),'');
});

test('only the Arbiter wallet can sign, others are read-only',()=>{
  const arbiter='0x111';
  assert.equal(canArbitrate(arbiter,arbiter,true),true);
  assert.equal(canArbitrate('0x222',arbiter,true),false);
  assert.equal(canArbitrate(arbiter,arbiter,false),false);
  assert.equal(canArbitrate('',arbiter,true),false);
});

test('settlement balance appears from contract read even when zero',()=>{
  assert.match(fundsText({creditsWei:'123'}),/可领取 123/);
  assert.match(fundsText({creditsWei:'0'}),/没有可领取/);
  assert.match(fundsText(null),/无法读取/);
});

test('evidence table parses rows and rejects loose text',()=>{
  const parsed=parseEvidence('a.py|3|SECRET = 1|读取了环境密钥');
  assert.deepEqual(parsed,[{file:'a.py',line:'3',quote:'SECRET = 1',explanation:'读取了环境密钥'}]);
  assert.equal(parseEvidence('just some words'),null);
});

test('wallet change clears all case drafts',()=>{
  let flow=selectCase(createFlow(),'0xAAA');bindPrepared(flow,'prep-1');
  flow=clearCase(flow);
  assert.equal(flow.key,null);assert.equal(flow.preparedId,null);
  let second=selectCase(createFlow(),'0xAAA');bindPrepared(second,'prep-2');
  second=pruneFlow(second,[]); // 服务器 CAMPS list no longer holds this key
  assert.equal(second.preparedId,null);
});

test('fifth-step role draft survives a refresh with the same addresses',()=>{
  const keys=[];
  const storage={getItem:k=>keys.includes(k)?'{"arbiter":"0xA","treasury":"0xB"}':null,
                 setItem:(k,v)=>{keys.push(k)},removeItem:k=>keys.splice(keys.indexOf(k),1)};
  saveRoleDraft('rev','0xowner',{arbiter:'0xA',treasury:'0xB'},storage);
  const restored=readRoleDraft('rev','0xowner',storage);
  assert.deepEqual(restored,{arbiter:'0xA',treasury:'0xB'});
  clearRoleDraft('rev','0xowner',storage);
  assert.deepEqual(readRoleDraft('rev','0xowner',storage),{arbiter:'',treasury:''});
  assert.match(roleDraftKey('rev','0xOwNeR'),/0xowner$/); // owner 大小写不影响恢复
});
