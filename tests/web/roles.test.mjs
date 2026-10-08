import test from 'node:test';import assert from 'node:assert/strict';
import {renderFindings,historyMessage} from '../../web/pages/detail.mjs';
import {canAdmin} from '../../web/pages/admin.mjs';
import {workerMessage} from '../../web/pages/audit.mjs';
import {createFlow,selectCase,bindPrepared,clearCase,assertFlowPrepared,pruneFlow} from '../../web/assets/decisionDraft.mjs';
const nodes=[];
function element(tag){return {tag,children:[],textContent:'',append(...children){this.children.push(...children)}}}
globalThis.document={createElement:element};
test('untrusted report evidence is plain text',()=>{const target=element('div');renderFindings([{rule:'X',evidence:'<img src=x onerror=alert(1)>',file:'a'}],target);assert.equal(target.children[0].children.at(-1).textContent,'<img src=x onerror=alert(1)>')});
test('history and offline status make evidence limits explicit',()=>{assert.match(historyMessage([],{status:3}),/未保存运行日志/);assert.match(workerMessage({state:'offline'}),/离线/)});
test('admin stays read-only for non-owner wallet',()=>{assert.equal(canAdmin('0x123','0x456',true),false);assert.equal(canAdmin('0x123','0x123',false),false);assert.equal(canAdmin('0x123','0x123',true),true)});

test('Agent timeline shows actual tool payload as plain text',async()=>{const {renderTimeline}=await import('../../web/pages/detail.mjs');const target=element('div');target.replaceChildren=()=>{target.children=[]};renderTimeline([{time:1,stage:'agent_tool_called',payload:{tool:'read_file',arguments:{path:'main.py',start:1,end:10}}}],target);assert.equal(target.children[0].children[1].textContent,'Agent 调用只读工具');assert.match(target.children[0].children[2].textContent,/read_file/);assert.match(target.children[0].children[2].textContent,/main.py/)});

// ---- 案件裁决草稿回归（切换案件清空草稿 / 签名前核对案件） ----
test('switching cases clears the previous draft binding',()=>{
  const flow=selectCase(createFlow(),'0xAAA');bindPrepared(flow,'prep-1');
  assert.equal(assertFlowPrepared(flow,'0xAAA','prep-1'),flow); // 草稿绑定当前案件
  selectCase(flow,'0xBBB');
  assert.throws(()=>assertFlowPrepared(flow,'0xAAA','prep-1'),/不一致/);
  assert.throws(()=>assertFlowPrepared(flow,'0xBBB','prep-1'),/不一致/); // preparedId 已随案件清空
});

test('same case repeated selection keeps the draft',()=>{
  const flow=selectCase(createFlow(),'0xAAA');bindPrepared(flow,'prep-1');selectCase(flow,'0xAAA');
  assert.doesNotThrow(()=>assertFlowPrepared(flow,'0xAAA','prep-1'));
});

test('case leaving the waiting list clears the draft',()=>{
  let flow=selectCase(createFlow(),'0xAAA');bindPrepared(flow,'prep-1');
  flow=pruneFlow(flow,['0xAAA']);assert.doesNotThrow(()=>assertFlowPrepared(flow,'0xAAA','prep-1'));
  flow=pruneFlow(flow,[]); // 案件已被处理消失 → 清空
  assert.throws(()=>assertFlowPrepared(flow,'0xAAA','prep-1'),/不一致/);
  assert.equal(flow.key,null);assert.equal(flow.preparedId,null);
});

test('deploy-scope change clears everything the same way',()=>{
  let flow=selectCase(createFlow(),'0xAAA');bindPrepared(flow,'prep-1');clearCase(flow);
  assert.throws(()=>assertFlowPrepared(flow,'0xAAA','prep-1'),/不一致/);
});

test('unsigned stale prepare is never sent for the wrong case',()=>{
  // 模拟：按钮 A 准备完后切到案件 B —— assertFlowPrepared 在签名前拒绝并发起 cancel 由调用方执行
  const flow=selectCase(createFlow(),'0xAAA');bindPrepared(flow,'prep-A');
  const prepared={id:'prep-A',key:'0xBBB'}; // 服务端为案件 B 准备的单
  assert.throws(()=>assertFlowPrepared(flow,prepared.key,prepared.id),/不一致/);
});
