/**
 * Suspicious 案件仲裁的页面侧草稿状态机（纯逻辑，无 DOM / 无 API 调用，可被 node:test 覆盖）。
 *
 * 背景（独立审查发现的回归风险）：prepare 请求发出后到钱包签名前，页面会按 2 秒刷新
 * 重建案件卡片；若期间切到另一个案件，旧的"待签交易"可能被误当作当前案件发送。
 * 服务端已按 wallet/案件/回执多重核验（ops/transactions.py），这里是页面侧的兜底：
 * - 选中别的案件 → 立即清空草稿（ preparedId 失效绑定）；
 * - 案件从待裁决列表消失 → 清空草稿；
 * - 签名前（sendAndConfirm 之前）核对「草稿案件 + 准备单 id」仍一致，不一致就不发钱包交易，
 *   由调用方对准备单执行 /api/auditor/cancel。
 */

export function createFlow() {
  return {key: null, preparedId: null};
}

/** 选中一个案件；切换到不同 key 时清掉旧草稿。同一个 key 重复选中不清（保留进度）。 */
export function selectCase(flow, key) {
  if (flow.key !== key) {
    flow.key = key;
    flow.preparedId = null;
  }
  return flow;
}

/** 把 prepare 返回的准备单 id 绑定到当前案件草稿上。 */
export function bindPrepared(flow, preparedId) {
  flow.preparedId = preparedId ?? null;
  return flow;
}

/** 清空整个草稿（签名完成后、案件消失、连接状态变化时）。 */
export function clearCase(flow) {
  flow.key = null;
  flow.preparedId = null;
  return flow;
}

/** 钱包签名前核对：草稿必须仍指向同一案件且绑定同一准备单。 */
export function assertFlowPrepared(flow, key, preparedId) {
  if (!flow.key || flow.key !== key || !flow.preparedId || flow.preparedId !== preparedId) {
    throw new Error('待签交易与当前裁决案件不一致，已取消发送');
  }
  return flow;
}

/** 按 refresh 后仍处于 waiting_human 的案件列表修剪草稿：案件消失即清空（返回 null 表示整体清掉）。 */
export function pruneFlow(flow, activeKeys) {
  if (!flow.key || !Array.isArray(activeKeys) || !activeKeys.includes(flow.key)) {
    return clearCase(flow);
  }
  return flow;
}
