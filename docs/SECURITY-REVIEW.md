# SkillGuard 合约安全审查（docs/PROMPTS.md 第 11 步 · 冻结前）

审查范围：`contracts/src/SkillRegistry.sol`、`contracts/src/SkillLicense.sol`
方法：逐函数人工评审 + 既有 103 个 Foundry 测试回归（全部通过）。
结论：**未发现需要立即修复的高危问题**；以下按严重度列出观察项，仅记录、未改动代码（符合"只修高危"约束）。

## 已确认到位的防护

- `submitReport` 有 `nonReentrant`，且严格遵循 checks-events-interactions（先清 `deposit`、改 `status`，最后才外部调用 mint / 转账）；
- 安全结论分支：先铸 NFT 再退款，publisher 若是拒收 NFT / 无 receive 的合约会让交易整体 revert，
  但受损方是 publisher 自己，且状态已持久化，无资金可被套走（有 `MintRejectingPublisher` /
  `NoReceivePublisher` / `NftReentrantPublisher` 测试覆盖）；
- mint 权限：`SkillLicense` 用 OZ `AccessControl`，`MINTER_ROLE` 只能由 `setRegistry` 内部授予/
  轮换，`DEFAULT_ADMIN_ROLE` 从未授予任何地址，外部 `grantRole` 无法扩大 minter 集合；
- `auditor` 地址不来自 mint 参数，而是回读可信 `registry.auditorOf(key)`，两合约 key 公式若漂移会
  以 `NoAuditor` 失败（失败安全）；
- `register` 幂等防覆盖（`KeyAlreadyExists`），同 key 重复注册被拒，配合"新版本必须重新审计"；
- 自审禁止（`SelfAuditForbidden`）、押金/质押金额下限、状态机非法迁移全部显式 revert。

## 观察项（不影响冻结，记录备查）

### 中（设计取舍，与 SPEC 一致）
1. **恶意结论的经济问责依赖 owner 仲裁**：任何已质押审计者可对任意 `AuditRequested` 版本提交
   `isMalicious=true` 并直接拿走押金；其质押（0.01 ETH）与押金同量级，谎报成本低。SPEC 3.1
   明确此为演示用简化（`slashAuditor` 由 owner 仲裁），真实化需多审计者多数投票或独立仲裁期。
2. **审计者质押无自主提款**：质押金只能通过 `slashAuditor` 罚没归 owner，长期看不激励诚实审计；
   可加 `unstake`（带离场延迟）作为后续改进。

### 低
3. **`reportHash` 未与登记的 `codeHash/metadataHash` 绑定校验**：链上无法判断报告是否确实对应
   该版本内容；当前由链下 `auditor/submit.py` 的预检查保证（status、codeHash 一致才广播）。
   可考虑在事件里同时携带 `codeHash` 供看板交叉验证。
4. **`setSkillLicense` 更换后旧 License 仍持有 MINTER_ROLE**：两套地址可被 owner 单独改，交叉
   而变（registry 指向新 license、新 license 未接线）时 mint 会被 `NoAuditor` 拦住，失败安全；
   建议部署脚本保持两条接线原子完成（现有 Deploy.s.sol 已如此）。
5. **publisher 可用另一地址质押并"自审"**：地址层面的 `SelfAuditForbidden` 无法防多账号；
   属于哺乳期市场通用风控问题，靠 owner 仲裁兜底。
6. **`register` 不校验 `repo` / 哈希非零**：允许登记空 repo 或全零哈希，垃圾数据会占存储；门禁
   侧会因哈希比对失败拒绝，影响有限。

## 测试

- `cd contracts && forge test -vv`：3 个套件 103 个测试全部通过（含重入、拒收、角色轮换用例）。
- 事后未改动任何合约代码，无需新增回归。
