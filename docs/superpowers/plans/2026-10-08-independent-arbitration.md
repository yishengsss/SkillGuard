# Independent Arbitration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 取消恶意判定奖金，通过独立仲裁结算冻结押金，并提供可实际操作的网页闭环。

**Architecture:** 保留现有 SkillRegistry/SkillLicense 接线和 ABI 中的已有查询形状，新增仲裁案件与领取余额。后端区分新旧协议能力；Agent 提交暂定恶意报告，独立仲裁钱包通过独立页面签名最终裁决。安装只接受最终 Verified。

**Tech Stack:** Solidity 0.8.24 / Foundry、Python 3.11 / Web3 / 当前 HTTP 服务、原生 HTML / ES modules；不增加生产依赖。

**Spec:** `docs/superpowers/specs/2026-10-08-independent-arbitration-design.md`（已确认）。

## Global Constraints

- MIN_DEPOSIT、AUDITOR_STAKE 均保持 `0.01 ether`；单位取部署网络原生币。
- 保持原状态 0..4，追加 ArbitrationPending=5、ArbitrationExpired=6；保持 skills 返回字段顺序。
- 仲裁期 `7 days`，`timestamp < deadline` 允许裁决；`timestamp >= deadline` 允许退款。
- 审计者始终不能获取发布者押金；确认恶意罚没至独立公共资金钱包，推翻退回发布者。
- 配置一次锁定；仲裁/公共资金地址非零、互不相同、均不等于 owner；每次案件也不能等于发布者或审计者。
- 状态变更使用领取余额，领取防重入；SAFE 也计入退款余额，不谎称已到账。
- 原审计与仲裁报告分别保留；新最终 reportHash 覆盖完整仲裁记录，原哈希保存于案件映射。
- 本轮不发送 BOT 交易、不切换实时部署、不改写历史报告或许可证、不复制私钥到工作树。
- 多层模型 Agent 是另外的未定需求；本次不把人工仲裁标为模型复核。

## Review Focus

1. 配置后 owner 转移给仲裁者/公共资金地址，不能破坏职责分离（Task 1）。
2. 收款地址拒绝原生币或重入，不能卡住状态结算或重复领取（Task 2）。
3. 待仲裁报告被误当最终恶意，或恢复交易重复提交（Task 3）。
4. 签名期间钱包/部署改变，过期准备交易不得用于新案件（Task 4）。
5. 老合约缺少新函数与 RPC 故障必须区分，不能把故障伪装成旧版并展示错误资金规则（Task 3/5）。

---

### Task 1: 合约身份与恶意报告冻结

**Files:** Modify `contracts/src/SkillRegistry.sol`; create `contracts/test/Arbitration.t.sol`; adapt `contracts/test/SkillRegistry.t.sol` setup.

**Interfaces:**
- `protocolVersion() external pure returns (uint256)` 返回 2。
- `configureArbitration(address arbiter_, address treasury_) external onlyOwner`，一次性配置。
- `arbiter()/treasury()/arbitrationConfigured()` 为公开查询。
- `arbitrations(bytes32 key)` 返回 `(address reporter, bytes32 originalReportHash, uint256 openedAt, uint256 deadline, bytes32 finalReportHash)`；仲裁者与公共资金地址配置后不可变。
- 仲裁裁决、到期释放与领取接口由 Task 2 实现；本任务只交付配置与案件冻结，不调用尚未实现的余额接口。

- [ ] 写失败测试：`testMaliciousReportFreezesDepositAndDoesNotRewardAuditor` 断言状态=5、deposit=原金额、审计者余额不增、NFT 数量=0。
- [ ] 写权限/状态测试：配置零地址/相同地址/owner 地址/重复配置拒绝；配置前 requestAudit 拒绝；发布者或审计者与受保护角色冲突拒绝；`transferOwnership` 给受保护地址拒绝。至少一个 ordinary owner 转移用例正常通过。
- [ ] 写案件记录测试：originalReportHash 等于提交哈希，openedAt 等于当前区块时间，deadline 等于 openedAt + 7 days，重复 submitReport 拒绝；没有配置不能锁入押金。
- [ ] Run `cd contracts && forge test --match-contract ArbitrationTest -vv`，确认新测试在当前实现失败。
- [ ] 实现上述接口与追加状态。submitReport(true) 仅冻结并记录案件；原报告哈希始终可查。保持普通 SAFE 铸证与旧退款行为，Task 2 统一转换为领取余额。
- [ ] 重跑目标测试并提交 `feat: freeze malicious deposits pending independent arbitration`。

### Task 2: 结算余额、防重入与资金守恒

**Files:** Modify `contracts/src/SkillRegistry.sol`, `contracts/test/Arbitration.t.sol`, `contracts/test/SkillRegistry.t.sol`。

**Interfaces:** 消费 Task 1 的冻结案件和不可变角色；新增 `resolveArbitration(string skillId,string version,bool confirmedMalicious,bytes32 arbitrationReportHash)`（仅仲裁者，截止前，非零哈希）、`expireArbitration(string skillId,string version)`（任何人，截止后），以及 `credits(address account) returns(uint256)`；`withdrawFunds() external nonReentrant` 将调用者余额清零后转账，失败回滚。事件 `FundsCredited(address recipient, bytes32 key, uint256 amount)`、`FundsWithdrawn(address recipient,uint256 amount)`。

- [ ] 写截止与权限测试：deadline-1 可裁决，deadline 仅可退款；错误仲裁者、零哈希、重复裁决拒绝，第三方无法改变退款受益人。
- [ ] 写失败测试：`testConfirmedMaliciousCreditsOnlyTreasury`、`testOverturnCreditsPublisherAndMints`、`testTimeoutCreditsPublisherWithoutLicense`、`testSafeReportCreditsPublisher`；均断言 deposit 清零、无审计者收益。
- [ ] 写 `testRejectingRecipientDoesNotBlockResolution`、`testFailedWithdrawPreservesCredit`、`testReentrantWithdrawCannotDoubleClaim`；修改收款方接受交易后可再次领取。断言空余额领取拒绝。
- [ ] 加 fuzz 资金守恒测试：每条结算分支后 contract.balance 等于所有未结算 deposit + auditorStake + credits 总和；允许超过最低金额的原始发布押金，结算全部原金额。
- [ ] Run `cd contracts && forge test --match-contract ArbitrationTest -vv` 验证失败，实现裁决、超时、余额结算和 withdrawFunds。resolve 更新 `s.reportHash` 为最终报告哈希并保持原 `s.auditor` 身份；案件保存原哈希；推翻时许可证使用最终报告哈希。不自动罚没被推翻报告的审计质押。
- [ ] 更新旧测试“恶意奖励”断言为“冻结→仲裁→领取”；原 owner slashAuditor 行为仍需单独通过旧权限测试。
- [ ] Run `cd contracts && forge test`，全部通过后提交 `feat: settle arbitration funds through pull withdrawals`。

### Task 3: 新旧能力识别、链查询与 Agent 回执

**Files:** Modify `ops/chain.py`, `ops/config.py`, `auditor/submit.py`, `auditor/recovery.py`, `auditor/agent.py`; create `ops/arbitration.py`; tests `tests/test_ops_chain.py`, `tests/test_submit.py`, `tests/test_agent.py`。

**Interfaces:**
- `registry_capabilities(w3,registry) -> dict` 返回 `{protocolVersion,arbitrationSupported}`；旧合约确定性缺少 selector 返回1，RPC/无代码错误传播为不可用。
- 新链详情字段 `{arbitration: {reporter,originalReportHash,openedAt,deadline,finalReportHash,arbiter,treasury}|null}`；旧字段不变。
- `ArbitrationService(root).list(scope) -> list[dict]`、`.case(scope,key) -> dict` 读取真实案件和两份报告；字段缺失不能伪造默认时间或状态。

- [ ] 写能力测试：已知旧合约=1，新合约=2，网络失败不返回1，无字节码拒绝；为旧部署保存必要 ABI/能力识别样例，不能用新版常量替代旧合约查询。
- [ ] 写报告提交测试：新协议 malicious 确认回执状态=5、原哈希对应，返回“待独立仲裁”；旧协议仍校验状态=4并明确旧奖励规则。SAFE 一直验证状态=3。
- [ ] 写恢复测试：实际已接受暂定恶意交易的响应丢失，恢复原 txHash；不增加新 nonce；第三次 run_once 跳过状态5。
- [ ] Run 对应测试确认失败；实现版本识别、新 ABI 查询及回执/恢复条件，Agent journal 增加 `arbitration_pending`，保留真实 tx 与案件哈希。
- [ ] Run `python -m pytest tests/test_ops_chain.py tests/test_submit.py tests/test_agent.py -q`，通过后提交 `feat: recognize arbitration protocol and pending audit receipts`。

### Task 4: 仲裁、退款与领取的真实钱包 API

**Files:** Modify `ops/app.py`, `ops/transactions.py`, `ops/reports.py`, `ops/arbitration.py`; create `tests/test_ops_arbitration.py`。

**Interfaces:**
- GET scoped `/api/arbitration/cases`、`/api/arbitration/cases/<key>`。
- POST `/api/arbitration/prepare` `{action:'resolve',key,decision:'safe'|'malicious',reason,evidence}`；POST `/api/arbitration/confirm` 使用已有 `{preparedId,txHash}`。
- POST `/api/funds/prepare` `{action:'expire',key}` 或 `{action:'withdraw'}`；POST `/api/funds/confirm` 同上。沿用 SIWE/CSRF/Origin、部署 revision、EOA 及真实回执校验。
- `ArbitrationService.prepare_decision(scope,key,session,decision,reason,evidence) -> dict`：核对来源哈希与原报告，原报告完整复制，追加 `originalReportHash` 和 `arbitration:{arbitrator,decision,reason,evidence}`；保留原 level/findings/auditor，不伪造原审计安全结论，保存后再准备交易。
- reason 非空且最多 4000 字符；evidence 1..100 项，每项 `{file,line,quote,explanation}` 使用现有只读快照证据校验，字符限制沿用 reasoner。链上只检查权限和非零哈希，不声称验证证据语义。

- [ ] 写失败测试：非仲裁者、公共资金钱包、错链、过期案件、报告篡改、路径逃逸/虚假引用、陈旧 revision 均拒绝；客户端请求受益人字段无效。
- [ ] 测试签名期间钱包改变、重放准备记录、receipt from/to/input/value 不匹配不得完成；确认结果校验最终状态、哈希、原审计身份和 credits 受益人。
- [ ] 测试保存失败不准备链上操作；仅领取本钱包 credits；旁观者可准备到期释放但无法改变退款地址。
- [ ] Run `python -m pytest tests/test_ops_arbitration.py -q` 确认失败；按现有 Transactions 存储/确认机制实现上述路由，不接收私钥。
- [ ] 重跑权限/报告/交易测试，通过后提交 `feat: add independent arbitration and fund withdrawal APIs`。

### Task 5: 部署向导、独立仲裁页及旧版提示

**Files:** Modify `ops/admin.py`、`contracts/script/Deploy.s.sol`, `tests/roles_fixtures.py`, `web/pages/admin.html`, `web/pages/admin.mjs`, `web/pages/publish.mjs`, `web/pages/detail.mjs`, `web/assets/shell.mjs`, `ops/app.py`; create `web/pages/arbitration.html`, `web/pages/arbitration.mjs`, `tests/web/arbitration.test.mjs`; adapt `tests/test_ops_deploy.py`, `tests/web/deployment-recovery.test.mjs`。

**Interfaces:**
- 独立路由 `/arbitration`，共享角色导航与当前 Apple 风格。
- 新部署步骤末尾追加 `configure_arbitration`，请求体 `{step,arbiter,treasury,creationTxHashes}`；冻结该草稿地址，刷新后恢复同一地址与5步回执。仅新部署配置，不修改当前旧合约。
- Deploy script 使用 `ARBITER_ADDRESS`、`TREASURY_ADDRESS`，缺失时拒绝完成启用；测试接口明确为 `runWithKey(uint256 deployerPrivateKey,address owner,address arbiter,address treasury,string outputPath) returns(address registry,address license)`；修改 `contracts/test/Deploy.t.sol`。`RoleFixture` 增加独立 `.arbiter`、`.treasury` 公开测试账户（六个不同账户），所有 fixture 同步配置。
- 激活新部署前核验 protocolVersion=2、配置锁定、地址职责分离及两合约接线；部署记录保存协议版本和角色地址。

- [ ] 在 `AdminService.prepare/activate` 的现有部署流程写失败测试：缺角色、地址冲突、配置回执不符、重复/乱序步骤、刷新恢复均拒绝错误激活。
- [ ] 写前端测试：待仲裁/到期状态标签；旧版明确“恶意押金给审计者”；RPC 故障不显示新版启用；非仲裁钱包只能读；结算显示“可领取”且独立领取；钱包变更清除裁决草稿。
- [ ] Run `node --test tests/web/*.test.mjs` 与 `python -m pytest tests/test_ops_deploy.py -q` 验证失败；实现向导额外回执及仲裁页，显示两份报告、被冻结押金、链上截止时间、裁决原因与真实 tx。
- [ ] 发布者页加入超时释放/余额领取；详情页展示暂定与最终结论；catalog/安装状态支持5/6但不能提供安装入口。复用现有输入和按钮，不加入假 Agent 日志。
- [ ] 重跑上述测试、浏览器验证手机/桌面布局与只读角色状态；提交 `feat: add arbitration workspace and explicit deposit settlement UI`。

### Task 6: 完整闭环、文档与独立审查

**Files:** Modify `tests/test_roles_e2e.py`, `tests/role_demo.py`, `README.md`; create `docs/independent-arbitration.md`；按实际路径补充 gate 状态拒绝测试。

- [ ] 写独立 Anvil HTTP 场景：公开钱包发布→质押→模拟协议 Agent 产生恶意→状态5/押金仍冻结→独立仲裁者确认→公共钱包领取；审计者余额除 gas 外不增加。
- [ ] 写推翻场景：状态5不可安装→真实仲裁回执→Verified/许可证→发布者领取→安装；原报告与最终报告哈希均可核对，最终报告包含仲裁身份，不能误称原审计者认定安全。
- [ ] 写到期场景：warp 时间至deadline，第三方释放→状态6/退款归发布者→安装拒绝；重复释放和领取拒绝。覆盖 SAFE 可领取退款、原 SUSPICIOUS 人工裁决及交易恢复。
- [ ] Run `cd contracts && forge test`；`python -m pytest -m 'not anvil' -q`；`python -m pytest tests/test_roles_e2e.py -q`；`node --test tests/web/*.test.mjs`。真实 API 只读公开样例另留证据，不能把模拟服务当 AI 验收。
- [ ] 请求一位独立 reviewer 审查完整分支：资金守恒、角色替换、截止边界、重放/重入、报告身份、新旧兼容；修复 Critical/Important，再运行受影响检查。
- [ ] 在原项目同步前逐文件比较基线，保留 .env、deployments.json、reports、installed 和 broadcast；已有旧合约运行时明显提示新规则尚未部署。保存本地新协议浏览器预览与链上回执证据，提交最终验收文档。
- [ ] 交付代码与本地验收，不自动部署 BOT。下一步用户配置独立钱包并授权新部署，届时走验证过的向导。

## Execution Handoff

建议 Native：六项任务共享同一套合约接口与状态，当前会话实现能减少接口漂移，完成后安排独立安全审查。用户审阅本计划并选择执行方式后开始代码实施。
