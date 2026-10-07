# SkillGuard 多页面与独立钱包 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 完成各角色连接自己钱包、自定义 ZIP 发布、可观察的自动审计和安装门禁这一条真实闭环。

**Architecture:** 保留 Python 本机服务、冻结合约、现有扫描器和 MCP 门禁。按身份、包存储、链上查询与交易核验、Agent 运行记录分离模块；浏览器负责人的签名，服务钱包只负责自动审计。共享前端模块服务六个独立页面，不引入应用框架。

**Tech Stack:** Python 3.11、现有 web3/eth-account、SQLite/zipfile/http.server/fcntl 标准库、HTML/CSS/ES modules、现有 viem 2.38.0、Foundry、pytest、Node 内置测试。

**Spec:** [已确认规格](../specs/2026-10-08-role-pages-design.md)。实现前同时阅读 `CLAUDE.md`、`SPEC.md` 和该规格；本计划是待审阅的实施文档，所列功能尚未实现。

## Global Constraints

- 保持 contracts/src、规则、现有样本和报告哈希算法不变；不增加 Git 拉取、公共托管、多审计者共识、沙箱执行或新的经济机制。
- 后端继续运行在本机，默认绑定 127.0.0.1。允许的操作网络限于本地 Anvil 31337 和 BOT Testnet 968。
- 以现有 BOT 配置读取真实历史；新增交易流程在隔离 Anvil 验收。原 BOT 部署不重建，不使用或复制原 .env 私钥。
- 网页 API 不使用 PRIVATE_KEY 或 OWNER_PRIVATE_KEY 代签人的动作。自动 Agent 使用 AUDITOR_PRIVATE_KEY，不自动质押，不调用 LLM，不执行上传代码。
- SIWE 挑战有效期为 5 分钟，会话有效期为 30 分钟；HttpOnly、SameSite=Strict 主机 Cookie、独立 CSRF token、Host/Origin 校验；账户、网络或部署作用域变化使会话失效。
- 压缩文件最多 10 MiB，解压总量最多 20 MiB，最多 512 个文件；name、version 分别最多 128、64 个 UTF-8 字节。
- 普通文件设为 0644，原有任一执行位的文件设为 0755，拒绝 setuid/setgid 等特殊位。未登记包仅所属钱包可读取；登记后开放经过校验的 manifest 和文件列表。
- codeHash、metadataHash、报告规范化和报告哈希继续使用现有函数；最终成功来自回执与链上状态。旧日志缺失如实显示，不推算百分比。
- 先保存报告再广播；失败游标可重试；已广播未确认交易先核验原交易，不能换 nonce 盲目重发。
- 任意外部文本用文本节点呈现；页面不接受服务器任意路径，不暴露密钥、签名、带凭据 RPC 或 .env。
- 六个页面为 `/`、`/publish`、`/audit`、`/admin`、`/skills/<key>`、`/install`；支持直接刷新、键盘操作和窄屏。

## Review Focus

1. 钱包在签名弹窗期间换账户或换链：迟到的签名/交易结果不得恢复旧会话或确认错误账户的操作（Task 6）。
2. ZIP 在 macOS 上出现 Unicode 规范化、大小写及文件/目录冲突：拒绝冲突而非静默覆盖（Task 2）。
3. 节点接受广播但响应丢失，或进程在响应前退出：从持久化的原交易恢复，不生成第二笔结论交易（Task 4）。
4. 两个管理员同时激活部署，或激活时旧 Agent 正在发送：保留一致配置，旧作用域完成/停止后再切换（Tasks 3、5）。
5. 历史报告损坏/缺失，或报告哈希属于另一条链/registry：单独显示链上结果和报告可用性，不能冒认已核对（Task 7）。

## 文件与接口约定

所有路径相对仓库根。新模块只承担列出的责任，旧 CLI 辅助函数保留；服务入口不继续堆放业务逻辑。

| 文件 | 责任 |
|---|---|
| `ops/models.py`、`ops/config.py` | 数据类型、公开配置、部署 revision、作用域核验与现有 RPC 读取 |
| `ops/auth.py`、`ops/app.py` | SIWE、会话、请求来源/CSRF、受控路由与响应 |
| `ops/packages.py`、`gate/identity.py` | ZIP 安全解包、包所有权与快照、发布/安装共用身份路径校验 |
| `ops/chain.py`、`ops/transactions.py` | 固定区块目录、钱包交易参数、回执及状态核验 |
| `ops/admin.py` | 冻结合约部署材料、接线核验、原子激活、slashAuditor |
| `auditor/journal.py`、`auditor/recovery.py` | SQLite 事件/任务/交易意图、原交易恢复 |
| `auditor/worker.py`、`ops/agent_service.py` | CLI/网页共有 worker 锁与循环、网页启动/停止适配 |
| `ops/reports.py`、`ops/install_service.py` | 作用域内报告读取、已登记包的现有门禁适配 |
| `ops/server.py` | 保留启动与旧 CLI 辅助函数；HTTP 委托 OpsApplication |
| `auditor/agent.py`、`auditor/submit.py` | 在真实处理/提交点接入记录和恢复，不复制规则 |
| `gate/mcp_server.py` | 复用新的身份片段校验，其余检查/复制语义保留 |
| `web/assets/{api,wallet,shell,transactions}.mjs`、`web/assets/app.css` | 共享请求、钱包、导航、签名与状态呈现 |
| `web/pages/{catalog,publish,audit,admin,detail,install}.{html,mjs}` | 各角色页面的标记与行为 |
| `tests/test_ops_{auth,packages,chain,transactions,admin,http}.py` | 后端权限、上传、实际回执及路由测试 |
| `tests/test_agent_{journal,recovery,worker}.py` | 运行记录、广播恢复、进程锁与停止测试 |
| `tests/test_ops_{reports,install}.py`、`tests/web/*.test.mjs` | 报告/门禁、共享钱包和页面行为测试 |
| `tests/roles_fixtures.py`、`tests/test_roles_e2e.py`、`tests/role_demo.py` | 公开本地钱包、动态技能夹具、完整 Anvil 流程、浏览器验收入口 |
| `README.md`、`docs/ROLE-PAGES-ACCEPTANCE.md` | 实际运行说明和验收证据 |

固定类型：`ChainScope(chain_id:int, registry:str, license:str, deployment_block:int, revision:str)`；`WalletSession(address:str, scope:ChainScope, expires_at:int)`；`HTTPReply(status:int, headers:dict[str,str], body:bytes)`。地址为 checksum，key/hash 为严格的 32 字节十六进制；wei 和 gas 在 JSON 中用十进制字符串。revision 是当前部署 JSON 规范化内容的 SHA-256。API 成功/失败统一 `{ok:true,data}` / `{ok:false,error,code}`，code 为稳定的错误标识。

`PackagePreview` 字段：`packageId,publisher,manifest,files,codeHash,metadataHash,source`。`PreparedTx` 字段：`id,scopeRevision,chainId,from,to,data,value,estimatedGas,estimatedFee`；创建合约时 `to=null`。`TxConfirmation` 字段：`preparedId,txHash,status,blockNumber,error`，status 为 `pending|confirmed|failed`。这些使用 TypedDict 定义；服务端保存 prepared 参数，confirm 不相信客户端重传参数。

链/任务标识用 `(chain_id, registry.lower(), key)`；运行记录另有 `runId,eventId`。新存储位于 `.cache/ops/`、`.cache/packages/`、`.cache/agent-journal.sqlite3`；现有 `reports/` 和 `.cache/agent_cursor.json` 语义保留。费用不确定时显示读取/估算失败，不写成 0。

HTTP 参数固定：auth challenge `{address}`、verify `{message,signature}`；packages POST 原始 ZIP、GET `/<packageId>` 读预览。publisher prepare `{action,packageId}` 用于 register，`{action,key}` 用于 request_audit；auditor prepare `{action,valueWei}` 质押或 `{action,key,decision}` 裁决；admin prepare `{step,creationTxHashes?,auditor?}`，其中 slashAuditor 的 step 为 `slash_auditor`。三个角色的 confirm 均为 `{preparedId,txHash}`；activate `{revision,txHashes}`；install check/execute `{key}`。GET skills/detail/reports、agent status/runs/events 带当前 `chainId,registry`，events 另带 `runId,after`；作用域不匹配返回 409，页首次进入使用 config 的真实作用域。

## 执行前置与保存点

执行方法由用户审阅本计划后选择。执行时先读取 using-git-worktrees 技能，优先建立 `codex/skillguard-role-pages` 隔离工作区；必须把原目录现有公开代码改动和公开未跟踪测试一并带入基线，不能只从 HEAD 丢失前轮修复。记录原始 diff 和文件摘要，按明确名单复制内容；排除 .env、缓存、报告、安装目录、广播记录及其他凭据。隔离工作区的基线提交明确标记为既有修复。

Foundry 库使用已安装的依赖；缺失时在隔离区按当前锁定版本恢复。本地夹具由公开 Anvil 助记词派生钱包，测试配置仅在隔离区生成并忽略。BOT 历史核验留在原目录并只读报告/公开部署信息；不复制整个原目录。

先在隔离区按 nodeid 排除已知旧 8545 集成项运行基线单元回归，记录实际数量及 skip；Task 1 在 conftest 注册 anvil 标记并标记 `test_ops_end_to_end_on_anvil`、依赖 anvil_chain 的 Agent 测试及依赖 anvil 的 MCP 测试。此后统一用 `-m 'not anvil'`，不得碰用户节点；Task 8 新集成标记 anvil 但由专用命令实际运行，必须通过而非 skip。每个 green 后只提交该任务文件，不使用 `git add -A` 包含其他工作。

### Task 1: 钱包会话与受控 HTTP 基础

**Files:** Create `ops/models.py,config.py,auth.py,app.py`、`tests/test_ops_auth.py`；Modify `ops/server.py`、`tests/conftest.py`、`tests/test_review_regressions.py` 的旧 HTTP 代签断言。

**Interfaces:** Consumes 现有 `_rpc_url()` 配置读取方式。Produces `load_scope(root:Path)->ChainScope`、`public_config(root:Path)->dict`、`AuthError`、`WalletAuth(root:Path).challenge(address:str,scope:ChainScope,origin:str)->str`、`verify(message:str,signature:str,scope:ChainScope,origin:str)->tuple[str,WalletSession]`、`require(token:str,scope:ChainScope)->WalletSession`、`logout(token:str)->None`，以及 `OpsApplication(root:Path).handle(method:str,path:str,headers:dict,body:bytes)->HTTPReply`。`OpsHTTPServer(address,handler=Handler,*,project_root:Path|None=None)` 支持夹具注入 root，默认仍用原 PROJECT_ROOT。

- [ ] **1. 写失败测试。** `test_siwe_nonce_is_single_use` 首次 verify 等于签名者，第二次抛 AuthError；`test_challenge_and_session_expiry` 在 +301/+1801 秒分别拒绝挑战/会话。另测错误 signer/domain/URI/chain/revision、重启/并发 nonce、错误 Cookie/跨来源、合约钱包、缺审计 key/坏配置。旧 HTTP 代签端点须返回 410 且旧函数零调用；CLI 辅助函数测试保留。

```python
token, session = auth.verify(message, signature, scope, origin)
assert session.address == wallet.address
with pytest.raises(AuthError):
    auth.verify(message, signature, scope, origin)
```

- [ ] **2. 运行 red。** `python -m pytest tests/test_ops_auth.py -q`；预期新模块缺失或上述行为失败，确认测试到达目标。
- [ ] **3. 实现接口。** 用现有 eth-account EIP-191 消息恢复，服务端生成并逐字核对 ERC-4361 消息；nonce 用 token_hex(16)，SQLite 原子消费，会话 token 只保存摘要。domain/URI 含允许 Origin 端口，chainId/作用域匹配；Cookie Path=/、上述 TTL/标志；EOA 在实际链无合约代码。先接 config/session/auth，旧代签端点 410，未知路径 404。Handler 有限读取后调用 handle，不留业务分支；保留 JSON/来源/CSRF 限制，安装只需本机会话。conftest 排除旧 8545 项并清理测试子进程的真实角色环境变量。
- [ ] **4. 运行 green。** `python -m pytest tests/test_ops_auth.py tests/test_review_regressions.py -q -m 'not anvil'`，全部选中项通过。公开 owner 来自链、登录地址来自签名、服务审计地址由 AUDITOR_PRIVATE_KEY 派生，响应不含密钥。
- [ ] **5. 保存点。** 仅提交本任务文件，消息 `feat: authenticate role operations with wallet sessions`。

### Task 2: 自定义 ZIP 包与发布/安装身份一致性

**Files:** Create `ops/packages.py`、`gate/identity.py`、`tests/test_ops_packages.py`；Modify `gate/mcp_server.py`、`ops/app.py`。

**Interfaces:** Consumes WalletSession、`capture_skill(path,source_root=root)`、`code_hash(snapshot)`、`metadata_hash(snapshot)`。Produces `safe_identity_component(value:str,max_bytes:int)->str|None`、`PackageError`、`PackageStore(root:Path).upload(data:bytes,session:WalletSession)->PackagePreview`、`preview(package_id:str,session:WalletSession)->PackagePreview`、`capture(package_id:str,publisher:str)->SkillSnapshot`、`resolve_source(source:str)->Path`。

- [ ] **1. 写失败测试。** `test_custom_zip_hashes_match_scanner_and_gate` 使用两个新名字及包装目录；真实 manifest/hash 一致，执行位为 0755，跨钱包草稿拒绝。名称测试 128/129、64/65 字节及安全中文名复制。`test_zip_filesystem_aliases_are_rejected` 拒 NFC/NFD、大小写、重复和文件-目录冲突；参数表拒 10 MiB+1、20 MiB+1、513 文件、路径逃逸、symlink/FIFO/特殊位、秘密/忽略目录、加密/损坏、字段非法及虚假解压大小，失败不留可发布目录，源内容改动拒绝。

```python
preview = store.upload(custom_zip, publisher_session)
captured = store.capture(preview['packageId'], publisher_session.address)
assert preview['codeHash'] == '0x' + code_hash(captured).hex()
assert preview['metadataHash'] == '0x' + metadata_hash(captured).hex()
```

- [ ] **2. 运行 red。** `python -m pytest tests/test_ops_packages.py -q`，预期上述接口缺失/断言失败。
- [ ] **3. 实现接口。** ZIP 使用 zipfile 逐项/分块限额读取，先完整校验再写临时目录并原子发布；source 为 `.cache/packages/<publisher>/<packageId>/source`，ID 从实际内容、权限和钱包计算，不直接使用 archive/name 路径。共用 safe_identity_component：不自动改写名字，拒绝空白首尾、斜杠/控制字符/单独点路径，按 UTF-8 字节上限校验；MCP name 用 128、version 用 64。包不得携带哈希函数忽略的秘密/目录内容，额外拒绝 `.cache`、`__pycache__`，明确返回原因；存储索引无需私钥。
- [ ] **4. 运行 green。** `python -m pytest tests/test_ops_packages.py tests/test_mcp_server.py tests/test_review_regressions.py -q -m 'not anvil'`，全部选中项通过，旧路径逃逸与复制权限断言仍成立。
- [ ] **5. 保存点。** 仅提交本任务文件，消息 `feat: accept immutable custom skill archives`。

### Task 3: 链上目录、人的交易准备/核验与管理员部署

**Files:** Create `ops/chain.py,transactions.py,admin.py`、`tests/test_ops_chain.py,test_ops_transactions.py,test_ops_admin.py`；Modify `ops/app.py`。

**Interfaces:** Consumes ChainScope、WalletSession、PackageStore。Produces `TransactionError`、`ChainRepository(root:Path).catalog(scope:ChainScope,publisher:str|None=None)->list[dict]`、`detail(scope:ChainScope,key:str)->dict`、`TransactionService(root:Path).prepare(action:str,session:WalletSession,payload:dict)->PreparedTx`、`confirm(prepared_id:str,tx_hash:str,session:WalletSession)->TxConfirmation`；`AdminService(root:Path).prepare(step:str,session:WalletSession,payload:dict)->PreparedTx`、`confirm(prepared_id:str,tx_hash:str,session:WalletSession)->TxConfirmation`、`activate(session:WalletSession,revision:str,tx_hashes:list[str])->ChainScope`。公开配置无部署或错链时只读并展示配置原因，不允许任何钱包自授初始管理员；隔离夹具使用 CLI 创建初始部署。

- [ ] **1. 写失败测试。** `test_confirm_requires_exact_sender_call_and_receipt` 拒错误 from/to/data/value/链，未出块 pending，失败 receipt 为 failed，真实 tuple 匹配才 confirmed。`test_concurrent_activation_keeps_one_configuration` 同 revision 仅一次激活成功。另测 RPC 错误/空代码、两发布者过滤、重复版本、异钱包押金、非 owner、四步拒签续办、伪造字节码/回执、重复/乱序回执；失败保留原部署字节。

```python
assert tx_service.confirm(plan['id'], unmined_hash, session)['status'] == 'pending'
with pytest.raises(TransactionError):
    tx_service.confirm(plan['id'], wrong_sender_hash, session)
assert original_deployment_bytes == deployment_path.read_bytes()
```

- [ ] **2. 运行 red。** `python -m pytest tests/test_ops_chain.py tests/test_ops_transactions.py tests/test_ops_admin.py -q`，确认对应行为失败。
- [ ] **3. 实现接口。** 固定同一个实际区块读 skills、owner、stake、tokenOfKey/licenses/ownerOf；按 deploymentBlock 分段取登记日志，目录缓存带 block/readAt，失败不返回伪造空目录。actions 仅 `register,request_audit,stake,human_decision,slash_auditor`；前两项验证包所有权及链上 publisher，deposit/stake/余额/估 gas 从链读取；admin 每次核 owner，审计人工动作匹配服务钱包。prepared 保存作用域、完整参数和待办阶段，10 分钟内可发送；已发送确认不因此 TTL 丢失。stake 金额必须明确填写并不低于实际缺额；额度用 wei 整数。人工报告接口在 Task 7 接通。
  AdminService 读取 forge build 的冻结 ABI/creation/runtime bytecode，四步随真实回执取得地址；不运行私钥广播脚本。激活核验全部交易、constructor owner、准确 runtime code、双方 owner/接线/minter、chainId、revision，再 fsync+atomic replace 部署 JSON；Task 5 接入 worker 协调，此前同样持有 config 写锁。
- [ ] **4. 运行 green。** `python -m pytest tests/test_ops_chain.py tests/test_ops_transactions.py tests/test_ops_admin.py -q -m 'not anvil'`，全部通过。
- [ ] **5. 保存点。** 仅提交本任务文件，消息 `feat: verify wallet transactions and deployment activation`。

### Task 4: Agent 真实事件与原交易恢复

**Files:** Create `auditor/journal.py,recovery.py`、`tests/test_agent_journal.py,test_agent_recovery.py`；Modify `auditor/agent.py,submit.py`。

**Interfaces:** Consumes AgentContext、process_request/run_once、submit_and_save_report 现有签名。Produces `Journal(root:Path).begin(chain_id:int,registry:str,key:str,request_block:int)->str`、`emit(run_id:str,stage:str,payload:dict)->int`、`runs(chain_id:int,registry:str,key:str|None=None)->list[dict]`、`events(run_id:str,after:int=0)->list[dict]`、`recover_submission(ctx:AgentContext,run_id:str,journal:Journal)->str`，结果 `absent|pending|confirmed|failed|conflict`。提交函数新增可选 `lifecycle:Callable[[str,dict],None]|None=None`；无 callback 的旧调用保持兼容。auditor 核心只依赖自己的模块和已有库，不导入 ops.models；web 层把 ChainScope 拆成原始字段。

- [ ] **1. 写失败测试。** `test_events_follow_actual_audit_actions` 检查请求→来源→核哈希→扫描→报告落盘→意图→广播→回执，SUSPICIOUS/落盘失败零广播。`test_lost_broadcast_response_reuses_original_transaction` 节点接受后超时，重启确认原 hash，结论交易仍为 1。另测 receipt 超时、DB/fsync 失败、原交易 pending/失败/其他结论、原 nonce 冲突、游标失败重试和同块多请求。

```python
assert stages.index('report_saved') < stages.index('tx_intent')
assert journal.events(run_id)[-1]['stage'] == 'receipt_confirmed'
assert recovered_hash == original_hash
assert chain.report_transaction_count == 1
```

- [ ] **2. 运行 red。** `python -m pytest tests/test_agent_journal.py tests/test_agent_recovery.py -q`，预期缺记录/重发行为失败。
- [ ] **3. 实现接口。** SQLite WAL、每操作独立连接、事务写入+同步，保存范围/请求/轮次/事件及最终报告引用；不从日志字符串倒推阶段。Agent 从同一快照先用已有 hash 函数核对，再调用原扫描器并保留原报告核验；ctx 增加可选 journal 和停止检查。报告文件使用现有原子 save_report；SUSPICIOUS 的 scoped 索引指向实际内容哈希，兼容现有 pending 文件。日志仅安全阶段/错误类别与受控原因。
  `_send` 广播前持久化已签交易 hash、nonce、完整 unsigned 参数和报告 hash；失败零广播。恢复先查 receipt/原交易/链上报告；未找到且 nonce 未占用才重新签名、核对 hash 并广播完全相同原交易，冲突显示 conflict，不换 nonce。恢复广播先验证保存报告真实哈希。
- [ ] **4. 运行 green。** `python -m pytest tests/test_agent_journal.py tests/test_agent_recovery.py tests/test_agent.py tests/test_submit.py tests/test_review_regressions.py -q -m 'not anvil'`，全部选中项通过。
- [ ] **5. 保存点。** 仅提交本任务文件，消息 `feat: persist audit events and recover pending submissions`。

### Task 5: 常驻 worker、CLI 互斥与部署切换

**Files:** Create `auditor/worker.py`、`ops/agent_service.py`、`tests/test_agent_worker.py`；Modify `auditor/agent.py` CLI 入口、`ops/app.py,admin.py`。

**Interfaces:** Consumes Journal、run_once 和 scoped cursor。Produces `AgentLease(root:Path,chain_id:int,registry:str,auditor:str,source:str)` 上下文管理器；`ManagedAgent(root:Path).start(session:WalletSession)->dict`、`stop(session:WalletSession)->dict`、`status(scope:ChainScope)->dict`、`drain_for_activation(revision:str,timeout:float=30)->None`；`run_worker(ctx:AgentContext,stop:threading.Event,poll:float=2)->int`。

- [ ] **1. 写失败测试。** `test_cli_and_managed_agent_share_wallet_lease` 两进程只有一方获锁；`test_stop_preserves_unstarted_request_cursor` 未开始请求重启后仍处理；`test_activation_waits_for_old_scope_broadcast` 等当前事务结束，不自动启动新 worker。覆盖四种状态、CLI 来源、无质押/错钱包、进程 crash、RPC 异常和激活竞争；失败保留原配置。

```python
assert first_worker.acquired is True
assert second_worker.acquired is False
manager.stop(auditor_session)
assert journal.unstarted_request_count == 1
```

- [ ] **2. 运行 red。** `python -m pytest tests/test_agent_worker.py -q`，确认互斥/停止/切换行为尚未满足。
- [ ] **3. 实现接口。** fcntl 非阻塞锁跨进程互斥，文件名用 chain+auditor 摘要，锁覆盖不同 registry 的同一钱包以防 nonce 冲突；记录 owner/source/实例 ID，心跳每 2 秒、10 秒无心跳显示离线，但不凭心跳抢占 OS 锁。网页 worker 使用受管理后台线程，CLI 同用 run_worker；启动核链、字节码、审计余额/质押，不自动押钱，非服务钱包禁止管理。
  心跳监测实际存活线程和持有实例锁，等待回执期间也有效；处理阶段只在真实动作时记录。stop 返回 stopping，当前广播/确认完成后停，超时原交易可恢复；cursor 不越过未开始请求。激活设置共享 transition 阻止新任务，CLI/网页 worker 核 revision，30 秒未完成则 409 并保留配置；不杀未知进程。
- [ ] **4. 运行 green。** `python -m pytest tests/test_agent_worker.py tests/test_agent.py tests/test_review_regressions.py -q -m 'not anvil'`，全部选中项通过。
- [ ] **5. 保存点。** 仅提交本任务文件，消息 `feat: manage audit worker lifecycle across roles`。

### Task 6: 共享钱包模块、技能库与自定义发布页

**Files:** Create `web/assets/{api,wallet,shell,transactions}.mjs,app.css`、`web/pages/{catalog,publish}.{html,mjs}`、`tests/web/{wallet,publisher}.test.mjs`、`tests/test_ops_http.py`；Modify `ops/app.py`、`web/ops.html`、`tests/test_review_regressions.py` 的旧 HTML 源码切片测试。

**Interfaces:** Consumes config/auth/packages/skills/publisher API。Produces `createWallet(provider,onChange)` 返回 `connect(),authenticate(),send(prepared),disconnect()`；`api(path,{method,body,zip})->Promise<object>`（返回 envelope.data，失败抛受控 ApiError）；`sendAndConfirm(prepared,confirmPath,onState)->Promise<TxConfirmation>`；`renderShell(pageId,config)`。所有 HTML 直接走白名单路由。

- [ ] **1. 写失败测试。** `wallet.test.mjs` 检查签名时换账户/链不恢复旧会话，无 provider 可浏览；`publisher.test.mjs` 检查真实上传、登记成功/押金拒签后续办、当前钱包过滤。另测 CDN失败、大 wei、过期会话、脚本样式外部文本；HTTP 拒 .env/../symlink/测试夹具/任意报告路径。

```javascript
await wallet.connect();
const signing = wallet.authenticate();
provider.changeAccounts([secondAddress]);
await assert.rejects(signing, /账户|会话/);
assert.equal(sessionRestored, false);
```

- [ ] **2. 运行 red。** `node --test tests/web/wallet.test.mjs tests/web/publisher.test.mjs`；`python -m pytest tests/test_ops_http.py -q`，确认目标缺模块或行为失败。
- [ ] **3. 实现接口。** 复用 viem 固定版本动态加载，钱包 EIP-1193 分连接/SIWE/发送阶段；仅允许两种操作网络，错链不发送。账户/链/部署变更递增 generation，核弹窗后的地址+链+generation，迟到 verify 响应须注销，不能重新启用按钮。经钱包会话的请求携带当前地址一致性头，服务端与 session 地址不符则 401，该头不授予权限。api 写前取得 CSRF，ZIP 用 application/zip；tx 的 from/data/value/to/chainId 与 prepared 一致。
  catalog 实际筛选；publish File input、真实预览、两笔签名进度与我的发布；依赖失败正文仍可见。导航公开，管理按钮只在对应页；ops.html 迁移入口，旧 HTML API 测试导入 api.mjs 保留 CSRF-before-POST 约束。HTTP 使用固定资源/MIME 白名单、scope 校验，支持直接刷新。
- [ ] **4. 运行 green。** `node --test tests/web/wallet.test.mjs tests/web/publisher.test.mjs` 和 `python -m pytest tests/test_ops_http.py tests/test_review_regressions.py -q -m 'not anvil'`，全部选中项通过。
- [ ] **5. 保存点。** 仅提交本任务文件，消息 `feat: publish custom skills from independent browser wallets`。

### Task 7: 审计运营、详情、管理员及安装页面

**Files:** Create `ops/reports.py,install_service.py`、`web/pages/{audit,admin,detail,install}.{html,mjs}`、`tests/test_ops_reports.py,test_ops_install.py`、`tests/web/roles.test.mjs`；Modify `ops/app.py,transactions.py`。

**Interfaces:** Consumes ChainRepository/Journal/ManagedAgent/AdminService 与现有 `check_skill`、`install_skill`。Produces `ReportService(root:Path).read(scope:ChainScope,hash:str)->dict`、`pending(scope:ChainScope,key:str)->dict`、`prepare_decision(scope:ChainScope,key:str,session:WalletSession,decision:str)->dict`；`InstallService(root:Path).check(scope:ChainScope,key:str)->dict`、`execute(scope:ChainScope,key:str)->dict`。ReportView 字段 `report,reportHash,reportMatchesChain,availability`，availability 为 present/missing/corrupt；技能详情另有 historyNote、events 与实际许可证数据。

- [ ] **1. 写失败测试。** `test_historical_result_without_logs_is_explicit`、`test_foreign_or_corrupted_report_is_not_verified`、`test_install_uses_only_registered_source_and_preserves_previous`；`roles.test.mjs` 检查详情 evidence 为文本、审计等待人工、admin 非 owner 只读、install 实际服务端目标说明。

```python
assert view['historyNote'] == '已有审计结果，未保存运行日志'
assert view['events'] == []
assert tampered_report_view['reportMatchesChain'] is False
assert install_service.execute(scope, malicious_key)['installed'] is False
```

- [ ] **2. 运行 red。** `python -m pytest tests/test_ops_reports.py tests/test_ops_install.py -q`；`node --test tests/web/roles.test.mjs`，确认目标行为失败。
- [ ] **3. 实现接口。** 报告必须严格 hash 路径、普通文件及实际 canonical hash 核验；读取当前作用域登记的真实 reportHash 或 Journal 关联的 pending hash，未知/另一作用域 hash 返回 404。BOT 历史用公开部署及原报告文件核对，日志缺失明确文案，报告缺失/损坏不否认真实链上判定也不冒认匹配。人工裁决仅 SUSPICIOUS，保留 findings、level 和原 timestamp，增加现有 humanDecision、实际 auditor，核 source/hash/stake 后 save_report，返回 PreparedTx 所需 digest，confirm 核链并记真实事件。
  audit 两秒只轮询 journal/status，显示时间线/待审/失败/报告/质押缺额及启停。detail 显示实际文件、hash、NFT token/owner/回执。admin 四步签名、revision、估费用、刷新及 slash；激活后重新认证。install 仅已登记来源，复用 MCP 复制/复检，配置用实际 venv Python 绝对路径，明确安装在服务机器。
- [ ] **4. 运行 green。** `python -m pytest tests/test_ops_reports.py tests/test_ops_install.py tests/test_gate.py tests/test_mcp_server.py -q -m 'not anvil'`；`node --test tests/web/roles.test.mjs`，全部选中项通过。
- [ ] **5. 保存点。** 仅提交本任务文件，消息 `feat: expose audit reports and separate role workflows`。

### Task 8: 隔离 Anvil 闭环、浏览器验收与交付

**Files:** Create `tests/roles_fixtures.py,test_roles_e2e.py,role_demo.py`、`tests/fixtures/role-wallet.mjs`、`docs/ROLE-PAGES-ACCEPTANCE.md`；Modify `tests/conftest.py`、`README.md`、`.gitignore`。

**Interfaces:** Consumes 前七任务全部接口。Produces `make_role_fixture(root:Path,rpc_port:int=18857,http_port:int=18701)->RoleFixture`（该文件定义 fixture 数据类，持有临时 root、进程、公开地址、部署）、`python tests/role_demo.py --rpc-port 18857 --port 18701` 浏览器验收入口；测试按实际空闲端口选择，不能占用/结束 8545、8765 或已有进程。

- [ ] **1. 写失败集成测试。** `test_two_publishers_custom_archive_to_audit_and_install` 由公开夹具的两个 EOA 经 SIWE/上传/钱包交易登记全新名字，只有审计钱包自动提交。断言链上 publisher、实际 codeHash/metadataHash、报告哈希、NFT token/owner 与本地安装文件逐项一致；没有钱包或真实链依赖时本组 fail 并说明缺失，不能 skip 假通过。

```python
assert detail_a['publisher'] == publisher_a.address
assert detail_b['publisher'] == publisher_b.address
assert verified['reportHash'] == report_hash_hex(saved_report)
assert verified['license']['owner'] == publisher_a.address
assert installed_file_bytes == audited_file_bytes
```

- [ ] **2. 运行 red。** `python -m pytest tests/test_roles_e2e.py -q`；夹具真实起独立 Anvil、从冻结 artifacts 部署基线、起临时 Ops 服务，不借原 .env 或 8545，先确认新增闭环测试能发现缺口。
- [ ] **3. 实现夹具和演示入口。** 动态生成 SAFE/MALICIOUS/SUSPICIOUS/来源失败/哈希改动技能，仅 example 域名标记。覆盖两发布者、拒签续办、stake/裁决、worker恢复、回执超时、错链/非owner/四步部署、MCP拒绝与旧安装保留。测试服务器独有 `/__test_wallet`，provider 用 viem accounts 在浏览器签公开夹具账户的消息/交易，发往真实 Anvil；生产不加载该 provider、不代签、不写死结果。仅白名单代理本地 RPC，清理仅夹具 PID。
- [ ] **4. 运行集成 green。** `python -m pytest tests/test_roles_e2e.py -q`，新增闭环全部通过，不能 skip。
- [ ] **5. 浏览器验收。** CUA 实际完成六页、两钱包发布、审计 timeline/report 和部署向导，存宽屏/窄屏截图、拒签/切换状态和链证据到忽略的 acceptance/。无真实扩展时如实标注“EOA 协议由本地测试 provider 验收，真实扩展弹窗待手动确认”。只读核对原 BOT 两条历史及报告；检查活动轮询不全链扫描、资源接口不露秘密。
- [ ] **6. 最终回归。** 隔离区执行 `python -m pytest -q -m 'not anvil'`、`python -m pytest tests/test_roles_e2e.py -q`、`node --test tests/web/*.test.mjs` 和 contracts 中 `forge test -vv`；记录实际 pass/skip，确认冻结源码/规则/样本/哈希函数摘要不变。
- [ ] **7. 写交付记录。** README 与验收文档记录实际六页启动、CLI迁移、服务钱包、MCP、测试数量和钱包弹窗边界；只有实测后写“可用”。
- [ ] **8. 保存点。** 检查 Git 无真实 key，仅提交本任务文件，消息 `test: verify role workflows on isolated Anvil`。

## 完成与集成条件

八个任务完成且上述检查有实际通过证据后，按用户选择的方法执行整体代码审查，修复实际发现，再把已验证的公开文件接回原项目。接回前逐文件比对起始摘要，保留原 .env、部署和报告；有并发变更时先合并内容，不覆盖用户工作。不自动合并远程分支或创建公网服务。

原本机 Ops 服务重启为新页面版本；首次启动不自动运行审计、不自动发链上交易。提供六页入口、截图与测试记录，原 BOT 页面读出真实历史即可验收交付；最终报告明确分别说明本地钱包交易闭环与 BOT 只读结果。

## 规格覆盖与执行建议

规格 1/9 的范围和冻结约束贯穿全部任务；规格 2 的六页由 Tasks 6–8；规格 3 的权限与自动钱包由 Tasks 1/3/5/6；规格 4 的 ZIP/发布由 Tasks 2/3/6/8；规格 5 的事件/恢复/worker由 Tasks 4/5/7/8；规格 6 的管理/安装由 Tasks 3/7/8；规格 7 的 API由 Tasks 1–7；规格 8 的验收由 Task 8。五项 Review Focus 都有对应命名测试，没有留待以后补的必需功能。

建议采用 **Native：在当前会话逐项实现，最后独立整体审查**。八个任务共享作用域、prepared 参数和 worker 生命周期接口，连续实现便于保持这些接口一致；每步仍执行 red/green 与保存点。另一个选项是 **Subagent-driven：各任务使用新的实现者和审查者**，逐项审查更细，但上下文与交接次数更多。选择后使用相应的 executing-plans 或 subagent-driven-development 技能。
