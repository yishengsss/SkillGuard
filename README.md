# SkillGuard · 技能卫士

**最终目标（SPEC 原话）：** 平台的服务对象是 Agent。安装方 Agent 在装技能前调用 SkillGuard 查链上许可证；审计方是一个常驻的审计 Agent，监听审计请求、执行规则检查与模型工具审计并提交结论。人只做两件事：押钱担保，和裁决争议。演示里各个钱包由我们自己控制。

AI Agent 技能供应链的安全审计市场：计算机安装第三方 MCP 技能前，由质押审计 Agent 做投毒检测，结论上链，恶意技能被经济问责。详见 [SPEC.md](SPEC.md)；开发步骤见 [docs/PROMPTS.md](docs/PROMPTS.md)。

## 多角色页面（本机 MVP）

启动 `.venv/bin/python -m ops.server --port 8765`，打开 `http://127.0.0.1:8765/`。技能库、发布者、审计运营、管理员、技能详情和安装分别有独立页面。发布者上传自己的 ZIP；人的交易由各自浏览器钱包签名，网页后端不使用发布者或 owner 私钥代签。

审计服务只配置 `RPC_URL`、`AUDITOR_PRIVATE_KEY` 与 `deployments.json`。连接该审计钱包签名质押后，从审计页启动 Agent，能查看实际阶段、报告和链上回执。CLI `python -m auditor.agent` 与网页共用钱包锁，不能同时运行同一审计钱包。安装复制到服务机器，失败保留已有版本。

无钱包可浏览及检查安装门禁；签名需 EIP-1193 EOA 钱包，操作网络仅限 BOT Testnet 968 / 本地 Anvil 31337。初始部署仍由本机 CLI 完成，随后只有当前合约 owner 可用网页四步部署并激活。

独立体验：`.venv/bin/python tests/role_demo.py --rpc-port 18857 --port 18701`。打开 `http://127.0.0.1:18701/` 后用顶部公开测试钱包选择器切换发布者 A、B、审计者、管理员。该测试入口只使用新的 Anvil，生产服务不提供测试钱包。真实扩展弹窗仍需手动确认。

完整测试和边界见 [角色页面验收](docs/ROLE-PAGES-ACCEPTANCE.md)。下方的 `.env` 发布者/owner 密钥方式仅适用于既有 CLI 演示。

## 主流程

```
人（发布者）：注册技能版本 → 请求审计（锁押金）
审计 Agent（常驻程序）：监听 AuditRequested → 取代码并核对哈希 → 规则扫描 → 模型 Agent 读取源码并验证证据 → 报告保存/结论上链
  SAFE：铸 VERIFIED NFT，押金退回
  MALICIOUS：罚没押金给审计者
  SUSPICIOUS：不上链，报告落 reports/pending/，等人裁决
安装方 Agent（无钱包）：安装前调用 MCP 工具 check_skill / install_skill 查链
```

## 角色与钱包（SPEC 10）

| 角色 | 谁 | 钱包（.env） | 做什么 |
|---|---|---|---|
| 发布者 | 人 | `PRIVATE_KEY` | 注册技能、请求审计并锁押金（押钱担保） |
| 审计者运营方 | 人 | `AUDITOR_PRIVATE_KEY` | 运行 `python -m auditor.stake` 质押（押钱担保）；裁决 SUSPICIOUS |
| 审计 Agent | 程序 | 使用 `AUDITOR_PRIVATE_KEY` 签名 | 监听、审计、提交结论 |
| 管理员 | 人 | `OWNER_PRIVATE_KEY` | 部署合约；`slashAuditor` 裁决争议 |
| 安装方 Agent | Agent | **无钱包** | 调用 MCP 工具查链、安装 |

三个私钥对应地址必须两两不同（`demo.sh` 启动时检查）。演示里三个钱包都由我们自己控制，演示时照实说明。

## 目录

| 目录 | 作用 |
|---|---|
| `contracts/` | Foundry 项目：SkillRegistry（注册/审计/罚没）、SkillLicense（ERC-721 许可证）；已冻结 |
| `auditor/`   | 规则引擎（`python -m auditor.cli`，`--submit`/`--llm`）、常驻审计 Agent（`agent`）、质押命令（`stake`） |
| `gate/`      | `gate.py` 门禁（人机界面）、`mcp_server.py` 安装方 Agent 的 MCP 工具（stdio） |
| `rules/`     | YAML 检测规则 + 仿冒包名清单（公共物品） |
| `samples/`   | 演示样本：weather(SAFE)、mail-helper(MALICIOUS)、requests-mcpp(MALICIOUS)；均为惰性夹具，运行时不读文件、不联网 |
| `demo-agent/`| 安装方 Agent 配置（.mcp.json + 一条规则） |
| `web/`       | 六个独立角色页面，共享 API / 钱包模块；原 `index.html` 只读看板保留 |
| `reports/`   | 审计报告归档（文件字节 = reportHash 原象）；SUSPICIOUS 在 `reports/pending/` |

## 快速开始（一键演示，Agent 版）

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env    # 按角色填 RPC_URL、PRIVATE_KEY、AUDITOR_PRIVATE_KEY、OWNER_PRIVATE_KEY

# 另开终端跑本地链（演示默认本地 anvil）
anvil

./demo.sh --no-pause
```

`demo.sh` 完整流程（关键步骤默认暂停等回车）：

1. 三钱包检查 → 管理员部署；
2. 人执行 `python -m auditor.stake` 质押（押钱是人的决定）；
3. 后台启动常驻审计 Agent（日志 `logs/agent.log`，无人参与判定）；
4. 发布者注册并请求审计 `weather` / `mail-helper`，等待 Agent 自动出结论上链（最多 60 秒）；
5. 安装方 Agent 通过最小 MCP 客户端调用 `install_skill`：weather 安装成功、mail-helper 因 Malicious 拒绝；
6. 退出时停掉审计 Agent。

提前完成的步骤（部署、质押）与使用的链（本地 anvil）在演示中说明。

## 常用命令

```bash
cd contracts && forge test -vv                  # 合约测试（104 个）
pytest -q                                       # Python 测试
python -m auditor.cli samples/weather           # 离线审计，报告存 reports/
python -m auditor.cli samples/weather --submit  # 并上链；SUSPICIOUS 会要求 --human-decision safe|malicious
python -m auditor.cli samples/weather --llm     # 追加 LLM 一致性检查（可选，缓存 .cache/）
python -m auditor.stake                         # 人：为审计者质押（押钱担保）
python -m auditor.agent [--once] [--from-block N] [--poll 秒]   # 常驻审计 Agent
python gate/gate.py install samples/weather     # 安装门禁（人机界面）
python gate/mcp_server.py                       # 安装方 Agent 的 MCP 工具（stdio）
.venv/bin/python ops/server.py                  # 网页操作台 http://127.0.0.1:8765（仅本机）
```

## 网页操作台（ops/）

使用 `.venv/bin/python -m ops.server --port 8765` 启动六个独立角色页面，只绑定本机。发布者上传 ZIP，两个独立钱包交易分别登记与锁押金；审计服务钱包经人签名质押后运行真实 Agent；可疑报告由同一审计者钱包人工裁决；管理员 owner 钱包逐步部署、接线并激活。各动作的回执和状态都由服务核验。

旧网页代签接口返回 410，服务不会使用发布者/管理员环境私钥替人签名。既有 CLI 工具仍可按下面的测试网配置使用。安装方无需钱包，由门禁核对来源、链上状态、哈希与许可证后复制到服务机器。

### BOT Chain 测试网

官方测试网：chainId `968`，RPC `https://rpc.bohr.life`，测试币 `tBOT`，
浏览器 <https://scan.bohr.life/>。网络说明：
<https://dev-docs.botchain.ai/docs/Developers/quick-guide/>。
水龙头 <https://faucet.botchain.ai/zh/basic> 每个地址每 24 小时最多领取 10 tBOT。

在项目 `.env` 中设置 `RPC_URL=https://rpc.bohr.life` 和专用 `AUDITOR_PRIVATE_KEY`。网页发布者与 owner 使用各自浏览器钱包；只有既有 CLI 演示仍读取另外两把私钥。发布者和审计者分别需要押金、质押与 gas 余额。
网页管理员需已有部署及其 owner 会话，按四步签名并核验激活。BOT 部署按顺序等待交易，逐笔查询四份实际回执，
核对两个合约代码、owner、双向接线和铸证权限；全部通过才原子替换部署配置。
失败保留之前的 `deployments.json`。合约源码保持不变。

BOT 部署配置包含 `deploymentBlock`。看板和审计 Agent 从该区块开始查询；
Agent 游标还记录 chainId 和 registry，切换网络或重新部署不会沿用不匹配的游标。
操作台显示实际网络和测试币单位。部署脚本只接受本地链、Sepolia 和 BOT 测试网，拒绝主网。

2026-10-08 已在 BOT 测试网完成实际部署和审计/安装验收：4 笔部署与接线交易、
7 笔质押/登记/审计交易全部回执成功。weather@1.0.0 获得 Verified 许可证并通过 MCP 安装；
mail-helper@1.0.0 判为 Malicious 并拒绝安装。未审计技能和代码哈希被篡改的副本也被拒绝，
报告文件、代码/元数据哈希、许可证持有人及审计者均与链上记录一致。

本次验收部署：[SkillRegistry](https://scan.bohr.life/address/0xEE41a45826e747e026B90177C086123490758731)、
[SkillLicense](https://scan.bohr.life/address/0x8316AE44Cfc46f1c244c64A6Ad7cD06a636411c2)，
起始区块 `26045862`。适配另通过 356 个 Python 测试、104 个 Foundry 测试及不广播的 BOT RPC 部署模拟。

“管理员：部署”每次创建新合约并切换配置；原有技能和质押留在原合约，新部署需要重新质押、登记和审计。
查看当前部署的状态使用“刷新面板”。

操作台校验 `Host`、`Origin` 与浏览器来源信息；写操作必须使用 JSON 并携带
`/api/session` 返回的当前进程令牌。页面自动获取令牌；其他同源客户端需先获取令牌，
通过 `X-SkillGuard-Token` 发送。该机制防止跨来源网页调用签名入口，本机程序仍属信任边界。
人工裁决只接受自动审计判为 SUSPICIOUS 的内容，并复用 CLI 的链配置、身份和内容哈希预检查。

Agent 的代码来源只支持本地路径（`repo` 字段为 `SKILL_SOURCE_ROOT`（默认项目根）内的
相对路径或 `file://` 绝对路径）；**不 import、不执行技能代码**；使用配置的模型调用只读快照工具。详见 [模型 Agent 审计](docs/tool-agent-auditing.md)。
Agent 从可信根逐段打开来源目录，扫描结论和哈希使用同一份不可变字节快照；
失败请求会保留在游标扫描范围内供下轮重试。CLI、Agent 和人工裁决在广播前将实际提交报告
原子保存为 `reports/<0xreportHash>.json`，同步文件与目录；保存失败则不广播。

## 安装方 Agent（demo-agent/）

| 工具 | 行为 | 返回 |
|---|---|---|
| `check_skill(skill_dir)` | 只读查链：审计状态、许可证、哈希比对 | `{allowed, skill, version, status, reason, chainId, registry}` |
| `install_skill(skill_dir)` | 只安装审计快照中的 manifest 和源码文件；staging 复检通过后替换 `installed/<name>-<version>/`，失败保留原安装 | `{installed, installed_path, ...}` |

在 `demo-agent/` 目录启动真实 Agent（`.mcp.json` 已登记 `gate/mcp_server.py`；指向的
Python 需与仓库 `.venv/bin/python` 一致或已在 PATH 中），用自然语言让它
"安装 ../samples/weather"。失败即拒绝：RPC 不通 / 状态异常 / 哈希不一致 / manifest 畸形，
一律 `allowed=false / installed=false`。

安装排除 `.env*`、`.git`、`.cache`、`__pycache__`、符号链接和非常规文件；
保留普通文件权限（含脚本执行位），不复制 setuid/setgid 等特殊权限。内容哈希格式保持兼容。

## 已知局限（SPEC 11.2 原样列出）

- 单个审计者即可定案；合约不校验结论是否正确；没有挑战期，判错的结论不能撤销，只能事后罚审计者。
- 没有审计费：审计者判通过没有收入，判恶意拿走押金，激励偏向判恶意，目前靠管理员仲裁约束。
- 审计者质押不能取回。
- 规则引擎是正则匹配，换措辞或拼接字符串即可绕过（见盲测样本）；STAT-002 对正常 https 地址误报偏多。
- 代码来源只支持本地路径。
- 安装方 Agent 的检查靠配置，不是强制钩子。
- 演示只在本地链上运行（除非另行部署并说明）。

## 路线图（SPEC 11.3，未实现）

多审计者与挑战期、审计费、押金分档、栈金丝雀与沙箱动态检测、从 git 拉取代码、
Agent 平台级安装钩子。

## 安全边界

- 演示样本不含真实攻击载荷，外连域名只用 `example.com / example.org`；
- 私钥 / RPC / API key 一律从 `.env` 读取，代码零硬编码；
- 审计引擎与门禁不导入、不执行技能代码；哈希/读取拒绝符号链接与非常规文件；
- 门禁与 MCP 工具输出的键来自不可信输入，拒绝路径逃逸，富文本装配防注入；
- 屏幕上的判定、哈希、交易号、余额、状态均由程序实时算出或链上读出（`demo.sh` 只 echo 步骤标题与真实数值，有 pytest 检查）。
