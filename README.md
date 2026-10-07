# SkillGuard · 技能卫士

**最终目标（SPEC 原话）：** 平台的服务对象是 Agent。安装方 Agent 在装技能前调用 SkillGuard 查链上许可证；审计方是一个常驻的审计 Agent，监听审计请求、自动运行开源规则引擎并提交结论。人只做两件事：押钱担保，和裁决争议。演示里各个钱包由我们自己控制。

AI Agent 技能供应链的安全审计市场：计算机安装第三方 MCP 技能前，由质押审计 Agent 做投毒检测，结论上链，恶意技能被经济问责。详见 [SPEC.md](SPEC.md)；开发步骤见 [docs/PROMPTS.md](docs/PROMPTS.md)。

## 主流程

```
人（发布者）：注册技能版本 → 请求审计（锁押金）
审计 Agent（常驻程序）：监听 AuditRequested → 取代码并核对哈希 → 规则引擎出报告 → 结论上链
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
| `web/`       | 只读看板 `index.html`（浏览器钱包 RPC 直读链上事件） |
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
cd contracts && forge test -vv                  # 合约测试（103 个）
pytest -q                                       # Python 测试
python -m auditor.cli samples/weather           # 离线审计，报告存 reports/
python -m auditor.cli samples/weather --submit  # 并上链；SUSPICIOUS 会要求 --human-decision safe|malicious
python -m auditor.cli samples/weather --llm     # 追加 LLM 一致性检查（可选，缓存 .cache/）
python -m auditor.stake                         # 人：为审计者质押（押钱担保）
python -m auditor.agent [--once] [--from-block N] [--poll 秒]   # 常驻审计 Agent
python gate/gate.py install samples/weather     # 安装门禁（人机界面）
python gate/mcp_server.py                       # 安装方 Agent 的 MCP 工具（stdio）
```

Agent 的代码来源只支持本地路径（`repo` 字段为 `SKILL_SOURCE_ROOT`（默认项目根）内的
相对路径或 `file://` 绝对路径）；**不 import、不执行技能代码**；不调用 LLM。

## 安装方 Agent（demo-agent/）

| 工具 | 行为 | 返回 |
|---|---|---|
| `check_skill(skill_dir)` | 只读查链：审计状态、许可证、哈希比对 | `{allowed, skill, version, status, reason, chainId, registry}` |
| `install_skill(skill_dir)` | 只在 `allowed` 时复制到 `installed/<name>-<version>/`，复制后对副本重算哈希再核对一次 | `{installed, installed_path, ...}` |

在 `demo-agent/` 目录启动真实 Agent（`.mcp.json` 已登记 `gate/mcp_server.py`；指向的
Python 需与仓库 `.venv/bin/python` 一致或已在 PATH 中），用自然语言让它
"安装 ../samples/weather"。失败即拒绝：RPC 不通 / 状态异常 / 哈希不一致 / manifest 畸形，
一律 `allowed=false / installed=false`。

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
Agent 平台级安装钩子、测试网部署。

## 安全边界

- 演示样本不含真实攻击载荷，外连域名只用 `example.com / example.org`；
- 私钥 / RPC / API key 一律从 `.env` 读取，代码零硬编码；
- 审计引擎与门禁不导入、不执行技能代码；哈希/读取拒绝符号链接与非常规文件；
- 门禁与 MCP 工具输出的键来自不可信输入，拒绝路径逃逸，富文本装配防注入；
- 屏幕上的判定、哈希、交易号、余额、状态均由程序实时算出或链上读出（`demo.sh` 只 echo 步骤标题与真实数值，有 pytest 检查）。
