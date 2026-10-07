# SkillGuard · 技能卫士

AI Agent 技能供应链的安全审计市场：企业安装第三方 MCP 技能前，由质押审计者做投毒检测，结论上链，恶意技能被经济问责。

详见 [SPEC.md](SPEC.md)；开发步骤见 [docs/PROMPTS.md](docs/PROMPTS.md)。

## 主流程

```
注册技能版本 → 请求审计（锁押金）→ 审计引擎出报告 → 报告哈希上链
  安全：铸 VERIFIED NFT ──────────────→ gate.py 安装前查链上许可证（放行）
  恶意：罚没押金给审计者 ────────────→ gate.py（拒绝安装）
```

## 目录

| 目录 | 作用 |
|---|---|
| `contracts/` | Foundry 项目：SkillRegistry（注册/审计/罚没）、SkillLicense（ERC-721 许可证） |
| `auditor/`   | Python 审计引擎（`python -m auditor.cli`），支持 `--submit` 上链与 `--llm` 一致性检查 |
| `gate/`      | `gate/gate.py` 安装门禁（只读查链，不执行技能代码） |
| `rules/`     | YAML 检测规则 + 仿冒包名清单（公共物品） |
| `samples/`   | 演示样本：weather(SAFE)、mail-helper(MALICIOUS)、requests-mcpp(MALICIOUS) |
| `web/`       | 只读看板 `index.html`（浏览器钱包 RPC 直读链上事件） |
| `reports/`   | 审计报告归档（文件字节 = 链上 reportHash 原象） |
| `deployments.json` | 合约地址 + chainId |

## 快速开始（一键演示）

```bash
# 前置：Foundry（cast/anvil/forge）、Python 3.11
cp .env.example .env   # 填 RPC_URL / PRIVATE_KEY(发布者) / AUDITOR_PRIVATE_KEY(审计者) / OWNER_PRIVATE_KEY(管理员)
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# 另开一个终端跑本地链（演示默认用本地 anvil，友好无 gas 成本）
anvil

./demo.sh
```

`demo.sh` 串起完整流程并验证两条路径：

1. `weather` → 审计 SAFE → Verified → 门禁绿色"✔ VERIFIED，允许安装"；
2. `mail-helper`（描述文字与字符串常量命中投毒规则，运行时不读文件、不联网）→ 审计 MALICIOUS → 押金罚没给审计者 → 门禁红色"✘ 拒绝安装"。

部署 Sepolia（可选）：`cd contracts && forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast`，
地址自动写回 `deployments.json`；`demo.sh` 遇到非本地链时不会自动重部署，只做校验与指引。

## 常用命令

```bash
cd contracts && forge test -vv            # 合约测试（103 个）
pytest -q                                  # Python 测试
python -m auditor.cli samples/weather      # 离线审计，报告存 reports/
python -m auditor.cli samples/weather --submit   # 并上链提交
python -m auditor.cli samples/weather --llm      # 追加 LLM 一致性检查（可缓存）
python -m auditor.stake                    # 人：为审计者质押（押钱担保）
python -m auditor.agent [--once]           # 常驻审计 Agent
python gate/gate.py install samples/weather      # 安装门禁（人机界面）
python gate/mcp_server.py                  # 安装方 Agent 的 MCP 工具（stdio）
```

## 安装方 Agent（demo-agent/）

任何支持 MCP 的 Agent 都能在安装前调用 SkillGuard 门禁工具：

| 工具 | 行为 |
|---|---|
| `check_skill(skill_dir)` | 查链上审计状态与许可证，比对本地与链上 codeHash/metadataHash |
| `install_skill(skill_dir)` | 只在链上允许时复制到 `installed/<name>-<version>/`，复制后对副本重算哈希再核对一次 |

启动方式：在 `demo-agent/` 目录里启动一个真实 Agent（例如 Claude Code，`.mcp.json`
已登记 `gate/mcp_server.py`），用自然语言让它"安装 ../samples/weather"。

**局限（SPEC 9.3，如实说明）：** Agent 是被 `demo-agent/CLAUDE.md` 这份规则**配置成**
安装前调用 `install_skill` 的；这不是平台级的强制安装钩子——若 Agent 用别的工具直接
复制文件，本系统拦不住。强制钩子属于路线图（SPEC 11.3）。

## 安全边界

- 演示样本不含真实攻击载荷，外连域名只用 `example.com / example.org`；
- 私钥 / RPC / API key 一律从 `.env` 读取，代码零硬编码；
- `gate.py` 与审计引擎不导入、不执行技能代码；哈希/读取拒绝符号链接与非常规文件；
  门禁输出的键来自不可信输入，使用富文本装配防注入。
