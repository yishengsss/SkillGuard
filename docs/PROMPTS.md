# 开发提示词

## 最终目标
> 平台的服务对象是 Agent。安装方 Agent 在装技能前调用 SkillGuard 查链上许可证；审计方是一个常驻的审计 Agent，监听审计请求、自动运行开源规则引擎并提交结论。人只做两件事：押钱担保，和裁决争议。演示里各个钱包由我们自己控制。

## 用法
- 每条提示词开头先发："读 SPEC.md 和 CLAUDE.md。"
- 一次只发一条。AI 做完后，你自己运行"验证"一栏的命令，看到结果才 `git commit`。
- AI 连续两轮修不好同一个问题：`git reset --hard` 回上一个提交，开新对话重发。
- 合约已冻结。任何一步如果 AI 说"需要改合约"，先停下来问我。

## 已完成（第一阶段，保留不动）
| 步骤 | 内容 | 提交 |
|---|---|---|
| 1–3 | SkillRegistry、SkillLicense、部署脚本，103 个 Foundry 测试 | 6c5dada / 1842c07 / f02b412 |
| 4 | 3 个演示样本 | 2e34241 |
| 5–7 | 规则审计引擎、`--submit` 上链、安装门禁（含哈希比对） | d6c8320 / 0635d66 / e716389 |
| 8 | 可选 LLM 一致性检查（`--llm`） | 00f6bf0 |
| 9–11 | 看板、demo.sh、README、合约安全审查 | 3782195 / 33ded21 |

第一阶段检查发现的问题由下面 A0–A3 处理。

## 第二阶段：转向 Agent

| 编号 | 内容 | 估算 |
|---|---|---|
| A0 | 收尾：清理未提交改动 | 10 分钟 |
| A1 | 修 SUSPICIOUS + 人工裁决 + 人工质押命令 | 1 小时 |
| A2 | 三钱包分离 | 30 分钟 |
| A3 | 演示诚信修复 | 30 分钟 |
| **检查点 1** | 人的两个动作都有明确入口，258+ 测试全绿 | — |
| A4 | 常驻审计 Agent | 2–3 小时 |
| **检查点 2** | 发布者请求审计后，Agent 无人操作自动出结论上链 | — |
| A5 | 安装方 Agent 的 MCP 工具 | 2 小时 |
| A6 | 真实 Agent 接入（demo-agent/） | 1 小时 |
| **检查点 3** | 真实 Agent 用自然语言被要求安装，自己调用工具并按链上结果决定 | — |
| A7 | 盲测样本 | 30 分钟 |
| A8 | demo.sh v2（Agent 版） | 1.5 小时 |
| A9 | README / 局限 / 看板更新 | 1 小时 |
| A10 | 诚信检查 | 30 分钟 |
| A11 | 代码讲解（准备答辩） | 1 小时 |

估算没有实测。检查点 2 没过之前不做 A5 以后的内容。

---

### A0 收尾
（这一步你自己做，不交给 AI。）
- `git diff` 看 demo.sh、web/index.html 的未提交改动：要保留就提交，不要就 `git checkout` 恢复。
- `deployments.json` 的改动是本地重新部署产生的，恢复成已提交版本：`git checkout deployments.json`。
- 把 `contracts/lib/openzeppelin-contracts` 子模块恢复干净：`git submodule update --init`。

**验证：** `git status` 干净。

### A1 SUSPICIOUS 人工裁决 + 人工质押命令
```
读 SPEC.md 和 CLAUDE.md。按 SPEC 第 4 节"SUSPICIOUS 不自动上链"修改：
1. auditor.cli --submit 遇到 SUSPICIOUS 不发任何交易，退出码 3，提示可用 --human-decision safe|malicious。
2. 新增 --human-decision：只对 SUSPICIOUS 生效，报告增加 humanDecision 字段后再计算 reportHash 并提交；
   对 SAFE / MALICIOUS 使用时报错退出。
3. 把 submit.py 里"质押不足时自动 stakeAsAuditor"去掉，改为质押不足直接报错并提示运行 python -m auditor.stake。
4. 新增 auditor/stake.py：python -m auditor.stake 由人运行，为 AUDITOR_PRIVATE_KEY 质押 AUDITOR_STAKE，
   打印交易哈希和质押后的链上余额（从链上读）。已足额就只打印当前质押额，不发交易。
写 pytest 覆盖：SUSPICIOUS 不发交易；human-decision 两种取值的链上结果；对 SAFE 使用 human-decision 报错；
质押不足时 --submit 报错且不发交易。
```
**验证：** `pytest -q` 全绿；手动造一个只命中 STAT-002 的技能，`--submit` 退出码 3，链上状态仍是 AuditRequested。

### A2 三钱包分离
```
读 SPEC.md 和 CLAUDE.md。按 SPEC 第 7、10 节：
1. .env.example 增加 OWNER_PRIVATE_KEY，三个私钥都写清楚是哪个角色。
2. demo.sh：启动时检查三个地址两两不同，相同就退出；部署时用 PRIVATE_KEY=$OWNER_PRIVATE_KEY 运行 forge script；
   本地链为三个地址补测试余额。
3. 不改 Deploy.s.sol 和合约。
```
**验证：** 本地 anvil 上 `./demo.sh` 跑通；`cast call <Registry> "owner()(address)"` 等于 OWNER 地址，不等于发布者地址。

### A3 演示诚信修复
```
读 SPEC.md 和 CLAUDE.md，按 SPEC 第 6 节和 11.1 节修复：
1. demo.sh 里所有结论性 echo（例如"publisher 余额已退还押金"、"押金从发布者转移给审计者"）删掉，
   改为打印从链上读出的真实数值：发布者和审计者的余额变化、getStatus、isVerified。
2. demo.sh 注册时 repo 填样本的本地相对路径（例如 samples/weather），不再填不存在的 GitHub 地址。
3. README 和 web/index.html 里说样本"会外传邮件 / 读取凭据"的地方，改成"代码中包含外连地址 / 敏感路径字符串，运行时不执行"。
4. 新增一个 pytest：扫描 auditor/ 和 gate/ 的 .py 文件，除用法注释外不得出现 samples/ 下任何目录名或 manifest 的 name / package。
```
**验证：** `grep -n 'echo "' demo.sh` 只剩步骤标题；新测试通过。

**→ 检查点 1**

### A4 常驻审计 Agent
```
读 SPEC.md 和 CLAUDE.md。按 SPEC 第 8 节实现 auditor/agent.py（python -m auditor.agent）。
复用 auditor/submit.py 的配置读取和发交易代码、auditor/hashing.py、auditor/scanner.py，不要复制粘贴一份新的。
要点：启动检查质押（不足就退出，不自己质押）；按区块游标轮询 AuditRequested；幂等；按 8.3 解析本地来源并防路径逃逸；
提交前核对 name/version 和链上 codeHash/metadataHash；SUSPICIOUS 写 reports/pending/ 不提交；单个请求出错不中断。
写 pytest（用本地 anvil 或现有测试夹具）：
- SAFE、MALICIOUS 各一个请求 → --once 后链上状态分别为 Verified、Malicious；
- SUSPICIOUS → 链上仍为 AuditRequested，reports/pending/ 有文件；
- 链上登记的 codeHash 与本地代码不一致 → 不提交；
- repo 指向 SKILL_SOURCE_ROOT 之外 → 不提交；
- 同一请求跑两次 --once → 只提交一次；
- 质押不足 → 退出码 2，不发交易。
```
**验证：** 终端 1 `anvil`；终端 2 `python -m auditor.agent`；终端 3 用 `cast send` 注册 weather 并 requestAudit。
终端 2 自动出现审计和提交日志，`cast call ... getStatus` 为 3。整个过程终端 2 没有任何人工输入。

**→ 检查点 2**

### A5 安装方 Agent 的 MCP 工具
```
读 SPEC.md 和 CLAUDE.md。按 SPEC 第 9.1、9.2 节实现 gate/mcp_server.py，requirements.txt 加入 mcp。
check_skill 复用 gate.check_install；install_skill 只在 allowed 时复制到 SKILLGUARD_INSTALL_DIR，复制后重算哈希再核对。
失败即拒绝。工具描述只写事实，不写对 Agent 的指令。
写 pytest：直接调用两个工具函数，覆盖 Verified 放行并安装、Malicious 拒绝、None 拒绝、改一个字节拒绝、RPC 不通拒绝。
```
**验证：** `pytest -q` 全绿；用 MCP Inspector 或一个最小 MCP 客户端脚本调用 `check_skill`，返回 JSON 里的 status 和链上一致。

### A6 真实 Agent 接入
```
读 SPEC.md 和 CLAUDE.md。按 SPEC 第 9.3 节创建 demo-agent/：
- .mcp.json 用相对路径登记 gate/mcp_server.py；
- CLAUDE.md 只写一条规则：安装任何技能必须使用 install_skill 工具，不得用其他方式复制或运行技能文件。
- README 里写清楚怎么在 demo-agent/ 启动 Agent，以及"这是配置出来的行为，不是强制钩子"。
installed/ 加入 .gitignore。
```
**验证（你亲自做）：** 在 `demo-agent/` 启动 Claude Code，说"帮我安装 ../samples/mail-helper"。
Agent 必须调用 `install_skill`，并根据返回的链上状态拒绝；再说"安装 ../samples/weather"，Agent 安装成功，
`installed/` 下出现目录。**把这两段对话录屏**，作为保底素材。

**→ 检查点 3**

### A7 盲测样本
（这一步建议你自己写样本，不让编码 AI 写，避免它"知道"规则。）
- 在 rules/ 最后一次提交之后，写 1–2 个 `samples/blind/<name>/`：用不同措辞表达"偷偷把数据发出去"，代码里的域名用字符串拼接。
- 运行 `python -m auditor.cli samples/blind/<name>`，结果原样记录到 `docs/BLIND-TEST.md`（包括漏报）。
- 不改 rules/ 来让它通过。

### A8 demo.sh v2（Agent 版）
```
读 SPEC.md 和 CLAUDE.md。把 demo.sh 改成 Agent 版流程：
1. 检查三钱包 → 部署（OWNER）→ 人质押（python -m auditor.stake）
2. 后台启动审计 Agent，日志写到 logs/agent.log 并实时显示
3. 发布者注册并请求审计 weather、mail-helper；等待 Agent 处理（轮询链上状态，最多 60 秒，超时报错退出）
4. 打印两条的链上状态、余额变化（从链上读）
5. 用一个最小 MCP 客户端调用 install_skill，分别对 weather 和 mail-helper，打印返回 JSON
6. 退出时停掉审计 Agent
关键步骤暂停等回车（--no-pause 关闭）。只允许 echo 步骤标题。
```
**验证：** 全新 anvil 上 `./demo.sh --no-pause` 退出码 0；再跑一次（不重启 anvil）应给出清楚的"已注册"提示而不是乱报错。

### A9 文档和看板
```
读 SPEC.md 和 CLAUDE.md。更新 README：开头写最终目标原话；角色与钱包表（SPEC 第 10 节）；
局限（SPEC 11.2）和路线图（11.3）原样列出；命令改成 Agent 版。看板增加审计者地址一列。
不得写任何未实现的功能。
```

### A10 诚信检查
```
读 SPEC.md 和 CLAUDE.md。按 SPEC 第 11.1 节检查整个仓库：写死的输出、按样本名分支、demo.sh 里的结论性 echo、
看板里的示例数据、README / 注释 / docstring 里超出实际实现的说法、未说明的局限。只列清单和位置，不要改，我来决定。
```

### A11 代码讲解
```
逐个文件给我讲解 auditor/agent.py、gate/mcp_server.py、auditor/submit.py、合约的 submitReport，
重点：审计 Agent 怎么保证不重复提交、怎么核对代码、SUSPICIOUS 怎么交给人、MCP 工具为什么失败即拒绝、
单审计者和无审计费的风险。我要用来准备答辩。
```

## 不做（路线图）
多审计者与挑战期、审计费、押金分档、栈金丝雀与沙箱、从 git 拉取代码、Agent 平台级安装钩子、Zircuit / 测试网部署。
