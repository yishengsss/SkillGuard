# A10 诚信检查清单（docs/PROMPTS.md A10；SPEC 11.1/11.2）

> 只列清单与位置，不做改动，由项目所有者决定。
> 方法：按 SPEC 11.1 五条规则逐一对仓库 grep/人工核对；行动范围：README / 注释 /
> docstring / demo.sh / 看板 / 源码分支。

## 1. 检查方法

- 写死输出：全文检索 `weather|mail-helper|ag-safe` 等样本名是否出现在 auditor/gate 源码（tests 有 `test_honesty.py` 把关；唯一白名单为 CLI 用法注释）；
- demo.sh 结论性 echo：`grep -nE '^\s*echo' demo.sh` —— 15 处全部为「从变量/链上 cast 读取打印」或步骤标题，无结论性文字；
- 看板示例数据：全仓检索 `mock|fake|dummy|示例数据`；看板所有渲染走 viem 读链，链上没有的字段显示 "—"（如末审计版本的审计者列）；
- 文档超实声明：检索 README/CLAUDE/SPEC 之外的新文档中不得出现"已实现"的路线图词（沙箱、挑战期、审计费…）。

## 2. 发现项（按位置列出，供决策）

### 状态：已确认合规
| 项 | 位置 | 结论 |
|---|---|---|
| auditor/、gate/ 源码 | `grep` 样本名 | 仅 `auditor/cli.py:4–6` 用法注释引用 `samples/mail-helper`，SPEC 8.4 允许 |
| demo.sh echo | `demo.sh:89–94, 202–217` | 全部打印真实链上数值；第 205/210 行为"超时指引"非结论 |
| 看板 | `web/index.html` | 无样例数据；空白列显示 "—"（如 `mcp-reg` 版本的审计者） |
| README 主流程图 | `README.md` | 与 SPEC 第 1/8/9 节一致（SAFE/MALICIOUS/SUSPICIOUS 三向） |
| 已知局限 | `README.md` 已知局限节 | SPEC 11.2 八条原样列出 |
| 路线图 | `README.md` 路线图节 | SPEC 11.3 原样列出，未写成已实现 |

### 需要所有者裁决的遗留项（未改动）
1. **`auditor/agent.py` docstring 开头的"已知收窄"**（agent.py 顶部 23–30 行）：如实写了游标写回策略的边界情况。属于"局限照实写"（符合 CLAUDE 规则 8），可保留；若嫌啰嗦可移动到 SPEC 11.2。
2. **`auditor/cli.py` docstring 的 demo 链路描述**：写的是 1.0 版本行为（自动质押），而 A1 已改为人工质押。建议同步更新为 A1 语义（小改，未动，等你确定）。
3. **`tests/test_agent.py` / `tests/test_mcp_server.py` 集成用例使用 anvil 默认助记词私钥**：私钥常量写进测试源码。语义上属"测试夹具 + 本地链 only"（文件头注释已说明），但严格读 CLAUDE 规则 3（"不要在代码里写私钥"）可算作资产；建议改为 `ANVIL_MNEMONIC` 常量 + HD 派生，而不是硬编码两个 key 字符串。**推荐处理：改为从助记词在测试内派生**。
4. **`web/index.html` 的 `VIEM_URL`**：使用 esm.sh 公共 CDN；断网演示时看板会失败。属"提前依赖外部网络"，建议演示时说明或 vendor 掉。
5. **`.pytest_cache/` 有旧 `_sandbox_harness` 字节码**（`tests/__pycache__/...pyc`）与 `auditor/__pycache__/` 内旧 `.pyc`：revert 后残留，不影响诚信；建议 `find . -name __pycache__ -type d | xargs rm -rf` 一次清掉。
6. **`reports/` 内含 `mcp-ok-*` 等测试生成的报告**：文件名是真实报告哈希、内容真实，但与人无关联的演示数据混在归档里。如果对外展示报告目录，建议清一次（例如只保留 weather/mail-helper 的最新提交版）。
7. **`gate/mcp_server.py` docstring 的启动命令 `python gate/mcp_server.py`**：演示时若使用 `.venv` 未激活，Agent 拿到的是系统 python，可能缺 `mcp` 包。`demo.sh` 用的 `PY=.venv/bin/python` 兜底；建议 README demo-agent 节写清楚「确保 MCP server 用 .venv 的解释器」。

## 2.1 SPEC 11.1 规则 5（提前完成步骤的说明）
- demo.sh 第 0 步的"自动重部署"在本地链上提前完成了部署流程；屏幕有 `用管理员钱包重新部署` 提示，README 快速开始也注明"演示默认本地 anvil"。符合规则 5。

## 3. 结论
未发现"判 dryer/写死样本名分支"级别的作假。遗留项全部是文档/历史残留级别的小项，安全；唯一建议尽快处理的是第 3 条（测试内硬编码 anvil 助记词派生私钥 → 改为源码里写助记词 + 运行时推导）。
