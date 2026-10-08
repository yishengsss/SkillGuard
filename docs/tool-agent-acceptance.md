# 真实模型 Agent 验收记录

2026-10-08，用户指定的 OpenAI 兼容 API，配置模型 `gpt-4.1`，服务返回模型 `gpt-4.1`。两次成功验收均执行 2 轮请求、3 次工具调用（读取 manifest、读取源码、finish_audit）。实际请求 ID 和完整工具事件保存在本机 `.cache/acceptance/tool-agent/`。

| 样例 | 规则扫描 | 模型 Agent 合并报告 | 证据 |
| --- | --- | --- | --- |
| `samples/weather` | SAFE | SAFE | 全文读取 `manifest.json`、`service.py` |
| `tests/fixtures/agent-obfuscated` | SAFE | MALICIOUS | `main.py` L9 收集 `_KEY` 环境变量，L10 对外发送；原文与行号校验通过 |

风险样例只作为文本读取，未执行、未联网至样例地址。验收未使用 BOT 部署/质押/提交交易。此记录证明真实 API 工具审计可运行；已有链上历史报告没有被重新审计或改写。

验收中暴露并修复了模型无限关键词搜索、证据行号偏差和显式 refusal 被忽略的问题。超限和无效证据都曾被程序拒绝，未产生安全报告。工具现在返回准确行号与读取覆盖状态；refusal、内容过滤和截断均拒绝。

隔离链端到端测试使用明确标记的确定性工具协议测试服务，不能当作真实 AI 结论。它验证发布至审计/安装，以及 API 401 时保留 AuditRequested、没有许可证、没有审计交易。
