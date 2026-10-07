# 给 AI 的项目规则

先读 SPEC.md，所有实现以 SPEC 为准；SPEC 没写的先问我，不要自己发明。

## 项目目标（最终目标，不得偏离）
平台的服务对象是 Agent。安装方 Agent 在装技能前调用 SkillGuard 查链上许可证；审计方是一个常驻的审计 Agent，监听审计请求、自动运行开源规则引擎并提交结论。人只做两件事：押钱担保，和裁决争议。演示里各个钱包由我们自己控制。

- 合约（contracts/src/）已冻结：本轮不改合约，除非我明确要求。
- 不要实现 SPEC 第 11.3 节"路线图"里的任何东西，也不要在文档里把它们写成已实现。

## 技术栈
- 合约：Solidity ^0.8.24，Foundry，OpenZeppelin v5（只用 OZ 组件，不手写 ERC721/权限逻辑）
- 审计引擎 / 门禁 / 审计 Agent：Python 3.11，web3.py，PyYAML，pytest，rich（彩色输出）
- 安装方 Agent 接口：Python `mcp` SDK（stdio）
- 看板：单个 HTML 或 Next.js + viem（加分项）

## 工作规则
1. 一次只做我要求的那一个模块，不要顺手改其他文件
2. 合约必须同时写 Foundry 测试；Python 必须写 pytest；改完自己跑测试并告诉我结果
3. 不要在代码里写私钥、RPC、API key，一律从 .env 读取
4. 演示样本不得包含真实攻击载荷，外连域名只用 example.com / example.org
5. 出错时先说明原因再改，不要大面积重写
6. 完成后简要列出：改了哪些文件、怎么运行、怎么验证
7. **不作假**：输出的判定、哈希、交易号、余额、状态必须来自真实运行或链上读取；不得写死结果、不得按样本名分支、不得为了让测试或演示通过而改规则或样本。做不到就如实告诉我"没做到 / 做到了哪一部分"
8. 文档和注释只描述已经实现并测过的行为；局限照实写

## 常用命令
- 合约测试：`cd contracts && forge test -vv`
- 部署：`cd contracts && forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast`
- 审计：`python -m auditor.cli samples/mail-helper [--submit] [--llm]`
- 门禁：`python gate/gate.py install samples/weather`
- 质押（人）：`python -m auditor.stake`
- 审计 Agent：`python -m auditor.agent [--once]`
- 安装方 Agent 工具：`python gate/mcp_server.py`
- Python 测试：`pytest -q`
