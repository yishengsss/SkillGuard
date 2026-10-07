# 给 AI 的项目规则

先读 SPEC.md，所有实现以 SPEC 为准；SPEC 没写的先问我，不要自己发明。

## 技术栈
- 合约：Solidity ^0.8.24，Foundry，OpenZeppelin v5（只用 OZ 组件，不手写 ERC721/权限逻辑）
- 审计引擎 / 门禁：Python 3.11，web3.py，PyYAML，pytest，rich（彩色输出）
- 看板：单个 HTML 或 Next.js + viem（加分项）

## 工作规则
1. 一次只做我要求的那一个模块，不要顺手改其他文件
2. 合约必须同时写 Foundry 测试；Python 必须写 pytest；改完自己跑测试并告诉我结果
3. 不要在代码里写私钥、RPC、API key，一律从 .env 读取
4. 演示样本不得包含真实攻击载荷，外连域名只用 example.com / example.org
5. 出错时先说明原因再改，不要大面积重写
6. 完成后简要列出：改了哪些文件、怎么运行、怎么验证

## 常用命令
- 合约测试：`cd contracts && forge test -vv`
- 部署：`cd contracts && forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast`
- 审计：`python -m auditor.cli samples/mail-helper [--submit] [--llm]`
- 门禁：`python gate/gate.py install samples/weather`
- Python 测试：`pytest -q`
