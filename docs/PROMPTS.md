# 开发提示词（按顺序发给 AI，每步验证通过后 git commit）

1. 读 SPEC.md 和 CLAUDE.md。在 contracts/ 初始化 Foundry 项目并安装 OpenZeppelin，实现 SkillRegistry.sol（SPEC 3.1），先不接 NFT。写完整测试并运行 forge test。
2. 实现 SkillLicense.sol（SPEC 3.2），修改 SkillRegistry 在审计通过时铸造。补测试，运行 forge test。
3. 写 script/Deploy.s.sol，部署两个合约并设置权限，把地址写入根目录 deployments.json。先在本地 anvil 跑通。
4. 按 SPEC 第 6 节在 samples/ 生成 3 个演示技能（manifest.json + 源码），不得包含真实攻击载荷。
5. 按 SPEC 第 4 节实现 auditor/（不含 LLM 和 --submit），使用 rules/ 下的规则。写 pytest 验证 3 个样本的等级分别为 MALICIOUS / MALICIOUS / SAFE。
6. 给 auditor 加 --submit：计算 reportHash，用 AUDITOR_PRIVATE_KEY 调 submitReport（必要时先 stakeAsAuditor），打印交易哈希。报告保存到 reports/。
7. 按 SPEC 第 5 节实现 gate/gate.py，用 rich 彩色输出。
8.（加分）给 auditor 加 --llm 一致性检查，temperature=0，缓存到 .cache/。
9.（加分）web/ 下做单个 index.html，用 viem 读链上事件，展示技能列表、状态、报告哈希、样本库。
10. 写 demo.sh 串起完整演示（注册→请求审计→审计上链→门禁），写 README。
11. 冻结前：请对合约做一轮安全审查，列出问题但只修高危项。
