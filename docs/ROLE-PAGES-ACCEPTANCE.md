# 多角色页面验收记录

日期：2026-10-08。实现分支：`codex/skillguard-role-pages`。现有修复基线：`24ccab4`。

## 可体验范围

本机服务提供 `/` 技能库、`/publish` 发布者、`/audit` 审计运营、`/admin` 管理员、`/skills/<key>` 详情及 `/install` 安装。人的登记、押金、质押、裁决、部署及罚没都由浏览器 EOA 钱包签名；后端保存准备参数，按实际发送者、链、调用参数、成功回执与链上状态核验。自动 Agent 使用配置的审计服务钱包，不自动质押，不执行上传代码，不调用 LLM。

自定义 ZIP 支持根目录或单层包装目录；10 MiB 压缩 / 20 MiB 解压 / 512 文件上限。归属、路径逃逸、特殊文件、秘密内容、Unicode/大小写别名和内容篡改均有测试。登记和安装共用 UTF-8 身份长度校验。

## 实测证据

- Python 单元回归：464 passed，11 deselected。排除项为 5 个原 8545 集成项、2 个新隔离部署/目录集成项、4 个新闭环集成项；不是 skip 伪通过。
- 新隔离链与 HTTP 合并检查：16 passed，包含 2 个独立部署/目录 Anvil 测试和 4 个完整 HTTP 闭环。
- 新完整 HTTP 闭环：4 passed，零 skip。两个 EOA 经真实签名登录、上传全新名称、登记和锁押金；审计服务钱包提交；实际哈希、NFT 持有人、报告哈希及安装字节逐项核对。
- MALICIOUS 不铸证、门禁拒绝；SUSPICIOUS 等人裁决并保留原 level/findings/timestamp；真实节点接收后丢失广播响应，从同一 hash 恢复，审计钱包 nonce 只增加一次。
- Node 钱包/页面行为：12 passed，零 skip；涵盖迟到签名/服务器验证、账户和链变化、大整数 wei、押金拒签续办、不可信报告纯文本。
- Foundry：104 passed，零 failed/skip。冻结的 contracts/src、rules、samples、auditor/hashing.py、auditor/report.py 相对基线无修改。签名缓存不能写入默认目录的警告未影响合约测试。

浏览器使用测试服务器专用的公开 Anvil EOA provider，在真实 Anvil 上完成两个钱包自定义 ZIP 发布、押金拒签及续办、质押、启动 worker、读取真实时间线与报告、NFT、门禁复制安装，以及四步部署和激活。验证非 owner 只读、换链失效、部署后重新认证，并检查 1280×900 和 390×844 布局。生产服务没有测试钱包端点，也不加载该 provider。

**EOA 协议由本地测试 provider 验收，真实扩展弹窗待手动确认。** iframe/浏览器没有真实钱包扩展的情况下，可以查看所有公开信息；使用钱包交易请在安装钱包扩展的浏览器中打开。

截图与原始日志留在实施工作区的 `.cache/acceptance/` 和 `.superpowers/sdd/2026-10-08-role-pages/`，不含真实私钥。主要截图：`audit-wide.png`、`detail-wide.png`、`install-wide.png`、`deposit-rejected.png`、`admin-four-receipts.png`、`wrong-chain.png`、`catalog-narrow.png`。

## BOT 只读核对

未发送新的 BOT 交易，未重建原 BOT 部署。chainId 968：Registry `0xEE41a45826e747e026B90177C086123490758731`，License `0x8316AE44Cfc46f1c244c64A6Ad7cD06a636411c2`。

实际读链：weather 1.0.0 为 Verified，tokenId 1，持有人为原发布者；mail-helper 1.0.0 为 Malicious，没有许可证。两个现有报告的实际哈希均匹配链上记录。旧部署没有保存本次新格式的运行日志，详情明确显示「已有审计结果，未保存运行日志」。公开只读结果保存为 `bot-history.json`。

## 启动和测试

```bash
.venv/bin/python -m ops.server --port 8765
# 独立 Anvil + HTTP + 公开测试钱包演示（不会使用原 .env）
.venv/bin/python tests/role_demo.py --rpc-port 18857 --port 18701
# 测试
.venv/bin/python -m pytest -q -m 'not anvil'
.venv/bin/python -m pytest tests/test_roles_e2e.py tests/test_ops_chain.py tests/test_ops_transactions.py tests/test_ops_admin.py -q
node --test tests/web/*.test.mjs
(cd contracts && forge test -vv)
```

演示只绑定本机端口，端口被占用时失败，不终止已有进程。公开测试钱包仅限独立 Anvil，不得向这些地址转入任何真实资产。CLI worker 与网页 worker 共用 chain+auditor OS 锁，停止等待当前任务；激活阻止新任务，等待旧钱包锁释放，超时保留原配置。

## 执行中的决定

1. 原生工作区工具指向 Playground 仓库，无法从 SkillGuard 提交建立工作区，因此使用真正的 SkillGuard linked worktree；保留原用户未提交的公开修复为隔离基线。
2. 依赖从本机已安装的 OpenZeppelin commit `69c8def5f222ff96f2b5beff05dfba996368aa79` 恢复，未升级版本或复制原 `.env`。
3. Task 2 同时调整 HTTP transport，使其传递有界原始 ZIP；真实 HTTP 测试先返回 415，修正后通过。
4. 将公开 Anvil fixture 提前至 Task 3，使部署与人的交易核验当步就有真实回执证据。
5. 来源不可用请求从成功跳过改为保留失败区块重试，零广播；相应旧断言同步更新。
6. 浏览器使用原生 EIP-1193 签名/发送和已准备 calldata，目录读取使用有作用域的后端。CDN 不可达不会禁用正常浏览或钱包功能；固定 viem 2.38.0 只用于隔离测试 provider 的本地签名。
7. 注销保持 Origin/CSRF 边界，但幂等清除 Cookie，不要求旧钱包作用域仍有效。受保护路由仍拒绝伪造 Cookie 与不匹配钱包。

原环境的 `.env`、部署 JSON、报告、安装目录和广播记录不在公开代码集成名单内。原用户公开文件在集成前逐项比对起始摘要；新增页面和代码由独立分支保留提交历史。

## 独立审查与修复

整分支独立审查未发现 Critical，发现 4 个 Important，均在单次修复中处理：

1. 安装从已绑定请求 key 的不可变快照复制；来源替换回归证实不能装入另一已验证技能。
2. CLI / 网页上下文保存构建时的部署 revision，取得钱包锁后重新核对，旧部署上下文零处理、零广播。
3. 准备交易携带部署步骤；首次及续办确认共用幂等持久化，先恢复四步向导再移除 pending。刷新续办不再重复创建合约。
4. 浏览器质押 / 人工裁决先取得同一审计钱包锁，运行中的 worker 会拒绝该准备请求。准备完成后持久预约阻止 CLI / 网页 worker 启动；终态回执解除预约，明确的 EIP-1193 4001 拒签可取消，遗弃准备十分钟到期。未知广播错误保留预约与回执续办。操作者不要在仍打开的钱包签名窗口中重新启动 worker。

补充测试先复现错误，再验证来源替换、旧上下文、刷新续办、钱包锁/预约/取消/到期。真实隔离链验证运行时人工裁决被拒绝且 nonce 不变，停止并排空后人工裁决只消耗一个新 nonce；另外核对预约取消、回执释放及相邻 nonce。未新增 BOT 广播。

8. 首次独立审查因模型额度中断而没有报告；替代审查完成整分支检查，修复后未重复发起审查。
9. 按已批准实施计划，将验收后的公开文件逐项接回原目录并重启本机服务；不再重复询问集成方式，不自动提交原用户工作区或推送远端。

安装页提供服务机器实际 Python 与 MCP 脚本的绝对路径配置。真实钱包扩展弹窗及新的 BOT 交易仍不在本轮验证范围。

## 接回原项目后的验收

公开代码已接回 `/Users/keason/Desktop/HKSS1/skillguard`；62 个文件逐项字节一致，并发公开改动为 0，45 个受保护运行文件内容保持不变。原目录保留用户工作区 Git 状态，提交历史在隔离分支；工作区和截图保留以便复核。

服务在 `http://127.0.0.1:8765/` 重启。六个页面已接入原 BOT 配置；角色页面 HTTP 200，`/__test_wallet` 与 `/.env` 均 404。浏览器真实读取两条历史技能，weather 的许可证持有人和报告哈希匹配，明确显示「已有审计结果，未保存运行日志」。截图：`original-bot-catalog.png`、`original-bot-weather.png`。

重启后曾出现 RPC TLS 暂态错误，随后在保持证书验证的情况下恢复并读出真实链上记录；未改 RPC 配置或关闭 TLS。

10. MCP Python 配置保留虚拟环境入口的绝对路径，避免解析符号链接后丢失环境依赖；回归先失败后通过。
