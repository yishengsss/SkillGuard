# LLM 一致性检查（`--llm`）

SPEC 第 4 节的第 4 个检测阶段：比较 **manifest 里工具描述声称的能力** 与
**源码实际行为**（数据流向、网络/文件/子进程访问、隐藏或欺骗性行为），
用来抓静态规则看不出、但与描述矛盾的行为。

## 用法

在项目根 `.env` 里填三项（`.env.example` 有占位）：

```
LLM_API_KEY=...
LLM_BASE_URL=https://你的网关/v1
LLM_MODEL=...
```

没有默认供应商、也没有默认模型——缺任一项 `--llm` 直接报错退出（返回码 2）。

```bash
python -m auditor.cli samples/weather --llm            # 静态结论 + LLM 结论
python -m auditor.cli samples/weather --llm --submit   # 通过后一并上链
```

不加 `--llm` 时**完全不读 LLM 配置、也不发任何请求**。

## 行为

- **接口**：POST `<LLM_BASE_URL>/chat/completions`（OpenAI 兼容），
  `temperature=0`、`response_format={"type": "json_object"}`。
- **追加而非改写**：LLM 结果作为 `rule=LLM-001, stage=llm` 的 `Finding` **追加**到静态
  结果后重算 `level`。模型无法降低静态结论，也无法修改报告（`rule`/`stage` 由本端固定，
  `file` 必须是本次真实发送过的相对路径）。空结果不改变静态等级。
- **失败即中止**：网络/响应/校验失败只在 stderr 打印固定文案（不含响应原文或 key），
  stdout 保持为空，返回码 2。此时**既不落盘报告，也不上链**——`--llm --submit` 失败
  的情况下一次链上调用都不会发生。
- **缓存**：`<项目根>/.cache/llm/<sha256>.json`。缓存键由「完整请求（含提示词、temperature）+ 报告
  codeHash/metadataHash + endpoint + model + 提示词版本」生成，因此源码、manifest、
  模型或提示词任一变化都会自动失效。缓存只存校验后的 findings 和版本信息，不额外保存完整源码、key 或 URL；
  写入是原子替换；缓存不可写时本次有效结果仍可使用，但下次会重新请求。缓存**没有签名**，本机被篡改时无法检测——它只用于省一次请求，
  不是可信来源；不做一致性检查时也没有缓存可复用。
- **发送前校验**：读取到的字节会按 SPEC 的哈希约定重算，必须与报告里的
  `codeHash`/`metadataHash` 相同，否则报错要求重新扫描（防止「旧报告 + 新源码」）。

## 限制

- 内容是**原样发送**给 LLM 的：技能源码属于不可信数据。提示词已声明其为数据而非指令，
  但提示注入无法被完全消除——因此发出的内容**不会**被当作可执行指令，也不会让模型获得
  任何工具；模型输出仍然逐条校验，非法 shape 一律当失败处理，绝不降级为 SAFE。
- 输入上限 256KB、文件数上限 200、响应上限 1MB、超时 30 秒，超限直接报错，**不静默截断**；
  技能目录过大时请自行精简（`.git/`、`.cache/`、`.env*` 已自动排除）。
- endpoint 必须是 HTTPS；仅 `localhost` / `127.0.0.1` / `::1` 允许 HTTP（便于本地联调）。
  拒绝 userinfo、query、fragment，并禁用重定向。
- 只读取 `iter_skill_files` 认可的常规文件：不读 `.env`、`.git/`、`.cache/`，
  不跟随符号链接。
- 这是**辅助**信号，不是判定权威：最终 `isMalicious` 仍由报告 `level` 决定，
  与 LLM 是否启用无关。

## 测试

`tests/test_llm.py` 只替换网络边界（`urllib.request.build_opener`），缓存根为临时目录，
凭据全部是 dummy fixture，不读取真实 `.env`、不外连。

```bash
pytest -q tests/test_llm.py tests/test_llm_security.py
```
