"""人工质押命令（SPEC 8.1 / docs/PROMPTS.md A1）。

用法（由**人**运行，押钱担保是人的决定；Agent 与 CLI 不代押）：
    python -m auditor.stake

行为：
1. 读配置：与 `auditor/submit.py` 相同——项目根 `.env` 的 `RPC_URL`、
   `AUDITOR_PRIVATE_KEY` 与 `deployments.json`。
2. 读链上 `auditorStake(自己)` 与常量 `AUDITOR_STAKE`：
   - 已足额：只打印当前质押额（从链上读），**不发交易**；
   - 不足：发一笔 `stakeAsAuditor{value: AUDITOR_STAKE}`，打印交易哈希，
     等回执后再读链打印质押后的余额。
3. 判定、数值全部来自真实链上读取；不打印私钥 / RPC URL。
"""

from __future__ import annotations

import sys

from .submit import (
    SubmitError,
    auditor_account,
    connect,
    contract_for,
    load_config,
)

# 与 auditor.submit 保持一致的发交易实现（预检查后的最小广播路径）
from . import submit as _submit_mod
from .submit import _send  # 包内复用，避免复制一份发交易代码


def stake(*, log=None) -> tuple[str | None, int]:
    """执行人工质押；返回 `(交易哈希|None, 质押后链上质押额)`。"""
    config = load_config()
    account = auditor_account(config.private_key)
    w3 = connect(config)
    contract = contract_for(w3, config)

    try:
        staked = int(contract.functions.auditorStake(account.address).call())
        minimum = int(contract.functions.AUDITOR_STAKE().call())
    except Exception as exc:
        raise SubmitError(f"读取质押额失败（{type(exc).__name__}）") from None

    if staked >= minimum:
        if log is not None:
            log(f"[SkillGuard] 质押已足额：{staked} wei（要求 {minimum}），不发交易")
        return None, staked

    tx_hash = _send(
        w3=w3,
        account=account,
        contract=contract,
        chain_id=config.chain_id,
        fn=contract.functions.stakeAsAuditor(),
        value=minimum,
        stage="质押审计者（stakeAsAuditor）",
        log=log,
    )

    try:
        after = int(contract.functions.auditorStake(account.address).call())
    except Exception as exc:
        raise SubmitError(f"质押后读取质押额失败（{type(exc).__name__}）") from None
    return tx_hash, after


def main(argv: list[str] | None = None) -> int:
    try:
        tx_hash, amount = stake(log=lambda line: print(line, file=sys.stderr))
    except SubmitError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return 3
    except Exception as exc:  # 兜底：只报类型，不回显异常原文
        print(f"[错误] 质押失败（{type(exc).__name__}）", file=sys.stderr)
        return 3
    if tx_hash is not None:
        print(f"[SkillGuard] 质押交易：{tx_hash}", file=sys.stderr)
    print(f"[SkillGuard] 当前质押额（链上读取）：{amount} wei")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
