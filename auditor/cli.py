"""审计引擎 CLI（SPEC 第 4 节，docs/PROMPTS.md 第 5/6 步）。

用法：
    python -m auditor.cli samples/mail-helper            # 输出报告，存 reports/
    python -m auditor.cli samples/mail-helper --submit   # 并上链

输出约定：
- **stdout 只有报告 JSON**（UTF-8，`json.loads` 可直接解析）。
- 非 JSON 的说明一律走 **stderr**：保存路径、reportHash、每笔广播交易哈希
  （交易哈希在广播后立刻打印，超时也能拿去查链）。
- `--llm`（第 8 步）**尚未实现**，传入会被拒绝。

落盘（`auditor/storage.py`）：`<项目根>/reports/<0x报告哈希>.json`，内容是
`canonical_json(report)` 的精确字节，因此 `keccak256(文件字节) == reportHash`。
离线报告同样保存，其 `auditor` 为零地址（表示未上链提交）；文件里**没有**
交易哈希字段。

`--submit` 时先用 `Account.from_key(AUDITOR_PRIVATE_KEY).address` 替换零地址，
再计算 reportHash（见 `auditor/submit.py`），报告字节与链上哈希因此一致。

`project_root` 参数只用于测试注入（隔离 `.env` / `deployments.json` / `reports/`），
`python -m auditor.cli` 不暴露对应开关，默认即仓库根目录。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .report import Report, report_hash
from .scanner import scan_skill_report
from .skill_dir import SkillDirError
from .storage import REPORTS_DIRNAME, save_report
from .submit import SubmitError, auditor_account, connect, contract_for, load_config
from .submit import submit_report_onchain, with_auditor

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m auditor.cli",
        description="SkillGuard 审计引擎：对 MCP 技能目录做离线静态审计，可选上链提交。",
    )
    parser.add_argument("skill_dir", help="技能目录（含 manifest.json 与源码）")
    parser.add_argument(
        "--submit",
        action="store_true",
        help="把报告哈希提交到 SkillRegistry（需项目根 .env 与 deployments.json）",
    )
    return parser


def _parser_with_llm_placeholder() -> argparse.ArgumentParser:
    """在正式参数之上声明 `--llm`，用于给出「尚未实现」的明确错误。"""
    parser = build_parser()
    parser.add_argument("--llm", action="store_true", help=argparse.SUPPRESS)
    return parser


def _hex_to_bytes(value: str) -> bytes:
    return bytes.fromhex(value[2:] if value.startswith("0x") else value)


def _reports_dir(project_root: Path) -> Path:
    return project_root / REPORTS_DIRNAME


def main(argv: list[str] | None = None, *, project_root: Path | None = None) -> int:
    root = Path(project_root) if project_root is not None else PROJECT_ROOT
    parser = _parser_with_llm_placeholder()
    args = parser.parse_args(argv)

    if args.llm:
        print("[错误] --llm（LLM 一致性检查）尚未实现，见 docs/PROMPTS.md 第 8 步", file=sys.stderr)
        return 2

    try:
        report = scan_skill_report(args.skill_dir)
    except SkillDirError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"[错误] 找不到文件: {exc}", file=sys.stderr)
        return 2

    if args.submit:
        # 先设置真实审计者并保存，再广播；回执超时也保留报告。
        try:
            _submit_and_save(report, root)
        except SubmitError as exc:
            print(f"[错误] 上链提交失败：{exc}", file=sys.stderr)
            return 3
        except OSError as exc:
            print(f"[错误] 报告保存失败（{type(exc).__name__}）", file=sys.stderr)
            return 2
        except Exception as exc:
            print(f"[错误] 上链提交失败（{type(exc).__name__}）", file=sys.stderr)
            return 3
        return 0

    payload = report.to_dict()
    print(
        f"[SkillGuard] 离线审计：{report.skill} {report.version} -> {report.level}"
        f"（{len(report.findings)} 条命中；未提交上链，auditor={report.auditor}）",
        file=sys.stderr,
    )
    try:
        path, digest_hex = save_report(payload, _reports_dir(root))
    except OSError as exc:
        print(f"[错误] 报告保存失败（{type(exc).__name__}）", file=sys.stderr)
        return 2
    print(f"[SkillGuard] 报告已保存：{path}", file=sys.stderr)
    print(f"[SkillGuard] reportHash：{digest_hex}", file=sys.stderr)
    # 规范报告 JSON，保证可被 json.loads 解析。
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False))
    return 0


def _submit_and_save(report: Report, root: Path) -> None:
    """设置真实审计者 → 保存报告 → 预检查 → 广播；失败时保留原报告。"""
    config = load_config(
        env_path=root / ".env",
        deployments_path=root / "deployments.json",
    )
    account = auditor_account(config.private_key)
    payload = with_auditor(report, account.address)

    print(
        f"[SkillGuard] 上链提交：{payload['skill']} {payload['version']} -> {payload['level']}"
        f"（auditor={account.address}）",
        file=sys.stderr,
    )

    path, digest_hex = save_report(payload, _reports_dir(root))
    print(f"[SkillGuard] 报告已保存：{path}", file=sys.stderr)
    print(f"[SkillGuard] reportHash：{digest_hex}", file=sys.stderr)

    w3 = connect(config)
    contract = contract_for(w3, config)
    submit_report_onchain(
        w3=w3,
        contract=contract,
        account=account,
        chain_id=config.chain_id,
        skill=payload["skill"],
        version=payload["version"],
        level=payload["level"],
        report_hash=report_hash(payload),
        code_hash=_hex_to_bytes(payload["codeHash"]),
        metadata_hash=_hex_to_bytes(payload["metadataHash"]),
        log=lambda line: print(line, file=sys.stderr),
    )

    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False))


if __name__ == "__main__":
    raise SystemExit(main())
