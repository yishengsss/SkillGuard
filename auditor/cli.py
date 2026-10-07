"""审计引擎 CLI（SPEC 第 4 节）。

用法：
    python -m auditor.cli samples/mail-helper

本步（docs/PROMPTS.md 第 5 步）只做离线审计：

- 不实现 `--llm`（SPEC 4 第 4 阶段）与 `--submit`（第 6 步）；传入会被拒绝。
- 默认输出 SPEC 结构的报告 JSON（UTF-8，便于管道与 `json.loads`），
  非 JSON 的说明文字一律写到 **stderr**。
- 离线审计的 `auditor` 字段固定为零地址
  `0x0000000000000000000000000000000000000000`，表示**本次未上链提交**；
  真实审计者地址在 `--submit` 上链时才写入。
- `timestamp` 为 Unix 秒；`engineVersion` 为 `0.1.0`。
"""

from __future__ import annotations

import argparse
import json
import sys

from .scanner import scan_skill_report
from .skill_dir import SkillDirError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m auditor.cli",
        description="SkillGuard 审计引擎：对 MCP 技能目录做离线静态审计。",
    )
    parser.add_argument("skill_dir", help="技能目录（含 manifest.json 与源码）")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        report = scan_skill_report(args.skill_dir)
    except SkillDirError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"[错误] 找不到文件: {exc}", file=sys.stderr)
        return 2

    payload = report.to_dict()
    print(
        f"[SkillGuard] 离线审计：{report.skill} {report.version} -> {report.level}"
        f"（{len(report.findings)} 条命中；未提交上链，auditor={report.auditor}）",
        file=sys.stderr,
    )
    # 规范报告 JSON，保证可被 json.loads 解析。
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
