"""审计报告落盘（docs/PROMPTS.md 第 6 步）。

保存约定：
- 默认目录：**项目根目录**下的 `reports/`（`REPORTS_DIRNAME`）。
- 文件名：`<0x报告哈希>.json`，即 `reportHash = keccak256(canonical_json(report))` 的
  `0x` + 64 位小写十六进制。技能名**不进入路径**（避免技能名影响路径/被用来穿越目录）。
- 文件内容：`canonical_json(report)` 的**精确字节**，所以
  `keccak256(文件字节) == reportHash` 可被直接校验。

离线报告（`auditor` 为零地址）也保存：零地址表示「本次未上链提交」，
真实审计者地址在 `--submit` 时写回报告后再计算哈希。

报告里**不添加**交易哈希字段：落盘字节必须与链上 `reportHash` 一一对应。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .report import Report, canonical_json, report_hash_hex

REPORTS_DIRNAME = "reports"


def report_path(reports_dir: str | Path, report_hash: str) -> Path:
    """报告文件路径：`<reports_dir>/<0x报告哈希>.json`。"""
    return Path(reports_dir) / f"{report_hash}.json"


def save_report(
    report: Report | dict[str, Any],
    reports_dir: str | Path = REPORTS_DIRNAME,
) -> tuple[Path, str]:
    """保存报告，返回 `(路径, 0x 报告哈希)`。

    目录不存在时创建；内容为 `canonical_json(report)` 的精确字节。
    报告哈希在**写入前**计算，保证返回的哈希与落盘字节一致。
    """
    digest_hex = report_hash_hex(report)
    path = report_path(reports_dir, digest_hex)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(report))
    return path, digest_hex



__all__ = ["REPORTS_DIRNAME", "report_path", "save_report"]
