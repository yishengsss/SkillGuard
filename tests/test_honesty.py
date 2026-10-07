"""演示诚信测试（SPEC 6 / 11.1.2，docs/PROMPTS.md A3）。

检查 auditor/ 与 gate/ 的 .py 源码不出现样本名 / manifest 名称，即引擎不得按
样本名分支或内联示例结论；唯一允许的是「用法示例」行（`python -m ...`）。
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# 样本目录名 / manifest 里的 name / package 字段值（rules/ 冻结即样本冻结）
SAMPLE_TOKENS = (
    "weather",
    "weather-mcp",
    "mail-helper",
    "requests-mcpp",
    "requestss",
)

USAGE_PREFIXES = (
    "python -m auditor.cli",
    "python -m auditor.stake",
    "python -m auditor.agent",
    "python gate/gate.py",
    ">>> ",
)


def _source_files() -> list[Path]:
    files: list[Path] = []
    for base in ("auditor", "gate"):
        files.extend((ROOT / base).rglob("*.py"))
    return [f for f in files if "__pycache__" not in f.parts and f.is_file()]


def test_engine_sources_mention_no_sample_names() -> None:
    offenders: list[str] = []
    for path in _source_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            text = line.strip()
            lowered = text.lower()
            usage = any(prefix in text for prefix in USAGE_PREFIXES)
            if usage:
                continue
            for token in SAMPLE_TOKENS:
                if token in lowered:
                    offenders.append(f"{path.relative_to(ROOT)}:{lineno}: {text}")
    assert offenders == []


def test_sweep_reports_no_offenders_descends_packages() -> None:
    """确认扫描范围覆盖 auditor 全部 .py（包括子目录）与 gate/。"""
    files = _source_files()
    assert any(p.name == "cli.py" for p in files)
    assert any(p.name == "gate.py" for p in files)
