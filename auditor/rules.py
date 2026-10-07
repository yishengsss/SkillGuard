"""规则加载（rules/*.yaml、rules/known_packages.txt）。

只读取 YAML 中已存在的字段，不发明新字段：
- metadata.yaml / static.yaml：id / name / severity / patterns / max_length
- known_packages.txt：每行一个已知包名（# 开头为注释）
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class Rule:
    """一条检测规则。"""

    id: str
    name: str
    severity: str
    patterns: tuple[re.Pattern[str], ...] = ()
    max_length: int | None = None


def _compile(patterns: list[str] | None) -> tuple[re.Pattern[str], ...]:
    # 规则里已有内联 (?i) 等标志，这里用 IGNORECASE 让中英文大小写都不漏。
    return tuple(re.compile(p, re.IGNORECASE) for p in (patterns or []))


def load_rules(rules_dir: Path, stage: str) -> list[Rule]:
    """加载某个阶段的规则（stage: "metadata" | "static"）。"""
    path = Path(rules_dir) / f"{stage}.yaml"
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    return [
        Rule(
            id=item["id"],
            name=item.get("name", ""),
            severity=item["severity"],
            patterns=_compile(item.get("patterns")),
            max_length=item.get("max_length"),
        )
        for item in raw
    ]


def load_known_packages(rules_dir: Path) -> list[str]:
    """加载已知包名列表（仿冒检测用）。"""
    path = Path(rules_dir) / "known_packages.txt"
    names: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        name = line.strip()
        if name and not name.startswith("#"):
            names.append(name)
    return names
