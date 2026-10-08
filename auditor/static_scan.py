"""静态扫描（rules/static.yaml）。

只读取技能目录内的**文本内容**做正则匹配，绝不 import / 执行技能代码。
文件遍历遵循 `skill_dir.iter_skill_files`：不跟随符号链接、跳过 .git/.cache/.env。
"""

from __future__ import annotations

from pathlib import Path

from .report import Finding
from .rules import Rule
from .skill_dir import SkillSnapshot, iter_skill_files, safe_read_bytes


def _clip(text: str, limit: int = 120) -> str:
    line = " ".join(text.split())
    if len(line) <= limit:
        return line
    return line[: limit - 1] + "…"


def scan_static(skill_dir: Path | SkillSnapshot, rules: list[Rule]) -> list[Finding]:
    """对技能源码逐文件应用静态规则，报告命中的文件与证据行。"""
    findings: list[Finding] = []
    files = skill_dir.files if isinstance(skill_dir, SkillSnapshot) else (
        (rel, safe_read_bytes(full)) for rel, full in iter_skill_files(skill_dir, include_manifest=False)
    )
    for rel, content in files:
        text = content.decode("utf-8", errors="replace")
        lines = text.splitlines() or [text]
        for rule in rules:
            evidence = _first_match(rule, lines)
            if evidence is not None:
                findings.append(
                    Finding(
                        rule=rule.id,
                        stage="static",
                        severity=rule.severity,
                        file=rel,
                        evidence=evidence,
                    )
                )
    return findings


def _first_match(rule: Rule, lines: list[str]) -> str | None:
    """返回该规则在文件中的首个命中行（同一规则同一文件只报一次）。"""
    for line in lines:
        if any(p.search(line) for p in rule.patterns):
            return _clip(line.strip())
    return None


__all__ = ["scan_static"]
