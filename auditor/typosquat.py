"""仿冒包名检测（SPEC 第 4 节：与 rules/known_packages.txt 编辑距离 ≤ 2 且不相同）。

编辑距离用 Levenshtein（插入/删除/替换各计 1）。包名与已知包名先统一小写并
去掉前后空白，避免大小写差异造成漏检。
"""

from __future__ import annotations

from .report import Finding

PKG_RULE_ID = "PKG-001"
MAX_EDIT_DISTANCE = 2


def levenshtein(a: str, b: str) -> int:
    """标准 Levenshtein 编辑距离。"""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost))
        previous = current
    return previous[-1]


def find_impersonation(package: str, known_packages: list[str]) -> tuple[str, int] | None:
    """返回 `(被仿冒的已知包, 编辑距离)`；没有命中返回 None。"""
    name = (package or "").strip().lower()
    if not name:
        return None
    best: tuple[str, int] | None = None
    for known in known_packages:
        target = known.strip().lower()
        if not target or target == name:
            continue
        distance = levenshtein(name, target)
        if 0 < distance <= MAX_EDIT_DISTANCE and (best is None or distance < best[1]):
            best = (target, distance)
    return best


def scan_package(package: str, known_packages: list[str]) -> list[Finding]:
    """对 manifest 的 package 字段做仿冒检测，命中记为 critical（SPEC：MALICIOUS）。"""
    hit = find_impersonation(package, known_packages)
    if hit is None:
        return []
    target, distance = hit
    return [
        Finding(
            rule=PKG_RULE_ID,
            stage="package",
            severity="critical",
            file="manifest.json",
            evidence=f"package={package!r} 与已知包 {target!r} 编辑距离 {distance}",
        )
    ]


__all__ = [
    "PKG_RULE_ID",
    "find_impersonation",
    "levenshtein",
    "scan_package",
]
