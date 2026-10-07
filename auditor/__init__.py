"""SkillGuard 审计引擎（SPEC 第 4 节）。

本步仅实现离线静态审计：metadata 规则、静态规则、仿冒包名、报告与 CLI。
不含 LLM 一致性检查（--llm）、上链提交（--submit）与门禁。
"""

from __future__ import annotations

ENGINE_VERSION = "0.1.0"

__all__ = ["ENGINE_VERSION"]
