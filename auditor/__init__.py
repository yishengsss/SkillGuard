"""SkillGuard 审计引擎（SPEC 第 4 节）。

包含离线静态审计（metadata 规则、静态规则、仿冒包名）、报告与 CLI、
上链提交（`--submit`，`auditor/submit.py`），以及可选的 LLM 一致性检查
（`--llm`，`auditor/llm.py`）。安装门禁在 `gate/gate.py`。
"""

from __future__ import annotations

ENGINE_VERSION = "0.1.0"

__all__ = ["ENGINE_VERSION"]
