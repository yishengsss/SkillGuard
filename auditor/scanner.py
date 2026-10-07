"""审计流程编排（SPEC 第 4 节检测阶段）。

阶段：1 描述投毒（metadata）→ 2 静态扫描（static）→ 3 仿冒包名（package）。
`--sandbox`（方案书 3.5.2 四段式流水线的第 3 段）与 LLM 一致性（第 4 阶段）**不在这里**：
它们由 CLI 在静态扫描之后按需调用 `auditor/sandbox.py` / `auditor/llm.py`，再把结果追加进报告
（见 `auditor/cli.py`）。

`scan_skill()` 返回 **dict**（SPEC 结构的报告 JSON），便于 CLI 直接输出与哈希。
需要 `Report` 对象时用 `scan_skill_report()`。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .hashing import code_hash as compute_code_hash
from .hashing import metadata_hash as compute_metadata_hash
from .metadata_scan import scan_metadata
from .report import Finding, Report, build_report
from .rules import load_known_packages, load_rules
from .skill_dir import MANIFEST_NAME, SkillDirError, safe_read_text
from .static_scan import scan_static
from .typosquat import scan_package

DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def _require_non_empty_str(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SkillDirError(f"{MANIFEST_NAME} 字段 {field} 必须是非空字符串")
    return value


def _validate_tool(tool: Any, index: int) -> None:
    where = f"tools[{index}]"
    if not isinstance(tool, dict):
        raise SkillDirError(f"{MANIFEST_NAME} 的 {where} 必须是对象")
    _require_non_empty_str(tool.get("name"), f"{where}.name")
    if not isinstance(tool.get("description"), str):
        raise SkillDirError(f"{MANIFEST_NAME} 的 {where}.description 必须是字符串")
    input_schema = tool.get("inputSchema")
    if not isinstance(input_schema, dict):
        raise SkillDirError(f"{MANIFEST_NAME} 的 {where}.inputSchema 必须是对象")


def _load_manifest(skill_dir: Path) -> dict[str, Any]:
    """读取并校验 manifest.json（形状不合规一律抛 `SkillDirError`）。

    形状要求（SPEC 第 4 节 manifest 格式）：
    - 顶层为对象；`name` / `package` / `version` 为非空字符串；
    - `tools` 为数组；每个 tool 为对象，含非空字符串 `name`、字符串 `description`、
      对象 `inputSchema`。

    文件本身用 `safe_read_text()` 读取：拒绝符号链接与 FIFO/设备等非常规文件。
    """
    if not skill_dir.is_dir():
        raise SkillDirError(f"技能目录不存在或不是目录: {skill_dir}")
    path = skill_dir / MANIFEST_NAME
    if path.is_symlink():
        raise SkillDirError(f"拒绝符号链接的 {MANIFEST_NAME}: {path}")
    if not path.exists():
        raise SkillDirError(f"缺少 {MANIFEST_NAME}: {skill_dir}")
    if not path.is_file():
        raise SkillDirError(f"拒绝非常规文件（FIFO/设备等）的 {MANIFEST_NAME}: {path}")
    raw = safe_read_text(path)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SkillDirError(f"{MANIFEST_NAME} 不是合法 JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise SkillDirError(f"{MANIFEST_NAME} 顶层必须是 JSON 对象")

    _require_non_empty_str(data.get("name"), "name")
    _require_non_empty_str(data.get("package"), "package")
    _require_non_empty_str(data.get("version"), "version")

    tools = data.get("tools")
    if not isinstance(tools, list):
        raise SkillDirError(f"{MANIFEST_NAME} 的 tools 必须是数组")
    for index, tool in enumerate(tools):
        _validate_tool(tool, index)

    return data


def _now() -> int:
    import time

    return int(time.time())


def scan_skill(skill_dir: str | Path, *, rules_dir: str | Path | None = None) -> dict[str, Any]:
    """扫描技能目录，返回 SPEC 结构的报告 dict。"""
    return scan_skill_report(skill_dir, rules_dir=rules_dir).to_dict()


def scan_skill_report(
    skill_dir: str | Path, *, rules_dir: str | Path | None = None
) -> Report:
    """扫描技能目录，返回 `Report` 对象。"""
    root = Path(skill_dir)
    rules_path = Path(rules_dir) if rules_dir is not None else DEFAULT_RULES_DIR

    manifest = _load_manifest(root)
    metadata_rules = load_rules(rules_path, "metadata")
    static_rules = load_rules(rules_path, "static")
    known_packages = load_known_packages(rules_path)

    findings: list[Finding] = []
    findings.extend(scan_metadata(manifest, metadata_rules))
    findings.extend(scan_static(root, static_rules))
    findings.extend(scan_package(str(manifest.get("package", "")), known_packages))

    skill_name = manifest["name"]
    version = manifest["version"]

    return build_report(
        skill=skill_name,
        version=version,
        code_hash=compute_code_hash(root),
        metadata_hash=compute_metadata_hash(root),
        findings=findings,
        timestamp=_now(),
    )


__all__ = ["DEFAULT_RULES_DIR", "scan_skill", "scan_skill_report"]
