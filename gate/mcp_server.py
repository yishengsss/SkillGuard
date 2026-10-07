"""安装方 Agent 的 MCP 工具（SPEC 9.1 / 9.2，docs/PROMPTS.md A5）。

启动（stdio 传输，Python `mcp` SDK）：
    python gate/mcp_server.py

两个工具（只读查链；不需要私钥、不发交易；两个工具都不 import、不执行技能代码）：

| 工具 | 行为 |
|---|---|
| `check_skill(skill_dir)` | 复用 `gate.check_install`：查许可证、链上状态，比对本地与链上 codeHash / metadataHash |
| `install_skill(skill_dir)` | 先做同样检查；只有 `allowed` 才把技能目录复制到 `SKILLGUARD_INSTALL_DIR`（默认
  `<项目根>/installed/<name>-<version>/`），复制后**对副本重算哈希再核对一次**，不一致就删除副本 |

失败即拒绝：RPC 不通、chainId 不一致、地址无字节码、manifest 畸形……全部
`allowed=false / installed=false`，`reason` 说明原因（不含异常原文/密钥/RPC URL）。

工具名称与描述只做事实说明，不含对 Agent 的指令性语句。
返回字段全部来自链上读取或本地计算，无写死值。
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer

# 直接以脚本运行（python gate/mcp_server.py）时，仓库根不会自动进 sys.path；
# 先算好再导入 gate / auditor。
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(PROJECT_ROOT / "gate") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "gate"))

from gate.gate import (  # noqa: E402
    Decision,
    GateConfig,
    GateError,
    check_install,
    load_gate_config,
)
from auditor.hashing import code_hash as compute_code_hash  # noqa: E402
from auditor.hashing import metadata_hash as compute_metadata_hash  # noqa: E402

INSTALL_DIR_ENV = "SKILLGUARD_INSTALL_DIR"
INSTALL_DIRNAME = "installed"

STATUS_UNKNOWN = "unknown"

server = MCPServer(
    name="skillguard-gate",
    description="SkillGuard 安装门禁：查询技能版本的链上审计状态与许可证，并按结果复制安装。",
    version="0.1.0",
)


# --------------------------------------------------------------------------
# 核心实现（与 fastmcp 装饰器解耦，测试直接调用下面两个函数）
# --------------------------------------------------------------------------
def _install_dir(project_root: Path | None = None) -> Path:
    root = PROJECT_ROOT if project_root is None else project_root
    custom = os.environ.get(INSTALL_DIR_ENV, "").strip()
    if custom:
        path = Path(custom)
        return path if path.is_absolute() else root / path
    return root / INSTALL_DIRNAME


def _safe_component(value: str) -> str | None:
    """把来自 manifest（不可信输入）的 name/version 限制成安全的路径分段。"""
    text = (value or "").strip()
    if not text or len(text) > 64:
        return None
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    if not all(ch in allowed for ch in text):
        return None
    if text.startswith(".") or "/" in text or "\\" in text:
        return None
    return text


def _result_base(skill: str, version: str, config: GateConfig | None) -> dict[str, Any]:
    return {
        "skill": skill,
        "version": version,
        "status": STATUS_UNKNOWN,
        "reason": "",
        "chainId": getattr(config, "chain_id", None),
        "registry": getattr(config, "registry_address", None),
    }


def check_skill(skill_dir: str, *, project_root: Path | None = None) -> dict[str, Any]:
    """只读查链并核对哈希；失败即拒绝。"""
    root = PROJECT_ROOT if project_root is None else project_root
    result: dict[str, Any]
    config: GateConfig | None = None
    try:
        config = load_gate_config(root)
    except GateError as exc:
        result = _result_base("", "", None)
        result["allowed"] = False
        result["reason"] = str(exc)
        return result
    except Exception as exc:
        result = _result_base("", "", None)
        result["allowed"] = False
        result["reason"] = f"读取配置失败（{type(exc).__name__}）"
        return result

    try:
        decision = check_install(Path(skill_dir), config)
    except GateError as exc:
        result = _result_base("", "", config)
        result["allowed"] = False
        result["reason"] = str(exc)
        return result
    except Exception as exc:
        result = _result_base("", "", config)
        result["allowed"] = False
        result["reason"] = f"检查未完成（{type(exc).__name__}）"
        return result

    result = _decision_to_result(decision, config)
    return result


def _decision_to_result(decision: Decision, config: GateConfig) -> dict[str, Any]:
    return {
        "allowed": decision.allowed,
        "skill": decision.skill,
        "version": decision.version,
        "status": decision.status,
        "reason": decision.reason,
        "chainId": config.chain_id,
        "registry": config.registry_address,
    }


def install_skill(skill_dir: str, *, project_root: Path | None = None, install_root: Path | None = None) -> dict[str, Any]:
    """检查 + 复制安装；只有 `allowed` 才复制，复制后对副本重算哈希再核对一次。"""
    root = PROJECT_ROOT if project_root is None else project_root
    base_root = install_root if install_root is not None else _install_dir(root)

    first = check_skill(skill_dir, project_root=root)
    if not first.get("allowed"):
        first["installed"] = False
        first["installed_path"] = None
        return first

    skill_component = _safe_component(str(first.get("skill", "")))
    version_component = _safe_component(str(first.get("version", "")))
    if skill_component is None or version_component is None:
        result = dict(first)
        result["installed"] = False
        result["installed_path"] = None
        result["reason"] = "manifest 的 name/version 含不安全字符，拒绝复制安装"
        return result

    destination = base_root / f"{skill_component}-{version_component}"
    try:
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(Path(skill_dir), destination)
    except (OSError, shutil.Error) as exc:
        result = dict(first)
        result["installed"] = False
        result["installed_path"] = None
        result["reason"] = f"复制技能目录失败（{type(exc).__name__}）"
        return result

    # 复制后对副本重算哈希，再与链上核对一次（SPEC 9.2）
    try:
        config = load_gate_config(root)
        copy_check = check_install(destination, config)
    except GateError as exc:
        _safe_remove(destination)
        result = dict(first)
        result["installed"] = False
        result["installed_path"] = None
        result["reason"] = f"副本复检失败：{exc}"
        return result
    except Exception as exc:
        _safe_remove(destination)
        result = dict(first)
        result["installed"] = False
        result["installed_path"] = None
        result["reason"] = f"副本复检未完成（{type(exc).__name__}）"
        return result

    if not copy_check.allowed:
        _safe_remove(destination)
        result = dict(first)
        result["installed"] = False
        result["installed_path"] = None
        result["reason"] = f"副本与链上登记不一致，已删除副本：{copy_check.reason}"
        return result

    result = dict(first)
    result["installed"] = True
    result["installed_path"] = str(destination)
    return result


def _safe_remove(path: Path) -> None:
    try:
        if path.exists():
            shutil.rmtree(path)
    except OSError:
        pass  # 删除失败如实保留现场，不允许"看起来安装成功"


# --------------------------------------------------------------------------
# MCP 工具注册（描述只写事实）
# --------------------------------------------------------------------------
@server.tool(
    name="check_skill",
    description="查询指定技能目录在 SkillGuard 链上的审计状态与许可证，并比对本地 codeHash/metadataHash 与链上登记是否一致。只读，不执行技能代码。",
)
def tool_check_skill(skill_dir: str) -> dict[str, Any]:
    return check_skill(skill_dir)


@server.tool(
    name="install_skill",
    description="先查询链上审计状态与许可证；只有链上允许时，把技能目录复制到安装目录并复核副本哈希。不执行技能代码。",
)
def tool_install_skill(skill_dir: str) -> dict[str, Any]:
    return install_skill(skill_dir)


def main() -> None:
    server.run()  # stdio（默认），不读私钥、不发交易


if __name__ == "__main__":
    main()
