"""安装方 Agent 的 MCP 工具（SPEC 9.1 / 9.2，docs/PROMPTS.md A5）。

启动（stdio 传输，Python `mcp` SDK）：
    python gate/mcp_server.py

两个工具（只读查链；不需要私钥、不发交易；两个工具都不 import、不执行技能代码）：

| 工具 | 行为 |
|---|---|
| `check_skill(skill_dir)` | 复用 `gate.check_install`：查许可证、链上状态，比对本地与链上 codeHash / metadataHash |
| `install_skill(skill_dir)` | 检查不可变快照；只有 `allowed` 才写审计范围内的文件到 staging，
  复检后替换 `SKILLGUARD_INSTALL_DIR`（默认 `<项目根>/installed/<name>-<version>/`），失败保留原安装 |

失败即拒绝：RPC 不通、chainId 不一致、地址无字节码、manifest 畸形……全部
`allowed=false / installed=false`，`reason` 说明原因（不含异常原文/密钥/RPC URL）。

工具名称与描述只做事实说明，不含对 Agent 的指令性语句。
返回字段全部来自链上读取或本地计算，无写死值。
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
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
    read_manifest_identity,
)
from auditor.skill_dir import MANIFEST_NAME, SkillSnapshot, capture_skill  # noqa: E402

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
    from gate.identity import safe_identity_component
    return safe_identity_component(value,64)


def _result_base(skill: str, version: str, config: GateConfig | None) -> dict[str, Any]:
    return {
        "skill": skill,
        "version": version,
        "status": STATUS_UNKNOWN,
        "reason": "",
        "chainId": getattr(config, "chain_id", None),
        "registry": getattr(config, "registry_address", None),
    }


def check_skill(skill_dir: str | SkillSnapshot, *, project_root: Path | None = None) -> dict[str, Any]:
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
        source = skill_dir if isinstance(skill_dir, SkillSnapshot) else Path(skill_dir)
        decision = check_install(source, config)
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


def install_skill(skill_dir: str | SkillSnapshot, *, project_root: Path | None = None, install_root: Path | None = None) -> dict[str, Any]:
    """检查快照、写入审计文件并复检；通过后替换正式安装，失败保留旧版本。"""
    root = PROJECT_ROOT if project_root is None else project_root
    base_root = install_root if install_root is not None else _install_dir(root)

    try:
        captured = skill_dir if isinstance(skill_dir, SkillSnapshot) else capture_skill(skill_dir)
    except Exception as exc:
        result = _result_base("", "", None)
        result.update(allowed=False, installed=False, installed_path=None,
                      reason=f"技能快照读取失败（{type(exc).__name__}）")
        return result
    first = check_skill(captured, project_root=root)
    if not first.get("allowed"):
        first["installed"] = False
        first["installed_path"] = None
        return first

    from gate.identity import safe_identity_component
    skill_component = safe_identity_component(str(first.get("skill", "")),128)
    version_component = _safe_component(str(first.get("version", "")))
    if skill_component is None or version_component is None:
        result = dict(first)
        result["installed"] = False
        result["installed_path"] = None
        result["reason"] = "manifest 的 name/version 含不安全字符，拒绝复制安装"
        return result

    destination = base_root / f"{skill_component}-{version_component}"
    result = dict(first, installed=False, installed_path=None)
    backup: Path | None = None
    try:
        if base_root.is_symlink() or destination.is_symlink():
            raise GateError("安装目标不能是符号链接")
        base_root.mkdir(parents=True, exist_ok=True)
        config = load_gate_config(root)
        with tempfile.TemporaryDirectory(prefix=".stage-", dir=base_root) as temporary:
            stage = Path(temporary) / "package"
            stage.mkdir()
            (stage / MANIFEST_NAME).write_bytes(captured.manifest_bytes)
            (stage / MANIFEST_NAME).chmod(captured.manifest_mode)
            modes = dict(captured.file_modes)
            for relative, content in captured.files:
                target = stage / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
                target.chmod(modes.get(relative, 0o644))
            copy_check = check_install(stage, config)
            if not copy_check.allowed:
                result["reason"] = f"副本与链上登记不一致：{copy_check.reason}"
                return result
            if destination.exists():
                if read_manifest_identity(destination) != (str(first["skill"]), str(first["version"])):
                    raise GateError("安装目标属于另一技能版本，拒绝替换")
                backup = Path(tempfile.mkdtemp(prefix=".previous-", dir=base_root))
                backup.rmdir()
                os.replace(destination, backup)
            try:
                os.replace(stage, destination)
            except OSError:
                if backup is not None:
                    os.replace(backup, destination)
                    backup = None
                raise
        if backup is not None:
            _safe_remove(backup)
    except Exception as exc:
        result["reason"] = f"复制或复检安装失败（{type(exc).__name__}）"
        if backup is not None and backup.exists():
            result["reason"] += f"；原安装保留于 {backup}"
        return result

    result = dict(first)
    result["installed"] = True
    result["installed_path"] = str(destination)
    return result


def _safe_remove(path: Path) -> None:
    try:
        if path.is_symlink():
            path.unlink()
        elif path.exists():
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
