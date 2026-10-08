"""安装前门禁（SPEC 第 5 节，docs/PROMPTS.md 第 7 步）。

用法：
    python gate/gate.py install samples/<skill>

只读检查，**不执行/安装/导入技能代码，不发交易，不需要私钥**：

1. 读技能目录的 `manifest.json`（拒绝符号链接 / FIFO / 畸形 JSON），取 `name` / `version`；
2. 从项目根 `deployments.json` 读 `chainId` / `SkillLicense` / `SkillRegistry`，
   从项目根 `.env` 读 `RPC_URL`（**只读不打印**；显式 `os.environ["RPC_URL"]` 覆盖 `.env`）；
3. 在**同一个 block_number** 上查询 `SkillLicense.isVerified(name, version)` 与
   `SkillRegistry.keyOf` / `skills(key)`：
   - 状态必须是 `Verified(3)`、许可证必须存在；
   - 登记的 `codeHash` / `metadataHash` 必须与本地用 `auditor.hashing` 算出的值一致，
     因此改源码或改 manifest 都不能复用已获证的版本。

  全部满足 → 绿色 `✔ VERIFIED，允许安装`（exit 0）；否则红色 `✘ 拒绝安装` 并显示状态/
   原因（exit 1，配置/网络类失败 exit 2）。

门禁的键（skillId = manifest `name`，version = manifest `version`）来自**不可信输入**，
因此所有输出都用 `rich.text.Text` 构造、不解析 markup，避免富文本注入。

`project_root` / `console` 参数只用于测试注入；默认项目根由 `__file__` 计算。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# 直接以脚本运行（python gate/gate.py）时，仓库根不会自动进 sys.path；
# 先算好再导入 auditor，才能复用哈希与安全读取实现。
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import dotenv_values  # noqa: E402
from rich.console import Console  # noqa: E402
from rich.text import Text  # noqa: E402
from web3 import Web3  # noqa: E402

from auditor.hashing import code_hash, metadata_hash  # noqa: E402
from auditor.skill_dir import MANIFEST_NAME, SkillDirError, SkillSnapshot, capture_skill  # noqa: E402

DEPLOYMENTS_FILE = "deployments.json"
ENV_FILE = ".env"
RPC_TIMEOUT_SECONDS = 15

EXIT_ALLOW = 0
EXIT_REJECT = 1
EXIT_ERROR = 2

ALLOW_MESSAGE = "✔ VERIFIED，允许安装"
REJECT_MESSAGE = "✘ 拒绝安装"

# SPEC 3.1 的状态枚举，完整映射并显示
STATUS_NAMES = {
    0: "None",
    1: "Registered",
    2: "AuditRequested",
    3: "Verified",
    4: "Malicious",
}
STATUS_VERIFIED = 3

# 最小只读 ABI（只含门禁用到的成员）
SKILL_LICENSE_ABI: list[dict[str, Any]] = [
    {
        "type": "function",
        "name": "isVerified",
        "stateMutability": "view",
        "inputs": [
            {"name": "skillId", "type": "string"},
            {"name": "version", "type": "string"},
        ],
        "outputs": [{"name": "", "type": "bool"}],
    },
]

SKILL_REGISTRY_ABI: list[dict[str, Any]] = [
    {
        "type": "function",
        "name": "keyOf",
        "stateMutability": "pure",
        "inputs": [
            {"name": "skillId", "type": "string"},
            {"name": "version", "type": "string"},
        ],
        "outputs": [{"name": "", "type": "bytes32"}],
    },
    {
        "type": "function",
        "name": "skills",
        "stateMutability": "view",
        "inputs": [{"name": "", "type": "bytes32"}],
        "outputs": [
            {"name": "publisher", "type": "address"},
            {"name": "repo", "type": "string"},
            {"name": "codeHash", "type": "bytes32"},
            {"name": "metadataHash", "type": "bytes32"},
            {"name": "deposit", "type": "uint256"},
            {"name": "status", "type": "uint8"},
            {"name": "reportHash", "type": "bytes32"},
            {"name": "auditor", "type": "address"},
        ],
    },
]


class GateError(Exception):
    """门禁无法完成（配置 / manifest / 网络错误）。

    只携带**安全消息**：阶段 + 异常类型，绝不含异常原文、RPC URL 或其他凭据。
    """


@dataclass(frozen=True)
class GateConfig:
    rpc_url: str = field(repr=False)
    chain_id: int
    license_address: str
    registry_address: str


@dataclass(frozen=True)
class Decision:
    allowed: bool
    skill: str
    version: str
    status: str
    reason: str = ""


# --------------------------------------------------------------------------
# 配置
# --------------------------------------------------------------------------
def _rpc_url(project_root: Path) -> str:
    """项目根 `.env` 的 `RPC_URL`；显式 `os.environ["RPC_URL"]` 覆盖文件值。"""
    env_path = project_root / ENV_FILE
    file_values: dict[str, Any] = {}
    if env_path.is_file():
        try:
            file_values = dict(dotenv_values(env_path))
        except Exception as exc:  # 只报类别，不回显内容
            raise GateError(f"配置文件解析失败（{type(exc).__name__}）") from None

    value = os.environ["RPC_URL"] if "RPC_URL" in os.environ else file_values.get("RPC_URL")
    rpc_url = (value or "").strip()
    if not rpc_url:
        raise GateError(f"缺少配置 RPC_URL（请写入项目根目录 {ENV_FILE}）")
    return rpc_url


def load_gate_config(project_root: Path) -> GateConfig:
    """读 `RPC_URL` + `deployments.json`；缺值/非法值一律 `GateError`。

    门禁不需要私钥，因此不复用 `auditor.submit.load_config`（它要求 AUDITOR_PRIVATE_KEY）。
    """
    rpc_url = _rpc_url(Path(project_root))

    deploy_file = Path(project_root) / DEPLOYMENTS_FILE
    if not deploy_file.is_file():
        raise GateError(f"缺少部署文件 {DEPLOYMENTS_FILE}")
    try:
        deployment = json.loads(deploy_file.read_text(encoding="utf-8"))
    except Exception as exc:
        raise GateError(f"部署文件不是合法 JSON（{type(exc).__name__}）") from None
    if not isinstance(deployment, dict):
        raise GateError(f"部署文件 {DEPLOYMENTS_FILE} 顶层必须是对象")

    chain_id = deployment.get("chainId")
    if not isinstance(chain_id, int) or isinstance(chain_id, bool) or chain_id <= 0:
        raise GateError("部署文件缺少合法的 chainId")

    addresses = {}
    for key in ("SkillLicense", "SkillRegistry"):
        value = deployment.get(key)
        if not isinstance(value, str) or not Web3.is_checksum_address(value):
            raise GateError(f"部署文件缺少合法的 {key} 地址")
        addresses[key] = value

    return GateConfig(
        rpc_url=rpc_url,
        chain_id=chain_id,
        license_address=addresses["SkillLicense"],
        registry_address=addresses["SkillRegistry"],
    )


# --------------------------------------------------------------------------
# manifest（只读取，不执行技能代码）
# --------------------------------------------------------------------------
def read_manifest_identity(skill_dir: Path | SkillSnapshot) -> tuple[str, str]:
    """读 manifest.json 的 `name` / `version`（顶层对象 + 非空字符串）。"""
    try:
        captured = skill_dir if isinstance(skill_dir, SkillSnapshot) else capture_skill(skill_dir)
        raw = captured.manifest_bytes.decode("utf-8", errors="replace")
    except SkillDirError as exc:
        raise GateError(str(exc)) from None

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        raise GateError(f"{MANIFEST_NAME} 不是合法 JSON") from None
    if not isinstance(data, dict):
        raise GateError(f"{MANIFEST_NAME} 顶层必须是 JSON 对象")

    identity: list[str] = []
    for name in ("name", "version"):
        value = data.get(name)
        if not isinstance(value, str) or not value.strip():
            raise GateError(f"{MANIFEST_NAME} 字段 {name} 必须是非空字符串")
        identity.append(value)
    return identity[0], identity[1]


# --------------------------------------------------------------------------
# 链上查询
# --------------------------------------------------------------------------
def connect(rpc_url: str) -> Web3:
    return Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": RPC_TIMEOUT_SECONDS}))


def _as_bytes32(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return bytes.fromhex(value[2:] if value.startswith("0x") else value)
    return bytes(value)


def _check_onchain(config: GateConfig, skill: str, version: str) -> tuple[int, bytes, bytes, bool]:
    """同一 block_number 读取许可证与登记状态/哈希，返回 `(status, codeHash, metadataHash, verified)`。"""
    try:
        w3 = connect(config.rpc_url)
    except Exception as exc:
        raise GateError(f"RPC 连接失败（{type(exc).__name__}）") from None

    try:
        connected = w3.is_connected()
    except Exception as exc:
        raise GateError(f"RPC 连接检查失败（{type(exc).__name__}）") from None
    if not connected:
        raise GateError("RPC 未连接")

    try:
        chain_id = w3.eth.chain_id
    except Exception as exc:
        raise GateError(f"读取 chainId 失败（{type(exc).__name__}）") from None
    if chain_id != config.chain_id:
        raise GateError(f"chainId 不匹配：链上 {chain_id} != 部署 {config.chain_id}")

    try:
        license_code = w3.eth.get_code(config.license_address)
        registry_code = w3.eth.get_code(config.registry_address)
    except Exception as exc:
        raise GateError(f"读取合约字节码失败（{type(exc).__name__}）") from None
    if not license_code:
        raise GateError("SkillLicense 地址没有合约字节码")
    if not registry_code:
        raise GateError("SkillRegistry 地址没有合约字节码")

    try:
        license_contract = w3.eth.contract(address=config.license_address, abi=SKILL_LICENSE_ABI)
        registry_contract = w3.eth.contract(address=config.registry_address, abi=SKILL_REGISTRY_ABI)
    except Exception as exc:
        raise GateError(f"绑定合约失败（{type(exc).__name__}）") from None

    try:
        block = w3.eth.block_number
    except Exception as exc:
        raise GateError(f"读取区块高度失败（{type(exc).__name__}）") from None

    try:
        key = registry_contract.functions.keyOf(skill, version).call(block_identifier=block)
        entry = registry_contract.functions.skills(key).call(block_identifier=block)
        verified = license_contract.functions.isVerified(skill, version).call(block_identifier=block)
    except Exception as exc:
        raise GateError(f"读取链上状态失败（{type(exc).__name__}）") from None

    return int(entry[5]), _as_bytes32(entry[2]), _as_bytes32(entry[3]), bool(verified)


def check_install(skill_dir: Path | SkillSnapshot, config: GateConfig) -> Decision:
    """完整门禁判定；`GateError` 表示无法完成（exit 2），否则返回 `Decision`。"""
    try:
        captured = skill_dir if isinstance(skill_dir, SkillSnapshot) else capture_skill(skill_dir)
        skill, version = read_manifest_identity(captured)
        local_code_hash = code_hash(captured)
        local_metadata_hash = metadata_hash(captured)
    except SkillDirError as exc:
        raise GateError(str(exc)) from None

    status, onchain_code_hash, onchain_metadata_hash, verified = _check_onchain(
        config, skill, version
    )
    label = f"{STATUS_NAMES.get(status, 'Unknown')}({status})"

    def reject(reason: str) -> Decision:
        return Decision(False, skill, version, label, reason)

    if status not in STATUS_NAMES:
        return reject(f"链上返回未知状态值 {status}")
    if status != STATUS_VERIFIED:
        return reject(f"技能状态不是 Verified({STATUS_VERIFIED})，当前 {label}")
    if not verified:
        return reject(f"链上没有 VERIFIED 许可证（状态 {label}）")
    if onchain_code_hash != local_code_hash:
        return reject("技能代码与链上登记不一致（codeHash 不同），请重新审计")
    if onchain_metadata_hash != local_metadata_hash:
        return reject("清单内容与链上登记不一致（metadataHash 不同），请重新审计")
    return Decision(True, skill, version, label)


# --------------------------------------------------------------------------
# 输出（全部经 Text 构造，不解析 markup）
# --------------------------------------------------------------------------
def _header(decision: Decision) -> Text:
    text = Text("[SkillGuard gate] ", style="cyan")
    text.append(decision.skill, style="bold")
    text.append(" ")
    text.append(decision.version, style="bold")
    text.append(f"（状态 {decision.status}）")
    return text


def _print_allow(console: Console, decision: Decision) -> None:
    console.print(_header(decision))
    console.print(Text(ALLOW_MESSAGE, style="bold green"))


def _print_reject(console: Console, *, reason: str, decision: Decision | None = None) -> None:
    if decision is None:
        console.print(Text("[SkillGuard gate] 门禁无法完成", style="cyan"))
    else:
        console.print(_header(decision))
    console.print(Text(f"{REJECT_MESSAGE}：{reason}", style="bold red"))


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python gate/gate.py",
        description="SkillGuard 安装门禁：安装前查询链上许可证，只读、不发交易、不需要私钥。",
    )
    parser.add_argument("command", choices=["install"], help="目前只支持 install")
    parser.add_argument("skill_dir", help="技能目录（含 manifest.json）")
    return parser


def main(
    argv: list[str] | None = None,
    *,
    project_root: Path | None = None,
    console: Console | None = None,
) -> int:
    args = build_parser().parse_args(argv)
    out = console if console is not None else Console()
    root = Path(project_root) if project_root is not None else PROJECT_ROOT

    try:
        config = load_gate_config(root)
        decision = check_install(Path(args.skill_dir), config)
    except GateError as exc:
        _print_reject(out, reason=str(exc))
        return EXIT_ERROR
    except Exception as exc:
        # Fail closed without exposing file contents or RPC credentials.
        _print_reject(out, reason=f"读取或验证失败（{type(exc).__name__}）")
        return EXIT_ERROR

    if decision.allowed:
        _print_allow(out, decision)
        return EXIT_ALLOW

    _print_reject(out, reason=decision.reason, decision=decision)
    return EXIT_REJECT


if __name__ == "__main__":
    raise SystemExit(main())
