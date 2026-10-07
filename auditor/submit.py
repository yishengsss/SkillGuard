"""上链提交（docs/PROMPTS.md 第 6 步，SPEC 第 3.1/7 节）。

流程（**预检查全过才发第一笔交易**）：

1. 读配置：`--submit` 时从**项目根目录的 `.env`** 读 `RPC_URL` 与
   `AUDITOR_PRIVATE_KEY`，从 `deployments.json` 读 `chainId` 与 `SkillRegistry`。
   代码只读不打印这些值。
2. 连接 `Web3.HTTPProvider(RPC_URL, timeout=15)`；用
   `Account.from_key(AUDITOR_PRIVATE_KEY)` 得到审计者地址，把报告里的零地址
   换成该地址后**再**算 `reportHash`（报告字节与链上哈希因此一致）。
3. 预检查：RPC 已连接、`eth.chain_id == deployments.chainId`、registry 地址有字节码；
   读 `keyOf(skill, version)` 与 `skills(key)`（`publisher / repo / codeHash /
   metadataHash / deposit / status / reportHash / auditor`），要求
   `status == AuditRequested(2)`、`publisher != auditor`、登记的 `codeHash` 与
   `metadataHash` 与报告一致。任一不过直接失败，**一笔都不发**。
4. `auditorStake(auditor)` 与常量 `AUDITOR_STAKE`：仅质押不足时才发一笔
   `stakeAsAuditor{value: AUDITOR_STAKE}`（合约每次至少要求最小值）。
5. 该笔回执 `status == 1` 后才 `submitReport(skill, version, isMalicious, reportHash)`，
   其中 `isMalicious = (level == MALICIOUS)`（SUSPICIOUS 按 SPEC 为 `false`）。

每笔交易都重新取 `pending` nonce，带 `chainId`、`gasPrice`、`estimate_gas` + 余量，
真实签名（`sign_transaction(...).raw_transaction`）后
`send_raw_transaction`，再 `wait_for_transaction_receipt(timeout=120, poll_latency=0.2)`。
交易哈希在广播后**立即**回调打印（`log`），超时也能拿哈希去查链；失败或超时返回
非零（抛 `SubmitError`），**不自动重发**。

敏感边界：未知/底层异常一律转成 `SubmitError` 的**安全自定义消息**（只含
失败类别与阶段），不打印异常原文、私钥或 RPC URL。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from dotenv import dotenv_values
from eth_account import Account
from web3 import Web3

from .report import MALICIOUS, Report

# 与 SkillRegistry.sol 精确对应的最小 ABI（只含用到的成员）
SKILL_REGISTRY_ABI: list[dict[str, Any]] = [
    {
        "type": "function",
        "name": "AUDITOR_STAKE",
        "stateMutability": "view",
        "inputs": [],
        "outputs": [{"name": "", "type": "uint256"}],
    },
    {
        "type": "function",
        "name": "auditorStake",
        "stateMutability": "view",
        "inputs": [{"name": "", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}],
    },
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
    {
        "type": "function",
        "name": "stakeAsAuditor",
        "stateMutability": "payable",
        "inputs": [],
        "outputs": [],
    },
    {
        "type": "function",
        "name": "submitReport",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "skillId", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "isMalicious", "type": "bool"},
            {"name": "reportHash", "type": "bytes32"},
        ],
        "outputs": [],
    },
]

STATUS_AUDIT_REQUESTED = 2

RPC_TIMEOUT_SECONDS = 15
RECEIPT_TIMEOUT_SECONDS = 120
RECEIPT_POLL_LATENCY = 0.2
GAS_MARGIN_NUMERATOR = 6  # 估 gas * 1.2
GAS_MARGIN_DENOMINATOR = 5

ENV_FILE = ".env"
DEPLOYMENTS_FILE = "deployments.json"


class SubmitError(Exception):
    """上链提交失败。

    只携带**安全消息**：失败类别/阶段 + 可公开的链上标识（如已广播的交易哈希），
    绝不含异常原文、私钥或 RPC URL。
    """


@dataclass(frozen=True)
class SubmitConfig:
    rpc_url: str = field(repr=False)
    private_key: str = field(repr=False)
    chain_id: int
    registry_address: str


def _read_kv_file(path: Path) -> dict[str, str | None]:
    try:
        return dict(dotenv_values(path))
    except SubmitError:
        raise
    except Exception as exc:  # 只报类别，不回显路径内容
        raise SubmitError(f"配置文件解析失败（{type(exc).__name__}）") from None


def load_config(
    *,
    env_path: str | Path | None = None,
    deployments_path: str | Path | None = None,
) -> SubmitConfig:
    """读取 `.env` 与 `deployments.json`（**只读不打印**）。

    `.env` 用 `dotenv_values` 解析，显式环境变量覆盖文件值，允许在保留项目配置的
    同时切换本地测试账户和 RPC。缺值/非法值一律 `SubmitError`，
    消息里不含具体取值。
    """
    env_file = Path(env_path) if env_path is not None else Path(ENV_FILE)
    file_values = _read_kv_file(env_file) if env_file.is_file() else {}
    merged = {key: value for key, value in file_values.items() if value is not None}
    for key in ("RPC_URL", "AUDITOR_PRIVATE_KEY"):
        if key in os.environ:
            merged[key] = os.environ[key]

    rpc_url = (merged.get("RPC_URL") or "").strip()
    private_key = (merged.get("AUDITOR_PRIVATE_KEY") or "").strip()
    if not rpc_url:
        raise SubmitError("缺少配置 RPC_URL（请写入项目根目录 .env）")
    if not private_key:
        raise SubmitError("缺少配置 AUDITOR_PRIVATE_KEY（请写入项目根目录 .env）")

    deploy_file = (
        Path(deployments_path) if deployments_path is not None else Path(DEPLOYMENTS_FILE)
    )
    if not deploy_file.is_file():
        raise SubmitError(f"缺少部署文件 {DEPLOYMENTS_FILE}")
    import json

    try:
        deployment = json.loads(deploy_file.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SubmitError(f"部署文件不是合法 JSON（{type(exc).__name__}）") from None
    if not isinstance(deployment, dict):
        raise SubmitError(f"部署文件 {DEPLOYMENTS_FILE} 顶层必须是对象")

    chain_id = deployment.get("chainId")
    if not isinstance(chain_id, int) or isinstance(chain_id, bool) or chain_id <= 0:
        raise SubmitError(f"部署文件缺少合法的 chainId")
    registry = deployment.get("SkillRegistry")
    if not isinstance(registry, str) or not Web3.is_checksum_address(registry):
        raise SubmitError("部署文件缺少合法的 SkillRegistry 地址")

    return SubmitConfig(
        rpc_url=rpc_url,
        private_key=private_key,
        chain_id=chain_id,
        registry_address=Web3.to_checksum_address(registry),
    )


def connect(config: SubmitConfig) -> Web3:
    """`Web3.HTTPProvider(RPC_URL, timeout=15)`。"""
    return Web3(Web3.HTTPProvider(config.rpc_url, request_kwargs={"timeout": RPC_TIMEOUT_SECONDS}))


def contract_for(w3: Any, config: SubmitConfig):
    """用最小 ABI 绑定 SkillRegistry。"""
    return w3.eth.contract(address=config.registry_address, abi=SKILL_REGISTRY_ABI)


def auditor_account(private_key: str) -> Any:
    """`Account.from_key(...)`；失败只报类别，不回显密钥。"""
    try:
        return Account.from_key(private_key)
    except Exception as exc:
        raise SubmitError(f"审计者私钥不可用（{type(exc).__name__}）") from None


def with_auditor(report: Report | dict[str, Any], auditor: str) -> dict[str, Any]:
    """把报告里的零地址审计者换成真实地址（返回新 dict，不改原对象）。

    必须在计算 `reportHash` **之前**做，报告字节才会与链上哈希一致。
    """
    payload = report.to_dict() if isinstance(report, Report) else dict(report)
    payload["auditor"] = auditor
    return payload


def _as_bytes32(value: Any) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return bytes.fromhex(value[2:] if value.startswith("0x") else value)
    return bytes(value)


def _precheck(
    *,
    w3: Any,
    contract: Any,
    chain_id: int,
    account: Any,
    skill: str,
    version: str,
    code_hash: bytes,
    metadata_hash: bytes,
) -> bytes:
    """全部预检查；返回版本登记 key。任一不过抛 `SubmitError`（零广播）。"""
    try:
        connected = w3.is_connected()
    except Exception as exc:
        raise SubmitError(f"RPC 连接检查失败（{type(exc).__name__}）") from None
    if not connected:
        raise SubmitError("RPC 未连接")

    try:
        actual_chain_id = w3.eth.chain_id
    except Exception as exc:
        raise SubmitError(f"读取 chainId 失败（{type(exc).__name__}）") from None
    if actual_chain_id != chain_id:
        raise SubmitError(
            f"chainId 不匹配：链上 {actual_chain_id} != 部署 chainId {chain_id}"
        )

    try:
        code = w3.eth.get_code(contract.address)
    except Exception as exc:
        raise SubmitError(f"读取 registry 字节码失败（{type(exc).__name__}）") from None
    if not code:
        raise SubmitError("registry 地址没有合约字节码")

    try:
        key = contract.functions.keyOf(skill, version).call()
        entry = contract.functions.skills(key).call()
    except Exception as exc:
        raise SubmitError(f"读取链上登记信息失败（{type(exc).__name__}）") from None

    publisher = Web3.to_checksum_address(entry[0])
    onchain_code_hash = _as_bytes32(entry[2])
    onchain_metadata_hash = _as_bytes32(entry[3])
    status = int(entry[5])

    if status != STATUS_AUDIT_REQUESTED:
        raise SubmitError(f"状态不是 AuditRequested(2)（当前 {status}）")
    if publisher == Web3.to_checksum_address(account.address):
        raise SubmitError("publisher 与审计者是同一地址，禁止自审")
    if onchain_code_hash != code_hash:
        raise SubmitError("链上 codeHash 与报告不一致")
    if onchain_metadata_hash != metadata_hash:
        raise SubmitError("链上 metadataHash 与报告不一致")

    return _as_bytes32(key)


def _send(
    *,
    w3: Any,
    account: Any,
    contract: Any,
    chain_id: int,
    fn: Any,
    value: int,
    stage: str,
    log: Callable[[str], None] | None,
) -> str:
    """取 nonce → 估 gas → 签名 → 广播 → 等回执；返回 0x 交易哈希。

    哈希在广播后立刻回调 `log`，超时/失败时也已可见。不自动重发。
    """
    try:
        nonce = w3.eth.get_transaction_count(account.address, "pending")
        gas_price = w3.eth.gas_price
    except Exception as exc:
        raise SubmitError(f"{stage}：读取 nonce/gasPrice 失败（{type(exc).__name__}）") from None

    params: dict[str, Any] = {"from": account.address, "nonce": nonce, "chainId": chain_id}
    if value:
        params["value"] = value
    try:
        estimate = fn.estimate_gas(params)
    except Exception as exc:
        raise SubmitError(f"{stage}：gas 估算失败（{type(exc).__name__}）") from None
    if not isinstance(estimate, int) or estimate <= 0:
        raise SubmitError(f"{stage}：gas 估算结果非法")

    try:
        tx = fn.build_transaction(
            {
                **params,
                "gas": estimate * GAS_MARGIN_NUMERATOR // GAS_MARGIN_DENOMINATOR,
                "gasPrice": gas_price,
                "value": value,
            }
        )
    except Exception as exc:
        raise SubmitError(f"{stage}：交易构造失败（{type(exc).__name__}）") from None

    try:
        signed = account.sign_transaction(tx)
    except Exception as exc:
        raise SubmitError(f"{stage}：交易签名失败（{type(exc).__name__}）") from None

    try:
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    except Exception as exc:
        raise SubmitError(f"{stage}：广播失败（{type(exc).__name__}）") from None

    tx_hash_hex = tx_hash.hex()
    if not tx_hash_hex.startswith("0x"):
        tx_hash_hex = "0x" + tx_hash_hex
    if log is not None:
        log(f"[SkillGuard] {stage}：已广播交易 {tx_hash_hex}")

    try:
        receipt = w3.eth.wait_for_transaction_receipt(
            tx_hash,
            timeout=RECEIPT_TIMEOUT_SECONDS,
            poll_latency=RECEIPT_POLL_LATENCY,
        )
    except Exception as exc:
        raise SubmitError(
            f"{stage}：等待回执超时或失败（{type(exc).__name__}），交易已广播 {tx_hash_hex}"
        ) from None
    if receipt.get("status") != 1:
        raise SubmitError(f"{stage}：交易回执失败（status != 1），交易 {tx_hash_hex}")

    return tx_hash_hex


def submit_report_onchain(
    *,
    w3: Any,
    contract: Any,
    account: Any,
    chain_id: int,
    skill: str,
    version: str,
    level: str,
    report_hash: bytes,
    code_hash: bytes,
    metadata_hash: bytes,
    log: Callable[[str], None] | None = None,
) -> list[str]:
    """预检查 → （必要时）质押 → 提交报告，返回按顺序广播的交易哈希。

    合约由调用方用 `contract_for()` 绑定后传入；预检查不过则一笔都不发。
    """
    _precheck(
        w3=w3,
        contract=contract,
        chain_id=chain_id,
        account=account,
        skill=skill,
        version=version,
        code_hash=code_hash,
        metadata_hash=metadata_hash,
    )

    tx_hashes: list[str] = []

    try:
        staked = int(contract.functions.auditorStake(account.address).call())
        minimum = int(contract.functions.AUDITOR_STAKE().call())
    except Exception as exc:
        raise SubmitError(f"读取质押额失败（{type(exc).__name__}）") from None

    if staked < minimum:
        tx_hashes.append(
            _send(
                w3=w3,
                account=account,
                contract=contract,
                chain_id=chain_id,
                fn=contract.functions.stakeAsAuditor(),
                value=minimum,
                stage="质押审计者（stakeAsAuditor）",
                log=log,
            )
        )

    tx_hashes.append(
        _send(
            w3=w3,
            account=account,
            contract=contract,
            chain_id=chain_id,
            fn=contract.functions.submitReport(
                skill, version, level == MALICIOUS, report_hash
            ),
            value=0,
            stage="提交审计报告（submitReport）",
            log=log,
        )
    )

    return tx_hashes


__all__ = [
    "DEPLOYMENTS_FILE",
    "ENV_FILE",
    "GAS_MARGIN_DENOMINATOR",
    "GAS_MARGIN_NUMERATOR",
    "RECEIPT_POLL_LATENCY",
    "RECEIPT_TIMEOUT_SECONDS",
    "RPC_TIMEOUT_SECONDS",
    "SKILL_REGISTRY_ABI",
    "STATUS_AUDIT_REQUESTED",
    "SubmitConfig",
    "SubmitError",
    "auditor_account",
    "connect",
    "contract_for",
    "load_config",
    "submit_report_onchain",
    "with_auditor",
]
