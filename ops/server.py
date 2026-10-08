"""SkillGuard 本机角色 HTTP 服务。

启动：.venv/bin/python ops/server.py，默认 127.0.0.1:8765。
HTTP 登录使用浏览器 EOA 的 SIWE 签名，旧人的代签端点返回 410。
原 Python 辅助函数保留供本机 CLI/旧测试使用，不由 HTTP 路由调用。
公开配置不包含私钥或带凭据 RPC；错误只返回受控说明。
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import dotenv_values  # noqa: E402
from web3 import Web3  # noqa: E402
from ops.app import OpsApplication  # noqa: E402

import auditor.submit as submit_mod  # noqa: E402
from auditor import agent as agent_mod  # noqa: E402
from auditor.hashing import code_hash as compute_code_hash  # noqa: E402
from auditor.hashing import metadata_hash as compute_metadata_hash  # noqa: E402
from auditor.report import SUSPICIOUS, report_hash  # noqa: E402
from auditor.scanner import scan_skill_report  # noqa: E402
from auditor.stake import stake as do_stake  # noqa: E402
from auditor.submit import (  # noqa: E402
    SubmitError,
    auditor_account,
    connect as connect_w3,
    contract_for,
    load_config as load_auditor_config,
)
from gate.gate import check_install, load_gate_config  # noqa: E402

HOST = "127.0.0.1"
DEFAULT_PORT = 8765
OPS_HTML = PROJECT_ROOT / "web" / "ops.html"
DEPLOYMENTS = PROJECT_ROOT / "deployments.json"

STATUS_NAMES = {0: "None", 1: "Registered", 2: "AuditRequested", 3: "Verified", 4: "Malicious"}
ZERO_ADDR = "0x" + "0" * 40


class OpsError(Exception):
    """操作台业务错误；str() 可直接展示给人（不含密钥/RPC URL）。"""


class HTTPError(OpsError):
    def __init__(self, message: str, status: int = 403) -> None:
        super().__init__(message)
        self.status = status


# --------------------------------------------------------------------------
# 配置与基础对象
# --------------------------------------------------------------------------
def _env() -> dict[str, str]:
    values = dict(dotenv_values(PROJECT_ROOT / ".env"))
    return {k: v for k, v in values.items() if v is not None}


def _rpc_url() -> str:
    return (os.environ.get("RPC_URL") or _env().get("RPC_URL") or "").strip()


def _w3() -> Web3:
    rpc = _rpc_url()
    if not rpc:
        raise OpsError("缺少 RPC_URL（请写入项目根 .env）")
    return connect_w3(submit_mod.SubmitConfig(
        rpc_url=rpc,
        private_key="0x" + "0" * 64,  # 只读用途；不参与签名
        chain_id=1,  # 实际 chainId 以链上为准（快照里如实显示）
        registry_address=Web3.to_checksum_address("0x" + "0" * 40),  # 占位；下方按地址重建
    ))


def _deployment() -> dict:
    if not DEPLOYMENTS.is_file():
        raise OpsError("缺少 deployments.json（先部署）")
    try:
        data = json.loads(DEPLOYMENTS.read_text(encoding="utf-8"))
    except ValueError:
        raise OpsError("deployments.json 不是合法 JSON") from None
    if not isinstance(data, dict):
        raise OpsError("deployments.json 顶层必须是对象")
    return data


def _registry_address() -> str:
    address = _deployment().get("SkillRegistry")
    if not isinstance(address, str) or not Web3.is_checksum_address(address):
        raise OpsError("deployments.json 缺少合法的 SkillRegistry 地址")
    return Web3.to_checksum_address(address)


def _license_address() -> str:
    address = _deployment().get("SkillLicense")
    if not isinstance(address, str) or not Web3.is_checksum_address(address):
        raise OpsError("deployments.json 缺少合法的 SkillLicense 地址")
    return Web3.to_checksum_address(address)


def _contract(w3: Web3, address: str):
    return w3.eth.contract(address=Web3.to_checksum_address(address), abi=ops_abi())


def _key(env: dict[str, str], name: str) -> str:
    value = (env.get(name) or "").strip()
    if not value:
        raise OpsError(f"缺少 {name}（按角色填入 .env）")
    return value


def audit_license_abi() -> list[dict]:
    return [
        {"type": "function", "name": "isVerified", "stateMutability": "view",
         "inputs": [{"name": "a", "type": "string"}, {"name": "b", "type": "string"}],
         "outputs": [{"name": "", "type": "bool"}]},
    ]


def ops_abi() -> list[dict]:
    """submit 最小 ABI + register / requestAudit / getStatus / MIN_DEPOSIT。"""
    return submit_mod.SKILL_REGISTRY_ABI + [
        {"type": "function", "name": "register", "stateMutability": "nonpayable",
         "inputs": [{"name": "s", "type": "string"}, {"name": "v", "type": "string"},
                     {"name": "r", "type": "string"}, {"name": "c", "type": "bytes32"},
                     {"name": "m", "type": "bytes32"}],
         "outputs": [{"name": "key", "type": "bytes32"}]},
        {"type": "function", "name": "requestAudit", "stateMutability": "payable",
         "inputs": [{"name": "s", "type": "string"}, {"name": "v", "type": "string"}],
         "outputs": []},
        {"type": "function", "name": "MIN_DEPOSIT", "stateMutability": "view",
         "inputs": [], "outputs": [{"name": "", "type": "uint256"}]},
        {"type": "function", "name": "getStatus", "stateMutability": "view",
         "inputs": [{"name": "s", "type": "string"}, {"name": "v", "type": "string"}],
         "outputs": [{"name": "", "type": "uint8"}]},
    ]


# --------------------------------------------------------------------------
# 角色
# --------------------------------------------------------------------------
def _role_addresses() -> dict[str, str | None]:
    env = _env()
    out: dict[str, str | None] = {}
    for env_name, label in (
        ("PRIVATE_KEY", "publisher"),
        ("AUDITOR_PRIVATE_KEY", "auditor"),
        ("OWNER_PRIVATE_KEY", "owner"),
    ):
        raw = (env.get(env_name) or "").strip()
        if not raw:
            out[label] = None
            continue
        try:
            out[label] = auditor_account(raw).address
        except Exception:
            out[label] = None
    try:
        out["registry"] = _registry_address()
        out["license"] = _license_address()
    except OpsError:
        out["registry"] = None
        out["license"] = None
    return out


def _short_role(address: str | None, roles: dict) -> str:
    """把角色地址换显示名（publisher/auditor/owner），否则显示 "—"。"""
    if not address or address == ZERO_ADDR:
        return "—"
    for label in ("publisher", "auditor", "owner"):
        value = roles.get(label)
        if value and str(value).lower() == str(address).lower():
            return label
    return address


def _require_key(env: dict[str, str], name: str) -> str:
    value = (env.get(name) or "").strip()
    if not value:
        raise OpsError(f"缺少 {name}（按角色填入 .env）")
    return value


# --------------------------------------------------------------------------
# 快照
# --------------------------------------------------------------------------
def snapshot() -> dict:
    env = _env()
    roles = _role_addresses()
    w3 = _w3()
    chain_id = w3.eth.chain_id
    deployed = _deployment()
    registry = roles.get("registry")
    has_code = bool(w3.eth.get_code(registry)) if registry else False

    skills: list[dict] = []
    staked_auditor: int | None = None
    min_deposit: int | None = None
    if registry and has_code:
        contract = _contract(w3, registry)
        min_deposit = int(contract.functions.MIN_DEPOSIT().call())
        auditor = roles.get("auditor")
        staked_auditor = int(contract.functions.auditorStake(auditor).call()) if auditor else None

        lic = w3.eth.contract(address=Web3.to_checksum_address(_license_address()), abi=audit_license_abi())
        seen: dict[bytes, dict] = {}
        events = contract.events.SkillRegistered.get_logs(
            from_block=deployed.get("deploymentBlock", 0), to_block="latest")
        for entry in events:
            args = entry["args"]
            key = bytes(args["key"])
            skill = str(args["skillId"])
            version = str(args["version"])
            state = contract.functions.skills(key).call()
            status = int(state[5])
            auditor_addr = Web3.to_checksum_address(state[7]) if state[7] else ZERO_ADDR
            try:
                licensed = bool(lic.functions.isVerified(skill, version).call())
            except Exception:
                verified = False
            seen[key] = {
                "skill": skill,
                "version": version,
                "repo": str(args["repo"]),
                "status": STATUS_NAMES.get(status, f"Unknown({status})"),
                "statusCode": status,
                # 审计者显示真实链上地址（未审计=零地址 → "—"），不做角色名替换
                "auditor": (auditor_addr if auditor_addr != ZERO_ADDR else "—"),
                "auditorFull": auditor_addr,
                "licensed": bool(lic.functions.isVerified(skill, version).call()) if has_code else False,
                "block": int(entry["blockNumber"]),
            }
        skills = sorted(seen.values(), key=lambda s: (s["skill"], s["version"]))

    balances = {}
    for label in ("publisher", "auditor", "owner"):
        addr = roles.get(label)
        try:
            balances[label] = str(w3.eth.get_balance(addr)) if addr else None
        except Exception:
            balances[label] = None

    pending_dir = PROJECT_ROOT / "reports" / "pending"
    pending: list[dict] = []
    if pending_dir.is_dir():
        for path in sorted(pending.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                continue
            pending.append({"file": path.name, "skill": data.get("skill"), "version": data.get("version")})

    return {
        "ok": True,
        "chainId": chain_id,
        "deployedChainId": deployed.get("chainId"),
        "networkName": {31337: "本地 Anvil", 11155111: "Sepolia", 968: "BOT Chain Testnet"}.get(chain_id, str(chain_id)),
        "nativeSymbol": "tBOT" if chain_id == 968 else "ETH",
        "deploymentBlock": deployed.get("deploymentBlock", 0),
        "registry": registry,
        "license": roles.get("license"),
        "hasCode": has_code,
        "block": w3.eth.block_number,
        "roles": roles,
        "balances": balances,
        "stakedAuditor": staked_auditor,
        "minDeposit": min_deposit,
        "skills": skills,
        "pending": pending,
        "cursor": agent_mod.read_cursor(PROJECT_ROOT, chain_id, registry),
    }


def display_name(address: str | None, roles: dict) -> str:
    if not address or address == ZERO_ADDR:
        return "—"
    for label in ("publisher", "auditor", "owner"):
        value = roles.get(label)
        if value and str(value).lower() == address.lower():
            return label
    return address


# --------------------------------------------------------------------------
# 动作
# --------------------------------------------------------------------------
def w3_or_url(rpc: str) -> Web3:
    return Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 15}))


def _fund_local(w3: Web3) -> None:
    """仅本地链（31337）：给 .env 三个角色地址补 2 ETH 测试余额（与 demo.sh 同语义）。

    这是演示自愈动作，屏幕/日志中如实呈现为「本地链补测试余额」；不在测试网生效。
    """
    if not w3.is_connected() or w3.eth.chain_id != 31337:
        return
    env = _env()
    for name in ("PRIVATE_KEY", "AUDITOR_PRIVATE_KEY", "OWNER_PRIVATE_KEY"):
        raw = env.get(name, "")
        if not raw:
            continue
        try:
            checksum = auditor_account(raw).address
        except Exception:
            continue
        if w3.eth.get_balance(checksum) <= 10**18:
            w3.provider.make_request("anvil_setBalance", [checksum, "0x1BC16D674EC80000"])


def _send(w3: Web3, private_key: str, fn, value: int = 0, stage: str = "") -> str:
    account = auditor_account(private_key)
    contract = _contract(w3, _registry_address())
    return submit_mod._send(
        w3=w3,
        account=account,
        contract=contract,
        chain_id=w3.eth.chain_id,
        fn=fn,
        value=value,
        stage=stage or "tx",
        log=None,
    )


def _forge_executable() -> str:
    executable = shutil.which("forge")
    if executable:
        return executable
    candidate = Path.home() / ".foundry" / "bin" / "forge"
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    raise OpsError("未找到可执行的 forge，请先安装 Foundry 并运行 foundryup")


def deploy() -> dict:
    forge = _forge_executable()
    env = _env()
    owner_key = _key(env, "OWNER_PRIVATE_KEY")
    rpc = _rpc_url()
    w3 = w3_or_url(rpc)
    chain_id = w3.eth.chain_id
    if chain_id == 968:
        return _deploy_bot(forge, owner_key, rpc, w3)
    if chain_id != 31337:
        raise OpsError("操作台仅支持本地链 31337 和 BOT 测试网 968 部署")
    _fund_local(w3_or_url(rpc))
    import subprocess

    proc = subprocess.run(
        [forge, "script", "script/Deploy.s.sol", "--rpc-url", rpc, "--broadcast"],
        cwd=str(PROJECT_ROOT / "contracts"),
        env={**os.environ, "PRIVATE_KEY": owner_key},
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    if proc.returncode != 0:
        raise OpsError(f"部署失败（forge exit {proc.returncode}）")
    data = _deployment()
    return {"registry": data.get("SkillRegistry"), "license": data.get("SkillLicense")}


def _verify_bot_deployment(w3: Web3, data: dict, owner: str) -> int:
    """Validate all four live receipts plus contract wiring; return creation block."""
    if data.get("chainId") != 968 or w3.eth.chain_id != 968:
        raise OpsError("BOT 部署 chainId 不匹配")
    addresses = []
    for name in ("SkillRegistry", "SkillLicense"):
        address = data.get(name)
        if not isinstance(address, str) or not Web3.is_checksum_address(address):
            raise OpsError(f"BOT 部署缺少合法的 {name} 地址")
        if not w3.eth.get_code(address):
            raise OpsError(f"BOT 部署 {name} 没有合约字节码")
        addresses.append(address)
    registry, license = addresses
    record_path = PROJECT_ROOT / "contracts/broadcast/Deploy.s.sol/968/run-latest.json"
    try:
        transactions = json.loads(record_path.read_text())["transactions"]
        expected = [("CREATE", registry), ("CREATE", license), ("CALL", registry), ("CALL", license)]
        if len(transactions) != len(expected):
            raise ValueError("unexpected transactions")
        blocks = []
        for transaction, (kind, address) in zip(transactions, expected):
            if transaction.get("transactionType") != kind or Web3.to_checksum_address(transaction["contractAddress"]) != address:
                raise ValueError("unexpected contract")
            receipt = w3.eth.get_transaction_receipt(transaction["hash"])
            if receipt["status"] != 1:
                raise OpsError("BOT 部署交易回执失败，未切换部署配置")
            if kind == "CREATE" and Web3.to_checksum_address(receipt["contractAddress"]) != address:
                raise ValueError("unexpected creation address")
            blocks.append(int(receipt["blockNumber"]))
    except OpsError:
        raise
    except Exception as exc:
        raise OpsError(f"BOT 部署回执核验失败（{type(exc).__name__}）") from None

    def view(name, output, inputs=None):
        return {"type": "function", "name": name, "stateMutability": "view",
                "inputs": inputs or [], "outputs": [{"type": output}]}
    reg = w3.eth.contract(address=registry, abi=[view("owner", "address"), view("skillLicense", "address")])
    lic = w3.eth.contract(address=license, abi=[view("owner", "address"), view("registry", "address"),
                         view("MINTER_ROLE", "bytes32"), view("hasRole", "bool", [{"type": "bytes32"}, {"type": "address"}])])
    if (reg.functions.owner().call() != owner or lic.functions.owner().call() != owner
            or reg.functions.skillLicense().call() != license or lic.functions.registry().call() != registry
            or not lic.functions.hasRole(lic.functions.MINTER_ROLE().call(), registry).call()):
        raise OpsError("BOT 合约接线或权限核验失败，未切换部署配置")
    return min(blocks)


def _deploy_bot(forge: str, owner_key: str, rpc: str, w3: Web3) -> dict:
    """Stage Foundry output and atomically activate only the verified BOT deployment."""
    import subprocess
    cache = PROJECT_ROOT / ".cache"
    cache.mkdir(exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="bot-deployment-", suffix=".json", dir=cache)
    os.close(fd)
    candidate = Path(name)
    try:
        proc = subprocess.run(
            [forge, "script", "script/Deploy.s.sol", "--rpc-url", rpc,
             "--broadcast", "--slow", "--legacy"],
            cwd=str(PROJECT_ROOT / "contracts"),
            env={**os.environ, "PRIVATE_KEY": owner_key, "DEPLOYMENTS_PATH": str(candidate)},
            capture_output=True, text=True, timeout=300, check=False)
        if proc.returncode != 0:
            raise OpsError(f"部署失败（forge exit {proc.returncode}）")
        data = json.loads(candidate.read_text(encoding="utf-8"))
        data["deploymentBlock"] = _verify_bot_deployment(w3, data, auditor_account(owner_key).address)
        with candidate.open("w", encoding="utf-8") as output:
            output.write(json.dumps(data, indent=2) + "\n")
            output.flush()
            os.fsync(output.fileno())
        candidate.replace(DEPLOYMENTS)
        return {"registry": data["SkillRegistry"], "license": data["SkillLicense"]}
    except OpsError:
        raise
    except Exception as exc:
        raise OpsError(f"BOT 部署失败（{type(exc).__name__}）") from None
    finally:
        candidate.unlink(missing_ok=True)


def stake() -> dict:
    logs: list[str] = []
    tx_hash, amount = do_stake(log=logs.append)
    return {"tx": tx_hash, "staked": amount, "logs": logs}


def _resolve_skill_dir(skill_dir: str) -> Path:
    text = (skill_dir or "").strip()
    if not text:
        raise OpsError("缺少 skill_dir")
    path = Path(text)
    if not path.is_absolute():
        path = PROJECT_ROOT / text
    resolved = path.resolve()
    root = PROJECT_ROOT.resolve()
    if root not in resolved.parents:
        raise OpsError("skill_dir 必须位于项目根内（防路径逃逸）")
    manifest_path = resolved / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise OpsError("缺少 manifest.json（拒绝符号链接）")
    return resolved


def register(skill_dir: str) -> dict:
    env = _env()
    publisher_key = _key(env, "PRIVATE_KEY")
    path = _resolve_skill_dir(skill_dir)

    manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
    skill = str(manifest.get("name", ""))
    version = str(manifest["version"])
    if not skill:
        raise OpsError("manifest.json 缺少 name")

    w3 = _w3()
    contract = _contract(w3, _registry_address())
    key = contract.functions.keyOf(skill, version).call()
    entry = contract.functions.skills(key).call()
    if int(entry[5]) != 0:
        raise OpsError(f"已注册：{skill}@{version}（status={int(entry[5])}）。换新版本号或重启本地链归零")

    deposit = int(contract.functions.MIN_DEPOSIT().call())
    code_hash_hex = "0x" + compute_code_hash(path).hex()
    metadata_hash_hex = "0x" + compute_metadata_hash(path).hex()
    tx_register = _send(
        w3, publisher_key,
        contract.functions.register(
            skill, version, str(path),
            bytes.fromhex(code_hash_hex[2:]), bytes.fromhex(metadata_hash_hex[2:]),
        ),
        0, "register",
    )
    tx_request = _send(
        w3, publisher_key,
        contract.functions.requestAudit(skill, version),
        deposit, "requestAudit",
    )
    return {
        "skill": skill, "version": version,
        "registerTx": tx_register, "requestAuditTx": tx_request,
        "deposit": deposit, "key": "0x" + key.hex(),
    }


def agent_once(from_block: int | None = None) -> dict:
    """与人相同的 CLI 语义跑一轮 Agent；复用 auditor.agent，不复制判定逻辑。

    `from_block` 显式给定（如 0）时覆盖持久化游标，等效 CLI --from-block。
    """
    config = load_auditor_config()
    account = auditor_account(config.private_key)
    w3 = _w3()
    contract = contract_for(w3, config)

    events_contract = w3.eth.contract(
        address=Web3.to_checksum_address(_registry_address()), abi=submit_mod.SKILL_REGISTRY_ABI
    )
    ctx = agent_mod.AgentContext(
        root=PROJECT_ROOT,
        contract=contract,
        account=account,
        chain_id=config.chain_id,
        fetch_requests=agent_mod.fetch_audit_requests,
        fetch_registrations=agent_mod.fetch_registrations,
        scanner=scan_skill_report,
        w3=w3,
        log=lambda line: None,
        submitter=submit_mod.submit_report_onchain,
        deployment_block=config.deployment_block,
    )
    staked = int(contract.functions.auditorStake(account.address).call())
    minimum = int(contract.functions.AUDITOR_STAKE().call())
    if staked < minimum:
        raise OpsError(f"审计者未质押（当前 {staked} < {minimum}），请先点「质押」")

    cursor = agent_mod.read_cursor(PROJECT_ROOT, config.chain_id, config.registry_address)
    if from_block is not None:
        cursor = max(0, int(from_block))
    new_cursor, latest = agent_mod.run_once(ctx, cursor)
    return {
        "cursorBefore": cursor,
        "cursorAfter": new_cursor,
        "latest": latest,
        "processed": list(ctx.outcomes),
    }


def decide(skill_dir: str, decision: str) -> dict:
    """SUSPICIOUS 人工裁决（与 cli --human-decision 同语义：人写结论 → 重算哈希 → 上链）。"""
    if decision not in ("safe", "malicious"):
        raise OpsError("decision 只能是 safe 或 malicious")
    path = _resolve_skill_dir(skill_dir)
    report = scan_skill_report(path)
    if report.level != SUSPICIOUS:
        raise OpsError(f"人工裁决只对 SUSPICIOUS 生效（当前 {report.level}）")
    config = load_auditor_config(env_path=PROJECT_ROOT / ".env", deployments_path=DEPLOYMENTS)
    account = auditor_account(config.private_key)
    w3 = _w3()
    contract = contract_for(w3, config)
    payload, transactions, _ = submit_mod.submit_and_save_report(
        report=report, reports_dir=PROJECT_ROOT / "reports", human_decision=decision,
        w3=w3, contract=contract, account=account, chain_id=config.chain_id,
    )
    digest = report_hash(payload)
    key = contract.functions.keyOf(str(payload["skill"]), str(payload["version"])).call()
    pending = PROJECT_ROOT / "reports" / "pending" / f"0x{bytes(key).hex()}.json"
    pending.unlink(missing_ok=True)  # 只有收到成功回执后才清理待裁决记录。
    return {"tx": transactions[-1], "decision": decision, "reportHash": "0x" + digest.hex(), "auditor": account.address}


def install(skill_dir: str) -> dict:
    """安装方语义：gate MCP 的 install_skill（查链→复制→复检）。"""
    from gate import mcp_server  # noqa: PLC0415

    env = _env()
    if "RPC_URL" not in os.environ and env.get("RPC_URL"):
        os.environ["RPC_URL"] = env["RPC_URL"]
    return mcp_server.install_skill(str(_resolve_skill_dir(skill_dir)), project_root=PROJECT_ROOT)


# --------------------------------------------------------------------------
# HTTP server
# --------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "SkillGuardOps/0.1"

    def log_message(self, fmt: str, *args) -> None:  # 静默默认访问日志
        pass

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        super().end_headers()

    def _authorize(self, *, mutating: bool = False) -> None:
        host = self.headers.get("Host", "")
        port = self.server.server_port
        if host not in (f"127.0.0.1:{port}", f"localhost:{port}"):
            raise HTTPError("请求来源不被允许")
        origin = self.headers.get("Origin")
        if (origin is not None and origin != f"http://{host}") or self.headers.get("Sec-Fetch-Site") not in (None, "none", "same-origin"):
            raise HTTPError("请求来源不被允许")
        if mutating:
            if origin != f"http://{host}":
                raise HTTPError("请求来源不被允许")
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            expected_type = "application/zip" if self.path == "/api/packages" else "application/json"
            if content_type != expected_type:
                raise HTTPError("请求格式不符合接口要求", 415)
            token = self.headers.get("X-SkillGuard-Token", "")
            if not token or not secrets.compare_digest(token, self.server.csrf_token):
                raise HTTPError("操作会话已失效，请刷新页面重试")

    def _jsonify(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in getattr(self, '_response_headers', {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _post_body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            raise HTTPError("请求长度无效", 400) from None
        if length < 0:
            raise HTTPError("请求长度无效", 400)
        if length > 64 * 1024:
            raise HTTPError("请求内容过大", 413)
        if not length:
            return {}
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(data, dict):
                raise HTTPError("请求内容必须是 JSON 对象", 400)
            return data
        except ValueError:
            raise HTTPError("请求不是合法 JSON", 400) from None

    def _application(self) -> OpsApplication:
        app = getattr(self.server, 'application', None)
        if app is None:
            app = OpsApplication(getattr(self.server, 'project_root', PROJECT_ROOT))
            app.csrf_token = self.server.csrf_token
            self.server.application = app
        app.server_port = self.server.server_port
        return app

    def _dispatch(self, method: str, body: bytes = b'') -> None:
        reply = self._application().handle(method, self.path, dict(self.headers.items()), body)
        self._response_headers = {key: value for key, value in reply.headers.items()
                                  if key not in ('Content-Type', 'Cache-Control')}
        if reply.headers.get('Content-Type', '').startswith('application/json'):
            self._jsonify(json.loads(reply.body), reply.status)
        else:
            self.send_response(reply.status)
            for key, value in reply.headers.items():
                self.send_header(key, value)
            self.send_header('Content-Length', str(len(reply.body)))
            self.end_headers()
            self.wfile.write(reply.body)

    def do_GET(self) -> None:  # noqa: N802
        try:
            self._authorize()
            self._dispatch('GET')
        except HTTPError as exc:
            self._jsonify({'ok': False, 'error': str(exc)}, exc.status)

    def do_POST(self) -> None:  # noqa: N802
        try:
            self._authorize(mutating=True)
            if self.path == '/api/packages':
                try:
                    length = int(self.headers.get('Content-Length', '0'))
                except ValueError:
                    raise HTTPError('请求长度无效', 400) from None
                if length < 0:
                    raise HTTPError('请求长度无效', 400)
                if length > 10 * 1024 * 1024:
                    raise HTTPError('请求内容过大', 413)
                self._dispatch('POST', self.rfile.read(length))
            else:
                payload = self._post_body()
                self._dispatch('POST', json.dumps(payload).encode())
        except HTTPError as exc:
            self._jsonify({'ok': False, 'error': str(exc)}, exc.status)


class OpsHTTPServer(ThreadingHTTPServer):
    def __init__(self, address, handler=Handler, *, project_root: Path | None = None) -> None:
        self.project_root = PROJECT_ROOT if project_root is None else project_root
        self.application = OpsApplication(self.project_root)
        self.csrf_token = self.application.csrf_token
        super().__init__(address, handler)
        self.application.server_port = self.server_port


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(prog="ops/server.py")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    httpd = OpsHTTPServer((HOST, args.port), Handler)
    print(f"✓ SkillGuard 操作台: http://127.0.0.1:{args.port}（仅本机）", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
