"""常驻审计 Agent（SPEC 第 8 节，docs/PROMPTS.md A4）。

用法：
    python -m auditor.agent [--once] [--from-block N] [--poll 秒]

要点（全部来自 SPEC 8，实现照此）：
- 配置与 auditor/submit.py 相同（`.env` 的 RPC_URL/AUDITOR_PRIVATE_KEY、deployments.json）；
- 启动时检查 `auditorStake(自己) >= AUDITOR_STAKE`，不足就退出（exit 2）并提示人先
  运行 `python -m auditor.stake`。Agent 自己不质押——押钱是人的决定；
- 代码来源只支持本地路径（SPEC 8.3）：`file://` 绝对路径，或相对 `SKILL_SOURCE_ROOT`
  （默认项目根）的相对路径；解析结果必须落在根内，否则记日志跳过、不提交；
- 提交前核对 manifest 的 name/version 与事件一致、本地哈希与链上登记一致；
- SUSPICIOUS 不发交易：报告写 `reports/pending/<key>.json`，日志提示人工裁决；
- 单个请求出错只记日志，不中断循环；
- 不 import / 不执行技能代码；不调用 LLM；不打印私钥 / RPC URL。

游标（SPEC 8.2）：存 `.cache/agent_cursor.json`，重启后从这里继续；语义为
"下一个要扫描的区块号"。本实现按"逐事件成功即推进"处理：某事件处理失败时不越过
该事件的区块（重启后会再看到），已成功处理的写回最大区块 + 1。已知收窄：若同
一批次里更晚区块的成功处理发生，早些失败的事件会丢——本地链演示环境概率可忽略，
局限如实说明，不夸大。

已知局限（SPEC 11.2 相关，如实陈述）：单个审计者即可定案；合约不校验结论正确性；
无挑战期。
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from .hashing import code_hash as compute_code_hash
from .hashing import metadata_hash as compute_metadata_hash
from .report import MALICIOUS, SUSPICIOUS, canonical_json, report_hash
from .scanner import scan_skill_report
from .skill_dir import MANIFEST_NAME, safe_read_text
from .submit import (
    SubmitError,
    auditor_account,
    connect as connect_w3,
    contract_for,
    load_config,
    submit_report_onchain,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

CURSOR_REL_PATH = ".cache/agent_cursor.json"
PENDING_DIRNAME = "reports/pending"
SOURCE_ROOT_ENV = "SKILL_SOURCE_ROOT"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NOT_STAKED = 2

STATUS_AUDIT_REQUESTED = 2


class AgentError(Exception):
    """Agent 侧错误，携带面向操作者的说明（不含密钥/RPC URL）。"""


@dataclass(frozen=True)
class AuditRequest:
    """一条 AuditRequested 事件（key + 触发区块）。"""

    key: bytes
    block: int


@dataclass(frozen=True)
class Registration:
    """SkillRegistered 事件的解析结果。"""

    skill: str
    version: str
    repo: str
    code_hash: bytes
    metadata_hash: bytes


@dataclass
class AgentContext:
    """可注入的依赖集合；`python -m auditor.agent` 的 main() 组装默认实现。

    fetch_requests / fetch_registrations / scanner 必须显式注入（无默认值）。
    """

    root: Path
    contract: Any
    account: Any
    chain_id: int
    fetch_requests: Callable[[Any, int, str], list[AuditRequest]]  # 必须显式注入
    fetch_registrations: Callable[[Any, int, str], dict[bytes, Registration]]  # 必须显式注入
    scanner: Callable[[Path], Any]
    w3: Any = None
    log: Callable[[str], None] = lambda line: None  # noqa: E731
    submitter: Callable[..., list[str]] = submit_report_onchain
    outcomes: list[str] = field(default_factory=list)  # 测试观察用


# --------------------------------------------------------------------------
# 游标
# --------------------------------------------------------------------------
def cursor_path(root: Path) -> Path:
    return root / CURSOR_REL_PATH


def read_cursor(root: Path) -> int:
    """读游标（下一个要扫描的区块）；缺失/非法视为 0。"""
    path = cursor_path(root)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        block = value.get("cursor")
        if isinstance(block, int) and not isinstance(block, bool) and block >= 0:
            return block
    except (OSError, ValueError):
        pass
    return 0


def write_cursor(root: Path, block: int) -> None:
    path = cursor_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"cursor": block}), encoding="utf-8")


# --------------------------------------------------------------------------
# 事件解码
# --------------------------------------------------------------------------
def fetch_audit_requests(contract: Any, from_block: int, to_block: str) -> list[AuditRequest]:
    """AuditRequested 事件：按 args.key 归并（web3 v8 事件对象）。"""
    events = contract.events.AuditRequested.get_logs(from_block=from_block, to_block=to_block)
    requests: list[AuditRequest] = []
    for entry in events:
        key = bytes(entry["args"]["key"])
        requests.append(AuditRequest(key=key, block=int(entry["blockNumber"])))
    return requests


def fetch_registrations(contract: Any, from_block: int, to_block: str) -> dict[bytes, Registration]:
    """SkillRegistered 事件：按 key 归并（合约不允许重复，后写覆盖无害）。"""
    events = contract.events.SkillRegistered.get_logs(from_block=from_block, to_block=to_block)
    registry: dict[bytes, Registration] = {}
    for entry in events:
        key = bytes(entry["args"]["key"])
        args = entry["args"]
        registry[key] = Registration(
            skill=str(args["skillId"]),
            version=str(args["version"]),
            repo=str(args["repo"]),
            code_hash=bytes(args["codeHash"]),
            metadata_hash=bytes(args["metadataHash"]),
        )
    return registry


# --------------------------------------------------------------------------
# 代码来源（SPEC 8.3）
# --------------------------------------------------------------------------
def resolve_source(repo: str, root: Path) -> Path | None:
    """把 repo 字段解析为根内的本地目录；不合法返回 None（记日志、跳过）。"""
    text = (repo or "").strip()
    try:
        if text.startswith("file://"):
            candidate = Path(text[len("file://"):])
        elif text.startswith(("http://", "https://", "git@", "git://", "ssh://")):
            return None  # SPEC 8.3：非本地来源记日志跳过
        else:
            candidate = root / text
        resolved = candidate.resolve()
        root_resolved = root.resolve()
        if resolved == root_resolved or root_resolved not in resolved.parents:
            return None  # 防路径逃逸：必须在根内（根目录本身不算）
        return resolved
    except (OSError, ValueError):
        return None


def read_manifest_json(source: Path) -> dict[str, Any]:
    raw = safe_read_text(source / MANIFEST_NAME)
    return json.loads(raw)


# --------------------------------------------------------------------------
# 单请求处理
# --------------------------------------------------------------------------
def process_request(ctx: AgentContext, request: AuditRequest, registration: Registration | None) -> str:
    """处理一条审计请求；返回给操作者看的结果短语。失败抛异常由调用方记日志。"""
    if registration is None:
        raise AgentError("找不到对应的 SkillRegistered 事件，跳过")

    entry = ctx.contract.functions.skills(request.key).call()
    # entry: publisher, repo, codeHash, metadataHash, deposit, status, reportHash, auditor
    status = int(entry[5])
    if status != STATUS_AUDIT_REQUESTED:
        return f"跳过（状态 {status}，非 AuditRequested）"  # 幂等（SPEC 8.2 第 2 条）
    onchain_code_hash = bytes(entry[2])
    onchain_metadata_hash = bytes(entry[3])

    source = resolve_source(registration.repo, ctx.root)
    if source is None:
        ctx.log(
            f"key=0x{request.key.hex()} repo={registration.repo} 不是本地路径或越出"
            " SKILL_SOURCE_ROOT，跳过（不提交任何结论）"
        )
        return "跳过（来源不可用）"

    # manifest 与链上登记核对（SPEC 8.2 第 5 条）
    manifest_raw = read_manifest_json(source)
    manifest_name = str(manifest_raw.get("name", ""))
    manifest_version = str(manifest_raw.get("version", ""))
    if manifest_name != registration.skill or manifest_version != registration.version:
        raise AgentError(
            f"manifest({manifest_name}@{manifest_version}) 与事件"
            f"({registration.skill}@{registration.version}) 不一致，跳过"
        )
    code_hash = compute_code_hash(source)
    metadata_hash = compute_metadata_hash(source)
    if code_hash != onchain_code_hash or metadata_hash != onchain_metadata_hash:
        raise AgentError("本地计算的 codeHash/metadataHash 与链上登记不一致，跳过")

    # 规则引擎（不带 LLM，SPEC 8.4）
    report = ctx.scanner(source)
    payload = dict(report.to_dict() if hasattr(report, "to_dict") else report)
    # 提交者地址先写实再算哈希（与 auditor/cli._submit_and_save 相同约定）
    payload["auditor"] = ctx.account.address
    digest = report_hash(payload)

    level = str(payload["level"])
    if level == SUSPICIOUS:
        target = ctx.root / PENDING_DIRNAME / f"0x{request.key.hex()}.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(canonical_json(payload))
        ctx.log(
            f"key=0x{request.key.hex()} 结论 SUSPICIOUS：已写 {target.relative_to(ctx.root)}，"
            "等人裁决（python -m auditor.cli <dir> --submit --human-decision safe|malicious）"
        )
        return "SUSPICIOUS 已落盘待裁决"

    is_malicious = level == MALICIOUS
    hashes = ctx.submitter(
        w3=ctx.w3,
        contract=ctx.contract,
        account=ctx.account,
        chain_id=ctx.chain_id,
        skill=registration.skill,
        version=registration.version,
        level=level,
        report_hash=digest,
        code_hash=code_hash,
        metadata_hash=metadata_hash,
        is_malicious=is_malicious,
        log=ctx.log,
    )
    verdict = "MALICIOUS" if is_malicious else "SAFE"
    ctx.log(
        f"key=0x{request.key.hex()} 结论 {verdict} 已提交"
        f"（{len(hashes)} 笔交易，reportHash=0x{digest.hex()}）"
    )
    return f"已提交（{verdict}）"


# --------------------------------------------------------------------------
# 循环
# --------------------------------------------------------------------------
def run_once(ctx: AgentContext, cursor: int) -> tuple[int, int]:
    """跑一轮 [cursor, latest]：返回 (新游标, latest)。错误只记日志，不中断。"""
    latest = int(ctx.w3.eth.block_number)  # type: ignore[attr-defined]
    if latest < cursor:
        return cursor, latest
    requests = ctx.fetch_requests(ctx.contract, cursor, latest)
    registrations = ctx.fetch_registrations(ctx.contract, 0, latest)

    best_block = cursor  # 已成功处理的最高区块；游标 = 最高成功区块 + 1
    for request in requests:
        try:
            outcome = process_request(ctx, request, registrations.get(request.key))
            ctx.log(f"块 {request.block}：{outcome}（key=0x{request.key.hex()}）")
            ctx.outcomes.append(outcome)
            best_block = max(best_block, request.block)
        except Exception as exc:  # 只记日志，不中断（SPEC 8.2 第 7 条）
            ctx.log(f"块 {request.block}：处理失败（{exc}），跳过")
    new_cursor = best_block + 1 if best_block >= cursor else cursor
    write_cursor(ctx.root, new_cursor)
    return new_cursor, latest


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m auditor.agent",
        description="SkillGuard 常驻审计 Agent：监听 AuditRequested 并自动审计提交。",
    )
    parser.add_argument("--once", action="store_true", help="处理完当前待审请求后退出")
    parser.add_argument("--from-block", type=int, default=None, help="本次扫描起始区块（覆盖游标）")
    parser.add_argument("--poll", type=float, default=2.0, help="轮询间隔秒（默认 2）")
    return parser


def stamped(log: Callable[[str], None]) -> Callable[[str], None]:
    def wrapped(line: str) -> None:
        log(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {line}")

    return wrapped


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    log = stamped(lambda line: print(line, flush=True))

    try:
        config = load_config()
    except SubmitError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return EXIT_ERROR
    try:
        account = auditor_account(config.private_key)
        w3 = connect_w3(config)
        contract = contract_for(w3, config)
    except SubmitError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return EXIT_ERROR

    ctx = AgentContext(
        root=PROJECT_ROOT,
        contract=contract,
        account=account,
        chain_id=config.chain_id,
        w3=w3,
        log=log,
        fetch_requests=fetch_audit_requests,
        fetch_registrations=fetch_registrations,
        scanner=scan_skill_report,
        submitter=submit_report_onchain,
    )

    # 启动自检：质押不足 → exit 2，不自行质押（SPEC 8.1）
    try:
        staked = int(contract.functions.auditorStake(account.address).call())
        minimum = int(contract.functions.AUDITOR_STAKE().call())
    except Exception as exc:
        print(f"[错误] 读取链上状态失败（{type(exc).__name__}）", file=sys.stderr)
        return EXIT_ERROR
    if staked < minimum:
        log(
            f"质押不足（当前 {staked} < 要求 {minimum}）：请先由人运行 python -m auditor.stake，"
            "本 Agent 不自行质押"
        )
        return EXIT_NOT_STAKED

    cursor = args.from_block if args.from_block is not None else read_cursor(PROJECT_ROOT)
    log(f"chainId={w3.eth.chain_id}")
    registry_addr = getattr(contract, "address", config.registry_address)
    log(f"registry={registry_addr}")
    log(f"auditor={account.address}")
    log(f"staked={staked}")
    log(f"cursor={cursor}")

    try:
        while True:
            new_cursor, _latest = run_once(ctx, cursor)
            cursor = new_cursor
            if args.once:
                return EXIT_OK
            time.sleep(max(args.poll, 0.2))
    except KeyboardInterrupt:
        return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
