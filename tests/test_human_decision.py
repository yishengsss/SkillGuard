"""A1：SUSPICIOUS 人工裁决 + 人工质押命令（docs/PROMPTS.md A1，SPEC 1/8.1 节）。

覆盖：
1. SUSPICIOUS + `--submit`（无裁决）→ 退出码 3、零交易、stderr 提示人工裁决命令；
2. SUSPICIOUS + `--human-decision safe|malicious` → 报告含 humanDecision 字段，
   reportHash 按含该字段的 payload 计算，isMalicious 分别为 false / true；
3. `--human-decision` 对 SAFE / MALICIOUS 使用 → 退出码 2、零交易；
4. `python -m auditor.stake`：已足额不发交易、只读链上质押额；不足时发一笔
   stakeAsAuditor（value == AUDITOR_STAKE），质押后余额从链上读。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from auditor import stake as stake_mod
from auditor import cli as cli_mod
from auditor.cli import main
from auditor.hashing import keccak_bytes
from auditor.report import canonical_json, report_hash
from auditor.scanner import scan_skill_report
from auditor.submit import auditor_account, with_auditor
from tests.test_submit import (  # 复用同一套网络边界 fake
    MIN_STAKE,
    REGISTRY_ADDRESS,
    SECRET_RPC,
    TEST_KEY,
    Ctx,
    FakeContract,
    FakeEth,
    FakeWeb3,
    SpyAccount,
    make_ctx,
    patch_network,
    project_dir,
    write_skill,
)

SUSPICIOUS_NOTE = "查询天气（edge case 占位）"


@pytest.fixture
def config_env(monkeypatch, tmp_path: Path):
    """与 tests/test_submit.py 的同名夹具一致（pytest 夹具不能跨文件复用，这里复制）。"""
    monkeypatch.chdir(tmp_path)
    for name in ("RPC_URL", "AUDITOR_PRIVATE_KEY"):
        monkeypatch.delenv(name, raising=False)


def make_suspicious_ctx(tmp_path: Path, **kwargs):  # type: ignore[no-untyped-def]
    """构造真实扫描即 SUSPICIOUS 的场景：源码含普通 https 域名（STAT-002，high-only）。

    make_ctx 对 payload 的 level 覆盖只影响 fake 参数；CLI 会重新扫描，因此
    SUSPICIOUS 必须来自真实规则命中。
    """
    ctx = make_ctx(tmp_path, **kwargs)
    skill_dir = tmp_path / "skill"
    code = (skill_dir / "service.py").read_text(encoding="utf-8")
    (skill_dir / "service.py").write_text(
        code + 'BACKUP_HOST = "https://telemetry.example.com/v1"\n', encoding="utf-8"
    )
    rescanned = scan_skill_report(skill_dir).to_dict()
    assert rescanned["level"] == "SUSPICIOUS"
    ctx.payload = with_auditor(rescanned, auditor_account(TEST_KEY).address)
    # 链上登记也要与重新扫描后的哈希一致（fake 静态 entry）
    from auditor.report import ZERO_ADDRESS
    from hexbytes import HexBytes

    ctx.contract.entry = (
        "0x" + "33" * 20,
        "https://example.com/repo",
        HexBytes(ctx.payload["codeHash"]),
        HexBytes(ctx.payload["metadataHash"]),
        10**16,
        2,  # AuditRequested
        bytes(32),
        ZERO_ADDRESS,
    )
    return ctx


# --------------------------------------------------------------------------
# 1. SUSPICIOUS 不自动上链
# --------------------------------------------------------------------------
def test_cli_submit_suspicious_exits_3_with_hint(
    tmp_path: Path, monkeypatch, capsys, config_env
) -> None:
    ctx = make_suspicious_ctx(tmp_path, staked=MIN_STAKE)
    project = project_dir(tmp_path)
    patch_network(monkeypatch, ctx)

    code = main([str(tmp_path / "skill"), "--submit"], project_root=project)
    captured = capsys.readouterr()
    assert code == 3
    assert captured.out.strip() == ""
    assert "--human-decision" in captured.err
    assert ctx.contract.sends == [] and ctx.eth.sent == []


@pytest.mark.parametrize("staked", [0, MIN_STAKE])
def test_suspicious_never_broadcasts_even_before_stake(
    tmp_path: Path, monkeypatch, capsys, config_env, staked: int
) -> None:
    ctx = make_suspicious_ctx(tmp_path, staked=staked)
    project = project_dir(tmp_path)
    patch_network(monkeypatch, ctx)

    code = main([str(tmp_path / "skill"), "--submit"], project_root=project)
    assert code == 3
    assert ctx.eth.sent == []


# --------------------------------------------------------------------------
# 2. --human-decision
# --------------------------------------------------------------------------
@pytest.mark.parametrize(("decision", "is_malicious"), [("safe", False), ("malicious", True)])
def test_human_decision_adds_field_and_submits(
    tmp_path: Path, monkeypatch, capsys, config_env, decision: str, is_malicious: bool
) -> None:
    ctx = make_suspicious_ctx(tmp_path, staked=MIN_STAKE)
    project = project_dir(tmp_path)
    patch_network(monkeypatch, ctx)

    code = main(
        [str(tmp_path / "skill"), "--submit", "--human-decision", decision],
        project_root=project,
    )
    captured = capsys.readouterr()
    assert code == 0
    payload = json.loads(captured.out)
    assert payload["humanDecision"] == decision

    # reportHash 必须按含 humanDecision 的 payload 计算，保存文件字节一致
    digest_hex = "0x" + report_hash(payload).hex()
    saved = project / "reports" / f"{digest_hex}.json"
    assert saved.is_file()
    assert saved.read_bytes() == canonical_json(payload)
    assert keccak_bytes(saved.read_bytes()).hex() == digest_hex[2:]

    name, args, _params = ctx.contract.sends[-1]
    assert name == "submitReport"
    assert args[2] is is_malicious
    assert bytes(args[3]) == keccak_bytes(saved.read_bytes())


@pytest.mark.parametrize("level", ["SAFE", "MALICIOUS"])
def test_human_decision_rejected_for_safe_and_malicious(
    tmp_path: Path, monkeypatch, capsys, config_env, level: str
) -> None:
    ctx = make_ctx(tmp_path, staked=MIN_STAKE, level=level)
    project = project_dir(tmp_path)
    patch_network(monkeypatch, ctx)

    code = main(
        [str(tmp_path / "skill"), "--submit", "--human-decision", "safe"],
        project_root=project,
    )
    captured = capsys.readouterr()
    assert code == 2
    assert "只对 SUSPICIOUS 生效" in captured.err
    assert captured.out.strip() == ""
    assert ctx.contract.sends == [] and ctx.eth.sent == []


# --------------------------------------------------------------------------
# 3. python -m auditor.stake
# --------------------------------------------------------------------------
def bind_stake_network(monkeypatch, ctx) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(stake_mod, "connect", lambda config: ctx.w3)
    monkeypatch.setattr(stake_mod, "contract_for", lambda w3, config: ctx.contract)


def test_stake_already_sufficient_prints_amount_without_tx(
    tmp_path: Path, monkeypatch, capsys, config_env
) -> None:
    ctx = make_ctx(tmp_path, staked=MIN_STAKE)
    project = project_dir(tmp_path)
    monkeypatch.chdir(project)
    bind_stake_network(monkeypatch, ctx)

    assert stake_mod.main([]) == 0
    captured = capsys.readouterr()
    assert "不发交易" in captured.err
    assert str(MIN_STAKE) in captured.out
    assert ctx.contract.sends == [] and ctx.eth.sent == []


def test_stake_insufficient_sends_one_tx_and_reads_back(
    tmp_path: Path, monkeypatch, capsys, config_env
) -> None:
    ctx = make_ctx(tmp_path, staked=0)
    project = project_dir(tmp_path)
    monkeypatch.chdir(project)
    bind_stake_network(monkeypatch, ctx)

    assert stake_mod.main([]) == 0
    captured = capsys.readouterr()
    name, _args, params = ctx.contract.sends[-1]
    assert len(ctx.contract.sends) == 1
    assert name == "stakeAsAuditor"
    assert params["value"] == MIN_STAKE
    assert "已广播交易" in captured.err  # 交易哈希已打印（stderr）
    assert "当前质押额" in captured.out  # 质押后余额从链上读


def test_stake_does_not_run_automatically_from_submit_hint(
    tmp_path: Path, monkeypatch, capsys, config_env
) -> None:
    """质押不足时 --submit 报错且零交易，并提示 python -m auditor.stake。"""
    ctx = make_ctx(tmp_path, staked=0)  # SAFE 样本，但审计者未质押
    project = project_dir(tmp_path)
    patch_network(monkeypatch, ctx)

    code = main([str(tmp_path / "skill"), "--submit"], project_root=project)
    captured = capsys.readouterr()
    assert code != 0
    assert "python -m auditor.stake" in captured.err
    assert ctx.eth.sent == [] and ctx.contract.sends == []
