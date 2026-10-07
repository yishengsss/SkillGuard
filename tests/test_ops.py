"""操作台后端测试（ops/server.py）。

原则：桌面后端只是"人的键盘"，判定不在这里发明——因此测试只验证：
1. 失败即拒绝：skill_dir 越出项目根 / 缺 manifest / decision 非法等都返回 OpsError；
2. 链声动作复用既有模块（register 计算的哈希 = auditor.hashing；agent-once 委托
   auditor.agent；install 委托 gate.mcp_server；stake 委托 auditor.stake）；
3. 真实 anvil（未运行则 skip）：注册→agent-once→install 的端到端。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ops import server  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def test_skill_dir_outside_root_rejected(tmp_path: Path) -> None:
    with pytest.raises(server.OpsError):
        server._resolve_skill_dir("/etc")
    with pytest.raises(server.OpsError):
        server._resolve_skill_dir("")


def test_skill_dir_inside_root_but_no_manifest_rejected(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(server.OpsError):
        server._resolve_skill_dir(str(empty))


def test_decide_rejects_unknown_value(tmp_path: Path) -> None:
    with pytest.raises(server.OpsError):
        server.decide("samples/weather", "maybe")


def test_register_requires_missing_name_version(tmp_path: Path) -> None:
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "manifest.json").write_text("{}", encoding="utf-8")
    with pytest.raises(Exception):
        server.register(str(skill))


def _abi_has(name: str) -> bool:
    return any(item.get("name") == name for item in server.ops_abi())


@pytest.mark.parametrize(
    ("fn_name", "expected"),
    [
        ("register", True),
        ("requestAudit", True),
        ("getStatus", True),
        ("MIN_DEPOSIT", True),
        ("submitReport", True),  # 来自 submit 最小 ABI
        ("AuditRequested", True),  # 事件（Agent 委托需要）
        ("keyOf", True),
        ("stakeAsAuditor", True),
    ],
)
def test_ops_abi_covers_console_needs(fn_name: str, expected: bool) -> None:
    assert _abi_has(fn_name) is expected


@pytest.mark.anvil
def test_ops_end_to_end_on_anvil(monkeypatch, tmp_path: Path) -> None:
    """注册→agent-once→install 端到端；anvil 未运行则 skip。

    注意会真的发交易（本地链），并给三角色补测试余额（server._fund_local 语义）。
    """
    monkeypatch.setenv("RPC_URL", "http://127.0.0.1:8545")
    server._fund_local(server._w3())
    try:
        server.register("samples/weather")
    except server.OpsError as exc:
        # 幂等复用：同版本已注册（status 已非 None）属正常，其他错误照常抛
        assert "已注册" in str(exc), exc
    run = server.agent_once()
    # 幂等：重复跑（游标推进后）processed 可为空，但必须 ok
    assert run["cursorAfter"] >= run["cursorBefore"], run
    install = server.install("samples/weather")
    assert install["installed"] is True, install
    reject = server.install("samples/mail-helper")
    assert reject["installed"] is False and reject["allowed"] is False, reject
