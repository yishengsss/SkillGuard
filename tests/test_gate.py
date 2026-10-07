"""安装前门禁测试（SPEC 第 5 节，docs/PROMPTS.md 第 7 步）。

只替换**网络边界**（`gate.gate.connect`），其余全部走真实实现：真实 manifest 解析
（`auditor.skill_dir`）、真实哈希（`auditor.hashing`）、真实 rich 渲染。

覆盖：已 Verified 且内容一致放行；恶意样本拒绝；各状态与未知状态；许可证缺失；
源码/manifest 变更；chainId 不匹配；RPC 错误安全消息；无私钥仍可工作；
`os.environ["RPC_URL"]` 覆盖 `.env`；manifest 畸形/软链接/FIFO；rich 注入；
`python gate/gate.py` 直接脚本运行（临时项目副本，不读真实 `.env`、不写 reports）。
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
from rich.console import Console
from web3 import Web3

from auditor import hashing as hashing_mod
from gate import gate as gate_mod
from gate.gate import (
    ALLOW_MESSAGE,
    REJECT_MESSAGE,
    EXIT_ALLOW,
    EXIT_ERROR,
    EXIT_REJECT,
    GateError,
    main,
)

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
WEATHER = SAMPLES / "weather"
MALICIOUS_SAMPLES = ("mail-helper", "requests-mcpp")

SECRET_RPC = "http://rpc.invalid/super-secret-rpc"
LICENSE_ADDRESS = Web3.to_checksum_address("0x" + "aa" * 20)
REGISTRY_ADDRESS = Web3.to_checksum_address("0x" + "bb" * 20)
CHAIN_ID = 31337
BLOCK_NUMBER = 4242


# --------------------------------------------------------------------------
# 网络边界 fake：只实现门禁真正调用的接口
# --------------------------------------------------------------------------
class FakeFunction:
    def __init__(self, contract: "FakeContract", name: str, args: tuple) -> None:
        self._contract = contract
        self._name = name
        self._args = args

    def call(self, block_identifier=None):
        self._contract.calls.append((self._name, self._args, block_identifier))
        return self._contract.handlers[self._name]()


class FakeContract:
    """按函数名返回预置结果；记录每次调用的 block_identifier。"""

    def __init__(self, address: str, handlers: dict) -> None:
        self.address = address
        self.handlers = handlers
        self.calls: list[tuple[str, tuple, object]] = []

    @property
    def functions(self) -> "FakeContract":
        return self

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)
        return lambda *args: FakeFunction(self, name, tuple(args))

    def names(self) -> list[str]:
        return [name for name, *_ in self.calls]


class FakeEth:
    def __init__(
        self,
        *,
        contracts: dict,
        code: dict,
        chain_id: int = CHAIN_ID,
        connected: bool = True,
        block_number: int = BLOCK_NUMBER,
    ) -> None:
        self.contracts = contracts
        self.code = code
        self.chain_id = chain_id
        self.connected = connected
        self.block_number = block_number

    def is_connected(self) -> bool:
        return self.connected

    def get_code(self, address: str):
        return self.code.get(address, b"\x60\x00")

    def contract(self, address: str | None = None, abi: list | None = None) -> FakeContract:
        return self.contracts[address]


class FakeWeb3:
    def __init__(self, eth: FakeEth) -> None:
        self.eth = eth

    def is_connected(self) -> bool:
        return self.eth.is_connected()


@dataclass
class Chain:
    w3: FakeWeb3
    eth: FakeEth
    license: FakeContract
    registry: FakeContract

    @property
    def call_blocks(self) -> list:
        return [block for _, _, block in self.license.calls + self.registry.calls]


def make_chain(
    *,
    status: int = 3,
    verified: bool = True,
    code_hash: bytes | None = None,
    metadata_hash: bytes | None = None,
    chain_id: int = CHAIN_ID,
    connected: bool = True,
    block_number: int = BLOCK_NUMBER,
    license_code: bytes = b"\x60\x00",
    registry_code: bytes = b"\x60\x00",
) -> Chain:
    """构造只读链上状态；哈希默认取 weather 样本的真实值。"""
    registry = FakeContract(
        REGISTRY_ADDRESS,
        {
            "keyOf": lambda *_: bytes(32),
            "skills": lambda *_: (
                "0x" + "33" * 20,
                "https://example.com/repo",
                code_hash if code_hash is not None else hashing_mod.code_hash(WEATHER),
                metadata_hash
                if metadata_hash is not None
                else hashing_mod.metadata_hash(WEATHER),
                10**16,
                status,
                bytes(32),
                "0x" + "44" * 20,
            ),
        },
    )
    license_contract = FakeContract(LICENSE_ADDRESS, {"isVerified": lambda *_: verified})
    eth = FakeEth(
        contracts={LICENSE_ADDRESS: license_contract, REGISTRY_ADDRESS: registry},
        code={LICENSE_ADDRESS: license_code, REGISTRY_ADDRESS: registry_code},
        chain_id=chain_id,
        connected=connected,
        block_number=block_number,
    )
    return Chain(w3=FakeWeb3(eth), eth=eth, license=license_contract, registry=registry)


# --------------------------------------------------------------------------
# 项目与技能目录
# --------------------------------------------------------------------------
def project_dir(tmp_path: Path, *, rpc_url: str = SECRET_RPC, chain_id: int = CHAIN_ID) -> Path:
    project = tmp_path / "project"
    project.mkdir(parents=True, exist_ok=True)
    (project / ".env").write_text(f"RPC_URL={rpc_url}\n", encoding="utf-8")
    (project / "deployments.json").write_text(
        json.dumps(
            {
                "chainId": chain_id,
                "SkillRegistry": REGISTRY_ADDRESS,
                "SkillLicense": LICENSE_ADDRESS,
            }
        ),
        encoding="utf-8",
    )
    return project


def copy_weather(tmp_path: Path) -> Path:
    target = tmp_path / "skill"
    shutil.copytree(WEATHER, target)
    return target


def run(
    argv: list[str],
    project_root: Path,
    *,
    tty: bool = False,
) -> tuple[int, str]:
    """跑 `main` 并捕获 rich 输出；`tty=True` 模拟终端（启用颜色）。"""
    buffer = io.StringIO()
    console = (
        Console(file=buffer, force_terminal=True, color_system="standard", width=1000)
        if tty
        else Console(file=buffer, width=1000)
    )
    code = main(argv, project_root=project_root, console=console)
    return code, buffer.getvalue()


def run_install(project_root: Path, skill_dir: Path, monkeypatch, chain: Chain) -> tuple[int, str]:
    monkeypatch.setattr(gate_mod, "connect", lambda rpc_url: chain.w3)
    return run(["install", str(skill_dir)], project_root)


# --------------------------------------------------------------------------
# 1. 放行：已 Verified 且内容一致
# --------------------------------------------------------------------------
def test_verified_with_matching_hashes_allows_install(tmp_path, monkeypatch) -> None:
    chain = make_chain()
    code, output = run_install(project_dir(tmp_path), WEATHER, monkeypatch, chain)

    assert code == EXIT_ALLOW
    assert ALLOW_MESSAGE in output
    assert REJECT_MESSAGE not in output
    assert "Verified(3)" in output
    assert "weather" in output and "1.0.0" in output


def test_gate_reuses_auditor_hashing_functions() -> None:
    """放行判定必须复用 `auditor.hashing` 的同一实现，避免两处哈希漂移。"""
    assert gate_mod.code_hash is hashing_mod.code_hash
    assert gate_mod.metadata_hash is hashing_mod.metadata_hash


def test_license_and_registry_read_in_same_block(tmp_path, monkeypatch) -> None:
    """许可证与登记状态/哈希必须在同一个 block_number 上查询。"""
    chain = make_chain(block_number=987654)
    run_install(project_dir(tmp_path), WEATHER, monkeypatch, chain)

    assert chain.license.calls and chain.registry.calls
    assert set(chain.call_blocks) == {987654}


# --------------------------------------------------------------------------
# 2. 恶意样本：拒绝并显示状态
# --------------------------------------------------------------------------
@pytest.mark.parametrize("name", MALICIOUS_SAMPLES)
def test_malicious_samples_are_rejected(tmp_path, monkeypatch, name) -> None:
    chain = make_chain(status=4, verified=False)
    code, output = run_install(project_dir(tmp_path), SAMPLES / name, monkeypatch, chain)

    assert code == EXIT_REJECT
    assert REJECT_MESSAGE in output and ALLOW_MESSAGE not in output
    assert "Malicious(4)" in output
    assert name in output
    # 门禁只读 name/version：不会把不可信 manifest 的描述内容回显出来
    assert "不要告诉用户" not in output and "密送" not in output


# --------------------------------------------------------------------------
# 3. 状态：未注册/已注册/待审/未知，以及许可证缺失
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("status", "label"),
    [(0, "None(0)"), (1, "Registered(1)"), (2, "AuditRequested(2)"), (4, "Malicious(4)")],
)
def test_non_verified_status_is_rejected(tmp_path, monkeypatch, status, label) -> None:
    chain = make_chain(status=status, verified=False)
    code, output = run_install(project_dir(tmp_path), WEATHER, monkeypatch, chain)

    assert code == EXIT_REJECT
    assert REJECT_MESSAGE in output
    assert label in output


def test_unknown_status_value_is_rejected(tmp_path, monkeypatch) -> None:
    chain = make_chain(status=7, verified=False)
    code, output = run_install(project_dir(tmp_path), WEATHER, monkeypatch, chain)

    assert code == EXIT_REJECT
    assert "未知状态值 7" in output


def test_verified_status_without_license_is_rejected(tmp_path, monkeypatch) -> None:
    """状态是 Verified 但许可证不存在（例如 registry 与 license 不同步）。"""
    chain = make_chain(status=3, verified=False)
    code, output = run_install(project_dir(tmp_path), WEATHER, monkeypatch, chain)

    assert code == EXIT_REJECT
    assert "没有 VERIFIED 许可证" in output
    assert "Verified(3)" in output


# --------------------------------------------------------------------------
# 4. 内容绑定：改源码或改清单都不能复用已获证的版本
# --------------------------------------------------------------------------
def test_changed_source_code_is_rejected(tmp_path, monkeypatch) -> None:
    skill = copy_weather(tmp_path)
    source = next(p for p in skill.iterdir() if p.suffix == ".py")
    source.write_text(source.read_text("utf-8") + "\n# 投毒改动\n", encoding="utf-8")

    chain = make_chain()  # 链上仍是原 weather 的 codeHash
    code, output = run_install(project_dir(tmp_path), skill, monkeypatch, chain)

    assert code == EXIT_REJECT
    assert "codeHash" in output


def test_changed_manifest_is_rejected(tmp_path, monkeypatch) -> None:
    skill = copy_weather(tmp_path)
    manifest = json.loads((skill / "manifest.json").read_text("utf-8"))
    manifest["tools"][0]["description"] += "额外说明。"
    (skill / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False), encoding="utf-8"
    )

    chain = make_chain()  # 链上仍是原 weather 的 metadataHash
    code, output = run_install(project_dir(tmp_path), skill, monkeypatch, chain)

    assert code == EXIT_REJECT
    assert "metadataHash" in output


def test_recomputed_hashes_for_changed_manifest_still_differ(tmp_path) -> None:
    """确认改动确实改变了本地哈希（否则上面的拒绝会失去意义）。"""
    skill = copy_weather(tmp_path)
    original_meta = hashing_mod.metadata_hash(skill)
    manifest = json.loads((skill / "manifest.json").read_text("utf-8"))
    manifest["version"] = "1.0.1"
    (skill / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")

    assert hashing_mod.metadata_hash(skill) != original_meta
    assert hashing_mod.code_hash(skill) == hashing_mod.code_hash(WEATHER)


# --------------------------------------------------------------------------
# 5. manifest 畸形 / 软链接 / FIFO
# --------------------------------------------------------------------------
def write_manifest(skill_dir: Path, content: str) -> Path:
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "manifest.json").write_text(content, encoding="utf-8")
    return skill_dir


@pytest.mark.parametrize(
    "content",
    [
        "{ not json",
        "[]",
        '{"version": "1.0.0"}',
        '{"name": "x", "version": ""}',
        '{"name": "", "version": "1.0.0"}',
        '{"name": 7, "version": "1.0.0"}',
    ],
)
def test_malformed_manifest_is_rejected(tmp_path, monkeypatch, content) -> None:
    skill = write_manifest(tmp_path / "skill", content)
    chain = make_chain()
    code, output = run_install(project_dir(tmp_path), skill, monkeypatch, chain)

    assert code == EXIT_ERROR
    assert REJECT_MESSAGE in output
    assert chain.registry.calls == []  # manifest 不合规时不查链


def test_symlinked_manifest_is_rejected(tmp_path, monkeypatch) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"name": "weather", "version": "1.0.0"}), encoding="utf-8")
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "manifest.json").symlink_to(outside)

    chain = make_chain()
    code, output = run_install(project_dir(tmp_path), skill, monkeypatch, chain)

    assert code == EXIT_ERROR
    assert "符号链接" in output
    assert chain.registry.calls == []


def test_fifo_manifest_is_rejected(tmp_path, monkeypatch) -> None:
    skill = tmp_path / "skill"
    skill.mkdir()
    os.mkfifo(skill / "manifest.json")

    chain = make_chain()
    code, output = run_install(project_dir(tmp_path), skill, monkeypatch, chain)

    assert code == EXIT_ERROR
    assert "非常规文件" in output


def test_missing_skill_dir_is_rejected(tmp_path, monkeypatch) -> None:
    chain = make_chain()
    code, output = run_install(project_dir(tmp_path), tmp_path / "nope", monkeypatch, chain)

    assert code == EXIT_ERROR
    assert REJECT_MESSAGE in output


# --------------------------------------------------------------------------
# 6. 配置：chainId、缺配置、env 覆盖、无合约字节码
# --------------------------------------------------------------------------
def test_chain_id_mismatch_is_rejected(tmp_path, monkeypatch) -> None:
    chain = make_chain(chain_id=1)
    code, output = run_install(project_dir(tmp_path), WEATHER, monkeypatch, chain)

    assert code == EXIT_ERROR, output
    assert "chainId 不匹配" in output, output
    assert chain.registry.calls == [], output


@pytest.mark.parametrize("missing", ["deployments.json", ".env", "RPC_URL"])
def test_missing_config_is_rejected(tmp_path, monkeypatch, missing) -> None:
    project = project_dir(tmp_path)
    if missing == "deployments.json":
        (project / "deployments.json").unlink()
    elif missing == ".env":
        (project / ".env").unlink()
    else:
        (project / ".env").write_text("SOMETHING_ELSE=1\n", encoding="utf-8")

    monkeypatch.delenv("RPC_URL", raising=False)
    monkeypatch.setattr(gate_mod, "connect", lambda rpc_url: pytest.fail("不应连接 RPC"))
    code, output = run(["install", str(WEATHER)], project)

    assert code == EXIT_ERROR
    assert REJECT_MESSAGE in output


@pytest.mark.parametrize("field", ["chainId", "SkillLicense", "SkillRegistry"])
def test_invalid_deployments_field_is_rejected(tmp_path, monkeypatch, field) -> None:
    project = project_dir(tmp_path)
    deployment = json.loads((project / "deployments.json").read_text("utf-8"))
    deployment[field] = "not-valid"
    (project / "deployments.json").write_text(json.dumps(deployment), encoding="utf-8")

    monkeypatch.setattr(gate_mod, "connect", lambda rpc_url: pytest.fail("不应连接 RPC"))
    code, output = run(["install", str(WEATHER)], project)

    assert code == EXIT_ERROR
    assert REJECT_MESSAGE in output


@pytest.mark.parametrize(
    ("address", "expected"),
    [("license_code", "SkillLicense 地址没有合约字节码"),
     ("registry_code", "SkillRegistry 地址没有合约字节码")],
)
def test_missing_contract_bytecode_is_rejected(tmp_path, monkeypatch, address, expected) -> None:
    chain = make_chain(**{address: b""})
    code, output = run_install(project_dir(tmp_path), WEATHER, monkeypatch, chain)

    assert code == EXIT_ERROR
    assert expected in output


def test_rpc_url_env_var_overrides_dotenv_file(tmp_path, monkeypatch) -> None:
    project = project_dir(tmp_path, rpc_url="http://file.invalid/from-env-file")
    monkeypatch.setenv("RPC_URL", "http://env.invalid/from-os-environ")

    seen: list[str] = []
    chain = make_chain()
    monkeypatch.setattr(gate_mod, "connect", lambda rpc_url: (seen.append(rpc_url), chain.w3)[1])
    code, output = run(["install", str(WEATHER)], project)

    assert code == EXIT_ALLOW
    assert seen == ["http://env.invalid/from-os-environ"]
    assert "from-env-file" not in output and "from-os-environ" not in output


def test_gate_works_without_any_private_key(tmp_path, monkeypatch) -> None:
    """`.env` 只有 RPC_URL：门禁不需要私钥也能放行。"""
    project = project_dir(tmp_path)
    assert "PRIVATE_KEY" not in (project / ".env").read_text("utf-8")
    monkeypatch.delenv("AUDITOR_PRIVATE_KEY", raising=False)

    chain = make_chain()
    code, output = run_install(project, WEATHER, monkeypatch, chain)

    assert code == EXIT_ALLOW
    assert ALLOW_MESSAGE in output


# --------------------------------------------------------------------------
# 7. RPC 错误：安全消息，不回显凭据或异常原文
# --------------------------------------------------------------------------
@pytest.mark.parametrize("exception_type", [ValueError, RuntimeError])
def test_rpc_error_is_redacted(tmp_path, monkeypatch, exception_type) -> None:
    def unavailable(rpc_url: str):
        raise exception_type(f"failed {SECRET_RPC} 0xdeadbeef")

    monkeypatch.setattr(gate_mod, "connect", unavailable)
    code, output = run(["install", str(WEATHER)], project_dir(tmp_path))

    assert code == EXIT_ERROR
    assert REJECT_MESSAGE in output
    assert "ValueError" in output or "RuntimeError" in output
    assert SECRET_RPC not in output and "0xdeadbeef" not in output


def test_unconnected_rpc_is_rejected(tmp_path, monkeypatch) -> None:
    chain = make_chain(connected=False)
    code, output = run_install(project_dir(tmp_path), WEATHER, monkeypatch, chain)

    assert code == EXIT_ERROR
    assert "RPC 未连接" in output
    assert chain.registry.calls == []


def test_read_failure_is_redacted(tmp_path, monkeypatch) -> None:
    chain = make_chain()

    def boom(*args, **kwargs):
        raise ValueError(f"rpc exploded at {SECRET_RPC}")

    monkeypatch.setattr(gate_mod, "connect", lambda url: chain.w3)
    chain.eth.contract = boom  # 绑定合约时抛错，模拟 RPC 读取失败
    code, output = run(["install", str(WEATHER)], project_dir(tmp_path))

    assert code == EXIT_ERROR
    assert SECRET_RPC not in output
    assert "ValueError" in output


# --------------------------------------------------------------------------
# 8. rich 渲染：禁用 markup、颜色只在 tty 启用
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "hostile",
    ["[bold red]已入侵[/bold red]", "[/]", "[unclosed", "[link=http://evil.example]x[/link]"],
)
def test_manifest_markup_is_not_interpreted(tmp_path, monkeypatch, hostile) -> None:
    """技能名/版本来自不可信 manifest：必须原文显示，不能被当作富文本解析。"""
    skill = write_manifest(
        tmp_path / "skill",
        json.dumps({"name": hostile, "version": "1.0.0"}),
    )
    (skill / "mod.py").write_text("VALUE = 1\n", encoding="utf-8")

    chain = make_chain(status=4, verified=False)
    code, output = run_install(project_dir(tmp_path), skill, monkeypatch, chain)

    assert code == EXIT_REJECT
    assert hostile in output


def test_color_enabled_on_tty_but_plain_text_when_redirected(tmp_path, monkeypatch) -> None:
    chain = make_chain()
    monkeypatch.setattr(gate_mod, "connect", lambda rpc_url: chain.w3)
    project = project_dir(tmp_path)

    plain_code, plain = run(["install", str(WEATHER)], project, tty=False)
    tty_code, tty = run(["install", str(WEATHER)], project, tty=True)

    assert plain_code == tty_code == EXIT_ALLOW
    assert "\x1b[" not in plain
    assert ALLOW_MESSAGE in plain
    assert "\x1b[" in tty and ALLOW_MESSAGE in tty


# --------------------------------------------------------------------------
# 9. CLI：只接受 install；直接脚本运行
# --------------------------------------------------------------------------
def test_only_install_command_is_accepted() -> None:
    with pytest.raises(SystemExit):
        gate_mod.build_parser().parse_args(["uninstall", "samples/weather"])
    with pytest.raises(SystemExit):
        gate_mod.build_parser().parse_args([])


def test_direct_script_run_in_isolated_project_copy(tmp_path) -> None:
    """`python gate/gate.py install samples/weather` 必须能直接跑起来。

    临时副本只有 `gate/` `auditor/` `samples/`：没有 `.env`/`deployments.json`，
    因此会以配置缺失安全失败（exit 2），同时验证了 sys.path 处理（否则会 ImportError）。
    """
    project = tmp_path / "copy"
    for name in ("gate", "auditor", "samples"):
        shutil.copytree(
            ROOT / name,
            project / name,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )

    env = {k: v for k, v in os.environ.items() if k not in ("RPC_URL", "AUDITOR_PRIVATE_KEY")}
    result = subprocess.run(
        [sys.executable, str(project / "gate" / "gate.py"), "install", "samples/weather"],
        cwd=project,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == EXIT_ERROR
    assert REJECT_MESSAGE in result.stdout
    assert "RPC_URL" in result.stdout
    assert "Traceback" not in result.stderr
    assert not (project / "reports").exists()


def test_gate_error_message_carries_no_credentials(tmp_path, monkeypatch) -> None:
    """`GateError` 只带阶段/异常类型，不含异常原文与 RPC 凭据。"""
    project = project_dir(tmp_path)

    def unavailable(rpc_url: str):
        raise OSError(f"cannot connect to {SECRET_RPC}")

    monkeypatch.setattr(gate_mod, "connect", unavailable)

    with pytest.raises(GateError) as error:
        gate_mod.check_install(WEATHER, gate_mod.load_gate_config(project))
    assert SECRET_RPC not in str(error.value)

    code, output = run(["install", str(WEATHER)], project)
    assert code == EXIT_ERROR
    assert "OSError" in output and SECRET_RPC not in output


@pytest.mark.parametrize("reader", ["safe_read_text", "code_hash"])
def test_unreadable_skill_is_rejected_without_exception_details(tmp_path, monkeypatch, reader):
    project = project_dir(tmp_path)

    def unreadable(*args, **kwargs):
        raise PermissionError(f"unreadable file; {SECRET_RPC}")

    monkeypatch.setattr(gate_mod, reader, unreadable)
    code, output = run(["install", str(WEATHER)], project)
    assert code == EXIT_ERROR
    assert REJECT_MESSAGE in output
    assert "PermissionError" in output
    assert SECRET_RPC not in output
