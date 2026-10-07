"""LLM 一致性检查测试（docs/PROMPTS.md 第 8 步；RED，auditor.llm 待实现）。

接口约定：LLMError / LLMConfig(api_key, base_url, model) / load_config(project_root)
/ check_consistency(skill_dir, report, config, cache_root) -> list[Finding]。
只 mock 网络边界（urllib.request.build_opener），缓存根为项目 `.cache/llm`。
凭据一律 dummy fixture，不读取真实 .env、不外连。
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from auditor import cli as cli_mod
from auditor import llm as llm_mod
from auditor.cli import main
from auditor.llm import LLMConfig, LLMError, check_consistency, load_config
from auditor.report import MALICIOUS, SAFE, Finding, derive_level
from auditor.scanner import scan_skill_report

KEY = "dummyfixture-key"
BASE = "https://example.org/v1"
MODEL = "dummyfixture-model"
SERIAL = json.dumps({"findings": []}).encode("utf-8")
MANIFEST = {
    "name": "weather",
    "package": "weather-mcp",
    "version": "1.0.0",
    "tools": [
        {
            "name": "get_weather",
            "description": "查询天气",
            "inputSchema": {"type": "object"},
        }
    ],
}


class FakeResponse:
    """最小 urllib 响应：支持 read/status 与上下文管理器。"""

    def __init__(self, body: bytes, status: int = 200) -> None:
        self._body, self.status = body, status

    def read(self, size: int = -1) -> bytes:
        return self._body if size < 0 else self._body[:size]

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False


class FakeOpener:
    """替身 opener：记录请求，按队列返回响应体或抛异常。"""

    def __init__(self, queue: list[object]) -> None:
        self.queue = list(queue)
        self.requests: list[urllib.request.Request] = []

    def open(self, req, *args, **kwargs) -> FakeResponse:
        self.requests.append(req)
        item = self.queue.pop(0) if self.queue else SERIAL
        if isinstance(item, BaseException):
            raise item
        assert isinstance(item, bytes)
        return FakeResponse(item)

    def last_json(self) -> dict:
        return json.loads(self.requests[-1].data.decode("utf-8"))


def write_skill(root: Path, *, description: str = "查询天气") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    manifest = dict(MANIFEST)
    manifest["tools"] = [dict(MANIFEST["tools"][0], description=description)]
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (root / "server.py").write_text("def get_weather():\n    return 'sunny'\n", encoding="utf-8")
    return root


def completion(findings: list | None = None) -> bytes:
    """OpenAI 兼容 chat completion，content 是 {"findings": [...]} 字符串。"""
    content = json.dumps({"findings": findings or []})
    body = {"choices": [{"message": {"role": "assistant", "content": content}}]}
    return json.dumps(body).encode("utf-8")


def canned(**kw: object) -> LLMConfig:
    return LLMConfig(**({"api_key": KEY, "base_url": BASE, "model": MODEL} | kw))


@pytest.fixture()
def skill(tmp_path: Path) -> Path:
    return write_skill(tmp_path / "skill")


@pytest.fixture()
def cache(tmp_path: Path) -> Path:
    return tmp_path / "cache" / "llm"


def run(skill: Path, report, config: LLMConfig, cache: Path, queue: list):
    """用给定响应队列跑一次 check_consistency，返回 (findings, fake_opener)。

    只替换 urllib 的网络边界（build_opener），并断言未启用重定向处理器。
    """
    fake = FakeOpener(list(queue))
    original = urllib.request.build_opener

    def fake_build_opener(*handlers):
        redirect_handlers = [h for h in handlers if isinstance(h, urllib.request.HTTPRedirectHandler)]
        assert redirect_handlers, "必须禁用 urllib 默认重定向"
        for h in redirect_handlers:
            assert h.redirect_request(None, None, 302, "redirect", {}, BASE) is None
        return fake

    urllib.request.build_opener = fake_build_opener
    try:
        return check_consistency(skill, report, config, cache), fake
    finally:
        urllib.request.build_opener = original


# --------------------------------------------------------------------------
# 配置：dataclass 不回显凭据；env 优先于 .env；缺配置报 LLMError
# --------------------------------------------------------------------------
def test_config_repr_and_str_hide_key() -> None:
    cfg = canned()
    assert KEY not in repr(cfg)
    assert KEY not in str(cfg)
    assert cfg.base_url == BASE and cfg.model == MODEL


def test_load_config_reads_env_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / ".env").write_text(
        f"LLM_API_KEY={KEY}\nLLM_BASE_URL={BASE}\nLLM_MODEL={MODEL}\n",
        encoding="utf-8",
    )
    cfg = load_config(tmp_path)
    assert (cfg.api_key, cfg.base_url, cfg.model) == (KEY, BASE, MODEL)


def test_load_config_env_beats_env_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / ".env").write_text(
        f"LLM_API_KEY=file-key\nLLM_BASE_URL=https://example.com/v1\nLLM_MODEL=file\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("LLM_API_KEY", KEY)
    monkeypatch.setenv("LLM_MODEL", MODEL)
    cfg = load_config(tmp_path)
    assert cfg.api_key == KEY and cfg.model == MODEL


def test_load_config_without_key_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("LLM_API_KEY", "LLM_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(LLMError):
        load_config(tmp_path)


# --------------------------------------------------------------------------
# 请求形状：temperature=0、JSON 模式、带上 manifest 与源码
# --------------------------------------------------------------------------
def test_request_shape_and_payload(skill: Path, cache: Path) -> None:
    report = scan_skill_report(skill)
    findings, fake = run(skill, report, canned(), cache, [completion()])
    assert findings == []
    assert len(fake.requests) == 1

    body = fake.last_json()
    assert body["model"] == MODEL
    assert body["temperature"] == 0
    assert body["response_format"] == {"type": "json_object"}

    blob = json.dumps(body, ensure_ascii=False)
    assert "weather" in blob and "get_weather" in blob  # manifest
    assert "sunny" in blob  # 源码
    assert fake.requests[-1].full_url.endswith("/chat/completions")


# --------------------------------------------------------------------------
# 等级：critical 把 SAFE 抬成 MALICIOUS；空结果不改静态结论
# --------------------------------------------------------------------------
def crit(**over: object) -> dict:
    item = {
        "rule": "LLM-001",
        "stage": "llm",
        "severity": "critical",
        "file": "server.py",
        "evidence": "描述声称只读天气，代码实际外发数据",
    }
    item.update(over)
    return item


def test_empty_findings_keep_static_level(skill: Path, cache: Path) -> None:
    report = scan_skill_report(skill)
    assert report.level == SAFE
    findings, _ = run(skill, report, canned(), cache, [completion()])
    assert findings == []
    assert derive_level([*report.findings, *findings]) == SAFE


def test_critical_finding_escalates_safe_to_malicious(skill: Path, cache: Path) -> None:
    report = scan_skill_report(skill)
    findings, _ = run(skill, report, canned(), cache, [completion([crit()])])
    assert [f.severity for f in findings] == ["critical"]
    assert all(isinstance(f, Finding) for f in findings)
    assert derive_level([*report.findings, *findings]) == MALICIOUS


def test_finding_fields_are_mapped(skill: Path, cache: Path) -> None:
    report = scan_skill_report(skill)
    findings, _ = run(skill, report, canned(), cache, [completion([crit()])])
    first = findings[0]
    assert (first.rule, first.severity, first.file) == ("LLM-001", "critical", "server.py")
    assert first.stage == "llm"
    assert first.evidence


# --------------------------------------------------------------------------
# 缓存：命中不请求；源码 / metadata / model 变更即失效
# --------------------------------------------------------------------------
def test_second_call_hits_cache(skill: Path, cache: Path) -> None:
    report = scan_skill_report(skill)
    run(skill, report, canned(), cache, [completion()])
    findings, second = run(skill, report, canned(), cache, [])
    assert findings == []
    assert second.requests == []


def test_source_change_invalidates_cache(skill: Path, cache: Path) -> None:
    report = scan_skill_report(skill)
    run(skill, report, canned(), cache, [completion()])
    (skill / "server.py").write_text("def get_weather():\n    return 'rain'\n", encoding="utf-8")
    report = scan_skill_report(skill)
    _, second = run(skill, report, canned(), cache, [completion()])
    assert len(second.requests) == 1


def test_manifest_change_invalidates_cache(skill: Path, cache: Path) -> None:
    report = scan_skill_report(skill)
    run(skill, report, canned(), cache, [completion()])
    changed = dict(MANIFEST, version="1.0.1")
    (skill / "manifest.json").write_text(json.dumps(changed), encoding="utf-8")
    report = scan_skill_report(skill)
    _, second = run(skill, report, canned(), cache, [completion()])
    assert len(second.requests) == 1


def test_model_change_invalidates_cache(skill: Path, cache: Path) -> None:
    report = scan_skill_report(skill)
    run(skill, report, canned(), cache, [completion()])
    _, second = run(skill, report, canned(model="other-model"), cache, [completion()])
    assert len(second.requests) == 1


# --------------------------------------------------------------------------
# 失败路径：网络异常 / 畸形 JSON 都是 LLMError，且不泄漏原始响应
# --------------------------------------------------------------------------
LEAK = "dummyfixture-raw-response-body"


def test_network_failure_raises_llm_error(skill: Path, cache: Path) -> None:
    report = scan_skill_report(skill)
    boom = urllib.error.URLError("connection refused")
    with pytest.raises(LLMError) as excinfo:
        run(skill, report, canned(), cache, [boom])
    assert LEAK not in str(excinfo.value)


def test_http_error_body_not_leaked(skill: Path, cache: Path) -> None:
    report = scan_skill_report(skill)
    err = urllib.error.HTTPError(BASE, 500, "err", {}, None)
    err.read = lambda: LEAK.encode("utf-8")  # type: ignore[method-assign]
    with pytest.raises(LLMError) as excinfo:
        run(skill, report, canned(), cache, [err])
    assert LEAK not in str(excinfo.value)


def test_invalid_json_raises_llm_error(skill: Path, cache: Path) -> None:
    report = scan_skill_report(skill)
    with pytest.raises(LLMError) as excinfo:
        run(skill, report, canned(), cache, [f"{{{LEAK}}}".encode("utf-8")])
    assert LEAK not in str(excinfo.value)


def test_content_not_json_raises_llm_error(skill: Path, cache: Path) -> None:
    report = scan_skill_report(skill)
    body = json.dumps({"choices": [{"message": {"content": LEAK}}]}).encode("utf-8")
    with pytest.raises(LLMError) as excinfo:
        run(skill, report, canned(), cache, [body])
    assert LEAK not in str(excinfo.value)


def test_missing_choices_raises_llm_error(skill: Path, cache: Path) -> None:
    report = scan_skill_report(skill)
    with pytest.raises(LLMError):
        run(skill, report, canned(), cache, [json.dumps({"choices": []}).encode("utf-8")])


def test_success_is_cached_only_after_valid_response(skill: Path, cache: Path) -> None:
    """失败不应写缓存：修好后仍要重新请求。"""
    report = scan_skill_report(skill)
    with pytest.raises(LLMError):
        run(skill, report, canned(), cache, [b"{bad json"])
    _, ok = run(skill, report, canned(), cache, [completion()])
    assert len(ok.requests) == 1


# --------------------------------------------------------------------------
# CLI：--llm 帮助可见、无 --llm 不调用、失败不提交上链
# --------------------------------------------------------------------------
def patch_llm(monkeypatch: pytest.MonkeyPatch, *, result=None, exc=None) -> list:
    """替换 CLI 会调用的 check_consistency，记录调用。"""
    calls: list = []

    def fake(skill_dir, report, config, cache_root):
        calls.append((Path(skill_dir), report, config, Path(cache_root)))
        if exc is not None:
            raise exc
        return list(result or [])

    for module in (llm_mod, cli_mod):
        if hasattr(module, "check_consistency"):
            monkeypatch.setattr(module, "check_consistency", fake)
    return calls


def test_cli_help_lists_llm(capsys: pytest.CaptureFixture) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0
    assert "--llm" in capsys.readouterr().out


def test_cli_without_llm_skips_check(
    tmp_path: Path, skill: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = patch_llm(monkeypatch)
    assert main([str(skill)], project_root=tmp_path) == 0
    assert calls == []
    assert (tmp_path / "reports").is_dir()  # 静态流程照常落盘


def test_cli_llm_uses_project_cache_and_merges_findings(
    tmp_path: Path, skill: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    (tmp_path / ".env").write_text(
        f"LLM_API_KEY={KEY}\nLLM_BASE_URL={BASE}\nLLM_MODEL={MODEL}\n",
        encoding="utf-8",
    )
    calls = patch_llm(monkeypatch, result=[Finding(**crit())])
    assert main([str(skill), "--llm"], project_root=tmp_path) == 0
    assert calls and calls[0][3] == tmp_path / ".cache" / "llm"
    assert json.loads(capsys.readouterr().out)["level"] == MALICIOUS


def test_cli_llm_without_config_fails(tmp_path: Path, skill: Path, monkeypatch) -> None:
    for name in ("LLM_API_KEY", "LLM_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    assert main([str(skill), "--llm"], project_root=tmp_path) != 0


def test_cli_llm_failure_blocks_submit(tmp_path: Path, skill: Path, monkeypatch) -> None:
    """--llm 失败时绝不能上链：_submit_and_save 一次都不能被调用。"""
    (tmp_path / ".env").write_text(
        f"LLM_API_KEY={KEY}\nLLM_BASE_URL={BASE}\nLLM_MODEL={MODEL}\n",
        encoding="utf-8",
    )
    patch_llm(monkeypatch, exc=LLMError("一致性检查失败"))
    submitted: list = []
    monkeypatch.setattr(cli_mod, "_submit_and_save", lambda *a, **k: submitted.append(a))
    assert main([str(skill), "--llm", "--submit"], project_root=tmp_path) != 0
    assert submitted == []


def test_cli_llm_failure_does_not_write_report(
    tmp_path: Path, skill: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".env").write_text(
        f"LLM_API_KEY={KEY}\nLLM_BASE_URL={BASE}\nLLM_MODEL={MODEL}\n",
        encoding="utf-8",
    )
    patch_llm(monkeypatch, exc=LLMError("一致性检查失败"))
    assert main([str(skill), "--llm"], project_root=tmp_path) != 0
    assert not (tmp_path / "reports").exists()


def test_cli_llm_network_error_does_not_leak(
    tmp_path: Path, skill: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """端到端：真实 check_consistency + 畸形响应，CLI 输出不得含原始响应体。"""
    (tmp_path / ".env").write_text(
        f"LLM_API_KEY={KEY}\nLLM_BASE_URL={BASE}\nLLM_MODEL={MODEL}\n",
        encoding="utf-8",
    )
    fake = FakeOpener([f"{{{LEAK}}}".encode("utf-8")])
    monkeypatch.setattr(urllib.request, "build_opener", lambda *h: fake)
    assert main([str(skill), "--llm"], project_root=tmp_path) != 0
    captured = capsys.readouterr()
    assert LEAK not in captured.out and LEAK not in captured.err
