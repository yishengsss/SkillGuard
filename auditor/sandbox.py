"""沙箱动态分析（方案书 3.5.2 四段式流水线的第 3 段；可选阶段，CLI `--sandbox`）。

工作方式（隔离预置演示，方案书 3.13）：
1. 用 `python -I` 在子进程中运行 `auditor/_sandbox_harness.py`（隔离模式：忽略
   PYTHONPATH 等环境变量、不加载 sitecustomize，技能代码无法通过导入路径逃逸）；
2. harness 先打补丁（socket / subprocess / open / environ 全部插桩），再按文件路径
   导入技能模块并调用 manifest 声明的工具函数；
3. 危险动作（外连、子进程、敏感路径）**记录后一律阻断** —— 沙箱内零真实外连；
4. 事件以固定格式文本（`egress host=...` / `spawn argv=...` / ...）流回父进程，
   在这里用 `rules/sandbox.yaml`（DYN-*）做正则匹配生成 findings（stage="sandbox"）。

失败语义：子进程超时/崩溃/无法解析只记录到 `SandboxResult.error`（stderr 可见），
**不产生任何 findings** —— 沙箱自身失败不是技能恶意的证据，不得抬高等级。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .report import Finding
from .rules import Rule

HARNESS_PATH = Path(__file__).resolve().parent / "_sandbox_harness.py"
DEFAULT_TIMEOUT = 5.0
EVIDENCE_LIMIT = 160


@dataclass
class SandboxResult:
    """沙箱运行结果：findings 进报告，events/error 只进 stderr 说明。"""

    findings: list[Finding] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    modules: list[str] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)
    error: str = ""


def _clip(text: str, limit: int = EVIDENCE_LIMIT) -> str:
    line = " ".join(text.split())
    if len(line) <= limit:
        return line
    return line[: limit - 1] + "…"


def _match_findings(events: list[str], rules: list[Rule]) -> list[Finding]:
    """把沙箱事件逐条与规则匹配；同一规则同一事件只报第一条。"""
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for event in events:
        for rule in rules:
            if rule.id in (f.rule for f in findings):
                continue
            hit = next((pattern.search(event) for pattern in rule.patterns), None)
            marker = (rule.id, event)
            if hit is not None and marker not in seen:
                seen.add(marker)
                findings.append(
                    Finding(
                        rule=rule.id,
                        stage="sandbox",
                        severity=rule.severity,
                        file="sandbox",
                        evidence=_clip(event),
                    )
                )
                break
    return findings


def run_sandbox(skill_dir: Path, rules: list[Rule], *, timeout: float = DEFAULT_TIMEOUT) -> SandboxResult:
    """在隔离子进程运行技能，捕获事件并匹配 DYN-* 规则。"""
    result = SandboxResult()

    read_fd, write_fd = os.pipe()
    try:
        process = subprocess.Popen(
            [sys.executable, "-I", str(HARNESS_PATH), str(Path(skill_dir)), str(write_fd)],
            pass_fds=(write_fd,),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            cwd=str(HARNESS_PATH.parent.parent),
        )
        os.close(write_fd)
        try:
            raw = _read_line(read_fd, timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            result.error = "sandbox-timeout"
            return result
        return_code = process.wait(timeout=timeout)
    finally:
        os.close(read_fd)

    try:
        payload = json.loads(raw)
    except ValueError:
        result.error = "bad-harness-output"
        return result
    result.modules = [str(item) for item in payload.get("modules", [])]
    result.calls = [str(item) for item in payload.get("calls", [])]
    result.events = [str(item) for item in payload.get("events", [])]
    harness_error = payload.get("error")
    if harness_error:
        result.error = f"harness-{harness_error}"
    if return_code != 0 and not result.error:
        result.error = f"exit-{return_code}"

    result.findings = _match_findings(result.events, rules)
    return result


def _read_line(read_fd: int, timeout: float) -> str:
    """带超时地读满一行（harness 在结束时写单行 JSON）。"""
    import selectors

    selector = selectors.DefaultSelector()
    selector.register(read_fd, selectors.EVENT_READ)
    pieces: list[bytes] = []
    try:
        while True:
            if not selector.select(timeout):
                raise subprocess.TimeoutExpired("harness", timeout)
            chunk = os.read(read_fd, 65536)
            if not chunk:
                break
            pieces.append(chunk)
            if b"\n" in chunk:
                break
    finally:
        selector.close()
    data = b"".join(pieces)
    end = data.find(b"\n")
    return (data[:end] if end != -1 else data).decode("utf-8", errors="replace")


__all__ = ["DEFAULT_TIMEOUT", "SandboxResult", "run_sandbox"]
