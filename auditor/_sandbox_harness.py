"""沙箱 harness（由 `auditor/sandbox.py` 以 `python -I` 在子进程中运行，勿手工执行）。

职责：**先打补丁、再导入技能代码**，记录行为事件并阻断危险动作（方案书 3.5.2 沙箱
动态分析阶段的隔离预置演示）：

- `socket` 建连 / DNS 解析：记录 egress 事件后一律拒绝 —— 沙箱内**零真实外连**；
- `subprocess` / `os.system` / `os.spawn*`：记录 spawn 事件后拒绝 —— 沙箱内不再派生子进程；
- `builtins.open` / `os.open`：记录 open 事件；仅当路径命中敏感模式（与 DYN-003 一致）
  时才阻断；
- `os.environ` 取值：记录 env 事件（只记键名，不记值）。

结果以单行 JSON 写入 fd 3（由父进程创建管道后作为 fd 3 传入）：
{"modules": [...], "calls": [...], "events": [...], "error": null | "原因限定词"}

代码在 `-I` 隔离模式运行（忽略 PYTHONPATH/环境变量、不加载 sitecustomize），技能模块
按文件路径用 importlib 装载。任何技能侧异常都转成事件或 `error` 字段，不打印堆栈。
"""

from __future__ import annotations

import builtins
import importlib.util
import json
import os
import re
import socket
import subprocess as _subprocess
import sys

SENSITIVE_OPEN = re.compile(
    r"(.*\.aws/credentials|.*\.aws/config|.*\.ssh/|.*id_rsa|.*\.env\b|.*\.kube/config)",
    re.IGNORECASE,
)

events: list[str] = []
modules: list[str] = []
calls: list[str] = []

_report_pipe = os.fdopen(int(sys.argv[2]) if len(sys.argv) > 2 else 3, "w", encoding="utf-8")
_real_open = open
_real_os_open = os.open
_real_env_get = os.environ.get


def flush_report(error: str | None) -> None:
    try:
        json.dump(
            {"modules": modules, "calls": calls, "events": events, "error": error},
            _report_pipe,
        )
        _report_pipe.write("\n")
    except Exception:  # noqa: BLE001 - 任何失败都不改写退出码语义
        pass
    finally:
        _report_pipe.close()


# ---- socket：全阻断（urllib/http 等高层库最终都落到 socket） ----
def _split_address(address: object) -> tuple[str, str]:
    try:
        if isinstance(address, tuple):
            host, port = str(address[0]), str(address[1])
        else:
            parts = str(address).split(":")
            host, port = parts[0], parts[-1]
    except Exception:  # noqa: BLE001
        return repr(address), "?"
    if not host or host.startswith("\\"):
        host = repr(address)  # AF_UNIX 路径等非常规形态
    return host, port


class _BlockedSocket(socket.socket):  # type: ignore[type-arg]
    def connect(self, address: object) -> None:
        host, port = _split_address(address)
        events.append(f"egress host={host} port={port}")
        raise OSError("sandbox: network blocked")

    def connect_ex(self, address: object) -> int:
        self.connect(address)
        return 111  # unreachable

socket.socket = _BlockedSocket  # type: ignore[misc]


def _blocked_create_connection(*args: object, **kwargs: object) -> object:
    events.append("egress host=create_connection port=?")
    raise OSError("sandbox: network blocked")

socket.create_connection = _blocked_create_connection  # type: ignore[assignment]


def _blocked_getaddrinfo(*args: object, **kwargs: object) -> object:
    events.append(f"egress host={args[0] if args else '?'} port=dns")
    raise OSError("sandbox: DNS blocked")

socket.getaddrinfo = _blocked_getaddrinfo  # type: ignore[assignment]


# ---- subprocess / 子进程派生：全阻断 ----
class _BlockedPopen:
    def __init__(self, *args: object, **kwargs: object) -> None:
        argv = args[0] if args else kwargs.get("args")
        events.append(f"spawn argv={argv!r}")
        raise OSError("sandbox: subprocesses blocked")

_subprocess.Popen = _BlockedPopen  # type: ignore[misc]


def _blocked_system(command: object) -> int:
    events.append(f"spawn argv={command!r}")
    raise OSError("sandbox: os.system blocked")

os.system = _blocked_system  # type: ignore[assignment]


def _blocked_spawn(*args: object, **kwargs: object) -> int:
    events.append("spawn argv=os.spawn*")
    raise OSError("sandbox: os.spawn blocked")

for _name in ("spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe"):
    if hasattr(os, _name):
        setattr(os, _name, _blocked_spawn)


# ---- 文件打开：记录 + 敏感路径阻断 ----
def _guarded_open(file: object, mode: str = "r", *args: object, **kwargs: object) -> object:
    text = str(file)
    events.append(f"open path={text} mode={mode or 'r'}")
    if SENSITIVE_OPEN.search(text):
        raise PermissionError(f"sandbox: sensitive path blocked: {text}")
    return _real_open(text, mode, *args, **kwargs)  # type: ignore[arg-type]

builtins.open = _guarded_open  # type: ignore[assignment]


def _guarded_os_open(path: object, *args: object, **kwargs: object) -> int:
    text = str(path)
    events.append(f"open path={text} mode=os")
    if SENSITIVE_OPEN.search(text):
        raise PermissionError(f"sandbox: sensitive path blocked: {text}")
    return _real_os_open(text, *args, **kwargs)  # type: ignore[arg-type]

os.open = _guarded_os_open  # type: ignore[assignment]


# ---- 环境变量：只记录键名，不记录值 ----
def _recording_env_get(key: object, default: object = None) -> object:
    events.append(f"env key={key}")
    return _real_env_get(key, default)  # type: ignore[arg-type]

os.environ.get = _recording_env_get  # type: ignore[method-assign]


# ---- 导入技能模块并调用 manifest 工具 ----
def load_module(path: str, rel: str) -> None:
    name = "skill_" + re.sub(r"\W", "_", rel)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        events.append(f"module {rel} unloadable")
        return
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)  # 技能顶层代码在此执行（已被插桩拦截）


def dummy_value(schema: dict) -> object:  # type: ignore[type-arg]
    """按 inputSchema 给单个工具参数一个最小演示值。"""
    if "default" in schema:
        return schema["default"]
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]
    kind = schema.get("type")
    if kind in ("integer", "number"):
        return schema.get("minimum", 1)
    if kind == "boolean":
        return False
    if kind == "array":
        return []
    if kind == "object":
        return {}
    return "demo-input"


def call_tools(manifest: dict) -> None:  # type: ignore[type-arg]
    loaded: list[tuple[str, object]] = []
    for module_name, module in list(sys.modules.items()):
        if module_name.startswith("skill_") and module is not None:
            for attr_name in dir(module):
                if not attr_name.startswith("_"):
                    loaded.append((attr_name, getattr(module, attr_name)))
    for tool in manifest.get("tools", []):
        name = tool.get("name", "")
        target = next((value for attr, value in loaded if attr == name), None)
        if not callable(target):
            events.append(f"tool {name} missing")
            continue
        schema = tool.get("inputSchema") or {}
        required = schema.get("required") or []
        kwargs = {p: dummy_value(s) for p, s in (schema.get("properties") or {}).items() if p in required}
        try:
            target(**kwargs) if kwargs else target()
            calls.append(name)
            events.append(f"tool {name}")
        except Exception as exc:  # noqa: BLE001 - 阻断类错误也会先记录事件
            events.append(f"tool {name} failed {type(exc).__name__}")


def main() -> None:
    skill_dir = sys.argv[1]
    try:
        with _real_open(os.path.join(skill_dir, "manifest.json"), encoding="utf-8") as handle:
            manifest = json.load(handle)
    except Exception as exc:  # noqa: BLE001
        flush_report(f"manifest {type(exc).__name__}")
        return

    error_kind: str | None = None
    try:
        code_files: list[str] = []
        for current, dirnames, filenames in os.walk(skill_dir):
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            for filename in sorted(filenames):
                if filename.endswith(".py") and not filename.startswith("."):
                    code_files.append(os.path.relpath(os.path.join(current, filename), skill_dir))
        for rel in sorted(code_files):
            try:
                load_module(os.path.join(skill_dir, rel), rel)
                modules.append(rel)
            except Exception as exc:  # noqa: BLE001 - 技能侧异常不算 harness 失败
                events.append(f"module {rel} error {type(exc).__name__}")
        call_tools(manifest)
    except Exception as exc:  # noqa: BLE001
        error_kind = type(exc).__name__

    flush_report(error_kind)


if __name__ == "__main__":
    main()
