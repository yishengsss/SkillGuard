"""技能目录的安全遍历与读取约定。

扫描**只读取文本，不执行技能代码**。为满足 SPEC/CLAUDE 的安全要求，遍历时：

- 不跟随任何符号链接（文件或目录），因此技能目录之外的内容不会被读入或哈希；
- 跳过 `.git/`、`.cache/`、`__pycache__/` 等目录；
- 跳过 `.env` 及以 `.env.` 开头的文件（如 `.env.local`）；
- 只处理常规文件（FIFO / 设备文件等不会阻塞读取）；
- 排除 `manifest.json`（其内容由 metadata 阶段单独读取原字节）。

返回结果按**相对 POSIX 路径排序**，保证确定性。

`manifest.json` 由 `safe_read_bytes()` / `safe_read_text()` 单独读取：二者共用
`_require_regular_file()`，**拒绝符号链接与非常规文件（FIFO/设备等）且不读取目标**，
因此指向目录外文件的 manifest 软链接不会被跟随。哈希函数也复用这些 helper。
"""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from pathlib import Path

SENSITIVE_DIRS = frozenset({".git", ".cache", "__pycache__"})
SENSITIVE_PREFIXES = (".env",)
MANIFEST_NAME = "manifest.json"


class SkillDirError(RuntimeError):
    """技能目录不合法（不存在、不是目录、manifest 缺失/畸形/软链接、JSON 损坏等）。"""


def _is_skipped_file(name: str) -> bool:
    return name.startswith(SENSITIVE_PREFIXES)


def _require_regular_file(path: Path) -> None:
    """确认 `path` 是非软链接的常规文件；否则抛 `SkillDirError`。

    只做 `lstat`/`stat`，**不打开、不读取**目标，因此 FIFO 不会阻塞、软链接不会被跟随。
    """
    if path.is_symlink():
        raise SkillDirError(f"拒绝符号链接: {path.name}")
    try:
        mode = path.stat().st_mode
    except FileNotFoundError as exc:
        raise SkillDirError(f"找不到文件: {path.name}") from exc
    if not stat.S_ISREG(mode):
        raise SkillDirError(f"拒绝非常规文件（FIFO/设备等）: {path.name}")


def safe_read_bytes(path: Path) -> bytes:
    """安全读取常规文件的原始字节；拒绝软链接与非常规文件。"""
    _require_regular_file(path)
    return path.read_bytes()


def safe_read_text(path: Path, *, errors: str = "replace") -> str:
    """安全读取常规文件的文本；拒绝软链接与非常规文件。"""
    _require_regular_file(path)
    return path.read_text(encoding="utf-8", errors=errors)


def iter_skill_files(skill_dir: Path, *, include_manifest: bool) -> Iterator[tuple[str, Path]]:
    """按相对 POSIX 路径排序产出 `(rel, full)`。

    `include_manifest=True` 时包含 manifest.json，否则排除。
    """
    root = Path(skill_dir)
    if not root.is_dir():
        raise SkillDirError(f"技能目录不存在或不是目录: {skill_dir}")

    found: dict[str, Path] = {}
    # followlinks=False + 显式裁剪 dirnames：符号链接目录一律不进入。
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        kept: list[str] = []
        for name in dirnames:
            candidate = current / name
            if name in SENSITIVE_DIRS or candidate.is_symlink():
                continue
            kept.append(name)
        dirnames[:] = kept  # 就地裁剪，阻止 os.walk 继续下探

        for name in filenames:
            full = current / name
            # 符号链接与非常规文件（FIFO、设备等）不读、不哈希。
            if full.is_symlink() or not full.is_file():
                continue
            if _is_skipped_file(name):
                continue
            if not include_manifest and name == MANIFEST_NAME:
                continue
            found[full.relative_to(root).as_posix()] = full

    for rel in sorted(found):
        yield rel, found[rel]


def read_text(path: Path) -> str:
    """读取文本；无法按 UTF-8 解码时用替换字符，保证扫描不因二进制失败。

    注意：本函数只用于已经过遍历筛选（非常规文件已在 `iter_skill_files` 排除）的
    源码文件，不做软链接/常规文件校验；manifest 请用 `safe_read_bytes()`。
    """
    return path.read_text(encoding="utf-8", errors="replace")


__all__ = [
    "MANIFEST_NAME",
    "SENSITIVE_DIRS",
    "SENSITIVE_PREFIXES",
    "SkillDirError",
    "iter_skill_files",
    "read_text",
    "safe_read_bytes",
    "safe_read_text",
]
