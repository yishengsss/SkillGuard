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
from dataclasses import dataclass
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
    return _read_regular(path)


def safe_read_text(path: Path, *, errors: str = "replace") -> str:
    """安全读取常规文件的文本；拒绝软链接与非常规文件。"""
    return safe_read_bytes(path).decode("utf-8", errors=errors)


def _read_regular(path: str | Path, *, dir_fd: int | None = None) -> bytes:
    return _read_file(path, dir_fd=dir_fd)[0]


def _read_file(path: str | Path, *, dir_fd: int | None = None) -> tuple[bytes, int]:
    """打开时拒绝链接；用已打开的描述符确认类型，避免检查后换成 FIFO/链接。"""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        if not stat.S_ISREG(os.stat(path, dir_fd=dir_fd, follow_symlinks=False).st_mode):
            raise SkillDirError(f"拒绝符号链接或非常规文件: {Path(path).name}")
        fd = os.open(path, flags, dir_fd=dir_fd)
    except PermissionError:
        raise
    except OSError as exc:
        raise SkillDirError(f"无法安全读取常规文件: {Path(path).name}（{type(exc).__name__}）") from None
    with os.fdopen(fd, "rb") as handle:
        mode = os.fstat(handle.fileno()).st_mode
        if not stat.S_ISREG(mode):
            raise SkillDirError(f"拒绝非常规文件: {Path(path).name}")
        return handle.read(), stat.S_IMODE(mode) & 0o777


@dataclass(frozen=True)
class SkillSnapshot:
    """审计与安装共同使用的不可变字节；只包含顶层清单和参与 codeHash 的文件。"""

    manifest_bytes: bytes
    files: tuple[tuple[str, bytes], ...]
    file_modes: tuple[tuple[str, int], ...] = ()
    manifest_mode: int = 0o644


def _open_skill_root(root: Path, source_root: Path | None) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if source_root is None:
        return os.open(root, flags)

    # 仅解析可信根；源路径各分段必须相对根逐一打开，不能重新 resolve 后跟随新链接。
    anchor = source_root.resolve(strict=True)
    try:
        relative = root.relative_to(anchor)
    except ValueError:
        raise SkillDirError("技能来源越出可信根目录") from None
    if not relative.parts or ".." in relative.parts:
        raise SkillDirError("技能来源必须位于可信根目录内")
    fd = os.open(anchor, flags)
    try:
        for component in relative.parts:
            child_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def capture_skill(skill_dir: str | Path, *, source_root: Path | None = None) -> SkillSnapshot:
    """只读取一次包内字节；可从可信根逐段定位，拒绝来源祖先与包内链接。"""
    try:
        root_fd = _open_skill_root(Path(skill_dir), source_root)
    except PermissionError:
        raise
    except OSError as exc:
        raise SkillDirError(f"无法安全打开技能目录（{type(exc).__name__}）") from None
    try:
        manifest_bytes, manifest_mode = _read_file(MANIFEST_NAME, dir_fd=root_fd)
        files: list[tuple[str, bytes]] = []
        modes: list[tuple[str, int]] = []

        def fail_walk(exc: OSError) -> None:
            raise exc

        for current, dirnames, filenames, directory_fd in os.fwalk(
            ".", topdown=True, follow_symlinks=False, dir_fd=root_fd, onerror=fail_walk
        ):
            dirnames[:] = [
                name for name in dirnames if name not in SENSITIVE_DIRS
                and stat.S_ISDIR(os.stat(name, dir_fd=directory_fd, follow_symlinks=False).st_mode)
            ]
            for name in filenames:
                if _is_skipped_file(name) or name == MANIFEST_NAME:
                    continue
                if not stat.S_ISREG(os.stat(name, dir_fd=directory_fd, follow_symlinks=False).st_mode):
                    continue
                relative = (Path(current) / name).as_posix()
                content, mode = _read_file(name, dir_fd=directory_fd)
                files.append((relative, content))
                modes.append((relative, mode))
        return SkillSnapshot(manifest_bytes, tuple(sorted(files)), tuple(sorted(modes)), manifest_mode)
    finally:
        os.close(root_fd)


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
    "SkillSnapshot",
    "capture_skill",
    "iter_skill_files",
    "read_text",
    "safe_read_bytes",
    "safe_read_text",
]
