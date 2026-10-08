"""哈希与代码包 enumerate 约定。

哈希一律使用 web3 的 keccak256。

**codeHash 约定（后续注册必须复用同一函数）**

codeHash 是「技能代码包」的无歧义确定性编码的 keccak256。编码规则：

1. 遍历技能目录内的文件，**排序后的相对 POSIX 路径**（`sorted()`，Python 默认
   Unicode 码点序）作为顺序，与文件系统遍历顺序无关。
2. 对每个文件，取「相对路径 UTF-8 字节」与「文件内容原始字节」，按
   `len(path_bytes).to_bytes(8, "big") + path_bytes + len(content).to_bytes(8, "big") + content`
   拼接后依次喂给 keccak。
3. 排除项（不参与哈希，也不参与扫描）：
   - `manifest.json`（其原字节哈希单独作为 metadataHash）
   - `.git/`、`.cache/`、`__pycache__/` 等目录
   - 以 `.env` 开头的文件
   - 符号链接：一律不跟随
4. 路径长度与内容长度都用 8 字节大端前缀，因此不同「路径/内容切分」不会产生
   相同编码，编码无歧义。

**metadataHash 约定**

metadataHash = keccak256(manifest.json 的**原始文件字节**)，不做 JSON 规范化，
即对文件内容逐字节哈希。

注册/提交上链时应复用 `code_hash()` 与 `metadata_hash()`，避免两处实现漂移。
"""

from __future__ import annotations

from pathlib import Path

from web3 import Web3

from .skill_dir import SkillSnapshot, iter_skill_files, safe_read_bytes

MANIFEST_NAME = "manifest.json"


def keccak_bytes(data: bytes) -> bytes:
    """keccak256，返回 32 字节摘要。"""
    return Web3.keccak(data)


def metadata_hash(skill_dir: Path | SkillSnapshot) -> bytes:
    """manifest.json 原始文件字节的 keccak256。

    通过 `safe_read_bytes()` 读取：拒绝符号链接与 FIFO/设备等非常规文件，
    不跟随软链接去读取目录外目标。
    """
    raw = skill_dir.manifest_bytes if isinstance(skill_dir, SkillSnapshot) else safe_read_bytes(Path(skill_dir) / MANIFEST_NAME)
    return keccak_bytes(raw)


def code_hash(skill_dir: Path | SkillSnapshot) -> bytes:
    """技能代码包的无歧义确定性编码的 keccak256。

    编码约定见模块文档。文件清单来自 `iter_skill_files`（已排除软链接、非常规文件
    与敏感路径）；内容再经 `safe_read_bytes()` 读取，作为纵深防御，即便清单来源
    变化也不会跟随软链接或读入 FIFO。
    """
    parts: list[bytes] = []
    files = skill_dir.files if isinstance(skill_dir, SkillSnapshot) else (
        (rel, safe_read_bytes(full)) for rel, full in iter_skill_files(skill_dir, include_manifest=False)
    )
    for rel, content in files:
        path_bytes = rel.encode("utf-8")
        parts.append(len(path_bytes).to_bytes(8, "big"))
        parts.append(path_bytes)
        parts.append(len(content).to_bytes(8, "big"))
        parts.append(content)
    return keccak_bytes(b"".join(parts))


__all__ = [
    "MANIFEST_NAME",
    "code_hash",
    "keccak_bytes",
    "metadata_hash",
]
