"""审计报告结构、等级判定、规范化 JSON 与 reportHash（SPEC 第 4 节）。

报告 JSON 字段（顺序即 SPEC 示例顺序）：
`skill / version / codeHash / metadataHash / level / findings / auditor / timestamp / engineVersion`

等级判定：命中任一 critical → MALICIOUS；仅 high/medium → SUSPICIOUS；无 → SAFE。
链上 `isMalicious = (level == MALICIOUS)`。

reportHash = keccak256(规范化 JSON：`sort_keys=True, separators=(",", ":")`，UTF-8)。
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any

from . import ENGINE_VERSION
from .hashing import keccak_bytes

ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"

MALICIOUS = "MALICIOUS"
SUSPICIOUS = "SUSPICIOUS"
SAFE = "SAFE"

_CRITICAL = "critical"


@dataclass(frozen=True)
class Finding:
    """单条命中：rule / stage / severity / file / evidence。"""

    rule: str
    stage: str
    severity: str
    file: str
    evidence: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class Report:
    """SPEC 结构的审计报告。"""

    skill: str
    version: str
    codeHash: str
    metadataHash: str
    level: str
    findings: list[Finding]
    auditor: str
    timestamp: int
    engineVersion: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "skill": self.skill,
            "version": self.version,
            "codeHash": self.codeHash,
            "metadataHash": self.metadataHash,
            "level": self.level,
            "findings": [f.to_dict() for f in self.findings],
            "auditor": self.auditor,
            "timestamp": self.timestamp,
            "engineVersion": self.engineVersion,
        }


def build_finding(rule: str, stage: str, severity: str, file: str, evidence: str) -> Finding:
    return Finding(rule=rule, stage=stage, severity=severity, file=file, evidence=evidence)


def derive_level(findings: list[Finding]) -> str:
    """critical → MALICIOUS；仅 high/medium → SUSPICIOUS；无 → SAFE。"""
    severities = {f.severity for f in findings}
    if _CRITICAL in severities:
        return MALICIOUS
    if severities:
        return SUSPICIOUS
    return SAFE


def build_report(
    *,
    skill: str,
    version: str,
    code_hash: bytes,
    metadata_hash: bytes,
    findings: list[Finding],
    timestamp: int,
    auditor: str = ZERO_ADDRESS,
    engine_version: str = ENGINE_VERSION,
) -> Report:
    """组装报告；离线审计用零地址表示未提交（详见 cli 的说明）。"""
    return Report(
        skill=skill,
        version=version,
        codeHash="0x" + code_hash.hex(),
        metadataHash="0x" + metadata_hash.hex(),
        level=derive_level(findings),
        findings=list(findings),
        auditor=auditor,
        timestamp=timestamp,
        engineVersion=engine_version,
    )


def canonical_json(report: Report | dict[str, Any]) -> bytes:
    """SPEC 规范化 JSON：sort_keys=True, separators=(",", ":")，UTF-8 字节。"""
    payload = report.to_dict() if isinstance(report, Report) else report
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def report_hash(report: Report | dict[str, Any]) -> bytes:
    """reportHash = keccak256(规范化 JSON)。"""
    return keccak_bytes(canonical_json(report))


def report_hash_hex(report: Report | dict[str, Any]) -> str:
    return "0x" + report_hash(report).hex()


__all__ = [
    "MALICIOUS",
    "SAFE",
    "SUSPICIOUS",
    "ZERO_ADDRESS",
    "Finding",
    "Report",
    "build_finding",
    "build_report",
    "canonical_json",
    "derive_level",
    "report_hash",
    "report_hash_hex",
]
