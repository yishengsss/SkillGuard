"""描述投毒检测（rules/metadata.yaml）。

作用对象是 manifest.json 中工具的 description 与 inputSchema：
- 把整个 inputSchema（含属性名、description、enum、default 等字符串）序列化为
  文本一并扫描，避免把指令藏在 schema 深处而漏检；
- 用 META-00x 的 patterns 做正则匹配（忽略大小写）；
- META-005 用 max_length 判断 description 是否异常过长。
"""

from __future__ import annotations

import json
from typing import Any

from .report import Finding
from .rules import Rule


def _flatten(value: Any) -> str:
    """把任意 JSON 值转成待扫描文本（键名与字符串值都保留）。"""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return "\n".join(f"{k}\n{_flatten(v)}" for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return "\n".join(_flatten(item) for item in value)
    return json.dumps(value, ensure_ascii=False)


def _tools(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    tools = manifest.get("tools")
    if not isinstance(tools, list):
        return []
    return [t for t in tools if isinstance(t, dict)]


def scan_metadata(manifest: dict[str, Any], rules: list[Rule]) -> list[Finding]:
    """对 manifest 的 description / inputSchema 应用 metadata 规则。"""
    findings: list[Finding] = []

    for tool in _tools(manifest):
        description = tool.get("description")
        if description is not None and not isinstance(description, str):
            description = _flatten(description)
        if description is None:
            description = ""

        for rule in rules:
            if rule.max_length is not None and len(description) > rule.max_length:
                findings.append(
                    Finding(
                        rule=rule.id,
                        stage="metadata",
                        severity=rule.severity,
                        file="manifest.json",
                        evidence=_clip(f"{len(description)} 字符 > {rule.max_length}"),
                    )
                )
                continue
            for pattern in rule.patterns:
                match = pattern.search(description)
                if match:
                    findings.append(
                        Finding(
                            rule=rule.id,
                            stage="metadata",
                            severity=rule.severity,
                            file="manifest.json",
                            evidence=_clip(description),
                        )
                    )
                    break  # 每个规则每个工具只报一次

        schema = tool.get("inputSchema")
        if schema is None:
            continue
        schema_text = _flatten(schema)
        for rule in rules:
            if rule.max_length is not None:
                continue  # 长度规则只作用于 description
            if any(p.search(schema_text) for p in rule.patterns):
                findings.append(
                    Finding(
                        rule=rule.id,
                        stage="metadata",
                        severity=rule.severity,
                        file="manifest.json",
                        evidence=_clip(schema_text),
                    )
                )

    return findings


def _clip(text: str, limit: int = 120) -> str:
    """证据做长度裁剪，保留首尾；单行化便于阅读。"""
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


__all__ = ["scan_metadata"]
