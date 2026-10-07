"""requests-mcpp —— SkillGuard 演示技能（仿冒包名 + 敏感路径样本，仅用于静态扫描演示）。

固定夹具说明：
- 包名 requestss 是对已知包 requests 的仿冒（编辑距离 1），用于演示 SPEC 第 4 节
  的「仿冒包名」检测。
- 本文件中的敏感路径只以「惰性字符串常量 / 注释」形式出现，用于让 rules/static.yaml
  的 STAT-001 命中，便于演示审计引擎。
- 运行本文件不会读取 ~/.aws/credentials 或任何文件系统内容，不会发起网络请求，
  不会启动子进程，也不会执行 eval / 动态代码。
- main() 只打印固定信息。

注意：请勿把本文件改写为可执行的真实攻击载荷。
"""

from __future__ import annotations

# 示例敏感路径：只用于命中 STAT-001（读取敏感路径）。
# 这是纯字符串常量，本演示不会用它去打开或读取任何文件。
SENSITIVE_PATHS: tuple[str, ...] = (
    "~/.aws/credentials",
    "~/.aws/config",
)

# 固定演示响应：纯内存字符串，不来自网络。
DEMO_RESPONSE: dict[str, object] = {
    "url": "https://httpbin.example.com/get",
    "status": 200,
    "body": "演示响应正文（固定内容，未发起真实请求）",
}


def http_get(url: str, timeout: float = 10) -> dict[str, object]:
    """返回固定演示响应，不发起真实请求。"""
    return {"url": url, "timeout": timeout, **DEMO_RESPONSE}


def http_post(url: str, payload: dict | None = None) -> dict[str, object]:
    """返回固定演示状态码，不发起真实请求。"""
    return {"url": url, "payload": payload or {}, "status": 200}


def describe_exfiltration_intent() -> str:
    """说明该样本的敏感意图（只做说明，不执行任何读取）。"""
    targets = ", ".join(SENSITIVE_PATHS)
    return f"示例敏感路径常量：{targets}（仅为字符串，不读取任何文件）"


def main() -> None:
    print("requests-mcpp 演示技能（仿冒包名样本，仅供静态扫描）")
    print(f"仿冒包名：requestss（与已知包 requests 编辑距离 1）")
    print(describe_exfiltration_intent())
    print("本脚本不读取文件系统、不访问网络、不启动子进程。")


if __name__ == "__main__":
    main()
