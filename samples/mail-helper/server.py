"""mail-helper —— SkillGuard 演示技能（恶意样本，仅用于静态扫描演示）。

固定夹具说明：
- 本文件中的敏感行为只以「惰性字符串 / 注释」形式出现，用于让 rules/ 下的
  静态规则命中，便于演示审计引擎。
- 运行本文件不会读取任何真实邮件、不会读取本地文件、不会发起网络请求、
  不会启动子进程，也不会执行 eval / 动态代码。
- main() 只打印固定信息。

注意：请勿把本文件改写为可执行的真实攻击载荷。
"""

from __future__ import annotations

# 示例外连地址：只用于命中 STAT-002（硬编码外连域名）。
# 使用保留域名 example.com，本演示不会向该地址发送任何数据。
FORWARD_ENDPOINT = "https://mail-sync.example.com/collect"

# 固定演示收件箱：纯内存数据，不来自真实邮箱或文件系统。
DEMO_INBOX: tuple[dict[str, str], ...] = (
    {"subject": "演示邮件 A", "sender": "alice@example.com"},
    {"subject": "演示邮件 B", "sender": "bob@example.org"},
    {"subject": "演示邮件 C", "sender": "carol@example.com"},
)


def list_recent_mails(limit: int = 10) -> list[dict[str, str]]:
    """返回固定演示邮件，不接触真实邮箱。"""
    return [dict(item) for item in DEMO_INBOX[:limit]]


def summarize_thread(thread_id: str, language: str = "zh") -> str:
    """返回固定摘要文本，不读取真实邮件内容。"""
    return f"会话 {thread_id} 的演示摘要（语言：{language}）"


def describe_poisoning() -> str:
    """说明该样本被规则命中的投毒意图（只做说明，不执行转发）。"""
    return f"示例投毒目标：{FORWARD_ENDPOINT}（仅为字符串常量，不发送任何数据）"


def main() -> None:
    print("mail-helper 演示技能（恶意样本，仅供静态扫描）")
    mails = list_recent_mails()
    print(f"固定演示邮件数量：{len(mails)}")
    for item in mails:
        print(f"  - {item['subject']} <- {item['sender']}")
    print(describe_poisoning())
    print("本脚本不读取真实邮件、不访问网络、不执行任何转发。")


if __name__ == "__main__":
    main()
