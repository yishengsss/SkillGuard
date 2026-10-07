"""weather —— SkillGuard 演示技能（干净样本，仅用于静态扫描演示）。

固定夹具说明：
- 本文件只操作固定内存字符串，不读取文件系统、不启动子进程、
  不执行 eval / 动态代码、不发送任何网络请求。
- 示例接口使用保留域名 example.com，且不会真正访问。
- main() 只打印固定演示数据。
"""

from __future__ import annotations

# 示例接口主机名：保留域名，演示中不会被访问。
DEMO_API_HOST = "weather.example.com"
DEMO_API_PATH = "/v1/current"

# 固定演示天气数据：纯内存常量，不来自任何真实接口。
DEMO_CURRENT: dict[str, object] = {
    "city": "demo-city",
    "temperature_c": 21.5,
    "condition": "sunny",
    "humidity": 48,
}

DEMO_FORECAST: tuple[dict[str, object], ...] = (
    {"day": "day-1", "high_c": 23.0, "low_c": 15.0, "condition": "sunny"},
    {"day": "day-2", "high_c": 21.0, "low_c": 14.0, "condition": "cloudy"},
    {"day": "day-3", "high_c": 19.0, "low_c": 13.0, "condition": "rain"},
)


def demo_endpoint() -> str:
    """返回示例接口地址字符串（仅用于展示，不发起请求）。"""
    return f"{DEMO_API_HOST}{DEMO_API_PATH}"


def get_current_weather(city: str, unit: str = "celsius") -> dict[str, object]:
    """返回固定演示天气数据，不访问真实接口。"""
    data = dict(DEMO_CURRENT)
    data["city"] = city
    data["unit"] = unit
    return data


def get_forecast(city: str, days: int = 3) -> list[dict[str, object]]:
    """返回固定演示预报数据，不访问真实接口。"""
    items = [dict(item) for item in DEMO_FORECAST[:days]]
    for item in items:
        item["city"] = city
    return items


def main() -> None:
    print("weather 演示技能（干净样本，仅供静态扫描）")
    print(f"示例接口（不会被访问）：{demo_endpoint()}")
    print(f"固定演示实况：{get_current_weather('demo-city')}")
    for item in get_forecast("demo-city"):
        print(f"固定演示预报：{item}")
    print("本脚本不读取文件、不访问网络、不启动子进程。")


if __name__ == "__main__":
    main()
