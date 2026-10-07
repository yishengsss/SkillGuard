"""pytest 配置。

1. 把仓库根目录加入 sys.path，使 `auditor` 包可被导入。
2. 为 **子进程 CLI 测试** 提供隔离的项目副本（`SKILLGUARD_TEST_PROJECT`）。

为什么需要副本：`auditor.cli` 默认把报告写到「项目根目录」的 `reports/`，并只在
`--submit` 时读根目录 `.env` / `deployments.json`。若子进程直接在仓库根目录运行，
测试就会（a）往仓库里写报告、（b）可能读到真实 `.env` 甚至尝试真实 RPC。

因此这里把 `auditor/` `rules/` `samples/` 复制到临时目录，作为子进程的 cwd：
- `python -m auditor.cli samples/weather` 仍在副本内正常工作；
- 报告落在 `<临时目录>/reports/`，仓库保持干净；
- 副本内**没有** `.env` / `deployments.json`，`--submit` 只会因缺配置失败，
  绝不会读取项目真实 `.env`、更不会外连。
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CLI_PROJECT_ENV = "SKILLGUARD_TEST_PROJECT"
_CONFIG_ENV_VARS = ("RPC_URL", "AUDITOR_PRIVATE_KEY")
_COPIED = ("auditor", "rules", "samples")


def cli_project_root() -> Path:
    """子进程 CLI 测试应使用的项目根目录（由下面的 fixture 注入）。"""
    return Path(os.environ.get(CLI_PROJECT_ENV, str(ROOT)))


@pytest.fixture(scope="session", autouse=True)
def isolated_cli_project(tmp_path_factory) -> Path:
    """把项目相关目录复制到临时目录，作为子进程 CLI 的隔离项目根。"""
    project = tmp_path_factory.mktemp("cli-project")
    for name in _COPIED:
        source = ROOT / name
        if source.is_dir():
            shutil.copytree(
                source,
                project / name,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
    previous = os.environ.get(CLI_PROJECT_ENV)
    os.environ[CLI_PROJECT_ENV] = str(project)
    # 开发机上可能导出了 RPC_URL / AUDITOR_PRIVATE_KEY；`load_config` 会合并
    # os.environ，子进程里必须清掉，否则 --submit 测试可能真的去连链。
    saved_values = {name: os.environ.pop(name) for name in _CONFIG_ENV_VARS if name in os.environ}
    yield project
    os.environ.update(saved_values)
    if previous is None:
        os.environ.pop(CLI_PROJECT_ENV, None)
    else:
        os.environ[CLI_PROJECT_ENV] = previous
