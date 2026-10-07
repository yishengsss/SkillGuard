"""pytest 配置：把仓库根目录加入 sys.path，使 `auditor` 包可被导入。"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
