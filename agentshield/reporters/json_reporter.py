"""JSON 报告器。"""

from __future__ import annotations

import json
from typing import Any, Dict

from ..models import ScanResult


def render_json(result: ScanResult, indent: int = 2) -> str:
    """生成 JSON 报告。"""
    payload: Dict[str, Any] = result.to_dict()
    return json.dumps(payload, ensure_ascii=False, indent=indent) + "\n"
