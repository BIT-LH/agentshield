"""终端报告器：带 ANSI 颜色的分组输出。"""

from __future__ import annotations

import os
import sys
from typing import Dict, List, Optional

from ..models import ScanResult, Severity

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[1;92m"

SEVERITY_STYLE = {
    Severity.CRITICAL: ("\033[1;97;41m", "严重"),
    Severity.HIGH: ("\033[1;91m", "高危"),
    Severity.MEDIUM: ("\033[1;93m", "中危"),
    Severity.LOW: ("\033[1;96m", "低危"),
    Severity.INFO: ("\033[1;94m", "提示"),
}


def supports_color(stream=None) -> bool:
    """判断当前终端是否支持 ANSI 颜色。"""
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("AGENTSHIELD_FORCE_COLOR"):
        return True
    if not hasattr(stream, "isatty"):
        return False
    try:
        return bool(stream.isatty())
    except Exception:
        return False


class _Style:
    """按需应用颜色。"""

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        if not self.enabled:
            return text
        return code + text + RESET


def render_console(
    result: ScanResult,
    color: Optional[bool] = None,
    show_remediation: bool = True,
    summary_only: bool = False,
) -> str:
    """生成终端报告文本。

    Args:
        result: 扫描结果。
        color: 是否使用 ANSI 颜色；None 表示自动判断。
        show_remediation: 是否展示每条命中的修复建议。
        summary_only: 只输出汇总，不展开逐条明细。
    """
    if color is None:
        color = supports_color()
    st = _Style(color)
    lines: List[str] = []

    title = "AgentShield 扫描报告 · " + result.root
    lines.append(st(title, BOLD))
    meta = (
        "扫描 %d 个文件 · 规则 %d 条 · 耗时 %d ms"
        % (result.scanned_files, result.rules_loaded, result.duration_ms)
    )
    lines.append(st(meta, DIM))
    lines.append("")

    if not result.findings:
        lines.append(st("✓ 未发现安全问题。", GREEN))
        return "\n".join(lines)

    counts = result.counts()
    parts = []
    for severity in (
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ):
        if counts[severity]:
            parts.append("%s %d" % (severity.label, counts[severity]))
    lines.append(st("风险汇总：", BOLD) + " " + " · ".join(parts))
    lines.append("")

    if summary_only:
        return "\n".join(lines).rstrip() + "\n"

    by_severity: Dict[Severity, List] = {}
    for f in result.findings:
        by_severity.setdefault(f.severity, []).append(f)

    for severity in (
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ):
        items = by_severity.get(severity)
        if not items:
            continue
        color_code, label = SEVERITY_STYLE[severity]
        lines.append(st("── %s (%d) ──" % (label, len(items)), color_code))
        for f in items:
            location = "%s:%d" % (f.file, f.line) if f.line else f.file
            lines.append(
                "  %s  %s  %s"
                % (st(f.severity.value.upper(), color_code), st(f.rule_id, BOLD), location)
            )
            lines.append("      " + f.title)
            lines.append("      " + st(f.message, DIM))
            if f.snippet:
                lines.append("      " + st("│ " + f.snippet, DIM))
            if show_remediation and f.remediation:
                lines.append("      " + st("修复建议: " + f.remediation, GREEN))
            lines.append("")

    if result.errors:
        lines.append(st("扫描过程中出现 %d 个错误：" % len(result.errors), BOLD))
        for err in result.errors[:10]:
            lines.append(st("  - " + err, DIM))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"
