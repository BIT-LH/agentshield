"""Markdown 报告器：适合贴进 issue / PR / 评审评论。"""

from __future__ import annotations

from typing import List

from ..models import ScanResult, Severity
from ..rules import CATEGORY_LABELS

_SEVERITY_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def render_markdown(result: ScanResult, title: str = None) -> str:
    """生成 Markdown 报告。"""
    counts = result.counts()
    lines: List[str] = []
    lines.append(f"# {title or 'AgentShield 安全扫描报告'}")
    lines.append("")
    lines.append(f"> 扫描目标：`{result.root}`  ")
    lines.append(
        f"> 扫描文件 {result.scanned_files} 个 · 规则 {result.rules_loaded} 条 · "
        f"耗时 {result.duration_ms} ms"
    )
    lines.append("")

    lines.append("## 风险汇总")
    lines.append("")
    lines.append("| 严重度 | 数量 |")
    lines.append("| --- | --- |")
    for severity in (
        Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
    ):
        lines.append(f"| {severity.label} | {counts[severity]} |")
    lines.append("")

    if not result.findings:
        lines.append("✅ 未发现安全问题。")
        return "\n".join(lines) + "\n"

    categories = result.by_category()
    if categories:
        lines.append("## 按类别分布")
        lines.append("")
        lines.append("| 类别 | 数量 |")
        lines.append("| --- | --- |")
        for cat, count in categories.items():
            lines.append(f"| {CATEGORY_LABELS.get(cat, cat)} | {count} |")
        lines.append("")

    lines.append("## 详细发现")
    lines.append("")
    for severity in (
        Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO
    ):
        items = [f for f in result.findings if f.severity is severity]
        if not items:
            continue
        lines.append(f"### {_SEVERITY_ICON[severity]} {severity.label}（{len(items)}）")
        lines.append("")
        for f in items:
            location = f"{f.file}:{f.line}" if f.line else f.file
            lines.append(f"#### `{f.rule_id}` {f.title}")
            lines.append("")
            lines.append(f"- **位置**：`{location}`")
            lines.append(f"- **类别**：{CATEGORY_LABELS.get(f.category, f.category)}")
            lines.append(f"- **置信度**：{f.confidence}")
            if f.cwe:
                lines.append(f"- **CWE**：{f.cwe}")
            lines.append(f"- **说明**：{f.message}")
            if f.snippet:
                snippet = f.snippet.replace("`", "'")
                lines.append("")
                lines.append("```text")
                lines.append(snippet)
                lines.append("```")
            if f.remediation:
                lines.append("")
                lines.append(f"**修复建议**：{f.remediation}")
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"
