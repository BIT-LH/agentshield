#!/usr/bin/env python
"""生成规则手册 docs/规则手册.md。

规则目录是唯一事实来源；本脚本从 `agentshield.rules` 渲染 Markdown，
避免文档与实现漂移。

用法::

    python scripts/gen_rule_docs.py
    python scripts/gen_rule_docs.py --output docs/规则手册.md
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agentshield import __version__  # noqa: E402
from agentshield.rules import CATEGORY_LABELS, get_rules  # noqa: E402

SEVERITY_LABEL = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "提示",
}

HEADER = """# AgentShield 规则手册

> 本文件由 `scripts/gen_rule_docs.py` 从代码中的规则目录自动生成，请勿手工编辑。
>
> 工具版本：AgentShield {version} · 规则总数：{count} 条

AgentShield 的检测由三类来源构成：

1. **正则规则**（`AS-*`）—— 对文件内容做模式匹配，带文件、行号、列号定位。
2. **结构化清单检查**（`AS-MANIFEST-*`）—— 解析 `package.json` / `.mcp.json` 等
   清单文件，检查安装期钩子、密钥硬编码与过宽权限。
3. **启发式检查**（`AS-HEU-*`）—— 不可见字符、熵值分析等正则难以表达的形态。

---

## 严重度定义

| 级别 | 含义 | 建议动作 |
| --- | --- | --- |
| 严重 | 可直接导致凭据泄露、任意代码执行或模型被完全控制 | 立即拒绝安装 |
| 高危 | 存在明确的高风险行为，需人工确认 | 安装前必须人工复核 |
| 中危 | 存在可疑设计或权限过宽 | 确认必要性，能收窄就收窄 |
| 低危 | 供应链卫生问题 | 建议整改 |
| 提示 | 仅供参考 | 可选整改 |

## 置信度定义

| 置信度 | 含义 |
| --- | --- |
| high | 模式特征明确，误报率低 |
| medium | 需要结合上下文判断，建议人工确认 |
| low | 启发式猜测，可能误报较多 |

---
"""

FOOTER = """
---

## 自定义规则

除内置规则外，可在 `.agentshield.json` 的 `custom_rules` 中定义组织专属规则：

```json
{
  "custom_rules": [
    {
      "id": "ORG-001",
      "title": "禁止调用内部财务接口",
      "severity": "high",
      "category": "exfiltration",
      "pattern": "https?://fin\\\\.internal\\\\.corp",
      "description": "技能不得直接访问财务系统。",
      "remediation": "改走已审计的服务网关。",
      "languages": ["any"],
      "tags": ["组织策略"]
    }
  ]
}
```

字段说明：

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `id` | 是 | 规则唯一标识，建议用组织前缀（如 `ORG-`） |
| `title` | 是 | 规则名称 |
| `severity` | 是 | `critical` / `high` / `medium` / `low` / `info` |
| `pattern` | 是 | Python 正则表达式（默认不区分大小写） |
| `category` | 否 | 分类标签，默认 `custom` |
| `description` | 否 | 规则说明 |
| `remediation` | 否 | 修复建议 |
| `languages` | 否 | 生效语言，默认 `["any"]` |
| `tags` | 否 | 标签列表 |
| `confidence` | 否 | `high` / `medium` / `low`，默认 `medium` |
| `case_sensitive` | 否 | 是否区分大小写，默认 `false` |
"""


def build_markdown() -> str:
    rules = get_rules()
    lines = [HEADER.format(version=__version__, count=len(rules))]

    by_category = {}
    for rule in rules:
        by_category.setdefault(rule.category, []).append(rule)

    order = [
        "prompt_injection",
        "credential_access",
        "exfiltration",
        "remote_execution",
        "persistence",
        "privilege",
        "obfuscation",
        "supply_chain",
        "destructive",
        "manifest",
        "custom",
    ]

    for category in order:
        items = by_category.get(category)
        if not items:
            continue
        lines.append("")
        lines.append("## %s（`%s`）" % (CATEGORY_LABELS[category], category))
        lines.append("")
        lines.append("| 规则 ID | 严重度 | 名称 | 说明 | CWE |")
        lines.append("| --- | --- | --- | --- | --- |")
        for rule in items:
            description = rule.description.replace("|", "\\|")
            title = rule.title.replace("|", "\\|")
            lines.append(
                "| `%s` | %s | %s | %s | %s |"
                % (rule.id, SEVERITY_LABEL[rule.severity.value], title, description, rule.cwe or "-")
            )
        lines.append("")
        for rule in items:
            lines.append("### `%s` %s" % (rule.id, rule.title))
            lines.append("")
            lines.append("- **类别**：%s" % CATEGORY_LABELS.get(rule.category, rule.category))
            lines.append("- **严重度**：%s" % SEVERITY_LABEL[rule.severity.value])
            lines.append("- **置信度**：%s" % rule.confidence)
            lines.append("- **生效语言**：%s" % ", ".join(rule.languages))
            if rule.tags:
                lines.append("- **标签**：%s" % ", ".join(rule.tags))
            if rule.cwe:
                lines.append("- **CWE**：%s" % rule.cwe)
            lines.append("")
            lines.append("**说明**：%s" % rule.description)
            lines.append("")
            lines.append("**修复建议**：%s" % rule.remediation)
            lines.append("")
            lines.append("**匹配模式**：`%s`" % rule.pattern)
            lines.append("")

    lines.append(FOOTER)
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="生成 AgentShield 规则手册")
    default_out = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "规则手册.md"
    )
    parser.add_argument("-o", "--output", default=default_out, help="输出文件路径")
    args = parser.parse_args()

    content = build_markdown()
    os.makedirs(os.path.dirname(os.path.abspath(args.output)) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(content)
    print("✓ 规则手册已生成：%s" % os.path.abspath(args.output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
