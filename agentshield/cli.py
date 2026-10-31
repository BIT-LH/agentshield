"""AgentShield 命令行入口。

子命令：

- ``scan``   扫描目标路径
- ``rules``  查看内置规则
- ``init``   生成配置文件
- ``version``显示版本
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import __version__
from .config import CONFIG_FILENAME, Config, ConfigError, DEFAULT_CONFIG_TEMPLATE
from .models import ScanResult, Severity
from .reporters import render_console, render_json, render_markdown, render_sarif
from .rules import CATEGORY_LABELS, get_rules
from .scanner import classify_target, scan_path

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_ERROR = 3

FORMATS = ("console", "json", "markdown", "sarif")


def _enable_utf8() -> None:
    """Windows 终端默认可能是 GBK，这里强制切到 UTF-8 以免输出中文报错。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentshield",
        description=(
            "AgentShield —— AI Agent 扩展 / 技能 / MCP Server 的供应链安全审计器。"
        ),
        epilog=(
            "示例：\n"
            "  agentshield scan ./my-skill\n"
            "  agentshield scan . --format json --output report.json\n"
            "  agentshield scan . --format sarif --output results.sarif --fail-on high\n"
            "  agentshield rules --category exfiltration\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version=f"AgentShield {__version__}"
    )
    sub = parser.add_subparsers(dest="command")

    # ---------------- scan ----------------
    scan = sub.add_parser(
        "scan",
        help="扫描目标路径中的 AI 扩展 / 技能 / MCP Server",
        description="扫描目标路径并输出安全风险报告。",
    )
    scan.add_argument("target", help="要扫描的文件或目录")
    scan.add_argument(
        "-f", "--format",
        choices=FORMATS,
        default="console",
        help="输出格式（默认 console）",
    )
    scan.add_argument("-o", "--output", help="报告输出文件；缺省写到标准输出")
    scan.add_argument(
        "-c", "--config", help=f"配置文件路径（默认向上查找 {CONFIG_FILENAME}）"
    )
    scan.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        help="当存在该严重度及以上的命中时以退出码 1 结束（用于 CI）",
    )
    scan.add_argument(
        "--severity",
        choices=[s.value for s in Severity],
        default="info",
        help="只输出不低于该严重度的命中（默认 info，输出全部）",
    )
    scan.add_argument(
        "--no-config", action="store_true", help="忽略配置文件，使用默认设置"
    )
    scan.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="额外排除的路径 glob，可重复指定",
    )
    scan.add_argument(
        "--no-color", action="store_true", help="关闭彩色输出"
    )
    scan.add_argument(
        "--quiet", action="store_true", help="只输出摘要，不打印逐条明细"
    )
    scan.add_argument(
        "--rule",
        action="append",
        default=[],
        metavar="RULE_ID",
        help="只运行指定规则（可重复指定）",
    )

    # ---------------- rules ----------------
    rules = sub.add_parser("rules", help="列出内置检测规则")
    rules.add_argument(
        "--category", help=f"按类别过滤，可选：{', '.join(CATEGORY_LABELS)}"
    )
    rules.add_argument(
        "--severity", choices=[s.value for s in Severity], help="按严重度过滤"
    )
    rules.add_argument("--json", action="store_true", help="以 JSON 输出")
    rules.add_argument("-o", "--output", help="输出文件")

    # ---------------- init ----------------
    init = sub.add_parser("init", help="生成配置文件")
    init.add_argument(
        "-o", "--output",
        default=CONFIG_FILENAME,
        help=f"配置文件路径（默认 ./{CONFIG_FILENAME}）",
    )
    init.add_argument(
        "--force", action="store_true", help="覆盖已存在的配置文件"
    )

    return parser


# ----------------------------------------------------------------------
# 子命令实现
# ----------------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> int:
    target = args.target
    if not os.path.exists(target):
        print(f"✗ 目标路径不存在：{target}", file=sys.stderr)
        return EXIT_USAGE

    abs_target = os.path.abspath(target)
    search_root = (
        abs_target if os.path.isdir(abs_target) else os.path.dirname(abs_target)
    )
    try:
        config = (
            Config()
            if args.no_config
            else Config.load(args.config, search_root=search_root or None)
        )
    except ConfigError as exc:
        print(f"✗ 配置错误：{exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.exclude:
        config.exclude = list(config.exclude) + list(args.exclude)

    rules = config.resolve_rules()
    rule_filter = None
    if args.rule:
        rule_filter = {r.upper() for r in args.rule}
        rules = [r for r in rules if r.id.upper() in rule_filter]
        if not rules:
            print(f"✗ 没有匹配 --rule 的规则：{', '.join(args.rule)}", file=sys.stderr)
            return EXIT_USAGE

    try:
        min_severity = Severity.parse(args.severity)
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return EXIT_USAGE

    result = scan_path(
        target,
        config=config,
        min_severity=min_severity,
        rules=rules,
        rule_filter=rule_filter,
    )

    if args.format == "json":
        content = render_json(result)
    elif args.format == "markdown":
        kind = classify_target(result.root)
        content = render_markdown(result, title=f"AgentShield 安全扫描报告 · {kind}")
    elif args.format == "sarif":
        content = render_sarif(result)
    else:
        color = None if not args.no_color else False
        content = render_console(result, color=color, summary_only=args.quiet)

    if args.output:
        out_path = os.path.abspath(args.output)
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(content)
        if args.format == "console":
            counts = result.counts()
            print(
                f"✓ 扫描完成：{result.scanned_files} 个文件，"
                f"{len(result.findings)} 个命中（严重 {counts[Severity.CRITICAL]} / "
                f"高危 {counts[Severity.HIGH]} / 中危 {counts[Severity.MEDIUM]}）"
            )
            print(f"✓ 报告已写入：{out_path}")
    else:
        sys.stdout.write(content)

    # 退出码策略
    fail_on = None
    if args.fail_on:
        fail_on = Severity.parse(args.fail_on)
    elif config.fail_on:
        fail_on = config.fail_on
    if fail_on is not None:
        for finding in result.findings:
            if finding.severity.rank >= fail_on.rank:
                return EXIT_FINDINGS
    return EXIT_OK


def cmd_rules(args: argparse.Namespace) -> int:
    rules = get_rules()
    if args.category:
        if args.category not in CATEGORY_LABELS:
            print(
                f"✗ 未知类别 {args.category}，可选：{', '.join(CATEGORY_LABELS)}",
                file=sys.stderr,
            )
            return EXIT_USAGE
        rules = [r for r in rules if r.category == args.category]
    if args.severity:
        threshold = Severity.parse(args.severity)
        rules = [r for r in rules if r.severity.rank >= threshold.rank]

    if args.json:
        payload = [
            {
                **r.to_dict(),
                "category_label": CATEGORY_LABELS.get(r.category, r.category),
            }
            for r in rules
        ]
        content = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    else:
        lines = []
        current = None
        for rule in rules:
            if rule.category != current:
                current = rule.category
                lines.append("")
                lines.append(f"== {CATEGORY_LABELS.get(current, current)} ==")
            langs = "/".join(rule.languages)
            lines.append(
                f"  {rule.id:<16} {rule.severity.value:<8} [{langs:<26}] {rule.title}"
            )
            lines.append(f"  {'':<16} {rule.description}")
        content = "\n".join(lines).strip() + "\n"
        content = f"共 {len(rules)} 条规则\n" + content

    if args.output:
        out_path = os.path.abspath(args.output)
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"✓ 已写出 {len(rules)} 条规则 → {out_path}")
    else:
        sys.stdout.write(content)
    return EXIT_OK


def cmd_init(args: argparse.Namespace) -> int:
    out_path = os.path.abspath(args.output)
    if os.path.exists(out_path) and not args.force:
        print(
            f"✗ {out_path} 已存在。使用 --force 覆盖。",
            file=sys.stderr,
        )
        return EXIT_USAGE
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(DEFAULT_CONFIG_TEMPLATE, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print(f"✓ 已生成配置文件：{out_path}")
    print("  提示：编辑其中的 rules / severity_overrides / custom_rules 来自定义组织基线。")
    return EXIT_OK


def cmd_version(args: argparse.Namespace) -> int:
    print(f"AgentShield {__version__}")
    print(f"内置规则：{len(get_rules())} 条")
    return EXIT_OK


# ----------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    _enable_utf8()
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return EXIT_USAGE

    handlers = {
        "scan": cmd_scan,
        "rules": cmd_rules,
        "init": cmd_init,
        "version": cmd_version,
    }
    try:
        return handlers[args.command](args)
    except KeyboardInterrupt:
        print("\n已中断。", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # pragma: no cover - 兜底
        print(f"✗ 运行失败：{exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
