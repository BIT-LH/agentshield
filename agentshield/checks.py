"""启发式检查：正则规则难以表达的形态。

- 零宽 / 双向控制字符（隐藏指令的常见载体）
- 高熵长字符串（疑似 Base64 / 加密载荷）
- 大段十六进制转义
- 技能清单中「可执行 + 联网 + 读环境」的能力叠加
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import List, Optional

from .models import Finding, Severity

#: 零宽 / 双向控制 / BOM 字符（用码点构造，避免源码中出现不可见字面量）
_ZERO_WIDTH_CODEPOINTS = {
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK",
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2060: "WORD JOINER",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE",
}

ZERO_WIDTH = {chr(cp): name for cp, name in _ZERO_WIDTH_CODEPOINTS.items()}

ZERO_WIDTH_RE = re.compile("[" + "".join(ZERO_WIDTH.keys()) + "]")

#: 连续十六进制转义
HEX_ESCAPE_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){12,}")

#: Base64 / Base32 样式长串
B64_RE = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
B64URL_RE = re.compile(r"[A-Za-z0-9_\-]{80,}={0,2}")

#: 十六进制长串
HEX_RE = re.compile(r"\b[0-9a-fA-F]{64,}\b")

#: 可疑的短 URL（IP 直连 / 非常规 TLD 组合）
IP_URL_RE = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?")


def shannon_entropy(text: str) -> float:
    """计算字符串的香农熵（bit/字符）。"""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum(
        (n / length) * math.log2(n / length) for n in counts.values()
    )


def check_zero_width(text: str, file: str) -> List[Finding]:
    """检测隐藏的零宽 / 双向控制字符。"""
    findings: List[Finding] = []
    for index, line in enumerate(text.splitlines(), start=1):
        for match in ZERO_WIDTH_RE.finditer(line):
            name = ZERO_WIDTH.get(match.group(0), "INVISIBLE CHARACTER")
            findings.append(
                Finding(
                    rule_id="AS-HEU-001",
                    title="文件中存在不可见字符",
                    severity=Severity.HIGH,
                    category="obfuscation",
                    message=(
                        f"第 {index} 行包含不可见字符 {name} (U+{ord(match.group(0)):04X})。"
                        "不可见字符常用于在用户看不到的地方藏匿针对模型的指令。"
                    ),
                    remediation=(
                        "移除不可见字符；如确需特殊符号，使用可见的转义写法。"
                    ),
                    file=file,
                    line=index,
                    column=match.start() + 1,
                    snippet=line.strip()[:160],
                    match=repr(match.group(0)),
                    tags=["隐藏字符", "提示注入"],
                    confidence="high",
                    cwe="CWE-77",
                )
            )
            break  # 每行只报一次，避免刷屏
    return findings


def check_high_entropy(text: str, file: str) -> List[Finding]:
    """检测长且高熵的字符串常量（疑似编码载荷）。"""
    findings: List[Finding] = []
    seen_lines = set()
    for match in list(B64_RE.finditer(text)) + list(B64URL_RE.finditer(text)):
        blob = match.group(0)
        if len(blob) < 120:
            continue
        entropy = shannon_entropy(blob)
        if entropy < 4.2:
            continue
        line_no = text.count("\n", 0, match.start()) + 1
        if line_no in seen_lines:
            continue
        seen_lines.add(line_no)
        findings.append(
            Finding(
                rule_id="AS-HEU-002",
                title="存在高熵长字符串常量",
                severity=Severity.MEDIUM,
                category="obfuscation",
                message=(
                    f"第 {line_no} 行存在长度 {len(blob)}、熵值 {entropy:.2f} bit/字符的字符串常量，"
                    "形态上与 Base64 编码的载荷一致，可能用于隐藏真实行为。"
                ),
                remediation=(
                    "若这是合法数据（如证书、内嵌资源），请在代码旁加注释说明来源；"
                    "若无可解释来源，请移除或改用明文。"
                ),
                file=file,
                line=line_no,
                column=1,
                snippet=blob[:64] + "…",
                match=blob[:32] + "…",
                tags=["混淆", "熵"],
                confidence="medium",
                cwe="CWE-506",
            )
        )
    return findings


def check_hex_escape(text: str, file: str) -> List[Finding]:
    """检测大段十六进制转义。"""
    findings: List[Finding] = []
    seen_lines = set()
    for match in HEX_ESCAPE_RE.finditer(text):
        line_no = text.count("\n", 0, match.start()) + 1
        if line_no in seen_lines:
            continue
        seen_lines.add(line_no)
        findings.append(
            Finding(
                rule_id="AS-HEU-003",
                title="存在大段十六进制转义",
                severity=Severity.MEDIUM,
                category="obfuscation",
                message=(
                    f"第 {line_no} 行出现连续 {len(match.group(0)) // 4} 个十六进制转义字符，"
                    "常用于把可执行内容藏起来以规避审查。"
                ),
                remediation="改用可读字符串字面量。",
                file=file,
                line=line_no,
                column=1,
                snippet=match.group(0)[:64] + "…",
                match=match.group(0)[:32] + "…",
                tags=["混淆"],
                confidence="medium",
                cwe="CWE-506",
            )
        )
    return findings


def check_ip_url(text: str, file: str) -> List[Finding]:
    """检测直连 IP 地址的 URL —— 常见的外泄回传地址。"""
    findings: List[Finding] = []
    seen_lines = set()
    for match in IP_URL_RE.finditer(text):
        line_no = text.count("\n", 0, match.start()) + 1
        if line_no in seen_lines:
            continue
        seen_lines.add(line_no)
        findings.append(
            Finding(
                rule_id="AS-HEU-004",
                title="代码中出现直连 IP 的 URL",
                severity=Severity.MEDIUM,
                category="exfiltration",
                message=(
                    f"第 {line_no} 行向裸 IP 地址发起请求：{match.group(0)}。"
                    "直连 IP 常用于绕开域名审计与证书校验。"
                ),
                remediation="使用经过审计的域名端点，并对目标主机做白名单校验。",
                file=file,
                line=line_no,
                column=match.start() + 1,
                snippet=match.group(0),
                match=match.group(0),
                tags=["外泄", "IOC"],
                confidence="medium",
                cwe="CWE-350",
            )
        )
    return findings


def check_frontmatter_capabilities(frontmatter: str, file: str) -> List[Finding]:
    """技能前言（frontmatter）中的能力声明叠加分析。

    单看 `allowed-tools: Bash` 并不危险；危险的是「可执行任意命令 + 可联网 + 可读环境变量」
    三者同时出现却没有声明网络白名单。
    """
    findings: List[Finding] = []
    lowered = frontmatter.lower()
    has_shell = "bash" in lowered or "shell" in lowered or "execute" in lowered
    has_network = any(k in lowered for k in ("network", "webfetch", "websearch", "fetch"))
    has_env = any(k in lowered for k in ("env", "environment", "secret", "credential"))
    if has_shell and has_network and has_env:
        findings.append(
            Finding(
                rule_id="AS-HEU-005",
                title="技能能力组合风险（执行 + 联网 + 读取凭据）",
                severity=Severity.MEDIUM,
                category="privilege",
                message=(
                    "技能前言同时声明了命令执行、网络访问与凭据/环境变量访问能力。"
                    "该组合使得一次提示注入即可导致凭据外泄，建议拆分能力或声明网络白名单。"
                ),
                remediation=(
                    "拆分技能职责；若必须保留组合，请在技能描述中写明允许访问的域名与变量名。"
                ),
                file=file,
                line=1,
                column=1,
                snippet=frontmatter.strip().splitlines()[0][:120] if frontmatter.strip() else "",
                match="allowed-tools / capabilities",
                tags=["能力组合", "提示注入"],
                confidence="medium",
                cwe="CWE-250",
            )
        )
    return findings
