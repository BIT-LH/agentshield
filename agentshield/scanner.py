"""扫描引擎：文件发现、语言识别、规则应用、清单结构检查。"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Dict, Iterable, List, Optional, Set, Tuple

from . import checks
from .config import Config
from .models import Finding, Rule, ScanResult, Severity
from .rules import get_rules

#: 扫描时始终跳过的目录
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", "env",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".nox", "dist", "build",
    ".next", ".nuxt", ".output", ".cache", "site-packages", "coverage", ".idea",
    ".vscode-test", "site", ".eggs", "*.egg-info", ".terraform", ".gradle",
}

#: 扩展名 -> 语言标识
LANGUAGE_BY_EXT = {
    ".py": "python",
    ".pyw": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".mts": "javascript",
    ".cts": "javascript",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ksh": "shell",
    ".fish": "shell",
    ".ps1": "shell",
    ".psm1": "shell",
    ".cmd": "shell",
    ".bat": "shell",
    ".md": "markdown",
    ".markdown": "markdown",
    ".mdx": "markdown",
    ".json": "json",
    ".jsonc": "json",
    ".yaml": "text",
    ".yml": "text",
    ".toml": "text",
    ".txt": "text",
    ".env": "text",
    ".ini": "text",
    ".cfg": "text",
    ".rb": "text",
    ".php": "text",
    ".go": "text",
    ".rs": "text",
    ".java": "text",
    ".kt": "text",
    ".c": "text",
    ".h": "text",
    ".cpp": "text",
    ".hpp": "text",
    ".cs": "text",
    ".swift": "text",
    ".lua": "text",
    ".pl": "text",
    ".r": "text",
}

#: 按文件名匹配需要扫描的文件
SCAN_FILENAMES = {
    ".env", "Dockerfile", "Makefile", "justfile", "Procfile", ".npmrc", ".pypirc",
    ".gitconfig", "requirements.txt", "Pipfile", "poetry.lock", "package.json",
}

#: 会被当作「清单文件」做结构化检查的文件名
MANIFEST_FILENAMES = {
    "package.json", "package-lock.json", "mcp.json", ".mcp.json", "plugin.json",
    "manifest.json", "claude_desktop_config.json", "claude_code_config.json",
    "settings.json", "settings.local.json", "pyproject.toml", "servers.json",
}

#: 单文件大小上限（字节）
MAX_FILE_SIZE = 2 * 1024 * 1024

#: 每条规则在单个文件内最多报告的命中数
MAX_HITS_PER_RULE_PER_FILE = 3

#: 扩展名 -> 语言
LANGUAGE_NAME = {
    "python": "Python",
    "javascript": "JavaScript/TypeScript",
    "shell": "Shell/PowerShell",
    "markdown": "Markdown",
    "json": "JSON",
    "text": "配置/文本",
}


def detect_language(path: str) -> Optional[str]:
    """根据文件扩展名或文件名判断语言。"""
    name = os.path.basename(path)
    if name in SCAN_FILENAMES:
        return "text"
    _, ext = os.path.splitext(name)
    return LANGUAGE_BY_EXT.get(ext.lower())


def is_manifest(path: str) -> bool:
    """是否为需要结构化检查的清单文件。"""
    name = os.path.basename(path)
    if name in MANIFEST_FILENAMES:
        return True
    return name.startswith(".mcp.") and name.endswith(".json")


def _should_skip_dir(name: str) -> bool:
    return name in SKIP_DIRS or name.endswith(".egg-info")


def iter_files(root: str, exclude_patterns: Iterable[str] = ()) -> Iterable[str]:
    """遍历目录下所有待扫描文件，返回绝对路径。"""
    import fnmatch

    excludes = list(exclude_patterns)
    root = os.path.abspath(root)
    if os.path.isfile(root):
        if detect_language(root):
            yield root
        return

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not _should_skip_dir(d))
        for filename in sorted(filenames):
            full = os.path.join(dirpath, filename)
            if detect_language(full) is None:
                continue
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if any(fnmatch.fnmatch(rel, pat) for pat in excludes):
                continue
            yield full


def _read_text(path: str) -> Optional[str]:
    """读取文本内容；二进制或过大文件返回 None。"""
    try:
        if os.path.getsize(path) > MAX_FILE_SIZE:
            return None
    except OSError:
        return None
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        return None
    if b"\x00" in raw:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _column_of(text: str, offset: int) -> int:
    line_start = text.rfind("\n", 0, offset) + 1
    return offset - line_start + 1


def _snippet(text: str, offset: int, width: int = 160) -> str:
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end].strip()
    return line[:width] + ("…" if len(line) > width else "")


def apply_rules(
    text: str,
    rel_path: str,
    language: str,
    rules: List[Rule],
) -> List[Finding]:
    """对单个文件应用正则规则。"""
    findings: List[Finding] = []
    for rule in rules:
        if not rule.enabled or not rule.applies_to(language):
            continue
        pattern = rule.compile()
        hits = 0
        for match in pattern.finditer(text):
            if hits >= MAX_HITS_PER_RULE_PER_FILE:
                break
            matched = match.group(0)
            if not matched.strip():
                continue
            offset = match.start()
            message = rule.message.format(
                rule_id=rule.id, title=rule.title, match=matched[:120]
            )
            findings.append(
                Finding(
                    rule_id=rule.id,
                    title=rule.title,
                    severity=rule.severity,
                    category=rule.category,
                    message=message,
                    remediation=rule.remediation,
                    file=rel_path,
                    line=_line_of(text, offset),
                    column=_column_of(text, offset),
                    snippet=_snippet(text, offset),
                    match=matched[:200],
                    tags=list(rule.tags),
                    confidence=rule.confidence,
                    cwe=rule.cwe,
                )
            )
            hits += 1
    return findings


def apply_heuristics(text: str, rel_path: str, language: str) -> List[Finding]:
    """应用启发式检查。"""
    findings: List[Finding] = []
    findings.extend(checks.check_zero_width(text, rel_path))
    if language in ("python", "javascript", "shell", "text"):
        findings.extend(checks.check_high_entropy(text, rel_path))
        findings.extend(checks.check_hex_escape(text, rel_path))
        findings.extend(checks.check_ip_url(text, rel_path))
    return findings


# ----------------------------------------------------------------------
# 清单文件结构化检查
# ----------------------------------------------------------------------

_SECRET_KEY_RE = re.compile(
    r"(sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}"
    r"|AIza[0-9A-Za-z_\-]{30,}|xox[baprs]-[A-Za-z0-9\-]{10,})"
)
_LIFECYCLE_HOOKS = ("preinstall", "install", "postinstall", "prepare", "postprepare")
_UNPINNED_RUNNER_RE = re.compile(
    r"\b(?:npx\s+(?:-y\s+)?|uvx\s+|pipx\s+run\s+|bunx\s+)(?![\w@./-]+@)([\w@./-]+)"
)
_PINNED_RUNNER_RE = re.compile(r"[\w@./-]+@[\d.]+[\w.\-]*")


def _finding(
    rule_id: str,
    title: str,
    severity: Severity,
    category: str,
    message: str,
    remediation: str,
    rel_path: str,
    line: int = 0,
    snippet: str = "",
    tags: Optional[List[str]] = None,
    cwe: Optional[str] = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        category=category,
        message=message,
        remediation=remediation,
        file=rel_path,
        line=line,
        column=1,
        snippet=snippet,
        match=snippet,
        tags=tags or [],
        confidence="high",
        cwe=cwe,
    )


def check_package_json(data: dict, rel_path: str) -> List[Finding]:
    """检查 npm 包的安装期钩子与依赖来源。"""
    findings: List[Finding] = []
    scripts = data.get("scripts") or {}
    if isinstance(scripts, dict):
        for hook in _LIFECYCLE_HOOKS:
            body = scripts.get(hook)
            if not body:
                continue
            dangerous = re.search(
                r"curl|wget|pip\s+install|npm\s+install|http://|child_process|exec|eval",
                str(body),
                re.IGNORECASE,
            )
            severity = Severity.HIGH if dangerous else Severity.MEDIUM
            findings.append(
                _finding(
                    "AS-MANIFEST-001",
                    f"package.json 定义了安装期执行钩子 `{hook}`",
                    severity,
                    "supply_chain",
                    f"包在 `npm install` 期间会自动执行 `{hook}` 脚本：{body}。"
                    "用户安装该包即等于执行其中代码，恶意包可借此窃取凭据。",
                    "移除安装期钩子；确需构建步骤请改用 `prepare` 之外的显式构建命令并说明。",
                    rel_path,
                    snippet=f'"{hook}": "{body}"',
                    tags=["供应链", "安装期钩子"],
                    cwe="CWE-506",
                )
            )

    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = data.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            spec = str(spec)
            if spec.startswith(("git+http://", "http://")) or "github.com" in spec and "@" not in spec.split("/")[-1]:
                findings.append(
                    _finding(
                        "AS-MANIFEST-002",
                        "依赖指向未固定的 Git / HTTP 源",
                        Severity.MEDIUM,
                        "supply_chain",
                        f"依赖 `{name}` 指向可变来源：{spec}。上游代码可在任意时刻被替换。",
                        "改用包仓库中的固定版本，并提交 lock 文件。",
                        rel_path,
                        snippet=f'"{name}": "{spec}"',
                        tags=["供应链", "依赖"],
                        cwe="CWE-1357",
                    )
                )
    return findings


def check_mcp_config(data: dict, rel_path: str) -> List[Finding]:
    """检查 MCP 服务器配置。"""
    findings: List[Finding] = []
    servers = data.get("mcpServers") or data.get("servers") or {}
    if not isinstance(servers, dict):
        servers = {}
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        command = str(cfg.get("command", ""))
        args = cfg.get("args") or []
        arg_text = " ".join(str(a) for a in args)

        if command in ("npx", "bunx", "uvx", "pipx") or command in ("npx.cmd",):
            if not _PINNED_RUNNER_RE.search(arg_text) and not _PINNED_RUNNER_RE.search(command):
                findings.append(
                    _finding(
                        "AS-MANIFEST-003",
                        "MCP 服务器通过包运行器拉取未固定版本的包",
                        Severity.MEDIUM,
                        "supply_chain",
                        f"MCP 服务器 `{name}` 使用 `{command}` 拉取 `{arg_text}`，未固定版本。"
                        "上游包一旦被投毒即会在本地执行。",
                        "固定到具体版本（`npx pkg@1.2.3`），或改用本地已审计的安装。",
                        rel_path,
                        snippet=f'"{name}": {{"command": "{command}", "args": {args}}}',
                        tags=["供应链", "MCP"],
                        cwe="CWE-1357",
                    )
                )

        env = cfg.get("env") or {}
        if isinstance(env, dict):
            for key, value in env.items():
                value = str(value)
                if _SECRET_KEY_RE.search(value):
                    findings.append(
                        _finding(
                            "AS-MANIFEST-004",
                            "MCP 配置中硬编码了密钥",
                            Severity.CRITICAL,
                            "credential_access",
                            f"MCP 服务器 `{name}` 的环境变量 `{key}` 中包含形似真实密钥的值："
                            f"{value[:12]}…{value[-4:]}。",
                            "立即吊销该密钥，改用系统环境变量或密钥管理服务注入。",
                            rel_path,
                            snippet=f'"{key}": "{value[:16]}…"',
                            tags=["凭据", "MCP", "密钥泄露"],
                            cwe="CWE-798",
                        )
                    )

        for scope_key in ("permissions", "allow", "allowedTools"):
            scope = cfg.get(scope_key)
            if isinstance(scope, list) and any(
                item in ("*", "all", "**/*") for item in scope
            ):
                findings.append(
                    _finding(
                        "AS-MANIFEST-005",
                        "MCP 服务器请求了全量权限",
                        Severity.HIGH,
                        "privilege",
                        f"MCP 服务器 `{name}` 的 `{scope_key}` 包含通配符 `*`，等同于授予全部权限。",
                        "按最小权限原则逐项列出需要的工具与路径。",
                        rel_path,
                        snippet=f'"{scope_key}": {scope}',
                        tags=["权限", "MCP"],
                        cwe="CWE-250",
                    )
                )
    return findings


_FRONT_MATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---\s*\n", re.DOTALL)


def check_skill_markdown(text: str, rel_path: str) -> List[Finding]:
    """检查技能 Markdown 的前言声明与提示注入。"""
    findings: List[Finding] = []
    match = _FRONT_MATTER_RE.match(text)
    if not match:
        return findings
    frontmatter = match.group(1)
    findings.extend(checks.check_frontmatter_capabilities(frontmatter, rel_path))

    allowed = re.search(r"allowed[-_]tools\s*:\s*(.+)", frontmatter, re.IGNORECASE)
    if allowed:
        value = allowed.group(1).strip()
        if value in ("*", "all") or re.search(r"Bash\(\s*\*\s*\)", value):
            findings.append(
                _finding(
                    "AS-MANIFEST-006",
                    "技能声明了无限制的命令执行权限",
                    Severity.HIGH,
                    "privilege",
                    f"技能前言声明 `allowed-tools: {value}`，等价于允许模型执行任意 shell 命令。",
                    "把可执行命令收敛为明确的允许列表。",
                    rel_path,
                    line=1,
                    snippet=allowed.group(0).strip(),
                    tags=["权限", "Skill"],
                    cwe="CWE-250",
                )
            )
    return findings


def check_manifest(path: str, text: str, rel_path: str) -> List[Finding]:
    """对清单文件做结构化检查（解析失败则退化为纯文本规则）。"""
    name = os.path.basename(path)
    if not name.endswith(".json"):
        return []
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []

    findings: List[Finding] = []
    if name == "package.json":
        findings.extend(check_package_json(data, rel_path))
    findings.extend(check_mcp_config(data, rel_path))
    return findings


# ----------------------------------------------------------------------
# 对外入口
# ----------------------------------------------------------------------

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def dedupe(findings: List[Finding]) -> List[Finding]:
    """按 (规则, 文件, 行) 去重。"""
    seen: Set[Tuple[str, str, int]] = set()
    out: List[Finding] = []
    for f in findings:
        key = (f.rule_id, f.file, f.line)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """按严重度、文件、行排序。"""
    return sorted(
        findings,
        key=lambda f: (
            _SEVERITY_ORDER.get(f.severity, 9),
            f.file,
            f.line,
            f.rule_id,
        ),
    )


def scan_path(
    target: str,
    config: Optional[Config] = None,
    min_severity: Severity = Severity.INFO,
    rules: Optional[List[Rule]] = None,
    rule_filter: Optional[Set[str]] = None,
) -> ScanResult:
    """扫描目标路径。

    Args:
        target: 文件或目录路径。
        config: 配置对象；为 None 时使用默认配置。
        min_severity: 低于该严重度的命中会被过滤掉。
        rules: 覆盖配置解析出的规则列表。
        rule_filter: 只保留这些规则 ID 的命中（大小写不敏感）；None 表示不过滤。

    Raises:
        FileNotFoundError: 目标路径不存在。

    Returns:
        ScanResult
    """
    started = time.time()
    if not os.path.exists(target):
        raise FileNotFoundError("目标路径不存在：%s" % target)
    config = config or Config()
    active_rules = rules if rules is not None else config.resolve_rules()
    root = os.path.abspath(target)

    if rule_filter is not None:
        normalized = {r.upper() for r in rule_filter}
        active_rules = [r for r in active_rules if r.id.upper() in normalized]

    findings: List[Finding] = []
    errors: List[str] = []
    scanned = 0
    skipped = 0

    for path in iter_files(root, config.exclude):
        language = detect_language(path)
        if language is None:
            continue
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        if config.is_excluded(rel):
            skipped += 1
            continue

        text = _read_text(path)
        if text is None:
            skipped += 1
            continue

        scanned += 1
        try:
            findings.extend(apply_rules(text, rel, language, active_rules))
            findings.extend(apply_heuristics(text, rel, language))
            if is_manifest(path):
                findings.extend(check_manifest(path, text, rel))
            if language == "markdown":
                findings.extend(check_skill_markdown(text, rel))
        except Exception as exc:  # 单文件失败不应中断整体扫描
            errors.append(f"{rel}: {exc}")

    unique = dedupe(findings)
    filtered = [f for f in unique if f.severity.rank >= min_severity.rank]
    if rule_filter is not None:
        normalized = {r.upper() for r in rule_filter}
        filtered = [f for f in filtered if f.rule_id.upper() in normalized]

    return ScanResult(
        root=root,
        findings=sort_findings(filtered),
        scanned_files=scanned,
        skipped_files=skipped,
        duration_ms=int((time.time() - started) * 1000),
        rules_loaded=len(active_rules),
        errors=errors,
    )


def classify_target(root: str) -> str:
    """判断被扫描对象的载体类型，用于报告标题。"""
    root = os.path.abspath(root)
    names = set()
    if os.path.isfile(root):
        names.add(os.path.basename(root))
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if not _should_skip_dir(d)]
            for f in filenames:
                names.add(f)
                if len(names) > 400:
                    break
            if len(names) > 400:
                break

    if "SKILL.md" in names:
        return "Claude Code Skill"
    if names & {"mcp.json", ".mcp.json"}:
        return "MCP Server 配置"
    if "package.json" in names:
        return "扩展 / npm 包"
    if "plugin.json" in names:
        return "Agent 插件"
    return "源码目录"
