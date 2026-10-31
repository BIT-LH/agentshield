"""AgentShield - AI Agent 扩展 / 技能 / MCP Server 供应链安全审计器.

一个零依赖的静态安全扫描器，用于在安装前审计 AI Agent 生态中的可执行产物：
  - Claude Code Skill (SKILL.md + scripts/)
  - MCP Server (Python / Node.js) 与 .mcp.json 配置
  - VS Code / Cursor 扩展 (package.json + 源码)
  - 通用 AI CLI 插件与脚本
"""

__version__ = "1.0.0"
__author__ = "AgentShield contributors"
__license__ = "MIT"

from .models import Finding, ScanResult, Severity
from .scanner import scan_path

__all__ = ["Finding", "ScanResult", "Severity", "scan_path", "__version__"]
