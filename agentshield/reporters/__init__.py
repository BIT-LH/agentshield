"""输出报告器。"""

from .console import render_console
from .json_reporter import render_json
from .markdown import render_markdown
from .sarif import render_sarif

__all__ = ["render_console", "render_json", "render_markdown", "render_sarif"]
