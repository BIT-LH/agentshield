"""配置加载：``.agentshield.json``。

配置文件示例::

    {
      "rules": {"AS-EXF-006": "off", "AS-DST-003": "warn"},
      "severity_overrides": {"AS-SUP-003": "medium"},
      "exclude": ["tests/fixtures/**", "**/node_modules/**"],
      "fail_on": "high",
      "custom_rules": [
        {
          "id": "ORG-001",
          "title": "禁止调用内网地址",
          "severity": "high",
          "category": "exfiltration",
          "pattern": "https?://10\\\\.\\\\d+",
          "remediation": "改走内网代理网关"
        }
      ]
    }
"""

from __future__ import annotations

import fnmatch
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .models import Rule, Severity
from .rules import get_rules

CONFIG_FILENAME = ".agentshield.json"

#: rule 状态取值
STATUS_OFF = "off"
STATUS_WARN = "warn"
STATUS_ON = "on"


@dataclass
class Config:
    """扫描配置。"""

    path: Optional[str] = None
    rule_status: Dict[str, str] = field(default_factory=dict)
    severity_overrides: Dict[str, Severity] = field(default_factory=dict)
    exclude: List[str] = field(default_factory=list)
    fail_on: Optional[Severity] = None
    custom_rules: List[Rule] = field(default_factory=list)
    extra_paths: List[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    @classmethod
    def load(cls, path: Optional[str] = None, search_root: Optional[str] = None) -> "Config":
        """加载配置文件。

        查找顺序：显式 ``path`` -> ``search_root`` 及其父目录中的 `.agentshield.json`
        -> 当前工作目录。找不到时返回默认配置。
        """
        resolved = cls._resolve_path(path, search_root)
        if resolved is None:
            return cls()

        try:
            with open(resolved, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"无法读取配置文件 {resolved}: {exc}") from exc

        return cls.from_dict(data, resolved)

    @classmethod
    def from_dict(cls, data: Dict[str, Any], path: Optional[str] = None) -> "Config":
        cfg = cls(path=path)
        for rid, status in (data.get("rules") or {}).items():
            cfg.rule_status[str(rid)] = str(status).lower()
        for rid, sev in (data.get("severity_overrides") or {}).items():
            try:
                cfg.severity_overrides[str(rid)] = Severity.parse(str(sev))
            except ValueError as exc:
                raise ConfigError(f"规则 {rid} 的严重度覆盖无效：{exc}") from exc
        cfg.exclude = [str(x) for x in (data.get("exclude") or [])]
        if data.get("fail_on"):
            try:
                cfg.fail_on = Severity.parse(str(data["fail_on"]))
            except ValueError as exc:
                raise ConfigError(f"fail_on 取值无效：{exc}") from exc
        cfg.extra_paths = [str(x) for x in (data.get("extra_paths") or [])]
        for raw in data.get("custom_rules") or []:
            try:
                cfg.custom_rules.append(Rule.from_dict(raw))
            except (ValueError, KeyError) as exc:
                raise ConfigError(f"自定义规则无效：{exc}") from exc
        return cfg

    # ------------------------------------------------------------------
    @staticmethod
    def _resolve_path(
        path: Optional[str], search_root: Optional[str]
    ) -> Optional[str]:
        if path:
            if not os.path.isfile(path):
                raise ConfigError(f"配置文件不存在：{path}")
            return os.path.abspath(path)
        root = os.path.abspath(search_root or os.getcwd())
        current = root
        while True:
            candidate = os.path.join(current, CONFIG_FILENAME)
            if os.path.isfile(candidate):
                return candidate
            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent
        return None

    # ------------------------------------------------------------------
    def resolve_rules(self) -> List[Rule]:
        """合并内置规则、配置开关、严重度覆盖与自定义规则。"""
        rules = get_rules()
        resolved: List[Rule] = []
        for rule in rules:
            status = self.rule_status.get(rule.id)
            if status == STATUS_OFF:
                continue
            if rule.id in self.severity_overrides:
                rule.severity = self.severity_overrides[rule.id]
            if status == STATUS_WARN:
                # 降一级但不低于 info
                order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
                idx = order.index(rule.severity)
                rule.severity = order[max(0, idx - 1)]
            resolved.append(rule)

        for custom in self.custom_rules:
            if custom.id in self.severity_overrides:
                custom.severity = self.severity_overrides[custom.id]
            resolved.append(custom)
        return resolved

    def is_excluded(self, rel_path: str) -> bool:
        """判断相对路径是否被排除。"""
        normalized = rel_path.replace(os.sep, "/")
        for pattern in self.exclude:
            if fnmatch.fnmatch(normalized, pattern):
                return True
            # 支持 `**/` 前缀的宽松匹配
            if fnmatch.fnmatch(normalized, "*/" + pattern.lstrip("/")):
                return True
            if pattern.endswith("/**") and normalized.startswith(pattern[:-3]):
                return True
        return False


class ConfigError(Exception):
    """配置文件错误。"""


DEFAULT_CONFIG_TEMPLATE: Dict[str, Any] = {
    "rules": {
        "AS-SUP-003": "warn",
    },
    "severity_overrides": {},
    "exclude": [
        "**/node_modules/**",
        "**/__pycache__/**",
        "**/.venv/**",
        "**/tests/fixtures/**",
    ],
    "fail_on": "high",
    "custom_rules": [
        {
            "id": "ORG-001",
            "title": "禁止访问内网地址",
            "severity": "medium",
            "category": "exfiltration",
            "pattern": r"https?://(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)",
            "description": "组织内网地址禁止出现在可外发的代码中。",
            "remediation": "改走内网代理网关访问。",
            "languages": ["any"],
            "tags": ["组织策略"],
        }
    ],
}
