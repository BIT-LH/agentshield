"""数据模型：严重度、命中项、扫描结果、规则定义."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    """风险严重度。数值越大越严重。"""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @property
    def label(self) -> str:
        return {
            Severity.CRITICAL: "严重",
            Severity.HIGH: "高危",
            Severity.MEDIUM: "中危",
            Severity.LOW: "低危",
            Severity.INFO: "提示",
        }[self]

    @classmethod
    def parse(cls, value: str) -> "Severity":
        key = (value or "").strip().lower()
        for member in cls:
            if member.value == key:
                return member
        raise ValueError(
            f"未知严重度 {value!r}，可选：{[m.value for m in cls]}"
        )

    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank < other.rank
        return NotImplemented

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank <= other.rank
        return NotImplemented

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank > other.rank
        return NotImplemented

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if isinstance(other, Severity):
            return self.rank >= other.rank
        return NotImplemented


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

#: SARIF level 映射
SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


@dataclass
class Finding:
    """一条安全命中。"""

    rule_id: str
    title: str
    severity: Severity
    category: str
    message: str
    remediation: str
    file: str
    line: int = 0
    column: int = 0
    snippet: str = ""
    match: str = ""
    tags: List[str] = field(default_factory=list)
    confidence: str = "high"
    cwe: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "severity_label": self.severity.label,
            "category": self.category,
            "message": self.message,
            "remediation": self.remediation,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "match": self.match,
            "tags": list(self.tags),
            "confidence": self.confidence,
            "cwe": self.cwe,
        }


@dataclass
class ScanResult:
    """一次扫描的完整结果。"""

    root: str
    findings: List[Finding] = field(default_factory=list)
    scanned_files: int = 0
    skipped_files: int = 0
    duration_ms: int = 0
    rules_loaded: int = 0
    errors: List[str] = field(default_factory=list)

    def counts(self) -> Dict[Severity, int]:
        counts = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    @property
    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def by_category(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.category] = counts.get(f.category, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": "agentshield",
            "root": self.root,
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            "duration_ms": self.duration_ms,
            "rules_loaded": self.rules_loaded,
            "summary": {s.value: c for s, c in self.counts().items()},
            "categories": self.by_category(),
            "findings": [f.to_dict() for f in self.findings],
            "errors": list(self.errors),
        }


@dataclass
class Rule:
    """一条静态检测规则。"""

    id: str
    title: str
    severity: Severity
    category: str
    pattern: str
    description: str
    remediation: str
    languages: List[str] = field(default_factory=lambda: ["any"])
    message: str = "命中规则 {rule_id}：{title}"
    tags: List[str] = field(default_factory=list)
    confidence: str = "high"
    cwe: Optional[str] = None
    enabled: bool = True
    case_sensitive: bool = False
    _compiled: Optional[re.Pattern] = field(default=None, repr=False, compare=False)

    def compile(self) -> re.Pattern:
        """编译并缓存正则。"""
        if self._compiled is None:
            flags = re.MULTILINE
            if not self.case_sensitive:
                flags |= re.IGNORECASE
            self._compiled = re.compile(self.pattern, flags)
        return self._compiled

    def applies_to(self, language: str) -> bool:
        if "any" in self.languages:
            return True
        return language in self.languages

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "description": self.description,
            "remediation": self.remediation,
            "languages": list(self.languages),
            "message": self.message,
            "tags": list(self.tags),
            "confidence": self.confidence,
            "cwe": self.cwe,
            "pattern": self.pattern,
            "case_sensitive": self.case_sensitive,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Rule":
        """从 JSON 字典构造（用于自定义规则）。"""
        missing = [k for k in ("id", "title", "severity", "pattern") if not data.get(k)]
        if missing:
            raise ValueError(f"自定义规则缺少必填字段：{', '.join(missing)}")
        severity = data["severity"]
        if isinstance(severity, str):
            severity = Severity.parse(severity)
        return cls(
            id=str(data["id"]),
            title=str(data["title"]),
            severity=severity,
            category=str(data.get("category", "custom")),
            pattern=str(data["pattern"]),
            description=str(data.get("description", "")),
            remediation=str(data.get("remediation", "")),
            languages=list(data.get("languages", ["any"])),
            message=str(data.get("message", "命中规则 {rule_id}：{title}")),
            tags=list(data.get("tags", [])),
            confidence=str(data.get("confidence", "medium")),
            cwe=data.get("cwe"),
            enabled=bool(data.get("enabled", True)),
            case_sensitive=bool(data.get("case_sensitive", False)),
        )
