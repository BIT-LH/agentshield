"""SARIF 2.1.0 报告器：可直接上传到 GitHub Code Scanning。"""

from __future__ import annotations

import json
from typing import Dict, List

from ..models import SARIF_LEVEL, ScanResult, Severity

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/"
    "sarif-schema-2.1.0.json"
)
TOOL_URI = "https://github.com/agentshield/agentshield"
TOOL_NAME = "AgentShield"


def render_sarif(result: ScanResult) -> str:
    """生成 SARIF 2.1.0 报告。"""
    rules: Dict[str, Dict] = {}
    sarif_results: List[Dict] = []

    for finding in result.findings:
        if finding.rule_id not in rules:
            rules[finding.rule_id] = {
                "id": finding.rule_id,
                "name": finding.rule_id.replace("-", ""),
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.message},
                "help": {"text": finding.remediation or finding.title},
                "properties": {
                    "category": finding.category,
                    "confidence": finding.confidence,
                    **({"tags": finding.tags} if finding.tags else {}),
                    **({"security-severity": _security_severity(finding.severity)} if finding.cwe else {}),
                },
                "defaultConfiguration": {
                    "level": SARIF_LEVEL.get(finding.severity, "warning")
                },
            }

        sarif_results.append(
            {
                "ruleId": finding.rule_id,
                "level": SARIF_LEVEL.get(finding.severity, "warning"),
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.file.replace("\\", "/"),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": max(1, finding.line),
                                "startColumn": max(1, finding.column),
                                **(
                                    {"snippet": {"text": finding.snippet}}
                                    if finding.snippet
                                    else {}
                                ),
                            },
                        }
                    }
                ],
            }
        )

    payload = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_URI,
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def _security_severity(severity: Severity) -> str:
    """映射到 GitHub 使用的 security-severity 分数。"""
    return {
        Severity.CRITICAL: "9.0",
        Severity.HIGH: "7.0",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "3.0",
        Severity.INFO: "1.0",
    }[severity]
