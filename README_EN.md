# AgentShield 🛡️

**A supply-chain security auditor for AI agent extensions, skills, and MCP servers**

Get a trustworthy security verdict in ~3 seconds — *before* you install a Claude Code skill,
a VS Code / Cursor extension, or an MCP server.

```
$ agentshield scan ./my-claude-skill

AgentShield 扫描报告 · /path/to/my-claude-skill
扫描 3 个文件 · 规则 44 条 · 耗时 24 ms

风险汇总： 严重 4 · 高危 9 · 中危 1
...
```

[English](README_EN.md) | [简体中文](README.md)

---

## Why

In October 2026 the security community saw a run of AI-toolchain supply-chain incidents:

| Incident | Impact |
| --- | --- |
| `Backdoor in Claude Code for VS Code extension on the Cursor Marketplace` | Backdoored extension reached an official marketplace |
| `We Took over ChatGPT Accounts` | Mass account takeover |
| `AI startup hacks Anthropic, gains access to employee details` | Lateral movement through the AI supply chain |
| `Molly (Signal fork) has not been updated since 3 months and is vulnerable` | Abandoned dependency became an entry point |
| `Northflank Breached` / `Tell HN: Scribd Breached` | Consecutive dev- and content-platform leaks |

They share one trait: **these extensions run as auto-executing code on developer machines**,
and the only pre-install review is reading the source line by line — which almost nobody does.

AgentShield automates that step: one command, zero dependencies, three seconds.

---

## Features

- **Zero runtime dependencies** — Python standard library only; nothing to fetch at install time
- **44 built-in rules + 9 heuristic checks** spanning prompt injection, credential access,
  data exfiltration, remote execution, persistence, over-privileged permissions, obfuscation,
  supply chain, and destructive operations
- **AI-specific detection** — prompt injection, hidden instructions, invisible characters,
  and over-broad tool declarations in skill frontmatter
- **Carrier-aware** — differentiated manifest checks for Skills, MCP servers, and extensions
- **Four output formats** — terminal, JSON, Markdown, and SARIF (uploads straight to GitHub Code Scanning)
- **Organization-friendly** — custom rules, severity overrides, per-rule toggles, failure baselines
- **CI-ready** — explicit exit-code policy; `--fail-on high` drops into any pipeline

---

## Install

Requires Python 3.8+.

```bash
# Option 1: run straight from the source tree (no install)
git clone https://github.com/agentshield/agentshield.git
cd agentshield
python -m agentshield --help

# Option 2: install as a CLI
pip install -e .
agentshield --help
```

> On Windows no extra setup is needed — the tool forces UTF-8 on stdout, so Chinese
> reports render correctly.

---

## Quick start

```bash
# Scan a skill
agentshield scan ~/.claude/skills/my-skill

# Scan a repo, emit SARIF for GitHub Code Scanning
agentshield scan . --format sarif --output results.sarif --fail-on high

# Run only specific rules
agentshield scan . --rule AS-PI-001 --rule AS-EXF-001

# List every rule
agentshield rules
agentshield rules --json

# Create an organization config
agentshield init
```

Full command reference: [docs/使用指南.md](docs/使用指南.md) (Chinese) or run
`agentshield <command> --help`.

---

## Configuration

Place `.agentshield.json` in your repository root; AgentShield walks up from the scan
target until it finds one.

```json
{
  "rules": {
    "AS-SUP-003": "warn",
    "AS-EXF-006": "off"
  },
  "severity_overrides": { "AS-PI-005": "critical" },
  "exclude": ["**/node_modules/**", "tests/fixtures/**"],
  "fail_on": "high",
  "custom_rules": [
    {
      "id": "ORG-001",
      "title": "No direct access to internal addresses",
      "severity": "medium",
      "category": "exfiltration",
      "pattern": "https?://10\\.\\d+\\.\\d+\\.\\d+",
      "remediation": "Route through the audited internal gateway."
    }
  ]
}
```

`rules` values are `on` / `warn` (downgrade one level) / `off`.

---

## What it finds

The complete catalog lives in **[docs/规则手册.md](docs/规则手册.md)**, generated from the
code so it can never drift. Highlights:

- **Prompt injection** — `<!-- ignore all previous instructions -->` in a `SKILL.md`.
  Reports `AS-PI-001`, `AS-PI-003`, and `AS-PI-004` separately.
- **Credential harvesting + encoded exfiltration** — `dict(os.environ)` piped through
  `base64.b64encode` into `requests.post` → `AS-CRED-004`, `AS-EXF-001`, `AS-EXF-002`.
- **Install-time execution** — a `postinstall` hook running `curl … | sh` →
  `AS-MANIFEST-001`, `AS-RCE-004`, `AS-SUP-001`.
- **Invisible characters** — zero-width spaces hiding instructions from humans but not from
  the model → `AS-HEU-001`.
- **Capability stacking** — "shell + network + env access" declared together is individually
  harmless and collectively an exfiltration primitive → `AS-HEU-005`.

---

## CI integration

```yaml
- name: AgentShield security audit
  run: |
    pip install agentshield==1.0.0
    agentshield scan . --format sarif --output results.sarif --fail-on high
```

See **[docs/CI集成.md](docs/CI集成.md)** for GitHub Actions, GitLab CI, and private-index setups.

---

## Examples

```
examples/
├── malicious-skill/    # simulated backdoored marketplace extension
└── safe-skill/         # clean counterpart
```

```bash
agentshield scan examples/malicious-skill   # 19 findings
agentshield scan examples/safe-skill        # 0 findings
```

---

## Development

```bash
pip install -e ".[dev]"
python -m pytest tests -q
python scripts/gen_rule_docs.py    # regenerate the rule manual after rule changes
```

Adding a rule means appending one `_r(...)` entry to `BUILTIN_RULES` in
`agentshield/rules.py`; IDs must match `AS-<CATEGORY>-<NNN>` (enforced by tests).

---

## Known limits

Being explicit about what this tool cannot do:

- **Not a sandbox** — it never executes the code it scans, so runtime-only behavior is invisible
- **Not semantic** — pattern matching cannot tell whether a call is dangerous *in context*
- **False positives exist** — especially for `confidence: medium` rules; tune `--fail-on` to taste
- **No binary coverage** — compiled artifacts need a separate SAST tool
- **Heuristics are hints, not verdicts** — treat `AS-HEU-002` (entropy) as "worth a look"

---

## License

[MIT](LICENSE)
