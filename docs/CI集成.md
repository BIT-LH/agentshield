# CI 集成指南

把 AgentShield 接进流水线，在安装 AI 扩展前自动拦截高风险产物。

---

## 目录

1. [通用原则](#1-通用原则)
2. [GitHub Actions](#2-github-actions)
3. [GitLab CI](#3-gitlab-ci)
4. [Jenkins](#4-jenkins)
5. [pre-commit](#5-pre-commit)
6. [私有包源](#6-私有包源)
7. [误报抑制](#7-误报抑制)
8. [报告留存](#8-报告留存)

---

## 1. 通用原则

### 退出码策略

| 场景 | 建议参数 | 理由 |
| --- | --- | --- |
| 首次接入，先观察 | `--fail-on critical` | 只阻断最确定的威胁，避免阻塞团队 |
| 稳定后收紧 | `--fail-on high` | 平衡安全与摩擦 |
| 审计分支 / 定时任务 | `--fail-on critical` + `--format markdown` | 只告警不阻断，生成人工复核清单 |
| 第三方扩展准入 | `--fail-on critical` | 准入门槛应高于日常开发 |

### 三层防线

```
第 1 层  本地 pre-commit     —— 开发者提交前自查，秒级反馈
第 2 层  PR 流水线            —— 阻断合并，需人工复核
第 3 层  定时全量扫描         —— 规则库更新后回扫历史，发现存量风险
```

---

## 2. GitHub Actions

仓库内已提供可直接使用的示例：`.github/workflows/agentshield.yml`。

### 最小可用版本

```yaml
name: AgentShield

on:
  push:
    branches: [main]
  pull_request:

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install agentshield==1.0.0
      - name: 扫描
        run: agentshield scan . --format sarif --output results.sarif --fail-on high
      - name: 上传到 GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
      - name: 生成可读摘要
        if: always()
        run: agentshield scan . --format markdown --output summary.md || true
      - name: 上传摘要
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: agentshield-summary
          path: summary.md
```

### 关键点

- **`if: always()`** —— 扫描失败时仍然产出摘要，方便排查
- **先产出 SARIF 再判定退出码** —— 即使流水线红，告警也已经进了 Code Scanning
- **`|| true`** —— 生成 Markdown 这一步不应掩盖前面的真实失败

### 只扫描特定目录

```yaml
- run: agentshield scan ./skills ./mcp-servers --fail-on high
```

### 扫描外部技能仓库

```yaml
jobs:
  audit-third-party:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          repository: some-org/some-skill
          path: skill
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install agentshield==1.0.0
      - run: agentshield scan ./skill --format sarif --output skill.sarif --fail-on critical
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: skill.sarif
```

---

## 3. GitLab CI

```yaml
stages:
  - test

agentshield:
  stage: test
  image: python:3.12-slim
  variables:
    PIP_DISABLE_PIP_VERSION_CHECK: "1"
  cache:
    key:
      files: [requirements.txt]
    paths: [.cache/pip]
  before_script:
    - pip install agentshield==1.0.0
  script:
    - agentshield scan . --format json --output agentshield.json --fail-on critical
  artifacts:
    when: always
    paths:
      - agentshield.json
    expire_in: 1 week
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

带缓存的写法（私有源场景见第 6 节）：

```yaml
agentshield:
  stage: test
  image: python:3.12-slim
  cache:
    key: agentshield-$CI_COMMIT_REF_SLUG
    paths: [.cache/pip]
  variables:
    PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"
  before_script:
    - pip install --cache-dir "$PIP_CACHE_DIR" agentshield
  script:
    - agentshield scan . --fail-on high
```

---

## 4. Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('AgentShield 安全审计') {
            steps {
                sh 'python3 -m pip install agentshield==1.0.0'
                sh '''
                    set +e
                    agentshield scan . --format sarif --output agentshield.sarif --fail-on high
                    RC=$?
                    set -e
                    if [ $RC -eq 1 ]; then
                        echo "发现高危 AI 供应链风险，详见构建产物"
                    elif [ $RC -ne 0 ]; then
                        exit $RC
                    fi
                '''
                archiveArtifacts artifacts: 'agentshield.sarif', allowEmptyArchive: true
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'agentshield.sarif', allowEmptyArchive: true
        }
    }
}
```

`set +e` / `set -e` 的包裹是必需的：否则退出码 `1` 会让 stage 直接失败，
拿不到 SARIF 产物。

---

## 5. pre-commit

在提交前给出秒级反馈，减少 CI 往返。

`.pre-commit-config.yaml`：

```yaml
repos:
  - repo: local
    hooks:
      - id: agentshield
        name: AgentShield 安全审计
        entry: agentshield scan --fail-on critical --no-color
        language: python
        additional_dependencies: ["agentshield"]
        pass_filenames: false
        always_run: true
```

安装：

```bash
pip install pre-commit
pre-commit install
```

> 建议本地用 `--fail-on critical`（避免频繁被打断），
> CI 用 `--fail-on high`（更严的闸门）。

---

## 6. 私有包源

内网环境需要指定 PyPI 镜像：

```yaml
- name: 安装 AgentShield
  run: |
    pip install agentshield==1.0.0 \
      --index-url "$PIP_INDEX_URL" \
      --trusted-host "$PIP_TRUSTED_HOST"
  env:
    PIP_INDEX_URL: ${{ vars.PIP_INDEX_URL }}
    PIP_TRUSTED_HOST: ${{ vars.PIP_TRUSTED_HOST }}
```

如果不想依赖包仓库，也可以直接从源码运行 —— AgentShield 是纯标准库实现，
克隆即可用：

```yaml
- uses: actions/checkout@v4
  with:
    repository: internal/agentshield
    path: agentshield-src
- run: python agentshield-src/agentshield/cli.py scan .
```

> ⚠️ 这一点本身就是 AgentShield 存在的理由：**审计工具本身也需要被审计**。
> 用 `agentshield scan agentshield-src` 自检是合理的第一步。

---

## 7. 误报抑制

真实项目里总会有需要放行的规则。把决策写进配置文件，而不是加 `--exclude` 参数：

```json
{
  "rules": {
    "AS-SUP-003": "off",
    "AS-HEU-002": "warn"
  },
  "severity_overrides": {
    "AS-EXF-006": "low"
  },
  "exclude": [
    "examples/malicious-skill/**",
    "tests/fixtures/**"
  ]
}
```

`exclude` 要**谨慎使用** —— 它会连同真正的风险一起排除。
优先用 `"off"` 关闭整条规则（影响范围明确、可追溯），
而不是排除整个目录。

### 审查误报的正确流程

1. 用 `agentshield rules --category <类别>` 找到规则，理解它在检测什么
2. 在项目里 grep 出所有命中位置，逐个确认是不是真问题
3. 确认是误报 → 在配置里关掉这条规则，或降级为 `"warn"`
4. 提交配置文件变更，让团队看到"我们为什么决定放过这条规则"

---

## 8. 报告留存

### 归档到制品

```yaml
- name: 生成报告
  run: |
    agentshield scan . --format json --output agentshield.json --fail-on high || true
- uses: actions/upload-artifact@v4
  with:
    name: agentshield-report
    path: agentshield.json
    retention-days: 30
```

### JSON 接入内部看板

```bash
agentshield scan . --format json --output report.json
```

然后用 `jq` 提取：

```bash
jq -r '.summary | to_entries[] | "\(.key): \(.value)"' report.json
jq -r '.findings[] | select(.severity=="critical") | "\(.file):\(.line) \(.rule_id)"' report.json
```

### 定时全量回扫

规则库更新后，回扫历史以发现存量风险：

```yaml
name: AgentShield 定时回扫
on:
  schedule:
    - cron: "0 3 * * 1"     # 每周一 UTC 03:00
  workflow_dispatch:

jobs:
  rescan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install agentshield==1.0.0
      - run: agentshield scan . --format markdown --output report.md --severity medium || true
      - uses: actions/upload-artifact@v4
        with:
          name: agentshield-full-report
          path: report.md
```

---

## 附：退出码速查

| 码 | 含义 | CI 中的处理 |
| --- | --- | --- |
| `0` | 无命中达到阈值 | 继续 |
| `1` | 有命中达到阈值 | 阻断（这是你想要的） |
| `2` | 参数 / 配置错误 | 视为流水线配置问题，需要修 |
| `3` | 运行异常 | 视为工具故障，需要看日志 |
