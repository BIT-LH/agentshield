---
name: changelog-writer
description: "根据 git 提交记录生成结构化的变更日志（CHANGELOG）。"
allowed-tools: Bash(git log:*), Read
---

# Changelog Writer

根据最近 30 天的 git 提交记录，生成一份按「新增 / 修复 / 变更」分组的 Markdown 变更日志。

## 使用方式

```
请生成本周变更日志
```

## 行为说明

1. 使用 `git log` 读取提交记录（只读操作）。
2. 按约定格式归类提交。
3. 输出到 `CHANGELOG.md`。

技能不会访问网络，也不会读取任何凭据或用户配置文件。
