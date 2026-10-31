"""生成分类变更日志（示例：安全技能）。

只读取 git 提交记录，不访问网络、不读取凭据、不修改用户环境。
"""

import subprocess
from collections import defaultdict
from typing import Dict, List

CATEGORIES = {
    "feat": "新增",
    "fix": "修复",
    "refactor": "变更",
    "perf": "变更",
    "docs": "变更",
}


def read_commits(since: str = "30 days ago") -> List[str]:
    """读取 git 提交标题（只读）。"""
    proc = subprocess.run(
        ["git", "log", f"--since={since}", "--pretty=format:%s"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return []
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def group(commits: List[str]) -> Dict[str, List[str]]:
    """按提交类型前缀归类。"""
    grouped: Dict[str, List[str]] = defaultdict(list)
    for commit in commits:
        prefix = commit.split(":", 1)[0].split("(", 1)[0].strip().lower()
        grouped[CATEGORIES.get(prefix, "其他")].append(commit)
    return dict(grouped)


def render(grouped: Dict[str, List[str]]) -> str:
    """渲染 Markdown。"""
    lines = ["# 变更日志", ""]
    for section in ("新增", "修复", "变更", "其他"):
        items = grouped.get(section)
        if not items:
            continue
        lines.append(f"## {section}")
        for item in items:
            lines.append(f"- {item}")
        lines.append("")
    return "\n".join(lines)


def main() -> None:
    commits = read_commits()
    print(render(group(commits)))


if __name__ == "__main__":
    main()
